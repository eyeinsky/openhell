module Main where

import Prelude
import Data.Monoid
import Data.Aeson qualified as A
import Data.Char
import Data.List
import Data.Maybe
import Data.Text.Encoding qualified as TS
import Data.Text qualified as TS
import Control.Monad
import Control.Monad.IO.Class
import Control.Monad.Except
import Data.ByteString qualified as BS
import Data.ByteString.Char8 qualified as BS
import Data.ByteString.Char8 qualified as BS8
import Data.ByteString.Lazy.Char8 qualified as BL8
import Time.Types as Hourglass
import Time.Compat as Hourglass
import Time.System as Hourglass
import Data.Time

import Control.Exception
import Options.Applicative

import Data.PEM qualified as PEM
import Crypto.PubKey.RSA qualified as RSA
import Data.X509 as X509
import Crypto.Store.PKCS8 qualified as PKCS8
-- import qualified Data.X509.PKCS10 as PKCS10

import qualified Key
import X509.Certificate qualified as Cert

import Helpers
import CLI.Key
import CLI.Cert qualified as Cert

-- * Options

data Options = Options
  { optCommand :: Command
  , verbose :: Bool
  } deriving (Show)

data Command
  = KeyOptions_ KeyOptions
  | CertOptions_ CertOptions
  | CSROptions_ CSROptions
  | CAOptions_ CAOptions
  | SignOptions_ SignOptions
  deriving (Show)

-- ** Key

data KeyOptions where
  KeyGenerate_ :: KeyGenerate -> KeyOptions
  KeyRead_ :: KeyRead -> KeyOptions

instance Show (Key.Conf alg) where show _ = "Key.Conf alg" -- temporary
deriving instance Show KeyOptions
deriving instance Show KeyGenerate

keyReadP :: Parser KeyRead
keyReadP = KeyRead <$> manyPaths "FILES to inspect"

keyCmdP :: Parser KeyOptions
keyCmdP = KeyRead_ <$> keyReadP
  <|> KeyGenerate_ <$> keyGenerateP

-- ** Certificate

data CertOptions
  = CertCreate_ Cert.Create
  | CertRead_ Cert.Read
  deriving Show

certCmdP :: Parser CertOptions
certCmdP
  = CertCreate_ <$> certCreate
  <|> CertRead_ <$> certRead
  where
    certCreate = Cert.Create
      <$> strOption (long "subject-key")
      <*> strOption (long "issuer-key")
      <*> strOption (long "subject")
    certRead = Cert.Read <$> manyPaths "CERT" <*> strOption (long "format" <> value "unspecified")

certCreate :: Cert.Create -> IO ()
certCreate Cert.Create{Cert.subjectKey, Cert.issuerKey, Cert.subjectName } = do
  validity1year <- Cert.validityIntervalFromNow
  let (tbs, alg) = Cert.newTBS subjectName "issuerName" validity1year
  -- get pubKey
  pem : _ <- either fail pure . PEM.pemParseBS =<< BS.readFile subjectKey
  let x = Key.parseHeaderless $ TS.decodeUtf8 $ PEM.pemContent pem
  -- print x
  undefined
  -- get privKey
  -- get (privKey matching) alg
  -- cert <- Cert.mkCertificate tbs undefined undefined undefined
  -- render to PEM
  -- send to stdout
  -- undefined

certRead :: Cert.Read -> IO ()
certRead Cert.Read{Cert.paths, Cert.format} = do
  mapM_ (doCert <=< BS.readFile) paths
  where
    shower = case format of
      "json" -> BL8.putStrLn . A.encode . A.toJSON
      _ -> showCert

    doCert bs = do
      signedExacts <- either fail pure $ Cert.fromPem bs
      mapM_ (shower . signedObject . getSigned) signedExacts

    showCert :: X509.Certificate -> IO ()
    showCert cert = putStrLn $ unlines
      [ showl "Serial" certSerial
      , showl "Signature algorithm" certSignatureAlg
      , showl "Version" certVersion
      , TS.unpack $ "Validity: " <> Cert.dateTimeToISO8601 validFrom <> " -- " <> Cert.dateTimeToISO8601 validTo
      , showDN "Issuer:" certIssuerDN
      , showDN "Subject:" certSubjectDN
      , "Extensions:\n" <> (maybe "" (unlines . map showExt) $ case certExtensions of Extensions mb -> mb)
      -- , show cert
      ]
      where
        showl label a = label <> ": " <> show a
        Certificate
          { certSerial, certSignatureAlg, certPubKey
          , certIssuerDN, certSubjectDN
          , certExtensions
          , certVersion
          , certValidity = (validFrom, validTo)
          } = cert

        showDN label o = unlines $ label : (map showWho $ getDistinguishedElements o)
        showWho (oid, cs) = "  " <> TS.unpack (Cert.oidLabel oid) <> " " <> TS.unpack (TS.decodeUtf8 (getCharacterStringRawData cs))

        showExt ExtensionRaw{extRawOID, extRawCritical, extRawContent} = "  " <> unwords [show extRawOID, show extRawCritical, unwords $ map show xs]
          where
            xs = filter (not . BS.null) $ BS8.splitWith (not . domainChar) extRawContent
            domainChar c = isAlpha c || isDigit c || c `elem` ['.', '-']
--        alg = signedAlg s
--        signature_ = signedSignature s

-- *** Generate

-- ** Certificate signing request

data CSROptions
  = CSRCreate_ CSRCreate
  | CSRRead_ CSRRead
  deriving (Show)

data CSRCreate = CSRCreate deriving (Show)
data CSRRead = CSRRead deriving (Show)

csrCmdP :: Parser CSROptions
csrCmdP = CSRCreate_ <$> undefined
      <|> CSRRead_ <$> undefined

-- ** Certificate authority

data CAOptions = CAOptions deriving (Show)

caCmdP :: Parser CAOptions
caCmdP = pure CAOptions

-- * Sign

-- ** Options

data CSR = CSR deriving (Show)
data SignOptions = SignOptions
  { privateKey :: FilePath
  , csrs :: [FilePath] -- todo: non-empty list
  , suffix :: String
  } deriving (Show)

signCmdP :: Parser SignOptions
signCmdP = SignOptions
  <$> key'ish
  <*> csr'ish
  <*> suffix'
  where
    key'ish = argument str (metavar "FILE" <> help "path to private key")
    csr'ish = some (argument str (metavar "FILES to inspect"))
    suffix' = option auto
       $ long "suffix"
      <> help "Suffix to add for signed certificates"
      <> showDefault
      <> value ".crt"
      <> metavar "SUFFIX"

-- ** Implementation

sign :: SignOptions -> IO ()
sign o = earlyExit $ do
  privateKey' <- tryReadFile $ privateKey o
  csrs' <- mapM tryReadFile $ csrs o
  pure ()
  where
    -- certify :: X509.PrivKey -> PKCS10.SignedCertificationRequest -> X509.SignedCertificate
    certify k p = undefined

-- * Key

keyGenerate :: KeyGenerate -> IO ()
keyGenerate o = case o of
  KeyGenerateRSA conf -> generateAndPrint conf
  KeyGenerateEd448 conf -> generateAndPrint conf
  KeyGenerateEd25519 conf -> generateAndPrint conf
  where
    generateAndPrint
      :: (Key.Generate alg, Key.ToPrivKey (Key.Private alg))
      => Key.Conf alg -> IO ()
    generateAndPrint conf = do
      (_, priv) <- Key.generate conf
      BS.putStr $ PEM.pemWriteBS $ Key.toPKCS8 priv

keyRead :: KeyRead -> IO ()
keyRead KeyRead{CLI.Key.paths} = earlyExit $ do
  liftIO $ putStrLn "Keys:"
  void $ case paths of
    [] -> liftIO showStdin
    _ -> forM_ paths $ \case
      "-" -> liftIO showStdin
      path -> liftIO . showBs path =<< tryReadFile path

  where
    showStdin :: IO ()
    showStdin = showBs "stdin" =<< BS.getContents

    showBs :: FilePath -> BS.ByteString -> IO ()
    showBs path bs = forM_ (PKCS8.parseKey . head =<< PEM.pemParseBS bs) (showPkcs8 path)
    -- TODO: ^ head: parse multiple keys from file

    showPkcs8 :: FilePath -> PKCS8.OptProtected X509.PrivKey -> IO ()
    showPkcs8 path pkcs8 = case pkcs8 of
      PKCS8.Unprotected key -> putStrLn $ "- " <> path <> ": " <> showKey key <> " private key"
      PKCS8.Protected _ -> print "password protected"

    showKey :: X509.PrivKey -> String
    showKey key = case key of
      X509.PrivKeyRSA rsa -> "RSA " <> show (RSA.public_size (RSA.private_pub rsa) * 8) <> " bit"
      X509.PrivKeyEd25519 _key -> "Ed25519"
      X509.PrivKeyEd448 _key -> "Ed448"
      X509.PrivKeyDSA _key -> "DSA"
      X509.PrivKeyEC _key -> "EC"
      X509.PrivKeyX25519 _key -> "X25519"
      X509.PrivKeyX448 _key -> "X448"

-- * Certificate signing request

csrRead :: CSRRead -> IO ()
csrRead o = undefined

csrCreate :: CSRCreate -> IO ()
csrCreate o = return ()

-- * Certificate authority

ca :: CAOptions -> IO ()
ca _ = return ()

-- * Main

opts :: Parser Options
opts = Options <$> hsubparser (key <> cert <> csr <> ca) <*> verbose
  where
    key = command "key" $ info (KeyOptions_ <$> keyCmdP)
        $ progDesc "Generate, check or password protect keys"
    cert = command "cert" $ info (CertOptions_ <$> certCmdP)
        $ progDesc "Create, modify or inspect certificates"
    csr = command "csr" $ info (CSROptions_ <$> csrCmdP)
        $ progDesc "Generate and check certificate signing requests"
    ca = command "ca" $ info (CAOptions_ <$> caCmdP)
       $ progDesc "CA ..."
    sign = command "sign" $ info (SignOptions_ <$> signCmdP)
        $ progDesc "Sign a CSR"

    verbose = switch
        $ long "verbose"
       <> short 'v'
       <> help "Whether to be verbose"

main :: IO ()
main = do
  opts :: Options <- execParser (info (helper <*> opts) idm)
  when (verbose opts) $ print opts
  case optCommand opts of
    KeyOptions_ keyOpts -> case keyOpts of
      KeyGenerate_ o -> keyGenerate o
      KeyRead_ o -> keyRead o
    CertOptions_ certOpts -> case certOpts of
      CertCreate_ o -> print o
      CertRead_ o -> certRead o
    CSROptions_ csrOpts -> case csrOpts of
      CSRRead_ o -> csrRead o
      CSRCreate_ o -> csrCreate o
    CAOptions_ o -> ca o

hot :: IO ()
hot = main

-- * Helpers

type EarlyExit a = ExceptT String IO a

tryReadFile :: FilePath -> EarlyExit BS.ByteString
tryReadFile path = do
  e <- liftIO $ try $ BS.readFile path
  case e of
    Left (err :: IOException) -> fail $ "Couldn't read file: " <> path
    Right bs -> return bs

earlyExit :: EarlyExit () -> IO ()
earlyExit m = runExceptT m >>= either putStrLn return
