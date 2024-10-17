module Main where

import Prelude
import Control.Monad
import Control.Monad.Except
import Data.ByteString qualified as BS
import Data.ByteString.Char8 qualified as BS

import Control.Exception
import Options.Applicative

import Data.PEM qualified as PEM
import Crypto.PubKey.RSA qualified as RSA
import Data.X509 qualified as X509
import Crypto.Store.PKCS8 qualified as PKCS8
-- import qualified Data.X509.PKCS10 as PKCS10

import qualified Key

import CLI.Key

-- * Options

data Options = Options
  { optCommand :: Command
  , verbose :: Bool
  } deriving (Show)

data Command
  = KeyOptions_ KeyOptions
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

data KeyRead = KeyRead
  { paths :: [FilePath]
  } deriving (Show)

keyReadP :: Parser KeyRead
keyReadP = KeyRead <$>
  many (argument str (metavar "FILES to inspect"))

keyCmdP :: Parser KeyOptions
keyCmdP = KeyRead_ <$> keyReadP
  <|> KeyGenerate_ <$> keyGenerateP

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
keyRead KeyRead{paths} = earlyExit $ do
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
    showBs path bs = forM_ (PKCS8.readKeyFileFromMemory bs) (showPkcs8 path)

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
opts = Options <$> hsubparser (key <> csr <> ca) <*> verbose
  where
    key = command "key" $ info (KeyOptions_ <$> keyCmdP)
        $ progDesc "Generate, check or password protect keys"
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
