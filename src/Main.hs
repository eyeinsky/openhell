module Main where

import Prelude
import Control.Monad
import Control.Monad.Except
import qualified Data.ByteString as BS

import Control.Exception
import Options.Applicative

import qualified Data.PEM as PEM
import qualified Crypto.PubKey.RSA as RSA
import qualified Data.X509 as X509
-- import qualified Crypto.Store.X509 as X509
import qualified Crypto.Store.PKCS8 as PKCS8
import qualified Data.X509.PKCS10 as PKCS10

-- * Options

data Options = Options
  { optCommand :: Command
  , verbose :: Bool
  } deriving (Show)

data Command
  = KeyOptions' KeyOptions
  | CSROptions' CSROptions
  | CAOptions' CAOptions
  | SignOptions' SignOptions
  deriving (Show)

-- ** Key

data KeyOptions
  = KeyGenerate' KeyGenerate
  | KeyRead' KeyRead
  deriving (Show)

data KeyGenerate = KeyGenerate
  { bits :: Int
  } deriving (Show)

data KeyRead = KeyRead
  { files :: [FilePath]
  } deriving (Show)

keyGenerateP :: Parser KeyGenerate
keyGenerateP = KeyGenerate
  <$> option auto
      ( long "bits"
     <> metavar "INT"
     <> showDefault
     <> value 2048
     <> help "Key size in bits" )

keyReadP :: Parser KeyRead
keyReadP = KeyRead <$>
  some (argument str (metavar "FILES to inspect"))

keyCmdP :: Parser KeyOptions
keyCmdP = KeyRead' <$> keyReadP
     <|> KeyGenerate' <$> keyGenerateP

-- ** Certificate signing request

data CSROptions
  = CSRCreate' CSRCreate
  | CSRRead' CSRRead
  deriving (Show)

data CSRCreate = CSRCreate deriving (Show)
data CSRRead = CSRRead deriving (Show)

csrCmdP :: Parser CSROptions
csrCmdP = CSRCreate' <$> undefined
      <|> CSRRead' <$> undefined

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
    certify :: X509.PrivKey -> PKCS10.SignedCertificationRequest -> X509.SignedCertificate
    certify k p = undefined



-- * Key

keyGenerate :: KeyGenerate -> IO ()
keyGenerate o = do
  let bytes = div (bits o) 8
  (pub, priv) <- RSA.generate bytes 65537
  let
    priv' = X509.PrivKeyRSA priv
    pem :: PEM.PEM
    pem = PKCS8.keyToPEM PKCS8.PKCS8Format priv'
  BS.putStr $ PEM.pemWriteBS pem

keyRead :: KeyRead -> IO ()
keyRead o = earlyExit $ do
  liftIO $ putStrLn "Keys:"
  forM_ (files o) $ \path -> do
    content :: BS.ByteString <- tryReadFile path
    forM_ (PKCS8.readKeyFileFromMemory content) $ \key -> liftIO $ case key of
      PKCS8.Unprotected key -> putStrLn $ "- " <> path <> ": " <> showKey key
      PKCS8.Protected _ -> print "password protected"

  where
    showKey :: X509.PrivKey -> String
    showKey key = case key of
      X509.PrivKeyRSA rsa -> "RSA, " <> show (RSA.public_size (RSA.private_pub rsa) * 8) <> " bit"
      _ -> "not implemented"

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
    key = command "key" $ info (KeyOptions' <$> keyCmdP)
        $ progDesc "Generate, check or password protect keys"
    csr = command "csr" $ info (CSROptions' <$> csrCmdP)
        $ progDesc "Generate and check certificate signing requests"
    ca = command "ca" $ info (CAOptions' <$> caCmdP)
       $ progDesc "CA ..."
    sign = command "sign" $ info (SignOptions' <$> signCmdP)
        $ progDesc "Sign a CSR"

    verbose = switch
        $ long "verbose"
       <> short 'v'
       <> help "Whether to be verbose"

main :: IO ()
main = do
  opts :: Options <- execParser (info opts idm)
  when (verbose opts) $ print opts
  case optCommand opts of
    KeyOptions' keyOpts -> case keyOpts of
      KeyGenerate' o -> keyGenerate o
      KeyRead' o -> keyRead o
    CSROptions' csrOpts -> case csrOpts of
      CSRRead' o -> csrRead o
      CSRCreate' o -> csrCreate o
    CAOptions' o -> ca o

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
