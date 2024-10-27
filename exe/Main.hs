module Main where

import Prelude
import Control.Monad
import Control.Monad.IO.Class
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
keyCmdP
  = KeyGenerate_ <$> keyGenerateP
  <|> KeyRead_ <$> keyReadP

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
    showBs path bs = forM_ (PKCS8.readKeyFileFromMemory bs) (showPkcs8 path)

    showPkcs8 :: FilePath -> PKCS8.OptProtected X509.PrivKey -> IO ()
    showPkcs8 path pkcs8 = case pkcs8 of
      PKCS8.Unprotected key -> putStrLn $ "- " <> path <> ": " <> showKey key <> " private key"
      PKCS8.Protected _ -> print "password protected" -- TODO

    showKey :: X509.PrivKey -> String
    showKey key = case key of
      X509.PrivKeyRSA rsa -> "RSA " <> show (RSA.public_size (RSA.private_pub rsa) * 8) <> " bit"
      X509.PrivKeyEd25519 _key -> "Ed25519"
      X509.PrivKeyEd448 _key -> "Ed448"
      X509.PrivKeyDSA _key -> "DSA"
      X509.PrivKeyEC _key -> "EC"
      X509.PrivKeyX25519 _key -> "X25519"
      X509.PrivKeyX448 _key -> "X448"


-- * Main

cli :: Parser Options
cli = Options <$> hsubparser key <*> verbose
  where
    key = command "key" $ info (KeyOptions_ <$> keyCmdP)
        $ progDesc "Generate, check or password protect keys"

    verbose = switch
        $ long "verbose"
       <> short 'v'
       <> help "Whether to be verbose"

main :: IO ()
main = do
  opts :: Options <- execParser (info (helper <*> cli) idm)
  when (verbose opts) $ putStrLn $ "CLI options: " <> show opts
  case optCommand opts of
    KeyOptions_ keyOpts -> case keyOpts of
      KeyGenerate_ o -> keyGenerate o
      KeyRead_ o -> keyRead o

hot :: IO ()
hot = main

-- * Helpers

type EarlyExit a = ExceptT String IO a

tryReadFile :: FilePath -> EarlyExit BS.ByteString
tryReadFile path = do
  e <- liftIO $ try $ BS.readFile path
  case e of
    Left (_err :: IOException) -> fail $ "Couldn't read file: " <> path
    Right bs -> return bs

earlyExit :: EarlyExit () -> IO ()
earlyExit m = runExceptT m >>= either putStrLn return
