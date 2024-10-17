module CLI.Key where

import Prelude
import Options.Applicative
import Key qualified


data KeyRead = KeyRead
  { paths :: [FilePath]
  } deriving (Show)

data KeyGenerate where
  KeyGenerateRSA :: Key.Conf Key.RSA -> KeyGenerate
  -- KeyGenerateDSA :: Key.Conf Key.DSA -> KeyGenerate
  -- KeyGenerateECDSA :: Key.Conf Key.ECDSA -> KeyGenerate
  KeyGenerateEd448 :: Key.Conf Key.Ed448 -> KeyGenerate
  KeyGenerateEd25519 :: Key.Conf Key.Ed25519 -> KeyGenerate

genRSA :: Parser (Key.Conf Key.RSA)
genRSA = Key.RSA'
  <$> option auto
      ( long "bits"
     <> metavar "INT"
     <> showDefault
     <> value 2048
     <> help "Key size in bits" )
  <*> option auto
      ( long "exponent"
     <> metavar "INT"
     <> showDefault
     <> value 65537
     <> help "Exponent" )

-- genDSA :: Parser (Key.Conf Key.DSA)
-- genDSA = Key.DSA' <$> undefined -- pure (DSA.Params undefined undefined undefined)

-- genECDSA :: Parser (Key.Conf Key.ECDSA)
-- genECDSA = Key.ECDSA' <$> undefined

genEd448 :: Parser (Key.Conf Key.Ed448)
genEd448 = pure Key.Ed448'

genEd25519 :: Parser (Key.Conf Key.Ed25519)
genEd25519 = pure Key.Ed25519'

keyGenerateP :: Parser KeyGenerate
keyGenerateP
  =   flag' () (long "rsa") *> (KeyGenerateRSA <$> genRSA)
  <|> flag' () (long "ed448") *> (KeyGenerateEd448 <$> genEd448)
  <|> flag' () (long "ed25519") *> (KeyGenerateEd25519 <$> genEd25519)
