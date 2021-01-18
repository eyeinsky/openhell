module Key where

import qualified Crypto.PubKey.DSA        as DSA
import qualified Crypto.PubKey.ECC.ECDSA  as ECDSA
import qualified Crypto.PubKey.ECC.Types  as ECC
import qualified Crypto.PubKey.ECC.Generate as ECC
import qualified Crypto.PubKey.Ed25519    as Ed25519
import qualified Crypto.PubKey.Ed448      as Ed448
import qualified Crypto.PubKey.RSA        as RSA
import qualified Crypto.PubKey.RSA.PKCS15 as RSA
import qualified Crypto.PubKey.RSA.PSS    as PSS

import qualified Data.PEM as PEM
import qualified Crypto.Store.PKCS8 as PKCS8
import qualified Data.X509 as X509

-- * Key algorithm types

data RSA
data DSA
data ECDSA
data Ed25519
data Ed448

type family Private t :: *
type instance Private RSA = RSA.PrivateKey
type instance Private DSA = DSA.PrivateKey
type instance Private ECDSA = ECDSA.PrivateKey
type instance Private Ed25519 = Ed25519.SecretKey
type instance Private Ed448 = Ed448.SecretKey

type family Public t :: *
type instance Public RSA = RSA.PublicKey
type instance Public DSA = DSA.PublicKey
type instance Public ECDSA = ECDSA.PublicKey
type instance Public Ed25519 = Ed25519.PublicKey
type instance Public Ed448 = Ed448.PublicKey

type Pair alg = (Public alg, Private alg)

-- * Generate

class Generate alg where
  data Conf alg :: *
  generate :: Conf alg -> IO (Pair alg)

instance Generate RSA where
  data Conf RSA = RSA' Int Integer
  generate (RSA' bits e) = RSA.generate size e
    where size = bits `div` 8

instance Generate DSA where
  data Conf DSA = DSA' DSA.Params
  generate (DSA' params) = do
    x <- DSA.generatePrivate params
    let y = DSA.calculatePublic params x
    return (DSA.PublicKey params y, DSA.PrivateKey params x)

instance Generate ECDSA where
  data Conf ECDSA = ECDSA' ECC.CurveName
  generate (ECDSA' name) = do
    let curve = ECC.getCurveByName name
    ECC.generate curve

instance Generate Ed25519 where
  data Conf Ed25519 = Ed25519'
  generate Ed25519' = do
    secret <- Ed25519.generateSecretKey
    return (Ed25519.toPublic secret, secret)

instance Generate Ed448 where
  data Conf Ed448 = Ed448'
  generate Ed448' = do
    secret <- Ed448.generateSecretKey
    return (Ed448.toPublic secret, secret)

-- * Serialize

-- | Convert keys into PKCS#8 PEM.
toPKCS8 :: ToPrivKey key => key -> PEM.PEM
toPKCS8 = PKCS8.keyToPEM PKCS8.PKCS8Format . toPrivKey

-- | Helper class to convert to the Data.X509.PrivKey data type
class ToPrivKey key where toPrivKey :: key -> X509.PrivKey
instance ToPrivKey RSA.PrivateKey where toPrivKey = X509.PrivKeyRSA
instance ToPrivKey DSA.PrivateKey where toPrivKey = X509.PrivKeyDSA
-- instance ToPrivKey ECDSA.PrivateKey where toPrivKey = X509.PrivKeyEC
instance ToPrivKey Ed25519.SecretKey where toPrivKey = X509.PrivKeyEd25519
instance ToPrivKey Ed448.SecretKey where toPrivKey = X509.PrivKeyEd448
