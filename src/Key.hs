{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE AllowAmbiguousTypes #-}
module Key where

import Prelude
import Data.Kind (Type)
import Data.List qualified as P
import Data.Maybe qualified as P
import Data.ByteString qualified as BS
import Data.Text qualified as TS
import Data.Text.IO qualified as TS
import Data.Text.Encoding qualified as TS
import Data.ByteArray.Encoding qualified as E

import Data.X509 (PubKey(..), PubKeyEC(..), SerializedPoint(..))
import Crypto.Number.Serialize (i2ospOf_)

import Crypto.PubKey.DSA qualified as DSA
import Crypto.PubKey.ECC.ECDSA qualified as ECDSA
import Crypto.PubKey.ECC.Types qualified as ECC
import Crypto.PubKey.ECC.Generate qualified as ECC
import Crypto.PubKey.Curve25519 qualified as X25519
import Crypto.PubKey.Curve448 qualified as X448
import Crypto.PubKey.Ed25519 qualified as Ed25519
import Crypto.PubKey.Ed448 qualified as Ed448
import Crypto.PubKey.RSA qualified as RSA
import Crypto.PubKey.RSA.PSS qualified as RSA

import Data.PEM qualified as PEM
import Crypto.Store.PKCS8 qualified as PKCS8
import Data.X509 qualified as X509

-- * Key algorithm types

data RSA
data DSA
data ECDSA
data EC
data X25519
data X448
data Ed25519
data Ed448

type family Private t :: Type
type instance Private RSA = RSA.PrivateKey
type instance Private DSA = DSA.PrivateKey
type instance Private ECDSA = ECDSA.PrivateKey
type instance Private EC = X509.PrivKeyEC
type instance Private Ed25519 = Ed25519.SecretKey
type instance Private Ed448 = Ed448.SecretKey
type instance Private X25519 = X25519.SecretKey
type instance Private X448 = X448.SecretKey

type family Public t :: Type
type instance Public RSA = RSA.PublicKey
type instance Public DSA = DSA.PublicKey
type instance Public ECDSA = ECDSA.PublicKey
type instance Public EC = X509.PubKeyEC
type instance Public Ed25519 = Ed25519.PublicKey
type instance Public Ed448 = Ed448.PublicKey
type instance Public X25519 = X25519.PublicKey
type instance Public X448 = X448.PublicKey

type Pair alg = (Public alg, Private alg)

-- * Generate

class Generate alg where
  data Conf alg :: Type
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

-- * Private to public key

-- | Extract public key from private
class PrivatePub alg where privatePub :: Private alg -> Public alg

instance PrivatePub RSA where privatePub = RSA.private_pub

instance PrivatePub DSA where
  privatePub (DSA.PrivateKey params privateNumber) =
    DSA.PublicKey params (DSA.calculatePublic params privateNumber)

instance PrivatePub ECDSA where
  privatePub (ECDSA.PrivateKey curve d) = ECDSA.PublicKey curve undefined -- TODO

instance PrivatePub EC where
  privatePub = \case
    X509.PrivKeyEC_Prime{} -> undefined -- TODO
    X509.PrivKeyEC_Named{} -> undefined -- TODO

instance PrivatePub X448 where privatePub = X448.toPublic

instance PrivatePub X25519 where privatePub = X25519.toPublic

instance PrivatePub Ed448 where privatePub = Ed448.toPublic

instance PrivatePub Ed25519 where privatePub = Ed25519.toPublic

getPubKey :: X509.PrivKey -> PubKey
getPubKey = \case
  X509.PrivKeyRSA k -> toPubKey $ privatePub @RSA k
  X509.PrivKeyDSA k -> toPubKey $ privatePub @DSA k
  X509.PrivKeyEC (k :: X509.PrivKeyEC) -> toPubKey $ privatePub @EC k
  X509.PrivKeyEd25519 k -> toPubKey $ privatePub @Ed25519 k
  X509.PrivKeyEd448 k -> toPubKey $ privatePub @Ed448 k
  X509.PrivKeyX25519 k -> toPubKey $ privatePub @X25519 k
  X509.PrivKeyX448 k -> toPubKey $ privatePub @X448 k

-- * Convert typed keys to ADTs from x509:Data.X509

-- | Serialize any private key to PKCS#8 PEM.
toPKCS8 :: ToPrivKey key => key -> PEM.PEM
toPKCS8 = PKCS8.keyToPEM PKCS8.PKCS8Format . toPrivKey

-- | Helper class to convert from separate types to the single
-- Data.X509.PrivKey ADT.
class ToPrivKey key where toPrivKey :: key -> X509.PrivKey
instance ToPrivKey RSA.PrivateKey where toPrivKey = X509.PrivKeyRSA
instance ToPrivKey DSA.PrivateKey where toPrivKey = X509.PrivKeyDSA
instance ToPrivKey Ed25519.SecretKey where toPrivKey = X509.PrivKeyEd25519
instance ToPrivKey Ed448.SecretKey where toPrivKey = X509.PrivKeyEd448
instance ToPrivKey X25519.SecretKey where toPrivKey = X509.PrivKeyX25519
instance ToPrivKey X448.SecretKey where toPrivKey = X509.PrivKeyX448

-- | Helper class to convert from separate types to the single
-- Data.X509.PubKey ADT.
class ToPubKey key where toPubKey :: key -> X509.PubKey
instance ToPubKey RSA.PublicKey where toPubKey = X509.PubKeyRSA
instance ToPubKey DSA.PublicKey where toPubKey = X509.PubKeyDSA

instance ToPubKey ECDSA.PublicKey where
  toPubKey key =
    let
      curveToCurveName :: ECC.Curve -> Maybe ECC.CurveName
      curveToCurveName curve = snd <$> maybeResult
        where
          allNames = [minBound .. maxBound] :: [ECC.CurveName]
          allCurvesWithName :: [(ECC.Curve, ECC.CurveName)]
          allCurvesWithName = map (\name -> (ECC.getCurveByName name, name)) allNames
          maybeResult :: Maybe (ECC.Curve, ECC.CurveName)
          maybeResult = P.find ((== curve). fst) allCurvesWithName

      curveFromKey = ECDSA.public_curve key :: ECC.Curve
      (x, y) = case ECDSA.public_q key of
        ECC.Point x' y' -> (x', y')
        _ -> error "TODO: unmatched pattern"
      pub   = SerializedPoint bs
      bs    = BS.cons 4 (i2ospOf_ bytes x `BS.append` i2ospOf_ bytes y)
      bits  = ECC.curveSizeBits curveFromKey
      bytes = (bits + 7) `div` 8

    in case curveToCurveName curveFromKey of
      Just name -> PubKeyEC (PubKeyEC_Named name pub)
      _ -> error "X509.SignatureAlgorithm.getPubKey: can't find ECC.CurveName for ECC.Curve"

instance ToPubKey X509.PubKeyEC where toPubKey = X509.PubKeyEC
instance ToPubKey Ed25519.PublicKey where toPubKey = X509.PubKeyEd25519
instance ToPubKey Ed448.PublicKey where toPubKey = X509.PubKeyEd448
instance ToPubKey X25519.PublicKey where toPubKey = X509.PubKeyX25519
instance ToPubKey X448.PublicKey where toPubKey = X509.PubKeyX448


-- * Parse

allPemHeaders :: [String]
allPemHeaders =
  [ "PRIVATE KEY"
  , "RSA PRIVATE KEY"
  , "DSA PRIVATE KEY"
  , "EC PRIVATE KEY"
  , "X25519 PRIVATE KEY"
  , "X448 PRIVATE KEY"
  , "ED25519 PRIVATE KEY"
  , "ED448 PRIVATE KEY"
  , "ENCRYPTED PRIVATE KEY"
  ]

-- | Parse private key without PEM headers
parseHeaderless :: TS.Text -> Either String [PKCS8.OptProtected X509.PrivKey]
parseHeaderless ts = do
  bs :: BS.ByteString <- fromBase64 ts
  let
    possiblePems :: [PEM.PEM]
    possiblePems = (\header -> PEM.PEM header [] bs) <$> allPemHeaders

    keys :: [PKCS8.OptProtected X509.PrivKey]
    keys = P.mapMaybe (either (const Nothing) Just . PKCS8.pemToKey) possiblePems

    cmp (PKCS8.Unprotected a) (PKCS8.Unprotected b) = a == b
    cmp _ _ = False

  return $ P.nubBy cmp keys

-- https://hackage.haskell.org/package/x509-store-1.6.7/docs/Data-X509-Memory.html
-- https://hackage.haskell.org/package/cryptostore-0.2.1.0/docs/src/Crypto.Store.PKCS8.html#OptProtected

-- * Helpers

-- | Convert base64 text to bytestring
fromBase64 :: TS.Text -> Either String BS.ByteString
fromBase64 ts = E.convertFromBase E.Base64 (TS.encodeUtf8 ts)
