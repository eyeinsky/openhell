module X509.SignatureAlgorithm where

import qualified Data.ByteString as BS

import Data.X509 (HashALG(..), SignatureALG(..), PubKeyALG(..), PubKey(..), PubKeyEC(..), SerializedPoint(..))

import Crypto.Number.Serialize (i2ospOf_)
import Crypto.Hash.Algorithms
import qualified Crypto.PubKey.DSA        as DSA
import qualified Crypto.PubKey.ECC.ECDSA  as ECDSA
import qualified Crypto.PubKey.ECC.Types  as ECC
import qualified Crypto.PubKey.ECC.Generate as ECC
import qualified Crypto.PubKey.Ed25519    as Ed25519
import qualified Crypto.PubKey.Ed448      as Ed448
import qualified Crypto.PubKey.RSA        as RSA
import qualified Crypto.PubKey.RSA.PKCS15 as RSA
import qualified Crypto.PubKey.RSA.PSS    as PSS

import qualified Key

-- * Match @hash@ algorithm type to @HashALG@ value

data Hash hash = Hash
  { hashALG :: HashALG      -- ADT from Data.X509.AlgorithmIdentifier
  , hashAlgorithm :: hash } -- Each its own type

hashMD2 :: Hash MD2
hashMD2 = Hash HashMD2 MD2

hashMD5 :: Hash MD5
hashMD5 = Hash HashMD5 MD5

hashSHA1 :: Hash SHA1
hashSHA1 = Hash HashSHA1 SHA1

hashSHA224 :: Hash SHA224
hashSHA224 = Hash HashSHA224 SHA224

hashSHA256 :: Hash SHA256
hashSHA256 = Hash HashSHA256 SHA256

hashSHA384 :: Hash SHA384
hashSHA384 = Hash HashSHA384 SHA384

hashSHA512 :: Hash SHA512
hashSHA512 = Hash HashSHA512 SHA512

-- * Signature algorithm

-- | Signature algorithm consists of a hash algorithm plus a public
-- key cryptosystem to sign the hash. (The cryptosystem doesn't
-- determine the signing algorithm as for RSA there are two.)
data SignatureAlgorithm alg where
  RSA
    :: (HashAlgorithm hash, RSA.HashAlgorithmASN1 hash)
    => Int -> Hash hash
    -> SignatureAlgorithm Key.RSA

  RSAPSS
    :: HashAlgorithm hash
    => Int -> PSS.PSSParams hash BS.ByteString BS.ByteString -> Hash hash
    -> SignatureAlgorithm Key.RSA

  DSA
    :: HashAlgorithm hash
    => DSA.Params -> Hash hash
    -> SignatureAlgorithm Key.DSA

  EC
    :: HashAlgorithm hash
    => ECC.CurveName -> Hash hash
    -> SignatureAlgorithm Key.ECDSA

  Ed25519 :: SignatureAlgorithm Key.Ed25519
  Ed448 :: SignatureAlgorithm Key.Ed448

signatureALG :: SignatureAlgorithm alg -> SignatureALG
signatureALG sa = case sa of
  RSA _ hash -> SignatureALG (hashALG hash) PubKeyALG_RSA
  RSAPSS _ _ hash -> SignatureALG (hashALG hash) PubKeyALG_RSAPSS
  DSA _ hash -> SignatureALG (hashALG hash) PubKeyALG_DSA
  EC _ hash -> SignatureALG (hashALG hash) PubKeyALG_EC
  Ed25519 -> SignatureALG_IntrinsicHash PubKeyALG_Ed25519
  Ed448 -> SignatureALG_IntrinsicHash PubKeyALG_Ed448

getPubKey :: SignatureAlgorithm alg -> Key.Public alg -> PubKey
getPubKey sa key = case sa of
  RSA _ _ -> PubKeyRSA key
  RSAPSS _ _ _ -> PubKeyRSA key
  DSA _ _ -> PubKeyDSA key
  EC name _ -> PubKeyEC (PubKeyEC_Named name pub)
    where
      ECC.Point x y = ECDSA.public_q key
      pub   = SerializedPoint bs
      bs    = BS.cons 4 (i2ospOf_ bytes x `BS.append` i2ospOf_ bytes y)
      bits  = ECC.curveSizeBits (ECC.getCurveByName name)
      bytes = (bits + 7) `div` 8
  Ed25519 -> PubKeyEd25519 key
  Ed448 -> PubKeyEd448 key