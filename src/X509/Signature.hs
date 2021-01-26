module X509.Signature where

import qualified Data.ByteString as BS
import Data.ByteArray (convert)

import qualified Data.ASN1.Types as ASN1
import qualified Data.ASN1.BinaryEncoding as ASN1
import qualified Data.ASN1.Encoding as ASN1

import Data.X509 (HashALG(..), SignatureALG(..), PubKeyALG(..))
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
data Algorithm alg where
  RSA
    :: (HashAlgorithm hash, RSA.HashAlgorithmASN1 hash)
    => Hash hash
    -> Algorithm Key.RSA

  RSAPSS
    :: HashAlgorithm hash
    => PSS.PSSParams hash BS.ByteString BS.ByteString -> Hash hash
    -> Algorithm Key.RSA

  DSA :: HashAlgorithm hash => Hash hash -> Algorithm Key.DSA
  EC :: HashAlgorithm hash => Hash hash -> Algorithm Key.ECDSA
  Ed25519 :: Algorithm Key.Ed25519
  Ed448 :: Algorithm Key.Ed448

signatureALG :: Algorithm alg -> SignatureALG
signatureALG sa = case sa of
  RSA hash -> SignatureALG (hashALG hash) PubKeyALG_RSA
  RSAPSS _ hash -> SignatureALG (hashALG hash) PubKeyALG_RSAPSS
  DSA hash -> SignatureALG (hashALG hash) PubKeyALG_DSA
  EC hash -> SignatureALG (hashALG hash) PubKeyALG_EC
  Ed25519 -> SignatureALG_IntrinsicHash PubKeyALG_Ed25519
  Ed448 -> SignatureALG_IntrinsicHash PubKeyALG_Ed448

-- | Sign @message@ with a signature algorithm and a fitting private key
sign :: Algorithm alg -> Key.Private alg -> BS.ByteString -> IO (Either RSA.Error BS.ByteString)
sign sa key message = case sa of
  RSA hash -> RSA.signSafer (Just $ hashAlgorithm hash) key message
  RSAPSS params _ -> PSS.signSafer params key message
  DSA hash -> do
    sig <- DSA.sign key (hashAlgorithm hash) message
    return $ Right $ ASN1.encodeASN1' ASN1.DER
      [ ASN1.Start ASN1.Sequence
      , ASN1.IntVal (DSA.sign_r sig)
      , ASN1.IntVal (DSA.sign_s sig)
      , ASN1.End ASN1.Sequence
      ]
  EC hash -> do
    sig <- ECDSA.sign key (hashAlgorithm hash) message
    return $ Right $ ASN1.encodeASN1' ASN1.DER
      [ ASN1.Start ASN1.Sequence
      , ASN1.IntVal (ECDSA.sign_r sig)
      , ASN1.IntVal (ECDSA.sign_s sig)
      , ASN1.End ASN1.Sequence
      ]
  Ed25519 -> return $ Right $ convert $ Ed25519.sign key (Ed25519.toPublic key) message
  Ed448 -> return $ Right $ convert $ Ed448.sign key (Ed448.toPublic key) message
