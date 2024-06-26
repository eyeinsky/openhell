{-# LANGUAGE AllowAmbiguousTypes #-}
module X509.Signature where

import Prelude
import Data.Maybe
import qualified Data.ByteString as BS
import Data.ByteArray (convert)
import Data.Text qualified as TS
import Data.Text.Encoding qualified as TS
import Data.Text.IO qualified as TS

import Data.ByteArray.Encoding (Base(Base64), convertToBase)

import Data.PEM qualified as PEM
import qualified Data.ASN1.Types as ASN1
import qualified Data.ASN1.BinaryEncoding as ASN1
import qualified Data.ASN1.Encoding as ASN1
import Data.X509 (HashALG(..), SignatureALG(..), PubKeyALG(..))
import Data.X509 qualified as Cryptostore
import Crypto.Store.PKCS8 qualified as PKCS8
import Crypto.Hash.Algorithms

import qualified Crypto.PubKey.DSA        as DSA
import qualified Crypto.PubKey.ECC.ECDSA  as ECDSA
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
signWithAlgorithm :: Algorithm alg -> Key.Private alg -> BS.ByteString -> IO (Either RSA.Error BS.ByteString)
signWithAlgorithm sa key message = case sa of
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

class DefaultAlgorithm alg where defaultAlgorithm :: Algorithm alg
instance DefaultAlgorithm Key.RSA where defaultAlgorithm = RSA hashSHA1

-- | Sign @message@ bytes with @key@, using some default algorithm for
-- any crypto system @alg@. To choose a different algorithm, use
-- @signWithAlgorithm@.
sign :: forall alg . DefaultAlgorithm alg => Key.Private alg -> BS.ByteString -> IO BS.ByteString
sign key message = either (error . show) id <$> signWithAlgorithm (defaultAlgorithm @alg) key message

-- *

-- | Read a single unencrypted private key as PEM from @path@
readPrivateKey :: FilePath -> IO (Key.Private Key.RSA)
readPrivateKey path = do
  pemText <- TS.readFile path
  case PEM.pemParseBS (TS.encodeUtf8 pemText) of
    Left err -> fail $ "PEM parsing error: " <> err
    Right (pem : _ ) -> do
      case catMaybes $ PKCS8.pemToKey [] pem of
        [a] -> case a of
          PKCS8.Protected _ -> fail "protected"
          PKCS8.Unprotected (key_ :: Cryptostore.PrivKey) -> do
            let Cryptostore.PrivKeyRSA (key :: RSA.PrivateKey) = key_
            return key
        [] -> fail $ "No PEMs found in file " <> path
        _ -> fail $ "More than one PEM found in file " <> path


encodeBase64 :: BS.ByteString -> BS.ByteString
encodeBase64 bs = convertToBase Base64 bs
