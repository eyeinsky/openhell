module X509.Certificate where

import Data.List
import Data.Maybe
import Data.String
import qualified Data.ByteString as BS
import Control.Monad.Except

import Time.System as Time
import Time.Types as Time
import Data.X509 hiding (Certificate, Extension)
import qualified Data.X509.PKCS10 as PKCS10
import qualified Data.X509 as X509
import qualified Crypto.PubKey.RSA as RSA
import Data.ASN1.Types

import qualified X509.Signature as Signature
import X509.Extensions
import qualified Key


type TBS = X509.Certificate

mkCertificate
  :: TBS
  -> Key.Private alg -> Signature.Algorithm alg
  -> PubKey
  -> IO (Signature.Algorithm alg, SignedCertificate)       -- ^ The new certificate/key pair
mkCertificate tbs signingKey sigAlg tbsPub = let
    signAlgI = Signature.signatureALG sigAlg :: SignatureALG
    signatureFunction :: BS.ByteString -> IO (BS.ByteString, SignatureALG)
    signatureFunction objRaw = do
      sigBits <- either (error . show) return =<< Signature.sign sigAlg signingKey objRaw
      return (sigBits, signAlgI)

    tbs' = tbs
      { certSignatureAlg = signAlgI
      , certPubKey       = tbsPub
      }
  in do
    signedCert :: SignedCertificate <- objectToSignedExactF signatureFunction tbs'
    return (sigAlg, signedCert)

mkCA
  :: (Key.ToPubKey (Key.Public alg))
  => TBS
  -> Key.Private alg -> Signature.Algorithm alg -- authority
  -> Key.Public alg
  -> IO (Signature.Algorithm alg, SignedCertificate)
mkCA tbs priv sigAlg pub = mkCertificate tbs priv sigAlg (Key.toPubKey pub)

mkLeaf
  :: TBS
  -> Key.Private alg -> Signature.Algorithm alg -- authority
  -> PubKey
  -> IO (Signature.Algorithm alg, SignedCertificate)
mkLeaf tbs priv sigAlg pub = mkCertificate tbs priv sigAlg pub

-- * Helpers

-- | Builds a DN with a single component.
mkCN :: ASN1CharacterString -> DistinguishedName
mkCN cn = DistinguishedName [(getObjectID DnCommonName, cn)]
