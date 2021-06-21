module X509.Certificate where

import Prelude
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

mkCertificate :: TBS -> Key.Private alg -> Signature.Algorithm alg -> PubKey -> IO SignedCertificate
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
  in objectToSignedExactF signatureFunction tbs'

mkCA
  :: (Key.ToPubKey (Key.Public alg))
  => TBS
  -> Key.Private alg -> Signature.Algorithm alg -- authority
  -> Key.Public alg
  -> IO SignedCertificate
mkCA tbs priv sigAlg pub = mkCertificate tbs priv sigAlg (Key.toPubKey pub)

-- * Helpers

-- | Builds a DN with a single component.
mkCN :: ASN1CharacterString -> DistinguishedName
mkCN cn = DistinguishedName [(getObjectID DnCommonName, cn)]
