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

signCsr
  :: (Monad m, MonadIO m)
  => PKCS10.SignedCertificationRequest
  -> RSA.PrivateKey -> ASN1CharacterString
  -> ExceptT String m
  (Signature.Algorithm Key.RSA, X509.SignedCertificate)
signCsr csr caPriv issuerName = do
  commonName :: String <- maybe (throwError "") return $ do
    let PKCS10.X520Attributes xs = PKCS10.subject $ PKCS10.certificationRequestInfo $ PKCS10.certificationRequest csr :: PKCS10.X520Attributes
    (_, cn) <- find ((PKCS10.X520CommonName ==) . fst) xs
    asn1CharacterToString cn

  now <- liftIO $ Time.dateCurrent

  let
    date = Time.dtDate now
    date' = date { Time.dateYear = (Time.dateYear date + 1) }
    until = now { Time.dtDate = date' }
    validity = (now, until) :: (DateTime, DateTime)

    pubKey :: X509.PubKey
    pubKey = PKCS10.subjectPublicKeyInfo $ PKCS10.certificationRequestInfo $ PKCS10.certificationRequest csr

    sigAlg' = Signature.RSA Signature.hashSHA256 :: Signature.Algorithm Key.RSA

    tbs :: TBS
    tbs = X509.Certificate
      { certVersion = 2
      , certSerial = 100
      , certValidity = validity

      , certSubjectDN = mkCN $ fromString commonName
      , certIssuerDN = mkCN issuerName

      , certExtensions = extensions
          $ digitalSignature <> keyEncipherment
          <> serverAuth <> clientAuth
      }

  liftIO $ mkLeaf tbs caPriv sigAlg' pubKey


type TBS = X509.Certificate

mkCertificate
  :: TBS
  -> Key.Private alg -> Signature.Algorithm alg
  -> PubKey
  -> IO (Signature.Algorithm alg, SignedCertificate)       -- ^ The new certificate/key pair
mkCertificate tbs signingKey algI tbsPub = let
    signAlgI = Signature.signatureALG algI :: SignatureALG
    signatureFunction :: BS.ByteString -> IO (BS.ByteString, SignatureALG)
    signatureFunction objRaw = do
      sigBits <- either (error . show) return =<< Signature.sign algI signingKey objRaw
      return (sigBits, signAlgI)

    tbs' = tbs
      { certSignatureAlg = signAlgI
      , certPubKey       = tbsPub
      }
  in do
    signedCert :: SignedCertificate <- objectToSignedExactF signatureFunction tbs'
    return (algI, signedCert)

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
