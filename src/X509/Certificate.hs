module X509.Certificate where

import Data.ASN1.Types
import Data.List
import Control.Monad.IO.Class
import Control.Monad.Except

import Time.System as Time
import Time.Types as Time

import Data.X509 hiding (Certificate) -- fixme
import qualified Data.X509.PKCS10 as PKCS10
import qualified Data.X509 as X509

-- hs-certificate tests Certificate.hs
import qualified Crypto.PubKey.DSA        as DSA
import qualified Crypto.PubKey.ECC.ECDSA  as ECDSA
import qualified Crypto.PubKey.Ed25519    as Ed25519
import qualified Crypto.PubKey.Ed448      as Ed448
import qualified Crypto.PubKey.RSA        as RSA
import qualified Crypto.PubKey.RSA.PKCS15 as RSA
import qualified Crypto.PubKey.RSA.PSS    as PSS

import qualified Data.ByteString as B
import Data.Maybe
import Data.String
import Data.ASN1.Encoding
import Data.ByteArray (convert)
import Data.ASN1.BinaryEncoding (DER(..))

import qualified X509.SignatureAlgorithm as SA
import X509.SignatureAlgorithm (SignatureAlgorithm, hashAlgorithm)

import qualified Key

signCsr
  :: (Monad m, MonadIO m)
  => PKCS10.SignedCertificationRequest
  -> RSA.PrivateKey -> ASN1CharacterString
  -> ExceptT String m
  (SignatureAlgorithm Key.RSA, X509.SignedCertificate)
signCsr csr caPriv issuerName = do
  commonName :: String <- maybe (throwError "") return $ do
    let PKCS10.X520Attributes xs = PKCS10.subject $ PKCS10.certificationRequestInfo $ PKCS10.certificationRequest csr :: PKCS10.X520Attributes
    (_, cn) <- find ((PKCS10.X520CommonName ==) . fst) xs
    asn1CharacterToString cn

  now <- liftIO $ Time.dateCurrent

  let
    issuerDN = mkCN issuerName
    date = Time.dtDate now
    date' = date { Time.dateYear = (Time.dateYear date + 1) }
    until = now { Time.dtDate = date' }
    validity = (now, until) :: (DateTime, DateTime)

    pubKey = PKCS10.subjectPublicKeyInfo $ PKCS10.certificationRequestInfo $ PKCS10.certificationRequest csr

    -- extensions :: Extensions
    -- extensions = Extensions $ Just $
    --   -- extensionEncode True $ ExtBasicConstraints True (Just 0)
    --   [ ExtensionRaw {extRawOID = [2,5,29,19], extRawCritical = True, extRawContent = "0\NUL" }
    --   , extensionEncode True $ ExtKeyUsage [KeyUsage_digitalSignature, KeyUsage_nonRepudiation, KeyUsage_keyEncipherment, KeyUsage_dataEncipherment]
    --   -- , ExtensionRaw {extRawOID = [2,5,29,15], extRawCritical = True, extRawContent = "\ETX\STX\EOT\240"}
    --   , extensionEncode True $ ExtExtendedKeyUsage [KeyUsagePurpose_ClientAuth]
    --   ]

    sigAlg' = SA.RSA 0 SA.hashSHA256 :: SA.SignatureAlgorithm Key.RSA

  liftIO $ mkLeaf commonName validity (caPriv, sigAlg', issuerDN) pubKey

-- | Sign @message@ with a signature algorithm and a fitting private key
sign :: SignatureAlgorithm alg -> Key.Private alg -> B.ByteString -> IO (Either RSA.Error B.ByteString)
sign sa key message = case sa of
  SA.RSA _ hash -> RSA.signSafer (Just $ hashAlgorithm hash) key message
  SA.RSAPSS _ params _ -> PSS.signSafer params key message
  SA.DSA _ hash -> do
    sig <- DSA.sign key (hashAlgorithm hash) message
    return $ Right $ encodeASN1' DER
      [ Start Sequence
      , IntVal (DSA.sign_r sig)
      , IntVal (DSA.sign_s sig)
      , End Sequence
      ]
  SA.EC _ hash -> do
    sig <- ECDSA.sign key (hashAlgorithm hash) message
    return $ Right $ encodeASN1' DER
      [ Start Sequence
      , IntVal (ECDSA.sign_r sig)
      , IntVal (ECDSA.sign_s sig)
      , End Sequence
      ]
  SA.Ed25519 -> return $ Right $ convert $ Ed25519.sign key (Ed25519.toPublic key) message
  SA.Ed448 -> return $ Right $ convert $ Ed448.sign key (Ed448.toPublic key) message

-- * New system

type Authority alg = (Key.Private alg, SignatureAlgorithm alg, DistinguishedName)

-- | Builds a certificate using the supplied keys and signs it with an
-- authority (itself or another certificate).
mkCertificate
  :: forall alg.
     Int                        -- ^ Certificate version
  -> Integer                    -- ^ Serial number
  -> DistinguishedName          -- ^ Subject DN
  -> (DateTime, DateTime)       -- ^ Certificate validity period
  -> [ExtensionRaw]             -- ^ Extensions to include
  -> Authority alg           -- ^ Authority signing the new certificate
  -> PubKey                     -- ^ Keys for the new certificate
  -> IO (SignatureAlgorithm alg, SignedCertificate)       -- ^ The new certificate/key pair
mkCertificate version serial dn validity exts (signingKey, algI, issuerDN) tbsPub = let

    signAlgI = SA.signatureALG algI :: SignatureALG
    extensions = Extensions (if null exts then Nothing else Just exts) :: Extensions

    signatureFunction :: B.ByteString -> IO (B.ByteString, SignatureALG)
    signatureFunction objRaw = do
      sigBits <- either (error . show) return =<< sign algI signingKey objRaw
      return (sigBits, signAlgI)

    tbs = X509.Certificate
      { certVersion      = version
      , certSerial       = serial
      , certSignatureAlg = signAlgI
      , certIssuerDN     = issuerDN
      , certValidity     = validity
      , certSubjectDN    = dn
      , certPubKey       = tbsPub
      , certExtensions   = extensions
      }

  in do
    signedCert :: SignedCertificate <- objectToSignedExactF signatureFunction tbs
    return (algI, signedCert)

mkCA
  :: Integer                    -- ^ Serial number
  -> String                     -- ^ Common name
  -> (DateTime, DateTime)       -- ^ Validity period
  -> Maybe ExtBasicConstraints  -- ^ Basic constraints
  -> Maybe ExtKeyUsage          -- ^ Key usage
  -> Authority alg           -- ^ Authority. CA is self-signed, so authority cryptosystem matches to-be-signed's
  -> Key.Public alg                       -- ^ Public key of the certificate
  -> IO (SignatureAlgorithm alg, SignedCertificate)
mkCA serial cn validity bc ku auth@ (_, sig, _) pub = let
    exts = catMaybes [ mkExtension True <$> bc, mkExtension False <$> ku ]
    pub' = SA.getPubKey sig pub
  in mkCertificate 2 serial (mkCN $ fromString cn) validity exts auth pub'

mkLeaf
  :: String               -- ^ Common name
  -> (DateTime, DateTime) -- ^ Certificate validity period
  -> Authority alg     -- ^ Authority signing the new certificate
  -> PubKey
  -> IO (SignatureAlgorithm alg, SignedCertificate)       -- ^ The new leaf certificate/key pair
mkLeaf cn validity auth pub = mkCertificate 2 100 (mkCN $ fromString cn) validity leafStdExts auth pub
  where
    -- | Default extensions in leaf certificates.
    leafStdExts :: [ExtensionRaw]
    leafStdExts = [ku, eku]
      where
        ku  = mkExtension False $ ExtKeyUsage
                   [ KeyUsage_digitalSignature , KeyUsage_keyEncipherment ]
        eku = mkExtension False $ ExtExtendedKeyUsage
                   [ KeyUsagePurpose_ServerAuth , KeyUsagePurpose_ClientAuth ]

-- * Helpers

-- | Builds a DN with a single component.
mkCN :: ASN1CharacterString -> DistinguishedName
mkCN cn = DistinguishedName [(getObjectID DnCommonName, cn)]

-- | Used to build a certificate extension.
mkExtension :: Extension a => Bool -> a -> ExtensionRaw
mkExtension crit ext = ExtensionRaw (extOID ext) crit (extEncodeBs ext)
