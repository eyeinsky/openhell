{-# LANGUAGE OverloadedStrings #-}
module X509.Certificate where

import Prelude
import Data.Char
import Data.Maybe
import Data.String
import Data.Aeson
import Data.Aeson.Key qualified as A
import Data.Coerce
import Data.Function
import Control.Monad.Except
import Data.ByteString qualified as BS
import Data.ByteString.Char8 qualified as BS8
import Data.X509 hiding (Certificate, Extension)
import qualified Data.X509 as X509
import Data.ASN1.Types
import Data.ASN1.Types.String
import Data.Text qualified as TS
import Data.Text.Encoding qualified as TS
import Data.PEM qualified as PEM
import Time.Types as Hourglass
import Time.Compat as Hourglass
import Time.System as Hourglass
import Lens.Micro

import X509.Extensions
import qualified X509.Signature as Signature
import qualified Key


type TBS = X509.Certificate

mkCertificate :: TBS -> Key.Private alg -> Signature.Algorithm alg -> PubKey -> IO SignedCertificate
mkCertificate tbs signingKey sigAlg tbsPub = let
    signAlgI = Signature.signatureALG sigAlg :: SignatureALG
    signatureFunction :: BS.ByteString -> IO (BS.ByteString, SignatureALG)
    signatureFunction objRaw = do
      sigBits <- either (error . show) return =<< Signature.signWithAlgorithm sigAlg signingKey objRaw
      return (sigBits, signAlgI)
    tbs' = tbs
      { certSignatureAlg = signAlgI
      , certPubKey       = tbsPub
      }
  in objectToSignedExactF signatureFunction tbs'

newTBS :: TS.Text -> TS.Text -> (DateTime, DateTime) -> (TBS, Signature.Algorithm Key.RSA)
newTBS subjectCN issuerCN validityInterval = (tbs, alg)
  where
    alg = Signature.RSA Signature.hashSHA256 :: Signature.Algorithm Key.RSA
    tbs :: TBS
    tbs = X509.Certificate
      { certVersion = 2
      , certSerial = 0 -- TODO
      , certValidity = validityInterval
      , certSubjectDN = textCN subjectCN
      , certIssuerDN = textCN issuerCN
      , certExtensions = extensions
          $ digitalSignature <> keyEncipherment
          <> serverAuth <> clientAuth
          -- <> (subjectAltName $ rfc822 $ TS.unpack email)
      , certSignatureAlg = error "certSignatureAlg should be populated before any use"
      , certPubKey = error "certPubKey should be populated before any use"
      }

fromPem :: BS.ByteString -> Either String [X509.SignedCertificate]
fromPem arg = do
  pems <- prefixLeft "pemParseBS" $ PEM.pemParseBS arg
  prefixLeft "decodeCertificate" $ traverse decodePem pems
  where
    decodePem = X509.decodeSignedCertificate . PEM.pemContent
    prefixLeft msg e = either (\err -> throwError $ msg <> ": " <> err) pure e

mkCA
  :: (Key.ToPubKey (Key.Public alg))
  => TBS
  -> Key.Private alg -> Signature.Algorithm alg -- authority
  -> Key.Public alg
  -> IO SignedCertificate
mkCA tbs priv sigAlg pub = mkCertificate tbs priv sigAlg (Key.toPubKey pub)

-- * ToJSON

instance ToJSON X509.Certificate where
  toJSON c = object
    [ "serial" .= certSerial
    , "validFrom" .= dateTimeToISO8601 validFrom
    , "validTo" .= dateTimeToISO8601 validTo
    , "publicKey" .= show certPubKey
    , "signatureAlgorithm" .= show certSignatureAlg
    , "subject" .= dn certSubjectDN
    , "issuer" .= dn certIssuerDN
    , "extensions" .= exts (rawExtensionList certExtensions)
    , "version" .= certVersion
    ]
    where
      X509.Certificate
        { certSerial, certSignatureAlg, certPubKey
        , certIssuerDN, certSubjectDN
        , certExtensions
        , certVersion
        , certValidity = (validFrom, validTo)
        } = c

      dn :: DistinguishedName -> Value
      dn = object . map (\(oid, cs) -> A.fromText (oidLabel oid) .= csText cs) . getDistinguishedElements

      csText :: ASN1CharacterString -> TS.Text
      csText = TS.decodeUtf8 . getCharacterStringRawData

      exts :: [ExtensionRaw] -> Value
      exts es = object $ map f es

      f ExtensionRaw{extRawOID, extRawCritical, extRawContent} = fromString (show extRawOID) .= show xs
        where
          xs = filter (not . BS.null) $ BS8.splitWith (not . domainChar) extRawContent
          domainChar c = isAlpha c || isDigit c || c `elem` ['.', '-']
          -- TODO

        -- alg = signedAlg s
        -- signature_ = signedSignature s

-- | OID labels for subject and issuer
oidLabel :: [Integer] -> TS.Text
oidLabel = \case
  [2, 5, 4, 3] -> "common name"
  [2, 5, 4, 10] -> "organization"
  [2, 5, 4, 11] -> "organization unit"
  _ -> "unknown"
  -- TODO: get all OIDs

dateTimeToISO8601 :: Hourglass.DateTime -> TS.Text
dateTimeToISO8601 DateTime{ dtDate = Date y m d, dtTime = Hourglass.TimeOfDay h m_ s n } =
  dateStr <> "T" <> timeStr <> "Z" -- ISO8601: yyyy-mm-ddThh:mm:ss[.ss]Z
  where
    dateStr = TS.intercalate "-" $ map tshow [fromIntegral y, fromEnum m, d]
    timeStr = TS.intercalate ":" $ map tshow [fromEnum h, fromEnum m_, fromEnum s]
    tshow = TS.pack . show

rawExtensionList :: Extensions -> [ExtensionRaw]
rawExtensionList = \case
  Extensions mb -> fromMaybe [] mb

-- * Helpers

-- | Builds a DN with a single component.
mkCN :: ASN1CharacterString -> DistinguishedName
mkCN cn = DistinguishedName [(getObjectID DnCommonName, cn)]

textCN :: TS.Text -> DistinguishedName
textCN t = mkCN $ ASN1CharacterString UTF8 (TS.encodeUtf8 t)

year :: Lens' Hourglass.Date Int
year f date@(Date y m d) = (\y' -> Date y' m d) <$> f y

date :: Lens' Hourglass.DateTime Hourglass.Date
date f dt@(DateTime d t) = (\d -> DateTime d t) <$> f d

validityIntervalFromNow :: IO (DateTime, DateTime)
validityIntervalFromNow = do
  validFrom :: DateTime <- Hourglass.dateCurrent
  let validTo = validFrom & date . year %~ (+1)
  return (validFrom, validTo)
