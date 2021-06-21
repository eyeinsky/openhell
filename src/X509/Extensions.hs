{-# OPTIONS_GHC -Wno-orphans #-}
module X509.Extensions
  -- | Render
  ( extensions

  -- | Change whether extension is critical or not (default is critical)
  , critical, nonCritical

  -- | Key usage
  , digitalSignature, nonRepudiation, keyEncipherment
  , dataEncipherment, keyAgreement, keyCertSign
  , cRLSign, encipherOnly, decipherOnly

  -- | Extended key usage
  , serverAuth, clientAuth, codeSigning, emailProtection
  , timeStamping, oCSPSigning, extendedKeyUsageUnknown

  -- | Key IDs
  , subjectKeyId, authorityKeyId

  -- | Alternative names
  , subjectAltName
  , rfc822, dns, uri, ip, xmpp, dnssrv
  )
  where

import Prelude
import Data.Maybe
import qualified Data.ByteString as BS

import Data.X509 hiding (Extension, Extensions)
import qualified Data.X509 as X509
import qualified Data.ASN1.OID as ASN1

type Extension = (Bool, Extension')

critical :: [Extension] -> [Extension]
critical extensions = map f extensions
  where f (_, extension) = (True, extension)

nonCritical :: [Extension] -> [Extension]
nonCritical extensions = map f extensions
  where f (_, extension) = (False, extension)

-- | This is the fan-in ADT for the various extensions
data Extension'
  = BasicConstraint ExtBasicConstraints
  | KeyUsage ExtKeyUsage
  | ExtendedKeyUsage ExtExtendedKeyUsage
  | SubjectKeyId ExtSubjectKeyId
  | SubjectAltName ExtSubjectAltName
  | AuthorityKeyId ExtAuthorityKeyId
  -- | CrlDistributionPoints ExtCrlDistributionPoints
  -- | NetscapeComment ExtNetscapeComment
  deriving (Eq, Show)

-- | Render extensions to the type the x509 package expecs
extensions :: [Extension] -> X509.Extensions
extensions es = let
  (a, b, c, d, e, f) = collect es
  rawAndSetExtensions = catMaybes [fmap encode a, fmap encode b, fmap encode c, fmap encode e, fmap encode f]
  in case rawAndSetExtensions of
    _ : _ -> X509.Extensions $ Just rawAndSetExtensions
    _ -> X509.Extensions Nothing

  where
    encode :: forall e. X509.Extension e => (Bool, e) -> ExtensionRaw
    encode (critical, extension) = extensionEncode critical extension

-- | Collect repeated extensions to groups by extension type
collect :: [Extension] -> GroupedExtensions
collect exts = foldl go emptyCollector exts
  where
    addExt :: Semigroup a => Maybe (Bool, a) -> (Bool, a) -> Maybe (Bool, a)
    addExt maybeSum ext'@ (crit, ext) = maybe (Just ext') (\(_, z) -> Just (crit, z <> ext)) maybeSum

    go coll@ (a, b, c, d, e, f) ext'@ (critical, extension) = case extension of
      BasicConstraint bc -> coll
      KeyUsage ku -> (a, addExt b (critical, ku), c, d, e, f)
      ExtendedKeyUsage eku -> (a, b, addExt c (critical, eku), d, e, f)
      SubjectKeyId ski -> (a, b, c, addExt d (critical, ski), e, f)
      SubjectAltName san -> (a, b, c, d, addExt e (critical, san), f)
      AuthorityKeyId aki -> (a, b, c, d, e, addExt f (critical, aki))

    emptyCollector :: GroupedExtensions
    emptyCollector = (Nothing, Nothing, Nothing, Nothing, Nothing, Nothing)

type F a = Maybe (Bool, a)
type GroupedExtensions = (F ExtBasicConstraints, F ExtKeyUsage, F ExtExtendedKeyUsage, F ExtSubjectKeyId, F ExtSubjectAltName, F ExtAuthorityKeyId)

-- * Key usage

mkKeyUsage :: ExtKeyUsageFlag -> [Extension]
mkKeyUsage flag = [(True, KeyUsage $ ExtKeyUsage [flag])]

digitalSignature, nonRepudiation, keyEncipherment, dataEncipherment
  , keyAgreement, keyCertSign, cRLSign, encipherOnly, decipherOnly :: [Extension]
digitalSignature = mkKeyUsage KeyUsage_digitalSignature
nonRepudiation = mkKeyUsage KeyUsage_nonRepudiation
keyEncipherment = mkKeyUsage KeyUsage_keyEncipherment
dataEncipherment = mkKeyUsage KeyUsage_dataEncipherment
keyAgreement = mkKeyUsage KeyUsage_keyAgreement
keyCertSign = mkKeyUsage KeyUsage_keyCertSign
cRLSign = mkKeyUsage KeyUsage_cRLSign
encipherOnly = mkKeyUsage KeyUsage_encipherOnly
decipherOnly = mkKeyUsage KeyUsage_decipherOnly

-- * Extended key usage

mkExtendedKeyUsage :: ExtKeyUsagePurpose -> [Extension]
mkExtendedKeyUsage flag = [(True, ExtendedKeyUsage $ ExtExtendedKeyUsage [flag])]

serverAuth, clientAuth, codeSigning, emailProtection, timeStamping, oCSPSigning :: [Extension]
serverAuth = mkExtendedKeyUsage KeyUsagePurpose_ServerAuth
clientAuth = mkExtendedKeyUsage KeyUsagePurpose_ClientAuth
codeSigning = mkExtendedKeyUsage KeyUsagePurpose_CodeSigning
emailProtection = mkExtendedKeyUsage KeyUsagePurpose_EmailProtection
timeStamping = mkExtendedKeyUsage KeyUsagePurpose_TimeStamping
oCSPSigning = mkExtendedKeyUsage KeyUsagePurpose_OCSPSigning

extendedKeyUsageUnknown :: ASN1.OID -> [Extension]
extendedKeyUsageUnknown oid = mkExtendedKeyUsage (KeyUsagePurpose_Unknown oid)

-- * Subject key ID

subjectKeyId :: BS.ByteString -> [Extension]
subjectKeyId bs = [(True, SubjectKeyId $ ExtSubjectKeyId bs)]

authorityKeyId :: BS.ByteString -> [Extension]
authorityKeyId bs = [(True, AuthorityKeyId $ ExtAuthorityKeyId bs)]

-- * Subject Alternative Name

subjectAltName :: AltName -> [Extension]
subjectAltName altName = [(True, SubjectAltName $ ExtSubjectAltName [altName])]

-- * Alternative names

rfc822 :: String -> AltName
rfc822 str = AltNameRFC822 str

dns :: String -> AltName
dns str = AltNameDNS str

uri :: String -> AltName
uri str = AltNameURI str

ip :: BS.ByteString -> AltName
ip bs = AltNameIP bs

xmpp :: String -> AltName
xmpp str = AltNameXMPP str

dnssrv :: String -> AltName
dnssrv str = AltNameDNSSRV str

-- * Semigroup and Monoid instances

instance Semigroup ExtBasicConstraints where
  _ <> b = b -- fixme: is this a good way to merge?
instance Monoid ExtBasicConstraints where
  mempty = ExtBasicConstraints True Nothing -- fixme: is this a good mempty?

instance Semigroup ExtKeyUsage where
  ExtKeyUsage a <> ExtKeyUsage b = ExtKeyUsage (a <> b)
instance Monoid ExtKeyUsage where
  mempty = ExtKeyUsage []

instance Semigroup ExtExtendedKeyUsage where
  ExtExtendedKeyUsage a <> ExtExtendedKeyUsage b = ExtExtendedKeyUsage (a <> b)
instance Monoid ExtExtendedKeyUsage where
  mempty = ExtExtendedKeyUsage []

instance Semigroup ExtSubjectAltName where
  ExtSubjectAltName a <> ExtSubjectAltName b = ExtSubjectAltName (a <> b)
instance Monoid ExtSubjectAltName where
  mempty = ExtSubjectAltName []

instance Semigroup ExtSubjectKeyId where
  _ <> b = b
instance Semigroup ExtAuthorityKeyId where
  _ <> b = b
