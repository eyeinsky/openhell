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
import Data.Coerce
import qualified Data.ByteString as BS
import qualified Data.X509 as X509
import qualified Data.ASN1.OID as ASN1

-- * DSL

-- | Extension wrapper with criticality
data Extension a = Extension Bool a

-- | Render extensions to the type the x509 package expecs
extensions :: [Extension Untyped] -> X509.Extensions
extensions es = let
  (a, b, c, d, e, f) = collect es :: GroupedExtensions
  rawAndSetExtensions :: [X509.ExtensionRaw]
  rawAndSetExtensions = catMaybes [fmap encode a, fmap encode b, fmap encode c, fmap encode d, fmap encode e, fmap encode f]
  in case rawAndSetExtensions of
    _ : _ -> X509.Extensions $ Just rawAndSetExtensions
    _ -> X509.Extensions Nothing
  where
    encode
      :: forall from to. (FromNewtype from ~ to, X509.Extension to, Coercible from to)
      => Extension from -> X509.ExtensionRaw
    encode (Extension critical extension) = X509.extensionEncode critical (coerce extension :: to)

-- ** Key usage

digitalSignature, nonRepudiation, keyEncipherment, dataEncipherment
  , keyAgreement, keyCertSign, cRLSign, encipherOnly, decipherOnly :: [Extension Untyped]
digitalSignature = mkKeyUsage X509.KeyUsage_digitalSignature
nonRepudiation = mkKeyUsage X509.KeyUsage_nonRepudiation
keyEncipherment = mkKeyUsage X509.KeyUsage_keyEncipherment
dataEncipherment = mkKeyUsage X509.KeyUsage_dataEncipherment
keyAgreement = mkKeyUsage X509.KeyUsage_keyAgreement
keyCertSign = mkKeyUsage X509.KeyUsage_keyCertSign
cRLSign = mkKeyUsage X509.KeyUsage_cRLSign
encipherOnly = mkKeyUsage X509.KeyUsage_encipherOnly
decipherOnly = mkKeyUsage X509.KeyUsage_decipherOnly

-- ** Extended key usage

serverAuth, clientAuth, codeSigning, emailProtection, timeStamping, oCSPSigning :: [Extension Untyped]
serverAuth = mkExtendedKeyUsage X509.KeyUsagePurpose_ServerAuth
clientAuth = mkExtendedKeyUsage X509.KeyUsagePurpose_ClientAuth
codeSigning = mkExtendedKeyUsage X509.KeyUsagePurpose_CodeSigning
emailProtection = mkExtendedKeyUsage X509.KeyUsagePurpose_EmailProtection
timeStamping = mkExtendedKeyUsage X509.KeyUsagePurpose_TimeStamping
oCSPSigning = mkExtendedKeyUsage X509.KeyUsagePurpose_OCSPSigning

extendedKeyUsageUnknown :: ASN1.OID -> [Extension Untyped]
extendedKeyUsageUnknown oid = mkExtendedKeyUsage (X509.KeyUsagePurpose_Unknown oid)

-- ** Subject and authority key ID

subjectKeyId :: BS.ByteString -> [Extension Untyped]
subjectKeyId bs = mkCritical $ SubjectKeyId $ coerce $ X509.ExtSubjectKeyId bs

authorityKeyId :: BS.ByteString -> [Extension Untyped]
authorityKeyId bs = mkCritical $ AuthorityKeyId $ coerce $ X509.ExtAuthorityKeyId bs

-- ** Subject Alternative Name

subjectAltName :: X509.AltName -> [Extension Untyped]
subjectAltName altName = mkCritical $ SubjectAltName $ coerce $ X509.ExtSubjectAltName [altName]

rfc822 :: String -> X509.AltName
rfc822 str = X509.AltNameRFC822 str

dns :: String -> X509.AltName
dns str = X509.AltNameDNS str

uri :: String -> X509.AltName
uri str = X509.AltNameURI str

ip :: BS.ByteString -> X509.AltName
ip bs = X509.AltNameIP bs

xmpp :: String -> X509.AltName
xmpp str = X509.AltNameXMPP str

dnssrv :: String -> X509.AltName
dnssrv str = X509.AltNameDNSSRV str

critical :: [Extension Untyped] -> [Extension Untyped]
critical extensions = map f extensions
  where f (Extension _ extension) = Extension True extension

nonCritical :: [Extension Untyped] -> [Extension Untyped]
nonCritical extensions = map f extensions
  where f (Extension _ extension) = Extension False extension

-- * Internal

-- | This is the fan-in ADT for the various extensions
data Untyped
  = BasicConstraint ExtBasicConstraints
  | KeyUsage ExtKeyUsage
  | ExtendedKeyUsage ExtExtendedKeyUsage
  | SubjectKeyId ExtSubjectKeyId
  | SubjectAltName ExtSubjectAltName
  | AuthorityKeyId ExtAuthorityKeyId
  -- | CrlDistributionPoints X509.ExtCrlDistributionPoints
  -- | NetscapeComment X509.ExtNetscapeComment
  deriving (Eq, Show)

-- | Collect repeated extensions to groups by extension type
collect :: [Extension Untyped] -> GroupedExtensions
collect exts = foldl go emptyCollector exts
  where
    merge :: Semigroup a => Maybe (Extension a) -> Bool -> a -> Maybe (Extension a)
    merge acc criticality newExt = case acc of
      Nothing -> Just $ Extension criticality newExt
      Just (Extension _ oldExt) -> Just $ Extension criticality $ oldExt <> newExt

    go :: GroupedExtensions -> Extension Untyped -> GroupedExtensions
    go (a, b, c, d, e, f) (Extension critical untyped) = case untyped of
      BasicConstraint typed -> (a <> Just (Extension critical typed), b, c, d, e, f)
      KeyUsage ku -> (a, merge b critical ku, c, d, e, f)
      ExtendedKeyUsage eku -> (a, b, merge c critical eku, d, e, f)
      SubjectKeyId ski -> (a, b, c, merge d critical ski, e, f)
      SubjectAltName san -> (a, b, c, d, merge e critical san, f)
      AuthorityKeyId aki -> (a, b, c, d, e, merge f critical aki)

    emptyCollector :: GroupedExtensions
    emptyCollector = (Nothing, Nothing, Nothing, Nothing, Nothing, Nothing)

type F a = Maybe (Extension a)
type GroupedExtensions = (F ExtBasicConstraints, F ExtKeyUsage, F ExtExtendedKeyUsage, F ExtSubjectKeyId, F ExtSubjectAltName, F ExtAuthorityKeyId)

-- ** Helpers

mkCritical :: Untyped -> [Extension Untyped]
mkCritical extension' = [Extension True extension']

mkKeyUsage :: X509.ExtKeyUsageFlag -> [Extension Untyped]
mkKeyUsage flag = mkCritical $ KeyUsage $ coerce $ X509.ExtKeyUsage [flag]

mkExtendedKeyUsage :: X509.ExtKeyUsagePurpose -> [Extension Untyped]
mkExtendedKeyUsage flag = mkCritical $ ExtendedKeyUsage $ coerce $ X509.ExtExtendedKeyUsage [flag]

-- ** Newtypes

-- | These are solely to avoid orphan instances.

newtype ExtBasicConstraints = ExtBasicConstraints X509.ExtBasicConstraints
  deriving (Eq, Show)
newtype ExtKeyUsage = ExtKeyUsage X509.ExtKeyUsage
  deriving (Eq, Show)
newtype ExtExtendedKeyUsage = ExtExtendedKeyUsage X509.ExtExtendedKeyUsage
  deriving (Eq, Show)
newtype ExtSubjectAltName = ExtSubjectAltName X509.ExtSubjectAltName
  deriving (Eq, Show)
newtype ExtSubjectKeyId = ExtSubjectKeyId X509.ExtSubjectKeyId
  deriving (Eq, Show)
newtype ExtAuthorityKeyId = ExtAuthorityKeyId X509.ExtAuthorityKeyId
  deriving (Eq, Show)

type family FromNewtype a where
  FromNewtype ExtBasicConstraints = X509.ExtBasicConstraints
  FromNewtype ExtKeyUsage = X509.ExtKeyUsage
  FromNewtype ExtExtendedKeyUsage = X509.ExtExtendedKeyUsage
  FromNewtype ExtSubjectAltName = X509.ExtSubjectAltName
  FromNewtype ExtSubjectKeyId = X509.ExtSubjectKeyId
  FromNewtype ExtAuthorityKeyId = X509.ExtAuthorityKeyId

-- ** Semigroup and Monoid instances

instance Semigroup ExtBasicConstraints where
  _ <> b = b
instance Monoid ExtBasicConstraints where
  mempty = ExtBasicConstraints $ X509.ExtBasicConstraints True Nothing

pattern ExtKeyUsageP :: [X509.ExtKeyUsageFlag] -> ExtKeyUsage
pattern ExtKeyUsageP a = ExtKeyUsage (X509.ExtKeyUsage a)
instance Semigroup ExtKeyUsage where
  ExtKeyUsageP a <> ExtKeyUsageP b = ExtKeyUsageP (a <> b)
instance Monoid ExtKeyUsage where
  mempty = ExtKeyUsageP []

pattern ExtExtendedKeyUsageP :: [X509.ExtKeyUsagePurpose] -> ExtExtendedKeyUsage
pattern ExtExtendedKeyUsageP a = ExtExtendedKeyUsage (X509.ExtExtendedKeyUsage a)
instance Semigroup ExtExtendedKeyUsage where
  ExtExtendedKeyUsageP a <> ExtExtendedKeyUsageP b = ExtExtendedKeyUsageP (a <> b)
instance Monoid ExtExtendedKeyUsage where
  mempty = ExtExtendedKeyUsageP []

pattern ExtSubjectAltNameP :: [X509.AltName] -> ExtSubjectAltName
pattern ExtSubjectAltNameP a = ExtSubjectAltName (X509.ExtSubjectAltName a)
instance Semigroup ExtSubjectAltName where
  ExtSubjectAltNameP a <> ExtSubjectAltNameP b = ExtSubjectAltNameP (a <> b)
instance Monoid ExtSubjectAltName where
  mempty = ExtSubjectAltNameP []

instance Semigroup ExtSubjectKeyId where
  _ <> b = b
instance Semigroup ExtAuthorityKeyId where
  _ <> b = b

instance Semigroup a => Semigroup (Extension a) where
  Extension _ a <> Extension critical b = Extension critical (a <> b)

{-# COMPLETE ExtKeyUsageP #-}
{-# COMPLETE ExtExtendedKeyUsageP #-}
{-# COMPLETE ExtSubjectAltNameP #-}
