module CLI.Cert where

-- import Prelude
import Data.List.NonEmpty
import Data.Text qualified as TS
import Options.Applicative

-- import Key qualified

data Create = Create
  { subjectKey :: FilePath
  , issuerKey :: FilePath
  , subjectName :: TS.Text
  }
  deriving Show

data Read = Read
  { paths :: [FilePath]
  , format :: String
  }
  deriving Show
