module CLI.Cert where

-- import Prelude
import Data.List.NonEmpty
import Options.Applicative

-- import Key qualified

data Create = Create
  deriving Show

data Read = Read
  { paths :: [FilePath] }
  deriving Show
