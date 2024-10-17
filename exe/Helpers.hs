module Helpers where

import Options.Applicative

manyPaths :: String -> Parser [FilePath]
manyPaths metaName = many (argument str (metavar metaName))
