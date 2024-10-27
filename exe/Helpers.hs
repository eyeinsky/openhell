module Helpers where

import Options.Applicative
import Control.Monad.Except
import Crypto.Store.PKCS8 qualified as PKCS8

manyPaths :: String -> Parser [FilePath]
manyPaths metaName = many (argument str (metavar metaName))

ensureOne :: String -> [a] -> Either String a
ensureOne tag xs = case xs of
  [a] -> Right a
  [] -> Left $ "No " <> tag <> " found"
  _ : _ : _ -> Left $ "More than one " <> tag <> " found"

showLeft :: Show e => Either e a -> Either String a
showLeft = either (Left . show) Right

ensureUnprotected :: String -> PKCS8.OptProtected a -> Either String a
ensureUnprotected tag o = case o of
  PKCS8.Unprotected k -> Right k
  PKCS8.Protected _ -> Left $ "Expected unprotected " <> tag <> ", but got proteckted"

throwPrefix :: (Applicative m, MonadError String m) => String -> Either String a -> m a
throwPrefix msg e = either (\err -> throwError $ msg <> ": " <> err) pure e
