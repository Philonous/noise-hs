module Util where


import           Data.ByteString (ByteString)
import qualified Data.ByteString as BS
import           Numeric

newtype Hex = Hex ByteString

hexWord8 :: (Integral a, Show a) => a -> String
hexWord8 w =
  case showHex w "" of
    [ ] -> error "showhex: empty string"
    [c] -> ['0', c]
    cs -> cs

instance Show Hex where
  show (Hex bs) = BS.unpack bs >>= hexWord8
