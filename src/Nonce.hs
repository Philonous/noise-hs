{-# LANGUAGE NamedFieldPuns #-}
module Nonce where

import           Data.Set  (Set)
import qualified Data.Set  as Set
import           Data.Word

data Window =
  Window { next :: !Word64 -- The next nonce we expect
         , missing :: Set Word64 -- Elements we haven't seen yet
         } deriving Show

newWindow :: Window
newWindow = Window { next = 0
                   , missing = mempty
                   }

cutoff :: Word64
cutoff = 20

checkNonce :: Word64 -> Window -> (Bool, Window)
checkNonce n w@Window{next, missing}
  -- This is the expected case
  | n == next = (True, Window { next = n + 1
                               -- Avoid manipulaing the Set in the common case
                              , missing = missing
                              })
  | n > next =
    -- `min n cutoff` to avoid wraparound
    --
    -- This would be the same as `max 0 (n - cuttoff + 1)` if we had negative
    -- numbers
    let oldest = n - min n cutoff
    in (True , Window{ next = n + 1
                     , missing =
                         -- Drop elements older than lower bound
                         let (_old, current) = Set.split oldest missing
                         in Set.union current $
                            -- Insert all elements from next + 1 to the new one
                            -- as missing
                            --
                            -- n can't be 0 he, so n - 1 is OK
                            Set.fromList [max next oldest .. (n - 1)]
                     }
      )
  | n >= next - min next cutoff
  , n `Set.member` missing
    = (True, Window{ next, missing = Set.delete n missing} )
  -- n < oldest or n not in missing elements
  | otherwise = (False, w)
