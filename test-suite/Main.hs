import           Data.Word
import qualified Test.Tasty
import           Test.Tasty.Hspec
import           Test.Hspec.Hedgehog

import           Data.Foldable
import           Data.Maybe          (catMaybes)
import           Data.Ord
import           Hedgehog
import qualified Hedgehog.Gen        as Gen
import qualified Hedgehog.Range      as Range

import           Wireguard.Nonce
import           Wireguard.Wire

main :: IO ()
main = do
  test <- testSpec "wireguard" spec
  Test.Tasty.defaultMain test

-- Test the nonce checker. First we have an enumeration of how a nonce might
-- come about, then we interpet those behaviours into a stream of nonces that we
-- then check

data NonceBehaviour
  = Normal -- This nonce arrives normally
  | Drop -- This nonce is dropped
  | Delay Word -- The package with the nonce is delayed
  | Replay Int -- This package is a replay of a nonce seen earlier
  deriving Show

interpretBehaviour :: [NonceBehaviour] -> [(Word64, Bool)]
interpretBehaviour bs = go bs 1 []
  where
    go [] _ _seen = []
    go (Normal : bs) n seen
      = (n, True) : go bs (n+1) (n:seen)
    -- Add Nothing instead of just dropping the element so "Delay" knows that
    -- there _should_ have been a nonce
    go (Drop : bs) n seen = go bs (n + 1) seen
    go (Delay d : bs) n seen =
      let (prefix, suffix) = splitAt (fromIntegral d) (go bs (n+1) seen)
          -- The nonce should be accepted iff we don't end up past a nonce 20
          -- higher
          accept = case prefix of
                     [] -> True
                     _ -> maximum (fst <$> prefix) < n + 20
      in prefix ++ [(n, accept)] ++ suffix
    -- Can't replay if there haven't been any accepted nonces yet
    go (Replay rp : bs) n [] = go bs (n + 1) []
    go (Replay rp : bs) n seen =
      let rpn = if rp >= length seen then last seen else seen !! rp
      in (rpn, False) : go bs (n + 1) seen

checkSequence :: MonadTest m => Window -> [(Word64, Bool)] -> m ()
checkSequence _window [] = return ()
checkSequence window ((n, accept) : ns) = do
  let (accepted, window') = checkNonce n window
  annotate $ show (n, window)
  accepted === accept
  checkSequence window' ns

genBehaviour :: Gen NonceBehaviour
genBehaviour =
  Gen.frequency [ (10, pure Normal)
                , (3, pure Drop)
                , (3, Delay <$> Gen.word (Range.linear 1 40))
                , (1, Replay <$> Gen.int (Range.linear 0 20))
                ]

nonceSpec :: Spec
nonceSpec = describe "Nonce" $ do
  it "Works with jumps" $ hedgehog $ do
    keep <- forAll $ Gen.list (Range.linear 0 200) Gen.bool
    let nonces = map snd . filter fst $ zip keep [1..]
    annotate $ show  nonces
    let (accept, _w) =
           foldl' (\(accept, w) n -> let (accept', w' ) = checkNonce n w
                                     in (accept && accept', w')
                  ) (True, newWindow) nonces
    accept === True
  it "Works with general sequences" $ hedgehog $ do
    behaviour <- forAll $ Gen.list (Range.linear 0 200) genBehaviour
    let nonces = interpretBehaviour behaviour
    annotate $ show nonces
    checkSequence newWindow nonces

wireSpec :: Spec
wireSpec = describe "Wire format" $ do
  describe "transport data message" $ do
    it "roundtrips through the parser" $ hedgehog $ do
      receiver <- forAll $ Gen.word32 Range.linearBounded
      counter <- forAll $ Gen.word64 Range.linearBounded
      packet <- forAll $ Gen.bytes (Range.linear 0 4069)
      let td = TransportData{..}
          bs = writeTransportDataMessage td
          message = getMessage bs
      message === Right (TransportDataMessage td)
      return ()

spec = do
  nonceSpec
  wireSpec
