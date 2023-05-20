{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE NamedFieldPuns #-}
{-# LANGUAGE StrictData #-}
{-# LANGUAGE ScopedTypeVariables #-}

module Wireguard.Messages where

import           Control.Monad          (guard)
import           Control.Monad.Trans
import           Crypto.Random.Types    (MonadRandom(getRandomBytes))
import           Data.Bits              (Bits(shiftL))
import           Data.ByteString        (ByteString)
import qualified Data.ByteString        as BS
import qualified Data.ByteString.Base64 as Base64
import           Data.Fixed
import           Data.Kind
import qualified Data.List              as List
import qualified Data.Text.Encoding     as Text
import           Data.Time.Clock
import           Data.Time.Clock.POSIX
import           Data.Word
import           Util

import           Wireguard.Crypto
import           Wireguard.Nonce
import qualified Wireguard.Wire         as Wire

import qualified Wireguard.Crypto       as Crypto

-- TODO: mac1 and mac2 in init and response messages
-- They require Blake2s keyed mode which isn't supported by cryptonite yet

construction :: ByteString
construction = "Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s"

identifier :: ByteString
identifier = "WireGuard v1 zx2c4 Jason@zx2c4.com"

labelMac1 :: ByteString
labelMac1= "mac1----"

newtype TAI64N  = TAI64N ByteString
  deriving (Eq, Ord)

-- Compare https://cr.yp.to/libtai/tai64.html
getTAI64N :: IO TAI64N
getTAI64N = do
  now <- getPOSIXTime
  let (seconds, picoNDT) = properFraction now :: (Word64, NominalDiffTime)
      taiLabel = seconds + 2 ^ 62
      MkFixed picoInt = nominalDiffTimeToSeconds picoNDT
  return $ TAI64N $ Wire.mkTAI64NBS taiLabel (fromInteger picoInt)

instance Show TAI64N where
  show (TAI64N bs) =
    let parsed = case Wire.parseTAI64NBS bs of
                   Left e -> "»invalid«"
                   Right (taiLabel, pico) ->
                     let seconds = taiLabel - 2^62
                         ptime = fromIntegral seconds + (fromIntegral pico / 2 ^ 32)
                         time = posixSecondsToUTCTime ptime
                     in show time
    in "TAI64N(" ++ show (Hex bs) ++ " = " ++ parsed ++ ")"

data Party
  = Initiator
  | Receiver
  deriving (Eq, Ord, Show)

data ConState
  = Initialized
  | SentInit
  | HaveInit
  | Open -- After we sent or received the response, respectively
  deriving (Show, Eq, Ord)

-- | Singleton for conState
--
-- [ConStateS]
-- When pattern matching on this value, we also learn the type of
-- the State we are in
data ConStateS (st :: ConState) where
  SInitialized :: ConStateS 'Initialized
  SSentInit :: ConStateS 'SentInit
  SHaveInit :: ConStateS 'HaveInit
  SOpen :: ConStateS 'Open

deriving instance Show (ConStateS st)

-- `AtStates states st a` is `a`` iff st is an element of states
--
-- Some fields should only be filled during certain stages of the lifetime of
-- State
type family AtStates (sts :: [ConState]) (st :: ConState) (a :: Type) :: Type where
  AtStates '[] st a = ()
  AtStates (st : sts) st a = a
  AtStates (notSt : sts) st a = AtStates sts st a

-- atStates :: AtStates sts st a -> ConIState st -> (Either a () -> r) -> r
-- atStates x SInitialized

data State (st :: ConState) =
  State
  { sPrivOur :: Crypto.SecretKey
  , sPubOur :: Crypto.PublicKey
  , ePrivOur :: AtStates '[ 'Initialized, 'SentInit, 'HaveInit] st Crypto.SecretKey
  , ePubOur :: AtStates '[ 'Initialized, 'SentInit, 'HaveInit] st Crypto.PublicKey
  , sPubTheirs :: AtStates '[ 'SentInit, 'HaveInit, 'Open] st Crypto.PublicKey
  , q
  , h :: ByteString
  , c :: AtStates '[ 'Initialized, 'SentInit, 'HaveInit] st ByteString
  , we :: Word32 -- ^ Randomly chosen, identifies the session
  , ePubTheirs :: AtStates '[ 'HaveInit] st Crypto.PublicKey
  , they :: AtStates [ 'HaveInit, 'Open] st Word32
  , tSend, tRecv :: AtStates '[ 'Open] st ByteString
  , nSend :: Word64
  , nRecv :: Window -- priority queue to keep track of which n we have seen
  , conState :: ConStateS st -- ^ See [ConStateS]
  , created :: UTCTime
  }

instance Show (State st) where
  -- Explicitly match on the conState to avoid having to bring in the heavy
  -- artillery (singletons)
  show State{..} =
    List.intercalate "\n  "
       [ "State"
       , "{ conState = "++ show conState
       , ", sPrivOur = "++ encd sPrivOur
       , ", sPubOur = "++ encd sPubOur
       , ", ePrivOur = "++ helperISH (encd @Crypto.SecretKey) ePrivOur
       , ", ePubOur = "++ helperISH (encd @Crypto.PublicKey) ePubOur
       , ", sPubTheirs = "++ case conState of
                           SSentInit -> encd sPubTheirs
                           SHaveInit -> encd sPubTheirs
                           SOpen -> encd sPubTheirs
                           _ -> "()"
       , ", ePubTheirs = "++ case conState of
                                SHaveInit -> encd ePubTheirs
                                _ -> "()"
       , ", q = "++ b64 q
       , ", h = "++ b64 h
       , ", c = "++ helperISH b64 c
       , ", we = "++ show we
       , ", they = "++ case conState of
                      SHaveInit -> show they
                      SOpen -> show they
                      _ -> "()"
       , ", tSend = "++ case conState of
                          SOpen -> b64 tSend
                          _ -> "()"
       , ", tRecv = "++ case conState of
                          SOpen -> b64 tRecv
                          _ -> "()"
       , ", nsend = "++ show nSend
       , ", nRecv = "++ show nRecv
       , "}"
       ]
    where
      encd :: EncodeBS a => a -> String
      encd = b64 . encodeBS
      b64 = show . Text.decodeUtf8 . Base64.encode
      -- Some uglyness to avoid bringing in singletons
      helperISH :: forall a. (a -> String)
                -> AtStates '[ 'Initialized, 'SentInit, 'HaveInit] st a
                -> String
      helperISH f k = case conState of
                            SInitialized -> f k
                            SSentInit -> f k
                            SHaveInit -> f k
                            _ -> "()"

-- | Existential for States so we can store them e.g. in a map.
--
-- To reciver the state index, pattern match on 'conState'
data SomeState where
  SomeState :: State st -> SomeState

getRandomWord32 :: MonadRandom m => m Word32
getRandomWord32 = do
  bytes <- getRandomBytes 4
  return $ BS.foldl' (\w b -> w `shiftL` 8 + fromIntegral b) 0 bytes

initState
  :: (MonadRandom m, MonadIO m) =>
     SecretKey
  -> m (State 'Initialized)
initState sPrivOur = do
  (ePrivOur, ePubOur) <- mkKeyPair
  created <- liftIO getCurrentTime
  we <- getRandomWord32
  let sPubOur = Crypto.toPublic sPrivOur
      q = BS.replicate 32 0
      c = hash construction
      h = hash (c <> identifier)
      ePubTheirs = ()
      they = ()
      tSend = ()
      tRecv = ()
      nSend = 0
      nRecv = newWindow
      sPubTheirs = ()
  return State{conState = SInitialized, ..}


mkInitMessage
  :: PublicKey
  -> TAI64N
  -> State 'Initialized
  -> (Wire.Init, State 'SentInit)
mkInitMessage sPubR (TAI64N tStamp) State{..} =
  let sPrivI=sPrivOur
      sPubI=sPubOur
      ePrivI=ePrivOur
      ePubI=ePubOur
      initSender=we
      hi=h
      ci=c

      hi' = hash (hi <> encodeBS sPubR)
      ci' = kdf1 ci (encodeBS ePubI)
      initEphemeral = encodeBS ePubI
      hi'' = hash (hi' <> initEphemeral)
      (ci'', k) = kdf2 ci' (dh ePrivI sPubR)
      initStatic = aeadEncrypt k 0 (encodeBS sPubI) hi''
      hi''' = hash (hi'' <> initStatic)
      (ci_final, k') = kdf2 ci'' (dh sPrivI sPubR)
      initTimestamp = aeadEncrypt k' 0 tStamp hi'''
      hi_final = hash (hi''' <> initTimestamp)

      initMessage = Wire.Init{..}
      bs = Wire.writeInitMessage initMessage
      -- TODO mac1 mac2
  in ( initMessage
     , State { c = ci_final
             , h = hi_final
             , sPubTheirs = sPubR
             , conState = SSentInit
             , ..
             })


checkInitMessage
  :: Maybe TAI64N
  -> Wire.Init
  -> State 'Initialized
  -> Maybe (PublicKey, TAI64N, State 'HaveInit)
checkInitMessage mbOldTStamp Wire.Init{..} State{..} = do -- Maybe
  let sPrivR = sPrivOur
      sPubR = sPubOur
      ci = c
      hi = h

  let hi' = hash (hi <> encodeBS sPubR)
  ePubI <- readPublicKey initEphemeral
  let ci' = kdf1 ci initEphemeral
      hi'' = hash (hi' <> initEphemeral)
      (ci'', k) = kdf2 ci' (dh sPrivR ePubI)

  sPubIReceivedBS <- aeadDecrypt k 0 initStatic hi''
  sPubIReceived <- readPublicKey sPubIReceivedBS

  let hi''' = hash (hi'' <> initStatic)
      (ci_final, k') = kdf2 ci'' (dh sPrivR sPubIReceived)

  tstamp <- TAI64N <$> aeadDecrypt k' 0 initTimestamp hi'''

  case mbOldTStamp of
    Nothing -> return ()
    Just oldTStamp -> guard $ oldTStamp < tstamp

  let hi_final = hash (hi''' <> initTimestamp)

  return ( sPubIReceived
         , tstamp
         , State { they = initSender
                 , h = hi_final
                 , c = ci_final
                 , ePubTheirs = ePubI
                 , sPubTheirs = sPubIReceived
                 , conState = SHaveInit
                 , ..
                 })

mkResponseMessage
  :: State 'HaveInit
  -> (Wire.InitResponse, State 'Open)
mkResponseMessage State{..} =
  let sPubI = sPubTheirs
      ePrivR = ePrivOur
      ePubR = ePubOur
      ePubI = ePubTheirs
      hr = h
      cr = c
      initResponseSender = we
      initResponseReceiver = they

      cr' = kdf1 cr (encodeBS ePubR)
      initResponseEphemeral = encodeBS ePubR
      hr' = hash (hr <> initResponseEphemeral)
      cr'' = kdf1 cr' (dh ePrivR ePubI)
      cr''' = kdf1 cr'' (dh ePrivR sPubI)
      (cr_final, t, k) = kdf3 cr''' q
      hr'' = hash (hr' <> t)
      initResponseEmpty = aeadEncrypt k 0 "" hr''
      hr_final = hash (hr'' <> initResponseEmpty)

      (tSend, tRecv) = kdf2 cr_final mempty
  in ( Wire.InitResponse{..}
     , State{ c = ()
            , h = hr_final
            , ePrivOur   = ()
            , ePubOur    = ()
            , ePubTheirs = ()
            , tSend
            , tRecv
            , conState = SOpen
            , ..
            })

checkResponseMessage
  :: State 'SentInit
  -> Wire.InitResponse
  -> Maybe (State 'Open)
checkResponseMessage State{..} Wire.InitResponse{..} = do -- Maybe
  guard $ initResponseReceiver == we
  let hr = h
      cr = c
      sPrivI = sPrivOur
      ePrivI = ePrivOur

  let cr' = kdf1 cr initResponseEphemeral
  ePubR <- readPublicKey initResponseEphemeral
  let hr' = hash (hr <> initResponseEphemeral)
      cr'' = kdf1 cr' (dh ePrivI ePubR)
      cr''' = kdf1 cr'' (dh sPrivI ePubR)
      (cr_final, t, k) = kdf3 cr''' q
      hr'' = hash (hr' <> t)

  nullBS <- aeadDecrypt k 0 initResponseEmpty hr''
  guard $ BS.null nullBS
  let hr_final = hash (hr'' <> initResponseEmpty)
      (tRecv, tSend) = kdf2 cr_final mempty

  Just State{ c = ()
            , h = hr_final
            , ePrivOur = ()
            , ePubOur = ()
            , ePubTheirs = ()
            , they = initResponseSender
            , tSend
            , tRecv
            , conState = SOpen
            , ..
            }

-- | Encrypt a packet with the symmetric key
-- 0-pads the payload to a multiple 16 bytes
mkTransportData
  :: ByteString
  -> State 'Open
  -> (Wire.TransportData, State 'Open)
mkTransportData bs st@State{nSend, tSend, they = transportDataReceiver} =
  let paddingLen = 16 - BS.length bs `mod` 16
      bsPadded = bs <> BS.replicate paddingLen 0x0
      transportDataPacket = aeadEncrypt tSend nSend bsPadded mempty
  in (Wire.TransportData{transportDataCounter = nSend, ..}, st{nSend = nSend + 1})


-- The state state isn't updated if the decryption fails
recvTransportData
  :: Wire.TransportData
  -> State 'Open
  -> Either String (ByteString, State 'Open)
recvTransportData Wire.TransportData{..} st@State{nRecv, tRecv} =
  case checkNonce transportDataCounter nRecv of
    -- When the nonce check fails, the state isn't changed
    (False, _nRecv') -> Left "Nonce error"
    (True, nRecv') ->
      case aeadDecrypt tRecv transportDataCounter transportDataPacket mempty of
        Nothing -> Left "Decryption error" -- never update state when we can't decrypt the message
        Just bs -> Right (bs, st{nRecv = nRecv'})
