{-# LANGUAGE NamedFieldPuns #-}
{-# LANGUAGE StrictData #-}

module Messages where

import           Control.Monad       (guard)
import           Crypto.Random.Types (MonadRandom(getRandomBytes))
import           Data.Bits           (Bits(shiftL))
import           Data.ByteString     (ByteString)
import qualified Data.ByteString     as BS
import           Data.Kind
import           Data.Word

import           Wireguard.Crypto
import           Wireguard.Nonce
import qualified Wireguard.Wire      as Wire

import qualified Wireguard.Crypto    as Crypto

construction :: ByteString
construction = "Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s"

identifier :: ByteString
identifier = "WireGuard v1 zx2c4 Jason@zx2c4.com"

labelMac1 :: ByteString
labelMac1= "mac1----"

data ConState
  = Initialized
  | SentInit
  | HaveInit
  | Open -- After we sent or received the response, respectively
  deriving (Show, Eq, Ord)

-- `AtStates states st a` is `a`` iff st is an element of states
--
-- Some fields should only be filled during certain stages of the lifetime of
-- State
type family AtStates (sts :: [ConState]) (st :: ConState) (a :: Type) :: Type where
  AtStates '[] st a = ()
  AtStates (st : sts) st a = a
  AtStates (notSt : sts) st a = AtStates sts st a


data State (st :: ConState) =
  State
  { sPrivOur :: Crypto.SecretKey
  , sPubOur :: Crypto.PublicKey
  , ePrivOur :: AtStates '[Initialized, SentInit, HaveInit] st Crypto.SecretKey
  , ePubOur :: AtStates '[Initialized, SentInit, HaveInit] st Crypto.PublicKey
  , sPubTheirs :: AtStates '[SentInit, HaveInit, Open] st Crypto.PublicKey
  , q
  , h :: ByteString
  , c :: AtStates '[Initialized, SentInit, HaveInit] st ByteString
  , we :: Word32
  , ePubTheirs :: AtStates '[HaveInit] st Crypto.PublicKey
  , they :: AtStates [HaveInit, Open] st Word32
  , tSend, tRecv :: AtStates '[Open] st ByteString
  , nSend :: Word64
  , nRecv :: Window -- priority queue to keep track of which n we have seen
  }

getRandomWord32 :: MonadRandom m => m Word32
getRandomWord32 = do
  bytes <- getRandomBytes 4
  return $ BS.foldl' (\w b -> w `shiftL` 8 + fromIntegral b) 0 bytes

initState
  :: MonadRandom m =>
     (SecretKey, PublicKey)
  -> m (State 'Initialized)
initState (sPrivOur, sPubOur) = do
  (ePrivOur, ePubOur) <- mkKeyPair
  we <- getRandomWord32
  let q = BS.replicate 32 0
      c = hash construction
      h = hash (c <> identifier)
      ePubTheirs = ()
      they = ()
      tSend = ()
      tRecv = ()
      nSend = 0
      nRecv = newWindow
      conState = Initialized
      sPubTheirs = ()
  return State{..}

mkInitMessage
  :: State Initialized
  -> ByteString
  -> PublicKey
  -> (Wire.Init, State SentInit)
mkInitMessage State{..} tStamp sPubR =
  let sPrivI=sPrivOur
      sPubI=sPubOur
      ePrivI=ePrivOur
      ePubI=ePubOur
      sender=we
      hi=h
      ci=c

      hi' = hash (hi <> encodeBS sPubR)
      ci' = kdf1 ci (encodeBS ePubI)
      ephemeral = encodeBS ePubI
      hi'' = hash (hi' <> ephemeral)
      (ci'', k) = kdf2 ci' (dh ePrivI sPubR)
      static = aeadEncrypt k 0 (encodeBS sPubI) hi''
      hi''' = hash (hi'' <> static)
      (ci_final, k') = kdf2 ci'' (dh sPrivI sPubR)
      timestamp = aeadEncrypt k' 0 tStamp hi'''
      hi_final = hash (hi''' <> timestamp)
  in (Wire.Init{..}, State { c = ci_final
                           , h = hi_final
                           , sPubTheirs = sPubR
                           , ..
                           })

checkInitMessage
  :: State Initialized
  -> Wire.Init
  -> Maybe PublicKey
  -> Maybe (ByteString, State HaveInit)
checkInitMessage State{..} Wire.Init{..} mbSPubIKnown = do -- Maybe
  let sPrivR = sPrivOur
      sPubR = sPubOur
      ci = c
      hi = h

  let hi' = hash (hi <> encodeBS sPubR)
  ePubI <- readPublicKey ephemeral
  let ci' = kdf1 ci ephemeral
      hi'' = hash (hi' <> ephemeral)
      (ci'', k) = kdf2 ci' (dh sPrivR ePubI)

  sPubIReceivedBS <- aeadDecrypt k 0 static hi''
  sPubIReceived <- readPublicKey sPubIReceivedBS
  sPubI <- case mbSPubIKnown of
            -- We don't know the key, so we take the one we received on faith
            Nothing -> Just sPubIReceived
            Just sPubIKnown | sPubIKnown == sPubIReceived -> Just sPubIKnown
                            | otherwise -> Nothing

  let hi''' = hash (hi'' <> static)
      (ci_final, k') = kdf2 ci'' (dh sPrivR sPubI)

  tstamp <-  aeadDecrypt k' 0 timestamp hi'''

  let hi_final = hash (hi''' <> timestamp)

  return ( tstamp
         , State { they = sender
                 , h = hi_final
                 , c = ci_final
                 , ePubTheirs = ePubI
                 , sPubTheirs = sPubI
                 , ..
                 })

mkResponseMessage
  :: State HaveInit
  -> (Wire.InitResponse, State Open)
mkResponseMessage State{..} =
  let sPubI = sPubTheirs
      ePrivR = ePrivOur
      ePubR = ePubOur
      ePubI = ePubTheirs
      hr = h
      cr = c
      sender = we
      receiver = they

      cr' = kdf1 cr (encodeBS ePubR)
      ephemeral = encodeBS ePubR
      hr' = hash (hr <> ephemeral)
      cr'' = kdf1 cr' (dh ePrivR ePubI)
      cr''' = kdf1 cr'' (dh ePrivR sPubI)
      (cr_final, t, k) = kdf3 cr''' q
      hr'' = hash (hr' <> t)
      empty = aeadEncrypt k 0 "" hr''
      hr_final = hash (hr'' <> empty)

      (tSend, tRecv) = kdf2 cr_final mempty
  in ( Wire.InitResponse{..}
     , State{ c = ()
            , h = hr_final
            , ePrivOur   = ()
            , ePubOur    = ()
            , ePubTheirs = ()
            , tSend
            , tRecv
            , ..
            })

checkResponseMessage
  :: State SentInit
  -> Wire.InitResponse
  -> Maybe (State Open)
checkResponseMessage State{..} Wire.InitResponse{..} = do -- Maybe
  let hr = h
      cr = c
      sPrivI = sPrivOur
      ePrivI = ePrivOur

  let cr' = kdf1 cr ephemeral
  ePubR <- readPublicKey ephemeral
  let hr' = hash (hr <> ephemeral)
      cr'' = kdf1 cr' (dh ePrivI ePubR)
      cr''' = kdf1 cr'' (dh sPrivI ePubR)
      (cr_final, t, k) = kdf3 cr''' q
      hr'' = hash (hr' <> t)

  nullBS <- aeadDecrypt k 0 empty hr''
  guard $ BS.null nullBS
  let hr_final = hash (hr'' <> empty)
      (tRecv, tSend) = kdf2 cr_final mempty

  Just State{ c = ()
            , h = hr_final
            , ePrivOur = ()
            , ePubOur = ()
            , ePubTheirs = ()
            , they = sender
            , tSend
            , tRecv
            , ..
            }

mkTransportData
  :: Word32
  -> ByteString
  -> State Open
  -> (Wire.TransportData, State Open)
mkTransportData receiver bs st@State{nSend, tSend} =
  let paddingLen = 16 - BS.length bs `mod` 16
      bsPadded = bs <> BS.replicate paddingLen 0x0
      packet = aeadEncrypt tSend nSend bsPadded mempty
  in (Wire.TransportData{counter = nSend, ..}, st{nSend = nSend + 1})

checkTransportData
  :: Wire.TransportData
  -> State Open
  -> (Maybe ByteString, State Open)
checkTransportData Wire.TransportData{..} st@State{nRecv, tRecv} =
  case checkNonce counter nRecv of
    (False, nRecv') -> (Nothing, st{nRecv = nRecv'})
    (True, nRecv') ->
      case aeadDecrypt tRecv counter packet mempty of
        Nothing -> (Nothing, st{nRecv = nRecv'})
        Just bs -> (Just bs, st{nRecv = nRecv'})

test :: IO ByteString
test = do
  keysI@(_, sPubI) <- mkKeyPair
  keysR@(_, sPubR) <- mkKeyPair

  stI <- initState keysI
  stR <- initState keysR
  let tstamp = BS.replicate 12 4
      (initMessage, stI') = mkInitMessage stI tstamp sPubR
      (tStamp, stR') = fromJust $ checkInitMessage stR initMessage (Just sPubI)
      (reponseMessage, stR'') = mkResponseMessage stR'
      stI'' = fromJust $ checkResponseMessage stI' reponseMessage
  return tStamp
  where
    fromJust (Just r) = r
    fromJust Nothing = error "fromJust"
