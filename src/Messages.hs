{-# LANGUAGE NamedFieldPuns #-}
module Messages where

import           Data.ByteString (ByteString)
import qualified Data.ByteString as BS
import           Data.Word
import           System.Random

import qualified Wire
import           Crypto

construction :: ByteString
construction = "Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s"

identifier :: ByteString
identifier = "WireGuard v1 zx2c4 Jason@zx2c4.com"

labelMac1 :: ByteString
labelMac1= "mac1----"

type Window = [Word64]

checkCounter :: Window -> Word64 -> (Window, Bool)
checkCounter = _

data State =
  State
  { sPrivOur, sPubOur
  , ePrivOur, ePubOur
  , sPubTheirs
  , q
  , h , c
    :: !ByteString
  , we :: !Word32
  -- We don't know the value of these initially
  , ePubTheirs :: ByteString
  , they :: Word32
  , tSend, tRecv :: ByteString
  , nSend :: !Word64
  , nRecv :: Window -- priority queue to keep track of which n we have seen
  } deriving Show

initState :: ByteString -> ByteString -> ByteString -> IO State
initState sPrivOur sPubOur sPubTheirs = do
  (ePrivOur, ePubOur) <- mkKeyPair
  we <- randomIO :: IO Word32
  let q = BS.replicate 32 0
      c = hash construction
      h = hash (c <> identifier)
      ePubTheirs = error "ePubTheirs unset"
      they = error "they unset"
      tSend = error "tSend unset"
      tRecv = error "tRecv unset"
      nSend = 0
      nRecv = []
  return State{..}

mkInitMessage :: State -> ByteString -> (Wire.Init, State)
mkInitMessage st@State { sPrivOur = sPrivI
                       , sPubOur = sPubI
                       , sPubTheirs = sPubR
                       , ePrivOur = ePrivI
                       , ePubOur = ePubI
                       , we = sender
                       , h = hi
                       , c = ci
                       }  tStamp =
  let hi' = hash (hi <> sPubR)
      ci' = kdf1 ci ePubI
      ephemeral = ePubI
      hi'' = hash (hi' <> ephemeral)
      (ci'', k) = kdf2 ci' (dh ePrivI sPubR)
      static = aeadEncrypt k 0 sPubI hi''
      hi''' = hash (hi'' <> static)
      (ci_final, k') = kdf2 ci'' (dh sPrivI sPubR)
      timestamp = aeadEncrypt k' 0 tStamp hi'''
      hi_final = hash (hi''' <> timestamp)
  in (Wire.Init{..}, st{c = ci_final, h = hi_final})

checkInitMessage :: State -> Wire.Init -> Maybe (ByteString, State)
checkInitMessage st@State{ sPrivOur = sPrivR
                         , sPubOur = sPubR
                         , sPubTheirs =  sPubI
                         , c = ci
                         , h = hi
                         }
                         Wire.Init{..} =
  let hi' = hash (hi <> sPubR)
      ePubI = ephemeral
      ci' = kdf1 ci ePubI
      hi'' = hash (hi' <> ephemeral)
      (ci'', k) = kdf2 ci' (dh sPrivR ePubI)
      mbSPubI' = aeadDecrypt k 0 static hi''
      hi''' = hash (hi'' <> static)
      (ci_final, k') = kdf2 ci'' (dh sPrivR sPubI)
      mbTstamp = aeadDecrypt k' 0 timestamp hi'''
      hi_final = hash (hi''' <> timestamp)
  in case ( mbSPubI' == Just sPubI
          , mbTstamp
          ) of
       (True, Just tstamp) ->
         let st' = st{ they = sender
                     , h = hi_final
                     , c = ci_final
                     , ePubTheirs = ePubI
                     }
         in Just (tstamp, st')
       _ -> Nothing


mkResponseMessage :: State -> (Wire.InitResponse, State)
mkResponseMessage st@State{ sPubTheirs = sPubI
                          , ePrivOur = ePrivR
                          , ePubOur = ePubR
                          , ePubTheirs = ePubI
                          , h = hr
                          , c = cr
                          , q
                          , we = sender
                          , they = receiver
                          }=
  let cr' = kdf1 cr ePubR
      ephemeral = ePubR
      hr' = hash (hr <> ephemeral)
      cr'' = kdf1 cr' (dh ePrivR ePubI)
      cr''' = kdf1 cr'' (dh ePrivR sPubI)
      (cr_final, t, k) = kdf3 cr''' q
      hr'' = hash (hr' <> t)
      empty = aeadEncrypt k 0 "" hr''
      hr_final = hash (hr'' <> empty)

      (tSend, tRecv) = kdf2 cr_final mempty
  in (Wire.InitResponse{..}, st{ c = mempty
                                      , h = mempty
                                      , ePrivOur = mempty
                                      , ePubOur = mempty
                                      , ePubTheirs = mempty
                                      , tSend
                                      , tRecv
                                      })

checkResponseMessage :: State -> Wire.InitResponse -> Maybe State
checkResponseMessage st@State{ h = hr
                             , c = cr
                             , sPrivOur = sPrivI
                             , ePrivOur = ePrivI
                             , q
                             } Wire.InitResponse{..} =
  let cr' = kdf1 cr ePubR
      ePubR = ephemeral
      hr' = hash (hr <> ephemeral)
      cr'' = kdf1 cr' (dh ePrivI ePubR)
      cr''' = kdf1 cr'' (dh sPrivI ePubR)
      (cr_final, t, k) = kdf3 cr''' q
      hr'' = hash (hr' <> t)
      mbNull = aeadDecrypt k 0 empty hr''
      hr_final = hash (hr'' <> empty)
      (tRecv, tSend) = kdf2 cr_final mempty
  in case mbNull of
       Just "" -> Just st{ c = mempty
                         , h = mempty
                         , ePrivOur = mempty
                         , ePubOur = mempty
                         , ePubTheirs = mempty
                         , they = sender
                         , tSend
                         , tRecv
                         }
       _ -> Nothing

mkTransportData :: Word32 -> ByteString -> State -> (Wire.TransportData, State)
mkTransportData receiver bs st@State{nSend, tSend} =
  let paddingLen = 16 - BS.length bs `mod` 16
      bsPadded = bs <> BS.replicate paddingLen 0x0
      packet = aeadEncrypt tSend nSend bsPadded mempty
  in (Wire.TransportData{counter = nSend, ..}, st{nSend = nSend + 1})

checkTransportData :: Wire.TransportData -> State -> (Maybe ByteString, State)
checkTransportData Wire.TransportData{..} st@State{nRecv, tRecv} =
  case checkCounter nRecv counter of
    (nRecv', False) -> (Nothing, st{nRecv = nRecv'})
    (nRecv', True) ->
      case aeadDecrypt tRecv counter packet mempty of
        Nothing -> (Nothing, st{nRecv = nRecv'})
        Just bs -> (Just bs, st{nRecv = nRecv'})

mkKey :: State -> (ByteString, ByteString)
mkKey State { c } = kdf2 c mempty

test = do
  (sPrivI, sPubI) <- mkKeyPair
  (sPrivR, sPubR) <- mkKeyPair

  stI <- initState sPrivI sPubI sPubR
  stR <- initState sPrivR sPubR sPubI
  let tstamp = BS.replicate 12 4
      (initMessage, stI') = mkInitMessage stI tstamp
      (tStamp, stR') = fromJust $ checkInitMessage stR initMessage
      (reponseMessage, stR'') = mkResponseMessage stR'
      stI'' = fromJust $ checkResponseMessage stI' reponseMessage
  return tStamp
  where
    fromJust (Just r) = r
    fromJust Nothing = error "fromJust"
