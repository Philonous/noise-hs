{-# LANGUAGE StrictData #-}
{-# LANGUAGE DuplicateRecordFields #-}

module Wireguard.Wire where

import           Control.Monad
import           Data.ByteString (ByteString)
import qualified Data.ByteString as BS
import           Data.Serialize
import           Data.Word

data Init =
  Init
  { initSender :: Word32
  , initEphemeral :: ByteString -- 32 bytes
  , initStatic :: ByteString -- 32 + 16 bytes
  , initTimestamp :: ByteString -- 12 + 16 bytes
  } deriving (Eq, Show)

getZeroes :: Int -> Get ()
getZeroes n = replicateM_ n $ do
  z <- getWord8
  unless (z == 0) $ fail $ "getZero: expected 0x00, got " ++ show z
{-# inline getZeroes #-}

assertEq :: (Show a, Eq a) => String -> a -> a -> Get ()
assertEq str x y = do
  unless (x == y) $ fail $
    str ++ " failed to parse, expected "
    ++ show x ++ " but got " ++ show y
{-# inline assertEq #-}

writeInitMessage :: Init -> ByteString
writeInitMessage Init{..} = runPut $ do
    putWord8 0x1
    replicateM_ 3 $ putWord8 0x0
    putWord32le   initSender
    putByteString initEphemeral
    putByteString initStatic
    putByteString initTimestamp

getInitMessage :: Get Init
getInitMessage = do
    -- Don't get the type octet, this is handled by the caller
    getZeroes 3
    initSender <- getWord32le
    initEphemeral  <- getByteString 32
    initStatic     <- getByteString (32 + 16)
    initTimestamp  <- getByteString (12 + 16)
    return Init{..}

data InitResponse =
  InitResponse
  { initResponseSender :: Word32
  , initResponseReceiver :: Word32
  , initResponseEphemeral :: ByteString -- 32 bytes
  , initResponseEmpty :: ByteString -- 0 + 16 bytes
  } deriving (Eq, Show)

writeInitResponseMessage :: InitResponse -> ByteString
writeInitResponseMessage InitResponse{..} = runPut $ do
    putWord8 0x02
    replicateM_ 3 $ putWord8 0
    putWord32le   initResponseSender
    putWord32le   initResponseReceiver
    putByteString initResponseEphemeral
    putByteString initResponseEmpty

getInitResponseMessage :: Get InitResponse
getInitResponseMessage = do
    -- Don't get the type octet, this is handled by the caller
    getZeroes 3
    initResponseSender <- getWord32le
    initResponseReceiver <- getWord32le
    initResponseEphemeral  <- getByteString 32
    initResponseEmpty      <- getByteString (0 + 16)
    return InitResponse{..}

data TransportData =
  TransportData
  { transportDataReceiver :: Word32
  , transportDataCounter :: Word64
  , transportDataPacket :: ByteString -- variable
  } deriving (Eq, Show)

writeTransportDataMessage :: TransportData -> ByteString
writeTransportDataMessage TransportData{..} = runPut $ do
    putWord8 0x4
    replicateM_ 3 $ putWord8 0
    putWord32le transportDataReceiver
    putWord64le transportDataCounter
    putByteString transportDataPacket

getTransportDataMessage :: Get TransportData
getTransportDataMessage = do
    -- Don't get the type octet, this is handled by the caller
    getZeroes 3
    transportDataReceiver <- getWord32le
    transportDataCounter <- getWord64le
    transportDataPacket <- remaining >>= getByteString
    return TransportData{..}

data MACed a =
  MACed
  { macEdPayload :: ByteString
  , macedMac1 :: ByteString -- 16 bytes
  , macedMac2 :: ByteString -- 16 bytes
  } deriving (Eq, Show)

addMacs :: MACed a -> ByteString
addMacs MACed{..} = BS.concat [macEdPayload, macedMac1, macedMac2]

getMacs :: ByteString -> Maybe (MACed a)
getMacs bs = case BS.length bs > 32 of
               False -> Nothing
               True ->
                 let (macEdPayload, macs) = BS.splitAt (BS.length bs - 32) bs
                     (macedMac1, macedMac2) = BS.splitAt 16 macs
                 in Just MACed{..}

data Message
  = InitMessage Init
  | InitResponseMessage InitResponse
  | TransportDataMessage TransportData
  deriving (Eq, Show)

-- getMessage :: Get Message --
getMessage :: ByteString -> Either String Message
getMessage = runGet $ do
  tp <- getWord8
  case tp of
    0x1 -> InitMessage <$> getInitMessage
    0x2 -> InitResponseMessage <$> getInitResponseMessage
    0x4 -> TransportDataMessage <$> getTransportDataMessage
    _ -> fail $ "unknown message type " ++ show tp

mkTAI64NBS :: Word64 -> Word32 -> ByteString
mkTAI64NBS seconds pico = runPut $ do
  putWord64be seconds
  putWord32be pico

parseTAI64NBS :: ByteString -> Either String (Word64, Word32)
parseTAI64NBS = runGet $ (,) <$> getWord64be <*> getWord32be
