{-# LANGUAGE StrictData #-}
{-# LANGUAGE DuplicateRecordFields #-}

module Wireguard.Wire where

import           Control.Monad
import           Data.ByteString    (ByteString)
import qualified Data.ByteString    as BS
import           Data.Serialize
import           Data.Word

data Init =
  Init
  { sender :: Word32
  , ephemeral :: ByteString -- 32 bytes
  , static :: ByteString -- 32 + 16 bytes
  , timestamp :: ByteString -- 12 + 16 bytes
  } deriving Show

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
    putWord32le sender
    putByteString ephemeral
    putByteString static
    putByteString timestamp

getInitMessage :: Get Init
getInitMessage = do
    -- Don't get the type octet, this is handled by the caller
    getZeroes 3
    sender <- getWord32le
    ephemeral  <- getByteString 32
    static     <- getByteString (32 + 16)
    timestamp  <- getByteString (12 + 16)
    return Init{..}

data InitResponse =
  InitResponse
  { sender :: Word32
  , receiver :: Word32
  , ephemeral :: ByteString -- 32 bytes
  , empty :: ByteString -- 0 + 16 bytes
  }

writeInitResponseMessage :: InitResponse -> ByteString
writeInitResponseMessage InitResponse{..} = runPut $ do
    putWord8 0x02
    replicateM_ 3 $ putWord8 0
    putWord32le sender
    putWord32le receiver
    putByteString ephemeral
    putByteString empty

getInitResponseMessage :: Get InitResponse
getInitResponseMessage = do
    -- Don't get the type octet, this is handled by the caller
    getZeroes 3
    sender <- getWord32le
    receiver <- getWord32le
    ephemeral  <- getByteString 32
    empty      <- getByteString (0 + 16)
    return InitResponse{..}

data TransportData =
  TransportData
  { receiver :: Word32
  , counter :: Word64
  , packet :: ByteString -- variable
  }

writeTransportDataMessage :: TransportData -> ByteString
writeTransportDataMessage TransportData{..} = runPut $ do
    putWord8 0x4
    replicateM_ 3 $ putWord8 0
    putWord32le receiver
    putWord64le counter
    putByteString packet

getTransportDataMessage :: Get TransportData
getTransportDataMessage = do
    -- Don't get the type octet, this is handled by the caller
    receiver <- getWord32le
    counter <- getWord64le
    packet <- remaining >>= getByteString
    return TransportData{..}

data MACed a =
  MACed
  { payload :: ByteString
  , mac1 :: ByteString -- 16 bytes
  , mac2 :: ByteString -- 16 bytes
  }

addMacs :: MACed a -> ByteString
addMacs MACed{..} = BS.concat [payload, mac1, mac2]

getMacs :: ByteString -> Maybe (MACed a)
getMacs bs = case BS.length bs > 32 of
               False -> Nothing
               True ->
                 let (payload, macs) = BS.splitAt (BS.length bs - 32) bs
                     (mac1, mac2) = BS.splitAt 16 macs
                 in Just MACed{..}

data Message
  = InitMessage Init
  | InitResponseMessage InitResponse
  | TransportDataMessage TransportData


-- getMessage :: Get Message --
getMessage :: ByteString -> Either String Message
getMessage = runGet $ do
  tp <- getWord8
  case tp of
    0x1 -> InitMessage <$> getInitMessage
    0x2 -> InitResponseMessage <$> getInitResponseMessage
    0x4 -> TransportDataMessage <$> getTransportDataMessage
    _ -> fail $ "unknown message type " ++ show tp
