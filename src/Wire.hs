{-# LANGUAGE StrictData #-}
{-# LANGUAGE DuplicateRecordFields #-}

module Wire where

import           Control.Monad
import           Data.ByteString    (ByteString)
import qualified Data.ByteString    as BS
import           Data.Serialize
import           Data.Serialize.Get
import           Data.Serialize.Put
import           Data.Word

data InitMessage =
  InitMessage
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

instance Serialize InitMessage where
  put InitMessage{..} = do
    putWord8 0x1
    replicateM_ 3 $ putWord8 0x0
    putWord32le sender
    putByteString ephemeral
    putByteString static
    putByteString timestamp
  get = do
    tp <- getWord8
    assertEq "type" 0x1 tp
    getZeroes 3
    sender <- getWord32le
    ephemeral  <- getByteString 32
    static     <- getByteString (32 + 16)
    timestamp  <- getByteString (12 + 16)
    return InitMessage{..}

data InitResponseMessage =
  InitResponseMessage
  { sender :: Word32
  , receiver :: Word32
  , ephemeral :: ByteString -- 32 bytes
  , empty :: ByteString -- 0 + 16 bytes
  }


instance Serialize InitResponseMessage where
  put InitResponseMessage{..} = do
    putWord8 0x02
    replicateM_ 3 $ putWord8 0
    putWord32le sender
    putWord32le receiver
    putByteString ephemeral
    putByteString empty
  get = do
    tp <- getWord8
    assertEq "type" 0x2 tp
    getZeroes 3
    sender <- getWord32le
    receiver <- getWord32le
    ephemeral  <- getByteString 32
    empty      <- getByteString (0 + 16)
    return InitResponseMessage{..}

data TransportDataMessage =
  TransportDataMessage
  { receiver :: Word32
  , counter :: Word64
  , packet :: ByteString -- variable
  }


instance Serialize TransportDataMessage where
  put TransportDataMessage{..} = do
    putWord8 0x4
    replicateM_ 3 $ putWord8 0
    putWord32le receiver
    putWord64le counter
    putByteString packet

  get = do
    getWord8 >>= assertEq "type" 0x4
    receiver <- getWord32le
    counter <- getWord64le
    packet <- remaining >>= getByteString
    return TransportDataMessage{..}
