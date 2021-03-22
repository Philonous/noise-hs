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

mkInitMessage sPrivI sPubI sPubR tStamp = do
  sender <- randomIO :: IO Word32
  (ePrivI, ePubI) <- mkKeyPair
  let ci = hash construction
      hi = hash (ci <> identifier)
      hi' = hash (hi <> sPubR)
      ci' = kdf1 ci ePubI
      ephemeral = ePubI
      hi'' = hash (hi' <> ephemeral)
      (ci'', k) = kdf2 ci' (dh ePrivI sPubR)
      static = aeadEncrypt k 0 sPubI hi''
      hi''' = hash (hi'' <> static)
      (ci''', k') = kdf2 ci'' (dh sPrivI sPubR)
      timestamp = aeadEncrypt k' 0 tStamp hi'''
      hi_final = hash (hi''' <> timestamp)
  -- return (InitMessage{..})
  return (Wire.InitMessage{..})

checkInitMessage sPrivR sPubI sPubR Wire.InitMessage{..} = do
  let ci = hash construction
      hi = hash (ci <> identifier)
      hi' = hash (hi <> sPubR)
      ePubI = ephemeral
      ci' = kdf1 ci ePubI
      hi'' = hash (hi' <> ephemeral)
      (ci'', k) = kdf2 ci' (dh sPrivR ePubI)
      mbSPubI' = aeadDecrypt k 0 static hi'' -- Check that sPubI' == SPubI
      hi''' = hash (hi'' <> static)
      (_ci''', k') = kdf2 ci'' (dh sPrivR sPubI)
      mbtStamp = aeadDecrypt k' 0 timestamp hi''' -- Check that timestamp is reasonable
      _hi_final = hash (hi''' <> timestamp)
  return ( mbSPubI' == Just sPubI
         , mbtStamp
         , ePubI
         )

test = do
  (sPrivI, sPubI) <- mkKeyPair
  (sPrivR, sPubR) <- mkKeyPair
  initMessage <- mkInitMessage sPrivI sPubI sPubR "timestamp123"
  checkInitMessage sPrivR sPubI sPubR initMessage
