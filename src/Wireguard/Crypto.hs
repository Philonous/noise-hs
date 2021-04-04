{-# LANGUAGE FlexibleInstances #-}

module Wireguard.Crypto
  ( module Wireguard.Crypto
  , SecretKey
  , PublicKey
  ) where

import qualified Crypto.PubKey.Curve25519     as Curve25519
import           Crypto.PubKey.Curve25519     (SecretKey, PublicKey)
import           Data.ByteString              (ByteString)
import qualified Data.ByteString              as BS
import           Data.Data                    (Proxy(..))
import qualified Data.Serialize               as Serialize
import           Data.Word

import qualified Crypto.Cipher.ChaChaPoly1305 as AEAD
import           Crypto.ECC
import           Crypto.Error                 (throwCryptoError, maybeCryptoError)
import qualified Crypto.Hash                  as Hash
import qualified Crypto.MAC.HMAC              as Hmac
import qualified Crypto.MAC.Poly1305          as Poly1305
import           Crypto.Random.Types          (MonadRandom)
import           Data.ByteArray

curveX25519 :: Proxy Curve_X25519
curveX25519 = Proxy @Curve_X25519

class EncodeBS a where
  encodeBS :: a -> ByteString

instance EncodeBS SecretKey where
  encodeBS = convert

instance EncodeBS PublicKey where
  encodeBS = encodePoint curveX25519

mkKeyPair :: MonadRandom m => m (SecretKey, PublicKey)
mkKeyPair = do
  kp <- curveGenerateKeyPair curveX25519
  let pub = keypairGetPublic kp
      priv = keypairGetPrivate kp
  return (priv, pub)

readPublicKey :: ByteString -> Maybe PublicKey
readPublicKey = maybeCryptoError . decodePoint curveX25519

readKeyPair :: ByteString -> ByteString -> Maybe (SecretKey, PublicKey)
readKeyPair secretKeyBD publicKeyBD = do -- Maybe
  secretKey <- maybeCryptoError $ Curve25519.secretKey secretKeyBD
  pubkey <- maybeCryptoError $ decodePoint curveX25519 publicKeyBD
  return (secretKey, pubkey)


dh :: SecretKey -> PublicKey -> ByteString
dh secretKey pubkey = throwCryptoError $ do
  convert <$> ecdh curveX25519 secretKey pubkey

hash :: ByteString -> ByteString
hash bs = convert $ Hash.hashWith Hash.Blake2s_256 bs

hmac :: ByteString -> ByteString -> ByteString
hmac key message = convert (Hmac.hmac key message :: Hmac.HMAC Hash.Blake2s_256)

kdf1 :: ByteString -> ByteString -> ByteString
kdf1 key input =
  let t0 = hmac key input
      t1 = hmac t0 (BS.singleton 0x1)
  in t1

kdf2 :: ByteString -> ByteString -> (ByteString, ByteString)
kdf2 key input =
  let t0 = hmac key input
      t1 = hmac t0 (BS.singleton 0x1)
      t2 = hmac t0 (t1 <> BS.singleton 0x2)
  in (t1, t2)

kdf3 :: ByteString -> ByteString -> (ByteString, ByteString, ByteString)
kdf3 key input =
  let t0 = hmac key input
      t1 = hmac t0 (BS.singleton 0x1)
      t2 = hmac t0 (t1 <> BS.singleton 0x2)
      t3 = hmac t0 (t2 <> BS.singleton 0x3)
  in (t1, t2, t3)

aeadEncrypt :: ByteString -> Word64 -> ByteString -> ByteString -> ByteString
aeadEncrypt key counter plain authText =
  let nonceBS = Serialize.runPut $ do
        Serialize.putWord32le 0x0
        Serialize.putWord64le counter
      nonce = throwCryptoError $ AEAD.nonce12 nonceBS
      state0 = throwCryptoError $ AEAD.initialize key nonce
      state1 = AEAD.appendAAD authText state0
      state2 = AEAD.finalizeAAD state1
      (cyphertext, state3) = AEAD.encrypt plain state2
  in (cyphertext <> convert (AEAD.finalize state3))

aeadDecrypt :: ByteString -> Word64 -> ByteString -> ByteString -> Maybe ByteString
aeadDecrypt key counter cypherBS authText =
  let (cyphertext, authtagBS) = BS.splitAt (BS.length cypherBS - 16) cypherBS
      authTag = throwCryptoError $ Poly1305.authTag authtagBS
      nonceBS = Serialize.runPut $ do
        Serialize.putWord32le 0x0
        Serialize.putWord64le counter
      nonce = throwCryptoError $ AEAD.nonce12 nonceBS
      state0 = throwCryptoError $ AEAD.initialize key nonce
      state1 = AEAD.appendAAD authText state0
      state2 = AEAD.finalizeAAD state1
      (plaintext, state3) = AEAD.decrypt cyphertext state2
  in case AEAD.finalize state3 == authTag of
       False -> Nothing
       True -> Just plaintext
