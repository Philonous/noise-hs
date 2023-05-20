{-# LANGUAGE TemplateHaskell #-}
{-# LANGUAGE QuasiQuotes #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE DeriveAnyClass #-}
{-# LANGUAGE StrictData #-}
{-# LANGUAGE NamedFieldPuns #-}

module Wireguard
  ( ConState(..)
  , ConStateS(..)
  , State
  , SomeState(..)
  -- * Keys
  , SecretKey
  , PublicKey
  , mkKeyPair
  , encodeKeyPair
  , encodePublicKey
  , readPublicKey
  , readKeyPair
  -- * State
  , initState
  -- * TAI64N
  , getTAI64N
  -- * Messages
  , mkInitMessage
  , writeInitMessage
  , checkInitMessage
  , mkResponseMessage
  , writeInitResponseMessage
  , checkResponseMessage
  , mkTransportData
  , writeTransportDataMessage
  , recvTransportData
  , getMessage
  ) where

import           Control.Concurrent
import           Control.Concurrent.Async
import qualified Control.Concurrent.Chan          as Chan
import           Control.Concurrent.MVar
import           Control.Concurrent.Thread.Delay  (delay)
import           Control.Monad                    (when)
import           Control.Monad                    (unless)
import qualified Control.Monad.Catch              as Ex
import           Data.ByteString                  (ByteString)
import qualified Data.ByteString                  as BS
import           Data.IORef
import           Data.String.Interpolate.IsString (i)
import           Data.Text                        (Text)
import qualified Data.Text.IO                     as Text
import qualified Data.Time.Clock
import           Data.Time.Clock                  (UTCTime)
import           Data.Typeable
import           System.IO                        (hPutStrLn, stderr)
import           System.IO                        (stderr)
import           System.Timeout                   (timeout)
import           Wireguard.Crypto
import           Wireguard.Messages
import           Wireguard.Wire

import           Prelude                          hiding (init)
import           Control.Concurrent.Async         (uninterruptibleCancel)

data Config = Config
  { configRekeyAfterMessages :: Int --  260 messages
  , configRejectAfterMessages :: Int --  264 − 213 − 1 messages
  , configRekeyAfterTime :: Integer --  120 seconds
  , configRejectAfterTime :: Integer --  180 seconds
  , configRekeyAttemptTime :: Integer --  90 seconds
  , configRekeyTimeout :: Integer --  5 seconds
  , configKeepaliveTimeout :: Integer --  10 seconds
  } deriving Show

defaultConfig =
  Config
  { configRekeyAfterMessages  = 260 --  messages
  , configRejectAfterMessages = 2^64 - 213 - 1 -- messages
  , configRekeyAfterTime      = 120_000_000 --  120 seconds
  , configRejectAfterTime     = 180_000_000 --  180 seconds
  , configRekeyAttemptTime    = 90_000_000 --  90 seconds
  , configRekeyTimeout        = 5_000_000 --  4 seconds
  , configKeepaliveTimeout    = 10_000_000 -- 10 seconds
  }

logError str = Text.hPutStrLn stderr $ "[Wireguard#Error]" <> str
logDebug str = Text.hPutStrLn stderr $ "[Wireguard#Debug]" <> str


data WaitSession =
  WaitSession
  { waitSessionAsync :: Async ()
  , waitSessionState :: State 'SentInit
  , waitSessionSendRekeyTimeoutReached :: IORef Bool
  , waitSessionReceiveRekeyTimeoutReached :: IORef Bool
  , waitSessionOnConnected :: MVar ()
  }

data St = StOpen | StClosed deriving (Show, Eq, Ord)

data WGConnection__ =
  WGConnection__
  { wgPreviousSession :: Maybe (State Open)
  , wgCurrentSession :: Maybe (State Open)
  , wgSendRekeyTimeoutReached :: IORef Bool -- Filled in by companion thread This
    -- always refers to the current session
  , wgReceiveRekeyTimeoutReached :: IORef Bool
  -- Filled by companion thread and emptied when we send data
  , wgSendWatchdog :: IORef (Maybe UTCTime)
  , wgNewSession :: Maybe WaitSession
  , wgSt :: St
  , wgSend :: ByteString -> IO ()
  , wgOurKey :: SecretKey
  , wgTheirKey :: PublicKey
  , wgConfig :: Config
  , wgState :: St
  }

newtype Connection = Connection (MVar WGConnection__)

withConnection :: Connection -> (WGConnection__ -> IO (WGConnection__, b)) -> IO b
withConnection (Connection mv) = modifyMVar mv

connection send ourKey theirKey = do
  wgSendRekeyTimeoutReached <- newIORef False
  wgReceiveRekeyTimeoutReached <- newIORef False
  wgSendWatchdog <- newIORef Nothing
  conVar <-  newMVar
      WGConnection__
      { wgPreviousSession = Nothing
      , wgCurrentSession = Nothing
      , wgNewSession = Nothing
      , wgSendRekeyTimeoutReached
      , wgReceiveRekeyTimeoutReached
      , wgSendWatchdog
      , wgSt = StOpen
      , wgSend = send
      , wgOurKey = ourKey
      , wgTheirKey = theirKey
      , wgConfig = defaultConfig
      , wgState = StOpen
      }
  mkWeakMVar conVar (close $ Connection conVar)
  return $ Connection conVar

waitSession config a sess onConnected = do
  waitSessionSendRekeyTimeoutReached <- newIORef False
  _ <- async $ do
    delay $ configRekeyAfterTime config
    atomicModifyIORef waitSessionSendRekeyTimeoutReached (const (False, ()))
  waitSessionReceiveRekeyTimeoutReached <- newIORef False
  _ <- async $ do
    delay $ configRejectAfterTime config
          - configKeepaliveTimeout config
          - configRekeyTimeout config
    atomicModifyIORef waitSessionReceiveRekeyTimeoutReached (const (False, ()))
  return WaitSession
          { waitSessionAsync = a
          , waitSessionState = sess
          , waitSessionSendRekeyTimeoutReached
          , waitSessionReceiveRekeyTimeoutReached
          , waitSessionOnConnected = onConnected
          }

-- | Try to connect to the peer, returns a function that waits for the
-- connection to complete
init :: Connection -> IO (IO ())
init con = withConnection con $ \con__ -> do
  -- We are the initiator
  case wgNewSession con__ of
    Just waiting -> return (con__, readMVar $ waitSessionOnConnected waiting)
    Nothing -> do
      onConnectedRef <- newEmptyMVar
      let onConnected = putMVar onConnectedRef ()
      sess <- doInit con__
      a <- async $ asyncInit (we sess) onConnectedRef
      -- Smart constructor for WaitSession
      ws <- waitSession (wgConfig con__)  a sess onConnectedRef
      return (con__{wgNewSession = Just ws }
             , readMVar onConnectedRef)
  where
    doInit con__ = do
      newSess <- initState (wgOurKey con__)
      now <- getTAI64N
      let (out, sess') = mkInitMessage (wgTheirKey con__) now newSess
      wgSend con__ $ writeInitMessage out
      return sess'
    asyncInit cur onConnected = do
      threadDelay 5_000_000
      cont <- withConnection con $ \con__ -> do
        case wgNewSession con__ of
          -- We are still waiting for the same session to complete
          Just s | we (waitSessionState s) == cur
                   -> do
                     sess <- doInit con__
                     ws <- waitSession (wgConfig con__) (waitSessionAsync s) sess
                                       onConnected
                     return ( con__{wgNewSession = Just ws}
                            , Just $ we sess
                            )
          -- Session initiation attempt has been completed or the session has
          -- been closed
          _ -> return (con__, Nothing)
      case cont of
        Nothing -> return ()
        Just cur' -> asyncInit cur' onConnected



close :: Connection -> IO ()
close con = withConnection con $ \con__ -> do
  -- Stop thread trying to connect
  case wgNewSession con__ of
    Nothing -> return ()
    Just ns -> uninterruptibleCancel $ waitSessionAsync ns
  hPutStrLn stderr "Closing connection"
  return
    (con__
      { wgPreviousSession = Nothing
      , wgCurrentSession = Nothing
      , wgNewSession = Nothing
      , wgSend = \_ -> return ()
      , wgOurKey = undefined
      , wgTheirKey = undefined
      , wgState = StClosed
      }, ())



data WireguardDataError = WireguardDataError Text
                        | NotConnected
  deriving (Show, Typeable, Ex.Exception)

-- | Feed an incoming packet into the connection, returns decrypted transport data packet if one was received
input :: Connection -> ByteString -> IO (Maybe BS.ByteString)
input con bs =
  case getMessage bs of
    Left e -> do
      logError [i|Could not parse wireguard message #{show bs}: #{show e}|]
      return Nothing
    Right (InitMessage msg) -> withConnection con $ \con__ -> do
      sess <- initState (wgOurKey con__)
      now <- getTAI64N
      -- TODO: Handle old timestamp
      case checkInitMessage Nothing msg sess of
        Nothing -> do
          logError [i|Received invalid init message|]
          return (con__, Nothing)
        Just (pubKey, tStamp, sess') -> do
          let (response, sess) = mkResponseMessage sess'
          wgSend con__ $ writeInitResponseMessage response
          return (con__{ wgPreviousSession = wgCurrentSession con__
                       , wgCurrentSession = Just sess
                       , wgNewSession = Nothing
                       }
                 , Nothing)
    Right (InitResponseMessage msg) -> withConnection con $ \con__ -> do
      case wgNewSession con__ of
        Nothing -> do
          logError [i|Received unexpected response message|]
          return (con__, Nothing)
        Just waitSession -> do
          case checkResponseMessage (waitSessionState waitSession) msg of
            -- Checking the message fails. Could indicate stale response to
            -- previous init, ignore
            Nothing -> do
              logDebug [i|Received unaccpetable response message #{msg}|]
              return (con__, Nothing)
            Just session -> do
              waitSessionOnConnected waitSession
              return (con__{ wgPreviousSession = wgCurrentSession con__
                           , wgCurrentSession = Just session
                           , wgNewSession = Nothing
                           }, Nothing)

          return (con__, Nothing)

    Right (TransportDataMessage msg) -> withConnection con $ \con__ -> do
      case wgCurrentSession con__ of
        Just cur | we cur == transportDataReceiver msg -> do
          case recvTransportData msg cur of
            Left e -> do
              logError [i|Couldn't decrypt message: #{e}|]
              return (con__, Nothing)
            Right (bs, st') -> do
              -- TODO: keepalive timeout
              -- Check and reset session timer
              tout <- atomicModifyIORef (wgReceiveRekeyTimeoutReached con__)
                                        (\reached -> (False, reached))
              when tout $ rekey con -- TODO
              return (con__{ wgCurrentSession = Just st'}
                     , Just bs
                     )
        -- Doesn't match current session, check previous session
        _ -> case wgPreviousSession con__ of
          Just prev | we prev == transportDataReceiver msg -> do
            case recvTransportData msg prev of
              Left e -> do
                logError [i|Couldn't decrypt message: #{e}|]
                return (con__, Nothing)
              Right (bs, st') -> do
                -- TODO?: keepalive timeout (Should be handled by ICE)

                -- Check message timer limit
                tout <- readIORef (wgReceiveRekeyTimeoutReached con__)
                when tout $ rekey con -- TODO
                return (con__{ wgPreviousSession = Just st'}
                       , Just bs
                       )
          -- Doesn't match previous session, drop
          _ -> do
            logError [i|Got transport data packet for session #{transportDataReceiver msg} that doesn't exist|]
            return (con__, Nothing)

rekey :: Connection -> IO ()
rekey con = do
  _ <- async $ init con
  return ()


send con bs = do
  done <- withConnection con $ \con__ ->
    case wgCurrentSession con__ of
      Nothing -> case wgState con__ of
                   StClosed -> Ex.throwM NotConnected
                   -- Connection not established, wait
                   StOpen -> return (con__, False)

      Just sess -> do
        let (tdm, sess') = mkTransportData  bs sess
        wgSend con__ $ writeTransportDataMessage tdm
        -- Check if timeout has triggered
        readIORef (wgSendRekeyTimeoutReached con__) >>= \case
          False -> return ()
          True -> rekey con

        return (con__{wgCurrentSession = Just sess'}, True)
  unless done $ do
    waitConnected <- init con
    waitConnected
    send con bs
