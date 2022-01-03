{-# LANGUAGE ForeignFunctionInterface #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE CApiFFI #-}

module Hsy
    ( initialize
    , kxKeygen
    , kxKk1
    , bin2hex
    , InitError
    , InitOk
    ) where


import qualified Foreign.C.Types as Fc
import qualified Foreign as F
import qualified Foreign.Storable
import qualified Data.ByteString as B
import qualified Data.Word
import qualified System.IO.Unsafe
import qualified Foreign.Marshal.Array as Fa
import qualified Data.Text
import qualified Data.Text.Encoding


foreign import capi "wrappers.h hydro_kx_kk_1_wrap"
    hydro_kx_kk_1
        :: F.Ptr Fc.CChar -- Public ephemeral key
        -> F.Ptr Fc.CChar -- Secret ephemeral key
        -> F.Ptr Fc.CUInt -- Hash state state
        -> F.Ptr Fc.CChar -- Hash state buf off
        -> F.Ptr Fc.CChar -- Hash state alignment
        -> F.Ptr Fc.CChar -- Packet 1
        -> F.Ptr Fc.CChar -- Peer public key
        -> F.Ptr Fc.CChar -- Public static key
        -> F.Ptr Fc.CChar -- Secret static key
        -> Fc.CInt


data KxState
    = KxState KxKeypair HashState


data HashState 
    = HashState HashStateState HashStateBufOff HashStateAlign


newtype HashStateAlign
    = HashStateAlign B.ByteString


newtype HashStateState
    = HashStateState [Data.Word.Word32]


newtype HashStateBufOff
    = HashStateBufOff Data.Word.Word8


data KxKeypair
    = KxKeypair
    { kxGetPublic :: KxPublicKey
    , kxGetSecret :: KxSecretKey
    }


instance Show KxKeypair where
    show (KxKeypair public secret) =
        mconcat
        [ "{ public: "
        , show public
        , ", secret: "
        , show secret
        , " }"
        ]


newtype KxPublicKey
    = KxPublicKey B.ByteString


instance Show KxPublicKey where
    show =
        Data.Text.unpack . bin2hex . encode


newtype KxSecretKey
    = KxSecretKey B.ByteString


instance Show KxSecretKey where
    show =
        Data.Text.unpack . bin2hex . encode


class Encodable a where
    encode :: a -> B.ByteString


instance Encodable KxSecretKey where
    encode (KxSecretKey s) =
        s


instance Encodable KxPublicKey where
    encode (KxPublicKey p) =
        p


allocInts :: (F.Ptr Fc.CUInt -> IO b) -> IO b
allocInts =
    Fa.allocaArray 12


newtype KxKkPacket1
    = KxKkPacket1 B.ByteString


kxKk1
    :: InitOk
    -> KxPublicKey
    -> KxKeypair
    -> IO (Maybe (KxKkPacket1, KxState))
kxKk1 _ publicKey keypair =
    F.allocaBytes kxPublicKeyBytes $ \publicEphemeralPtr ->
    F.allocaBytes kxSecretKeyBytes $ \secretEphemeralPtr ->
    allocInts $ \hashStateStatePtr ->
    F.allocaBytes 1 $ \hashStateBufOffPtr ->
    F.allocaBytes 3 $ \hashStateAlignPtr ->
    F.allocaBytes kxKkPacket1Bytes $ \packet1Ptr ->
    B.useAsCStringLen (encode publicKey) $ \(peerPublicPtr, _) ->
    B.useAsCStringLen (encode (kxGetPublic keypair)) $
        \(myPublicStaticPtr, _) ->
    B.useAsCStringLen (encode ( kxGetSecret keypair)) $
        \(mySecretStaticPtr, _) ->

        let
        result =
            hydro_kx_kk_1
                publicEphemeralPtr
                secretEphemeralPtr
                hashStateStatePtr
                hashStateBufOffPtr
                hashStateAlignPtr
                packet1Ptr
                peerPublicPtr
                myPublicStaticPtr
                mySecretStaticPtr
        in
        if result == 0 then
            do
            publicEphemeral <-
                B.packCStringLen (publicEphemeralPtr, kxPublicKeyBytes)
            secretEphemeral <-
                B.packCStringLen (secretEphemeralPtr, kxSecretKeyBytes)
            hashStateState <- Fa.peekArray 12 hashStateStatePtr

            hashStateBufOff <-
                Foreign.Storable.peek hashStateBufOffPtr
            hashStateAlign <- B.packCStringLen (hashStateAlignPtr, 3)
            packet1 <- B.packCStringLen (packet1Ptr, kxKkPacket1Bytes)
            let
                ephemeralKp =
                    KxKeypair
                        (KxPublicKey publicEphemeral)
                        (KxSecretKey secretEphemeral)
                hashState =
                    HashState
                        (HashStateState $
                            map fromIntegral hashStateState)
                        (HashStateBufOff $
                            fromIntegral hashStateBufOff)
                        (HashStateAlign hashStateAlign)
            return $
                Just
                    ( KxKkPacket1 packet1
                    , KxState ephemeralKp hashState
                    )
        else
            return Nothing


foreign import capi "hydrogen.h hydro_init"
    hydro_init :: IO Fc.CInt 


foreign import capi "hydrogen.h hydro_bin2hex"
    hydro_bin2hex
        :: F.Ptr Fc.CChar
        -> Fc.CSize
        -> F.Ptr Fc.CChar
        -> Fc.CSize
        -> IO (F.Ptr Fc.CChar)


bin2hex :: B.ByteString -> Data.Text.Text
bin2hex bin =
    let
    len = B.length bin
    in
    System.IO.Unsafe.unsafePerformIO $
    F.allocaBytes (len * 2 + 1) $ \hexPtr ->
    B.useAsCStringLen bin $ \(binPtr, _) ->
    do
    _ <- hydro_bin2hex
            hexPtr
            ((fromIntegral len) * 2 + 1)
            binPtr
            (fromIntegral len)
    hex <- B.packCString hexPtr
    case Data.Text.Encoding.decodeUtf8' hex of
        Left err ->
            error $ show err

        Right text ->
            return text


initialize :: IO (Either InitError InitOk)
initialize =
    do
    ret <- hydro_init
    return $
        if ret == 0 then
            Right InitOk

        else
            Left InitError


data InitError
    = InitError


instance Show InitError where
    show _ =
        "initialization error"


foreign import capi "wrappers.h hydro_kx_keygen_wrap"
    hydro_kx_keygen :: F.Ptr Fc.CChar -> F.Ptr Fc.CChar -> IO ()


foreign import capi "hydrogen.h value hydro_kx_PUBLICKEYBYTES"
    hydro_kx_PUBLICKEYBYTES :: Fc.CInt


kxPublicKeyBytes :: Int
kxPublicKeyBytes =
    fromIntegral hydro_kx_PUBLICKEYBYTES


foreign import capi "hydrogen.h value hydro_kx_SECRETKEYBYTES"
    hydro_kx_SECRETKEYBYTES :: Fc.CInt


kxSecretKeyBytes :: Int
kxSecretKeyBytes =
    fromIntegral hydro_kx_SECRETKEYBYTES


foreign import capi "hydrogen.h value hydro_kx_KK_PACKET1BYTES"
    hydro_kx_KK_PACKET1BYTES :: Fc.CInt


kxKkPacket1Bytes :: Int
kxKkPacket1Bytes =
    fromIntegral hydro_kx_KK_PACKET1BYTES


data InitOk
    = InitOk


kxKeygen :: InitOk -> IO KxKeypair
kxKeygen _ =
    F.allocaBytes kxPublicKeyBytes $ \publicPtr ->
    F.allocaBytes kxSecretKeyBytes $ \secretPtr ->
    do
    hydro_kx_keygen publicPtr secretPtr
    public <- B.packCStringLen (publicPtr, kxPublicKeyBytes)
    secret <- B.packCStringLen (secretPtr, kxSecretKeyBytes)
    return (KxKeypair (KxPublicKey public) (KxSecretKey secret))
