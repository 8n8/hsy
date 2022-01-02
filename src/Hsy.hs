{-# LANGUAGE ForeignFunctionInterface #-}
{-# LANGUAGE CApiFFI #-}

module Hsy
    ( initialize
    , kxKeygen
    , InitError
    , InitOk
    ) where


import qualified Foreign.C.Types as Fc
import qualified Foreign as F
import qualified Data.ByteArray as B


foreign import capi "hydrogen.h hydro_init"
    hydro_init :: IO Fc.CInt 


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
    deriving (Show, Eq)


foreign import capi "wrappers.h hydro_kx_keygen_wrap"
    hydro_kx_keygen :: F.Ptr Fc.CUChar -> F.Ptr Fc.CUChar -> IO ()


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


data InitOk
    = InitOk
    deriving (Show, Eq)


kxKeygen :: InitOk -> IO KeyPair
kxKeygen _ =
    do
    (secret, public) <-
        B.allocRet kxPublicKeyBytes $ \publicPtr ->
            (B.alloc kxSecretKeyBytes $ \secretPtr ->
                hydro_kx_keygen publicPtr secretPtr)
    return (SecretKey secret, PublicKey public)


type KeyPair
    = (SecretKey, PublicKey)


newtype SecretKey
    = SecretKey B.ScrubbedBytes
    deriving (Show, Eq)


newtype PublicKey
    = PublicKey B.ScrubbedBytes
    deriving (Show, Eq)
