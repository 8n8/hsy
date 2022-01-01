{-# LANGUAGE ForeignFunctionInterface #-}
{-# LANGUAGE CApiFFI #-}

module Lib
    ( hydro_init
    ) where


import qualified Foreign.C.Types as F


foreign import capi "hydrogen.h hydro_init" hydro_init :: IO F.CInt 
