module Main (main) where

import qualified Hsy

main :: IO ()
main =
    do
    res <- Hsy.initialize
    case res of
        Left err ->
            print err

        Right ok ->
            do
            keypair <- Hsy.kxKeygen ok
            print keypair
