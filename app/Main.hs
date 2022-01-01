module Main where

import Lib

main :: IO ()
main =
    do
    res <- hydro_init
    print res
