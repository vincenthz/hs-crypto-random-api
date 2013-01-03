-- |
-- Module      : Crypto.Random.API
-- License     : BSD-style
-- Maintainer  : Vincent Hanquez <vincent@snarc.org>
-- Stability   : experimental
-- Portability : Good

module Crypto.Random.API
    ( CPRG(..)
    , ReseedPolicy(..)
    , genRandomBytes
    , withRandomBytes
    , getSystemEntropy
    ) where

import qualified Data.ByteString as B
import Data.ByteString (ByteString)
import System.Entropy (getEntropy)
-- | This is the reseed policy requested by the CPRG
data ReseedPolicy =
      NeverReseed          -- ^ there is no need to reseed as either
                           -- the RG doesn't supports it, it's done automatically
                           -- or pratically the reseeding period exceed a Word64 type.
    | ReseedInBytes Word64 -- ^ the RG need to be reseed in the number
                           -- of bytes joined to the type. it should be done before
                           -- the number reached 0, otherwise an user of the RG
                           -- might request too many bytes and get repeated random bytes.
    deriving (Show,Eq)

-- | A class of Cryptographic Secure Random generator.
--
-- The main difference with the generic haskell RNG is that
-- it return bytes instead of integer.
--
-- It is quite similar to the CryptoRandomGen class in crypto-api
-- except that error are not returned to the user. Instead
-- the user is suppose to handle reseeding by using the NeedReseed
-- and SupplyEntropy methods. For other type of errors, the user
-- is expected to generate bytes with the parameters bounds explicity
-- defined here.
-- 
-- The CPRG need to be able to generate up to 2^20 bytes in one call,
--
class CPRG g where
    -- | Provide a way to query the CPRG to calculate when new entropy
    -- is required to be supplied so the CPRG doesn't repeat output, and
    -- break assumptions. This returns the number of bytes before
    -- which supply entropy should have been called.
    cprgNeedReseed    :: g -> ReseedPolicy

    -- | Supply entropy to the CPRG, that can be used now or later
    -- to reseed the CPRG. This should be used in conjunction to
    -- NeedReseed to know when to supply entropy.
    cprgSupplyEntropy :: g -> ByteString -> g

    -- | Generate bytes using the CPRG and the number specified.
    --
    -- For user of the API, it's recommended to use genRandomBytes
    -- instead of this method directly.
    cprgGenBytes      :: g -> Int -> (ByteString, g)

-- | Generate bytes using the cprg in parameter.
-- 
-- arbitrary limit the number of bytes that can be generated in
-- one go to 10mb.
genRandomBytes :: CPRG g => g   -- ^ CPRG to use
                         -> Int -- ^ number of bytes to return
                         -> (ByteString, g)
genRandomBytes rng len
    | len < 0    = error "genBytes: cannot request negative amount of bytes."
    | len > 2^20 = error "genBytes: cannot request more than 1mb of bytes in one go."
    | len == 0   = (B.empty, rng)
    | otherwise  = cprgGenBytes rng len

-- | this is equivalent to using Control.Arrow 'first' with genBytes.
--
-- namely it generate @len bytes and map the bytes to the function @f
withRandomBytes :: CPRG g => g -> Int -> (ByteString -> a) -> (a, g)
withRandomBytes rng len f = (f bs, rng')
    where (bs, rng') = genRandomBytes rng len

-- | Return system entropy using the entropy package 'getEntropy'
getSystemEntropy :: Int -> IO ByteString
getSystemEntropy = getEntropy
