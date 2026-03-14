// SPDX-License-Identifier: GPL-2.0-or-later
pragma solidity ^0.8.14;

/**
 * @title TickMath
 * @notice Computes sqrt price for ticks of size 1.0001, i.e., sqrt(1.0001^tick) as fixed-point Q64.96 numbers.
 *
 * @dev Key relationships:
 *      - price = 1.0001^tick
 *      - sqrtPrice = sqrt(1.0001^tick) = 1.0001^(tick/2)
 *      - sqrtPriceX96 = sqrtPrice * 2^96
 *
 *      The math uses binary decomposition of the tick to compute the power efficiently:
 *      1.0001^tick = 1.0001^(b0*1 + b1*2 + b2*4 + ... + b19*524288)
 *                  = product of 1.0001^(bi * 2^i) for each bit i that is set
 *
 *      Each factor 1.0001^(2^i) is a precomputed constant.
 *      This allows computing any tick's price in O(20) multiplications.
 *
 * Vulnerability surfaces:
 *      - Q64.96 overflow in intermediate computations
 *      - Off-by-one in tick boundaries (min/max tick)
 *      - Precision loss in the inverse function (getTickAtSqrtRatio)
 *      - These functions are called in hot paths (every swap step) — gas matters
 */
library TickMath {
    /// @dev The minimum tick that may be passed to #getSqrtRatioAtTick computed from log base 1.0001 of 2**-128
    int24 internal constant MIN_TICK = -887272;
    /// @dev The maximum tick that may be passed to #getSqrtRatioAtTick computed from log base 1.0001 of 2**128
    int24 internal constant MAX_TICK = -MIN_TICK;

    /// @dev The minimum value that can be returned from #getSqrtRatioAtTick. Equivalent to getSqrtRatioAtTick(MIN_TICK)
    uint160 internal constant MIN_SQRT_RATIO = 4295128739;
    /// @dev The maximum value that can be returned from #getSqrtRatioAtTick. Equivalent to getSqrtRatioAtTick(MAX_TICK)
    uint160 internal constant MAX_SQRT_RATIO = 1461446703485210103287273052203988822378723970342;

    /**
     * @notice Calculates sqrt(1.0001^tick) * 2^96.
     * @dev Throws if |tick| > MAX_TICK.
     *
     *      Algorithm: binary decomposition
     *      For tick = sum(bi * 2^i), compute product of precomputed ratios.
     *      Each ratio is sqrt(1.0001^(2^i)) * 2^128, using 128-bit fixed point internally,
     *      then shifting down to Q64.96 at the end.
     *
     * @param tick The input tick for the above formula
     * @return sqrtPriceX96 A Fixed point Q64.96 number representing the sqrt of the ratio of the two assets (token1/token0)
     */
    function getSqrtRatioAtTick(int24 tick) internal pure returns (uint160 sqrtPriceX96) {
        uint256 absTick = tick < 0 ? uint256(-int256(tick)) : uint256(int256(tick));
        require(absTick <= uint256(int256(MAX_TICK)), "T");

        // Start with ratio = 1.0 in Q128.128
        uint256 ratio = 0x100000000000000000000000000000000;

        // Precomputed constants: sqrt(1.0001^(2^i)) * 2^128
        // Each multiplication and right-shift maintains Q128.128 precision

        // bit 0: 1.0001^1 = 1.00005 (sqrt)
        if (absTick & 0x1 != 0) ratio = (ratio * 0xfffcb933bd6fad37aa2d162d1a594001) >> 128;
        // bit 1: 1.0001^2
        if (absTick & 0x2 != 0) ratio = (ratio * 0xfff97272373d413259a46990580e213a) >> 128;
        // bit 2: 1.0001^4
        if (absTick & 0x4 != 0) ratio = (ratio * 0xfff2e50f5f656932ef12357cf3c7fdcc) >> 128;
        // bit 3: 1.0001^8
        if (absTick & 0x8 != 0) ratio = (ratio * 0xffe5caca7e10e4e61c3624eaa0941cd0) >> 128;
        // bit 4: 1.0001^16
        if (absTick & 0x10 != 0) ratio = (ratio * 0xffcb9843d60f6159c9db58835c926644) >> 128;
        // bit 5: 1.0001^32
        if (absTick & 0x20 != 0) ratio = (ratio * 0xff973b41fa98c081472e6896dfb254c0) >> 128;
        // bit 6: 1.0001^64
        if (absTick & 0x40 != 0) ratio = (ratio * 0xff2ea16466c96a3843ec78b326b52861) >> 128;
        // bit 7: 1.0001^128
        if (absTick & 0x80 != 0) ratio = (ratio * 0xfe5dee046a99a2a811c461f1969c3053) >> 128;
        // bit 8: 1.0001^256
        if (absTick & 0x100 != 0) ratio = (ratio * 0xfcbe86c7900a88aedcffc83b479aa3a4) >> 128;
        // bit 9: 1.0001^512
        if (absTick & 0x200 != 0) ratio = (ratio * 0xf987a7253ac413176f2b074cf7815e54) >> 128;
        // bit 10: 1.0001^1024
        if (absTick & 0x400 != 0) ratio = (ratio * 0xf3392b0822b70005940c7a398e4b70f3) >> 128;
        // bit 11: 1.0001^2048
        if (absTick & 0x800 != 0) ratio = (ratio * 0xe7159475a2c29b7443b29c7fa6e889d9) >> 128;
        // bit 12: 1.0001^4096
        if (absTick & 0x1000 != 0) ratio = (ratio * 0xd097f3bdfd2022b8845ad8f792aa5825) >> 128;
        // bit 13: 1.0001^8192
        if (absTick & 0x2000 != 0) ratio = (ratio * 0xa9f746462d870fdf8a65dc1f90e061e5) >> 128;
        // bit 14: 1.0001^16384
        if (absTick & 0x4000 != 0) ratio = (ratio * 0x70d869a156d2a1b890bb3df62baf32f7) >> 128;
        // bit 15: 1.0001^32768
        if (absTick & 0x8000 != 0) ratio = (ratio * 0x31be135f97d08fd981231505542fcfa6) >> 128;
        // bit 16: 1.0001^65536
        if (absTick & 0x10000 != 0) ratio = (ratio * 0x9aa508b5b7a84e1c677de54f3e99bc9) >> 128;
        // bit 17: 1.0001^131072
        if (absTick & 0x20000 != 0) ratio = (ratio * 0x5d6af8dedb81196699c329225ee604) >> 128;
        // bit 18: 1.0001^262144
        if (absTick & 0x40000 != 0) ratio = (ratio * 0x2216e584f5fa1ea926041bedfe98) >> 128;
        // bit 19: 1.0001^524288
        if (absTick & 0x80000 != 0) ratio = (ratio * 0x48a170391f7dc42444e8fa2) >> 128;

        // If tick is positive, we computed 1/sqrtPrice; invert
        if (tick > 0) ratio = type(uint256).max / ratio;

        // Shift from Q128.128 to Q64.96, rounding up
        sqrtPriceX96 = uint160((ratio >> 32) + (ratio % (1 << 32) == 0 ? 0 : 1));
    }

    /**
     * @notice Calculates the greatest tick value such that getRatioAtTick(tick) <= ratio.
     * @dev Uses binary search on the most significant bit, then refines.
     *
     *      The algorithm:
     *      1. Find the most significant bit of ratio to get an initial tick estimate
     *      2. Refine by checking each bit position from high to low
     *
     *      This is the inverse of getSqrtRatioAtTick, and precision must match exactly
     *      to avoid off-by-one errors that could break tick crossing during swaps.
     *
     * @param sqrtPriceX96 The sqrt ratio for which to compute the tick as a Q64.96
     * @return tick The greatest tick for which the ratio is less than or equal to the input ratio
     */
    function getTickAtSqrtRatio(uint160 sqrtPriceX96) internal pure returns (int24 tick) {
        // Validate input is within bounds
        require(sqrtPriceX96 >= MIN_SQRT_RATIO && sqrtPriceX96 < MAX_SQRT_RATIO, "R");

        uint256 ratio = uint256(sqrtPriceX96) << 32;

        // Find the most significant bit using binary search
        uint256 r = ratio;
        uint256 msb = 0;

        // Each step: check if the upper half has bits set, shift accordingly
        assembly {
            let f := shl(7, gt(r, 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF))
            msb := or(msb, f)
            r := shr(f, r)
        }
        assembly {
            let f := shl(6, gt(r, 0xFFFFFFFFFFFFFFFF))
            msb := or(msb, f)
            r := shr(f, r)
        }
        assembly {
            let f := shl(5, gt(r, 0xFFFFFFFF))
            msb := or(msb, f)
            r := shr(f, r)
        }
        assembly {
            let f := shl(4, gt(r, 0xFFFF))
            msb := or(msb, f)
            r := shr(f, r)
        }
        assembly {
            let f := shl(3, gt(r, 0xFF))
            msb := or(msb, f)
            r := shr(f, r)
        }
        assembly {
            let f := shl(2, gt(r, 0xF))
            msb := or(msb, f)
            r := shr(f, r)
        }
        assembly {
            let f := shl(1, gt(r, 0x3))
            msb := or(msb, f)
            r := shr(f, r)
        }
        assembly {
            let f := gt(r, 0x1)
            msb := or(msb, f)
        }

        // Compute log_2(ratio) in Q128.128 fixed point
        int256 log_2;
        if (msb >= 128) {
            r = ratio >> (msb - 127);
        } else {
            r = ratio << (127 - msb);
        }

        log_2 = (int256(msb) - 128) << 128;

        // Refine: square and check 13 fractional bits
        assembly {
            r := shr(127, mul(r, r))
            let f := shr(128, r)
            log_2 := or(log_2, shl(63, f))
            r := shr(f, r)
        }
        assembly {
            r := shr(127, mul(r, r))
            let f := shr(128, r)
            log_2 := or(log_2, shl(62, f))
            r := shr(f, r)
        }
        assembly {
            r := shr(127, mul(r, r))
            let f := shr(128, r)
            log_2 := or(log_2, shl(61, f))
            r := shr(f, r)
        }
        assembly {
            r := shr(127, mul(r, r))
            let f := shr(128, r)
            log_2 := or(log_2, shl(60, f))
            r := shr(f, r)
        }
        assembly {
            r := shr(127, mul(r, r))
            let f := shr(128, r)
            log_2 := or(log_2, shl(59, f))
            r := shr(f, r)
        }
        assembly {
            r := shr(127, mul(r, r))
            let f := shr(128, r)
            log_2 := or(log_2, shl(58, f))
            r := shr(f, r)
        }
        assembly {
            r := shr(127, mul(r, r))
            let f := shr(128, r)
            log_2 := or(log_2, shl(57, f))
            r := shr(f, r)
        }

        // Convert log_2 to log_sqrt(1.0001) and then to tick
        // log_sqrt(1.0001) = log_2 * ln(2) / ln(sqrt(1.0001))
        int256 log_sqrt10001 = log_2 * 255738958999603826347141; // ln(2) / ln(sqrt(1.0001)) * 2^128

        // Compute tick bounds
        int24 tickLow = int24((log_sqrt10001 - 3402992956809132418596140100660247210) >> 128);
        int24 tickHi = int24((log_sqrt10001 + 291339464771989622907027621153398088495) >> 128);

        // Pick the correct tick
        tick = tickLow == tickHi ? tickLow : (getSqrtRatioAtTick(tickHi) <= sqrtPriceX96 ? tickHi : tickLow);
    }
}
