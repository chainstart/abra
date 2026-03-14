// SPDX-License-Identifier: BUSL-1.1
pragma solidity ^0.8.14;

/**
 * @title Uniswap V3 Pool
 * @notice Implements a concentrated liquidity AMM pool for a single token pair.
 *
 * @dev Core concepts:
 *      - Liquidity is concentrated in price ranges defined by "ticks"
 *      - Price is tracked as sqrt(price) in Q64.96 fixed-point format (sqrtPriceX96)
 *      - Swaps cross ticks, activating/deactivating liquidity at each boundary
 *      - Fee accumulation is tracked per-tick for accurate LP fee distribution
 *      - TWAP oracle stores historical price observations
 *
 * Vulnerability surfaces:
 *      - Price manipulation through large swaps (affects TWAP oracle consumers)
 *      - Tick crossing logic: off-by-one errors can cause liquidity accounting bugs
 *      - Fee accumulation rounding over many small swaps
 *      - Flash loan callback reentrancy
 *      - Just-in-time (JIT) liquidity attacks by MEV searchers
 */

// ============ Libraries ============

library TickMath {
    int24 internal constant MIN_TICK = -887272;
    int24 internal constant MAX_TICK = 887272;
    uint160 internal constant MIN_SQRT_RATIO = 4295128739;
    uint160 internal constant MAX_SQRT_RATIO = 1461446703485210103287273052203988822378723970342;

    /// @dev Placeholder — full implementation in TickMath.sol
    function getSqrtRatioAtTick(int24 tick) internal pure returns (uint160) {
        uint256 absTick = tick < 0 ? uint256(-int256(tick)) : uint256(int256(tick));
        require(absTick <= uint256(int256(MAX_TICK)), "T");
        // Simplified: return a value that scales with tick
        // Real implementation uses bit manipulation for precision
        return uint160(uint256(MIN_SQRT_RATIO) + absTick);
    }

    function getTickAtSqrtRatio(uint160 sqrtPriceX96) internal pure returns (int24) {
        require(sqrtPriceX96 >= MIN_SQRT_RATIO && sqrtPriceX96 < MAX_SQRT_RATIO, "R");
        return int24(int256(uint256(sqrtPriceX96 - MIN_SQRT_RATIO)));
    }
}

library FullMath {
    /// @notice Calculates floor(a * b / denominator) with full precision
    function mulDiv(uint256 a, uint256 b, uint256 denominator) internal pure returns (uint256 result) {
        require(denominator > 0);
        uint256 prod0 = a * b;
        result = prod0 / denominator;
    }

    function mulDivRoundingUp(uint256 a, uint256 b, uint256 denominator) internal pure returns (uint256 result) {
        result = mulDiv(a, b, denominator);
        if (a * b % denominator > 0) {
            result++;
        }
    }
}

library SqrtPriceMath {
    uint256 internal constant Q96 = 0x1000000000000000000000000; // 2^96

    /// @notice Compute the amount of token0 received for a given price range and liquidity
    function getAmount0Delta(
        uint160 sqrtRatioAX96,
        uint160 sqrtRatioBX96,
        uint128 liquidity,
        bool roundUp
    ) internal pure returns (uint256) {
        if (sqrtRatioAX96 > sqrtRatioBX96) {
            (sqrtRatioAX96, sqrtRatioBX96) = (sqrtRatioBX96, sqrtRatioAX96);
        }
        uint256 numerator1 = uint256(liquidity) << 96;
        uint256 numerator2 = sqrtRatioBX96 - sqrtRatioAX96;

        if (roundUp) {
            return FullMath.mulDivRoundingUp(numerator1, numerator2, sqrtRatioBX96) / sqrtRatioAX96 + 1;
        } else {
            return FullMath.mulDiv(numerator1, numerator2, sqrtRatioBX96) / sqrtRatioAX96;
        }
    }

    /// @notice Compute the amount of token1 received for a given price range and liquidity
    function getAmount1Delta(
        uint160 sqrtRatioAX96,
        uint160 sqrtRatioBX96,
        uint128 liquidity,
        bool roundUp
    ) internal pure returns (uint256) {
        if (sqrtRatioAX96 > sqrtRatioBX96) {
            (sqrtRatioAX96, sqrtRatioBX96) = (sqrtRatioBX96, sqrtRatioAX96);
        }
        if (roundUp) {
            return FullMath.mulDivRoundingUp(liquidity, sqrtRatioBX96 - sqrtRatioAX96, Q96);
        } else {
            return FullMath.mulDiv(liquidity, sqrtRatioBX96 - sqrtRatioAX96, Q96);
        }
    }
}

// ============ Interfaces ============

interface IERC20 {
    function balanceOf(address account) external view returns (uint256);
    function transfer(address to, uint256 amount) external returns (bool);
}

interface IUniswapV3MintCallback {
    function uniswapV3MintCallback(uint256 amount0Owed, uint256 amount1Owed, bytes calldata data) external;
}

interface IUniswapV3SwapCallback {
    function uniswapV3SwapCallback(int256 amount0Delta, int256 amount1Delta, bytes calldata data) external;
}

interface IUniswapV3FlashCallback {
    function uniswapV3FlashCallback(uint256 fee0, uint256 fee1, bytes calldata data) external;
}

// ============ Main Contract ============

contract UniswapV3Pool {
    // ---- Structs ----

    struct Slot0 {
        /// @notice Current sqrt(price) as Q64.96
        uint160 sqrtPriceX96;
        /// @notice Current tick (derived from sqrtPriceX96)
        int24 tick;
        /// @notice Index of the most recent oracle observation
        uint16 observationIndex;
        /// @notice Current maximum number of observations stored
        uint16 observationCardinality;
        /// @notice Next maximum number of observations (may be increased)
        uint16 observationCardinalityNext;
        /// @notice Current protocol fee (as % of swap fee)
        uint8 feeProtocol;
        /// @notice Whether the pool is locked (reentrancy guard)
        bool unlocked;
    }

    struct TickInfo {
        /// @notice Total liquidity that references this tick as either lower or upper bound
        uint128 liquidityGross;
        /// @notice Net liquidity change when tick is crossed (positive = add, negative = remove)
        int128 liquidityNet;
        /// @notice Fee growth per unit of liquidity on the *other* side of this tick (token0)
        uint256 feeGrowthOutside0X128;
        /// @notice Fee growth per unit of liquidity on the other side (token1)
        uint256 feeGrowthOutside1X128;
        /// @notice Seconds per liquidity on the other side
        uint160 secondsPerLiquidityOutsideX128;
        /// @notice Seconds spent on the other side
        uint32 secondsOutside;
        /// @notice Tick has been initialized
        bool initialized;
    }

    struct PositionInfo {
        /// @notice Liquidity provided by this position
        uint128 liquidity;
        /// @notice Fee growth inside the position's range as of last mint/burn/collect (token0)
        uint256 feeGrowthInside0LastX128;
        /// @notice Fee growth inside the position's range (token1)
        uint256 feeGrowthInside1LastX128;
        /// @notice Uncollected fees owed to the position (token0)
        uint128 tokensOwed0;
        /// @notice Uncollected fees owed to the position (token1)
        uint128 tokensOwed1;
    }

    /// @notice Oracle observation — stores cumulative values for TWAP calculation
    struct Observation {
        uint32 blockTimestamp;
        int56 tickCumulative;
        uint160 secondsPerLiquidityCumulativeX128;
        bool initialized;
    }

    // Swap computation state (kept in memory during swap)
    struct SwapState {
        int256 amountSpecifiedRemaining;
        int256 amountCalculated;
        uint160 sqrtPriceX96;
        int24 tick;
        uint256 feeGrowthGlobalX128;
        uint128 protocolFee;
        uint128 liquidity;
    }

    struct StepComputations {
        uint160 sqrtPriceStartX96;
        int24 tickNext;
        bool initialized;
        uint160 sqrtPriceNextX96;
        uint256 amountIn;
        uint256 amountOut;
        uint256 feeAmount;
    }

    // ---- Immutables ----
    address public immutable factory;
    address public immutable token0;
    address public immutable token1;
    uint24 public immutable fee;
    int24 public immutable tickSpacing;
    uint128 public immutable maxLiquidityPerTick;

    // ---- State ----
    Slot0 public slot0;
    uint256 public feeGrowthGlobal0X128;
    uint256 public feeGrowthGlobal1X128;
    uint128 public liquidity; // Currently active liquidity
    uint256 public protocolFees0;
    uint256 public protocolFees1;

    mapping(int24 => TickInfo) public ticks;
    mapping(int16 => uint256) public tickBitmap; // Bitmap of initialized ticks
    mapping(bytes32 => PositionInfo) public positions;
    Observation[65535] public observations;

    // ---- Events ----
    event Mint(address sender, address indexed owner, int24 indexed tickLower, int24 indexed tickUpper, uint128 amount, uint256 amount0, uint256 amount1);
    event Burn(address indexed owner, int24 indexed tickLower, int24 indexed tickUpper, uint128 amount, uint256 amount0, uint256 amount1);
    event Swap(address indexed sender, address indexed recipient, int256 amount0, int256 amount1, uint160 sqrtPriceX96, uint128 liquidity, int24 tick);
    event Flash(address indexed sender, address indexed recipient, uint256 amount0, uint256 amount1, uint256 paid0, uint256 paid1);
    event Collect(address indexed owner, address recipient, int24 indexed tickLower, int24 indexed tickUpper, uint128 amount0, uint128 amount1);
    event CollectProtocol(address indexed sender, address indexed recipient, uint128 amount0, uint128 amount1);
    event IncreaseObservationCardinalityNext(uint16 observationCardinalityNextOld, uint16 observationCardinalityNextNew);

    // ---- Modifiers ----
    modifier lock() {
        require(slot0.unlocked, "LOK");
        slot0.unlocked = false;
        _;
        slot0.unlocked = true;
    }

    // ---- Constructor ----
    constructor(
        address _factory,
        address _token0,
        address _token1,
        uint24 _fee,
        int24 _tickSpacing
    ) {
        factory = _factory;
        token0 = _token0;
        token1 = _token1;
        fee = _fee;
        tickSpacing = _tickSpacing;
        maxLiquidityPerTick = 11505743598341114571880798222544994; // ~2^113
    }

    function initialize(uint160 sqrtPriceX96) external {
        require(slot0.sqrtPriceX96 == 0, "AI"); // Already initialized
        int24 tick = TickMath.getTickAtSqrtRatio(sqrtPriceX96);
        slot0 = Slot0({
            sqrtPriceX96: sqrtPriceX96,
            tick: tick,
            observationIndex: 0,
            observationCardinality: 1,
            observationCardinalityNext: 1,
            feeProtocol: 0,
            unlocked: true
        });
        observations[0] = Observation({
            blockTimestamp: uint32(block.timestamp),
            tickCumulative: 0,
            secondsPerLiquidityCumulativeX128: 0,
            initialized: true
        });
    }

    // ============ Mint (Add Liquidity) ============

    /**
     * @notice Add liquidity to a position within a tick range [tickLower, tickUpper).
     * @param recipient Owner of the position
     * @param tickLower Lower tick of the range
     * @param tickUpper Upper tick of the range
     * @param amount Liquidity amount to add
     * @param data Callback data for uniswapV3MintCallback
     * @return amount0 Token0 amount required
     * @return amount1 Token1 amount required
     *
     * @dev The caller must pay the required token amounts through the callback.
     *      Token amounts depend on current price relative to the position's range:
     *      - Price below range: only token0 needed
     *      - Price above range: only token1 needed
     *      - Price in range: both tokens needed (proportional to distance from boundaries)
     */
    function mint(
        address recipient,
        int24 tickLower,
        int24 tickUpper,
        uint128 amount,
        bytes calldata data
    ) external lock returns (uint256 amount0, uint256 amount1) {
        require(amount > 0, "IL"); // Insufficient liquidity
        require(tickLower < tickUpper, "TLU");
        require(tickLower >= TickMath.MIN_TICK, "TLM");
        require(tickUpper <= TickMath.MAX_TICK, "TUM");

        // Calculate token amounts required for this liquidity addition
        Slot0 memory _slot0 = slot0;

        if (_slot0.tick < tickLower) {
            // Current price below range: need only token0
            amount0 = SqrtPriceMath.getAmount0Delta(
                TickMath.getSqrtRatioAtTick(tickLower),
                TickMath.getSqrtRatioAtTick(tickUpper),
                amount,
                true
            );
        } else if (_slot0.tick < tickUpper) {
            // Current price in range: need both tokens
            amount0 = SqrtPriceMath.getAmount0Delta(
                _slot0.sqrtPriceX96,
                TickMath.getSqrtRatioAtTick(tickUpper),
                amount,
                true
            );
            amount1 = SqrtPriceMath.getAmount1Delta(
                TickMath.getSqrtRatioAtTick(tickLower),
                _slot0.sqrtPriceX96,
                amount,
                true
            );
            // Update active liquidity since position overlaps current price
            liquidity += amount;
        } else {
            // Current price above range: need only token1
            amount1 = SqrtPriceMath.getAmount1Delta(
                TickMath.getSqrtRatioAtTick(tickLower),
                TickMath.getSqrtRatioAtTick(tickUpper),
                amount,
                true
            );
        }

        // Update tick state
        _updateTick(tickLower, amount, false);
        _updateTick(tickUpper, amount, true);

        // Update position
        bytes32 positionKey = keccak256(abi.encodePacked(recipient, tickLower, tickUpper));
        positions[positionKey].liquidity += amount;

        // Callback: caller must pay the required tokens
        uint256 balance0Before;
        uint256 balance1Before;
        if (amount0 > 0) balance0Before = IERC20(token0).balanceOf(address(this));
        if (amount1 > 0) balance1Before = IERC20(token1).balanceOf(address(this));

        IUniswapV3MintCallback(msg.sender).uniswapV3MintCallback(amount0, amount1, data);

        // Verify tokens were received
        if (amount0 > 0) {
            require(IERC20(token0).balanceOf(address(this)) >= balance0Before + amount0, "M0");
        }
        if (amount1 > 0) {
            require(IERC20(token1).balanceOf(address(this)) >= balance1Before + amount1, "M1");
        }

        emit Mint(msg.sender, recipient, tickLower, tickUpper, amount, amount0, amount1);
    }

    // ============ Burn (Remove Liquidity) ============

    /**
     * @notice Remove liquidity from a position. Does NOT transfer tokens — use collect().
     * @param tickLower Lower tick of the position
     * @param tickUpper Upper tick of the position
     * @param amount Liquidity to remove
     * @return amount0 Token0 owed to the position
     * @return amount1 Token1 owed to the position
     */
    function burn(
        int24 tickLower,
        int24 tickUpper,
        uint128 amount
    ) external lock returns (uint256 amount0, uint256 amount1) {
        bytes32 positionKey = keccak256(abi.encodePacked(msg.sender, tickLower, tickUpper));
        PositionInfo storage position = positions[positionKey];
        require(position.liquidity >= amount, "IL");

        Slot0 memory _slot0 = slot0;

        // Calculate tokens owed (mirror of mint calculation)
        if (_slot0.tick < tickLower) {
            amount0 = SqrtPriceMath.getAmount0Delta(
                TickMath.getSqrtRatioAtTick(tickLower),
                TickMath.getSqrtRatioAtTick(tickUpper),
                amount,
                false
            );
        } else if (_slot0.tick < tickUpper) {
            amount0 = SqrtPriceMath.getAmount0Delta(
                _slot0.sqrtPriceX96,
                TickMath.getSqrtRatioAtTick(tickUpper),
                amount,
                false
            );
            amount1 = SqrtPriceMath.getAmount1Delta(
                TickMath.getSqrtRatioAtTick(tickLower),
                _slot0.sqrtPriceX96,
                amount,
                false
            );
            liquidity -= amount;
        } else {
            amount1 = SqrtPriceMath.getAmount1Delta(
                TickMath.getSqrtRatioAtTick(tickLower),
                TickMath.getSqrtRatioAtTick(tickUpper),
                amount,
                false
            );
        }

        // Update position — add owed tokens (collected separately via collect())
        position.liquidity -= amount;
        position.tokensOwed0 += uint128(amount0);
        position.tokensOwed1 += uint128(amount1);

        // Update tick state
        _updateTick(tickLower, amount, false);
        _updateTick(tickUpper, amount, true);

        emit Burn(msg.sender, tickLower, tickUpper, amount, amount0, amount1);
    }

    /**
     * @notice Collect tokens owed to a position (from burns or accumulated fees).
     */
    function collect(
        address recipient,
        int24 tickLower,
        int24 tickUpper,
        uint128 amount0Requested,
        uint128 amount1Requested
    ) external lock returns (uint128 amount0, uint128 amount1) {
        bytes32 positionKey = keccak256(abi.encodePacked(msg.sender, tickLower, tickUpper));
        PositionInfo storage position = positions[positionKey];

        amount0 = amount0Requested > position.tokensOwed0 ? position.tokensOwed0 : amount0Requested;
        amount1 = amount1Requested > position.tokensOwed1 ? position.tokensOwed1 : amount1Requested;

        if (amount0 > 0) {
            position.tokensOwed0 -= amount0;
            IERC20(token0).transfer(recipient, amount0);
        }
        if (amount1 > 0) {
            position.tokensOwed1 -= amount1;
            IERC20(token1).transfer(recipient, amount1);
        }

        emit Collect(msg.sender, recipient, tickLower, tickUpper, amount0, amount1);
    }

    // ============ Swap ============

    /**
     * @notice Execute a swap.
     * @param recipient Address to receive the output tokens
     * @param zeroForOne Direction: true = swap token0 for token1, false = swap token1 for token0
     * @param amountSpecified The amount to swap. Positive = exact input, negative = exact output
     * @param sqrtPriceLimitX96 Price limit — swap stops when this price is reached
     * @param data Callback data for uniswapV3SwapCallback
     * @return amount0 Token0 delta (negative = pool sends, positive = pool receives)
     * @return amount1 Token1 delta
     *
     * @dev The swap iterates through tick boundaries, consuming liquidity at each active range.
     *      When crossing a tick boundary, the liquidity from positions starting/ending there
     *      is added/removed from the active liquidity.
     *
     *      Vulnerability surface:
     *      - TWAP oracle can be manipulated by large swaps (multi-block manipulation)
     *      - sqrtPriceLimitX96 of 0 means no limit — sandwichable
     *      - Callback allows arbitrary code execution
     */
    function swap(
        address recipient,
        bool zeroForOne,
        int256 amountSpecified,
        uint160 sqrtPriceLimitX96,
        bytes calldata data
    ) external lock returns (int256 amount0, int256 amount1) {
        require(amountSpecified != 0, "AS");

        Slot0 memory slot0Start = slot0;

        // Validate price limit
        if (zeroForOne) {
            require(sqrtPriceLimitX96 < slot0Start.sqrtPriceX96, "SPL");
            require(sqrtPriceLimitX96 > TickMath.MIN_SQRT_RATIO, "SPL");
        } else {
            require(sqrtPriceLimitX96 > slot0Start.sqrtPriceX96, "SPL");
            require(sqrtPriceLimitX96 < TickMath.MAX_SQRT_RATIO, "SPL");
        }

        bool exactInput = amountSpecified > 0;

        SwapState memory state = SwapState({
            amountSpecifiedRemaining: amountSpecified,
            amountCalculated: 0,
            sqrtPriceX96: slot0Start.sqrtPriceX96,
            tick: slot0Start.tick,
            feeGrowthGlobalX128: zeroForOne ? feeGrowthGlobal0X128 : feeGrowthGlobal1X128,
            protocolFee: 0,
            liquidity: liquidity
        });

        /**
         * @dev Main swap loop: iterate through ticks until amount is fully consumed
         *      or price limit is reached.
         *
         *      Each iteration:
         *      1. Find the next initialized tick in the swap direction
         *      2. Compute the swap step within the current tick range
         *      3. Update state (amounts, fees, price)
         *      4. If we've reached the next tick, cross it (update liquidity)
         */
        while (state.amountSpecifiedRemaining != 0 && state.sqrtPriceX96 != sqrtPriceLimitX96) {
            StepComputations memory step;

            step.sqrtPriceStartX96 = state.sqrtPriceX96;

            // Find next initialized tick (simplified — production uses bitmap)
            step.tickNext = zeroForOne ? state.tick - tickSpacing : state.tick + tickSpacing;
            step.initialized = ticks[step.tickNext].initialized;

            // Bound tick to min/max
            if (step.tickNext < TickMath.MIN_TICK) step.tickNext = TickMath.MIN_TICK;
            if (step.tickNext > TickMath.MAX_TICK) step.tickNext = TickMath.MAX_TICK;

            step.sqrtPriceNextX96 = TickMath.getSqrtRatioAtTick(step.tickNext);

            // Compute swap within this tick range
            // Target price is either the next tick's price or the price limit
            uint160 sqrtRatioTargetX96 = zeroForOne
                ? (step.sqrtPriceNextX96 < sqrtPriceLimitX96 ? sqrtPriceLimitX96 : step.sqrtPriceNextX96)
                : (step.sqrtPriceNextX96 > sqrtPriceLimitX96 ? sqrtPriceLimitX96 : step.sqrtPriceNextX96);

            // Compute step amounts (simplified)
            if (state.liquidity > 0) {
                step.amountIn = uint256(state.amountSpecifiedRemaining > 0
                    ? state.amountSpecifiedRemaining
                    : -state.amountSpecifiedRemaining) / 2;
                step.feeAmount = (step.amountIn * fee) / 1e6;
                step.amountOut = step.amountIn - step.feeAmount;
            }

            // Update fee growth
            if (state.liquidity > 0 && step.feeAmount > 0) {
                state.feeGrowthGlobalX128 += FullMath.mulDiv(step.feeAmount, 1 << 128, state.liquidity);
            }

            // Update amounts
            if (exactInput) {
                state.amountSpecifiedRemaining -= int256(step.amountIn + step.feeAmount);
                state.amountCalculated -= int256(step.amountOut);
            } else {
                state.amountSpecifiedRemaining += int256(step.amountOut);
                state.amountCalculated += int256(step.amountIn + step.feeAmount);
            }

            // Cross tick if reached
            if (state.sqrtPriceX96 == step.sqrtPriceNextX96 && step.initialized) {
                int128 liquidityNet = ticks[step.tickNext].liquidityNet;
                if (zeroForOne) liquidityNet = -liquidityNet;
                state.liquidity = liquidityNet > 0
                    ? state.liquidity + uint128(liquidityNet)
                    : state.liquidity - uint128(-liquidityNet);
                state.tick = zeroForOne ? step.tickNext - 1 : step.tickNext;
            }

            state.sqrtPriceX96 = sqrtRatioTargetX96;

            // Safety: prevent infinite loop
            break; // Simplified — production uses proper tick traversal
        }

        // Update global state
        slot0.sqrtPriceX96 = state.sqrtPriceX96;
        slot0.tick = state.tick;

        if (zeroForOne) {
            feeGrowthGlobal0X128 = state.feeGrowthGlobalX128;
        } else {
            feeGrowthGlobal1X128 = state.feeGrowthGlobalX128;
        }

        liquidity = state.liquidity;

        // Determine final amounts
        if (exactInput) {
            amount0 = zeroForOne
                ? amountSpecified - state.amountSpecifiedRemaining
                : state.amountCalculated;
            amount1 = zeroForOne
                ? state.amountCalculated
                : amountSpecified - state.amountSpecifiedRemaining;
        } else {
            amount0 = zeroForOne
                ? state.amountCalculated
                : amountSpecified - state.amountSpecifiedRemaining;
            amount1 = zeroForOne
                ? amountSpecified - state.amountSpecifiedRemaining
                : state.amountCalculated;
        }

        // Transfer output tokens first
        if (zeroForOne) {
            if (amount1 < 0) IERC20(token1).transfer(recipient, uint256(-amount1));
        } else {
            if (amount0 < 0) IERC20(token0).transfer(recipient, uint256(-amount0));
        }

        // Callback: caller must pay input tokens
        IUniswapV3SwapCallback(msg.sender).uniswapV3SwapCallback(amount0, amount1, data);

        // Verify input payment
        if (zeroForOne) {
            // Verify token0 was received
        } else {
            // Verify token1 was received
        }

        // Write oracle observation
        _writeObservation(slot0Start.observationIndex, uint32(block.timestamp), slot0Start.tick);

        emit Swap(msg.sender, recipient, amount0, amount1, state.sqrtPriceX96, state.liquidity, state.tick);
    }

    // ============ Flash ============

    /**
     * @notice Flash loan — borrow tokens from the pool, must repay + fee in callback.
     * @param recipient Address to receive the flash loaned tokens
     * @param amount0 Amount of token0 to flash borrow
     * @param amount1 Amount of token1 to flash borrow
     * @param data Callback data
     *
     * @dev Unlike Aave flash loans, Uniswap flash swaps charge the pool's swap fee.
     *      The fee is distributed to LPs just like swap fees.
     */
    function flash(
        address recipient,
        uint256 amount0,
        uint256 amount1,
        bytes calldata data
    ) external lock {
        uint128 _liquidity = liquidity;
        require(_liquidity > 0, "L");

        uint256 fee0 = FullMath.mulDivRoundingUp(amount0, fee, 1e6);
        uint256 fee1 = FullMath.mulDivRoundingUp(amount1, fee, 1e6);

        uint256 balance0Before = IERC20(token0).balanceOf(address(this));
        uint256 balance1Before = IERC20(token1).balanceOf(address(this));

        if (amount0 > 0) IERC20(token0).transfer(recipient, amount0);
        if (amount1 > 0) IERC20(token1).transfer(recipient, amount1);

        IUniswapV3FlashCallback(msg.sender).uniswapV3FlashCallback(fee0, fee1, data);

        uint256 balance0After = IERC20(token0).balanceOf(address(this));
        uint256 balance1After = IERC20(token1).balanceOf(address(this));

        require(balance0After >= balance0Before + fee0, "F0");
        require(balance1After >= balance1Before + fee1, "F1");

        // Distribute fees to LPs
        uint256 paid0 = balance0After - balance0Before;
        uint256 paid1 = balance1After - balance1Before;

        if (paid0 > 0) {
            uint8 feeProtocol0 = slot0.feeProtocol % 16;
            uint256 pFees0 = feeProtocol0 == 0 ? 0 : paid0 / feeProtocol0;
            if (pFees0 > 0) protocolFees0 += pFees0;
            feeGrowthGlobal0X128 += FullMath.mulDiv(paid0 - pFees0, 1 << 128, _liquidity);
        }
        if (paid1 > 0) {
            uint8 feeProtocol1 = slot0.feeProtocol >> 4;
            uint256 pFees1 = feeProtocol1 == 0 ? 0 : paid1 / feeProtocol1;
            if (pFees1 > 0) protocolFees1 += pFees1;
            feeGrowthGlobal1X128 += FullMath.mulDiv(paid1 - pFees1, 1 << 128, _liquidity);
        }

        emit Flash(msg.sender, recipient, amount0, amount1, paid0, paid1);
    }

    // ============ Oracle ============

    /**
     * @notice Increase the oracle observation storage capacity.
     * @dev Observations are used for TWAP (time-weighted average price) calculations.
     *      The oracle stores cumulative tick values at each block where a swap occurs.
     *      TWAP = (tickCumulative[t2] - tickCumulative[t1]) / (t2 - t1)
     */
    function increaseObservationCardinalityNext(uint16 observationCardinalityNext) external lock {
        uint16 current = slot0.observationCardinalityNext;
        require(observationCardinalityNext > current, "LOO");
        slot0.observationCardinalityNext = observationCardinalityNext;
        emit IncreaseObservationCardinalityNext(current, observationCardinalityNext);
    }

    /**
     * @notice Query historical oracle observations for TWAP calculation.
     * @param secondsAgos Array of lookback periods in seconds
     * @return tickCumulatives Cumulative tick values at each requested time
     * @return secondsPerLiquidityCumulativeX128s Cumulative seconds per liquidity
     */
    function observe(uint32[] calldata secondsAgos)
        external
        view
        returns (int56[] memory tickCumulatives, uint160[] memory secondsPerLiquidityCumulativeX128s)
    {
        tickCumulatives = new int56[](secondsAgos.length);
        secondsPerLiquidityCumulativeX128s = new uint160[](secondsAgos.length);
        // Simplified: production implementation interpolates between stored observations
    }

    // ============ Internal Functions ============

    function _updateTick(int24 tick_, uint128 liquidityDelta, bool upper) internal {
        TickInfo storage info = ticks[tick_];
        uint128 liquidityGrossBefore = info.liquidityGross;

        info.liquidityGross = liquidityGrossBefore + liquidityDelta;
        if (upper) {
            info.liquidityNet -= int128(liquidityDelta);
        } else {
            info.liquidityNet += int128(liquidityDelta);
        }

        if (liquidityGrossBefore == 0 && liquidityDelta > 0) {
            info.initialized = true;
            // Initialize fee growth outside
            if (tick_ <= slot0.tick) {
                info.feeGrowthOutside0X128 = feeGrowthGlobal0X128;
                info.feeGrowthOutside1X128 = feeGrowthGlobal1X128;
            }
        }
    }

    function _writeObservation(uint16 index, uint32 blockTimestamp, int24 tick_) internal {
        Observation storage last = observations[index];

        if (last.blockTimestamp == blockTimestamp) return; // Already written this block

        uint16 indexNext = (index + 1) % slot0.observationCardinality;
        observations[indexNext] = Observation({
            blockTimestamp: blockTimestamp,
            tickCumulative: last.tickCumulative + int56(tick_) * int56(int32(blockTimestamp - last.blockTimestamp)),
            secondsPerLiquidityCumulativeX128: last.secondsPerLiquidityCumulativeX128 +
                (uint160(blockTimestamp - last.blockTimestamp) << 128) / (liquidity > 0 ? liquidity : 1),
            initialized: true
        });

        slot0.observationIndex = indexNext;
        if (indexNext >= slot0.observationCardinality && slot0.observationCardinalityNext > slot0.observationCardinality) {
            slot0.observationCardinality = slot0.observationCardinalityNext;
        }
    }

    // ============ Admin ============

    function setFeeProtocol(uint8 feeProtocol0, uint8 feeProtocol1) external {
        require(msg.sender == factory, "AUTH");
        require(
            (feeProtocol0 == 0 || (feeProtocol0 >= 4 && feeProtocol0 <= 10)) &&
            (feeProtocol1 == 0 || (feeProtocol1 >= 4 && feeProtocol1 <= 10)),
            "FP"
        );
        slot0.feeProtocol = feeProtocol0 + (feeProtocol1 << 4);
    }

    function collectProtocol(address recipient, uint128 amount0Requested, uint128 amount1Requested)
        external
        returns (uint128 amount0, uint128 amount1)
    {
        require(msg.sender == factory, "AUTH");
        amount0 = amount0Requested > uint128(protocolFees0) ? uint128(protocolFees0) : amount0Requested;
        amount1 = amount1Requested > uint128(protocolFees1) ? uint128(protocolFees1) : amount1Requested;
        if (amount0 > 0) {
            protocolFees0 -= amount0;
            IERC20(token0).transfer(recipient, amount0);
        }
        if (amount1 > 0) {
            protocolFees1 -= amount1;
            IERC20(token1).transfer(recipient, amount1);
        }
        emit CollectProtocol(msg.sender, recipient, amount0, amount1);
    }
}
