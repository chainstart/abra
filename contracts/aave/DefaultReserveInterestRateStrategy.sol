// SPDX-License-Identifier: BUSL-1.1
pragma solidity ^0.8.10;

/**
 * @title DefaultReserveInterestRateStrategy
 * @notice Implements the interest rate model for Aave V3 reserves.
 *
 * @dev The model uses a two-slope curve:
 *      - Below optimal utilization: rates increase linearly at a gentle slope
 *      - Above optimal utilization: rates increase steeply to discourage over-borrowing
 *
 *      Rate curve:
 *      if U <= U_optimal:
 *          R_variable = R_base + (U / U_optimal) * R_slope1
 *      else:
 *          R_variable = R_base + R_slope1 + ((U - U_optimal) / (1 - U_optimal)) * R_slope2
 *
 *      where U = utilization = totalDebt / totalLiquidity
 *
 *      This creates a kink in the rate curve at U_optimal (typically 80-90%).
 *
 * Vulnerability surfaces:
 *      - Rate manipulation through large supply/borrow in same block
 *      - Precision loss in ray math at extreme utilization values
 *      - Stable rate rebalancing can be gamed if conditions are predictable
 */

library WadRayMath {
    uint256 internal constant RAY = 1e27;
    uint256 internal constant HALF_RAY = RAY / 2;

    function rayMul(uint256 a, uint256 b) internal pure returns (uint256) {
        return (a * b + HALF_RAY) / RAY;
    }

    function rayDiv(uint256 a, uint256 b) internal pure returns (uint256) {
        return (a * RAY + b / 2) / b;
    }
}

library PercentageMath {
    uint256 internal constant PERCENTAGE_FACTOR = 1e4;

    function percentMul(uint256 value, uint256 percentage) internal pure returns (uint256) {
        return (value * percentage + PERCENTAGE_FACTOR / 2) / PERCENTAGE_FACTOR;
    }
}

interface IPoolAddressesProvider {
    function getPool() external view returns (address);
}

contract DefaultReserveInterestRateStrategy {
    using WadRayMath for uint256;
    using PercentageMath for uint256;

    // ---- Constants ----
    uint256 public constant MAX_EXCESS_USAGE_RATIO = 1e27; // 100% in RAY
    uint256 public constant MAX_EXCESS_STABLE_TO_TOTAL_DEBT_RATIO = 1e27;

    // ---- Immutable Parameters ----

    /// @notice Optimal utilization rate (ray). Typically 0.8e27 = 80%
    uint256 public immutable OPTIMAL_USAGE_RATIO;

    /// @notice = 1 - OPTIMAL_USAGE_RATIO, cached for gas savings
    uint256 public immutable MAX_EXCESS_USAGE_RATIO_CACHED;

    /// @notice Optimal ratio of stable debt to total debt
    uint256 public immutable OPTIMAL_STABLE_TO_TOTAL_DEBT_RATIO;

    /// @notice Base variable borrow rate (ray). Rate when utilization = 0
    uint256 public immutable BASE_VARIABLE_BORROW_RATE;

    /// @notice Variable rate slope below optimal utilization
    uint256 public immutable VARIABLE_RATE_SLOPE_1;

    /// @notice Variable rate slope above optimal utilization (steep)
    uint256 public immutable VARIABLE_RATE_SLOPE_2;

    /// @notice Stable rate slope below optimal utilization
    uint256 public immutable STABLE_RATE_SLOPE_1;

    /// @notice Stable rate slope above optimal utilization
    uint256 public immutable STABLE_RATE_SLOPE_2;

    /// @notice Base stable borrow rate offset over the market rate
    uint256 public immutable BASE_STABLE_BORROW_RATE;

    /// @notice Premium over variable rate applied to stable rate
    uint256 public immutable STABLE_RATE_EXCESS_OFFSET;

    IPoolAddressesProvider public immutable ADDRESSES_PROVIDER;

    // ---- Constructor ----
    constructor(
        address provider,
        uint256 optimalUsageRatio,
        uint256 baseVariableBorrowRate,
        uint256 variableRateSlope1,
        uint256 variableRateSlope2,
        uint256 stableRateSlope1,
        uint256 stableRateSlope2,
        uint256 baseStableRateOffset,
        uint256 stableRateExcessOffset,
        uint256 optimalStableToTotalDebtRatio
    ) {
        require(optimalUsageRatio <= WadRayMath.RAY, "INVALID_OPTIMAL_USAGE_RATIO");

        ADDRESSES_PROVIDER = IPoolAddressesProvider(provider);
        OPTIMAL_USAGE_RATIO = optimalUsageRatio;
        MAX_EXCESS_USAGE_RATIO_CACHED = WadRayMath.RAY - optimalUsageRatio;
        OPTIMAL_STABLE_TO_TOTAL_DEBT_RATIO = optimalStableToTotalDebtRatio;
        BASE_VARIABLE_BORROW_RATE = baseVariableBorrowRate;
        VARIABLE_RATE_SLOPE_1 = variableRateSlope1;
        VARIABLE_RATE_SLOPE_2 = variableRateSlope2;
        STABLE_RATE_SLOPE_1 = stableRateSlope1;
        STABLE_RATE_SLOPE_2 = stableRateSlope2;
        BASE_STABLE_BORROW_RATE = baseStableRateOffset;
        STABLE_RATE_EXCESS_OFFSET = stableRateExcessOffset;
    }

    // ============ Rate Calculation ============

    /**
     * @notice Calculate interest rates for a reserve based on current state.
     * @param totalStableDebt Total outstanding stable rate debt
     * @param totalVariableDebt Total outstanding variable rate debt
     * @param averageStableBorrowRate Weighted average stable borrow rate
     * @param reserveFactor Reserve factor (percentage of interest going to protocol)
     * @param reserve Address of the reserve's underlying asset
     * @param aToken Address of the reserve's aToken
     * @return currentLiquidityRate Rate earned by suppliers (ray)
     * @return currentStableBorrowRate Stable borrow rate (ray)
     * @return currentVariableBorrowRate Variable borrow rate (ray)
     *
     * @dev The liquidity rate is derived from the borrow rates:
     *      liquidityRate = overallBorrowRate * utilizationRate * (1 - reserveFactor)
     *      This ensures that supplier yield = borrower cost * utilization * (1 - protocol cut)
     */
    function calculateInterestRates(
        uint256 totalStableDebt,
        uint256 totalVariableDebt,
        uint256 averageStableBorrowRate,
        uint256 reserveFactor,
        address reserve,
        address aToken
    ) external view returns (
        uint256 currentLiquidityRate,
        uint256 currentStableBorrowRate,
        uint256 currentVariableBorrowRate
    ) {
        uint256 totalDebt = totalStableDebt + totalVariableDebt;

        // Available liquidity = underlying balance held by the aToken
        // NOTE: In production this uses IERC20(reserve).balanceOf(aToken)
        // which means any direct transfers to the aToken affect the rate calculation
        uint256 availableLiquidity = 100e18; // Placeholder

        uint256 totalLiquidity = availableLiquidity + totalDebt;

        // Calculate utilization rate
        uint256 utilizationRate = totalDebt == 0
            ? 0
            : totalDebt.rayDiv(totalLiquidity);

        // ---- Variable Rate Calculation ----
        currentVariableBorrowRate = _calcVariableRate(utilizationRate);

        // ---- Stable Rate Calculation ----
        currentStableBorrowRate = _calcStableRate(
            utilizationRate,
            totalStableDebt,
            totalDebt,
            currentVariableBorrowRate
        );

        // ---- Liquidity (Supply) Rate ----
        // Overall borrow rate = weighted average of stable and variable rates
        uint256 overallBorrowRate;
        if (totalDebt > 0) {
            uint256 weightedVariableRate = currentVariableBorrowRate.rayMul(totalVariableDebt);
            uint256 weightedStableRate = averageStableBorrowRate.rayMul(totalStableDebt);
            overallBorrowRate = (weightedVariableRate + weightedStableRate).rayDiv(totalDebt);
        }

        /**
         * @dev Supply rate = overallBorrowRate * utilizationRate * (1 - reserveFactor)
         *
         * Key insight: suppliers only earn on the utilized portion of their deposits.
         * The reserveFactor (e.g., 10%) goes to the protocol treasury.
         */
        currentLiquidityRate = overallBorrowRate
            .rayMul(utilizationRate)
            .percentMul(PercentageMath.PERCENTAGE_FACTOR - reserveFactor);
    }

    /**
     * @dev Calculate variable borrow rate using the two-slope model.
     */
    function _calcVariableRate(uint256 utilizationRate) internal view returns (uint256) {
        uint256 rate = BASE_VARIABLE_BORROW_RATE;

        if (utilizationRate <= OPTIMAL_USAGE_RATIO) {
            // Below kink: gentle slope
            // rate = base + (U / U_optimal) * slope1
            rate += VARIABLE_RATE_SLOPE_1.rayMul(
                utilizationRate.rayDiv(OPTIMAL_USAGE_RATIO)
            );
        } else {
            // Above kink: steep slope
            // rate = base + slope1 + ((U - U_optimal) / (1 - U_optimal)) * slope2
            rate += VARIABLE_RATE_SLOPE_1;

            uint256 excessUtilization = utilizationRate - OPTIMAL_USAGE_RATIO;
            rate += VARIABLE_RATE_SLOPE_2.rayMul(
                excessUtilization.rayDiv(MAX_EXCESS_USAGE_RATIO_CACHED)
            );
        }

        return rate;
    }

    /**
     * @dev Calculate stable borrow rate.
     *      Stable rate = base stable rate + rate adjustments based on utilization
     *      + additional premium if stable debt ratio is too high
     */
    function _calcStableRate(
        uint256 utilizationRate,
        uint256 totalStableDebt,
        uint256 totalDebt,
        uint256 currentVariableBorrowRate
    ) internal view returns (uint256) {
        uint256 rate = BASE_STABLE_BORROW_RATE + currentVariableBorrowRate;

        if (utilizationRate <= OPTIMAL_USAGE_RATIO) {
            rate += STABLE_RATE_SLOPE_1.rayMul(
                utilizationRate.rayDiv(OPTIMAL_USAGE_RATIO)
            );
        } else {
            rate += STABLE_RATE_SLOPE_1;
            rate += STABLE_RATE_SLOPE_2.rayMul(
                (utilizationRate - OPTIMAL_USAGE_RATIO).rayDiv(MAX_EXCESS_USAGE_RATIO_CACHED)
            );
        }

        // Excess stable debt premium: if stable debt is too large a share of total debt,
        // increase the stable rate to discourage further stable borrowing
        if (totalDebt > 0) {
            uint256 stableToTotalDebtRatio = totalStableDebt.rayDiv(totalDebt);
            if (stableToTotalDebtRatio > OPTIMAL_STABLE_TO_TOTAL_DEBT_RATIO) {
                uint256 excessRatio = stableToTotalDebtRatio - OPTIMAL_STABLE_TO_TOTAL_DEBT_RATIO;
                uint256 maxExcess = WadRayMath.RAY - OPTIMAL_STABLE_TO_TOTAL_DEBT_RATIO;
                rate += STABLE_RATE_EXCESS_OFFSET.rayMul(excessRatio.rayDiv(maxExcess));
            }
        }

        return rate;
    }

    // ============ View Helpers ============

    function getMaxVariableBorrowRate() external view returns (uint256) {
        return BASE_VARIABLE_BORROW_RATE + VARIABLE_RATE_SLOPE_1 + VARIABLE_RATE_SLOPE_2;
    }

    function getOptimalUsageRatio() external view returns (uint256) {
        return OPTIMAL_USAGE_RATIO;
    }
}
