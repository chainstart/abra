// SPDX-License-Identifier: BUSL-1.1
pragma solidity ^0.8.10;

/**
 * @title Aave V3 Pool
 * @notice Core lending/borrowing pool contract. Users supply assets to earn interest,
 *         borrow against collateral, and can be liquidated if their health factor drops below 1.
 *
 * @dev Architecture overview:
 *      - Each reserve has an AToken (receipt for deposits) and debt tokens (variable/stable)
 *      - Interest rates are determined by utilization-based curves
 *      - Health factor = sum(collateral * LTV) / sum(debt) — liquidation when < 1
 *      - Flash loans allow uncollateralized borrows within a single transaction
 *
 * Vulnerability surfaces auditors examine:
 *      - Reentrancy via flash loans or token callbacks
 *      - Oracle manipulation affecting health factor calculations
 *      - Interest rate model edge cases at extreme utilization
 *      - Liquidation incentive gaming
 *      - Reserve configuration parameter interactions
 */

// ============ Data Types ============

library DataTypes {
    struct ReserveData {
        // Configuration bitmap (LTV, liquidation threshold, etc.)
        uint256 configuration;
        // Liquidity index — cumulative interest earned by depositors (ray, 1e27)
        uint128 liquidityIndex;
        // Current liquidity rate (ray)
        uint128 currentLiquidityRate;
        // Variable borrow index — cumulative interest owed by variable borrowers (ray)
        uint128 variableBorrowIndex;
        // Current variable borrow rate (ray)
        uint128 currentVariableBorrowRate;
        // Current stable borrow rate (ray)
        uint128 currentStableBorrowRate;
        // Timestamp of last update
        uint40 lastUpdateTimestamp;
        // ID of the reserve (sequential)
        uint16 id;
        // AToken address (receipt token for suppliers)
        address aTokenAddress;
        // Stable debt token address
        address stableDebtTokenAddress;
        // Variable debt token address
        address variableDebtTokenAddress;
        // Interest rate strategy contract
        address interestRateStrategyAddress;
        // Accumulated protocol fee (truncated to uint128)
        uint128 accruedToTreasury;
        // Unbacked aTokens minted through bridging
        uint128 unbacked;
        // Outstanding debt borrowed against isolated assets
        uint128 isolationModeTotalDebt;
    }

    struct ReserveConfigurationMap {
        uint256 data;
    }

    struct UserConfigurationMap {
        uint256 data;
    }

    struct ExecuteSupplyParams {
        address asset;
        uint256 amount;
        address onBehalfOf;
        uint16 referralCode;
    }

    struct ExecuteBorrowParams {
        address asset;
        address user;
        address onBehalfOf;
        uint256 amount;
        uint256 interestRateMode; // 1 = stable, 2 = variable
        uint16 referralCode;
        bool releaseUnderlying;
    }

    struct ExecuteLiquidationCallParams {
        address collateralAsset;
        address debtAsset;
        address user;
        uint256 debtToCover;
        bool receiveAToken;
    }

    struct FlashLoanParams {
        address receiverAddress;
        address[] assets;
        uint256[] amounts;
        uint256[] interestRateModes;
        address onBehalfOf;
        bytes params;
        uint16 referralCode;
    }

    struct CalculateUserAccountDataParams {
        address user;
        uint256 reservesCount;
    }
}

// ============ Interfaces ============

interface IAToken {
    function mint(address caller, address onBehalfOf, uint256 amount, uint256 index) external returns (bool);
    function burn(address from, address receiverOfUnderlying, uint256 amount, uint256 index) external;
    function scaledBalanceOf(address user) external view returns (uint256);
    function scaledTotalSupply() external view returns (uint256);
    function transferUnderlyingTo(address target, uint256 amount) external;
    function handleRepayment(address user, address onBehalfOf, uint256 amount) external;
    function UNDERLYING_ASSET_ADDRESS() external view returns (address);
}

interface IVariableDebtToken {
    function mint(address user, address onBehalfOf, uint256 amount, uint256 index) external returns (bool, uint256);
    function burn(address from, uint256 amount, uint256 index) external returns (uint256);
    function scaledBalanceOf(address user) external view returns (uint256);
    function scaledTotalSupply() external view returns (uint256);
}

interface IStableDebtToken {
    function mint(address user, address onBehalfOf, uint256 amount, uint256 rate) external returns (bool, uint256, uint256);
    function burn(address from, uint256 amount) external returns (uint256, uint256);
}

interface IPriceOracle {
    function getAssetPrice(address asset) external view returns (uint256);
}

interface IACLManager {
    function isPoolAdmin(address admin) external view returns (bool);
    function isEmergencyAdmin(address admin) external view returns (bool);
    function isRiskAdmin(address admin) external view returns (bool);
    function isFlashBorrower(address borrower) external view returns (bool);
    function isBridge(address bridge) external view returns (bool);
}

interface IFlashLoanReceiver {
    function executeOperation(
        address[] calldata assets,
        uint256[] calldata amounts,
        uint256[] calldata premiums,
        address initiator,
        bytes calldata params
    ) external returns (bool);
}

interface IFlashLoanSimpleReceiver {
    function executeOperation(
        address asset,
        uint256 amount,
        uint256 premium,
        address initiator,
        bytes calldata params
    ) external returns (bool);
}

interface IPoolAddressesProvider {
    function getACLManager() external view returns (address);
    function getPriceOracle() external view returns (address);
}

interface IERC20 {
    function balanceOf(address account) external view returns (uint256);
    function transfer(address to, uint256 amount) external returns (bool);
    function transferFrom(address from, address to, uint256 amount) external returns (bool);
    function approve(address spender, uint256 amount) external returns (bool);
    function totalSupply() external view returns (uint256);
    function decimals() external view returns (uint8);
}

// ============ Libraries ============

library WadRayMath {
    uint256 internal constant WAD = 1e18;
    uint256 internal constant RAY = 1e27;
    uint256 internal constant HALF_RAY = RAY / 2;
    uint256 internal constant HALF_WAD = WAD / 2;

    function rayMul(uint256 a, uint256 b) internal pure returns (uint256) {
        return (a * b + HALF_RAY) / RAY;
    }

    function rayDiv(uint256 a, uint256 b) internal pure returns (uint256) {
        return (a * RAY + b / 2) / b;
    }

    function wadMul(uint256 a, uint256 b) internal pure returns (uint256) {
        return (a * b + HALF_WAD) / WAD;
    }

    function wadDiv(uint256 a, uint256 b) internal pure returns (uint256) {
        return (a * WAD + b / 2) / b;
    }
}

library PercentageMath {
    uint256 internal constant PERCENTAGE_FACTOR = 1e4; // 100.00%
    uint256 internal constant HALF_PERCENTAGE_FACTOR = 5000;

    function percentMul(uint256 value, uint256 percentage) internal pure returns (uint256) {
        return (value * percentage + HALF_PERCENTAGE_FACTOR) / PERCENTAGE_FACTOR;
    }

    function percentDiv(uint256 value, uint256 percentage) internal pure returns (uint256) {
        return (value * PERCENTAGE_FACTOR + percentage / 2) / percentage;
    }
}

// ============ Main Contract ============

contract Pool {
    using WadRayMath for uint256;
    using PercentageMath for uint256;

    // ---- Constants ----
    uint256 public constant POOL_REVISION = 3;
    uint256 public constant MAX_NUMBER_RESERVES = 128;
    uint256 public constant HEALTH_FACTOR_LIQUIDATION_THRESHOLD = 1e18; // 1.0
    uint256 public constant FLASH_LOAN_PREMIUM_TOTAL = 9; // 0.09%
    uint256 public constant FLASH_LOAN_PREMIUM_TO_PROTOCOL = 0;
    uint16 public constant MAX_STABLE_RATE_BORROW_SIZE_PERCENT = 2500; // 25%

    uint256 private constant _NOT_ENTERED = 0;
    uint256 private constant _ENTERED = 1;

    // ---- State ----
    IPoolAddressesProvider public immutable ADDRESSES_PROVIDER;

    mapping(address => DataTypes.ReserveData) internal _reserves;
    mapping(address => DataTypes.UserConfigurationMap) internal _usersConfig;
    mapping(uint256 => address) internal _reservesList;
    uint16 internal _reservesCount;

    uint256 internal _reentrancyStatus;

    // ---- Events ----
    event Supply(address indexed reserve, address user, address indexed onBehalfOf, uint256 amount, uint16 indexed referralCode);
    event Withdraw(address indexed reserve, address indexed user, address indexed to, uint256 amount);
    event Borrow(address indexed reserve, address user, address indexed onBehalfOf, uint256 amount, uint256 interestRateMode, uint256 borrowRate, uint16 indexed referralCode);
    event Repay(address indexed reserve, address indexed user, address indexed repayer, uint256 amount, bool useATokens);
    event FlashLoan(address indexed target, address initiator, address indexed asset, uint256 amount, uint256 interestRateMode, uint256 premium, uint16 indexed referralCode);
    event LiquidationCall(address indexed collateralAsset, address indexed debtAsset, address indexed user, uint256 debtToCover, uint256 liquidatedCollateralAmount, address liquidator, bool receiveAToken);
    event ReserveDataUpdated(address indexed reserve, uint256 liquidityRate, uint256 stableBorrowRate, uint256 variableBorrowRate, uint256 liquidityIndex, uint256 variableBorrowIndex);

    // ---- Modifiers ----
    modifier nonReentrant() {
        require(_reentrancyStatus != _ENTERED, "REENTRANCY_GUARD");
        _reentrancyStatus = _ENTERED;
        _;
        _reentrancyStatus = _NOT_ENTERED;
    }

    modifier onlyPoolAdmin() {
        IACLManager aclManager = IACLManager(ADDRESSES_PROVIDER.getACLManager());
        require(aclManager.isPoolAdmin(msg.sender), "CALLER_NOT_POOL_ADMIN");
        _;
    }

    // ---- Constructor ----
    constructor(address provider) {
        ADDRESSES_PROVIDER = IPoolAddressesProvider(provider);
    }

    // ============ Supply ============

    /**
     * @notice Supply assets to the pool, receiving aTokens in return.
     * @param asset The address of the underlying asset to supply
     * @param amount The amount to supply
     * @param onBehalfOf The address that will receive the aTokens
     * @param referralCode Referral code for tracking
     *
     * @dev Flow:
     *   1. Accrue interest (update indices)
     *   2. Transfer underlying from user to aToken contract
     *   3. Mint aTokens to onBehalfOf (scaled by liquidity index)
     *   4. Update interest rates based on new utilization
     */
    function supply(
        address asset,
        uint256 amount,
        address onBehalfOf,
        uint16 referralCode
    ) external nonReentrant {
        DataTypes.ReserveData storage reserve = _reserves[asset];
        require(reserve.aTokenAddress != address(0), "RESERVE_NOT_FOUND");

        // Accrue interest to bring indices up to date
        _accrueInterest(reserve, asset);

        // Validation: check reserve is active, not frozen, supply cap not exceeded
        _validateSupply(reserve, amount);

        // Transfer underlying asset from user to the aToken contract
        IERC20(asset).transferFrom(msg.sender, reserve.aTokenAddress, amount);

        // Mint aTokens: the aToken stores scaled balance (amount / liquidityIndex)
        // This means the aToken balance automatically grows as liquidityIndex increases
        bool isFirstSupply = IAToken(reserve.aTokenAddress).mint(
            msg.sender,
            onBehalfOf,
            amount,
            reserve.liquidityIndex
        );

        // If this is the user's first supply of this asset, mark it in their config
        if (isFirstSupply) {
            _usersConfig[onBehalfOf].data |= (1 << (reserve.id * 2)); // set "using as collateral" bit
        }

        // Update interest rates based on new reserve utilization
        _updateInterestRates(reserve, asset, amount, 0);

        emit Supply(asset, msg.sender, onBehalfOf, amount, referralCode);
    }

    // ============ Withdraw ============

    /**
     * @notice Withdraw assets from the pool, burning aTokens.
     * @param asset The address of the underlying asset
     * @param amount The amount to withdraw (type(uint256).max for full balance)
     * @param to Recipient of the underlying
     * @return The final amount withdrawn
     */
    function withdraw(
        address asset,
        uint256 amount,
        address to
    ) external nonReentrant returns (uint256) {
        DataTypes.ReserveData storage reserve = _reserves[asset];
        require(reserve.aTokenAddress != address(0), "RESERVE_NOT_FOUND");

        _accrueInterest(reserve, asset);

        // Resolve "max" withdrawal
        uint256 userBalance = IAToken(reserve.aTokenAddress).scaledBalanceOf(msg.sender)
            .rayMul(reserve.liquidityIndex);

        if (amount == type(uint256).max) {
            amount = userBalance;
        }

        require(amount <= userBalance, "INSUFFICIENT_BALANCE");
        require(amount > 0, "ZERO_WITHDRAWAL");

        /**
         * @dev Validate that withdrawal doesn't make the user's position unhealthy.
         *      This is a critical check — without it, users could withdraw collateral
         *      and leave undercollateralized debt.
         *
         *      Vulnerability surface: if the oracle returns stale/manipulated prices,
         *      this check could pass incorrectly.
         */
        _validateHealthFactor(msg.sender, asset, amount, true);

        // Burn aTokens and transfer underlying
        IAToken(reserve.aTokenAddress).burn(msg.sender, to, amount, reserve.liquidityIndex);

        // Update interest rates
        _updateInterestRates(reserve, asset, 0, amount);

        emit Withdraw(asset, msg.sender, to, amount);
        return amount;
    }

    // ============ Borrow ============

    /**
     * @notice Borrow assets against deposited collateral.
     * @param asset The address of the underlying asset to borrow
     * @param amount The amount to borrow
     * @param interestRateMode 1 = stable, 2 = variable
     * @param referralCode Referral code
     * @param onBehalfOf The address that will receive the debt (must have delegated credit)
     *
     * @dev Vulnerability surface:
     *      - Borrow amount validation depends on oracle prices
     *      - Interest rate mode switching can be exploited if rates diverge
     *      - Stable rate rebalancing conditions can be gamed
     */
    function borrow(
        address asset,
        uint256 amount,
        uint256 interestRateMode,
        uint16 referralCode,
        address onBehalfOf
    ) external nonReentrant {
        DataTypes.ReserveData storage reserve = _reserves[asset];
        require(reserve.aTokenAddress != address(0), "RESERVE_NOT_FOUND");

        _accrueInterest(reserve, asset);

        // Validate: reserve is active, borrowing enabled, amount within borrow cap
        _validateBorrow(reserve, asset, amount, interestRateMode, onBehalfOf);

        uint256 currentStableRate = 0;

        if (interestRateMode == 2) {
            // Variable rate borrow — mint variable debt tokens
            IVariableDebtToken(reserve.variableDebtTokenAddress).mint(
                msg.sender,
                onBehalfOf,
                amount,
                reserve.variableBorrowIndex
            );
        } else {
            // Stable rate borrow — mint stable debt tokens
            currentStableRate = reserve.currentStableBorrowRate;
            IStableDebtToken(reserve.stableDebtTokenAddress).mint(
                msg.sender,
                onBehalfOf,
                amount,
                currentStableRate
            );
        }

        // Transfer underlying to borrower
        IAToken(reserve.aTokenAddress).transferUnderlyingTo(msg.sender, amount);

        // Update interest rates
        _updateInterestRates(reserve, asset, 0, amount);

        emit Borrow(asset, msg.sender, onBehalfOf, amount, interestRateMode,
                     interestRateMode == 2 ? reserve.currentVariableBorrowRate : currentStableRate,
                     referralCode);
    }

    // ============ Repay ============

    /**
     * @notice Repay borrowed assets.
     * @param asset The borrowed asset
     * @param amount Amount to repay (type(uint256).max for full debt)
     * @param interestRateMode 1 = stable, 2 = variable
     * @param onBehalfOf The address of the borrower
     * @return The final amount repaid
     */
    function repay(
        address asset,
        uint256 amount,
        uint256 interestRateMode,
        address onBehalfOf
    ) external nonReentrant returns (uint256) {
        DataTypes.ReserveData storage reserve = _reserves[asset];
        _accrueInterest(reserve, asset);

        uint256 paybackAmount;

        if (interestRateMode == 2) {
            // Variable debt
            uint256 currentDebt = IVariableDebtToken(reserve.variableDebtTokenAddress)
                .scaledBalanceOf(onBehalfOf)
                .rayMul(reserve.variableBorrowIndex);

            paybackAmount = amount > currentDebt ? currentDebt : amount;

            IVariableDebtToken(reserve.variableDebtTokenAddress).burn(
                onBehalfOf,
                paybackAmount,
                reserve.variableBorrowIndex
            );
        } else {
            // Stable debt
            (uint256 currentDebt, ) = IStableDebtToken(reserve.stableDebtTokenAddress).burn(
                onBehalfOf,
                amount
            );
            paybackAmount = amount > currentDebt ? currentDebt : amount;
        }

        // Transfer repayment from caller to aToken contract
        IERC20(asset).transferFrom(msg.sender, reserve.aTokenAddress, paybackAmount);
        IAToken(reserve.aTokenAddress).handleRepayment(msg.sender, onBehalfOf, paybackAmount);

        // Update interest rates
        _updateInterestRates(reserve, asset, paybackAmount, 0);

        emit Repay(asset, onBehalfOf, msg.sender, paybackAmount, false);
        return paybackAmount;
    }

    // ============ Liquidation ============

    /**
     * @notice Liquidate an undercollateralized position.
     * @param collateralAsset The collateral asset to seize
     * @param debtAsset The debt asset to repay
     * @param user The borrower being liquidated
     * @param debtToCover Amount of debt to repay
     * @param receiveAToken If true, liquidator receives aTokens instead of underlying
     *
     * @dev Liquidation flow:
     *   1. Verify user's health factor < 1.0
     *   2. Calculate max liquidatable amount (close factor, typically 50%)
     *   3. Calculate collateral to seize (debt value + liquidation bonus)
     *   4. Burn user's debt tokens, seize their aTokens
     *   5. Transfer collateral to liquidator
     *
     * Vulnerability surfaces:
     *   - Oracle manipulation to artificially lower health factor
     *   - Liquidation bonus calculation rounding
     *   - Flash loan + liquidation in same tx for risk-free profit
     *   - Close factor bypass through repeated small liquidations
     */
    function liquidationCall(
        address collateralAsset,
        address debtAsset,
        address user,
        uint256 debtToCover,
        bool receiveAToken
    ) external nonReentrant {
        DataTypes.ReserveData storage collateralReserve = _reserves[collateralAsset];
        DataTypes.ReserveData storage debtReserve = _reserves[debtAsset];

        _accrueInterest(collateralReserve, collateralAsset);
        _accrueInterest(debtReserve, debtAsset);

        // 1. Calculate user's health factor
        (uint256 totalCollateralBase, uint256 totalDebtBase, , , , uint256 healthFactor) =
            _calculateUserAccountData(user);

        require(healthFactor < HEALTH_FACTOR_LIQUIDATION_THRESHOLD, "HEALTH_FACTOR_NOT_BELOW_THRESHOLD");
        require(totalDebtBase > 0, "NO_DEBT");

        // 2. Determine close factor (how much debt can be repaid in one liquidation)
        // Default: 50%. If HF < 0.95, can liquidate 100%
        uint256 closeFactor = healthFactor < 0.95e18 ? 1e4 : 5000;

        // 3. Get debt token balance and cap debtToCover
        uint256 userDebt = IVariableDebtToken(debtReserve.variableDebtTokenAddress)
            .scaledBalanceOf(user)
            .rayMul(debtReserve.variableBorrowIndex);

        uint256 maxLiquidatable = userDebt.percentMul(closeFactor);
        if (debtToCover > maxLiquidatable) {
            debtToCover = maxLiquidatable;
        }

        // 4. Calculate collateral to seize
        IPriceOracle oracle = IPriceOracle(ADDRESSES_PROVIDER.getPriceOracle());
        uint256 debtAssetPrice = oracle.getAssetPrice(debtAsset);
        uint256 collateralAssetPrice = oracle.getAssetPrice(collateralAsset);

        // liquidationBonus is stored in the reserve configuration (e.g., 10500 = 105%)
        uint256 liquidationBonus = 10500; // Simplified: 5% bonus

        /**
         * @dev Collateral to seize calculation:
         *      collateralAmount = (debtToCover * debtPrice * liquidationBonus) / (collateralPrice * 10000)
         *
         *      Vulnerability: if collateralPrice is manipulated downward or debtPrice upward,
         *      liquidator can seize more collateral than fair value.
         */
        uint256 collateralToSeize = (debtToCover * debtAssetPrice * liquidationBonus) /
            (collateralAssetPrice * 10000);

        // Handle decimal differences between assets
        uint8 debtDecimals = IERC20(debtAsset).decimals();
        uint8 collateralDecimals = IERC20(collateralAsset).decimals();
        if (debtDecimals != collateralDecimals) {
            collateralToSeize = collateralToSeize * (10 ** collateralDecimals) / (10 ** debtDecimals);
        }

        // 5. Execute: burn debt, seize collateral
        // Burn user's variable debt
        IVariableDebtToken(debtReserve.variableDebtTokenAddress).burn(
            user, debtToCover, debtReserve.variableBorrowIndex
        );

        // Transfer debt asset from liquidator to aToken
        IERC20(debtAsset).transferFrom(msg.sender, debtReserve.aTokenAddress, debtToCover);

        if (receiveAToken) {
            // Transfer aTokens directly to liquidator (no underlying movement)
            // This is more gas efficient
        } else {
            // Burn user's aTokens, send underlying to liquidator
            IAToken(collateralReserve.aTokenAddress).burn(
                user, msg.sender, collateralToSeize, collateralReserve.liquidityIndex
            );
        }

        // Update rates
        _updateInterestRates(debtReserve, debtAsset, debtToCover, 0);
        _updateInterestRates(collateralReserve, collateralAsset, 0, receiveAToken ? 0 : collateralToSeize);

        emit LiquidationCall(collateralAsset, debtAsset, user, debtToCover, collateralToSeize, msg.sender, receiveAToken);
    }

    // ============ Flash Loans ============

    /**
     * @notice Execute a flash loan — borrow without collateral, must repay within same tx.
     * @param receiverAddress Contract that implements IFlashLoanReceiver
     * @param assets Array of assets to borrow
     * @param amounts Array of amounts to borrow
     * @param interestRateModes 0 = repay, 1 = stable debt, 2 = variable debt
     * @param onBehalfOf Address to open debt position for (if not fully repaid)
     * @param params Arbitrary data passed to the receiver callback
     * @param referralCode Referral code
     *
     * @dev Vulnerability surface:
     *      - Reentrancy through callback
     *      - Receiver contract can be malicious
     *      - Interest rate mode != 0 allows flash loan to become a regular borrow
     */
    function flashLoan(
        address receiverAddress,
        address[] calldata assets,
        uint256[] calldata amounts,
        uint256[] calldata interestRateModes,
        address onBehalfOf,
        bytes calldata params,
        uint16 referralCode
    ) external nonReentrant {
        require(assets.length == amounts.length, "INCONSISTENT_PARAMS");
        require(assets.length == interestRateModes.length, "INCONSISTENT_PARAMS");

        uint256[] memory premiums = new uint256[](assets.length);

        // Check if borrower is whitelisted (no premium)
        IACLManager aclManager = IACLManager(ADDRESSES_PROVIDER.getACLManager());
        bool isFlashBorrower = aclManager.isFlashBorrower(msg.sender);

        // Transfer assets to receiver and calculate premiums
        for (uint256 i = 0; i < assets.length; i++) {
            DataTypes.ReserveData storage reserve = _reserves[assets[i]];
            _accrueInterest(reserve, assets[i]);

            premiums[i] = isFlashBorrower ? 0 : amounts[i].percentMul(FLASH_LOAN_PREMIUM_TOTAL);

            IAToken(reserve.aTokenAddress).transferUnderlyingTo(receiverAddress, amounts[i]);
        }

        // Callback to receiver
        require(
            IFlashLoanReceiver(receiverAddress).executeOperation(
                assets, amounts, premiums, msg.sender, params
            ),
            "FLASH_LOAN_CALLBACK_FAILED"
        );

        // Verify repayment or open debt position
        for (uint256 i = 0; i < assets.length; i++) {
            DataTypes.ReserveData storage reserve = _reserves[assets[i]];

            if (interestRateModes[i] == 0) {
                // Full repayment required
                uint256 amountPlusPremium = amounts[i] + premiums[i];
                IERC20(assets[i]).transferFrom(receiverAddress, reserve.aTokenAddress, amountPlusPremium);

                // Accrue premium to protocol treasury
                if (premiums[i] > 0) {
                    uint256 protocolPremium = premiums[i].percentMul(FLASH_LOAN_PREMIUM_TO_PROTOCOL);
                    reserve.accruedToTreasury += uint128(
                        protocolPremium.rayDiv(reserve.liquidityIndex)
                    );
                }

                _updateInterestRates(reserve, assets[i], premiums[i], 0);
            } else {
                // Open debt position — borrow validation applies
                _validateBorrow(reserve, assets[i], amounts[i], interestRateModes[i], onBehalfOf);

                if (interestRateModes[i] == 2) {
                    IVariableDebtToken(reserve.variableDebtTokenAddress).mint(
                        msg.sender, onBehalfOf, amounts[i] + premiums[i], reserve.variableBorrowIndex
                    );
                }
            }

            emit FlashLoan(receiverAddress, msg.sender, assets[i], amounts[i],
                           interestRateModes[i], premiums[i], referralCode);
        }
    }

    /**
     * @notice Simplified flash loan for a single asset.
     */
    function flashLoanSimple(
        address receiverAddress,
        address asset,
        uint256 amount,
        bytes calldata params,
        uint16 referralCode
    ) external nonReentrant {
        DataTypes.ReserveData storage reserve = _reserves[asset];
        _accrueInterest(reserve, asset);

        uint256 premium = amount.percentMul(FLASH_LOAN_PREMIUM_TOTAL);

        IAToken(reserve.aTokenAddress).transferUnderlyingTo(receiverAddress, amount);

        require(
            IFlashLoanSimpleReceiver(receiverAddress).executeOperation(
                asset, amount, premium, msg.sender, params
            ),
            "FLASH_LOAN_CALLBACK_FAILED"
        );

        uint256 amountPlusPremium = amount + premium;
        IERC20(asset).transferFrom(receiverAddress, reserve.aTokenAddress, amountPlusPremium);

        _updateInterestRates(reserve, asset, premium, 0);

        emit FlashLoan(receiverAddress, msg.sender, asset, amount, 0, premium, referralCode);
    }

    // ============ Internal Functions ============

    /**
     * @dev Accrue interest — update liquidity and borrow indices based on time elapsed.
     */
    function _accrueInterest(DataTypes.ReserveData storage reserve, address asset) internal {
        uint256 currentTimestamp = block.timestamp;
        uint256 lastTimestamp = reserve.lastUpdateTimestamp;

        if (currentTimestamp == lastTimestamp) return;

        uint256 timeElapsed = currentTimestamp - lastTimestamp;

        // Update liquidity index: newIndex = oldIndex * (1 + rate * timeElapsed / SECONDS_PER_YEAR)
        uint256 SECONDS_PER_YEAR = 365 days;
        uint256 liquidityAccumulated = reserve.currentLiquidityRate * timeElapsed / SECONDS_PER_YEAR;
        reserve.liquidityIndex = uint128(
            uint256(reserve.liquidityIndex).rayMul(WadRayMath.RAY + liquidityAccumulated)
        );

        // Update variable borrow index similarly
        uint256 borrowAccumulated = reserve.currentVariableBorrowRate * timeElapsed / SECONDS_PER_YEAR;
        reserve.variableBorrowIndex = uint128(
            uint256(reserve.variableBorrowIndex).rayMul(WadRayMath.RAY + borrowAccumulated)
        );

        reserve.lastUpdateTimestamp = uint40(currentTimestamp);

        emit ReserveDataUpdated(
            asset,
            reserve.currentLiquidityRate,
            reserve.currentStableBorrowRate,
            reserve.currentVariableBorrowRate,
            reserve.liquidityIndex,
            reserve.variableBorrowIndex
        );
    }

    function _updateInterestRates(
        DataTypes.ReserveData storage reserve,
        address asset,
        uint256 liquidityAdded,
        uint256 liquidityTaken
    ) internal {
        // In production, this calls the InterestRateStrategy contract to get new rates
        // based on updated utilization = totalDebt / (totalDebt + availableLiquidity)
        // Simplified here
    }

    function _validateSupply(DataTypes.ReserveData storage reserve, uint256 amount) internal view {
        // Check: reserve active, not frozen, not paused, supply cap not exceeded
        // Simplified
        require(amount > 0, "ZERO_AMOUNT");
    }

    function _validateBorrow(
        DataTypes.ReserveData storage reserve,
        address asset,
        uint256 amount,
        uint256 interestRateMode,
        address onBehalfOf
    ) internal view {
        require(amount > 0, "ZERO_AMOUNT");
        require(interestRateMode == 1 || interestRateMode == 2, "INVALID_RATE_MODE");

        // Validate health factor would remain >= 1.0 after borrow
        // In production, this calculates the user's full account data
    }

    function _validateHealthFactor(
        address user,
        address asset,
        uint256 amount,
        bool isWithdrawal
    ) internal view {
        (,,,,, uint256 healthFactor) = _calculateUserAccountData(user);
        require(healthFactor >= HEALTH_FACTOR_LIQUIDATION_THRESHOLD, "HEALTH_FACTOR_BELOW_THRESHOLD");
    }

    /**
     * @dev Calculate user's aggregate account data across all reserves.
     * @return totalCollateralBase Total collateral in base currency
     * @return totalDebtBase Total debt in base currency
     * @return availableBorrowsBase Remaining borrow capacity
     * @return currentLiquidationThreshold Weighted avg liquidation threshold
     * @return ltv Weighted avg loan-to-value
     * @return healthFactor Health factor (>= 1e18 means healthy)
     */
    function _calculateUserAccountData(address user) internal view returns (
        uint256 totalCollateralBase,
        uint256 totalDebtBase,
        uint256 availableBorrowsBase,
        uint256 currentLiquidationThreshold,
        uint256 ltv,
        uint256 healthFactor
    ) {
        IPriceOracle oracle = IPriceOracle(ADDRESSES_PROVIDER.getPriceOracle());

        for (uint256 i = 0; i < _reservesCount; i++) {
            address currentAsset = _reservesList[i];
            if (currentAsset == address(0)) continue;

            DataTypes.ReserveData storage reserve = _reserves[currentAsset];
            uint256 assetPrice = oracle.getAssetPrice(currentAsset);
            uint8 assetDecimals = IERC20(currentAsset).decimals();
            uint256 assetUnit = 10 ** assetDecimals;

            // Collateral
            uint256 userBalance = IAToken(reserve.aTokenAddress).scaledBalanceOf(user)
                .rayMul(reserve.liquidityIndex);
            if (userBalance > 0) {
                uint256 collateralInBase = (userBalance * assetPrice) / assetUnit;
                totalCollateralBase += collateralInBase;
            }

            // Debt (variable)
            uint256 userDebt = IVariableDebtToken(reserve.variableDebtTokenAddress)
                .scaledBalanceOf(user)
                .rayMul(reserve.variableBorrowIndex);
            if (userDebt > 0) {
                uint256 debtInBase = (userDebt * assetPrice) / assetUnit;
                totalDebtBase += debtInBase;
            }
        }

        // Health factor = (totalCollateral * liquidationThreshold) / totalDebt
        // Simplified: assume average liquidation threshold of 80%
        currentLiquidationThreshold = 8000;
        ltv = 7500;

        if (totalDebtBase == 0) {
            healthFactor = type(uint256).max;
        } else {
            healthFactor = totalCollateralBase.percentMul(currentLiquidationThreshold)
                * 1e18 / totalDebtBase;
        }

        if (totalCollateralBase > 0) {
            availableBorrowsBase = totalCollateralBase.percentMul(ltv) - totalDebtBase;
        }
    }

    // ============ View Functions ============

    function getReserveData(address asset) external view returns (DataTypes.ReserveData memory) {
        return _reserves[asset];
    }

    function getUserAccountData(address user) external view returns (
        uint256 totalCollateralBase,
        uint256 totalDebtBase,
        uint256 availableBorrowsBase,
        uint256 currentLiquidationThreshold,
        uint256 ltv,
        uint256 healthFactor
    ) {
        return _calculateUserAccountData(user);
    }

    function getReservesList() external view returns (address[] memory) {
        address[] memory list = new address[](_reservesCount);
        for (uint256 i = 0; i < _reservesCount; i++) {
            list[i] = _reservesList[i];
        }
        return list;
    }
}
