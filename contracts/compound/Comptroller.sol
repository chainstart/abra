// SPDX-License-Identifier: BSD-3-Clause
pragma solidity ^0.8.10;

/**
 * @title Compound Comptroller
 * @notice The Comptroller is the risk management layer of Compound. It controls:
 *         - Which markets users can enter/exit
 *         - Collateral factors (how much can be borrowed against each asset)
 *         - Liquidation incentives
 *         - Borrow caps and supply caps
 *         - COMP reward distribution
 *
 * @dev The Comptroller is called by CToken markets to validate operations.
 *      It acts as a policy engine — CTokens ask "is this allowed?" before executing.
 *
 *      Architecture: Comptroller is a proxy (upgradeable). This contract represents
 *      the implementation logic.
 *
 * Vulnerability surfaces:
 *      - Oracle manipulation affects all collateral/liquidity calculations
 *      - Incorrect collateral factor allows over-borrowing
 *      - Market listing: new markets can be added that interact poorly with existing ones
 *      - COMP distribution math: rounding errors can be exploited for excess rewards
 *      - Proxy upgrade: admin can change all risk parameters
 *      - Short-circuit liquidation: allowing liquidation when health factor is borderline
 */

// ============ Interfaces ============

interface ICToken {
    function totalSupply() external view returns (uint256);
    function totalBorrows() external view returns (uint256);
    function borrowIndex() external view returns (uint256);
    function exchangeRateStored() external view returns (uint256);
    function borrowBalanceStored(address account) external view returns (uint256);
    function balanceOf(address account) external view returns (uint256);
    function underlying() external view returns (address);
    function accrueInterest() external returns (uint256);
}

interface IPriceOracle {
    function getUnderlyingPrice(address cToken) external view returns (uint256);
}

interface IERC20 {
    function transfer(address to, uint256 amount) external returns (bool);
    function balanceOf(address account) external view returns (uint256);
}

// ============ Main Contract ============

contract Comptroller {
    // ---- Constants ----
    uint256 internal constant expScale = 1e18;
    uint256 internal constant halfExpScale = expScale / 2;
    uint256 internal constant closeFactorMinMantissa = 0.05e18; // 5%
    uint256 internal constant closeFactorMaxMantissa = 0.9e18;  // 90%
    uint256 internal constant collateralFactorMaxMantissa = 0.9e18; // 90%
    uint256 internal constant liquidationIncentiveMinMantissa = 1.0e18; // 100% (no bonus)
    uint256 internal constant liquidationIncentiveMaxMantissa = 1.5e18; // 150% (50% bonus)

    // Error codes
    uint256 internal constant NO_ERROR = 0;
    uint256 internal constant REJECTION = 1;
    uint256 internal constant MATH_ERROR = 9;
    uint256 internal constant INSUFFICIENT_LIQUIDITY = 3;
    uint256 internal constant MARKET_NOT_LISTED = 12;

    // ---- Structs ----
    struct Market {
        bool isListed;                  // Whether this market is recognized
        uint256 collateralFactorMantissa; // Max borrow ratio against this collateral (e.g., 0.75e18 = 75%)
        mapping(address => bool) accountMembership; // User has entered this market
        bool isComped;                  // Whether COMP rewards are active for this market
    }

    /// @notice COMP distribution tracking per market
    struct CompMarketState {
        uint224 index;       // Cumulative COMP per unit of supply/borrow
        uint32 block_;       // Last block number at which index was updated
    }

    // ---- State ----
    address public admin;
    address public pendingAdmin;

    /// @notice Price oracle
    IPriceOracle public oracle;

    /// @notice Close factor — max fraction of debt that can be liquidated in one tx
    uint256 public closeFactorMantissa;

    /// @notice Liquidation incentive — bonus collateral liquidators receive
    uint256 public liquidationIncentiveMantissa;

    /// @notice Max number of assets a user can enter
    uint256 public maxAssets;

    /// @notice Markets: cToken address => Market struct
    mapping(address => Market) public markets;

    /// @notice List of all market addresses
    address[] public allMarkets;

    /// @notice Per-user list of entered markets
    mapping(address => address[]) public accountAssets;

    /// @notice Borrow caps: max borrow per market (0 = no cap)
    mapping(address => uint256) public borrowCaps;

    /// @notice Supply caps: max supply per market (0 = no cap)
    mapping(address => uint256) public supplyCaps;

    /// @notice Pause guardians can pause certain operations
    address public pauseGuardian;
    mapping(address => bool) public mintGuardianPaused;
    mapping(address => bool) public borrowGuardianPaused;
    bool public transferGuardianPaused;
    bool public seizeGuardianPaused;

    // ---- COMP Distribution ----
    /// @notice The COMP token address
    address public compToken;

    /// @notice COMP distribution speed per block per market (for suppliers and borrowers)
    mapping(address => uint256) public compSupplySpeeds;
    mapping(address => uint256) public compBorrowSpeeds;

    /// @notice COMP supply state per market
    mapping(address => CompMarketState) public compSupplyState;
    /// @notice COMP borrow state per market
    mapping(address => CompMarketState) public compBorrowState;

    /// @notice Per-user COMP supply index per market
    mapping(address => mapping(address => uint256)) public compSupplierIndex;
    /// @notice Per-user COMP borrow index per market
    mapping(address => mapping(address => uint256)) public compBorrowerIndex;

    /// @notice Accrued COMP per user (claimable)
    mapping(address => uint256) public compAccrued;

    // ---- Events ----
    event MarketListed(address cToken);
    event MarketEntered(address cToken, address account);
    event MarketExited(address cToken, address account);
    event NewCloseFactor(uint256 oldCloseFactorMantissa, uint256 newCloseFactorMantissa);
    event NewCollateralFactor(address cToken, uint256 oldCollateralFactorMantissa, uint256 newCollateralFactorMantissa);
    event NewLiquidationIncentive(uint256 oldLiquidationIncentiveMantissa, uint256 newLiquidationIncentiveMantissa);
    event NewPriceOracle(IPriceOracle oldPriceOracle, IPriceOracle newPriceOracle);
    event CompGranted(address recipient, uint256 amount);
    event DistributedSupplierComp(address indexed cToken, address indexed supplier, uint256 compDelta, uint256 compSupplyIndex);
    event DistributedBorrowerComp(address indexed cToken, address indexed borrower, uint256 compDelta, uint256 compBorrowIndex);
    event ActionPaused(address cToken, string action, bool pauseState);
    event NewBorrowCap(address indexed cToken, uint256 newBorrowCap);
    event NewSupplyCap(address indexed cToken, uint256 newSupplyCap);

    // ---- Constructor ----
    constructor() {
        admin = msg.sender;
        closeFactorMantissa = 0.5e18; // 50%
        liquidationIncentiveMantissa = 1.08e18; // 8% bonus
    }

    // ============ Enter/Exit Markets ============

    /**
     * @notice Enter markets to use as collateral.
     * @param cTokens List of CToken markets to enter
     * @return Array of error codes (0 = success)
     *
     * @dev Entering a market allows the user's deposits in that market to count
     *      as collateral for borrowing. Users must enter a market before they can borrow.
     */
    function enterMarkets(address[] calldata cTokens) external returns (uint256[] memory) {
        uint256 len = cTokens.length;
        uint256[] memory results = new uint256[](len);
        for (uint256 i = 0; i < len; i++) {
            results[i] = addToMarketInternal(cTokens[i], msg.sender);
        }
        return results;
    }

    function addToMarketInternal(address cToken, address borrower) internal returns (uint256) {
        Market storage marketToJoin = markets[cToken];
        if (!marketToJoin.isListed) return MARKET_NOT_LISTED;

        if (marketToJoin.accountMembership[borrower]) return NO_ERROR; // Already joined

        marketToJoin.accountMembership[borrower] = true;
        accountAssets[borrower].push(cToken);

        emit MarketEntered(cToken, borrower);
        return NO_ERROR;
    }

    /**
     * @notice Exit a market — stop using it as collateral.
     * @param cTokenAddress The market to exit
     * @return Error code (0 = success)
     *
     * @dev Will fail if exiting would make the user's position undercollateralized.
     *      This is a critical check — without it, users could exit collateral markets
     *      while maintaining borrows.
     */
    function exitMarket(address cTokenAddress) external returns (uint256) {
        Market storage market = markets[cTokenAddress];
        if (!market.accountMembership[msg.sender]) return NO_ERROR;

        // Check: would exiting make the user underwater?
        (uint256 err, , uint256 shortfall) = getHypotheticalAccountLiquidityInternal(
            msg.sender, cTokenAddress, ICToken(cTokenAddress).balanceOf(msg.sender), 0
        );
        require(err == 0, "LIQUIDITY_CHECK_FAILED");
        require(shortfall == 0, "INSUFFICIENT_LIQUIDITY");

        market.accountMembership[msg.sender] = false;

        // Remove from accountAssets array
        address[] storage assets = accountAssets[msg.sender];
        for (uint256 i = 0; i < assets.length; i++) {
            if (assets[i] == cTokenAddress) {
                assets[i] = assets[assets.length - 1];
                assets.pop();
                break;
            }
        }

        emit MarketExited(cTokenAddress, msg.sender);
        return NO_ERROR;
    }

    // ============ Policy Hooks (Called by CToken) ============

    function mintAllowed(address cToken, address minter, uint256 mintAmount) external returns (uint256) {
        require(markets[cToken].isListed, "MARKET_NOT_LISTED");
        require(!mintGuardianPaused[cToken], "MINT_PAUSED");

        // Supply cap check
        if (supplyCaps[cToken] > 0) {
            uint256 totalSupply = ICToken(cToken).totalSupply();
            uint256 exchangeRate = ICToken(cToken).exchangeRateStored();
            uint256 totalUnderlyingSupply = totalSupply * exchangeRate / expScale;
            require(totalUnderlyingSupply + mintAmount <= supplyCaps[cToken], "SUPPLY_CAP_REACHED");
        }

        // Update COMP supply distribution
        updateCompSupplyIndex(cToken);
        distributeSupplierComp(cToken, minter);

        return NO_ERROR;
    }

    function mintVerify(address cToken, address minter, uint256 actualMintAmount, uint256 mintTokens) external {
        // Post-mint hook — currently unused but kept for future extensions
    }

    function redeemAllowed(address cToken, address redeemer, uint256 redeemTokens) external returns (uint256) {
        require(markets[cToken].isListed, "MARKET_NOT_LISTED");

        // If the redeemer has borrows, check that redeeming doesn't make them underwater
        if (!markets[cToken].accountMembership[redeemer]) {
            return NO_ERROR; // Not using this as collateral, always allowed
        }

        (uint256 err, , uint256 shortfall) = getHypotheticalAccountLiquidityInternal(
            redeemer, cToken, redeemTokens, 0
        );
        require(err == 0, "LIQUIDITY_CHECK_FAILED");
        require(shortfall == 0, "INSUFFICIENT_LIQUIDITY");

        updateCompSupplyIndex(cToken);
        distributeSupplierComp(cToken, redeemer);

        return NO_ERROR;
    }

    function redeemVerify(address cToken, address redeemer, uint256 redeemAmount, uint256 redeemTokens) external {
        // Verify the redeem was valid
        if (redeemTokens == 0 && redeemAmount > 0) {
            revert("REDEEM_TOKENS_ZERO");
        }
    }

    function borrowAllowed(address cToken, address borrower, uint256 borrowAmount) external returns (uint256) {
        require(markets[cToken].isListed, "MARKET_NOT_LISTED");
        require(!borrowGuardianPaused[cToken], "BORROW_PAUSED");

        // Auto-enter market if not already in it
        if (!markets[cToken].accountMembership[borrower]) {
            // Only the CToken itself can call borrowAllowed, so we can trust it
            require(msg.sender == cToken, "SENDER_MUST_BE_CTOKEN");
            addToMarketInternal(cToken, borrower);
        }

        // Borrow cap check
        if (borrowCaps[cToken] > 0) {
            uint256 totalBorrows = ICToken(cToken).totalBorrows();
            require(totalBorrows + borrowAmount <= borrowCaps[cToken], "BORROW_CAP_REACHED");
        }

        // Liquidity check
        (uint256 err, , uint256 shortfall) = getHypotheticalAccountLiquidityInternal(
            borrower, cToken, 0, borrowAmount
        );
        require(err == 0, "LIQUIDITY_CHECK_FAILED");
        require(shortfall == 0, "INSUFFICIENT_LIQUIDITY");

        // Update COMP borrow distribution
        updateCompBorrowIndex(cToken);
        distributeBorrowerComp(cToken, borrower);

        return NO_ERROR;
    }

    function borrowVerify(address cToken, address borrower, uint256 borrowAmount) external { }

    function repayBorrowAllowed(address cToken, address payer, address borrower, uint256 repayAmount) external returns (uint256) {
        require(markets[cToken].isListed, "MARKET_NOT_LISTED");

        updateCompBorrowIndex(cToken);
        distributeBorrowerComp(cToken, borrower);

        return NO_ERROR;
    }

    function liquidateBorrowAllowed(
        address cTokenBorrowed,
        address cTokenCollateral,
        address liquidator,
        address borrower,
        uint256 repayAmount
    ) external returns (uint256) {
        require(markets[cTokenBorrowed].isListed && markets[cTokenCollateral].isListed, "MARKET_NOT_LISTED");

        // Check that borrower is actually underwater
        (uint256 err, , uint256 shortfall) = getAccountLiquidityInternal(borrower);
        require(err == 0, "LIQUIDITY_CHECK_FAILED");
        require(shortfall > 0, "BORROWER_NOT_UNDERWATER");

        // Check close factor — can't repay more than closeFactorMantissa% of the debt
        uint256 borrowBalance = ICToken(cTokenBorrowed).borrowBalanceStored(borrower);
        uint256 maxClose = borrowBalance * closeFactorMantissa / expScale;
        require(repayAmount <= maxClose, "CLOSE_FACTOR_EXCEEDED");

        return NO_ERROR;
    }

    function seizeAllowed(
        address cTokenCollateral,
        address cTokenBorrowed,
        address liquidator,
        address borrower,
        uint256 seizeTokens
    ) external returns (uint256) {
        require(!seizeGuardianPaused, "SEIZE_PAUSED");
        require(markets[cTokenCollateral].isListed && markets[cTokenBorrowed].isListed, "MARKET_NOT_LISTED");

        // Update COMP for both parties
        updateCompSupplyIndex(cTokenCollateral);
        distributeSupplierComp(cTokenCollateral, borrower);
        distributeSupplierComp(cTokenCollateral, liquidator);

        return NO_ERROR;
    }

    function transferAllowed(address cToken, address src, address dst, uint256 transferTokens) external returns (uint256) {
        require(!transferGuardianPaused, "TRANSFER_PAUSED");

        // If sender has borrows, check liquidity
        if (markets[cToken].accountMembership[src]) {
            (uint256 err, , uint256 shortfall) = getHypotheticalAccountLiquidityInternal(
                src, cToken, transferTokens, 0
            );
            require(err == 0, "LIQUIDITY_CHECK_FAILED");
            require(shortfall == 0, "INSUFFICIENT_LIQUIDITY");
        }

        updateCompSupplyIndex(cToken);
        distributeSupplierComp(cToken, src);
        distributeSupplierComp(cToken, dst);

        return NO_ERROR;
    }

    // ============ Account Liquidity ============

    /**
     * @notice Calculate account liquidity (excess collateral or shortfall).
     * @return (error, excess liquidity, shortfall)
     *         If excess > 0: user can borrow more
     *         If shortfall > 0: user is underwater and can be liquidated
     *
     * @dev Iterates through all markets the user has entered:
     *      For each market:
     *        collateral += cTokenBalance * exchangeRate * collateralFactor * oraclePrice
     *        debt += borrowBalance * oraclePrice
     *      liquidity = collateral - debt
     *
     *      Vulnerability: O(n) iteration over user's markets. Too many markets = gas DoS.
     *      Compound limits this via maxAssets and careful market listing.
     */
    function getAccountLiquidity(address account) external view returns (uint256, uint256, uint256) {
        return getAccountLiquidityInternal(account);
    }

    function getAccountLiquidityInternal(address account) internal view returns (uint256, uint256, uint256) {
        return getHypotheticalAccountLiquidityInternal(account, address(0), 0, 0);
    }

    /**
     * @dev Calculate liquidity assuming a hypothetical redeem or borrow.
     * @param account The account to check
     * @param cTokenModify The market being modified (for hypothetical check)
     * @param redeemTokens Hypothetical CTokens being redeemed
     * @param borrowAmount Hypothetical underlying being borrowed
     */
    function getHypotheticalAccountLiquidityInternal(
        address account,
        address cTokenModify,
        uint256 redeemTokens,
        uint256 borrowAmount
    ) internal view returns (uint256, uint256, uint256) {
        uint256 sumCollateral = 0;
        uint256 sumBorrowPlusEffects = 0;

        address[] memory assets = accountAssets[account];

        for (uint256 i = 0; i < assets.length; i++) {
            address asset = assets[i];
            ICToken cToken = ICToken(asset);

            // Get user's balance and borrow in this market
            uint256 cTokenBalance = cToken.balanceOf(account);
            uint256 borrowBalance = cToken.borrowBalanceStored(account);
            uint256 exchangeRateMantissa = cToken.exchangeRateStored();

            /**
             * @dev Get oracle price.
             *
             *      CRITICAL: this is where oracle manipulation attacks target.
             *      If the oracle returns an inflated price for the collateral asset
             *      or a deflated price for the borrowed asset, the user appears
             *      more solvent than they are, allowing excess borrowing.
             */
            uint256 oraclePrice = oracle.getUnderlyingPrice(asset);
            require(oraclePrice > 0, "ORACLE_PRICE_ZERO");

            uint256 collateralFactor = markets[asset].collateralFactorMantissa;

            // Collateral value = cTokenBalance * exchangeRate * collateralFactor * price
            uint256 tokensToDenom = (collateralFactor * exchangeRateMantissa / expScale) * oraclePrice / expScale;
            sumCollateral += cTokenBalance * tokensToDenom / expScale;

            // Borrow value = borrowBalance * price
            sumBorrowPlusEffects += borrowBalance * oraclePrice / expScale;

            // Apply hypothetical modification
            if (asset == cTokenModify) {
                // Hypothetical redeem
                sumBorrowPlusEffects += redeemTokens * tokensToDenom / expScale;
                // Hypothetical borrow
                sumBorrowPlusEffects += borrowAmount * oraclePrice / expScale;
            }
        }

        if (sumCollateral > sumBorrowPlusEffects) {
            return (NO_ERROR, sumCollateral - sumBorrowPlusEffects, 0);
        } else {
            return (NO_ERROR, 0, sumBorrowPlusEffects - sumCollateral);
        }
    }

    /**
     * @notice Calculate the number of collateral tokens to seize during liquidation.
     * @param cTokenBorrowed The market whose debt is being repaid
     * @param cTokenCollateral The market from which collateral will be seized
     * @param actualRepayAmount Amount of debt actually repaid
     * @return (error, seizeTokens)
     *
     * @dev seizeTokens = actualRepayAmount * liquidationIncentive * priceBorrowed / (priceCollateral * exchangeRate)
     */
    function liquidateCalculateSeizeTokens(
        address cTokenBorrowed,
        address cTokenCollateral,
        uint256 actualRepayAmount
    ) external view returns (uint256, uint256) {
        uint256 priceBorrowed = oracle.getUnderlyingPrice(cTokenBorrowed);
        uint256 priceCollateral = oracle.getUnderlyingPrice(cTokenCollateral);
        require(priceBorrowed > 0 && priceCollateral > 0, "ORACLE_PRICE_ZERO");

        uint256 exchangeRateMantissa = ICToken(cTokenCollateral).exchangeRateStored();

        // seizeAmount (in underlying) = repayAmount * liquidationIncentive * priceBorrowed / priceCollateral
        uint256 seizeAmount = actualRepayAmount * liquidationIncentiveMantissa / expScale;
        seizeAmount = seizeAmount * priceBorrowed / priceCollateral;

        // Convert to CTokens
        uint256 seizeTokens = seizeAmount * expScale / exchangeRateMantissa;

        return (NO_ERROR, seizeTokens);
    }

    // ============ COMP Distribution ============

    /**
     * @notice Claim COMP accrued by a user across all markets.
     * @param holder The address to claim for
     *
     * @dev COMP is distributed proportionally based on supply/borrow share in each market.
     *      Speed (COMP per block) is set per-market by admin.
     *
     *      Vulnerability: early Compound had a bug where the COMP distribution for
     *      borrowers used the wrong index, leading to over-distribution of ~80M COMP.
     */
    function claimComp(address holder) external {
        address[] memory markets_ = accountAssets[holder];
        for (uint256 i = 0; i < markets_.length; i++) {
            address cToken = markets_[i];

            updateCompSupplyIndex(cToken);
            distributeSupplierComp(cToken, holder);

            updateCompBorrowIndex(cToken);
            distributeBorrowerComp(cToken, holder);
        }

        uint256 accrued = compAccrued[holder];
        if (accrued > 0) {
            compAccrued[holder] = 0;
            IERC20(compToken).transfer(holder, accrued);
            emit CompGranted(holder, accrued);
        }
    }

    function updateCompSupplyIndex(address cToken) internal {
        CompMarketState storage supplyState = compSupplyState[cToken];
        uint256 supplySpeed = compSupplySpeeds[cToken];
        uint256 blockNumber = block.number;
        uint256 deltaBlocks = blockNumber - supplyState.block_;

        if (deltaBlocks > 0 && supplySpeed > 0) {
            uint256 supplyTokens = ICToken(cToken).totalSupply();
            uint256 compAccrued_ = deltaBlocks * supplySpeed;
            uint256 ratio = supplyTokens > 0 ? compAccrued_ * expScale / supplyTokens : 0;
            supplyState.index = uint224(uint256(supplyState.index) + ratio);
        }
        supplyState.block_ = uint32(blockNumber);
    }

    function updateCompBorrowIndex(address cToken) internal {
        CompMarketState storage borrowState = compBorrowState[cToken];
        uint256 borrowSpeed = compBorrowSpeeds[cToken];
        uint256 blockNumber = block.number;
        uint256 deltaBlocks = blockNumber - borrowState.block_;

        if (deltaBlocks > 0 && borrowSpeed > 0) {
            uint256 borrowAmount = ICToken(cToken).totalBorrows();
            uint256 borrowIndex = ICToken(cToken).borrowIndex();
            // Normalize borrows to initial index for consistent comparison
            uint256 totalBorrowsNormalized = borrowAmount * expScale / borrowIndex;

            uint256 compAccrued_ = deltaBlocks * borrowSpeed;
            uint256 ratio = totalBorrowsNormalized > 0 ? compAccrued_ * expScale / totalBorrowsNormalized : 0;
            borrowState.index = uint224(uint256(borrowState.index) + ratio);
        }
        borrowState.block_ = uint32(blockNumber);
    }

    function distributeSupplierComp(address cToken, address supplier) internal {
        CompMarketState storage supplyState = compSupplyState[cToken];
        uint256 supplyIndex = supplyState.index;
        uint256 supplierIndex = compSupplierIndex[cToken][supplier];

        compSupplierIndex[cToken][supplier] = supplyIndex;

        if (supplierIndex == 0 && supplyIndex >= expScale) {
            supplierIndex = expScale; // Initial index
        }

        uint256 deltaIndex = supplyIndex - supplierIndex;
        uint256 supplierTokens = ICToken(cToken).balanceOf(supplier);
        uint256 supplierDelta = supplierTokens * deltaIndex / expScale;

        compAccrued[supplier] += supplierDelta;
        emit DistributedSupplierComp(cToken, supplier, supplierDelta, supplyIndex);
    }

    function distributeBorrowerComp(address cToken, address borrower) internal {
        CompMarketState storage borrowState = compBorrowState[cToken];
        uint256 borrowIndex = borrowState.index;
        uint256 borrowerIndex = compBorrowerIndex[cToken][borrower];

        compBorrowerIndex[cToken][borrower] = borrowIndex;

        if (borrowerIndex == 0 && borrowIndex >= expScale) {
            borrowerIndex = expScale;
        }

        uint256 deltaIndex = borrowIndex - borrowerIndex;
        // Use normalized borrow balance for fair distribution
        uint256 borrowerBorrows = ICToken(cToken).borrowBalanceStored(borrower);
        uint256 cTokenBorrowIndex = ICToken(cToken).borrowIndex();
        uint256 borrowerNormalized = borrowerBorrows * expScale / cTokenBorrowIndex;

        uint256 borrowerDelta = borrowerNormalized * deltaIndex / expScale;

        compAccrued[borrower] += borrowerDelta;
        emit DistributedBorrowerComp(cToken, borrower, borrowerDelta, borrowIndex);
    }

    // ============ Admin Functions ============

    function _supportMarket(address cToken) external returns (uint256) {
        require(msg.sender == admin, "ONLY_ADMIN");
        require(!markets[cToken].isListed, "ALREADY_LISTED");

        markets[cToken].isListed = true;
        markets[cToken].collateralFactorMantissa = 0; // Must be set separately
        allMarkets.push(cToken);

        emit MarketListed(cToken);
        return NO_ERROR;
    }

    function _setCollateralFactor(address cToken, uint256 newCollateralFactorMantissa) external returns (uint256) {
        require(msg.sender == admin, "ONLY_ADMIN");
        require(markets[cToken].isListed, "MARKET_NOT_LISTED");
        require(newCollateralFactorMantissa <= collateralFactorMaxMantissa, "COLLATERAL_FACTOR_TOO_HIGH");

        // Ensure oracle is set and returns a valid price
        uint256 price = oracle.getUnderlyingPrice(cToken);
        require(price > 0, "ORACLE_PRICE_ZERO");

        uint256 old = markets[cToken].collateralFactorMantissa;
        markets[cToken].collateralFactorMantissa = newCollateralFactorMantissa;
        emit NewCollateralFactor(cToken, old, newCollateralFactorMantissa);
        return NO_ERROR;
    }

    function _setCloseFactor(uint256 newCloseFactorMantissa) external returns (uint256) {
        require(msg.sender == admin, "ONLY_ADMIN");
        require(newCloseFactorMantissa >= closeFactorMinMantissa, "TOO_LOW");
        require(newCloseFactorMantissa <= closeFactorMaxMantissa, "TOO_HIGH");

        uint256 old = closeFactorMantissa;
        closeFactorMantissa = newCloseFactorMantissa;
        emit NewCloseFactor(old, newCloseFactorMantissa);
        return NO_ERROR;
    }

    function _setLiquidationIncentive(uint256 newLiquidationIncentiveMantissa) external returns (uint256) {
        require(msg.sender == admin, "ONLY_ADMIN");
        require(newLiquidationIncentiveMantissa >= liquidationIncentiveMinMantissa, "TOO_LOW");
        require(newLiquidationIncentiveMantissa <= liquidationIncentiveMaxMantissa, "TOO_HIGH");

        uint256 old = liquidationIncentiveMantissa;
        liquidationIncentiveMantissa = newLiquidationIncentiveMantissa;
        emit NewLiquidationIncentive(old, newLiquidationIncentiveMantissa);
        return NO_ERROR;
    }

    function _setPriceOracle(address newOracle) external returns (uint256) {
        require(msg.sender == admin, "ONLY_ADMIN");
        IPriceOracle old = oracle;
        oracle = IPriceOracle(newOracle);
        emit NewPriceOracle(old, oracle);
        return NO_ERROR;
    }

    function _setBorrowCap(address cToken, uint256 newBorrowCap) external {
        require(msg.sender == admin, "ONLY_ADMIN");
        borrowCaps[cToken] = newBorrowCap;
        emit NewBorrowCap(cToken, newBorrowCap);
    }

    function _setSupplyCap(address cToken, uint256 newSupplyCap) external {
        require(msg.sender == admin, "ONLY_ADMIN");
        supplyCaps[cToken] = newSupplyCap;
        emit NewSupplyCap(cToken, newSupplyCap);
    }

    function _setCompSpeeds(
        address[] calldata cTokens,
        uint256[] calldata supplySpeeds_,
        uint256[] calldata borrowSpeeds_
    ) external {
        require(msg.sender == admin, "ONLY_ADMIN");
        require(cTokens.length == supplySpeeds_.length && cTokens.length == borrowSpeeds_.length, "INVALID_INPUT");

        for (uint256 i = 0; i < cTokens.length; i++) {
            // Accrue before changing speeds to ensure fair distribution
            updateCompSupplyIndex(cTokens[i]);
            updateCompBorrowIndex(cTokens[i]);
            compSupplySpeeds[cTokens[i]] = supplySpeeds_[i];
            compBorrowSpeeds[cTokens[i]] = borrowSpeeds_[i];
        }
    }

    function _setPauseGuardian(address newPauseGuardian) external returns (uint256) {
        require(msg.sender == admin, "ONLY_ADMIN");
        pauseGuardian = newPauseGuardian;
        return NO_ERROR;
    }

    function _setMintPaused(address cToken, bool state) external returns (bool) {
        require(msg.sender == pauseGuardian || msg.sender == admin, "UNAUTHORIZED");
        mintGuardianPaused[cToken] = state;
        emit ActionPaused(cToken, "Mint", state);
        return state;
    }

    function _setBorrowPaused(address cToken, bool state) external returns (bool) {
        require(msg.sender == pauseGuardian || msg.sender == admin, "UNAUTHORIZED");
        borrowGuardianPaused[cToken] = state;
        emit ActionPaused(cToken, "Borrow", state);
        return state;
    }

    // ============ View Functions ============

    function getAllMarkets() external view returns (address[] memory) {
        return allMarkets;
    }

    function getAssetsIn(address account) external view returns (address[] memory) {
        return accountAssets[account];
    }

    function checkMembership(address account, address cToken) external view returns (bool) {
        return markets[cToken].accountMembership[account];
    }
}
