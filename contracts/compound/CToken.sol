// SPDX-License-Identifier: BSD-3-Clause
pragma solidity ^0.8.10;

/**
 * @title Compound CToken
 * @notice CToken is the receipt token for lending in Compound V2. When users supply assets,
 *         they receive CTokens representing their share of the lending pool. CToken value
 *         increases over time as interest accrues.
 *
 * @dev Key mechanics:
 *      - Exchange rate = (totalCash + totalBorrows - totalReserves) / totalSupply
 *      - User's underlying balance = cTokenBalance * exchangeRate
 *      - Interest accrues per-block via `accrueInterest()`
 *      - Borrows are tracked per-user with an interest index
 *
 *      This is the CToken (CErc20) implementation for ERC20 underlying assets.
 *      CEther is similar but uses ETH directly.
 *
 * Vulnerability surfaces:
 *      - Exchange rate manipulation via direct token donations
 *      - First depositor attack: manipulate exchange rate with tiny supply + large donation
 *      - doTransferIn/doTransferOut: fee-on-transfer tokens break accounting
 *      - Reentrancy via underlying token callbacks (ERC777, hooks)
 *      - Interest accrual skipping: if accrueInterest reverts, state becomes stale
 *      - Borrow rate overflow at extreme utilization
 */

// ============ Interfaces ============

interface IComptroller {
    function mintAllowed(address cToken, address minter, uint256 mintAmount) external returns (uint256);
    function mintVerify(address cToken, address minter, uint256 actualMintAmount, uint256 mintTokens) external;
    function redeemAllowed(address cToken, address redeemer, uint256 redeemTokens) external returns (uint256);
    function redeemVerify(address cToken, address redeemer, uint256 redeemAmount, uint256 redeemTokens) external;
    function borrowAllowed(address cToken, address borrower, uint256 borrowAmount) external returns (uint256);
    function borrowVerify(address cToken, address borrower, uint256 borrowAmount) external;
    function repayBorrowAllowed(address cToken, address payer, address borrower, uint256 repayAmount) external returns (uint256);
    function liquidateBorrowAllowed(address cTokenBorrowed, address cTokenCollateral, address liquidator, address borrower, uint256 repayAmount) external returns (uint256);
    function seizeAllowed(address cTokenCollateral, address cTokenBorrowed, address liquidator, address borrower, uint256 seizeTokens) external returns (uint256);
    function transferAllowed(address cToken, address src, address dst, uint256 transferTokens) external returns (uint256);
    function liquidateCalculateSeizeTokens(address cTokenBorrowed, address cTokenCollateral, uint256 actualRepayAmount) external view returns (uint256, uint256);
}

interface IInterestRateModel {
    function getBorrowRate(uint256 cash, uint256 borrows, uint256 reserves) external view returns (uint256);
    function getSupplyRate(uint256 cash, uint256 borrows, uint256 reserves, uint256 reserveFactorMantissa) external view returns (uint256);
}

interface IERC20 {
    function balanceOf(address account) external view returns (uint256);
    function transfer(address to, uint256 amount) external returns (bool);
    function transferFrom(address from, address to, uint256 amount) external returns (bool);
}

// ============ Main Contract ============

contract CToken {
    // ---- Constants ----
    uint256 internal constant borrowRateMaxMantissa = 0.0005e16; // 0.0005% per block
    uint256 internal constant reserveFactorMaxMantissa = 1e18;   // 100%
    uint256 internal constant initialExchangeRateMantissa_ = 2e16; // 0.02 (50 cTokens per underlying)
    uint256 internal constant expScale = 1e18;
    uint256 internal constant halfExpScale = expScale / 2;

    // Error codes (Compound V2 style)
    uint256 internal constant NO_ERROR = 0;
    uint256 internal constant MATH_ERROR = 9;
    uint256 internal constant MARKET_NOT_LISTED = 12;
    uint256 internal constant INSUFFICIENT_BALANCE = 13;

    // ---- Storage (matching Compound's storage layout) ----

    /// @notice ERC20 token name
    string public name;
    string public symbol;
    uint8 public decimals;

    /// @notice Underlying ERC20 asset
    address public underlying;

    /// @notice Comptroller (access control + market policy)
    IComptroller public comptroller;

    /// @notice Interest rate model
    IInterestRateModel public interestRateModel;

    /// @notice Exchange rate mantissa at genesis (before any accrual)
    uint256 public initialExchangeRateMantissa;

    /// @notice Reserve factor — fraction of interest that goes to protocol reserves
    uint256 public reserveFactorMantissa;

    /// @notice Block number of last accrueInterest()
    uint256 public accrualBlockNumber;

    /// @notice Accumulator of total earned borrow interest (per unit of borrow)
    uint256 public borrowIndex;

    /// @notice Total outstanding borrows (underlying)
    uint256 public totalBorrows;

    /// @notice Protocol reserves (underlying)
    uint256 public totalReserves;

    /// @notice Total CToken supply
    uint256 public totalSupply;

    /// @notice CToken balances
    mapping(address => uint256) internal accountTokens;

    /// @notice ERC20 allowances
    mapping(address => mapping(address => uint256)) internal transferAllowances;

    /// @notice Per-account borrow state
    struct BorrowSnapshot {
        uint256 principal;     // Total outstanding borrow at last interaction
        uint256 interestIndex; // Borrow index at last interaction
    }
    mapping(address => BorrowSnapshot) internal accountBorrows;

    /// @notice Contract admin
    address public admin;
    address public pendingAdmin;

    /// @notice Reentrancy guard
    bool internal _notEntered;

    // ---- Events ----
    event Mint(address minter, uint256 mintAmount, uint256 mintTokens);
    event Redeem(address redeemer, uint256 redeemAmount, uint256 redeemTokens);
    event Borrow(address borrower, uint256 borrowAmount, uint256 accountBorrows, uint256 totalBorrows);
    event RepayBorrow(address payer, address borrower, uint256 repayAmount, uint256 accountBorrows, uint256 totalBorrows);
    event LiquidateBorrow(address liquidator, address borrower, uint256 repayAmount, address cTokenCollateral, uint256 seizeTokens);
    event AccrueInterest(uint256 cashPrior, uint256 interestAccumulated, uint256 borrowIndex, uint256 totalBorrows);
    event NewReserveFactor(uint256 oldReserveFactorMantissa, uint256 newReserveFactorMantissa);
    event ReservesAdded(address benefactor, uint256 addAmount, uint256 newTotalReserves);
    event ReservesReduced(address admin, uint256 reduceAmount, uint256 newTotalReserves);
    event Transfer(address indexed from, address indexed to, uint256 amount);
    event Approval(address indexed owner, address indexed spender, uint256 amount);
    event NewComptroller(IComptroller oldComptroller, IComptroller newComptroller);
    event NewMarketInterestRateModel(IInterestRateModel oldInterestRateModel, IInterestRateModel newInterestRateModel);

    // ---- Modifiers ----
    modifier nonReentrant() {
        require(_notEntered, "REENTRANCY");
        _notEntered = false;
        _;
        _notEntered = true;
    }

    // ---- Constructor ----
    constructor(
        address _underlying,
        address _comptroller,
        address _interestRateModel,
        string memory _name,
        string memory _symbol,
        uint8 _decimals
    ) {
        admin = msg.sender;
        underlying = _underlying;
        comptroller = IComptroller(_comptroller);
        interestRateModel = IInterestRateModel(_interestRateModel);
        initialExchangeRateMantissa = initialExchangeRateMantissa_;
        accrualBlockNumber = block.number;
        borrowIndex = expScale; // 1e18
        name = _name;
        symbol = _symbol;
        decimals = _decimals;
        _notEntered = true;
    }

    // ============ Interest Accrual ============

    /**
     * @notice Accrue interest since last accrual. Updates borrowIndex, totalBorrows, totalReserves.
     * @dev Called at the start of every state-changing function.
     *
     *      Math:
     *      - borrowRate = interestRateModel.getBorrowRate(cash, borrows, reserves)
     *      - interestAccumulated = borrowRate * blockDelta * totalBorrows / 1e18
     *      - totalBorrows += interestAccumulated
     *      - totalReserves += interestAccumulated * reserveFactor / 1e18
     *      - borrowIndex *= (1 + borrowRate * blockDelta)
     *
     *      Vulnerability: if this function is not called before state changes,
     *      interest calculations will be incorrect. All public functions must
     *      call accrueInterest() first (the "interest accumulation pattern").
     */
    function accrueInterest() public returns (uint256) {
        uint256 currentBlockNumber = block.number;
        uint256 accrualBlockNumberPrior = accrualBlockNumber;

        if (currentBlockNumber == accrualBlockNumberPrior) {
            return NO_ERROR; // Already accrued this block
        }

        uint256 cashPrior = getCashPrior();
        uint256 borrowsPrior = totalBorrows;
        uint256 reservesPrior = totalReserves;
        uint256 borrowIndexPrior = borrowIndex;

        // Get the current borrow rate from the interest rate model
        uint256 borrowRateMantissa = interestRateModel.getBorrowRate(cashPrior, borrowsPrior, reservesPrior);
        require(borrowRateMantissa <= borrowRateMaxMantissa, "BORROW_RATE_ABSURD");

        // Calculate blocks elapsed and interest accumulated
        uint256 blockDelta = currentBlockNumber - accrualBlockNumberPrior;

        /**
         * @dev Interest math using simple (not compounding) interest per block:
         *      simpleInterestFactor = borrowRate * blockDelta
         *      interestAccumulated = simpleInterestFactor * totalBorrows
         *
         *      NOTE: Compound V2 uses simple interest between accruals, not continuous compounding.
         *      This means the effective rate depends on accrual frequency.
         *      More frequent accruals = slightly higher effective rate (interest on interest).
         */
        uint256 simpleInterestFactor = borrowRateMantissa * blockDelta;
        uint256 interestAccumulated = simpleInterestFactor * borrowsPrior / expScale;

        uint256 totalBorrowsNew = borrowsPrior + interestAccumulated;
        uint256 totalReservesNew = reservesPrior + (interestAccumulated * reserveFactorMantissa / expScale);
        uint256 borrowIndexNew = borrowIndexPrior + (simpleInterestFactor * borrowIndexPrior / expScale);

        // Update state
        accrualBlockNumber = currentBlockNumber;
        borrowIndex = borrowIndexNew;
        totalBorrows = totalBorrowsNew;
        totalReserves = totalReservesNew;

        emit AccrueInterest(cashPrior, interestAccumulated, borrowIndexNew, totalBorrowsNew);
        return NO_ERROR;
    }

    // ============ Supply / Mint ============

    /**
     * @notice Supply underlying assets and receive cTokens.
     * @param mintAmount Amount of underlying to supply
     * @return 0 on success, error code otherwise
     *
     * @dev Exchange rate at mint time determines how many cTokens are received:
     *      cTokens = mintAmount / exchangeRate
     *
     *      Vulnerability: first depositor attack
     *      If totalSupply == 0, exchangeRate = initialExchangeRateMantissa.
     *      Attacker can: (1) mint 1 wei of cTokens, (2) donate large amount of underlying,
     *      (3) exchange rate inflates, (4) next user's mint rounds down to 0 cTokens.
     *      Mitigation: check mintTokens > 0, or use virtual shares.
     */
    function mint(uint256 mintAmount) external nonReentrant returns (uint256) {
        accrueInterest();
        return mintInternal(mintAmount);
    }

    function mintInternal(uint256 mintAmount) internal returns (uint256) {
        // Comptroller check
        uint256 allowed = comptroller.mintAllowed(address(this), msg.sender, mintAmount);
        require(allowed == 0, "COMPTROLLER_REJECTED");

        uint256 exchangeRateMantissa = exchangeRateStoredInternal();

        // Transfer underlying in
        uint256 actualMintAmount = doTransferIn(msg.sender, mintAmount);

        /**
         * @dev Calculate cTokens to mint:
         *      mintTokens = actualMintAmount * 1e18 / exchangeRate
         *
         *      Vulnerability: if actualMintAmount is very small relative to exchangeRate,
         *      mintTokens rounds down to 0 and the user loses their deposit.
         */
        uint256 mintTokens = actualMintAmount * expScale / exchangeRateMantissa;
        require(mintTokens > 0, "ZERO_MINT");

        totalSupply += mintTokens;
        accountTokens[msg.sender] += mintTokens;

        emit Mint(msg.sender, actualMintAmount, mintTokens);
        emit Transfer(address(0), msg.sender, mintTokens);

        comptroller.mintVerify(address(this), msg.sender, actualMintAmount, mintTokens);
        return NO_ERROR;
    }

    // ============ Withdraw / Redeem ============

    /**
     * @notice Redeem cTokens for underlying assets.
     * @param redeemTokens Amount of cTokens to redeem
     */
    function redeem(uint256 redeemTokens) external nonReentrant returns (uint256) {
        accrueInterest();
        return redeemInternal(redeemTokens);
    }

    /**
     * @notice Redeem a specific amount of underlying.
     * @param redeemAmount Amount of underlying to receive
     */
    function redeemUnderlying(uint256 redeemAmount) external nonReentrant returns (uint256) {
        accrueInterest();
        return redeemUnderlyingInternal(redeemAmount);
    }

    function redeemInternal(uint256 redeemTokens) internal returns (uint256) {
        uint256 exchangeRateMantissa = exchangeRateStoredInternal();
        uint256 redeemAmount = redeemTokens * exchangeRateMantissa / expScale;

        return redeemFresh(msg.sender, redeemTokens, redeemAmount);
    }

    function redeemUnderlyingInternal(uint256 redeemAmount) internal returns (uint256) {
        uint256 exchangeRateMantissa = exchangeRateStoredInternal();
        uint256 redeemTokens = redeemAmount * expScale / exchangeRateMantissa;

        return redeemFresh(msg.sender, redeemTokens, redeemAmount);
    }

    function redeemFresh(address redeemer, uint256 redeemTokens, uint256 redeemAmount) internal returns (uint256) {
        require(redeemTokens > 0 || redeemAmount > 0, "ZERO_REDEEM");

        // Comptroller: check if redeem would make position unhealthy
        uint256 allowed = comptroller.redeemAllowed(address(this), redeemer, redeemTokens);
        require(allowed == 0, "COMPTROLLER_REJECTED");

        require(getCashPrior() >= redeemAmount, "INSUFFICIENT_CASH");
        require(accountTokens[redeemer] >= redeemTokens, "INSUFFICIENT_BALANCE");

        totalSupply -= redeemTokens;
        accountTokens[redeemer] -= redeemTokens;

        doTransferOut(redeemer, redeemAmount);

        emit Redeem(redeemer, redeemAmount, redeemTokens);
        emit Transfer(redeemer, address(0), redeemTokens);

        comptroller.redeemVerify(address(this), redeemer, redeemAmount, redeemTokens);
        return NO_ERROR;
    }

    // ============ Borrow ============

    /**
     * @notice Borrow underlying assets.
     * @param borrowAmount Amount to borrow
     * @return 0 on success
     *
     * @dev The Comptroller checks that the user has sufficient collateral.
     *      Borrow balance tracking uses an index system:
     *      - accountBorrows[user].principal = outstanding borrow principal
     *      - accountBorrows[user].interestIndex = borrowIndex at last interaction
     *      - currentBorrow = principal * currentBorrowIndex / storedInterestIndex
     */
    function borrow(uint256 borrowAmount) external nonReentrant returns (uint256) {
        accrueInterest();
        return borrowInternal(borrowAmount);
    }

    function borrowInternal(uint256 borrowAmount) internal returns (uint256) {
        uint256 allowed = comptroller.borrowAllowed(address(this), msg.sender, borrowAmount);
        require(allowed == 0, "COMPTROLLER_REJECTED");

        require(getCashPrior() >= borrowAmount, "INSUFFICIENT_CASH");

        // Calculate current borrow balance
        uint256 accountBorrowsPrev = borrowBalanceStoredInternal(msg.sender);
        uint256 accountBorrowsNew = accountBorrowsPrev + borrowAmount;
        uint256 totalBorrowsNew = totalBorrows + borrowAmount;

        // Update state
        accountBorrows[msg.sender].principal = accountBorrowsNew;
        accountBorrows[msg.sender].interestIndex = borrowIndex;
        totalBorrows = totalBorrowsNew;

        // Transfer underlying to borrower
        doTransferOut(msg.sender, borrowAmount);

        emit Borrow(msg.sender, borrowAmount, accountBorrowsNew, totalBorrowsNew);
        comptroller.borrowVerify(address(this), msg.sender, borrowAmount);
        return NO_ERROR;
    }

    // ============ Repay ============

    /**
     * @notice Repay borrowed assets.
     * @param repayAmount Amount to repay (type(uint256).max for full repayment)
     */
    function repayBorrow(uint256 repayAmount) external nonReentrant returns (uint256) {
        accrueInterest();
        return repayBorrowInternal(repayAmount);
    }

    function repayBorrowBehalf(address borrower, uint256 repayAmount) external nonReentrant returns (uint256) {
        accrueInterest();
        return repayBorrowBehalfInternal(borrower, repayAmount);
    }

    function repayBorrowInternal(uint256 repayAmount) internal returns (uint256) {
        uint256 allowed = comptroller.repayBorrowAllowed(address(this), msg.sender, msg.sender, repayAmount);
        require(allowed == 0, "COMPTROLLER_REJECTED");

        return repayBorrowFresh(msg.sender, msg.sender, repayAmount);
    }

    function repayBorrowBehalfInternal(address borrower, uint256 repayAmount) internal returns (uint256) {
        uint256 allowed = comptroller.repayBorrowAllowed(address(this), msg.sender, borrower, repayAmount);
        require(allowed == 0, "COMPTROLLER_REJECTED");

        return repayBorrowFresh(msg.sender, borrower, repayAmount);
    }

    function repayBorrowFresh(address payer, address borrower, uint256 repayAmount) internal returns (uint256) {
        uint256 accountBorrowsPrev = borrowBalanceStoredInternal(borrower);

        uint256 repayAmountFinal;
        if (repayAmount == type(uint256).max) {
            repayAmountFinal = accountBorrowsPrev;
        } else {
            repayAmountFinal = repayAmount;
        }

        // Transfer underlying from payer
        uint256 actualRepayAmount = doTransferIn(payer, repayAmountFinal);

        uint256 accountBorrowsNew = accountBorrowsPrev - actualRepayAmount;
        uint256 totalBorrowsNew = totalBorrows - actualRepayAmount;

        accountBorrows[borrower].principal = accountBorrowsNew;
        accountBorrows[borrower].interestIndex = borrowIndex;
        totalBorrows = totalBorrowsNew;

        emit RepayBorrow(payer, borrower, actualRepayAmount, accountBorrowsNew, totalBorrowsNew);
        return NO_ERROR;
    }

    // ============ Liquidation ============

    /**
     * @notice Liquidate an undercollateralized borrow.
     * @param borrower The borrower to liquidate
     * @param repayAmount Amount of debt to repay
     * @param cTokenCollateral The CToken market to seize collateral from
     *
     * @dev Liquidation flow:
     *      1. Verify borrower is underwater (Comptroller.liquidateBorrowAllowed)
     *      2. Repay portion of borrower's debt
     *      3. Seize equivalent collateral + liquidation incentive from borrower
     *
     *      The liquidation incentive (e.g., 8%) rewards liquidators for maintaining
     *      system solvency.
     *
     *      Vulnerability surfaces:
     *      - Close factor limits how much can be liquidated per tx
     *      - Price oracle manipulation allows profitable liquidation of healthy users
     *      - Self-liquidation: user creates underwater position and liquidates themselves
     *        for the incentive (possible if gas cost < incentive value)
     */
    function liquidateBorrow(
        address borrower,
        uint256 repayAmount,
        address cTokenCollateral
    ) external nonReentrant returns (uint256) {
        accrueInterest();
        // Also accrue interest on the collateral market
        CToken(cTokenCollateral).accrueInterest();

        return liquidateBorrowInternal(borrower, repayAmount, cTokenCollateral);
    }

    function liquidateBorrowInternal(
        address borrower,
        uint256 repayAmount,
        address cTokenCollateral
    ) internal returns (uint256) {
        uint256 allowed = comptroller.liquidateBorrowAllowed(
            address(this), cTokenCollateral, msg.sender, borrower, repayAmount
        );
        require(allowed == 0, "COMPTROLLER_REJECTED");

        require(borrower != msg.sender, "CANNOT_SELF_LIQUIDATE");
        require(repayAmount > 0, "ZERO_REPAY");
        require(repayAmount != type(uint256).max, "USE_EXACT_AMOUNT");

        // Repay debt on behalf of borrower
        uint256 actualRepayAmount = doTransferIn(msg.sender, repayAmount);

        // Reduce borrower's debt
        uint256 accountBorrowsPrev = borrowBalanceStoredInternal(borrower);
        uint256 accountBorrowsNew = accountBorrowsPrev - actualRepayAmount;
        accountBorrows[borrower].principal = accountBorrowsNew;
        accountBorrows[borrower].interestIndex = borrowIndex;
        totalBorrows -= actualRepayAmount;

        // Calculate collateral to seize
        (uint256 err, uint256 seizeTokens) = comptroller.liquidateCalculateSeizeTokens(
            address(this), cTokenCollateral, actualRepayAmount
        );
        require(err == 0, "SEIZE_CALCULATION_FAILED");

        // Seize collateral from borrower
        require(CToken(cTokenCollateral).seize(msg.sender, borrower, seizeTokens) == 0, "SEIZE_FAILED");

        emit LiquidateBorrow(msg.sender, borrower, actualRepayAmount, cTokenCollateral, seizeTokens);
        return NO_ERROR;
    }

    /**
     * @notice Seize collateral tokens during liquidation.
     * @dev Only callable by another CToken market during liquidation.
     */
    function seize(address liquidator, address borrower, uint256 seizeTokens) external returns (uint256) {
        uint256 allowed = comptroller.seizeAllowed(address(this), msg.sender, liquidator, borrower, seizeTokens);
        require(allowed == 0, "COMPTROLLER_REJECTED");

        require(accountTokens[borrower] >= seizeTokens, "INSUFFICIENT_COLLATERAL");

        // Transfer cTokens from borrower to liquidator
        // A portion goes to protocol reserves (as additional incentive alignment)
        uint256 protocolSeizeShare = seizeTokens * 2.8e16 / expScale; // ~2.8% to reserves
        uint256 liquidatorSeizeTokens = seizeTokens - protocolSeizeShare;

        accountTokens[borrower] -= seizeTokens;
        accountTokens[liquidator] += liquidatorSeizeTokens;

        // Protocol share: convert to underlying and add to reserves
        uint256 exchangeRateMantissa = exchangeRateStoredInternal();
        uint256 protocolSeizeAmount = protocolSeizeShare * exchangeRateMantissa / expScale;
        totalReserves += protocolSeizeAmount;
        totalSupply -= protocolSeizeShare;

        emit Transfer(borrower, liquidator, liquidatorSeizeTokens);
        emit Transfer(borrower, address(0), protocolSeizeShare);
        return NO_ERROR;
    }

    // ============ Exchange Rate ============

    /**
     * @notice Get the current exchange rate (CToken to underlying).
     * @dev exchangeRate = (totalCash + totalBorrows - totalReserves) / totalSupply
     *
     *      If totalSupply == 0, returns initialExchangeRateMantissa.
     *
     *      Vulnerability: this function reads the current cash balance of the contract.
     *      If someone donates underlying tokens directly (not through mint()),
     *      the exchange rate increases — benefiting all existing CToken holders
     *      but not minting any new CTokens. This is the exchange rate manipulation vector.
     */
    function exchangeRateStored() public view returns (uint256) {
        return exchangeRateStoredInternal();
    }

    function exchangeRateStoredInternal() internal view returns (uint256) {
        if (totalSupply == 0) {
            return initialExchangeRateMantissa;
        }

        uint256 totalCash = getCashPrior();
        uint256 cashPlusBorrowsMinusReserves = totalCash + totalBorrows - totalReserves;

        uint256 exchangeRate = cashPlusBorrowsMinusReserves * expScale / totalSupply;
        return exchangeRate;
    }

    /**
     * @notice Get the current exchange rate, accruing interest first.
     */
    function exchangeRateCurrent() external returns (uint256) {
        accrueInterest();
        return exchangeRateStoredInternal();
    }

    // ============ Borrow Balance ============

    function borrowBalanceStored(address account) public view returns (uint256) {
        return borrowBalanceStoredInternal(account);
    }

    /**
     * @dev Calculate current borrow balance including accrued interest.
     *      currentBorrow = principal * currentBorrowIndex / storedBorrowIndex
     */
    function borrowBalanceStoredInternal(address account) internal view returns (uint256) {
        BorrowSnapshot storage borrowSnapshot = accountBorrows[account];
        if (borrowSnapshot.principal == 0) return 0;

        // Apply interest since last interaction
        uint256 principalTimesIndex = borrowSnapshot.principal * borrowIndex;
        return principalTimesIndex / borrowSnapshot.interestIndex;
    }

    // ============ Token Transfer Helpers ============

    /**
     * @dev Transfer underlying tokens into this contract.
     * @return The actual amount received (accounts for fee-on-transfer tokens).
     *
     * Vulnerability: fee-on-transfer tokens will cause actualAmount < amount,
     * leading to accounting discrepancies if not handled. Compound V2 originally
     * didn't account for this, leading to issues with deflationary tokens.
     */
    function doTransferIn(address from, uint256 amount) internal returns (uint256) {
        uint256 balanceBefore = IERC20(underlying).balanceOf(address(this));
        IERC20(underlying).transferFrom(from, address(this), amount);
        uint256 balanceAfter = IERC20(underlying).balanceOf(address(this));

        // Return actual amount received (handles fee-on-transfer)
        return balanceAfter - balanceBefore;
    }

    /**
     * @dev Transfer underlying tokens out of this contract.
     *
     * Vulnerability: if underlying is an ERC777 or has a transfer hook,
     * the recipient's callback could re-enter this contract.
     * The nonReentrant modifier on external functions mitigates this.
     */
    function doTransferOut(address to, uint256 amount) internal {
        bool success = IERC20(underlying).transfer(to, amount);
        require(success, "TRANSFER_OUT_FAILED");
    }

    function getCashPrior() internal view returns (uint256) {
        return IERC20(underlying).balanceOf(address(this));
    }

    // ============ ERC20 Implementation ============

    function balanceOf(address owner) external view returns (uint256) {
        return accountTokens[owner];
    }

    /**
     * @notice Get the underlying balance of an account (cTokens * exchangeRate).
     */
    function balanceOfUnderlying(address owner) external returns (uint256) {
        accrueInterest();
        return accountTokens[owner] * exchangeRateStoredInternal() / expScale;
    }

    function transfer(address dst, uint256 amount) external nonReentrant returns (bool) {
        return transferTokens(msg.sender, msg.sender, dst, amount) == 0;
    }

    function transferFrom(address src, address dst, uint256 amount) external nonReentrant returns (bool) {
        return transferTokens(msg.sender, src, dst, amount) == 0;
    }

    function transferTokens(address spender, address src, address dst, uint256 tokens) internal returns (uint256) {
        // Comptroller: verify transfer doesn't make sender's position unhealthy
        uint256 allowed = comptroller.transferAllowed(address(this), src, dst, tokens);
        require(allowed == 0, "COMPTROLLER_REJECTED");

        if (src != spender) {
            uint256 startingAllowance = transferAllowances[src][spender];
            require(startingAllowance >= tokens, "INSUFFICIENT_ALLOWANCE");
            transferAllowances[src][spender] = startingAllowance - tokens;
        }

        require(accountTokens[src] >= tokens, "INSUFFICIENT_BALANCE");
        accountTokens[src] -= tokens;
        accountTokens[dst] += tokens;

        emit Transfer(src, dst, tokens);
        return NO_ERROR;
    }

    function approve(address spender, uint256 amount) external returns (bool) {
        transferAllowances[msg.sender][spender] = amount;
        emit Approval(msg.sender, spender, amount);
        return true;
    }

    function allowance(address owner, address spender) external view returns (uint256) {
        return transferAllowances[owner][spender];
    }

    // ============ Admin ============

    function _setReserveFactor(uint256 newReserveFactorMantissa) external returns (uint256) {
        accrueInterest();
        require(msg.sender == admin, "ONLY_ADMIN");
        require(newReserveFactorMantissa <= reserveFactorMaxMantissa, "INVALID_RESERVE_FACTOR");
        uint256 old = reserveFactorMantissa;
        reserveFactorMantissa = newReserveFactorMantissa;
        emit NewReserveFactor(old, newReserveFactorMantissa);
        return NO_ERROR;
    }

    function _setInterestRateModel(address newInterestRateModel) external returns (uint256) {
        require(msg.sender == admin, "ONLY_ADMIN");
        accrueInterest();
        interestRateModel = IInterestRateModel(newInterestRateModel);
        emit NewMarketInterestRateModel(IInterestRateModel(address(0)), interestRateModel);
        return NO_ERROR;
    }

    function _setComptroller(address newComptroller) external returns (uint256) {
        require(msg.sender == admin, "ONLY_ADMIN");
        IComptroller old = comptroller;
        comptroller = IComptroller(newComptroller);
        emit NewComptroller(old, comptroller);
        return NO_ERROR;
    }

    function _reduceReserves(uint256 reduceAmount) external returns (uint256) {
        accrueInterest();
        require(msg.sender == admin, "ONLY_ADMIN");
        require(reduceAmount <= totalReserves, "INSUFFICIENT_RESERVES");
        require(reduceAmount <= getCashPrior(), "INSUFFICIENT_CASH");
        totalReserves -= reduceAmount;
        doTransferOut(admin, reduceAmount);
        emit ReservesReduced(admin, reduceAmount, totalReserves);
        return NO_ERROR;
    }

    function _addReserves(uint256 addAmount) external returns (uint256) {
        accrueInterest();
        uint256 actualAddAmount = doTransferIn(msg.sender, addAmount);
        totalReserves += actualAddAmount;
        emit ReservesAdded(msg.sender, actualAddAmount, totalReserves);
        return NO_ERROR;
    }
}
