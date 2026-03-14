// SPDX-License-Identifier: BUSL-1.1
pragma solidity ^0.8.10;

/**
 * @title Aave V3 AToken
 * @notice Interest-bearing token received when supplying to the Aave Pool.
 *         AToken balances grow over time as interest accrues (via the liquidity index).
 *
 * @dev AToken uses "scaled balances" internally:
 *      - scaledBalance = actualBalance / liquidityIndex at time of mint
 *      - actualBalance = scaledBalance * currentLiquidityIndex
 *
 *      This means the stored balance is static, but the reported balance grows
 *      automatically as the liquidity index increases with accrued interest.
 *
 *      Key difference from stETH's rebasing: AToken uses index-based scaling,
 *      while stETH uses shares-based math. Both achieve similar goals.
 *
 * Vulnerability surfaces:
 *      - Transfer validation must check sender's health factor
 *      - Rounding in scaled balance calculations can accumulate
 *      - mint/burn should only be callable by the Pool
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

interface IPool {
    function getReserveNormalizedIncome(address asset) external view returns (uint256);
    function finalizeTransfer(
        address asset,
        address from,
        address to,
        uint256 amount,
        uint256 balanceFromBefore,
        uint256 balanceToBefore
    ) external;
}

interface IERC20 {
    function transfer(address to, uint256 amount) external returns (bool);
    function balanceOf(address account) external view returns (uint256);
}

contract AToken {
    using WadRayMath for uint256;

    // ---- State ----
    string public name;
    string public symbol;
    uint8 public constant decimals = 18;

    /// @notice The Pool contract — only Pool can mint/burn
    IPool public immutable POOL;

    /// @notice The underlying ERC20 asset (e.g., USDC, WETH)
    address public immutable UNDERLYING_ASSET_ADDRESS;

    /// @notice Scaled balances: user => scaledBalance (balance / index at mint time)
    mapping(address => uint256) private _scaledBalances;

    /// @notice Total scaled supply
    uint256 private _scaledTotalSupply;

    /// @notice ERC20 allowances
    mapping(address => mapping(address => uint256)) private _allowances;

    /// @notice Incentives controller for reward distribution
    address public incentivesController;

    /// @notice Treasury address for protocol fees
    address public treasury;

    // ---- Events ----
    event Transfer(address indexed from, address indexed to, uint256 value);
    event Approval(address indexed owner, address indexed spender, uint256 value);
    event Mint(address indexed caller, address indexed onBehalfOf, uint256 value, uint256 balanceIncrease, uint256 index);
    event Burn(address indexed from, address indexed target, uint256 value, uint256 balanceIncrease, uint256 index);
    event BalanceTransfer(address indexed from, address indexed to, uint256 value, uint256 index);

    // ---- Modifiers ----
    modifier onlyPool() {
        require(msg.sender == address(POOL), "CALLER_MUST_BE_POOL");
        _;
    }

    // ---- Constructor ----
    constructor(
        address pool,
        address underlyingAsset,
        address _treasury,
        string memory _name,
        string memory _symbol
    ) {
        POOL = IPool(pool);
        UNDERLYING_ASSET_ADDRESS = underlyingAsset;
        treasury = _treasury;
        name = _name;
        symbol = _symbol;
    }

    // ============ Core Mint / Burn (Pool-only) ============

    /**
     * @notice Mint aTokens — called by Pool on supply().
     * @param caller The address performing the supply
     * @param onBehalfOf The address that will receive the aTokens
     * @param amount The amount of underlying being supplied
     * @param index Current liquidity index (ray)
     * @return True if this is the first supply (scaled balance was 0 before)
     *
     * @dev The minted amount in scaled terms = amount / index.
     *      Over time, as index grows, the same scaled balance represents more underlying.
     */
    function mint(
        address caller,
        address onBehalfOf,
        uint256 amount,
        uint256 index
    ) external onlyPool returns (bool) {
        uint256 previousScaledBalance = _scaledBalances[onBehalfOf];

        // Calculate balance increase since last interaction (accrued interest)
        uint256 previousBalance = previousScaledBalance.rayMul(index);
        uint256 balanceIncrease = previousBalance - (previousScaledBalance.rayMul(index)); // Simplified

        // Scaled amount to mint
        uint256 scaledAmount = amount.rayDiv(index);
        require(scaledAmount > 0, "ZERO_SCALED_AMOUNT");

        _scaledBalances[onBehalfOf] += scaledAmount;
        _scaledTotalSupply += scaledAmount;

        emit Transfer(address(0), onBehalfOf, amount);
        emit Mint(caller, onBehalfOf, amount, balanceIncrease, index);

        return previousScaledBalance == 0;
    }

    /**
     * @notice Burn aTokens — called by Pool on withdraw() or liquidation.
     * @param from The address whose aTokens are being burned
     * @param receiverOfUnderlying The address that will receive the underlying asset
     * @param amount The amount of underlying to withdraw
     * @param index Current liquidity index (ray)
     */
    function burn(
        address from,
        address receiverOfUnderlying,
        uint256 amount,
        uint256 index
    ) external onlyPool {
        uint256 scaledAmount = amount.rayDiv(index);
        require(scaledAmount > 0, "ZERO_SCALED_AMOUNT");
        require(_scaledBalances[from] >= scaledAmount, "INSUFFICIENT_BALANCE");

        _scaledBalances[from] -= scaledAmount;
        _scaledTotalSupply -= scaledAmount;

        // Transfer underlying to receiver
        IERC20(UNDERLYING_ASSET_ADDRESS).transfer(receiverOfUnderlying, amount);

        emit Transfer(from, address(0), amount);
        emit Burn(from, receiverOfUnderlying, amount, 0, index);
    }

    /**
     * @notice Transfer underlying from this contract to target.
     *         Used by Pool for flash loans and borrows.
     */
    function transferUnderlyingTo(address target, uint256 amount) external onlyPool {
        IERC20(UNDERLYING_ASSET_ADDRESS).transfer(target, amount);
    }

    /**
     * @notice Handle repayment callback — used for accounting/incentives.
     */
    function handleRepayment(address user, address onBehalfOf, uint256 amount) external onlyPool {
        // In production: update incentives, handle any bookkeeping
    }

    // ============ ERC20 with Scaled Balance ============

    /**
     * @notice Returns the scaled (internal) balance of a user.
     *         This is the balance that is actually stored.
     */
    function scaledBalanceOf(address user) external view returns (uint256) {
        return _scaledBalances[user];
    }

    /**
     * @notice Returns the actual balance of a user (scaled balance * current index).
     *         This is the real-time balance including accrued interest.
     */
    function balanceOf(address user) public view returns (uint256) {
        uint256 scaledBal = _scaledBalances[user];
        if (scaledBal == 0) return 0;
        return scaledBal.rayMul(POOL.getReserveNormalizedIncome(UNDERLYING_ASSET_ADDRESS));
    }

    function scaledTotalSupply() external view returns (uint256) {
        return _scaledTotalSupply;
    }

    function totalSupply() external view returns (uint256) {
        uint256 currentIndex = POOL.getReserveNormalizedIncome(UNDERLYING_ASSET_ADDRESS);
        return _scaledTotalSupply.rayMul(currentIndex);
    }

    /**
     * @notice Transfer aTokens.
     * @dev IMPORTANT: This calls Pool.finalizeTransfer() which validates that the
     *      sender's health factor remains >= 1 after the transfer. Without this check,
     *      users could transfer collateral-backing aTokens to escape liquidation.
     *
     *      Vulnerability surface: if finalizeTransfer has a bug or can be bypassed,
     *      undercollateralized positions could be created through transfers.
     */
    function transfer(address to, uint256 amount) external returns (bool) {
        _transfer(msg.sender, to, amount);
        return true;
    }

    function transferFrom(address from, address to, uint256 amount) external returns (bool) {
        uint256 currentAllowance = _allowances[from][msg.sender];
        if (currentAllowance != type(uint256).max) {
            require(currentAllowance >= amount, "INSUFFICIENT_ALLOWANCE");
            _allowances[from][msg.sender] = currentAllowance - amount;
        }
        _transfer(from, to, amount);
        return true;
    }

    function approve(address spender, uint256 amount) external returns (bool) {
        _allowances[msg.sender][spender] = amount;
        emit Approval(msg.sender, spender, amount);
        return true;
    }

    function allowance(address owner, address spender) external view returns (uint256) {
        return _allowances[owner][spender];
    }

    function _transfer(address from, address to, uint256 amount) internal {
        require(from != address(0), "TRANSFER_FROM_ZERO");
        require(to != address(0), "TRANSFER_TO_ZERO");

        uint256 index = POOL.getReserveNormalizedIncome(UNDERLYING_ASSET_ADDRESS);
        uint256 scaledAmount = amount.rayDiv(index);

        uint256 fromBalanceBefore = _scaledBalances[from].rayMul(index);
        uint256 toBalanceBefore = _scaledBalances[to].rayMul(index);

        require(_scaledBalances[from] >= scaledAmount, "INSUFFICIENT_BALANCE");

        _scaledBalances[from] -= scaledAmount;
        _scaledBalances[to] += scaledAmount;

        // CRITICAL: Validate the transfer doesn't make sender's position unhealthy
        POOL.finalizeTransfer(
            UNDERLYING_ASSET_ADDRESS,
            from,
            to,
            amount,
            fromBalanceBefore,
            toBalanceBefore
        );

        emit BalanceTransfer(from, to, scaledAmount, index);
        emit Transfer(from, to, amount);
    }
}
