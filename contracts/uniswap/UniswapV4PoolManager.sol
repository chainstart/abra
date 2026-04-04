// SPDX-License-Identifier: BUSL-1.1
pragma solidity ^0.8.24;

/**
 * @title Uniswap V4 PoolManager
 * @notice Singleton contract managing all Uniswap V4 pools. Key architectural changes from V3:
 *         - Single contract holds all pool state (no per-pool deployments)
 *         - Hook system: pluggable logic before/after each pool action
 *         - Flash accounting: net token transfers settled at end of lock scope
 *         - ERC-6909 claims: internal balances for gas-efficient multi-hop swaps
 *
 * @dev V4 uses a "lock and callback" pattern:
 *      1. User calls lock() which calls back to the user's contract
 *      2. Inside the callback, user performs swaps/liquidity operations
 *      3. Each operation only updates internal deltas (no token transfers yet)
 *      4. At the end of lock(), all deltas must net to zero (settled via take/settle)
 *
 *      This design eliminates intermediate token transfers in multi-hop swaps,
 *      saving significant gas.
 *
 * Vulnerability surfaces:
 *      - Hook contracts have powerful capabilities; malicious hooks can steal funds
 *      - Flash accounting: delta tracking must be exact or funds can be drained
 *      - Re-initialization of pools with different hooks
 *      - Hook permission flags in the address (leading bits) must match actual behavior
 *      - Lock reentrancy through hooks
 */

// ============ Types ============

/// @notice Identifies a pool. Hooks are embedded in the pool's identity.
struct PoolKey {
    address currency0;  // Lower-address token
    address currency1;  // Higher-address token
    uint24 fee;         // Fee tier
    int24 tickSpacing;  // Tick spacing
    address hooks;      // Hook contract address (permissions encoded in leading bits)
}

/// @notice Pool state stored in the singleton
struct PoolState {
    uint160 sqrtPriceX96;
    int24 tick;
    uint16 observationIndex;
    uint16 observationCardinality;
    uint16 observationCardinalityNext;
    uint8 feeProtocol;
    uint128 liquidity;
    uint256 feeGrowthGlobal0X128;
    uint256 feeGrowthGlobal1X128;
}

struct BalanceDelta {
    int128 amount0;
    int128 amount1;
}

struct ModifyLiquidityParams {
    int24 tickLower;
    int24 tickUpper;
    int256 liquidityDelta; // Positive = add, negative = remove
    bytes32 salt;          // Allows multiple positions per (owner, tickLower, tickUpper)
}

struct SwapParams {
    bool zeroForOne;
    int256 amountSpecified;
    uint160 sqrtPriceLimitX96;
}

// ============ Interfaces ============

interface IHooks {
    function beforeInitialize(address sender, PoolKey calldata key, uint160 sqrtPriceX96, bytes calldata hookData) external returns (bytes4);
    function afterInitialize(address sender, PoolKey calldata key, uint160 sqrtPriceX96, int24 tick, bytes calldata hookData) external returns (bytes4);
    function beforeAddLiquidity(address sender, PoolKey calldata key, ModifyLiquidityParams calldata params, bytes calldata hookData) external returns (bytes4);
    function afterAddLiquidity(address sender, PoolKey calldata key, ModifyLiquidityParams calldata params, BalanceDelta calldata delta, bytes calldata hookData) external returns (bytes4);
    function beforeRemoveLiquidity(address sender, PoolKey calldata key, ModifyLiquidityParams calldata params, bytes calldata hookData) external returns (bytes4);
    function afterRemoveLiquidity(address sender, PoolKey calldata key, ModifyLiquidityParams calldata params, BalanceDelta calldata delta, bytes calldata hookData) external returns (bytes4);
    function beforeSwap(address sender, PoolKey calldata key, SwapParams calldata params, bytes calldata hookData) external returns (bytes4, int128);
    function afterSwap(address sender, PoolKey calldata key, SwapParams calldata params, BalanceDelta calldata delta, bytes calldata hookData) external returns (bytes4, int128);
    function beforeDonate(address sender, PoolKey calldata key, uint256 amount0, uint256 amount1, bytes calldata hookData) external returns (bytes4);
    function afterDonate(address sender, PoolKey calldata key, uint256 amount0, uint256 amount1, bytes calldata hookData) external returns (bytes4);
}

interface ILockCallback {
    function lockAcquired(bytes calldata data) external returns (bytes memory);
}

interface IERC20 {
    function balanceOf(address account) external view returns (uint256);
    function transfer(address to, uint256 amount) external returns (bool);
    function transferFrom(address from, address to, uint256 amount) external returns (bool);
}

// ============ Main Contract ============

contract UniswapV4PoolManager {
    // ---- Constants ----
    uint256 private constant HOOK_BEFORE_INITIALIZE_FLAG = 1 << 159;
    uint256 private constant HOOK_AFTER_INITIALIZE_FLAG = 1 << 158;
    uint256 private constant HOOK_BEFORE_ADD_LIQUIDITY_FLAG = 1 << 157;
    uint256 private constant HOOK_AFTER_ADD_LIQUIDITY_FLAG = 1 << 156;
    uint256 private constant HOOK_BEFORE_REMOVE_LIQUIDITY_FLAG = 1 << 155;
    uint256 private constant HOOK_AFTER_REMOVE_LIQUIDITY_FLAG = 1 << 154;
    uint256 private constant HOOK_BEFORE_SWAP_FLAG = 1 << 153;
    uint256 private constant HOOK_AFTER_SWAP_FLAG = 1 << 152;
    uint256 private constant HOOK_BEFORE_DONATE_FLAG = 1 << 151;
    uint256 private constant HOOK_AFTER_DONATE_FLAG = 1 << 150;
    uint256 private constant HOOK_ACCESS_LOCK_FLAG = 1 << 149;

    // ---- State ----

    /// @notice Pool ID => Pool state
    mapping(bytes32 => PoolState) public pools;

    /// @notice The current lock caller (0 if not locked)
    address private _lockCaller;

    /// @notice Transient token deltas during lock scope: (locker, currency) => delta
    /// @dev Positive delta = PoolManager is owed tokens; Negative = PoolManager owes tokens
    mapping(address => mapping(address => int256)) public currencyDelta;

    /// @notice ERC-6909 internal balances (claims)
    /// @dev Users can hold token balances inside PoolManager for gas efficiency
    mapping(address => mapping(address => uint256)) public balanceOf;

    /// @notice Total supply of each ERC-6909 claim
    mapping(address => uint256) public totalSupply;

    /// @notice Nonce for non-zero delta tracking
    uint256 public nonzeroDeltaCount;

    /// @notice Protocol fee controller
    address public protocolFeeController;

    /// @notice Owner (governance)
    address public owner;

    // ---- Events ----
    event Initialize(bytes32 indexed poolId, address indexed currency0, address indexed currency1, uint24 fee, int24 tickSpacing, address hooks);
    event ModifyLiquidity(bytes32 indexed poolId, address indexed sender, int24 tickLower, int24 tickUpper, int256 liquidityDelta);
    event Swap(bytes32 indexed poolId, address indexed sender, int128 amount0, int128 amount1, uint160 sqrtPriceX96, uint128 liquidity, int24 tick);
    event Donate(bytes32 indexed poolId, address indexed sender, uint256 amount0, uint256 amount1);
    event Transfer(address indexed from, address indexed to, address indexed currency, uint256 amount);

    // ---- Modifiers ----

    /// @dev Only callable inside a lock() callback
    modifier onlyByLocker() {
        require(msg.sender == _lockCaller, "NOT_LOCKER");
        _;
    }

    modifier onlyOwner() {
        require(msg.sender == owner, "NOT_OWNER");
        _;
    }

    // ---- Constructor ----
    constructor() {
        owner = msg.sender;
    }

    // ============ Lock (Entry Point) ============

    /**
     * @notice Acquire a lock and execute operations via callback.
     * @param data Arbitrary data passed to the callback
     * @return result Data returned from the callback
     *
     * @dev This is the entry point for all pool operations. The flow:
     *      1. Set msg.sender as the lock holder
     *      2. Call back to msg.sender.lockAcquired(data)
     *      3. Inside callback: user calls swap/modifyLiquidity/etc — these only update deltas
     *      4. User calls settle() to pay tokens owed, take() to receive tokens owed
     *      5. After callback returns: verify all deltas are zero
     *
     *      Vulnerability surface:
     *      - If delta accounting has any bug, tokens can be stolen
     *      - Hooks called during the callback could manipulate state
     *      - Nested locks must be prevented (or carefully handled)
     */
    function lock(bytes calldata data) external returns (bytes memory result) {
        require(_lockCaller == address(0), "ALREADY_LOCKED");
        _lockCaller = msg.sender;

        // Callback — all pool operations happen here
        result = ILockCallback(msg.sender).lockAcquired(data);

        /**
         * @dev CRITICAL: After the callback, ALL currency deltas must be zero.
         *      This is the flash accounting invariant — it ensures that the PoolManager
         *      is never left owing or owed tokens.
         */
        require(nonzeroDeltaCount == 0, "CURRENCY_DELTAS_NOT_ZERO");

        _lockCaller = address(0);
    }

    // ============ Pool Initialization ============

    /**
     * @notice Initialize a new pool.
     * @param key Pool identification (token pair, fee, hooks)
     * @param sqrtPriceX96 Initial price
     * @param hookData Data forwarded to hook callbacks
     * @return tick The initial tick derived from the price
     */
    function initialize(
        PoolKey calldata key,
        uint160 sqrtPriceX96,
        bytes calldata hookData
    ) external returns (int24 tick) {
        // Validate pool key
        require(key.currency0 < key.currency1, "CURRENCIES_NOT_SORTED");
        require(key.fee < 1000000, "FEE_TOO_LARGE");

        /**
         * @dev Validate hook permissions match the hook address's leading bits.
         *      In V4, the hook's address encodes which callbacks it wants to receive.
         *      If the hook address has bit 159 set, it expects beforeInitialize calls.
         *      This is enforced at deploy time through CREATE2 mining.
         */
        _validateHookPermissions(key.hooks);

        bytes32 poolId = _getPoolId(key);
        require(pools[poolId].sqrtPriceX96 == 0, "POOL_ALREADY_INITIALIZED");

        // Before hook
        if (_hasPermission(key.hooks, HOOK_BEFORE_INITIALIZE_FLAG)) {
            require(
                IHooks(key.hooks).beforeInitialize(msg.sender, key, sqrtPriceX96, hookData)
                    == IHooks.beforeInitialize.selector,
                "HOOK_BEFORE_INIT_FAILED"
            );
        }

        // Initialize pool state
        tick = _getTickAtSqrtRatio(sqrtPriceX96);
        pools[poolId] = PoolState({
            sqrtPriceX96: sqrtPriceX96,
            tick: tick,
            observationIndex: 0,
            observationCardinality: 1,
            observationCardinalityNext: 1,
            feeProtocol: 0,
            liquidity: 0,
            feeGrowthGlobal0X128: 0,
            feeGrowthGlobal1X128: 0
        });

        // After hook
        if (_hasPermission(key.hooks, HOOK_AFTER_INITIALIZE_FLAG)) {
            require(
                IHooks(key.hooks).afterInitialize(msg.sender, key, sqrtPriceX96, tick, hookData)
                    == IHooks.afterInitialize.selector,
                "HOOK_AFTER_INIT_FAILED"
            );
        }

        emit Initialize(poolId, key.currency0, key.currency1, key.fee, key.tickSpacing, key.hooks);
    }

    // ============ Modify Liquidity ============

    /**
     * @notice Add or remove liquidity from a pool.
     * @param key Pool identifier
     * @param params Liquidity modification parameters
     * @param hookData Data forwarded to hooks
     * @return delta Token amounts owed/received
     *
     * @dev Does not transfer tokens — only updates deltas. Caller must settle via take/settle.
     */
    function modifyLiquidity(
        PoolKey calldata key,
        ModifyLiquidityParams calldata params,
        bytes calldata hookData
    ) external onlyByLocker returns (BalanceDelta memory delta) {
        bytes32 poolId = _getPoolId(key);
        PoolState storage pool = pools[poolId];
        require(pool.sqrtPriceX96 != 0, "POOL_NOT_INITIALIZED");

        // Before hook
        if (params.liquidityDelta > 0 && _hasPermission(key.hooks, HOOK_BEFORE_ADD_LIQUIDITY_FLAG)) {
            require(
                IHooks(key.hooks).beforeAddLiquidity(msg.sender, key, params, hookData)
                    == IHooks.beforeAddLiquidity.selector,
                "HOOK_FAILED"
            );
        } else if (params.liquidityDelta < 0 && _hasPermission(key.hooks, HOOK_BEFORE_REMOVE_LIQUIDITY_FLAG)) {
            require(
                IHooks(key.hooks).beforeRemoveLiquidity(msg.sender, key, params, hookData)
                    == IHooks.beforeRemoveLiquidity.selector,
                "HOOK_FAILED"
            );
        }

        // Compute token deltas (simplified)
        // In production: full tick math, fee computation, position management
        if (params.liquidityDelta > 0) {
            delta.amount0 = int128(params.liquidityDelta / 2);
            delta.amount1 = int128(params.liquidityDelta / 2);
            pool.liquidity += uint128(int128(params.liquidityDelta));
        } else {
            delta.amount0 = int128(params.liquidityDelta / 2);
            delta.amount1 = int128(params.liquidityDelta / 2);
            pool.liquidity -= uint128(int128(-params.liquidityDelta));
        }

        // Update currency deltas (flash accounting)
        _accountDelta(key.currency0, delta.amount0);
        _accountDelta(key.currency1, delta.amount1);

        // After hook
        if (params.liquidityDelta > 0 && _hasPermission(key.hooks, HOOK_AFTER_ADD_LIQUIDITY_FLAG)) {
            IHooks(key.hooks).afterAddLiquidity(msg.sender, key, params, delta, hookData);
        } else if (params.liquidityDelta < 0 && _hasPermission(key.hooks, HOOK_AFTER_REMOVE_LIQUIDITY_FLAG)) {
            IHooks(key.hooks).afterRemoveLiquidity(msg.sender, key, params, delta, hookData);
        }

        emit ModifyLiquidity(poolId, msg.sender, params.tickLower, params.tickUpper, params.liquidityDelta);
    }

    // ============ Swap ============

    /**
     * @notice Execute a swap.
     * @param key Pool identifier
     * @param params Swap parameters (direction, amount, price limit)
     * @param hookData Data forwarded to hooks
     * @return delta Token amounts swapped
     *
     * @dev Hooks can return a "hookDelta" to modify the swap amounts. This is used
     *      for features like dynamic fees, TWAMM, limit orders, etc.
     *
     *      Vulnerability surface:
     *      - beforeSwap hook can modify swap parameters or front-run
     *      - afterSwap hook sees final state and could manipulate
     *      - Hook delta allows hooks to take extra tokens (must be audited per-hook)
     */
    function swap(
        PoolKey calldata key,
        SwapParams calldata params,
        bytes calldata hookData
    ) external onlyByLocker returns (BalanceDelta memory delta) {
        bytes32 poolId = _getPoolId(key);
        PoolState storage pool = pools[poolId];
        require(pool.sqrtPriceX96 != 0, "POOL_NOT_INITIALIZED");

        // Before swap hook
        int128 hookDeltaSpecified = 0;
        if (_hasPermission(key.hooks, HOOK_BEFORE_SWAP_FLAG)) {
            bytes4 selector;
            (selector, hookDeltaSpecified) = IHooks(key.hooks).beforeSwap(
                msg.sender, key, params, hookData
            );
            require(selector == IHooks.beforeSwap.selector, "HOOK_BEFORE_SWAP_FAILED");
        }

        // Execute swap logic (simplified)
        // In production: iterates through ticks like V3
        int256 amountSpecified = params.amountSpecified + hookDeltaSpecified;
        bool exactInput = amountSpecified > 0;

        if (params.zeroForOne) {
            // Sell token0, buy token1
            delta.amount0 = int128(amountSpecified);
            // Apply fee
            uint256 feeAmount = uint256(amountSpecified > 0 ? amountSpecified : -amountSpecified) * key.fee / 1e6;
            delta.amount1 = -int128(int256(uint256(amountSpecified > 0 ? amountSpecified : -amountSpecified) - feeAmount));
            // Update price (simplified)
            pool.tick -= 1;
        } else {
            delta.amount1 = int128(amountSpecified);
            uint256 feeAmount = uint256(amountSpecified > 0 ? amountSpecified : -amountSpecified) * key.fee / 1e6;
            delta.amount0 = -int128(int256(uint256(amountSpecified > 0 ? amountSpecified : -amountSpecified) - feeAmount));
            pool.tick += 1;
        }

        // After swap hook
        int128 hookDeltaUnspecified = 0;
        if (_hasPermission(key.hooks, HOOK_AFTER_SWAP_FLAG)) {
            bytes4 selector;
            (selector, hookDeltaUnspecified) = IHooks(key.hooks).afterSwap(
                msg.sender, key, params, delta, hookData
            );
            require(selector == IHooks.afterSwap.selector, "HOOK_AFTER_SWAP_FAILED");
        }

        // Apply hook deltas
        if (hookDeltaUnspecified != 0) {
            if (params.zeroForOne) {
                delta.amount1 += hookDeltaUnspecified;
            } else {
                delta.amount0 += hookDeltaUnspecified;
            }
        }

        // Update flash accounting deltas
        _accountDelta(key.currency0, delta.amount0);
        _accountDelta(key.currency1, delta.amount1);

        emit Swap(poolId, msg.sender, delta.amount0, delta.amount1, pool.sqrtPriceX96, pool.liquidity, pool.tick);
    }

    // ============ Donate ============

    /**
     * @notice Donate tokens to in-range LPs (distribute fees/rewards).
     */
    function donate(
        PoolKey calldata key,
        uint256 amount0,
        uint256 amount1,
        bytes calldata hookData
    ) external onlyByLocker returns (BalanceDelta memory delta) {
        bytes32 poolId = _getPoolId(key);
        PoolState storage pool = pools[poolId];
        require(pool.liquidity > 0, "NO_LIQUIDITY");

        if (_hasPermission(key.hooks, HOOK_BEFORE_DONATE_FLAG)) {
            require(
                IHooks(key.hooks).beforeDonate(msg.sender, key, amount0, amount1, hookData)
                    == IHooks.beforeDonate.selector,
                "HOOK_FAILED"
            );
        }

        delta.amount0 = int128(int256(amount0));
        delta.amount1 = int128(int256(amount1));

        // Distribute to LPs via fee growth
        if (amount0 > 0) {
            pool.feeGrowthGlobal0X128 += (amount0 << 128) / pool.liquidity;
        }
        if (amount1 > 0) {
            pool.feeGrowthGlobal1X128 += (amount1 << 128) / pool.liquidity;
        }

        _accountDelta(key.currency0, delta.amount0);
        _accountDelta(key.currency1, delta.amount1);

        if (_hasPermission(key.hooks, HOOK_AFTER_DONATE_FLAG)) {
            IHooks(key.hooks).afterDonate(msg.sender, key, amount0, amount1, hookData);
        }

        emit Donate(poolId, msg.sender, amount0, amount1);
    }

    // ============ Settlement (Flash Accounting) ============

    /**
     * @notice Take tokens from the PoolManager (when delta is negative = PM owes caller).
     * @param currency Token to take
     * @param to Recipient
     * @param amount Amount to take
     */
    function take(address currency, address to, uint256 amount) external onlyByLocker {
        _accountDelta(currency, int256(amount)); // Increases what caller owes
        IERC20(currency).transfer(to, amount);
    }

    /**
     * @notice Pay tokens to the PoolManager (when delta is positive = caller owes PM).
     * @param currency Token to settle
     * @return paid Amount of tokens credited to the caller's settlement
     *
     * @dev Caller must have already transferred tokens to this contract.
     *      settle() checks the balance increase to credit the caller.
     */
    function settle(address currency) external payable onlyByLocker returns (uint256 paid) {
        // Check how many tokens were received (compare current balance to expected)
        uint256 reservesBefore = _getReserves(currency);
        // In production: caller has already transferred tokens before calling settle
        paid = IERC20(currency).balanceOf(address(this)) - reservesBefore;
        _accountDelta(currency, -int256(paid)); // Decreases what caller owes
    }

    /**
     * @notice Mint ERC-6909 claim tokens (internal balance) instead of transferring.
     *         More gas efficient for users who will use the tokens in subsequent operations.
     */
    function mint(address to, address currency, uint256 amount) external onlyByLocker {
        _accountDelta(currency, int256(amount));
        balanceOf[to][currency] += amount;
        totalSupply[currency] += amount;
    }

    /**
     * @notice Burn ERC-6909 claim tokens to settle a positive delta.
     */
    function burn(address from, address currency, uint256 amount) external onlyByLocker {
        require(msg.sender == from || msg.sender == _lockCaller, "NOT_AUTHORIZED");
        _accountDelta(currency, -int256(amount));
        balanceOf[from][currency] -= amount;
        totalSupply[currency] -= amount;
    }

    // ============ Internal Functions ============

    /**
     * @dev Update the currency delta for the current locker.
     *      Tracks nonzeroDeltaCount for the final invariant check.
     */
    function _accountDelta(address currency, int256 delta) internal {
        if (delta == 0) return;

        int256 current = currencyDelta[_lockCaller][currency];
        int256 next = current + delta;

        if (next == 0 && current != 0) {
            nonzeroDeltaCount--;
        } else if (next != 0 && current == 0) {
            nonzeroDeltaCount++;
        }

        currencyDelta[_lockCaller][currency] = next;
    }

    function _getPoolId(PoolKey calldata key) internal pure returns (bytes32) {
        return keccak256(abi.encode(key));
    }

    function _hasPermission(address hooks, uint256 flag) internal pure returns (bool) {
        if (hooks == address(0)) return false;
        return uint256(uint160(hooks)) & flag != 0;
    }

    function _validateHookPermissions(address hooks) internal pure {
        // In production: validates that the hook address's leading bits match
        // the actual callback implementations the hook contract has
        // This prevents hooks from receiving unexpected callbacks
    }

    function _getTickAtSqrtRatio(uint160 sqrtPriceX96) internal pure returns (int24) {
        // Simplified — full implementation in TickMath library
        return int24(int256(uint256(sqrtPriceX96)));
    }

    function _getReserves(address currency) internal view returns (uint256) {
        return IERC20(currency).balanceOf(address(this)) - totalSupply[currency];
    }
}
