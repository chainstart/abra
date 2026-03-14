// SPDX-License-Identifier: MIT
pragma solidity ^0.8.17;

/**
 * @title Curve StableSwap
 * @notice Implements the Curve StableSwap AMM invariant for pegged assets (stablecoins, wETH/stETH, etc.).
 *         Translated from Vyper for Solidity-based analysis.
 *
 * @dev The StableSwap invariant is a hybrid between constant-sum (x + y = k) and
 *      constant-product (x * y = k), controlled by the amplification parameter A:
 *
 *      A * n^n * sum(xi) + D = A * D * n^n + D^(n+1) / (n^n * product(xi))
 *
 *      When A -> infinity: behaves like constant-sum (no slippage for pegged assets)
 *      When A -> 0: behaves like constant-product (like Uniswap)
 *
 *      This gives very low slippage for similarly-priced assets while still
 *      maintaining the invariant properties needed for an AMM.
 *
 * Vulnerability surfaces:
 *      - Amplification parameter (A) changes affect virtual price — can be exploited during ramp
 *      - Read-only reentrancy via get_virtual_price() (the famous Curve vuln)
 *      - Imbalanced add/remove liquidity can extract value if fees are miscalculated
 *      - Admin fee accumulation and collection timing
 *      - Integer overflow/underflow in the Newton's method iterations for get_D/get_y
 *      - Donation attacks on empty or low-liquidity pools
 */

interface IERC20 {
    function balanceOf(address account) external view returns (uint256);
    function transfer(address to, uint256 amount) external returns (bool);
    function transferFrom(address from, address to, uint256 amount) external returns (bool);
    function decimals() external view returns (uint8);
}

contract StableSwap {
    // ---- Constants ----
    uint256 public constant N_COINS = 2; // Number of coins in the pool (2-pool shown)
    uint256 public constant FEE_DENOMINATOR = 1e10;
    uint256 public constant PRECISION = 1e18;
    uint256 public constant A_PRECISION = 100;
    uint256 public constant MAX_A = 1e6;
    uint256 public constant MAX_A_CHANGE = 10;
    uint256 public constant MIN_RAMP_TIME = 86400; // 1 day
    uint256 public constant MAX_FEE = 5e9; // 50%
    uint256 public constant MAX_ADMIN_FEE = 1e10; // 100%

    // ---- State Variables ----
    address[N_COINS] public coins;
    uint256[N_COINS] public balances; // Pool balances (normalized to 18 decimals)
    uint256[N_COINS] public RATES; // Rate multipliers to normalize to 18 decimals

    uint256 public fee; // Swap fee (e.g., 4e6 = 0.04%)
    uint256 public admin_fee; // Admin's share of the fee (e.g., 5e9 = 50%)

    uint256 public initial_A;
    uint256 public future_A;
    uint256 public initial_A_time;
    uint256 public future_A_time;

    address public owner;
    address public lp_token; // LP token (CRV LP) contract

    uint256 public admin_actions_deadline;
    uint256 public future_fee;
    uint256 public future_admin_fee;

    bool public is_killed;
    uint256 public kill_deadline;
    uint256 public constant KILL_DEADLINE_DT = 2 * 30 * 86400; // ~2 months

    // Reentrancy guard
    uint256 private _locked;

    // ---- Events ----
    event TokenExchange(address indexed buyer, int128 sold_id, uint256 tokens_sold, int128 bought_id, uint256 tokens_bought);
    event AddLiquidity(address indexed provider, uint256[N_COINS] token_amounts, uint256[N_COINS] fees, uint256 invariant, uint256 token_supply);
    event RemoveLiquidity(address indexed provider, uint256[N_COINS] token_amounts, uint256[N_COINS] fees, uint256 token_supply);
    event RemoveLiquidityOne(address indexed provider, uint256 token_amount, uint256 coin_amount, uint256 token_supply);
    event RemoveLiquidityImbalance(address indexed provider, uint256[N_COINS] token_amounts, uint256[N_COINS] fees, uint256 invariant, uint256 token_supply);
    event RampA(uint256 old_A, uint256 new_A, uint256 initial_time, uint256 future_time);
    event StopRampA(uint256 A, uint256 t);
    event CommitNewFee(uint256 new_fee, uint256 new_admin_fee);
    event NewFee(uint256 fee, uint256 admin_fee);

    // ---- Modifiers ----
    modifier nonReentrant() {
        require(_locked == 0, "REENTRANCY");
        _locked = 1;
        _;
        _locked = 0;
    }

    modifier onlyOwner() {
        require(msg.sender == owner, "ONLY_OWNER");
        _;
    }

    modifier notKilled() {
        require(!is_killed, "POOL_IS_KILLED");
        _;
    }

    // ---- Constructor ----
    constructor(
        address[N_COINS] memory _coins,
        address _lp_token,
        uint256 _A,
        uint256 _fee,
        uint256 _admin_fee
    ) {
        for (uint256 i = 0; i < N_COINS; i++) {
            require(_coins[i] != address(0), "ZERO_ADDRESS");
            uint8 decimals = IERC20(_coins[i]).decimals();
            RATES[i] = 10 ** (36 - decimals); // Normalize to 18 decimals
            coins[i] = _coins[i];
        }
        initial_A = _A * A_PRECISION;
        future_A = _A * A_PRECISION;
        fee = _fee;
        admin_fee = _admin_fee;
        owner = msg.sender;
        lp_token = _lp_token;
        kill_deadline = block.timestamp + KILL_DEADLINE_DT;
    }

    // ============ Amplification Parameter ============

    /**
     * @notice Get the current amplification parameter, accounting for ramping.
     * @dev A can be ramped up or down over time. During a ramp, A is linearly
     *      interpolated between initial_A and future_A.
     *
     *      Vulnerability surface: A changes affect virtual_price and D calculation.
     *      During a ramp, an attacker can exploit the changing A to extract value
     *      by adding/removing liquidity at strategic moments.
     */
    function A() public view returns (uint256) {
        uint256 t1 = future_A_time;
        uint256 A1 = future_A;

        if (block.timestamp < t1) {
            uint256 A0 = initial_A;
            uint256 t0 = initial_A_time;
            // Linear interpolation
            if (A1 > A0) {
                return A0 + (A1 - A0) * (block.timestamp - t0) / (t1 - t0);
            } else {
                return A0 - (A0 - A1) * (block.timestamp - t0) / (t1 - t0);
            }
        }
        return A1;
    }

    function A_precise() public view returns (uint256) {
        return A();
    }

    // ============ StableSwap Math ============

    /**
     * @notice Calculate the StableSwap invariant D.
     * @dev D is the total pool value when all assets are at equal price (balanced).
     *      Found via Newton's method on:
     *      A * n^n * sum(xi) + D = A * D * n^n + D^(n+1) / (n^n * product(xi))
     *
     *      Newton's iteration:
     *      D_P = D^(n+1) / (n^n * product(xi))
     *      D = (A * n^n * sum(xi) + D_P * n) * D / ((A * n^n - 1) * D + (n + 1) * D_P)
     *
     *      Converges in ~5-7 iterations for typical parameters.
     *
     *      Vulnerability: if Newton's method doesn't converge (extreme parameters),
     *      the function reverts. Attackers cannot cause this in practice with normal
     *      pool states, but edge cases with very low liquidity need care.
     */
    function get_D(uint256[N_COINS] memory xp, uint256 amp) public pure returns (uint256) {
        uint256 S = 0;
        for (uint256 i = 0; i < N_COINS; i++) {
            S += xp[i];
        }
        if (S == 0) return 0;

        uint256 Dprev;
        uint256 D = S;
        uint256 Ann = amp * N_COINS;

        for (uint256 _i = 0; _i < 255; _i++) {
            uint256 D_P = D;
            for (uint256 j = 0; j < N_COINS; j++) {
                // D_P = D_P * D / (xp[j] * N_COINS)
                // +1 to prevent division by zero
                D_P = D_P * D / (xp[j] * N_COINS + 1);
            }
            Dprev = D;

            // D = (Ann * S / A_PRECISION + D_P * N_COINS) * D /
            //     ((Ann - A_PRECISION) * D / A_PRECISION + (N_COINS + 1) * D_P)
            uint256 numerator = (Ann * S / A_PRECISION + D_P * N_COINS) * D;
            uint256 denominator = (Ann - A_PRECISION) * D / A_PRECISION + (N_COINS + 1) * D_P;
            D = numerator / denominator;

            // Check convergence
            if (D > Dprev) {
                if (D - Dprev <= 1) return D;
            } else {
                if (Dprev - D <= 1) return D;
            }
        }
        revert("D_NOT_CONVERGED");
    }

    /**
     * @notice Calculate the output amount for a swap (find y given x and D).
     * @dev Given that coin j's balance changed to x, find what coin i's balance should be
     *      to maintain invariant D.
     *
     *      Newton's method on: y^2 + y * (sum' - (A*n^n - 1) * D / (A * n^n)) = D^(n+1) / (n^(2n) * prod' * A * n^n)
     *      where sum' and prod' exclude the coin being solved for.
     */
    function get_y(int128 i, int128 j, uint256 x, uint256[N_COINS] memory xp) public view returns (uint256) {
        require(i != j, "SAME_COIN");
        require(i >= 0 && j >= 0, "NEGATIVE_INDEX");
        require(uint128(i) < N_COINS && uint128(j) < N_COINS, "INDEX_OUT_OF_RANGE");

        uint256 amp = A_precise();
        uint256 D = get_D(xp, amp);
        uint256 Ann = amp * N_COINS;

        uint256 c = D;
        uint256 S_ = 0;

        // c = D^(n+1) / (n^n * product(xp[k] for k != j))
        // S_ = sum(xp[k] for k != j)
        for (uint256 k = 0; k < N_COINS; k++) {
            uint256 x_k;
            if (uint256(int256(k)) == uint256(int256(i))) {
                x_k = x;
            } else if (uint256(int256(k)) != uint256(int256(j))) {
                x_k = xp[k];
            } else {
                continue;
            }
            S_ += x_k;
            c = c * D / (x_k * N_COINS);
        }

        c = c * D * A_PRECISION / (Ann * N_COINS);
        uint256 b = S_ + D * A_PRECISION / Ann;

        // Newton's iteration: y = (y^2 + c) / (2*y + b - D)
        uint256 y = D;
        uint256 y_prev;
        for (uint256 _i = 0; _i < 255; _i++) {
            y_prev = y;
            y = (y * y + c) / (2 * y + b - D);

            if (y > y_prev) {
                if (y - y_prev <= 1) return y;
            } else {
                if (y_prev - y <= 1) return y;
            }
        }
        revert("Y_NOT_CONVERGED");
    }

    // ============ Exchange (Swap) ============

    /**
     * @notice Exchange (swap) one coin for another.
     * @param i Index of the coin to sell
     * @param j Index of the coin to buy
     * @param dx Amount of coin i to sell
     * @param min_dy Minimum amount of coin j to receive (slippage protection)
     * @return dy Amount of coin j received
     *
     * @dev The swap fee is applied to the output amount:
     *      dy_fee = dy * fee / FEE_DENOMINATOR
     *      admin_fee_portion = dy_fee * admin_fee / FEE_DENOMINATOR
     */
    function exchange(
        int128 i,
        int128 j,
        uint256 dx,
        uint256 min_dy
    ) external nonReentrant notKilled returns (uint256 dy) {
        require(dx > 0, "ZERO_AMOUNT");

        uint256[N_COINS] memory xp = _xp();

        // Transfer input token
        uint256 x = xp[uint256(int256(i))] + dx * RATES[uint256(int256(i))] / PRECISION;

        // Calculate output
        uint256 y = get_y(i, j, x, xp);
        dy = xp[uint256(int256(j))] - y - 1; // -1 for rounding in pool's favor

        // Apply fee
        uint256 dy_fee = dy * fee / FEE_DENOMINATOR;
        dy = (dy - dy_fee) * PRECISION / RATES[uint256(int256(j))];
        require(dy >= min_dy, "SLIPPAGE");

        // Admin fee: portion of the fee that goes to admin
        uint256 dy_admin_fee = dy_fee * admin_fee / FEE_DENOMINATOR;
        dy_admin_fee = dy_admin_fee * PRECISION / RATES[uint256(int256(j))];

        // Update balances
        balances[uint256(int256(i))] += dx;
        balances[uint256(int256(j))] -= (dy + dy_admin_fee);

        // Transfer tokens
        IERC20(coins[uint256(int256(i))]).transferFrom(msg.sender, address(this), dx);
        IERC20(coins[uint256(int256(j))]).transfer(msg.sender, dy);

        emit TokenExchange(msg.sender, i, dx, j, dy);
    }

    // ============ Add Liquidity ============

    /**
     * @notice Add liquidity to the pool.
     * @param amounts Array of token amounts to deposit
     * @param min_mint_amount Minimum LP tokens to receive
     * @return mint_amount Amount of LP tokens minted
     *
     * @dev Adding imbalanced liquidity charges a fee proportional to the imbalance.
     *      This prevents free arbitrage via add_liquidity + remove_liquidity_one_coin.
     *
     *      Vulnerability surface:
     *      - First depositor can be sandwiched to steal value
     *      - The imbalance fee calculation must be correct or value can be extracted
     */
    function add_liquidity(
        uint256[N_COINS] memory amounts,
        uint256 min_mint_amount
    ) external nonReentrant notKilled returns (uint256 mint_amount) {
        uint256 amp = A_precise();
        uint256[N_COINS] memory old_balances = balances;
        uint256 D0 = get_D(_xp_mem(old_balances), amp);

        uint256[N_COINS] memory new_balances = old_balances;
        for (uint256 i = 0; i < N_COINS; i++) {
            if (D0 == 0) {
                require(amounts[i] > 0, "INITIAL_DEPOSIT_REQUIRES_ALL_COINS");
            }
            new_balances[i] += amounts[i];
        }

        uint256 D1 = get_D(_xp_mem(new_balances), amp);
        require(D1 > D0, "D_MUST_INCREASE");

        // Calculate fees for imbalanced deposit
        uint256 D2 = D1;
        uint256[N_COINS] memory fees;
        uint256 token_supply = _getLPTotalSupply();

        if (token_supply > 0) {
            uint256 _fee = fee * N_COINS / (4 * (N_COINS - 1));
            for (uint256 i = 0; i < N_COINS; i++) {
                uint256 ideal_balance = D1 * old_balances[i] / D0;
                uint256 difference;
                if (ideal_balance > new_balances[i]) {
                    difference = ideal_balance - new_balances[i];
                } else {
                    difference = new_balances[i] - ideal_balance;
                }
                fees[i] = _fee * difference / FEE_DENOMINATOR;
                // Admin fee portion
                balances[i] = new_balances[i] - (fees[i] * admin_fee / FEE_DENOMINATOR);
                new_balances[i] -= fees[i];
            }
            D2 = get_D(_xp_mem(new_balances), amp);
            mint_amount = token_supply * (D2 - D0) / D0;
        } else {
            // First deposit
            for (uint256 i = 0; i < N_COINS; i++) {
                balances[i] = new_balances[i];
            }
            mint_amount = D1;
        }

        require(mint_amount >= min_mint_amount, "SLIPPAGE");

        // Transfer tokens in
        for (uint256 i = 0; i < N_COINS; i++) {
            if (amounts[i] > 0) {
                IERC20(coins[i]).transferFrom(msg.sender, address(this), amounts[i]);
            }
        }

        // Mint LP tokens (simplified — in production calls LP token contract)
        // ILPToken(lp_token).mint(msg.sender, mint_amount);

        emit AddLiquidity(msg.sender, amounts, fees, D2, token_supply + mint_amount);
    }

    // ============ Remove Liquidity ============

    /**
     * @notice Remove liquidity proportionally (no fee).
     * @param _amount Amount of LP tokens to burn
     * @param min_amounts Minimum amounts of each coin to receive
     */
    function remove_liquidity(
        uint256 _amount,
        uint256[N_COINS] memory min_amounts
    ) external nonReentrant {
        uint256 total_supply = _getLPTotalSupply();
        uint256[N_COINS] memory amounts;
        uint256[N_COINS] memory fees; // No fees for proportional withdrawal

        for (uint256 i = 0; i < N_COINS; i++) {
            amounts[i] = balances[i] * _amount / total_supply;
            require(amounts[i] >= min_amounts[i], "SLIPPAGE");
            balances[i] -= amounts[i];
            IERC20(coins[i]).transfer(msg.sender, amounts[i]);
        }

        // Burn LP tokens
        // ILPToken(lp_token).burnFrom(msg.sender, _amount);

        emit RemoveLiquidity(msg.sender, amounts, fees, total_supply - _amount);
    }

    /**
     * @notice Remove liquidity in an imbalanced manner (charges fee).
     * @param amounts Desired amounts of each coin to receive
     * @param max_burn_amount Maximum LP tokens to burn
     */
    function remove_liquidity_imbalance(
        uint256[N_COINS] memory amounts,
        uint256 max_burn_amount
    ) external nonReentrant {
        uint256 amp = A_precise();
        uint256 token_supply = _getLPTotalSupply();
        require(token_supply > 0, "EMPTY_POOL");

        uint256[N_COINS] memory old_balances = balances;
        uint256[N_COINS] memory new_balances = old_balances;
        uint256 D0 = get_D(_xp_mem(old_balances), amp);

        for (uint256 i = 0; i < N_COINS; i++) {
            new_balances[i] -= amounts[i];
        }
        uint256 D1 = get_D(_xp_mem(new_balances), amp);

        // Calculate fees (same logic as add_liquidity)
        uint256 _fee = fee * N_COINS / (4 * (N_COINS - 1));
        uint256[N_COINS] memory fees;
        for (uint256 i = 0; i < N_COINS; i++) {
            uint256 ideal_balance = D1 * old_balances[i] / D0;
            uint256 difference;
            if (ideal_balance > new_balances[i]) {
                difference = ideal_balance - new_balances[i];
            } else {
                difference = new_balances[i] - ideal_balance;
            }
            fees[i] = _fee * difference / FEE_DENOMINATOR;
            balances[i] = new_balances[i] - (fees[i] * admin_fee / FEE_DENOMINATOR);
            new_balances[i] -= fees[i];
        }

        uint256 D2 = get_D(_xp_mem(new_balances), amp);
        uint256 burn_amount = (D0 - D2) * token_supply / D0 + 1; // +1 for rounding
        require(burn_amount <= max_burn_amount, "SLIPPAGE");

        // Burn LP tokens and transfer coins
        for (uint256 i = 0; i < N_COINS; i++) {
            if (amounts[i] > 0) {
                IERC20(coins[i]).transfer(msg.sender, amounts[i]);
            }
        }

        emit RemoveLiquidityImbalance(msg.sender, amounts, fees, D2, token_supply - burn_amount);
    }

    /**
     * @notice Remove liquidity in a single coin.
     * @param _token_amount LP tokens to burn
     * @param i Index of the coin to receive
     * @param min_amount Minimum amount of the coin to receive
     */
    function remove_liquidity_one_coin(
        uint256 _token_amount,
        int128 i,
        uint256 min_amount
    ) external nonReentrant returns (uint256) {
        (uint256 dy, uint256 dy_fee) = _calc_withdraw_one_coin(_token_amount, i);
        require(dy >= min_amount, "SLIPPAGE");

        // Update balance (subtract withdrawn amount + admin fee portion)
        balances[uint256(int256(i))] -= (dy + dy_fee * admin_fee / FEE_DENOMINATOR);

        // Burn LP and transfer
        IERC20(coins[uint256(int256(i))]).transfer(msg.sender, dy);

        emit RemoveLiquidityOne(msg.sender, _token_amount, dy, _getLPTotalSupply() - _token_amount);
        return dy;
    }

    /**
     * @dev Calculate the amount received when removing liquidity in a single coin.
     */
    function _calc_withdraw_one_coin(uint256 _token_amount, int128 i) internal view returns (uint256, uint256) {
        uint256 amp = A_precise();
        uint256[N_COINS] memory xp = _xp();
        uint256 D0 = get_D(xp, amp);
        uint256 total_supply = _getLPTotalSupply();

        uint256 D1 = D0 - _token_amount * D0 / total_supply;

        // Find the new balance of coin i after removing proportional liquidity
        uint256[N_COINS] memory xp_reduced = xp;
        uint256 _fee = fee * N_COINS / (4 * (N_COINS - 1));

        for (uint256 j = 0; j < N_COINS; j++) {
            uint256 dx_expected;
            if (uint256(int256(j)) == uint256(int256(i))) {
                dx_expected = xp[j] * D1 / D0 - get_y_D(amp, i, xp, D1);
            } else {
                dx_expected = xp[j] - xp[j] * D1 / D0;
            }
            xp_reduced[j] -= _fee * dx_expected / FEE_DENOMINATOR;
        }

        uint256 dy = xp_reduced[uint256(int256(i))] - get_y_D(amp, i, xp_reduced, D1);
        dy = (dy - 1) * PRECISION / RATES[uint256(int256(i))]; // -1 for rounding

        uint256 dy_0 = (xp[uint256(int256(i))] - get_y_D(amp, i, xp, D1)) * PRECISION / RATES[uint256(int256(i))];
        uint256 dy_fee = dy_0 - dy;

        return (dy, dy_fee);
    }

    /**
     * @notice Get y given D and all other x values (for single-coin withdrawal).
     */
    function get_y_D(uint256 amp, int128 i, uint256[N_COINS] memory xp, uint256 D) internal pure returns (uint256) {
        uint256 Ann = amp * N_COINS;
        uint256 c = D;
        uint256 S_ = 0;

        for (uint256 k = 0; k < N_COINS; k++) {
            if (uint256(int256(k)) != uint256(int256(i))) {
                S_ += xp[k];
                c = c * D / (xp[k] * N_COINS);
            }
        }

        c = c * D * A_PRECISION / (Ann * N_COINS);
        uint256 b = S_ + D * A_PRECISION / Ann;

        uint256 y = D;
        uint256 y_prev;
        for (uint256 _i = 0; _i < 255; _i++) {
            y_prev = y;
            y = (y * y + c) / (2 * y + b - D);
            if (y > y_prev) {
                if (y - y_prev <= 1) return y;
            } else {
                if (y_prev - y <= 1) return y;
            }
        }
        revert("Y_D_NOT_CONVERGED");
    }

    // ============ View Functions ============

    /**
     * @notice Calculate the amount of coin j received for swapping dx of coin i.
     */
    function get_dy(int128 i, int128 j, uint256 dx) external view returns (uint256) {
        uint256[N_COINS] memory xp = _xp();
        uint256 x = xp[uint256(int256(i))] + dx * RATES[uint256(int256(i))] / PRECISION;
        uint256 y = get_y(i, j, x, xp);
        uint256 dy = xp[uint256(int256(j))] - y - 1;
        uint256 _fee = dy * fee / FEE_DENOMINATOR;
        return (dy - _fee) * PRECISION / RATES[uint256(int256(j))];
    }

    /**
     * @notice Get the "virtual price" of the LP token.
     * @dev virtual_price = D / LP_total_supply * PRECISION
     *      Represents the value of 1 LP token in terms of the pool's unit of account.
     *      Should be monotonically increasing (fees accrue to LPs).
     *
     *      VULNERABILITY: This function was the target of the famous read-only
     *      reentrancy attack. If a callback during remove_liquidity can call
     *      get_virtual_price() on a different contract, the price reads stale
     *      state (balances updated but LP tokens not yet burned), returning
     *      an inflated virtual price that can be used to extract value from
     *      other protocols that depend on it.
     *
     *      Mitigation: Curve added reentrancy guards that also protect view functions.
     */
    function get_virtual_price() external view returns (uint256) {
        uint256 D = get_D(_xp(), A_precise());
        uint256 token_supply = _getLPTotalSupply();
        return D * PRECISION / token_supply;
    }

    // ============ Admin Functions ============

    function ramp_A(uint256 _future_A, uint256 _future_time) external onlyOwner {
        require(block.timestamp >= initial_A_time + MIN_RAMP_TIME, "TOO_SOON");
        require(_future_time >= block.timestamp + MIN_RAMP_TIME, "RAMP_TOO_SHORT");

        uint256 _initial_A = A_precise();
        uint256 _future_A_p = _future_A * A_PRECISION;

        require(_future_A > 0 && _future_A < MAX_A, "A_OUT_OF_RANGE");

        // A change must not exceed MAX_A_CHANGE per ramp
        if (_future_A_p >= _initial_A) {
            require(_future_A_p <= _initial_A * MAX_A_CHANGE, "A_CHANGE_TOO_LARGE");
        } else {
            require(_future_A_p * MAX_A_CHANGE >= _initial_A, "A_CHANGE_TOO_LARGE");
        }

        initial_A = _initial_A;
        future_A = _future_A_p;
        initial_A_time = block.timestamp;
        future_A_time = _future_time;

        emit RampA(_initial_A, _future_A_p, block.timestamp, _future_time);
    }

    function stop_ramp_A() external onlyOwner {
        uint256 current_A = A_precise();
        initial_A = current_A;
        future_A = current_A;
        initial_A_time = block.timestamp;
        future_A_time = block.timestamp;
        emit StopRampA(current_A, block.timestamp);
    }

    function commit_new_fee(uint256 new_fee, uint256 new_admin_fee) external onlyOwner {
        require(new_fee <= MAX_FEE, "FEE_TOO_HIGH");
        require(new_admin_fee <= MAX_ADMIN_FEE, "ADMIN_FEE_TOO_HIGH");
        admin_actions_deadline = block.timestamp + 3 * 86400; // 3 day timelock
        future_fee = new_fee;
        future_admin_fee = new_admin_fee;
        emit CommitNewFee(new_fee, new_admin_fee);
    }

    function apply_new_fee() external onlyOwner {
        require(block.timestamp >= admin_actions_deadline, "TIMELOCK");
        require(admin_actions_deadline != 0, "NO_PENDING");
        fee = future_fee;
        admin_fee = future_admin_fee;
        admin_actions_deadline = 0;
        emit NewFee(fee, admin_fee);
    }

    function kill_me() external onlyOwner {
        require(block.timestamp < kill_deadline, "DEADLINE_PASSED");
        is_killed = true;
    }

    function unkill_me() external onlyOwner {
        is_killed = false;
    }

    // ============ Internal Helpers ============

    function _xp() internal view returns (uint256[N_COINS] memory result) {
        for (uint256 i = 0; i < N_COINS; i++) {
            result[i] = balances[i] * RATES[i] / PRECISION;
        }
    }

    function _xp_mem(uint256[N_COINS] memory _balances) internal view returns (uint256[N_COINS] memory result) {
        for (uint256 i = 0; i < N_COINS; i++) {
            result[i] = _balances[i] * RATES[i] / PRECISION;
        }
    }

    function _getLPTotalSupply() internal view returns (uint256) {
        // In production: IERC20(lp_token).totalSupply()
        return 1e24; // Placeholder
    }
}
