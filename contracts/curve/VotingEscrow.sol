// SPDX-License-Identifier: MIT
pragma solidity ^0.8.17;

/**
 * @title Voting Escrow (veCRV)
 * @notice Lock CRV tokens for a period (up to 4 years) to receive veCRV voting power.
 *         Voting power decays linearly over the lock period, incentivizing longer locks.
 *         Translated from Vyper for Solidity-based analysis.
 *
 * @dev Key mechanics:
 *      - Lock CRV for up to MAX_LOCK_TIME (4 years)
 *      - veCRV balance = locked_amount * remaining_lock_time / MAX_LOCK_TIME
 *      - veCRV is non-transferable (soulbound)
 *      - Lock time is rounded down to the nearest WEEK (epoch alignment)
 *      - Historical balances queryable via checkpoint system
 *
 *      The checkpoint system stores slope changes at future timestamps,
 *      allowing O(1) balance queries for any historical block without
 *      iterating through all locks.
 *
 * Vulnerability surfaces:
 *      - Lock manipulation: extending lock time vs creating new locks
 *      - Checkpoint gas consumption: many small locks can make checkpoints expensive
 *      - Timestamp manipulation: week-aligned unlocks can be front-run
 *      - Flash loan + lock: borrowing CRV to get temporary voting power
 *        (mitigated by requiring tokens to be locked, not just held)
 *      - Governance attacks: acquiring veCRV shortly before a vote
 */

interface IERC20 {
    function transfer(address to, uint256 amount) external returns (bool);
    function transferFrom(address from, address to, uint256 amount) external returns (bool);
    function balanceOf(address account) external view returns (uint256);
}

contract VotingEscrow {
    // ---- Constants ----
    uint256 public constant WEEK = 7 * 86400;      // 1 week in seconds
    uint256 public constant MAX_LOCK_TIME = 4 * 365 * 86400; // 4 years
    uint256 public constant MULTIPLIER = 1e18;
    int128 public constant DEPOSIT_FOR_TYPE = 0;
    int128 public constant CREATE_LOCK_TYPE = 1;
    int128 public constant INCREASE_LOCK_AMOUNT = 2;
    int128 public constant INCREASE_UNLOCK_TIME = 3;

    // ---- Structs ----

    /// @notice A lock represents a user's locked CRV
    struct LockedBalance {
        int128 amount;    // Locked CRV amount (int128 for delta math)
        uint256 end;      // Lock expiry timestamp (week-aligned)
    }

    /// @notice A point on the decay curve: bias - slope * (t - ts)
    struct Point {
        int128 bias;      // veCRV balance at timestamp ts
        int128 slope;     // Decay rate: -locked_amount / MAX_LOCK_TIME
        uint256 ts;       // Timestamp
        uint256 blk;      // Block number
    }

    // ---- State ----
    string public name;
    string public symbol;
    uint8 public constant decimals = 18;

    /// @notice The CRV token being locked
    IERC20 public token;

    /// @notice Total supply of locked CRV (not veCRV — actual locked amount)
    uint256 public supply;

    /// @notice User address => locked balance
    mapping(address => LockedBalance) public locked;

    /// @notice Global point history (append-only)
    uint256 public epoch;
    Point[100000000] public point_history; // epoch => Point

    /// @notice Per-user point history
    mapping(address => Point[1000000000]) public user_point_history;
    mapping(address => uint256) public user_point_epoch;

    /// @notice Scheduled slope changes (at lock expiry timestamps)
    /// @dev slope_changes[t] = sum of slope deltas that take effect at timestamp t
    mapping(uint256 => int128) public slope_changes;

    /// @notice Admin / controller
    address public admin;

    /// @notice Reentrancy guard
    uint256 private _locked;

    // ---- Events ----
    event Deposit(address indexed provider, uint256 value, uint256 indexed locktime, int128 type_, uint256 ts);
    event Withdraw(address indexed provider, uint256 value, uint256 ts);
    event Supply(uint256 prevSupply, uint256 supply);

    // ---- Modifiers ----
    modifier nonReentrant() {
        require(_locked == 0, "REENTRANCY");
        _locked = 1;
        _;
        _locked = 0;
    }

    // ---- Constructor ----
    constructor(
        address _token,
        string memory _name,
        string memory _symbol
    ) {
        token = IERC20(_token);
        name = _name;
        symbol = _symbol;
        admin = msg.sender;

        // Initialize the first global checkpoint
        point_history[0] = Point({
            bias: 0,
            slope: 0,
            ts: block.timestamp,
            blk: block.number
        });
    }

    // ============ Core Lock Functions ============

    /**
     * @notice Create a new lock. Deposits CRV and sets the unlock time.
     * @param _value Amount of CRV to lock
     * @param _unlock_time Desired unlock timestamp (will be rounded down to nearest WEEK)
     *
     * @dev Requirements:
     *      - User must not have an existing lock
     *      - _value > 0
     *      - _unlock_time is in the future and <= MAX_LOCK_TIME from now
     *      - _unlock_time is week-aligned
     */
    function create_lock(uint256 _value, uint256 _unlock_time) external nonReentrant {
        _unlock_time = (_unlock_time / WEEK) * WEEK; // Round down to week
        LockedBalance memory _locked_bal = locked[msg.sender];

        require(_value > 0, "ZERO_VALUE");
        require(_locked_bal.amount == 0, "EXISTING_LOCK");
        require(_unlock_time > block.timestamp, "UNLOCK_IN_PAST");
        require(_unlock_time <= block.timestamp + MAX_LOCK_TIME, "LOCK_TOO_LONG");

        _deposit_for(msg.sender, _value, _unlock_time, _locked_bal, CREATE_LOCK_TYPE);
    }

    /**
     * @notice Increase the locked amount without changing the unlock time.
     * @param _value Additional CRV to lock
     */
    function increase_amount(uint256 _value) external nonReentrant {
        LockedBalance memory _locked_bal = locked[msg.sender];

        require(_value > 0, "ZERO_VALUE");
        require(_locked_bal.amount > 0, "NO_EXISTING_LOCK");
        require(_locked_bal.end > block.timestamp, "LOCK_EXPIRED");

        _deposit_for(msg.sender, _value, 0, _locked_bal, INCREASE_LOCK_AMOUNT);
    }

    /**
     * @notice Extend the lock duration without adding more CRV.
     * @param _unlock_time New unlock timestamp (must be after current unlock time)
     */
    function increase_unlock_time(uint256 _unlock_time) external nonReentrant {
        _unlock_time = (_unlock_time / WEEK) * WEEK;
        LockedBalance memory _locked_bal = locked[msg.sender];

        require(_locked_bal.amount > 0, "NO_EXISTING_LOCK");
        require(_locked_bal.end > block.timestamp, "LOCK_EXPIRED");
        require(_unlock_time > _locked_bal.end, "MUST_EXTEND");
        require(_unlock_time <= block.timestamp + MAX_LOCK_TIME, "LOCK_TOO_LONG");

        _deposit_for(msg.sender, 0, _unlock_time, _locked_bal, INCREASE_UNLOCK_TIME);
    }

    /**
     * @notice Deposit on behalf of another user (e.g., for reward distribution).
     * @param _addr Address to deposit for
     * @param _value Amount to deposit
     */
    function deposit_for(address _addr, uint256 _value) external nonReentrant {
        LockedBalance memory _locked_bal = locked[_addr];
        require(_value > 0, "ZERO_VALUE");
        require(_locked_bal.amount > 0, "NO_EXISTING_LOCK");
        require(_locked_bal.end > block.timestamp, "LOCK_EXPIRED");

        _deposit_for(_addr, _value, 0, _locked_bal, DEPOSIT_FOR_TYPE);
    }

    /**
     * @dev Internal deposit logic. Updates the user's lock, global checkpoints,
     *      and slope change schedule.
     */
    function _deposit_for(
        address _addr,
        uint256 _value,
        uint256 unlock_time,
        LockedBalance memory _locked_bal,
        int128 type_
    ) internal {
        uint256 supply_before = supply;
        supply += _value;

        LockedBalance memory old_locked = _locked_bal;
        LockedBalance memory new_locked;

        // Calculate new locked balance
        new_locked.amount = old_locked.amount + int128(int256(_value));
        if (unlock_time != 0) {
            new_locked.end = unlock_time;
        } else {
            new_locked.end = old_locked.end;
        }
        locked[_addr] = new_locked;

        // Update checkpoints (global and per-user)
        _checkpoint(_addr, old_locked, new_locked);

        // Transfer CRV from sender
        if (_value > 0) {
            require(token.transferFrom(msg.sender, address(this), _value), "TRANSFER_FAILED");
        }

        emit Deposit(_addr, _value, new_locked.end, type_, block.timestamp);
        emit Supply(supply_before, supply);
    }

    // ============ Withdraw ============

    /**
     * @notice Withdraw locked CRV after the lock has expired.
     * @dev Can only be called after lock.end has passed.
     *      No partial withdrawals — must withdraw entire locked amount.
     *
     *      Vulnerability note: Users cannot withdraw early under any circumstances.
     *      This is a design feature (commitment mechanism) but means locked CRV
     *      is truly illiquid for the lock duration.
     */
    function withdraw() external nonReentrant {
        LockedBalance memory _locked_bal = locked[msg.sender];
        require(block.timestamp >= _locked_bal.end, "LOCK_NOT_EXPIRED");
        require(_locked_bal.amount > 0, "NOTHING_TO_WITHDRAW");

        uint256 value = uint256(int256(_locked_bal.amount));

        LockedBalance memory old_locked = _locked_bal;
        LockedBalance memory new_locked = LockedBalance({amount: 0, end: 0});
        locked[msg.sender] = new_locked;

        uint256 supply_before = supply;
        supply -= value;

        // Update checkpoints
        _checkpoint(msg.sender, old_locked, new_locked);

        // Transfer CRV back to user
        require(token.transfer(msg.sender, value), "TRANSFER_FAILED");

        emit Withdraw(msg.sender, value, block.timestamp);
        emit Supply(supply_before, supply);
    }

    // ============ Checkpoint System ============

    /**
     * @dev Record global and per-user checkpoints.
     *
     *      The checkpoint system maintains a piecewise linear function of voting power:
     *      - Each lock contributes a line segment: bias_i - slope_i * (t - t_start)
     *      - slope_i = locked_amount / MAX_LOCK_TIME
     *      - At lock expiry, slope_i is subtracted from the global slope
     *
     *      Global state: sum of all individual decay lines
     *      slope_changes[t] records when slopes change (at lock expiry times)
     *
     *      To compute voting power at any historical time:
     *      1. Start from the nearest checkpoint
     *      2. Walk forward, applying slope_changes at each week boundary
     *      3. Use linear interpolation within a week
     *
     *      Vulnerability surface:
     *      - Gas cost grows with number of weeks between checkpoints
     *      - Malicious users could create many small locks to inflate gas costs
     *      - The MAX_ITERATIONS limit prevents DoS but means very old checkpoints
     *        might not be reachable
     */
    function _checkpoint(
        address _addr,
        LockedBalance memory old_locked,
        LockedBalance memory new_locked
    ) internal {
        Point memory u_old;
        Point memory u_new;
        int128 old_dslope = 0;
        int128 new_dslope = 0;

        // Calculate old and new user points
        if (_addr != address(0)) {
            if (old_locked.end > block.timestamp && old_locked.amount > 0) {
                u_old.slope = old_locked.amount / int128(int256(MAX_LOCK_TIME));
                u_old.bias = u_old.slope * int128(int256(old_locked.end - block.timestamp));
            }
            if (new_locked.end > block.timestamp && new_locked.amount > 0) {
                u_new.slope = new_locked.amount / int128(int256(MAX_LOCK_TIME));
                u_new.bias = u_new.slope * int128(int256(new_locked.end - block.timestamp));
            }

            // Read old slope changes
            old_dslope = slope_changes[old_locked.end];
            if (new_locked.end != 0) {
                if (new_locked.end == old_locked.end) {
                    new_dslope = old_dslope;
                } else {
                    new_dslope = slope_changes[new_locked.end];
                }
            }
        }

        // Update global point
        Point memory last_point;
        if (epoch > 0) {
            last_point = point_history[epoch];
        } else {
            last_point = Point({bias: 0, slope: 0, ts: block.timestamp, blk: block.number});
        }

        uint256 last_checkpoint = last_point.ts;

        // Walk through weeks to fill in missed checkpoints
        // This is necessary because slope changes happen at week boundaries
        Point memory initial_last_point = last_point;
        uint256 block_slope = 0;
        if (block.timestamp > last_point.ts) {
            block_slope = MULTIPLIER * (block.number - last_point.blk) / (block.timestamp - last_point.ts);
        }

        uint256 t_i = (last_checkpoint / WEEK) * WEEK;
        for (uint256 i = 0; i < 255; i++) { // Max 255 weeks (~5 years)
            t_i += WEEK;
            int128 d_slope = 0;

            if (t_i > block.timestamp) {
                t_i = block.timestamp;
            } else {
                d_slope = slope_changes[t_i];
            }

            // Apply linear decay from last_point to t_i
            last_point.bias -= last_point.slope * int128(int256(t_i - last_checkpoint));
            last_point.slope += d_slope;

            // Clamp to zero (bias can't be negative)
            if (last_point.bias < 0) last_point.bias = 0;
            if (last_point.slope < 0) last_point.slope = 0;

            last_checkpoint = t_i;
            last_point.ts = t_i;
            last_point.blk = initial_last_point.blk + block_slope * (t_i - initial_last_point.ts) / MULTIPLIER;

            epoch += 1;
            if (t_i == block.timestamp) {
                last_point.blk = block.number;
                break;
            }
            point_history[epoch] = last_point;
        }

        point_history[epoch] = last_point;

        // Update slope changes schedule
        if (_addr != address(0)) {
            // Remove old slope change, add new one
            if (old_locked.end > block.timestamp) {
                old_dslope += u_old.slope;
                if (new_locked.end == old_locked.end) {
                    old_dslope -= u_new.slope;
                }
                slope_changes[old_locked.end] = old_dslope;
            }

            if (new_locked.end > block.timestamp) {
                if (new_locked.end > old_locked.end) {
                    new_dslope -= u_new.slope;
                    slope_changes[new_locked.end] = new_dslope;
                }
            }

            // Record user's checkpoint
            uint256 user_epoch = user_point_epoch[_addr] + 1;
            user_point_epoch[_addr] = user_epoch;
            u_new.ts = block.timestamp;
            u_new.blk = block.number;
            user_point_history[_addr][user_epoch] = u_new;
        }
    }

    /**
     * @notice Trigger a global checkpoint (no user state change).
     */
    function checkpoint() external {
        _checkpoint(address(0), LockedBalance(0, 0), LockedBalance(0, 0));
    }

    // ============ Balance Queries ============

    /**
     * @notice Get the current veCRV balance of an address.
     * @dev balance = user_point.bias - user_point.slope * (now - user_point.ts)
     *      Returns 0 if the result would be negative (lock expired).
     */
    function balanceOf(address _addr) external view returns (uint256) {
        return balanceOf(_addr, block.timestamp);
    }

    function balanceOf(address _addr, uint256 _t) public view returns (uint256) {
        uint256 _epoch = user_point_epoch[_addr];
        if (_epoch == 0) return 0;

        Point memory last_point = user_point_history[_addr][_epoch];

        int128 bias = last_point.bias - last_point.slope * int128(int256(_t - last_point.ts));
        if (bias < 0) return 0;
        return uint256(int256(bias));
    }

    /**
     * @notice Get the current total veCRV supply.
     * @dev Walks forward from the last global checkpoint, applying slope changes.
     */
    function totalSupply() external view returns (uint256) {
        return totalSupply(block.timestamp);
    }

    function totalSupply(uint256 _t) public view returns (uint256) {
        Point memory last_point = point_history[epoch];
        return _supply_at(last_point, _t);
    }

    function _supply_at(Point memory point, uint256 t) internal view returns (uint256) {
        uint256 t_i = (point.ts / WEEK) * WEEK;

        for (uint256 i = 0; i < 255; i++) {
            t_i += WEEK;
            int128 d_slope = 0;

            if (t_i > t) {
                t_i = t;
            } else {
                d_slope = slope_changes[t_i];
            }

            point.bias -= point.slope * int128(int256(t_i - point.ts));
            if (t_i == t) break;
            point.slope += d_slope;
            point.ts = t_i;
        }

        if (point.bias < 0) point.bias = 0;
        return uint256(int256(point.bias));
    }

    /**
     * @notice Get the veCRV balance at a specific historical block.
     * @dev Uses binary search to find the epoch, then interpolates.
     */
    function balanceOfAt(address _addr, uint256 _block) external view returns (uint256) {
        require(_block <= block.number, "FUTURE_BLOCK");

        // Binary search for the user's epoch at the given block
        uint256 _min = 0;
        uint256 _max = user_point_epoch[_addr];
        for (uint256 i = 0; i < 128; i++) {
            if (_min >= _max) break;
            uint256 _mid = (_min + _max + 1) / 2;
            if (user_point_history[_addr][_mid].blk <= _block) {
                _min = _mid;
            } else {
                _max = _mid - 1;
            }
        }

        Point memory upoint = user_point_history[_addr][_min];

        // Interpolate timestamp from block number
        uint256 max_epoch = epoch;
        uint256 _epoch = _find_block_epoch(_block, max_epoch);
        Point memory point_0 = point_history[_epoch];
        uint256 d_block = 0;
        uint256 d_t = 0;
        if (_epoch < max_epoch) {
            Point memory point_1 = point_history[_epoch + 1];
            d_block = point_1.blk - point_0.blk;
            d_t = point_1.ts - point_0.ts;
        } else {
            d_block = block.number - point_0.blk;
            d_t = block.timestamp - point_0.ts;
        }

        uint256 block_time = point_0.ts;
        if (d_block > 0) {
            block_time += d_t * (_block - point_0.blk) / d_block;
        }

        int128 bias = upoint.bias - upoint.slope * int128(int256(block_time - upoint.ts));
        if (bias < 0) return 0;
        return uint256(int256(bias));
    }

    function _find_block_epoch(uint256 _block, uint256 max_epoch) internal view returns (uint256) {
        uint256 _min = 0;
        uint256 _max = max_epoch;
        for (uint256 i = 0; i < 128; i++) {
            if (_min >= _max) break;
            uint256 _mid = (_min + _max + 1) / 2;
            if (point_history[_mid].blk <= _block) {
                _min = _mid;
            } else {
                _max = _mid - 1;
            }
        }
        return _min;
    }

    // ============ View Helpers ============

    /**
     * @notice Total locked CRV supply (not voting power — actual locked tokens).
     */
    function totalCRVLocked() external view returns (uint256) {
        return supply;
    }

    /**
     * @notice Get a user's lock information.
     */
    function getLocked(address _addr) external view returns (int128 amount, uint256 end) {
        LockedBalance memory l = locked[_addr];
        return (l.amount, l.end);
    }
}
