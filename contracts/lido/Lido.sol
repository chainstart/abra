// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.9;

import "./WstETH.sol";

/**
 * @title Lido Liquid Staking Protocol
 * @notice Core staking contract — users deposit ETH, receive stETH (rebasing token).
 *         stETH balance updates daily based on oracle reports of beacon chain rewards/penalties.
 * @dev stETH is implemented as shares internally. A user's stETH balance =
 *      (user_shares * totalPooledEther) / totalShares.
 *      This design allows rebasing without per-account storage writes.
 */

// ============ Interfaces ============

interface ILidoOracle {
    function getLastCompletedReportDelta()
        external
        view
        returns (
            uint256 postTotalPooledEther,
            uint256 preTotalPooledEther,
            uint256 timeElapsed
        );
}

interface INodeOperatorsRegistry {
    function getActiveNodeOperatorsCount() external view returns (uint256);
    function getNodeOperator(uint256 _id) external view returns (
        bool active,
        string memory name,
        address rewardAddress,
        uint64 stakingLimit,
        uint64 stoppedValidators,
        uint64 totalSigningKeys,
        uint64 usedSigningKeys
    );
    function trimUnusedKeys() external;
}

interface IWithdrawalQueue {
    function enqueue(
        address _owner,
        uint256 _stETHAmount,
        uint256 _sharesAmount
    ) external returns (uint256 requestId);
    function finalize(uint256 _lastRequestIdToFinalize, uint256 _shareRate) external payable;
}

interface IDepositContract {
    function deposit(
        bytes calldata pubkey,
        bytes calldata withdrawal_credentials,
        bytes calldata signature,
        bytes32 deposit_data_root
    ) external payable;
}

// ============ Main Contract ============

contract Lido {
    // ---- Constants & Roles ----
    bytes32 public constant PAUSE_ROLE = keccak256("PAUSE_ROLE");
    bytes32 public constant RESUME_ROLE = keccak256("RESUME_ROLE");
    bytes32 public constant STAKING_PAUSE_ROLE = keccak256("STAKING_PAUSE_ROLE");
    bytes32 public constant MANAGE_FEE = keccak256("MANAGE_FEE");
    bytes32 public constant MANAGE_WITHDRAWAL_KEY = keccak256("MANAGE_WITHDRAWAL_KEY");
    bytes32 public constant MANAGE_PROTOCOL_CONTRACTS_ROLE = keccak256("MANAGE_PROTOCOL_CONTRACTS_ROLE");
    bytes32 public constant BURN_ROLE = keccak256("BURN_ROLE");
    bytes32 public constant SET_EL_REWARDS_VAULT_ROLE = keccak256("SET_EL_REWARDS_VAULT_ROLE");
    bytes32 public constant STAKING_CONTROL_ROLE = keccak256("STAKING_CONTROL_ROLE");

    uint256 internal constant DEPOSIT_SIZE = 32 ether;
    uint256 internal constant BASIS_POINTS = 10000;
    /// @dev Maximum basis points for total fee (100%)
    uint256 internal constant MAX_FEE_BASIS_POINTS = 10000;
    /// @dev Denomination for share/token math
    uint256 internal constant INFINITE_ALLOWANCE = type(uint256).max;

    // ---- State Variables ----

    /// @notice Total amount of ether controlled by the protocol (buffered + beacon deposited + rewards)
    uint256 internal _totalPooledEther;

    /// @notice Sum of all issued shares
    uint256 internal _totalShares;

    /// @notice Ether temporarily buffered in this contract, not yet deposited to beacon chain
    uint256 internal _bufferedEther;

    /// @notice Number of validators deposited via this contract
    uint256 internal _depositedValidators;

    /// @notice Number of beacon chain validators whose state is "active" or "pending"
    uint256 internal _beaconValidators;

    /// @notice Beacon chain balance tracked by oracle
    uint256 internal _beaconBalance;

    /// @notice Total fee in basis points (split between treasury, insurance, node operators)
    uint16 public totalFeeBasicPoints;

    /// @notice Fee split: treasury, insurance fund, node operators (in basis points, summing to BASIS_POINTS)
    uint16 public treasuryFeeBasisPoints;
    uint16 public insuranceFeeBasisPoints;
    uint16 public operatorsFeeBasisPoints;

    /// @notice Protocol paused state
    bool public isStopped;

    /// @notice Staking rate limit — max ETH that can be staked per block
    bool public isStakingPaused;
    uint256 public stakingLimitMaxStakePerBlock;
    uint256 public stakingLimitStakeLimit;

    // ERC20 storage
    mapping(address => uint256) private _shares;
    mapping(address => mapping(address => uint256)) private _allowances;

    // Access control
    mapping(bytes32 => mapping(address => bool)) private _roles;
    address public admin;

    // External contract references
    IDepositContract public depositContract;
    ILidoOracle public oracle;
    INodeOperatorsRegistry public nodeOperatorsRegistry;
    IWithdrawalQueue public withdrawalQueue;
    address public treasury;
    address public insuranceFund;
    address public elRewardsVault;

    // Withdrawal credentials (for validator deposits)
    bytes32 public withdrawalCredentials;

    // Reentrancy guard
    uint256 private constant _NOT_ENTERED = 1;
    uint256 private constant _ENTERED = 2;
    uint256 private _reentrancyStatus;

    // ---- Events ----
    event Submitted(address indexed sender, uint256 amount, address referral);
    event Unbuffered(uint256 amount);
    event WithdrawalsReceived(uint256 amount);
    event ELRewardsReceived(uint256 amount);
    event Transfer(address indexed from, address indexed to, uint256 value);
    event Approval(address indexed owner, address indexed spender, uint256 value);
    event TransferShares(address indexed from, address indexed to, uint256 sharesValue);
    event SharesBurnt(address indexed account, uint256 preRebaseTokenAmount, uint256 postRebaseTokenAmount, uint256 sharesAmount);
    event Stopped();
    event Resumed();
    event StakingPaused();
    event StakingResumed();
    event FeeSet(uint16 feeBasisPoints);
    event FeeDistributionSet(uint16 treasuryFeeBasisPoints, uint16 insuranceFeeBasisPoints, uint16 operatorsFeeBasisPoints);
    event ELRewardsVaultSet(address executionLayerRewardsVault);
    event BeaconReported(uint256 beaconBalance, uint256 beaconValidators, uint256 timestamp);

    // ---- Modifiers ----

    modifier whenNotStopped() {
        require(!isStopped, "CONTRACT_IS_STOPPED");
        _;
    }

    modifier whenNotStakingPaused() {
        require(!isStakingPaused, "STAKING_IS_PAUSED");
        _;
    }

    modifier onlyRole(bytes32 role) {
        require(_roles[role][msg.sender] || msg.sender == admin, "ACCESS_DENIED");
        _;
    }

    modifier nonReentrant() {
        require(_reentrancyStatus != _ENTERED, "REENTRANCY");
        _reentrancyStatus = _ENTERED;
        _;
        _reentrancyStatus = _NOT_ENTERED;
    }

    // ---- Constructor ----

    constructor(
        address _depositContract,
        address _oracle,
        address _nodeOperatorsRegistry,
        address _treasury,
        address _insuranceFund
    ) {
        admin = msg.sender;
        depositContract = IDepositContract(_depositContract);
        oracle = ILidoOracle(_oracle);
        nodeOperatorsRegistry = INodeOperatorsRegistry(_nodeOperatorsRegistry);
        treasury = _treasury;
        insuranceFund = _insuranceFund;
        _reentrancyStatus = _NOT_ENTERED;
    }

    // ---- Receive / Fallback ----

    /// @notice Accepts direct ETH transfers (execution layer rewards, MEV, etc.)
    receive() external payable {
        // NOTE: potential vulnerability surface — unguarded receive allows anyone to
        // inflate totalPooledEther if _processELRewards is called without proper checks.
        // In production this is mitigated by only counting EL rewards vault balance.
    }

    // ============ Core Staking Functions ============

    /**
     * @notice Submit ETH for staking, receive stETH in return.
     * @param _referral Referral address for tracking.
     * @return Amount of stETH shares minted.
     */
    function submit(address _referral) external payable whenNotStopped whenNotStakingPaused nonReentrant returns (uint256) {
        require(msg.value > 0, "ZERO_DEPOSIT");

        // Staking rate limit check
        if (stakingLimitStakeLimit > 0) {
            require(msg.value <= stakingLimitStakeLimit, "STAKE_LIMIT_EXCEEDED");
        }

        return _submit(msg.sender, msg.value, _referral);
    }

    /**
     * @dev Internal submit logic. Calculates shares based on current share rate and mints.
     *      CRITICAL: share calculation uses totalPooledEther BEFORE adding the new deposit.
     *      This ensures fair pricing — new depositor gets shares proportional to their
     *      contribution relative to existing pool.
     * @param _sender The address of the staker
     * @param _value The ETH amount being staked
     * @param _referral Referral address
     * @return sharesAmount Number of shares minted
     */
    function _submit(address _sender, uint256 _value, address _referral) internal returns (uint256 sharesAmount) {
        // Calculate shares BEFORE updating totalPooledEther (ordering matters!)
        // If totalPooledEther is 0 (first deposit), shares = deposit amount 1:1
        if (_totalShares == 0) {
            sharesAmount = _value;
        } else {
            /**
             * @dev Share calculation:
             *   sharesAmount = (_value * _totalShares) / _totalPooledEther
             *
             * Vulnerability surface: if totalPooledEther can be manipulated (e.g., through
             * direct ETH sends or oracle manipulation), share pricing becomes unfair.
             * Mitigation: totalPooledEther only changes through controlled paths
             * (deposits, oracle reports, EL reward harvesting).
             */
            sharesAmount = (_value * _totalShares) / _totalPooledEther;
        }

        require(sharesAmount > 0, "ZERO_SHARES");

        // Update state
        _totalPooledEther += _value;
        _bufferedEther += _value;

        // Mint shares to sender
        _mintShares(_sender, sharesAmount);

        emit Submitted(_sender, _value, _referral);
        emit Transfer(address(0), _sender, getPooledEthByShares(sharesAmount));
        emit TransferShares(address(0), _sender, sharesAmount);

        return sharesAmount;
    }

    // ============ Withdrawal Functions ============

    /**
     * @notice Request stETH withdrawal. Burns stETH shares, enqueues withdrawal request.
     * @param _stETHAmount Amount of stETH to withdraw
     * @return requestId The withdrawal queue request ID
     */
    function withdraw(uint256 _stETHAmount) external whenNotStopped nonReentrant returns (uint256 requestId) {
        require(_stETHAmount > 0, "ZERO_WITHDRAWAL");

        uint256 sharesAmount = getSharesByPooledEth(_stETHAmount);
        require(sharesAmount > 0, "ZERO_SHARES");
        require(sharesOf(msg.sender) >= sharesAmount, "INSUFFICIENT_SHARES");

        // Burn shares from the sender
        _burnShares(msg.sender, sharesAmount);
        _totalPooledEther -= _stETHAmount;

        emit Transfer(msg.sender, address(0), _stETHAmount);
        emit TransferShares(msg.sender, address(0), sharesAmount);

        // Enqueue withdrawal request in the withdrawal queue contract
        requestId = withdrawalQueue.enqueue(msg.sender, _stETHAmount, sharesAmount);

        return requestId;
    }

    // ============ Oracle Reporting ============

    /**
     * @notice Handle oracle report — called by LidoOracle after quorum is reached.
     *         Updates beacon chain balance and validator count, distributes rewards/penalties.
     * @dev This is the most critical function in the protocol. It updates the share rate
     *      which affects every stETH holder's balance.
     *
     *      Vulnerability surface:
     *      - Oracle manipulation could inflate/deflate totalPooledEther
     *      - Sanity checks prevent large single-report changes
     *      - Fee distribution rounding can accumulate dust
     *
     * @param _beaconValidators Number of Lido validators on beacon chain
     * @param _beaconBalance Total balance of Lido validators on beacon chain (in wei)
     */
    function handleOracleReport(
        uint256 _beaconValidators,
        uint256 _beaconBalance
    ) external {
        require(msg.sender == address(oracle), "ONLY_ORACLE");

        uint256 prePooledEther = _totalPooledEther;

        // Update beacon state
        uint256 appearedValidators = _beaconValidators - _beaconValidators; // NOTE: should be _beaconValidators - _depositedValidators delta tracking
        _beaconValidators = _beaconValidators;

        // Calculate the new total pooled ether
        // totalPooledEther = bufferedEther + beaconBalance + transientBalance
        uint256 postPooledEther = _bufferedEther + _beaconBalance;

        // Sanity check: revert if reported balance implies unreasonable change
        // (protects against oracle bugs/attacks)
        if (postPooledEther > prePooledEther) {
            uint256 rewardsDelta = postPooledEther - prePooledEther;
            // Annual rewards cap: ~15% APR as sanity bound
            // For per-report: depends on reporting frequency
            require(
                rewardsDelta * 365 * BASIS_POINTS / prePooledEther / 1 <= 1500, // ~15% annual
                "REWARD_TOO_LARGE"
            );
        }

        _beaconBalance = _beaconBalance;
        _totalPooledEther = postPooledEther;

        // If there are rewards, distribute fee
        if (postPooledEther > prePooledEther) {
            uint256 rewards = postPooledEther - prePooledEther;
            _distributeFee(rewards);
        }

        emit BeaconReported(_beaconBalance, _beaconValidators, block.timestamp);
    }

    /**
     * @dev Distribute protocol fee on rewards. Fee is taken as newly minted shares,
     *      diluting existing holders proportionally.
     *
     *      Fee share math:
     *        feeShares = (rewards * totalFee * totalShares) /
     *                    (totalPooledEther * BASIS_POINTS - rewards * totalFee)
     *
     *      This ensures that after minting fee shares, the share rate remains such that
     *      (1 - fee%) of rewards accrue to existing holders.
     */
    function _distributeFee(uint256 _rewards) internal {
        if (totalFeeBasicPoints == 0) return;

        // Calculate fee in stETH terms
        uint256 feeInEth = (_rewards * totalFeeBasicPoints) / BASIS_POINTS;

        /**
         * @dev Calculate shares to mint for the fee.
         *      shares = feeInEth * totalShares / (totalPooledEther - feeInEth)
         *
         *      Vulnerability surface: integer division truncation accumulates over time.
         *      With large pools this is negligible; with small pools it can be material.
         */
        uint256 feeShares = (feeInEth * _totalShares) / (_totalPooledEther - feeInEth);

        if (feeShares == 0) return;

        // Split fee shares between treasury, insurance, and node operators
        uint256 treasuryShares = (feeShares * treasuryFeeBasisPoints) / BASIS_POINTS;
        uint256 insuranceShares = (feeShares * insuranceFeeBasisPoints) / BASIS_POINTS;
        uint256 operatorsShares = feeShares - treasuryShares - insuranceShares;

        _mintShares(treasury, treasuryShares);
        _mintShares(insuranceFund, insuranceShares);

        // Distribute operator shares among active node operators
        _distributeOperatorShares(operatorsShares);
    }

    /**
     * @dev Distribute node operator fee shares proportionally among active operators.
     */
    function _distributeOperatorShares(uint256 _shares) internal {
        uint256 operatorCount = nodeOperatorsRegistry.getActiveNodeOperatorsCount();
        if (operatorCount == 0) {
            // If no operators, treasury gets the remainder
            _mintShares(treasury, _shares);
            return;
        }

        uint256 perOperator = _shares / operatorCount;
        uint256 distributed = 0;

        for (uint256 i = 0; i < operatorCount; i++) {
            (bool active, , address rewardAddress, , , , ) = nodeOperatorsRegistry.getNodeOperator(i);
            if (active && rewardAddress != address(0)) {
                _mintShares(rewardAddress, perOperator);
                distributed += perOperator;
            }
        }

        // Dust goes to first operator (or treasury)
        uint256 dust = _shares - distributed;
        if (dust > 0) {
            _mintShares(treasury, dust);
        }
    }

    // ============ Deposit to Beacon Chain ============

    /**
     * @notice Deposit buffered ETH to the beacon chain deposit contract.
     * @param _maxDeposits Maximum number of 32 ETH deposits to make.
     */
    function depositBufferedEther(uint256 _maxDeposits) external onlyRole(STAKING_CONTROL_ROLE) {
        uint256 depositsCount = _min(_maxDeposits, _bufferedEther / DEPOSIT_SIZE);
        require(depositsCount > 0, "NOTHING_TO_DEPOSIT");

        for (uint256 i = 0; i < depositsCount; i++) {
            _bufferedEther -= DEPOSIT_SIZE;
            _depositedValidators += 1;
            // In production, signing keys are fetched from NodeOperatorsRegistry
            // depositContract.deposit{value: DEPOSIT_SIZE}(pubkey, withdrawalCredentials, signature, depositDataRoot);
        }

        emit Unbuffered(depositsCount * DEPOSIT_SIZE);
    }

    // ============ ERC20 stETH (Rebasing Token) ============

    function name() external pure returns (string memory) { return "Liquid staked Ether 2.0"; }
    function symbol() external pure returns (string memory) { return "stETH"; }
    function decimals() external pure returns (uint8) { return 18; }

    /**
     * @notice Total supply of stETH = totalPooledEther.
     *         Every share-holding address's balance sums to this.
     */
    function totalSupply() external view returns (uint256) {
        return _totalPooledEther;
    }

    /**
     * @notice stETH balance of an account. Computed dynamically from shares.
     * @dev balanceOf = (sharesOf(account) * totalPooledEther) / totalShares
     *      This means balances change WITHOUT Transfer events when oracle reports.
     *      Integrators must be aware of this non-standard rebasing behavior.
     */
    function balanceOf(address _account) external view returns (uint256) {
        return getPooledEthByShares(_shares[_account]);
    }

    function sharesOf(address _account) public view returns (uint256) {
        return _shares[_account];
    }

    function getTotalShares() external view returns (uint256) {
        return _totalShares;
    }

    function getTotalPooledEther() external view returns (uint256) {
        return _totalPooledEther;
    }

    /**
     * @notice Convert share amount to stETH amount.
     * @dev pooledEth = (shares * totalPooledEther) / totalShares
     */
    function getPooledEthByShares(uint256 _sharesAmount) public view returns (uint256) {
        if (_totalShares == 0) return 0;
        return (_sharesAmount * _totalPooledEther) / _totalShares;
    }

    /**
     * @notice Convert stETH amount to shares.
     * @dev shares = (stETH * totalShares) / totalPooledEther
     */
    function getSharesByPooledEth(uint256 _ethAmount) public view returns (uint256) {
        if (_totalPooledEther == 0) return 0;
        return (_ethAmount * _totalShares) / _totalPooledEther;
    }

    function transfer(address _to, uint256 _amount) external returns (bool) {
        _transfer(msg.sender, _to, _amount);
        return true;
    }

    function approve(address _spender, uint256 _amount) external returns (bool) {
        _allowances[msg.sender][_spender] = _amount;
        emit Approval(msg.sender, _spender, _amount);
        return true;
    }

    function allowance(address _owner, address _spender) external view returns (uint256) {
        return _allowances[_owner][_spender];
    }

    function transferFrom(address _from, address _to, uint256 _amount) external returns (bool) {
        uint256 currentAllowance = _allowances[_from][msg.sender];
        if (currentAllowance != INFINITE_ALLOWANCE) {
            require(currentAllowance >= _amount, "ALLOWANCE_EXCEEDED");
            _allowances[_from][msg.sender] = currentAllowance - _amount;
        }
        _transfer(_from, _to, _amount);
        return true;
    }

    /**
     * @dev Transfers stETH by converting to shares internally.
     *      Vulnerability note: transferring stETH amounts that don't map cleanly to
     *      whole shares can cause 1-wei rounding discrepancies. This is a known
     *      integration issue for protocols building on stETH.
     */
    function _transfer(address _from, address _to, uint256 _amount) internal {
        require(_from != address(0), "TRANSFER_FROM_ZERO");
        require(_to != address(0), "TRANSFER_TO_ZERO");

        uint256 sharesToTransfer = getSharesByPooledEth(_amount);
        require(sharesToTransfer > 0, "ZERO_SHARES_TRANSFER");
        require(_shares[_from] >= sharesToTransfer, "INSUFFICIENT_BALANCE");

        _shares[_from] -= sharesToTransfer;
        _shares[_to] += sharesToTransfer;

        emit Transfer(_from, _to, _amount);
        emit TransferShares(_from, _to, sharesToTransfer);
    }

    // ============ Internal Share Accounting ============

    function _mintShares(address _to, uint256 _sharesAmount) internal {
        require(_to != address(0), "MINT_TO_ZERO");
        _totalShares += _sharesAmount;
        _shares[_to] += _sharesAmount;
    }

    function _burnShares(address _from, uint256 _sharesAmount) internal {
        require(_from != address(0), "BURN_FROM_ZERO");
        require(_shares[_from] >= _sharesAmount, "INSUFFICIENT_SHARES");
        _totalShares -= _sharesAmount;
        _shares[_from] -= _sharesAmount;
    }

    // ============ Admin / Governance ============

    function stop() external onlyRole(PAUSE_ROLE) {
        isStopped = true;
        emit Stopped();
    }

    function resume() external onlyRole(RESUME_ROLE) {
        isStopped = false;
        emit Resumed();
    }

    function pauseStaking() external onlyRole(STAKING_PAUSE_ROLE) {
        isStakingPaused = true;
        emit StakingPaused();
    }

    function resumeStaking() external onlyRole(STAKING_PAUSE_ROLE) {
        isStakingPaused = false;
        emit StakingResumed();
    }

    function setFee(uint16 _feeBasisPoints) external onlyRole(MANAGE_FEE) {
        require(_feeBasisPoints <= MAX_FEE_BASIS_POINTS, "FEE_TOO_HIGH");
        totalFeeBasicPoints = _feeBasisPoints;
        emit FeeSet(_feeBasisPoints);
    }

    function setFeeDistribution(
        uint16 _treasuryFeeBasisPoints,
        uint16 _insuranceFeeBasisPoints,
        uint16 _operatorsFeeBasisPoints
    ) external onlyRole(MANAGE_FEE) {
        require(
            _treasuryFeeBasisPoints + _insuranceFeeBasisPoints + _operatorsFeeBasisPoints == BASIS_POINTS,
            "FEE_DISTRIBUTION_INVALID"
        );
        treasuryFeeBasisPoints = _treasuryFeeBasisPoints;
        insuranceFeeBasisPoints = _insuranceFeeBasisPoints;
        operatorsFeeBasisPoints = _operatorsFeeBasisPoints;
        emit FeeDistributionSet(_treasuryFeeBasisPoints, _insuranceFeeBasisPoints, _operatorsFeeBasisPoints);
    }

    function setWithdrawalCredentials(bytes32 _withdrawalCredentials) external onlyRole(MANAGE_WITHDRAWAL_KEY) {
        withdrawalCredentials = _withdrawalCredentials;
    }

    function setELRewardsVault(address _elRewardsVault) external onlyRole(SET_EL_REWARDS_VAULT_ROLE) {
        elRewardsVault = _elRewardsVault;
        emit ELRewardsVaultSet(_elRewardsVault);
    }

    function grantRole(bytes32 _role, address _account) external {
        require(msg.sender == admin, "ONLY_ADMIN");
        _roles[_role][_account] = true;
    }

    function revokeRole(bytes32 _role, address _account) external {
        require(msg.sender == admin, "ONLY_ADMIN");
        _roles[_role][_account] = false;
    }

    // ============ Helpers ============

    function _min(uint256 a, uint256 b) internal pure returns (uint256) {
        return a < b ? a : b;
    }

    /**
     * @notice Returns the buffered ether waiting to be deposited.
     */
    function getBufferedEther() external view returns (uint256) {
        return _bufferedEther;
    }

    /**
     * @notice Returns beacon chain statistics tracked by oracle.
     */
    function getBeaconStat() external view returns (
        uint256 depositedValidators,
        uint256 beaconValidators,
        uint256 beaconBalance
    ) {
        return (_depositedValidators, _beaconValidators, _beaconBalance);
    }
}
