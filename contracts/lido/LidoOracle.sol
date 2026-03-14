// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.9;

/**
 * @title Lido Oracle
 * @notice Aggregates beacon chain state reports from trusted oracle members.
 *         When quorum is reached (majority of members report the same data for the same
 *         epoch), the report is finalized and pushed to the Lido contract.
 *
 * @dev Security model:
 *      - Oracle members are whitelisted addresses (typically run by different entities)
 *      - Quorum = ceil(N/2) where N = number of members
 *      - Reports are per-epoch; only one report per member per epoch
 *      - Sanity checks on reported values prevent extreme outliers
 *
 *      Vulnerability surfaces:
 *      - Quorum manipulation if oracle members are compromised
 *      - Timing attacks around epoch boundaries
 *      - Sanity check bounds may be too loose or too tight
 */

interface ILido {
    function handleOracleReport(uint256 _beaconValidators, uint256 _beaconBalance) external;
    function getTotalPooledEther() external view returns (uint256);
    function getBufferedEther() external view returns (uint256);
}

contract LidoOracle {
    // ---- Constants ----
    uint256 public constant MAX_ORACLE_MEMBERS = 256;
    /// @dev Allowed annual increase in balance (basis points). Used for sanity checks.
    uint256 public constant MAX_ALLOWED_APR_BP = 1500; // 15% annual max
    /// @dev Allowed single-report balance decrease (basis points). Slashing protection.
    uint256 public constant MAX_ALLOWED_DECREASE_BP = 500; // 5% max drop per report

    // ---- Structs ----
    struct BeaconReport {
        uint256 beaconValidators;
        uint256 beaconBalance;
    }

    struct MemberReport {
        uint256 epochId;
        uint256 beaconValidators;
        uint256 beaconBalance;
    }

    // ---- State ----

    /// @notice Reference to the Lido staking contract
    ILido public lido;

    /// @notice The list of oracle member addresses
    address[] public oracleMembers;
    mapping(address => bool) public isMember;

    /// @notice Required number of matching reports to reach quorum
    uint256 public quorum;

    /// @notice The epoch for which we are currently collecting reports
    uint256 public currentReportableEpoch;

    /// @notice Beacon chain specification
    uint256 public beaconSpec_epochsPerFrame; // e.g., 225 epochs per frame (~24h)
    uint256 public beaconSpec_slotsPerEpoch;  // 32
    uint256 public beaconSpec_secondsPerSlot; // 12
    uint256 public beaconSpec_genesisTime;

    /// @notice Last completed epoch
    uint256 public lastCompletedEpochId;

    /// @notice Stored report after last quorum
    uint256 public lastReportedBeaconValidators;
    uint256 public lastReportedBeaconBalance;

    /// @notice Reports for current epoch: member address => report
    mapping(address => MemberReport) public currentMemberReports;
    /// @notice Count of each distinct reported hash in the current epoch
    mapping(bytes32 => uint256) public reportHashCount;
    /// @notice Track which hashes have been submitted this epoch
    bytes32[] private currentReportHashes;

    /// @notice Contract admin
    address public admin;

    /// @notice Expected epoch boundaries
    uint256 public expectedEpochId;

    // ---- Events ----
    event MemberAdded(address indexed member);
    event MemberRemoved(address indexed member);
    event QuorumChanged(uint256 quorum);
    event BeaconReported(
        uint256 indexed epochId,
        uint256 beaconValidators,
        uint256 beaconBalance,
        address indexed caller
    );
    event BeaconReportQuorumReached(
        uint256 indexed epochId,
        uint256 beaconValidators,
        uint256 beaconBalance
    );
    event ExpectedEpochIdUpdated(uint256 epochId);
    event BeaconSpecSet(
        uint256 epochsPerFrame,
        uint256 slotsPerEpoch,
        uint256 secondsPerSlot,
        uint256 genesisTime
    );

    // ---- Modifiers ----
    modifier onlyAdmin() {
        require(msg.sender == admin, "ONLY_ADMIN");
        _;
    }

    modifier onlyMember() {
        require(isMember[msg.sender], "ONLY_ORACLE_MEMBER");
        _;
    }

    // ---- Constructor ----
    constructor(address _lido) {
        require(_lido != address(0), "ZERO_ADDRESS");
        lido = ILido(_lido);
        admin = msg.sender;
        quorum = 1; // Initial quorum, should be updated after adding members
    }

    // ============ Oracle Reporting ============

    /**
     * @notice Report beacon chain state for the current reportable epoch.
     * @param _epochId The epoch being reported (must match expectedEpochId)
     * @param _beaconValidators Number of Lido validators on beacon chain
     * @param _beaconBalance Total balance of Lido validators (in Gwei, converted to wei internally)
     *
     * @dev Flow:
     *   1. Validate epoch matches expected
     *   2. Record member's report
     *   3. Check if quorum reached for this (validators, balance) tuple
     *   4. If quorum: run sanity checks, push to Lido, advance epoch
     *
     * Vulnerability surface:
     *   - If oracle members collude, they can report arbitrary balances
     *   - Sanity checks are the last line of defense
     *   - Race condition: multiple members submitting in same block may bypass
     *     sequential assumptions (mitigated by per-member tracking)
     */
    function reportBeacon(
        uint256 _epochId,
        uint256 _beaconValidators,
        uint256 _beaconBalance
    ) external onlyMember {
        require(_epochId == expectedEpochId, "UNEXPECTED_EPOCH");
        require(_epochId > lastCompletedEpochId, "EPOCH_ALREADY_REPORTED");

        // Check member hasn't already reported for this epoch
        MemberReport storage existingReport = currentMemberReports[msg.sender];
        require(
            existingReport.epochId != _epochId,
            "ALREADY_REPORTED"
        );

        // Store this member's report
        currentMemberReports[msg.sender] = MemberReport({
            epochId: _epochId,
            beaconValidators: _beaconValidators,
            beaconBalance: _beaconBalance
        });

        emit BeaconReported(_epochId, _beaconValidators, _beaconBalance, msg.sender);

        // Hash the report data to count matching reports
        bytes32 reportHash = keccak256(abi.encodePacked(_epochId, _beaconValidators, _beaconBalance));

        if (reportHashCount[reportHash] == 0) {
            currentReportHashes.push(reportHash);
        }
        reportHashCount[reportHash] += 1;

        // Check quorum
        if (reportHashCount[reportHash] >= quorum) {
            _finalizeReport(_epochId, _beaconValidators, _beaconBalance);
        }
    }

    /**
     * @dev Finalize a report after quorum is reached. Run sanity checks, then push to Lido.
     */
    function _finalizeReport(
        uint256 _epochId,
        uint256 _beaconValidators,
        uint256 _beaconBalance
    ) internal {
        // ---- Sanity Checks ----

        // 1. Validator count should not decrease (validators can't un-deposit)
        require(
            _beaconValidators >= lastReportedBeaconValidators,
            "VALIDATORS_DECREASED"
        );

        // 2. Check balance change is within acceptable bounds
        if (lastReportedBeaconBalance > 0) {
            // Check for unreasonable increase (potential oracle manipulation)
            if (_beaconBalance > lastReportedBeaconBalance) {
                uint256 increase = _beaconBalance - lastReportedBeaconBalance;
                uint256 maxIncrease = (lastReportedBeaconBalance * MAX_ALLOWED_APR_BP) /
                    (10000 * 365); // daily cap assuming daily reporting
                require(increase <= maxIncrease, "BALANCE_INCREASE_TOO_LARGE");
            }

            // Check for unreasonable decrease (potential mass slashing or bug)
            if (_beaconBalance < lastReportedBeaconBalance) {
                uint256 decrease = lastReportedBeaconBalance - _beaconBalance;
                uint256 maxDecrease = (lastReportedBeaconBalance * MAX_ALLOWED_DECREASE_BP) / 10000;
                require(decrease <= maxDecrease, "BALANCE_DECREASE_TOO_LARGE");
            }
        }

        // ---- Update State ----
        lastCompletedEpochId = _epochId;
        lastReportedBeaconValidators = _beaconValidators;
        lastReportedBeaconBalance = _beaconBalance;

        // Advance to next expected epoch
        expectedEpochId = _epochId + beaconSpec_epochsPerFrame;

        // Clean up current epoch reports
        _clearReports();

        emit BeaconReportQuorumReached(_epochId, _beaconValidators, _beaconBalance);
        emit ExpectedEpochIdUpdated(expectedEpochId);

        // Push report to Lido
        lido.handleOracleReport(_beaconValidators, _beaconBalance);
    }

    /**
     * @dev Clear all stored reports for the current epoch. Called after finalization.
     */
    function _clearReports() internal {
        for (uint256 i = 0; i < currentReportHashes.length; i++) {
            delete reportHashCount[currentReportHashes[i]];
        }
        delete currentReportHashes;

        // NOTE: We don't clear individual member reports since they are overwritten
        // per-epoch. This saves gas but means stale data exists in storage.
    }

    // ============ Oracle Member Management ============

    function addOracleMember(address _member) external onlyAdmin {
        require(_member != address(0), "ZERO_ADDRESS");
        require(!isMember[_member], "ALREADY_MEMBER");
        require(oracleMembers.length < MAX_ORACLE_MEMBERS, "MAX_MEMBERS_REACHED");

        oracleMembers.push(_member);
        isMember[_member] = true;

        emit MemberAdded(_member);
    }

    function removeOracleMember(address _member) external onlyAdmin {
        require(isMember[_member], "NOT_MEMBER");

        isMember[_member] = false;

        // Remove from array (swap with last element)
        for (uint256 i = 0; i < oracleMembers.length; i++) {
            if (oracleMembers[i] == _member) {
                oracleMembers[i] = oracleMembers[oracleMembers.length - 1];
                oracleMembers.pop();
                break;
            }
        }

        // Adjust quorum if needed
        if (quorum > oracleMembers.length) {
            quorum = oracleMembers.length;
            emit QuorumChanged(quorum);
        }

        emit MemberRemoved(_member);
    }

    function setQuorum(uint256 _quorum) external onlyAdmin {
        require(_quorum > 0, "ZERO_QUORUM");
        require(_quorum <= oracleMembers.length, "QUORUM_TOO_LARGE");
        quorum = _quorum;
        emit QuorumChanged(_quorum);
    }

    // ============ Beacon Spec Configuration ============

    function setBeaconSpec(
        uint256 _epochsPerFrame,
        uint256 _slotsPerEpoch,
        uint256 _secondsPerSlot,
        uint256 _genesisTime
    ) external onlyAdmin {
        require(_epochsPerFrame > 0, "ZERO_EPOCHS");
        require(_slotsPerEpoch > 0, "ZERO_SLOTS");
        require(_secondsPerSlot > 0, "ZERO_SECONDS");

        beaconSpec_epochsPerFrame = _epochsPerFrame;
        beaconSpec_slotsPerEpoch = _slotsPerEpoch;
        beaconSpec_secondsPerSlot = _secondsPerSlot;
        beaconSpec_genesisTime = _genesisTime;

        emit BeaconSpecSet(_epochsPerFrame, _slotsPerEpoch, _secondsPerSlot, _genesisTime);
    }

    function setExpectedEpochId(uint256 _epochId) external onlyAdmin {
        expectedEpochId = _epochId;
        emit ExpectedEpochIdUpdated(_epochId);
    }

    // ============ View Functions ============

    function getOracleMembers() external view returns (address[] memory) {
        return oracleMembers;
    }

    function getLastCompletedReportDelta()
        external
        view
        returns (
            uint256 postTotalPooledEther,
            uint256 preTotalPooledEther,
            uint256 timeElapsed
        )
    {
        // This would require storing pre/post values on each report
        // Simplified: return current state
        postTotalPooledEther = lido.getTotalPooledEther();
        preTotalPooledEther = postTotalPooledEther; // Simplified
        timeElapsed = beaconSpec_epochsPerFrame * beaconSpec_slotsPerEpoch * beaconSpec_secondsPerSlot;
    }

    /**
     * @notice Calculate current epoch from block timestamp.
     */
    function getCurrentEpochId() external view returns (uint256) {
        require(block.timestamp >= beaconSpec_genesisTime, "BEFORE_GENESIS");
        uint256 secondsSinceGenesis = block.timestamp - beaconSpec_genesisTime;
        uint256 slotsSinceGenesis = secondsSinceGenesis / beaconSpec_secondsPerSlot;
        return slotsSinceGenesis / beaconSpec_slotsPerEpoch;
    }
}
