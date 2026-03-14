// SPDX-License-Identifier: BSD-3-Clause
pragma solidity ^0.8.10;

/**
 * @title Compound GovernorBravo
 * @notice Compound's governance contract. COMP token holders create and vote on proposals
 *         that, after a timelock delay, execute arbitrary transactions (parameter changes,
 *         protocol upgrades, treasury management).
 *
 * @dev Governance flow:
 *      1. propose(): Create a proposal (requires proposalThreshold COMP voting power)
 *      2. Voting delay (e.g., 1 block): time before voting starts
 *      3. Voting period (e.g., 3 days): COMP holders vote For/Against/Abstain
 *      4. If quorum met and more For than Against: proposal succeeds
 *      5. queue(): Queue proposal in Timelock
 *      6. Timelock delay (e.g., 2 days): mandatory waiting period
 *      7. execute(): Execute the proposal's transactions
 *
 * Vulnerability surfaces:
 *      - Flash loan governance attacks: borrow COMP, vote, return in same tx
 *        Mitigated by snapshot-based voting (votes counted at proposal creation block)
 *      - Proposal execution timing: proposals in timelock can be front-run
 *      - Guardian powers: admin can cancel any proposal
 *      - Quorum threshold: if too low, small holders can pass controversial proposals
 *      - Voting power delegation: can concentrate power through delegation chains
 *      - Timelock bypass: emergency actions circumvent governance
 */

// ============ Interfaces ============

interface IComp {
    function getPriorVotes(address account, uint256 blockNumber) external view returns (uint96);
    function delegates(address account) external view returns (address);
}

interface ITimelock {
    function delay() external view returns (uint256);
    function GRACE_PERIOD() external view returns (uint256);
    function queuedTransactions(bytes32 hash) external view returns (bool);
    function queueTransaction(address target, uint256 value, string calldata signature, bytes calldata data, uint256 eta) external returns (bytes32);
    function cancelTransaction(address target, uint256 value, string calldata signature, bytes calldata data, uint256 eta) external;
    function executeTransaction(address target, uint256 value, string calldata signature, bytes calldata data, uint256 eta) external payable returns (bytes memory);
    function admin() external view returns (address);
}

// ============ Main Contract ============

contract GovernorBravo {
    // ---- Constants ----
    string public constant name = "Compound Governor Bravo";

    /// @notice Minimum voting period (blocks) ~24 hours at 12s/block
    uint256 public constant MIN_VOTING_PERIOD = 7200;
    /// @notice Maximum voting period (blocks) ~2 weeks
    uint256 public constant MAX_VOTING_PERIOD = 100800;

    /// @notice Minimum voting delay (blocks) — 1 block
    uint256 public constant MIN_VOTING_DELAY = 1;
    /// @notice Maximum voting delay (blocks) ~1 week
    uint256 public constant MAX_VOTING_DELAY = 50400;

    /// @notice Minimum proposal threshold — 1,000 COMP
    uint256 public constant MIN_PROPOSAL_THRESHOLD = 1000e18;
    /// @notice Maximum proposal threshold — 100,000 COMP
    uint256 public constant MAX_PROPOSAL_THRESHOLD = 100000e18;

    /// @notice Maximum operations per proposal (prevents gas DoS on execution)
    uint256 public constant MAX_OPERATIONS = 10;

    // Proposal states
    uint8 public constant PROPOSAL_PENDING = 0;
    uint8 public constant PROPOSAL_ACTIVE = 1;
    uint8 public constant PROPOSAL_CANCELED = 2;
    uint8 public constant PROPOSAL_DEFEATED = 3;
    uint8 public constant PROPOSAL_SUCCEEDED = 4;
    uint8 public constant PROPOSAL_QUEUED = 5;
    uint8 public constant PROPOSAL_EXPIRED = 6;
    uint8 public constant PROPOSAL_EXECUTED = 7;

    // Vote types
    uint8 public constant VOTE_AGAINST = 0;
    uint8 public constant VOTE_FOR = 1;
    uint8 public constant VOTE_ABSTAIN = 2;

    // ---- Structs ----
    struct Proposal {
        uint256 id;
        address proposer;
        uint256 eta;           // Execution time (after timelock delay)
        address[] targets;     // Contracts to call
        uint256[] values;      // ETH values to send
        string[] signatures;   // Function signatures
        bytes[] calldatas;     // Encoded function arguments
        uint256 startBlock;    // Block when voting starts
        uint256 endBlock;      // Block when voting ends
        uint256 forVotes;      // Total For votes
        uint256 againstVotes;  // Total Against votes
        uint256 abstainVotes;  // Total Abstain votes
        bool canceled;
        bool executed;
        mapping(address => Receipt) receipts;
    }

    struct Receipt {
        bool hasVoted;
        uint8 support;
        uint96 votes;
    }

    // ---- State ----
    /// @notice Governance parameters
    uint256 public votingDelay;
    uint256 public votingPeriod;
    uint256 public proposalThreshold;
    uint256 public quorumVotes; // Minimum votes for a proposal to pass (e.g., 400,000 COMP)

    /// @notice Proposal counter
    uint256 public proposalCount;

    /// @notice Proposals mapping
    mapping(uint256 => Proposal) public proposals;

    /// @notice Latest proposal ID per proposer (prevents spam)
    mapping(address => uint256) public latestProposalIds;

    /// @notice COMP token (for voting power)
    IComp public comp;

    /// @notice Timelock contract (delayed execution)
    ITimelock public timelock;

    /// @notice Admin / guardian — can cancel proposals
    address public admin;

    /// @notice Pending admin (for two-step admin transfer)
    address public pendingAdmin;

    /// @notice Implementation address (for proxy pattern)
    address public implementation;

    /// @notice Whether the contract has been initialized
    bool public initialized;

    // ---- Events ----
    event ProposalCreated(uint256 id, address proposer, address[] targets, uint256[] values, string[] signatures, bytes[] calldatas, uint256 startBlock, uint256 endBlock, string description);
    event VoteCast(address indexed voter, uint256 proposalId, uint8 support, uint256 votes, string reason);
    event ProposalCanceled(uint256 id);
    event ProposalQueued(uint256 id, uint256 eta);
    event ProposalExecuted(uint256 id);

    // ---- Constructor / Initializer ----
    constructor(
        address _timelock,
        address _comp,
        uint256 _votingPeriod,
        uint256 _votingDelay,
        uint256 _proposalThreshold,
        uint256 _quorumVotes
    ) {
        require(_votingPeriod >= MIN_VOTING_PERIOD && _votingPeriod <= MAX_VOTING_PERIOD, "INVALID_VOTING_PERIOD");
        require(_votingDelay >= MIN_VOTING_DELAY && _votingDelay <= MAX_VOTING_DELAY, "INVALID_VOTING_DELAY");
        require(_proposalThreshold >= MIN_PROPOSAL_THRESHOLD && _proposalThreshold <= MAX_PROPOSAL_THRESHOLD, "INVALID_THRESHOLD");

        timelock = ITimelock(_timelock);
        comp = IComp(_comp);
        votingPeriod = _votingPeriod;
        votingDelay = _votingDelay;
        proposalThreshold = _proposalThreshold;
        quorumVotes = _quorumVotes;
        admin = msg.sender;
    }

    // ============ Propose ============

    /**
     * @notice Create a new governance proposal.
     * @param targets Array of contract addresses to call
     * @param values Array of ETH values to send with each call
     * @param signatures Array of function signatures (e.g., "transfer(address,uint256)")
     * @param calldatas Array of encoded function arguments
     * @param description Human-readable description of the proposal
     * @return proposalId The ID of the created proposal
     *
     * @dev Proposer must have voting power >= proposalThreshold at the current block.
     *      Voting power is determined by COMP delegation — tokens must be delegated
     *      (even to self) to count.
     *
     *      Vulnerability note: proposalThreshold is checked at proposal creation time.
     *      The proposer could sell/transfer their COMP immediately after proposing.
     *      However, this doesn't affect voting since votes are snapshotted at startBlock.
     */
    function propose(
        address[] memory targets,
        uint256[] memory values,
        string[] memory signatures,
        bytes[] memory calldatas,
        string memory description
    ) external returns (uint256) {
        require(targets.length == values.length, "ARITY_MISMATCH");
        require(targets.length == signatures.length, "ARITY_MISMATCH");
        require(targets.length == calldatas.length, "ARITY_MISMATCH");
        require(targets.length > 0, "NO_ACTIONS");
        require(targets.length <= MAX_OPERATIONS, "TOO_MANY_ACTIONS");

        /**
         * @dev Check proposer has sufficient voting power.
         *      getPriorVotes uses the PREVIOUS block's snapshot, preventing
         *      flash loan attacks (can't borrow COMP and propose in same block).
         */
        require(
            comp.getPriorVotes(msg.sender, block.number - 1) >= proposalThreshold,
            "BELOW_THRESHOLD"
        );

        // Check proposer doesn't have a pending/active proposal
        uint256 latestProposalId = latestProposalIds[msg.sender];
        if (latestProposalId != 0) {
            uint8 proposalState = state(latestProposalId);
            require(proposalState != PROPOSAL_ACTIVE, "ALREADY_ACTIVE_PROPOSAL");
            require(proposalState != PROPOSAL_PENDING, "ALREADY_PENDING_PROPOSAL");
        }

        uint256 startBlock = block.number + votingDelay;
        uint256 endBlock = startBlock + votingPeriod;

        proposalCount++;
        uint256 newProposalId = proposalCount;

        Proposal storage newProposal = proposals[newProposalId];
        newProposal.id = newProposalId;
        newProposal.proposer = msg.sender;
        newProposal.targets = targets;
        newProposal.values = values;
        newProposal.signatures = signatures;
        newProposal.calldatas = calldatas;
        newProposal.startBlock = startBlock;
        newProposal.endBlock = endBlock;

        latestProposalIds[msg.sender] = newProposalId;

        emit ProposalCreated(newProposalId, msg.sender, targets, values, signatures, calldatas, startBlock, endBlock, description);
        return newProposalId;
    }

    // ============ Voting ============

    /**
     * @notice Cast a vote on a proposal.
     * @param proposalId The proposal to vote on
     * @param support 0 = Against, 1 = For, 2 = Abstain
     *
     * @dev Voting power is snapshotted at proposal's startBlock (proposal creation + delay).
     *      This prevents flash loan attacks:
     *      - Attacker borrows COMP
     *      - Proposal already exists with startBlock in the past
     *      - Attacker's getPriorVotes at startBlock returns 0 (didn't hold COMP then)
     *      - Attack fails
     */
    function castVote(uint256 proposalId, uint8 support) external {
        _castVote(msg.sender, proposalId, support);
    }

    /**
     * @notice Cast a vote with a reason string (for transparency).
     */
    function castVoteWithReason(uint256 proposalId, uint8 support, string calldata reason) external {
        _castVote(msg.sender, proposalId, support);
        emit VoteCast(msg.sender, proposalId, support, 0, reason);
    }

    function _castVote(address voter, uint256 proposalId, uint8 support) internal {
        require(state(proposalId) == PROPOSAL_ACTIVE, "VOTING_CLOSED");
        require(support <= 2, "INVALID_VOTE_TYPE");

        Proposal storage proposal = proposals[proposalId];
        Receipt storage receipt = proposal.receipts[voter];

        require(!receipt.hasVoted, "ALREADY_VOTED");

        /**
         * @dev Get voting power at the proposal's start block.
         *      This is the critical snapshot mechanism that prevents flash loan attacks.
         */
        uint96 votes = comp.getPriorVotes(voter, proposal.startBlock);

        if (support == VOTE_AGAINST) {
            proposal.againstVotes += votes;
        } else if (support == VOTE_FOR) {
            proposal.forVotes += votes;
        } else {
            proposal.abstainVotes += votes;
        }

        receipt.hasVoted = true;
        receipt.support = support;
        receipt.votes = votes;

        emit VoteCast(voter, proposalId, support, votes, "");
    }

    // ============ Queue & Execute ============

    /**
     * @notice Queue a successful proposal for execution via Timelock.
     * @param proposalId The proposal to queue
     *
     * @dev Each action in the proposal becomes a separate timelock transaction.
     *      The ETA (earliest time available) = block.timestamp + timelock.delay().
     */
    function queue(uint256 proposalId) external {
        require(state(proposalId) == PROPOSAL_SUCCEEDED, "NOT_SUCCEEDED");

        Proposal storage proposal = proposals[proposalId];
        uint256 eta = block.timestamp + timelock.delay();
        proposal.eta = eta;

        for (uint256 i = 0; i < proposal.targets.length; i++) {
            _queueOrRevert(
                proposal.targets[i],
                proposal.values[i],
                proposal.signatures[i],
                proposal.calldatas[i],
                eta
            );
        }

        emit ProposalQueued(proposalId, eta);
    }

    function _queueOrRevert(
        address target,
        uint256 value,
        string memory signature,
        bytes memory data,
        uint256 eta
    ) internal {
        bytes32 txHash = keccak256(abi.encode(target, value, signature, data, eta));
        require(!timelock.queuedTransactions(txHash), "IDENTICAL_ACTION_ALREADY_QUEUED");
        timelock.queueTransaction(target, value, signature, data, eta);
    }

    /**
     * @notice Execute a queued proposal after the timelock delay has passed.
     * @param proposalId The proposal to execute
     *
     * @dev Each action is executed via the Timelock, which is the actual caller.
     *      This means the Timelock must have permissions for the target contracts.
     *
     *      Vulnerability surface:
     *      - Timelock's executeTransaction can fail for individual actions
     *      - If one action fails, the entire execution reverts (atomic)
     *      - MEV searchers can front-run execution for profit
     *      - Grace period expiry: if not executed within Timelock.GRACE_PERIOD, proposal expires
     */
    function execute(uint256 proposalId) external payable {
        require(state(proposalId) == PROPOSAL_QUEUED, "NOT_QUEUED");

        Proposal storage proposal = proposals[proposalId];
        proposal.executed = true;

        for (uint256 i = 0; i < proposal.targets.length; i++) {
            timelock.executeTransaction{value: proposal.values[i]}(
                proposal.targets[i],
                proposal.values[i],
                proposal.signatures[i],
                proposal.calldatas[i],
                proposal.eta
            );
        }

        emit ProposalExecuted(proposalId);
    }

    /**
     * @notice Cancel a proposal. Can be called by:
     *         - The admin/guardian at any time
     *         - Anyone if the proposer's voting power drops below threshold
     *
     * @dev The "anyone can cancel if proposer lost votes" mechanism prevents
     *      zombie proposals from proposers who sold their COMP.
     */
    function cancel(uint256 proposalId) external {
        require(state(proposalId) != PROPOSAL_EXECUTED, "CANNOT_CANCEL_EXECUTED");

        Proposal storage proposal = proposals[proposalId];

        if (msg.sender != admin) {
            // Anyone can cancel if proposer's voting power dropped below threshold
            require(
                comp.getPriorVotes(proposal.proposer, block.number - 1) < proposalThreshold,
                "PROPOSER_ABOVE_THRESHOLD"
            );
        }

        proposal.canceled = true;

        // Cancel all queued timelock transactions
        for (uint256 i = 0; i < proposal.targets.length; i++) {
            timelock.cancelTransaction(
                proposal.targets[i],
                proposal.values[i],
                proposal.signatures[i],
                proposal.calldatas[i],
                proposal.eta
            );
        }

        emit ProposalCanceled(proposalId);
    }

    // ============ State ============

    /**
     * @notice Get the current state of a proposal.
     */
    function state(uint256 proposalId) public view returns (uint8) {
        require(proposalId > 0 && proposalId <= proposalCount, "INVALID_PROPOSAL_ID");

        Proposal storage proposal = proposals[proposalId];

        if (proposal.canceled) return PROPOSAL_CANCELED;
        if (proposal.executed) return PROPOSAL_EXECUTED;

        if (block.number <= proposal.startBlock) return PROPOSAL_PENDING;
        if (block.number <= proposal.endBlock) return PROPOSAL_ACTIVE;

        // Voting ended — check results
        if (proposal.forVotes <= proposal.againstVotes || proposal.forVotes < quorumVotes) {
            return PROPOSAL_DEFEATED;
        }

        // Succeeded but not yet queued
        if (proposal.eta == 0) return PROPOSAL_SUCCEEDED;

        // Queued — check if expired
        if (block.timestamp >= proposal.eta + timelock.GRACE_PERIOD()) {
            return PROPOSAL_EXPIRED;
        }

        return PROPOSAL_QUEUED;
    }

    // ============ View Functions ============

    function getActions(uint256 proposalId) external view returns (
        address[] memory targets,
        uint256[] memory values,
        string[] memory signatures,
        bytes[] memory calldatas
    ) {
        Proposal storage p = proposals[proposalId];
        return (p.targets, p.values, p.signatures, p.calldatas);
    }

    function getReceipt(uint256 proposalId, address voter) external view returns (Receipt memory) {
        return proposals[proposalId].receipts[voter];
    }

    // ============ Admin ============

    function _setVotingDelay(uint256 newVotingDelay) external {
        require(msg.sender == admin, "ONLY_ADMIN");
        require(newVotingDelay >= MIN_VOTING_DELAY && newVotingDelay <= MAX_VOTING_DELAY, "INVALID_VOTING_DELAY");
        votingDelay = newVotingDelay;
    }

    function _setVotingPeriod(uint256 newVotingPeriod) external {
        require(msg.sender == admin, "ONLY_ADMIN");
        require(newVotingPeriod >= MIN_VOTING_PERIOD && newVotingPeriod <= MAX_VOTING_PERIOD, "INVALID_VOTING_PERIOD");
        votingPeriod = newVotingPeriod;
    }

    function _setProposalThreshold(uint256 newProposalThreshold) external {
        require(msg.sender == admin, "ONLY_ADMIN");
        require(newProposalThreshold >= MIN_PROPOSAL_THRESHOLD && newProposalThreshold <= MAX_PROPOSAL_THRESHOLD, "INVALID_THRESHOLD");
        proposalThreshold = newProposalThreshold;
    }

    function _setQuorumVotes(uint256 newQuorumVotes) external {
        require(msg.sender == admin, "ONLY_ADMIN");
        quorumVotes = newQuorumVotes;
    }

    function _setPendingAdmin(address newPendingAdmin) external {
        require(msg.sender == admin, "ONLY_ADMIN");
        pendingAdmin = newPendingAdmin;
    }

    function _acceptAdmin() external {
        require(msg.sender == pendingAdmin, "ONLY_PENDING_ADMIN");
        admin = msg.sender;
        pendingAdmin = address(0);
    }
}
