# Lido Protocol -- Security Audit Report

**Audit Date:** 2026-02-24
**Auditor:** Blockchain Security Research Division
**Report Version:** 1.0
**Methodology:** Static analysis, manual code review, threat modeling
**Solidity Version:** ^0.8.9

---

## 1. Executive Summary

### 1.1 Protocol Overview

Lido is a liquid staking protocol that allows users to stake ETH on the Ethereum beacon chain without locking assets or maintaining validator infrastructure. Users deposit ETH into the Lido contract and receive stETH, a rebasing ERC-20 token whose balance updates daily to reflect staking rewards. The protocol also offers wstETH, a non-rebasing wrapper suitable for DeFi integrations that cannot handle rebasing tokens.

### 1.2 Significance

Lido is the single largest protocol in DeFi by Total Value Locked (TVL), securing approximately **$38 billion** in staked ETH. The protocol's stETH token serves as foundational collateral across the DeFi ecosystem -- it is integrated into Aave, Curve, MakerDAO, and dozens of other protocols. Any vulnerability in Lido's core contracts could have cascading effects across the entire DeFi landscape.

### 1.3 Audit Scope

This audit covers three core contracts comprising approximately **1,214 lines of code**:

| Contract | File | LOC | Purpose |
|----------|------|-----|---------|
| Lido.sol | `contracts/lido/Lido.sol` | 645 | Core staking, stETH token, share accounting |
| LidoOracle.sol | `contracts/lido/LidoOracle.sol` | 353 | Beacon chain reporting, quorum mechanism |
| WstETH.sol | `contracts/lido/WstETH.sol` | 216 | Non-rebasing wrapper token |

### 1.4 Key Findings Summary

The automated scanner identified **68 findings** across the three contract files. After manual triage and analysis, these have been consolidated and re-classified into **17 distinct findings**:

| Severity | Count | Description |
|----------|-------|-------------|
| Critical | 2 | Oracle report logic bug, missing reentrancy guards on critical paths |
| High | 3 | Share rate manipulation, centralized admin control, CEI violations |
| Medium | 7 | Division-by-zero risks, fee rounding, quorum weaknesses, precision loss |
| Low | 3 | Missing zero-address checks, hardcoded decimals, missing events |
| Informational | 2 | Gas optimizations, code quality |

**Scanner Finding Triage Note:** Of the 68 raw scanner findings, 4 were classified High (the `transfer`/`transferFrom` access control flags are false positives -- these are standard ERC-20 functions that are intentionally public), 47 Medium (many are duplicates from the reentrancy analyzer flagging every cross-function pair involving `deposit`), and 17 Low. After manual review, findings have been consolidated and re-assessed against protocol-specific context.

---

## 2. Protocol Architecture

### 2.1 Contract Interaction Diagram

```
                          +-------------------+
                          |    End Users      |
                          +--------+----------+
                                   |
                    ETH deposit    |    stETH transfers
                    via submit()   |    via transfer()
                                   v
+----------------+       +--------+----------+       +------------------+
|  Withdrawal    |<------+     Lido.sol       |<------+  LidoOracle.sol  |
|  Queue         |       |  (Core Staking)    |       |  (Beacon Reports)|
|  (IWithdrawal  | withdraw()  |   stETH Token    | handleOracle  |  (Quorum-based) |
|   Queue)       |       |   Share Accounting |  Report()  |  (Sanity Checks)|
+----------------+       +---+----+------+----+       +--------+---------+
                              |    |      |                    |
                   deposit    |    |      | mint/burn          | reportBeacon()
                   Buffered   |    |      | shares             |
                   Ether()    |    |      |               +----+----+
                              v    |      v               | Oracle  |
                   +----------+-+  |  +---+----------+    | Members |
                   | Deposit    |  |  | Node         |    | (N-of-M |
                   | Contract   |  |  | Operators    |    |  quorum)|
                   | (Beacon    |  |  | Registry     |    +---------+
                   |  Chain)    |  |  | (Fee split)  |
                   +------------+  |  +--------------+
                                   |
                              wrap/unwrap
                                   v
                          +--------+----------+
                          |   WstETH.sol       |
                          | (Non-rebasing      |
                          |  wrapper)          |
                          +-------------------+
                                   |
                          Used as collateral in:
                          Aave, Curve, Compound,
                          Balancer, etc.
```

### 2.2 Key Data Flows

**ETH Deposit Flow:**
1. User calls `submit()` with ETH value attached
2. Contract calculates shares: `sharesAmount = (msg.value * totalShares) / totalPooledEther`
3. Shares are minted to the user via `_mintShares()`
4. `_totalPooledEther` and `_bufferedEther` are incremented
5. Buffered ETH is later deposited to the beacon chain via `depositBufferedEther()`

**Oracle Reporting Flow:**
1. Oracle members independently observe beacon chain state
2. Each member calls `reportBeacon()` with epoch, validator count, and balance
3. Reports are hashed and counted; when `quorum` matching reports exist, finalization triggers
4. `_finalizeReport()` runs sanity checks (APR cap, slashing cap)
5. The report is pushed to `Lido.handleOracleReport()`, updating `_totalPooledEther`
6. If rewards exist, protocol fees are distributed as newly minted shares

**wstETH Wrapping Flow:**
1. User approves WstETH contract to spend stETH
2. User calls `wrap()` -- stETH is transferred in, wstETH is minted 1:1 with underlying shares
3. To unwrap, user calls `unwrap()` -- wstETH is burned, stETH is transferred out at current rate

### 2.3 Share-Based Accounting Model

The protocol uses a shares model rather than balance-based accounting. Every user holds a number of shares, and their stETH balance is computed dynamically:

```
balanceOf(user) = (sharesOf(user) * totalPooledEther) / totalShares
```

This design allows the protocol to rebase all balances simultaneously by simply updating `totalPooledEther` through oracle reports, without needing to iterate over every account.

---

## 3. Audit Scope

### 3.1 Files Audited

| # | File | Path | LOC | Compiler |
|---|------|------|-----|----------|
| 1 | Lido.sol | `/home/biostar/blockchain-security/contracts/lido/Lido.sol` | 645 | Solidity ^0.8.9 |
| 2 | LidoOracle.sol | `/home/biostar/blockchain-security/contracts/lido/LidoOracle.sol` | 353 | Solidity ^0.8.9 |
| 3 | WstETH.sol | `/home/biostar/blockchain-security/contracts/lido/WstETH.sol` | 216 | Solidity ^0.8.9 |

### 3.2 Out of Scope

The following components were not included in this audit:
- NodeOperatorsRegistry implementation (only the interface `INodeOperatorsRegistry` was reviewed)
- WithdrawalQueue implementation (only the interface `IWithdrawalQueue` was reviewed)
- Deposit Contract (Ethereum consensus layer contract)
- Governance/DAO contracts
- Off-chain oracle daemon software
- Frontend and API layers

### 3.3 Analysis Methods

| Method | Tools/Approach |
|--------|----------------|
| Automated scanning | Custom static analyzer (5 analyzers: access-control, reentrancy, oracle-dependency, arithmetic) |
| Manual review | Line-by-line code inspection with threat modeling |
| Architecture review | Data flow analysis, trust boundary mapping |
| Known vulnerability patterns | OWASP Smart Contract Top 10, SWC Registry checks |

---

## 4. Findings

### LIDO-01: Critical Logic Bug in Oracle Report -- Validator Delta Always Zero

- **ID:** LIDO-01
- **Title:** `handleOracleReport` validator delta computation is a no-op
- **Severity:** Critical
- **Category:** SC-06: Arithmetic / Logic Error
- **Location:** `Lido.sol:325`
- **Status:** Open

**Description:**

In `handleOracleReport()`, the appeared validator delta computation subtracts a variable from itself, producing zero in every case:

```solidity
// Lido.sol, line 325
uint256 appearedValidators = _beaconValidators - _beaconValidators;
// NOTE: should be _beaconValidators - _depositedValidators delta tracking
```

The parameter `_beaconValidators` is subtracted from itself rather than from the stored state variable `_beaconValidators` (the storage variable). This is because the parameter shadows the storage variable name. The result is that `appearedValidators` is always `0`, meaning the protocol cannot track how many new validators have appeared since the last report.

Furthermore, on line 326, the storage variable `_beaconValidators` is overwritten with the parameter value, and on line 330, `postPooledEther` is computed using `_bufferedEther + _beaconBalance` but the `_beaconBalance` reference on this line is ambiguous -- the parameter `_beaconBalance` shadows the storage variable. On line 344, `_beaconBalance = _beaconBalance` is a self-assignment of the parameter, which has no effect on storage.

**Impact:**

- Validator appearance tracking is broken -- the protocol cannot detect discrepancies between deposited validators and those reported by the oracle
- The `postPooledEther` calculation on line 330 uses the function parameter `_beaconBalance` rather than the newly reported value being stored, which is actually correct by coincidence (the parameter IS the new reported value), but the storage write on line 344 is a no-op
- The code comment on line 325 acknowledges this is incorrect, suggesting this is a known issue in a simplified implementation

**Proof of Concept:**

```
1. Oracle reports _beaconValidators = 1000
2. appearedValidators = 1000 - 1000 = 0 (always zero)
3. Protocol cannot detect validator count discrepancies
4. Line 344: _beaconBalance = _beaconBalance (no-op, storage unchanged if
   the compiler treats this as parameter self-assignment)
```

**Recommendation:**

Rename the function parameters to avoid shadowing storage variables, and implement correct delta tracking:

```solidity
function handleOracleReport(
    uint256 _reportedValidators,
    uint256 _reportedBalance
) external {
    require(msg.sender == address(oracle), "ONLY_ORACLE");

    uint256 appearedValidators = _reportedValidators > _beaconValidators
        ? _reportedValidators - _beaconValidators
        : 0;

    _beaconValidators = _reportedValidators;
    _beaconBalance = _reportedBalance;

    uint256 postPooledEther = _bufferedEther + _reportedBalance;
    // ... remainder of logic
}
```

---

### LIDO-02: Missing Reentrancy Guard on `handleOracleReport` Allows State Manipulation

- **ID:** LIDO-02
- **Title:** Critical state-modifying function `handleOracleReport` lacks reentrancy protection
- **Severity:** Critical
- **Category:** SC-01: Reentrancy
- **Location:** `Lido.sol:316-354`
- **Status:** Open

**Description:**

The `handleOracleReport()` function modifies critical protocol state (`_beaconValidators`, `_beaconBalance`, `_totalPooledEther`) and makes external calls through `_distributeFee()` -> `_distributeOperatorShares()` -> `nodeOperatorsRegistry.getActiveNodeOperatorsCount()` and `nodeOperatorsRegistry.getNodeOperator()`. However, it does not use the `nonReentrant` modifier that is defined in the contract (lines 177-182).

The scanner identified **24 cross-function reentrancy paths** originating from the deposit contract's external call at line 52, and additional paths through `depositBufferedEther` at line 431. While many of these are false positives (admin-gated functions cannot be re-entered by an attacker without the role), the `handleOracleReport` -> `_distributeFee` -> `_distributeOperatorShares` path is a genuine concern.

```solidity
// Lido.sol, line 316 -- no nonReentrant modifier
function handleOracleReport(
    uint256 _beaconValidators,
    uint256 _beaconBalance
) external {
    require(msg.sender == address(oracle), "ONLY_ORACLE");
    // ... modifies _totalPooledEther, then calls _distributeFee
```

```solidity
// Lido.sol, lines 399-423 -- external calls to nodeOperatorsRegistry
function _distributeOperatorShares(uint256 _shares) internal {
    uint256 operatorCount = nodeOperatorsRegistry.getActiveNodeOperatorsCount();
    // ...
    for (uint256 i = 0; i < operatorCount; i++) {
        (bool active, , address rewardAddress, , , , ) =
            nodeOperatorsRegistry.getNodeOperator(i);  // external call in loop
```

**Impact:**

If the `nodeOperatorsRegistry` contract is compromised or contains a callback mechanism, an attacker could re-enter the Lido contract during fee distribution. Since `_totalPooledEther` has already been updated but fee shares may not be fully minted, re-entry into `_submit()` or other share-calculation functions would use an inconsistent state, potentially allowing share inflation or value extraction.

**Proof of Concept:**

```
1. Oracle calls handleOracleReport() with increased beacon balance
2. _totalPooledEther is updated (line 345)
3. _distributeFee() calls _distributeOperatorShares()
4. _distributeOperatorShares() calls nodeOperatorsRegistry.getNodeOperator(i)
5. If the registry (or operator reward address via a receive callback) re-enters
   submit(), the share calculation uses the updated _totalPooledEther but
   fee shares haven't been fully minted yet
6. Attacker receives more shares than entitled
```

**Recommendation:**

Add the `nonReentrant` modifier to `handleOracleReport()`:

```solidity
function handleOracleReport(
    uint256 _beaconValidators,
    uint256 _beaconBalance
) external nonReentrant {
```

Additionally, consider following the Checks-Effects-Interactions pattern by computing all fee shares before making any external calls.

---

### LIDO-03: stETH/wstETH Exchange Rate Manipulation via Share Calculation

- **ID:** LIDO-03
- **Title:** First depositor can manipulate share pricing through donation attack
- **Severity:** High
- **Category:** SC-06: Arithmetic
- **Location:** `Lido.sol:239-255`
- **Status:** Open

**Description:**

The share calculation in `_submit()` is vulnerable to the well-known ERC-4626 "inflation attack" (also known as the donation attack). When `_totalShares` is zero, shares are minted 1:1 with the deposit (line 243). A subsequent depositor's shares are calculated as:

```solidity
// Lido.sol, line 254
sharesAmount = (_value * _totalShares) / _totalPooledEther;
```

An attacker who is the first depositor can:
1. Deposit 1 wei of ETH, receiving 1 share
2. Directly send a large amount of ETH to the contract (inflating `_totalPooledEther` via the `receive()` function or through oracle manipulation)
3. The next depositor's shares will be calculated against the inflated `_totalPooledEther`, causing extreme precision loss

```solidity
// Lido.sol, lines 204-209 -- unguarded receive()
receive() external payable {
    // NOTE: potential vulnerability surface -- unguarded receive allows anyone to
    // inflate totalPooledEther if _processELRewards is called without proper checks.
}
```

**Impact:**

While the `receive()` function alone does not directly update `_totalPooledEther` (the comment notes this surface), the risk materializes through the oracle reporting path. If an attacker controls oracle reports or can influence the beacon balance calculation, they can inflate the denominator in the share formula, causing subsequent depositors to receive zero shares (truncated by integer division) and lose their entire deposit.

With a $38B TVL protocol, the practical risk of this specific attack is low (the pool is already well-established), but it represents a design concern for any protocol fork or fresh deployment.

**Proof of Concept:**

```
1. Attacker deposits 1 wei ETH as first depositor -> receives 1 share
2. Attacker manipulates _totalPooledEther to 10 ETH (e.g., through oracle)
3. Victim deposits 9.99 ETH
4. Victim shares = (9.99e18 * 1) / 10e18 = 0 (truncated)
5. Victim loses 9.99 ETH; attacker's 1 share is now worth ~20 ETH
```

**Recommendation:**

Implement a minimum initial deposit or "dead shares" mechanism similar to OpenZeppelin's ERC-4626 implementation:

```solidity
function _submit(...) internal returns (uint256 sharesAmount) {
    if (_totalShares == 0) {
        sharesAmount = _value - MINIMUM_DEPOSIT;
        _mintShares(address(0xdead), MINIMUM_DEPOSIT); // dead shares
    } else {
        sharesAmount = (_value * _totalShares) / _totalPooledEther;
    }
    // ...
}
```

---

### LIDO-04: Centralized Admin Control -- Single Point of Failure

- **ID:** LIDO-04
- **Title:** Unrestricted admin privileges without timelock or multi-sig enforcement
- **Severity:** High
- **Category:** SC-02: Access Control
- **Location:** `Lido.sol:123,612-620`, `LidoOracle.sol:84,256-295`
- **Status:** Open

**Description:**

Both `Lido.sol` and `LidoOracle.sol` vest extreme authority in a single `admin` address. The admin can:

**In Lido.sol:**
- Grant and revoke any role to any address (`grantRole`/`revokeRole`, lines 612-620)
- By extension, any account granted `PAUSE_ROLE` can halt the entire protocol
- Any account granted `MANAGE_FEE` can set fees up to 100% (`MAX_FEE_BASIS_POINTS = 10000`)
- Any account granted `MANAGE_WITHDRAWAL_KEY` can change withdrawal credentials
- Any account granted `MANAGE_PROTOCOL_CONTRACTS_ROLE` can change protocol contract addresses

**In LidoOracle.sol:**
- Add/remove oracle members (`addOracleMember`/`removeOracleMember`, lines 256-288)
- Set quorum to any value including 1 (`setQuorum`, lines 290-295)
- Set expected epoch arbitrarily (`setExpectedEpochId`, lines 317-320)
- Modify beacon chain specification parameters (`setBeaconSpec`, lines 299-315)

There is no timelock, no multi-signature requirement, and no admin transfer mechanism.

```solidity
// Lido.sol, line 612-615
function grantRole(bytes32 _role, address _account) external {
    require(msg.sender == admin, "ONLY_ADMIN");
    _roles[_role][_account] = true;
}
```

**Impact:**

If the admin private key is compromised, the attacker can:
- Pause the protocol, locking $38B in staked ETH
- Set fees to 100%, extracting all future staking rewards
- Replace oracle members and set quorum to 1, enabling arbitrary balance reporting
- Change withdrawal credentials to redirect all unstaked ETH
- This represents a catastrophic single point of failure for a $38B protocol

**Proof of Concept:**

```
1. Attacker compromises admin private key
2. Attacker calls setQuorum(1) on LidoOracle
3. Attacker calls addOracleMember(attackerAddress) on LidoOracle
4. Attacker calls reportBeacon() with inflated balance
5. Quorum of 1 is immediately met, pushing false report to Lido
6. Inflated _totalPooledEther causes attacker's shares to be worth more
7. Attacker withdraws at inflated rate, draining protocol value
```

**Recommendation:**

1. Replace single `admin` with a timelock + multi-sig governance structure
2. Implement a 48-hour timelock for all admin operations
3. Add an admin transfer mechanism with two-step acceptance pattern
4. Cap individual operation scope (e.g., fee changes capped at +2% per governance cycle)
5. Emit events for all role changes (currently `grantRole`/`revokeRole` do not emit events)

---

### LIDO-05: CEI Pattern Violation in `depositBufferedEther`

- **ID:** LIDO-05
- **Title:** State changes interleaved with external calls in deposit loop
- **Severity:** High
- **Category:** SC-01: Reentrancy
- **Location:** `Lido.sol:431-443`
- **Status:** Open

**Description:**

The `depositBufferedEther()` function modifies state variables `_bufferedEther` and `_depositedValidators` inside a loop that would contain an external call to the deposit contract in production:

```solidity
// Lido.sol, lines 431-443
function depositBufferedEther(uint256 _maxDeposits) external onlyRole(STAKING_CONTROL_ROLE) {
    uint256 depositsCount = _min(_maxDeposits, _bufferedEther / DEPOSIT_SIZE);
    require(depositsCount > 0, "NOTHING_TO_DEPOSIT");

    for (uint256 i = 0; i < depositsCount; i++) {
        _bufferedEther -= DEPOSIT_SIZE;
        _depositedValidators += 1;
        // In production, signing keys are fetched from NodeOperatorsRegistry
        // depositContract.deposit{value: DEPOSIT_SIZE}(...);
    }

    emit Unbuffered(depositsCount * DEPOSIT_SIZE);
}
```

The commented-out `depositContract.deposit{value: DEPOSIT_SIZE}(...)` call would be an external call made AFTER state changes within the loop body. This violates the Checks-Effects-Interactions (CEI) pattern. While the function is gated by `onlyRole(STAKING_CONTROL_ROLE)`, the deposit contract itself could be malicious or compromised.

Additionally, the function lacks the `nonReentrant` modifier, unlike `submit()` and `withdraw()` which do use it.

**Impact:**

If the deposit contract is upgradeable or compromised, a callback during `deposit()` could re-enter the Lido contract. Since `_bufferedEther` and `_depositedValidators` are partially updated mid-loop, re-entering `submit()` or `withdraw()` would operate on inconsistent state.

**Recommendation:**

1. Add the `nonReentrant` modifier to `depositBufferedEther()`
2. Batch all state changes before the external call loop:

```solidity
function depositBufferedEther(uint256 _maxDeposits) external
    onlyRole(STAKING_CONTROL_ROLE)
    nonReentrant
{
    uint256 depositsCount = _min(_maxDeposits, _bufferedEther / DEPOSIT_SIZE);
    require(depositsCount > 0, "NOTHING_TO_DEPOSIT");

    // Effects first
    _bufferedEther -= depositsCount * DEPOSIT_SIZE;
    _depositedValidators += depositsCount;

    // Interactions last
    for (uint256 i = 0; i < depositsCount; i++) {
        depositContract.deposit{value: DEPOSIT_SIZE}(...);
    }

    emit Unbuffered(depositsCount * DEPOSIT_SIZE);
}
```

---

### LIDO-06: Oracle Quorum Mechanism Weaknesses

- **ID:** LIDO-06
- **Title:** Quorum can be set to 1, and initial quorum defaults to 1
- **Severity:** Medium
- **Category:** SC-02: Access Control
- **Location:** `LidoOracle.sol:128,290-295`
- **Status:** Open

**Description:**

The oracle quorum is initialized to 1 in the constructor and can be set to any value >= 1 by the admin:

```solidity
// LidoOracle.sol, line 128
constructor(address _lido) {
    // ...
    quorum = 1; // Initial quorum, should be updated after adding members
}

// LidoOracle.sol, lines 290-295
function setQuorum(uint256 _quorum) external onlyAdmin {
    require(_quorum > 0, "ZERO_QUORUM");
    require(_quorum <= oracleMembers.length, "QUORUM_TOO_LARGE");
    quorum = _quorum;
    emit QuorumChanged(_quorum);
}
```

A quorum of 1 means a single oracle member can unilaterally push reports to the Lido contract. Additionally, when `removeOracleMember()` reduces the member count below the current quorum, the quorum is automatically lowered (line 282-284), potentially reaching 1.

**Impact:**

- If quorum = 1, oracle decentralization is illusory; one compromised member can push arbitrary reports
- The automatic quorum reduction on member removal can silently weaken security
- No minimum quorum floor (e.g., 3-of-5 minimum) is enforced

**Proof of Concept:**

```
1. Admin adds 5 oracle members, sets quorum to 3
2. Admin removes 3 members (for legitimate operational reasons)
3. Quorum is automatically reduced to 2 (line 283)
4. Admin removes 1 more member
5. Quorum is automatically reduced to 1
6. Single remaining member has unilateral control over reports
```

**Recommendation:**

1. Enforce a minimum quorum floor (e.g., `require(_quorum >= 3, "QUORUM_TOO_LOW")`)
2. Require quorum to be a strict majority: `require(_quorum > oracleMembers.length / 2)`
3. Do not automatically reduce quorum when removing members; instead, revert if removal would break quorum invariants

---

### LIDO-07: Share Precision Loss on Small Deposits

- **ID:** LIDO-07
- **Title:** Integer division truncation causes precision loss for small stETH operations
- **Severity:** Medium
- **Category:** SC-06: Arithmetic
- **Location:** `Lido.sol:254,487,496`
- **Status:** Open

**Description:**

The share calculation uses integer division, which truncates the result:

```solidity
// Lido.sol, line 254
sharesAmount = (_value * _totalShares) / _totalPooledEther;

// Lido.sol, line 487
return (_sharesAmount * _totalPooledEther) / _totalShares;

// Lido.sol, line 496
return (_ethAmount * _totalShares) / _totalPooledEther;
```

The scanner flagged these as potential division-by-zero risks (lines 254, 487, 496). While the code does include zero-checks on lines 242 and 486/495 (`if (_totalShares == 0) return 0`), the precision loss from truncation is a separate concern.

As the share rate diverges from 1:1 (which it does as rewards accumulate), small deposits and transfers experience proportionally larger rounding errors. This is the documented "1-2 wei rounding issue" in stETH.

**Impact:**

- Users making small deposits may receive fewer shares than expected
- Transfers of stETH amounts may result in the recipient receiving 1-2 wei less than the sender sent
- Over time, these rounding losses accumulate and are effectively captured by the protocol
- DeFi integrations that perform many small operations (e.g., interest accrual) are disproportionately affected

**Proof of Concept:**

```
Given: totalPooledEther = 1,000,000e18, totalShares = 999,000e18
User deposits 1 wei:
  sharesAmount = (1 * 999,000e18) / 1,000,000e18 = 0 (truncated)
  -> require(sharesAmount > 0) reverts, deposit fails

User deposits 2 wei:
  sharesAmount = (2 * 999,000e18) / 1,000,000e18 = 1
  -> User gets 1 share worth ~1.001 wei (gained ~0.001 wei)
  -> But reverse: getPooledEthByShares(1) = 1 * 1,000,000e18 / 999,000e18 = 1
  -> User lost ~0.001 wei in the round-trip
```

**Recommendation:**

1. Document the minimum effective deposit amount in the contract and revert for deposits below it
2. Consider using `mulDiv` with rounding direction control (round down for deposits/minting, round up for withdrawals/burning) to minimize systematic bias
3. Add a minimum deposit requirement (e.g., 100 wei) to prevent dust deposits

---

### LIDO-08: Fee Distribution Rounding Accumulates Dust

- **ID:** LIDO-08
- **Title:** Sequential fee split divisions cause cumulative rounding loss
- **Severity:** Medium
- **Category:** SC-06: Arithmetic
- **Location:** `Lido.sol:371-393`
- **Status:** Open

**Description:**

The fee distribution performs multiple sequential divisions:

```solidity
// Lido.sol, line 371
uint256 feeInEth = (_rewards * totalFeeBasicPoints) / BASIS_POINTS;

// Lido.sol, line 380
uint256 feeShares = (feeInEth * _totalShares) / (_totalPooledEther - feeInEth);

// Lido.sol, lines 385-387
uint256 treasuryShares = (feeShares * treasuryFeeBasisPoints) / BASIS_POINTS;
uint256 insuranceShares = (feeShares * insuranceFeeBasisPoints) / BASIS_POINTS;
uint256 operatorsShares = feeShares - treasuryShares - insuranceShares;
```

The scanner flagged five division-by-zero risks on lines 371, 385, 386, 407, and 432. While `BASIS_POINTS` is a constant (10000) and cannot be zero, the `_totalPooledEther - feeInEth` denominator on line 380 could theoretically be zero if `totalFeeBasicPoints == BASIS_POINTS` (100% fee) and the check on line 583 allows this.

The more practical concern is cumulative truncation: three sequential divisions compound the rounding error, and the `operatorsShares` remainder captures some but not all dust.

```solidity
// Lido.sol, lines 407-422 -- further division in operator distribution
uint256 perOperator = _shares / operatorCount;  // truncation
uint256 distributed = 0;
// ...
uint256 dust = _shares - distributed;  // dust goes to treasury
```

**Impact:**

- With daily oracle reports and 10% total fee, truncation losses of ~1-10 wei per report accumulate
- Over a year: ~365 reports * ~5 wei lost = ~1,825 wei (~$0.005 at current prices)
- While economically negligible for the $38B protocol, the dust consistently favors operators (via the remainder calculation) or treasury (via the dust redistribution), creating a systematic bias

**Recommendation:**

1. Use a single division where possible: compute `feeShares` directly without intermediate `feeInEth`
2. Ensure the dust distribution is intentional and documented
3. Consider using `mulDiv` for exact computation

---

### LIDO-09: `handleOracleReport` Sanity Check Contains Division-Before-Multiplication

- **ID:** LIDO-09
- **Title:** Reward sanity check uses division before multiplication, reducing effectiveness
- **Severity:** Medium
- **Category:** SC-06: Arithmetic
- **Location:** `Lido.sol:338-341`
- **Status:** Open

**Description:**

The annual reward rate sanity check performs division before multiplication, which reduces precision:

```solidity
// Lido.sol, lines 338-341
require(
    rewardsDelta * 365 * BASIS_POINTS / prePooledEther / 1 <= 1500,
    "REWARD_TOO_LARGE"
);
```

The scanner flagged this as a triple multiplication overflow risk (line 339). While `rewardsDelta * 365 * BASIS_POINTS` could overflow for extremely large reward deltas (unlikely but possible with manipulated oracle reports), the more immediate issue is the trailing `/ 1` which is a no-op but suggests the formula may be incomplete (possibly a simplified version of a per-frame-duration check).

Additionally, the expression `rewardsDelta * 365 * BASIS_POINTS / prePooledEther` performs integer division, which truncates. If `prePooledEther` is very large relative to `rewardsDelta`, the result could be 0 even for non-trivial reward rates, allowing them to bypass the sanity check.

**Impact:**

- The sanity check may be ineffective for certain reward/pool-size combinations
- An attacker who can influence oracle reports near the boundary conditions could bypass the cap
- The `/ 1` divisor suggests the formula may be a placeholder for a more sophisticated time-based check

**Recommendation:**

Replace with a correctly-structured check:

```solidity
// Check: rewardsDelta / prePooledEther <= 1500 / (365 * BASIS_POINTS)
// Rearranged to avoid division: rewardsDelta * 365 * BASIS_POINTS <= 1500 * prePooledEther
require(
    rewardsDelta * 365 * BASIS_POINTS <= 1500 * prePooledEther,
    "REWARD_TOO_LARGE"
);
```

---

### LIDO-10: Unchecked External Call Return Value in Withdrawal Flow

- **ID:** LIDO-10
- **Title:** Withdrawal queue enqueue call return value not validated for plausibility
- **Severity:** Medium
- **Category:** SC-07: Input Validation
- **Location:** `Lido.sol:280-298`
- **Status:** Open

**Description:**

The `withdraw()` function calls the withdrawal queue to enqueue a request, but the returned `requestId` is not validated:

```solidity
// Lido.sol, lines 280-298
function withdraw(uint256 _stETHAmount) external whenNotStopped nonReentrant returns (uint256 requestId) {
    // ... burns shares, updates _totalPooledEther ...

    // Enqueue withdrawal request in the withdrawal queue contract
    requestId = withdrawalQueue.enqueue(msg.sender, _stETHAmount, sharesAmount);

    return requestId;
}
```

If the `withdrawalQueue` contract returns `requestId = 0` or an otherwise invalid value, the user has already had their shares burned with no way to verify their withdrawal request was properly registered. The function burns shares and decrements `_totalPooledEther` BEFORE the external call, which is good for CEI but means the user's funds are irrevocably committed before the queue confirms acceptance.

**Impact:**

- If the withdrawal queue is misconfigured, upgraded, or returns an unexpected value, users could lose their stETH with no withdrawal request
- The `withdrawalQueue` address is set by an admin role and could potentially be changed to a malicious contract

**Recommendation:**

1. Validate the return value: `require(requestId > 0, "INVALID_REQUEST_ID")`
2. Consider implementing a withdrawal queue interface version check
3. Emit the `requestId` in an event so users can track their withdrawal off-chain

---

### LIDO-11: `setFeeDistribution` Allows Fee Manipulation Without Timelock

- **ID:** LIDO-11
- **Title:** Fee distribution can be changed instantaneously by MANAGE_FEE role
- **Severity:** Medium
- **Category:** SC-07: Input Validation
- **Location:** `Lido.sol:582-601`
- **Status:** Open

**Description:**

The fee-related functions allow instant changes:

```solidity
// Lido.sol, lines 582-586
function setFee(uint16 _feeBasisPoints) external onlyRole(MANAGE_FEE) {
    require(_feeBasisPoints <= MAX_FEE_BASIS_POINTS, "FEE_TOO_HIGH");
    totalFeeBasicPoints = _feeBasisPoints;
    emit FeeSet(_feeBasisPoints);
}

// Lido.sol, lines 588-601
function setFeeDistribution(
    uint16 _treasuryFeeBasisPoints,
    uint16 _insuranceFeeBasisPoints,
    uint16 _operatorsFeeBasisPoints
) external onlyRole(MANAGE_FEE) {
    require(
        _treasuryFeeBasisPoints + _insuranceFeeBasisPoints + _operatorsFeeBasisPoints == BASIS_POINTS,
        "FEE_DISTRIBUTION_INVALID"
    );
    // ...
}
```

The scanner identified that `setFeeDistribution` "lacks bounds validation" on individual components (line 588). While the sum must equal `BASIS_POINTS`, individual values are unconstrained. The `setFee` function allows fees up to `MAX_FEE_BASIS_POINTS = 10000` (100%), meaning the MANAGE_FEE role holder can extract 100% of staking rewards.

**Impact:**

- A compromised `MANAGE_FEE` holder can set `totalFeeBasicPoints = 10000`, redirecting all staking rewards to protocol fee recipients
- Fee distribution can be set to `(10000, 0, 0)`, sending all fees to treasury
- No timelock means users have no opportunity to exit before fee changes take effect

**Recommendation:**

1. Enforce a maximum total fee (e.g., 20%): `require(_feeBasisPoints <= 2000, "FEE_TOO_HIGH")`
2. Add a timelock delay for fee changes (e.g., 7 days)
3. Enforce minimum non-zero allocation to operators to prevent undermining validator incentives

---

### LIDO-12: Read-Only Reentrancy in WstETH Price Functions

- **ID:** LIDO-12
- **Title:** `stEthPerToken` and `tokensPerStEth` vulnerable to read-only reentrancy
- **Severity:** Medium
- **Category:** SC-01: Reentrancy
- **Location:** `WstETH.sol:117-132`
- **Status:** Open

**Description:**

The scanner identified read-only reentrancy risks in WstETH's view functions (lines 117-131). These functions query the Lido contract's state:

```solidity
// WstETH.sol, lines 117-121
function stEthPerToken() external view returns (uint256) {
    uint256 totalShares = stETH.getTotalShares();
    if (totalShares == 0) return 1e18;
    return stETH.getPooledEthByShares(1e18);
}

// WstETH.sol, lines 128-132
function tokensPerStEth() external view returns (uint256) {
    uint256 totalPooled = stETH.getTotalPooledEther();
    if (totalPooled == 0) return 1e18;
    return stETH.getSharesByPooledEth(1e18);
}
```

If another contract calls these functions during a callback (e.g., inside a Lido `withdraw()` -> WithdrawalQueue callback chain), the values returned may reflect an intermediate state where `_totalPooledEther` has been decremented but shares have not been fully burned, or vice versa. External DeFi protocols that use these functions for oracle pricing are vulnerable.

**Impact:**

This is the classic "read-only reentrancy" pattern that has caused real exploits (e.g., Curve/Balancer LP token pricing attacks). Any protocol using `stEthPerToken()` or `tokensPerStEth()` as a price oracle during a Lido state transition will receive stale or manipulated prices, potentially enabling:
- Under-collateralized borrowing on lending protocols
- Arbitrage on DEXes that use these as reference prices
- Liquidation manipulation

**Recommendation:**

1. Add a reentrancy lock that external protocols can check: `require(_reentrancyStatus == _NOT_ENTERED, "REENTRANCY")`
2. Document the read-only reentrancy risk for all integrators
3. Consider implementing EIP-6093 style reentrancy detection that view functions can reference

---

### LIDO-13: WstETH `unwrap` Missing Reentrancy Guard

- **ID:** LIDO-13
- **Title:** `unwrap()` makes external call to stETH.transfer without reentrancy protection
- **Severity:** Medium
- **Category:** SC-01: Reentrancy
- **Location:** `WstETH.sol:92-108`
- **Status:** Open

**Description:**

The scanner flagged `unwrap()` at line 92 as missing `nonReentrant`. The function burns wstETH tokens, then makes an external call to `stETH.transfer()`:

```solidity
// WstETH.sol, lines 92-108
function unwrap(uint256 _wstETHAmount) external returns (uint256 stETHAmount) {
    require(_wstETHAmount > 0, "ZERO_AMOUNT");
    require(_balances[msg.sender] >= _wstETHAmount, "INSUFFICIENT_BALANCE");

    stETHAmount = stETH.getPooledEthByShares(_wstETHAmount);
    require(stETHAmount > 0, "ZERO_STETH");

    _burn(msg.sender, _wstETHAmount);               // Effects
    bool success = stETH.transfer(msg.sender, stETHAmount);  // Interaction
    require(success, "STETH_TRANSFER_FAILED");

    emit Unwrap(msg.sender, _wstETHAmount, stETHAmount);
}
```

While the function does follow CEI pattern (burn before transfer), the WstETH contract does not implement any reentrancy guard. The `stETH.transfer()` call could trigger callbacks if stETH has hooks (unlikely in current implementation, but a concern for upgradeable contracts or ERC-777-style callbacks in future versions).

**Impact:**

An attacker could potentially re-enter `unwrap()` or `wrap()` during the `stETH.transfer()` call, but since `_burn()` is called first and reduces `_balances`, a direct re-entrant `unwrap()` would fail the balance check. The risk is more theoretical than practical in the current implementation, but represents a defense-in-depth gap.

**Recommendation:**

Add a reentrancy guard to WstETH:

```solidity
uint256 private _reentrancyStatus = 1;
modifier nonReentrant() {
    require(_reentrancyStatus != 2, "REENTRANCY");
    _reentrancyStatus = 2;
    _;
    _reentrancyStatus = 1;
}

function unwrap(...) external nonReentrant returns (...) { ... }
function wrap(...) external nonReentrant returns (...) { ... }
```

---

### LIDO-14: Missing Zero-Address Checks in Lido Constructor

- **ID:** LIDO-14
- **Title:** Constructor accepts zero addresses for critical contract references
- **Severity:** Low
- **Category:** SC-07: Input Validation
- **Location:** `Lido.sol:186-200`
- **Status:** Open

**Description:**

The scanner identified 5 missing zero-address checks in the Lido constructor for parameters `_depositContract`, `_oracle`, `_nodeOperatorsRegistry`, `_treasury`, and `_insuranceFund`:

```solidity
// Lido.sol, lines 186-200
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
```

In contrast, the WstETH constructor does validate its parameter: `require(_stETH != address(0), "ZERO_ADDRESS")` (line 50).

**Impact:**

If any address is accidentally set to `address(0)`:
- `depositContract = address(0)`: All beacon chain deposits would fail
- `oracle = address(0)`: No oracle reports would be accepted (but `handleOracleReport` checks `msg.sender == address(oracle)`, so anyone could call it if oracle is zero -- actually `address(0)` cannot send transactions, so it would be permanently locked)
- `treasury = address(0)`: Fee shares would be minted to the zero address and burned
- `insuranceFund = address(0)`: Same as treasury

Since the constructor is only called once at deployment, this is primarily a deployment safety concern.

**Recommendation:**

Add zero-address checks for all parameters:

```solidity
constructor(...) {
    require(_depositContract != address(0), "ZERO_DEPOSIT_CONTRACT");
    require(_oracle != address(0), "ZERO_ORACLE");
    require(_nodeOperatorsRegistry != address(0), "ZERO_REGISTRY");
    require(_treasury != address(0), "ZERO_TREASURY");
    require(_insuranceFund != address(0), "ZERO_INSURANCE");
    // ...
}
```

---

### LIDO-15: Hardcoded 1e18 Decimal Assumption in WstETH

- **ID:** LIDO-15
- **Title:** Rate functions assume 18-decimal precision without validation
- **Severity:** Low
- **Category:** SC-09: Oracle Dependency / SC-06: Arithmetic
- **Location:** `WstETH.sol:119-131`
- **Status:** Open

**Description:**

The scanner flagged 6 instances of hardcoded `1e18` values in WstETH's rate functions:

```solidity
// WstETH.sol, lines 119-120
if (totalShares == 0) return 1e18;
return stETH.getPooledEthByShares(1e18);

// WstETH.sol, lines 130-131
if (totalPooled == 0) return 1e18;
return stETH.getSharesByPooledEth(1e18);
```

While both stETH and wstETH are designed as 18-decimal tokens, the hardcoded `1e18` creates an implicit coupling. If the underlying stETH implementation were ever upgraded or forked with different decimal precision, these functions would return incorrect values.

**Impact:**

Low in practice since both tokens are immutably 18 decimals. However, the scanner correctly identifies this as a code quality concern. The `1e18` values serve double duty as both "1 token" and "decimal precision", which reduces code clarity.

**Recommendation:**

Define a named constant for clarity:

```solidity
uint256 private constant ONE_TOKEN = 1e18;

function stEthPerToken() external view returns (uint256) {
    uint256 totalShares = stETH.getTotalShares();
    if (totalShares == 0) return ONE_TOKEN;
    return stETH.getPooledEthByShares(ONE_TOKEN);
}
```

---

### LIDO-16: Missing Events for Critical State Changes

- **ID:** LIDO-16
- **Title:** Role changes and withdrawal credential updates lack event emission
- **Severity:** Low
- **Category:** SC-04: Denial of Service / Monitoring
- **Location:** `Lido.sol:603-620`
- **Status:** Open

**Description:**

Several critical administrative functions do not emit events:

```solidity
// Lido.sol, lines 603-605 -- no event emitted
function setWithdrawalCredentials(bytes32 _withdrawalCredentials) external onlyRole(MANAGE_WITHDRAWAL_KEY) {
    withdrawalCredentials = _withdrawalCredentials;
}

// Lido.sol, lines 612-615 -- no event emitted
function grantRole(bytes32 _role, address _account) external {
    require(msg.sender == admin, "ONLY_ADMIN");
    _roles[_role][_account] = true;
}

// Lido.sol, lines 617-620 -- no event emitted
function revokeRole(bytes32 _role, address _account) external {
    require(msg.sender == admin, "ONLY_ADMIN");
    _roles[_role][_account] = false;
}
```

**Impact:**

- Off-chain monitoring systems cannot detect withdrawal credential changes, which is one of the most security-critical parameters in the protocol
- Role grants/revocations are invisible to governance watchers and security monitoring tools
- Post-incident forensics would lack an on-chain audit trail for these changes

**Recommendation:**

Add events and emit them:

```solidity
event WithdrawalCredentialsSet(bytes32 withdrawalCredentials);
event RoleGranted(bytes32 indexed role, address indexed account, address indexed sender);
event RoleRevoked(bytes32 indexed role, address indexed account, address indexed sender);
```

---

### LIDO-17: Gas Optimization and Code Quality

- **ID:** LIDO-17
- **Title:** Multiple gas optimization opportunities and code quality improvements
- **Severity:** Informational
- **Category:** Gas Optimization / Code Quality
- **Location:** Multiple
- **Status:** Open

**Description:**

Several minor improvements were identified:

**1. Unbounded Loop in `_distributeOperatorShares` (Lido.sol:410-416)**

```solidity
for (uint256 i = 0; i < operatorCount; i++) {
    (bool active, , address rewardAddress, , , , ) =
        nodeOperatorsRegistry.getNodeOperator(i);
```

This loop makes an external call per iteration with no upper bound on `operatorCount`. With hundreds of operators, this could exceed block gas limits.

**2. Unbounded Loop in `_clearReports` (LidoOracle.sol:244-248)**

```solidity
for (uint256 i = 0; i < currentReportHashes.length; i++) {
    delete reportHashCount[currentReportHashes[i]];
}
```

The number of distinct report hashes is bounded by the number of oracle members, but there is no explicit cap.

**3. Stale Member Reports Not Cleared (LidoOracle.sol:250-252)**

```solidity
// NOTE: We don't clear individual member reports since they are overwritten
// per-epoch. This saves gas but means stale data exists in storage.
```

While functionally correct (the epoch check prevents replays), stale storage data increases the contract's state footprint.

**4. `totalFeeBasicPoints` Typo (Lido.sol:102)**

The variable name uses "Basic" instead of "Basis" -- `totalFeeBasicPoints` should be `totalFeeBasisPoints` for consistency with the other fee variables (`treasuryFeeBasisPoints`, etc.).

**Recommendation:**

1. Cap `operatorCount` loop iterations or use a batch-based distribution
2. Define `MAX_ORACLE_MEMBERS` as the implicit bound for report hash cleanup
3. Consider clearing member reports periodically or on member removal
4. Rename `totalFeeBasicPoints` to `totalFeeBasisPoints`

---

## 5. Protocol-Specific Risk Analysis

### 5.1 Systemic Risk: stETH as DeFi Collateral

Lido's stETH and wstETH tokens are used as collateral across the DeFi ecosystem:

| Protocol | Usage | Risk Exposure |
|----------|-------|---------------|
| Aave V3 | Collateral for borrowing | ~$8B in stETH/wstETH collateral |
| Curve | stETH/ETH pool liquidity | ~$2B in pool TVL |
| MakerDAO | wstETH vaults for DAI minting | ~$3B in vault collateral |
| Balancer | wstETH/WETH pools | ~$500M in pool TVL |
| Compound V3 | wstETH collateral | ~$1B in collateral |

A vulnerability that affects the stETH/ETH exchange rate (e.g., oracle manipulation via LIDO-01/LIDO-02) could trigger cascading liquidations across all of these protocols simultaneously. The 2022 stETH depeg event (which reached ~0.93 ETH per stETH) demonstrated that even a confidence-driven price deviation can cause billions in liquidations.

### 5.2 Validator Slashing Risk

The protocol's share price is directly tied to beacon chain validator performance. If a significant number of Lido validators are slashed:

- `_beaconBalance` decreases in the next oracle report
- `_totalPooledEther` decreases accordingly
- All stETH holders' balances decrease proportionally
- No individual holder is insulated from slashing events

The sanity check in `LidoOracle._finalizeReport()` limits per-report balance decreases to 5% (`MAX_ALLOWED_DECREASE_BP = 500`), which provides some protection against oracle bugs but also means genuine large slashing events would be artificially capped, requiring multiple reporting cycles to fully reflect.

### 5.3 Oracle Committee Trust Analysis

The oracle security model relies on several assumptions:

| Assumption | Status | Risk |
|------------|--------|------|
| Oracle members are independent entities | **Trust assumption** | If members share infrastructure, a single failure can compromise quorum |
| Quorum > N/2 is maintained | **Not enforced in code** | Admin can set quorum = 1 (see LIDO-06) |
| Sanity checks catch all manipulation | **Partially effective** | Bounds may be too loose for sophisticated attacks (see LIDO-09) |
| Oracle daemon software is correct | **Out of scope** | Software bugs could cause all members to report identical wrong values |

The most dangerous scenario is "honest but wrong" -- where all oracle members independently compute the same incorrect value due to a shared software bug. Quorum consensus provides no protection in this case.

### 5.4 Governance Centralization Analysis

The current governance structure concentrates significant power:

```
admin (single EOA or multisig)
  |
  +-- grantRole() / revokeRole()
  |     |
  |     +-- PAUSE_ROLE -> stop() / resume()
  |     +-- STAKING_PAUSE_ROLE -> pauseStaking() / resumeStaking()
  |     +-- MANAGE_FEE -> setFee() / setFeeDistribution()
  |     +-- MANAGE_WITHDRAWAL_KEY -> setWithdrawalCredentials()
  |     +-- SET_EL_REWARDS_VAULT_ROLE -> setELRewardsVault()
  |     +-- STAKING_CONTROL_ROLE -> depositBufferedEther()
  |     +-- BURN_ROLE -> (burn functionality)
  |
  +-- (Oracle) addOracleMember() / removeOracleMember() / setQuorum()
```

Every critical parameter change flows through a single `admin` address. There is:
- No timelock on any operation
- No multi-step execution (propose/execute pattern)
- No admin transfer functionality (if the key is lost, governance is permanently frozen)
- No emergency guardian role separation

---

## 6. Recommendations Summary

### Priority 1 -- Critical (Address Immediately)

| ID | Finding | Recommendation |
|----|---------|----------------|
| LIDO-01 | Validator delta always zero | Fix parameter shadowing; rename function parameters |
| LIDO-02 | Missing reentrancy guard on handleOracleReport | Add `nonReentrant` modifier |

### Priority 2 -- High (Address Before Next Deployment)

| ID | Finding | Recommendation |
|----|---------|----------------|
| LIDO-03 | Share inflation attack | Implement dead shares or minimum deposit |
| LIDO-04 | Centralized admin control | Implement timelock + multi-sig |
| LIDO-05 | CEI violation in depositBufferedEther | Batch state changes before external calls; add nonReentrant |

### Priority 3 -- Medium (Address in Next Update Cycle)

| ID | Finding | Recommendation |
|----|---------|----------------|
| LIDO-06 | Quorum can be set to 1 | Enforce minimum quorum floor |
| LIDO-07 | Share precision loss | Add minimum deposit; use directional rounding |
| LIDO-08 | Fee rounding dust | Consolidate divisions; document dust allocation |
| LIDO-09 | Sanity check arithmetic | Restructure to avoid division; use multiplication comparison |
| LIDO-10 | Unchecked withdrawal queue return | Validate requestId > 0 |
| LIDO-11 | Fee manipulation without timelock | Cap fees; add timelock |
| LIDO-12 | Read-only reentrancy in WstETH | Add reentrancy status check for view functions |
| LIDO-13 | unwrap missing nonReentrant | Add reentrancy guard to WstETH |

### Priority 4 -- Low / Informational (Best Practice)

| ID | Finding | Recommendation |
|----|---------|----------------|
| LIDO-14 | Missing zero-address checks | Add require statements in constructor |
| LIDO-15 | Hardcoded 1e18 | Define named constant |
| LIDO-16 | Missing events | Add events for role and credential changes |
| LIDO-17 | Gas and code quality | Cap loops; fix typo; clean stale storage |

---

## 7. Scanner Finding Correlation

The following table maps the 68 raw scanner findings to the consolidated audit findings in this report:

| Scanner Category | Count | Consolidated Into |
|-----------------|-------|-------------------|
| access-control: Unprotected transfer/transferFrom | 4 (High) | **Reclassified as False Positive** -- ERC-20 functions are intentionally public |
| reentrancy: Missing nonReentrant on deposit interface | 1 (Medium) | LIDO-02, LIDO-05 |
| reentrancy: Cross-function reentrancy (Lido deposit paths) | 22 (Medium) | LIDO-02, LIDO-05 |
| reentrancy: Cross-function reentrancy (WstETH paths) | 10 (Medium) | LIDO-12, LIDO-13 |
| reentrancy: CEI violation in deposit | 1 (Medium) | LIDO-05 |
| reentrancy: Missing nonReentrant on unwrap | 1 (Medium) | LIDO-13 |
| reentrancy: Read-only reentrancy risks | 2 (Low) | LIDO-12 |
| arithmetic: Division by zero risks | 10 (Medium) | LIDO-07, LIDO-08, LIDO-09 |
| arithmetic: Triple multiplication overflow | 2 (Low) | LIDO-09 |
| arithmetic: Hardcoded 18 decimals | 4 (Low) | LIDO-15 |
| access-control: Missing zero-address checks | 5 (Low) | LIDO-14 |
| access-control: Setter lacks bounds validation | 1 (Medium) | LIDO-11 |
| oracle-dependency: Hardcoded decimal assumption | 5 (Low) | LIDO-15 |

**Key reclassifications:**
- The 4 High findings (unprotected `transfer`/`transferFrom`) are **false positives**. These are standard ERC-20 token functions that must be callable by any address. The scanner incorrectly flagged them because they perform "sensitive operations" (balance changes) without access control, but this is by design for token transfers.
- The 22 cross-function reentrancy findings stemming from the `IDepositContract.deposit` interface declaration (line 52) are **over-reported** -- many involve admin-gated functions that cannot be called by an attacker during re-entry.

---

## 8. Disclaimer

This security audit report is provided for informational purposes only. It represents the auditor's assessment at the time of review and should not be considered a guarantee of the protocol's security.

**Limitations:**
- This audit was conducted on a specific code snapshot and does not account for future modifications
- Automated scanner results were used as one input among several; they may contain false positives and false negatives
- The audit scope was limited to the three contracts listed; interactions with external contracts (NodeOperatorsRegistry, WithdrawalQueue, DepositContract) were analyzed only at the interface level
- No formal verification was performed
- Economic attack vectors involving cross-protocol interactions (e.g., flash loan-enabled attacks through Aave/Curve) were not fully explored
- Off-chain components (oracle daemon, key management, deployment scripts) were out of scope

**Usage:**
- This report should be used alongside other security measures including formal verification, economic audits, and ongoing monitoring
- All findings should be independently verified before implementing fixes
- The severity classifications reflect the auditor's judgment and may differ from the protocol team's risk assessment
- This report does not constitute financial, legal, or investment advice

**Auditor Independence:**
- The auditor has no financial stake in the Lido protocol or its governance tokens
- No prior relationship exists between the auditor and the Lido development team
- This audit was conducted independently and without influence from any third party

---

*End of Report*

*Report generated: 2026-02-24 | Contracts analyzed: 3 | Total LOC: 1,214 | Findings: 17 (2 Critical, 3 High, 7 Medium, 3 Low, 2 Informational)*
