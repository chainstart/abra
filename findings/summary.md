# DeFi Security Audit — Cross-Protocol Findings Summary

**Date:** 2026-02-24
**Protocols Audited:** 5 (Lido, Aave, Uniswap, Curve, Compound)
**Total Contracts Analyzed:** 15
**Total Lines of Code:** ~7,700 LOC
**Total Scanner Findings:** 651 (triaged to ~65 unique findings across all protocols)

---

## Aggregate Statistics

### Scanner Findings by Severity

| Severity | Lido | Aave | Uniswap | Curve | Compound | **Total** |
|----------|------|------|---------|-------|----------|-----------|
| Critical | 0 | 0 | 2 | 0 | 0 | **2** |
| High | 4 | 6 | 4 | 0 | 3 | **17** |
| Medium | 47 | 65 | 108 | 105 | 99 | **424** |
| Low | 17 | 25 | 67 | 67 | 32 | **208** |
| **Total** | **68** | **96** | **181** | **172** | **134** | **651** |

### Scanner Findings by Analyzer

| Analyzer | Lido | Aave | Uniswap | Curve | Compound | **Total** |
|----------|------|------|---------|-------|----------|-----------|
| Access Control | 10 | 11 | 9 | 1 | 8 | **39** |
| Reentrancy | 37 | 60 | 111 | 79 | 79 | **366** |
| Oracle Dependency | 4 | 2 | 0 | 0 | 3 | **9** |
| Arithmetic | 17 | 23 | 61 | 92 | 44 | **237** |

### Manual Audit Findings (Post-Triage)

| Severity | Lido | Aave | Uniswap | Curve | Compound | **Total** |
|----------|------|------|---------|-------|----------|-----------|
| Critical | 2 | 1 | 2 | 0 | 0 | **5** |
| High | 3 | 3 | 4 | 3 | 3 | **16** |
| Medium | 7 | 6 | 12 | 7 | 10 | **42** |
| Low/Info | 5 | 3 | 8 | 3 | 5 | **24** |
| **Total** | **17** | **13** | **26** | **13** | **18** | **87** |

---

## Top Critical & High Findings Across All Protocols

| # | Protocol | ID | Title | Severity | Category |
|---|----------|----|-------|----------|----------|
| 1 | Lido | LIDO-01 | Validator balance delta always zero (parameter shadowing) | Critical | Logic Error |
| 2 | Lido | LIDO-02 | Missing reentrancy guard on `handleOracleReport` | Critical | Reentrancy |
| 3 | Aave | F-01 | Flash loan + oracle manipulation composite attack vector | Critical | Oracle/Flash Loan |
| 4 | Uniswap | CRIT-01 | `initialize()` without `initializer` modifier (V3Pool) | Critical | Access Control |
| 5 | Uniswap | CRIT-02 | `initialize()` without `initializer` modifier (V4PoolManager) | Critical | Access Control |
| 6 | Lido | LIDO-03 | Share inflation / first depositor attack | High | Arithmetic |
| 7 | Lido | LIDO-04 | Centralized admin without timelock | High | Access Control |
| 8 | Lido | LIDO-05 | CEI violation in `depositBufferedEther` | High | Reentrancy |
| 9 | Aave | F-02 | Unprotected AToken mint/burn (relies on `onlyPool`) | High | Access Control |
| 10 | Aave | F-03 | Liquidation cascade risk at HF=0.95 cliff | High | Logic Error |
| 11 | Aave | F-04 | Interest rate model div-by-zero at 100% utilization | High | Arithmetic |
| 12 | Uniswap | HIGH-01 | Unprotected `mint`/`burn` in V3Pool | High | Access Control |
| 13 | Uniswap | HIGH-02 | Unprotected `modifyLiquidity` in V4 | High | Access Control |
| 14 | Uniswap | HIGH-03 | `settle()` with `onlyByLocker` bypass risk | High | Access Control |
| 15 | Uniswap | HIGH-04 | Hook delta manipulation in V4 swap path | High | Logic Error |
| 16 | Curve | H-01 | Reentrancy in `exchange()` (Vyper incident reference) | High | Reentrancy |
| 17 | Curve | H-02 | Newton's method convergence failure | High | Arithmetic |
| 18 | Curve | H-03 | First depositor / virtual price manipulation | High | Arithmetic |
| 19 | Compound | H-01 | cToken exchange rate manipulation | High | Arithmetic |
| 20 | Compound | H-02 | Governance proposal execution risk | High | Governance |
| 21 | Compound | H-03 | Unprotected Comptroller hook functions | High | Access Control |

---

## Cross-Protocol Common Vulnerability Patterns

### 1. First Depositor / Share Inflation Attack
**Affected:** Lido, Curve, Compound
**Pattern:** When a vault/pool has zero deposits, the first depositor can manipulate the exchange rate by donating tokens directly, causing subsequent depositors to receive fewer shares than expected.
**Mitigation:** Dead shares (mint minimum initial shares to address(0)), minimum deposit requirements.

### 2. Reentrancy Risks
**Affected:** All 5 protocols
**Pattern:** External calls (token transfers, callbacks, oracle queries) followed by state changes. The most prevalent finding category (366 raw scanner findings).
**Key variants:**
- Classic reentrancy (Curve 2023 Vyper exploit)
- Cross-function reentrancy (Aave supply/borrow paths)
- Read-only reentrancy (Lido wstETH price functions, Curve virtual price)
- Flash loan callback reentrancy (Aave, Uniswap)
**Mitigation:** `nonReentrant` modifiers, CEI pattern, reentrancy-aware view functions.

### 3. Oracle Dependency Without Fallback
**Affected:** Lido, Aave, Compound
**Pattern:** Critical price-dependent operations (liquidations, health factor calculations) rely on a single oracle source without staleness checks, deviation bounds, or fallback mechanisms.
**Mitigation:** Multi-oracle aggregation, staleness checks, circuit breakers, L2 sequencer uptime feeds.

### 4. Arithmetic Precision Loss
**Affected:** All 5 protocols
**Pattern:** Division-before-multiplication causing truncation, unsafe integer downcasts, missing zero-denominator checks.
**Most affected:** Curve (92 findings) — due to Newton's method iterations and fee calculations.
**Mitigation:** `Math.mulDiv`, `SafeCast`, multiplication-before-division ordering.

### 5. Governance Centralization
**Affected:** Lido, Compound, Curve
**Pattern:** Admin/governance roles with insufficient time-delay or multi-sig protection for critical parameter changes.
**Historical incidents:** Compound COMP bug ($80M, 2021), Beanstalk ($182M, 2022).
**Mitigation:** Timelocks, multi-sig, guardian roles, parameter bounds enforcement.

### 6. Access Control Gaps
**Affected:** Uniswap, Aave, Compound
**Pattern:** Functions with sensitive operations (mint, burn, seize) lacking explicit access modifiers, relying on implicit trust assumptions.
**Mitigation:** Role-based access control, explicit `require(msg.sender == ...)` checks.

---

## Protocol Risk Rankings

| Rank | Protocol | TVL | Critical | High | Medium | Composite Risk Score | Primary Risk |
|------|----------|-----|----------|------|--------|---------------------|--------------|
| 1 | **Aave** | $38B | 1 | 3 | 6 | 20/30 | Oracle dependency |
| 2 | **Compound** | $2.1B | 0 | 3 | 10 | 20/30 | Governance + exchange rate |
| 3 | **Curve** | $2.7B | 0 | 3 | 7 | 18/30 | Newton convergence + Vyper |
| 4 | **Lido** | $38B | 2 | 3 | 7 | 14/30 | Oracle committee + centralization |
| 5 | **Uniswap** | $6B | 2 | 4 | 12 | 13/30 | V4 hooks attack surface |

---

## Recommendations Priority Matrix

### Immediate Action (All Protocols)
1. Fix access control gaps (unprotected initialization, missing modifiers)
2. Add reentrancy guards to all state-changing external-calling functions
3. Implement oracle staleness checks and circuit breakers

### Short-Term (1-3 months)
4. Implement first-depositor attack mitigations (dead shares)
5. Add `SafeCast` for all integer type conversions
6. Implement governance timelocks where missing
7. Add comprehensive event emission for monitoring

### Long-Term (3-6 months)
8. Multi-oracle fallback mechanisms
9. Formal verification of core invariants (Curve invariant, Uniswap TickMath)
10. V4 hooks audit framework and registry
11. Cross-protocol impact analysis and systemic risk monitoring

---

## Tool Effectiveness Analysis

| Analyzer | True Positives | False Positives | Precision |
|----------|---------------|-----------------|-----------|
| Access Control | ~25 | ~14 | ~64% |
| Reentrancy | ~120 | ~246 | ~33% |
| Oracle Dependency | ~9 | ~0 | ~100% |
| Arithmetic | ~95 | ~142 | ~40% |
| **Overall** | **~249** | **~402** | **~38%** |

The reentrancy analyzer has the highest false positive rate due to flagging interface declarations and pure/view functions. The oracle dependency analyzer has the highest precision. Future improvements should focus on reducing false positives in the reentrancy and arithmetic analyzers through better context-aware analysis.

---

*Generated by abra-toolkit | 5 protocols | 15 contracts | 651 findings triaged to 87 unique issues*
