# Report 27: Replay Verification Results

**Generated:** 2026-05-13T15:27:09.618006+00:00

## Summary

- Replay cases tracked: 12
- Implemented Foundry replay tests: 3
- Verified fork replays: 1
- Missing RPC configuration: 0
- Archive-state unavailable on configured/public RPC: 1
- Replay logic/assertion failures: 1
- Missing replay test implementation: 9
- Failed or timed out replay attempts: 2
- Log directory: `reports/replay_runs/20260513_152704`

## Case Matrix

| Incident | Chain | Family | Fork block | Test | Status | Blocker |
|---|---|---|---:|---|---|---|
| Euler Finance | ethereum | flash_loan | 16817995 | `test_EulerReplay` | `verified` |  |
| BonqDAO & AllianceBlock | polygon | oracle_manipulation | 38792977 | `test_BonqReplayTx1` | `failed` | archive_state_unavailable |
| Lendf.Me | ethereum | reentrancy | 9899725 | `test_LendfMeReplay` | `failed` | replay_assertion_or_execution_failure |
| Fei Protocol & Rari Capital | ethereum | reentrancy |  | `` | `no_test` | replay_test_not_implemented |
| Beanstalk | ethereum | flash_loan_governance |  | `` | `no_test` | replay_test_not_implemented |
| UwU Lend | ethereum | oracle_manipulation |  | `` | `no_test` | replay_test_not_implemented |
| Cream Finance | ethereum | flash_loan |  | `` | `no_test` | replay_test_not_implemented |
| xToken | ethereum | oracle_manipulation |  | `` | `no_test` | replay_test_not_implemented |
| flash.sx | eos | reentrancy |  | `` | `no_test` | replay_test_not_implemented |
| Mirror Protocol | terra | contract_bug |  | `` | `no_test` | replay_test_not_implemented |
| Cetus | sui | contract_bug |  | `` | `no_test` | replay_test_not_implemented |
| Balancer V2 | multi_evm | logic_bug |  | `` | `no_test` | replay_test_not_implemented |

## Interpretation

A case is counted as replay-verified only when the concrete Foundry replay test runs
against a configured RPC endpoint and exits successfully. Metadata-only tests, missing
RPC configuration, and unimplemented replay scaffolds are not replay evidence.

This run provides replay evidence for: Euler Finance. These cases can be
used as concrete empirical support in the paper, subject to adding negative
controls and documenting the fork block, chain, and replay command.

Archive-state access remains a chain-specific blocker for: BonqDAO & AllianceBlock.
Those cases need archive-capable RPC on the affected chain before the replay
logic can be evaluated.

Replay logic or anchoring must be repaired for: Lendf.Me.
These failures indicate that archive state was reachable but the current PoC
does not yet reproduce the intended exploit path.

Replay tests are still missing for: Fei Protocol & Rari Capital, Beanstalk, UwU Lend, Cream Finance, xToken, flash.sx, Mirror Protocol, Cetus, Balancer V2.
These should be treated as implementation backlog, not failed replay evidence.

## Next Implementation Targets

1. Configure archive-capable RPC for the blocked chains and rerun those cases.
2. Repair replay anchors and exploit steps for assertion/execution failures.
3. Implement high-value missing replay tests, prioritizing Fei/Rari, Beanstalk, and UwU Lend.
4. Add negative controls for each verified replay and report pass/fail separation.
