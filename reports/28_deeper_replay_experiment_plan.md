# Report 28: Deeper Replay Experiment Plan

**Date:** 2026-05-13

## Objective

The current paper is blocked by weak replay evidence. The next experimental phase should turn the
Phase-2 incident shortlist from a catalog of plausible attacks into an auditable replay benchmark
with explicit success, failure, and blocker states.

The goal is not to claim that every incident is replayable. The goal is to make each replay outcome
scientifically interpretable:

1. verified fork replay,
2. implemented but blocked by archive state,
3. implemented but failing an exploit assertion,
4. not yet implemented,
5. out of scope for Foundry because the chain is not EVM-compatible.

## Current Execution Baseline

`tools/replay_runner.py` now records replay outcomes without treating missing RPC or skipped fork
execution as success. The latest run used public Ethereum and Polygon RPC endpoints:

```bash
ETH_RPC_URL=https://ethereum.publicnode.com \
POLYGON_RPC_URL=https://polygon-bor-rpc.publicnode.com \
python3 tools/replay_runner.py --timeout 300 --verbosity=-vv
```

Current result:

| Category | Count |
|---|---:|
| Replay cases tracked | 12 |
| Implemented Foundry replay tests | 3 |
| Verified fork replays | 0 |
| Archive-state unavailable on public RPC | 3 |
| Missing replay test implementation | 9 |

The three implemented cases all compile and pass metadata checks, but public RPC endpoints do not
serve the required historical state:

| Incident | Chain | Fork block | Current blocker |
|---|---|---:|---|
| Euler Finance | Ethereum | 16817995 | `archive_state_unavailable` |
| BonqDAO & AllianceBlock | Polygon | 38792977 | `archive_state_unavailable` |
| Lendf.Me | Ethereum | 9899725 | `archive_state_unavailable` |

This is already stronger evidence than a plain `0/20` result: the blocker is not merely missing
environment variables, but lack of archive-state access for historically old fork blocks.

## Static-Analysis Baseline

A fresh scanner run was also generated for the local contract corpus:

```bash
python3 tools/scanner.py \
  --target contracts \
  --output json \
  --output-file data/processed/scanner_findings_latest.json
```

Scanner output:

| Metric | Value |
|---|---:|
| Solidity files scanned | 16 |
| Analyzers run | 5 |
| Raw findings | 691 |
| Critical | 2 |
| High | 17 |
| Medium | 451 |
| Low | 221 |
| Reentrancy findings | 381 |
| Arithmetic findings | 256 |
| Access-control findings | 41 |
| Oracle-dependency findings | 13 |

This scanner output should be treated as the raw-alert layer for the next ARA paper revision.

## Phase A: Archive RPC Verification

Priority: high.

Required endpoints:

- `ETH_RPC_URL`: archive-capable Ethereum endpoint supporting block `9899725` and `16817995`.
- `POLYGON_RPC_URL`: archive-capable Polygon endpoint supporting block `38792977`.

Success criterion:

- At least one of Euler, BonqDAO, or Lendf.Me reaches `status=verified` in
  `data/processed/replay_results.csv`.

Expected commands:

```bash
ETH_RPC_URL=... python3 tools/replay_runner.py --only lendf-me --timeout 900 --verbosity=-vvv
ETH_RPC_URL=... python3 tools/replay_runner.py --only euler-finance --timeout 900 --verbosity=-vvv
POLYGON_RPC_URL=... python3 tools/replay_runner.py --only bonqdao-allianceblock --timeout 900 --verbosity=-vvv
```

If a paid archive RPC still fails, preserve the forge log and classify the blocker as either
`replay_assertion_or_execution_failure`, `rpc_transport_failure`, or `rpc_rate_limited`.

## Phase B: Negative Controls

Priority: high after the first verified replay.

For each verified replay, add at least two controls:

1. wrong fork block, expecting the exploit assertion to fail;
2. disabled or perturbed attack parameter, expecting no profit or no victim loss.

These controls are necessary because several existing replay tests use Foundry cheatcodes such as
`deal` and `prank`. The paper needs to show that replay success depends on historically relevant
state and exploit mechanics, not merely on locally fabricated balances.

## Phase C: New Replay Implementations

Priority order:

1. Fei Protocol / Rari Capital: reentrancy, high loss, complements Lendf.Me.
2. Beanstalk: flash-loan governance, high loss, distinct mechanism.
3. UwU Lend: oracle manipulation, useful contrast with BonqDAO.
4. Cream Finance: flash-loan lending exploit, fallback if Beanstalk is too complex.

Each new replay should include:

- incident card with tx hash, block number, target contracts, and attacker addresses;
- dedicated `test/replay/<Incident>Replay.t.sol`;
- one success assertion tied to profit or victim-state loss;
- at least one negative control after positive replay is verified.

## Phase D: ARA Integration

ARA should consume only structured outputs:

- `data/processed/replay_results.csv`
- `data/processed/replay_blocker_matrix.csv`
- `data/processed/scanner_findings_latest.json`
- `reports/27_replay_verification_results.md`

The paper should count a replay as verified only when `verified=true`. Any `no_rpc`,
`archive_state_unavailable`, `no_test`, or failed assertion must remain a blocker, not a replay
success.

## Expected Paper Impact

The current ARA paper is around a 5/10 because it has no verified replay and relies heavily on
internally adjudicated grouping. A credible next target is:

- 6/10: archive-RPC attempts documented, full blocker matrix, all baseline grouping tables included;
- 7/10: at least one verified replay plus negative controls;
- 8/10: three or more verified replays spanning at least two exploit families, with stratified
  blockers and reproducible scripts.

