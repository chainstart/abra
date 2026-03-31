# Report 20: Phase-2 Fork Replay Setup

**Date:** 2026-03-31

## Delivered

1. Foundry project configuration added: `foundry.toml`
2. `forge-std` installed under `lib/forge-std`
3. Shared fork test base added: `test/helpers/BaseForkTest.t.sol`
4. Batch-1 replay catalog added: `test/replay/Phase2Batch1Catalog.t.sol`
5. Experiment workspace documented: `experiments/phase2/README.md`
6. Foundry source root isolated to `src/` so replay tests are not blocked by intentionally vulnerable audit corpus under `contracts/`

## Batch-1 focus

The current shortlist covers 12 incidents across:

- flash-loan-assisted exploits
- oracle manipulation
- reentrancy
- business-logic / contract bugs

The next implementation step is to convert the highest-value replayable incidents into dedicated Foundry fork tests. The best initial candidates are:

1. Euler Finance
2. BonqDAO & AllianceBlock
3. Fei Protocol / Rari Capital
4. UwU Lend
5. Lendf.Me

## Environment note

Fork execution requires RPC aliases or explicit URLs configured in the Foundry environment, for example:

```bash
export ETH_RPC_URL=...
export ARBITRUM_RPC_URL=...
```

And then use those aliases in concrete replay tests via `vm.createSelectFork(...)`.
