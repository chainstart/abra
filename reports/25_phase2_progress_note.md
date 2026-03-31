# Report 25: Phase-2 Progress Note

**Date:** 2026-03-31

## Completed replay candidates

1. Euler Finance
2. BonqDAO & AllianceBlock (`tx1` core borrow leg)
3. Lendf.Me

## Deferred items

### Fei Protocol / Rari Capital

Public code references found during this round did not cleanly map to the exact Fei/Rari incident path. Implementing a replay from those references would risk encoding the wrong exploit.

### UwU Lend

Public PoC references exist, but the exploit path is materially larger and depends on a multi-flash-loan, multi-pool manipulation sequence. It is better handled in a dedicated pass rather than folded into this batch hastily.

## Decision

This round prioritized correctness over quantity. Only exploits with high-confidence public paths were converted into replay candidates.

