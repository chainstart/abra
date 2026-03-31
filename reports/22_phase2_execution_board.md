# Report 22: Phase-2 Execution Board

**Date:** 2026-03-31

## Current status

| Incident | Family | Card | Test Scaffold | Replay Logic | Fork Run Verified |
|---|---|---|---|---|---|
| Euler Finance | flash_loan | yes | yes | yes | no |
| BonqDAO & AllianceBlock | oracle_manipulation | yes | yes | yes (tx1) | no |
| Fei Protocol & Rari Capital | reentrancy | yes | no | no | no |
| UwU Lend | oracle_manipulation | yes | no | no | no |
| Lendf.Me | reentrancy | yes | yes | yes | no |
| Beanstalk | flash_loan | yes | no | no | no |
| Cream Finance | flash_loan | yes | no | no | no |
| xToken | oracle_manipulation | yes | no | no | no |
| flash.sx | reentrancy | yes | no | no | no |
| Mirror Protocol | contract_bug | yes | no | no | no |
| Cetus | contract_bug | yes | no | no | no |
| Balancer V2 | logic_bug | yes | no | no | no |

## Blocking item

End-to-end fork execution has not been verified yet because no `ETH_RPC_URL` is configured in the current shell environment.

## Immediate next targets

1. Fei Protocol / Rari Capital
2. UwU Lend
3. Beanstalk
