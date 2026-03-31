# Incident Card - Fei Protocol & Rari Capital

## Metadata

- Incident ID: `046a16602f1f313ccd81ca63123fd96494d1bd5d`
- Date: `2022-04-30`
- DeFi Label: `true`
- Attack Family: `reentrancy`
- Attack Method (raw): `Reentrancy Attack`
- Estimated Loss: `$80000000.00`
- Protocol Slug Guess: `rari-capital`
- Reference URL: https://twitter.com/feiprotocol/status/1520344430242254849

## Source Description

Fei Protocol officially tweeted that it has noticed multiple exploits of Rari Capital’s Fuse pool, has identified the root cause and suspended all lending to mitigate further losses. And shout that hackers, if they can return user funds, will get a bounty of 10 million US dollars. According to previous news, Fei Protocol was attacked, and the loss exceeded 28,380 ETH, about 80.34 million US dollars. The attacker's address was 0x6162759eDAd730152F0dF8115c698a42E666157F. The Rari Capital pool was attacked due to a classic reentrancy vulnerability. Its function exitMaket has no reentrancy protection.

## Replay Plan

1. Root Cause Hypothesis:
2. Attack Path (step-by-step):
3. Required On-chain Preconditions:
4. Needed Contracts/Addresses:
5. Fork Block Number:
6. Success Criteria / Assertions:

## Sandbox Experiment Notes

- PoC status: `todo`
- Repro command: `todo`
- Defense patch idea: `todo`
- Residual risk after patch: `todo`
