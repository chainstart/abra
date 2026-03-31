# Incident Card - BonqDAO & AllianceBlock

## Metadata

- Incident ID: `7493b5601979d4b397c6a253dcaecdc0d294925f`
- Date: `2023-02-02`
- DeFi Label: `true`
- Attack Family: `oracle_manipulation`
- Attack Method (raw): `Price Manipulation`
- Estimated Loss: `$120000000.00`
- Protocol Slug Guess: `bonqdao`
- Reference URL: https://www.theblock.co/post/207799/bonqdao-exploited-for-88-million-allianceblock-tokens-stolen-during-the-exploit

## Source Description

Non-custodial lending platform BonqDAO and crypto infrastructure platform AllianceBlock were hacked due to a bug in BonqDAO's smart contracts, resulting in losses of approximately $120 million. Among them, hackers removed approximately 114 million WALBT ($11 million), AllianceBlock’s wrapped native token, and 98 million BEUR tokens ($108 million) from a BonqDAO vault. According to the analysis of SlowMist, the root cause of the attack is that the attacker uses the oracle machine to quote the required collateral, which is much lower than the profit obtained by the attack, thereby manipulating the market and liquidating other users by maliciously submitting wrong prices. In addition, AllianceBlock stated that the incident has nothing to do with the BonqDAO vault, no smart contracts were breached, and both teams are working on eliminating liquidity to mitigate hackers converting stolen tokens into other assets.

## Replay Plan

1. Root Cause Hypothesis: `TellorFlex` accepted an attacker-controlled wALBT price update cheaply enough that the collateral valuation could be pushed far above reality.
2. Attack Path (step-by-step): `stake/report manipulated Tellor price -> create trove -> deposit 0.1 wALBT -> borrow 100M BEUR -> later crash price and liquidate other wALBT troves`
3. Required On-chain Preconditions: Polygon fork near `38792977`, Tellor staking/reporting path operational, Bonq trove factory active.
4. Needed Contracts/Addresses: `TellorFlex 0x8f55D884...4d5B`, `BonqFactory 0x3bB7fFD0...68B3`, `TRB 0xE3322702...e5f1`, `wALBT 0x35b2ECE5...0632`, `BEUR 0x338Eb4d3...4B81`
5. Fork Block Number: `38792977`
6. Success Criteria / Assertions: tx1 replay can borrow roughly `100M BEUR` after the malicious price update.

## Sandbox Experiment Notes

- PoC status: `tx1 scaffolded in test/replay/BonqDAOReplay.t.sol`
- Repro command: `POLYGON_RPC_URL=... forge test --match-path test/replay/BonqDAOReplay.t.sol -vv`
- Defense patch idea: `use post-dispute-window oracle values and reject instant low-cost self-reported price moves for critical collateral`
- Residual risk after patch: `liquidation-side edge cases and cross-market oracle dependencies still need coverage`
