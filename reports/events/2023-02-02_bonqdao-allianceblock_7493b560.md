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
