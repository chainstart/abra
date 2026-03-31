# Incident Card - Euler Finance

## Metadata

- Incident ID: `9c8e1b8431b3cb32761e7d0cabce8b29125d3bd4`
- Date: `2023-03-13`
- DeFi Label: `true`
- Attack Family: `flash_loan`
- Attack Method (raw): `Flash Loan Attack`
- Estimated Loss: `$197000000.00`
- Protocol Slug Guess: ``
- Reference URL: https://twitter.com/SlowMist_Team/status/1635288963580825606

## Source Description

The DeFi lending protocol Euler Finance was attacked, and the attackers made a profit of about 197 million US dollars. The attacker used flashloans to deposit funds and then leveraged them twice to trigger the liquidation logic, donating the funds to the reserve address and conducting a self-liquidation to collect any remaining assets. Two key factors contributed to the success of the attack: 1. Funds were donated to the reserved address without being subjected to a liquidity check. This created a mechanism that could directly trigger soft liquidation. 2. When the soft liquidation logic was triggered by high leverage, the yield value increased, enabling the liquidator to obtain most of the collateral funds from the liquidated user's account by transferring only a portion of the liabilities to themselves. Given that the value of the collateral funds exceeded the value of the liabilities (which were only partially transferred due to the soft liquidation), the liquidator was able to successfully pass their health factor check (checkLiquidity) and withdraw the obtained funds. On April 4th, Euler Labs tweeted that after a successful negotiation, the attacker has returned all the funds stolen from the agreement on March 13th, because the attacker has returned the funds, the $1 million reward campaign launched by the foundation No new information will be accepted.

## Replay Plan

1. Root Cause Hypothesis: `donateToReserves()` reduced collateral health without a liquidity check, allowing the account to become liquidatable after repeated leverage.
2. Attack Path (step-by-step): `flash loan 30M DAI -> deposit 20M -> mint 200M dDAI/eDAI -> repay 10M -> mint again -> donate 100M eDAI to reserves -> liquidate violator -> withdraw DAI -> repay flash loan`
3. Required On-chain Preconditions: Euler DAI market and Aave V2 liquidity must match the exploit-era state near block `16817995`.
4. Needed Contracts/Addresses: `AaveV2 0x7d2768...c7A9`, `Euler core 0x271828...25d3`, `Euler entry 0xf43ce1...5b34`, `eDAI 0xe025E3...D9DC`, `dDAI 0x6085Bc...4686`
5. Fork Block Number: `16817995`
6. Success Criteria / Assertions: attack contract balance after flash-loan repayment remains positive and exceeds a conservative floor; liquidation path succeeds.

## Sandbox Experiment Notes

- PoC status: `scaffolded in test/replay/EulerFinanceReplay.t.sol`
- Repro command: `ETH_RPC_URL=... forge test --match-path test/replay/EulerFinanceReplay.t.sol -vv`
- Defense patch idea: `enforce liquidity checks on reserve-donation paths and cap liquidation yield under soft-liquidation transitions`
- Residual risk after patch: `other leverage-sensitive liquidation edge cases still require invariant testing`
