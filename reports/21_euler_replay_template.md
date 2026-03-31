# Report 21: Euler Finance Replay Template

**Status:** implemented as replay candidate  
**Test file:** `test/replay/EulerFinanceReplay.t.sol`

## Fixed assumptions

- Chain: Ethereum mainnet
- Initial fork block: `16822500`
- Replay objective: reconstruct the flash-loan-assisted liquidation path that produced the March 13, 2023 loss
- Flash-loan source: `Aave V2` at `0x7d2768dE32b0b80b7a3454c06BdAc94A69DDc7A9`
- Euler core: `0x27182842E098f60e3D576794A5bFFb0777E025d3`
- Euler entrypoint: `0xf43ce1d09050BAfd6980dD43Cde2aB9F18C85b34`
- DAI market tokens:
  - `eDAI`: `0xe025E3ca2bE02316033184551D4d3Aa22024D9DC`
  - `dDAI`: `0x6085Bc95F506c326DCBCD7A6dd6c79FBc18d4686`

## Implementation checklist

1. Replay 30M DAI flash loan from Aave V2.
2. Move the flash-loaned DAI into a dedicated violator contract.
3. Reproduce the `deposit -> mint -> repay -> mint -> donateToReserves` path.
4. Use a separate liquidator contract to call `checkLiquidation` and `liquidate`.
5. Withdraw DAI via `eDAI.withdraw(...)`.
6. Assert post-exploit balance remains above flash-loan repayment.

## Current limitation

The exploit logic is encoded and compiles. It still requires a valid `ETH_RPC_URL` to run the fork test end-to-end in this environment.
