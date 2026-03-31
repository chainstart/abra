# Report 24: Lendf.Me Replay Template

**Status:** implemented as replay candidate  
**Test file:** `test/replay/LendfMeReplay.t.sol`

## Fixed assumptions

- Chain: Ethereum mainnet
- Initial fork block: `9899725`
- Replay objective: trigger ERC777 callback reentrancy during `imBTC` supply/withdraw flow

## Core addresses

- Lendf.Me market: `0x0eEe3E3828A45f7601D5F54bF49bB01d1A9dF5ea`
- imBTC whale / seeded attacker source: `0xA9BF70A420d364e923C74448D9D817d3F2A77822`
- imBTC: `0x3212b29E33587A00FB1C83346f5dBFA69A458923`
- ERC1820 registry: `0x1820a4B7618BdE71Dce8cdc73aAB6C95905faD24`

## Replay path

1. impersonate an imBTC-rich address
2. register ERC777 sender hook in ERC1820
3. supply imBTC twice, with the second amount equal to `1`
4. trigger reentrant `withdraw(max)` from `tokensToSend`
5. assert attacker balance rises while market balance falls

## Current limitation

End-to-end fork execution still requires `ETH_RPC_URL` in the environment.

