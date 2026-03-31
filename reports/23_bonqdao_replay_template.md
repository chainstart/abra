# Report 23: BonqDAO Replay Template

**Status:** implemented as tx1 replay candidate  
**Test file:** `test/replay/BonqDAOReplay.t.sol`

## Fixed assumptions

- Chain: Polygon
- Initial fork block: `38792977`
- Replay scope: tx1 only
- Objective: prove that the manipulated Tellor price lets the attacker borrow roughly `100M BEUR` with only `0.1 wALBT`

## Core addresses

- TellorFlex: `0x8f55D884CAD66B79e1a131f6bCB0e66f4fD84d5B`
- Bonq factory proxy: `0x3bB7fFD08f46620beA3a9Ae7F096cF2b213768B3`
- TRB: `0xE3322702BEdaaEd36CdDAb233360B939775ae5f1`
- wALBT: `0x35b2ECE5B1eD6a7a99b83508F8ceEAB8661E0632`
- BEUR: `0x338Eb4d394a4327E5dB80d08628fa56EA2FD4B81`

## Implementation note

This replay covers the most defensible exploit core:

1. post malicious Tellor price
2. create malicious trove
3. deposit `0.1 wALBT`
4. borrow `100M BEUR`

The later liquidation leg is intentionally left for a separate follow-up test because it depends on enumerating and liquidating many troves.

## Current limitation

End-to-end fork execution still requires `POLYGON_RPC_URL` in the environment.

