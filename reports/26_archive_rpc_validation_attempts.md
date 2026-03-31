# Report 26: Archive RPC Validation Attempts

**Date:** 2026-04-01

## Objective

Attempt end-to-end fork validation for existing replay candidates using publicly reachable RPC endpoints before requiring a dedicated paid archive provider.

## Targets

1. `test/replay/LendfMeReplay.t.sol`
2. `test/replay/BonqDAOReplay.t.sol`

## Endpoints tested

### Ethereum

1. `https://eth.llamarpc.com`
2. `https://ethereum-rpc.publicnode.com`
3. `https://eth-mainnet.public.blastapi.io`

### Polygon

1. `https://polygon-bor-rpc.publicnode.com`

## Results

### Lendf.Me

All tested public Ethereum endpoints failed to create a usable historical fork for block `9899725`.

Observed failure modes:

1. `fork id not initialized`
2. historical state unavailable for the required pre-state

Interpretation:

- The replay test itself is structurally runnable.
- The blocker is not Foundry logic; it is lack of guaranteed archive-state availability from free public endpoints.

### BonqDAO

The tested public Polygon endpoint failed with:

- `historical state ... is not available`

Interpretation:

- The replay requires historical Polygon state at block `38792977`.
- The tested public endpoint does not provide the required archive depth for deterministic fork validation.

## Practical conclusion

The repository now has three replay candidates with implemented exploit logic, but archive validation for historical incidents still requires dedicated archive-capable RPC providers. Public unauthenticated endpoints are insufficient for the current replay blocks.

## Recommended provider requirements

1. Ethereum archive access with reliable state availability for blocks around `9899725` and `16817995`
2. Polygon archive access with reliable state availability for block `38792977`
3. Stable response behavior under Foundry fork requests
4. No gateway policy that silently disables fork creation or historical state access
