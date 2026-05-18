# ABRA: Automated Blockchain Research Agents

ABRA is the ARA ecosystem's blockchain security domain lab. It preserves the
existing static analysis, DeFi incident pipeline, Foundry replay, reports,
findings, and paper artifacts while adding a small manifest and CLI surface for
harness-driven inspection.

The historical repository name `blockchain-security` remains supported through
`research_lab.yaml` legacy aliases.

## ABRA Harness Entry Points

From the repository root:

```bash
# Inspect the ARA-compatible lab manifest.
python3 -m abra labs inspect --json

# Run side-effect-free manifest, tool, report, and findings smoke checks.
python3 -m abra labs smoke --json

# List the preserved blockchain security domain tools exposed to ABRA.
python3 -m abra tools list --json
```

ARA discovers this lab through `research_lab.yaml`, which declares:

- `lab_id: abra`
- `bundles.produced: abra_result_bundle`
- safe command prefixes for `python3 -m abra`, existing local tools, and bounded Foundry replay tests
- deny patterns for destructive shell operations, private-key use, broadcast transactions, and direct chain writes
- artifact globs that retain reports, event cards, findings, replay outputs, and generated bundles

## Protocols Audited

| Protocol | TVL | Type | Findings | Report |
|----------|-----|------|----------|--------|
| Lido | ~$38B | Liquid Staking | 17 (2C, 3H, 7M, 5L) | [01_lido_audit.md](reports/01_lido_audit.md) |
| Aave V3 | ~$38B | Lending | 13 (1C, 3H, 6M, 3L) | [02_aave_audit.md](reports/02_aave_audit.md) |
| Uniswap V3/V4 | ~$6B | DEX (AMM) | 26 (2C, 4H, 12M, 8L) | [03_uniswap_audit.md](reports/03_uniswap_audit.md) |
| Curve | ~$2.7B | Stablecoin DEX | 13 (0C, 3H, 7M, 3L) | [04_curve_audit.md](reports/04_curve_audit.md) |
| Compound | ~$2.1B | Lending | 18 (0C, 3H, 10M, 5L) | [05_compound_audit.md](reports/05_compound_audit.md) |

**Total:** 87 unique findings across 15 contracts (~7,700 LOC)

## Project Structure

```
abra/
├── README.md                          # This file
├── reports/                           # Audit reports
│   ├── 00_defi_tvl_landscape.md       # DeFi TVL landscape research
│   ├── 01_lido_audit.md               # Lido security audit
│   ├── 02_aave_audit.md               # Aave V3 security audit
│   ├── 03_uniswap_audit.md            # Uniswap V3/V4 security audit
│   ├── 04_curve_audit.md              # Curve security audit
│   └── 05_compound_audit.md           # Compound security audit
├── tools/                             # Static analysis toolkit
│   ├── analyzers/                     # Analysis modules
│   │   ├── base.py                    # Base classes (Finding, Severity, BaseAnalyzer)
│   │   ├── access_control.py          # Access control vulnerability detection
│   │   ├── reentrancy.py              # Reentrancy pattern detection
│   │   ├── oracle_dependency.py       # Oracle risk analysis
│   │   ├── arithmetic.py              # Arithmetic safety checks
│   │   └── upgrade_safety.py          # Proxy/upgrade risk detection
│   ├── scanner.py                     # Unified scanning CLI
│   ├── report_generator.py            # Markdown report generator
│   └── requirements.txt               # Python dependencies
├── contracts/                         # Protocol contract sources
│   ├── lido/                          # Lido.sol, WstETH.sol, LidoOracle.sol
│   ├── aave/                          # Pool.sol, AToken.sol, FlashLoanLogic.sol, ...
│   ├── uniswap/                       # UniswapV3Pool.sol, V4PoolManager.sol, TickMath.sol
│   ├── curve/                         # StableSwap.sol, VotingEscrow.sol
│   └── compound/                      # CToken.sol, Comptroller.sol, GovernorBravo.sol
└── findings/
    └── summary.md                     # Cross-protocol findings summary
```

## Quick Start

### Run the Scanner

```bash
cd tools/

# Scan all contracts
python3 scanner.py --target ../contracts/ --output console

# Scan a specific protocol
python3 scanner.py --target ../contracts/lido/ --output markdown --output-file ../findings/lido_scan.md

# Run specific analyzers with severity filter
python3 scanner.py --target ../contracts/aave/ --analyzers reentrancy,oracle-dependency --severity High

# Output JSON for programmatic use
python3 scanner.py --target ../contracts/ --output json --output-file findings.json
```

### Generate Reports

```bash
# Generate a formatted audit report from scan results
python3 scanner.py --target ../contracts/lido/ --output json --output-file /tmp/scan.json
python3 report_generator.py --input /tmp/scan.json --protocol-name "Lido" --output ../reports/auto_lido.md
```

### Run Phase-1 Data Pipeline

```bash
# From repository root
python3 tools/pipeline/run_phase1.py --start-page 1 --end-page 3 --top-protocols 200

# Output:
# - data/raw/slowmist/
# - data/raw/defillama/
# - data/processed/
# - reports/17_phase1_data_quality.md

# Generate top incident replay cards
python3 tools/pipeline/generate_event_cards.py --top-n 50
```

### Run Phase-2 Shortlisting And Replay Skeleton

```bash
# Select the first replay batch from normalized incidents
python3 tools/pipeline/select_phase2_incidents.py

# Generate replay cards for the selected batch
python3 tools/pipeline/generate_event_cards.py \
  --selected-incidents-csv data/processed/phase2_batch1_incidents.csv \
  --output-dir reports/events \
  --top-n 12

# Validate Foundry replay skeleton
forge test --match-path test/replay/Phase2Batch1Catalog.t.sol
forge test --match-path test/replay/EulerFinanceReplay.t.sol
```

### Run Replay Verification Matrix

Use the replay runner instead of raw `forge test` when producing paper evidence. It separates
verified replay from missing RPC, archive-state failures, and missing replay implementations.

```bash
# Public RPC endpoints can test connectivity, but may not serve old archive state.
ETH_RPC_URL=https://ethereum.publicnode.com \
POLYGON_RPC_URL=https://polygon-bor-rpc.publicnode.com \
python3 tools/replay_runner.py --timeout 300 --verbosity=-vv

# Archive-capable endpoints are required for verified historical replay.
ETH_RPC_URL=... python3 tools/replay_runner.py --only lendf-me euler-finance
POLYGON_RPC_URL=... python3 tools/replay_runner.py --only bonqdao-allianceblock
```

Outputs:

- `data/processed/replay_results.csv`
- `data/processed/replay_results.json`
- `data/processed/replay_blocker_matrix.csv`
- `reports/27_replay_verification_results.md`

## Audit Framework

Based on **OWASP Smart Contract Top 10 (2026)** with protocol-specific business logic analysis:

| # | Category | Description |
|---|----------|-------------|
| SC-01 | Reentrancy | State inconsistency from recursive calls |
| SC-02 | Access Control | Missing/incorrect authorization |
| SC-03 | Oracle Manipulation | Price feed dependency risks |
| SC-04 | Flash Loan Attacks | Flash-loan-amplified exploits |
| SC-05 | Input Validation | Parameter validation gaps |
| SC-06 | Arithmetic | Precision, overflow, rounding issues |
| SC-07 | Logic Errors | Business logic flaws |
| SC-08 | Upgrade Safety | Proxy/upgrade mechanism risks |
| SC-09 | Governance | Governance attack vectors |
| SC-10 | External Calls | Unchecked call return values |

## Analysis Tools

5 specialized analyzers with 50+ detection rules:

- **Access Control** (10 rules): Unprotected functions, tx.origin, zero-address, centralization
- **Reentrancy** (7 rules): CEI violations, cross-function, read-only, callback patterns
- **Oracle Dependency** (10 rules): Staleness, validation, fallback, L2 sequencer, TWAP
- **Arithmetic** (10 rules): Division-before-multiplication, unchecked blocks, unsafe casts, rounding
- **Upgrade Safety** (10 rules): Delegatecall, initializers, storage gaps, selfdestruct, selector clashes

## Key Findings

### Cross-Protocol Patterns

1. **First Depositor Attack** — Lido, Curve, Compound vulnerable to share/exchange rate manipulation
2. **Reentrancy** — Most prevalent category (366 raw findings); real-world precedent: Curve $62M (2023)
3. **Oracle Dependency** — Aave & Compound critically dependent on Chainlink without fallback
4. **Governance Risks** — Historical: Compound $80M COMP bug (2021), Beanstalk $182M (2022)
5. **V4 Hooks** — Uniswap V4's hook system introduces a novel, largely untested attack surface

## Dependencies

- Python 3.10+
- `rich` (colored console output)
- `jinja2` (report templates)
- `pyyaml` (configuration)

```bash
pip install -r tools/requirements.txt
```
