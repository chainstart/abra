# Blockchain DeFi Security Audit Project

Deep security audit of 5 high-TVL DeFi protocols with custom static analysis tooling.

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
blockchain-security/
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
