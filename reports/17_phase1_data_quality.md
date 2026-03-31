# Phase-1 Data Quality Report

- Generated at (UTC): 2026-03-31T04:30:49Z
- Incidents source: `data/processed/incidents_normalized_latest.csv`
- Protocols source: `data/processed/protocols_normalized_latest.csv`

## Coverage Summary

| Metric | Value |
|---|---:|
| Incident rows | 2036 |
| Unique incident IDs | 2035 |
| Duplicate rows | 1 (0.05%) |
| DeFi-labeled incidents | 1378 (67.68%) |
| Protocol rows | 7250 |
| Loss parsing coverage | 1185/1464 (80.94%) |

## Missingness

| Field | Missing Rows | Missing Rate |
|---|---:|---:|
| event_date | 0 | 0.00% |
| target | 0 | 0.00% |
| attack_method_raw | 0 | 0.00% |
| reference_url | 6 | 0.29% |
| description | 0 | 0.00% |

## Top Attack Families

| Rank | Attack Family | Count |
|---:|---|---:|
| 1 | other | 864 |
| 2 | contract_bug | 262 |
| 3 | account_compromise | 253 |
| 4 | social_engineering | 161 |
| 5 | flash_loan | 154 |
| 6 | bridge_message | 109 |
| 7 | oracle_manipulation | 89 |
| 8 | logic_bug | 47 |
| 9 | reentrancy | 39 |
| 10 | access_control | 29 |

## Top Raw Attack Methods

| Rank | Method | Count |
|---:|---|---:|
| 1 | Contract Vulnerability | 347 |
| 2 | Rug Pull | 265 |
| 3 | Account Compromise | 238 |
| 4 | Unknown | 122 |
| 5 | Flash Loan Attack | 88 |
| 6 | Private Key Leakage | 80 |
| 7 | Scam | 48 |
| 8 | Price Manipulation | 46 |
| 9 | Wallet Stolen | 45 |
| 10 | Flash loan attack | 45 |
