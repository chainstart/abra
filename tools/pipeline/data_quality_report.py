#!/usr/bin/env python3
"""Generate a lightweight data-quality report for normalized datasets."""

from __future__ import annotations

import argparse
from collections import Counter
from pathlib import Path

from common import now_utc_iso, read_csv


def safe_pct(numerator: int, denominator: int) -> str:
    if denominator <= 0:
        return "0.00%"
    return f"{(numerator / denominator) * 100:.2f}%"


def render_report(incidents: list[dict], protocols: list[dict], incidents_csv: str, protocols_csv: str) -> str:
    total = len(incidents)
    unique_ids = len({row.get("incident_id", "") for row in incidents if row.get("incident_id", "")})
    duplicate_count = max(total - unique_ids, 0)

    missing_fields = ["event_date", "target", "attack_method_raw", "reference_url", "description"]
    missing_stats = {}
    for field in missing_fields:
        missing = sum(1 for row in incidents if not (row.get(field, "") or "").strip())
        missing_stats[field] = (missing, safe_pct(missing, total))

    loss_candidates = 0
    loss_parsed = 0
    for row in incidents:
        raw_loss = (row.get("loss_usd_raw", "") or "").strip()
        if any(ch.isdigit() for ch in raw_loss):
            loss_candidates += 1
            if (row.get("loss_usd", "") or "").strip():
                loss_parsed += 1

    defi_count = sum(1 for row in incidents if (row.get("is_defi", "") or "").lower() == "true")
    source_breakdown = Counter((row.get("category_filter", "") or "unknown") for row in incidents).most_common(10)
    direct_tx_count = sum(1 for row in incidents if (row.get("seed_transaction_hash", "") or "").strip())
    fork_block_count = sum(1 for row in incidents if (row.get("fork_block", "") or "").strip())
    attack_family_top = Counter((row.get("attack_family", "") or "other") for row in incidents).most_common(10)
    attack_method_top = Counter((row.get("attack_method_raw", "") or "unknown") for row in incidents).most_common(10)

    lines: list[str] = []
    lines.append("# Phase-1 Data Quality Report")
    lines.append("")
    lines.append(f"- Generated at (UTC): {now_utc_iso()}")
    lines.append(f"- Incidents source: `{incidents_csv}`")
    lines.append(f"- Protocols source: `{protocols_csv}`")
    lines.append("")
    lines.append("## Coverage Summary")
    lines.append("")
    lines.append("| Metric | Value |")
    lines.append("|---|---:|")
    lines.append(f"| Incident rows | {total} |")
    lines.append(f"| Unique incident IDs | {unique_ids} |")
    lines.append(f"| Duplicate rows | {duplicate_count} ({safe_pct(duplicate_count, total)}) |")
    lines.append(f"| DeFi-labeled incidents | {defi_count} ({safe_pct(defi_count, total)}) |")
    lines.append(f"| Seed transaction hash coverage | {direct_tx_count} ({safe_pct(direct_tx_count, total)}) |")
    lines.append(f"| Fork block coverage | {fork_block_count} ({safe_pct(fork_block_count, total)}) |")
    lines.append(f"| Protocol rows | {len(protocols)} |")
    lines.append(
        f"| Loss parsing coverage | {loss_parsed}/{loss_candidates} ({safe_pct(loss_parsed, loss_candidates)}) |"
    )
    lines.append("")
    lines.append("## Candidate Source Breakdown")
    lines.append("")
    lines.append("| Rank | Candidate Source | Count |")
    lines.append("|---:|---|---:|")
    for idx, (name, count) in enumerate(source_breakdown, start=1):
        lines.append(f"| {idx} | {name} | {count} |")
    lines.append("")
    lines.append("## Missingness")
    lines.append("")
    lines.append("| Field | Missing Rows | Missing Rate |")
    lines.append("|---|---:|---:|")
    for field in missing_fields:
        count, rate = missing_stats[field]
        lines.append(f"| {field} | {count} | {rate} |")
    lines.append("")
    lines.append("## Top Attack Families")
    lines.append("")
    lines.append("| Rank | Attack Family | Count |")
    lines.append("|---:|---|---:|")
    for idx, (name, count) in enumerate(attack_family_top, start=1):
        lines.append(f"| {idx} | {name} | {count} |")
    lines.append("")
    lines.append("## Top Raw Attack Methods")
    lines.append("")
    lines.append("| Rank | Method | Count |")
    lines.append("|---:|---|---:|")
    for idx, (name, count) in enumerate(attack_method_top, start=1):
        lines.append(f"| {idx} | {name} | {count} |")
    lines.append("")

    return "\n".join(lines)


def main() -> None:
    parser = argparse.ArgumentParser(description="Generate quality report for normalized data")
    parser.add_argument(
        "--incidents-csv",
        default="data/processed/incidents_normalized_latest.csv",
        help="Normalized incidents CSV",
    )
    parser.add_argument(
        "--protocols-csv",
        default="data/processed/protocols_normalized_latest.csv",
        help="Normalized protocols CSV",
    )
    parser.add_argument(
        "--output-md",
        default="reports/17_phase1_data_quality.md",
        help="Output markdown report path",
    )
    args = parser.parse_args()

    incidents = read_csv(Path(args.incidents_csv))
    protocols = read_csv(Path(args.protocols_csv))
    report = render_report(
        incidents=incidents,
        protocols=protocols,
        incidents_csv=args.incidents_csv,
        protocols_csv=args.protocols_csv,
    )
    out_path = Path(args.output_md)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(report, encoding="utf-8")
    print(f"[dq] wrote report: {args.output_md}")


if __name__ == "__main__":
    main()
