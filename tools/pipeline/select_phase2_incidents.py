#!/usr/bin/env python3
"""Select high-priority DeFi incidents for Phase-2 fork replay."""

from __future__ import annotations

import argparse
from collections import defaultdict
from pathlib import Path

from common import read_csv, write_csv

FAMILY_WEIGHT = {
    "oracle_manipulation": 5,
    "flash_loan": 5,
    "reentrancy": 5,
    "access_control": 4,
    "logic_bug": 4,
    "contract_bug": 4,
    "bridge_message": 3,
    "governance": 3,
    "other": 1,
}

EXCLUDED_FAMILIES = {
    "account_compromise",
    "social_engineering",
    "supply_chain",
}


def parse_float(value: str) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        return 0.0


def should_include(row: dict, min_loss: float) -> bool:
    if (row.get("is_defi", "") or "").lower() != "true":
        return False

    family = (row.get("attack_family", "") or "").strip()
    if family in EXCLUDED_FAMILIES:
        return False

    method = (row.get("attack_method_raw", "") or "").lower()
    description = (row.get("description", "") or "").lower()
    loss = parse_float(row.get("loss_usd", ""))
    technical_signal = any(
        kw in f"{method} {description}"
        for kw in [
            "oracle",
            "reentrancy",
            "flash loan",
            "contract",
            "logic",
            "price manipulation",
            "cross-chain",
            "bridge",
            "governance",
        ]
    )
    return loss >= min_loss or technical_signal


def score_row(row: dict) -> float:
    family = (row.get("attack_family", "") or "").strip()
    weight = FAMILY_WEIGHT.get(family, 1)
    loss = parse_float(row.get("loss_usd", ""))
    has_reference = 1 if (row.get("reference_url", "") or "").startswith("http") else 0
    return (weight * 1_000_000_000.0) + loss + (has_reference * 100_000.0)


def select_rows(rows: list[dict], top_n: int, min_loss: float, max_per_family: int) -> list[dict]:
    candidates = [row for row in rows if should_include(row, min_loss=min_loss)]
    candidates.sort(key=score_row, reverse=True)

    selected: list[dict] = []
    family_count: dict[str, int] = defaultdict(int)
    for row in candidates:
        family = (row.get("attack_family", "") or "other").strip()
        if family_count[family] >= max_per_family:
            continue
        selected.append(row)
        family_count[family] += 1
        if len(selected) >= top_n:
            break
    return selected


def to_markdown(rows: list[dict], min_loss: float, max_per_family: int) -> str:
    lines: list[str] = []
    lines.append("# Report 19: Phase-2 Batch-1 Incident Shortlist")
    lines.append("")
    lines.append("## Selection Rules")
    lines.append("")
    lines.append(f"- Include only DeFi-labeled incidents (`is_defi=true`)")
    lines.append(f"- Exclude operational families: `{', '.join(sorted(EXCLUDED_FAMILIES))}`")
    lines.append(f"- Minimum parsed loss threshold: `${min_loss:,.0f}` (technical-signal rows can still be included)")
    lines.append(f"- Family diversification cap: `{max_per_family}` rows per attack family")
    lines.append("")
    lines.append("## Selected Incidents")
    lines.append("")
    lines.append("| Rank | Date | Target | Family | Loss USD | Reference | Incident ID |")
    lines.append("|---:|---|---|---|---:|---|---|")
    for idx, row in enumerate(rows, start=1):
        loss = parse_float(row.get("loss_usd", ""))
        ref = row.get("reference_url", "") or "-"
        lines.append(
            f"| {idx} | {row.get('event_date', '')} | {row.get('target', '')} | "
            f"{row.get('attack_family', '')} | {loss:,.2f} | {ref} | `{row.get('incident_id', '')}` |"
        )
    lines.append("")
    lines.append("## Next Action")
    lines.append("")
    lines.append("Run card generation for this shortlist and start Foundry fork replay implementation.")
    lines.append("")
    return "\n".join(lines)


def main() -> None:
    parser = argparse.ArgumentParser(description="Select high-priority incidents for Phase-2")
    parser.add_argument(
        "--incidents-csv",
        default="data/processed/incidents_anchored_latest.csv",
        help="Input anchored incidents csv",
    )
    parser.add_argument(
        "--output-csv",
        default="data/processed/phase2_batch1_incidents.csv",
        help="Selected incidents output csv",
    )
    parser.add_argument(
        "--output-md",
        default="reports/19_phase2_batch1_incident_shortlist.md",
        help="Selection report markdown output",
    )
    parser.add_argument("--top-n", type=int, default=12, help="Number of incidents to select")
    parser.add_argument("--min-loss", type=float, default=100000.0, help="Minimum parsed loss threshold")
    parser.add_argument("--max-per-family", type=int, default=3, help="Max selected rows per family")
    args = parser.parse_args()

    rows = read_csv(Path(args.incidents_csv))
    selected = select_rows(
        rows=rows,
        top_n=args.top_n,
        min_loss=args.min_loss,
        max_per_family=args.max_per_family,
    )

    out_csv = Path(args.output_csv)
    out_csv.parent.mkdir(parents=True, exist_ok=True)
    fieldnames = list(rows[0].keys()) if rows else []
    write_csv(out_csv, selected, fieldnames)

    out_md = Path(args.output_md)
    out_md.parent.mkdir(parents=True, exist_ok=True)
    out_md.write_text(
        to_markdown(
            rows=selected,
            min_loss=args.min_loss,
            max_per_family=args.max_per_family,
        ),
        encoding="utf-8",
    )

    print(f"[phase2] selected {len(selected)} incidents")
    print(f"[phase2] csv: {args.output_csv}")
    print(f"[phase2] report: {args.output_md}")


if __name__ == "__main__":
    main()
