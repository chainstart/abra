#!/usr/bin/env python3
"""Generate per-incident markdown cards for replay and lab planning."""

from __future__ import annotations

import argparse
import re
from pathlib import Path

from common import read_csv


def to_filename(event_date: str, target: str, incident_id: str) -> str:
    slug = re.sub(r"[^a-z0-9]+", "-", target.lower()).strip("-")
    slug = slug[:48] if slug else "unknown-target"
    return f"{event_date}_{slug}_{incident_id[:8]}.md"


def build_card(row: dict) -> str:
    loss_usd = row.get("loss_usd", "")
    loss_usd_raw = row.get("loss_usd_raw", "")
    loss_display = f"${loss_usd}" if loss_usd else loss_usd_raw or "-"
    reference = row.get("reference_url", "") or "(missing)"

    lines = []
    lines.append(f"# Incident Card - {row.get('target', 'Unknown')}")
    lines.append("")
    lines.append("## Metadata")
    lines.append("")
    lines.append(f"- Incident ID: `{row.get('incident_id', '')}`")
    lines.append(f"- Date: `{row.get('event_date', '')}`")
    lines.append(f"- DeFi Label: `{row.get('is_defi', '')}`")
    lines.append(f"- Attack Family: `{row.get('attack_family', '')}`")
    lines.append(f"- Attack Method (raw): `{row.get('attack_method_raw', '')}`")
    lines.append(f"- Estimated Loss: `{loss_display}`")
    lines.append(f"- Protocol Slug Guess: `{row.get('protocol_slug_guess', '')}`")
    lines.append(f"- Reference URL: {reference}")
    lines.append("")
    lines.append("## Source Description")
    lines.append("")
    lines.append(row.get("description", "").strip())
    lines.append("")
    lines.append("## Replay Plan")
    lines.append("")
    lines.append("1. Root Cause Hypothesis:")
    lines.append("2. Attack Path (step-by-step):")
    lines.append("3. Required On-chain Preconditions:")
    lines.append("4. Needed Contracts/Addresses:")
    lines.append("5. Fork Block Number:")
    lines.append("6. Success Criteria / Assertions:")
    lines.append("")
    lines.append("## Sandbox Experiment Notes")
    lines.append("")
    lines.append("- PoC status: `todo`")
    lines.append("- Repro command: `todo`")
    lines.append("- Defense patch idea: `todo`")
    lines.append("- Residual risk after patch: `todo`")
    lines.append("")
    return "\n".join(lines)


def main() -> None:
    parser = argparse.ArgumentParser(description="Generate incident replay cards in markdown")
    parser.add_argument(
        "--incidents-csv",
        default="data/processed/incidents_anchored_latest.csv",
        help="Input anchored incidents CSV",
    )
    parser.add_argument(
        "--output-dir",
        default="reports/events",
        help="Output directory for incident cards",
    )
    parser.add_argument(
        "--top-n",
        type=int,
        default=50,
        help="Generate cards for top N DeFi incidents by parsed loss",
    )
    parser.add_argument(
        "--selected-incidents-csv",
        default="",
        help="Optional CSV containing selected incident rows (uses incident_id column)",
    )
    args = parser.parse_args()

    rows = read_csv(Path(args.incidents_csv))
    selected_ids: set[str] = set()
    if args.selected_incidents_csv:
        selected_rows = read_csv(Path(args.selected_incidents_csv))
        selected_ids = {r.get("incident_id", "") for r in selected_rows if r.get("incident_id", "")}

    defi_rows = [r for r in rows if (r.get("is_defi", "") or "").lower() == "true"]
    if selected_ids:
        defi_rows = [r for r in defi_rows if r.get("incident_id", "") in selected_ids]

    def parse_float(v: str) -> float:
        try:
            return float(v)
        except (TypeError, ValueError):
            return 0.0

    defi_rows.sort(key=lambda r: parse_float(r.get("loss_usd", "")), reverse=True)
    selected = defi_rows[: args.top_n]

    out_dir = Path(args.output_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    for row in selected:
        filename = to_filename(
            event_date=row.get("event_date", "unknown-date"),
            target=row.get("target", "unknown-target"),
            incident_id=row.get("incident_id", "unknown-id"),
        )
        (out_dir / filename).write_text(build_card(row), encoding="utf-8")

    print(f"[cards] generated {len(selected)} cards into {args.output_dir}")


if __name__ == "__main__":
    main()
