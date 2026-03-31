#!/usr/bin/env python3
"""Run the full Phase-1 pipeline: collect -> normalize -> quality report."""

from __future__ import annotations

import argparse
import subprocess
import sys
from pathlib import Path


def run_cmd(cmd: list[str], cwd: Path) -> None:
    """Run command and fail fast on non-zero exit."""
    print(f"[phase1] running: {' '.join(cmd)}", flush=True)
    subprocess.run(cmd, cwd=str(cwd), check=True)


def main() -> None:
    parser = argparse.ArgumentParser(description="Execute Phase-1 data foundation pipeline")
    parser.add_argument("--start-page", type=int, default=1, help="SlowMist start page")
    parser.add_argument("--end-page", type=int, default=8, help="SlowMist end page")
    parser.add_argument("--category", default="", help="SlowMist category filter")
    parser.add_argument("--delay-seconds", type=float, default=0.15, help="SlowMist request delay")
    parser.add_argument("--top-protocols", type=int, default=400, help="Top N protocols from DefiLlama")
    parser.add_argument("--save-html", action="store_true", help="Persist raw SlowMist HTML pages")
    args = parser.parse_args()

    repo_root = Path(__file__).resolve().parents[2]
    py = sys.executable
    scripts_dir = Path(__file__).resolve().parent

    slowmist_cmd = [
        py,
        str(scripts_dir / "slowmist_collector.py"),
        "--start-page",
        str(args.start_page),
        "--end-page",
        str(args.end_page),
        "--category",
        args.category,
        "--delay-seconds",
        str(args.delay_seconds),
        "--output-dir",
        "data/raw/slowmist",
    ]
    if args.save_html:
        slowmist_cmd.append("--save-html")

    defillama_cmd = [
        py,
        str(scripts_dir / "defillama_collector.py"),
        "--top-n",
        str(args.top_protocols),
        "--output-dir",
        "data/raw/defillama",
    ]

    normalize_cmd = [
        py,
        str(scripts_dir / "normalize.py"),
        "--slowmist-csv",
        "data/raw/slowmist/slowmist_events_latest.csv",
        "--defillama-protocols-csv",
        "data/raw/defillama/defillama_protocols_slim_latest.csv",
        "--output-dir",
        "data/processed",
    ]

    dq_cmd = [
        py,
        str(scripts_dir / "data_quality_report.py"),
        "--incidents-csv",
        "data/processed/incidents_normalized_latest.csv",
        "--protocols-csv",
        "data/processed/protocols_normalized_latest.csv",
        "--output-md",
        "reports/17_phase1_data_quality.md",
    ]

    run_cmd(slowmist_cmd, cwd=repo_root)
    run_cmd(defillama_cmd, cwd=repo_root)
    run_cmd(normalize_cmd, cwd=repo_root)
    run_cmd(dq_cmd, cwd=repo_root)
    print("[phase1] pipeline completed.")


if __name__ == "__main__":
    main()
