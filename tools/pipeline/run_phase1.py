#!/usr/bin/env python3
"""Run Phase 1: collect candidates -> normalize -> enrich evidence -> quality report."""

from __future__ import annotations

import argparse
import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from abra.runtime_bootstrap import ensure_repo_runtime

DEFAULT_PHASE1_MAX_DEFIHACKLABS = 40


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
    parser.add_argument(
        "--max-defihacklabs",
        type=int,
        default=DEFAULT_PHASE1_MAX_DEFIHACKLABS,
        help="Max DeFiHackLabs replay fixtures to ingest",
    )
    parser.add_argument("--save-html", action="store_true", help="Persist raw SlowMist HTML pages")
    args = parser.parse_args()
    ensure_repo_runtime(REPO_ROOT, required_modules=("requests", "bs4"))

    repo_root = REPO_ROOT
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

    direct_evidence_cmd = [
        py,
        str(scripts_dir / "direct_evidence_collector.py"),
        "--output-dir",
        "data/raw/direct_evidence",
        "--max-defihacklabs",
        str(args.max_defihacklabs),
    ]

    normalize_cmd = [
        py,
        str(scripts_dir / "normalize.py"),
        "--slowmist-csv",
        "data/raw/slowmist/slowmist_events_latest.csv",
        "--defillama-protocols-csv",
        "data/raw/defillama/defillama_protocols_slim_latest.csv",
        "--defillama-hacks-csv",
        "data/raw/defillama/defillama_hacks_latest.csv",
        "--direct-evidence-csv",
        "data/raw/direct_evidence/direct_evidence_latest.csv",
        "--output-dir",
        "data/processed",
    ]

    evidence_cmd = [
        py,
        "-m",
        "abra",
        "evidence",
        "produce",
        "--incidents-csv",
        "data/processed/incidents_normalized_latest.csv",
        "--out-dir",
        "data/processed",
        "--json",
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
    run_cmd(direct_evidence_cmd, cwd=repo_root)
    run_cmd(normalize_cmd, cwd=repo_root)
    run_cmd(evidence_cmd, cwd=repo_root)
    run_cmd(dq_cmd, cwd=repo_root)
    print("[phase1] pipeline completed.")


if __name__ == "__main__":
    main()
