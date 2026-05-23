from __future__ import annotations

import csv
import json
import subprocess
import sys
from pathlib import Path

from abra.replay_cohort import build_replay_cohort


def _write_csv(path: Path, rows: list[dict[str, object]]) -> None:
    fieldnames = [
        "incident_id",
        "event_date",
        "target",
        "protocol_slug_guess",
        "is_defi",
        "attack_method_raw",
        "attack_family",
        "loss_usd_raw",
        "loss_usd",
        "reference_url",
        "source_url",
        "source_page",
        "category_filter",
        "description",
        "normalized_at",
    ]
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="") as fp:
        writer = csv.DictWriter(fp, fieldnames=fieldnames)
        writer.writeheader()
        for row in rows:
            writer.writerow({field: row.get(field, "") for field in fieldnames})


def _incident(index: int, **overrides: object) -> dict[str, object]:
    target = str(overrides.get("target") or f"Fixture Protocol {index}")
    slug = target.lower().replace(" ", "-")
    row: dict[str, object] = {
        "incident_id": f"incident-{index:02d}",
        "event_date": f"2026-01-{index:02d}",
        "target": target,
        "protocol_slug_guess": slug,
        "is_defi": "true",
        "attack_method_raw": "Oracle Manipulation",
        "attack_family": "oracle_manipulation",
        "loss_usd_raw": "$ 1,000,000",
        "loss_usd": str(1_000_000 + index),
        "reference_url": f"https://example.test/incidents/{index}",
        "source_url": "https://hacked.slowmist.io/?c=&page=1",
        "source_page": "1",
        "category_filter": "all",
        "description": f"{target} suffered a DeFi exploit on Ethereum.",
        "normalized_at": "2026-05-23T00:00:00Z",
    }
    row.update(overrides)
    return row


def test_replay_cohort_builds_manifest_exclusion_log_and_case_files(tmp_path):
    incidents_csv = tmp_path / "incidents.csv"
    _write_csv(
        incidents_csv,
        [
            *[_incident(index) for index in range(1, 13)],
            _incident(20, is_defi="false", target="Centralized Exchange"),
            _incident(21, reference_url="", target="Missing Provenance"),
            _incident(22, target="Sui Perps", description="Sui perpetual protocol exploit"),
        ],
    )

    payload = build_replay_cohort(
        incidents_csv=incidents_csv,
        out=tmp_path / "cohort",
        min_cases=10,
        max_cases=12,
        evm_only=True,
        require_seed_transaction_hash=False,
        require_replay_block=False,
    )

    assert payload["schema_version"] == "abra.replay_cohort.v1"
    assert payload["status"] == "passed"
    assert payload["case_count"] == 12
    assert payload["quality"]["meets_case_count_requirement"] is True
    assert payload["artifacts"]["manifest"] == "manifest.json"
    assert payload["artifacts"]["exclusion_log"] == "exclusion_log.json"

    out = tmp_path / "cohort"
    manifest = json.loads((out / "manifest.json").read_text(encoding="utf-8"))
    exclusion_log = json.loads((out / "exclusion_log.json").read_text(encoding="utf-8"))
    case_files = sorted((out / "cases").glob("*.json"))

    assert manifest["schema_version"] == "abra.replay_cohort.manifest.v1"
    assert manifest["case_count"] == 12
    assert len(manifest["cases"]) == 12
    assert len(case_files) == 12
    assert all(case["chain"] == "ethereum" for case in manifest["cases"])
    assert all(case["provenance_url"].startswith("https://example.test/") for case in manifest["cases"])
    assert all("missing_seed_transaction_hash" in case["missing_fields"] for case in manifest["cases"])
    assert all((out / case["case_file"]).exists() for case in manifest["cases"])

    excluded = {(entry["slug"], entry["reason"]) for entry in exclusion_log["entries"]}
    assert ("centralized-exchange", "not_defi") in excluded
    assert ("missing-provenance", "missing_provenance") in excluded
    assert ("sui-perps", "non_evm_chain") in excluded


def test_replay_cohort_fails_when_strict_seed_hash_requirement_is_not_met(tmp_path):
    incidents_csv = tmp_path / "incidents.csv"
    _write_csv(incidents_csv, [_incident(index) for index in range(1, 13)])

    payload = build_replay_cohort(
        incidents_csv=incidents_csv,
        out=tmp_path / "cohort",
        min_cases=10,
        max_cases=12,
        evm_only=True,
        require_seed_transaction_hash=True,
        require_replay_block=False,
    )

    assert payload["status"] == "failed"
    assert payload["case_count"] == 0
    assert payload["quality"]["eligible_before_case_count"] == 0
    assert "insufficient_eligible_cases" in payload["errors"]
    exclusion_log = json.loads((tmp_path / "cohort" / "exclusion_log.json").read_text(encoding="utf-8"))
    assert {entry["reason"] for entry in exclusion_log["entries"]} == {"missing_seed_transaction_hash"}


def test_replay_cohort_cli_round_trip(tmp_path):
    incidents_csv = tmp_path / "incidents.csv"
    _write_csv(incidents_csv, [_incident(index) for index in range(1, 11)])
    out = tmp_path / "cohort"

    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "abra",
            "replay",
            "cohort",
            "--incidents-csv",
            str(incidents_csv),
            "--out",
            str(out),
            "--min-cases",
            "10",
            "--max-cases",
            "10",
            "--allow-missing-seed-transaction-hash",
            "--allow-missing-replay-block",
            "--json",
        ],
        check=False,
        capture_output=True,
        text=True,
    )

    assert result.returncode == 0, result.stderr
    payload = json.loads(result.stdout)
    assert payload["status"] == "passed"
    assert payload["case_count"] == 10
    assert (out / "manifest.json").exists()
    assert (out / "exclusion_log.json").exists()
    assert len(list((out / "cases").glob("*.json"))) == 10
