from __future__ import annotations

import json
from pathlib import Path

from abra.replay_agent import assess_replay_fixture, validate_evidence_bundle


FIXTURE_PATH = Path(__file__).parent / "fixtures" / "replay_case.json"


def test_replay_assessment_persists_run_and_memory_ledgers(tmp_path):
    bundle_dir = tmp_path / "replay_bundle"

    first = assess_replay_fixture(FIXTURE_PATH, bundle_dir)
    second = assess_replay_fixture(FIXTURE_PATH, bundle_dir)

    run_ledger_path = bundle_dir / "memory" / "replay_run_ledger.jsonl"
    memory_ledger_path = bundle_dir / "memory" / "replay_memory_ledger.json"
    run_entries = [
        json.loads(line)
        for line in run_ledger_path.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]
    memory = json.loads(memory_ledger_path.read_text(encoding="utf-8"))

    assert first["run_ledger"]["run_id"] != second["run_ledger"]["run_id"]
    assert len(run_entries) == 2
    assert [entry["schema_version"] for entry in run_entries] == [
        "abra.replay_run_ledger.entry.v1",
        "abra.replay_run_ledger.entry.v1",
    ]
    assert all(entry["safety"]["broadcasts_transactions"] is False for entry in run_entries)
    assert all(entry["safety"]["requires_private_keys"] is False for entry in run_entries)
    assert run_entries[-1]["blocker_summary"]["category_counts"]["safety_decision"] == 4
    assert memory["schema_version"] == "abra.replay_memory_ledger.v1"
    assert memory["summary"]["run_count"] == 2
    assert memory["summary"]["incident_observation_count"] == 8
    assert memory["summary"]["latest_run_id"] == second["run_ledger"]["run_id"]

    validation = validate_evidence_bundle(bundle_dir, min_level="L1")
    assert validation["status"] == "passed", validation["errors"]
