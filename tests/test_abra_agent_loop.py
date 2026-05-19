from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

from abra.agent import run_research_agent
from abra.replay_agent import validate_evidence_bundle


FIXTURE_PATH = Path(__file__).parent / "fixtures" / "replay_case.json"


def test_agent_loop_writes_state_ledgers_replay_review_and_ara_bundle(tmp_path):
    bundle_dir = tmp_path / "agent_bundle"

    payload = run_research_agent(case_fixture=FIXTURE_PATH, out=bundle_dir, rounds=3)

    assert payload["status"] == "passed", payload["validation"]["errors"]
    assert payload["round_count"] == 3
    assert payload["case_count"] == 4
    assert payload["evidence_levels"] == {"L4": 1, "L1": 3}
    assert (bundle_dir / "agent_run_state.json").exists()
    assert (bundle_dir / "evidence_review.json").exists()
    assert (bundle_dir / "final_report.md").exists()
    assert (bundle_dir / "memory" / "agent_decision_ledger.jsonl").exists()
    assert (bundle_dir / "memory" / "agent_observation_ledger.jsonl").exists()
    assert (bundle_dir / "memory" / "agent_reflection_ledger.jsonl").exists()
    assert (bundle_dir / "memory" / "agent_run_ledger.jsonl").exists()
    assert (bundle_dir / "memory" / "agent_memory_ledger.json").exists()
    assert (bundle_dir / "replay_assessment" / "evidence_bundle.json").exists()
    assert (bundle_dir / "bundle_manifest.json").exists()
    assert (bundle_dir / "claims.json").exists()
    assert (bundle_dir / "artifact_manifest.json").exists()
    assert (bundle_dir / "evidence_bundle.json").exists()

    state = json.loads((bundle_dir / "agent_run_state.json").read_text(encoding="utf-8"))
    review = json.loads((bundle_dir / "evidence_review.json").read_text(encoding="utf-8"))
    claims = json.loads((bundle_dir / "claims.json").read_text(encoding="utf-8"))["claims"]

    assert [observation["step"] for observation in state["observations"]] == [
        "inventory",
        "replay_assessment",
        "evidence_review",
    ]
    assert state["safety"]["broadcasts_transactions"] is False
    assert state["safety"]["requires_private_keys"] is False
    assert state["safety"]["state_changing_rpc"] is False
    assert review["evidence_policy"]["non_l4_replay_claims_are_successful_replays"] is False
    assert review["summary"]["open_blocker_count"] > 0
    assert any(claim["evidence_level"] == "L4" and claim["status"] == "supported" for claim in claims)

    validation = validate_evidence_bundle(bundle_dir, min_level="L1")
    assert validation["status"] == "passed", validation["errors"]


def test_agent_loop_appends_memory_between_runs(tmp_path):
    bundle_dir = tmp_path / "agent_bundle"

    first = run_research_agent(case_fixture=FIXTURE_PATH, out=bundle_dir, rounds=2)
    second = run_research_agent(case_fixture=FIXTURE_PATH, out=bundle_dir, rounds=2)

    run_entries = [
        json.loads(line)
        for line in (bundle_dir / "memory" / "agent_run_ledger.jsonl").read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]
    memory = json.loads((bundle_dir / "memory" / "agent_memory_ledger.json").read_text(encoding="utf-8"))

    assert first["run_id"] != second["run_id"]
    assert len(run_entries) == 2
    assert memory["schema_version"] == "abra.agent_memory_ledger.v1"
    assert memory["summary"]["run_count"] == 2
    assert memory["summary"]["latest_run_id"] == second["run_id"]
    assert all(entry["safety"]["broadcasts_transactions"] is False for entry in run_entries)


def test_agent_run_cli_round_trip(tmp_path):
    bundle_dir = tmp_path / "agent_bundle"
    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "abra",
            "agent",
            "run",
            "--case-fixture",
            str(FIXTURE_PATH),
            "--out",
            str(bundle_dir),
            "--rounds",
            "3",
            "--json",
        ],
        check=False,
        capture_output=True,
        text=True,
    )

    assert result.returncode == 0, result.stderr
    payload = json.loads(result.stdout)
    assert payload["status"] == "passed", payload["validation"]["errors"]
    assert payload["bundle_type"] == "abra_research_agent_bundle"
    assert payload["round_count"] == 3
