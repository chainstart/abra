from __future__ import annotations

import hashlib
import json
import subprocess
import sys
from pathlib import Path

from abra.replay_agent import assess_replay_fixture, validate_evidence_bundle
from tools.replay_runner import classify_failure


FIXTURE_PATH = Path(__file__).parent / "fixtures" / "replay_case.json"


def test_replay_fixture_assessment_writes_structured_bundle_without_mutating_fixture(tmp_path):
    before = hashlib.sha256(FIXTURE_PATH.read_bytes()).hexdigest()

    payload = assess_replay_fixture(FIXTURE_PATH, tmp_path / "replay_bundle")

    after = hashlib.sha256(FIXTURE_PATH.read_bytes()).hexdigest()
    assert before == after
    assert payload["status"] == "passed"
    assert payload["case_count"] == 4
    assert payload["evidence_levels"] == {"L4": 1, "L1": 3}
    assert payload["status_counts"]["verified"] == 1
    assert payload["status_counts"]["no_rpc"] == 1
    assert payload["status_counts"]["no_test"] == 1

    bundle_dir = tmp_path / "replay_bundle"
    assert (bundle_dir / "replay_feasibility_report.json").exists()
    assert (bundle_dir / "replay_feasibility_report.md").exists()
    assert (bundle_dir / "evidence_bundle.json").exists()
    assert (bundle_dir / "artifact_manifest.json").exists()

    report = json.loads((bundle_dir / "replay_feasibility_report.json").read_text(encoding="utf-8"))
    cases = {case["slug"]: case for case in report["cases"]}
    assert report["safety"]["broadcasts_transactions"] is False
    assert report["safety"]["requires_private_keys"] is False
    assert cases["fixture-euler"]["evidence_level"] == "L4"
    assert cases["fixture-archive-blocked"]["failure_reason"]["code"] == "archive_state_unavailable"
    assert cases["fixture-archive-blocked"]["feasibility"] == "blocked_archive_rpc"
    assert cases["fixture-missing-rpc"]["failure_reason"]["code"] == "missing_rpc"
    assert cases["fixture-missing-rpc"]["required_environment"][0]["name"] == "ETH_RPC_URL"
    assert cases["fixture-missing-rpc"]["required_environment"][0]["present"] is False
    assert cases["fixture-missing-test"]["failure_reason"]["code"] == "replay_test_not_implemented"
    assert all(not case["safety_violations"] for case in cases.values())


def test_evidence_validator_accepts_replay_bundle_and_enforces_minimum_level(tmp_path):
    assess_replay_fixture(FIXTURE_PATH, tmp_path / "replay_bundle")

    validation = validate_evidence_bundle(tmp_path / "replay_bundle", min_level="L1")

    assert validation["status"] == "passed", validation["errors"]
    assert validation["minimum_level"] == "L1"
    assert validation["claim_count"] == 4
    assert validation["evidence_levels"] == {"L4": 1, "L1": 3}
    assert "replay_feasibility_report.json" in validation["files_checked"]

    strict_validation = validate_evidence_bundle(tmp_path / "replay_bundle", min_level="L4")
    assert strict_validation["status"] == "failed"
    assert any("below minimum evidence level L4" in error for error in strict_validation["errors"])


def test_replay_assess_and_evidence_validate_cli_round_trip(tmp_path):
    bundle_dir = tmp_path / "replay_bundle"
    assess = subprocess.run(
        [
            sys.executable,
            "-m",
            "abra",
            "replay",
            "assess",
            "--case-fixture",
            str(FIXTURE_PATH),
            "--out",
            str(bundle_dir),
            "--json",
        ],
        check=False,
        capture_output=True,
        text=True,
    )
    assert assess.returncode == 0, assess.stderr
    assess_payload = json.loads(assess.stdout)
    assert assess_payload["status"] == "passed"
    assert assess_payload["case_count"] == 4

    validate = subprocess.run(
        [
            sys.executable,
            "-m",
            "abra",
            "evidence",
            "validate",
            str(bundle_dir),
            "--min-level",
            "L1",
            "--json",
        ],
        check=False,
        capture_output=True,
        text=True,
    )
    assert validate.returncode == 0, validate.stderr
    validate_payload = json.loads(validate.stdout)
    assert validate_payload["status"] == "passed"
    assert validate_payload["minimum_level"] == "L1"


def test_replay_runner_failure_classifier_is_exposed_for_agent_support():
    assert classify_failure("Error: missing trie node for historical state") == "archive_state_unavailable"
