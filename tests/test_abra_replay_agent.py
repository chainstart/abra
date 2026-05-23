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
    assert (bundle_dir / "replay_blocker_ledger.json").exists()
    assert (bundle_dir / "archive_rpc_validation.json").exists()
    assert (bundle_dir / "memory" / "replay_run_ledger.jsonl").exists()
    assert (bundle_dir / "memory" / "replay_memory_ledger.json").exists()
    assert (bundle_dir / "evidence_bundle.json").exists()
    assert (bundle_dir / "artifact_manifest.json").exists()

    report = json.loads((bundle_dir / "replay_feasibility_report.json").read_text(encoding="utf-8"))
    cases = {case["slug"]: case for case in report["cases"]}
    assert report["blocker_ledger"] == "replay_blocker_ledger.json"
    assert report["archive_rpc_validation"] == "archive_rpc_validation.json"
    assert report["safety"]["broadcasts_transactions"] is False
    assert report["safety"]["requires_private_keys"] is False
    assert report["safety"]["validation_mode"] == "deterministic_local"
    assert cases["fixture-euler"]["evidence_level"] == "L4"
    assert cases["fixture-archive-blocked"]["failure_reason"]["code"] == "archive_state_unavailable"
    assert cases["fixture-archive-blocked"]["feasibility"] == "blocked_archive_rpc"
    assert cases["fixture-missing-rpc"]["failure_reason"]["code"] == "missing_rpc"
    assert cases["fixture-missing-rpc"]["required_environment"][0]["name"] == "ETH_RPC_URL"
    assert cases["fixture-missing-rpc"]["required_environment"][0]["present"] is False
    assert cases["fixture-missing-test"]["failure_reason"]["code"] == "replay_test_not_implemented"
    assert cases["fixture-missing-test"]["trace"]["status"] == "unavailable"
    assert all(not case["safety_violations"] for case in cases.values())


def test_replay_blocker_ledger_and_archive_validation_are_serialized(tmp_path):
    payload = assess_replay_fixture(FIXTURE_PATH, tmp_path / "replay_bundle")
    bundle_dir = tmp_path / "replay_bundle"

    ledger = json.loads((bundle_dir / "replay_blocker_ledger.json").read_text(encoding="utf-8"))
    validation = json.loads((bundle_dir / "archive_rpc_validation.json").read_text(encoding="utf-8"))

    assert payload["blocker_ledger"]["entry_count"] == ledger["summary"]["entry_count"]
    assert {
        "archive_rpc_state",
        "trace_availability",
        "fork_block_gap",
        "simulation_precondition",
        "safety_decision",
    } <= set(ledger["summary"]["category_counts"])
    entries = {(entry["slug"], entry["category"], entry["code"]): entry for entry in ledger["entries"]}
    assert entries[("fixture-archive-blocked", "archive_rpc_state", "archive_state_unavailable")]["status"] == "open"
    assert entries[("fixture-missing-rpc", "archive_rpc_state", "missing_archive_rpc_env")]["retryable"] is True
    assert entries[("fixture-missing-test", "fork_block_gap", "fork_block_not_declared")]["severity"] == "blocking"
    safety_entries = [entry for entry in ledger["entries"] if entry["category"] == "safety_decision"]
    assert len(safety_entries) == 4
    assert all(entry["details"]["broadcasts_transactions"] is False for entry in safety_entries)
    assert all(entry["details"]["requires_private_keys"] is False for entry in safety_entries)

    assert validation["mode"] == "deterministic_local"
    assert validation["network_access"] == "not_used"
    assert validation["broadcasts_transactions"] is False
    assert validation["private_keys"] == "not_used"
    assert validation["summary"]["status_counts"]["blocked_missing_archive_rpc"] == 1
    missing_rpc = next(check for check in validation["checks"] if check["slug"] == "fixture-missing-rpc")
    assert missing_rpc["live_validation_requires"]["archive_rpc_env"] == "ETH_RPC_URL"
    assert missing_rpc["live_validation_requires"]["private_key_required"] is False
    assert missing_rpc["live_validation_requires"]["broadcast_required"] is False


def test_evidence_validator_accepts_replay_bundle_and_enforces_minimum_level(tmp_path):
    assess_replay_fixture(FIXTURE_PATH, tmp_path / "replay_bundle")

    validation = validate_evidence_bundle(tmp_path / "replay_bundle", min_level="L1")

    assert validation["status"] == "passed", validation["errors"]
    assert validation["minimum_level"] == "L1"
    assert validation["claim_count"] == 4
    assert validation["evidence_levels"] == {"L4": 1, "L1": 3}
    assert "replay_feasibility_report.json" in validation["files_checked"]
    assert "replay_blocker_ledger.json" in validation["files_checked"]
    assert "archive_rpc_validation.json" in validation["files_checked"]
    assert "memory/replay_run_ledger.jsonl" in validation["files_checked"]

    strict_validation = validate_evidence_bundle(tmp_path / "replay_bundle", min_level="L4")
    assert strict_validation["status"] == "failed"
    assert any("below minimum evidence level L4" in error for error in strict_validation["errors"])


def test_evidence_validator_rejects_replay_ledger_safety_regression(tmp_path):
    bundle_dir = tmp_path / "replay_bundle"
    assess_replay_fixture(FIXTURE_PATH, bundle_dir)
    ledger_path = bundle_dir / "replay_blocker_ledger.json"
    ledger = json.loads(ledger_path.read_text(encoding="utf-8"))
    safety = next(entry for entry in ledger["entries"] if entry["category"] == "safety_decision")
    safety["details"]["broadcasts_transactions"] = True
    ledger_path.write_text(json.dumps(ledger, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    validation = validate_evidence_bundle(bundle_dir, min_level="L1")

    assert validation["status"] == "failed"
    assert any("broadcasts_transactions=false" in error for error in validation["errors"])


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


def test_replay_assess_cohort_cli_consumes_cohort_cases(tmp_path):
    cohort_dir = tmp_path / "cohort"
    cases_dir = cohort_dir / "cases"
    cases_dir.mkdir(parents=True)
    case_payload = {
        "schema_version": "abra.replay_cohort.case.v1",
        "case_id": "incident-euler",
        "slug": "fixture-euler",
        "incident": "Fixture Euler",
        "chain": "ethereum",
        "attack_family": "flash_loan",
        "loss_usd": 1000000,
        "fork_block": 16817995,
        "seed_transaction_hash": "0x" + "1" * 64,
        "test_path": "test/replay/FixtureEulerReplay.t.sol",
        "replay_test": "test_FixtureEulerReplay",
        "metadata_test": "test_FixtureEulerReplayMetadata",
        "environment": {"ETH_RPC_URL": True},
        "fixture_result": {
            "status": "verified",
            "metadata_status": "passed",
            "returncode": 0,
            "verified": True,
            "log_text": "[PASS] test_FixtureEulerReplay()",
        },
    }
    (cases_dir / "fixture-euler.json").write_text(json.dumps(case_payload), encoding="utf-8")
    (cohort_dir / "manifest.json").write_text(
        json.dumps(
            {
                "schema_version": "abra.replay_cohort.manifest.v1",
                "cohort_id": "cohort-test",
                "case_count": 1,
                "cases": [{"slug": "fixture-euler", "case_file": "cases/fixture-euler.json"}],
            }
        ),
        encoding="utf-8",
    )
    out_dir = tmp_path / "cohort_evidence"

    assess = subprocess.run(
        [
            sys.executable,
            "-m",
            "abra",
            "replay",
            "assess-cohort",
            "--cohort",
            str(cohort_dir),
            "--out",
            str(out_dir),
            "--json",
        ],
        check=False,
        capture_output=True,
        text=True,
    )

    assert assess.returncode == 0, assess.stderr
    payload = json.loads(assess.stdout)
    assert payload["schema_version"] == "abra.replay_cohort_assessment.v1"
    assert payload["status"] == "passed"
    assert payload["case_count"] == 1
    assert payload["assessed_count"] == 1
    assert payload["verified_count"] == 1
    assert (out_dir / "cohort_evidence_manifest.json").exists()
    assert (out_dir / "cases" / "fixture-euler" / "evidence_bundle.json").exists()
    assert (out_dir / "cases" / "fixture-euler" / "replay_feasibility_report.json").exists()


def test_replay_runner_failure_classifier_is_exposed_for_agent_support():
    assert classify_failure("Error: missing trie node for historical state") == "archive_state_unavailable"
