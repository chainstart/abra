from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

from abra.replay_agent import assess_replay_fixture, validate_evidence_bundle


FIXTURE_PATH = Path(__file__).parent / "fixtures" / "replay_case.json"
ARCHIVE_PROFILE_PATH = Path(__file__).parent / "fixtures" / "archive_rpc_profile.json"


def test_archive_replay_profile_upgrades_fixture_to_l4_bundle(tmp_path):
    bundle_dir = tmp_path / "archive_replay_bundle"

    payload = assess_replay_fixture(FIXTURE_PATH, bundle_dir, archive_profile=ARCHIVE_PROFILE_PATH)

    assert payload["status"] == "passed", payload["validation"]["errors"]
    assert payload["case_count"] == 4
    assert payload["archive_profile"] == str(ARCHIVE_PROFILE_PATH.resolve())
    assert payload["evidence_levels"] == {"L4": 4}
    assert payload["status_counts"] == {"verified": 4}
    assert payload["archive_rpc_validation"]["mode"] == "production_local_archive_profile"
    assert payload["archive_rpc_preflight"]["status"] == "passed"

    report = json.loads((bundle_dir / "replay_feasibility_report.json").read_text(encoding="utf-8"))
    assert report["safety"]["validation_mode"] == "production_local_archive_profile"
    assert report["safety"]["broadcasts_transactions"] is False
    assert report["safety"]["requires_private_keys"] is False
    assert all(case["evidence_level"] == "L4" for case in report["cases"])
    assert all(case["archive_profile"]["read_only"] is True for case in report["cases"])
    assert all(case["archive_profile"]["private_keys"] == "not_used" for case in report["cases"])
    assert all(case["trace"]["status"] == "available" for case in report["cases"])
    assert all(case["trace"]["path"].startswith("artifacts/traces/") for case in report["cases"])

    preflight = json.loads((bundle_dir / "archive_rpc_preflight.json").read_text(encoding="utf-8"))
    assert preflight["mode"] == "production_local"
    assert preflight["read_only"] is True
    assert preflight["broadcasts_transactions"] is False
    assert preflight["private_keys"] == "not_used"
    assert preflight["state_changing_rpc"] is False
    assert preflight["summary"]["status_counts"] == {"passed": 4}
    assert preflight["summary"]["trace_capture_count"] == 4
    assert preflight["summary"]["log_capture_count"] == 4

    manifest = json.loads((bundle_dir / "artifact_manifest.json").read_text(encoding="utf-8"))
    kinds = {artifact["kind"] for artifact in manifest["artifacts"]}
    assert {"archive_rpc_profile", "archive_rpc_preflight", "archive_replay_trace"} <= kinds
    assert len([artifact for artifact in manifest["artifacts"] if artifact["kind"] == "archive_replay_trace"]) == 4


def test_archive_replay_profile_evidence_validates_at_l4(tmp_path):
    bundle_dir = tmp_path / "archive_replay_bundle"
    assess_replay_fixture(FIXTURE_PATH, bundle_dir, archive_profile=ARCHIVE_PROFILE_PATH)

    validation = validate_evidence_bundle(bundle_dir, min_level="L4")

    assert validation["status"] == "passed", validation["errors"]
    assert validation["minimum_level"] == "L4"
    assert validation["evidence_levels"] == {"L4": 4}
    assert "archive_rpc_preflight.json" in validation["files_checked"]


def test_archive_replay_cli_accepts_profile_and_l4_validation(tmp_path):
    bundle_dir = tmp_path / "archive_replay_bundle"

    assess = subprocess.run(
        [
            sys.executable,
            "-m",
            "abra",
            "replay",
            "assess",
            "--case-fixture",
            str(FIXTURE_PATH),
            "--archive-profile",
            str(ARCHIVE_PROFILE_PATH),
            "--out",
            str(bundle_dir),
            "--json",
        ],
        check=False,
        capture_output=True,
        text=True,
    )
    assert assess.returncode == 0, assess.stderr
    assert json.loads(assess.stdout)["evidence_levels"] == {"L4": 4}

    validate = subprocess.run(
        [
            sys.executable,
            "-m",
            "abra",
            "evidence",
            "validate",
            str(bundle_dir),
            "--min-level",
            "L4",
            "--json",
        ],
        check=False,
        capture_output=True,
        text=True,
    )
    assert validate.returncode == 0, validate.stderr
    assert json.loads(validate.stdout)["status"] == "passed"


def test_archive_replay_profile_rejects_broadcast_or_private_key_markers(tmp_path):
    profile = json.loads(ARCHIVE_PROFILE_PATH.read_text(encoding="utf-8"))
    profile["cases"]["fixture-euler"]["command"] = (
        "forge script script/Exploit.s.sol --broadcast --private-key PRIVATE_KEY"
    )
    unsafe_profile = tmp_path / "unsafe_archive_profile.json"
    unsafe_profile.write_text(json.dumps(profile, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    with pytest.raises(ValueError, match="denied command markers|denied marker"):
        assess_replay_fixture(FIXTURE_PATH, tmp_path / "bundle", archive_profile=unsafe_profile)
