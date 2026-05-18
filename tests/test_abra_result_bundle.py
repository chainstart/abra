from __future__ import annotations

import hashlib
import json
import subprocess
import sys
from pathlib import Path

from abra.bundle import build_result_bundle, validate_result_bundle


FIXTURE_ROOT = Path(__file__).parent / "fixtures" / "abra_bundle_source"


def test_bundle_builder_writes_expected_files_and_preserves_sources(tmp_path):
    source = FIXTURE_ROOT / "reports"
    before = _fingerprints(FIXTURE_ROOT)
    result = build_result_bundle(source, tmp_path / "bundle")
    after = _fingerprints(FIXTURE_ROOT)

    assert before == after
    assert result.payload["status"] == "passed"
    bundle_dir = tmp_path / "bundle"
    assert (bundle_dir / "abra_result_bundle.json").exists()
    assert (bundle_dir / "evidence_bundle.json").exists()
    assert (bundle_dir / "artifact_manifest.json").exists()
    assert (bundle_dir / "writing_brief.md").exists()
    assert (bundle_dir / "limitations.md").exists()

    bundle = json.loads((bundle_dir / "abra_result_bundle.json").read_text(encoding="utf-8"))
    levels = {claim["evidence_level"] for claim in bundle["claims"]}
    assert {"L1", "L4", "L6"} <= levels
    assert bundle["summary"]["evidence_level_counts"]["L1"] == 1
    assert bundle["summary"]["evidence_level_counts"]["L4"] == 1
    assert bundle["summary"]["evidence_level_counts"]["L6"] == 1
    assert any("archive_state_unavailable" in item["description"] for item in bundle["limitations"])
    assert "Do not describe L1 static alerts" in (bundle_dir / "writing_brief.md").read_text(encoding="utf-8")


def test_bundle_validator_accepts_valid_bundle(tmp_path):
    build_result_bundle(FIXTURE_ROOT / "reports", tmp_path / "bundle")

    validation = validate_result_bundle(tmp_path / "bundle")

    assert validation["status"] == "passed", validation["errors"]
    assert validation["evidence_levels"] == {"L1": 1, "L4": 1, "L6": 1}
    assert "artifact_manifest.json" in validation["files_checked"]


def test_bundle_validator_rejects_l1_to_l4_conflation(tmp_path):
    build_result_bundle(FIXTURE_ROOT / "reports", tmp_path / "bundle")
    bundle_path = tmp_path / "bundle" / "abra_result_bundle.json"
    evidence_path = tmp_path / "bundle" / "evidence_bundle.json"
    bundle = json.loads(bundle_path.read_text(encoding="utf-8"))
    evidence = json.loads(evidence_path.read_text(encoding="utf-8"))

    bundle["claims"][0]["evidence_level"] = "L4"
    bundle["claims"][0]["evidence_label"] = "fork_replayed"
    evidence["claims"] = bundle["claims"]
    bundle_path.write_text(json.dumps(bundle), encoding="utf-8")
    evidence_path.write_text(json.dumps(evidence), encoding="utf-8")

    validation = validate_result_bundle(tmp_path / "bundle")

    assert validation["status"] == "failed"
    assert any("L4 claim" in error and "replay_result" in error for error in validation["errors"])
    assert any("L4 claim" in error and "verified" in error for error in validation["errors"])


def test_bundle_cli_build_and_validate_round_trip(tmp_path):
    bundle_dir = tmp_path / "bundle"
    build = subprocess.run(
        [
            sys.executable,
            "-m",
            "abra",
            "bundle",
            "build",
            "--source",
            str(FIXTURE_ROOT / "reports"),
            "--out",
            str(bundle_dir),
            "--json",
        ],
        check=False,
        capture_output=True,
        text=True,
    )
    assert build.returncode == 0, build.stderr
    build_payload = json.loads(build.stdout)
    assert build_payload["status"] == "passed"
    assert build_payload["claim_count"] == 3

    validate = subprocess.run(
        [
            sys.executable,
            "-m",
            "abra",
            "bundle",
            "validate",
            str(bundle_dir),
            "--json",
        ],
        check=False,
        capture_output=True,
        text=True,
    )
    assert validate.returncode == 0, validate.stderr
    validate_payload = json.loads(validate.stdout)
    assert validate_payload["status"] == "passed"


def _fingerprints(root: Path) -> dict[str, str]:
    result: dict[str, str] = {}
    for path in sorted(root.rglob("*")):
        if path.is_file():
            result[str(path.relative_to(root))] = hashlib.sha256(path.read_bytes()).hexdigest()
    return result
