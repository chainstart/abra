from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

from abra.replay_agent import assess_replay_fixture


FIXTURE_PATH = Path(__file__).parent / "fixtures" / "replay_case.json"


def test_ara_production_profile_emits_conservative_public_sidecars(tmp_path):
    bundle_dir = tmp_path / "ara_production_bundle"

    payload = assess_replay_fixture(FIXTURE_PATH, bundle_dir, profile="ara-production")

    assert payload["status"] == "passed", payload["validation"]["errors"]
    assert payload["profile"] == "ara-production"
    assert payload["evidence_levels"] == {"L1": 3, "L4": 1}
    assert payload["ara_production_contract"]["status"] == "emitted"
    for relative in (
        "bundle_manifest.json",
        "claims.json",
        "drafting_brief.md",
        "limitations.md",
        "ara_production_contract.json",
    ):
        assert (bundle_dir / relative).exists()

    manifest = json.loads((bundle_dir / "bundle_manifest.json").read_text(encoding="utf-8"))
    assert manifest["contract_profile"] == "ara-production"
    assert manifest["ara_production_contract"] == "ara_production_contract.json"

    contract = json.loads((bundle_dir / "ara_production_contract.json").read_text(encoding="utf-8"))
    assert contract["schema_version"] == "abra.ara_production_contract.v1"
    assert contract["drafting_gate"]["allowed_claim_ids"] == ["l4-replay-fixture-euler"]
    assert set(contract["drafting_gate"]["blocked_claim_ids"]) == {
        "l1-replay-fixture-archive-blocked",
        "l1-replay-fixture-missing-rpc",
        "l1-replay-fixture-missing-test",
    }
    assert contract["reproduction_gate"]["independent_reproduction_claim"] is False
    assert contract["reproduction_gate"]["broadcasts_transactions"] is False
    assert contract["reproduction_gate"]["requires_private_keys"] is False

    claims = json.loads((bundle_dir / "claims.json").read_text(encoding="utf-8"))["claims"]
    allowed = [claim for claim in claims if claim["status"] == "supported"]
    blocked = [claim for claim in claims if claim["status"] == "blocked"]
    assert [claim["claim_id"] for claim in allowed] == ["l4-replay-fixture-euler"]
    assert all(claim["evidence_level"] == "L1" for claim in blocked)
    assert all(claim["reproduction_status"] != "verified" for claim in blocked)


def test_ara_production_profile_validates_with_public_ara(tmp_path):
    bundle_dir = tmp_path / "ara_production_bundle"
    assess_replay_fixture(FIXTURE_PATH, bundle_dir, profile="ara-production")

    result = subprocess.run(
        [
            sys.executable,
            "tools/ara_bundle_validate.py",
            str(bundle_dir),
            "--json",
        ],
        check=False,
        capture_output=True,
        text=True,
    )

    assert result.returncode == 0, result.stderr
    payload = json.loads(result.stdout)
    assert payload["status"] == "passed", payload["errors"]
    assert payload["contract_summary"]["allowed_claim_ids"] == ["l4-replay-fixture-euler"]
    assert set(payload["contract_summary"]["blocked_claim_ids"]) == {
        "l1-replay-fixture-archive-blocked",
        "l1-replay-fixture-missing-rpc",
        "l1-replay-fixture-missing-test",
    }


def test_replay_cli_accepts_ara_production_profile(tmp_path):
    bundle_dir = tmp_path / "ara_production_bundle"

    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "abra",
            "replay",
            "assess",
            "--case-fixture",
            str(FIXTURE_PATH),
            "--profile",
            "ara-production",
            "--out",
            str(bundle_dir),
            "--json",
        ],
        check=False,
        capture_output=True,
        text=True,
    )

    assert result.returncode == 0, result.stderr
    payload = json.loads(result.stdout)
    assert payload["profile"] == "ara-production"
    assert payload["ara_production_contract"]["path"] == "ara_production_contract.json"
