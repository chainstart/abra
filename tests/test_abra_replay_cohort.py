from __future__ import annotations

import csv
import json
import subprocess
import sys
from pathlib import Path

import pytest

from abra.replay_cohort import build_replay_cohort


@pytest.fixture(autouse=True)
def _disable_live_anchor_discovery_by_default(monkeypatch):
    monkeypatch.setenv("ABRA_ONCHAIN_ANCHOR_DISCOVERY", "0")


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
        "seed_transaction_hash",
        "fork_block",
        "description",
        "normalized_at",
    ]
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="") as fp:
        writer = csv.DictWriter(fp, fieldnames=fieldnames)
        writer.writeheader()
        for row in rows:
            writer.writerow({field: row.get(field, "") for field in fieldnames})


def _write_replay_results_csv(path: Path, rows: list[dict[str, object]]) -> None:
    fieldnames = [
        "incident",
        "slug",
        "chain",
        "rpc_env",
        "attack_family",
        "loss_usd",
        "fork_block",
        "test_path",
        "replay_test",
        "metadata_test",
        "status",
        "metadata_status",
        "command",
        "returncode",
        "duration_seconds",
        "log_path",
        "blocker",
        "verified",
    ]
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="") as fp:
        writer = csv.DictWriter(fp, fieldnames=fieldnames)
        writer.writeheader()
        for row in rows:
            writer.writerow({field: row.get(field, "") for field in fieldnames})


def _write_event_card(path: Path, *, slug: str, incident: str, reference_url: str, fork_block: int) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        f"""# Incident Card - {incident}

## Metadata

- Incident ID: `{slug}`
- Date: `2025-01-01`
- DeFi Label: `true`
- Attack Family: `oracle_manipulation`
- Attack Method (raw): `Oracle Manipulation`
- Estimated Loss: `$1000000`
- Reference URL: {reference_url}

## Replay Plan

1. Required On-chain Preconditions: Ethereum fork near block `{fork_block}`.
2. Fork Block Number: `{fork_block}`
""",
        encoding="utf-8",
    )


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
        "reference_url": f"https://www.certik.com/resources/blog/fixture-protocol-{index}",
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
        rpc_supported_chains=["ethereum"],
    )

    assert payload["schema_version"] == "abra.replay_cohort.v1"
    assert payload["status"] == "passed"
    assert payload["case_count"] == 12
    assert payload["quality"]["meets_case_count_requirement"] is True
    assert payload["artifacts"]["manifest"] == "manifest.json"
    assert payload["artifacts"]["exclusion_log"] == "exclusion_log.json"
    assert payload["artifacts"]["stage_ledger"] == "stage_ledger.json"

    out = tmp_path / "cohort"
    manifest = json.loads((out / "manifest.json").read_text(encoding="utf-8"))
    exclusion_log = json.loads((out / "exclusion_log.json").read_text(encoding="utf-8"))
    stage_ledger = json.loads((out / "stage_ledger.json").read_text(encoding="utf-8"))
    case_files = sorted((out / "cases").glob("*.json"))

    assert manifest["schema_version"] == "abra.replay_cohort.manifest.v1"
    assert manifest["security_evidence_csv"].endswith("security_evidence_enriched_latest.csv")
    assert manifest["alchemy_backfill_csv"].endswith("alchemy_onchain_backfill_latest.csv")
    assert manifest["case_count"] == 12
    assert manifest["stage_order"] == [
        "candidate_discovery",
        "security_evidence_enrichment",
        "alchemy_onchain_backfill",
        "replay_cohort_selection",
    ]
    assert len(manifest["cases"]) == 12
    assert len(case_files) == 12
    assert all(case["chain"] == "ethereum" for case in manifest["cases"])
    assert all(case["provenance_url"].startswith("https://www.certik.com/") for case in manifest["cases"])
    assert all("missing_seed_transaction_hash" in case["missing_fields"] for case in manifest["cases"])
    assert all(case["pipeline_stages"]["security_evidence_enrichment"]["status"] == "verified" for case in manifest["cases"])
    assert all(
        case["pipeline_stages"]["alchemy_onchain_backfill"]["status"] == "required"
        for case in manifest["cases"]
    )
    assert all((out / case["case_file"]).exists() for case in manifest["cases"])
    assert stage_ledger["schema_version"] == "abra.replay_cohort.stage_ledger.v1"
    assert stage_ledger["source_stage_artifacts"] == {
        "security_evidence_csv": str(incidents_csv.parent / "security_evidence_enriched_latest.csv"),
        "alchemy_backfill_csv": str(incidents_csv.parent / "alchemy_onchain_backfill_latest.csv"),
    }
    assert stage_ledger["stage_order"] == manifest["stage_order"]
    assert stage_ledger["summary"]["candidate_discovery_count"] == 15
    assert stage_ledger["summary"]["security_evidence_enriched_count"] == 14
    assert stage_ledger["summary"]["replay_metadata_promoted_count"] == 0

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
        include_evidence_candidates=False,
        rpc_supported_chains=["ethereum"],
    )

    assert payload["status"] == "failed"
    assert payload["case_count"] == 0
    assert payload["quality"]["eligible_before_case_count"] == 0
    assert "insufficient_eligible_cases" in payload["errors"]
    exclusion_log = json.loads((tmp_path / "cohort" / "exclusion_log.json").read_text(encoding="utf-8"))
    assert {entry["reason"] for entry in exclusion_log["entries"]} == {"missing_seed_transaction_hash"}


def test_replay_cohort_fails_when_selected_evidence_candidates_still_lack_onchain_anchors(tmp_path):
    incidents_csv = tmp_path / "incidents.csv"
    _write_csv(incidents_csv, [_incident(index) for index in range(1, 13)])

    payload = build_replay_cohort(
        incidents_csv=incidents_csv,
        out=tmp_path / "cohort",
        min_cases=10,
        max_cases=12,
        evm_only=True,
        require_seed_transaction_hash=True,
        require_replay_block=True,
        include_evidence_candidates=True,
        rpc_supported_chains=["ethereum"],
    )

    assert payload["status"] == "failed"
    assert payload["case_count"] == 12
    assert payload["quality"]["missing_seed_transaction_hash_count"] == 12
    assert payload["quality"]["missing_replay_block_count"] == 12
    assert "selected_cases_missing_seed_transaction_hash" in payload["errors"]
    assert "selected_cases_missing_replay_block" in payload["errors"]
    assert "selected_cases_include_diagnostic_evidence_boundaries" in payload["warnings"]

    manifest = json.loads((tmp_path / "cohort" / "manifest.json").read_text(encoding="utf-8"))
    assert manifest["case_count"] == 12
    assert {case["eligibility"] for case in manifest["cases"]} == {"security_anchor_backfill_required"}
    assert all(
        case["pipeline_stages"]["alchemy_onchain_backfill"]["status"] == "required"
        for case in manifest["cases"]
    )


def test_replay_cohort_reports_missing_alchemy_configuration(tmp_path, monkeypatch):
    monkeypatch.setenv("ABRA_DISABLE_LOCAL_ENV", "1")
    for key in (
        "ALCHEMY_API_KEY",
        "ALCHEMY_RPC_URL",
        "ALCHEMY_MAINNET_RPC_URL",
        "ALCHEMY_HTTP_URL",
        "ETH_RPC_URL",
        "POLYGON_RPC_URL",
    ):
        monkeypatch.delenv(key, raising=False)
    incidents_csv = tmp_path / "incidents.csv"
    _write_csv(incidents_csv, [_incident(index) for index in range(1, 11)])

    payload = build_replay_cohort(
        incidents_csv=incidents_csv,
        out=tmp_path / "cohort",
        min_cases=10,
        max_cases=10,
        evm_only=True,
        require_seed_transaction_hash=False,
        require_replay_block=False,
    )

    assert payload["status"] == "failed"
    assert "alchemy_rpc_not_configured" in payload["errors"]
    assert "insufficient_eligible_cases" in payload["errors"]
    assert "alchemy_rpc_not_configured" in payload["warnings"]
    assert payload["quality"]["selected_rpc_supported_count"] == 0
    manifest = json.loads((tmp_path / "cohort" / "manifest.json").read_text(encoding="utf-8"))
    assert manifest["rpc_provider"] == "alchemy"
    assert manifest["rpc_supported_chains"] == []


def test_replay_cohort_uses_alchemy_api_key_as_default_rpc_boundary(tmp_path, monkeypatch):
    monkeypatch.setenv("ALCHEMY_API_KEY", "alchemy-test-key")
    monkeypatch.delenv("ETH_RPC_URL", raising=False)
    monkeypatch.delenv("POLYGON_RPC_URL", raising=False)
    incidents_csv = tmp_path / "incidents.csv"
    rows = [_incident(index) for index in range(1, 10)]
    rows.append(
        _incident(
            10,
            target="Polygon Candidate",
            description="Polygon DeFi oracle manipulation candidate.",
        )
    )
    rows.append(
        _incident(
            11,
            target="EOS Candidate",
            description="EOS DeFi contract exploit candidate.",
        )
    )
    _write_csv(incidents_csv, rows)

    payload = build_replay_cohort(
        incidents_csv=incidents_csv,
        out=tmp_path / "cohort",
        min_cases=10,
        max_cases=10,
        evm_only=True,
        require_seed_transaction_hash=False,
        require_replay_block=False,
    )

    assert payload["status"] == "passed"
    assert payload["case_count"] == 10
    assert payload["quality"]["selected_rpc_supported_count"] == 10
    assert "alchemy_rpc_not_configured" not in payload["errors"]
    manifest = json.loads((tmp_path / "cohort" / "manifest.json").read_text(encoding="utf-8"))
    assert "ethereum" in manifest["rpc_supported_chains"]
    assert "polygon" in manifest["rpc_supported_chains"]
    assert "eos" not in manifest["rpc_supported_chains"]
    assert {case["chain"] for case in manifest["cases"]} == {"ethereum", "polygon"}
    assert all(case["rpc_supported"] is True for case in manifest["cases"])


def test_replay_cohort_treats_alchemy_l2s_as_evm_supported(tmp_path, monkeypatch):
    monkeypatch.setenv("ALCHEMY_API_KEY", "alchemy-test-key")
    incidents_csv = tmp_path / "incidents.csv"
    rows = [
        _incident(1, target="Base Candidate", description="Base DeFi exploit candidate."),
        _incident(2, target="Celo Candidate", description="Celo DeFi exploit candidate."),
        _incident(3, target="zkSync Candidate", description="zkSync DeFi exploit candidate."),
        _incident(4, target="Polygon zkEVM Candidate", description="Polygon zkEVM DeFi exploit candidate."),
    ]
    _write_csv(incidents_csv, rows)

    payload = build_replay_cohort(
        incidents_csv=incidents_csv,
        out=tmp_path / "cohort",
        min_cases=4,
        max_cases=4,
        evm_only=True,
        require_seed_transaction_hash=False,
        require_replay_block=False,
    )

    assert payload["status"] == "passed"
    manifest = json.loads((tmp_path / "cohort" / "manifest.json").read_text(encoding="utf-8"))
    by_chain = {case["chain"]: case for case in manifest["cases"]}
    assert by_chain["base"]["chain_id"] == 8453
    assert by_chain["celo"]["chain_id"] == 42220
    assert by_chain["zksync"]["chain_id"] == 324
    assert by_chain["polygon_zkevm"]["chain_id"] == 1101
    assert all(case["rpc_supported"] is True for case in manifest["cases"])


def test_replay_cohort_requires_security_anchor_before_alchemy_backfill(tmp_path):
    incidents_csv = tmp_path / "incidents.csv"
    _write_csv(
        incidents_csv,
        [
            _incident(
                1,
                target="Unanchored Ethereum Candidate",
                reference_url="https://example.test/incidents/unanchored-ethereum-candidate",
                source_url="https://example.test/feed/unanchored-ethereum-candidate",
                description="Ethereum oracle manipulation candidate without any anchored security report.",
            )
        ],
    )

    payload = build_replay_cohort(
        incidents_csv=incidents_csv,
        out=tmp_path / "cohort",
        min_cases=1,
        max_cases=1,
        evm_only=True,
        require_seed_transaction_hash=True,
        require_replay_block=True,
        rpc_supported_chains=["ethereum"],
    )

    assert payload["status"] == "failed"
    assert payload["case_count"] == 0
    assert "insufficient_eligible_cases" in payload["errors"]

    exclusion_log = json.loads((tmp_path / "cohort" / "exclusion_log.json").read_text(encoding="utf-8"))
    excluded = {(entry["slug"], entry["reason"]) for entry in exclusion_log["entries"]}
    assert ("unanchored-ethereum-candidate", "missing_security_anchor") in excluded


def test_replay_cohort_accepts_complete_onchain_evidence_without_security_anchor(tmp_path):
    tx_hash = "0x" + "b" * 64
    incidents_csv = tmp_path / "incidents.csv"
    _write_csv(
        incidents_csv,
        [
            _incident(
                1,
                target="Reference Only Onchain Candidate",
                reference_url=f"https://example.test/incidents/reference-only?tx={tx_hash}",
                source_url="https://defillama.com/hacks",
                seed_transaction_hash="",
                fork_block="",
                description="Ethereum exploit with direct transaction evidence but no security-company report.",
            )
        ],
    )

    def fake_rpc_caller(chain: str, method: str, params: list[str]) -> dict[str, str]:
        assert chain == "ethereum"
        assert method == "eth_getTransactionReceipt"
        assert params == [tx_hash]
        return {"blockNumber": hex(20_000_001)}

    payload = build_replay_cohort(
        incidents_csv=incidents_csv,
        out=tmp_path / "cohort",
        min_cases=1,
        max_cases=1,
        evm_only=True,
        require_seed_transaction_hash=True,
        require_replay_block=True,
        rpc_supported_chains=["ethereum"],
        source_fetcher=lambda _url: {"status": "source_fetch_skipped:test"},
        rpc_caller=fake_rpc_caller,
    )

    assert payload["status"] == "passed"
    assert payload["case_count"] == 1
    manifest = json.loads((tmp_path / "cohort" / "manifest.json").read_text(encoding="utf-8"))
    case = manifest["cases"][0]
    assert case["security_anchor"] is False
    assert case["seed_transaction_hash"] == tx_hash
    assert case["fork_block"] == 20_000_001
    assert case["eligibility"] == "onchain_anchor_ready"
    assert case["pipeline_stages"]["security_evidence_enrichment"]["status"] == "reference_only"
    assert case["pipeline_stages"]["alchemy_onchain_backfill"]["status"] == "verified"


def test_replay_cohort_accepts_social_alert_after_abra_discovers_onchain_anchor(tmp_path, monkeypatch):
    monkeypatch.setenv("ABRA_ONCHAIN_ANCHOR_DISCOVERY", "1")
    tx_hash = "0x" + "c" * 64
    explorer_url = f"https://etherscan.io/tx/{tx_hash}"
    incidents_csv = tmp_path / "incidents.csv"
    _write_csv(
        incidents_csv,
        [
            _incident(
                1,
                target="Social Alert Cohort Candidate",
                reference_url="https://x.com/PeckShieldAlert/status/2035565047133401563",
                source_url="https://hacked.slowmist.io/?c=&page=1",
                seed_transaction_hash="",
                fork_block="",
                description="Ethereum exploit first referenced by an official security alert.",
            )
        ],
    )

    def fake_anchor_searcher(context: dict[str, str]) -> list[dict[str, str]]:
        assert context["target"] == "Social Alert Cohort Candidate"
        return [
            {
                "status": "fetched",
                "url": explorer_url,
                "text": f"Exploit transaction: {explorer_url}",
            }
        ]

    def fake_rpc_caller(chain: str, method: str, params: list[str]) -> dict[str, str]:
        assert chain == "ethereum"
        assert method == "eth_getTransactionReceipt"
        assert params == [tx_hash]
        return {"blockNumber": hex(20_000_004)}

    payload = build_replay_cohort(
        incidents_csv=incidents_csv,
        out=tmp_path / "cohort",
        min_cases=1,
        max_cases=1,
        evm_only=True,
        require_seed_transaction_hash=True,
        require_replay_block=True,
        rpc_supported_chains=["ethereum"],
        source_fetcher=lambda url: {"status": "source_fetch_skipped:social_api_required", "url": url, "text": ""},
        anchor_searcher=fake_anchor_searcher,
        rpc_caller=fake_rpc_caller,
    )

    assert payload["status"] == "passed"
    assert payload["case_count"] == 1
    manifest = json.loads((tmp_path / "cohort" / "manifest.json").read_text(encoding="utf-8"))
    case = manifest["cases"][0]
    assert case["security_anchor"] is True
    assert case["seed_transaction_hash"] == tx_hash
    assert case["fork_block"] == 20_000_004
    assert case["eligibility"] == "security_anchor_ready"
    assert case["pipeline_stages"]["alchemy_onchain_backfill"]["status"] == "verified"


def test_replay_cohort_does_not_treat_candidate_feed_as_security_evidence(tmp_path):
    incidents_csv = tmp_path / "incidents.csv"
    _write_csv(
        incidents_csv,
        [
            _incident(
                1,
                target="SlowMist Feed Only Candidate",
                reference_url="https://decrypt.co/358374/oracle-error-leaves-defi-lender-moonwell-1-8-million-bad-debt",
                source_url="https://hacked.slowmist.io/?c=&page=1",
                description="A DeFi lending protocol incurred bad debt due to an oracle configuration error.",
            )
        ],
    )

    payload = build_replay_cohort(
        incidents_csv=incidents_csv,
        out=tmp_path / "cohort",
        min_cases=1,
        max_cases=1,
        evm_only=True,
        require_seed_transaction_hash=False,
        require_replay_block=False,
        rpc_supported_chains=["ethereum"],
    )

    assert payload["status"] == "failed"
    assert payload["case_count"] == 0
    assert "insufficient_eligible_cases" in payload["errors"]

    exclusion_log = json.loads((tmp_path / "cohort" / "exclusion_log.json").read_text(encoding="utf-8"))
    entry = exclusion_log["entries"][0]
    assert entry["reason"] == "missing_security_anchor"
    assert entry["pipeline_stages"]["candidate_discovery"]["status"] == "accepted"
    assert entry["pipeline_stages"]["security_evidence_enrichment"]["status"] == "missing"
    assert entry["candidate_discovery_sources"] == [
        {
            "source": "slowmist_hacked",
            "url": "https://hacked.slowmist.io/?c=&page=1",
            "role": "candidate_discovery",
        }
    ]
    assert entry["security_report_sources"] == []


def test_replay_cohort_requires_security_source_url_not_only_description_mentions(tmp_path):
    incidents_csv = tmp_path / "incidents.csv"
    _write_csv(
        incidents_csv,
        [
            _incident(
                1,
                target="Mention Only Candidate",
                reference_url="https://decrypt.co/incident-with-security-company-mention",
                source_url="https://hacked.slowmist.io/?c=&page=1",
                description="Decrypt summarized a DeFi exploit and mentioned BlockSec and PeckShield in passing.",
            )
        ],
    )

    payload = build_replay_cohort(
        incidents_csv=incidents_csv,
        out=tmp_path / "cohort",
        min_cases=1,
        max_cases=1,
        evm_only=True,
        require_seed_transaction_hash=False,
        require_replay_block=False,
        rpc_supported_chains=["ethereum"],
    )

    assert payload["status"] == "failed"
    assert payload["case_count"] == 0
    exclusion_log = json.loads((tmp_path / "cohort" / "exclusion_log.json").read_text(encoding="utf-8"))
    entry = exclusion_log["entries"][0]
    assert entry["reason"] == "missing_security_anchor"
    assert entry["security_report_sources"] == []


def test_replay_cohort_uses_replay_results_only_as_fixture_metadata(tmp_path):
    incidents_csv = tmp_path / "incidents.csv"
    replay_results_csv = tmp_path / "replay_results.csv"
    event_cards_dir = tmp_path / "events"
    _write_csv(
        incidents_csv,
        [
            _incident(
                1,
                target="Anchored SlowMist Candidate",
                reference_url="https://hacked.slowmist.io/incidents/anchored-slowmist-candidate",
                source_url="https://hacked.slowmist.io/?c=&page=1",
                description="SlowMist reported an Ethereum oracle manipulation candidate.",
            )
        ],
    )
    _write_replay_results_csv(
        replay_results_csv,
        [
            {
                "incident": "Anchored SlowMist Candidate",
                "slug": "anchored-slowmist-candidate",
                "chain": "ethereum",
                "rpc_env": "ETH_RPC_URL",
                "attack_family": "oracle_manipulation",
                "loss_usd": 1_000_000,
                "fork_block": 17_000_001,
                "test_path": "test/replay/AnchoredSlowMistCandidate.t.sol",
                "replay_test": "test_AnchoredSlowMistCandidate",
                "metadata_test": "test_AnchoredSlowMistCandidateMetadata",
                "status": "verified",
                "metadata_status": "passed",
                "verified": "True",
            },
            {
                "incident": "Replay Only Fixture",
                "slug": "replay-only-fixture",
                "chain": "ethereum",
                "rpc_env": "ETH_RPC_URL",
                "attack_family": "flash_loan",
                "loss_usd": 2_000_000,
                "fork_block": 17_000_002,
                "test_path": "test/replay/ReplayOnlyFixture.t.sol",
                "replay_test": "test_ReplayOnlyFixture",
                "metadata_test": "test_ReplayOnlyFixtureMetadata",
                "status": "verified",
                "metadata_status": "passed",
                "verified": "True",
            },
        ],
    )
    _write_event_card(
        event_cards_dir / "2025-01-01_replay-only-fixture_abcdef01.md",
        slug="replay-only-fixture",
        incident="Replay Only Fixture",
        reference_url="https://hacked.slowmist.io/incidents/replay-only-fixture",
        fork_block=17_000_002,
    )

    payload = build_replay_cohort(
        incidents_csv=incidents_csv,
        replay_results_csv=replay_results_csv,
        event_cards_dir=event_cards_dir,
        out=tmp_path / "cohort",
        min_cases=1,
        max_cases=2,
        evm_only=True,
        require_seed_transaction_hash=False,
        require_replay_block=False,
        rpc_supported_chains=["ethereum"],
    )

    assert payload["status"] == "passed"
    assert payload["case_count"] == 1
    assert payload["quality"]["selected_replay_metadata_count"] == 0
    assert payload["quality"]["selected_fixture_metadata_attached_count"] == 1

    manifest = json.loads((tmp_path / "cohort" / "manifest.json").read_text(encoding="utf-8"))
    assert [case["slug"] for case in manifest["cases"]] == ["anchored-slowmist-candidate"]
    case = manifest["cases"][0]
    assert case["replay_test"] == "test_AnchoredSlowMistCandidate"
    assert case["test_path"] == "test/replay/AnchoredSlowMistCandidate.t.sol"
    assert case["fixture_result"]["status"] == "verified"
    assert case["eligibility"] == "security_anchor_with_replay_fixture"
    assert case["pipeline_stages"]["security_evidence_enrichment"]["status"] == "verified"
    assert case["pipeline_stages"]["replay_cohort_selection"]["fixture_metadata_attached"] is True


def test_replay_cohort_enriches_public_candidates_and_filters_by_supported_rpc_chain(tmp_path):
    incidents_csv = tmp_path / "incidents.csv"
    replay_results_csv = tmp_path / "replay_results.csv"
    event_cards_dir = tmp_path / "events"
    _write_csv(
        incidents_csv,
        [
            _incident(
                1,
                target="SlowMist Candidate",
                reference_url="https://hacked.slowmist.io/incidents/slowmist-candidate",
                source_url="https://hacked.slowmist.io/?c=&page=1",
                description="SlowMist reported an Ethereum oracle manipulation candidate.",
            ),
            _incident(
                2,
                target="CertiK Candidate",
                reference_url="https://www.certik.com/resources/blog/certik-candidate-postmortem",
                source_url="https://www.certik.com/resources/blog/certik-candidate-postmortem",
                description="CertiK reported an Ethereum flash-loan candidate.",
            ),
            _incident(
                3,
                target="Unsupported Polygon Candidate",
                reference_url="https://hacked.slowmist.io/incidents/polygon-candidate",
                source_url="https://hacked.slowmist.io/?c=&page=1",
                description="SlowMist reported a Polygon candidate.",
            ),
        ],
    )
    _write_replay_results_csv(
        replay_results_csv,
        [
            {
                "incident": f"Catalog Replay {index}",
                "slug": f"catalog-replay-{index}",
                "chain": "ethereum",
                "rpc_env": "ETH_RPC_URL",
                "attack_family": "oracle_manipulation",
                "loss_usd": 1_000_000 + index,
                "fork_block": 17_000_000 + index,
                "test_path": f"test/replay/CatalogReplay{index}.t.sol",
                "replay_test": f"test_CatalogReplay{index}",
                "metadata_test": f"test_CatalogReplay{index}Metadata",
                "status": "no_rpc",
                "metadata_status": "passed",
                "blocker": "ETH_RPC_URL not configured",
                "verified": "False",
            }
            for index in range(1, 10)
        ],
    )
    for index in range(1, 10):
        slug = f"catalog-replay-{index}"
        _write_event_card(
            event_cards_dir / f"2025-01-01_{slug}_abcdef{index}.md",
            slug=slug,
            incident=f"Catalog Replay {index}",
            reference_url=f"https://hacked.slowmist.io/incidents/{slug}",
            fork_block=17_000_000 + index,
        )

    payload = build_replay_cohort(
        incidents_csv=incidents_csv,
        replay_results_csv=replay_results_csv,
        event_cards_dir=event_cards_dir,
        out=tmp_path / "cohort",
        min_cases=10,
        max_cases=10,
        evm_only=True,
        require_seed_transaction_hash=True,
        require_replay_block=True,
        rpc_supported_chains=["ethereum"],
    )

    assert payload["status"] == "failed"
    assert payload["case_count"] == 2
    assert payload["quality"]["selected_replay_metadata_count"] == 0
    assert payload["quality"]["selected_security_report_count"] == 2
    assert payload["quality"]["selected_fixture_metadata_attached_count"] == 0
    assert payload["quality"]["selected_rpc_supported_count"] == 2
    assert payload["quality"]["missing_seed_transaction_hash_count"] == 2
    assert "insufficient_eligible_cases" in payload["errors"]
    assert "selected_cases_include_diagnostic_evidence_boundaries" in payload["warnings"]

    manifest = json.loads((tmp_path / "cohort" / "manifest.json").read_text(encoding="utf-8"))
    assert manifest["case_count"] == 2
    assert {case["slug"] for case in manifest["cases"]} == {"slowmist-candidate", "certik-candidate"}
    eligibilities = {case["eligibility"] for case in manifest["cases"]}
    assert eligibilities == {"security_anchor_backfill_required"}
    assert {case["chain"] for case in manifest["cases"]} == {"ethereum"}
    assert all(case["rpc_supported"] is True for case in manifest["cases"])
    assert all(case["security_report_sources"] for case in manifest["cases"])
    assert all(case["evidence_level_target"] == "L1" for case in manifest["cases"])
    assert all(
        case["pipeline_stages"]["alchemy_onchain_backfill"]["status"] == "required"
        for case in manifest["cases"]
    )
    exclusion_log = json.loads((tmp_path / "cohort" / "exclusion_log.json").read_text(encoding="utf-8"))
    excluded = {(entry["slug"], entry["reason"]) for entry in exclusion_log["entries"]}
    assert ("unsupported-polygon-candidate", "rpc_chain_unsupported") in excluded
    assert ("catalog-replay-1", "missing_security_anchor") not in excluded


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
            "--rpc-supported-chain",
            "ethereum",
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
    assert (out / "stage_ledger.json").exists()
    assert len(list((out / "cases").glob("*.json"))) == 10


def test_replay_cohort_cli_accepts_explicit_no_backfill_switch(tmp_path):
    incidents_csv = tmp_path / "incidents.csv"
    _write_csv(
        incidents_csv,
        [
            _incident(
                1,
                target="Strict Complete Candidate",
                seed_transaction_hash="0x" + "1" * 64,
                fork_block=17_000_000,
            )
        ],
    )
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
            "1",
            "--max-cases",
            "1",
            "--no-security-anchor-backfill",
            "--rpc-supported-chain",
            "ethereum",
            "--json",
        ],
        check=False,
        capture_output=True,
        text=True,
    )

    assert result.returncode == 0, result.stderr
    payload = json.loads(result.stdout)
    assert payload["status"] == "passed"
    assert payload["case_count"] == 1
