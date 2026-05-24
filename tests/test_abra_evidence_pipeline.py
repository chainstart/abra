from __future__ import annotations

import csv
import importlib.util
import json
import subprocess
import sys
from pathlib import Path

import pytest

from abra.chain_support import rpc_url_for_chain
from abra.evidence_pipeline import produce_evidence_pipeline


@pytest.fixture(autouse=True)
def _disable_live_anchor_discovery_by_default(monkeypatch):
    monkeypatch.setenv("ABRA_ONCHAIN_ANCHOR_DISCOVERY", "0")


def _write_incidents_csv(path: Path, rows: list[dict[str, object]]) -> None:
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
        "chain",
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


def _read_csv(path: Path) -> list[dict[str, str]]:
    with path.open("r", encoding="utf-8", newline="") as fp:
        return list(csv.DictReader(fp))


def _load_pipeline_module(name: str):
    path = Path(__file__).resolve().parents[1] / "tools" / "pipeline" / f"{name}.py"
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.path.insert(0, str(path.parent))
    try:
        spec.loader.exec_module(module)
    finally:
        sys.path.pop(0)
    return module


def _incident(index: int, **overrides: object) -> dict[str, object]:
    row: dict[str, object] = {
        "incident_id": f"incident-{index:02d}",
        "event_date": f"2026-02-{index:02d}",
        "target": f"Fixture Protocol {index}",
        "protocol_slug_guess": f"fixture-protocol-{index}",
        "is_defi": "true",
        "attack_method_raw": "Oracle Manipulation",
        "attack_family": "oracle_manipulation",
        "loss_usd_raw": "$ 1,000,000",
        "loss_usd": str(1_000_000 + index),
        "chain": "ethereum",
        "reference_url": f"https://www.certik.com/resources/blog/fixture-protocol-{index}",
        "source_url": "https://hacked.slowmist.io/?c=&page=1",
        "source_page": "1",
        "category_filter": "all",
        "description": f"Fixture Protocol {index} suffered a DeFi exploit on Ethereum.",
        "normalized_at": "2026-05-24T00:00:00Z",
    }
    row.update(overrides)
    return row


def test_evidence_pipeline_materializes_security_enrichment_and_alchemy_backfill(tmp_path, monkeypatch):
    monkeypatch.setenv("ALCHEMY_API_KEY", "alchemy-test-key")
    incidents_csv = tmp_path / "incidents_normalized_latest.csv"
    out_dir = tmp_path / "processed"
    _write_incidents_csv(
        incidents_csv,
        [
            _incident(
                1,
                target="CertiK Anchored Missing Onchain",
                reference_url="https://www.certik.com/resources/blog/certik-anchored-missing-onchain-postmortem",
                source_url="https://hacked.slowmist.io/?c=&page=1",
                seed_transaction_hash="",
                fork_block="",
            ),
            _incident(
                2,
                target="BlockSec Complete Anchor",
                reference_url="https://blocksec.com/blog/blocksec-complete-anchor-analysis",
                source_url="https://defillama.com/hacks",
                seed_transaction_hash="0x" + "2" * 64,
                fork_block="19000000",
            ),
            _incident(
                3,
                target="SlowMist Feed Only",
                reference_url="https://decrypt.co/incident-with-security-company-mention",
                source_url="https://hacked.slowmist.io/?c=&page=2",
                description="Decrypt mentioned BlockSec and PeckShield, but the URL is not an anchored security report.",
            ),
        ],
    )

    payload = produce_evidence_pipeline(
        incidents_csv=incidents_csv,
        out_dir=out_dir,
        rpc_supported_chains=["ethereum"],
    )

    assert payload["schema_version"] == "abra.evidence_pipeline.v1"
    assert payload["status"] == "passed"
    assert payload["summary"]["candidate_count"] == 3
    assert payload["summary"]["security_anchored_count"] == 2
    assert payload["summary"]["alchemy_backfill_candidate_count"] == 3
    assert payload["artifacts"] == {
        "security_evidence_csv": "security_evidence_enriched_latest.csv",
        "security_evidence_json": "security_evidence_enriched_latest.json",
        "alchemy_backfill_csv": "alchemy_onchain_backfill_latest.csv",
        "alchemy_backfill_json": "alchemy_onchain_backfill_latest.json",
    }

    enriched_rows = _read_csv(out_dir / "security_evidence_enriched_latest.csv")
    enriched_by_slug = {row["slug"]: row for row in enriched_rows}
    assert enriched_by_slug["certik-anchored-missing-onchain"]["security_anchor"] == "true"
    assert json.loads(enriched_by_slug["certik-anchored-missing-onchain"]["security_report_sources"]) == [
        {
            "source": "certik",
            "url": "https://www.certik.com/resources/blog/certik-anchored-missing-onchain-postmortem",
        }
    ]
    assert json.loads(enriched_by_slug["blocksec-complete-anchor"]["candidate_discovery_sources"]) == [
        {"role": "candidate_discovery", "source": "defillama_hacks", "url": "https://defillama.com/hacks"}
    ]
    assert enriched_by_slug["slowmist-feed-only"]["security_anchor"] == "false"
    assert set(enriched_by_slug["slowmist-feed-only"]["evidence_gap"].split("|")) == {
        "missing_security_anchor",
        "missing_seed_transaction_hash",
        "missing_replay_block",
    }
    assert json.loads(enriched_by_slug["slowmist-feed-only"]["security_report_sources"]) == []

    backfill_rows = _read_csv(out_dir / "alchemy_onchain_backfill_latest.csv")
    assert {row["slug"] for row in backfill_rows} == {
        "certik-anchored-missing-onchain",
        "blocksec-complete-anchor",
        "slowmist-feed-only",
    }
    backfill_by_slug = {row["slug"]: row for row in backfill_rows}
    assert backfill_by_slug["certik-anchored-missing-onchain"]["backfill_status"] == "missing_onchain_anchor"
    assert backfill_by_slug["certik-anchored-missing-onchain"]["rpc_supported"] == "true"
    assert backfill_by_slug["blocksec-complete-anchor"]["backfill_status"] == "not_required"
    assert backfill_by_slug["blocksec-complete-anchor"]["seed_transaction_hash"] == "0x" + "2" * 64
    assert backfill_by_slug["slowmist-feed-only"]["security_anchor"] == "false"
    assert backfill_by_slug["slowmist-feed-only"]["backfill_status"] == "missing_onchain_anchor"

    enriched_json = json.loads((out_dir / "security_evidence_enriched_latest.json").read_text(encoding="utf-8"))
    assert enriched_json["stage"] == "security_evidence_enrichment"
    assert enriched_json["summary"]["text_only_security_mentions_ignored_count"] == 1

    backfill_json = json.loads((out_dir / "alchemy_onchain_backfill_latest.json").read_text(encoding="utf-8"))
    assert backfill_json["stage"] == "alchemy_onchain_backfill"
    assert backfill_json["rpc_capability"]["provider"] == "alchemy"
    assert backfill_json["summary"]["backfill_candidate_count"] == 3
    assert backfill_json["summary"]["security_anchored_backfill_count"] == 2
    assert backfill_json["summary"]["reference_only_backfill_count"] == 1
    assert backfill_json["summary"]["unanchored_skipped_count"] == 1


def test_evidence_pipeline_cli_round_trip(tmp_path):
    incidents_csv = tmp_path / "incidents_normalized_latest.csv"
    out_dir = tmp_path / "processed"
    _write_incidents_csv(
        incidents_csv,
        [
            _incident(
                1,
                reference_url="https://peckshield.com/en/security-audit/fixture-incident",
                seed_transaction_hash="0x" + "1" * 64,
                fork_block="18000000",
            )
        ],
    )

    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "abra",
            "evidence",
            "produce",
            "--incidents-csv",
            str(incidents_csv),
            "--out-dir",
            str(out_dir),
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
    assert (out_dir / "security_evidence_enriched_latest.csv").exists()
    assert (out_dir / "alchemy_onchain_backfill_latest.csv").exists()


def test_evidence_pipeline_uses_broad_alchemy_supported_chain_boundary(tmp_path, monkeypatch):
    monkeypatch.setenv("ALCHEMY_API_KEY", "alchemy-test-key")
    incidents_csv = tmp_path / "incidents_normalized_latest.csv"
    out_dir = tmp_path / "processed"
    _write_incidents_csv(
        incidents_csv,
        [
            _incident(
                1,
                target="Astar Candidate",
                chain="Astar",
                reference_url="https://blocksec.com/blog/astar-candidate-analysis",
            ),
            _incident(
                2,
                target="Rootstock Candidate",
                chain="Rootstock",
                reference_url="https://peckshield.com/en/security-audit/rootstock-candidate",
            ),
        ],
    )

    payload = produce_evidence_pipeline(incidents_csv=incidents_csv, out_dir=out_dir)

    assert payload["status"] == "passed"
    rows = _read_csv(out_dir / "alchemy_onchain_backfill_latest.csv")
    assert {row["chain"] for row in rows} == {"astar", "rootstock"}
    assert {row["backfill_status"] for row in rows} == {"missing_onchain_anchor"}
    assert all(row["rpc_supported"] == "true" for row in rows)


def test_evidence_pipeline_accepts_official_security_alert_x_accounts_only(tmp_path):
    incidents_csv = tmp_path / "incidents_normalized_latest.csv"
    out_dir = tmp_path / "processed"
    _write_incidents_csv(
        incidents_csv,
        [
            _incident(
                1,
                target="PeckShield Alert Candidate",
                reference_url="https://x.com/PeckShieldAlert/status/2035565047133401563",
                source_url="https://hacked.slowmist.io/?c=&page=1",
                description="PeckShield alerted on X about suspicious minting activity.",
            ),
            _incident(
                2,
                target="Random X Candidate",
                reference_url="https://x.com/random_user/status/2035565047133401563",
                source_url="https://hacked.slowmist.io/?c=&page=1",
                description="A random user mentioned PeckShield in passing.",
            ),
        ],
    )

    produce_evidence_pipeline(
        incidents_csv=incidents_csv,
        out_dir=out_dir,
        rpc_supported_chains=["ethereum"],
    )

    rows = {row["slug"]: row for row in _read_csv(out_dir / "security_evidence_enriched_latest.csv")}
    peckshield_sources = json.loads(rows["peckshield-alert-candidate"]["security_report_sources"])
    assert peckshield_sources == [
        {"source": "peckshield", "url": "https://x.com/PeckShieldAlert/status/2035565047133401563"}
    ]
    assert rows["peckshield-alert-candidate"]["security_anchor"] == "true"
    assert rows["random-x-candidate"]["security_anchor"] == "false"
    assert json.loads(rows["random-x-candidate"]["security_report_sources"]) == []


def test_evidence_pipeline_backfills_tx_hash_and_block_from_security_source_and_alchemy(tmp_path, monkeypatch):
    monkeypatch.setenv("ALCHEMY_API_KEY", "alchemy-test-key")
    tx_hash = "0x" + "a" * 64
    source_url = "https://www.certik.com/resources/blog/backfill-candidate-postmortem"
    incidents_csv = tmp_path / "incidents_normalized_latest.csv"
    out_dir = tmp_path / "processed"
    _write_incidents_csv(
        incidents_csv,
        [
            _incident(
                1,
                target="Backfill Candidate",
                reference_url=source_url,
                source_url="https://hacked.slowmist.io/?c=&page=1",
                seed_transaction_hash="",
                fork_block="",
            ),
        ],
    )

    fetched_urls: list[str] = []
    rpc_calls: list[tuple[str, str, list[str]]] = []

    def fake_source_fetcher(url: str) -> dict[str, str]:
        fetched_urls.append(url)
        return {
            "status": "fetched",
            "url": url,
            "text": f"CertiK identified the exploit transaction as {tx_hash}.",
        }

    def fake_rpc_caller(chain: str, method: str, params: list[str]) -> dict[str, str]:
        rpc_calls.append((chain, method, params))
        assert chain == "ethereum"
        assert method == "eth_getTransactionReceipt"
        assert params == [tx_hash]
        return {"blockNumber": hex(19_012_345)}

    produce_evidence_pipeline(
        incidents_csv=incidents_csv,
        out_dir=out_dir,
        rpc_supported_chains=["ethereum"],
        source_fetcher=fake_source_fetcher,
        rpc_caller=fake_rpc_caller,
    )

    rows = _read_csv(out_dir / "alchemy_onchain_backfill_latest.csv")
    assert len(rows) == 1
    row = rows[0]
    assert fetched_urls == [source_url]
    assert rpc_calls == [("ethereum", "eth_getTransactionReceipt", [tx_hash])]
    assert row["backfill_status"] == "backfilled_onchain_anchor"
    assert row["seed_transaction_hash"] == tx_hash
    assert row["fork_block"] == "19012345"
    assert row["source_fetch_status"] == "fetched"
    assert row["source_evidence_url"] == source_url
    assert row["source_extracted_seed_transaction_hash"] == tx_hash
    assert row["rpc_backfill_status"] == "receipt_verified"

    payload = json.loads((out_dir / "alchemy_onchain_backfill_latest.json").read_text(encoding="utf-8"))
    assert payload["summary"]["backfilled_onchain_anchor_count"] == 1
    assert payload["summary"]["onchain_anchor_complete_count"] == 1


def test_evidence_pipeline_backfills_reference_tx_without_security_source_anchor(tmp_path, monkeypatch):
    monkeypatch.setenv("ALCHEMY_API_KEY", "alchemy-test-key")
    tx_hash = "0x" + "b" * 64
    incidents_csv = tmp_path / "incidents_normalized_latest.csv"
    out_dir = tmp_path / "processed"
    _write_incidents_csv(
        incidents_csv,
        [
            _incident(
                1,
                target="Reference Only Onchain Candidate",
                reference_url=f"https://example.org/incidents/reference-only?tx={tx_hash}",
                source_url="https://defillama.com/hacks",
                seed_transaction_hash="",
                fork_block="",
                description="Reference-only report with a direct transaction anchor.",
            ),
        ],
    )

    def fake_rpc_caller(chain: str, method: str, params: list[str]) -> dict[str, str]:
        assert chain == "ethereum"
        assert method == "eth_getTransactionReceipt"
        assert params == [tx_hash]
        return {"blockNumber": hex(20_000_001)}

    produce_evidence_pipeline(
        incidents_csv=incidents_csv,
        out_dir=out_dir,
        rpc_supported_chains=["ethereum"],
        source_fetcher=lambda _url: {"status": "source_fetch_skipped:test"},
        rpc_caller=fake_rpc_caller,
    )

    rows = _read_csv(out_dir / "alchemy_onchain_backfill_latest.csv")
    assert len(rows) == 1
    assert rows[0]["security_anchor"] == "false"
    assert rows[0]["backfill_status"] == "backfilled_onchain_anchor"
    assert rows[0]["seed_transaction_hash"] == tx_hash
    assert rows[0]["fork_block"] == "20000001"
    assert rows[0]["rpc_backfill_status"] == "receipt_verified"


def test_evidence_pipeline_uses_target_context_when_extracting_weekly_roundup_tx_hashes(tmp_path):
    squid_tx = "0x" + "1" * 64
    sas_tx = "0x" + "2" * 64
    incidents_csv = tmp_path / "incidents_normalized_latest.csv"
    out_dir = tmp_path / "processed"
    report_url = "https://blocksec.com/blog/weekly-web3-security-incident-roundup-fixture"
    _write_incidents_csv(
        incidents_csv,
        [
            _incident(
                1,
                target="Squid Multicall",
                reference_url=report_url,
                seed_transaction_hash="",
                fork_block="",
            ),
            _incident(
                2,
                target="SAS Token",
                chain="bsc",
                reference_url=report_url,
                seed_transaction_hash="",
                fork_block="",
            ),
        ],
    )

    def fake_source_fetcher(_url: str) -> dict[str, str]:
        return {
            "status": "fetched",
            "url": report_url,
            "text": (
                f"Squid Multicall exploit transaction: {squid_tx}. "
                "Additional details on Ethereum. "
                f"SAS Token attacker transaction: {sas_tx}. "
                "Additional details on BNB Chain."
            ),
        }

    def fake_rpc_caller(_chain: str, _method: str, _params: list[str]) -> dict[str, str]:
        return {"error": "offline_test"}

    produce_evidence_pipeline(
        incidents_csv=incidents_csv,
        out_dir=out_dir,
        rpc_supported_chains=["ethereum", "bsc"],
        source_fetcher=fake_source_fetcher,
        rpc_caller=fake_rpc_caller,
    )

    rows = {row["slug"]: row for row in _read_csv(out_dir / "alchemy_onchain_backfill_latest.csv")}
    assert rows["squid-multicall"]["seed_transaction_hash"] == squid_tx
    assert rows["sas-token"]["seed_transaction_hash"] == sas_tx


def test_evidence_pipeline_extracts_explorer_tx_links_from_reference_pages(tmp_path, monkeypatch):
    monkeypatch.setenv("ALCHEMY_API_KEY", "alchemy-test-key")
    tx_hash = "0x" + "c" * 64
    report_url = "https://example.org/reports/explorer-link-candidate"
    incidents_csv = tmp_path / "incidents_normalized_latest.csv"
    out_dir = tmp_path / "processed"
    _write_incidents_csv(
        incidents_csv,
        [
            _incident(
                1,
                target="Explorer Link Candidate",
                reference_url=report_url,
                source_url="https://defillama.com/hacks",
                seed_transaction_hash="",
                fork_block="",
            ),
        ],
    )

    def fake_source_fetcher(url: str) -> dict[str, str]:
        assert url == report_url
        return {
            "status": "fetched",
            "url": url,
            "text": f'Attack transaction: <a href="https://etherscan.io/tx/{tx_hash}">exploit tx</a>',
        }

    def fake_rpc_caller(_chain: str, _method: str, _params: list[str]) -> dict[str, str]:
        return {"blockNumber": hex(20_000_002)}

    produce_evidence_pipeline(
        incidents_csv=incidents_csv,
        out_dir=out_dir,
        rpc_supported_chains=["ethereum"],
        source_fetcher=fake_source_fetcher,
        rpc_caller=fake_rpc_caller,
    )

    rows = _read_csv(out_dir / "alchemy_onchain_backfill_latest.csv")
    assert len(rows) == 1
    assert rows[0]["security_anchor"] == "false"
    assert rows[0]["seed_transaction_hash"] == tx_hash
    assert rows[0]["fork_block"] == "20000002"


def test_evidence_pipeline_does_not_live_fetch_generic_reference_pages_without_tx_hint(tmp_path, monkeypatch):
    monkeypatch.setenv("ALCHEMY_API_KEY", "alchemy-test-key")
    monkeypatch.setenv("ABRA_REFERENCE_FETCH_BUDGET", "0")
    incidents_csv = tmp_path / "incidents_normalized_latest.csv"
    out_dir = tmp_path / "processed"
    _write_incidents_csv(
        incidents_csv,
        [
            _incident(
                1,
                target="Generic News Candidate",
                reference_url="https://example.org/news/generic-defi-incident",
                source_url="https://defillama.com/hacks",
                seed_transaction_hash="",
                fork_block="",
            ),
        ],
    )

    def fail_if_fetched(url: str) -> dict[str, str]:
        raise AssertionError(f"generic reference should not be live-fetched by default: {url}")

    produce_evidence_pipeline(
        incidents_csv=incidents_csv,
        out_dir=out_dir,
        rpc_supported_chains=["ethereum"],
        source_fetcher=fail_if_fetched,
    )

    rows = _read_csv(out_dir / "alchemy_onchain_backfill_latest.csv")
    assert len(rows) == 1
    assert rows[0]["source_fetch_status"] == "source_fetch_skipped:no_tx_hint"
    assert rows[0]["backfill_status"] == "missing_onchain_anchor"


def test_evidence_pipeline_skips_default_live_fetch_for_social_alert_urls(tmp_path, monkeypatch):
    monkeypatch.setenv("ALCHEMY_API_KEY", "alchemy-test-key")
    incidents_csv = tmp_path / "incidents_normalized_latest.csv"
    out_dir = tmp_path / "processed"
    _write_incidents_csv(
        incidents_csv,
        [
            _incident(
                1,
                target="Social Alert Candidate",
                reference_url="https://x.com/PeckShieldAlert/status/2035565047133401563",
                source_url="https://hacked.slowmist.io/?c=&page=1",
                seed_transaction_hash="",
                fork_block="",
            ),
        ],
    )

    produce_evidence_pipeline(
        incidents_csv=incidents_csv,
        out_dir=out_dir,
        rpc_supported_chains=["ethereum"],
    )

    rows = _read_csv(out_dir / "alchemy_onchain_backfill_latest.csv")
    assert len(rows) == 1
    assert rows[0]["security_anchor"] == "true"
    assert rows[0]["backfill_status"] == "missing_onchain_anchor"
    assert rows[0]["source_fetch_status"] == "source_fetch_skipped:social_api_required"
    assert rows[0]["source_evidence_url"] == ""
    assert rows[0]["rpc_backfill_status"] == "not_attempted"


def test_evidence_pipeline_discovers_tx_anchor_after_social_alert_fetch_is_skipped(tmp_path, monkeypatch):
    monkeypatch.setenv("ALCHEMY_API_KEY", "alchemy-test-key")
    monkeypatch.setenv("ABRA_ONCHAIN_ANCHOR_DISCOVERY", "1")
    tx_hash = "0x" + "d" * 64
    alert_url = "https://x.com/PeckShieldAlert/status/2035565047133401563"
    explorer_url = f"https://etherscan.io/tx/{tx_hash}"
    incidents_csv = tmp_path / "incidents_normalized_latest.csv"
    out_dir = tmp_path / "processed"
    _write_incidents_csv(
        incidents_csv,
        [
            _incident(
                1,
                target="Social Alert Needs Onchain Anchor",
                reference_url=alert_url,
                source_url="https://hacked.slowmist.io/?c=&page=1",
                seed_transaction_hash="",
                fork_block="",
            ),
        ],
    )

    def fake_source_fetcher(url: str) -> dict[str, str]:
        assert url == alert_url
        return {"status": "source_fetch_skipped:social_api_required", "url": url, "text": ""}

    def fake_anchor_searcher(context: dict[str, str]) -> list[dict[str, str]]:
        assert context["target"] == "Social Alert Needs Onchain Anchor"
        return [
            {
                "status": "fetched",
                "query": "Social Alert Needs Onchain Anchor exploit transaction",
                "url": explorer_url,
                "text": f"Exploit transaction: {explorer_url}",
            }
        ]

    def fake_rpc_caller(chain: str, method: str, params: list[str]) -> dict[str, str]:
        assert chain == "ethereum"
        assert method == "eth_getTransactionReceipt"
        assert params == [tx_hash]
        return {"blockNumber": hex(20_000_003)}

    produce_evidence_pipeline(
        incidents_csv=incidents_csv,
        out_dir=out_dir,
        rpc_supported_chains=["ethereum"],
        source_fetcher=fake_source_fetcher,
        anchor_searcher=fake_anchor_searcher,
        rpc_caller=fake_rpc_caller,
    )

    rows = _read_csv(out_dir / "alchemy_onchain_backfill_latest.csv")
    assert len(rows) == 1
    row = rows[0]
    assert row["security_anchor"] == "true"
    assert row["source_fetch_status"] == "source_fetch_skipped:social_api_required"
    assert row["anchor_discovery_status"] == "discovered"
    assert row["anchor_discovery_url"] == explorer_url
    assert row["anchor_discovery_seed_transaction_hash"] == tx_hash
    assert row["seed_transaction_hash"] == tx_hash
    assert row["fork_block"] == "20000003"
    assert row["rpc_backfill_status"] == "receipt_verified"
    assert row["backfill_status"] == "backfilled_onchain_anchor"

    payload = json.loads((out_dir / "alchemy_onchain_backfill_latest.json").read_text(encoding="utf-8"))
    assert payload["summary"]["anchor_discovered_count"] == 1
    assert payload["summary"]["onchain_anchor_complete_count"] == 1


def test_evidence_pipeline_uses_alchemy_receipt_before_anchor_discovery_when_seed_tx_exists(tmp_path, monkeypatch):
    monkeypatch.setenv("ALCHEMY_API_KEY", "alchemy-test-key")
    monkeypatch.setenv("ABRA_ONCHAIN_ANCHOR_DISCOVERY", "1")
    tx_hash = "0x" + "e" * 64
    alert_url = "https://x.com/PeckShieldAlert/status/2035565047133401563"
    incidents_csv = tmp_path / "incidents_normalized_latest.csv"
    out_dir = tmp_path / "processed"
    _write_incidents_csv(
        incidents_csv,
        [
            _incident(
                1,
                target="Seed Tx Only Candidate",
                reference_url=alert_url,
                source_url="https://hacked.slowmist.io/?c=&page=1",
                seed_transaction_hash=tx_hash,
                fork_block="",
            ),
        ],
    )

    def fail_if_search_called(context: dict[str, str]) -> list[dict[str, str]]:
        raise AssertionError(f"anchor discovery should not run when seed tx is enough for RPC: {context}")

    def fake_rpc_caller(chain: str, method: str, params: list[str]) -> dict[str, str]:
        assert chain == "ethereum"
        assert method == "eth_getTransactionReceipt"
        assert params == [tx_hash]
        return {"blockNumber": hex(20_000_005)}

    produce_evidence_pipeline(
        incidents_csv=incidents_csv,
        out_dir=out_dir,
        rpc_supported_chains=["ethereum"],
        source_fetcher=lambda url: {"status": "source_fetch_skipped:social_api_required", "url": url, "text": ""},
        anchor_searcher=fail_if_search_called,
        rpc_caller=fake_rpc_caller,
    )

    rows = _read_csv(out_dir / "alchemy_onchain_backfill_latest.csv")
    assert len(rows) == 1
    row = rows[0]
    assert row["seed_transaction_hash"] == tx_hash
    assert row["fork_block"] == "20000005"
    assert row["rpc_backfill_status"] == "receipt_verified"
    assert row["anchor_discovery_status"] == "not_required"


def test_evidence_pipeline_records_explorer_url_from_anchor_search_result_text(tmp_path, monkeypatch):
    monkeypatch.setenv("ALCHEMY_API_KEY", "alchemy-test-key")
    monkeypatch.setenv("ABRA_ONCHAIN_ANCHOR_DISCOVERY", "1")
    tx_hash = "0x" + "f" * 64
    explorer_url = f"https://etherscan.io/tx/{tx_hash}"
    search_url = "https://duckduckgo.com/html/?q=fixture"
    incidents_csv = tmp_path / "incidents_normalized_latest.csv"
    out_dir = tmp_path / "processed"
    _write_incidents_csv(
        incidents_csv,
        [
            _incident(
                1,
                target="Explorer Url From Search Text",
                reference_url="https://x.com/PeckShieldAlert/status/2035565047133401563",
                source_url="https://hacked.slowmist.io/?c=&page=1",
                seed_transaction_hash="",
                fork_block="",
            ),
        ],
    )

    def fake_anchor_searcher(_context: dict[str, str]) -> list[dict[str, str]]:
        return [
            {
                "status": "fetched",
                "url": search_url,
                "text": f'Result link: <a href="{explorer_url}">exploit tx</a>',
            }
        ]

    produce_evidence_pipeline(
        incidents_csv=incidents_csv,
        out_dir=out_dir,
        rpc_supported_chains=["ethereum"],
        source_fetcher=lambda url: {"status": "source_fetch_skipped:social_api_required", "url": url, "text": ""},
        anchor_searcher=fake_anchor_searcher,
        rpc_caller=lambda *_args: {"blockNumber": hex(20_000_006)},
    )

    rows = _read_csv(out_dir / "alchemy_onchain_backfill_latest.csv")
    assert rows[0]["anchor_discovery_url"] == explorer_url
    assert rows[0]["anchor_discovery_seed_transaction_hash"] == tx_hash


def test_evidence_pipeline_can_disable_live_security_source_fetch(tmp_path, monkeypatch):
    monkeypatch.setenv("ALCHEMY_API_KEY", "alchemy-test-key")
    monkeypatch.setenv("ABRA_EVIDENCE_SOURCE_FETCH", "0")
    incidents_csv = tmp_path / "incidents_normalized_latest.csv"
    out_dir = tmp_path / "processed"
    _write_incidents_csv(
        incidents_csv,
        [
            _incident(
                1,
                target="Offline Fetch Candidate",
                reference_url="https://blocksec.com/blog/offline-fetch-candidate",
                seed_transaction_hash="",
                fork_block="",
            ),
        ],
    )

    produce_evidence_pipeline(
        incidents_csv=incidents_csv,
        out_dir=out_dir,
        rpc_supported_chains=["ethereum"],
    )

    rows = _read_csv(out_dir / "alchemy_onchain_backfill_latest.csv")
    assert len(rows) == 1
    assert rows[0]["source_fetch_status"] == "source_fetch_skipped:disabled"
    assert rows[0]["rpc_backfill_status"] == "not_attempted"


def test_alchemy_rpc_url_derivation_prefers_unified_api_key_over_legacy_rpc_env(monkeypatch):
    monkeypatch.setenv("ALCHEMY_API_KEY", "alchemy-test-key")
    monkeypatch.setenv("ETH_RPC_URL", "https://mainnet.infura.io/v3/legacy-key")
    monkeypatch.setenv("BSC_RPC_URL", "https://bsc-mainnet.infura.io/v3/legacy-key")

    assert rpc_url_for_chain("ethereum") == "https://eth-mainnet.g.alchemy.com/v2/alchemy-test-key"
    assert rpc_url_for_chain("bsc") == "https://bnb-mainnet.g.alchemy.com/v2/alchemy-test-key"


def test_defillama_collector_persists_hack_candidates(tmp_path, monkeypatch):
    collector = _load_pipeline_module("defillama_collector")

    def fake_fetch_json(_session, url: str):
        if url == collector.CHAIN_URL:
            return [{"name": "Ethereum", "chainId": 1, "tokenSymbol": "ETH", "tvl": 100}]
        if url == collector.PROTOCOLS_URL:
            return [{"id": 1, "name": "Fixture Protocol", "slug": "fixture-protocol", "tvl": 100, "chains": ["Ethereum"]}]
        if url == collector.HACKS_URL:
            return [
                {
                    "date": 1711065600,
                    "name": "Fixture Protocol",
                    "classification": "Protocol Logic",
                    "technique": "Oracle Manipulation",
                    "amount": 4800000,
                    "chain": ["Ethereum"],
                    "targetType": "DeFi Protocol",
                    "source": "https://blocksec.com/blog/fixture-protocol-analysis",
                    "language": "Solidity",
                }
            ]
        raise AssertionError(url)

    monkeypatch.setattr(collector, "fetch_json", fake_fetch_json)
    summary = collector.collect_defillama(output_dir=tmp_path, top_n=10)

    assert summary["hack_count"] == 1
    hacks_csv = tmp_path / "defillama_hacks_latest.csv"
    rows = _read_csv(hacks_csv)
    assert rows[0]["target"] == "Fixture Protocol"
    assert rows[0]["source_url"] == "https://defillama.com/hacks"
    assert rows[0]["reference_url"] == "https://blocksec.com/blog/fixture-protocol-analysis"


def test_normalize_merges_slowmist_and_defillama_hack_candidates(tmp_path):
    normalize = _load_pipeline_module("normalize")
    slowmist_csv = tmp_path / "slowmist.csv"
    protocols_csv = tmp_path / "protocols.csv"
    hacks_csv = tmp_path / "hacks.csv"
    output_dir = tmp_path / "processed"

    with slowmist_csv.open("w", encoding="utf-8", newline="") as fp:
        writer = csv.DictWriter(
            fp,
            fieldnames=[
                "incident_id",
                "event_date",
                "target",
                "description",
                "loss_usd_raw",
                "loss_usd",
                "attack_method",
                "reference_url",
                "source_url",
                "source_page",
                "category_filter",
                "collected_at",
            ],
        )
        writer.writeheader()
        writer.writerow(
            {
                "incident_id": "slowmist-1",
                "event_date": "2026-01-01",
                "target": "SlowMist Candidate",
                "description": "Ethereum lending protocol oracle manipulation.",
                "loss_usd_raw": "$1,000,000",
                "loss_usd": "1000000",
                "attack_method": "Oracle Manipulation",
                "reference_url": "https://www.certik.com/resources/blog/slowmist-candidate",
                "source_url": "https://hacked.slowmist.io/?c=&page=1",
                "source_page": "1",
                "category_filter": "all",
                "collected_at": "2026-05-24T00:00:00Z",
            }
        )
    with protocols_csv.open("w", encoding="utf-8", newline="") as fp:
        writer = csv.DictWriter(fp, fieldnames=["id", "name", "slug", "category", "tvl", "chain", "chains_count", "chains"])
        writer.writeheader()
        writer.writerow(
            {
                "id": "1",
                "name": "DefiLlama Candidate",
                "slug": "defillama-candidate",
                "category": "Lending",
                "tvl": "100",
                "chain": "Ethereum",
                "chains_count": "1",
                "chains": "Ethereum",
            }
        )
    with hacks_csv.open("w", encoding="utf-8", newline="") as fp:
        writer = csv.DictWriter(
            fp,
            fieldnames=[
                "incident_id",
                "event_date",
                "target",
                "description",
                "loss_usd_raw",
                "loss_usd",
                "attack_method",
                "classification",
                "chain",
                "target_type",
                "reference_url",
                "source_url",
                "collected_at",
            ],
        )
        writer.writeheader()
        writer.writerow(
            {
                "incident_id": "defillama-1",
                "event_date": "2026-01-02",
                "target": "DefiLlama Candidate",
                "description": "DefiLlama hack entry for an Ethereum lending exploit.",
                "loss_usd_raw": "2100000",
                "loss_usd": "2100000",
                "attack_method": "Flash Loan",
                "classification": "Protocol Logic",
                "chain": "Ethereum",
                "target_type": "DeFi Protocol",
                "reference_url": "https://blocksec.com/blog/defillama-candidate",
                "source_url": "https://defillama.com/hacks",
                "collected_at": "2026-05-24T00:00:00Z",
            }
        )

    summary = normalize.normalize_datasets(
        slowmist_csv=slowmist_csv,
        defillama_protocols_csv=protocols_csv,
        output_dir=output_dir,
        defillama_hacks_csv=hacks_csv,
    )

    assert summary["incident_rows"] == 2
    rows = _read_csv(output_dir / "incidents_normalized_latest.csv")
    by_id = {row["incident_id"]: row for row in rows}
    assert by_id["slowmist-1"]["source_url"] == "https://hacked.slowmist.io/?c=&page=1"
    assert by_id["defillama-1"]["source_url"] == "https://defillama.com/hacks"
    assert by_id["defillama-1"]["chain"] == "Ethereum"
