from __future__ import annotations

import base64
import csv
import importlib.util
import io
import json
import subprocess
import sys
from pathlib import Path
from urllib.error import HTTPError

import pytest

from abra.chain_support import rpc_url_for_chain
from abra.evidence_pipeline import _onchain_anchor_queries
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


def test_evidence_pipeline_recognizes_direct_tx_security_sources(tmp_path, monkeypatch):
    monkeypatch.setenv("ALCHEMY_API_KEY", "alchemy-test-key")
    incidents_csv = tmp_path / "incidents_normalized_latest.csv"
    out_dir = tmp_path / "processed"
    rows = [
        _incident(
            1,
            target="Phalcon Direct Candidate",
            reference_url="https://phalcon.blocksec.com/explorer/security-incidents/fixture",
        ),
        _incident(
            2,
            target="MetaSleuth Direct Candidate",
            reference_url="https://metasleuth.io/result/eth/0x1234",
        ),
        _incident(
            3,
            target="DeFiHackLabs Direct Candidate",
            reference_url="https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/Fixture.t.sol",
        ),
    ]
    _write_incidents_csv(incidents_csv, rows)

    produce_evidence_pipeline(
        incidents_csv=incidents_csv,
        out_dir=out_dir,
        rpc_supported_chains=["ethereum"],
    )

    enriched = {row["slug"]: row for row in _read_csv(out_dir / "security_evidence_enriched_latest.csv")}
    assert json.loads(enriched["phalcon-direct-candidate"]["security_report_sources"]) == [
        {
            "source": "blocksec_phalcon",
            "url": "https://phalcon.blocksec.com/explorer/security-incidents/fixture",
        }
    ]
    assert json.loads(enriched["metasleuth-direct-candidate"]["security_report_sources"]) == [
        {"source": "metasleuth", "url": "https://metasleuth.io/result/eth/0x1234"}
    ]
    assert json.loads(enriched["defihacklabs-direct-candidate"]["security_report_sources"]) == [
        {
            "source": "defihacklabs",
            "url": "https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/Fixture.t.sol",
        }
    ]
    assert all(row["security_anchor"] == "true" for row in enriched.values())


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


def test_evidence_pipeline_skips_source_fetch_for_alchemy_unsupported_chains(tmp_path, monkeypatch):
    monkeypatch.setenv("ALCHEMY_API_KEY", "alchemy-test-key")
    incidents_csv = tmp_path / "incidents_normalized_latest.csv"
    out_dir = tmp_path / "processed"
    _write_incidents_csv(
        incidents_csv,
        [
            _incident(
                1,
                target="EOS Unsupported Candidate",
                chain="eos",
                reference_url="https://blocksec.com/blog/eos-candidate-analysis",
                source_url="https://hacked.slowmist.io/?c=&page=1",
                seed_transaction_hash="",
                fork_block="",
            )
        ],
    )

    def fail_if_fetched(*_args, **_kwargs):
        raise AssertionError("unsupported Alchemy chains must not consume source-fetch budget")

    produce_evidence_pipeline(
        incidents_csv=incidents_csv,
        out_dir=out_dir,
        rpc_supported_chains=["ethereum"],
        source_fetcher=fail_if_fetched,
    )

    rows = _read_csv(out_dir / "alchemy_onchain_backfill_latest.csv")
    assert rows[0]["rpc_supported"] == "false"
    assert rows[0]["backfill_status"] == "blocked_rpc_unsupported"
    assert rows[0]["source_fetch_status"] == "source_fetch_skipped:rpc_unsupported"


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


def test_evidence_pipeline_reports_missing_twitterapi_io_key_for_default_x_alert_fetch(tmp_path, monkeypatch):
    monkeypatch.setenv("ALCHEMY_API_KEY", "alchemy-test-key")
    monkeypatch.setenv("ABRA_DISABLE_LOCAL_ENV", "1")
    monkeypatch.delenv("TWITTERAPI_IO_KEY", raising=False)
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
    assert rows[0]["source_fetch_status"] == "twitterapi_io_not_configured"
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


def test_evidence_pipeline_prioritizes_security_alerts_for_anchor_discovery_budget(tmp_path, monkeypatch):
    monkeypatch.setenv("ALCHEMY_API_KEY", "alchemy-test-key")
    monkeypatch.setenv("ABRA_REFERENCE_FETCH_BUDGET", "0")
    monkeypatch.setenv("ABRA_ONCHAIN_ANCHOR_DISCOVERY", "1")
    monkeypatch.setenv("ABRA_ONCHAIN_ANCHOR_DISCOVERY_BUDGET", "1")
    tx_hash = "0x" + "1" * 64
    explorer_url = f"https://basescan.org/tx/{tx_hash}"
    incidents_csv = tmp_path / "incidents_normalized_latest.csv"
    out_dir = tmp_path / "processed"
    _write_incidents_csv(
        incidents_csv,
        [
            _incident(
                1,
                target="Generic News Candidate",
                chain="ethereum",
                reference_url="https://example.org/news/generic-defi-incident",
                source_url="https://defillama.com/hacks",
                seed_transaction_hash="",
                fork_block="",
            ),
            _incident(
                2,
                target="Base Security Alert Candidate",
                chain="base",
                reference_url="https://x.com/PeckShieldAlert/status/2035565047133401563",
                source_url="https://hacked.slowmist.io/?c=&page=1",
                seed_transaction_hash="",
                fork_block="",
            ),
        ],
    )

    searched_targets: list[str] = []

    def fake_anchor_searcher(context: dict[str, str]) -> list[dict[str, str]]:
        searched_targets.append(context["target"])
        return [
            {
                "status": "fetched",
                "url": explorer_url,
                "text": f"Exploit transaction: {explorer_url}",
            }
        ]

    def fake_rpc_caller(chain: str, method: str, params: list[str]) -> dict[str, str]:
        assert chain == "base"
        assert method == "eth_getTransactionReceipt"
        assert params == [tx_hash]
        return {"blockNumber": hex(20_000_007)}

    produce_evidence_pipeline(
        incidents_csv=incidents_csv,
        out_dir=out_dir,
        rpc_supported_chains=["ethereum", "base"],
        source_fetcher=lambda url: {"status": "source_fetch_skipped:social_api_required", "url": url, "text": ""},
        anchor_searcher=fake_anchor_searcher,
        rpc_caller=fake_rpc_caller,
    )

    rows = {row["slug"]: row for row in _read_csv(out_dir / "alchemy_onchain_backfill_latest.csv")}
    assert searched_targets == ["Base Security Alert Candidate"]
    assert rows["generic-news-candidate"]["anchor_discovery_status"] == "anchor_discovery_skipped:disabled_or_budget"
    assert rows["generic-news-candidate"]["rpc_backfill_status"] == "not_attempted"
    assert rows["base-security-alert-candidate"]["anchor_discovery_status"] == "discovered"
    assert rows["base-security-alert-candidate"]["anchor_discovery_url"] == explorer_url
    assert rows["base-security-alert-candidate"]["seed_transaction_hash"] == tx_hash
    assert rows["base-security-alert-candidate"]["fork_block"] == "20000007"
    assert rows["base-security-alert-candidate"]["rpc_backfill_status"] == "receipt_verified"


def test_evidence_pipeline_falls_back_when_anchor_search_provider_resets(tmp_path, monkeypatch):
    monkeypatch.setenv("ALCHEMY_API_KEY", "alchemy-test-key")
    monkeypatch.setenv("ABRA_ONCHAIN_ANCHOR_DISCOVERY", "1")
    monkeypatch.setenv("ABRA_ONCHAIN_ANCHOR_DISCOVERY_BUDGET", "1")
    monkeypatch.setenv("ABRA_ONCHAIN_SEARCH_PROVIDERS", "duckduckgo,bing")
    tx_hash = "0x" + "3" * 64
    explorer_url = f"https://etherscan.io/tx/{tx_hash}"
    incidents_csv = tmp_path / "incidents_normalized_latest.csv"
    out_dir = tmp_path / "processed"
    _write_incidents_csv(
        incidents_csv,
        [
            _incident(
                1,
                target="Fallback Search Candidate",
                reference_url="https://x.com/PeckShieldAlert/status/2035565047133401563",
                source_url="https://hacked.slowmist.io/?c=&page=1",
                seed_transaction_hash="",
                fork_block="",
            ),
        ],
    )

    requested_urls: list[str] = []

    class FakeSearchResponse:
        headers = {"content-type": "text/html"}

        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return False

        def read(self, _limit: int) -> bytes:
            return f'<a href="{explorer_url}">exploit tx</a>'.encode()

    def fake_urlopen(request, timeout: int):
        del timeout
        url = request.full_url
        requested_urls.append(url)
        if "duckduckgo.com" in url:
            raise ConnectionResetError("simulated reset")
        if "bing.com" in url:
            return FakeSearchResponse()
        raise AssertionError(url)

    def fake_rpc_caller(chain: str, method: str, params: list[str]) -> dict[str, str]:
        assert chain == "ethereum"
        assert method == "eth_getTransactionReceipt"
        assert params == [tx_hash]
        return {"blockNumber": hex(20_000_008)}

    monkeypatch.setattr("abra.evidence_pipeline.urllib.request.urlopen", fake_urlopen)
    produce_evidence_pipeline(
        incidents_csv=incidents_csv,
        out_dir=out_dir,
        rpc_supported_chains=["ethereum"],
        source_fetcher=lambda url: {"status": "source_fetch_skipped:social_api_required", "url": url, "text": ""},
        rpc_caller=fake_rpc_caller,
    )

    rows = _read_csv(out_dir / "alchemy_onchain_backfill_latest.csv")
    assert len(rows) == 1
    row = rows[0]
    assert any("duckduckgo.com" in url for url in requested_urls)
    assert any("bing.com" in url for url in requested_urls)
    assert row["anchor_discovery_status"] == "discovered"
    assert row["anchor_discovery_url"] == explorer_url
    assert row["anchor_discovery_seed_transaction_hash"] == tx_hash
    assert row["seed_transaction_hash"] == tx_hash
    assert row["fork_block"] == "20000008"
    assert row["rpc_backfill_status"] == "receipt_verified"


def test_evidence_pipeline_bounds_anchor_search_requests_and_timeout(tmp_path, monkeypatch):
    monkeypatch.setenv("ALCHEMY_API_KEY", "alchemy-test-key")
    monkeypatch.setenv("ABRA_ONCHAIN_ANCHOR_DISCOVERY", "1")
    monkeypatch.setenv("ABRA_ONCHAIN_ANCHOR_DISCOVERY_BUDGET", "1")
    monkeypatch.setenv("ABRA_ONCHAIN_SEARCH_PROVIDERS", "duckduckgo,bing,brave")
    monkeypatch.setenv("ABRA_ONCHAIN_SEARCH_MAX_REQUESTS", "2")
    monkeypatch.setenv("ABRA_ONCHAIN_SEARCH_TIMEOUT_SECONDS", "1.5")
    incidents_csv = tmp_path / "incidents_normalized_latest.csv"
    out_dir = tmp_path / "processed"
    _write_incidents_csv(
        incidents_csv,
        [
            _incident(
                1,
                target="Bounded Search Candidate",
                reference_url="https://x.com/PeckShieldAlert/status/2035565047133401563",
                source_url="https://hacked.slowmist.io/?c=&page=1",
                seed_transaction_hash="",
                fork_block="",
            ),
        ],
    )

    requested: list[tuple[str, float]] = []

    def fake_urlopen(request, timeout: float):
        requested.append((request.full_url, timeout))
        raise TimeoutError("simulated slow search")

    monkeypatch.setattr("abra.evidence_pipeline.urllib.request.urlopen", fake_urlopen)
    payload = produce_evidence_pipeline(
        incidents_csv=incidents_csv,
        out_dir=out_dir,
        rpc_supported_chains=["ethereum"],
        source_fetcher=lambda url: {"status": "source_fetch_skipped:social_api_required", "url": url, "text": ""},
    )

    rows = _read_csv(out_dir / "alchemy_onchain_backfill_latest.csv")
    assert len(rows) == 1
    assert payload["status"] == "failed"
    assert "anchor_discovery_attempted_without_onchain_anchor" in payload["errors"]
    assert "anchor_discovery_all_attempts_timed_out" in payload["errors"]
    assert payload["summary"]["anchor_discovery_attempted_count"] == 1
    assert payload["summary"]["anchor_discovery_result_count"] == 2
    assert payload["summary"]["anchor_discovery_timeout_result_count"] == 2
    assert payload["summary"]["anchor_discovery_exhausted_count"] == 1
    assert len(requested) == 2
    assert all(timeout == 1.5 for _, timeout in requested)
    assert all("brave.com" not in url for url, _ in requested)
    assert rows[0]["anchor_discovery_status"] == "anchor_discovery_search_exhausted:all_timeouts"
    assert rows[0]["anchor_discovery_attempt_count"] == "2"
    assert rows[0]["anchor_discovery_timeout_count"] == "2"
    assert rows[0]["anchor_discovery_result_statuses"] == "anchor_discovery_failed:TimeoutError"
    assert rows[0]["rpc_backfill_status"] == "not_attempted"


def test_evidence_pipeline_uses_security_source_specific_anchor_queries(tmp_path, monkeypatch):
    monkeypatch.setenv("ALCHEMY_API_KEY", "alchemy-test-key")
    monkeypatch.setenv("ABRA_ONCHAIN_ANCHOR_DISCOVERY", "1")
    monkeypatch.setenv("ABRA_ONCHAIN_ANCHOR_DISCOVERY_BUDGET", "1")
    monkeypatch.setenv("ABRA_ONCHAIN_SEARCH_PROVIDERS", "bing")
    monkeypatch.setenv("ABRA_ONCHAIN_SEARCH_MAX_REQUESTS", "8")
    tx_hash = "0x" + "4" * 64
    explorer_url = f"https://basescan.org/tx/{tx_hash}"
    incidents_csv = tmp_path / "incidents_normalized_latest.csv"
    out_dir = tmp_path / "processed"
    _write_incidents_csv(
        incidents_csv,
        [
            _incident(
                1,
                target="Blockaid Source Candidate",
                chain="base",
                reference_url="https://x.com/blockaid_/status/2054593377438421492",
                source_url="https://hacked.slowmist.io/?c=&page=1",
                seed_transaction_hash="",
                fork_block="",
            ),
        ],
    )

    requested_urls: list[str] = []

    class FakeSearchResponse:
        headers = {"content-type": "text/html"}

        def __init__(self, text: str):
            self.text = text

        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return False

        def read(self, _limit: int) -> bytes:
            return self.text.encode()

    def fake_urlopen(request, timeout: float):
        del timeout
        requested_urls.append(request.full_url)
        decoded_url = request.full_url.lower()
        if "site%3ablockaid.io" in decoded_url:
            return FakeSearchResponse(f'Blockaid analysis: <a href="{explorer_url}">attacker tx</a>')
        return FakeSearchResponse("generic search result without transaction evidence")

    def fake_rpc_caller(chain: str, method: str, params: list[str]) -> dict[str, str]:
        assert chain == "base"
        assert method == "eth_getTransactionReceipt"
        assert params == [tx_hash]
        return {"blockNumber": hex(20_000_009)}

    monkeypatch.setattr("abra.evidence_pipeline.urllib.request.urlopen", fake_urlopen)
    produce_evidence_pipeline(
        incidents_csv=incidents_csv,
        out_dir=out_dir,
        rpc_supported_chains=["base"],
        source_fetcher=lambda url: {"status": "source_fetch_skipped:social_api_required", "url": url, "text": ""},
        rpc_caller=fake_rpc_caller,
    )

    rows = _read_csv(out_dir / "alchemy_onchain_backfill_latest.csv")
    assert len(rows) == 1
    row = rows[0]
    assert any("site%3ablockaid.io" in url.lower() for url in requested_urls)
    assert row["anchor_discovery_status"] == "discovered"
    assert row["anchor_discovery_url"] == explorer_url
    assert row["anchor_discovery_seed_transaction_hash"] == tx_hash
    assert row["seed_transaction_hash"] == tx_hash
    assert row["fork_block"] == "20000009"
    assert row["rpc_backfill_status"] == "receipt_verified"


def test_evidence_pipeline_fetches_trusted_search_result_pages_for_tx_anchor(tmp_path, monkeypatch):
    monkeypatch.setenv("ALCHEMY_API_KEY", "alchemy-test-key")
    monkeypatch.setenv("ABRA_ONCHAIN_ANCHOR_DISCOVERY", "1")
    monkeypatch.setenv("ABRA_ONCHAIN_ANCHOR_DISCOVERY_BUDGET", "1")
    monkeypatch.setenv("ABRA_ONCHAIN_SEARCH_PROVIDERS", "bing")
    monkeypatch.setenv("ABRA_ONCHAIN_SEARCH_MAX_REQUESTS", "1")
    monkeypatch.setenv("ABRA_ONCHAIN_SEARCH_SECOND_HOP_MAX_REQUESTS", "2")
    tx_hash = "0x" + "5" * 64
    trusted_url = "https://blocksec.com/blog/trusted-second-hop-candidate-analysis"
    bing_redirect = (
        "https://www.bing.com/ck/a?u=a1"
        + base64.urlsafe_b64encode(trusted_url.encode()).decode().rstrip("=")
    )
    explorer_url = f"https://etherscan.io/tx/{tx_hash}"
    incidents_csv = tmp_path / "incidents_normalized_latest.csv"
    out_dir = tmp_path / "processed"
    _write_incidents_csv(
        incidents_csv,
        [
            _incident(
                1,
                target="Trusted Second Hop Candidate",
                reference_url="https://x.com/Phalcon_xyz/status/2054593377438421492",
                source_url="https://hacked.slowmist.io/?c=&page=1",
                seed_transaction_hash="",
                fork_block="",
            ),
        ],
    )

    requested_urls: list[str] = []

    class FakeSearchResponse:
        headers = {"content-type": "text/html"}

        def __init__(self, text: str):
            self.text = text

        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return False

        def read(self, _limit: int) -> bytes:
            return self.text.encode()

    def fake_urlopen(request, timeout: float):
        del timeout
        requested_urls.append(request.full_url)
        if "bing.com/search" in request.full_url:
            return FakeSearchResponse(
                f'<a href="https://random.example/report">noise</a>'
                f'<a href="{bing_redirect}">BlockSec analysis</a>'
            )
        if request.full_url == trusted_url:
            return FakeSearchResponse(
                f"Trusted Second Hop Candidate exploit transaction: {explorer_url}"
            )
        raise AssertionError(request.full_url)

    def fake_rpc_caller(chain: str, method: str, params: list[str]) -> dict[str, str]:
        assert chain == "ethereum"
        assert method == "eth_getTransactionReceipt"
        assert params == [tx_hash]
        return {"blockNumber": hex(20_000_010)}

    monkeypatch.setattr("abra.evidence_pipeline.urllib.request.urlopen", fake_urlopen)
    produce_evidence_pipeline(
        incidents_csv=incidents_csv,
        out_dir=out_dir,
        rpc_supported_chains=["ethereum"],
        source_fetcher=lambda url: {"status": "source_fetch_skipped:social_api_required", "url": url, "text": ""},
        rpc_caller=fake_rpc_caller,
    )

    rows = _read_csv(out_dir / "alchemy_onchain_backfill_latest.csv")
    assert len(rows) == 1
    row = rows[0]
    assert any("bing.com/search" in url for url in requested_urls)
    assert trusted_url in requested_urls
    assert row["anchor_discovery_status"] == "discovered"
    assert row["anchor_discovery_url"] == explorer_url
    assert row["anchor_discovery_seed_transaction_hash"] == tx_hash
    assert row["seed_transaction_hash"] == tx_hash
    assert row["fork_block"] == "20000010"
    assert row["rpc_backfill_status"] == "receipt_verified"


def test_onchain_anchor_queries_include_source_specific_security_domains():
    context = {
        "target": "Fixture Exploit",
        "slug": "fixture-exploit",
        "event_date": "2026-02-01",
        "chain": "ethereum",
        "security_report_sources": json.dumps(
            [
                {"source": "blocksec", "url": "https://x.com/Phalcon_xyz/status/1"},
                {"source": "peckshield", "url": "https://x.com/PeckShieldAlert/status/2"},
                {"source": "slowmist", "url": "https://x.com/SlowMist_Team/status/3"},
                {"source": "defimon", "url": "https://x.com/DefimonAlerts/status/4"},
            ]
        ),
    }

    queries = _onchain_anchor_queries(context)
    query_text = "\n".join(queries).lower()

    assert "site:phalcon.blocksec.com" in query_text
    assert "site:app.blocksec.com" in query_text
    assert "site:peckshield.com" in query_text
    assert "site:slowmist.io" in query_text
    assert "site:defimon.xyz" in query_text
    assert "site:etherscan.io/tx" in query_text


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


def test_evidence_pipeline_fetches_x_alert_text_with_twitterapi_io(tmp_path, monkeypatch):
    monkeypatch.setenv("ALCHEMY_API_KEY", "alchemy-test-key")
    monkeypatch.setenv("TWITTERAPI_IO_KEY", "twitterapi-test-key")
    tx_hash = "0x" + "6" * 64
    alert_url = "https://x.com/blockaid_/status/2054593377438421492"
    incidents_csv = tmp_path / "incidents_normalized_latest.csv"
    out_dir = tmp_path / "processed"
    _write_incidents_csv(
        incidents_csv,
        [
            _incident(
                1,
                target="TwitterAPI Alert Candidate",
                reference_url=alert_url,
                source_url="https://hacked.slowmist.io/?c=&page=1",
                seed_transaction_hash="",
                fork_block="",
            ),
        ],
    )

    requested_urls: list[str] = []

    class FakeResponse:
        headers = {"content-type": "application/json"}

        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return False

        def read(self, _limit: int) -> bytes:
            return json.dumps(
                {
                    "status": "success",
                    "tweets": [
                        {
                            "id": "2054593377438421492",
                            "url": alert_url,
                            "text": f"Exploit transaction: https://arbiscan.io/tx/{tx_hash}",
                            "author": {"userName": "blockaid_"},
                            "entities": {"urls": []},
                        }
                    ],
                }
            ).encode()

    def fake_urlopen(request, timeout: float):
        del timeout
        requested_urls.append(request.full_url)
        assert request.headers["X-api-key"] == "twitterapi-test-key"
        assert request.full_url == "https://api.twitterapi.io/twitter/tweets?tweet_ids=2054593377438421492"
        return FakeResponse()

    def fake_rpc_caller(chain: str, method: str, params: list[str]) -> dict[str, str]:
        assert chain == "ethereum"
        assert method == "eth_getTransactionReceipt"
        assert params == [tx_hash]
        return {"blockNumber": hex(20_000_011)}

    monkeypatch.setattr("abra.evidence_pipeline.urllib.request.urlopen", fake_urlopen)
    produce_evidence_pipeline(
        incidents_csv=incidents_csv,
        out_dir=out_dir,
        rpc_supported_chains=["ethereum"],
        rpc_caller=fake_rpc_caller,
    )

    rows = _read_csv(out_dir / "alchemy_onchain_backfill_latest.csv")
    assert requested_urls == ["https://api.twitterapi.io/twitter/tweets?tweet_ids=2054593377438421492"]
    assert rows[0]["source_fetch_status"] == "twitterapi_io_fetched"
    assert rows[0]["source_evidence_url"] == alert_url
    assert rows[0]["source_extracted_seed_transaction_hash"] == tx_hash
    assert rows[0]["seed_transaction_hash"] == tx_hash
    assert rows[0]["fork_block"] == "20000011"
    assert rows[0]["rpc_backfill_status"] == "receipt_verified"


def test_evidence_pipeline_resolves_x_thread_follow_up_tweet_for_tx_hash(tmp_path, monkeypatch):
    monkeypatch.setenv("ALCHEMY_API_KEY", "alchemy-test-key")
    monkeypatch.setenv("TWITTERAPI_IO_KEY", "twitterapi-test-key")
    tx_hash = "0x" + "8" * 64
    root_tweet_id = "2054593377438421492"
    follow_up_tweet_id = "2054593377438421493"
    root_url = f"https://x.com/blockaid_/status/{root_tweet_id}"
    follow_up_url = f"https://x.com/blockaid_/status/{follow_up_tweet_id}"
    incidents_csv = tmp_path / "incidents_normalized_latest.csv"
    out_dir = tmp_path / "processed"
    _write_incidents_csv(
        incidents_csv,
        [
            _incident(
                1,
                target="Twitter Thread Alert Candidate",
                reference_url=root_url,
                source_url="https://hacked.slowmist.io/?c=&page=1",
                seed_transaction_hash="",
                fork_block="",
            ),
        ],
    )

    requested_urls: list[str] = []

    class FakeResponse:
        headers = {"content-type": "application/json"}

        def __init__(self, payload: dict[str, object]):
            self._payload = payload

        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return False

        def read(self, _limit: int) -> bytes:
            return json.dumps(self._payload).encode()

    def fake_urlopen(request, timeout: float):
        del timeout
        requested_urls.append(request.full_url)
        if request.full_url == f"https://api.twitterapi.io/twitter/tweets?tweet_ids={root_tweet_id}":
            return FakeResponse(
                {
                    "status": "success",
                    "tweets": [
                        {
                            "id": root_tweet_id,
                            "url": root_url,
                            "text": "Community alert. More details in thread.",
                            "replyCount": 2,
                            "author": {"userName": "blockaid_"},
                            "entities": {
                                "user_mentions": [
                                    {"screen_name": "ShapeShift", "name": "ShapeShift"},
                                ],
                                "urls": [],
                            },
                        }
                    ],
                }
            )
        if request.full_url == f"https://api.twitterapi.io/twitter/tweet/thread_context?tweetId={root_tweet_id}":
            return FakeResponse(
                {
                    "status": "success",
                    "replies": [
                        {
                            "id": root_tweet_id,
                            "url": root_url,
                            "text": "Community alert. More details in thread.",
                            "conversationId": root_tweet_id,
                            "author": {"userName": "blockaid_"},
                            "entities": {"urls": []},
                        },
                        {
                            "id": follow_up_tweet_id,
                            "url": follow_up_url,
                            "text": f"Exploit transaction: https://arbiscan.io/tx/{tx_hash}",
                            "conversationId": root_tweet_id,
                            "author": {"userName": "blockaid_"},
                            "entities": {"urls": []},
                        },
                    ],
                    "has_next_page": False,
                    "next_cursor": "",
                }
            )
        raise AssertionError(f"unexpected URL requested: {request.full_url}")

    def fake_rpc_caller(chain: str, method: str, params: list[str]) -> dict[str, str]:
        assert chain == "ethereum"
        assert method == "eth_getTransactionReceipt"
        assert params == [tx_hash]
        return {"blockNumber": hex(20_000_013)}

    monkeypatch.setattr("abra.evidence_pipeline.urllib.request.urlopen", fake_urlopen)
    produce_evidence_pipeline(
        incidents_csv=incidents_csv,
        out_dir=out_dir,
        rpc_supported_chains=["ethereum"],
        rpc_caller=fake_rpc_caller,
    )

    rows = _read_csv(out_dir / "alchemy_onchain_backfill_latest.csv")
    assert requested_urls == [
        f"https://api.twitterapi.io/twitter/tweets?tweet_ids={root_tweet_id}",
        f"https://api.twitterapi.io/twitter/tweet/thread_context?tweetId={root_tweet_id}",
    ]
    assert rows[0]["source_fetch_status"] == "twitterapi_io_fetched"
    assert rows[0]["source_evidence_url"] == follow_up_url
    assert rows[0]["source_extracted_seed_transaction_hash"] == tx_hash
    assert rows[0]["seed_transaction_hash"] == tx_hash
    assert rows[0]["fork_block"] == "20000013"
    assert rows[0]["rpc_backfill_status"] == "receipt_verified"


def test_evidence_pipeline_ignores_x_thread_context_tweets_from_other_conversations(tmp_path, monkeypatch):
    monkeypatch.setenv("ALCHEMY_API_KEY", "alchemy-test-key")
    monkeypatch.setenv("TWITTERAPI_IO_KEY", "twitterapi-test-key")
    correct_tx_hash = "0x" + "a" * 64
    unrelated_tx_hash = "0x" + "b" * 64
    root_tweet_id = "2054593377438421492"
    correct_tweet_id = "2054593661518610792"
    unrelated_tweet_id = "2058372418557595890"
    root_url = f"https://x.com/blockaid_/status/{root_tweet_id}"
    correct_url = f"https://x.com/blockaid_/status/{correct_tweet_id}"
    unrelated_url = f"https://x.com/blockaid_/status/{unrelated_tweet_id}"
    incidents_csv = tmp_path / "incidents_normalized_latest.csv"
    out_dir = tmp_path / "processed"
    _write_incidents_csv(
        incidents_csv,
        [
            _incident(
                1,
                target="ShapeShift FOX Colony",
                reference_url=root_url,
                source_url="https://hacked.slowmist.io/?c=&page=1",
                seed_transaction_hash="",
                fork_block="",
            ),
        ],
    )

    class FakeResponse:
        headers = {"content-type": "application/json"}

        def __init__(self, payload: dict[str, object]):
            self._payload = payload

        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return False

        def read(self, _limit: int) -> bytes:
            return json.dumps(self._payload).encode()

    def fake_urlopen(request, timeout: float):
        del timeout
        if request.full_url == f"https://api.twitterapi.io/twitter/tweets?tweet_ids={root_tweet_id}":
            return FakeResponse(
                {
                    "status": "success",
                    "tweets": [
                        {
                            "id": root_tweet_id,
                            "url": root_url,
                            "text": "Community alert. ShapeShift FOX Colony. More details in thread.",
                            "conversationId": root_tweet_id,
                            "author": {"userName": "blockaid_"},
                            "entities": {"urls": []},
                        }
                    ],
                }
            )
        if request.full_url == f"https://api.twitterapi.io/twitter/tweet/thread_context?tweetId={root_tweet_id}":
            return FakeResponse(
                {
                    "status": "success",
                    "tweets": [
                        {
                            "id": root_tweet_id,
                            "url": root_url,
                            "text": "Community alert. ShapeShift FOX Colony. More details in thread.",
                            "conversationId": root_tweet_id,
                            "author": {"userName": "blockaid_"},
                            "entities": {"urls": []},
                        },
                        {
                            "id": correct_tweet_id,
                            "url": correct_url,
                            "text": f"Tx: https://arbiscan.io/tx/{correct_tx_hash}",
                            "conversationId": root_tweet_id,
                            "inReplyToId": root_tweet_id,
                            "author": {"userName": "blockaid_"},
                            "entities": {"urls": []},
                        },
                        {
                            "id": unrelated_tweet_id,
                            "url": unrelated_url,
                            "text": f"Unrelated StablR tx: https://etherscan.io/tx/{unrelated_tx_hash}",
                            "conversationId": unrelated_tweet_id,
                            "author": {"userName": "blockaid_"},
                            "entities": {"urls": []},
                        },
                    ],
                    "has_next_page": False,
                    "next_cursor": "",
                }
            )
        raise AssertionError(f"unexpected URL requested: {request.full_url}")

    def fake_rpc_caller(_chain: str, _method: str, params: list[str]) -> dict[str, str]:
        assert params == [correct_tx_hash]
        return {"blockNumber": hex(20_000_015)}

    monkeypatch.setattr("abra.evidence_pipeline.urllib.request.urlopen", fake_urlopen)
    produce_evidence_pipeline(
        incidents_csv=incidents_csv,
        out_dir=out_dir,
        rpc_supported_chains=["ethereum"],
        rpc_caller=fake_rpc_caller,
    )

    rows = _read_csv(out_dir / "alchemy_onchain_backfill_latest.csv")
    assert rows[0]["source_evidence_url"] == correct_url
    assert rows[0]["source_extracted_seed_transaction_hash"] == correct_tx_hash
    assert rows[0]["seed_transaction_hash"] == correct_tx_hash
    assert rows[0]["fork_block"] == "20000015"


def test_evidence_pipeline_recovers_x_tx_from_advanced_search_when_thread_context_is_empty(tmp_path, monkeypatch):
    monkeypatch.setenv("ALCHEMY_API_KEY", "alchemy-test-key")
    monkeypatch.setenv("TWITTERAPI_IO_KEY", "twitterapi-test-key")
    tx_hash = "0x" + "9" * 64
    root_tweet_id = "2054593377438421492"
    root_url = f"https://x.com/blockaid_/status/{root_tweet_id}"
    search_hit_url = "https://x.com/blockaid_/status/2054593377438421494"
    incidents_csv = tmp_path / "incidents_normalized_latest.csv"
    out_dir = tmp_path / "processed"
    _write_incidents_csv(
        incidents_csv,
        [
            _incident(
                1,
                target="Twitter Search Recovery Candidate",
                reference_url=root_url,
                source_url="https://hacked.slowmist.io/?c=&page=1",
                seed_transaction_hash="",
                fork_block="",
            ),
        ],
    )

    requested_urls: list[str] = []

    class FakeResponse:
        headers = {"content-type": "application/json"}

        def __init__(self, payload: dict[str, object]):
            self._payload = payload

        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return False

        def read(self, _limit: int) -> bytes:
            return json.dumps(self._payload).encode()

    def fake_urlopen(request, timeout: float):
        del timeout
        requested_urls.append(request.full_url)
        if request.full_url == f"https://api.twitterapi.io/twitter/tweets?tweet_ids={root_tweet_id}":
            return FakeResponse(
                {
                    "status": "success",
                    "tweets": [
                        {
                            "id": root_tweet_id,
                            "url": root_url,
                            "text": "Community alert. More details in thread.",
                            "replyCount": 3,
                            "createdAt": "Wed May 13 16:03:28 +0000 2026",
                            "author": {"userName": "blockaid_"},
                            "entities": {
                                "user_mentions": [
                                    {"screen_name": "ShapeShift", "name": "ShapeShift"},
                                ],
                                "urls": [],
                            },
                        }
                    ],
                }
            )
        if request.full_url == f"https://api.twitterapi.io/twitter/tweet/thread_context?tweetId={root_tweet_id}":
            return FakeResponse({"status": "success", "replies": [], "has_next_page": False, "next_cursor": ""})
        if request.full_url == f"https://api.twitterapi.io/twitter/tweet/replies?tweetId={root_tweet_id}":
            return FakeResponse({"status": "success", "replies": [], "has_next_page": False, "next_cursor": ""})
        if request.full_url.startswith("https://api.twitterapi.io/twitter/tweet/advanced_search?"):
            return FakeResponse(
                {
                    "status": "success",
                    "tweets": [
                        {
                            "id": "2054593377438421494",
                            "url": search_hit_url,
                            "text": f"Attack transaction located: https://arbiscan.io/tx/{tx_hash}",
                            "author": {"userName": "blockaid_"},
                            "entities": {"urls": []},
                        }
                    ],
                    "has_next_page": False,
                    "next_cursor": "",
                }
            )
        raise AssertionError(f"unexpected URL requested: {request.full_url}")

    def fake_rpc_caller(chain: str, method: str, params: list[str]) -> dict[str, str]:
        assert chain == "ethereum"
        assert method == "eth_getTransactionReceipt"
        assert params == [tx_hash]
        return {"blockNumber": hex(20_000_014)}

    monkeypatch.setattr("abra.evidence_pipeline.urllib.request.urlopen", fake_urlopen)
    produce_evidence_pipeline(
        incidents_csv=incidents_csv,
        out_dir=out_dir,
        rpc_supported_chains=["ethereum"],
        rpc_caller=fake_rpc_caller,
    )

    rows = _read_csv(out_dir / "alchemy_onchain_backfill_latest.csv")
    assert requested_urls[:3] == [
        f"https://api.twitterapi.io/twitter/tweets?tweet_ids={root_tweet_id}",
        f"https://api.twitterapi.io/twitter/tweet/thread_context?tweetId={root_tweet_id}",
        f"https://api.twitterapi.io/twitter/tweet/replies?tweetId={root_tweet_id}",
    ]
    assert any(
        url.startswith("https://api.twitterapi.io/twitter/tweet/advanced_search?")
        for url in requested_urls
    )
    assert rows[0]["source_fetch_status"] == "twitterapi_io_fetched"
    assert rows[0]["source_evidence_url"] == search_hit_url
    assert rows[0]["source_extracted_seed_transaction_hash"] == tx_hash
    assert rows[0]["seed_transaction_hash"] == tx_hash
    assert rows[0]["fork_block"] == "20000014"
    assert rows[0]["rpc_backfill_status"] == "receipt_verified"


def test_evidence_pipeline_reports_missing_twitterapi_io_key_for_x_alerts(tmp_path, monkeypatch):
    monkeypatch.setenv("ALCHEMY_API_KEY", "alchemy-test-key")
    monkeypatch.setenv("ABRA_DISABLE_LOCAL_ENV", "1")
    monkeypatch.delenv("TWITTERAPI_IO_KEY", raising=False)
    incidents_csv = tmp_path / "incidents_normalized_latest.csv"
    out_dir = tmp_path / "processed"
    _write_incidents_csv(
        incidents_csv,
        [
            _incident(
                1,
                target="TwitterAPI Missing Key Candidate",
                reference_url="https://x.com/SlowMist_Team/status/2054163700035289446",
                source_url="https://hacked.slowmist.io/?c=&page=1",
                seed_transaction_hash="",
                fork_block="",
            ),
        ],
    )

    def fail_if_network_called(*_args, **_kwargs):
        raise AssertionError("TwitterAPI.io should not be called without TWITTERAPI_IO_KEY")

    monkeypatch.setattr("abra.evidence_pipeline.urllib.request.urlopen", fail_if_network_called)
    produce_evidence_pipeline(
        incidents_csv=incidents_csv,
        out_dir=out_dir,
        rpc_supported_chains=["ethereum"],
    )

    rows = _read_csv(out_dir / "alchemy_onchain_backfill_latest.csv")
    assert rows[0]["source_fetch_status"] == "twitterapi_io_not_configured"
    assert rows[0]["source_extracted_seed_transaction_hash"] == ""
    assert rows[0]["rpc_backfill_status"] == "not_attempted"


def test_evidence_pipeline_uses_twitterapi_io_cache_for_x_alerts(tmp_path, monkeypatch):
    monkeypatch.setenv("ALCHEMY_API_KEY", "alchemy-test-key")
    monkeypatch.setenv("TWITTERAPI_IO_KEY", "twitterapi-test-key")
    monkeypatch.setenv("ABRA_TWITTERAPI_IO_CACHE_DIR", str(tmp_path / "twitterapi-cache"))
    tx_hash = "0x" + "7" * 64
    tweet_id = "2054163700035289446"
    alert_url = f"https://x.com/SlowMist_Team/status/{tweet_id}"
    cache_dir = tmp_path / "twitterapi-cache"
    cache_dir.mkdir()
    (cache_dir / f"{tweet_id}.json").write_text(
        json.dumps(
            {
                "status": "success",
                "tweets": [
                    {
                        "id": tweet_id,
                        "url": alert_url,
                        "text": f"Attack tx hash {tx_hash}",
                        "author": {"userName": "SlowMist_Team"},
                    }
                ],
            }
        )
        + "\n",
        encoding="utf-8",
    )
    incidents_csv = tmp_path / "incidents_normalized_latest.csv"
    out_dir = tmp_path / "processed"
    _write_incidents_csv(
        incidents_csv,
        [
            _incident(
                1,
                target="TwitterAPI Cache Candidate",
                reference_url=alert_url,
                source_url="https://hacked.slowmist.io/?c=&page=1",
                seed_transaction_hash="",
                fork_block="",
            ),
        ],
    )

    def fail_if_network_called(*_args, **_kwargs):
        raise AssertionError("cached TwitterAPI.io tweet should not call the network")

    monkeypatch.setattr("abra.evidence_pipeline.urllib.request.urlopen", fail_if_network_called)
    produce_evidence_pipeline(
        incidents_csv=incidents_csv,
        out_dir=out_dir,
        rpc_supported_chains=["ethereum"],
        rpc_caller=lambda *_args: {"blockNumber": hex(20_000_012)},
    )

    rows = _read_csv(out_dir / "alchemy_onchain_backfill_latest.csv")
    assert rows[0]["source_fetch_status"] == "twitterapi_io_fetched"
    assert rows[0]["source_extracted_seed_transaction_hash"] == tx_hash
    assert rows[0]["fork_block"] == "20000012"


def test_evidence_pipeline_bounds_twitterapi_io_requests(tmp_path, monkeypatch):
    monkeypatch.setenv("ALCHEMY_API_KEY", "alchemy-test-key")
    monkeypatch.setenv("TWITTERAPI_IO_KEY", "twitterapi-test-key")
    monkeypatch.setenv("ABRA_TWITTERAPI_IO_MAX_REQUESTS", "1")
    incidents_csv = tmp_path / "incidents_normalized_latest.csv"
    out_dir = tmp_path / "processed"
    _write_incidents_csv(
        incidents_csv,
        [
            _incident(
                1,
                target="TwitterAPI Budget Candidate One",
                reference_url="https://x.com/blockaid_/status/2054593377438421492",
                source_url="https://hacked.slowmist.io/?c=&page=1",
                seed_transaction_hash="",
                fork_block="",
            ),
            _incident(
                2,
                target="TwitterAPI Budget Candidate Two",
                reference_url="https://x.com/SlowMist_Team/status/2054163700035289446",
                source_url="https://hacked.slowmist.io/?c=&page=1",
                seed_transaction_hash="",
                fork_block="",
            ),
        ],
    )

    requested_urls: list[str] = []

    class FakeResponse:
        headers = {"content-type": "application/json"}

        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return False

        def read(self, _limit: int) -> bytes:
            return json.dumps({"status": "success", "tweets": [{"text": "no tx"}]}).encode()

    def fake_urlopen(request, timeout: float):
        del timeout
        requested_urls.append(request.full_url)
        return FakeResponse()

    monkeypatch.setattr("abra.evidence_pipeline.urllib.request.urlopen", fake_urlopen)
    produce_evidence_pipeline(
        incidents_csv=incidents_csv,
        out_dir=out_dir,
        rpc_supported_chains=["ethereum"],
    )

    rows = _read_csv(out_dir / "alchemy_onchain_backfill_latest.csv")
    assert len(requested_urls) == 1
    assert rows[0]["source_fetch_status"] == "fetched_no_onchain_anchor"
    assert rows[1]["source_fetch_status"] == "twitterapi_io_budget_exhausted"


def test_evidence_pipeline_fails_when_twitterapi_io_is_exhausted_without_anchor(tmp_path, monkeypatch):
    monkeypatch.setenv("ALCHEMY_API_KEY", "alchemy-test-key")
    monkeypatch.setenv("TWITTERAPI_IO_KEY", "twitterapi-test-key")
    monkeypatch.setenv("ABRA_TWITTERAPI_IO_MAX_REQUESTS", "0")
    incidents_csv = tmp_path / "incidents_normalized_latest.csv"
    out_dir = tmp_path / "processed"
    _write_incidents_csv(
        incidents_csv,
        [
            _incident(
                1,
                target="TwitterAPI Exhausted Candidate",
                reference_url="https://x.com/blockaid_/status/2054593377438421492",
                source_url="https://hacked.slowmist.io/?c=&page=1",
                seed_transaction_hash="",
                fork_block="",
            ),
        ],
    )

    payload = produce_evidence_pipeline(
        incidents_csv=incidents_csv,
        out_dir=out_dir,
        rpc_supported_chains=["ethereum"],
    )

    rows = _read_csv(out_dir / "alchemy_onchain_backfill_latest.csv")
    assert rows[0]["source_fetch_status"] == "twitterapi_io_budget_exhausted"
    assert payload["status"] == "failed"
    assert "x_source_fetch_exhausted_without_onchain_anchor" in payload["errors"]
    assert payload["summary"]["x_source_fetch_exhausted_count"] == 1


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


def test_direct_evidence_collector_persists_defihacklabs_replay_candidates(tmp_path, monkeypatch):
    collector = _load_pipeline_module("direct_evidence_collector")

    def fake_fetch_tree() -> list[dict[str, str]]:
        return [
            {"path": "src/test/2026-01/MTToken_exp.sol"},
            {"path": "src/test/helpers/BaseForkTest.t.sol"},
            {"path": "src/test/2026-03/Curve_LlamaLend_exp.sol"},
        ]

    def fake_fetch_contents(path: str) -> dict[str, str]:
        if path == "src/test/2026-01/MTToken_exp.sol":
            return {
                "path": path,
                "html_url": "https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2026-01/MTToken_exp.sol",
                "download_url": "https://raw.githubusercontent.com/SunWeb3Sec/DeFiHackLabs/main/src/test/2026-01/MTToken_exp.sol",
                "content": """
// Attack Tx (BSC) : https://bscscan.com/tx/0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
contract MTExploitTest is Test {
    uint256 internal constant ATTACK_BLOCK = 74_937_080;
    uint256 internal constant FORK_BLOCK = ATTACK_BLOCK - 1;
    function setUp() public {
        vm.createSelectFork("bsc", FORK_BLOCK);
    }
}
                """,
            }
        if path == "src/test/2026-03/Curve_LlamaLend_exp.sol":
            return {
                "path": path,
                "html_url": "https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2026-03/Curve_LlamaLend_exp.sol",
                "download_url": "https://raw.githubusercontent.com/SunWeb3Sec/DeFiHackLabs/main/src/test/2026-03/Curve_LlamaLend_exp.sol",
                "content": """
// Attack Tx (Ethereum) : https://etherscan.io/tx/0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb
contract CurveLlamaLendExploitTest is Test {
    uint256 internal constant FORK_BLOCK = 22_044_321;
    function setUp() public {
        vm.createSelectFork("ethereum", FORK_BLOCK);
    }
}
                """,
            }
        raise AssertionError(path)

    monkeypatch.setattr(collector, "fetch_defihacklabs_tree", fake_fetch_tree)
    monkeypatch.setattr(collector, "fetch_defihacklabs_fixture", fake_fetch_contents)

    summary = collector.collect_direct_evidence(output_dir=tmp_path, max_defihacklabs=10)

    assert summary["direct_candidate_count"] == 2
    assert summary["defihacklabs_candidate_count"] == 2
    rows = _read_csv(tmp_path / "direct_evidence_latest.csv")
    by_id = {row["incident_id"]: row for row in rows}
    assert sorted(by_id) == [
        "defihacklabs-2026-01-mttoken",
        "defihacklabs-2026-03-curve-llamalend",
    ]
    assert by_id["defihacklabs-2026-01-mttoken"]["source_url"] == "https://github.com/SunWeb3Sec/DeFiHackLabs"
    assert by_id["defihacklabs-2026-01-mttoken"]["reference_url"].endswith("MTToken_exp.sol")
    assert by_id["defihacklabs-2026-01-mttoken"]["chain"] == "bsc"
    assert by_id["defihacklabs-2026-01-mttoken"]["seed_transaction_hash"] == "0x" + "a" * 64
    assert by_id["defihacklabs-2026-01-mttoken"]["fork_block"] == "74937079"
    assert by_id["defihacklabs-2026-03-curve-llamalend"]["chain"] == "ethereum"
    assert by_id["defihacklabs-2026-03-curve-llamalend"]["seed_transaction_hash"] == "0x" + "b" * 64
    assert by_id["defihacklabs-2026-03-curve-llamalend"]["fork_block"] == "22044321"


def test_direct_evidence_collector_adds_github_auth_headers_when_token_is_available(tmp_path, monkeypatch):
    collector = _load_pipeline_module("direct_evidence_collector")
    monkeypatch.setenv("GITHUB_TOKEN", "gh-test-token")

    class FakeResponse:
        def __init__(self, payload: bytes) -> None:
            self._payload = payload

        def read(self) -> bytes:
            return self._payload

        def __enter__(self) -> FakeResponse:
            return self

        def __exit__(self, exc_type, exc, tb) -> bool:
            return False

    seen_auth_headers: list[str | None] = []

    def fake_urlopen(request, timeout: float):
        seen_auth_headers.append(request.get_header("Authorization"))
        if request.full_url == collector.DEFIHACKLABS_TREE_URL:
            return FakeResponse(json.dumps({"tree": [{"path": "src/test/2026-01/MTToken_exp.sol"}]}).encode("utf-8"))
        if request.full_url == collector.DEFIHACKLABS_RAW_URL.format(path="src/test/2026-01/MTToken_exp.sol"):
            return FakeResponse(
                b'// Attack Tx (BSC): https://bscscan.com/tx/0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n'
            )
        raise AssertionError(request.full_url)

    monkeypatch.setattr(collector, "urlopen", fake_urlopen)

    summary = collector.collect_direct_evidence(output_dir=tmp_path, max_defihacklabs=1)

    assert summary["direct_candidate_count"] == 1
    assert seen_auth_headers == ["Bearer gh-test-token", "Bearer gh-test-token"]


def test_direct_evidence_collector_caches_git_credential_token_lookup(monkeypatch):
    collector = _load_pipeline_module("direct_evidence_collector")
    monkeypatch.delenv("GITHUB_PERSONAL_ACCESS_TOKEN", raising=False)
    monkeypatch.delenv("GITHUB_TOKEN", raising=False)
    monkeypatch.delenv("GH_TOKEN", raising=False)

    calls: list[list[str]] = []

    class FakeCompletedProcess:
        stdout = "protocol=https\nhost=github.com\nusername=codex\npassword=gh-cached-token\n"

    def fake_run(cmd, **kwargs):
        calls.append(cmd)
        return FakeCompletedProcess()

    monkeypatch.setattr(collector.subprocess, "run", fake_run)

    assert collector._github_headers()["Authorization"] == "Bearer gh-cached-token"
    assert collector._github_raw_headers()["Authorization"] == "Bearer gh-cached-token"
    assert collector._github_token() == "gh-cached-token"
    assert calls == [["git", "credential", "fill"]]


def test_direct_evidence_collector_keeps_partial_rows_when_github_rate_limit_hits(tmp_path, monkeypatch):
    collector = _load_pipeline_module("direct_evidence_collector")

    def fake_fetch_tree() -> list[dict[str, str]]:
        return [
            {"path": "src/test/2026-01/MTToken_exp.sol"},
            {"path": "src/test/2026-03/Curve_LlamaLend_exp.sol"},
        ]

    def fake_fetch_contents(path: str) -> dict[str, str]:
        if path == "src/test/2026-01/MTToken_exp.sol":
            return {
                "path": path,
                "html_url": "https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2026-01/MTToken_exp.sol",
                "download_url": "https://raw.githubusercontent.com/SunWeb3Sec/DeFiHackLabs/main/src/test/2026-01/MTToken_exp.sol",
                "content": """
// Attack Tx (BSC) : https://bscscan.com/tx/0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
contract MTExploitTest is Test {
    uint256 internal constant FORK_BLOCK = 74_937_079;
    function setUp() public {
        vm.createSelectFork("bsc", FORK_BLOCK);
    }
}
                """,
            }
        raise HTTPError(
            collector.DEFIHACKLABS_RAW_URL.format(path=path),
            403,
            "Forbidden",
            {"X-RateLimit-Remaining": "0"},
            io.BytesIO(b'{"message":"API rate limit exceeded"}'),
        )

    monkeypatch.setattr(collector, "fetch_defihacklabs_tree", fake_fetch_tree)
    monkeypatch.setattr(collector, "fetch_defihacklabs_fixture", fake_fetch_contents)

    summary = collector.collect_direct_evidence(output_dir=tmp_path, max_defihacklabs=10)

    assert summary["collection_status"] == "rate_limited"
    assert summary["direct_candidate_count"] == 1
    rows = _read_csv(tmp_path / "direct_evidence_latest.csv")
    assert len(rows) == 1
    assert rows[0]["incident_id"] == "defihacklabs-2026-01-mttoken"
    assert "GitHub rate limit hit" in str(summary["collection_warning"])


def test_direct_evidence_collector_cli_help_runs_as_script():
    repo_root = Path(__file__).resolve().parents[1]
    script = repo_root / "tools" / "pipeline" / "direct_evidence_collector.py"
    completed = subprocess.run(
        [sys.executable, str(script), "--help"],
        cwd=repo_root,
        capture_output=True,
        text=True,
        check=False,
    )

    assert completed.returncode == 0
    assert "Collect direct evidence candidates" in completed.stdout


def test_direct_evidence_collector_fetches_fixture_from_raw_github_url(monkeypatch):
    collector = _load_pipeline_module("direct_evidence_collector")

    class FakeResponse:
        def __init__(self, payload: bytes) -> None:
            self._payload = payload

        def read(self) -> bytes:
            return self._payload

        def __enter__(self) -> FakeResponse:
            return self

        def __exit__(self, exc_type, exc, tb) -> bool:
            return False

    seen_urls: list[str] = []

    def fake_urlopen(request, timeout: float):
        seen_urls.append(request.full_url)
        return FakeResponse(b"// fixture body")

    monkeypatch.setattr(collector, "urlopen", fake_urlopen)

    fixture = collector.fetch_defihacklabs_fixture("src/test/2026-01/MTToken_exp.sol")

    assert fixture["download_url"] == (
        "https://raw.githubusercontent.com/SunWeb3Sec/DeFiHackLabs/main/src/test/2026-01/MTToken_exp.sol"
    )
    assert fixture["html_url"] == (
        "https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2026-01/MTToken_exp.sol"
    )
    assert fixture["content"] == "// fixture body"
    assert seen_urls == [
        "https://raw.githubusercontent.com/SunWeb3Sec/DeFiHackLabs/main/src/test/2026-01/MTToken_exp.sol"
    ]


def test_direct_evidence_collector_falls_back_to_contents_api_when_raw_github_unreachable(monkeypatch):
    collector = _load_pipeline_module("direct_evidence_collector")

    class FakeResponse:
        def __init__(self, payload: bytes) -> None:
            self._payload = payload

        def read(self) -> bytes:
            return self._payload

        def __enter__(self) -> FakeResponse:
            return self

        def __exit__(self, exc_type, exc, tb) -> bool:
            return False

    seen_urls: list[str] = []

    def fake_urlopen(request, timeout: float):
        seen_urls.append(request.full_url)
        if request.full_url == collector.DEFIHACKLABS_RAW_URL.format(path="src/test/2026-01/MTToken_exp.sol"):
            raise HTTPError(request.full_url, 504, "Gateway Timeout", {}, io.BytesIO(b""))
        if request.full_url == collector.DEFIHACKLABS_CONTENTS_URL.format(path="src/test/2026-01/MTToken_exp.sol"):
            payload = {
                "path": "src/test/2026-01/MTToken_exp.sol",
                "html_url": "https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2026-01/MTToken_exp.sol",
                "download_url": "https://raw.githubusercontent.com/SunWeb3Sec/DeFiHackLabs/main/src/test/2026-01/MTToken_exp.sol",
                "encoding": "base64",
                "content": base64.b64encode(b"// contents fallback body").decode("ascii"),
            }
            return FakeResponse(json.dumps(payload).encode("utf-8"))
        raise AssertionError(request.full_url)

    monkeypatch.setattr(collector, "urlopen", fake_urlopen)

    fixture = collector.fetch_defihacklabs_fixture("src/test/2026-01/MTToken_exp.sol")

    assert fixture["content"] == "// contents fallback body"
    assert seen_urls == [
        "https://raw.githubusercontent.com/SunWeb3Sec/DeFiHackLabs/main/src/test/2026-01/MTToken_exp.sol",
        "https://api.github.com/repos/SunWeb3Sec/DeFiHackLabs/contents/src/test/2026-01/MTToken_exp.sol?ref=main",
    ]


def test_run_phase1_uses_bounded_direct_evidence_default(monkeypatch):
    run_phase1 = _load_pipeline_module("run_phase1")
    commands: list[list[str]] = []

    monkeypatch.setattr(run_phase1, "ensure_repo_runtime", lambda *args, **kwargs: None)
    monkeypatch.setattr(run_phase1, "run_cmd", lambda cmd, cwd: commands.append(cmd))
    monkeypatch.setattr(
        sys,
        "argv",
        ["run_phase1.py", "--start-page", "1", "--end-page", "1", "--top-protocols", "10"],
    )

    run_phase1.main()

    direct_cmd = commands[2]
    max_index = direct_cmd.index("--max-defihacklabs")
    assert direct_cmd[max_index + 1] == "40"


def test_normalize_preserves_direct_evidence_seed_tx_and_fork_block(tmp_path):
    normalize = _load_pipeline_module("normalize")
    slowmist_csv = tmp_path / "slowmist.csv"
    protocols_csv = tmp_path / "protocols.csv"
    direct_csv = tmp_path / "direct_evidence.csv"
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

    with protocols_csv.open("w", encoding="utf-8", newline="") as fp:
        writer = csv.DictWriter(fp, fieldnames=["id", "name", "slug", "category", "tvl", "chain", "chains_count", "chains"])
        writer.writeheader()
        writer.writerow(
            {
                "id": "1",
                "name": "MTToken",
                "slug": "mttoken",
                "category": "Dexs",
                "tvl": "100",
                "chain": "Binance",
                "chains_count": "1",
                "chains": "Binance",
            }
        )

    with direct_csv.open("w", encoding="utf-8", newline="") as fp:
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
                "seed_transaction_hash",
                "fork_block",
                "direct_source_name",
                "collected_at",
            ],
        )
        writer.writeheader()
        writer.writerow(
            {
                "incident_id": "defihacklabs-2026-01-mttoken",
                "event_date": "2026-01-01",
                "target": "MTToken",
                "description": "DeFiHackLabs replay fixture with direct attack transaction evidence.",
                "loss_usd_raw": "",
                "loss_usd": "",
                "attack_method": "Contract Vulnerability",
                "reference_url": "https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2026-01/MTToken_exp.sol",
                "source_url": "https://github.com/SunWeb3Sec/DeFiHackLabs",
                "source_page": "",
                "category_filter": "defihacklabs_replay",
                "seed_transaction_hash": "0x" + "a" * 64,
                "fork_block": "74937079",
                "direct_source_name": "defihacklabs",
                "collected_at": "2026-05-24T00:00:00Z",
            }
        )

    summary = normalize.normalize_datasets(
        slowmist_csv=slowmist_csv,
        defillama_protocols_csv=protocols_csv,
        output_dir=output_dir,
        direct_evidence_csv=direct_csv,
    )

    assert summary["incident_rows"] == 1
    rows = _read_csv(output_dir / "incidents_normalized_latest.csv")
    assert rows[0]["incident_id"] == "defihacklabs-2026-01-mttoken"
    assert rows[0]["source_url"] == "https://github.com/SunWeb3Sec/DeFiHackLabs"
    assert rows[0]["category_filter"] == "defihacklabs_replay"
    assert rows[0]["seed_transaction_hash"] == "0x" + "a" * 64
    assert rows[0]["fork_block"] == "74937079"


def test_evidence_pipeline_marks_direct_replay_sources_as_candidate_discovery(tmp_path, monkeypatch):
    monkeypatch.setenv("ALCHEMY_API_KEY", "alchemy-test-key")
    incidents_csv = tmp_path / "incidents_normalized_latest.csv"
    out_dir = tmp_path / "processed"
    _write_incidents_csv(
        incidents_csv,
        [
            _incident(
                1,
                target="DeFiHackLabs Replay Candidate",
                reference_url="https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2026-01/MTToken_exp.sol",
                source_url="https://github.com/SunWeb3Sec/DeFiHackLabs",
                category_filter="defihacklabs_replay",
                seed_transaction_hash="0x" + "a" * 64,
                fork_block="74937079",
            )
        ],
    )

    produce_evidence_pipeline(
        incidents_csv=incidents_csv,
        out_dir=out_dir,
        rpc_supported_chains=["bsc"],
    )

    rows = _read_csv(out_dir / "security_evidence_enriched_latest.csv")
    assert len(rows) == 1
    assert json.loads(rows[0]["candidate_discovery_sources"]) == [
        {
            "role": "candidate_discovery",
            "source": "defihacklabs_replay",
            "url": "https://github.com/SunWeb3Sec/DeFiHackLabs",
        }
    ]
    assert json.loads(rows[0]["security_report_sources"]) == [
        {
            "source": "defihacklabs",
            "url": "https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2026-01/MTToken_exp.sol",
        }
    ]


def test_evidence_pipeline_prioritizes_direct_sources_when_reference_fetch_budget_is_tight(tmp_path, monkeypatch):
    monkeypatch.setenv("ALCHEMY_API_KEY", "alchemy-test-key")
    monkeypatch.setenv("ABRA_REFERENCE_FETCH_BUDGET", "1")
    incidents_csv = tmp_path / "incidents_normalized_latest.csv"
    out_dir = tmp_path / "processed"
    _write_incidents_csv(
        incidents_csv,
        [
            _incident(
                1,
                target="Generic Report Candidate",
                reference_url="https://www.certik.com/resources/blog/generic-report-candidate",
                source_url="https://defillama.com/hacks",
                seed_transaction_hash="",
                fork_block="",
            ),
            _incident(
                2,
                target="Direct Replay Candidate",
                reference_url="https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2026-01/MTToken_exp.sol",
                source_url="https://github.com/SunWeb3Sec/DeFiHackLabs",
                category_filter="defihacklabs_replay",
                seed_transaction_hash="",
                fork_block="",
            ),
        ],
    )

    fetched_urls: list[str] = []

    def fake_source_fetcher(url: str) -> dict[str, str]:
        fetched_urls.append(url)
        return {"status": "fetched", "url": url, "text": "no onchain anchor in fixture"}

    produce_evidence_pipeline(
        incidents_csv=incidents_csv,
        out_dir=out_dir,
        rpc_supported_chains=["ethereum"],
        source_fetcher=fake_source_fetcher,
    )

    assert fetched_urls == [
        "https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2026-01/MTToken_exp.sol"
    ]
