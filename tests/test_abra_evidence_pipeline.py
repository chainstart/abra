from __future__ import annotations

import csv
import importlib.util
import json
import subprocess
import sys
from pathlib import Path

from abra.evidence_pipeline import produce_evidence_pipeline


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
    assert payload["summary"]["alchemy_backfill_candidate_count"] == 2
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
    }
    backfill_by_slug = {row["slug"]: row for row in backfill_rows}
    assert backfill_by_slug["certik-anchored-missing-onchain"]["backfill_status"] == "missing_onchain_anchor"
    assert backfill_by_slug["certik-anchored-missing-onchain"]["rpc_supported"] == "true"
    assert backfill_by_slug["blocksec-complete-anchor"]["backfill_status"] == "not_required"
    assert backfill_by_slug["blocksec-complete-anchor"]["seed_transaction_hash"] == "0x" + "2" * 64

    enriched_json = json.loads((out_dir / "security_evidence_enriched_latest.json").read_text(encoding="utf-8"))
    assert enriched_json["stage"] == "security_evidence_enrichment"
    assert enriched_json["summary"]["text_only_security_mentions_ignored_count"] == 1

    backfill_json = json.loads((out_dir / "alchemy_onchain_backfill_latest.json").read_text(encoding="utf-8"))
    assert backfill_json["stage"] == "alchemy_onchain_backfill"
    assert backfill_json["rpc_capability"]["provider"] == "alchemy"
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
