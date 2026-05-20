from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

from abra.memory import build_memory_index, query_memory_index


def test_memory_build_indexes_incidents_replay_findings_and_agent_ledgers(tmp_path):
    reports, data = _write_memory_fixture(tmp_path)
    out = tmp_path / "memory_index"

    payload = build_memory_index(reports, data, out)

    assert payload["status"] == "passed"
    assert payload["summary"]["incident_count"] == 2
    assert payload["summary"]["replay_memory_count"] >= 4
    assert payload["summary"]["finding_count"] >= 1
    assert payload["summary"]["decision_count"] == 1
    assert payload["summary"]["observation_count"] >= 2
    assert payload["summary"]["evidence_levels"]["L4"] >= 1
    assert (out / "index.json").exists()
    assert (out / "replay_memory.jsonl").exists()
    assert (out / "observations.jsonl").exists()

    index = json.loads((out / "index.json").read_text(encoding="utf-8"))
    assert index["schema_version"] == "abra.incident_memory_index.v1"
    assert index["deterministic"] is True
    assert index["summary"] == payload["summary"]


def test_memory_query_returns_replay_topic_results(tmp_path):
    reports, data = _write_memory_fixture(tmp_path)
    out = tmp_path / "memory_index"
    build_memory_index(reports, data, out)

    payload = query_memory_index(out, "replay")

    assert payload["status"] == "passed"
    assert payload["topic"] == "replay"
    assert payload["matched_count"] >= 4
    assert payload["type_counts"]["replay"] >= 4
    assert any(result["evidence_level"] == "L4" for result in payload["results"])
    assert any("archive_state_unavailable" in json.dumps(result) for result in payload["results"])


def test_memory_cli_build_and_query_round_trip(tmp_path):
    reports, data = _write_memory_fixture(tmp_path)
    out = tmp_path / "memory_index"

    build_result = subprocess.run(
        [
            sys.executable,
            "-m",
            "abra",
            "memory",
            "build",
            "--reports",
            str(reports),
            "--data",
            str(data),
            "--out",
            str(out),
            "--json",
        ],
        check=False,
        capture_output=True,
        text=True,
    )
    assert build_result.returncode == 0, build_result.stderr
    build_payload = json.loads(build_result.stdout)
    assert build_payload["summary"]["incident_count"] == 2

    query_result = subprocess.run(
        [
            sys.executable,
            "-m",
            "abra",
            "memory",
            "query",
            "--index",
            str(out),
            "--topic",
            "replay",
            "--json",
        ],
        check=False,
        capture_output=True,
        text=True,
    )
    assert query_result.returncode == 0, query_result.stderr
    query_payload = json.loads(query_result.stdout)
    assert query_payload["matched_count"] >= 4


def _write_memory_fixture(tmp_path: Path) -> tuple[Path, Path]:
    reports = tmp_path / "reports"
    data = tmp_path / "data"
    processed = data / "processed"
    events = reports / "events"
    memory = reports / "agent_bundle" / "memory"
    processed.mkdir(parents=True)
    events.mkdir(parents=True)
    memory.mkdir(parents=True)

    (processed / "incidents_normalized_latest.csv").write_text(
        "\n".join(
            [
                "incident_id,event_date,target,protocol_slug_guess,is_defi,attack_method_raw,attack_family,loss_usd_raw,loss_usd,reference_url,source_url,source_page,category_filter,description,normalized_at",
                "inc-euler,2023-03-13,Euler Finance,euler-finance,true,Flash Loan Attack,flash_loan,$197000000,197000000,https://example.test/euler,source,1,all,Euler exploit description,2026-05-20T00:00:00Z",
                "inc-bonq,2023-02-02,BonqDAO & AllianceBlock,bonqdao-allianceblock,true,Oracle Manipulation,oracle_manipulation,$120000000,120000000,https://example.test/bonq,source,1,all,Bonq exploit description,2026-05-20T00:00:00Z",
            ]
        )
        + "\n",
        encoding="utf-8",
    )
    (processed / "replay_results.csv").write_text(
        "\n".join(
            [
                "incident,slug,chain,rpc_env,attack_family,loss_usd,fork_block,test_path,replay_test,status,metadata_status,command,returncode,duration_seconds,log_path,blocker,verified",
                "Euler Finance,euler-finance,ethereum,ETH_RPC_URL,flash_loan,197000000,16817995,test/Euler.t.sol,test_Euler,verified,passed,forge test,0,1.0,reports/replay_runs/euler.log,,True",
                "BonqDAO & AllianceBlock,bonqdao-allianceblock,polygon,POLYGON_RPC_URL,oracle_manipulation,120000000,38792977,test/Bonq.t.sol,test_Bonq,failed,passed,forge test,1,1.0,reports/replay_runs/bonq.log,archive_state_unavailable,False",
            ]
        )
        + "\n",
        encoding="utf-8",
    )
    (processed / "replay_blocker_matrix.csv").write_text(
        "\n".join(
            [
                "incident,slug,chain,status,has_replay_test,rpc_configured,metadata_passed,needs_archive_rpc,needs_replay_logic,needs_non_evm_harness,verified,blocker",
                "Euler Finance,euler-finance,ethereum,verified,True,True,True,False,False,False,True,",
                "BonqDAO & AllianceBlock,bonqdao-allianceblock,polygon,failed,True,True,True,True,False,False,False,archive_state_unavailable",
            ]
        )
        + "\n",
        encoding="utf-8",
    )
    (events / "2023-03-13_euler-finance_fixture.md").write_text(
        """# Incident Card - Euler Finance

## Metadata

- Incident ID: `inc-euler`
- Date: `2023-03-13`
- DeFi Label: `true`
- Attack Family: `flash_loan`
- Attack Method (raw): `Flash Loan Attack`
- Estimated Loss: `$197000000.00`
- Reference URL: https://example.test/euler

## Source Description

Euler event card description.
""",
        encoding="utf-8",
    )
    (reports / "27_replay_verification_results.md").write_text(
        """# Report 27: Replay Verification Results

Replay cases tracked with archive-state blocker and verified fork replay separation.
""",
        encoding="utf-8",
    )
    (memory / "agent_decision_ledger.jsonl").write_text(
        json.dumps(
            {
                "schema_version": "abra.agent_decision_ledger.entry.v1",
                "run_id": "agent-run-fixture",
                "round": 2,
                "step": "replay_assessment",
                "selected_action": "Run bounded replay assessment over the local fixture.",
                "rationale": "Use local ABRA tools and fixture evidence only.",
            },
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )
    (memory / "agent_observation_ledger.jsonl").write_text(
        json.dumps(
            {
                "schema_version": "abra.agent_observation_ledger.entry.v1",
                "run_id": "agent-run-fixture",
                "round": 2,
                "step": "replay_assessment",
                "status": "passed",
                "summary": {"case_count": 2, "evidence_levels": {"L4": 1, "L1": 1}},
            },
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )
    (memory / "replay_run_ledger.jsonl").write_text(
        json.dumps(
            {
                "schema_version": "abra.replay_run_ledger.entry.v1",
                "run_id": "replay-run-fixture",
                "cases": [
                    {
                        "case_id": "case-1",
                        "slug": "euler-finance",
                        "incident": "Euler Finance",
                        "chain": "ethereum",
                        "replay_status": "verified",
                        "feasibility": "replay_verified",
                        "evidence_level": "L4",
                        "failure_code": "",
                    }
                ],
            },
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )
    return reports, data
