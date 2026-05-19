"""Bounded multi-round ABRA research agent loop."""

from __future__ import annotations

import hashlib
import json
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from abra.bundle import (
    ARTIFACT_MANIFEST_SCHEMA_VERSION,
    EVIDENCE_BUNDLE_SCHEMA_VERSION,
    EVIDENCE_LABELS,
    ara_bundle_manifest,
    ara_claims_payload,
)
from abra.manifest import load_manifest
from abra.replay_agent import assess_replay_fixture, validate_evidence_bundle
from abra.tools import list_tools


AGENT_RUN_SCHEMA_VERSION = "abra.agent_run.v1"
AGENT_STATE_SCHEMA_VERSION = "abra.agent_state.v1"
AGENT_DECISION_LEDGER_SCHEMA_VERSION = "abra.agent_decision_ledger.entry.v1"
AGENT_OBSERVATION_LEDGER_SCHEMA_VERSION = "abra.agent_observation_ledger.entry.v1"
AGENT_REFLECTION_LEDGER_SCHEMA_VERSION = "abra.agent_reflection_ledger.entry.v1"
AGENT_MEMORY_LEDGER_SCHEMA_VERSION = "abra.agent_memory_ledger.v1"
AGENT_EVIDENCE_REVIEW_SCHEMA_VERSION = "abra.agent_evidence_review.v1"
AGENT_BUNDLE_TYPE = "abra_research_agent_bundle"
DEFAULT_MAX_ROUNDS = 3
MAX_ROUNDS = 5


def run_research_agent(
    *,
    case_fixture: str | Path,
    out: str | Path,
    rounds: int = DEFAULT_MAX_ROUNDS,
    min_level: str = "L1",
) -> dict[str, Any]:
    """Run a deterministic local plan-act-observe-reflect loop over ABRA tools."""

    fixture_path = Path(case_fixture).expanduser().resolve()
    out_path = Path(out).expanduser().resolve()
    if not fixture_path.exists() or not fixture_path.is_file():
        raise FileNotFoundError(f"Replay case fixture not found: {fixture_path}")
    bounded_rounds = _bounded_rounds(rounds)
    generated_at = _utc_now()
    out_path.mkdir(parents=True, exist_ok=True)

    previous_run_count = _jsonl_entry_count(out_path / "memory" / "agent_run_ledger.jsonl")
    run_id = _run_id(generated_at, fixture_path, out_path, previous_run_count + 1)
    decisions: list[dict[str, Any]] = []
    observations: list[dict[str, Any]] = []
    reflections: list[dict[str, Any]] = []
    replay_payload: dict[str, Any] | None = None
    replay_validation: dict[str, Any] | None = None

    for round_number in range(1, bounded_rounds + 1):
        step = _round_step(round_number)
        decisions.append(_decision(run_id, generated_at, round_number, step))
        if step == "inventory":
            observations.append(_observe_inventory(run_id, generated_at, round_number))
        elif step == "replay_assessment":
            replay_payload = assess_replay_fixture(fixture_path, out_path / "replay_assessment")
            observations.append(_observe_replay(run_id, generated_at, round_number, replay_payload))
        elif step == "evidence_review":
            replay_dir = out_path / "replay_assessment"
            if replay_payload is None:
                replay_payload = assess_replay_fixture(fixture_path, replay_dir)
            replay_validation = validate_evidence_bundle(replay_dir, min_level=min_level)
            observations.append(_observe_evidence_review(run_id, generated_at, round_number, replay_validation))
        else:
            observations.append(_observe_memory(run_id, generated_at, round_number, out_path))
        reflections.append(_reflection(run_id, generated_at, round_number, step, observations[-1]))

    if replay_payload is None:
        replay_payload = assess_replay_fixture(fixture_path, out_path / "replay_assessment")
    if replay_validation is None:
        replay_validation = validate_evidence_bundle(out_path / "replay_assessment", min_level=min_level)

    evidence_review = _build_evidence_review(
        generated_at=generated_at,
        run_id=run_id,
        fixture_path=fixture_path,
        replay_payload=replay_payload,
        replay_validation=replay_validation,
        observations=observations,
    )
    state = _build_state(
        generated_at=generated_at,
        run_id=run_id,
        fixture_path=fixture_path,
        out_path=out_path,
        rounds=bounded_rounds,
        decisions=decisions,
        observations=observations,
        reflections=reflections,
        replay_payload=replay_payload,
        replay_validation=replay_validation,
    )

    written = _write_agent_files(out_path, state, decisions, observations, reflections, evidence_review)
    run_ledger_entry = _build_run_ledger_entry(state, evidence_review)
    _append_jsonl(out_path / "memory" / "agent_run_ledger.jsonl", run_ledger_entry)
    written.append("memory/agent_run_ledger.jsonl")
    memory = _build_memory_ledger(generated_at, fixture_path, out_path / "memory" / "agent_run_ledger.jsonl")
    memory_path = out_path / "memory" / "agent_memory_ledger.json"
    memory_path.write_text(json.dumps(memory, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    written.append("memory/agent_memory_ledger.json")

    artifact_entries = _agent_artifacts(out_path)
    claims = _build_claims(state, evidence_review, artifact_entries)
    limitations = _build_limitations(claims, evidence_review)
    _write_ara_sidecars(out_path, generated_at, fixture_path, claims, limitations, len(artifact_entries) + 1)

    evidence_bundle = {
        "schema_version": EVIDENCE_BUNDLE_SCHEMA_VERSION,
        "bundle_type": AGENT_BUNDLE_TYPE,
        "lab_id": "abra",
        "generated_at": generated_at,
        "source_fixture": str(fixture_path),
        "agent_state": "agent_run_state.json",
        "evidence_review": "evidence_review.json",
        "run_ledger": "memory/agent_run_ledger.jsonl",
        "memory_ledger": "memory/agent_memory_ledger.json",
        "replay_bundle": "replay_assessment/evidence_bundle.json",
        "evidence_levels": EVIDENCE_LABELS,
        "claims": claims,
        "limitations": limitations,
        "safety": state["safety"],
    }
    evidence_path = out_path / "evidence_bundle.json"
    evidence_path.write_text(json.dumps(evidence_bundle, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    artifact_entries.append(_artifact_entry(out_path, evidence_path, "evidence_bundle", "claim_index"))
    artifact_manifest = {
        "schema_version": ARTIFACT_MANIFEST_SCHEMA_VERSION,
        "generated_at": generated_at,
        "source_path": str(fixture_path),
        "artifacts": artifact_entries,
    }
    (out_path / "artifact_manifest.json").write_text(
        json.dumps(artifact_manifest, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    written.extend(
        [
            "bundle_manifest.json",
            "claims.json",
            "limitations.md",
            "drafting_brief.md",
            "writing_brief.md",
            "evidence_bundle.json",
            "artifact_manifest.json",
        ]
    )

    validation = validate_evidence_bundle(out_path, min_level=min_level)
    return {
        "schema_version": AGENT_RUN_SCHEMA_VERSION,
        "status": "passed" if validation["status"] == "passed" and replay_payload["status"] == "passed" else "failed",
        "bundle_type": AGENT_BUNDLE_TYPE,
        "bundle_path": str(out_path),
        "run_id": run_id,
        "source_fixture": str(fixture_path),
        "round_count": bounded_rounds,
        "case_count": replay_payload.get("case_count", 0),
        "replay_bundle": str(out_path / "replay_assessment"),
        "evidence_levels": evidence_review["summary"]["evidence_levels"],
        "open_blocker_count": evidence_review["summary"]["open_blocker_count"],
        "files_written": sorted(set(written)),
        "validation": validation,
    }


def _bounded_rounds(rounds: int) -> int:
    try:
        value = int(rounds)
    except (TypeError, ValueError) as exc:
        raise ValueError("rounds must be an integer") from exc
    if value < 1:
        raise ValueError("rounds must be at least 1")
    return min(value, MAX_ROUNDS)


def _round_step(round_number: int) -> str:
    if round_number == 1:
        return "inventory"
    if round_number == 2:
        return "replay_assessment"
    if round_number == 3:
        return "evidence_review"
    return "memory_reflection"


def _decision(run_id: str, generated_at: str, round_number: int, step: str) -> dict[str, Any]:
    action_by_step = {
        "inventory": "Inspect manifest and local tool inventory.",
        "replay_assessment": "Run bounded replay assessment over the local fixture.",
        "evidence_review": "Validate replay evidence levels and blocker boundaries.",
        "memory_reflection": "Summarize prior agent/replay memory without external access.",
    }
    return {
        "schema_version": AGENT_DECISION_LEDGER_SCHEMA_VERSION,
        "run_id": run_id,
        "round": round_number,
        "phase": "plan",
        "step": step,
        "selected_action": action_by_step[step],
        "rationale": "Use local ABRA tools and fixture evidence only.",
        "safety_constraints": _safety_constraints(),
    }


def _observe_inventory(run_id: str, generated_at: str, round_number: int) -> dict[str, Any]:
    manifest = load_manifest()
    tools = list_tools()
    return {
        "schema_version": AGENT_OBSERVATION_LEDGER_SCHEMA_VERSION,
        "run_id": run_id,
        "generated_at": generated_at,
        "round": round_number,
        "phase": "observe",
        "step": "inventory",
        "status": "passed" if manifest.validation.valid and all(tool["exists"] for tool in tools) else "failed",
        "summary": {
            "manifest_valid": manifest.validation.valid,
            "tool_count": len(tools),
            "available_tool_count": sum(1 for tool in tools if tool["exists"]),
            "produced_bundles": manifest.produced_bundles,
        },
        "artifacts": ["research_lab.yaml"],
    }


def _observe_replay(
    run_id: str,
    generated_at: str,
    round_number: int,
    replay_payload: dict[str, Any],
) -> dict[str, Any]:
    return {
        "schema_version": AGENT_OBSERVATION_LEDGER_SCHEMA_VERSION,
        "run_id": run_id,
        "generated_at": generated_at,
        "round": round_number,
        "phase": "observe",
        "step": "replay_assessment",
        "status": replay_payload.get("status"),
        "summary": {
            "case_count": replay_payload.get("case_count", 0),
            "status_counts": replay_payload.get("status_counts", {}),
            "feasibility_counts": replay_payload.get("feasibility_counts", {}),
            "evidence_levels": replay_payload.get("evidence_levels", {}),
        },
        "artifacts": ["replay_assessment/evidence_bundle.json", "replay_assessment/replay_blocker_ledger.json"],
    }


def _observe_evidence_review(
    run_id: str,
    generated_at: str,
    round_number: int,
    replay_validation: dict[str, Any],
) -> dict[str, Any]:
    return {
        "schema_version": AGENT_OBSERVATION_LEDGER_SCHEMA_VERSION,
        "run_id": run_id,
        "generated_at": generated_at,
        "round": round_number,
        "phase": "observe",
        "step": "evidence_review",
        "status": replay_validation.get("status"),
        "summary": {
            "minimum_level": replay_validation.get("minimum_level"),
            "claim_count": replay_validation.get("claim_count", 0),
            "artifact_count": replay_validation.get("artifact_count", 0),
            "evidence_levels": replay_validation.get("evidence_levels", {}),
            "error_count": len(replay_validation.get("errors") or []),
            "warning_count": len(replay_validation.get("warnings") or []),
        },
        "artifacts": ["replay_assessment/evidence_bundle.json"],
    }


def _observe_memory(run_id: str, generated_at: str, round_number: int, out_path: Path) -> dict[str, Any]:
    run_count = _jsonl_entry_count(out_path / "memory" / "agent_run_ledger.jsonl")
    return {
        "schema_version": AGENT_OBSERVATION_LEDGER_SCHEMA_VERSION,
        "run_id": run_id,
        "generated_at": generated_at,
        "round": round_number,
        "phase": "observe",
        "step": "memory_reflection",
        "status": "passed",
        "summary": {
            "previous_agent_run_count": run_count,
            "memory_scope": "output_bundle_local",
        },
        "artifacts": ["memory/agent_run_ledger.jsonl"],
    }


def _reflection(
    run_id: str,
    generated_at: str,
    round_number: int,
    step: str,
    observation: dict[str, Any],
) -> dict[str, Any]:
    status = str(observation.get("status") or "unknown")
    return {
        "schema_version": AGENT_REFLECTION_LEDGER_SCHEMA_VERSION,
        "run_id": run_id,
        "generated_at": generated_at,
        "round": round_number,
        "phase": "reflect",
        "step": step,
        "status": status,
        "decision": "continue" if status == "passed" else "record_blocker",
        "lesson": _reflection_lesson(step, status, observation),
    }


def _reflection_lesson(step: str, status: str, observation: dict[str, Any]) -> str:
    if step == "replay_assessment":
        levels = observation.get("summary", {}).get("evidence_levels", {})
        return f"Replay evidence remains bounded by observed levels {levels}; blockers are retained for non-L4 cases."
    if step == "evidence_review":
        return "Evidence validator output controls whether the agent bundle can be consumed downstream."
    if status != "passed":
        return "The failed local observation is preserved as a blocker instead of escalating to live actions."
    return "Local observation completed without external accounts, private keys, or broadcasts."


def _build_evidence_review(
    *,
    generated_at: str,
    run_id: str,
    fixture_path: Path,
    replay_payload: dict[str, Any],
    replay_validation: dict[str, Any],
    observations: list[dict[str, Any]],
) -> dict[str, Any]:
    replay_dir = Path(str(replay_payload["bundle_path"]))
    blocker_ledger = _load_json(replay_dir / "replay_blocker_ledger.json")
    blocker_entries = blocker_ledger.get("entries", []) if isinstance(blocker_ledger.get("entries"), list) else []
    open_blockers = [
        entry
        for entry in blocker_entries
        if isinstance(entry, dict) and entry.get("status") == "open" and entry.get("severity") == "blocking"
    ]
    return {
        "schema_version": AGENT_EVIDENCE_REVIEW_SCHEMA_VERSION,
        "bundle_type": AGENT_BUNDLE_TYPE,
        "lab_id": "abra",
        "generated_at": generated_at,
        "run_id": run_id,
        "source_fixture": str(fixture_path),
        "replay_bundle": "replay_assessment",
        "summary": {
            "replay_status": replay_payload.get("status"),
            "validation_status": replay_validation.get("status"),
            "case_count": replay_payload.get("case_count", 0),
            "claim_count": replay_validation.get("claim_count", 0),
            "evidence_levels": replay_validation.get("evidence_levels", {}),
            "open_blocker_count": len(open_blockers),
            "observation_count": len(observations),
        },
        "blockers": [
            {
                "blocker_id": entry.get("blocker_id"),
                "slug": entry.get("slug"),
                "category": entry.get("category"),
                "code": entry.get("code"),
                "required_action": entry.get("required_action"),
            }
            for entry in open_blockers
        ],
        "evidence_policy": {
            "minimum_level": replay_validation.get("minimum_level"),
            "accepted": replay_validation.get("status") == "passed",
            "non_l4_replay_claims_are_successful_replays": False,
            "private_keys_required": False,
            "broadcasts_transactions": False,
        },
        "validation": replay_validation,
    }


def _build_state(
    *,
    generated_at: str,
    run_id: str,
    fixture_path: Path,
    out_path: Path,
    rounds: int,
    decisions: list[dict[str, Any]],
    observations: list[dict[str, Any]],
    reflections: list[dict[str, Any]],
    replay_payload: dict[str, Any],
    replay_validation: dict[str, Any],
) -> dict[str, Any]:
    return {
        "schema_version": AGENT_STATE_SCHEMA_VERSION,
        "bundle_type": AGENT_BUNDLE_TYPE,
        "lab_id": "abra",
        "run_id": run_id,
        "generated_at": generated_at,
        "source_fixture": str(fixture_path),
        "bundle_path": str(out_path),
        "round_count": rounds,
        "loop": {
            "model": "bounded_plan_act_observe_reflect",
            "phases": ["plan", "act", "observe", "reflect"],
            "max_rounds": MAX_ROUNDS,
        },
        "safety": {
            "network_access": "not_used_by_agent_loop",
            "broadcasts_transactions": False,
            "requires_private_keys": False,
            "live_trading": False,
            "state_changing_rpc": False,
            "external_accounts_required": False,
            "allowed_actions": ["manifest_inspection", "tool_inventory", "local_replay_assessment", "evidence_validation"],
            "denied_actions": ["cast send", "forge --broadcast", "private_key_loading", "live_trading"],
        },
        "decisions": decisions,
        "observations": observations,
        "reflections": reflections,
        "replay_assessment": {
            "bundle_path": "replay_assessment",
            "status": replay_payload.get("status"),
            "case_count": replay_payload.get("case_count"),
            "evidence_levels": replay_payload.get("evidence_levels"),
        },
        "evidence_validation": replay_validation,
    }


def _write_agent_files(
    out_path: Path,
    state: dict[str, Any],
    decisions: list[dict[str, Any]],
    observations: list[dict[str, Any]],
    reflections: list[dict[str, Any]],
    evidence_review: dict[str, Any],
) -> list[str]:
    files: list[str] = []
    json_files = {
        "agent_run_state.json": state,
        "evidence_review.json": evidence_review,
    }
    for relative, payload in json_files.items():
        path = out_path / relative
        path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        files.append(relative)
    ledgers = {
        "memory/agent_decision_ledger.jsonl": decisions,
        "memory/agent_observation_ledger.jsonl": observations,
        "memory/agent_reflection_ledger.jsonl": reflections,
    }
    for relative, rows in ledgers.items():
        path = out_path / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("".join(json.dumps(row, sort_keys=True) + "\n" for row in rows), encoding="utf-8")
        files.append(relative)
    report = _render_final_report(state, evidence_review)
    (out_path / "final_report.md").write_text(report, encoding="utf-8")
    files.append("final_report.md")
    return files


def _build_run_ledger_entry(state: dict[str, Any], evidence_review: dict[str, Any]) -> dict[str, Any]:
    return {
        "schema_version": AGENT_RUN_SCHEMA_VERSION,
        "run_id": state["run_id"],
        "generated_at": state["generated_at"],
        "bundle_type": AGENT_BUNDLE_TYPE,
        "bundle_path": state["bundle_path"],
        "source_fixture": state["source_fixture"],
        "round_count": state["round_count"],
        "case_count": state["replay_assessment"]["case_count"],
        "evidence_levels": evidence_review["summary"]["evidence_levels"],
        "open_blocker_count": evidence_review["summary"]["open_blocker_count"],
        "safety": state["safety"],
        "artifacts": {
            "agent_state": "agent_run_state.json",
            "evidence_review": "evidence_review.json",
            "final_report": "final_report.md",
            "replay_bundle": "replay_assessment/evidence_bundle.json",
        },
    }


def _build_memory_ledger(generated_at: str, fixture_path: Path, run_ledger_path: Path) -> dict[str, Any]:
    runs = _read_jsonl_objects(run_ledger_path)
    return {
        "schema_version": AGENT_MEMORY_LEDGER_SCHEMA_VERSION,
        "bundle_type": AGENT_BUNDLE_TYPE,
        "lab_id": "abra",
        "generated_at": generated_at,
        "source_fixture": str(fixture_path),
        "run_ledger": "agent_run_ledger.jsonl",
        "summary": {
            "run_count": len(runs),
            "latest_run_id": runs[-1].get("run_id") if runs else "",
            "total_round_count": sum(int(run.get("round_count") or 0) for run in runs),
            "total_open_blocker_count": sum(int(run.get("open_blocker_count") or 0) for run in runs),
        },
        "runs": runs,
    }


def _agent_artifacts(out_path: Path) -> list[dict[str, Any]]:
    relative_files = [
        ("agent_run_state.json", "agent_run_state", "run_state"),
        ("memory/agent_decision_ledger.jsonl", "agent_decision_ledger", "decision_memory"),
        ("memory/agent_observation_ledger.jsonl", "agent_observation_ledger", "observation_memory"),
        ("memory/agent_reflection_ledger.jsonl", "agent_reflection_ledger", "reflection_memory"),
        ("memory/agent_run_ledger.jsonl", "agent_run_ledger", "run_memory"),
        ("memory/agent_memory_ledger.json", "agent_memory_ledger", "memory_summary"),
        ("evidence_review.json", "agent_evidence_review", "evidence_review"),
        ("final_report.md", "agent_final_report", "human_readable_report"),
        ("replay_assessment/evidence_bundle.json", "replay_evidence_bundle", "replay_claim_index"),
        ("replay_assessment/replay_feasibility_report.json", "replay_feasibility_report", "replay_assessment"),
        ("replay_assessment/replay_blocker_ledger.json", "replay_blocker_ledger", "blocker_index"),
        ("replay_assessment/archive_rpc_validation.json", "archive_rpc_validation", "bounded_archive_rpc_validation"),
    ]
    entries: list[dict[str, Any]] = []
    for relative, kind, role in relative_files:
        path = out_path / relative
        if path.exists() and path.is_file():
            entries.append(_artifact_entry(out_path, path, kind, role))
    return entries


def _build_claims(
    state: dict[str, Any],
    evidence_review: dict[str, Any],
    artifacts: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    artifact_ids = {artifact["bundle_path"]: artifact["artifact_id"] for artifact in artifacts}
    common_support = [
        artifact_ids["agent_run_state.json"],
        artifact_ids["evidence_review.json"],
        artifact_ids["memory/agent_run_ledger.jsonl"],
    ]
    claims = [
        {
            "claim_id": f"l1-agent-loop-{state['run_id']}",
            "claim_type": "agent_run",
            "source_kind": "agent_state",
            "title": "Bounded ABRA research agent loop completed",
            "claim": (
                f"ABRA completed {state['round_count']} local plan-act-observe-reflect rounds "
                "over manifest, tool inventory, replay assessment, evidence review, and memory."
            ),
            "evidence_level": "L1",
            "evidence_label": EVIDENCE_LABELS["L1"],
            "subject": {"kind": "agent_run", "run_id": state["run_id"], "lab_id": "abra"},
            "supported_by": common_support + [artifact_ids["memory/agent_decision_ledger.jsonl"]],
            "reproduction": {
                "status": "bounded_local_agent_run",
                "commands": [],
                "duration_seconds": 0.0,
            },
            "limitations": [
                "Agent output is bounded to local fixture evidence and local ABRA tool contracts.",
                "The loop does not independently prove exploit reproducibility beyond replay evidence levels.",
            ],
        },
        {
            "claim_id": f"l1-agent-safety-{state['run_id']}",
            "claim_type": "agent_safety_boundary",
            "source_kind": "agent_state",
            "title": "Agent loop preserved local safety boundaries",
            "claim": "The agent loop did not require private keys, broadcasts, live trading, external accounts, or state-changing RPC.",
            "evidence_level": "L1",
            "evidence_label": EVIDENCE_LABELS["L1"],
            "subject": {"kind": "safety_policy", "run_id": state["run_id"]},
            "supported_by": common_support,
            "reproduction": {"status": "safety_policy_recorded", "commands": [], "duration_seconds": 0.0},
            "limitations": ["Safety claim covers the ABRA agent loop and fixture assessment, not arbitrary external commands."],
        },
    ]
    if evidence_review["summary"]["evidence_levels"].get("L4", 0) > 0:
        claims.append(
            {
                "claim_id": f"l4-agent-reviewed-replay-{state['run_id']}",
                "claim_type": "agent_evidence_review",
                "source_kind": "replay_evidence_bundle",
                "title": "Agent reviewed replay evidence without upgrading blocked claims",
                "claim": (
                    "The agent evidence review preserved replay bundle evidence levels, including "
                    f"{evidence_review['summary']['evidence_levels'].get('L4', 0)} L4 replay claim(s), "
                    "while keeping blocker claims out of successful replay conclusions."
                ),
                "evidence_level": "L4",
                "evidence_label": EVIDENCE_LABELS["L4"],
                "subject": {"kind": "replay_evidence_review", "run_id": state["run_id"]},
                "supported_by": common_support
                + [
                    artifact_ids["replay_assessment/evidence_bundle.json"],
                    artifact_ids["replay_assessment/replay_feasibility_report.json"],
                    artifact_ids["replay_assessment/replay_blocker_ledger.json"],
                ],
                "reproduction": {
                    "status": "verified",
                    "commands": ["python3 -m abra replay assess --case-fixture <fixture> --out <bundle> --json"],
                    "duration_seconds": 0.0,
                },
                "limitations": [
                    "This agent claim inherits the replay bundle evidence boundary.",
                    "Blocked L1 replay-feasibility claims remain blockers, not successful exploit replay.",
                ],
            }
        )
    return claims


def _build_limitations(claims: list[dict[str, Any]], evidence_review: dict[str, Any]) -> list[dict[str, Any]]:
    return [
        {
            "limitation_id": "lim-agent-local-only",
            "scope": "agent_loop",
            "description": "The agent loop is deterministic and local; it does not use external accounts, private keys, broadcasts, or state-changing RPC.",
            "affected_claim_ids": [claim["claim_id"] for claim in claims],
        },
        {
            "limitation_id": "lim-agent-replay-boundary",
            "scope": "evidence_review",
            "description": "The agent reviews replay bundle evidence levels and blockers; it must not upgrade L1 replay-feasibility blockers into successful replay claims.",
            "affected_claim_ids": [claim["claim_id"] for claim in claims],
        },
        {
            "limitation_id": "lim-agent-open-blockers",
            "scope": "blockers",
            "description": f"The reviewed replay bundle has {evidence_review['summary']['open_blocker_count']} open blocking replay precondition(s).",
            "affected_claim_ids": [claim["claim_id"] for claim in claims],
        },
    ]


def _write_ara_sidecars(
    out_path: Path,
    generated_at: str,
    fixture_path: Path,
    claims: list[dict[str, Any]],
    limitations: list[dict[str, Any]],
    artifact_count: int,
) -> None:
    files = {
        "bundle_manifest.json": ara_bundle_manifest(
            generated_at=generated_at,
            source_path=str(fixture_path),
            source_bundle_type=AGENT_BUNDLE_TYPE,
            claim_count=len(claims),
            artifact_count=artifact_count,
        ),
        "claims.json": ara_claims_payload(claims, generated_at, AGENT_BUNDLE_TYPE),
    }
    for name, payload in files.items():
        (out_path / name).write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    limitations_text = _render_limitations(limitations)
    report_text = _render_drafting_brief(claims, limitations)
    (out_path / "limitations.md").write_text(limitations_text, encoding="utf-8")
    (out_path / "drafting_brief.md").write_text(report_text, encoding="utf-8")
    (out_path / "writing_brief.md").write_text(report_text, encoding="utf-8")


def _render_final_report(state: dict[str, Any], evidence_review: dict[str, Any]) -> str:
    summary = evidence_review["summary"]
    lines = [
        "# ABRA Research Agent Report",
        "",
        f"- Run: `{state['run_id']}`",
        f"- Rounds: {state['round_count']}",
        f"- Replay cases: {summary['case_count']}",
        f"- Evidence levels: `{summary['evidence_levels']}`",
        f"- Open blocking replay preconditions: {summary['open_blocker_count']}",
        "",
        "## Safety",
        "",
        "- No private keys.",
        "- No transaction broadcast.",
        "- No live trading or state-changing RPC.",
        "",
        "## Rounds",
        "",
    ]
    for observation in state["observations"]:
        lines.append(
            f"- Round {observation['round']} `{observation['step']}`: "
            f"`{observation['status']}` with summary `{observation['summary']}`."
        )
    return "\n".join(lines) + "\n"


def _render_limitations(limitations: list[dict[str, Any]]) -> str:
    lines = ["# ABRA Agent Bundle Limitations", ""]
    for limitation in limitations:
        lines.append(f"- `{limitation['limitation_id']}` ({limitation['scope']}): {limitation['description']}")
    return "\n".join(lines) + "\n"


def _render_drafting_brief(claims: list[dict[str, Any]], limitations: list[dict[str, Any]]) -> str:
    lines = [
        "# ABRA Agent ARA Drafting Brief",
        "",
        "## Evidence Boundary",
        "",
        "- Treat the agent bundle as local orchestration evidence.",
        "- Do not describe L1 replay-feasibility blockers as successful exploit replay.",
        "- Do not use private keys, broadcasts, live trading, or state-changing RPC.",
        "",
        "## Claims",
        "",
    ]
    for claim in claims:
        lines.append(f"- `{claim['claim_id']}` ({claim['evidence_level']} {claim['evidence_label']}): {claim['claim']}")
    lines.extend(["", "## Limitations", ""])
    for limitation in limitations:
        lines.append(f"- `{limitation['limitation_id']}`: {limitation['description']}")
    return "\n".join(lines) + "\n"


def _safety_constraints() -> dict[str, Any]:
    return {
        "private_keys_required": False,
        "broadcasts_transactions": False,
        "state_changing_rpc": False,
        "external_accounts_required": False,
    }


def _artifact_entry(root: Path, path: Path, kind: str, role: str) -> dict[str, Any]:
    relative = path.relative_to(root)
    return {
        "artifact_id": _artifact_id(relative),
        "kind": kind,
        "role": role,
        "description": _artifact_description(kind, role),
        "path": relative.as_posix(),
        "bundle_path": relative.as_posix(),
        "sha256": _sha256_file(path),
        "size_bytes": path.stat().st_size,
    }


def _artifact_description(kind: str, role: str) -> str:
    if kind.startswith("agent_"):
        return f"ABRA agent artifact for {role}."
    if kind.startswith("replay_"):
        return "Nested replay assessment artifact reviewed by the ABRA agent loop."
    if kind == "archive_rpc_validation":
        return "Nested deterministic archive RPC validation artifact; no live RPC used by agent loop."
    if kind == "evidence_bundle":
        return "ABRA agent evidence bundle claim index."
    return f"ABRA agent bundle artifact for {role}."


def _artifact_id(relative: Path) -> str:
    normalized = re.sub(r"[^a-zA-Z0-9]+", "-", relative.as_posix()).strip("-").lower()
    digest = hashlib.sha256(relative.as_posix().encode("utf-8")).hexdigest()[:10]
    return f"artifact-{normalized}-{digest}"


def _append_jsonl(path: Path, entry: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(entry, sort_keys=True) + "\n")


def _read_jsonl_objects(path: Path) -> list[dict[str, Any]]:
    if not path.exists():
        return []
    rows: list[dict[str, Any]] = []
    for line in path.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        try:
            data = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(data, dict):
            rows.append(data)
    return rows


def _jsonl_entry_count(path: Path) -> int:
    return len(_read_jsonl_objects(path))


def _load_json(path: Path) -> dict[str, Any]:
    if not path.exists():
        return {}
    data = json.loads(path.read_text(encoding="utf-8"))
    return data if isinstance(data, dict) else {}


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _run_id(generated_at: str, fixture_path: Path, out_path: Path, run_number: int) -> str:
    stamp = re.sub(r"[^0-9A-Za-z]+", "", generated_at)
    digest = hashlib.sha256(f"{generated_at}|{fixture_path}|{out_path}|{run_number}".encode("utf-8")).hexdigest()[:10]
    return f"agent-run-{stamp}-{run_number:04d}-{digest}"


def _utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()
