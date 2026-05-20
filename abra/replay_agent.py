"""Bounded ABRA replay feasibility and evidence bundle support."""

from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
from dataclasses import asdict
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
from tools.replay_runner import ReplayResult, classify_failure


REPLAY_CASE_FIXTURE_SCHEMA_VERSION = "abra.replay_case_fixture.v1"
ARCHIVE_RPC_PROFILE_SCHEMA_VERSION = "abra.archive_rpc_profile.v1"
ARCHIVE_RPC_PREFLIGHT_SCHEMA_VERSION = "abra.archive_rpc_preflight.v1"
ARCHIVE_REPLAY_TRACE_SCHEMA_VERSION = "abra.archive_replay_trace_fixture.v1"
REPLAY_FEASIBILITY_REPORT_SCHEMA_VERSION = "abra.replay_feasibility_report.v2"
REPLAY_BLOCKER_LEDGER_SCHEMA_VERSION = "abra.replay_blocker_ledger.v1"
ARCHIVE_RPC_VALIDATION_SCHEMA_VERSION = "abra.archive_rpc_validation.v1"
ARA_PRODUCTION_CONTRACT_SCHEMA_VERSION = "abra.ara_production_contract.v1"
REPLAY_RUN_LEDGER_ENTRY_SCHEMA_VERSION = "abra.replay_run_ledger.entry.v1"
REPLAY_MEMORY_LEDGER_SCHEMA_VERSION = "abra.replay_memory_ledger.v1"
REPLAY_ASSESSMENT_SCHEMA_VERSION = "abra.replay_assessment.build.v1"
EVIDENCE_VALIDATION_SCHEMA_VERSION = "abra.evidence.validation.v1"
REPLAY_BUNDLE_TYPE = "abra_replay_evidence_bundle"
EVIDENCE_ORDER = {level: index for index, level in enumerate(EVIDENCE_LABELS)}
DENIED_COMMAND_PATTERNS = (
    "--broadcast",
    "cast send",
    "PRIVATE_KEY",
    "private_key",
    "private-key",
    "eth_sendRawTransaction",
)
REQUIRED_BLOCKER_LEDGER_CATEGORIES = {
    "archive_rpc_state",
    "trace_availability",
    "fork_block_gap",
    "simulation_precondition",
    "safety_decision",
}
NON_EVM_CHAINS = {"eos", "sui", "terra"}


def assess_replay_fixture(
    case_fixture: str | Path,
    out: str | Path,
    archive_profile: str | Path | None = None,
    profile: str | None = None,
) -> dict[str, Any]:
    """Assess replay feasibility from a local fixture and write a replay evidence bundle."""

    profile_name = _normalize_replay_profile(profile)
    fixture_path = Path(case_fixture).expanduser().resolve()
    out_path = Path(out).expanduser().resolve()
    if not fixture_path.exists() or not fixture_path.is_file():
        raise FileNotFoundError(f"Replay case fixture not found: {fixture_path}")

    fixture = _load_json_object(fixture_path)
    cases = _fixture_cases(fixture)
    profile_path: Path | None = None
    profile: dict[str, Any] | None = None
    if archive_profile is not None:
        profile_path = Path(archive_profile).expanduser().resolve()
        if not profile_path.exists() or not profile_path.is_file():
            raise FileNotFoundError(f"Archive RPC replay profile not found: {profile_path}")
        profile = _load_archive_profile(profile_path)
        cases = _apply_archive_profile(cases, profile)
    generated_at = _utc_now()
    out_path.mkdir(parents=True, exist_ok=True)
    artifacts_dir = out_path / "artifacts"
    artifacts_dir.mkdir(parents=True, exist_ok=True)

    fixture_copy = artifacts_dir / "input" / fixture_path.name
    fixture_copy.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(fixture_path, fixture_copy)
    profile_copy: Path | None = None
    if profile_path is not None:
        profile_copy = artifacts_dir / "input" / profile_path.name
        profile_copy.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(profile_path, profile_copy)

    global_env = _environment_map(fixture.get("environment"))
    use_process_environment = bool(fixture.get("allow_process_environment"))
    assessments: list[dict[str, Any]] = []
    log_paths: list[Path] = []
    for index, raw_case in enumerate(cases, start=1):
        assessment, log_path = _assess_case(raw_case, index, global_env, out_path, use_process_environment)
        assessments.append(assessment)
        if log_path is not None:
            log_paths.append(log_path)

    trace_paths = _write_archive_profile_trace_artifacts(out_path, generated_at, assessments)
    blocker_ledger = _build_blocker_ledger(
        generated_at=generated_at,
        fixture_path=fixture_path,
        fixture=fixture,
        assessments=assessments,
    )
    archive_rpc_validation = _build_archive_rpc_validation(
        generated_at=generated_at,
        fixture_path=fixture_path,
        fixture=fixture,
        assessments=assessments,
        archive_profile=profile,
    )
    archive_rpc_preflight = _build_archive_rpc_preflight(
        generated_at=generated_at,
        profile_path=profile_path,
        profile=profile,
        assessments=assessments,
    )
    report = _build_replay_report(
        generated_at=generated_at,
        fixture_path=fixture_path,
        fixture=fixture,
        assessments=assessments,
        blocker_ledger=blocker_ledger,
        archive_rpc_validation=archive_rpc_validation,
    )
    report_json_path = out_path / "replay_feasibility_report.json"
    report_md_path = out_path / "replay_feasibility_report.md"
    blocker_ledger_path = out_path / "replay_blocker_ledger.json"
    archive_rpc_validation_path = out_path / "archive_rpc_validation.json"
    archive_rpc_preflight_path = out_path / "archive_rpc_preflight.json"
    report_json_path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    report_md_path.write_text(_render_replay_report(report), encoding="utf-8")
    blocker_ledger_path.write_text(json.dumps(blocker_ledger, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    archive_rpc_validation_path.write_text(
        json.dumps(archive_rpc_validation, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    if archive_rpc_preflight is not None:
        archive_rpc_preflight_path.write_text(
            json.dumps(archive_rpc_preflight, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )

    run_ledger_path = out_path / "memory" / "replay_run_ledger.jsonl"
    run_entry = _build_run_ledger_entry(
        generated_at=generated_at,
        fixture_path=fixture_path,
        out_path=out_path,
        fixture=fixture,
        assessments=assessments,
        blocker_ledger=blocker_ledger,
        archive_rpc_validation=archive_rpc_validation,
        existing_run_count=_jsonl_entry_count(run_ledger_path),
    )
    _append_jsonl(run_ledger_path, run_entry)
    memory_ledger_path = out_path / "memory" / "replay_memory_ledger.json"
    memory_ledger = _build_memory_ledger(generated_at, fixture_path, run_ledger_path)
    memory_ledger_path.write_text(json.dumps(memory_ledger, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    artifact_entries = [
        _artifact_entry(out_path, report_json_path, "replay_feasibility_report", "replay_assessment"),
        _artifact_entry(out_path, report_md_path, "replay_feasibility_report", "human_readable_replay_assessment"),
        _artifact_entry(out_path, blocker_ledger_path, "replay_blocker_ledger", "blocker_index"),
        _artifact_entry(
            out_path,
            archive_rpc_validation_path,
            "archive_rpc_validation",
            "bounded_archive_rpc_validation",
        ),
        _artifact_entry(out_path, run_ledger_path, "replay_run_ledger", "memory_run_index"),
        _artifact_entry(out_path, memory_ledger_path, "replay_memory_ledger", "memory_summary"),
        _artifact_entry(out_path, fixture_copy, "replay_case_fixture", "input_fixture"),
    ]
    if profile_copy is not None:
        artifact_entries.append(_artifact_entry(out_path, profile_copy, "archive_rpc_profile", "input_profile"))
    if archive_rpc_preflight is not None:
        artifact_entries.append(
            _artifact_entry(out_path, archive_rpc_preflight_path, "archive_rpc_preflight", "read_only_preflight")
        )
    artifact_entries.extend(
        _artifact_entry(out_path, path, "replay_log", "fixture_replay_log") for path in sorted(log_paths)
    )
    artifact_entries.extend(
        _artifact_entry(out_path, path, "archive_replay_trace", "fixture_trace_capture")
        for path in sorted(trace_paths)
    )

    artifact_by_path = {entry["bundle_path"]: entry for entry in artifact_entries}
    claims = _build_claims(assessments, artifact_entries, artifact_by_path)
    limitations = _bundle_limitations(assessments, claims)
    evidence_bundle = {
        "schema_version": EVIDENCE_BUNDLE_SCHEMA_VERSION,
        "bundle_type": REPLAY_BUNDLE_TYPE,
        "lab_id": "abra",
        "generated_at": generated_at,
        "source_fixture": str(fixture_path),
        "archive_profile": str(profile_path) if profile_path else "",
        "replay_report": "replay_feasibility_report.json",
        "blocker_ledger": "replay_blocker_ledger.json",
        "archive_rpc_validation": "archive_rpc_validation.json",
        "archive_rpc_preflight": "archive_rpc_preflight.json" if archive_rpc_preflight is not None else "",
        "run_ledger": "memory/replay_run_ledger.jsonl",
        "memory_ledger": "memory/replay_memory_ledger.json",
        "evidence_levels": EVIDENCE_LABELS,
        "claims": claims,
        "limitations": limitations,
        "safety": report["safety"],
    }
    evidence_path = out_path / "evidence_bundle.json"
    evidence_path.write_text(json.dumps(evidence_bundle, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    artifact_entries.append(_artifact_entry(out_path, evidence_path, "evidence_bundle", "claim_index"))
    ara_production_contract_path: Path | None = None
    if profile_name == "ara-production":
        ara_production_contract_path = out_path / "ara_production_contract.json"
        ara_production_contract = _build_ara_production_contract(
            generated_at=generated_at,
            fixture_path=fixture_path,
            claims=claims,
            limitations=limitations,
            archive_rpc_validation=archive_rpc_validation,
            archive_rpc_preflight=archive_rpc_preflight,
        )
        ara_production_contract_path.write_text(
            json.dumps(ara_production_contract, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        artifact_entries.append(
            _artifact_entry(out_path, ara_production_contract_path, "ara_production_contract", "public_ara_gate")
        )

    ara_files = _write_ara_contract_files(
        out_path=out_path,
        generated_at=generated_at,
        source_fixture=str(fixture_path),
        claims=claims,
        limitations=limitations,
        artifact_count=len(artifact_entries),
        contract_profile=profile_name,
        ara_production_contract="ara_production_contract.json" if ara_production_contract_path is not None else "",
    )

    artifact_manifest = {
        "schema_version": ARTIFACT_MANIFEST_SCHEMA_VERSION,
        "generated_at": generated_at,
        "source_path": str(fixture_path),
        "artifacts": artifact_entries,
    }
    artifact_manifest_path = out_path / "artifact_manifest.json"
    artifact_manifest_path.write_text(json.dumps(artifact_manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    validation = validate_evidence_bundle(out_path, min_level="L1")
    files_written = [
        "replay_feasibility_report.json",
        "replay_feasibility_report.md",
        "replay_blocker_ledger.json",
        "archive_rpc_validation.json",
        "memory/replay_run_ledger.jsonl",
        "memory/replay_memory_ledger.json",
        "evidence_bundle.json",
        "artifact_manifest.json",
    ]
    if archive_rpc_preflight is not None:
        files_written.append("archive_rpc_preflight.json")
    if profile_copy is not None:
        files_written.append(str(profile_copy.relative_to(out_path)))
    if ara_production_contract_path is not None:
        files_written.append("ara_production_contract.json")
    files_written.extend(ara_files)
    files_written.extend(str(path.relative_to(out_path)) for path in sorted(log_paths))
    files_written.extend(str(path.relative_to(out_path)) for path in sorted(trace_paths))
    payload = {
        "schema_version": REPLAY_ASSESSMENT_SCHEMA_VERSION,
        "status": "passed" if validation["status"] == "passed" else "failed",
        "bundle_type": REPLAY_BUNDLE_TYPE,
        "bundle_path": str(out_path),
        "source_fixture": str(fixture_path),
        "profile": profile_name,
        "archive_profile": str(profile_path) if profile_path else "",
        "case_count": len(assessments),
        "status_counts": _count_by_key(assessments, "replay_status"),
        "feasibility_counts": _count_by_key(assessments, "feasibility"),
        "blocker_ledger": {
            "path": "replay_blocker_ledger.json",
            "entry_count": blocker_ledger["summary"]["entry_count"],
            "category_counts": blocker_ledger["summary"]["category_counts"],
        },
        "archive_rpc_validation": {
            "path": "archive_rpc_validation.json",
            "mode": archive_rpc_validation["mode"],
            "status_counts": archive_rpc_validation["summary"]["status_counts"],
        },
        "archive_rpc_preflight": {
            "path": "archive_rpc_preflight.json" if archive_rpc_preflight is not None else "",
            "status": archive_rpc_preflight["status"] if archive_rpc_preflight is not None else "not_requested",
        },
        "ara_production_contract": {
            "path": "ara_production_contract.json" if ara_production_contract_path is not None else "",
            "profile": profile_name,
            "status": "emitted" if ara_production_contract_path is not None else "not_requested",
        },
        "run_ledger": {
            "path": "memory/replay_run_ledger.jsonl",
            "run_id": run_entry["run_id"],
        },
        "evidence_levels": _evidence_counts(claims),
        "files_written": files_written,
        "validation": validation,
    }
    return payload


def validate_evidence_bundle(bundle_path: str | Path, min_level: str = "L0") -> dict[str, Any]:
    """Validate a replay or result evidence bundle directory."""

    root = Path(bundle_path).expanduser().resolve()
    errors: list[str] = []
    warnings: list[str] = []
    files_checked: list[str] = []
    minimum = str(min_level or "L0").upper()
    if minimum not in EVIDENCE_ORDER:
        errors.append(f"Unsupported minimum evidence level: {min_level}")
        minimum = "L0"

    if not root.exists() or not root.is_dir():
        return _evidence_validation_payload(root, minimum, errors + [f"Bundle directory not found: {root}"], warnings, [], [], [])

    evidence = _load_bundle_json(root / "evidence_bundle.json", errors)
    artifact_manifest = _load_bundle_json(root / "artifact_manifest.json", errors)
    for relative in ("evidence_bundle.json", "artifact_manifest.json"):
        if (root / relative).exists():
            files_checked.append(relative)
        else:
            errors.append(f"Required evidence file is missing: {relative}")
    if not evidence or not artifact_manifest:
        return _evidence_validation_payload(root, minimum, errors, warnings, files_checked, [], [])

    if evidence.get("schema_version") != EVIDENCE_BUNDLE_SCHEMA_VERSION:
        errors.append("evidence_bundle.json has an unsupported schema_version.")
    if artifact_manifest.get("schema_version") != ARTIFACT_MANIFEST_SCHEMA_VERSION:
        errors.append("artifact_manifest.json has an unsupported schema_version.")
    if evidence.get("lab_id") != "abra":
        errors.append("evidence_bundle.json must declare lab_id `abra`.")

    artifacts = artifact_manifest.get("artifacts")
    if not isinstance(artifacts, list) or not artifacts:
        errors.append("artifact_manifest.json must contain at least one artifact.")
        artifacts = []
    artifact_ids = _validate_evidence_artifacts(root, artifacts, errors, warnings, files_checked)

    claims = evidence.get("claims")
    if not isinstance(claims, list) or not claims:
        errors.append("evidence_bundle.json must contain at least one claim.")
        claims = []
    _validate_evidence_claims(claims, artifact_ids, minimum, errors, warnings)

    if evidence.get("bundle_type") == REPLAY_BUNDLE_TYPE:
        _validate_replay_report(root, errors, warnings, files_checked)
        _validate_replay_blocker_ledger(root, evidence, errors, warnings, files_checked)
        _validate_archive_rpc_validation(root, evidence, errors, warnings, files_checked)
        _validate_archive_rpc_preflight(root, evidence, errors, warnings, files_checked)
        _validate_replay_memory_ledgers(root, evidence, errors, warnings, files_checked)

    return _evidence_validation_payload(root, minimum, errors, warnings, files_checked, claims, artifacts)


def _assess_case(
    raw_case: dict[str, Any],
    index: int,
    global_env: dict[str, bool],
    out_path: Path,
    use_process_environment: bool,
) -> tuple[dict[str, Any], Path | None]:
    if not isinstance(raw_case, dict):
        raise ValueError(f"Replay fixture case {index} must be a mapping.")

    result_data = dict(raw_case.get("fixture_result") or {})
    incident = str(raw_case.get("incident") or f"Fixture case {index}").strip()
    slug = _slug(str(raw_case.get("slug") or incident))
    chain = str(raw_case.get("chain") or "unknown")
    rpc_env = str(raw_case.get("rpc_env") or "")
    attack_family = str(raw_case.get("attack_family") or "unknown")
    fork_block = raw_case.get("fork_block")
    test_path = _optional_str(raw_case.get("test_path"))
    metadata_test = _optional_str(raw_case.get("metadata_test"))
    replay_test = _optional_str(raw_case.get("replay_test"))
    env_present, env_source = _case_env_present(raw_case, global_env, rpc_env, use_process_environment)

    command = str(result_data.get("command") or raw_case.get("command") or "")
    if not command and test_path and replay_test:
        command = _forge_command_text(test_path, replay_test)
    safety_violations = _command_safety_violations(command)

    log_text = str(result_data.get("log_text") or raw_case.get("log_text") or "")
    blocker = str(result_data.get("blocker") or raw_case.get("blocker") or "")
    returncode = result_data.get("returncode", raw_case.get("returncode"))
    explicit_status = str(result_data.get("status") or raw_case.get("status") or "")
    status = _resolve_status(
        explicit_status=explicit_status,
        test_path=test_path,
        replay_test=replay_test,
        rpc_env=rpc_env,
        env_present=env_present,
        returncode=returncode,
    )
    if not blocker:
        blocker = _infer_blocker(status, rpc_env, log_text)
    if safety_violations:
        status = "unsafe_fixture_command"
        blocker = "unsafe_fixture_command"

    verified = bool(result_data.get("verified")) or status == "verified" or returncode == 0
    if status != "verified":
        verified = False
    evidence_level = "L4" if verified else "L1"
    log_path = _write_case_log(out_path, slug, log_text)
    bundle_log_path = str(log_path.relative_to(out_path)) if log_path else ""
    trace = _trace_metadata(raw_case, result_data)
    archive_profile_metadata = raw_case.get("_archive_profile")
    if not isinstance(archive_profile_metadata, dict):
        archive_profile_metadata = {}
    metadata_status = str(
        result_data.get("metadata_status")
        or raw_case.get("metadata_status")
        or _metadata_status(test_path, metadata_test)
    )
    replay_result = ReplayResult(
        incident=incident,
        slug=slug,
        chain=chain,
        rpc_env=rpc_env,
        attack_family=attack_family,
        loss_usd=int(raw_case.get("loss_usd") or 0),
        fork_block=int(fork_block) if isinstance(fork_block, int) else None,
        test_path=test_path,
        replay_test=replay_test,
        status=status,
        metadata_status=metadata_status,
        command=command,
        returncode=returncode if isinstance(returncode, int) else None,
        duration_seconds=float(result_data.get("duration_seconds") or raw_case.get("duration_seconds") or 0.0),
        log_path=bundle_log_path,
        blocker=blocker,
        verified=verified,
    )

    required_environment = []
    if rpc_env:
        required_environment.append(
            {
                "name": rpc_env,
                "required": bool(test_path and replay_test),
                "present": env_present,
                "source": env_source,
                "purpose": f"Archive-capable {chain} RPC for fork replay",
                "fork_block": fork_block,
                "note": _rpc_note(status, rpc_env, env_present),
            }
        )
    failure_reason = _failure_reason(status, blocker, rpc_env)
    simulation_preconditions = _simulation_preconditions(
        chain=chain,
        rpc_env=rpc_env,
        env_present=env_present,
        env_source=env_source,
        fork_block=fork_block,
        test_path=test_path,
        replay_test=replay_test,
        metadata_status=metadata_status,
        safety_violations=safety_violations,
    )
    assessment = {
        "case_id": f"replay-case-{index:04d}-{slug}",
        "incident": incident,
        "slug": slug,
        "chain": chain,
        "attack_family": attack_family,
        "loss_usd": int(raw_case.get("loss_usd") or 0),
        "fork_block": fork_block,
        "runner": {
            "source": "tools.replay_runner",
            "result_model": "ReplayResult",
            "test_path": test_path,
            "metadata_test": metadata_test,
            "replay_test": replay_test,
            "command": command,
            "dry_run": True,
            "executed_live": False,
        },
        "replay_status": status,
        "metadata_status": replay_result.metadata_status,
        "feasibility": _feasibility(status, blocker),
        "verified": verified,
        "evidence_level": evidence_level,
        "evidence_label": EVIDENCE_LABELS[evidence_level],
        "failure_reason": failure_reason,
        "required_environment": required_environment,
        "trace": trace,
        "archive_profile": archive_profile_metadata,
        "simulation_preconditions": simulation_preconditions,
        "safety_violations": safety_violations,
        "log_path": bundle_log_path,
        "normalized_replay_result": asdict(replay_result),
    }
    return assessment, log_path


def _build_replay_report(
    *,
    generated_at: str,
    fixture_path: Path,
    fixture: dict[str, Any],
    assessments: list[dict[str, Any]],
    blocker_ledger: dict[str, Any],
    archive_rpc_validation: dict[str, Any],
) -> dict[str, Any]:
    verified = [case for case in assessments if case["verified"]]
    blocked = [case for case in assessments if not case["verified"]]
    validation_mode = (
        "production_local_archive_profile"
        if any(case.get("archive_profile") for case in assessments)
        else "deterministic_local"
    )
    claims_preview = [
        {
            "case_id": case["case_id"],
            "slug": case["slug"],
            "evidence_level": case["evidence_level"],
            "evidence_label": case["evidence_label"],
            "replay_status": case["replay_status"],
            "failure_code": case["failure_reason"]["code"],
        }
        for case in assessments
    ]
    return {
        "schema_version": REPLAY_FEASIBILITY_REPORT_SCHEMA_VERSION,
        "bundle_type": REPLAY_BUNDLE_TYPE,
        "lab_id": "abra",
        "generated_at": generated_at,
        "source_fixture": str(fixture_path),
        "fixture_id": fixture.get("fixture_id"),
        "summary": {
            "case_count": len(assessments),
            "verified_count": len(verified),
            "blocked_count": len(blocked),
            "status_counts": _count_by_key(assessments, "replay_status"),
            "feasibility_counts": _count_by_key(assessments, "feasibility"),
            "evidence_level_counts": _count_by_key(assessments, "evidence_level"),
            "blocker_category_counts": blocker_ledger["summary"]["category_counts"],
            "archive_rpc_validation_status_counts": archive_rpc_validation["summary"]["status_counts"],
        },
        "safety": {
            "broadcasts_transactions": False,
            "requires_private_keys": False,
            "live_trading": False,
            "runs_forge": False,
            "validation_mode": validation_mode,
            "notes": [
                "This bounded workflow assesses fixture-declared replay outcomes and local validation preconditions only.",
                "It does not broadcast transactions, require private keys, or perform live trading.",
            ],
        },
        "blocker_ledger": "replay_blocker_ledger.json",
        "archive_rpc_validation": "archive_rpc_validation.json",
        "run_ledger": "memory/replay_run_ledger.jsonl",
        "claims_preview": claims_preview,
        "cases": assessments,
    }


def _build_blocker_ledger(
    *,
    generated_at: str,
    fixture_path: Path,
    fixture: dict[str, Any],
    assessments: list[dict[str, Any]],
) -> dict[str, Any]:
    entries: list[dict[str, Any]] = []
    for case in assessments:
        entries.extend(_case_blocker_entries(case))

    return {
        "schema_version": REPLAY_BLOCKER_LEDGER_SCHEMA_VERSION,
        "bundle_type": REPLAY_BUNDLE_TYPE,
        "lab_id": "abra",
        "generated_at": generated_at,
        "source_fixture": str(fixture_path),
        "fixture_id": fixture.get("fixture_id"),
        "category_definitions": {
            "archive_rpc_state": "Archive RPC configuration or historical state needed for fork replay.",
            "trace_availability": "Transaction or execution traces needed to inspect replay behavior.",
            "fork_block_gap": "Missing or ambiguous fork block / historical checkpoint.",
            "simulation_precondition": "Local replay harness, metadata, and environment preconditions.",
            "safety_decision": "Explicit decision to keep assessment non-broadcast and keyless.",
        },
        "summary": {
            "case_count": len(assessments),
            "entry_count": len(entries),
            "open_blocker_count": sum(
                1 for entry in entries if entry["status"] == "open" and entry["severity"] == "blocking"
            ),
            "category_counts": _count_by_key(entries, "category"),
            "severity_counts": _count_by_key(entries, "severity"),
            "status_counts": _count_by_key(entries, "status"),
        },
        "entries": entries,
    }


def _case_blocker_entries(case: dict[str, Any]) -> list[dict[str, Any]]:
    entries: list[dict[str, Any]] = []
    failure_code = str(case.get("failure_reason", {}).get("code") or "")
    env = _first_required_environment(case)
    env_present = env.get("present") if env else None
    rpc_env = str(env.get("name") or case.get("normalized_replay_result", {}).get("rpc_env") or "") if env else ""

    if not env:
        entries.append(
            _ledger_entry(
                case,
                category="archive_rpc_state",
                code="archive_rpc_env_not_declared",
                severity="warning",
                status="open",
                retryable=False,
                message="No archive RPC environment variable is declared for this case.",
                required_action="Declare the read-only archive RPC environment variable needed for live validation.",
                details={"fork_block": case.get("fork_block")},
            )
        )
    elif failure_code == "archive_state_unavailable":
        entries.append(
            _ledger_entry(
                case,
                category="archive_rpc_state",
                code="archive_state_unavailable",
                severity="blocking",
                status="open",
                retryable=True,
                message="The configured RPC endpoint did not provide historical archive state for the fork block.",
                required_action="Use an archive-capable RPC endpoint for the chain and fork block, then rerun bounded replay.",
                details={"rpc_env": rpc_env, "fork_block": case.get("fork_block"), "source": env.get("source") if env else ""},
            )
        )
    elif env and env_present is False:
        entries.append(
            _ledger_entry(
                case,
                category="archive_rpc_state",
                code="missing_archive_rpc_env",
                severity="blocking",
                status="open",
                retryable=True,
                message=f"Required archive RPC environment variable is unavailable: {rpc_env}.",
                required_action="Configure a read-only archive-capable RPC endpoint before live fork validation.",
                details={"rpc_env": rpc_env, "fork_block": case.get("fork_block"), "source": env.get("source")},
            )
        )
    elif env:
        entries.append(
            _ledger_entry(
                case,
                category="archive_rpc_state",
                code="archive_rpc_fixture_declared",
                severity="info",
                status="fixture_declared",
                retryable=False,
                message=f"Fixture declares archive RPC availability through {rpc_env}.",
                required_action="Use live read-only validation before upgrading beyond fixture evidence.",
                details={"rpc_env": rpc_env, "fork_block": case.get("fork_block"), "source": env.get("source")},
            )
        )

    trace = case.get("trace") if isinstance(case.get("trace"), dict) else {}
    trace_status = str(trace.get("status") or "unavailable")
    if trace_status in {"available", "declared"}:
        entries.append(
            _ledger_entry(
                case,
                category="trace_availability",
                code="trace_fixture_declared",
                severity="info",
                status="fixture_declared",
                retryable=False,
                message="Fixture declares trace or replay log availability for this case.",
                required_action="Preserve trace artifacts in the bundle before using them as replay evidence.",
                details=trace,
            )
        )
    else:
        entries.append(
            _ledger_entry(
                case,
                category="trace_availability",
                code="trace_unavailable",
                severity="warning",
                status="open",
                retryable=True,
                message="No transaction or execution trace artifact is available in the local fixture.",
                required_action="Collect read-only transaction traces or replay logs when archive RPC supports them.",
                details=trace,
            )
        )

    if case.get("fork_block") is None:
        entries.append(
            _ledger_entry(
                case,
                category="fork_block_gap",
                code="fork_block_not_declared",
                severity="blocking",
                status="open",
                retryable=False,
                message="The case does not declare a fork block or equivalent historical checkpoint.",
                required_action="Add a fork block for EVM replay, or document a chain-specific checkpoint for non-EVM replay.",
                details={"chain": case.get("chain"), "non_evm": case.get("chain") in NON_EVM_CHAINS},
            )
        )
    else:
        entries.append(
            _ledger_entry(
                case,
                category="fork_block_gap",
                code="fork_block_declared",
                severity="info",
                status="fixture_declared",
                retryable=False,
                message="Fixture declares a fork block for bounded replay assessment.",
                required_action="Verify the fork block against public incident transaction metadata before audit use.",
                details={"fork_block": case.get("fork_block")},
            )
        )

    missing_preconditions = [
        item
        for item in case.get("simulation_preconditions", [])
        if isinstance(item, dict) and item.get("required") is True and item.get("satisfied") is not True
    ]
    if missing_preconditions:
        for item in missing_preconditions:
            entries.append(
                _ledger_entry(
                    case,
                    category="simulation_precondition",
                    code=str(item.get("name") or "simulation_precondition_missing"),
                    severity="blocking",
                    status="open",
                    retryable=bool(item.get("retryable")),
                    message=str(item.get("message") or "A required simulation precondition is not satisfied."),
                    required_action=str(item.get("required_action") or "Satisfy the missing precondition before replay."),
                    details=item,
                )
            )
    else:
        entries.append(
            _ledger_entry(
                case,
                category="simulation_precondition",
                code="simulation_preconditions_satisfied",
                severity="info",
                status="fixture_declared",
                retryable=False,
                message="Fixture-declared simulation preconditions are satisfied for bounded local assessment.",
                required_action="Run live read-only validation before treating this as non-fixture replay evidence.",
                details={"preconditions": case.get("simulation_preconditions", [])},
            )
        )

    safety_violations = list(case.get("safety_violations") or [])
    entries.append(
        _ledger_entry(
            case,
            category="safety_decision",
            code="non_broadcast_keyless_validation" if not safety_violations else "unsafe_command_marker",
            severity="info" if not safety_violations else "blocking",
            status="accepted_safety_decision" if not safety_violations else "open",
            retryable=False,
            message="Assessment is explicitly limited to non-broadcast, keyless replay evidence handling."
            if not safety_violations
            else "Fixture command contains a denied broadcast, private-key, or live-send marker.",
            required_action="Do not use private keys or broadcast transactions; use read-only archive RPC validation only."
            if not safety_violations
            else "Remove unsafe command markers before any replay assessment can be accepted.",
            details={
                "broadcasts_transactions": False,
                "requires_private_keys": False,
                "live_trading": False,
                "runs_forge": False,
                "denied_markers": safety_violations,
            },
        )
    )
    return entries


def _ledger_entry(
    case: dict[str, Any],
    *,
    category: str,
    code: str,
    severity: str,
    status: str,
    retryable: bool,
    message: str,
    required_action: str,
    details: dict[str, Any],
) -> dict[str, Any]:
    slug = str(case.get("slug") or "case")
    return {
        "blocker_id": f"replay-blocker-{slug}-{_slug(category)}-{_slug(code)}",
        "case_id": case.get("case_id"),
        "slug": slug,
        "incident": case.get("incident"),
        "chain": case.get("chain"),
        "category": category,
        "code": code,
        "severity": severity,
        "status": status,
        "retryable": retryable,
        "message": message,
        "required_action": required_action,
        "evidence_level": case.get("evidence_level"),
        "replay_status": case.get("replay_status"),
        "feasibility": case.get("feasibility"),
        "details": details,
    }


def _build_archive_rpc_validation(
    *,
    generated_at: str,
    fixture_path: Path,
    fixture: dict[str, Any],
    assessments: list[dict[str, Any]],
    archive_profile: dict[str, Any] | None = None,
) -> dict[str, Any]:
    checks = [_archive_rpc_case_validation(case) for case in assessments]
    profile_enabled = archive_profile is not None
    return {
        "schema_version": ARCHIVE_RPC_VALIDATION_SCHEMA_VERSION,
        "bundle_type": REPLAY_BUNDLE_TYPE,
        "lab_id": "abra",
        "generated_at": generated_at,
        "source_fixture": str(fixture_path),
        "fixture_id": fixture.get("fixture_id"),
        "profile_id": archive_profile.get("profile_id") if archive_profile else "",
        "mode": "production_local_archive_profile" if profile_enabled else "deterministic_local",
        "deterministic": True,
        "network_access": "fixture_profile_only" if profile_enabled else "not_used",
        "private_keys": "not_used",
        "broadcasts_transactions": False,
        "archive_rpc_preflight": "archive_rpc_preflight.json" if profile_enabled else "",
        "summary": {
            "case_count": len(checks),
            "status_counts": _count_by_key(checks, "local_status"),
            "live_ready_count": sum(
                1
                for check in checks
                if check["local_status"] in {"fixture_declared_replay_verified", "profile_declared_replay_verified"}
            ),
        },
        "live_validation_requirements": [
            "Archive-capable read-only RPC endpoint for each chain and fork block.",
            "Foundry test dependencies and the declared replay test path.",
            "Historical state calls only; optional debug_trace/trace calls when the provider supports them.",
            "No transaction broadcast, private keys, live trading, or state-changing RPC calls.",
        ],
        "prohibited_actions": [
            "Do not pass --broadcast to forge or cast.",
            "Do not load or request private keys.",
            "Do not use cast send or any state-changing transaction command.",
        ],
        "checks": checks,
    }


def _archive_rpc_case_validation(case: dict[str, Any]) -> dict[str, Any]:
    env = _first_required_environment(case)
    failure_code = str(case.get("failure_reason", {}).get("code") or "")
    local_status = _archive_rpc_validation_status(case, env, failure_code)
    command = str(case.get("runner", {}).get("command") or "")
    return {
        "validation_id": f"archive-rpc-validation-{case['slug']}",
        "case_id": case["case_id"],
        "slug": case["slug"],
        "incident": case["incident"],
        "chain": case["chain"],
        "fork_block": case.get("fork_block"),
        "rpc_env": env.get("name") if env else "",
        "local_status": local_status,
        "basis": "fixture_metadata_only",
        "checks": [
            {
                "name": "rpc_env_declared",
                "passed": bool(env),
                "source": env.get("source") if env else "not_declared",
            },
            {
                "name": "rpc_env_fixture_present",
                "passed": bool(env and env.get("present") is True),
                "source": env.get("source") if env else "not_declared",
            },
            {
                "name": "fork_block_declared",
                "passed": case.get("fork_block") is not None,
                "source": "fixture.case.fork_block",
            },
            {
                "name": "replay_test_declared",
                "passed": bool(case.get("runner", {}).get("test_path") and case.get("runner", {}).get("replay_test")),
                "source": "fixture.case.replay_test",
            },
            {
                "name": "non_broadcast_safety",
                "passed": not case.get("safety_violations"),
                "source": "abra.replay_agent.safety_policy",
            },
        ],
        "read_only_live_steps": _live_validation_steps(case, env, command),
        "live_validation_requires": _live_validation_requirements_for_case(case, env),
        "prohibited_actions": ["broadcast_transactions", "load_private_keys", "live_trading"],
        "notes": [
            "Local deterministic validation does not contact RPC endpoints.",
            "Live validation would be read-only and must keep evidence levels bounded until replay succeeds.",
        ],
    }


def _archive_rpc_validation_status(case: dict[str, Any], env: dict[str, Any] | None, failure_code: str) -> str:
    if case.get("safety_violations"):
        return "blocked_unsafe_command"
    if not case.get("runner", {}).get("test_path") or not case.get("runner", {}).get("replay_test"):
        return "blocked_missing_replay_test"
    if case.get("fork_block") is None:
        return "blocked_missing_fork_block"
    if env and env.get("present") is False:
        return "blocked_missing_archive_rpc"
    if failure_code == "archive_state_unavailable":
        return "blocked_archive_state_unavailable"
    if case.get("verified") and case.get("archive_profile"):
        return "profile_declared_replay_verified"
    if case.get("verified"):
        return "fixture_declared_replay_verified"
    return "not_live_validated"


def _live_validation_steps(case: dict[str, Any], env: dict[str, Any] | None, command: str) -> list[str]:
    steps = [
        "Confirm the RPC endpoint is archive-capable for the declared fork block using read-only calls.",
        "Run the declared Foundry replay test in a forked local EVM without --broadcast.",
        "Store replay logs, command metadata, return code, and trace availability in the evidence bundle.",
    ]
    if env:
        steps.insert(0, f"Configure {env.get('name')} with a read-only archive RPC URL.")
    if command:
        steps.append(f"Bounded local command shape: {command}")
    return steps


def _live_validation_requirements_for_case(case: dict[str, Any], env: dict[str, Any] | None) -> dict[str, Any]:
    return {
        "archive_rpc_env": env.get("name") if env else "",
        "chain": case.get("chain"),
        "fork_block": case.get("fork_block"),
        "test_path": case.get("runner", {}).get("test_path"),
        "replay_test": case.get("runner", {}).get("replay_test"),
        "trace_support": "optional_debug_or_trace_api",
        "private_key_required": False,
        "broadcast_required": False,
    }


def _build_run_ledger_entry(
    *,
    generated_at: str,
    fixture_path: Path,
    out_path: Path,
    fixture: dict[str, Any],
    assessments: list[dict[str, Any]],
    blocker_ledger: dict[str, Any],
    archive_rpc_validation: dict[str, Any],
    existing_run_count: int,
) -> dict[str, Any]:
    run_id = _run_id(generated_at, fixture_path, out_path, existing_run_count + 1)
    return {
        "schema_version": REPLAY_RUN_LEDGER_ENTRY_SCHEMA_VERSION,
        "run_id": run_id,
        "generated_at": generated_at,
        "bundle_type": REPLAY_BUNDLE_TYPE,
        "bundle_path": str(out_path),
        "source_fixture": str(fixture_path),
        "fixture_id": fixture.get("fixture_id"),
        "artifacts": {
            "replay_report": "replay_feasibility_report.json",
            "blocker_ledger": "replay_blocker_ledger.json",
            "archive_rpc_validation": "archive_rpc_validation.json",
            "evidence_bundle": "evidence_bundle.json",
            "artifact_manifest": "artifact_manifest.json",
        },
        "case_count": len(assessments),
        "status_counts": _count_by_key(assessments, "replay_status"),
        "feasibility_counts": _count_by_key(assessments, "feasibility"),
        "evidence_levels": _count_by_key(assessments, "evidence_level"),
        "blocker_summary": blocker_ledger["summary"],
        "archive_rpc_validation_summary": archive_rpc_validation["summary"],
        "safety": {
            "broadcasts_transactions": False,
            "requires_private_keys": False,
            "live_trading": False,
            "validation_mode": "production_local_archive_profile"
            if any(case.get("archive_profile") for case in assessments)
            else "deterministic_local",
        },
        "cases": [
            {
                "case_id": case["case_id"],
                "slug": case["slug"],
                "incident": case["incident"],
                "chain": case["chain"],
                "replay_status": case["replay_status"],
                "feasibility": case["feasibility"],
                "evidence_level": case["evidence_level"],
                "failure_code": case["failure_reason"]["code"],
            }
            for case in assessments
        ],
    }


def _build_memory_ledger(generated_at: str, fixture_path: Path, run_ledger_path: Path) -> dict[str, Any]:
    runs = _read_jsonl_objects(run_ledger_path)
    incidents: list[dict[str, Any]] = []
    for run in runs:
        for case in run.get("cases", []):
            if isinstance(case, dict):
                incidents.append(
                    {
                        "run_id": run.get("run_id"),
                        "case_id": case.get("case_id"),
                        "slug": case.get("slug"),
                        "incident": case.get("incident"),
                        "chain": case.get("chain"),
                        "replay_status": case.get("replay_status"),
                        "feasibility": case.get("feasibility"),
                        "evidence_level": case.get("evidence_level"),
                        "failure_code": case.get("failure_code"),
                    }
                )
    return {
        "schema_version": REPLAY_MEMORY_LEDGER_SCHEMA_VERSION,
        "bundle_type": REPLAY_BUNDLE_TYPE,
        "lab_id": "abra",
        "generated_at": generated_at,
        "source_fixture": str(fixture_path),
        "run_ledger": str(run_ledger_path.name),
        "summary": {
            "run_count": len(runs),
            "incident_observation_count": len(incidents),
            "latest_run_id": runs[-1].get("run_id") if runs else "",
        },
        "runs": [
            {
                "run_id": run.get("run_id"),
                "generated_at": run.get("generated_at"),
                "case_count": run.get("case_count"),
                "status_counts": run.get("status_counts"),
                "evidence_levels": run.get("evidence_levels"),
                "blocker_summary": run.get("blocker_summary"),
            }
            for run in runs
        ],
        "incidents": incidents,
    }


def _build_claims(
    assessments: list[dict[str, Any]],
    artifacts: list[dict[str, Any]],
    artifact_by_path: dict[str, dict[str, Any]],
) -> list[dict[str, Any]]:
    report_id = artifact_by_path["replay_feasibility_report.json"]["artifact_id"]
    blocker_ledger_id = artifact_by_path["replay_blocker_ledger.json"]["artifact_id"]
    archive_validation_id = artifact_by_path["archive_rpc_validation.json"]["artifact_id"]
    run_ledger_id = artifact_by_path["memory/replay_run_ledger.jsonl"]["artifact_id"]
    fixture_artifact = next(artifact for artifact in artifacts if artifact["kind"] == "replay_case_fixture")
    fixture_id = fixture_artifact["artifact_id"]
    common_support = [
        artifact["artifact_id"]
        for artifact in artifacts
        if artifact.get("kind") in {"archive_rpc_profile", "archive_rpc_preflight"}
    ]
    claims: list[dict[str, Any]] = []
    for case in assessments:
        supported_by = [report_id, fixture_id, blocker_ledger_id, archive_validation_id, run_ledger_id]
        supported_by.extend(common_support)
        if case.get("log_path") and case["log_path"] in artifact_by_path:
            supported_by.append(artifact_by_path[case["log_path"]]["artifact_id"])
        trace_path = str(case.get("trace", {}).get("path") or "") if isinstance(case.get("trace"), dict) else ""
        if trace_path and trace_path in artifact_by_path:
            supported_by.append(artifact_by_path[trace_path]["artifact_id"])
        if case["verified"]:
            claim_type = "fork_replay"
            source_kind = "replay_result"
            if case.get("archive_profile"):
                title = f"Read-only archive replay profile for {case['incident']}"
                claim_text = (
                    f"{case['incident']} has fixture-backed L4 read-only archive replay evidence: "
                    f"fork block `{case['fork_block']}`, replay test `{case['runner']['replay_test']}`, "
                    "and captured trace/log metadata from the production-local archive profile."
                )
            else:
                title = f"Verified fork replay fixture for {case['incident']}"
                claim_text = (
                    f"{case['incident']} has fixture-backed L4 fork replay evidence: "
                    f"status `{case['replay_status']}` for `{case['runner']['replay_test']}` on {case['chain']}."
                )
            reproduction_status = "verified"
        else:
            claim_type = "replay_feasibility_assessment"
            source_kind = "replay_feasibility_report"
            title = f"Replay feasibility blocker for {case['incident']}"
            claim_text = (
                f"{case['incident']} is not L4 replay evidence in this fixture: "
                f"status `{case['replay_status']}`, feasibility `{case['feasibility']}`, "
                f"reason `{case['failure_reason']['code']}`."
            )
            reproduction_status = case["replay_status"]
        claims.append(
            {
                "claim_id": f"{case['evidence_level'].lower()}-replay-{case['slug']}",
                "claim_type": claim_type,
                "source_kind": source_kind,
                "title": title,
                "claim": claim_text,
                "evidence_level": case["evidence_level"],
                "evidence_label": case["evidence_label"],
                "subject": {
                    "kind": "incident_replay",
                    "incident": case["incident"],
                    "slug": case["slug"],
                    "chain": case["chain"],
                    "attack_family": case["attack_family"],
                    "fork_block": case["fork_block"],
                },
                "supported_by": supported_by,
                "reproduction": {
                    "status": reproduction_status,
                    "commands": [case["runner"]["command"]] if case["runner"]["command"] else [],
                    "test_path": case["runner"]["test_path"],
                    "replay_test": case["runner"]["replay_test"],
                    "returncode": case["normalized_replay_result"]["returncode"],
                    "duration_seconds": case["normalized_replay_result"]["duration_seconds"],
                },
                "failure_reason": case["failure_reason"],
                "required_environment": case["required_environment"],
                "limitations": _claim_limitations(case),
            }
        )
    return claims


def _bundle_limitations(assessments: list[dict[str, Any]], claims: list[dict[str, Any]]) -> list[dict[str, Any]]:
    blocked_claim_ids = [claim["claim_id"] for claim in claims if claim.get("evidence_level") != "L4"]
    verified_claim_ids = [claim["claim_id"] for claim in claims if claim.get("evidence_level") == "L4"]
    limitations = [
        {
            "limitation_id": "lim-replay-feasibility-not-reproduction",
            "scope": "replay_feasibility",
            "description": (
                "L1 replay-feasibility claims record blockers or missing preconditions only; "
                "public drafting must not treat them as successful exploit replay."
            ),
            "affected_claim_ids": blocked_claim_ids,
        },
        {
            "limitation_id": "lim-no-broadcast-or-private-keys",
            "scope": "safety",
            "description": (
                "The assessment is deterministic and local: no private keys, transaction broadcast, "
                "live trading, or state-changing RPC calls are used."
            ),
            "affected_claim_ids": [claim["claim_id"] for claim in claims],
        },
        {
            "limitation_id": "lim-fixture-backed-replay-boundary",
            "scope": "replay_evidence",
            "description": (
                "L4 replay claims in this bundle are fixture-backed local fork replay observations; "
                "they do not prove adjacent exploit variants or live-chain exploitability."
            ),
            "affected_claim_ids": verified_claim_ids,
        },
    ]
    for case in assessments:
        if case.get("verified"):
            continue
        limitations.append(
            {
                "limitation_id": f"lim-replay-{case['slug']}",
                "scope": "replay_blocker",
                "description": (
                    f"{case['incident']} remains blocked with replay status `{case['replay_status']}`, "
                    f"feasibility `{case['feasibility']}`, and failure code `{case['failure_reason']['code']}`."
                ),
                "affected_claim_ids": [f"{case['evidence_level'].lower()}-replay-{case['slug']}"],
            }
        )
    return limitations


def _write_ara_contract_files(
    *,
    out_path: Path,
    generated_at: str,
    source_fixture: str,
    claims: list[dict[str, Any]],
    limitations: list[dict[str, Any]],
    artifact_count: int,
    contract_profile: str,
    ara_production_contract: str,
) -> list[str]:
    bundle_manifest = ara_bundle_manifest(
        generated_at=generated_at,
        source_path=source_fixture,
        source_bundle_type=REPLAY_BUNDLE_TYPE,
        claim_count=len(claims),
        artifact_count=artifact_count,
    )
    if contract_profile:
        bundle_manifest["contract_profile"] = contract_profile
    if ara_production_contract:
        bundle_manifest["ara_production_contract"] = ara_production_contract
    files = {
        "bundle_manifest.json": bundle_manifest,
        "claims.json": ara_claims_payload(claims, generated_at, REPLAY_BUNDLE_TYPE),
    }
    for name, payload in files.items():
        (out_path / name).write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    limitations_text = _render_bundle_limitations(limitations)
    drafting_text = _render_drafting_brief(claims, limitations)
    (out_path / "limitations.md").write_text(limitations_text, encoding="utf-8")
    (out_path / "drafting_brief.md").write_text(drafting_text, encoding="utf-8")
    (out_path / "writing_brief.md").write_text(drafting_text, encoding="utf-8")
    return ["bundle_manifest.json", "claims.json", "limitations.md", "drafting_brief.md", "writing_brief.md"]


def _build_ara_production_contract(
    *,
    generated_at: str,
    fixture_path: Path,
    claims: list[dict[str, Any]],
    limitations: list[dict[str, Any]],
    archive_rpc_validation: dict[str, Any],
    archive_rpc_preflight: dict[str, Any] | None,
) -> dict[str, Any]:
    ara_claims = ara_claims_payload(claims, generated_at, REPLAY_BUNDLE_TYPE)["claims"]
    allowed_claim_ids = [
        str(claim.get("claim_id"))
        for claim in ara_claims
        if claim.get("status") == "supported" and str(claim.get("evidence_level") or "") in {"L4", "L5", "L6"}
    ]
    blocked_claim_ids = [
        str(claim.get("claim_id"))
        for claim in ara_claims
        if claim.get("status") != "supported" or str(claim.get("evidence_level") or "") in {"L0", "L1", "L2", "L3"}
    ]
    return {
        "schema_version": ARA_PRODUCTION_CONTRACT_SCHEMA_VERSION,
        "bundle_type": REPLAY_BUNDLE_TYPE,
        "lab_id": "abra",
        "profile": "ara-production",
        "generated_at": generated_at,
        "source_fixture": str(fixture_path),
        "public_ara_sidecars": {
            "bundle_manifest": "bundle_manifest.json",
            "claims": "claims.json",
            "drafting_brief": "drafting_brief.md",
            "limitations": "limitations.md",
            "artifact_manifest": "artifact_manifest.json",
        },
        "drafting_gate": {
            "allowed_claim_ids": allowed_claim_ids,
            "blocked_claim_ids": blocked_claim_ids,
            "policy": (
                "Only supported L4+ replay evidence may enter ARA allowed_claims; "
                "L1 static, blocker, and replay-feasibility claims must remain blocked."
            ),
        },
        "reproduction_gate": {
            "successful_replay_claim_ids": allowed_claim_ids,
            "blocked_feasibility_claim_ids": blocked_claim_ids,
            "requires_private_keys": False,
            "broadcasts_transactions": False,
            "live_trading": False,
            "state_changing_rpc": False,
            "independent_reproduction_claim": False,
            "policy": (
                "Production-local ABRA replay output is an ARA result-bundle input. "
                "It is not an independent ARA reproduction-gate pass."
            ),
        },
        "archive_rpc_validation": {
            "path": "archive_rpc_validation.json",
            "mode": archive_rpc_validation.get("mode"),
            "network_access": archive_rpc_validation.get("network_access"),
            "private_keys": archive_rpc_validation.get("private_keys"),
            "broadcasts_transactions": archive_rpc_validation.get("broadcasts_transactions"),
        },
        "archive_rpc_preflight": {
            "path": "archive_rpc_preflight.json" if archive_rpc_preflight is not None else "",
            "status": archive_rpc_preflight.get("status") if archive_rpc_preflight else "not_requested",
        },
        "claim_counts": _evidence_counts(claims),
        "limitations": [limitation.get("limitation_id") for limitation in limitations],
    }


def _render_bundle_limitations(limitations: list[dict[str, Any]]) -> str:
    lines = ["# ABRA Replay Bundle Limitations", ""]
    for limitation in limitations:
        lines.append(f"- `{limitation['limitation_id']}` ({limitation['scope']}): {limitation['description']}")
    return "\n".join(lines) + "\n"


def _render_drafting_brief(claims: list[dict[str, Any]], limitations: list[dict[str, Any]]) -> str:
    counts = _evidence_counts(claims)
    lines = [
        "# ABRA ARA Drafting Brief",
        "",
        "## Evidence Boundary",
        "",
        f"- L4 fork replay claims available to public drafting: {counts.get('L4', 0)}",
        f"- L1 replay-feasibility or blocker claims excluded from successful replay drafting: {counts.get('L1', 0)}",
        "- Do not describe replay blockers, static alerts, missing tests, or RPC failures as successful exploit replay.",
        "- Do not use private keys, broadcast transactions, live trading, or state-changing RPC calls for this bundle.",
        "",
        "## Claims",
        "",
    ]
    for claim in claims:
        ara_status = "supported" if claim.get("evidence_level") == "L4" else "blocked"
        lines.append(
            f"- `{claim['claim_id']}` ({claim['evidence_level']} {claim['evidence_label']}, ARA status `{ara_status}`): "
            f"{claim['claim']}"
        )
    lines.extend(["", "## Limitations", ""])
    for limitation in limitations:
        lines.append(f"- `{limitation['limitation_id']}`: {limitation['description']}")
    return "\n".join(lines) + "\n"


def _validate_evidence_artifacts(
    root: Path,
    artifacts: list[Any],
    errors: list[str],
    warnings: list[str],
    files_checked: list[str],
) -> set[str]:
    seen: set[str] = set()
    for index, artifact in enumerate(artifacts):
        if not isinstance(artifact, dict):
            errors.append(f"Artifact entry {index} must be a mapping.")
            continue
        artifact_id = str(artifact.get("artifact_id") or "")
        if not artifact_id:
            errors.append(f"Artifact entry {index} is missing artifact_id.")
        elif artifact_id in seen:
            errors.append(f"Duplicate artifact_id: {artifact_id}")
        seen.add(artifact_id)
        for key in ("kind", "role", "path", "bundle_path", "sha256", "size_bytes"):
            if key not in artifact:
                errors.append(f"Artifact {artifact_id or index} is missing `{key}`.")
        artifact_path = root / str(artifact.get("bundle_path") or "")
        if not artifact_path.exists() or not artifact_path.is_file():
            errors.append(f"Bundled artifact file is missing: {artifact.get('bundle_path')}")
            continue
        files_checked.append(str(artifact.get("bundle_path")))
        digest = _sha256_file(artifact_path)
        if artifact.get("sha256") and digest != artifact.get("sha256"):
            errors.append(f"Artifact digest mismatch for {artifact_id}.")
        if artifact.get("kind") == "replay_log" and artifact_path.stat().st_size == 0:
            warnings.append(f"Replay log artifact is empty: {artifact.get('bundle_path')}")
    return seen


def _validate_evidence_claims(
    claims: list[Any],
    artifact_ids: set[str],
    minimum: str,
    errors: list[str],
    warnings: list[str],
) -> None:
    seen: set[str] = set()
    for index, claim in enumerate(claims):
        if not isinstance(claim, dict):
            errors.append(f"Claim entry {index} must be a mapping.")
            continue
        claim_id = str(claim.get("claim_id") or "")
        if not claim_id:
            errors.append(f"Claim entry {index} is missing claim_id.")
        elif claim_id in seen:
            errors.append(f"Duplicate claim_id: {claim_id}")
        seen.add(claim_id)
        level = str(claim.get("evidence_level") or "")
        if level not in EVIDENCE_ORDER:
            errors.append(f"Claim {claim_id or index} has invalid evidence_level: {level}")
            continue
        if EVIDENCE_ORDER[level] < EVIDENCE_ORDER[minimum]:
            errors.append(f"Claim {claim_id or index} is below minimum evidence level {minimum}.")
        if claim.get("evidence_label") != EVIDENCE_LABELS.get(level):
            errors.append(f"Claim {claim_id or index} evidence_label does not match evidence_level.")
        supported_by = claim.get("supported_by")
        if not isinstance(supported_by, list) or not supported_by:
            errors.append(f"Claim {claim_id or index} must have non-empty supported_by.")
        else:
            missing = [artifact_id for artifact_id in supported_by if artifact_id not in artifact_ids]
            if missing:
                errors.append(f"Claim {claim_id or index} references unknown artifacts: {missing}")
        reproduction = claim.get("reproduction")
        if not isinstance(reproduction, dict):
            errors.append(f"Claim {claim_id or index} must include reproduction metadata.")
            reproduction = {}
        if level == "L4" and reproduction.get("status") != "verified":
            errors.append(f"L4 claim {claim_id or index} must have reproduction.status `verified`.")
        if level != "L4" and reproduction.get("status") == "verified":
            warnings.append(f"Non-L4 claim {claim_id or index} should not use verified reproduction status.")


def _validate_replay_report(
    root: Path,
    errors: list[str],
    warnings: list[str],
    files_checked: list[str],
) -> None:
    report = _load_bundle_json(root / "replay_feasibility_report.json", errors)
    if not report:
        errors.append("Replay evidence bundle is missing replay_feasibility_report.json.")
        return
    files_checked.append("replay_feasibility_report.json")
    if report.get("schema_version") != REPLAY_FEASIBILITY_REPORT_SCHEMA_VERSION:
        errors.append("replay_feasibility_report.json has an unsupported schema_version.")
    safety = report.get("safety")
    if not isinstance(safety, dict):
        errors.append("Replay report must include safety metadata.")
        safety = {}
    if safety.get("broadcasts_transactions") is not False:
        errors.append("Replay report must declare broadcasts_transactions=false.")
    if safety.get("requires_private_keys") is not False:
        errors.append("Replay report must declare requires_private_keys=false.")
    if safety.get("live_trading") is not False:
        errors.append("Replay report must declare live_trading=false.")
    cases = report.get("cases")
    if not isinstance(cases, list) or not cases:
        errors.append("Replay report must contain at least one assessed case.")
        return
    for case in cases:
        if not isinstance(case, dict):
            errors.append("Replay report case entries must be mappings.")
            continue
        if case.get("safety_violations"):
            errors.append(f"Replay case {case.get('slug')} contains unsafe command markers.")
        if case.get("replay_status") == "no_rpc":
            env = case.get("required_environment")
            if not isinstance(env, list) or not any(item.get("present") is False for item in env if isinstance(item, dict)):
                errors.append(f"Replay case {case.get('slug')} no_rpc status must record missing RPC environment.")
        if case.get("verified") is True and case.get("evidence_level") != "L4":
            errors.append(f"Replay case {case.get('slug')} verified status must map to L4.")
        if case.get("verified") is not True and case.get("evidence_level") == "L4":
            errors.append(f"Replay case {case.get('slug')} cannot be L4 without verified=true.")
    safety_mode = str(safety.get("validation_mode") or "")
    if safety_mode != "production_local_archive_profile" and not any(
        case.get("replay_status") == "no_rpc" for case in cases if isinstance(case, dict)
    ):
        warnings.append("Replay report does not include a no_rpc fixture case.")


def _validate_replay_blocker_ledger(
    root: Path,
    evidence: dict[str, Any],
    errors: list[str],
    warnings: list[str],
    files_checked: list[str],
) -> None:
    relative = str(evidence.get("blocker_ledger") or "replay_blocker_ledger.json")
    ledger = _load_bundle_json(root / relative, errors)
    if not ledger:
        errors.append(f"Replay evidence bundle is missing blocker ledger: {relative}")
        return
    files_checked.append(relative)
    if ledger.get("schema_version") != REPLAY_BLOCKER_LEDGER_SCHEMA_VERSION:
        errors.append("replay_blocker_ledger.json has an unsupported schema_version.")
    entries = ledger.get("entries")
    if not isinstance(entries, list) or not entries:
        errors.append("Replay blocker ledger must contain at least one entry.")
        return
    categories = {str(entry.get("category") or "") for entry in entries if isinstance(entry, dict)}
    missing_categories = sorted(REQUIRED_BLOCKER_LEDGER_CATEGORIES - categories)
    if missing_categories:
        errors.append(f"Replay blocker ledger is missing required categories: {missing_categories}")
    seen: set[str] = set()
    safety_decisions = 0
    for index, entry in enumerate(entries):
        if not isinstance(entry, dict):
            errors.append(f"Replay blocker ledger entry {index} must be a mapping.")
            continue
        blocker_id = str(entry.get("blocker_id") or "")
        if not blocker_id:
            errors.append(f"Replay blocker ledger entry {index} is missing blocker_id.")
        elif blocker_id in seen:
            errors.append(f"Duplicate replay blocker ledger entry: {blocker_id}")
        seen.add(blocker_id)
        for key in ("case_id", "category", "code", "severity", "status", "message", "required_action"):
            if key not in entry:
                errors.append(f"Replay blocker ledger entry {blocker_id or index} is missing `{key}`.")
        if entry.get("category") == "safety_decision":
            safety_decisions += 1
            details = entry.get("details") if isinstance(entry.get("details"), dict) else {}
            if details.get("broadcasts_transactions") is not False:
                errors.append(f"Safety ledger entry {blocker_id or index} must declare broadcasts_transactions=false.")
            if details.get("requires_private_keys") is not False:
                errors.append(f"Safety ledger entry {blocker_id or index} must declare requires_private_keys=false.")
    if safety_decisions == 0:
        errors.append("Replay blocker ledger must include explicit non-broadcast safety decisions.")
    if not all(isinstance(entry, dict) and entry.get("evidence_level") == "L4" for entry in entries) and not any(
        isinstance(entry, dict)
        and entry.get("category") == "archive_rpc_state"
        and entry.get("severity") == "blocking"
        for entry in entries
    ):
        warnings.append("Replay blocker ledger does not include a blocking archive RPC state entry.")


def _validate_archive_rpc_validation(
    root: Path,
    evidence: dict[str, Any],
    errors: list[str],
    warnings: list[str],
    files_checked: list[str],
) -> None:
    relative = str(evidence.get("archive_rpc_validation") or "archive_rpc_validation.json")
    validation = _load_bundle_json(root / relative, errors)
    if not validation:
        errors.append(f"Replay evidence bundle is missing archive RPC validation artifact: {relative}")
        return
    files_checked.append(relative)
    if validation.get("schema_version") != ARCHIVE_RPC_VALIDATION_SCHEMA_VERSION:
        errors.append("archive_rpc_validation.json has an unsupported schema_version.")
    allowed_modes = {"deterministic_local", "production_local_archive_profile"}
    if validation.get("mode") not in allowed_modes:
        errors.append("Archive RPC validation must run in deterministic_local or production_local_archive_profile mode.")
    allowed_network = {"not_used", "fixture_profile_only"}
    if validation.get("network_access") not in allowed_network:
        errors.append("Archive RPC validation must not use live network access in local mode.")
    if validation.get("broadcasts_transactions") is not False:
        errors.append("Archive RPC validation must declare broadcasts_transactions=false.")
    if validation.get("private_keys") != "not_used":
        errors.append("Archive RPC validation must declare private_keys=not_used.")
    requirements = validation.get("live_validation_requirements")
    if not isinstance(requirements, list) or not requirements:
        errors.append("Archive RPC validation must describe live validation requirements.")
    checks = validation.get("checks")
    if not isinstance(checks, list) or not checks:
        errors.append("Archive RPC validation must contain per-case checks.")
        return
    for index, check in enumerate(checks):
        if not isinstance(check, dict):
            errors.append(f"Archive RPC validation check {index} must be a mapping.")
            continue
        if not check.get("validation_id"):
            errors.append(f"Archive RPC validation check {index} is missing validation_id.")
        if not check.get("local_status"):
            errors.append(f"Archive RPC validation check {index} is missing local_status.")
        live_requires = check.get("live_validation_requires")
        if not isinstance(live_requires, dict):
            errors.append(f"Archive RPC validation check {check.get('validation_id') or index} needs live requirements.")
            continue
        if live_requires.get("private_key_required") is not False:
            errors.append(f"Archive RPC validation check {check.get('validation_id') or index} must not require private keys.")
        if live_requires.get("broadcast_required") is not False:
            errors.append(f"Archive RPC validation check {check.get('validation_id') or index} must not require broadcast.")
    if validation.get("mode") != "production_local_archive_profile" and not any(
        isinstance(check, dict)
        and str(check.get("local_status") or "").startswith("blocked_missing")
        for check in checks
    ):
        warnings.append("Archive RPC validation does not include a missing-precondition case.")


def _validate_archive_rpc_preflight(
    root: Path,
    evidence: dict[str, Any],
    errors: list[str],
    warnings: list[str],
    files_checked: list[str],
) -> None:
    relative = str(evidence.get("archive_rpc_preflight") or "")
    if not relative:
        return
    preflight = _load_bundle_json(root / relative, errors)
    if not preflight:
        errors.append(f"Replay evidence bundle is missing archive RPC preflight artifact: {relative}")
        return
    files_checked.append(relative)
    if preflight.get("schema_version") != ARCHIVE_RPC_PREFLIGHT_SCHEMA_VERSION:
        errors.append("archive_rpc_preflight.json has an unsupported schema_version.")
    if preflight.get("mode") != "production_local":
        errors.append("Archive RPC preflight must declare mode=production_local.")
    if preflight.get("read_only") is not True:
        errors.append("Archive RPC preflight must declare read_only=true.")
    if preflight.get("broadcasts_transactions") is not False:
        errors.append("Archive RPC preflight must declare broadcasts_transactions=false.")
    if preflight.get("private_keys") != "not_used":
        errors.append("Archive RPC preflight must declare private_keys=not_used.")
    if preflight.get("state_changing_rpc") is not False:
        errors.append("Archive RPC preflight must declare state_changing_rpc=false.")
    checks = preflight.get("checks")
    if not isinstance(checks, list) or not checks:
        errors.append("Archive RPC preflight must contain per-case checks.")
        return
    for index, check in enumerate(checks):
        if not isinstance(check, dict):
            errors.append(f"Archive RPC preflight check {index} must be a mapping.")
            continue
        if not check.get("preflight_id"):
            errors.append(f"Archive RPC preflight check {index} is missing preflight_id.")
        if check.get("preflight_status") != "passed":
            errors.append(f"Archive RPC preflight check {check.get('preflight_id') or index} did not pass.")
        if not check.get("fork_block"):
            errors.append(f"Archive RPC preflight check {check.get('preflight_id') or index} must include fork_block.")
        trace_capture = check.get("trace_capture") if isinstance(check.get("trace_capture"), dict) else {}
        log_capture = check.get("log_capture") if isinstance(check.get("log_capture"), dict) else {}
        if trace_capture.get("status") not in {"available", "declared"}:
            errors.append(f"Archive RPC preflight check {check.get('preflight_id') or index} must capture trace metadata.")
        if log_capture.get("status") != "available":
            errors.append(f"Archive RPC preflight check {check.get('preflight_id') or index} must capture replay logs.")
        prohibited = check.get("prohibited_actions")
        if not isinstance(prohibited, list) or "broadcast_transactions" not in prohibited:
            errors.append(f"Archive RPC preflight check {check.get('preflight_id') or index} must deny broadcast actions.")


def _validate_replay_memory_ledgers(
    root: Path,
    evidence: dict[str, Any],
    errors: list[str],
    warnings: list[str],
    files_checked: list[str],
) -> None:
    run_relative = str(evidence.get("run_ledger") or "memory/replay_run_ledger.jsonl")
    run_path = root / run_relative
    if not run_path.exists():
        errors.append(f"Replay run ledger is missing: {run_relative}")
        return
    files_checked.append(run_relative)
    runs: list[dict[str, Any]] = []
    for line_no, line in enumerate(run_path.read_text(encoding="utf-8").splitlines(), start=1):
        if not line.strip():
            continue
        try:
            data = json.loads(line)
        except json.JSONDecodeError as exc:
            errors.append(f"Invalid JSON in replay run ledger line {line_no}: {exc}")
            continue
        if not isinstance(data, dict):
            errors.append(f"Replay run ledger line {line_no} must be a JSON object.")
            continue
        runs.append(data)
        if data.get("schema_version") != REPLAY_RUN_LEDGER_ENTRY_SCHEMA_VERSION:
            errors.append(f"Replay run ledger line {line_no} has unsupported schema_version.")
        safety = data.get("safety") if isinstance(data.get("safety"), dict) else {}
        if safety.get("broadcasts_transactions") is not False:
            errors.append(f"Replay run ledger line {line_no} must declare broadcasts_transactions=false.")
        if safety.get("requires_private_keys") is not False:
            errors.append(f"Replay run ledger line {line_no} must declare requires_private_keys=false.")
    if not runs:
        errors.append("Replay run ledger must contain at least one run entry.")

    memory_relative = str(evidence.get("memory_ledger") or "memory/replay_memory_ledger.json")
    memory = _load_bundle_json(root / memory_relative, errors)
    if not memory:
        errors.append(f"Replay memory ledger is missing: {memory_relative}")
        return
    files_checked.append(memory_relative)
    if memory.get("schema_version") != REPLAY_MEMORY_LEDGER_SCHEMA_VERSION:
        errors.append("replay_memory_ledger.json has an unsupported schema_version.")
    summary = memory.get("summary") if isinstance(memory.get("summary"), dict) else {}
    if summary.get("run_count") != len(runs):
        errors.append("Replay memory ledger run_count does not match replay run ledger entries.")
    if summary.get("incident_observation_count", 0) <= 0:
        warnings.append("Replay memory ledger does not contain incident observations.")


def _load_archive_profile(path: Path) -> dict[str, Any]:
    profile = _load_json_object(path)
    if profile.get("schema_version") != ARCHIVE_RPC_PROFILE_SCHEMA_VERSION:
        raise ValueError("Archive RPC replay profile has an unsupported schema_version.")
    if profile.get("mode") != "production_local":
        raise ValueError("Archive RPC replay profile must declare mode=production_local.")
    safety = profile.get("safety") if isinstance(profile.get("safety"), dict) else {}
    required_safety = {
        "read_only": True,
        "deny_private_keys": True,
        "deny_transaction_broadcast": True,
        "deny_state_changing_rpc": True,
    }
    for key, expected in required_safety.items():
        if safety.get(key) is not expected:
            raise ValueError(f"Archive RPC replay profile must declare safety.{key}={str(expected).lower()}.")
    if safety.get("private_keys") not in (None, "not_used"):
        raise ValueError("Archive RPC replay profile must declare private_keys=not_used when present.")
    cases = _archive_profile_cases(profile)
    if not cases:
        raise ValueError("Archive RPC replay profile must contain at least one case profile.")
    denied_markers = list(DENIED_COMMAND_PATTERNS)
    denied_markers.extend(str(item) for item in safety.get("denied_command_markers", []) if isinstance(item, str))
    for slug, case_profile in cases.items():
        for key in ("command", "log_text"):
            violations = _command_safety_violations(str(case_profile.get(key) or ""))
            if violations:
                raise ValueError(f"Archive RPC replay profile case {slug} contains denied command markers: {violations}")
        for marker in denied_markers:
            if marker and marker in json.dumps(case_profile, sort_keys=True):
                if marker in {"--broadcast", "cast send", "PRIVATE_KEY", "private-key", "eth_sendRawTransaction"}:
                    raise ValueError(f"Archive RPC replay profile case {slug} contains denied marker: {marker}")
    return profile


def _normalize_replay_profile(profile: str | None) -> str:
    value = str(profile or "").strip()
    if not value:
        return ""
    if value != "ara-production":
        raise ValueError(f"Unsupported replay profile: {profile}")
    return value


def _archive_profile_cases(profile: dict[str, Any]) -> dict[str, dict[str, Any]]:
    raw_cases = profile.get("cases")
    result: dict[str, dict[str, Any]] = {}
    if isinstance(raw_cases, dict):
        for slug, case_profile in raw_cases.items():
            if isinstance(slug, str) and isinstance(case_profile, dict):
                result[_slug(slug)] = dict(case_profile)
    elif isinstance(raw_cases, list):
        for case_profile in raw_cases:
            if isinstance(case_profile, dict):
                slug = _optional_str(case_profile.get("slug") or case_profile.get("case_slug"))
                if slug:
                    result[_slug(slug)] = dict(case_profile)
    return result


def _apply_archive_profile(cases: list[dict[str, Any]], profile: dict[str, Any]) -> list[dict[str, Any]]:
    case_profiles = _archive_profile_cases(profile)
    require_all = profile.get("require_all_cases", True) is not False
    merged: list[dict[str, Any]] = []
    missing: list[str] = []
    for raw_case in cases:
        if not isinstance(raw_case, dict):
            merged.append(raw_case)
            continue
        slug = _slug(str(raw_case.get("slug") or raw_case.get("incident") or "case"))
        case_profile = case_profiles.get(slug)
        if case_profile is None:
            if require_all:
                missing.append(slug)
            merged.append(dict(raw_case))
            continue
        merged.append(_merge_archive_profile_case(raw_case, case_profile, profile))
    if missing:
        raise ValueError(f"Archive RPC replay profile is missing required case profiles: {missing}")
    return merged


def _merge_archive_profile_case(
    raw_case: dict[str, Any],
    case_profile: dict[str, Any],
    profile: dict[str, Any],
) -> dict[str, Any]:
    merged = dict(raw_case)
    for key in ("rpc_env", "fork_block", "test_path", "metadata_test", "replay_test"):
        if key in case_profile:
            merged[key] = case_profile[key]
    rpc_env = str(merged.get("rpc_env") or "")
    if rpc_env:
        environment = _environment_map(merged.get("environment"))
        environment[rpc_env] = True
        merged["environment"] = environment

    trace_capture = case_profile.get("trace_capture") if isinstance(case_profile.get("trace_capture"), dict) else {}
    log_capture = case_profile.get("log_capture") if isinstance(case_profile.get("log_capture"), dict) else {}
    trace_status = str(trace_capture.get("status") or "available")
    merged["trace"] = {
        "status": trace_status,
        "source": "archive_rpc_profile.trace_capture",
        "path": str(trace_capture.get("path") or ""),
        "provider_method": str(trace_capture.get("provider_method") or "debug_traceTransaction"),
        "required_for_live_validation": True,
        "note": str(trace_capture.get("note") or "Trace capture is declared by the read-only archive RPC profile."),
    }

    test_path = _optional_str(merged.get("test_path"))
    replay_test = _optional_str(merged.get("replay_test"))
    command = str(case_profile.get("command") or "")
    if not command and test_path and replay_test:
        command = _forge_command_text(test_path, replay_test)
    log_text = str(
        case_profile.get("log_text")
        or log_capture.get("text")
        or f"[PASS] {replay_test or 'archive_replay'}() (archive profile)"
    )
    merged["fixture_result"] = {
        "status": "verified",
        "metadata_status": str(case_profile.get("metadata_status") or "passed"),
        "command": command,
        "returncode": 0,
        "duration_seconds": float(case_profile.get("duration_seconds") or 0.0),
        "blocker": "",
        "verified": True,
        "log_text": log_text,
        "trace": merged["trace"],
    }
    merged["_archive_profile"] = {
        "profile_id": profile.get("profile_id"),
        "profile_mode": profile.get("mode"),
        "case_profile_id": case_profile.get("profile_case_id") or case_profile.get("case_profile_id") or "",
        "rpc_preflight": case_profile.get("rpc_preflight") if isinstance(case_profile.get("rpc_preflight"), dict) else {},
        "trace_capture": trace_capture,
        "log_capture": log_capture,
        "read_only": True,
        "broadcasts_transactions": False,
        "private_keys": "not_used",
        "evidence_upgrade": "fixture_backed_l4_archive_replay",
    }
    return merged


def _build_archive_rpc_preflight(
    *,
    generated_at: str,
    profile_path: Path | None,
    profile: dict[str, Any] | None,
    assessments: list[dict[str, Any]],
) -> dict[str, Any] | None:
    if profile is None:
        return None
    checks: list[dict[str, Any]] = []
    for case in assessments:
        env = _first_required_environment(case)
        trace = case.get("trace") if isinstance(case.get("trace"), dict) else {}
        profile_meta = case.get("archive_profile") if isinstance(case.get("archive_profile"), dict) else {}
        rpc_preflight = profile_meta.get("rpc_preflight") if isinstance(profile_meta.get("rpc_preflight"), dict) else {}
        checks.append(
            {
                "preflight_id": f"archive-rpc-preflight-{case['slug']}",
                "case_id": case["case_id"],
                "slug": case["slug"],
                "chain": case["chain"],
                "rpc_env": env.get("name") if env else "",
                "fork_block": case.get("fork_block"),
                "preflight_status": "passed" if case.get("verified") and env and case.get("fork_block") is not None else "blocked",
                "archive_state": str(rpc_preflight.get("archive_state") or "fixture_declared_available"),
                "block_hash_checked": bool(rpc_preflight.get("block_hash_checked", True)),
                "receipt_checked": bool(rpc_preflight.get("receipt_checked", True)),
                "trace_capture": {
                    "status": trace.get("status") or "unavailable",
                    "path": trace.get("path") or "",
                    "provider_method": trace.get("provider_method") or "debug_traceTransaction",
                },
                "log_capture": {
                    "status": "available" if case.get("log_path") else "missing",
                    "path": case.get("log_path") or "",
                },
                "read_only_rpc_methods": [
                    "eth_chainId",
                    "eth_getBlockByNumber",
                    "eth_getTransactionReceipt",
                    "debug_traceTransaction",
                ],
                "prohibited_actions": ["broadcast_transactions", "load_private_keys", "state_changing_rpc"],
            }
        )
    safety = profile.get("safety") if isinstance(profile.get("safety"), dict) else {}
    return {
        "schema_version": ARCHIVE_RPC_PREFLIGHT_SCHEMA_VERSION,
        "bundle_type": REPLAY_BUNDLE_TYPE,
        "lab_id": "abra",
        "generated_at": generated_at,
        "profile_id": profile.get("profile_id"),
        "profile_path": str(profile_path) if profile_path else "",
        "mode": "production_local",
        "deterministic": True,
        "network_access": str(safety.get("network_access") or "fixture_profile_only"),
        "read_only": True,
        "private_keys": "not_used",
        "broadcasts_transactions": False,
        "state_changing_rpc": False,
        "status": "passed" if checks and all(check["preflight_status"] == "passed" for check in checks) else "failed",
        "summary": {
            "case_count": len(checks),
            "status_counts": _count_by_key(checks, "preflight_status"),
            "trace_capture_count": sum(1 for check in checks if check["trace_capture"]["status"] in {"available", "declared"}),
            "log_capture_count": sum(1 for check in checks if check["log_capture"]["status"] == "available"),
        },
        "denied_actions": [
            "private_key_material",
            "transaction_broadcast",
            "cast_send",
            "forge_script_broadcast",
            "eth_sendRawTransaction",
        ],
        "checks": checks,
    }


def _write_archive_profile_trace_artifacts(
    out_path: Path,
    generated_at: str,
    assessments: list[dict[str, Any]],
) -> list[Path]:
    paths: list[Path] = []
    for case in assessments:
        profile_meta = case.get("archive_profile") if isinstance(case.get("archive_profile"), dict) else {}
        trace_capture = profile_meta.get("trace_capture") if isinstance(profile_meta.get("trace_capture"), dict) else {}
        if not trace_capture:
            continue
        path = out_path / "artifacts" / "traces" / f"{case['slug']}.archive_trace.json"
        path.parent.mkdir(parents=True, exist_ok=True)
        payload = {
            "schema_version": ARCHIVE_REPLAY_TRACE_SCHEMA_VERSION,
            "generated_at": generated_at,
            "profile_id": profile_meta.get("profile_id"),
            "case_id": case.get("case_id"),
            "slug": case.get("slug"),
            "chain": case.get("chain"),
            "fork_block": case.get("fork_block"),
            "provider_method": trace_capture.get("provider_method") or "debug_traceTransaction",
            "status": trace_capture.get("status") or "available",
            "read_only": True,
            "broadcasts_transactions": False,
            "private_keys": "not_used",
            "capture": trace_capture.get("capture") if "capture" in trace_capture else trace_capture,
        }
        path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        relative = path.relative_to(out_path).as_posix()
        trace = case.get("trace") if isinstance(case.get("trace"), dict) else {}
        trace["path"] = relative
        trace["status"] = str(trace.get("status") or "available")
        trace["source"] = "archive_rpc_profile.trace_capture"
        case["trace"] = trace
        paths.append(path)
    return paths


def _fixture_cases(fixture: dict[str, Any]) -> list[dict[str, Any]]:
    if fixture.get("schema_version") not in (None, REPLAY_CASE_FIXTURE_SCHEMA_VERSION):
        raise ValueError("Replay case fixture has an unsupported schema_version.")
    cases = fixture.get("cases")
    if isinstance(cases, list) and cases:
        return cases
    if "incident" in fixture:
        return [fixture]
    raise ValueError("Replay case fixture must contain a non-empty `cases` list.")


def _load_json_object(path: Path) -> dict[str, Any]:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise ValueError(f"Invalid JSON in replay case fixture: {exc}") from exc
    if not isinstance(data, dict):
        raise ValueError("Replay case fixture root must be a JSON object.")
    return data


def _load_bundle_json(path: Path, errors: list[str]) -> dict[str, Any] | None:
    if not path.exists():
        return None
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        errors.append(f"Invalid JSON in {path.name}: {exc}")
        return None
    if not isinstance(data, dict):
        errors.append(f"{path.name} must contain a JSON object.")
        return None
    return data


def _trace_metadata(raw_case: dict[str, Any], result_data: dict[str, Any]) -> dict[str, Any]:
    raw_trace = raw_case.get("trace")
    trace = dict(raw_trace) if isinstance(raw_trace, dict) else {}
    result_trace = result_data.get("trace")
    if isinstance(result_trace, dict):
        trace.update(result_trace)
    trace_path = _optional_str(trace.get("path") or raw_case.get("trace_path") or result_data.get("trace_path"))
    status = _optional_str(trace.get("status") or raw_case.get("trace_status") or result_data.get("trace_status"))
    if not status:
        status = "available" if trace_path else "unavailable"
    if trace.get("source"):
        source = str(trace["source"])
    elif isinstance(raw_trace, dict) or isinstance(result_trace, dict) or trace_path:
        source = "fixture.trace"
    else:
        source = "not_declared"
    return {
        "status": status,
        "path": trace_path,
        "source": source,
        "required_for_live_validation": True,
        "note": str(
            trace.get("note")
            or (
                "Trace artifact is declared by the fixture."
                if status in {"available", "declared"}
                else "No transaction or execution trace artifact is declared by the fixture."
            )
        ),
    }


def _simulation_preconditions(
    *,
    chain: str,
    rpc_env: str,
    env_present: bool,
    env_source: str,
    fork_block: Any,
    test_path: str | None,
    replay_test: str | None,
    metadata_status: str,
    safety_violations: list[str],
) -> list[dict[str, Any]]:
    return [
        {
            "name": "replay_test_declared",
            "required": True,
            "satisfied": bool(test_path and replay_test),
            "retryable": False,
            "message": "No concrete replay test is declared for this case.",
            "required_action": "Implement or declare a bounded replay test before simulation.",
            "details": {"test_path": test_path, "replay_test": replay_test},
        },
        {
            "name": "archive_rpc_env_configured",
            "required": bool(rpc_env and test_path and replay_test),
            "satisfied": bool(env_present),
            "retryable": True,
            "message": f"Archive RPC environment variable is unavailable: {rpc_env}.",
            "required_action": "Configure a read-only archive RPC endpoint for fork replay.",
            "details": {"rpc_env": rpc_env, "source": env_source},
        },
        {
            "name": "fork_block_declared",
            "required": chain not in NON_EVM_CHAINS and bool(test_path and replay_test),
            "satisfied": fork_block is not None,
            "retryable": False,
            "message": "Fork block is missing for an EVM replay case.",
            "required_action": "Add the incident fork block before replay validation.",
            "details": {"fork_block": fork_block, "chain": chain},
        },
        {
            "name": "metadata_or_compile_passed",
            "required": bool(test_path and replay_test),
            "satisfied": metadata_status in {"passed", "not_run", "not_declared"},
            "retryable": True,
            "message": "Metadata or compile precheck did not pass.",
            "required_action": "Repair metadata or compile failures before replay validation.",
            "details": {"metadata_status": metadata_status},
        },
        {
            "name": "non_broadcast_command",
            "required": True,
            "satisfied": not safety_violations,
            "retryable": False,
            "message": "Replay command contains a denied broadcast/private-key marker.",
            "required_action": "Remove denied live-transaction markers and keep replay read-only.",
            "details": {"denied_markers": safety_violations},
        },
    ]


def _first_required_environment(case: dict[str, Any]) -> dict[str, Any] | None:
    env = case.get("required_environment")
    if not isinstance(env, list):
        return None
    for item in env:
        if isinstance(item, dict):
            return item
    return None


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


def _environment_map(value: Any) -> dict[str, bool]:
    if not isinstance(value, dict):
        return {}
    result: dict[str, bool] = {}
    for key, present in value.items():
        if isinstance(key, str):
            result[key] = bool(present)
    return result


def _case_env_present(
    raw_case: dict[str, Any],
    global_env: dict[str, bool],
    rpc_env: str,
    use_process_environment: bool,
) -> tuple[bool, str]:
    if not rpc_env:
        return False, "not_declared"
    case_env = _environment_map(raw_case.get("environment"))
    if rpc_env in case_env:
        return case_env[rpc_env], "fixture.case.environment"
    if rpc_env in global_env:
        return global_env[rpc_env], "fixture.environment"
    if use_process_environment:
        return bool(os.environ.get(rpc_env)), "process_environment"
    return False, "deterministic_local_missing_fixture_environment"


def _resolve_status(
    *,
    explicit_status: str,
    test_path: str | None,
    replay_test: str | None,
    rpc_env: str,
    env_present: bool,
    returncode: Any,
) -> str:
    if explicit_status:
        return explicit_status
    if not test_path or not replay_test:
        return "no_test"
    if rpc_env and not env_present:
        return "no_rpc"
    if isinstance(returncode, int):
        return "verified" if returncode == 0 else "failed"
    return "fixture_not_executed"


def _infer_blocker(status: str, rpc_env: str, log_text: str) -> str:
    if status == "verified":
        return ""
    if status == "no_rpc":
        return f"{rpc_env} not configured" if rpc_env else "rpc not configured"
    if status == "no_test":
        return "replay_test_not_implemented"
    if status == "fixture_not_executed":
        return "fixture_result_not_declared"
    if log_text:
        return classify_failure(log_text)
    return status


def _failure_reason(status: str, blocker: str, rpc_env: str) -> dict[str, Any]:
    if status == "verified":
        return {
            "code": "none",
            "category": "verified",
            "message": "Fixture declares a successful fork replay result.",
            "retryable": False,
        }
    if status == "no_rpc":
        return {
            "code": "missing_rpc",
            "category": "environment",
            "message": f"Required archive RPC environment variable is not configured: {rpc_env}.",
            "retryable": True,
        }
    if status == "no_test":
        return {
            "code": "replay_test_not_implemented",
            "category": "implementation",
            "message": "No concrete replay test is declared for this case.",
            "retryable": False,
        }
    if blocker == "archive_state_unavailable":
        return {
            "code": "archive_state_unavailable",
            "category": "rpc_archive_state",
            "message": "RPC endpoint did not provide historical state required for the fork block.",
            "retryable": True,
        }
    if status == "unsafe_fixture_command":
        return {
            "code": "unsafe_fixture_command",
            "category": "safety",
            "message": "Fixture command includes a denied broadcast, private-key, or live-send marker.",
            "retryable": False,
        }
    return {
        "code": blocker or status,
        "category": "replay_execution",
        "message": f"Replay fixture is not verified: {blocker or status}.",
        "retryable": status in {"failed", "timeout", "metadata_failed"},
    }


def _feasibility(status: str, blocker: str) -> str:
    if status == "verified":
        return "replay_verified"
    if status == "no_rpc":
        return "blocked_missing_rpc"
    if status == "no_test":
        return "blocked_missing_replay_test"
    if blocker == "archive_state_unavailable":
        return "blocked_archive_rpc"
    if status == "metadata_failed":
        return "blocked_metadata_failure"
    if status == "timeout":
        return "blocked_timeout"
    if status == "unsafe_fixture_command":
        return "blocked_unsafe_fixture_command"
    return "blocked_replay_failure"


def _claim_limitations(case: dict[str, Any]) -> list[str]:
    if case["verified"]:
        return [
            "L4 means the fixture declares a successful local fork replay result; it is not evidence for adjacent exploit variants.",
            "This bounded workflow did not broadcast transactions or require private keys.",
        ]
    return [
        "This claim records replay feasibility or a blocker, not exploit reproduction.",
        "A blocked replay must not be written as proof that the exploit path is impossible.",
    ]


def _metadata_status(test_path: str | None, metadata_test: str | None) -> str:
    if not test_path:
        return "not_applicable"
    if metadata_test:
        return "not_run"
    return "not_declared"


def _rpc_note(status: str, rpc_env: str, env_present: bool) -> str:
    if not env_present:
        return f"{rpc_env} is required before live fork replay can be attempted."
    if status == "verified":
        return f"{rpc_env} was marked present by the fixture for the verified replay result."
    return f"{rpc_env} was marked present, but the replay is not verified."


def _write_case_log(out_path: Path, slug: str, log_text: str) -> Path | None:
    if not log_text:
        return None
    path = out_path / "artifacts" / "logs" / f"{slug}.replay.log"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(log_text.rstrip() + "\n", encoding="utf-8")
    return path


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
    if kind == "replay_log":
        return "Fork replay log artifact for bounded local replay evidence."
    if kind == "replay_feasibility_report":
        return "Replay feasibility report; distinguishes verified fork replay from blocked preconditions."
    if kind == "replay_blocker_ledger":
        return "Replay blocker ledger preserving missing preconditions and non-reproduction boundaries."
    if kind == "archive_rpc_validation":
        return "Deterministic local archive RPC validation artifact; no network access or transaction broadcast."
    if kind == "archive_rpc_profile":
        return "Read-only production-local archive RPC replay profile fixture."
    if kind == "archive_rpc_preflight":
        return "Read-only archive RPC preflight checks for fork block, trace capture, and replay logs."
    if kind == "archive_replay_trace":
        return "Fixture-backed archive replay trace capture metadata."
    if kind == "ara_production_contract":
        return "ARA production drafting and replay-reproduction gate sidecar."
    if kind == "replay_case_fixture":
        return "Input fixture declaring bounded replay cases and expected local outcomes."
    if kind == "evidence_bundle":
        return "ABRA evidence bundle claim index for replay assessment."
    if kind.startswith("replay_"):
        return "ABRA replay memory artifact for deterministic local assessment."
    return f"ABRA artifact for {role}."


def _artifact_id(relative: Path) -> str:
    normalized = re.sub(r"[^a-zA-Z0-9]+", "-", relative.as_posix()).strip("-").lower()
    digest = hashlib.sha256(relative.as_posix().encode("utf-8")).hexdigest()[:10]
    return f"artifact-{normalized}-{digest}"


def _run_id(generated_at: str, fixture_path: Path, out_path: Path, run_number: int) -> str:
    stamp = re.sub(r"[^0-9A-Za-z]+", "", generated_at)
    digest = hashlib.sha256(f"{generated_at}|{fixture_path}|{out_path}|{run_number}".encode("utf-8")).hexdigest()[:10]
    return f"replay-run-{stamp}-{run_number:04d}-{digest}"


def _render_replay_report(report: dict[str, Any]) -> str:
    summary = report["summary"]
    lines = [
        "# ABRA Replay Feasibility Report",
        "",
        f"- Bundle type: `{report['bundle_type']}`",
        f"- Cases assessed: {summary['case_count']}",
        f"- Verified fork replays: {summary['verified_count']}",
        f"- Blocked or unverified cases: {summary['blocked_count']}",
        f"- Status counts: `{summary['status_counts']}`",
        f"- Blocker ledger: `{report['blocker_ledger']}`",
        f"- Archive RPC validation: `{report['archive_rpc_validation']}`",
        "",
        "## Case Matrix",
        "",
        "| Incident | Chain | Fork block | Status | Feasibility | Evidence | Failure reason |",
        "|---|---|---:|---|---|---|---|",
    ]
    for case in report["cases"]:
        block = case["fork_block"] if case["fork_block"] is not None else ""
        lines.append(
            f"| {case['incident']} | {case['chain']} | {block} | `{case['replay_status']}` | "
            f"`{case['feasibility']}` | `{case['evidence_level']}` | `{case['failure_reason']['code']}` |"
        )
    lines.extend(
        [
            "",
            "## Safety",
            "",
            "- Does not broadcast transactions.",
            "- Does not require private keys.",
            "- Does not perform live trading.",
        ]
    )
    return "\n".join(lines) + "\n"


def _evidence_validation_payload(
    root: Path,
    minimum: str,
    errors: list[str],
    warnings: list[str],
    files_checked: list[str],
    claims: list[Any],
    artifacts: list[Any],
) -> dict[str, Any]:
    valid_claims = [claim for claim in claims if isinstance(claim, dict)]
    return {
        "schema_version": EVIDENCE_VALIDATION_SCHEMA_VERSION,
        "status": "passed" if not errors else "failed",
        "bundle_path": str(root),
        "minimum_level": minimum,
        "claim_count": len(valid_claims),
        "artifact_count": len([artifact for artifact in artifacts if isinstance(artifact, dict)]),
        "evidence_levels": _evidence_counts(valid_claims),
        "errors": errors,
        "warnings": warnings,
        "files_checked": sorted(set(files_checked)),
    }


def _count_by_key(rows: list[dict[str, Any]], key: str) -> dict[str, int]:
    counts: dict[str, int] = {}
    for row in rows:
        value = str(row.get(key) or "unknown")
        counts[value] = counts.get(value, 0) + 1
    return counts


def _evidence_counts(claims: list[dict[str, Any]]) -> dict[str, int]:
    counts: dict[str, int] = {}
    for claim in claims:
        level = str(claim.get("evidence_level") or "unknown")
        counts[level] = counts.get(level, 0) + 1
    return counts


def _command_safety_violations(command: str) -> list[str]:
    if not command:
        return []
    return [pattern for pattern in DENIED_COMMAND_PATTERNS if pattern in command]


def _forge_command_text(test_path: str, replay_test: str) -> str:
    return f"forge test --match-path {test_path} --match-test {replay_test} -vv"


def _optional_str(value: Any) -> str | None:
    if value in (None, ""):
        return None
    return str(value)


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _slug(value: str) -> str:
    slug = re.sub(r"[^a-zA-Z0-9]+", "-", value.strip().lower()).strip("-")
    return slug or "case"


def _utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()
