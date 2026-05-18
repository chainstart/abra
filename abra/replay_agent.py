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

from abra.bundle import ARTIFACT_MANIFEST_SCHEMA_VERSION, EVIDENCE_BUNDLE_SCHEMA_VERSION, EVIDENCE_LABELS
from tools.replay_runner import ReplayResult, classify_failure


REPLAY_CASE_FIXTURE_SCHEMA_VERSION = "abra.replay_case_fixture.v1"
REPLAY_FEASIBILITY_REPORT_SCHEMA_VERSION = "abra.replay_feasibility_report.v1"
REPLAY_ASSESSMENT_SCHEMA_VERSION = "abra.replay_assessment.build.v1"
EVIDENCE_VALIDATION_SCHEMA_VERSION = "abra.evidence.validation.v1"
REPLAY_BUNDLE_TYPE = "abra_replay_evidence_bundle"
EVIDENCE_ORDER = {level: index for index, level in enumerate(EVIDENCE_LABELS)}
DENIED_COMMAND_PATTERNS = ("--broadcast", "cast send", "PRIVATE_KEY")


def assess_replay_fixture(case_fixture: str | Path, out: str | Path) -> dict[str, Any]:
    """Assess replay feasibility from a local fixture and write a replay evidence bundle."""

    fixture_path = Path(case_fixture).expanduser().resolve()
    out_path = Path(out).expanduser().resolve()
    if not fixture_path.exists() or not fixture_path.is_file():
        raise FileNotFoundError(f"Replay case fixture not found: {fixture_path}")

    fixture = _load_json_object(fixture_path)
    cases = _fixture_cases(fixture)
    generated_at = _utc_now()
    out_path.mkdir(parents=True, exist_ok=True)
    artifacts_dir = out_path / "artifacts"
    artifacts_dir.mkdir(parents=True, exist_ok=True)

    fixture_copy = artifacts_dir / "input" / fixture_path.name
    fixture_copy.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(fixture_path, fixture_copy)

    global_env = _environment_map(fixture.get("environment"))
    assessments: list[dict[str, Any]] = []
    log_paths: list[Path] = []
    for index, raw_case in enumerate(cases, start=1):
        assessment, log_path = _assess_case(raw_case, index, global_env, out_path)
        assessments.append(assessment)
        if log_path is not None:
            log_paths.append(log_path)

    report = _build_replay_report(
        generated_at=generated_at,
        fixture_path=fixture_path,
        fixture=fixture,
        assessments=assessments,
    )
    report_json_path = out_path / "replay_feasibility_report.json"
    report_md_path = out_path / "replay_feasibility_report.md"
    report_json_path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    report_md_path.write_text(_render_replay_report(report), encoding="utf-8")

    artifact_entries = [
        _artifact_entry(out_path, report_json_path, "replay_feasibility_report", "replay_assessment"),
        _artifact_entry(out_path, report_md_path, "replay_feasibility_report", "human_readable_replay_assessment"),
        _artifact_entry(out_path, fixture_copy, "replay_case_fixture", "input_fixture"),
    ]
    artifact_entries.extend(
        _artifact_entry(out_path, path, "replay_log", "fixture_replay_log") for path in sorted(log_paths)
    )

    artifact_by_path = {entry["bundle_path"]: entry for entry in artifact_entries}
    claims = _build_claims(assessments, artifact_entries, artifact_by_path)
    evidence_bundle = {
        "schema_version": EVIDENCE_BUNDLE_SCHEMA_VERSION,
        "bundle_type": REPLAY_BUNDLE_TYPE,
        "lab_id": "abra",
        "generated_at": generated_at,
        "source_fixture": str(fixture_path),
        "replay_report": "replay_feasibility_report.json",
        "evidence_levels": EVIDENCE_LABELS,
        "claims": claims,
        "safety": report["safety"],
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
    artifact_manifest_path = out_path / "artifact_manifest.json"
    artifact_manifest_path.write_text(json.dumps(artifact_manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    validation = validate_evidence_bundle(out_path, min_level="L1")
    files_written = [
        "replay_feasibility_report.json",
        "replay_feasibility_report.md",
        "evidence_bundle.json",
        "artifact_manifest.json",
    ]
    files_written.extend(str(path.relative_to(out_path)) for path in sorted(log_paths))
    payload = {
        "schema_version": REPLAY_ASSESSMENT_SCHEMA_VERSION,
        "status": "passed" if validation["status"] == "passed" else "failed",
        "bundle_type": REPLAY_BUNDLE_TYPE,
        "bundle_path": str(out_path),
        "source_fixture": str(fixture_path),
        "case_count": len(assessments),
        "status_counts": _count_by_key(assessments, "replay_status"),
        "feasibility_counts": _count_by_key(assessments, "feasibility"),
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

    return _evidence_validation_payload(root, minimum, errors, warnings, files_checked, claims, artifacts)


def _assess_case(
    raw_case: dict[str, Any],
    index: int,
    global_env: dict[str, bool],
    out_path: Path,
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
    env_present, env_source = _case_env_present(raw_case, global_env, rpc_env)

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
        metadata_status=str(result_data.get("metadata_status") or raw_case.get("metadata_status") or _metadata_status(test_path, metadata_test)),
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
) -> dict[str, Any]:
    verified = [case for case in assessments if case["verified"]]
    blocked = [case for case in assessments if not case["verified"]]
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
        },
        "safety": {
            "broadcasts_transactions": False,
            "requires_private_keys": False,
            "live_trading": False,
            "runs_forge": False,
            "notes": [
                "This MVP assesses fixture-declared replay outcomes only.",
                "It does not broadcast transactions, require private keys, or perform live trading.",
            ],
        },
        "claims_preview": claims_preview,
        "cases": assessments,
    }


def _build_claims(
    assessments: list[dict[str, Any]],
    artifacts: list[dict[str, Any]],
    artifact_by_path: dict[str, dict[str, Any]],
) -> list[dict[str, Any]]:
    report_id = artifact_by_path["replay_feasibility_report.json"]["artifact_id"]
    fixture_artifact = next(artifact for artifact in artifacts if artifact["kind"] == "replay_case_fixture")
    fixture_id = fixture_artifact["artifact_id"]
    claims: list[dict[str, Any]] = []
    for case in assessments:
        supported_by = [report_id, fixture_id]
        if case.get("log_path") and case["log_path"] in artifact_by_path:
            supported_by.append(artifact_by_path[case["log_path"]]["artifact_id"])
        if case["verified"]:
            claim_type = "fork_replay"
            source_kind = "replay_result"
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
    if not any(case.get("replay_status") == "no_rpc" for case in cases if isinstance(case, dict)):
        warnings.append("Replay report does not include a no_rpc fixture case.")


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


def _environment_map(value: Any) -> dict[str, bool]:
    if not isinstance(value, dict):
        return {}
    result: dict[str, bool] = {}
    for key, present in value.items():
        if isinstance(key, str):
            result[key] = bool(present)
    return result


def _case_env_present(raw_case: dict[str, Any], global_env: dict[str, bool], rpc_env: str) -> tuple[bool, str]:
    if not rpc_env:
        return False, "not_declared"
    case_env = _environment_map(raw_case.get("environment"))
    if rpc_env in case_env:
        return case_env[rpc_env], "fixture.case.environment"
    if rpc_env in global_env:
        return global_env[rpc_env], "fixture.environment"
    return bool(os.environ.get(rpc_env)), "process_environment"


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
            "This MVP did not broadcast transactions or require private keys.",
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
        "path": relative.as_posix(),
        "bundle_path": relative.as_posix(),
        "sha256": _sha256_file(path),
        "size_bytes": path.stat().st_size,
    }


def _artifact_id(relative: Path) -> str:
    normalized = re.sub(r"[^a-zA-Z0-9]+", "-", relative.as_posix()).strip("-").lower()
    digest = hashlib.sha256(relative.as_posix().encode("utf-8")).hexdigest()[:10]
    return f"artifact-{normalized}-{digest}"


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
