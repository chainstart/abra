"""Assess replay evidence for every case in an ABRA replay cohort."""

from __future__ import annotations

import json
import os
import shutil
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from abra.replay_agent import REPLAY_CASE_FIXTURE_SCHEMA_VERSION, assess_replay_fixture, validate_evidence_bundle


COHORT_ASSESSMENT_SCHEMA_VERSION = "abra.replay_cohort_assessment.v1"
COHORT_EVIDENCE_MANIFEST_SCHEMA_VERSION = "abra.replay_cohort_evidence_manifest.v1"
COHORT_MANIFEST_SCHEMA_VERSION = "abra.replay_cohort.manifest.v1"
COHORT_CASE_SCHEMA_VERSION = "abra.replay_cohort.case.v1"


def assess_replay_cohort(
    *,
    cohort: str | Path,
    out: str | Path,
    min_level: str = "L1",
) -> dict[str, Any]:
    """Run ABRA replay assessment over every case JSON in a replay cohort."""

    cohort_path = Path(cohort).expanduser().resolve()
    out_path = Path(out).expanduser().resolve()
    if not cohort_path.exists():
        raise FileNotFoundError(f"Replay cohort not found: {cohort_path}")

    manifest_path = cohort_path if cohort_path.is_file() else cohort_path / "manifest.json"
    if not manifest_path.exists() or not manifest_path.is_file():
        raise FileNotFoundError(f"Replay cohort manifest not found: {manifest_path}")

    manifest = _load_json_object(manifest_path)
    case_paths = _cohort_case_paths(manifest_path, manifest)
    generated_at = _utc_now()
    if out_path.exists():
        shutil.rmtree(out_path)
    out_path.mkdir(parents=True, exist_ok=True)
    fixtures_dir = out_path / "case_fixtures"
    bundles_dir = out_path / "cases"
    fixtures_dir.mkdir(parents=True, exist_ok=True)
    bundles_dir.mkdir(parents=True, exist_ok=True)

    case_entries: list[dict[str, Any]] = []
    errors: list[str] = []
    status_counts: dict[str, int] = {}
    evidence_levels: dict[str, int] = {}
    verified_count = 0

    for index, case_path in enumerate(case_paths, start=1):
        try:
            case_payload = _load_json_object(case_path)
            fixture = _replay_fixture_from_cohort_case(case_payload, manifest, case_path)
            slug = str(fixture["cases"][0]["slug"])
            fixture_path = fixtures_dir / f"{slug}.json"
            fixture_path.write_text(json.dumps(fixture, indent=2, sort_keys=True) + "\n", encoding="utf-8")
            bundle_dir = bundles_dir / slug
            assessment = assess_replay_fixture(fixture_path, bundle_dir)
            validation = validate_evidence_bundle(bundle_dir, min_level=min_level)
            status = "passed" if assessment.get("status") == "passed" and validation.get("status") == "passed" else "failed"
            verified = int(assessment.get("status_counts", {}).get("verified", 0) or 0)
            verified_count += verified
            for key, value in (assessment.get("status_counts") or {}).items():
                status_counts[str(key)] = status_counts.get(str(key), 0) + int(value or 0)
            for key, value in (assessment.get("evidence_levels") or {}).items():
                evidence_levels[str(key)] = evidence_levels.get(str(key), 0) + int(value or 0)
            if status != "passed":
                errors.append(f"{slug}: assessment or validation failed")
            case_entries.append(
                {
                    "index": index,
                    "case_id": case_payload.get("case_id") or case_payload.get("incident_id") or slug,
                    "slug": slug,
                    "source_case": str(case_path),
                    "fixture": _relative_to(fixture_path, out_path),
                    "bundle": _relative_to(bundle_dir, out_path),
                    "status": status,
                    "assessment_status": assessment.get("status"),
                    "validation_status": validation.get("status"),
                    "case_count": assessment.get("case_count", 0),
                    "verified_count": verified,
                    "evidence_levels": assessment.get("evidence_levels", {}),
                    "status_counts": assessment.get("status_counts", {}),
                    "errors": list(validation.get("errors") or []),
                }
            )
        except Exception as exc:
            slug = case_path.stem
            errors.append(f"{slug}: {type(exc).__name__}: {exc}")
            case_entries.append(
                {
                    "index": index,
                    "case_id": slug,
                    "slug": slug,
                    "source_case": str(case_path),
                    "status": "failed",
                    "assessment_status": "not_run",
                    "validation_status": "not_run",
                    "case_count": 0,
                    "verified_count": 0,
                    "evidence_levels": {},
                    "status_counts": {},
                    "errors": [f"{type(exc).__name__}: {exc}"],
                }
            )

    manifest_payload = {
        "schema_version": COHORT_EVIDENCE_MANIFEST_SCHEMA_VERSION,
        "generated_at": generated_at,
        "source_cohort": str(manifest_path),
        "cohort_id": manifest.get("cohort_id"),
        "case_count": len(case_paths),
        "assessed_count": sum(1 for entry in case_entries if entry["assessment_status"] != "not_run"),
        "verified_count": verified_count,
        "status_counts": status_counts,
        "evidence_levels": evidence_levels,
        "cases": case_entries,
    }
    manifest_out = out_path / "cohort_evidence_manifest.json"
    manifest_out.write_text(json.dumps(manifest_payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    payload = {
        "schema_version": COHORT_ASSESSMENT_SCHEMA_VERSION,
        "status": "passed" if not errors else "failed",
        "cohort_id": manifest.get("cohort_id"),
        "case_count": len(case_paths),
        "assessed_count": manifest_payload["assessed_count"],
        "verified_count": verified_count,
        "status_counts": status_counts,
        "evidence_levels": evidence_levels,
        "errors": errors,
        "artifacts": {
            "manifest": "cohort_evidence_manifest.json",
            "cases_dir": "cases",
            "case_fixtures_dir": "case_fixtures",
        },
        "out": str(out_path),
    }
    return payload


def _cohort_case_paths(manifest_path: Path, manifest: dict[str, Any]) -> list[Path]:
    if manifest.get("schema_version") not in (None, COHORT_MANIFEST_SCHEMA_VERSION):
        raise ValueError("Replay cohort manifest has an unsupported schema_version.")
    root = manifest_path.parent
    cases = manifest.get("cases")
    paths: list[Path] = []
    if isinstance(cases, list):
        for item in cases:
            if not isinstance(item, dict):
                continue
            case_file = str(item.get("case_file") or "").strip()
            if case_file:
                paths.append((root / case_file).resolve())
    if not paths:
        paths = sorted((root / "cases").glob("*.json"))
    if not paths:
        raise ValueError("Replay cohort manifest does not reference any case JSON files.")
    return paths


def _replay_fixture_from_cohort_case(
    case: dict[str, Any],
    cohort_manifest: dict[str, Any],
    case_path: Path,
) -> dict[str, Any]:
    if case.get("schema_version") not in (None, COHORT_CASE_SCHEMA_VERSION, REPLAY_CASE_FIXTURE_SCHEMA_VERSION):
        raise ValueError("Replay cohort case has an unsupported schema_version.")
    slug = str(case.get("slug") or case_path.stem).strip() or case_path.stem
    incident = str(case.get("incident") or case.get("name") or slug).strip()
    chain = str(case.get("chain") or "unknown").strip().lower()
    rpc_env = str(case.get("rpc_env") or _rpc_env_for_chain(chain)).strip()
    fixture_case = {
        "incident": incident,
        "slug": slug,
        "chain": chain,
        "rpc_env": rpc_env,
        "attack_family": case.get("attack_family") or "unknown",
        "loss_usd": int(case.get("loss_usd") or 0),
        "fork_block": case.get("fork_block"),
        "test_path": case.get("test_path") or None,
        "metadata_test": case.get("metadata_test") or None,
        "replay_test": case.get("replay_test") or None,
        "seed_transaction_hash": case.get("seed_transaction_hash") or "",
        "provenance_url": case.get("provenance_url") or "",
        "source_cohort_case": str(case_path),
    }
    if isinstance(case.get("environment"), dict):
        fixture_case["environment"] = case["environment"]
    elif rpc_env:
        fixture_case["environment"] = {rpc_env: bool(os.environ.get(rpc_env))}
    if isinstance(case.get("fixture_result"), dict):
        fixture_case["fixture_result"] = case["fixture_result"]
    if isinstance(case.get("trace"), dict):
        fixture_case["trace"] = case["trace"]
    return {
        "schema_version": REPLAY_CASE_FIXTURE_SCHEMA_VERSION,
        "fixture_id": f"{cohort_manifest.get('cohort_id') or 'cohort'}-{slug}",
        "description": f"ABRA replay assessment fixture generated from cohort case {slug}.",
        "allow_process_environment": True,
        "source_cohort_manifest": str(case_path.parent.parent / "manifest.json"),
        "cases": [fixture_case],
    }


def _rpc_env_for_chain(chain: str) -> str:
    normalized = chain.strip().lower().replace("-", "_").replace(" ", "_")
    mapping = {
        "ethereum": "ETH_RPC_URL",
        "eth": "ETH_RPC_URL",
        "mainnet": "ETH_RPC_URL",
        "polygon": "POLYGON_RPC_URL",
        "bsc": "BSC_RPC_URL",
        "bnb": "BSC_RPC_URL",
        "arbitrum": "ARBITRUM_RPC_URL",
        "optimism": "OPTIMISM_RPC_URL",
        "base": "BASE_RPC_URL",
        "avalanche": "AVALANCHE_RPC_URL",
        "sui": "SUI_RPC_URL",
        "terra": "TERRA_RPC_URL",
        "eos": "EOS_RPC_URL",
    }
    return mapping.get(normalized, "ARCHIVE_RPC_URL")


def _load_json_object(path: Path) -> dict[str, Any]:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise ValueError(f"Invalid JSON in {path}: {exc}") from exc
    if not isinstance(data, dict):
        raise ValueError(f"{path} must contain a JSON object.")
    return data


def _relative_to(path: Path, base: Path) -> str:
    try:
        return str(path.relative_to(base))
    except ValueError:
        return str(path)


def _utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
