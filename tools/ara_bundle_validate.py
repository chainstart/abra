#!/usr/bin/env python3
"""Validate an ABRA bundle through public ARA bundle and drafting consumers."""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
from pathlib import Path
from typing import Any


ARA_ROOT = Path(os.environ.get("ARA_REPO", "/home/biostar/work/projects/ara"))
SCHEMA_VERSION = "abra.ara_contract_smoke.v1"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("bundle_path", help="ABRA bundle directory to validate with public ARA.")
    parser.add_argument("--ara-root", default=str(ARA_ROOT), help="Path to the public ARA repository.")
    parser.add_argument("--json", action="store_true", help="Print JSON output.")
    args = parser.parse_args(argv)

    bundle_path = Path(args.bundle_path).expanduser().resolve()
    ara_root = Path(args.ara_root).expanduser().resolve()
    result = validate_with_ara(bundle_path, ara_root)
    _emit(result, args.json)
    return 0 if result["status"] == "passed" else 1


def validate_with_ara(bundle_path: Path, ara_root: Path) -> dict[str, Any]:
    errors: list[str] = []
    warnings: list[str] = []
    if not ara_root.is_dir():
        errors.append(f"ARA repository not found: {ara_root}")
        return _payload(bundle_path, ara_root, errors, warnings, None, None)

    validation = _run_ara_json(ara_root, ["bundles", "validate", str(bundle_path), "--json"])
    drafting = _run_ara_json(ara_root, ["drafting", "context", str(bundle_path), "--json"])

    if validation["returncode"] != 0:
        errors.append("ARA bundle validation command failed.")
    if drafting["returncode"] != 0:
        errors.append("ARA drafting context command failed.")

    validation_payload = validation.get("payload")
    drafting_payload = drafting.get("payload")
    if not isinstance(validation_payload, dict):
        errors.append("ARA bundle validation did not return a JSON object.")
    elif validation_payload.get("valid") is not True:
        errors.extend(f"ARA validation: {item}" for item in validation_payload.get("errors", []))
        warnings.extend(f"ARA validation: {item}" for item in validation_payload.get("warnings", []))

    if not isinstance(drafting_payload, dict):
        errors.append("ARA drafting context did not return a JSON object.")
    else:
        errors.extend(_drafting_contract_errors(drafting_payload))
        warnings.extend(f"ARA drafting: {item}" for item in drafting_payload.get("warnings", []))

    if validation.get("stderr"):
        warnings.append(f"ARA validation stderr: {validation['stderr'].strip()}")
    if drafting.get("stderr"):
        warnings.append(f"ARA drafting stderr: {drafting['stderr'].strip()}")

    return _payload(bundle_path, ara_root, errors, warnings, validation_payload, drafting_payload)


def _run_ara_json(ara_root: Path, args: list[str]) -> dict[str, Any]:
    env = dict(os.environ)
    existing_pythonpath = env.get("PYTHONPATH", "")
    env["PYTHONPATH"] = str(ara_root) if not existing_pythonpath else f"{ara_root}{os.pathsep}{existing_pythonpath}"
    completed = subprocess.run(
        [sys.executable, "-m", "ara", *args],
        cwd=str(ara_root),
        env=env,
        check=False,
        capture_output=True,
        text=True,
    )
    payload: Any = None
    if completed.stdout.strip():
        try:
            payload = json.loads(completed.stdout)
        except json.JSONDecodeError:
            payload = None
    return {
        "returncode": completed.returncode,
        "stdout": completed.stdout,
        "stderr": completed.stderr,
        "payload": payload,
    }


def _drafting_contract_errors(payload: dict[str, Any]) -> list[str]:
    errors: list[str] = []
    allowed_claims = payload.get("allowed_claims")
    blocked_claims = payload.get("blocked_claims")
    if not isinstance(allowed_claims, list):
        return ["ARA drafting context missing allowed_claims list."]
    if not isinstance(blocked_claims, list):
        return ["ARA drafting context missing blocked_claims list."]

    if not allowed_claims:
        errors.append("ARA drafting context did not expose any allowed claims.")
    for claim in allowed_claims:
        if not isinstance(claim, dict):
            errors.append("ARA allowed_claims contains a non-object claim.")
            continue
        level = str(claim.get("evidence_level") or "")
        if _evidence_rank(level) < 4 and _looks_like_replay_or_static_boundary(claim):
            errors.append(
                f"ARA allowed non-L4 replay/static boundary claim as citable: {claim.get('claim_id')}"
            )
        if level == "L4" and str(claim.get("status") or "").lower() in {"blocked", "failed", "unknown"}:
            errors.append(f"ARA allowed a blocked L4 claim as citable: {claim.get('claim_id')}")

    blocked_lower = [
        str(claim.get("claim_id"))
        for claim in blocked_claims
        if isinstance(claim, dict) and str(claim.get("evidence_level") or "") in {"L0", "L1", "L2", "L3"}
    ]
    if not blocked_lower:
        errors.append("ARA drafting context did not block any lower-than-L4 replay/static boundary claims.")
    return errors


def _looks_like_replay_or_static_boundary(claim: dict[str, Any]) -> bool:
    text = " ".join(
        str(claim.get(key) or "").lower()
        for key in ("claim", "claim_id", "status", "evidence_level")
    )


def _evidence_rank(level: str) -> int:
    if level.startswith("L") and level[1:].isdigit():
        return int(level[1:])
    return -1
    return any(
        marker in text
        for marker in (
            "static alert",
            "replay feasibility",
            "not l4 replay",
            "blocked replay",
            "fork replay",
            "fork-replay",
            "fork replayed",
        )
    )


def _payload(
    bundle_path: Path,
    ara_root: Path,
    errors: list[str],
    warnings: list[str],
    validation_payload: dict[str, Any] | None,
    drafting_payload: dict[str, Any] | None,
) -> dict[str, Any]:
    allowed_claims = drafting_payload.get("allowed_claims", []) if isinstance(drafting_payload, dict) else []
    blocked_claims = drafting_payload.get("blocked_claims", []) if isinstance(drafting_payload, dict) else []
    return {
        "schema_version": SCHEMA_VERSION,
        "status": "passed" if not errors else "failed",
        "bundle_path": str(bundle_path),
        "ara_root": str(ara_root),
        "errors": errors,
        "warnings": warnings,
        "ara_validation": validation_payload,
        "drafting_context": drafting_payload,
        "contract_summary": {
            "allowed_claim_count": len(allowed_claims) if isinstance(allowed_claims, list) else 0,
            "blocked_claim_count": len(blocked_claims) if isinstance(blocked_claims, list) else 0,
            "allowed_claim_ids": [
                str(claim.get("claim_id"))
                for claim in allowed_claims
                if isinstance(claim, dict) and claim.get("claim_id")
            ],
            "blocked_claim_ids": [
                str(claim.get("claim_id"))
                for claim in blocked_claims
                if isinstance(claim, dict) and claim.get("claim_id")
            ],
        },
    }


def _emit(payload: dict[str, Any], as_json: bool) -> None:
    if as_json:
        print(json.dumps(payload, indent=2, sort_keys=True))
        return
    print(f"{payload['schema_version']}: {payload['status']}")
    for error in payload["errors"]:
        print(f"error: {error}")
    for warning in payload["warnings"]:
        print(f"warning: {warning}")


if __name__ == "__main__":
    raise SystemExit(main())
