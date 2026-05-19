"""Side-effect-free ABRA manifest and repository smoke checks."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from abra.manifest import ResearchLabManifest, load_manifest, repo_root
from abra.tools import list_tools


SMOKE_SCHEMA_VERSION = "abra.lab_smoke.v1"


def build_smoke_report(manifest_path: str | Path | None = None) -> dict[str, Any]:
    """Build a side-effect-free ABRA smoke report."""

    manifest = load_manifest(manifest_path)
    root = repo_root()
    checks = [
        _check(
            name="manifest",
            passed=manifest.validation.valid,
            message="research_lab.yaml validates against the ABRA lab contract.",
            errors=manifest.validation.errors,
        ),
        _check(
            name="agent_cli",
            passed="python3 -m abra" in manifest.entrypoints["agent_cli"],
            message="ABRA declares the python module CLI entrypoint.",
        ),
        _check(
            name="result_bundle",
            passed="abra_result_bundle" in manifest.produced_bundles,
            message="ABRA declares the ARA-consumable result bundle type.",
        ),
        _check(
            name="agent_bundle",
            passed="abra_research_agent_bundle" in manifest.produced_bundles,
            message="ABRA declares the bounded research agent bundle type.",
        ),
        _check(
            name="command_policy",
            passed=_command_policy_is_hardened(manifest),
            message="ABRA command policy allows local inspection and denies write-risk commands.",
        ),
        _check(
            name="tools",
            passed=all(tool["exists"] for tool in list_tools(root)),
            message="Declared ABRA tool files are present.",
            metadata={"tools": list_tools(root)},
        ),
        _check(
            name="reports",
            passed=(root / "reports").is_dir() and (root / "reports" / "events").is_dir(),
            message="Existing report and event-card artifacts are still present.",
        ),
        _check(
            name="findings",
            passed=(root / "findings").is_dir(),
            message="Existing findings artifacts are still present.",
        ),
    ]
    status = "passed" if all(check["status"] == "passed" for check in checks) else "failed"
    return {
        "schema_version": SMOKE_SCHEMA_VERSION,
        "lab_id": manifest.lab_id,
        "status": status,
        "manifest_path": str(manifest.path),
        "checks": checks,
    }


def _command_policy_is_hardened(manifest: ResearchLabManifest) -> bool:
    allow_prefixes = set(manifest.command_policy["allow_prefixes"])
    deny_patterns = set(manifest.command_policy["deny_patterns"])
    return (
        "python3 -m abra" in allow_prefixes
        and "rm -rf" in deny_patterns
        and "cast send" in deny_patterns
        and "--broadcast" in deny_patterns
        and "PRIVATE_KEY" in deny_patterns
        and manifest.safety.get("destructive_commands") is False
    )


def _check(
    *,
    name: str,
    passed: bool,
    message: str,
    errors: list[str] | None = None,
    metadata: dict[str, Any] | None = None,
) -> dict[str, Any]:
    payload = {
        "name": name,
        "status": "passed" if passed else "failed",
        "message": message,
    }
    if errors:
        payload["errors"] = list(errors)
    if metadata:
        payload.update(metadata)
    return payload
