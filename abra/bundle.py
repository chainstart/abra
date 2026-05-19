"""ABRA result bundle construction and validation."""

from __future__ import annotations

import csv
import hashlib
import json
import re
import shutil
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from abra.manifest import repo_root


RESULT_BUNDLE_SCHEMA_VERSION = "abra.result_bundle.v1"
EVIDENCE_BUNDLE_SCHEMA_VERSION = "abra.evidence_bundle.v1"
ARTIFACT_MANIFEST_SCHEMA_VERSION = "abra.artifact_manifest.v1"
WRITING_BRIEF_SCHEMA_VERSION = "abra.writing_brief.v1"
BUILD_SCHEMA_VERSION = "abra.result_bundle.build.v1"
VALIDATION_SCHEMA_VERSION = "abra.result_bundle.validation.v1"
ARA_BUNDLE_MANIFEST_SCHEMA_VERSION = "ara.result_bundle.v1"
ARA_CLAIMS_SCHEMA_VERSION = "abra.ara_claims.v1"
ARA_DOMAIN = "blockchain_security"

EVIDENCE_LABELS = {
    "L0": "hypothesis",
    "L1": "static_alert",
    "L2": "source_confirmed",
    "L3": "local_reproduced",
    "L4": "fork_replayed",
    "L5": "externally_correlated",
    "L6": "audit_ready",
}
REQUIRED_BUNDLE_FILES = (
    "abra_result_bundle.json",
    "bundle_manifest.json",
    "claims.json",
    "evidence_bundle.json",
    "artifact_manifest.json",
    "drafting_brief.md",
    "writing_brief.md",
    "limitations.md",
)


@dataclass(frozen=True)
class BuildResult:
    """Result returned by the bundle builder."""

    payload: dict[str, Any]
    bundle: dict[str, Any]


def build_result_bundle(source: str | Path, out: str | Path) -> BuildResult:
    """Build an ARA-consumable ABRA result bundle from local artifacts."""

    source_path = Path(source).expanduser().resolve()
    out_path = Path(out).expanduser().resolve()
    if not source_path.exists() or not source_path.is_dir():
        raise FileNotFoundError(f"Bundle source directory not found: {source_path}")
    if _is_relative_to(out_path, source_path):
        raise ValueError("Bundle output must not be inside the source reports directory.")

    out_path.mkdir(parents=True, exist_ok=True)
    artifacts_dir = out_path / "artifacts"
    artifacts_dir.mkdir(parents=True, exist_ok=True)

    artifacts = _collect_artifacts(source_path)
    manifest_entries = [_copy_artifact(path, artifacts_dir, source_path) for path in artifacts]
    artifact_manifest = {
        "schema_version": ARTIFACT_MANIFEST_SCHEMA_VERSION,
        "generated_at": _utc_now(),
        "source_path": str(source_path),
        "artifacts": manifest_entries,
    }

    claims = _build_claims(manifest_entries)
    limitations = _build_limitations(manifest_entries, claims)
    writing_brief = _build_writing_brief(claims, limitations, manifest_entries)
    evidence_bundle = {
        "schema_version": EVIDENCE_BUNDLE_SCHEMA_VERSION,
        "bundle_type": "abra_result_bundle",
        "lab_id": "abra",
        "claims": claims,
        "limitations": limitations,
        "evidence_levels": EVIDENCE_LABELS,
    }
    bundle = {
        "schema_version": RESULT_BUNDLE_SCHEMA_VERSION,
        "bundle_type": "abra_result_bundle",
        "lab_id": "abra",
        "generated_at": artifact_manifest["generated_at"],
        "source_path": str(source_path),
        "summary": _bundle_summary(claims, manifest_entries),
        "evidence_levels": EVIDENCE_LABELS,
        "claims": claims,
        "artifact_manifest": artifact_manifest,
        "limitations": limitations,
        "writing_brief": writing_brief,
    }

    files_written = _write_bundle_files(out_path, bundle, evidence_bundle, artifact_manifest, limitations, writing_brief)
    validation = validate_result_bundle(out_path)
    payload = {
        "schema_version": BUILD_SCHEMA_VERSION,
        "status": "passed" if validation["status"] == "passed" else "failed",
        "bundle_type": "abra_result_bundle",
        "bundle_path": str(out_path),
        "source_path": str(source_path),
        "claim_count": len(claims),
        "artifact_count": len(manifest_entries),
        "evidence_levels": _evidence_level_counts(claims),
        "files_written": files_written,
        "validation": validation,
    }
    return BuildResult(payload=payload, bundle=bundle)


def validate_result_bundle(bundle_path: str | Path) -> dict[str, Any]:
    """Validate an ABRA result bundle directory."""

    root = Path(bundle_path).expanduser().resolve()
    errors: list[str] = []
    warnings: list[str] = []
    files_checked: list[str] = []
    if not root.exists() or not root.is_dir():
        return {
            "schema_version": VALIDATION_SCHEMA_VERSION,
            "status": "failed",
            "bundle_path": str(root),
            "errors": [f"Bundle directory not found: {root}"],
            "warnings": [],
            "files_checked": [],
        }

    for relative in REQUIRED_BUNDLE_FILES:
        path = root / relative
        if not path.exists():
            errors.append(f"Required bundle file is missing: {relative}")
        else:
            files_checked.append(relative)

    bundle = _load_json_file(root / "abra_result_bundle.json", errors)
    evidence_bundle = _load_json_file(root / "evidence_bundle.json", errors)
    artifact_manifest = _load_json_file(root / "artifact_manifest.json", errors)
    if not bundle or not evidence_bundle or not artifact_manifest:
        return _validation_payload(root, errors, warnings, files_checked, [], [])

    if bundle.get("schema_version") != RESULT_BUNDLE_SCHEMA_VERSION:
        errors.append("abra_result_bundle.json has an unsupported schema_version.")
    if evidence_bundle.get("schema_version") != EVIDENCE_BUNDLE_SCHEMA_VERSION:
        errors.append("evidence_bundle.json has an unsupported schema_version.")
    if artifact_manifest.get("schema_version") != ARTIFACT_MANIFEST_SCHEMA_VERSION:
        errors.append("artifact_manifest.json has an unsupported schema_version.")
    if bundle.get("bundle_type") != "abra_result_bundle":
        errors.append("abra_result_bundle.json must declare bundle_type `abra_result_bundle`.")

    claims = bundle.get("claims")
    artifacts = artifact_manifest.get("artifacts")
    if not isinstance(claims, list) or not claims:
        errors.append("Bundle must contain at least one claim.")
        claims = []
    if not isinstance(artifacts, list) or not artifacts:
        errors.append("Artifact manifest must contain at least one artifact.")
        artifacts = []

    artifact_ids = {str(artifact.get("artifact_id")) for artifact in artifacts if artifact.get("artifact_id")}
    _validate_artifacts(root, artifacts, errors, warnings, files_checked)
    _validate_claims(claims, artifact_ids, errors, warnings)

    if evidence_bundle.get("claims") != claims:
        errors.append("evidence_bundle.json claims must match abra_result_bundle.json claims.")
    bundle_manifest_ids = {
        str(artifact.get("artifact_id"))
        for artifact in bundle.get("artifact_manifest", {}).get("artifacts", [])
        if isinstance(artifact, dict)
    }
    if artifact_ids != bundle_manifest_ids:
        errors.append("Embedded artifact_manifest must match artifact_manifest.json artifact ids.")

    levels = _evidence_level_counts(claims)
    for required in ("L1", "L4", "L6"):
        if levels.get(required, 0) == 0:
            errors.append(f"Bundle must include at least one {required} claim.")

    return _validation_payload(root, errors, warnings, files_checked, claims, artifacts)


def _collect_artifacts(source_path: Path) -> list[Path]:
    roots = _candidate_context_roots(source_path)
    collected: dict[Path, Path] = {}

    report_root = source_path / "reports" if (source_path / "reports").is_dir() else source_path
    for pattern in ("*.md", "events/*.md", "replay_runs/**/*.log", "replay_runs/**/*.json", "replay_runs/**/*.csv"):
        for path in report_root.glob(pattern):
            if path.is_file():
                collected[path.resolve()] = path

    for root in roots:
        for relative in (
            "data/processed/scanner_findings_latest.json",
            "data/processed/replay_results.json",
            "data/processed/replay_results.csv",
            "data/processed/replay_blocker_matrix.csv",
            "findings/summary.md",
        ):
            path = root / relative
            if path.is_file():
                collected[path.resolve()] = path

    return sorted(collected.values(), key=lambda path: _stable_artifact_path(path, source_path))


def _candidate_context_roots(source_path: Path) -> list[Path]:
    root = repo_root().resolve()
    roots = [source_path, source_path.parent]
    if source_path.name == "reports":
        roots.insert(0, source_path.parent)
    if source_path.resolve() == root or source_path.parent.resolve() == root:
        roots.append(root)
    unique: list[Path] = []
    seen: set[Path] = set()
    for root in roots:
        resolved = root.resolve()
        if resolved not in seen:
            unique.append(resolved)
            seen.add(resolved)
    return unique


def _copy_artifact(path: Path, artifacts_dir: Path, source_path: Path) -> dict[str, Any]:
    relative = _stable_artifact_path(path, source_path)
    bundled_relative = Path("artifacts") / relative
    destination = artifacts_dir / relative
    destination.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(path, destination)
    digest = _sha256_file(destination)
    return {
        "artifact_id": _artifact_id(relative),
        "kind": _artifact_kind(relative),
        "role": _artifact_role(relative),
        "description": _artifact_description(relative),
        "original_path": str(path.resolve()),
        "source_path": relative.as_posix(),
        "path": bundled_relative.as_posix(),
        "bundle_path": bundled_relative.as_posix(),
        "sha256": digest,
        "size_bytes": destination.stat().st_size,
    }


def _stable_artifact_path(path: Path, source_path: Path) -> Path:
    root = repo_root()
    resolved = path.resolve()
    for base in (source_path.parent if source_path.name == "reports" else source_path, source_path.parent, root):
        base_resolved = base.resolve()
        if _is_relative_to(resolved, base_resolved):
            return resolved.relative_to(base_resolved)
    return Path(_slug(path.stem) + path.suffix)


def _artifact_id(relative: Path) -> str:
    normalized = re.sub(r"[^a-zA-Z0-9]+", "-", relative.as_posix()).strip("-").lower()
    digest = hashlib.sha256(relative.as_posix().encode("utf-8")).hexdigest()[:10]
    return f"artifact-{normalized}-{digest}"


def _artifact_kind(relative: Path) -> str:
    parts = set(relative.parts)
    name = relative.name
    suffix = relative.suffix.lower()
    if name == "scanner_findings_latest.json":
        return "scanner_results"
    if name in {"replay_results.json", "replay_results.csv"}:
        return "replay_results"
    if name == "replay_blocker_matrix.csv":
        return "replay_blocker_matrix"
    if "replay_runs" in parts and suffix == ".log":
        return "replay_log"
    if relative.parts[:2] == ("reports", "events") and suffix == ".md":
        return "incident_card"
    if name == "27_replay_verification_results.md":
        return "replay_report"
    if relative.parts[:1] == ("findings",) and suffix == ".md":
        return "findings_summary"
    if suffix == ".md":
        return "report_markdown"
    return "artifact"


def _artifact_role(relative: Path) -> str:
    kind = _artifact_kind(relative)
    if kind == "scanner_results":
        return "static_analysis_source"
    if kind == "replay_results":
        return "replay_evidence_source"
    if kind == "replay_blocker_matrix":
        return "replay_limitation_source"
    if kind == "replay_log":
        return "replay_log"
    if kind == "incident_card":
        return "incident_context"
    if kind == "replay_report":
        return "replay_interpretation"
    if kind == "findings_summary":
        return "manual_audit_summary"
    return "supporting_report"


def _artifact_description(relative: Path) -> str:
    kind = _artifact_kind(relative)
    if kind == "scanner_results":
        return "Static analysis source artifact; supports L1 static-alert claims only."
    if kind == "replay_results":
        return "Fork replay result table used to distinguish verified L4 replay from blocked replay attempts."
    if kind == "replay_blocker_matrix":
        return "Replay blocker matrix used to preserve replay limitations and missing preconditions."
    if kind == "replay_log":
        return "Fork replay log artifact for a bounded local replay result."
    if kind == "incident_card":
        return "Incident context card for claim background and citation."
    if kind == "replay_report":
        return "Human replay interpretation report; does not upgrade static alerts by itself."
    if kind == "findings_summary":
        return "Manual audit summary for source-level finding context."
    return "Supporting ABRA bundle artifact."


def _build_claims(artifacts: list[dict[str, Any]]) -> list[dict[str, Any]]:
    claims: list[dict[str, Any]] = []
    artifacts_by_kind = _artifacts_by_kind(artifacts)
    scanner_artifact = _first_artifact(artifacts_by_kind, "scanner_results")
    replay_artifact = _first_artifact(artifacts_by_kind, "replay_results", suffix=".json")

    if scanner_artifact:
        claims.extend(_static_claims(scanner_artifact))
    l1_count = len(claims)
    if replay_artifact:
        claims.extend(_replay_claims(replay_artifact, artifacts))
    if claims[l1_count:] and l1_count:
        claims.append(_audit_ready_claim(claims[:l1_count], claims[l1_count:], artifacts))
    return claims


def _static_claims(scanner_artifact: dict[str, Any]) -> list[dict[str, Any]]:
    data = _read_json_path(Path(scanner_artifact["original_path"]))
    findings = data.get("findings", []) if isinstance(data, dict) else data
    if not isinstance(findings, list):
        return []

    claims: list[dict[str, Any]] = []
    for index, finding in enumerate(findings, start=1):
        if not isinstance(finding, dict):
            continue
        severity = str(finding.get("severity") or "Unknown")
        title = str(finding.get("title") or "Untitled static alert").strip()
        analyzer = str(finding.get("analyzer") or "scanner").strip()
        source_file = _short_file_path(str(finding.get("file") or ""))
        line = finding.get("line")
        location = f"{source_file}:{line}" if source_file and line not in (None, "") else source_file
        claim_id = f"l1-static-{index:04d}-{_slug(analyzer)}"
        claim_text = f"{analyzer} reported a {severity} static alert"
        if title:
            claim_text += f": {title}"
        if location:
            claim_text += f" at {location}"
        claim_text += "."
        claims.append(
            {
                "claim_id": claim_id,
                "claim_type": "static_alert",
                "source_kind": "scanner_static_alert",
                "title": title,
                "claim": claim_text,
                "evidence_level": "L1",
                "evidence_label": EVIDENCE_LABELS["L1"],
                "subject": {
                    "kind": "contract_finding",
                    "protocol": _infer_protocol(source_file),
                    "file": source_file,
                    "line": line,
                    "severity": severity,
                    "analyzer": analyzer,
                    "category": finding.get("category"),
                },
                "supported_by": [scanner_artifact["artifact_id"]],
                "reproduction": {
                    "status": "not_attempted",
                    "commands": [],
                },
                "limitations": [
                    "Static analysis alone is not exploit reproduction.",
                    "This claim must not be written as a confirmed vulnerability without source review or replay evidence.",
                ],
            }
        )
    return claims


def _replay_claims(replay_artifact: dict[str, Any], artifacts: list[dict[str, Any]]) -> list[dict[str, Any]]:
    data = _read_json_path(Path(replay_artifact["original_path"]))
    rows = data.get("results", data) if isinstance(data, dict) else data
    if not isinstance(rows, list):
        return []

    log_by_path = {artifact["path"]: artifact for artifact in artifacts if artifact.get("kind") == "replay_log"}
    card_by_slug = _incident_cards_by_slug(artifacts)
    claims: list[dict[str, Any]] = []
    for row in rows:
        if not isinstance(row, dict):
            continue
        if row.get("verified") is not True and row.get("status") != "verified":
            continue
        slug = str(row.get("slug") or _slug(str(row.get("incident") or "replay")))
        incident = str(row.get("incident") or slug)
        supported_by = [replay_artifact["artifact_id"]]
        log_path = str(row.get("log_path") or "")
        if log_path in log_by_path:
            supported_by.append(log_by_path[log_path]["artifact_id"])
        if slug in card_by_slug:
            supported_by.append(card_by_slug[slug]["artifact_id"])
        fork_block = row.get("fork_block")
        block_text = f" at fork block {fork_block}" if fork_block not in (None, "") else ""
        claim = (
            f"{incident} has L4 fork replay evidence: replay test "
            f"`{row.get('replay_test')}` completed successfully on {row.get('chain')}{block_text}."
        )
        claims.append(
            {
                "claim_id": f"l4-replay-{_slug(slug)}",
                "claim_type": "fork_replay",
                "source_kind": "replay_result",
                "title": f"Verified fork replay for {incident}",
                "claim": claim,
                "evidence_level": "L4",
                "evidence_label": EVIDENCE_LABELS["L4"],
                "subject": {
                    "kind": "incident_replay",
                    "incident": incident,
                    "slug": slug,
                    "chain": row.get("chain"),
                    "attack_family": row.get("attack_family"),
                    "fork_block": fork_block,
                },
                "supported_by": supported_by,
                "reproduction": {
                    "status": "verified",
                    "commands": [row.get("command")] if row.get("command") else [],
                    "test_path": row.get("test_path"),
                    "replay_test": row.get("replay_test"),
                    "returncode": row.get("returncode"),
                    "duration_seconds": row.get("duration_seconds"),
                },
                "limitations": [
                    "L4 means the local fork replay test passed; it is not a blanket proof for adjacent exploit variants.",
                    "Negative controls and external transaction correlation are still required before making broader L6 exploit claims.",
                ],
            }
        )
    return claims


def _audit_ready_claim(
    static_claims: list[dict[str, Any]],
    replay_claims: list[dict[str, Any]],
    artifacts: list[dict[str, Any]],
) -> dict[str, Any]:
    support_kinds = {
        "scanner_results",
        "replay_results",
        "replay_report",
        "findings_summary",
        "replay_blocker_matrix",
    }
    supported_by = [
        artifact["artifact_id"]
        for artifact in artifacts
        if artifact.get("kind") in support_kinds
    ]
    if not supported_by:
        supported_by = sorted({claim["supported_by"][0] for claim in static_claims + replay_claims if claim.get("supported_by")})
    return {
        "claim_id": "l6-audit-ready-evidence-boundary",
        "claim_type": "audit_ready_synthesis",
        "source_kind": "bundle_synthesis",
        "title": "Audit-ready evidence boundary for ABRA writing",
        "claim": (
            "This ABRA bundle is audit-ready as an evidence-indexed writing brief: "
            "it separates L1 static alerts from L4 verified fork replay evidence and records replay blockers as limitations."
        ),
        "evidence_level": "L6",
        "evidence_label": EVIDENCE_LABELS["L6"],
        "subject": {
            "kind": "bundle_synthesis",
            "static_claim_count": len(static_claims),
            "verified_replay_claim_count": len(replay_claims),
        },
        "supported_by": supported_by,
        "reproduction": {
            "status": "synthesized_from_artifacts",
            "commands": [],
        },
        "synthesized_from": [static_claims[0]["claim_id"], replay_claims[0]["claim_id"]],
        "limitations": [
            "L6 applies to the bundle's writing boundary and evidence discipline, not to every underlying static finding.",
            "Individual static alerts remain L1 unless separately confirmed.",
            "Only replay rows with verified=true are L4 replay evidence.",
        ],
    }


def _build_limitations(artifacts: list[dict[str, Any]], claims: list[dict[str, Any]]) -> list[dict[str, Any]]:
    limitations: list[dict[str, Any]] = [
        {
            "limitation_id": "lim-static-alerts-not-replays",
            "scope": "static_analysis",
            "description": "L1 scanner claims are static alerts and must not be described as exploited or replayed.",
            "affected_claim_ids": [claim["claim_id"] for claim in claims if claim.get("evidence_level") == "L1"],
        },
        {
            "limitation_id": "lim-no-broadcast-or-private-keys",
            "scope": "safety",
            "description": "The bundle records local read-only artifacts only; it does not require private keys, broadcast transactions, or live trading.",
            "affected_claim_ids": [],
        },
    ]
    replay_artifact = _first_artifact(_artifacts_by_kind(artifacts), "replay_results", suffix=".json")
    if replay_artifact:
        rows = _read_json_path(Path(replay_artifact["original_path"]))
        rows = rows.get("results", rows) if isinstance(rows, dict) else rows
        if isinstance(rows, list):
            for row in rows:
                if not isinstance(row, dict):
                    continue
                if row.get("verified") is True or row.get("status") == "verified":
                    continue
                slug = str(row.get("slug") or _slug(str(row.get("incident") or "replay")))
                blocker = str(row.get("blocker") or row.get("status") or "not_verified")
                limitations.append(
                    {
                        "limitation_id": f"lim-replay-{_slug(slug)}",
                        "scope": "replay",
                        "description": (
                            f"{row.get('incident') or slug} is not L4 replay evidence in this bundle "
                            f"because replay status is `{row.get('status')}` with blocker `{blocker}`."
                        ),
                        "affected_claim_ids": [],
                    }
                )
    return limitations


def _build_writing_brief(
    claims: list[dict[str, Any]],
    limitations: list[dict[str, Any]],
    artifacts: list[dict[str, Any]],
) -> dict[str, Any]:
    by_level = _evidence_level_counts(claims)
    return {
        "schema_version": WRITING_BRIEF_SCHEMA_VERSION,
        "allowed_claim_ids": [claim["claim_id"] for claim in claims],
        "evidence_level_counts": by_level,
        "must_not_write": [
            "Do not describe L1 static alerts as exploited, reproduced, or fork-replayed.",
            "Do not treat replay blockers, missing tests, or RPC failures as proof that an exploit path is impossible.",
            "Do not claim L6 for individual vulnerabilities unless root cause, impact, reproduction, limitations, and mitigation are all present.",
        ],
        "citation_guidance": [
            {
                "artifact_id": artifact["artifact_id"],
                "path": artifact["path"],
                "role": artifact["role"],
            }
            for artifact in artifacts
            if artifact["kind"] in {"scanner_results", "replay_results", "replay_report", "findings_summary", "incident_card"}
        ],
        "limitation_ids": [limitation["limitation_id"] for limitation in limitations],
    }


def _write_bundle_files(
    out_path: Path,
    bundle: dict[str, Any],
    evidence_bundle: dict[str, Any],
    artifact_manifest: dict[str, Any],
    limitations: list[dict[str, Any]],
    writing_brief: dict[str, Any],
) -> list[str]:
    generated_at = str(bundle["generated_at"])
    files = {
        "abra_result_bundle.json": bundle,
        "bundle_manifest.json": ara_bundle_manifest(
            generated_at=generated_at,
            source_path=str(bundle["source_path"]),
            source_bundle_type="abra_result_bundle",
            claim_count=len(bundle["claims"]),
            artifact_count=len(artifact_manifest["artifacts"]),
        ),
        "claims.json": ara_claims_payload(bundle["claims"], generated_at, "abra_result_bundle"),
        "evidence_bundle.json": evidence_bundle,
        "artifact_manifest.json": artifact_manifest,
    }
    for name, payload in files.items():
        (out_path / name).write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    (out_path / "limitations.md").write_text(_render_limitations(limitations), encoding="utf-8")
    drafting_brief = _render_writing_brief(writing_brief, bundle["claims"])
    (out_path / "drafting_brief.md").write_text(drafting_brief, encoding="utf-8")
    (out_path / "writing_brief.md").write_text(drafting_brief, encoding="utf-8")
    (out_path / "final_report.md").write_text(_render_final_report(bundle), encoding="utf-8")
    return [*files.keys(), "limitations.md", "drafting_brief.md", "writing_brief.md", "final_report.md"]


def ara_bundle_manifest(
    *,
    generated_at: str,
    source_path: str,
    source_bundle_type: str,
    claim_count: int,
    artifact_count: int,
) -> dict[str, Any]:
    return {
        "schema_version": ARA_BUNDLE_MANIFEST_SCHEMA_VERSION,
        "bundle_type": "abra_result_bundle",
        "domain": ARA_DOMAIN,
        "created_at": generated_at,
        "producer": "abra",
        "source_bundle_type": source_bundle_type,
        "source_path": source_path,
        "claim_count": claim_count,
        "artifact_count": artifact_count,
        "safety": {
            "broadcasts_transactions": False,
            "requires_private_keys": False,
            "live_trading": False,
        },
    }


def ara_claims_payload(claims: list[dict[str, Any]], generated_at: str, source_bundle_type: str) -> dict[str, Any]:
    return {
        "schema_version": ARA_CLAIMS_SCHEMA_VERSION,
        "producer": "abra",
        "generated_at": generated_at,
        "source_bundle_type": source_bundle_type,
        "claims": [_ara_claim(claim) for claim in claims],
    }


def _ara_claim(claim: dict[str, Any]) -> dict[str, Any]:
    reproduction = claim.get("reproduction") if isinstance(claim.get("reproduction"), dict) else {}
    level = str(claim.get("evidence_level") or "")
    status = "supported" if level in {"L4", "L6"} and reproduction.get("status") in {"verified", "synthesized_from_artifacts"} else "blocked"
    return {
        "claim_id": str(claim.get("claim_id") or ""),
        "claim": str(claim.get("claim") or ""),
        "status": status,
        "evidence_level": level,
        "source_kind": claim.get("source_kind"),
        "claim_type": claim.get("claim_type"),
        "reproduction_status": str(reproduction.get("status") or ""),
        "supported_by": [str(item) for item in claim.get("supported_by", []) if isinstance(item, str)],
        "limitations": [str(item) for item in claim.get("limitations", []) if isinstance(item, str)],
    }


def _render_writing_brief(writing_brief: dict[str, Any], claims: list[dict[str, Any]]) -> str:
    lines = [
        "# ABRA Writing Brief",
        "",
        "## Evidence Level Counts",
        "",
    ]
    for level in ("L1", "L4", "L6"):
        lines.append(f"- {level} {EVIDENCE_LABELS[level]}: {writing_brief['evidence_level_counts'].get(level, 0)}")
    lines.extend(["", "## Supported Claims", ""])
    for claim in claims:
        lines.append(f"- `{claim['claim_id']}` ({claim['evidence_level']} {claim['evidence_label']}): {claim['claim']}")
    lines.extend(["", "## Must Not Write", ""])
    for item in writing_brief["must_not_write"]:
        lines.append(f"- {item}")
    lines.extend(["", "## Citation Guidance", ""])
    for item in writing_brief["citation_guidance"]:
        lines.append(f"- `{item['artifact_id']}` -> `{item['path']}` ({item['role']})")
    return "\n".join(lines) + "\n"


def _render_limitations(limitations: list[dict[str, Any]]) -> str:
    lines = ["# ABRA Bundle Limitations", ""]
    for limitation in limitations:
        lines.append(f"- `{limitation['limitation_id']}` ({limitation['scope']}): {limitation['description']}")
    return "\n".join(lines) + "\n"


def _render_final_report(bundle: dict[str, Any]) -> str:
    summary = bundle["summary"]
    return (
        "# ABRA Result Bundle Summary\n\n"
        f"- Bundle type: `{bundle['bundle_type']}`\n"
        f"- Claims: {summary['claim_count']}\n"
        f"- Artifacts: {summary['artifact_count']}\n"
        f"- Evidence levels: {summary['evidence_level_counts']}\n\n"
        "Use `writing_brief.md` for claim-level writing guidance and `artifact_manifest.json` for citations.\n"
    )


def _bundle_summary(claims: list[dict[str, Any]], artifacts: list[dict[str, Any]]) -> dict[str, Any]:
    return {
        "claim_count": len(claims),
        "artifact_count": len(artifacts),
        "evidence_level_counts": _evidence_level_counts(claims),
        "artifact_kinds": _artifact_kind_counts(artifacts),
    }


def _validate_artifacts(
    root: Path,
    artifacts: list[Any],
    errors: list[str],
    warnings: list[str],
    files_checked: list[str],
) -> None:
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
        bundle_path = root / str(artifact.get("bundle_path") or "")
        if bundle_path.exists() and bundle_path.is_file():
            files_checked.append(str(artifact.get("bundle_path")))
            digest = _sha256_file(bundle_path)
            if artifact.get("sha256") and digest != artifact.get("sha256"):
                errors.append(f"Artifact digest mismatch for {artifact_id}.")
        else:
            warnings.append(f"Bundled artifact file is missing: {artifact.get('bundle_path')}")


def _validate_claims(
    claims: list[Any],
    artifact_ids: set[str],
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
        level = claim.get("evidence_level")
        if level not in EVIDENCE_LABELS:
            errors.append(f"Claim {claim_id or index} has invalid evidence_level: {level}")
        if claim.get("evidence_label") != EVIDENCE_LABELS.get(str(level)):
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
        if level == "L1" and claim.get("source_kind") != "scanner_static_alert":
            errors.append(f"L1 claim {claim_id or index} must come from scanner_static_alert.")
        if level == "L1" and reproduction.get("status") == "verified":
            errors.append(f"L1 claim {claim_id or index} must not use verified replay reproduction status.")
        if level == "L4":
            if claim.get("source_kind") != "replay_result":
                errors.append(f"L4 claim {claim_id or index} must come from replay_result.")
            if reproduction.get("status") != "verified":
                errors.append(f"L4 claim {claim_id or index} must have reproduction.status `verified`.")
        if level == "L6":
            if claim.get("source_kind") != "bundle_synthesis":
                errors.append(f"L6 claim {claim_id or index} must be bundle_synthesis in this exporter.")
            if not claim.get("limitations"):
                warnings.append(f"L6 claim {claim_id or index} should carry explicit limitations.")


def _validation_payload(
    root: Path,
    errors: list[str],
    warnings: list[str],
    files_checked: list[str],
    claims: list[Any],
    artifacts: list[Any],
) -> dict[str, Any]:
    return {
        "schema_version": VALIDATION_SCHEMA_VERSION,
        "status": "passed" if not errors else "failed",
        "bundle_type": "abra_result_bundle",
        "bundle_path": str(root),
        "claim_count": len(claims),
        "artifact_count": len(artifacts),
        "evidence_levels": _evidence_level_counts([claim for claim in claims if isinstance(claim, dict)]),
        "errors": errors,
        "warnings": warnings,
        "files_checked": sorted(set(files_checked)),
    }


def _load_json_file(path: Path, errors: list[str]) -> dict[str, Any] | None:
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


def _read_json_path(path: Path) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}


def _artifacts_by_kind(artifacts: list[dict[str, Any]]) -> dict[str, list[dict[str, Any]]]:
    result: dict[str, list[dict[str, Any]]] = {}
    for artifact in artifacts:
        result.setdefault(str(artifact.get("kind")), []).append(artifact)
    return result


def _first_artifact(
    artifacts_by_kind: dict[str, list[dict[str, Any]]],
    kind: str,
    *,
    suffix: str | None = None,
) -> dict[str, Any] | None:
    for artifact in artifacts_by_kind.get(kind, []):
        if suffix is None or str(artifact.get("path", "")).endswith(suffix):
            return artifact
    return None


def _incident_cards_by_slug(artifacts: list[dict[str, Any]]) -> dict[str, dict[str, Any]]:
    cards: dict[str, dict[str, Any]] = {}
    for artifact in artifacts:
        if artifact.get("kind") != "incident_card":
            continue
        name = Path(str(artifact.get("path") or "")).stem
        parts = name.split("_")
        if len(parts) >= 2:
            cards[parts[1]] = artifact
    return cards


def _evidence_level_counts(claims: list[dict[str, Any]]) -> dict[str, int]:
    counts: dict[str, int] = {}
    for claim in claims:
        level = str(claim.get("evidence_level") or "unknown")
        counts[level] = counts.get(level, 0) + 1
    return counts


def _artifact_kind_counts(artifacts: list[dict[str, Any]]) -> dict[str, int]:
    counts: dict[str, int] = {}
    for artifact in artifacts:
        kind = str(artifact.get("kind") or "artifact")
        counts[kind] = counts.get(kind, 0) + 1
    return counts


def _short_file_path(value: str) -> str:
    if not value:
        return ""
    path = Path(value)
    root = repo_root()
    try:
        return path.resolve().relative_to(root).as_posix()
    except (OSError, ValueError):
        return value


def _infer_protocol(source_file: str) -> str:
    parts = Path(source_file).parts
    if "contracts" in parts:
        index = parts.index("contracts")
        if index + 1 < len(parts):
            return parts[index + 1].replace("_", " ").title()
    return ""


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _slug(value: str) -> str:
    slug = re.sub(r"[^a-zA-Z0-9]+", "-", value.strip().lower()).strip("-")
    return slug or "item"


def _utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def _is_relative_to(path: Path, base: Path) -> bool:
    try:
        path.relative_to(base)
        return True
    except ValueError:
        return False


def read_csv(path: Path) -> list[dict[str, str]]:
    """Read a CSV file as dictionaries. Kept for future replay bundle extensions."""

    with path.open(newline="", encoding="utf-8") as handle:
        return list(csv.DictReader(handle))
