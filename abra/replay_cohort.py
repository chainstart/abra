"""Build replay-oriented incident cohorts from ABRA incident data."""

from __future__ import annotations

import csv
import hashlib
import json
import re
import shutil
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from typing import Callable

from abra.chain_support import (
    EVM_CHAIN_IDS,
    chain_id as _shared_chain_id,
    chain_rpc_supported as _shared_chain_rpc_supported,
    infer_chain as _shared_infer_chain,
    load_local_environment,
    normalize_chain as _shared_normalize_chain,
    rpc_capability_state as _shared_rpc_capability_state,
    rpc_env_for_chain as _shared_rpc_env_for_chain,
)
from abra.evidence_sources import (
    candidate_discovery_sources as _shared_candidate_discovery_sources,
    is_security_reference_url as _shared_is_security_reference_url,
    marker_matches_host as _shared_marker_matches_host,
    security_report_sources as _shared_security_report_sources,
    url_host as _shared_url_host,
)
from abra.evidence_pipeline import (
    ALCHEMY_BACKFILL_CSV,
    ANCHORED_INCIDENTS_CSV,
    SECURITY_EVIDENCE_CSV,
    produce_evidence_pipeline,
)
from abra.manifest import repo_root


COHORT_SCHEMA_VERSION = "abra.replay_cohort.v1"
MANIFEST_SCHEMA_VERSION = "abra.replay_cohort.manifest.v1"
EXCLUSION_LOG_SCHEMA_VERSION = "abra.replay_cohort.exclusion_log.v1"
STAGE_LEDGER_SCHEMA_VERSION = "abra.replay_cohort.stage_ledger.v1"

STAGE_ORDER = [
    "candidate_discovery",
    "security_evidence_enrichment",
    "alchemy_onchain_backfill",
    "replay_cohort_selection",
]

TECHNICAL_FAMILY_WEIGHTS = {
    "oracle_manipulation": 9,
    "flash_loan": 9,
    "reentrancy": 9,
    "logic_bug": 7,
    "contract_bug": 7,
    "access_control": 7,
    "bridge_message": 6,
    "governance": 6,
    "other": 1,
}

OPERATIONAL_FAMILIES = {
    "account_compromise",
    "social_engineering",
    "supply_chain",
}

DEFAULT_ANCHORED_INCIDENTS_PATH = f"data/processed/{ANCHORED_INCIDENTS_CSV}"
DEFAULT_NORMALIZED_INCIDENTS_PATH = "data/processed/incidents_normalized_latest.csv"

def build_replay_cohort(
    *,
    incidents_csv: str | Path = DEFAULT_ANCHORED_INCIDENTS_PATH,
    selected_incidents_csv: str | Path | None = None,
    replay_results_csv: str | Path = "data/processed/replay_results.csv",
    event_cards_dir: str | Path = "reports/events",
    out: str | Path = "runs/abra_sufficiency/cohort",
    min_cases: int = 10,
    max_cases: int = 20,
    evm_only: bool = True,
    refresh: bool = False,
    refresh_start_page: int = 1,
    refresh_end_page: int = 8,
    refresh_top_protocols: int = 400,
    require_seed_transaction_hash: bool = True,
    require_replay_block: bool = True,
    include_evidence_candidates: bool = True,
    rpc_provider: str = "alchemy",
    rpc_supported_chains: list[str] | None = None,
    source_fetcher: Callable[[str], dict[str, str]] | None = None,
    anchor_searcher: Callable[[dict[str, str]], list[dict[str, str]]] | None = None,
    rpc_caller: Callable[[str, str, list[str]], dict[str, Any]] | None = None,
) -> dict[str, Any]:
    """Materialize a bounded replay cohort and explicit exclusion log.

    The default mode is intentionally strict: cases without a seed transaction
    hash or replay/fork block are excluded so quality gaps surface instead of
    being hidden behind fixture-backed replay assessment.
    """

    root = repo_root()
    load_local_environment(root)
    if min_cases < 1:
        raise ValueError("min_cases must be positive.")
    if max_cases < min_cases:
        raise ValueError("max_cases must be greater than or equal to min_cases.")

    if refresh:
        _run_phase1_refresh(root, refresh_start_page, refresh_end_page, refresh_top_protocols)

    incidents_path = _resolve_incidents_source_path(
        root,
        incidents_csv,
        rpc_provider=rpc_provider,
        rpc_supported_chains=rpc_supported_chains,
        source_fetcher=source_fetcher,
        anchor_searcher=anchor_searcher,
        rpc_caller=rpc_caller,
    )
    produce_evidence_pipeline(
        incidents_csv=incidents_path,
        out_dir=incidents_path.parent,
        rpc_provider=rpc_provider,
        rpc_supported_chains=rpc_supported_chains,
        source_fetcher=source_fetcher,
        anchor_searcher=anchor_searcher,
        rpc_caller=rpc_caller,
    )
    security_evidence_path = incidents_path.parent / SECURITY_EVIDENCE_CSV
    alchemy_backfill_path = incidents_path.parent / ALCHEMY_BACKFILL_CSV
    selected_path = _resolve_optional_repo_path(root, selected_incidents_csv)
    replay_path = _resolve_repo_path(root, replay_results_csv)
    cards_dir = _resolve_repo_path(root, event_cards_dir)
    out_path = _resolve_repo_path(root, out)

    incidents = _read_csv(incidents_path)
    security_stage_by_id = _stage_rows_by_incident_id(security_evidence_path)
    alchemy_stage_by_id = _stage_rows_by_incident_id(alchemy_backfill_path)
    selected_ids = _selected_incident_ids(selected_path)
    replay_by_slug = _replay_metadata_by_slug(replay_path)
    cards_by_slug = _event_cards_by_slug(cards_dir)
    rpc_state = _rpc_capability_state(provider=rpc_provider, explicit_chains=rpc_supported_chains)
    rpc_chains = rpc_state["supported_chains"]

    generated_at = _utc_now()
    all_cases: list[dict[str, Any]] = []
    candidates: list[dict[str, Any]] = []
    exclusions: list[dict[str, Any]] = []
    exclusion_reasons: dict[str, str] = {}

    for row in incidents:
        incident_id = row.get("incident_id") or _sha1([row.get("target") or row.get("incident") or "", row.get("event_date", "")])
        normalized = _normalize_incident(
            row,
            replay_by_slug,
            cards_by_slug,
            selected_ids,
            rpc_chains,
            security_stage=security_stage_by_id.get(incident_id, {}),
            alchemy_stage=alchemy_stage_by_id.get(incident_id, {}),
        )
        all_cases.append(normalized)
        reason = _exclusion_reason(
            normalized,
            evm_only=evm_only,
            require_seed_transaction_hash=require_seed_transaction_hash,
            require_replay_block=require_replay_block,
            include_evidence_candidates=include_evidence_candidates,
        )
        if reason:
            exclusions.append(_exclusion_entry(normalized, reason))
            exclusion_reasons[normalized["incident_id"]] = reason
            continue
        candidates.append(normalized)

    candidates.sort(key=_candidate_score, reverse=True)
    selected = candidates[:max_cases]
    selected_ids_for_stage = {case["incident_id"] for case in selected}
    errors: list[str] = []
    if rpc_state["missing_configuration_error"]:
        errors.append(rpc_state["missing_configuration_error"])
    if len(selected) < min_cases:
        errors.append("insufficient_eligible_cases")
    errors.extend(
        _selected_strict_requirement_errors(
            selected,
            require_seed_transaction_hash=require_seed_transaction_hash,
            require_replay_block=require_replay_block,
        )
    )

    _reset_out_dir(out_path)
    cases_dir = out_path / "cases"
    cases_dir.mkdir(parents=True, exist_ok=True)

    manifest_cases: list[dict[str, Any]] = []
    for case in selected:
        case_payload = _case_payload(case, generated_at)
        case_file = cases_dir / f"{case_payload['slug']}.json"
        _write_json(case_file, case_payload)
        case_payload["case_file"] = str(case_file.relative_to(out_path))
        manifest_cases.append(case_payload)

    manifest = {
        "schema_version": MANIFEST_SCHEMA_VERSION,
        "cohort_id": _cohort_id(generated_at, selected),
        "generated_at": generated_at,
        "stage_order": list(STAGE_ORDER),
        "source_incidents_csv": str(incidents_path),
        "security_evidence_csv": str(security_evidence_path),
        "alchemy_backfill_csv": str(alchemy_backfill_path),
        "selected_incidents_csv": str(selected_path) if selected_path else None,
        "replay_results_csv": str(replay_path) if replay_path.exists() else None,
        "event_cards_dir": str(cards_dir) if cards_dir.exists() else None,
        "min_cases": min_cases,
        "max_cases": max_cases,
        "evm_only": evm_only,
        "rpc_provider": rpc_provider,
        "rpc_supported_chains": sorted(rpc_chains),
        "rpc_capability": {
            "provider": rpc_state["provider"],
            "configured": rpc_state["configured"],
            "configuration_sources": rpc_state["configuration_sources"],
            "supported_chains": sorted(rpc_chains),
        },
        "strict_requirements": {
            "seed_transaction_hash": require_seed_transaction_hash,
            "replay_block": require_replay_block,
        },
        "case_count": len(manifest_cases),
        "cases": manifest_cases,
        "quality": {
            "candidate_count": len(candidates),
            "eligible_before_case_count": len(candidates),
            "selected_count": len(manifest_cases),
            "excluded_count": len(exclusions),
            "selected_replay_metadata_count": 0,
            "selected_fixture_metadata_attached_count": sum(1 for case in selected if case["fixture_metadata_attached"]),
            "selected_security_report_count": sum(1 for case in selected if case["security_report_sources"]),
            "selected_rpc_supported_count": sum(1 for case in selected if case["rpc_supported"]),
            "missing_seed_transaction_hash_count": sum(
                1 for case in selected if not case["seed_transaction_hash"]
            ),
            "missing_replay_block_count": sum(1 for case in selected if not case["fork_block"]),
            "meets_case_count_requirement": min_cases <= len(manifest_cases) <= max_cases,
        },
        "stage_ledger": "stage_ledger.json",
    }
    exclusion_log = {
        "schema_version": EXCLUSION_LOG_SCHEMA_VERSION,
        "generated_at": generated_at,
        "source_incidents_csv": str(incidents_path),
        "entries": sorted(exclusions, key=lambda entry: (entry["reason"], entry["slug"])),
        "summary": _exclusion_summary(exclusions),
    }
    stage_ledger = _stage_ledger_payload(
        generated_at=generated_at,
        cases=all_cases,
        selected_ids=selected_ids_for_stage,
        exclusion_reasons=exclusion_reasons,
        source_stage_artifacts={
            "security_evidence_csv": str(security_evidence_path),
            "alchemy_backfill_csv": str(alchemy_backfill_path),
        },
    )

    _write_json(out_path / "manifest.json", manifest)
    _write_json(out_path / "exclusion_log.json", exclusion_log)
    _write_json(out_path / "stage_ledger.json", stage_ledger)

    warnings = _cohort_warnings(selected, rpc_state)
    payload = {
        "schema_version": COHORT_SCHEMA_VERSION,
        "status": "passed" if not errors else "failed",
        "cohort_id": manifest["cohort_id"],
        "case_count": len(manifest_cases),
        "min_cases": min_cases,
        "max_cases": max_cases,
        "evm_only": evm_only,
        "quality": manifest["quality"],
        "errors": errors,
        "warnings": warnings,
        "artifacts": {
            "manifest": "manifest.json",
            "exclusion_log": "exclusion_log.json",
            "cases_dir": "cases",
            "stage_ledger": "stage_ledger.json",
        },
        "out": str(out_path),
    }
    return payload


def _run_phase1_refresh(root: Path, start_page: int, end_page: int, top_protocols: int) -> None:
    cmd = [
        sys.executable,
        "tools/pipeline/run_phase1.py",
        "--start-page",
        str(start_page),
        "--end-page",
        str(end_page),
        "--top-protocols",
        str(top_protocols),
    ]
    subprocess.run(cmd, cwd=str(root), check=True)


def _resolve_incidents_source_path(
    root: Path,
    incidents_csv: str | Path,
    *,
    rpc_provider: str,
    rpc_supported_chains: list[str] | None,
    source_fetcher: Callable[[str], dict[str, str]] | None,
    anchor_searcher: Callable[[dict[str, str]], list[dict[str, str]]] | None,
    rpc_caller: Callable[[str, str, list[str]], dict[str, Any]] | None,
) -> Path:
    incidents_path = _resolve_repo_path(root, incidents_csv)
    if incidents_path.exists():
        return incidents_path
    if not _uses_default_anchored_incidents_path(incidents_csv):
        raise FileNotFoundError(f"Incident CSV not found: {incidents_path}")

    normalized_path = _resolve_repo_path(root, DEFAULT_NORMALIZED_INCIDENTS_PATH)
    if not normalized_path.exists():
        raise FileNotFoundError(f"Incident CSV not found: {incidents_path}")

    produce_evidence_pipeline(
        incidents_csv=normalized_path,
        out_dir=normalized_path.parent,
        rpc_provider=rpc_provider,
        rpc_supported_chains=rpc_supported_chains,
        source_fetcher=source_fetcher,
        anchor_searcher=anchor_searcher,
        rpc_caller=rpc_caller,
    )
    if incidents_path.exists():
        return incidents_path
    raise FileNotFoundError(f"Incident CSV not found: {incidents_path}")


def _uses_default_anchored_incidents_path(value: str | Path) -> bool:
    return Path(value) == Path(DEFAULT_ANCHORED_INCIDENTS_PATH)


def _resolve_repo_path(root: Path, value: str | Path) -> Path:
    path = Path(value).expanduser()
    if path.is_absolute():
        return path
    return root / path


def _resolve_optional_repo_path(root: Path, value: str | Path | None) -> Path | None:
    if value in (None, ""):
        return None
    path = _resolve_repo_path(root, value)
    return path if path.exists() else None


def _read_csv(path: Path) -> list[dict[str, str]]:
    if not path.exists():
        raise FileNotFoundError(f"Incident CSV not found: {path}")
    with path.open("r", encoding="utf-8", newline="") as fp:
        return list(csv.DictReader(fp))


def _stage_rows_by_incident_id(path: Path) -> dict[str, dict[str, str]]:
    if not path.exists():
        return {}
    return {row.get("incident_id", ""): row for row in _read_csv(path) if row.get("incident_id")}


def _selected_incident_ids(path: Path | None) -> set[str]:
    if not path:
        return set()
    return {row.get("incident_id", "") for row in _read_csv(path) if row.get("incident_id")}


def _replay_metadata_by_slug(path: Path) -> dict[str, dict[str, str]]:
    if not path.exists():
        return {}
    rows = _read_csv(path)
    return {_slug(row.get("slug") or row.get("incident") or ""): row for row in rows}


def _event_cards_by_slug(cards_dir: Path) -> dict[str, Path]:
    if not cards_dir.exists():
        return {}
    cards: dict[str, Path] = {}
    for path in cards_dir.glob("*.md"):
        if path.name.upper() == "INDEX.md":
            continue
        slug = _slug(path.stem)
        parts = path.stem.split("_")
        if len(parts) >= 2:
            slug = _slug(parts[1])
        cards[slug] = path
    return cards


def _event_card_metadata(path: Path | None) -> dict[str, str]:
    if not path or not path.exists():
        return {}
    text = path.read_text(encoding="utf-8", errors="replace")
    metadata: dict[str, str] = {}
    patterns = {
        "incident_id": r"Incident ID:\s*`?([^`\n]+)`?",
        "event_date": r"Date:\s*`?([^`\n]+)`?",
        "attack_family": r"Attack Family:\s*`?([^`\n]+)`?",
        "attack_method_raw": r"Attack Method \(raw\):\s*`?([^`\n]+)`?",
        "loss_usd": r"Estimated Loss:\s*`\$?([^`\n]+)`?",
        "reference_url": r"Reference URL:\s*(\S+)",
        "fork_block": r"Fork Block Number:\s*`?([0-9,]+)`?",
        "repro_command": r"Repro command:\s*`([^`]+)`",
        "poc_status": r"PoC status:\s*`([^`]+)`",
    }
    for key, pattern in patterns.items():
        match = re.search(pattern, text, flags=re.IGNORECASE)
        if match:
            metadata[key] = match.group(1).strip()
    tx_match = re.search(r"0x[a-fA-F0-9]{64}", text)
    if tx_match:
        metadata["seed_transaction_hash"] = tx_match.group(0)
    return metadata


def _normalize_incident(
    row: dict[str, str],
    replay_by_slug: dict[str, dict[str, str]],
    cards_by_slug: dict[str, Path],
    selected_ids: set[str],
    rpc_supported_chains: set[str],
    security_stage: dict[str, str] | None = None,
    alchemy_stage: dict[str, str] | None = None,
) -> dict[str, Any]:
    security_stage = security_stage or {}
    alchemy_stage = alchemy_stage or {}
    incident = (row.get("target") or row.get("incident") or "").strip()
    slug = _slug(row.get("slug") or incident or row.get("incident_id") or "incident")
    replay = replay_by_slug.get(slug, {})
    event_card = cards_by_slug.get(slug)
    card = _event_card_metadata(event_card)
    inferred_chain = _normalize_chain(security_stage.get("chain") or _infer_chain(row, replay))
    chain_id = _parse_int(security_stage.get("chain_id")) if security_stage.get("chain_id") else _chain_id(inferred_chain)
    seed_hash = (
        alchemy_stage.get("seed_transaction_hash")
        or security_stage.get("seed_transaction_hash")
        or _extract_seed_transaction_hash(row, replay, card)
    )
    fork_block = _parse_int(
        alchemy_stage.get("fork_block")
        or security_stage.get("fork_block")
        or replay.get("fork_block")
        or card.get("fork_block")
        or row.get("fork_block")
        or row.get("replay_block")
    )
    reference = (security_stage.get("reference_url") or row.get("reference_url") or card.get("reference_url") or "").strip()
    security_sources = _parse_json_list_cell(security_stage.get("security_report_sources")) or _security_report_sources(row, card)
    security_anchor = bool(security_sources)
    candidate_sources = _parse_json_list_cell(security_stage.get("candidate_discovery_sources")) or _candidate_discovery_sources(row)
    rpc_env = alchemy_stage.get("rpc_env") or _rpc_env_for_chain(inferred_chain, replay)
    rpc_supported = _parse_bool(alchemy_stage.get("rpc_supported")) if "rpc_supported" in alchemy_stage else _chain_rpc_supported(inferred_chain, rpc_supported_chains)
    fixture_metadata_attached = bool(replay or event_card)
    missing: list[str] = []
    if not security_anchor:
        missing.append("missing_security_anchor")
    if not seed_hash:
        missing.append("missing_seed_transaction_hash")
    if not fork_block:
        missing.append("missing_replay_block")
    if not reference:
        missing.append("missing_provenance_url")
    if not inferred_chain:
        missing.append("missing_chain")
    if chain_id is None and inferred_chain not in {"multi_evm", ""}:
        missing.append("missing_chain_id")

    return {
        "incident_id": row.get("incident_id") or _sha1([incident, row.get("event_date", "")]),
        "incident": incident,
        "slug": slug,
        "event_date": row.get("event_date") or "",
        "is_defi": (row.get("is_defi") or "").lower() == "true",
        "chain": inferred_chain,
        "chain_id": chain_id,
        "attack_family": row.get("attack_family") or replay.get("attack_family") or card.get("attack_family") or "other",
        "attack_method_raw": row.get("attack_method_raw") or card.get("attack_method_raw") or "",
        "loss_usd": _parse_float(row.get("loss_usd") or replay.get("loss_usd") or card.get("loss_usd")),
        "seed_transaction_hash": seed_hash,
        "fork_block": fork_block,
        "provenance_url": reference,
        "source_url": row.get("source_url") or "",
        "fixture_source": str(event_card) if event_card else "",
        "event_card": str(event_card) if event_card else "",
        "candidate_discovery_sources": candidate_sources,
        "security_report_sources": security_sources,
        "security_anchor": security_anchor,
        "rpc_env": rpc_env,
        "rpc_supported": rpc_supported,
        "alchemy_backfill_status": alchemy_stage.get("backfill_status") or "",
        "replay_test": replay.get("replay_test") or "",
        "metadata_test": replay.get("metadata_test") or "",
        "test_path": replay.get("test_path") or "",
        "replay_status": replay.get("status") or "",
        "replay_blocker": replay.get("blocker") or "",
        "verified": _parse_bool(replay.get("verified")),
        "fixture_result": _fixture_result_from_replay(replay),
        "fixture_metadata_attached": fixture_metadata_attached,
        "stage_source_artifacts": {
            "security_evidence": bool(security_stage),
            "alchemy_onchain_backfill": bool(alchemy_stage),
        },
        "selected_source": "selected_incidents_csv" if row.get("incident_id") in selected_ids else "candidate_discovery",
        "description": row.get("description") or "",
        "missing_fields": missing,
        "raw": row,
    }


def _infer_chain(row: dict[str, str], replay: dict[str, str]) -> str:
    return _shared_infer_chain(row, replay)


def _normalize_chain(chain: str) -> str:
    return _shared_normalize_chain(chain)


def _chain_id(chain: str) -> int | None:
    return _shared_chain_id(chain)


def _rpc_env_for_chain(chain: str, replay: dict[str, str] | None = None) -> str:
    return _shared_rpc_env_for_chain(chain, replay)


def _rpc_capability_state(*, provider: str, explicit_chains: list[str] | None) -> dict[str, Any]:
    return _shared_rpc_capability_state(provider=provider, explicit_chains=explicit_chains)


def _chain_rpc_supported(chain: str, rpc_supported_chains: set[str]) -> bool:
    return _shared_chain_rpc_supported(chain, rpc_supported_chains)


def _security_report_sources(row: dict[str, str], card: dict[str, str]) -> list[dict[str, str]]:
    return _shared_security_report_sources(row, card)


def _candidate_discovery_sources(row: dict[str, str]) -> list[dict[str, str]]:
    return _shared_candidate_discovery_sources(row)


def _parse_json_list_cell(value: str | None) -> list[dict[str, str]]:
    if not value:
        return []
    try:
        parsed = json.loads(value)
    except json.JSONDecodeError:
        return []
    if not isinstance(parsed, list):
        return []
    rows: list[dict[str, str]] = []
    for item in parsed:
        if isinstance(item, dict):
            rows.append({str(key): str(val) for key, val in item.items()})
    return rows


def _is_security_reference_url(url: str) -> bool:
    return _shared_is_security_reference_url(url)


def _url_host(url: str) -> str:
    return _shared_url_host(url)


def _marker_matches_host(marker: str, host: str) -> bool:
    return _shared_marker_matches_host(marker, host)


def _extract_seed_transaction_hash(
    row: dict[str, str],
    replay: dict[str, str],
    card: dict[str, str] | None = None,
) -> str | None:
    card = card or {}
    for key in ("seed_transaction_hash", "transaction_hash", "tx_hash", "attack_tx", "tx"):
        value = (row.get(key) or replay.get(key) or card.get(key) or "").strip()
        if _is_tx_hash(value):
            return value
    text = " ".join(str(value) for value in [*row.values(), *replay.values(), *card.values()])
    match = re.search(r"0x[a-fA-F0-9]{64}", text)
    return match.group(0) if match else None


def _fixture_result_from_replay(replay: dict[str, str]) -> dict[str, Any]:
    status = str(replay.get("status") or "").strip()
    if not status:
        return {}
    result: dict[str, Any] = {"status": status}
    metadata_status = str(replay.get("metadata_status") or "").strip()
    if metadata_status:
        result["metadata_status"] = metadata_status
    returncode = _parse_int(replay.get("returncode"))
    if returncode is not None:
        result["returncode"] = returncode
    blocker = str(replay.get("blocker") or "").strip()
    if blocker:
        result["blocker"] = blocker
    command = str(replay.get("command") or "").strip()
    if command:
        result["command"] = command
    duration = _parse_float(replay.get("duration_seconds"))
    if duration is not None:
        result["duration_seconds"] = duration
    result["verified"] = _parse_bool(replay.get("verified")) or status == "verified" or returncode == 0
    return result


def _exclusion_reason(
    case: dict[str, Any],
    *,
    evm_only: bool,
    require_seed_transaction_hash: bool,
    require_replay_block: bool,
    include_evidence_candidates: bool,
) -> str | None:
    if not case["is_defi"]:
        return "not_defi"
    if case["attack_family"] in OPERATIONAL_FAMILIES:
        return "operational_or_offchain_family"
    if evm_only and case["chain"] not in EVM_CHAIN_IDS:
        return "non_evm_chain"
    if not case["rpc_supported"]:
        return "rpc_chain_unsupported"
    if not case["provenance_url"]:
        return "missing_provenance"
    if not case["security_anchor"] and (not case["seed_transaction_hash"] or not case["fork_block"]):
        return "missing_security_anchor"
    if not include_evidence_candidates:
        if not case["seed_transaction_hash"]:
            return "missing_seed_transaction_hash"
        if not case["fork_block"]:
            return "missing_replay_block"
        return None
    evidence_candidate = bool(include_evidence_candidates and case["rpc_supported"] and case["security_anchor"])
    if require_seed_transaction_hash and not case["seed_transaction_hash"] and not evidence_candidate:
        return "missing_seed_transaction_hash"
    if require_replay_block and not case["fork_block"] and not evidence_candidate:
        return "missing_replay_block"
    return None


def _exclusion_entry(case: dict[str, Any], reason: str) -> dict[str, Any]:
    return {
        "incident_id": case["incident_id"],
        "slug": case["slug"],
        "incident": case["incident"],
        "event_date": case["event_date"],
        "chain": case["chain"],
        "attack_family": case["attack_family"],
        "loss_usd": case["loss_usd"],
        "reason": reason,
        "missing_fields": case["missing_fields"],
        "provenance_url": case["provenance_url"],
        "rpc_env": case.get("rpc_env") or "",
        "rpc_supported": bool(case.get("rpc_supported")),
        "candidate_discovery_sources": case.get("candidate_discovery_sources") or [],
        "security_anchor": bool(case.get("security_anchor")),
        "security_report_sources": case.get("security_report_sources") or [],
        "pipeline_stages": _pipeline_stages(case, selection_status="excluded", exclusion_reason=reason),
    }


def _candidate_score(case: dict[str, Any]) -> tuple[float, str]:
    family_score = TECHNICAL_FAMILY_WEIGHTS.get(case["attack_family"], 1) * 1_000_000_000
    source_boost = 100_000_000 if case["selected_source"] == "selected_incidents_csv" else 0
    replay_boost = 120_000_000 if case["replay_test"] else 0
    security_source_boost = 60_000_000 if case["security_report_sources"] else 0
    rpc_boost = 30_000_000 if case["rpc_supported"] else 0
    anchor_penalty = 10_000_000 if not case["seed_transaction_hash"] else 0
    block_penalty = 5_000_000 if not case["fork_block"] else 0
    loss = case["loss_usd"] or 0.0
    return family_score + source_boost + replay_boost + security_source_boost + rpc_boost + loss - anchor_penalty - block_penalty, case["event_date"]


def _case_payload(case: dict[str, Any], generated_at: str) -> dict[str, Any]:
    eligibility = _case_eligibility(case)
    return {
        "schema_version": "abra.replay_cohort.case.v1",
        "generated_at": generated_at,
        "case_id": case["incident_id"],
        "slug": case["slug"],
        "incident": case["incident"],
        "event_date": case["event_date"],
        "chain": case["chain"],
        "chain_id": case["chain_id"],
        "attack_family": case["attack_family"],
        "loss_usd": case["loss_usd"],
        "fork_block": case["fork_block"],
        "seed_transaction_hash": case["seed_transaction_hash"],
        "provenance_url": case["provenance_url"],
        "fixture_source": case["fixture_source"],
        "event_card": case["event_card"],
        "candidate_discovery_sources": case["candidate_discovery_sources"],
        "security_report_sources": case["security_report_sources"],
        "security_anchor": case["security_anchor"],
        "rpc_env": case["rpc_env"],
        "rpc_supported": case["rpc_supported"],
        "replay_test": case["replay_test"],
        "metadata_test": case["metadata_test"],
        "test_path": case["test_path"],
        "replay_status": case["replay_status"],
        "fixture_result": case["fixture_result"],
        "fixture_metadata_attached": case["fixture_metadata_attached"],
        "eligibility": eligibility,
        "pipeline_stages": _pipeline_stages(case, selection_status="selected"),
        "evidence_level_target": "L4" if case["verified"] else "L1",
        "missing_fields": list(case["missing_fields"]),
        "description": case["description"],
    }


def _case_eligibility(case: dict[str, Any]) -> str:
    if case["replay_test"] and case["test_path"] and case["security_anchor"]:
        return "security_anchor_with_replay_fixture"
    if case["seed_transaction_hash"] and case["fork_block"]:
        return "onchain_anchor_ready" if not case["security_anchor"] else "security_anchor_ready"
    if case["security_anchor"] and (not case["seed_transaction_hash"] or not case["fork_block"]):
        return "security_anchor_backfill_required"
    return "candidate_discovery_only"


def _cohort_warnings(selected: list[dict[str, Any]], rpc_state: dict[str, Any]) -> list[str]:
    warnings: list[str] = []
    missing_rpc_configuration = str(rpc_state.get("missing_configuration_error") or "")
    if missing_rpc_configuration:
        warnings.append(missing_rpc_configuration)
    if any(not case["seed_transaction_hash"] or not case["fork_block"] for case in selected):
        warnings.append("selected_cases_include_diagnostic_evidence_boundaries")
    return warnings


def _selected_strict_requirement_errors(
    selected: list[dict[str, Any]],
    *,
    require_seed_transaction_hash: bool,
    require_replay_block: bool,
) -> list[str]:
    errors: list[str] = []
    if require_seed_transaction_hash and any(not case["seed_transaction_hash"] for case in selected):
        errors.append("selected_cases_missing_seed_transaction_hash")
    if require_replay_block and any(not case["fork_block"] for case in selected):
        errors.append("selected_cases_missing_replay_block")
    return errors


def _stage_ledger_payload(
    *,
    generated_at: str,
    cases: list[dict[str, Any]],
    selected_ids: set[str],
    exclusion_reasons: dict[str, str],
    source_stage_artifacts: dict[str, str],
) -> dict[str, Any]:
    entries: list[dict[str, Any]] = []
    for case in cases:
        incident_id = case["incident_id"]
        reason = exclusion_reasons.get(incident_id, "")
        if incident_id in selected_ids:
            selection_status = "selected"
        elif reason:
            selection_status = "excluded"
        else:
            selection_status = "eligible_not_selected"
        entries.append(
            {
                "incident_id": incident_id,
                "slug": case["slug"],
                "incident": case["incident"],
                "chain": case["chain"],
                "selection_status": selection_status,
                "exclusion_reason": reason,
                "candidate_discovery_sources": case.get("candidate_discovery_sources") or [],
                "security_report_sources": case.get("security_report_sources") or [],
                "missing_fields": case.get("missing_fields") or [],
                "pipeline_stages": _pipeline_stages(
                    case,
                    selection_status=selection_status,
                    exclusion_reason=reason or None,
                ),
            }
        )
    return {
        "schema_version": STAGE_LEDGER_SCHEMA_VERSION,
        "generated_at": generated_at,
        "stage_order": list(STAGE_ORDER),
        "source_stage_artifacts": source_stage_artifacts,
        "summary": _stage_ledger_summary(cases, selected_ids, exclusion_reasons),
        "entries": sorted(entries, key=lambda entry: (entry["selection_status"], entry["slug"])),
    }


def _stage_ledger_summary(
    cases: list[dict[str, Any]],
    selected_ids: set[str],
    exclusion_reasons: dict[str, str],
) -> dict[str, int]:
    return {
        "candidate_discovery_count": sum(1 for case in cases if case.get("candidate_discovery_sources")),
        "security_evidence_enriched_count": sum(1 for case in cases if case.get("security_anchor")),
        "alchemy_onchain_backfill_required_count": sum(
            1
            for case in cases
            if case.get("security_anchor") and (not case.get("seed_transaction_hash") or not case.get("fork_block"))
        ),
        "replay_metadata_promoted_count": 0,
        "fixture_metadata_attached_count": sum(1 for case in cases if case.get("fixture_metadata_attached")),
        "selected_count": len(selected_ids),
        "excluded_count": len(exclusion_reasons),
        "eligible_not_selected_count": max(len(cases) - len(selected_ids) - len(exclusion_reasons), 0),
    }


def _pipeline_stages(
    case: dict[str, Any],
    *,
    selection_status: str,
    exclusion_reason: str | None = None,
) -> dict[str, Any]:
    return {
        "candidate_discovery": {
            "status": "accepted" if case.get("candidate_discovery_sources") else "unattributed",
            "sources": case.get("candidate_discovery_sources") or [],
        },
        "security_evidence_enrichment": {
            "status": "verified"
            if case.get("security_anchor")
            else "reference_only"
            if case.get("seed_transaction_hash")
            else "missing",
            "sources": case.get("security_report_sources") or [],
        },
        "alchemy_onchain_backfill": _alchemy_backfill_stage(case),
        "replay_cohort_selection": {
            "status": selection_status,
            "exclusion_reason": exclusion_reason or "",
            "fixture_metadata_attached": bool(case.get("fixture_metadata_attached")),
            "replay_metadata_promoted": False,
        },
    }


def _alchemy_backfill_stage(case: dict[str, Any]) -> dict[str, Any]:
    missing = [
        field
        for field, value in (
            ("seed_transaction_hash", case.get("seed_transaction_hash")),
            ("fork_block", case.get("fork_block")),
        )
        if not value
    ]
    if not case.get("security_anchor"):
        status = "verified" if not missing else "required"
    elif not missing:
        status = "verified"
    elif case.get("rpc_supported"):
        status = "required"
    else:
        status = "blocked_rpc_unsupported"
    return {
        "status": status,
        "provider": "alchemy",
        "rpc_supported": bool(case.get("rpc_supported")),
        "missing_fields": missing,
    }


def _reset_out_dir(path: Path) -> None:
    if path.exists():
        shutil.rmtree(path)
    path.mkdir(parents=True, exist_ok=True)


def _write_json(path: Path, payload: object) -> None:
    path.write_text(json.dumps(payload, indent=2, ensure_ascii=False, sort_keys=True) + "\n", encoding="utf-8")


def _utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _exclusion_summary(exclusions: list[dict[str, Any]]) -> dict[str, Any]:
    counts: dict[str, int] = {}
    for entry in exclusions:
        counts[entry["reason"]] = counts.get(entry["reason"], 0) + 1
    return {"entry_count": len(exclusions), "reason_counts": counts}


def _cohort_id(generated_at: str, cases: list[dict[str, Any]]) -> str:
    return "cohort-" + _sha1([generated_at, *[case["slug"] for case in cases]])[:12]


def _sha1(parts: list[str]) -> str:
    h = hashlib.sha1()
    for part in parts:
        h.update(str(part).encode("utf-8"))
        h.update(b"|")
    return h.hexdigest()


def _slug(value: str) -> str:
    slug = re.sub(r"[^a-z0-9]+", "-", (value or "").lower()).strip("-")
    slug = re.sub(r"^\\d{4}-\\d{2}-\\d{2}-", "", slug)
    slug = re.sub(r"-[a-f0-9]{8}$", "", slug)
    return slug or "incident"


def _parse_float(value: Any) -> float | None:
    try:
        if value in (None, ""):
            return None
        return float(str(value).replace(",", ""))
    except (TypeError, ValueError):
        return None


def _parse_int(value: Any) -> int | None:
    try:
        if value in (None, ""):
            return None
        return int(float(str(value).replace(",", "")))
    except (TypeError, ValueError):
        return None


def _parse_bool(value: Any) -> bool:
    if isinstance(value, bool):
        return value
    return str(value or "").strip().lower() in {"1", "true", "yes", "y", "passed", "verified"}


def _is_tx_hash(value: str) -> bool:
    return bool(re.fullmatch(r"0x[a-fA-F0-9]{64}", value or ""))
