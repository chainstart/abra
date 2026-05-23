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

from abra.manifest import repo_root


COHORT_SCHEMA_VERSION = "abra.replay_cohort.v1"
MANIFEST_SCHEMA_VERSION = "abra.replay_cohort.manifest.v1"
EXCLUSION_LOG_SCHEMA_VERSION = "abra.replay_cohort.exclusion_log.v1"

EVM_CHAIN_IDS = {
    "ethereum": 1,
    "eth": 1,
    "mainnet": 1,
    "polygon": 137,
    "arbitrum": 42161,
    "optimism": 10,
    "base": 8453,
    "bnb": 56,
    "bsc": 56,
    "avalanche": 43114,
    "blast": 81457,
    "sonic": 146,
    "mantle": 5000,
    "linea": 59144,
    "berachain": 80094,
    "multi_evm": None,
}

NON_EVM_MARKERS = {
    "sui": "sui",
    "terra": "terra",
    "cosmos": "cosmos",
    "eos": "eos",
    "stellar": "stellar",
    "algorand": "algorand",
    "near": "near",
    "solana": "solana",
    "bitcoin": "bitcoin",
}

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


def build_replay_cohort(
    *,
    incidents_csv: str | Path = "data/processed/incidents_normalized_latest.csv",
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
) -> dict[str, Any]:
    """Materialize a bounded replay cohort and explicit exclusion log.

    The default mode is intentionally strict: cases without a seed transaction
    hash or replay/fork block are excluded so quality gaps surface instead of
    being hidden behind fixture-backed replay assessment.
    """

    root = repo_root()
    if min_cases < 1:
        raise ValueError("min_cases must be positive.")
    if max_cases < min_cases:
        raise ValueError("max_cases must be greater than or equal to min_cases.")

    if refresh:
        _run_phase1_refresh(root, refresh_start_page, refresh_end_page, refresh_top_protocols)

    incidents_path = _resolve_repo_path(root, incidents_csv)
    selected_path = _resolve_optional_repo_path(root, selected_incidents_csv)
    replay_path = _resolve_repo_path(root, replay_results_csv)
    cards_dir = _resolve_repo_path(root, event_cards_dir)
    out_path = _resolve_repo_path(root, out)

    incidents = _read_csv(incidents_path)
    selected_ids = _selected_incident_ids(selected_path)
    replay_by_slug = _replay_metadata_by_slug(replay_path)
    cards_by_slug = _event_cards_by_slug(cards_dir)

    generated_at = _utc_now()
    candidates: list[dict[str, Any]] = []
    exclusions: list[dict[str, Any]] = []

    for row in incidents:
        normalized = _normalize_incident(row, replay_by_slug, cards_by_slug, selected_ids)
        reason = _exclusion_reason(
            normalized,
            evm_only=evm_only,
            require_seed_transaction_hash=require_seed_transaction_hash,
            require_replay_block=require_replay_block,
        )
        if reason:
            exclusions.append(_exclusion_entry(normalized, reason))
            continue
        candidates.append(normalized)

    candidates.sort(key=_candidate_score, reverse=True)
    selected = candidates[:max_cases]
    errors: list[str] = []
    if len(selected) < min_cases:
        errors.append("insufficient_eligible_cases")

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
        "source_incidents_csv": str(incidents_path),
        "selected_incidents_csv": str(selected_path) if selected_path else None,
        "replay_results_csv": str(replay_path) if replay_path.exists() else None,
        "event_cards_dir": str(cards_dir) if cards_dir.exists() else None,
        "min_cases": min_cases,
        "max_cases": max_cases,
        "evm_only": evm_only,
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
            "meets_case_count_requirement": min_cases <= len(manifest_cases) <= max_cases,
        },
    }
    exclusion_log = {
        "schema_version": EXCLUSION_LOG_SCHEMA_VERSION,
        "generated_at": generated_at,
        "source_incidents_csv": str(incidents_path),
        "entries": sorted(exclusions, key=lambda entry: (entry["reason"], entry["slug"])),
        "summary": _exclusion_summary(exclusions),
    }

    _write_json(out_path / "manifest.json", manifest)
    _write_json(out_path / "exclusion_log.json", exclusion_log)

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
        "artifacts": {
            "manifest": "manifest.json",
            "exclusion_log": "exclusion_log.json",
            "cases_dir": "cases",
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


def _normalize_incident(
    row: dict[str, str],
    replay_by_slug: dict[str, dict[str, str]],
    cards_by_slug: dict[str, Path],
    selected_ids: set[str],
) -> dict[str, Any]:
    incident = (row.get("target") or row.get("incident") or "").strip()
    slug = _slug(row.get("slug") or incident or row.get("incident_id") or "incident")
    replay = replay_by_slug.get(slug, {})
    inferred_chain = _infer_chain(row, replay)
    chain_id = _chain_id(inferred_chain)
    seed_hash = _extract_seed_transaction_hash(row, replay)
    fork_block = _parse_int(replay.get("fork_block") or row.get("fork_block") or row.get("replay_block"))
    event_card = cards_by_slug.get(slug)
    reference = (row.get("reference_url") or "").strip()
    missing: list[str] = []
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
        "attack_family": row.get("attack_family") or replay.get("attack_family") or "other",
        "attack_method_raw": row.get("attack_method_raw") or "",
        "loss_usd": _parse_float(row.get("loss_usd") or replay.get("loss_usd")),
        "seed_transaction_hash": seed_hash,
        "fork_block": fork_block,
        "provenance_url": reference,
        "source_url": row.get("source_url") or "",
        "fixture_source": str(event_card) if event_card else "",
        "event_card": str(event_card) if event_card else "",
        "replay_test": replay.get("replay_test") or "",
        "test_path": replay.get("test_path") or "",
        "replay_status": replay.get("status") or "",
        "selected_source": "selected_incidents_csv" if row.get("incident_id") in selected_ids else "incidents_csv",
        "description": row.get("description") or "",
        "missing_fields": missing,
        "raw": row,
    }


def _infer_chain(row: dict[str, str], replay: dict[str, str]) -> str:
    chain = (replay.get("chain") or row.get("chain") or "").strip().lower()
    if chain:
        return _normalize_chain(chain)
    text = " ".join(
        [
            row.get("target", ""),
            row.get("protocol_slug_guess", ""),
            row.get("description", ""),
            row.get("reference_url", ""),
        ]
    ).lower()
    for marker, normalized in NON_EVM_MARKERS.items():
        if marker in text:
            return normalized
    for marker in EVM_CHAIN_IDS:
        if marker in text:
            return _normalize_chain(marker)
    if any(marker in text for marker in ("bsc", "bnb chain", "pancake")):
        return "bsc"
    if "base" in text:
        return "base"
    return "ethereum"


def _normalize_chain(chain: str) -> str:
    chain = chain.strip().lower().replace(" ", "_").replace("-", "_")
    if chain in {"eth", "mainnet"}:
        return "ethereum"
    if chain in {"bnb_chain", "binance"}:
        return "bsc"
    return chain


def _chain_id(chain: str) -> int | None:
    return EVM_CHAIN_IDS.get(chain)


def _extract_seed_transaction_hash(row: dict[str, str], replay: dict[str, str]) -> str | None:
    for key in ("seed_transaction_hash", "transaction_hash", "tx_hash", "attack_tx", "tx"):
        value = (row.get(key) or replay.get(key) or "").strip()
        if _is_tx_hash(value):
            return value
    text = " ".join(str(value) for value in [*row.values(), *replay.values()])
    match = re.search(r"0x[a-fA-F0-9]{64}", text)
    return match.group(0) if match else None


def _exclusion_reason(
    case: dict[str, Any],
    *,
    evm_only: bool,
    require_seed_transaction_hash: bool,
    require_replay_block: bool,
) -> str | None:
    if not case["is_defi"]:
        return "not_defi"
    if case["attack_family"] in OPERATIONAL_FAMILIES:
        return "operational_or_offchain_family"
    if evm_only and case["chain"] not in EVM_CHAIN_IDS:
        return "non_evm_chain"
    if not case["provenance_url"]:
        return "missing_provenance"
    if require_seed_transaction_hash and not case["seed_transaction_hash"]:
        return "missing_seed_transaction_hash"
    if require_replay_block and not case["fork_block"]:
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
    }


def _candidate_score(case: dict[str, Any]) -> tuple[float, str]:
    family_score = TECHNICAL_FAMILY_WEIGHTS.get(case["attack_family"], 1) * 1_000_000_000
    source_boost = 100_000_000 if case["selected_source"] == "selected_incidents_csv" else 0
    replay_boost = 50_000_000 if case["replay_test"] else 0
    loss = case["loss_usd"] or 0.0
    return family_score + source_boost + replay_boost + loss, case["event_date"]


def _case_payload(case: dict[str, Any], generated_at: str) -> dict[str, Any]:
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
        "replay_test": case["replay_test"],
        "test_path": case["test_path"],
        "replay_status": case["replay_status"],
        "eligibility": "selected",
        "missing_fields": list(case["missing_fields"]),
        "description": case["description"],
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


def _is_tx_hash(value: str) -> bool:
    return bool(re.fullmatch(r"0x[a-fA-F0-9]{64}", value or ""))
