"""Materialize ABRA's staged event collection and evidence-production pipeline."""

from __future__ import annotations

import csv
import html
import json
import os
import re
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable
from urllib.parse import quote_plus, urlparse

from abra.chain_support import (
    chain_id,
    chain_rpc_supported,
    infer_chain,
    load_local_environment,
    normalize_chain,
    rpc_capability_state,
    rpc_env_for_chain,
    rpc_url_for_chain,
)
from abra.evidence_sources import (
    candidate_discovery_sources,
    security_report_sources,
    text_only_security_mentions_ignored,
)
from abra.manifest import repo_root


EVIDENCE_PIPELINE_SCHEMA_VERSION = "abra.evidence_pipeline.v1"
SECURITY_EVIDENCE_SCHEMA_VERSION = "abra.security_evidence_enriched.v1"
ALCHEMY_BACKFILL_SCHEMA_VERSION = "abra.alchemy_onchain_backfill.v1"

SECURITY_EVIDENCE_CSV = "security_evidence_enriched_latest.csv"
SECURITY_EVIDENCE_JSON = "security_evidence_enriched_latest.json"
ALCHEMY_BACKFILL_CSV = "alchemy_onchain_backfill_latest.csv"
ALCHEMY_BACKFILL_JSON = "alchemy_onchain_backfill_latest.json"

SECURITY_EVIDENCE_FIELDS = [
    "incident_id",
    "slug",
    "target",
    "event_date",
    "chain",
    "chain_id",
    "attack_family",
    "loss_usd",
    "reference_url",
    "source_url",
    "candidate_discovery_sources",
    "security_report_sources",
    "security_source_name",
    "security_source_url",
    "security_anchor",
    "confidence",
    "evidence_gap",
    "seed_transaction_hash",
    "fork_block",
    "description",
]

ALCHEMY_BACKFILL_FIELDS = [
    "incident_id",
    "slug",
    "target",
    "event_date",
    "chain",
    "chain_id",
    "rpc_provider",
    "rpc_env",
    "rpc_supported",
    "security_anchor",
    "backfill_status",
    "missing_onchain_fields",
    "seed_transaction_hash",
    "fork_block",
    "source_fetch_status",
    "source_evidence_url",
    "source_extracted_seed_transaction_hash",
    "source_extracted_block",
    "anchor_discovery_status",
    "anchor_discovery_url",
    "anchor_discovery_seed_transaction_hash",
    "anchor_discovery_block",
    "rpc_backfill_status",
    "reference_url",
    "security_report_sources",
]

SourceFetcher = Callable[[str], dict[str, str]]
RpcCaller = Callable[[str, str, list[str]], dict[str, Any]]
AnchorSearcher = Callable[[dict[str, str]], list[dict[str, str]]]


def produce_evidence_pipeline(
    *,
    incidents_csv: str | Path = "data/processed/incidents_normalized_latest.csv",
    out_dir: str | Path = "data/processed",
    rpc_provider: str = "alchemy",
    rpc_supported_chains: list[str] | None = None,
    source_fetcher: SourceFetcher | None = None,
    anchor_searcher: AnchorSearcher | None = None,
    rpc_caller: RpcCaller | None = None,
) -> dict[str, Any]:
    """Write explicit candidate enrichment and Alchemy backfill stage products."""

    root = repo_root()
    load_local_environment(root)
    incidents_path = _resolve_repo_path(root, incidents_csv)
    out_path = _resolve_repo_path(root, out_dir)
    out_path.mkdir(parents=True, exist_ok=True)

    incident_rows = _read_csv(incidents_path)
    rpc_state = rpc_capability_state(provider=rpc_provider, explicit_chains=rpc_supported_chains)
    rpc_chains = rpc_state["supported_chains"]
    generated_at = _utc_now()

    enriched_rows = [_enrich_security_evidence(row) for row in incident_rows]
    reference_fetch_budget = _reference_fetch_budget()
    anchor_discovery_budget = _onchain_anchor_discovery_budget()
    backfill_candidate_rows = [
        row
        for row in enriched_rows
        if row["reference_url"] or row["seed_transaction_hash"] or extract_seed_transaction_hash(row)
    ]
    reference_fetch_ids = _prioritized_reference_fetch_ids(backfill_candidate_rows, rpc_chains, reference_fetch_budget)
    anchor_discovery_ids = _prioritized_anchor_discovery_ids(
        backfill_candidate_rows,
        rpc_chains,
        anchor_discovery_budget,
    )
    backfill_rows = [
        _build_backfill_row(
            row,
            rpc_provider=rpc_state["provider"],
            rpc_supported_chains=rpc_chains,
            incident_context=row,
            source_fetcher=source_fetcher or fetch_security_source_text,
            anchor_searcher=anchor_searcher or search_onchain_anchor_sources,
            rpc_caller=rpc_caller or json_rpc_call,
            allow_reference_fetch=row["security_anchor"] == "true" or row["incident_id"] in reference_fetch_ids,
            allow_anchor_discovery=_onchain_anchor_discovery_enabled()
            and row["incident_id"] in anchor_discovery_ids,
        )
        for row in backfill_candidate_rows
    ]

    _write_csv(out_path / SECURITY_EVIDENCE_CSV, enriched_rows, SECURITY_EVIDENCE_FIELDS)
    _write_json(
        out_path / SECURITY_EVIDENCE_JSON,
        {
            "schema_version": SECURITY_EVIDENCE_SCHEMA_VERSION,
            "stage": "security_evidence_enrichment",
            "generated_at": generated_at,
            "source_incidents_csv": str(incidents_path),
            "summary": _security_summary(enriched_rows, incident_rows),
            "rows": enriched_rows,
        },
    )
    _write_csv(out_path / ALCHEMY_BACKFILL_CSV, backfill_rows, ALCHEMY_BACKFILL_FIELDS)
    _write_json(
        out_path / ALCHEMY_BACKFILL_JSON,
        {
            "schema_version": ALCHEMY_BACKFILL_SCHEMA_VERSION,
            "stage": "alchemy_onchain_backfill",
            "generated_at": generated_at,
            "source_security_evidence_csv": SECURITY_EVIDENCE_CSV,
            "rpc_capability": {
                "provider": rpc_state["provider"],
                "configured": rpc_state["configured"],
                "configuration_sources": rpc_state["configuration_sources"],
                "supported_chains": sorted(rpc_chains),
            },
            "summary": _backfill_summary(enriched_rows, backfill_rows),
            "rows": backfill_rows,
        },
    )

    errors: list[str] = []
    if rpc_state["missing_configuration_error"]:
        errors.append(rpc_state["missing_configuration_error"])

    return {
        "schema_version": EVIDENCE_PIPELINE_SCHEMA_VERSION,
        "status": "passed" if not errors else "failed",
        "source_incidents_csv": str(incidents_path),
        "out_dir": str(out_path),
        "summary": {
            **_security_summary(enriched_rows, incident_rows),
            "alchemy_backfill_candidate_count": len(backfill_rows),
        },
        "errors": errors,
        "artifacts": {
            "security_evidence_csv": SECURITY_EVIDENCE_CSV,
            "security_evidence_json": SECURITY_EVIDENCE_JSON,
            "alchemy_backfill_csv": ALCHEMY_BACKFILL_CSV,
            "alchemy_backfill_json": ALCHEMY_BACKFILL_JSON,
        },
    }


def _enrich_security_evidence(row: dict[str, str]) -> dict[str, str]:
    candidate_sources = candidate_discovery_sources(row)
    security_sources = security_report_sources(row)
    security_anchor = bool(security_sources)
    chain = infer_chain(row)
    seed_hash = extract_seed_transaction_hash(row)
    fork_block = parse_int(row.get("fork_block") or row.get("replay_block"))
    missing: list[str] = []
    if not candidate_sources:
        missing.append("missing_candidate_source")
    if not security_anchor:
        missing.append("missing_security_anchor")
    if not seed_hash:
        missing.append("missing_seed_transaction_hash")
    if fork_block is None:
        missing.append("missing_replay_block")
    primary_source = security_sources[0] if security_sources else {}
    return {
        "incident_id": row.get("incident_id") or _sha1([row.get("target", ""), row.get("event_date", "")]),
        "slug": slugify(row.get("slug") or row.get("target") or row.get("incident") or "incident"),
        "target": row.get("target") or row.get("incident") or "",
        "event_date": row.get("event_date") or "",
        "chain": chain,
        "chain_id": "" if chain_id(chain) is None else str(chain_id(chain)),
        "attack_family": row.get("attack_family") or "other",
        "loss_usd": row.get("loss_usd") or "",
        "reference_url": row.get("reference_url") or "",
        "source_url": row.get("source_url") or "",
        "candidate_discovery_sources": _json_cell(candidate_sources),
        "security_report_sources": _json_cell(security_sources),
        "security_source_name": str(primary_source.get("source") or ""),
        "security_source_url": str(primary_source.get("url") or ""),
        "security_anchor": str(security_anchor).lower(),
        "confidence": _confidence(security_anchor=security_anchor, candidate_sources=candidate_sources),
        "evidence_gap": "|".join(missing),
        "seed_transaction_hash": seed_hash or "",
        "fork_block": "" if fork_block is None else str(fork_block),
        "description": row.get("description") or "",
    }


def _build_backfill_row(
    row: dict[str, str],
    *,
    rpc_provider: str,
    rpc_supported_chains: set[str],
    incident_context: dict[str, str],
    source_fetcher: SourceFetcher,
    anchor_searcher: AnchorSearcher,
    rpc_caller: RpcCaller,
    allow_reference_fetch: bool,
    allow_anchor_discovery: bool,
) -> dict[str, str]:
    chain = normalize_chain(row.get("chain") or "")
    seed_hash = row.get("seed_transaction_hash") or extract_seed_transaction_hash(row) or ""
    fork_block = row.get("fork_block") or ""
    evidence_sources = _backfill_evidence_sources(row)
    source_evidence_url = ""
    source_fetch_status = "not_required" if seed_hash and fork_block else "not_attempted"
    source_extracted_hash = ""
    source_extracted_block = ""
    anchor_discovery_status = "not_required" if seed_hash and fork_block else "not_attempted"
    anchor_discovery_url = ""
    anchor_discovery_hash = ""
    anchor_discovery_block = ""
    if (not seed_hash or not fork_block) and evidence_sources:
        source_evidence = _extract_onchain_anchor_from_security_sources(
            evidence_sources,
            incident_context=incident_context,
            source_fetcher=source_fetcher,
            allow_reference_fetch=allow_reference_fetch,
        )
        source_fetch_status = source_evidence["source_fetch_status"]
        source_evidence_url = source_evidence["source_evidence_url"]
        source_extracted_hash = source_evidence["source_extracted_seed_transaction_hash"]
        source_extracted_block = source_evidence["source_extracted_block"]
        seed_hash = seed_hash or source_extracted_hash
        fork_block = fork_block or source_extracted_block

    rpc_backfill_status = "not_required" if fork_block else "not_attempted"
    supported = chain_rpc_supported(chain, rpc_supported_chains)
    if seed_hash and not fork_block and supported:
        rpc_result = _fetch_fork_block_from_rpc(chain, seed_hash, rpc_caller)
        rpc_backfill_status = rpc_result["rpc_backfill_status"]
        fork_block = rpc_result["fork_block"] or fork_block

    if seed_hash and fork_block and anchor_discovery_status == "not_attempted":
        anchor_discovery_status = "not_required"

    if (not seed_hash) or (seed_hash and not fork_block):
        if allow_anchor_discovery:
            discovered = _discover_onchain_anchor(
                row,
                incident_context=incident_context,
                anchor_searcher=anchor_searcher,
            )
            anchor_discovery_status = discovered["anchor_discovery_status"]
            anchor_discovery_url = discovered["anchor_discovery_url"]
            anchor_discovery_hash = discovered["anchor_discovery_seed_transaction_hash"]
            anchor_discovery_block = discovered["anchor_discovery_block"]
            seed_hash = seed_hash or anchor_discovery_hash
            fork_block = fork_block or anchor_discovery_block
            if seed_hash and not fork_block and supported:
                rpc_result = _fetch_fork_block_from_rpc(chain, seed_hash, rpc_caller)
                rpc_backfill_status = rpc_result["rpc_backfill_status"]
                fork_block = rpc_result["fork_block"] or fork_block
        else:
            anchor_discovery_status = "anchor_discovery_skipped:disabled_or_budget"

    missing = [
        field
        for field, value in (
            ("seed_transaction_hash", seed_hash),
            ("fork_block", fork_block),
        )
        if not value
    ]
    if not missing:
        status = "not_required" if row.get("seed_transaction_hash") and row.get("fork_block") else "backfilled_onchain_anchor"
    elif not supported:
        status = "blocked_rpc_unsupported"
    else:
        status = "missing_onchain_anchor"
    return {
        "incident_id": row["incident_id"],
        "slug": row["slug"],
        "target": row["target"],
        "event_date": row["event_date"],
        "chain": chain,
        "chain_id": row.get("chain_id") or "",
        "rpc_provider": rpc_provider,
        "rpc_env": rpc_env_for_chain(chain),
        "rpc_supported": str(supported).lower(),
        "security_anchor": row["security_anchor"],
        "backfill_status": status,
        "missing_onchain_fields": "|".join(missing),
        "seed_transaction_hash": seed_hash,
        "fork_block": fork_block,
        "source_fetch_status": source_fetch_status,
        "source_evidence_url": source_evidence_url,
        "source_extracted_seed_transaction_hash": source_extracted_hash,
        "source_extracted_block": source_extracted_block,
        "anchor_discovery_status": anchor_discovery_status,
        "anchor_discovery_url": anchor_discovery_url,
        "anchor_discovery_seed_transaction_hash": anchor_discovery_hash,
        "anchor_discovery_block": anchor_discovery_block,
        "rpc_backfill_status": rpc_backfill_status,
        "reference_url": row["reference_url"],
        "security_report_sources": row["security_report_sources"],
    }


def _security_summary(enriched_rows: list[dict[str, str]], original_rows: list[dict[str, str]]) -> dict[str, int]:
    return {
        "candidate_count": len(enriched_rows),
        "candidate_discovery_count": sum(1 for row in enriched_rows if json.loads(row["candidate_discovery_sources"])),
        "security_anchored_count": sum(1 for row in enriched_rows if row["security_anchor"] == "true"),
        "missing_security_anchor_count": sum(1 for row in enriched_rows if row["security_anchor"] != "true"),
        "text_only_security_mentions_ignored_count": sum(
            1 for row in original_rows if text_only_security_mentions_ignored(row)
        ),
    }


def _backfill_summary(enriched_rows: list[dict[str, str]], backfill_rows: list[dict[str, str]]) -> dict[str, int]:
    return {
        "backfill_candidate_count": len(backfill_rows),
        "security_anchored_backfill_count": sum(1 for row in backfill_rows if row["security_anchor"] == "true"),
        "reference_only_backfill_count": sum(1 for row in backfill_rows if row["security_anchor"] != "true"),
        # Backward-compatible alias kept for existing consumers.
        "security_anchored_count": sum(1 for row in backfill_rows if row["security_anchor"] == "true"),
        "not_required_count": sum(1 for row in backfill_rows if row["backfill_status"] == "not_required"),
        "backfilled_onchain_anchor_count": sum(
            1 for row in backfill_rows if row["backfill_status"] == "backfilled_onchain_anchor"
        ),
        "missing_onchain_anchor_count": sum(
            1 for row in backfill_rows if row["backfill_status"] == "missing_onchain_anchor"
        ),
        "blocked_rpc_unsupported_count": sum(
            1 for row in backfill_rows if row["backfill_status"] == "blocked_rpc_unsupported"
        ),
        "anchor_discovered_count": sum(
            1 for row in backfill_rows if row.get("anchor_discovery_status") == "discovered"
        ),
        "onchain_anchor_complete_count": sum(
            1 for row in backfill_rows if row.get("seed_transaction_hash") and row.get("fork_block")
        ),
        "unanchored_skipped_count": sum(
            1
            for row in enriched_rows
            if row["security_anchor"] != "true" and not row.get("seed_transaction_hash") and not extract_seed_transaction_hash(row)
        ),
    }


def _prioritized_reference_fetch_ids(
    rows: list[dict[str, str]],
    rpc_supported_chains: set[str],
    budget: int,
) -> set[str]:
    if budget <= 0:
        return set()
    return _top_budgeted_incident_ids(
        rows,
        budget,
        priority_fn=lambda row: _reference_fetch_priority(row, rpc_supported_chains),
    )


def _prioritized_anchor_discovery_ids(
    rows: list[dict[str, str]],
    rpc_supported_chains: set[str],
    budget: int,
) -> set[str]:
    if budget <= 0:
        return set()
    return _top_budgeted_incident_ids(
        rows,
        budget,
        priority_fn=lambda row: _anchor_discovery_priority(row, rpc_supported_chains),
    )


def _top_budgeted_incident_ids(
    rows: list[dict[str, str]],
    budget: int,
    *,
    priority_fn: Callable[[dict[str, str]], int],
) -> set[str]:
    ranked: list[tuple[int, int, str]] = []
    for index, row in enumerate(rows):
        priority = priority_fn(row)
        if priority <= 0:
            continue
        ranked.append((priority, -index, row["incident_id"]))
    ranked.sort(reverse=True)
    return {incident_id for _, _, incident_id in ranked[:budget]}


def _reference_fetch_priority(row: dict[str, str], rpc_supported_chains: set[str]) -> int:
    if row.get("seed_transaction_hash") and row.get("fork_block"):
        return 0
    if not _row_rpc_supported(row, rpc_supported_chains):
        return 0
    priority = 10
    if _row_has_tx_hint(row):
        priority += 100
    if row.get("security_anchor") == "true":
        priority += 80
    if _row_has_security_social_source(row):
        priority += 20
    return priority


def _anchor_discovery_priority(row: dict[str, str], rpc_supported_chains: set[str]) -> int:
    if row.get("seed_transaction_hash") and row.get("fork_block"):
        return 0
    if not _row_rpc_supported(row, rpc_supported_chains):
        return 0
    missing_seed = not row.get("seed_transaction_hash")
    missing_block = not row.get("fork_block")
    if not missing_seed and not missing_block:
        return 0
    priority = 10
    if row.get("security_anchor") == "true":
        priority += 100
    if _row_has_security_social_source(row):
        priority += 40
    if _row_has_tx_hint(row):
        priority += 30
    if missing_seed:
        priority += 10
    if missing_block:
        priority += 5
    return priority


def _row_rpc_supported(row: dict[str, str], rpc_supported_chains: set[str]) -> bool:
    return chain_rpc_supported(normalize_chain(row.get("chain") or ""), rpc_supported_chains)


def _row_has_security_social_source(row: dict[str, str]) -> bool:
    return any(
        _requires_specialized_social_fetch(str(source.get("url") or ""))
        for source in _safe_json_list(row.get("security_report_sources") or "[]")
    )


def _row_has_tx_hint(row: dict[str, str]) -> bool:
    if extract_seed_transaction_hash(row):
        return True
    text = " ".join(
        [
            str(row.get("reference_url") or ""),
            str(row.get("source_url") or ""),
            str(row.get("description") or ""),
        ]
    ).lower()
    return any(
        marker in text
        for marker in (
            "/tx/",
            "tx=",
            "transaction hash",
            "attack tx",
            "exploit tx",
            "etherscan",
            "bscscan",
            "arbiscan",
            "basescan",
            "polygonscan",
        )
    )


def _safe_json_list(value: str) -> list[dict[str, str]]:
    try:
        loaded = json.loads(value)
    except json.JSONDecodeError:
        return []
    if not isinstance(loaded, list):
        return []
    return [item for item in loaded if isinstance(item, dict)]


def _backfill_evidence_sources(row: dict[str, str]) -> list[dict[str, str]]:
    sources = _safe_json_list(row.get("security_report_sources") or "[]")
    urls = {str(source.get("url") or "") for source in sources}
    reference_url = str(row.get("reference_url") or "").strip()
    if reference_url and reference_url not in urls:
        sources.append({"source": "reference_url", "url": reference_url})
    return sources


def _extract_onchain_anchor_from_security_sources(
    sources: list[dict[str, str]],
    *,
    incident_context: dict[str, str],
    source_fetcher: SourceFetcher,
    allow_reference_fetch: bool,
) -> dict[str, str]:
    last_status = "not_attempted"
    for source in sources:
        url = str(source.get("url") or "")
        if not url:
            continue
        if not _should_fetch_for_onchain_anchor(source, allow_reference_fetch=allow_reference_fetch):
            last_status = "source_fetch_skipped:no_tx_hint"
            continue
        try:
            fetched = source_fetcher(url)
        except Exception as exc:  # pragma: no cover - defensive boundary for live source failures
            last_status = f"source_fetch_failed:{exc.__class__.__name__}"
            continue
        status = str(fetched.get("status") or "fetched")
        if status != "fetched":
            last_status = status
            continue
        text = str(fetched.get("text") or "")
        evidence_text = select_incident_context_text(text, incident_context)
        seed_hash = extract_seed_transaction_hash({"source_text": evidence_text}) or ""
        block = extract_block_number(evidence_text)
        if seed_hash or block:
            return {
                "source_fetch_status": status,
                "source_evidence_url": url,
                "source_extracted_seed_transaction_hash": seed_hash,
                "source_extracted_block": "" if block is None else str(block),
            }
        last_status = "fetched_no_onchain_anchor"
    return {
        "source_fetch_status": last_status,
        "source_evidence_url": "",
        "source_extracted_seed_transaction_hash": "",
        "source_extracted_block": "",
    }


def _discover_onchain_anchor(
    row: dict[str, str],
    *,
    incident_context: dict[str, str],
    anchor_searcher: AnchorSearcher,
) -> dict[str, str]:
    try:
        results = anchor_searcher(_anchor_discovery_context(row, incident_context))
    except Exception as exc:  # pragma: no cover - defensive boundary for live search failures
        return _empty_anchor_discovery(f"anchor_discovery_failed:{exc.__class__.__name__}")

    last_status = "anchor_discovery_no_results"
    for result in results:
        status = str(result.get("status") or "fetched")
        if status != "fetched":
            last_status = status
            continue
        url = str(result.get("url") or "")
        text = " ".join([url, str(result.get("text") or "")])
        evidence_text = select_incident_context_text(text, incident_context)
        seed_hash = extract_seed_transaction_hash({"url": url, "source_text": evidence_text}) or ""
        block = extract_block_number(evidence_text)
        if seed_hash or block:
            evidence_url = extract_transaction_url(evidence_text, seed_hash) or url
            return {
                "anchor_discovery_status": "discovered",
                "anchor_discovery_url": evidence_url,
                "anchor_discovery_seed_transaction_hash": seed_hash,
                "anchor_discovery_block": "" if block is None else str(block),
            }
        last_status = "anchor_discovery_no_onchain_anchor"
    return _empty_anchor_discovery(last_status)


def _empty_anchor_discovery(status: str) -> dict[str, str]:
    return {
        "anchor_discovery_status": status,
        "anchor_discovery_url": "",
        "anchor_discovery_seed_transaction_hash": "",
        "anchor_discovery_block": "",
    }


def _anchor_discovery_context(row: dict[str, str], incident_context: dict[str, str]) -> dict[str, str]:
    context = {str(key): str(value) for key, value in {**incident_context, **row}.items()}
    context["target"] = context.get("target") or context.get("incident") or ""
    context["slug"] = context.get("slug") or slugify(context["target"] or "incident")
    context["chain"] = normalize_chain(context.get("chain") or "")
    return context


def select_incident_context_text(text: str, incident_context: dict[str, str]) -> str:
    targets = [
        str(incident_context.get("target") or ""),
        str(incident_context.get("slug") or "").replace("-", " "),
    ]
    haystack = text or ""
    lower = haystack.lower()
    for target in targets:
        normalized = " ".join(target.split()).lower()
        if not normalized:
            continue
        index = lower.find(normalized)
        if index >= 0:
            start = index
            end = min(len(haystack), index + len(normalized) + 1200)
            return haystack[start:end]
    if len(re.findall(r"0x[a-fA-F0-9]{64}", haystack)) > 1:
        return ""
    return haystack


def _should_fetch_for_onchain_anchor(source: dict[str, str], *, allow_reference_fetch: bool) -> bool:
    source_name = str(source.get("source") or "")
    url = str(source.get("url") or "")
    if source_name != "reference_url":
        return True
    if allow_reference_fetch:
        return True
    lowered = url.lower()
    if extract_seed_transaction_hash({"url": url}):
        return True
    return any(marker in lowered for marker in ("/tx/", "tx=", "transaction", "etherscan", "bscscan", "arbiscan", "polygonscan"))


def _reference_fetch_budget() -> int:
    try:
        return max(0, int(os.environ.get("ABRA_REFERENCE_FETCH_BUDGET", "20")))
    except ValueError:
        return 20


def _onchain_anchor_discovery_enabled() -> bool:
    value = os.environ.get("ABRA_ONCHAIN_ANCHOR_DISCOVERY", "1").strip().lower()
    if value in {"0", "false", "no", "off"}:
        return False
    return True


def _onchain_anchor_discovery_budget() -> int:
    try:
        return max(0, int(os.environ.get("ABRA_ONCHAIN_ANCHOR_DISCOVERY_BUDGET", "20")))
    except ValueError:
        return 20


def search_onchain_anchor_sources(context: dict[str, str]) -> list[dict[str, str]]:
    """Search public web result pages for transaction/explorer anchors.

    This is a bounded best-effort discovery step. It never creates incidents;
    it only attempts to add tx/block anchors to an already selected candidate.
    """

    if not _onchain_anchor_discovery_enabled():
        return [{"status": "anchor_discovery_skipped:disabled", "url": "", "text": ""}]

    results: list[dict[str, str]] = []
    for query in _onchain_anchor_queries(context):
        url = f"https://duckduckgo.com/html/?q={quote_plus(query)}"
        request = urllib.request.Request(
            url,
            headers={
                "User-Agent": "ABRA/1.0 onchain-anchor-discovery (+https://github.com/chainstart/abra)",
                "Accept": "text/html,application/xhtml+xml,text/plain;q=0.9,*/*;q=0.8",
            },
        )
        try:
            with urllib.request.urlopen(request, timeout=15) as response:
                raw = response.read(1_000_000)
        except urllib.error.HTTPError as exc:
            results.append({"status": f"http_{exc.code}", "query": query, "url": url, "text": ""})
            continue
        except urllib.error.URLError as exc:
            reason = getattr(exc, "reason", "")
            reason_name = reason.__class__.__name__ if reason else exc.__class__.__name__
            results.append(
                {"status": f"anchor_discovery_failed:{reason_name}", "query": query, "url": url, "text": ""}
            )
            continue
        text = html.unescape(raw.decode("utf-8", errors="replace"))
        results.append({"status": "fetched", "query": query, "url": url, "text": text})
        if extract_seed_transaction_hash({"source_text": text}):
            break
    return results


def _onchain_anchor_queries(context: dict[str, str]) -> list[str]:
    target = str(context.get("target") or context.get("incident") or "").strip()
    slug = str(context.get("slug") or "").replace("-", " ").strip()
    chain = normalize_chain(str(context.get("chain") or ""))
    date = str(context.get("event_date") or "").strip()
    security_source_names = _security_source_names_from_context(context)
    names = [name for name in (target, slug) if name]
    if not names:
        names = ["DeFi exploit"]
    base = names[0]
    explorer = _explorer_domain_for_chain(chain)
    suffix = f" {date}" if date else ""
    queries = [
        f"{base}{suffix} site:{explorer}/tx",
        f"{base}{suffix} exploit transaction hash",
        f"{base}{suffix} attack tx hash",
        f"{base}{suffix} {explorer} tx",
        f"{base}{suffix} BlockSec PeckShield CertiK exploit transaction",
    ]
    for source_name in security_source_names:
        queries.extend(
            [
                f"{base}{suffix} {source_name} transaction hash",
                f"{base}{suffix} {source_name} {explorer} tx",
            ]
        )
    return _dedupe_strings(queries)


def _security_source_names_from_context(context: dict[str, str]) -> list[str]:
    names: list[str] = []
    for source in _safe_json_list(str(context.get("security_report_sources") or "[]")):
        name = str(source.get("source") or "").strip()
        if name:
            names.append(name)
    return _dedupe_strings(names)


def _explorer_domain_for_chain(chain: str) -> str:
    return {
        "ethereum": "etherscan.io",
        "bsc": "bscscan.com",
        "bnb": "bscscan.com",
        "polygon": "polygonscan.com",
        "arbitrum": "arbiscan.io",
        "optimism": "optimistic.etherscan.io",
        "base": "basescan.org",
        "avalanche": "snowtrace.io",
        "celo": "celoscan.io",
        "zksync": "era.zksync.network",
        "polygon_zkevm": "zkevm.polygonscan.com",
    }.get(normalize_chain(chain), "etherscan.io")


def extract_transaction_url(text: str, tx_hash: str = "") -> str:
    tx_pattern = tx_hash if is_tx_hash(tx_hash) else r"0x[a-fA-F0-9]{64}"
    pattern = rf"https?://[^\s\"'<>)]*/tx/{tx_pattern}"
    match = re.search(pattern, text, flags=re.IGNORECASE)
    if match:
        return match.group(0).rstrip(".,;")
    return ""


def _dedupe_strings(values: list[str]) -> list[str]:
    seen: set[str] = set()
    deduped: list[str] = []
    for value in values:
        normalized = " ".join(value.split())
        key = normalized.lower()
        if normalized and key not in seen:
            seen.add(key)
            deduped.append(normalized)
    return deduped


def fetch_security_source_text(url: str) -> dict[str, str]:
    if _requires_specialized_social_fetch(url):
        return {"status": "source_fetch_skipped:social_api_required", "url": url, "text": ""}
    if os.environ.get("ABRA_EVIDENCE_SOURCE_FETCH", "").strip().lower() in {"0", "false", "no", "off"}:
        return {"status": "source_fetch_skipped:disabled", "url": url, "text": ""}
    request = urllib.request.Request(
        url,
        headers={
            "User-Agent": "ABRA/1.0 evidence-backfill (+https://github.com/chainstart/abra)",
            "Accept": "text/html,application/xhtml+xml,text/plain;q=0.9,*/*;q=0.8",
        },
    )
    try:
        with urllib.request.urlopen(request, timeout=20) as response:
            content_type = response.headers.get("content-type", "")
            raw = response.read(1_000_000)
    except urllib.error.HTTPError as exc:
        return {"status": f"http_{exc.code}", "url": url, "text": ""}
    except urllib.error.URLError as exc:
        reason = getattr(exc, "reason", "")
        reason_name = reason.__class__.__name__ if reason else exc.__class__.__name__
        return {"status": f"source_fetch_failed:{reason_name}", "url": url, "text": ""}
    text = raw.decode("utf-8", errors="replace")
    return {"status": "fetched", "url": url, "content_type": content_type, "text": text}


def _requires_specialized_social_fetch(url: str) -> bool:
    host = urlparse(url.strip()).netloc.lower().removeprefix("www.")
    return host in {"x.com", "twitter.com"}


def json_rpc_call(chain: str, method: str, params: list[str]) -> dict[str, Any]:
    rpc_url = rpc_url_for_chain(chain)
    if not rpc_url:
        return {"error": "rpc_url_missing"}
    payload = json.dumps({"jsonrpc": "2.0", "id": 1, "method": method, "params": params}).encode("utf-8")
    request = urllib.request.Request(
        rpc_url,
        data=payload,
        headers={"Content-Type": "application/json", "Accept": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(request, timeout=20) as response:
            raw = response.read(1_000_000)
    except urllib.error.HTTPError as exc:
        return {"error": f"http_{exc.code}"}
    except urllib.error.URLError as exc:
        reason = getattr(exc, "reason", "")
        reason_name = reason.__class__.__name__ if reason else exc.__class__.__name__
        return {"error": f"rpc_transport_failed:{reason_name}"}
    try:
        decoded = json.loads(raw.decode("utf-8", errors="replace"))
    except json.JSONDecodeError:
        return {"error": "rpc_invalid_json"}
    if decoded.get("error"):
        return {"error": "rpc_error", "details": decoded.get("error")}
    result = decoded.get("result")
    return result if isinstance(result, dict) else {"error": "rpc_empty_result"}


def _fetch_fork_block_from_rpc(chain: str, seed_hash: str, rpc_caller: RpcCaller) -> dict[str, str]:
    try:
        receipt = rpc_caller(chain, "eth_getTransactionReceipt", [seed_hash])
    except Exception as exc:  # pragma: no cover - defensive boundary for live RPC failures
        return {"rpc_backfill_status": f"rpc_failed:{exc.__class__.__name__}", "fork_block": ""}
    if not isinstance(receipt, dict):
        return {"rpc_backfill_status": "rpc_invalid_response", "fork_block": ""}
    if receipt.get("error"):
        return {"rpc_backfill_status": str(receipt["error"]), "fork_block": ""}
    block = parse_rpc_int(receipt.get("blockNumber"))
    if block is None:
        return {"rpc_backfill_status": "receipt_missing_block", "fork_block": ""}
    return {"rpc_backfill_status": "receipt_verified", "fork_block": str(block)}


def extract_block_number(text: str) -> int | None:
    for pattern in (
        r"\b(?:fork\s+block|replay\s+block|block\s+number|block|height)\s*[:#]?\s*([0-9][0-9,]{3,})\b",
        r"\bat\s+block\s+([0-9][0-9,]{3,})\b",
    ):
        match = re.search(pattern, text, flags=re.IGNORECASE)
        if match:
            return parse_int(match.group(1))
    return None


def parse_rpc_int(value: Any) -> int | None:
    if isinstance(value, str) and value.startswith("0x"):
        try:
            return int(value, 16)
        except ValueError:
            return None
    return parse_int(value)


def _resolve_repo_path(root: Path, value: str | Path) -> Path:
    path = Path(value).expanduser()
    if path.is_absolute():
        return path
    return root / path


def _read_csv(path: Path) -> list[dict[str, str]]:
    if not path.exists():
        raise FileNotFoundError(f"Incident CSV not found: {path}")
    with path.open("r", encoding="utf-8", newline="") as fp:
        return list(csv.DictReader(fp))


def _write_csv(path: Path, rows: list[dict[str, str]], fieldnames: list[str]) -> None:
    with path.open("w", encoding="utf-8", newline="") as fp:
        writer = csv.DictWriter(fp, fieldnames=fieldnames)
        writer.writeheader()
        for row in rows:
            writer.writerow({field: row.get(field, "") for field in fieldnames})


def _write_json(path: Path, payload: object) -> None:
    path.write_text(json.dumps(payload, indent=2, ensure_ascii=False, sort_keys=True) + "\n", encoding="utf-8")


def _json_cell(value: object) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True)


def _confidence(*, security_anchor: bool, candidate_sources: list[dict[str, str]]) -> str:
    if security_anchor and candidate_sources:
        return "high"
    if security_anchor:
        return "medium"
    return "low"


def extract_seed_transaction_hash(row: dict[str, str]) -> str | None:
    for key in ("seed_transaction_hash", "transaction_hash", "tx_hash", "attack_tx", "tx"):
        value = (row.get(key) or "").strip()
        if is_tx_hash(value):
            return value
    text = " ".join(str(value) for value in row.values())
    match = re.search(r"0x[a-fA-F0-9]{64}", text)
    return match.group(0) if match else None


def is_tx_hash(value: str) -> bool:
    return bool(re.fullmatch(r"0x[a-fA-F0-9]{64}", value or ""))


def parse_int(value: Any) -> int | None:
    try:
        if value in (None, ""):
            return None
        return int(float(str(value).replace(",", "")))
    except (TypeError, ValueError):
        return None


def slugify(value: str) -> str:
    slug = re.sub(r"[^a-z0-9]+", "-", (value or "").lower()).strip("-")
    slug = re.sub(r"^\\d{4}-\\d{2}-\\d{2}-", "", slug)
    slug = re.sub(r"-[a-f0-9]{8}$", "", slug)
    return slug or "incident"


def _sha1(parts: list[str]) -> str:
    import hashlib

    h = hashlib.sha1()
    for part in parts:
        h.update(str(part).encode("utf-8"))
        h.update(b"|")
    return h.hexdigest()


def _utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
