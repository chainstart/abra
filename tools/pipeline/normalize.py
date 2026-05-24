#!/usr/bin/env python3
"""Normalize raw datasets into analysis-ready CSV tables."""

from __future__ import annotations

import argparse
import re
from collections import defaultdict
from pathlib import Path

from common import (
    ensure_dir,
    normalize_text,
    now_utc_iso,
    parse_loss_usd,
    read_csv,
    write_csv,
)


DEFI_KEYWORDS = [
    "defi",
    "lending",
    "borrow",
    "liquidation",
    "oracle",
    "flash loan",
    "flashloan",
    "amm",
    "dex",
    "pool",
    "liquidity",
    "vault",
    "staking",
    "restaking",
    "yield",
    "bridge",
    "swap",
    "market",
    "protocol",
    "token",
]

GENERIC_PROTOCOL_TOKENS = {
    "finance",
    "protocol",
    "swap",
    "dex",
    "dao",
    "network",
    "token",
    "pool",
    "labs",
    "chain",
    "market",
}


def classify_attack_family(attack_method: str, description: str) -> str:
    """Map raw method text to coarse attack family labels."""
    method_text = (attack_method or "").lower()
    text = f"{attack_method} {description}".lower()
    if "reentrancy" in method_text or "reentrancy" in text:
        return "reentrancy"
    if "governance" in method_text or "governance" in text:
        return "governance"
    if "flash loan" in method_text or "flash loan" in text:
        return "flash_loan"
    if "oracle" in method_text or "oracle" in text or "price manipulation" in text:
        return "oracle_manipulation"
    if "bridge" in text or "cross-chain" in text:
        return "bridge_message"
    if "social engineering" in text or "phishing" in text or "dns" in text:
        return "social_engineering"
    if "account compromise" in text or "private key" in text:
        return "account_compromise"
    if "supply chain" in text:
        return "supply_chain"
    if "logic" in text or "business logic" in text:
        return "logic_bug"
    if "access control" in text or "permission" in text:
        return "access_control"
    if "contract vulnerability" in text:
        return "contract_bug"
    return "other"


def build_protocol_index(protocol_rows: list[dict]) -> tuple[list[dict], dict[str, list[int]], dict[str, str]]:
    """Build lookup indexes for fast protocol matching."""
    entries: list[dict] = []
    token_index: dict[str, list[int]] = defaultdict(list)
    exact_norm: dict[str, str] = {}

    for row in protocol_rows:
        name = (row.get("name", "") or "").strip()
        slug = (row.get("slug", "") or "").strip()
        if not name or not slug:
            continue
        name_lower = name.lower()
        name_norm = normalize_text(name_lower)
        if len(name_norm) < 4:
            continue

        proto_tokens = [t for t in re.findall(r"[a-z0-9]+", name_lower) if len(t) >= 4]
        sig_tokens = [t for t in proto_tokens if t not in GENERIC_PROTOCOL_TOKENS]
        if not sig_tokens:
            continue

        idx = len(entries)
        entry = {
            "name_lower": name_lower,
            "name_norm": name_norm,
            "slug": slug,
            "sig_tokens": set(sig_tokens),
            "score": len(name_norm),
        }
        entries.append(entry)

        for token in set(sig_tokens):
            token_index[token].append(idx)

        prev_slug = exact_norm.get(name_norm)
        if not prev_slug:
            exact_norm[name_norm] = slug

    return entries, token_index, exact_norm


def guess_protocol_slug(
    target: str,
    entries: list[dict],
    token_index: dict[str, list[int]],
    exact_norm: dict[str, str],
) -> str:
    """Attempt to match target text to a known DefiLlama protocol slug."""
    target_lower = (target or "").lower()
    target_norm = normalize_text(target_lower)
    target_tokens = set(re.findall(r"[a-z0-9]+", target_lower))
    if not target_lower:
        return ""

    slug = exact_norm.get(target_norm)
    if slug:
        return slug

    candidate_indexes: set[int] = set()
    for token in target_tokens:
        for idx in token_index.get(token, []):
            candidate_indexes.add(idx)

    if not candidate_indexes:
        return ""

    candidates = sorted(
        (entries[idx] for idx in candidate_indexes),
        key=lambda x: x["score"],
        reverse=True,
    )

    for candidate in candidates:
        name_lower = candidate["name_lower"]
        sig_tokens = candidate["sig_tokens"]
        slug = candidate["slug"]

        if name_lower in target_lower:
            return slug
        if len(sig_tokens) >= 2 and sig_tokens.issubset(target_tokens):
            return slug
        if len(sig_tokens) == 1:
            single = next(iter(sig_tokens))
            if len(single) >= 6 and single in target_tokens:
                return slug
    return ""


def is_defi_event(target: str, description: str, attack_method: str, protocol_slug: str) -> bool:
    """Heuristic DeFi classification."""
    combined = f"{target} {description} {attack_method}".lower()
    if protocol_slug:
        return True
    if "account compromise" in combined and "contract" not in combined:
        return False
    if "social engineering" in combined and "protocol" not in combined and "pool" not in combined:
        return False
    return any(keyword in combined for keyword in DEFI_KEYWORDS)


def normalize_datasets(
    slowmist_csv: Path,
    defillama_protocols_csv: Path,
    output_dir: Path,
    defillama_hacks_csv: Path | None = None,
) -> dict[str, str | int]:
    """Build normalized incidents and protocol tables."""
    ensure_dir(output_dir)

    slowmist_rows = read_csv(slowmist_csv)
    defillama_hack_rows = read_csv(defillama_hacks_csv) if defillama_hacks_csv and defillama_hacks_csv.exists() else []
    protocols_rows = read_csv(defillama_protocols_csv)

    entries, token_index, exact_norm = build_protocol_index(protocols_rows)

    normalized_incidents = []
    for row in slowmist_rows:
        target = row.get("target", "")
        description = row.get("description", "")
        attack_method = row.get("attack_method", "")
        protocol_slug = guess_protocol_slug(target, entries, token_index, exact_norm)
        loss_raw = row.get("loss_usd_raw", "")
        loss_val = parse_loss_usd(loss_raw)
        family = classify_attack_family(attack_method, description)
        defi_flag = is_defi_event(target, description, attack_method, protocol_slug)

        normalized_incidents.append(
            {
                "incident_id": row.get("incident_id", ""),
                "event_date": row.get("event_date", ""),
                "target": target,
                "protocol_slug_guess": protocol_slug,
                "is_defi": str(defi_flag).lower(),
                "attack_method_raw": attack_method,
                "attack_family": family,
                "loss_usd_raw": loss_raw,
                "loss_usd": "" if loss_val is None else f"{loss_val:.2f}",
                "chain": "",
                "reference_url": row.get("reference_url", ""),
                "source_url": row.get("source_url", ""),
                "source_page": row.get("source_page", ""),
                "category_filter": row.get("category_filter", ""),
                "description": description,
                "normalized_at": now_utc_iso(),
            }
        )
    for row in defillama_hack_rows:
        target = row.get("target", "")
        description = row.get("description", "")
        attack_method = row.get("attack_method", "")
        protocol_slug = guess_protocol_slug(target, entries, token_index, exact_norm)
        loss_val = parse_loss_usd(str(row.get("loss_usd_raw") or row.get("loss_usd") or ""))
        family = classify_attack_family(attack_method or row.get("classification", ""), description)
        defi_flag = is_defi_event(target, description, attack_method, protocol_slug) or _is_defillama_defi_hack(row)
        normalized_incidents.append(
            {
                "incident_id": row.get("incident_id", ""),
                "event_date": row.get("event_date", ""),
                "target": target,
                "protocol_slug_guess": protocol_slug,
                "is_defi": str(defi_flag).lower(),
                "attack_method_raw": attack_method,
                "attack_family": family,
                "loss_usd_raw": row.get("loss_usd_raw", ""),
                "loss_usd": "" if loss_val is None else f"{loss_val:.2f}",
                "chain": row.get("chain", ""),
                "reference_url": row.get("reference_url", ""),
                "source_url": row.get("source_url", ""),
                "source_page": "",
                "category_filter": "defillama_hacks",
                "description": description,
                "normalized_at": now_utc_iso(),
            }
        )

    normalized_protocols = []
    for row in protocols_rows:
        normalized_protocols.append(
            {
                "protocol_id": row.get("id", ""),
                "name": row.get("name", ""),
                "slug": row.get("slug", ""),
                "category": row.get("category", ""),
                "parent_protocol": row.get("parent_protocol", ""),
                "tvl": row.get("tvl", ""),
                "primary_chain": row.get("chain", ""),
                "chains_count": row.get("chains_count", ""),
                "chains": row.get("chains", ""),
                "audits": row.get("audits", ""),
                "listed_at": row.get("listed_at", ""),
                "url": row.get("url", ""),
                "normalized_at": now_utc_iso(),
            }
        )

    incidents_out = output_dir / "incidents_normalized_latest.csv"
    protocols_out = output_dir / "protocols_normalized_latest.csv"
    write_csv(
        incidents_out,
        normalized_incidents,
        [
            "incident_id",
            "event_date",
            "target",
            "protocol_slug_guess",
            "is_defi",
            "attack_method_raw",
            "attack_family",
            "loss_usd_raw",
            "loss_usd",
            "chain",
            "reference_url",
            "source_url",
            "source_page",
            "category_filter",
            "description",
            "normalized_at",
        ],
    )
    write_csv(
        protocols_out,
        normalized_protocols,
        [
            "protocol_id",
            "name",
            "slug",
            "category",
            "parent_protocol",
            "tvl",
            "primary_chain",
            "chains_count",
            "chains",
            "audits",
            "listed_at",
            "url",
            "normalized_at",
        ],
    )

    return {
        "incident_rows": len(normalized_incidents),
        "protocol_rows": len(normalized_protocols),
        "incidents_output": str(incidents_out),
        "protocols_output": str(protocols_out),
    }


def _is_defillama_defi_hack(row: dict) -> bool:
    text = " ".join(
        [
            str(row.get("target_type") or ""),
            str(row.get("classification") or ""),
            str(row.get("description") or ""),
        ]
    ).lower()
    return "defi" in text or "protocol" in text or "bridge" in text


def main() -> None:
    parser = argparse.ArgumentParser(description="Normalize raw incident/protocol datasets")
    parser.add_argument(
        "--slowmist-csv",
        default="data/raw/slowmist/slowmist_events_latest.csv",
        help="Input CSV from slowmist_collector.py",
    )
    parser.add_argument(
        "--defillama-protocols-csv",
        default="data/raw/defillama/defillama_protocols_slim_latest.csv",
        help="Input protocol CSV from defillama_collector.py",
    )
    parser.add_argument(
        "--defillama-hacks-csv",
        default="data/raw/defillama/defillama_hacks_latest.csv",
        help="Optional DefiLlama hacks CSV from defillama_collector.py",
    )
    parser.add_argument("--output-dir", default="data/processed", help="Output directory")
    args = parser.parse_args()

    summary = normalize_datasets(
        slowmist_csv=Path(args.slowmist_csv),
        defillama_protocols_csv=Path(args.defillama_protocols_csv),
        output_dir=Path(args.output_dir),
        defillama_hacks_csv=Path(args.defillama_hacks_csv),
    )
    print(
        f"[normalize] incidents: {summary['incident_rows']} | "
        f"protocols: {summary['protocol_rows']}"
    )
    print(f"[normalize] incidents csv: {summary['incidents_output']}")


if __name__ == "__main__":
    main()
