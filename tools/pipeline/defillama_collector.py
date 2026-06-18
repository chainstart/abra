#!/usr/bin/env python3
"""Collect protocol and chain snapshots from DefiLlama API."""

from __future__ import annotations

import argparse
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[2]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from abra.runtime_bootstrap import ensure_repo_runtime
from common import ensure_dir, now_utc_iso, write_csv, write_json

CHAIN_URL = "https://api.llama.fi/chains"
PROTOCOLS_URL = "https://api.llama.fi/protocols"
HACKS_URL = "https://api.llama.fi/hacks"
USER_AGENT = "abra-research-bot/1.0"
_REQUESTS = None


def _requests_runtime() -> Any:
    global _REQUESTS
    if _REQUESTS is None:
        ensure_repo_runtime(REPO_ROOT, required_modules=("requests",))
        import requests as requests_module

        _REQUESTS = requests_module
    return _REQUESTS


def fetch_json(session: requests.Session, url: str) -> Any:
    """Fetch JSON from API endpoint."""
    resp = session.get(url, timeout=45)
    resp.raise_for_status()
    return resp.json()


def collect_defillama(output_dir: Path, top_n: int) -> dict[str, Any]:
    """Collect raw and slim datasets from DefiLlama."""
    ensure_dir(output_dir)
    requests_module = _requests_runtime()
    session = requests_module.Session()
    session.headers.update({"User-Agent": USER_AGENT})

    chains = fetch_json(session, CHAIN_URL)
    protocols = fetch_json(session, PROTOCOLS_URL)
    hacks = fetch_json(session, HACKS_URL)

    protocols_sorted = sorted(
        protocols,
        key=lambda x: float(x.get("tvl") or 0),
        reverse=True,
    )
    top_protocols = protocols_sorted[:top_n]

    timestamp = now_utc_iso().replace(":", "").replace("-", "")
    chains_json = output_dir / f"defillama_chains_{timestamp}.json"
    protocols_json = output_dir / f"defillama_protocols_{timestamp}.json"
    top_json = output_dir / f"defillama_top{top_n}_{timestamp}.json"
    chains_latest = output_dir / "defillama_chains_latest.json"
    protocols_latest = output_dir / "defillama_protocols_latest.json"
    top_latest = output_dir / f"defillama_top{top_n}_latest.json"
    protocols_slim_csv = output_dir / "defillama_protocols_slim_latest.csv"
    chains_slim_csv = output_dir / "defillama_chains_slim_latest.csv"
    hacks_latest_json = output_dir / "defillama_hacks_latest.json"
    hacks_slim_csv = output_dir / "defillama_hacks_latest.csv"

    write_json(chains_json, chains)
    write_json(protocols_json, protocols)
    write_json(top_json, top_protocols)
    write_json(chains_latest, chains)
    write_json(protocols_latest, protocols)
    write_json(top_latest, top_protocols)
    write_json(hacks_latest_json, hacks)

    protocol_rows = []
    for p in protocols_sorted:
        chains_list = p.get("chains") or []
        protocol_rows.append(
            {
                "id": p.get("id", ""),
                "name": p.get("name", ""),
                "slug": p.get("slug", ""),
                "category": p.get("category", ""),
                "parent_protocol": p.get("parentProtocol", ""),
                "tvl": p.get("tvl", ""),
                "chain": p.get("chain", ""),
                "chains_count": len(chains_list),
                "chains": "|".join(chains_list),
                "audits": p.get("audits", ""),
                "listed_at": p.get("listedAt", ""),
                "url": p.get("url", ""),
                "module": p.get("module", ""),
                "methodology": p.get("methodology", ""),
            }
        )

    chain_rows = []
    for c in chains:
        chain_rows.append(
            {
                "name": c.get("name", ""),
                "chain_id": c.get("chainId", ""),
                "token_symbol": c.get("tokenSymbol", ""),
                "gecko_id": c.get("gecko_id", ""),
                "cmc_id": c.get("cmcId", ""),
                "tvl": c.get("tvl", ""),
            }
        )

    hack_rows = []
    for item in hacks if isinstance(hacks, list) else []:
        if not isinstance(item, dict):
            continue
        name = str(item.get("name") or "").strip()
        timestamp_value = item.get("date")
        event_date = _unix_date(timestamp_value)
        chains_list = item.get("chain") if isinstance(item.get("chain"), list) else []
        technique = str(item.get("technique") or "").strip()
        classification = str(item.get("classification") or "").strip()
        source_url = "https://defillama.com/hacks"
        reference_url = str(item.get("source") or "").strip()
        hack_rows.append(
            {
                "incident_id": f"defillama-{event_date}-{_slug(name)}",
                "event_date": event_date,
                "target": name,
                "description": f"DefiLlama hacks entry: {classification} / {technique}".strip(),
                "loss_usd_raw": item.get("amount", ""),
                "loss_usd": item.get("amount", ""),
                "attack_method": technique,
                "classification": classification,
                "chain": "|".join(str(chain) for chain in chains_list),
                "target_type": item.get("targetType", ""),
                "reference_url": reference_url,
                "source_url": source_url,
                "defillama_id": item.get("defillamaId", ""),
                "bridge_hack": item.get("bridgeHack", ""),
                "returned_funds": item.get("returnedFunds", ""),
                "language": item.get("language", ""),
                "collected_at": now_utc_iso(),
            }
        )

    write_csv(
        protocols_slim_csv,
        protocol_rows,
        [
            "id",
            "name",
            "slug",
            "category",
            "parent_protocol",
            "tvl",
            "chain",
            "chains_count",
            "chains",
            "audits",
            "listed_at",
            "url",
            "module",
            "methodology",
        ],
    )
    write_csv(
        chains_slim_csv,
        chain_rows,
        ["name", "chain_id", "token_symbol", "gecko_id", "cmc_id", "tvl"],
    )
    write_csv(
        hacks_slim_csv,
        hack_rows,
        [
            "incident_id",
            "event_date",
            "target",
            "description",
            "loss_usd_raw",
            "loss_usd",
            "attack_method",
            "classification",
            "chain",
            "target_type",
            "reference_url",
            "source_url",
            "defillama_id",
            "bridge_hack",
            "returned_funds",
            "language",
            "collected_at",
        ],
    )

    summary = {
        "source": "api.llama.fi",
        "protocol_count": len(protocols),
        "chain_count": len(chains),
        "hack_count": len(hack_rows),
        "top_n": top_n,
        "top_protocol_count": len(top_protocols),
        "protocols_latest_json": str(protocols_latest),
        "chains_latest_json": str(chains_latest),
        "hacks_latest_json": str(hacks_latest_json),
        "protocols_slim_csv": str(protocols_slim_csv),
        "chains_slim_csv": str(chains_slim_csv),
        "hacks_slim_csv": str(hacks_slim_csv),
        "generated_at": now_utc_iso(),
    }
    write_json(output_dir / "defillama_collection_summary_latest.json", summary)
    return summary


def _unix_date(value: Any) -> str:
    try:
        seconds = int(float(value))
    except (TypeError, ValueError):
        return ""
    return datetime.fromtimestamp(seconds, timezone.utc).strftime("%Y-%m-%d")


def _slug(value: str) -> str:
    import re

    return re.sub(r"[^a-z0-9]+", "-", value.lower()).strip("-") or "incident"


def main() -> None:
    parser = argparse.ArgumentParser(description="Collect DefiLlama protocol/chain snapshots")
    parser.add_argument("--top-n", type=int, default=300, help="Number of top protocols by TVL to snapshot")
    parser.add_argument("--output-dir", default="data/raw/defillama", help="Output directory")
    args = parser.parse_args()

    summary = collect_defillama(output_dir=Path(args.output_dir), top_n=args.top_n)
    print(
        f"[defillama] collected {summary['protocol_count']} protocols and "
        f"{summary['chain_count']} chains and {summary['hack_count']} hacks"
    )
    print(f"[defillama] latest protocols csv: {summary['protocols_slim_csv']}")


if __name__ == "__main__":
    main()
