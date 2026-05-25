#!/usr/bin/env python3
"""Collect direct evidence candidates from replay- and tx-oriented public sources."""

from __future__ import annotations

import argparse
import base64
import json
import re
from pathlib import Path
from typing import Any
from urllib.parse import urlparse
from urllib.request import Request, urlopen

from common import ensure_dir, now_utc_iso, write_csv, write_json

DEFIHACKLABS_REPO_ROOT = "https://github.com/SunWeb3Sec/DeFiHackLabs"
DEFIHACKLABS_TREE_URL = "https://api.github.com/repos/SunWeb3Sec/DeFiHackLabs/git/trees/main?recursive=1"
DEFIHACKLABS_CONTENTS_URL = "https://api.github.com/repos/SunWeb3Sec/DeFiHackLabs/contents/{path}?ref=main"
USER_AGENT = "abra-direct-evidence/1.0"


def _fetch_json(url: str) -> dict[str, Any]:
    request = Request(url, headers={"User-Agent": USER_AGENT, "Accept": "application/json"})
    with urlopen(request, timeout=30) as response:
        payload = json.loads(response.read().decode("utf-8", errors="replace"))
    if not isinstance(payload, dict):
        raise ValueError(f"Expected JSON object from {url}")
    return payload


def fetch_defihacklabs_tree() -> list[dict[str, str]]:
    payload = _fetch_json(DEFIHACKLABS_TREE_URL)
    items = payload.get("tree")
    if not isinstance(items, list):
        return []
    return [item for item in items if isinstance(item, dict)]


def fetch_defihacklabs_fixture(path: str) -> dict[str, str]:
    payload = _fetch_json(DEFIHACKLABS_CONTENTS_URL.format(path=path))
    content = str(payload.get("content") or "")
    encoding = str(payload.get("encoding") or "")
    if encoding == "base64":
        decoded = base64.b64decode(content).decode("utf-8", errors="replace")
    else:
        decoded = content
    return {
        "path": str(payload.get("path") or path),
        "html_url": str(payload.get("html_url") or ""),
        "download_url": str(payload.get("download_url") or ""),
        "content": decoded,
    }


def collect_direct_evidence(output_dir: Path, max_defihacklabs: int = 250) -> dict[str, Any]:
    """Persist direct evidence candidates from public replay-oriented sources."""

    ensure_dir(output_dir)
    rows = _collect_defihacklabs_rows(max_fixtures=max_defihacklabs)

    latest_csv = output_dir / "direct_evidence_latest.csv"
    latest_json = output_dir / "direct_evidence_latest.json"
    fieldnames = [
        "incident_id",
        "event_date",
        "target",
        "description",
        "loss_usd_raw",
        "loss_usd",
        "attack_method",
        "chain",
        "reference_url",
        "source_url",
        "source_page",
        "category_filter",
        "seed_transaction_hash",
        "fork_block",
        "direct_source_name",
        "collected_at",
    ]
    write_csv(latest_csv, rows, fieldnames)
    summary = {
        "source": "direct_evidence_sources",
        "generated_at": now_utc_iso(),
        "direct_candidate_count": len(rows),
        "defihacklabs_candidate_count": len(rows),
        "direct_evidence_csv": str(latest_csv),
    }
    write_json(latest_json, {"summary": summary, "rows": rows})
    return summary


def _collect_defihacklabs_rows(*, max_fixtures: int) -> list[dict[str, str]]:
    rows: list[dict[str, str]] = []
    for item in fetch_defihacklabs_tree():
        path = str(item.get("path") or "")
        if not _is_defihacklabs_exploit_fixture(path):
            continue
        fixture = fetch_defihacklabs_fixture(path)
        parsed = _parse_defihacklabs_fixture(fixture)
        if parsed:
            rows.append(parsed)
        if len(rows) >= max_fixtures:
            break
    return rows


def _is_defihacklabs_exploit_fixture(path: str) -> bool:
    return bool(re.fullmatch(r"src/test/\d{4}-\d{2}/[^/]+_exp\.sol", path))


def _parse_defihacklabs_fixture(fixture: dict[str, str]) -> dict[str, str]:
    path = str(fixture.get("path") or "")
    html_url = str(fixture.get("html_url") or "")
    text = str(fixture.get("content") or "")
    year_month, target = _fixture_period_and_target(path)
    if not year_month or not target:
        return {}
    event_date = f"{year_month}-01"
    tx_hash = _extract_tx_hash(text)
    fork_block = _extract_fork_block(text)
    chain = _extract_chain(text, tx_hash)
    return {
        "incident_id": f"defihacklabs-{year_month}-{_slug(target)}",
        "event_date": event_date,
        "target": target,
        "description": _extract_description(text),
        "loss_usd_raw": "",
        "loss_usd": "",
        "attack_method": _extract_attack_method(text),
        "chain": chain,
        "reference_url": html_url or DEFIHACKLABS_REPO_ROOT,
        "source_url": DEFIHACKLABS_REPO_ROOT,
        "source_page": "",
        "category_filter": "defihacklabs_replay",
        "seed_transaction_hash": tx_hash,
        "fork_block": "" if fork_block is None else str(fork_block),
        "direct_source_name": "defihacklabs",
        "collected_at": now_utc_iso(),
    }


def _fixture_period_and_target(path: str) -> tuple[str, str]:
    match = re.fullmatch(r"src/test/(\d{4}-\d{2})/([^/]+)_exp\.sol", path)
    if not match:
        return "", ""
    year_month = match.group(1)
    target = match.group(2).replace("_", " ").strip()
    return year_month, target


def _extract_tx_hash(text: str) -> str:
    match = re.search(r"0x[a-fA-F0-9]{64}", text)
    return match.group(0) if match else ""


def _extract_fork_block(text: str) -> int | None:
    constants: dict[str, int] = {}
    for match in re.finditer(r"uint256\s+\w+\s+constant\s+([A-Z_]+)\s*=\s*([^;]+);", text):
        name = match.group(1)
        value = _parse_uint_expression(match.group(2), constants)
        if value is not None:
            constants[name] = value
    if "FORK_BLOCK" in constants:
        return constants["FORK_BLOCK"]
    if "ATTACK_BLOCK" in constants:
        return constants["ATTACK_BLOCK"]
    return None


def _parse_uint_expression(expression: str, constants: dict[str, int]) -> int | None:
    expr = re.sub(r"(?<=\d)_(?=\d)", "", expression.strip())
    if expr.isdigit():
        return int(expr)
    minus = re.fullmatch(r"([A-Z_]+)\s*-\s*(\d+)", expr)
    if minus:
        base = constants.get(minus.group(1))
        return None if base is None else base - int(minus.group(2))
    plus = re.fullmatch(r"([A-Z_]+)\s*\+\s*(\d+)", expr)
    if plus:
        base = constants.get(plus.group(1))
        return None if base is None else base + int(plus.group(2))
    return constants.get(expr)


def _extract_chain(text: str, tx_hash: str) -> str:
    match = re.search(r"Attack Tx\s*\(([^)]+)\)", text, flags=re.IGNORECASE)
    if match:
        return _normalize_chain_label(match.group(1))
    fork_match = re.search(r'createSelectFork\("([^"]+)"', text)
    if fork_match:
        return _normalize_chain_label(fork_match.group(1))
    tx_url = _extract_transaction_url(text, tx_hash)
    if tx_url:
        host = urlparse(tx_url).netloc.lower()
        host_map = {
            "etherscan.io": "ethereum",
            "bscscan.com": "bsc",
            "arbiscan.io": "arbitrum",
            "basescan.org": "base",
            "polygonscan.com": "polygon",
            "snowtrace.io": "avalanche",
            "optimistic.etherscan.io": "optimism",
            "celoscan.io": "celo",
            "zkevm.polygonscan.com": "polygon_zkevm",
            "era.zksync.network": "zksync",
        }
        for domain, chain in host_map.items():
            if host == domain or host.endswith(f".{domain}"):
                return chain
    return ""


def _normalize_chain_label(label: str) -> str:
    lowered = label.strip().lower().replace(" ", "_").replace("-", "_")
    aliases = {
        "eth": "ethereum",
        "ethereum": "ethereum",
        "bsc": "bsc",
        "bnb": "bsc",
        "bnb_chain": "bsc",
        "arb": "arbitrum",
        "arbitrum": "arbitrum",
        "base": "base",
        "polygon": "polygon",
        "avax": "avalanche",
        "avalanche": "avalanche",
        "op": "optimism",
        "optimism": "optimism",
        "celo": "celo",
        "zksync": "zksync",
        "polygon_zkevm": "polygon_zkevm",
    }
    return aliases.get(lowered, lowered)


def _extract_transaction_url(text: str, tx_hash: str) -> str:
    if tx_hash:
        match = re.search(rf"https?://[^\s\"')]+{re.escape(tx_hash)}", text, flags=re.IGNORECASE)
        if match:
            return match.group(0).rstrip(".,;")
    match = re.search(r"https?://[^\s\"')]+/tx/[^\s\"')]+", text, flags=re.IGNORECASE)
    return match.group(0).rstrip(".,;") if match else ""


def _extract_description(text: str) -> str:
    for prefix in ("Root cause:", "@KeyInfo", "// @KeyInfo"):
        for line in text.splitlines():
            cleaned = line.strip().lstrip("/").strip()
            if cleaned.startswith(prefix):
                return cleaned
    for line in text.splitlines():
        if not line.strip().startswith("//"):
            continue
        cleaned = line.strip().lstrip("/").strip()
        if cleaned and not _is_boilerplate_fixture_line(cleaned):
            return cleaned
    return ""


def _is_boilerplate_fixture_line(line: str) -> bool:
    lowered = line.lower()
    if lowered.startswith(("spdx-license-identifier", "pragma solidity", "import ")):
        return True
    if lowered.startswith(("contract ", "interface ", "library ", "function ")):
        return True
    return False


def _extract_attack_method(text: str) -> str:
    for label in ("Root cause:", "@KeyInfo"):
        if label.lower() in text.lower():
            return "Replay Fixture"
    return ""


def _slug(value: str) -> str:
    return re.sub(r"[^a-z0-9]+", "-", value.lower()).strip("-")


def main() -> None:
    parser = argparse.ArgumentParser(description="Collect direct evidence candidates from public replay-oriented sources")
    parser.add_argument("--output-dir", default="data/raw/direct_evidence", help="Output directory")
    parser.add_argument("--max-defihacklabs", type=int, default=250, help="Maximum DeFiHackLabs fixtures to ingest")
    args = parser.parse_args()

    summary = collect_direct_evidence(Path(args.output_dir), max_defihacklabs=args.max_defihacklabs)
    print(f"[direct-evidence] collected {summary['direct_candidate_count']} candidates")
    print(f"[direct-evidence] latest csv: {summary['direct_evidence_csv']}")


if __name__ == "__main__":
    main()
