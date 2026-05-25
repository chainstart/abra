#!/usr/bin/env python3
"""Collect direct evidence candidates from replay- and tx-oriented public sources."""

from __future__ import annotations

import argparse
import base64
from concurrent.futures import ThreadPoolExecutor
from functools import lru_cache
import json
import os
import re
import subprocess
import sys
from pathlib import Path
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import urlparse
from urllib.request import Request, urlopen

REPO_ROOT = Path(__file__).resolve().parents[2]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from abra.chain_support import load_local_environment
from common import ensure_dir, now_utc_iso, write_csv, write_json

DEFIHACKLABS_REPO_ROOT = "https://github.com/SunWeb3Sec/DeFiHackLabs"
DEFIHACKLABS_TREE_URL = "https://api.github.com/repos/SunWeb3Sec/DeFiHackLabs/git/trees/main?recursive=1"
DEFIHACKLABS_CONTENTS_URL = "https://api.github.com/repos/SunWeb3Sec/DeFiHackLabs/contents/{path}?ref=main"
DEFIHACKLABS_HTML_URL = "https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/{path}"
DEFIHACKLABS_RAW_URL = "https://raw.githubusercontent.com/SunWeb3Sec/DeFiHackLabs/main/{path}"
USER_AGENT = "abra-direct-evidence/1.0"
GITHUB_API_VERSION = "2022-11-28"
DEFAULT_DIRECT_EVIDENCE_WORKERS = 16
DEFAULT_GITHUB_API_TIMEOUT_SECONDS = 30.0
DEFAULT_GITHUB_RAW_TIMEOUT_SECONDS = 5.0


def _fetch_json(url: str) -> dict[str, Any]:
    request = Request(url, headers=_github_headers())
    with urlopen(request, timeout=_api_timeout_seconds()) as response:
        payload = json.loads(response.read().decode("utf-8", errors="replace"))
    if not isinstance(payload, dict):
        raise ValueError(f"Expected JSON object from {url}")
    return payload


def _fetch_text(url: str) -> str:
    request = Request(url, headers=_github_raw_headers())
    with urlopen(request, timeout=_raw_timeout_seconds()) as response:
        return response.read().decode("utf-8", errors="replace")


def _github_headers() -> dict[str, str]:
    headers = {
        "User-Agent": USER_AGENT,
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": GITHUB_API_VERSION,
    }
    token = _github_token()
    if token:
        headers["Authorization"] = f"Bearer {token}"
    return headers


def _github_raw_headers() -> dict[str, str]:
    headers = {
        "User-Agent": USER_AGENT,
        "Accept": "text/plain",
    }
    token = _github_token()
    if token:
        headers["Authorization"] = f"Bearer {token}"
    return headers


@lru_cache(maxsize=1)
def _github_token() -> str:
    for env_name in ("GITHUB_PERSONAL_ACCESS_TOKEN", "GITHUB_TOKEN", "GH_TOKEN"):
        token = os.environ.get(env_name, "").strip()
        if token:
            return token
    return _git_credential_token()


def _git_credential_token() -> str:
    try:
        completed = subprocess.run(
            ["git", "credential", "fill"],
            input="protocol=https\nhost=github.com\n\n",
            text=True,
            capture_output=True,
            check=True,
            env={**os.environ, "GIT_TERMINAL_PROMPT": "0"},
        )
    except (OSError, subprocess.CalledProcessError):
        return ""
    for line in completed.stdout.splitlines():
        if line.startswith("password="):
            return line.partition("=")[2].strip()
    return ""


def fetch_defihacklabs_tree() -> list[dict[str, str]]:
    payload = _fetch_json(DEFIHACKLABS_TREE_URL)
    items = payload.get("tree")
    if not isinstance(items, list):
        return []
    return [item for item in items if isinstance(item, dict)]


def fetch_defihacklabs_fixture(path: str) -> dict[str, str]:
    html_url = DEFIHACKLABS_HTML_URL.format(path=path)
    download_url = DEFIHACKLABS_RAW_URL.format(path=path)
    try:
        decoded = _fetch_text(download_url)
    except Exception as exc:
        if not _should_fallback_to_contents_api(exc):
            raise
        return _fetch_defihacklabs_fixture_via_contents_api(path)
    return {
        "path": path,
        "html_url": html_url,
        "download_url": download_url,
        "content": decoded,
    }


def _fetch_defihacklabs_fixture_via_contents_api(path: str) -> dict[str, str]:
    payload = _fetch_json(DEFIHACKLABS_CONTENTS_URL.format(path=path))
    content = str(payload.get("content") or "")
    encoding = str(payload.get("encoding") or "")
    if encoding == "base64":
        decoded = base64.b64decode(content).decode("utf-8", errors="replace")
    else:
        decoded = content
    return {
        "path": str(payload.get("path") or path),
        "html_url": str(payload.get("html_url") or DEFIHACKLABS_HTML_URL.format(path=path)),
        "download_url": str(payload.get("download_url") or DEFIHACKLABS_RAW_URL.format(path=path)),
        "content": decoded,
    }


def _should_fallback_to_contents_api(exc: Exception) -> bool:
    if isinstance(exc, URLError):
        return True
    if isinstance(exc, TimeoutError):
        return True
    if isinstance(exc, HTTPError):
        return exc.code in {403, 408, 409, 425, 429, 500, 502, 503, 504}
    return isinstance(exc, OSError)


def _api_timeout_seconds() -> float:
    return _timeout_from_env("ABRA_GITHUB_API_TIMEOUT_SECONDS", DEFAULT_GITHUB_API_TIMEOUT_SECONDS)


def _raw_timeout_seconds() -> float:
    return _timeout_from_env("ABRA_GITHUB_RAW_TIMEOUT_SECONDS", DEFAULT_GITHUB_RAW_TIMEOUT_SECONDS)


def _timeout_from_env(env_name: str, default: float) -> float:
    raw = os.environ.get(env_name, "").strip()
    try:
        value = float(raw) if raw else default
    except ValueError:
        value = default
    return max(0.5, min(value, 60.0))


def collect_direct_evidence(output_dir: Path, max_defihacklabs: int = 250) -> dict[str, Any]:
    """Persist direct evidence candidates from public replay-oriented sources."""

    ensure_dir(output_dir)
    load_local_environment(REPO_ROOT)
    rows, collection_status, collection_warning = _collect_defihacklabs_rows(max_fixtures=max_defihacklabs)

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
        "collection_status": collection_status,
    }
    if collection_warning:
        summary["collection_warning"] = collection_warning
    write_json(latest_json, {"summary": summary, "rows": rows})
    return summary


def _collect_defihacklabs_rows(*, max_fixtures: int) -> tuple[list[dict[str, str]], str, str]:
    rows: list[dict[str, str]] = []
    collection_status = "complete"
    collection_warning = ""
    try:
        items = fetch_defihacklabs_tree()
    except HTTPError as exc:
        if _is_github_rate_limit_error(exc):
            return rows, "rate_limited", _format_rate_limit_warning(exc, DEFIHACKLABS_TREE_URL)
        raise

    fixture_paths = [str(item.get("path") or "") for item in items if _is_defihacklabs_exploit_fixture(str(item.get("path") or ""))]
    workers = _direct_evidence_workers()
    cursor = 0

    while cursor < len(fixture_paths) and len(rows) < max_fixtures:
        remaining = max_fixtures - len(rows)
        batch_span = min(len(fixture_paths) - cursor, max(remaining, workers * 2))
        batch_paths = fixture_paths[cursor : cursor + batch_span]
        cursor += batch_span
        batch_rows, batch_status, batch_warning = _collect_defihacklabs_batch(
            batch_paths,
            max_rows=remaining,
            workers=workers,
        )
        rows.extend(batch_rows)
        if batch_status != "complete":
            collection_status = batch_status
            collection_warning = batch_warning
            break
    return rows[:max_fixtures], collection_status, collection_warning


def _collect_defihacklabs_batch(
    paths: list[str],
    *,
    max_rows: int,
    workers: int,
) -> tuple[list[dict[str, str]], str, str]:
    rows: list[dict[str, str]] = []
    if not paths or max_rows <= 0:
        return rows, "complete", ""

    with ThreadPoolExecutor(max_workers=min(workers, len(paths))) as executor:
        future_entries = [(path, executor.submit(fetch_defihacklabs_fixture, path)) for path in paths]
        for path, future in future_entries:
            try:
                fixture = future.result()
            except HTTPError as exc:
                if _is_github_rate_limit_error(exc):
                    for _pending_path, pending_future in future_entries:
                        pending_future.cancel()
                    return rows, "rate_limited", _format_rate_limit_warning(exc, path)
                raise
            parsed = _parse_defihacklabs_fixture(fixture)
            if parsed:
                rows.append(parsed)
                if len(rows) >= max_rows:
                    for _pending_path, pending_future in future_entries:
                        pending_future.cancel()
                    break
    return rows, "complete", ""


def _direct_evidence_workers() -> int:
    raw = os.environ.get("ABRA_DIRECT_EVIDENCE_WORKERS", "").strip()
    try:
        value = int(raw) if raw else DEFAULT_DIRECT_EVIDENCE_WORKERS
    except ValueError:
        value = DEFAULT_DIRECT_EVIDENCE_WORKERS
    return max(1, min(value, 32))


def _is_github_rate_limit_error(exc: HTTPError) -> bool:
    headers = getattr(exc, "headers", None)
    remaining = ""
    if headers is not None:
        remaining = str(headers.get("X-RateLimit-Remaining", "")).strip()
    text = _http_error_text(exc).lower()
    return exc.code == 429 or remaining == "0" or "rate limit" in text


def _format_rate_limit_warning(exc: HTTPError, subject: str) -> str:
    message = _http_error_text(exc).strip() or str(exc)
    return f"GitHub rate limit hit while fetching {subject}: {message}"


def _http_error_text(exc: HTTPError) -> str:
    body = ""
    try:
        body = exc.read().decode("utf-8", errors="replace")
    except Exception:
        body = ""
    reason = str(exc.reason or "")
    return " ".join(part for part in (reason, body) if part).strip()


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
