#!/usr/bin/env python3
"""Collect incident events from hacked.slowmist.io pages."""

from __future__ import annotations

import argparse
import re
import sys
import time
from pathlib import Path
from typing import Any
from urllib.parse import quote

REPO_ROOT = Path(__file__).resolve().parents[2]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from abra.runtime_bootstrap import ensure_repo_runtime
from common import ensure_dir, now_utc_iso, parse_loss_usd, sha1_id, write_csv, write_json

BASE_URL = "https://hacked.slowmist.io/"
USER_AGENT = "abra-research-bot/1.0"
_REQUESTS = None
_BEAUTIFULSOUP = None


def _slowmist_runtime() -> tuple[Any, Any]:
    global _REQUESTS, _BEAUTIFULSOUP
    if _REQUESTS is None or _BEAUTIFULSOUP is None:
        ensure_repo_runtime(REPO_ROOT, required_modules=("requests", "bs4"))
        import requests as requests_module
        from bs4 import BeautifulSoup as beautifulsoup_class

        _REQUESTS = requests_module
        _BEAUTIFULSOUP = beautifulsoup_class
    return _REQUESTS, _BEAUTIFULSOUP


def fetch_html(session: requests.Session, page: int, category: str) -> str:
    """Fetch one SlowMist index page as HTML text."""
    category_q = quote(category) if category else ""
    url = f"{BASE_URL}?c={category_q}&page={page}"
    resp = session.get(url, timeout=30)
    resp.raise_for_status()
    return resp.text


def parse_total_pages(html: str) -> int | None:
    """Extract total page count from pagination text."""
    _requests_module, beautifulsoup_class = _slowmist_runtime()
    soup = beautifulsoup_class(html, "html.parser")
    node = soup.find(string=re.compile(r"Page\s+\d+\s+of\s+\d+", re.IGNORECASE))
    if not node:
        return None
    m = re.search(r"Page\s+\d+\s+of\s+(\d+)", str(node), re.IGNORECASE)
    return int(m.group(1)) if m else None


def parse_events(html: str, page: int, category: str) -> list[dict[str, Any]]:
    """Parse events from one page."""
    _requests_module, beautifulsoup_class = _slowmist_runtime()
    soup = beautifulsoup_class(html, "html.parser")
    rows: list[dict[str, Any]] = []

    event_nodes = soup.select("div.case-content > ul > li")
    for node in event_nodes:
        date_node = node.select_one("span.time")
        target_node = node.select_one("h3")
        ref_node = node.select_one("p.link-reference a")

        ps = node.find_all("p", recursive=False)
        desc_raw = ""
        loss_raw = ""
        attack_method = ""

        for p in ps:
            text = p.get_text(" ", strip=True)
            if text.startswith("Description of the event:"):
                desc_raw = text.replace("Description of the event:", "", 1).strip()
            if "Amount of loss:" in text and "Attack method:" in text:
                spans = p.find_all("span")
                if len(spans) >= 1:
                    loss_raw = spans[0].get_text(" ", strip=True).replace("Amount of loss:", "").strip()
                if len(spans) >= 2:
                    attack_method = spans[1].get_text(" ", strip=True).replace("Attack method:", "").strip()

        event_date = date_node.get_text(strip=True) if date_node else ""
        target_text = ""
        if target_node:
            target_text = target_node.get_text(" ", strip=True).replace("Hacked target:", "").strip()

        reference_url = ref_node.get("href", "").strip() if ref_node else ""
        if reference_url and not reference_url.startswith("http"):
            reference_url = ""
        source_url = f"{BASE_URL}?c={quote(category) if category else ''}&page={page}"
        incident_id = sha1_id([event_date, target_text, attack_method, loss_raw, reference_url])

        rows.append(
            {
                "incident_id": incident_id,
                "event_date": event_date,
                "target": target_text,
                "description": desc_raw,
                "loss_usd_raw": loss_raw,
                "loss_usd": parse_loss_usd(loss_raw),
                "attack_method": attack_method,
                "reference_url": reference_url,
                "source_url": source_url,
                "source_page": page,
                "category_filter": category or "all",
                "collected_at": now_utc_iso(),
            }
        )

    return rows


def collect_events(
    start_page: int,
    end_page: int | None,
    category: str,
    delay_seconds: float,
    save_html: bool,
    output_dir: Path,
) -> dict[str, Any]:
    """Collect and persist SlowMist event data."""
    ensure_dir(output_dir)
    ensure_dir(output_dir / "html")

    requests_module, _beautifulsoup_class = _slowmist_runtime()
    session = requests_module.Session()
    session.headers.update({"User-Agent": USER_AGENT})

    page = start_page
    all_rows: list[dict[str, Any]] = []
    discovered_total_pages: int | None = None

    if end_page is None:
        bootstrap_html = fetch_html(session, start_page, category)
        discovered_total_pages = parse_total_pages(bootstrap_html)
        end_page = discovered_total_pages or start_page
        if save_html:
            (output_dir / "html" / f"slowmist_page_{start_page:04d}.html").write_text(
                bootstrap_html,
                encoding="utf-8",
            )
        all_rows.extend(parse_events(bootstrap_html, start_page, category))
        page = start_page + 1
        if delay_seconds > 0:
            time.sleep(delay_seconds)

    while page <= end_page:
        html = fetch_html(session, page, category)
        if save_html:
            (output_dir / "html" / f"slowmist_page_{page:04d}.html").write_text(
                html,
                encoding="utf-8",
            )
        all_rows.extend(parse_events(html, page, category))
        page += 1
        if delay_seconds > 0:
            time.sleep(delay_seconds)

    timestamp = now_utc_iso().replace(":", "").replace("-", "")
    csv_snapshot = output_dir / f"slowmist_events_{start_page}_{end_page}_{timestamp}.csv"
    csv_latest = output_dir / "slowmist_events_latest.csv"
    json_snapshot = output_dir / f"slowmist_events_{start_page}_{end_page}_{timestamp}.json"
    json_latest = output_dir / "slowmist_events_latest.json"

    fieldnames = [
        "incident_id",
        "event_date",
        "target",
        "description",
        "loss_usd_raw",
        "loss_usd",
        "attack_method",
        "reference_url",
        "source_url",
        "source_page",
        "category_filter",
        "collected_at",
    ]
    write_csv(csv_snapshot, all_rows, fieldnames)
    write_csv(csv_latest, all_rows, fieldnames)

    summary = {
        "source": "hacked.slowmist.io",
        "category_filter": category or "all",
        "start_page": start_page,
        "end_page": end_page,
        "discovered_total_pages": discovered_total_pages,
        "event_count": len(all_rows),
        "csv_snapshot": str(csv_snapshot),
        "csv_latest": str(csv_latest),
        "generated_at": now_utc_iso(),
    }
    write_json(json_snapshot, {"summary": summary, "events": all_rows})
    write_json(json_latest, {"summary": summary, "events": all_rows})
    return summary


def main() -> None:
    parser = argparse.ArgumentParser(description="Collect incidents from hacked.slowmist.io")
    parser.add_argument("--start-page", type=int, default=1, help="Start page number")
    parser.add_argument(
        "--end-page",
        type=int,
        default=None,
        help="End page number (omit to auto-detect total pages)",
    )
    parser.add_argument("--category", default="", help="SlowMist category filter, e.g. ETH/BSC/Bridge")
    parser.add_argument("--delay-seconds", type=float, default=0.15, help="Delay between requests")
    parser.add_argument("--save-html", action="store_true", help="Save raw HTML pages for reproducibility")
    parser.add_argument(
        "--output-dir",
        default="data/raw/slowmist",
        help="Output directory for collected artifacts",
    )
    args = parser.parse_args()

    summary = collect_events(
        start_page=args.start_page,
        end_page=args.end_page,
        category=args.category,
        delay_seconds=args.delay_seconds,
        save_html=args.save_html,
        output_dir=Path(args.output_dir),
    )
    print(
        f"[slowmist] collected {summary['event_count']} events "
        f"(pages {summary['start_page']}-{summary['end_page']})"
    )
    print(f"[slowmist] latest csv: {summary['csv_latest']}")


if __name__ == "__main__":
    main()
