#!/usr/bin/env python3
"""Shared helpers for the Phase-1 data pipeline."""

from __future__ import annotations

import csv
import hashlib
import json
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable


def now_utc_iso() -> str:
    """Return current UTC timestamp in ISO-8601 format."""
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def ensure_dir(path: Path) -> None:
    """Create directory recursively if it does not exist."""
    path.mkdir(parents=True, exist_ok=True)


def write_json(path: Path, payload: object) -> None:
    """Write JSON payload with UTF-8 encoding."""
    path.write_text(
        json.dumps(payload, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )


def write_csv(path: Path, rows: list[dict], fieldnames: list[str]) -> None:
    """Write a list of dictionaries to CSV."""
    with path.open("w", encoding="utf-8", newline="") as fp:
        writer = csv.DictWriter(fp, fieldnames=fieldnames)
        writer.writeheader()
        for row in rows:
            writer.writerow({k: row.get(k, "") for k in fieldnames})


def read_csv(path: Path) -> list[dict]:
    """Read CSV into a list of dictionaries."""
    with path.open("r", encoding="utf-8", newline="") as fp:
        return list(csv.DictReader(fp))


def sha1_id(parts: Iterable[str]) -> str:
    """Build deterministic identifier from ordered string parts."""
    h = hashlib.sha1()
    for part in parts:
        h.update((part or "").strip().encode("utf-8"))
        h.update(b"|")
    return h.hexdigest()


def normalize_text(value: str) -> str:
    """Normalize text for approximate matching."""
    return re.sub(r"[^a-z0-9]+", "", (value or "").lower())


def parse_loss_usd(raw_value: str) -> float | None:
    """Parse human-readable USD loss string to numeric value.

    Examples:
    - "$ 1,780,000.00" -> 1780000.0
    - "$100,000" -> 100000.0
    - "-" -> None
    - "0" -> 0.0
    """
    if raw_value is None:
        return None

    text = raw_value.strip().lower()
    if not text or text == "-":
        return None

    multiplier = 1.0
    if "billion" in text:
        multiplier = 1_000_000_000.0
    elif "million" in text:
        multiplier = 1_000_000.0
    elif re.search(r"\bk\b", text):
        multiplier = 1_000.0

    cleaned = text.replace("$", "").replace(",", "").replace(" ", "")
    cleaned = re.sub(r"(billion|million|k|usd|us\$)", "", cleaned)
    cleaned = cleaned.strip()
    if not cleaned:
        return None

    try:
        return float(cleaned) * multiplier
    except ValueError:
        return None

