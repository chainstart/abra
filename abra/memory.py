"""Repo-level ABRA incident, finding, replay, and agent memory index."""

from __future__ import annotations

import csv
import hashlib
import json
import re
from collections import Counter
from pathlib import Path
from typing import Any, Iterable


MEMORY_INDEX_SCHEMA_VERSION = "abra.incident_memory_index.v1"
MEMORY_QUERY_SCHEMA_VERSION = "abra.incident_memory_query.v1"
DETERMINISTIC_BUILT_AT = "1970-01-01T00:00:00Z"
DEFAULT_QUERY_LIMIT = 25
INDEX_FILES = {
    "incidents": "incidents.jsonl",
    "findings": "findings.jsonl",
    "replay": "replay_memory.jsonl",
    "decisions": "decisions.jsonl",
    "observations": "observations.jsonl",
}


def build_memory_index(reports: str | Path, data: str | Path, out: str | Path) -> dict[str, Any]:
    """Build a deterministic repo-level memory index from ABRA artifacts."""

    reports_path = Path(reports).expanduser().resolve()
    data_path = Path(data).expanduser().resolve()
    out_path = Path(out).expanduser().resolve()
    if not reports_path.exists() or not reports_path.is_dir():
        raise FileNotFoundError(f"Reports directory not found: {reports_path}")
    if not data_path.exists() or not data_path.is_dir():
        raise FileNotFoundError(f"Data directory not found: {data_path}")

    out_path.mkdir(parents=True, exist_ok=True)
    for relative in [*INDEX_FILES.values(), "index.json", "README.md"]:
        stale_path = out_path / relative
        if stale_path.exists() and stale_path.is_file():
            stale_path.unlink()

    incidents = _incident_records(reports_path, data_path)
    replay = _replay_records(reports_path, data_path)
    findings = _finding_records(reports_path)
    decisions = _decision_records(reports_path, reports_path.parent / "docs" / "decisions")
    observations = _observation_records(incidents, replay, reports_path)
    source_files = _source_files(reports_path, data_path, reports_path.parent / "docs" / "decisions")
    source_fingerprint = _fingerprint_files(source_files)

    shards = {
        "incidents": incidents,
        "findings": findings,
        "replay": replay,
        "decisions": decisions,
        "observations": observations,
    }
    files_written: list[str] = []
    for name, rows in shards.items():
        relative = INDEX_FILES[name]
        _write_jsonl(out_path / relative, rows)
        files_written.append(relative)

    summary = {
        "incident_count": len(incidents),
        "finding_count": len(findings),
        "replay_memory_count": len(replay),
        "decision_count": len(decisions),
        "observation_count": len(observations),
        "source_file_count": len(source_files),
        "evidence_levels": _count_values(
            [row.get("evidence_level") for rows in shards.values() for row in rows if row.get("evidence_level")]
        ),
        "replay_statuses": _count_values(row.get("replay_status") for row in replay if row.get("replay_status")),
        "blocker_codes": _count_values(row.get("blocker_code") for row in replay if row.get("blocker_code")),
    }
    index = {
        "schema_version": MEMORY_INDEX_SCHEMA_VERSION,
        "status": "passed",
        "lab_id": "abra",
        "built_at": DETERMINISTIC_BUILT_AT,
        "deterministic": True,
        "source_fingerprint": source_fingerprint,
        "reports_path": str(reports_path),
        "data_path": str(data_path),
        "index_path": str(out_path),
        "files": INDEX_FILES,
        "summary": summary,
    }
    (out_path / "index.json").write_text(json.dumps(index, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    (out_path / "README.md").write_text(_render_readme(index), encoding="utf-8")
    files_written.extend(["index.json", "README.md"])

    return {
        "schema_version": MEMORY_INDEX_SCHEMA_VERSION,
        "status": "passed",
        "index_path": str(out_path),
        "source_fingerprint": source_fingerprint,
        "summary": summary,
        "files_written": sorted(files_written),
    }


def query_memory_index(index: str | Path, topic: str, limit: int = DEFAULT_QUERY_LIMIT) -> dict[str, Any]:
    """Query a built ABRA memory index by topic text."""

    index_path = Path(index).expanduser().resolve()
    if not index_path.exists() or not index_path.is_dir():
        raise FileNotFoundError(f"Memory index directory not found: {index_path}")
    index_payload = _load_json(index_path / "index.json")
    topic_text = str(topic or "").strip().lower()
    if not topic_text:
        raise ValueError("topic must be non-empty")
    bounded_limit = max(1, min(int(limit), 200))

    rows: list[dict[str, Any]] = []
    for memory_type, relative in INDEX_FILES.items():
        for row in _read_jsonl(index_path / relative):
            if _matches_topic(row, topic_text):
                item = dict(row)
                item["memory_type"] = memory_type
                item["score"] = _topic_score(row, topic_text, memory_type)
                rows.append(item)

    rows.sort(key=lambda row: (-int(row.get("score") or 0), str(row.get("id") or "")))
    results = rows[:bounded_limit]
    return {
        "schema_version": MEMORY_QUERY_SCHEMA_VERSION,
        "status": "passed",
        "index_path": str(index_path),
        "topic": topic_text,
        "limit": bounded_limit,
        "matched_count": len(rows),
        "returned_count": len(results),
        "type_counts": _count_values(row.get("memory_type") for row in rows),
        "index_summary": index_payload.get("summary", {}),
        "results": results,
    }


def _incident_records(reports_path: Path, data_path: Path) -> list[dict[str, Any]]:
    records: dict[str, dict[str, Any]] = {}
    for csv_path in _existing(
        data_path / "processed" / "incidents_normalized_latest.csv",
        data_path / "processed" / "phase2_batch1_incidents.csv",
    ):
        for row in _csv_rows(csv_path):
            target = _clean(row.get("target") or row.get("incident") or row.get("name"))
            if not target:
                continue
            slug = _slug(row.get("protocol_slug_guess") or row.get("slug") or target)
            record = {
                "id": _record_id("incident", slug, row.get("incident_id") or target),
                "kind": "incident",
                "slug": slug,
                "title": target,
                "event_date": _clean(row.get("event_date") or row.get("date")),
                "chain": _clean(row.get("chain")),
                "attack_family": _clean(row.get("attack_family")),
                "attack_method": _clean(row.get("attack_method_raw")),
                "loss_usd": _clean(row.get("loss_usd")),
                "is_defi": _boolish(row.get("is_defi")),
                "description": _clip(_clean(row.get("description")), 500),
                "source": _relative(csv_path),
                "reference_url": _clean(row.get("reference_url")),
                "evidence_level": "L1",
                "topics": _topics("incident", row.get("attack_family"), row.get("attack_method_raw"), row.get("chain")),
            }
            records.setdefault(slug, record)

    for path in sorted((reports_path / "events").glob("*.md")):
        if path.name.upper() == "INDEX.MD":
            continue
        card = _event_card(path)
        if not card:
            continue
        slug = card["slug"]
        existing = records.get(slug)
        if existing:
            existing["event_report"] = _relative(path)
            existing["title"] = existing.get("title") or card["title"]
            existing["description"] = existing.get("description") or card.get("description", "")
            existing["topics"] = sorted(set(existing.get("topics", []) + card.get("topics", [])))
        else:
            records[slug] = card
    return sorted(records.values(), key=lambda row: (str(row.get("event_date") or ""), str(row.get("slug") or "")))


def _event_card(path: Path) -> dict[str, Any] | None:
    text = path.read_text(encoding="utf-8", errors="replace")
    title = _first_heading(text) or path.stem
    metadata = _metadata_bullets(text)
    slug = _slug(path.stem.split("_", 1)[-1].rsplit("_", 1)[0] or title)
    description = _section_text(text, "Source Description")
    attack_family = _clean(metadata.get("Attack Family"))
    return {
        "id": _record_id("incident", slug, path.name),
        "kind": "incident",
        "slug": slug,
        "title": title.replace("Incident Card - ", ""),
        "event_date": _clean(metadata.get("Date")),
        "chain": "",
        "attack_family": attack_family,
        "attack_method": _clean(metadata.get("Attack Method (raw)")),
        "loss_usd": _clean(metadata.get("Estimated Loss")).replace("$", ""),
        "is_defi": _boolish(metadata.get("DeFi Label")),
        "description": _clip(description, 500),
        "source": _relative(path),
        "event_report": _relative(path),
        "reference_url": _clean(metadata.get("Reference URL")),
        "evidence_level": "L1",
        "topics": _topics("incident", attack_family, metadata.get("Attack Method (raw)")),
    }


def _replay_records(reports_path: Path, data_path: Path) -> list[dict[str, Any]]:
    records: dict[str, dict[str, Any]] = {}
    replay_results = data_path / "processed" / "replay_results.csv"
    for row in _csv_rows(replay_results):
        slug = _slug(row.get("slug") or row.get("incident"))
        if not slug:
            continue
        verified = _boolish(row.get("verified")) is True or _clean(row.get("status")) == "verified"
        records[f"csv-result-{slug}"] = {
            "id": _record_id("replay", "result", slug),
            "kind": "replay",
            "slug": slug,
            "incident": _clean(row.get("incident")),
            "chain": _clean(row.get("chain")),
            "attack_family": _clean(row.get("attack_family")),
            "fork_block": _clean(row.get("fork_block")),
            "replay_status": _clean(row.get("status")),
            "feasibility": "verified_replay" if verified else "blocked_or_backlog",
            "evidence_level": "L4" if verified else "L1",
            "blocker_code": _clean(row.get("blocker")),
            "test_path": _clean(row.get("test_path")),
            "replay_test": _clean(row.get("replay_test")),
            "log_path": _clean(row.get("log_path")),
            "source": _relative(replay_results),
            "summary": _replay_summary(row, verified),
            "topics": _topics("replay", row.get("status"), row.get("blocker"), row.get("chain"), row.get("attack_family")),
        }

    blocker_matrix = data_path / "processed" / "replay_blocker_matrix.csv"
    for row in _csv_rows(blocker_matrix):
        slug = _slug(row.get("slug") or row.get("incident"))
        if not slug:
            continue
        blocker = _clean(row.get("blocker"))
        verified = _boolish(row.get("verified")) is True
        key = f"csv-blocker-{slug}"
        records[key] = {
            "id": _record_id("replay", "blocker", slug, blocker),
            "kind": "replay_blocker",
            "slug": slug,
            "incident": _clean(row.get("incident")),
            "chain": _clean(row.get("chain")),
            "attack_family": "",
            "fork_block": "",
            "replay_status": _clean(row.get("status")),
            "feasibility": "verified_replay" if verified else "blocked_or_backlog",
            "evidence_level": "L4" if verified else "L1",
            "blocker_code": blocker,
            "test_path": "",
            "replay_test": "",
            "log_path": "",
            "source": _relative(blocker_matrix),
            "summary": _matrix_summary(row),
            "topics": _topics("replay", "blocker", row.get("status"), blocker, row.get("chain")),
        }

    for ledger_path in sorted(reports_path.glob("**/memory/replay_run_ledger.jsonl")):
        for run in _read_jsonl(ledger_path):
            for case in run.get("cases", []):
                if not isinstance(case, dict):
                    continue
                slug = _slug(case.get("slug") or case.get("incident"))
                if not slug:
                    continue
                key = f"ledger-{run.get('run_id')}-{slug}"
                records[key] = {
                    "id": _record_id("replay-ledger", run.get("run_id"), slug),
                    "kind": "replay_run_case",
                    "slug": slug,
                    "incident": _clean(case.get("incident")),
                    "chain": _clean(case.get("chain")),
                    "attack_family": "",
                    "fork_block": "",
                    "replay_status": _clean(case.get("replay_status")),
                    "feasibility": _clean(case.get("feasibility")),
                    "evidence_level": _clean(case.get("evidence_level")) or "L1",
                    "blocker_code": _clean(case.get("failure_code")),
                    "test_path": "",
                    "replay_test": "",
                    "log_path": "",
                    "source": _relative(ledger_path),
                    "run_id": _clean(run.get("run_id")),
                    "summary": f"Replay ledger case {slug} recorded status {case.get('replay_status')}.",
                    "topics": _topics("replay", "ledger", case.get("replay_status"), case.get("failure_code")),
                }
    return sorted(records.values(), key=lambda row: (str(row.get("slug") or ""), str(row.get("id") or "")))


def _finding_records(reports_path: Path) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    for path in sorted(reports_path.glob("*.md")):
        text = path.read_text(encoding="utf-8", errors="replace")
        title = _first_heading(text) or path.stem
        summary = _first_paragraph(text)
        topics = _report_topics(text, title)
        if not topics and "replay" not in path.name.lower():
            continue
        records.append(
            {
                "id": _record_id("finding", path.name),
                "kind": "finding",
                "title": title,
                "slug": _slug(path.stem),
                "source": _relative(path),
                "summary": _clip(summary, 700),
                "evidence_level": "L1",
                "topics": topics or ["report"],
            }
        )
    return records


def _decision_records(reports_path: Path, decision_dir: Path) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    for path in sorted(reports_path.glob("**/memory/agent_decision_ledger.jsonl")):
        for row in _read_jsonl(path):
            records.append(
                {
                    "id": _record_id("agent-decision", path, row.get("run_id"), row.get("round"), row.get("step")),
                    "kind": "agent_decision",
                    "source": _relative(path),
                    "run_id": _clean(row.get("run_id")),
                    "round": row.get("round"),
                    "step": _clean(row.get("step")),
                    "decision": _clean(row.get("selected_action")),
                    "rationale": _clean(row.get("rationale")),
                    "evidence_level": "L1",
                    "topics": _topics("agent", "decision", row.get("step"), row.get("selected_action")),
                }
            )
    if decision_dir.exists():
        for path in sorted(decision_dir.glob("*.md")):
            text = path.read_text(encoding="utf-8", errors="replace")
            records.append(
                {
                    "id": _record_id("repo-decision", path.name),
                    "kind": "repo_decision",
                    "source": _relative(path),
                    "title": _first_heading(text) or path.stem,
                    "decision": _clip(_first_paragraph(text), 600),
                    "rationale": "",
                    "evidence_level": "L1",
                    "topics": _topics("decision", "spec", "governance", path.stem),
                }
            )
    return sorted(records, key=lambda row: str(row.get("id") or ""))


def _observation_records(incidents: list[dict[str, Any]], replay: list[dict[str, Any]], reports_path: Path) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    blocker_counts = Counter(row.get("blocker_code") for row in replay if row.get("blocker_code"))
    for blocker, count in sorted(blocker_counts.items()):
        records.append(
            {
                "id": _record_id("observation", "replay-blocker", blocker),
                "kind": "reusable_observation",
                "topic": "replay",
                "title": f"Replay blocker pattern: {blocker}",
                "summary": f"{count} replay memory record(s) preserve blocker `{blocker}`; do not draft these as successful exploit replay.",
                "evidence_level": "L1",
                "source": "data/processed/replay_blocker_matrix.csv",
                "topics": _topics("replay", "blocker", blocker),
            }
        )
    family_counts = Counter(row.get("attack_family") for row in incidents if row.get("attack_family"))
    for family, count in sorted(family_counts.items()):
        if count < 2:
            continue
        records.append(
            {
                "id": _record_id("observation", "attack-family", family),
                "kind": "reusable_observation",
                "topic": "incident",
                "title": f"Repeated incident family: {family}",
                "summary": f"{count} incident record(s) share attack family `{family}`.",
                "evidence_level": "L1",
                "source": "data/processed/incidents_normalized_latest.csv",
                "topics": _topics("incident", family),
            }
        )
    for path in sorted(reports_path.glob("**/memory/agent_observation_ledger.jsonl")):
        for row in _read_jsonl(path):
            summary = row.get("summary") if isinstance(row.get("summary"), dict) else {}
            records.append(
                {
                    "id": _record_id("agent-observation", path, row.get("run_id"), row.get("round"), row.get("step")),
                    "kind": "agent_observation",
                    "topic": _clean(row.get("step")),
                    "source": _relative(path),
                    "run_id": _clean(row.get("run_id")),
                    "round": row.get("round"),
                    "title": f"Agent observation: {row.get('step')}",
                    "summary": json.dumps(summary, sort_keys=True),
                    "status": _clean(row.get("status")),
                    "evidence_level": "L1",
                    "topics": _topics("agent", "observation", row.get("step"), row.get("status")),
                }
            )
    return sorted(records, key=lambda row: str(row.get("id") or ""))


def _source_files(reports_path: Path, data_path: Path, decision_dir: Path) -> list[Path]:
    files: list[Path] = []
    for pattern in ("*.md", "events/*.md", "**/memory/*.json", "**/memory/*.jsonl"):
        files.extend(path for path in reports_path.glob(pattern) if path.is_file())
    for pattern in ("processed/*.csv",):
        files.extend(path for path in data_path.glob(pattern) if path.is_file())
    if decision_dir.exists():
        files.extend(path for path in decision_dir.glob("*.md") if path.is_file())
    return sorted(set(files))


def _csv_rows(path: Path) -> list[dict[str, str]]:
    if not path.exists() or not path.is_file():
        return []
    with path.open("r", encoding="utf-8", newline="") as handle:
        return [dict(row) for row in csv.DictReader(handle)]


def _existing(*paths: Path) -> list[Path]:
    return [path for path in paths if path.exists() and path.is_file()]


def _write_jsonl(path: Path, rows: Iterable[dict[str, Any]]) -> None:
    path.write_text("".join(json.dumps(row, sort_keys=True) + "\n" for row in rows), encoding="utf-8")


def _read_jsonl(path: Path) -> list[dict[str, Any]]:
    if not path.exists() or not path.is_file():
        return []
    rows: list[dict[str, Any]] = []
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        if not line.strip():
            continue
        try:
            row = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(row, dict):
            rows.append(row)
    return rows


def _load_json(path: Path) -> dict[str, Any]:
    if not path.exists() or not path.is_file():
        return {}
    payload = json.loads(path.read_text(encoding="utf-8"))
    return payload if isinstance(payload, dict) else {}


def _fingerprint_files(paths: list[Path]) -> str:
    digest = hashlib.sha256()
    for path in paths:
        digest.update(str(_relative(path)).encode("utf-8"))
        digest.update(b"\0")
        digest.update(path.read_bytes())
        digest.update(b"\0")
    return digest.hexdigest()


def _record_id(*parts: Any) -> str:
    raw = "|".join(str(part) for part in parts if part is not None)
    return hashlib.sha1(raw.encode("utf-8")).hexdigest()[:20]


def _slug(value: Any) -> str:
    text = _clean(value).lower()
    text = text.replace("&", " and ")
    text = re.sub(r"[^a-z0-9]+", "-", text).strip("-")
    return text or "unknown"


def _clean(value: Any) -> str:
    if value is None:
        return ""
    return re.sub(r"\s+", " ", str(value).strip().strip("`"))


def _clip(value: str, limit: int) -> str:
    text = _clean(value)
    if len(text) <= limit:
        return text
    return text[: limit - 3].rstrip() + "..."


def _boolish(value: Any) -> bool | None:
    text = _clean(value).lower()
    if text in {"true", "1", "yes", "y"}:
        return True
    if text in {"false", "0", "no", "n"}:
        return False
    return None


def _relative(path: Path) -> str:
    try:
        return str(path.resolve().relative_to(Path.cwd().resolve()))
    except ValueError:
        return str(path)


def _count_values(values: Iterable[Any]) -> dict[str, int]:
    return dict(sorted(Counter(str(value) for value in values if value not in {None, ""}).items()))


def _topics(*values: Any) -> list[str]:
    topics: set[str] = set()
    for value in values:
        for part in re.split(r"[^a-zA-Z0-9_]+", _clean(value).lower()):
            if part and len(part) > 1:
                topics.add(part)
    return sorted(topics)


def _first_heading(text: str) -> str:
    for line in text.splitlines():
        if line.startswith("#"):
            return _clean(line.lstrip("#"))
    return ""


def _first_paragraph(text: str) -> str:
    lines: list[str] = []
    for line in text.splitlines():
        clean = line.strip()
        if not clean or clean.startswith("#") or clean.startswith("|") or clean.startswith("```"):
            if lines:
                break
            continue
        lines.append(clean)
        if len(" ".join(lines)) > 500:
            break
    return " ".join(lines)


def _metadata_bullets(text: str) -> dict[str, str]:
    metadata: dict[str, str] = {}
    for line in text.splitlines():
        match = re.match(r"-\s+([^:]+):\s+(.+)$", line.strip())
        if match:
            metadata[_clean(match.group(1))] = _clean(match.group(2))
    return metadata


def _section_text(text: str, heading: str) -> str:
    capture = False
    lines: list[str] = []
    for line in text.splitlines():
        if line.startswith("## "):
            if capture:
                break
            capture = _clean(line.lstrip("#")) == heading
            continue
        if capture and line.strip():
            lines.append(line.strip())
    return " ".join(lines)


def _report_topics(text: str, title: str) -> list[str]:
    haystack = f"{title}\n{text}".lower()
    topics = []
    for topic in (
        "audit",
        "finding",
        "vulnerability",
        "oracle",
        "replay",
        "blocker",
        "incident",
        "attack",
        "evidence",
        "risk",
    ):
        if topic in haystack:
            topics.append(topic)
    return topics


def _replay_summary(row: dict[str, str], verified: bool) -> str:
    if verified:
        return f"{row.get('incident')} has L4 fixture-backed replay status `{row.get('status')}`."
    blocker = _clean(row.get("blocker")) or _clean(row.get("status"))
    return f"{row.get('incident')} remains bounded to L1 replay feasibility because `{blocker}`."


def _matrix_summary(row: dict[str, str]) -> str:
    blocker = _clean(row.get("blocker")) or "none"
    return f"{row.get('incident')} replay matrix status `{row.get('status')}` with blocker `{blocker}`."


def _matches_topic(row: dict[str, Any], topic: str) -> bool:
    if topic in {str(value).lower() for value in row.get("topics", []) if isinstance(row.get("topics"), list)}:
        return True
    return topic in json.dumps(row, sort_keys=True).lower()


def _topic_score(row: dict[str, Any], topic: str, memory_type: str) -> int:
    score = 0
    if topic in {str(value).lower() for value in row.get("topics", []) if isinstance(row.get("topics"), list)}:
        score += 5
    if topic == memory_type:
        score += 4
    if topic in str(row.get("title") or row.get("incident") or "").lower():
        score += 3
    if topic in str(row.get("summary") or "").lower():
        score += 2
    if topic in json.dumps(row, sort_keys=True).lower():
        score += 1
    return score


def _render_readme(index: dict[str, Any]) -> str:
    summary = index["summary"]
    return "\n".join(
        [
            "# ABRA Incident Memory Index",
            "",
            f"- Schema: `{index['schema_version']}`",
            f"- Source fingerprint: `{index['source_fingerprint']}`",
            f"- Incidents: {summary['incident_count']}",
            f"- Findings: {summary['finding_count']}",
            f"- Replay memories: {summary['replay_memory_count']}",
            f"- Decisions: {summary['decision_count']}",
            f"- Observations: {summary['observation_count']}",
            "",
            "Use `python3 -m abra memory query --index <index> --topic replay --json` to retrieve topic memories.",
            "",
        ]
    )
