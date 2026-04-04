"""历史攻击案例仓库。"""

from __future__ import annotations

import json
from pathlib import Path

from services.research.models import IncidentRecord
from services.storage.task_database import list_incidents, upsert_incidents


INCIDENT_BASE_FIELDS = {
    "incident_id",
    "title",
    "protocol_name",
    "protocol_type",
    "year",
    "summary",
    "root_cause",
    "attack_patterns",
    "affected_categories",
    "keywords",
    "source_reports",
    "evidence_payload",
}


def normalize_incident_dict(data: dict) -> dict:
    """把案例 JSON 规范化为数据库可存储结构。"""

    normalized = dict(data)
    explicit_payload = normalized.get("evidence_payload")
    if not isinstance(explicit_payload, dict):
        explicit_payload = {}

    extra_payload = {
        key: value
        for key, value in normalized.items()
        if key not in INCIDENT_BASE_FIELDS
    }
    normalized["evidence_payload"] = {
        **extra_payload,
        **explicit_payload,
    }

    for key in list(extra_payload):
        normalized.pop(key, None)

    normalized.setdefault("evidence_payload", {})
    return normalized


def load_incidents(incident_dir: str | Path) -> list[IncidentRecord]:
    """加载目录下的结构化案例，并同步到数据库。"""

    root = Path(incident_dir).resolve()
    if not root.exists():
        return []

    raw_incidents: list[dict] = []
    for path in sorted(root.glob("*.json")):
        data = normalize_incident_dict(json.loads(path.read_text(encoding="utf-8")))
        raw_incidents.append(data)

    if raw_incidents:
        upsert_incidents(raw_incidents)
        return [IncidentRecord(**item) for item in list_incidents(limit=1000)]

    return []
