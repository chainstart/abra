"""外部发现事件候选仓库。"""

from __future__ import annotations

import json
from pathlib import Path

from services.research.models import DiscoveredIncidentCandidate
from services.shared.settings import ProjectSettings


def _storage_path() -> Path:
    """返回候选事件缓存路径。"""

    settings = ProjectSettings.from_env()
    path = settings.data_dir / "discovered_incidents.json"
    path.parent.mkdir(parents=True, exist_ok=True)
    return path


def list_discovered_incidents(limit: int = 100) -> list[DiscoveredIncidentCandidate]:
    """读取已缓存的候选事件。"""

    path = _storage_path()
    if not path.exists():
        return []
    raw = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(raw, list):
        return []
    items = [
        DiscoveredIncidentCandidate(**item)
        for item in raw
        if isinstance(item, dict)
    ]
    return items[:limit]


def save_discovered_incidents(candidates: list[DiscoveredIncidentCandidate]) -> None:
    """保存或更新候选事件缓存。"""

    existing = {item.candidate_id: item for item in list_discovered_incidents(limit=1000)}
    for candidate in candidates:
        existing[candidate.candidate_id] = candidate
    payload = [item.to_dict() for item in existing.values()]
    payload.sort(
        key=lambda item: (
            item.get("discovered_at", ""),
            item.get("title", ""),
        ),
        reverse=True,
    )
    _storage_path().write_text(
        json.dumps(payload, indent=2, ensure_ascii=False),
        encoding="utf-8",
    )


def load_discovered_incident(candidate_id: str) -> DiscoveredIncidentCandidate | None:
    """按 candidate_id 读取候选事件。"""

    for item in list_discovered_incidents(limit=1000):
        if item.candidate_id == candidate_id:
            return item
    return None
