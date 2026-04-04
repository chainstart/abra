"""标准化新事件发现入口。"""

from __future__ import annotations

from dataclasses import dataclass

from services.research.discovered_incident_repository import list_discovered_incidents
from services.research.external_incident_discovery import discover_external_incidents
from services.research.models import DiscoveredIncidentCandidate


@dataclass(frozen=True)
class EventDiscoveryResult:
    """统一事件发现结果。"""

    summary: str
    selected_candidate_id: str
    selected_title: str
    sources: list[str]
    discovered_candidates: list[DiscoveredIncidentCandidate]

    def to_dict(self) -> dict[str, object]:
        return {
            "summary": self.summary,
            "selected_candidate_id": self.selected_candidate_id,
            "selected_title": self.selected_title,
            "sources": self.sources,
            "discovered_candidates": [item.to_dict() for item in self.discovered_candidates],
        }


def run_event_discovery_round(
    *,
    limit: int = 12,
    min_relevance: float = 0.45,
    refresh: bool = True,
) -> EventDiscoveryResult:
    """运行一轮新事件发现并选择当前最值得研究的候选。"""

    discovered = (
        discover_external_incidents(limit=limit, min_relevance=min_relevance, save=True)
        if refresh
        else list_discovered_incidents(limit=limit)
    )
    if not discovered:
        discovered = list_discovered_incidents(limit=limit)
    if not discovered:
        raise ValueError("当前未发现可进入研究链的新事件候选。")

    ranked = sorted(
        discovered,
        key=lambda item: (
            -item.relevance_score,
            item.discovered_at,
            item.title,
        ),
    )
    selected = ranked[0]
    summary = (
        f"当前发现 {len(ranked)} 个外部事件候选，"
        f"系统优先选择 {selected.title} 进入研究链。"
    )
    return EventDiscoveryResult(
        summary=summary,
        selected_candidate_id=selected.candidate_id,
        selected_title=selected.title,
        sources=sorted({item.source for item in ranked}),
        discovered_candidates=ranked[:limit],
    )


def render_event_discovery_markdown(result: EventDiscoveryResult | dict) -> str:
    """输出事件发现结果 Markdown。"""

    if isinstance(result, dict):
        payload = result
        candidates = payload.get("discovered_candidates", []) or []
    else:
        payload = result.to_dict()
        candidates = payload["discovered_candidates"]

    lines = [
        "# Event Discovery",
        "",
        f"- Summary: {payload.get('summary', '')}",
        f"- Selected Candidate ID: {payload.get('selected_candidate_id', '')}",
        f"- Selected Title: {payload.get('selected_title', '')}",
        f"- Sources: {'；'.join(payload.get('sources', []) or []) or '暂无'}",
        "",
        "## Candidates",
        "",
    ]
    for item in candidates:
        lines.extend(
            [
                f"### {item.get('title', '')}",
                "",
                f"- Candidate ID: {item.get('candidate_id', '')}",
                f"- Source: {item.get('source', '')}",
                f"- Discovered At: {item.get('discovered_at', '')}",
                f"- Relevance: {item.get('relevance_score', 0)}",
                f"- Summary: {item.get('summary', '')}",
                f"- Attack Method: {item.get('attack_method', '')}",
                f"- Loss: {item.get('loss_text', '')}",
                "",
            ]
        )
    return "\n".join(lines).strip() + "\n"
