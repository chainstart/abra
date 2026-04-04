"""历史攻击相似案例检索。"""

from __future__ import annotations

import re

from services.analysis.models import ProtocolClassification
from services.research.incident_repository import load_incidents
from services.research.models import RelatedIncidentMatch
from services.shared.settings import ProjectSettings
from services.shared.models import FindingRecord


CATEGORY_KEYWORD_MAP = {
    "SC-01: Reentrancy": {"reentrancy", "callback", "cei"},
    "SC-02: Access Control": {"admin", "ownership", "privilege", "governance"},
    "SC-03: Oracle Manipulation": {"oracle", "price", "twap", "misconfigured oracle"},
    "SC-09: Governance": {"governance", "vote", "proposal"},
}


def _tokenize(text: str) -> set[str]:
    """做一个足够轻量但稳定的 token 拆分。"""

    return {
        token
        for token in re.split(r"[^a-zA-Z0-9_\-]+", text.lower())
        if token
    }


def _extract_query_tokens(
    classification: ProtocolClassification,
    findings: list[FindingRecord],
) -> set[str]:
    """从审计结果抽取检索信号。"""

    tokens = set()
    tokens.update(_tokenize(classification.protocol_type))
    tokens.update(_tokenize(classification.protocol_name))
    for finding in findings:
        tokens.update(_tokenize(finding.title))
        tokens.update(_tokenize(finding.category))
        tokens.update(_tokenize(finding.description))
        tokens.update(CATEGORY_KEYWORD_MAP.get(finding.category, set()))
    return tokens


def _score_incident(
    classification: ProtocolClassification,
    findings: list[FindingRecord],
    incident_match,
) -> RelatedIncidentMatch:
    """给单个案例打相关性分数。"""

    incident = incident_match
    score = 0
    reasons: list[str] = []
    query_tokens = _extract_query_tokens(classification, findings)

    if incident.protocol_type == classification.protocol_type:
        score += 4
        reasons.append("协议类型一致")

    finding_categories = {finding.category for finding in findings if finding.category}
    category_overlap = finding_categories.intersection(set(incident.affected_categories))
    if category_overlap:
        score += 5 * len(category_overlap)
        reasons.append(f"漏洞类别重合: {', '.join(sorted(category_overlap))}")

    incident_tokens = set(incident.keywords)
    incident_tokens.update(_tokenize(incident.summary))
    incident_tokens.update(_tokenize(incident.root_cause))
    incident_tokens.update(_tokenize(" ".join(incident.attack_patterns)))
    overlap = query_tokens.intersection(incident_tokens)
    if overlap:
        score += min(len(overlap), 6)
        reasons.append(f"关键词重合: {', '.join(sorted(list(overlap))[:6])}")

    if incident.protocol_name.lower() in classification.protocol_name.lower():
        score += 2
        reasons.append("协议名称相近")

    return RelatedIncidentMatch(
        incident=incident,
        score=score,
        reasons=reasons,
    )


def find_related_incidents(
    *,
    classification: ProtocolClassification,
    findings: list[FindingRecord],
    limit: int = 3,
) -> list[RelatedIncidentMatch]:
    """根据当前审计结果检索相似历史案例。"""

    settings = ProjectSettings.from_env()
    incident_dir = settings.research_dir / "incidents"
    incidents = load_incidents(incident_dir)

    scored = [
        _score_incident(classification, findings, incident)
        for incident in incidents
    ]
    filtered = [match for match in scored if match.score > 0]
    filtered.sort(
        key=lambda match: (
            -match.score,
            -match.incident.year,
            match.incident.incident_id,
        )
    )
    return filtered[:limit]
