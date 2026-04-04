"""Phase 1 证据聚合器。"""

from __future__ import annotations

from collections import Counter

from services.analysis.models import EvidenceSummary, flatten_evidence
from services.shared.models import FindingRecord


def build_evidence_summary(findings: list[FindingRecord]) -> EvidenceSummary:
    """把分散的 evidence 聚合成适合报告展示的摘要。"""

    evidence_items = flatten_evidence(findings)
    source_type_breakdown = Counter(
        evidence.source_type for evidence in evidence_items
    )
    analyzer_breakdown = Counter(
        finding.analyzer for finding in findings
    )
    reproducible_count = sum(
        1 for evidence in evidence_items if evidence.reproducible
    )

    return EvidenceSummary(
        evidence_count=len(evidence_items),
        reproducible_count=reproducible_count,
        source_type_breakdown=dict(source_type_breakdown),
        analyzer_breakdown=dict(analyzer_breakdown),
    )
