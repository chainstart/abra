"""引用校验。"""

from __future__ import annotations

import re

from services.research.models import (
    CitationRecord,
    ReferenceValidationIssue,
    ReferenceValidationResult,
    ResearchIdea,
)


def _normalize_text(text: str) -> str:
    """规范化文本。"""

    return " ".join((text or "").replace("\n", " ").split()).strip()


def _is_noisy(text: str) -> bool:
    """判断文本是否像表格碎片或脏摘录。"""

    normalized = _normalize_text(text)
    if not normalized:
        return True
    if len(normalized) < 20:
        return True
    if any(marker in normalized for marker in ["|", "```", "###"]):
        return True
    if normalized.count("[") >= 2 or normalized.count("]") >= 2:
        return True
    return False


def _clean_summary(citation: CitationRecord) -> str:
    """选择更适合引用的摘要。"""

    for candidate in [citation.key_takeaway, citation.snippet, citation.citation_reason]:
        normalized = _normalize_text(candidate)
        if normalized and not _is_noisy(normalized):
            return normalized
    return ""


def validate_references(
    *,
    citations: list[CitationRecord],
    research_idea: ResearchIdea,
) -> ReferenceValidationResult:
    """对引用质量做确定性校验。"""

    issues: list[ReferenceValidationIssue] = []
    validated: list[CitationRecord] = []
    rejected_count = 0

    for citation in citations:
        cleaned = _clean_summary(citation)
        if not cleaned:
            issues.append(
                ReferenceValidationIssue(
                    citation_id=citation.citation_id,
                    title=citation.title,
                    severity="high",
                    message="引用摘录明显像表格碎片、截断文本或空内容。",
                    suggestion="替换为 incident 级引用，或重新抽取更干净的摘要片段。",
                )
            )
            rejected_count += 1
            continue

        if not citation.claim_supported and (research_idea.research_questions or []):
            issues.append(
                ReferenceValidationIssue(
                    citation_id=citation.citation_id,
                    title=citation.title,
                    severity="medium",
                    message="该引用未明确绑定到某条研究主张。",
                    suggestion="为引用补充 claim_supported，避免只做背景性罗列。",
                )
            )

        if citation.source_type == "report" and citation.support_level == "reference":
            issues.append(
                ReferenceValidationIssue(
                    citation_id=citation.citation_id,
                    title=citation.title,
                    severity="low",
                    message="该引用仅为参考级，不应成为核心论证支撑。",
                    suggestion="优先使用 incident、高强度报告或已验证材料支撑核心结论。",
                )
            )

        validated.append(
            CitationRecord(
                citation_id=citation.citation_id,
                title=citation.title,
                source_type=citation.source_type,
                source_ref=citation.source_ref,
                snippet=cleaned,
                relevance_score=citation.relevance_score,
                claim_supported=citation.claim_supported,
                citation_reason=_normalize_text(citation.citation_reason),
                support_level=citation.support_level,
                key_takeaway=cleaned,
            )
        )

    accepted_count = len(validated)
    summary = (
        f"引用校验完成：接受 {accepted_count} 条，拒绝 {rejected_count} 条。"
    )
    return ReferenceValidationResult(
        accepted_count=accepted_count,
        rejected_count=rejected_count,
        summary=summary,
        validated_citations=validated,
        issues=issues,
    )
