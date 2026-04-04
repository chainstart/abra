"""构建论文主张-证据矩阵。"""

from __future__ import annotations

import re

from services.research.models import (
    CitationRecord,
    ClaimEvidenceMatrix,
    ClaimEvidenceMatrixRow,
    EvidenceAssessment,
    ExperimentPlan,
    ResearchIdea,
)


def _fragments(text: str) -> list[str]:
    normalized = re.sub(r"[^\w\u4e00-\u9fff]+", " ", (text or "").lower()).strip()
    parts = [part for part in normalized.split() if len(part) >= 2]
    return parts[:8]


def _score_match(claim: str, candidate: str) -> int:
    score = 0
    lowered = (candidate or "").lower()
    for fragment in _fragments(claim):
        if fragment in lowered:
            score += max(1, len(fragment) // 3)
    return score


def _pick_refs(claim: str, candidates: list[tuple[str, str]], limit: int) -> list[str]:
    ranked = sorted(
        candidates,
        key=lambda item: (_score_match(claim, item[1]), len(item[1])),
        reverse=True,
    )
    picked = [title for title, _ in ranked if title][:limit]
    if not picked:
        picked = [title for title, _ in candidates[:limit] if title]
    return picked


def build_claim_evidence_matrix(
    *,
    research_idea: ResearchIdea,
    citations: list[CitationRecord],
    experiment_plan: ExperimentPlan | None,
    evidence_assessment: EvidenceAssessment | None,
) -> ClaimEvidenceMatrix:
    """把 claim、证据、引用和实验设计组织成矩阵。"""

    checks = list(evidence_assessment.claim_checks if evidence_assessment else [])
    evidence_candidates = [
        (
            item.title,
            " ".join([item.title, item.summary, item.reasoning]),
        )
        for item in (research_idea.evidence_chain or [])
    ]
    citation_candidates = [
        (
            citation.title,
            " ".join(
                [
                    citation.title,
                    citation.claim_supported,
                    citation.citation_reason,
                    citation.key_takeaway,
                    citation.snippet,
                ]
            ),
        )
        for citation in citations
    ]
    experiment_candidates = [
        (
            design.title,
            " ".join([design.title, design.objective, " ".join(design.metrics), " ".join(design.procedures)]),
        )
        for design in ((experiment_plan.designs or []) if experiment_plan else [])
    ]

    rows: list[ClaimEvidenceMatrixRow] = []
    for index, check in enumerate(checks, start=1):
        evidence_refs = _pick_refs(check.claim, evidence_candidates, max(check.evidence_count, 1))
        claim_specific_citations = [
            citation
            for citation in citations
            if not citation.claim_supported or citation.claim_supported == check.claim
        ] or citations
        citation_refs = _pick_refs(
            check.claim,
            [
                (
                    citation.title,
                    " ".join(
                        [
                            citation.title,
                            citation.claim_supported,
                            citation.citation_reason,
                            citation.key_takeaway,
                            citation.snippet,
                        ]
                    ),
                )
                for citation in claim_specific_citations
            ],
            max(check.citation_count, 1),
        )
        experiment_refs = (
            _pick_refs(check.claim, experiment_candidates, 2)
            if check.has_experiment and experiment_candidates
            else []
        )
        boundary_notes = []
        if check.status != "covered":
            boundary_notes.append("当前主张尚未形成完全闭环，不宜上升为更宽泛结论。")
        if not check.has_experiment:
            boundary_notes.append("当前主张仍缺少与正文明确对应的实验或反证路径。")
        if not boundary_notes:
            boundary_notes.append("当前主张已具备可写入正文的最小闭环，但外推范围仍需受限。")
        primary_gap = ""
        if check.status == "missing":
            primary_gap = "缺少足够的证据、引用或验证闭环。"
        elif check.status == "partial":
            primary_gap = "已有部分支撑，但验证或引用链条仍不完整。"
        rows.append(
            ClaimEvidenceMatrixRow(
                claim_id=f"claim_{index}",
                claim=check.claim,
                status=check.status,
                evidence_refs=evidence_refs,
                citation_refs=citation_refs,
                experiment_refs=experiment_refs,
                supporting_points=[check.reasoning],
                boundary_notes=boundary_notes,
                primary_gap=primary_gap,
            )
        )

    covered_count = sum(1 for row in rows if row.status == "covered")
    partial_count = sum(1 for row in rows if row.status == "partial")
    missing_count = sum(1 for row in rows if row.status == "missing")
    summary = (
        f"矩阵覆盖 {len(rows)} 条核心主张，其中 fully covered {covered_count} 条、"
        f"partial {partial_count} 条、missing {missing_count} 条。"
    )
    return ClaimEvidenceMatrix(
        summary=summary,
        rows=rows,
        covered_count=covered_count,
        partial_count=partial_count,
        missing_count=missing_count,
    )


def render_claim_evidence_matrix_markdown(matrix: ClaimEvidenceMatrix | dict) -> str:
    """输出主张-证据矩阵 Markdown。"""

    if isinstance(matrix, dict):
        summary = str(matrix.get("summary") or "")
        covered_count = int(matrix.get("covered_count") or 0)
        partial_count = int(matrix.get("partial_count") or 0)
        missing_count = int(matrix.get("missing_count") or 0)
        rows = matrix.get("rows") or []
    else:
        summary = matrix.summary
        covered_count = matrix.covered_count
        partial_count = matrix.partial_count
        missing_count = matrix.missing_count
        rows = [item.to_dict() for item in matrix.rows]

    sections = [
        "# Claim-Evidence Matrix",
        "",
        f"- Summary: {summary}",
        f"- Covered: {covered_count}",
        f"- Partial: {partial_count}",
        f"- Missing: {missing_count}",
        "",
    ]
    for row in rows:
        sections.extend(
            [
                f"## {row.get('claim', '')}",
                "",
                f"- Status: {row.get('status', '')}",
                f"- Evidence Refs: {'；'.join(row.get('evidence_refs', []) or []) or '暂无'}",
                f"- Citation Refs: {'；'.join(row.get('citation_refs', []) or []) or '暂无'}",
                f"- Experiment Refs: {'；'.join(row.get('experiment_refs', []) or []) or '暂无'}",
                f"- Supporting Points: {'；'.join(row.get('supporting_points', []) or []) or '暂无'}",
                f"- Boundary Notes: {'；'.join(row.get('boundary_notes', []) or []) or '暂无'}",
                f"- Primary Gap: {row.get('primary_gap', '') or '无'}",
                "",
            ]
        )
    return "\n".join(sections).strip() + "\n"
