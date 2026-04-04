"""论文修订与评审。"""

from __future__ import annotations

import re
from typing import Any

from services.research.models import (
    CitationRecord,
    IncidentEvidencePackage,
    PaperDraft,
    PaperRevisionResult,
    ReferenceValidationResult,
    ReviewAspectResult,
    ReviewBlockResult,
)
from services.shared.llm_client import OpenAiCompatibleLlmClient
from services.shared.settings import ProjectSettings


BLOCK_DEFINITIONS = [
    {
        "block_id": "structure",
        "name": "Structure",
        "headings": [
            "## 摘要",
            "## 1. Introduction",
            "## 2. Background and Context",
            "## 3. Problem Statement",
            "## 4. Research Questions",
            "## 5. Evidence and Observations",
            "## 6. Related Work",
            "## 7. Methodology",
            "## 8. Evaluation and Validation Plan",
            "## 9. Preliminary Results and Discussion",
            "## 10. Expected Contributions",
            "## 11. Threats to Validity",
            "## 12. Conclusion",
            "## References",
        ],
    },
    {
        "block_id": "evidence",
        "name": "Evidence",
        "headings": [
            "## 2. Background and Context",
            "## 5. Evidence and Observations",
        ],
    },
    {
        "block_id": "validation",
        "name": "Validation",
        "headings": [
            "## 8. Evaluation and Validation Plan",
            "## 9. Preliminary Results and Discussion",
        ],
    },
    {
        "block_id": "related_work",
        "name": "Related Work",
        "headings": [
            "## 6. Related Work",
            "## References",
        ],
    },
    {
        "block_id": "conclusion",
        "name": "Conclusion",
        "headings": [
            "## 11. Threats to Validity",
            "## 12. Conclusion",
        ],
    },
]


def _aspect(
    aspect_id: str,
    name: str,
    accepted: bool,
    score: float,
    summary: str,
    required_change: str = "",
) -> ReviewAspectResult:
    """构造单个 review 视角。"""

    return ReviewAspectResult(
        aspect_id=aspect_id,
        name=name,
        accepted=accepted,
        score=round(score, 1),
        summary=summary,
        required_change=required_change,
    )


def _split_markdown_sections(markdown: str) -> list[tuple[str, str]]:
    """按二级标题切分 Markdown。"""

    lines = markdown.splitlines()
    sections: list[tuple[str, str]] = []
    current_heading = "#TITLE"
    current_lines: list[str] = []

    for line in lines:
        if line.startswith("## "):
            sections.append((current_heading, "\n".join(current_lines).strip()))
            current_heading = line.strip()
            current_lines = []
        else:
            current_lines.append(line)
    sections.append((current_heading, "\n".join(current_lines).strip()))
    return sections


def _section_text(markdown: str, headings: list[str], max_chars: int = 1200) -> str:
    """抽取指定章节文本。"""

    matched = []
    for heading, body in _split_markdown_sections(markdown):
        if heading in headings:
            matched.append(f"{heading}\n{body}".strip())
    text = "\n\n".join(matched).strip()
    if len(text) <= max_chars:
        return text
    return text[:max_chars].rstrip() + "\n..."


def _flatten_block_issues(blocks: list[ReviewBlockResult], key: str) -> list[str]:
    """把 block 中的某类问题展平。"""

    items: list[str] = []
    for block in blocks:
        for value in getattr(block, key):
            if value not in items:
                items.append(value)
    return items


def _has_verification_summary(markdown: str) -> bool:
    """判断正文中是否存在验证结果摘要小节。"""

    return bool(
        re.search(
            r"^###\s+(?:[A-Z]\.\s+)?Verification Summary\b",
            markdown,
            flags=re.MULTILINE,
        )
    )


def _block_effectively_accepted(block: ReviewBlockResult) -> bool:
    """按最终展示语义计算 block 是否真的通过。"""

    aspects_ok = all(aspect.accepted for aspect in block.aspects) if block.aspects else True
    has_required_changes = any(str(item).strip() for item in block.required_changes)
    return bool(block.accepted and aspects_ok and not has_required_changes)


def _normalize_block_acceptance(block: ReviewBlockResult) -> ReviewBlockResult:
    """统一收敛 block 的 accepted 标记，避免出现“有问题但仍通过”的假阳性。"""

    return ReviewBlockResult(
        block_id=block.block_id,
        name=block.name,
        accepted=_block_effectively_accepted(block),
        score=block.score,
        aspects=block.aspects,
        strengths=block.strengths,
        weaknesses=block.weaknesses,
        required_changes=block.required_changes,
        addressed_changes=block.addressed_changes,
    )


def _deterministic_blocks(
    *,
    paper_draft: PaperDraft,
    reference_validation: ReferenceValidationResult,
    incident_evidence_packages: list[IncidentEvidencePackage],
    addressed_changes: list[str] | None = None,
) -> list[ReviewBlockResult]:
    """构造确定性分块评审。"""

    markdown = paper_draft.markdown
    addressed_changes = addressed_changes or []
    blocks: list[ReviewBlockResult] = []

    # Structure
    missing = [heading for heading in BLOCK_DEFINITIONS[0]["headings"] if heading not in markdown]
    structure_strengths = []
    structure_weaknesses = []
    structure_changes = []
    structure_score = 10.0
    if missing:
        structure_weaknesses.append("缺少关键章节：" + "；".join(missing[:6]))
        structure_changes.append("补齐论文主结构中的缺失章节。")
        structure_score = max(2.0, 10.0 - len(missing) * 0.8)
    else:
        structure_strengths.append("论文主结构完整。")
    structure_aspects = [
        _aspect(
            "section_coverage",
            "Section Coverage",
            not missing,
            structure_score,
            "关键章节齐全。" if not missing else "存在关键章节缺失。",
            "" if not missing else "补齐论文主结构中的缺失章节。",
        ),
        _aspect(
            "narrative_flow",
            "Narrative Flow",
            "## 3. Problem Statement" in markdown and "## 12. Conclusion" in markdown,
            8.0 if "## 3. Problem Statement" in markdown and "## 12. Conclusion" in markdown else 4.0,
            "问题定义与结论主线可追踪。" if "## 3. Problem Statement" in markdown and "## 12. Conclusion" in markdown else "问题定义到结论的叙事链不完整。",
            "" if "## 3. Problem Statement" in markdown and "## 12. Conclusion" in markdown else "强化从问题定义到结论的叙事闭环。",
        ),
    ]
    blocks.append(
        ReviewBlockResult(
            block_id="structure",
            name="Structure",
            accepted=not missing,
            score=round(structure_score, 1),
            aspects=structure_aspects,
            strengths=structure_strengths,
            weaknesses=structure_weaknesses,
            required_changes=structure_changes,
            addressed_changes=[item for item in addressed_changes if "章节" in item or "结构" in item],
        )
    )

    # Evidence
    strong_incidents = sum(1 for package in incident_evidence_packages if not package.missing_artifacts)
    evidence_strengths = []
    evidence_weaknesses = []
    evidence_changes = []
    evidence_score = 4.0
    if strong_incidents >= 1:
        evidence_strengths.append("至少存在一个完整 incident evidence package。")
        evidence_score += 3.0
    else:
        evidence_weaknesses.append("缺少完整的 incident 证据包。")
        evidence_changes.append("补齐链上交易锚点、时间线和关键实体。")
    if "### Incident Context" in markdown and "## 5. Evidence and Observations" in markdown:
        evidence_strengths.append("论文显式纳入了 incident 背景与证据链。")
        evidence_score += 2.0
    else:
        evidence_weaknesses.append("论文没有把 incident context 和证据链组织得足够清楚。")
        evidence_changes.append("在 Background / Evidence 中明确区分 incident context 与结构化证据。")
    evidence_aspects = [
        _aspect(
            "incident_grounding",
            "Incident Grounding",
            strong_incidents >= 1,
            9.0 if strong_incidents >= 1 else 3.5,
            "incident evidence package 完整。" if strong_incidents >= 1 else "incident 证据包不完整。",
            "" if strong_incidents >= 1 else "补齐链上交易锚点、时间线和关键实体。",
        ),
        _aspect(
            "evidence_mapping",
            "Evidence Mapping",
            "### Incident Context" in markdown and "## 5. Evidence and Observations" in markdown,
            8.5 if "### Incident Context" in markdown and "## 5. Evidence and Observations" in markdown else 4.0,
            "incident 背景与正文证据链映射清楚。" if "### Incident Context" in markdown and "## 5. Evidence and Observations" in markdown else "incident 背景与正文证据链映射不清楚。",
            "" if "### Incident Context" in markdown and "## 5. Evidence and Observations" in markdown else "在 Background / Evidence 中明确区分 incident context 与结构化证据。",
        ),
    ]
    blocks.append(
        ReviewBlockResult(
            block_id="evidence",
            name="Evidence",
            accepted=strong_incidents >= 1 and "### Incident Context" in markdown,
            score=round(min(evidence_score, 10.0), 1),
            aspects=evidence_aspects,
            strengths=evidence_strengths,
            weaknesses=evidence_weaknesses,
            required_changes=evidence_changes,
            addressed_changes=[item for item in addressed_changes if "incident" in item.lower() or "证据" in item],
        )
    )

    # Validation
    validation_strengths = []
    validation_weaknesses = []
    validation_changes = []
    validation_score = 4.0
    if _has_verification_summary(markdown):
        validation_strengths.append("论文显式总结了本地 fork / PoC 验证结果。")
        validation_score += 3.0
    else:
        validation_weaknesses.append("缺少 Verification Summary。")
        validation_changes.append("把本地验证结果写进正文，而不是停留在后台工件。")
    if any(package.verification_results for package in incident_evidence_packages):
        validation_strengths.append("incident 证据包中包含本地验证结果。")
        validation_score += 2.0
    else:
        validation_weaknesses.append("incident 证据包中没有可用的本地验证结果。")
        validation_changes.append("补充 fork / PoC 验证结果后再生成可靠研究稿。")
    validation_aspects = [
        _aspect(
            "verification_presence",
            "Verification Presence",
            any(package.verification_results for package in incident_evidence_packages),
            9.0 if any(package.verification_results for package in incident_evidence_packages) else 3.0,
            "存在本地验证结果。" if any(package.verification_results for package in incident_evidence_packages) else "缺少本地验证结果。",
            "" if any(package.verification_results for package in incident_evidence_packages) else "补充 fork / PoC 验证结果后再生成可靠研究稿。",
        ),
        _aspect(
            "result_reporting",
            "Result Reporting",
            _has_verification_summary(markdown),
            8.5 if _has_verification_summary(markdown) else 3.5,
            "论文显式报告了验证结果。" if _has_verification_summary(markdown) else "论文没有显式报告验证结果。",
            "" if _has_verification_summary(markdown) else "把本地验证结果写进正文，而不是停留在后台工件。",
        ),
    ]
    blocks.append(
        ReviewBlockResult(
            block_id="validation",
            name="Validation",
            accepted=(_has_verification_summary(markdown) and any(package.verification_results for package in incident_evidence_packages)),
            score=round(min(validation_score, 10.0), 1),
            aspects=validation_aspects,
            strengths=validation_strengths,
            weaknesses=validation_weaknesses,
            required_changes=validation_changes,
            addressed_changes=[item for item in addressed_changes if "Verification" in item or "验证" in item],
        )
    )

    # Related work
    related_strengths = []
    related_weaknesses = []
    related_changes = []
    related_score = 4.0
    if reference_validation.accepted_count >= 3:
        related_strengths.append("核心引用数量足够，且已通过基础校验。")
        related_score += 3.0
    else:
        related_weaknesses.append(reference_validation.summary)
        related_changes.append("增加高质量 incident / 高支撑报告引用。")
    if reference_validation.rejected_count > 0:
        related_weaknesses.append("仍存在被拒绝的引用。")
        related_changes.append("移除或替换被拒绝的引用片段。")
    else:
        related_score += 2.0
    related_aspects = [
        _aspect(
            "citation_quality",
            "Citation Quality",
            reference_validation.rejected_count == 0,
            9.0 if reference_validation.rejected_count == 0 else 4.0,
            "未发现被拒绝的引用。" if reference_validation.rejected_count == 0 else "仍存在被拒绝的引用。",
            "" if reference_validation.rejected_count == 0 else "移除或替换被拒绝的引用片段。",
        ),
        _aspect(
            "claim_alignment",
            "Claim Alignment",
            reference_validation.accepted_count >= 3,
            8.5 if reference_validation.accepted_count >= 3 else 4.0,
            "核心引用数量足够。" if reference_validation.accepted_count >= 3 else "核心引用数量不足。",
            "" if reference_validation.accepted_count >= 3 else "增加高质量 incident / 高支撑报告引用。",
        ),
    ]
    blocks.append(
        ReviewBlockResult(
            block_id="related_work",
            name="Related Work",
            accepted=reference_validation.accepted_count >= 3 and reference_validation.rejected_count == 0,
            score=round(min(related_score, 10.0), 1),
            aspects=related_aspects,
            strengths=related_strengths,
            weaknesses=related_weaknesses,
            required_changes=related_changes,
            addressed_changes=[item for item in addressed_changes if "引用" in item or "reference" in item.lower()],
        )
    )

    # Conclusion
    conclusion_strengths = []
    conclusion_weaknesses = []
    conclusion_changes = []
    conclusion_score = 4.0
    conclusion_grounded = any(
        token in markdown
        for token in [
            "本文当前版本的核心价值",
            "本文的核心价值",
        ]
    )
    if conclusion_grounded:
        conclusion_strengths.append("结论段能够回到 incident、证据与验证结果。")
        conclusion_score += 3.0
    else:
        conclusion_weaknesses.append("结论段仍缺少对论文贡献和边界的明确落点。")
        conclusion_changes.append("收紧 Conclusion，使其明确回到 incident、证据和验证结果。")
    if "## 11. Threats to Validity" in markdown:
        conclusion_strengths.append("局限性与边界条件已显式讨论。")
        conclusion_score += 2.0
    conclusion_aspects = [
        _aspect(
            "claim_grounding",
            "Claim Grounding",
            conclusion_grounded,
            8.5 if conclusion_grounded else 4.0,
            "结论明确回到 incident、证据与验证结果。" if conclusion_grounded else "结论缺少明确落点。",
            "" if conclusion_grounded else "收紧 Conclusion，使其明确回到 incident、证据和验证结果。",
        ),
        _aspect(
            "limitations",
            "Limitations",
            "## 11. Threats to Validity" in markdown,
            8.0 if "## 11. Threats to Validity" in markdown else 4.0,
            "局限性讨论存在。" if "## 11. Threats to Validity" in markdown else "局限性讨论不足。",
            "" if "## 11. Threats to Validity" in markdown else "补充 Threats to Validity，并明确仍未解决的边界。",
        ),
    ]
    blocks.append(
        ReviewBlockResult(
            block_id="conclusion",
            name="Conclusion",
            accepted=conclusion_grounded,
            score=round(min(conclusion_score, 10.0), 1),
            aspects=conclusion_aspects,
            strengths=conclusion_strengths,
            weaknesses=conclusion_weaknesses,
            required_changes=conclusion_changes,
            addressed_changes=[item for item in addressed_changes if "Conclusion" in item or "结论" in item],
        )
    )
    return blocks


def _aggregate_review_result(
    *,
    paper_draft: PaperDraft,
    blocks: list[ReviewBlockResult],
    rounds: int,
    summary: str,
    addressed_changes: list[str] | None = None,
) -> PaperRevisionResult:
    """把分块结果聚合成整体 revision result。"""

    normalized_blocks = [_normalize_block_acceptance(block) for block in blocks]
    strengths = _flatten_block_issues(blocks, "strengths")
    weaknesses = _flatten_block_issues(blocks, "weaknesses")
    required_changes = _flatten_block_issues(blocks, "required_changes")
    final_score = round(sum(block.score for block in normalized_blocks) / max(len(normalized_blocks), 1), 1)
    accepted = all(block.accepted for block in normalized_blocks) and final_score >= 7.5
    status = "accepted" if accepted else "needs_revision"
    return PaperRevisionResult(
        status=status,
        accepted=accepted,
        final_score=final_score,
        summary=summary,
        rounds=rounds,
        review_blocks=normalized_blocks,
        strengths=strengths,
        weaknesses=weaknesses,
        required_changes=required_changes,
        addressed_changes=addressed_changes or [],
        revised_markdown=paper_draft.markdown,
    )


def _build_review_summary(blocks: list[ReviewBlockResult], accepted: bool) -> str:
    """构造整体 review 摘要。"""

    if accepted:
        return "论文初稿已通过分块 review，可作为可靠研究稿接受。"
    weak_blocks = [block.name for block in blocks if not _block_effectively_accepted(block)]
    return "论文仍需修订，主要问题集中在：" + "、".join(weak_blocks[:4]) + "。"


def review_paper_draft(
    *,
    paper_draft: PaperDraft,
    reference_validation: ReferenceValidationResult,
    incident_evidence_packages: list[IncidentEvidencePackage],
    settings: ProjectSettings | None = None,
    client: OpenAiCompatibleLlmClient | None = None,
    rounds: int = 0,
    addressed_changes: list[str] | None = None,
) -> PaperRevisionResult:
    """对论文初稿做分块 review：确定性规则 + 证据约束 AI reviewer。"""

    deterministic_blocks = _deterministic_blocks(
        paper_draft=paper_draft,
        reference_validation=reference_validation,
        incident_evidence_packages=incident_evidence_packages,
        addressed_changes=addressed_changes,
    )
    deterministic_accepted = all(
        _block_effectively_accepted(block) for block in deterministic_blocks
    )
    resolved_settings = settings or ProjectSettings.from_env()
    if not resolved_settings.research_llm_available or (deterministic_accepted and client is None):
        return _aggregate_review_result(
            paper_draft=paper_draft,
            blocks=deterministic_blocks,
            rounds=rounds,
            summary=_build_review_summary(deterministic_blocks, deterministic_accepted),
            addressed_changes=addressed_changes,
        )

    ai_blocks = review_paper_draft_with_llm(
        paper_draft=paper_draft,
        deterministic_blocks=deterministic_blocks,
        reference_validation=reference_validation,
        incident_evidence_packages=incident_evidence_packages,
        settings=resolved_settings,
        client=client,
    )
    if not ai_blocks:
        accepted = all(_block_effectively_accepted(block) for block in deterministic_blocks)
        return _aggregate_review_result(
            paper_draft=paper_draft,
            blocks=deterministic_blocks,
            rounds=rounds,
            summary=_build_review_summary(deterministic_blocks, accepted),
            addressed_changes=addressed_changes,
        )

    merged_blocks: list[ReviewBlockResult] = []
    ai_map = {block.block_id: block for block in ai_blocks}
    for block in deterministic_blocks:
        ai_block = ai_map.get(block.block_id)
        if not ai_block:
            merged_blocks.append(block)
            continue
        merged_blocks.append(
            ReviewBlockResult(
                block_id=block.block_id,
                name=block.name,
                accepted=block.accepted and ai_block.accepted,
                score=round(min(block.score, ai_block.score), 1),
                aspects=ai_block.aspects or block.aspects,
                strengths=list(dict.fromkeys(block.strengths + ai_block.strengths)),
                weaknesses=list(dict.fromkeys(block.weaknesses + ai_block.weaknesses)),
                required_changes=list(dict.fromkeys(block.required_changes + ai_block.required_changes)),
                addressed_changes=list(dict.fromkeys((addressed_changes or []) + ai_block.addressed_changes)),
            )
        )

    accepted = all(_block_effectively_accepted(block) for block in merged_blocks)
    return _aggregate_review_result(
        paper_draft=paper_draft,
        blocks=merged_blocks,
        rounds=rounds,
        summary=_build_review_summary(merged_blocks, accepted),
        addressed_changes=addressed_changes,
    )


def _build_review_system_prompt() -> str:
    """返回 AI reviewer 系统提示词。"""

    return (
        "你是严格的安全研究论文 reviewer。"
        "请对给定论文做分块审稿。"
        "每个块都必须明确指出 strengths、weaknesses 和 required_changes。"
        "不得补充未提供的新事实。输出必须是 JSON。"
    )


def _safe_lines(items: list[str], limit: int = 10) -> str:
    """把列表渲染成提示片段。"""

    if not items:
        return "- 暂无"
    return "\n".join(f"- {item}" for item in items[:limit])


def _paper_relevant_issue_lines(
    reference_validation: ReferenceValidationResult,
    markdown: str,
) -> list[str]:
    """仅保留与当前论文正文直接相关的引用问题。"""

    related = []
    for issue in reference_validation.issues:
        title = str(issue.title or "").strip()
        if title and title in markdown:
            related.append(f"{title} | {issue.severity} | {issue.message}")
    return related


def _paper_relevant_citations(
    citations: list[CitationRecord],
    markdown: str,
) -> list[CitationRecord]:
    """为 review / revise 提示词筛出当前论文真正相关的引用。"""

    selected: list[CitationRecord] = []
    seen_ids: set[str] = set()
    for citation in citations:
        title = str(citation.title or "").strip()
        is_used_in_paper = bool(title and title in markdown)
        if not (
            is_used_in_paper
            or citation.source_type == "incident"
            or citation.support_level in {"high", "medium"}
        ):
            continue
        if citation.citation_id in seen_ids:
            continue
        seen_ids.add(citation.citation_id)
        selected.append(citation)
    return selected


def _build_review_user_prompt(
    *,
    paper_draft: PaperDraft,
    deterministic_blocks: list[ReviewBlockResult],
    reference_validation: ReferenceValidationResult,
    incident_evidence_packages: list[IncidentEvidencePackage],
) -> str:
    """构造 AI review 用户提示词。"""

    incident_lines = _safe_lines(
        [
            f"{package.title} | missing={';'.join(package.missing_artifacts) or 'none'} | verification={';'.join(item.get('summary','') for item in package.verification_results[:2]) or 'none'}"
            for package in incident_evidence_packages[:3]
        ],
        limit=3,
    )
    reference_issue_lines = _safe_lines(
        _paper_relevant_issue_lines(reference_validation, paper_draft.markdown),
        limit=8,
    )
    block_sections = []
    for block in deterministic_blocks:
        headings = next(item["headings"] for item in BLOCK_DEFINITIONS if item["block_id"] == block.block_id)
        section_text = _section_text(paper_draft.markdown, headings, max_chars=1000)
        block_sections.append(
            "\n".join(
                [
                    f"block_id: {block.block_id}",
                    f"name: {block.name}",
                    f"deterministic_score: {block.score}",
                    f"deterministic_accepted: {block.accepted}",
                    "deterministic_weaknesses:",
                    _safe_lines(block.weaknesses, limit=6),
                    "deterministic_required_changes:",
                    _safe_lines(block.required_changes, limit=6),
                    "deterministic_aspects:",
                    _safe_lines(
                        [
                            f"{aspect.name} | accepted={aspect.accepted} | score={aspect.score} | {aspect.summary}"
                            for aspect in block.aspects
                        ],
                        limit=8,
                    ),
                    "section_excerpt:",
                    section_text or "- 暂无",
                ]
            )
        )

    return "\n\n".join(
        [
            "请对下面的论文进行分块审稿。",
            "",
            "incident 证据摘要：",
            incident_lines,
            "",
            "引用校验问题：",
            reference_issue_lines,
            "",
            "分块输入：",
            "\n\n---\n\n".join(block_sections),
            "",
            "返回 JSON：",
            "{",
            '  "blocks": [',
            "    {",
            '      "block_id": "structure|evidence|validation|related_work|conclusion",',
            '      "accepted": true|false,',
            '      "score": 0-10,',
            '      "aspects": [',
            '        {"aspect_id": "string", "name": "string", "accepted": true|false, "score": 0-10, "summary": "一句话问题或优点", "required_change": "若有问题则给出修改要求"}',
            "      ],",
            '      "strengths": ["最多 4 条"],',
            '      "weaknesses": ["最多 5 条"],',
            '      "required_changes": ["最多 5 条"],',
            '      "addressed_changes": []',
            "    }",
            "  ]",
            "}",
        ]
    )


def review_paper_draft_with_llm(
    *,
    paper_draft: PaperDraft,
    deterministic_blocks: list[ReviewBlockResult],
    reference_validation: ReferenceValidationResult,
    incident_evidence_packages: list[IncidentEvidencePackage],
    settings: ProjectSettings | None = None,
    client: OpenAiCompatibleLlmClient | None = None,
) -> list[ReviewBlockResult] | None:
    """让 AI reviewer 做分块审稿。"""

    resolved_settings = settings or ProjectSettings.from_env()
    if not resolved_settings.research_llm_available:
        return None

    llm_client = client or OpenAiCompatibleLlmClient(resolved_settings)
    response = llm_client.complete_json(
        system_prompt=_build_review_system_prompt(),
        user_prompt=_build_review_user_prompt(
            paper_draft=paper_draft,
            deterministic_blocks=deterministic_blocks,
            reference_validation=reference_validation,
            incident_evidence_packages=incident_evidence_packages,
        ),
    )
    payload = response.content
    raw_blocks = payload.get("blocks")
    if not isinstance(raw_blocks, list) or not raw_blocks:
        return None

    results: list[ReviewBlockResult] = []
    for item in raw_blocks:
        if not isinstance(item, dict):
            continue
        block_id = str(item.get("block_id", "")).strip()
        if block_id not in {definition["block_id"] for definition in BLOCK_DEFINITIONS}:
            continue
        results.append(
            ReviewBlockResult(
                block_id=block_id,
                name=next(definition["name"] for definition in BLOCK_DEFINITIONS if definition["block_id"] == block_id),
                accepted=bool(item.get("accepted", False)),
                score=float(item.get("score", 0)),
                aspects=[
                    ReviewAspectResult(
                        aspect_id=str(aspect.get("aspect_id", "")).strip() or f"{block_id}_aspect_{index}",
                        name=str(aspect.get("name", "")).strip() or f"Aspect {index}",
                        accepted=bool(aspect.get("accepted", False)),
                        score=float(aspect.get("score", 0)),
                        summary=str(aspect.get("summary", "")).strip(),
                        required_change=str(aspect.get("required_change", "")).strip(),
                    )
                    for index, aspect in enumerate(item.get("aspects", []) if isinstance(item.get("aspects"), list) else [], start=1)
                    if isinstance(aspect, dict)
                ],
                strengths=[str(v).strip() for v in item.get("strengths", []) if str(v).strip()] if isinstance(item.get("strengths"), list) else [],
                weaknesses=[str(v).strip() for v in item.get("weaknesses", []) if str(v).strip()] if isinstance(item.get("weaknesses"), list) else [],
                required_changes=[str(v).strip() for v in item.get("required_changes", []) if str(v).strip()] if isinstance(item.get("required_changes"), list) else [],
                addressed_changes=[str(v).strip() for v in item.get("addressed_changes", []) if str(v).strip()] if isinstance(item.get("addressed_changes"), list) else [],
            )
        )
    return results or None


def _build_revision_system_prompt() -> str:
    """返回修订阶段系统提示词。"""

    return (
        "你是严谨的安全研究论文修订助手。"
        "你必须根据分块 reviewer 给出的 required_changes 修改论文初稿。"
        "只能使用给定论文与给定问题，不允许补充外部事实。"
        "输出必须是 JSON。"
    )


def _build_revision_user_prompt(
    *,
    paper_draft: PaperDraft,
    review_result: PaperRevisionResult,
    citations: list[CitationRecord],
    incident_evidence_packages: list[IncidentEvidencePackage],
) -> str:
    """构造修订用户提示词。"""

    revision_citations = _paper_relevant_citations(citations, paper_draft.markdown)
    citation_lines = _safe_lines(
        [
            f"{citation.title} | {citation.support_level} | {citation.key_takeaway or citation.snippet}"
            for citation in revision_citations[:6]
        ],
        limit=6,
    )
    incident_lines = _safe_lines(
        [
            f"{package.title} | {package.loss_summary} | {package.evidence_summary[-1] if package.evidence_summary else package.summary}"
            for package in incident_evidence_packages[:3]
        ],
        limit=3,
    )
    target_blocks = [block for block in review_result.review_blocks if not block.accepted][:3]
    block_specs = []
    for block in target_blocks:
        headings = next(item["headings"] for item in BLOCK_DEFINITIONS if item["block_id"] == block.block_id)
        block_specs.append(
            "\n".join(
                [
                    f"block_id: {block.block_id}",
                    f"name: {block.name}",
                    "required_changes:",
                    _safe_lines(block.required_changes, limit=6),
                    "section_excerpt:",
                    _section_text(paper_draft.markdown, headings, max_chars=1200) or "- 暂无",
                ]
            )
        )

    return "\n\n".join(
        [
            "请根据下面未通过的分块 review 修改论文草稿。",
            "",
            "未通过的 block：",
            "\n\n---\n\n".join(block_specs) or "- 暂无",
            "",
            "incident 证据：",
            incident_lines,
            "",
            "可用引用：",
            citation_lines,
            "",
            "返回 JSON：",
            "{",
            '  "updated_sections": [',
            "    {",
            '      "heading": "必须是现有二级标题，如 ## 6. Related Work",',
            '      "content": "该标题下修订后的完整正文内容"',
            "    }",
            "  ],",
            '  "addressed_changes": ["最多 8 条"]',
            "}",
        ]
    )


def _apply_section_updates(markdown: str, updates: list[dict[str, str]]) -> str:
    """把按 section 返回的修订应用回整篇论文。"""

    def _normalize_updated_content(heading: str, content: str) -> str:
        normalized = content.strip()
        if normalized.startswith(heading):
            normalized = normalized[len(heading) :].lstrip()
        normalized = re.sub(
            r"^###\s+(?:[A-Z]\.\s+)?Verification Summary\b",
            "### Verification Summary",
            normalized,
            flags=re.MULTILINE,
        )
        return normalized

    sections = _split_markdown_sections(markdown)
    update_map = {
        str(item.get("heading", "")).strip(): _normalize_updated_content(
            str(item.get("heading", "")).strip(),
            str(item.get("content", "")).strip(),
        )
        for item in updates
        if str(item.get("heading", "")).strip() and str(item.get("content", "")).strip()
    }
    seen_headings: set[str] = set()
    rebuilt: list[str] = []
    for heading, body in sections:
        if heading == "#TITLE":
            if body:
                rebuilt.append(body)
            continue
        seen_headings.add(heading)
        rebuilt.append(heading)
        rebuilt.append("")
        rebuilt.append(update_map.get(heading, body))
        rebuilt.append("")

    for definition in BLOCK_DEFINITIONS:
        for heading in definition["headings"]:
            if heading in seen_headings or heading not in update_map:
                continue
            rebuilt.append(heading)
            rebuilt.append("")
            rebuilt.append(update_map[heading])
            rebuilt.append("")
            seen_headings.add(heading)
    return "\n".join(line for line in rebuilt if line is not None).strip() + "\n"


def _extract_subheading_block(
    markdown: str,
    *,
    parent_heading: str,
    subheading: str,
) -> str:
    """从指定 section 中抽取三级标题块。"""

    for heading, body in _split_markdown_sections(markdown):
        if heading != parent_heading:
            continue
        lines = body.splitlines()
        captured: list[str] = []
        in_target = False
        for line in lines:
            stripped = line.strip()
            if stripped.startswith("### "):
                if in_target and stripped != subheading:
                    break
                if stripped == subheading:
                    in_target = True
                    captured = [subheading]
                    continue
            if in_target:
                captured.append(line)
        block = "\n".join(captured).strip()
        if block:
            return block
    return ""


def _generate_verification_summary_block(
    incident_evidence_packages: list[IncidentEvidencePackage],
) -> str:
    """基于 incident 包生成最小但明确的验证摘要块。"""

    lines = ["### Verification Summary", "", "本地主网 fork / PoC 验证的当前已完成结果如下：", ""]
    seen: set[str] = set()
    for package in incident_evidence_packages[:3]:
        for result in package.verification_results[:4]:
            if not result.get("passed"):
                continue
            summary = str(result.get("summary") or "").strip()
            label = (
                str(result.get("description") or "").strip()
                or str(result.get("match_path") or "").strip()
                or package.title
            )
            line = f"- {label}: {summary or '验证已通过。'}"
            if line in seen:
                continue
            seen.add(line)
            lines.append(line)
    if len(lines) == 4:
        lines.append("- 当前未记录通过的本地验证结果。")
    return "\n".join(lines).strip()


def _append_block_to_section(
    markdown: str,
    *,
    target_heading: str,
    block: str,
) -> str:
    """把块内容追加到指定 section。"""

    sections = _split_markdown_sections(markdown)
    rebuilt: list[str] = []
    inserted = False
    for heading, body in sections:
        if heading == "#TITLE":
            if body:
                rebuilt.append(body)
            continue
        rebuilt.append(heading)
        rebuilt.append("")
        next_body = body.strip()
        if heading == target_heading:
            next_body = (
                f"{next_body}\n\n{block}".strip()
                if next_body
                else block.strip()
            )
            inserted = True
        rebuilt.append(next_body)
        rebuilt.append("")
    if not inserted:
        rebuilt.extend([target_heading, "", block.strip(), ""])
    return "\n".join(line for line in rebuilt if line is not None).strip() + "\n"


def _enforce_required_revision_guards(
    *,
    original_markdown: str,
    revised_markdown: str,
    incident_evidence_packages: list[IncidentEvidencePackage],
) -> str:
    """修订后做最小硬护栏，避免 AI 删除必要证据结构。"""

    normalized = re.sub(
        r"^###\s+(?:[A-Z]\.\s+)?Verification Summary\b.*$",
        "### Verification Summary",
        revised_markdown,
        flags=re.MULTILINE,
    )

    needs_verification_summary = any(
        package.verification_results for package in incident_evidence_packages
    )
    if needs_verification_summary and not _has_verification_summary(normalized):
        preserved = _extract_subheading_block(
            original_markdown,
            parent_heading="## 9. Preliminary Results and Discussion",
            subheading="### Verification Summary",
        )
        normalized = _append_block_to_section(
            normalized,
            target_heading="## 9. Preliminary Results and Discussion",
            block=preserved or _generate_verification_summary_block(incident_evidence_packages),
        )

    return normalized


def revise_paper_draft_with_llm(
    *,
    paper_draft: PaperDraft,
    review_result: PaperRevisionResult,
    citations: list[CitationRecord],
    incident_evidence_packages: list[IncidentEvidencePackage],
    settings: ProjectSettings | None = None,
    client: OpenAiCompatibleLlmClient | None = None,
) -> tuple[PaperDraft | None, list[str]]:
    """用 LLM 基于 review 结果修订论文初稿。"""

    resolved_settings = settings or ProjectSettings.from_env()
    if not resolved_settings.research_llm_available:
        return None, []

    llm_client = client or OpenAiCompatibleLlmClient(resolved_settings)
    response = llm_client.complete_json(
        system_prompt=_build_revision_system_prompt(),
        user_prompt=_build_revision_user_prompt(
            paper_draft=paper_draft,
            review_result=review_result,
            citations=citations,
            incident_evidence_packages=incident_evidence_packages,
        ),
    )
    payload = response.content
    raw_updates = payload.get("updated_sections")
    if not isinstance(raw_updates, list) or not raw_updates:
        return None, []

    revised_markdown = _apply_section_updates(paper_draft.markdown, raw_updates)
    revised_markdown = _enforce_required_revision_guards(
        original_markdown=paper_draft.markdown,
        revised_markdown=revised_markdown,
        incident_evidence_packages=incident_evidence_packages,
    )
    addressed_changes = [
        str(item).strip()
        for item in payload.get("addressed_changes", [])
        if str(item).strip()
    ][:8] if isinstance(payload.get("addressed_changes"), list) else []

    return (
        PaperDraft(
            title=paper_draft.title,
            markdown=revised_markdown,
        ),
        addressed_changes,
    )


def run_revision_cycle(
    *,
    paper_draft: PaperDraft,
    reference_validation: ReferenceValidationResult,
    incident_evidence_packages: list[IncidentEvidencePackage],
    citations: list[CitationRecord],
    settings: ProjectSettings | None = None,
    client: OpenAiCompatibleLlmClient | None = None,
    max_rounds: int = 3,
) -> PaperRevisionResult:
    """运行 AI review -> AI revise -> 再 review。"""

    resolved_settings = settings or ProjectSettings.from_env()
    current_draft = paper_draft
    addressed_changes: list[str] = []
    current_review = review_paper_draft(
        paper_draft=current_draft,
        reference_validation=reference_validation,
        incident_evidence_packages=incident_evidence_packages,
        settings=resolved_settings,
        client=client,
        rounds=0,
        addressed_changes=addressed_changes,
    )
    if current_review.accepted:
        return current_review

    if not resolved_settings.research_llm_available or max_rounds <= 0:
        return current_review

    for round_index in range(1, max_rounds + 1):
        revised_draft, newly_addressed = revise_paper_draft_with_llm(
            paper_draft=current_draft,
            review_result=current_review,
            citations=citations,
            incident_evidence_packages=incident_evidence_packages,
            settings=resolved_settings,
            client=client,
        )
        if revised_draft is None:
            return current_review
        current_draft = revised_draft
        addressed_changes = list(dict.fromkeys(addressed_changes + newly_addressed))
        current_review = review_paper_draft(
            paper_draft=current_draft,
            reference_validation=reference_validation,
            incident_evidence_packages=incident_evidence_packages,
            settings=resolved_settings,
            client=client,
            rounds=round_index,
            addressed_changes=addressed_changes,
        )
        if current_review.accepted:
            return current_review

    return current_review
