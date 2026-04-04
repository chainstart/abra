"""基于 manuscript package 的分节 AI 成稿器。"""

from __future__ import annotations

from typing import Any

from services.research.models import CitationRecord, IncidentEvidencePackage, ManuscriptPackage, PaperDraft
from services.research.paper_revision import _apply_section_updates, _enforce_required_revision_guards, _section_text
from services.shared.llm_client import OpenAiCompatibleLlmClient
from services.shared.settings import ProjectSettings


SECTION_GROUPS = [
    {
        "name": "front_matter",
        "headings": [
            "## 摘要",
            "## 1. Introduction",
            "## 2. Background and Context",
            "## 3. Problem Statement",
            "## 4. Research Questions",
        ],
    },
    {
        "name": "core_argument",
        "headings": [
            "## 5. Evidence and Observations",
            "## 6. Related Work",
            "## 7. Methodology",
        ],
    },
    {
        "name": "validation_and_discussion",
        "headings": [
            "## 8. Evaluation and Validation Plan",
            "## 9. Preliminary Results and Discussion",
        ],
    },
    {
        "name": "closing",
        "headings": [
            "## 10. Expected Contributions",
            "## 11. Threats to Validity",
            "## 12. Conclusion",
        ],
    },
]


def _safe_lines(items: list[str], limit: int = 8) -> str:
    if not items:
        return "- 暂无"
    return "\n".join(f"- {item}" for item in items[:limit])


def _build_system_prompt() -> str:
    return (
        "你是区块链安全论文写作编辑。"
        "请把给定 section 重写成更接近期刊 case-study/security-systems 论文的中文学术 prose。"
        "必须严格保留事实边界、引用角色、验证边界和 heading。"
        "禁止添加任何未提供的新事实、新实验、新结论。"
        "去掉工作流说明腔、报告导出腔、内部字段腔、模板化免责声明的重复堆叠。"
        "除 Research Questions 外，不要把正文写成 checklist。"
        "输出必须是 JSON。"
    )


def _build_group_payload(package: ManuscriptPackage, group_name: str) -> dict[str, Any]:
    return {
        "front_matter": {
            "abstract_points": package.abstract_points,
            "introduction_points": package.introduction_points,
            "background_points": package.background_points,
            "incident_context_points": package.incident_context_points,
            "problem_statement_points": package.problem_statement_points,
            "research_questions": package.research_questions,
        },
        "core_argument": {
            "evidence_points": package.evidence_points,
            "claims": [item.to_dict() for item in package.claims],
            "observations": package.observations,
            "references": [item.to_dict() for item in package.references],
            "methodology_points": package.methodology_points,
        },
        "validation_and_discussion": {
            "evaluation_points": package.evaluation_points,
            "discussion_points": package.discussion_points,
            "claims": [item.to_dict() for item in package.claims],
        },
        "closing": {
            "contribution_points": package.contribution_points,
            "threats_points": package.threats_points,
            "conclusion_points": package.conclusion_points,
            "claims": [item.to_dict() for item in package.claims],
        },
    }.get(group_name, {})


def _build_user_prompt(
    *,
    group: dict[str, Any],
    current_markdown: str,
    package: ManuscriptPackage,
    citations: list[CitationRecord],
    incident_evidence_packages: list[IncidentEvidencePackage],
) -> str:
    heading_lines = _safe_lines(group["headings"])
    group_payload = _build_group_payload(package, group["name"])
    citation_lines = _safe_lines(
        [
            f"{citation.title} | {citation.support_level} | {citation.claim_supported or citation.citation_reason or citation.key_takeaway}"
            for citation in citations[:8]
        ],
        limit=8,
    )
    incident_lines = _safe_lines(
        [
            f"{item.title} | {item.loss_summary} | {item.evidence_summary[-1] if item.evidence_summary else item.summary}"
            for item in incident_evidence_packages[:3]
        ],
        limit=3,
    )
    section_blocks = []
    for heading in group["headings"]:
        excerpt = _section_text(current_markdown, [heading], max_chars=2200)
        if excerpt:
            section_blocks.append(excerpt)
    return "\n\n".join(
        [
            "请重写以下 section，使其更接近期刊论文正文。",
            "",
            "本轮需要改写的 headings：",
            heading_lines,
            "",
            "必须满足的写作要求：",
            _safe_lines(
                [
                    "摘要必须像论文摘要，不要像系统说明或任务回顾。",
                    "证据部分必须写成连续学术 prose，不要写成导出条目。",
                    "Related Work 必须是综述，而不是逐条解释为什么保留引用。",
                    "References 必须像论文条目，不要出现内部字段腔。",
                    "保留结论边界，但不要反复堆叠“当前版本”“当前稿件”等模板话。",
                ],
                limit=8,
            ),
            "",
            "incident 事实：",
            incident_lines,
            "",
            "可用引用：",
            citation_lines,
            "",
            "manuscript package 摘要：",
            str(group_payload),
            "",
            "当前 section 草稿：",
            "\n\n---\n\n".join(section_blocks),
            "",
            "返回 JSON：",
            "{",
            '  "updated_sections": [',
            "    {",
            '      "heading": "必须是现有 heading",',
            '      "content": "该 heading 下改写后的完整正文"',
            "    }",
            "  ],",
            '  "notes": ["最多 6 条，说明本轮改善了什么"]',
            "}",
        ]
    )


def write_manuscript_with_llm(
    *,
    paper_draft: PaperDraft,
    package: ManuscriptPackage,
    citations: list[CitationRecord],
    incident_evidence_packages: list[IncidentEvidencePackage],
    settings: ProjectSettings | None = None,
    client: OpenAiCompatibleLlmClient | None = None,
) -> tuple[PaperDraft | None, list[str]]:
    """按 section group 用 AI 重写论文章节。"""

    resolved_settings = settings or ProjectSettings.from_env()
    if not resolved_settings.research_llm_available:
        return None, []

    llm_client = client or OpenAiCompatibleLlmClient(resolved_settings)
    current_markdown = paper_draft.markdown
    notes: list[str] = []

    for group in SECTION_GROUPS:
        response = llm_client.complete_json(
            system_prompt=_build_system_prompt(),
            user_prompt=_build_user_prompt(
                group=group,
                current_markdown=current_markdown,
                package=package,
                citations=citations,
                incident_evidence_packages=incident_evidence_packages,
            ),
        )
        payload = response.content
        raw_updates = payload.get("updated_sections")
        if not isinstance(raw_updates, list) or not raw_updates:
            continue
        current_markdown = _apply_section_updates(current_markdown, raw_updates)
        notes.extend(
            str(item).strip()
            for item in payload.get("notes", [])
            if str(item).strip()
        )

    if current_markdown == paper_draft.markdown:
        return None, []
    current_markdown = _enforce_required_revision_guards(
        original_markdown=paper_draft.markdown,
        revised_markdown=current_markdown,
        incident_evidence_packages=incident_evidence_packages,
    )
    return PaperDraft(title=paper_draft.title, markdown=current_markdown), list(dict.fromkeys(notes))[:8]
