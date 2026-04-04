"""研究工作流的可选 LLM 增强层。

设计原则：

- LLM 只能在本地证据之上做选择、重写和总结
- 不允许跳出给定证据胡编协议事实
- 没有配置时静默回退到纯本地工作流
"""

from __future__ import annotations

from dataclasses import replace
from typing import Any

from services.research.models import (
    CitationRecord,
    ExperimentPlan,
    LlmResearchEnhancement,
    ResearchIdea,
)
from services.shared.llm_client import OpenAiCompatibleLlmClient
from services.shared.settings import ProjectSettings


def _safe_lines(items: list[str], limit: int = 6) -> str:
    """渲染列表为提示词片段。"""

    if not items:
        return "- 暂无"
    return "\n".join(f"- {item}" for item in items[:limit])


def _normalize_string_list(value: Any, limit: int) -> list[str]:
    """把任意值规范成字符串列表。"""

    if not isinstance(value, list):
        return []
    items: list[str] = []
    for item in value:
        text = str(item).strip()
        if text:
            items.append(text)
    return items[:limit]


def _build_package_system_prompt() -> str:
    """返回研究包总结阶段系统提示词。"""

    return (
        "你是 DeFi 安全研究助手。请基于已经给定的研究方向、证据链、引用和实验设计，"
        "生成简洁但专业的执行摘要和论文摘要，并补充每条引用的支撑主张。"
        "不得引入未提供的新事实。输出必须是 JSON 对象。"
    )


def _build_package_user_prompt(
    selected_idea: ResearchIdea,
    citations: list[CitationRecord],
    experiment_plan: ExperimentPlan,
) -> str:
    """构造研究包总结阶段用户提示词。"""

    citation_lines = _safe_lines(
        [
            f"{citation.citation_id} | {citation.title} | {citation.source_type} | "
            f"{citation.snippet} | score={citation.relevance_score}"
            for citation in citations[:6]
        ],
        limit=6,
    )
    experiment_lines = _safe_lines(
        [
            f"{design.design_id} | {design.title} | objective={design.objective} | "
            f"metrics={'; '.join(design.metrics)} | deliverables={'; '.join(design.deliverables)}"
            for design in (experiment_plan.designs or [])[:3]
        ],
        limit=3,
    )

    return "\n\n".join(
        [
            "请基于以下研究包生成摘要，并为引用补充更具体的支撑说明。",
            "",
            "研究方向：",
            f"- title: {selected_idea.title}",
            f"- problem_statement: {selected_idea.problem_statement}",
            f"- hypothesis: {selected_idea.hypothesis}",
            "research_questions:",
            _safe_lines(selected_idea.research_questions or [], limit=3),
            "evidence_chain:",
            _safe_lines(
                [
                    f"{item.evidence_id} | {item.title} | {item.summary} | {item.strength}"
                    for item in (selected_idea.evidence_chain or [])
                ],
                limit=5,
            ),
            "",
            "引用：",
            citation_lines,
            "",
            "实验设计：",
            experiment_lines,
            "",
            "返回 JSON，字段如下：",
            "{",
            '  "executive_summary": "面向产品工作台的执行摘要",',
            '  "draft_abstract": "面向论文的扩展摘要",',
            '  "writing_highlights": ["最多 3 条"],',
            '  "used_citation_ids": ["必须来自 citation_id，最多 6 个"],',
            '  "citation_updates": [',
            '    {',
            '      "citation_id": "必须来自给定 citation_id",',
            '      "claim_supported": "该引用支撑的具体主张",',
            '      "citation_reason": "为什么要用它",',
            '      "key_takeaway": "一句话关键结论",',
            '      "support_level": "high|medium|reference"',
            "    }",
            "  ]",
            "}",
        ]
    )


def summarize_research_package_with_llm(
    *,
    selected_idea: ResearchIdea,
    citations: list[CitationRecord],
    experiment_plan: ExperimentPlan,
    settings: ProjectSettings | None = None,
    client: OpenAiCompatibleLlmClient | None = None,
) -> tuple[list[CitationRecord], LlmResearchEnhancement | None]:
    """让 LLM 基于最终研究包生成摘要并细化引用解释。"""

    resolved_settings = settings or ProjectSettings.from_env()
    if not resolved_settings.research_llm_available:
        return citations, None

    llm_client = client or OpenAiCompatibleLlmClient(resolved_settings)
    response = llm_client.complete_json(
        system_prompt=_build_package_system_prompt(),
        user_prompt=_build_package_user_prompt(selected_idea, citations, experiment_plan),
    )
    payload = response.content

    citation_map = {citation.citation_id: citation for citation in citations}
    updated_citations = citations[:]
    for item in payload.get("citation_updates", []) or []:
        citation_id = str(item.get("citation_id", "")).strip()
        if citation_id not in citation_map:
            continue
        base = citation_map[citation_id]
        replacement = replace(
            base,
            claim_supported=str(item.get("claim_supported") or base.claim_supported).strip(),
            citation_reason=str(item.get("citation_reason") or base.citation_reason).strip(),
            key_takeaway=str(item.get("key_takeaway") or base.key_takeaway or base.snippet).strip(),
            support_level=(
                str(item.get("support_level") or base.support_level).strip()
                if str(item.get("support_level") or "").strip() in {"high", "medium", "reference"}
                else base.support_level
            ),
        )
        updated_citations = [
            replacement if citation.citation_id == citation_id else citation
            for citation in updated_citations
        ]

    enhancement = LlmResearchEnhancement(
        provider="openai-compatible",
        model=response.model,
        status="completed",
        selected_idea_id=selected_idea.idea_id,
        selection_reason=selected_idea.selection_reason,
        executive_summary=str(payload.get("executive_summary", "")).strip(),
        draft_abstract=str(payload.get("draft_abstract", "")).strip(),
        writing_highlights=_normalize_string_list(payload.get("writing_highlights"), limit=3),
        used_evidence_ids=[item.evidence_id for item in (selected_idea.evidence_chain or [])],
        used_citation_ids=[
            citation_id
            for citation_id in _normalize_string_list(payload.get("used_citation_ids"), limit=6)
            if citation_id in citation_map
        ],
        raw_payload={
            "package_summary": payload,
        },
    )
    return updated_citations, enhancement
