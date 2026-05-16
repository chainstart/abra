"""LLM 研究增强产物写作器。"""

from __future__ import annotations

from typing import Any

from services.research.models import LlmResearchEnhancement


def _as_dict(enhancement: LlmResearchEnhancement | dict[str, Any]) -> dict[str, Any]:
    """统一转成字典。"""

    if isinstance(enhancement, LlmResearchEnhancement):
        return enhancement.to_dict()
    return enhancement


def render_llm_enhancement_markdown(
    enhancement: LlmResearchEnhancement | dict[str, Any]
) -> str:
    """把 LLM 研究增强结果写成独立 Markdown。"""

    payload = _as_dict(enhancement)
    highlights = "\n".join(
        f"- {item}" for item in payload.get("writing_highlights", [])
    ) or "- 暂无额外高亮。"
    evidence_lines = "\n".join(
        f"- {item}" for item in payload.get("used_evidence_ids", [])
    ) or "- 暂无显式引用的 evidence_id。"
    citation_lines = "\n".join(
        f"- {item}" for item in payload.get("used_citation_ids", [])
    ) or "- 暂无显式引用的 citation_id。"

    return "\n".join(
        [
            "# AI 研究增强摘要",
            "",
            f"- Provider: {payload.get('provider', '')}",
            f"- Model: {payload.get('model', '')}",
            f"- Status: {payload.get('status', '')}",
            f"- Selected Idea ID: {payload.get('selected_idea_id', '')}",
            "",
            "## 方向选择说明",
            "",
            str(payload.get("selection_reason", "")).strip() or "暂无。",
            "",
            "## 执行摘要",
            "",
            str(payload.get("executive_summary", "")).strip() or "暂无。",
            "",
            "## 论文摘要草案",
            "",
            str(payload.get("draft_abstract", "")).strip() or "暂无。",
            "",
            "## 写作高亮",
            "",
            highlights,
            "",
            "## 使用的证据 ID",
            "",
            evidence_lines,
            "",
            "## 使用的引用 ID",
            "",
            citation_lines,
        ]
    ) + "\n"
