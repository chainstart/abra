"""研究备忘录生成器。"""

from __future__ import annotations

from services.analysis.models import AuditRunResult
from services.research.models import (
    CitationRecord,
    ExperimentPlan,
    LlmResearchEnhancement,
    ResearchIdea,
    ResearchMemo,
)


def render_research_memo(
    *,
    research_idea: ResearchIdea,
    audit_result: AuditRunResult,
    citations: list[CitationRecord],
    experiment_plan: ExperimentPlan,
    llm_enhancement: LlmResearchEnhancement | None = None,
) -> ResearchMemo:
    """生成结构化研究备忘录。"""

    evidence_lines = "\n".join(
        [
            (
                f"- [{item.evidence_type}/{item.strength}] {item.title}\n"
                f"  - 证据摘要: {item.summary}\n"
                f"  - 来源: {item.source_ref}\n"
                f"  - 解释: {item.reasoning}"
            )
            for item in (research_idea.evidence_chain or [])
        ]
    ) or "- 暂无支持性证据摘要。"

    citation_lines = "\n".join(
        [
            (
                f"- [{citation.source_type}/{citation.support_level}] {citation.title}\n"
                f"  - 支撑主张: {citation.claim_supported}\n"
                f"  - 关键结论: {citation.key_takeaway or citation.snippet}\n"
                f"  - 采用理由: {citation.citation_reason}"
            )
            for citation in citations
        ]
    ) or "- 暂无可引用的本地 related work。"

    experiment_design_lines = "\n".join(
        [
            (
                f"### {design.title}\n\n"
                f"- 目标: {design.objective}\n"
                f"- 数据集: {'；'.join(design.datasets)}\n"
                f"- 基线: {'；'.join(design.baselines)}\n"
                f"- 指标: {'；'.join(design.metrics)}\n"
                f"- 步骤: {'；'.join(design.procedures)}\n"
                f"- 成功标准: {'；'.join(design.success_criteria)}\n"
                f"- 失败条件: {'；'.join(design.failure_criteria)}\n"
                f"- 产出: {'；'.join(design.deliverables)}"
            )
            for design in (experiment_plan.designs or [])
        ]
    ) or "- 暂无实验设计。"

    contribution_lines = "\n".join(
        f"- {item}" for item in (research_idea.expected_contributions or [])
    ) or "- 暂无预期贡献描述。"

    risk_lines = "\n".join(
        f"- {item}" for item in (experiment_plan.open_risks or [])
    ) or "- 暂无显式风险。"

    ranking_context = (
        f"- 研究方向状态: {research_idea.decision_status}\n"
        f"- 选择理由: {research_idea.selection_reason}\n"
        f"- 综合评分: {research_idea.composite_score}\n"
        f"- 证据评分: {research_idea.evidence_score}\n"
        f"- 可执行性评分: {research_idea.feasibility_score}\n"
        f"- 影响力评分: {research_idea.impact_score}\n"
        f"- novelty 评分: {research_idea.novelty_score}"
    )
    llm_block = ""
    if llm_enhancement:
        llm_block = "\n".join(
            [
                "## 1.5 AI 增强摘要",
                "",
                f"- Provider: {llm_enhancement.provider}",
                f"- Model: {llm_enhancement.model}",
                f"- Status: {llm_enhancement.status}",
                "",
                "### AI 执行摘要",
                "",
                llm_enhancement.executive_summary or "暂无。",
                "",
                "### AI 写作高亮",
                "",
                "\n".join(f"- {item}" for item in llm_enhancement.writing_highlights)
                or "- 暂无额外高亮。",
                "",
            ]
        )

    markdown = "\n".join(
        [
            f"# {research_idea.title} 研究备忘录",
            "",
            "## 1. 方向选择结论",
            "",
            ranking_context,
            "",
            llm_block,
            "## 2. 问题定义",
            "",
            research_idea.problem_statement or research_idea.hypothesis,
            "",
            "## 3. 核心假设",
            "",
            research_idea.hypothesis,
            "",
            "## 4. 研究问题",
            "",
            "\n".join(f"- {question}" for question in (research_idea.research_questions or [])),
            "",
            "## 5. 关键观察",
            "",
            "\n".join(f"- {item}" for item in (research_idea.key_observations or [])),
            "",
            "## 6. 当前证据链",
            "",
            evidence_lines,
            "",
            "## 7. Related Work 与引用理由",
            "",
            citation_lines,
            "",
            "## 8. 实验设计",
            "",
            experiment_design_lines,
            "",
            "## 9. 预期贡献",
            "",
            contribution_lines,
            "",
            "## 10. 风险与边界",
            "",
            risk_lines,
            "",
            "## 11. 当前目标上下文",
            "",
            f"- 协议: {audit_result.classification.protocol_name}",
            f"- 类型: {audit_result.classification.protocol_type}",
            f"- finding 总数: {audit_result.audit_summary.total_findings}",
            f"- 历史案例数: {len(audit_result.related_incidents)}",
            f"- Solidity 文件数: {audit_result.ingestion.solidity_file_count}",
        ]
    ) + "\n"

    return ResearchMemo(
        title=f"{research_idea.title} 研究备忘录",
        markdown=markdown,
    )
