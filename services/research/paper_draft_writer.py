"""论文初稿写作器。"""

from __future__ import annotations

from services.analysis.models import AuditRunResult
from services.research.manuscript_package_builder import build_manuscript_package
from services.research.models import (
    ClaimEvidenceMatrix,
    CitationRecord,
    ContributionProfile,
    ExperimentPlan,
    ExperimentGapReport,
    IncidentEvidencePackage,
    LlmResearchEnhancement,
    ManuscriptPackage,
    PaperDraft,
    ResearchIdea,
)
from services.research.publication_task_design import PublicationTaskDesign
from services.research.section_writers import (
    write_abstract,
    write_background,
    write_conclusion,
    write_contributions,
    write_discussion,
    write_evaluation,
    write_evidence_and_observations,
    write_incident_context,
    write_introduction,
    write_methodology,
    write_problem_statement,
    write_references,
    write_related_work,
    write_research_questions,
    write_threats,
)


def _paper_title(research_idea: ResearchIdea, audit_result: AuditRunResult) -> str:
    base_title = " ".join((research_idea.title or "").split()).strip() or "研究论文草稿"
    protocol_name = " ".join((audit_result.classification.protocol_name or "").split()).strip()
    if not protocol_name or protocol_name in base_title or "为例" in base_title:
        return base_title
    return f"{base_title}：以 {protocol_name} 为例"


def _keyword_line(keywords: list[str]) -> str:
    return "**关键词：** " + "；".join(keywords[:6]) if keywords else "**关键词：** 暂无"


def _remaining_validation_gaps(experiment_gap_report: ExperimentGapReport | None) -> str:
    if not experiment_gap_report:
        return "本文尚未显式生成实验缺口报告。"

    lines: list[str] = []
    for label, items in [
        ("主要缺口", experiment_gap_report.major_gaps),
        ("次要缺口", experiment_gap_report.minor_gaps),
    ]:
        if not items:
            continue
        rendered = "；".join(
            f"{item.title}：{item.description}"
            for item in items[:2]
        )
        if rendered:
            lines.append(f"就 {label} 而言，现阶段仍需正视以下问题：{rendered}")
    if experiment_gap_report.next_best_experiments:
        lines.append("下一步最值得优先补强的动作包括：" + "；".join(experiment_gap_report.next_best_experiments[:4]))
    lines.append(experiment_gap_report.publishability_note)
    return "\n\n".join(lines)


def _verification_summary(audit_result: AuditRunResult) -> str:
    verification_lines = [
        item
        for item in (audit_result.semantic_summary.ast_summary.get("incident_verifications", []) or [])
        if item.get("passed")
    ]
    if not verification_lines:
        return "当前未记录通过的本地验证结果，因此本文不会把“可复现性”作为已完成结论写入正文。"
    statements = []
    for index, item in enumerate(verification_lines[:3], start=1):
        label = item.get("description") or item.get("match_path") or f"验证项 {index}"
        summary = item.get("summary") or "验证已通过。"
        statements.append(f"{index}. {label}：{summary}")
    coverage_index = len(statements) + 1
    statements.append(
        f"{coverage_index}. 覆盖范围说明：本次验证聚焦于 createMarket 零验证与欠抵押借款路径，"
        "尚未覆盖更广的 Oracle 设计变体与防御策略组合。"
    )
    return "\n".join(statements)


def _section_plan(
    package: ManuscriptPackage,
    *,
    contribution_profile: ContributionProfile | None,
    experiment_gap_report: ExperimentGapReport | None,
    audit_result: AuditRunResult,
) -> list[tuple[str, str]]:
    paper_type = package.paper_type or "case_study"
    related_work_content = (
        write_related_work(package)
        + "\n\n### 本文相对既有工作的增量\n\n"
        + (
            contribution_profile.novelty_positioning
            if contribution_profile
            else "本文的增量在于个案锚定的机制抽象与最小复现实证链，而非全新攻击原语。"
        )
    )
    evaluation_content = (
        write_evaluation(package)
        + "\n\n### Remaining Validation Gaps\n\n"
        + _remaining_validation_gaps(experiment_gap_report)
    )
    discussion_content = (
        write_discussion(package)
        + "\n\n### Verification Summary\n\n"
        + _verification_summary(audit_result)
    )
    if paper_type == "measurement":
        return [
            ("## 1. Introduction", write_introduction(package)),
            ("## 2. Problem Formulation and Dataset", write_background(package) + "\n\n### Incident Context\n\n" + write_incident_context(package)),
            ("## 3. Problem Statement", write_problem_statement(package)),
            ("## 4. Research Questions", write_research_questions(package)),
            ("## 5. Dataset and Incident Modeling", write_evidence_and_observations(package)),
            ("## 6. Related Work", related_work_content),
            ("## 7. Methodology", write_methodology(package)),
            ("## 8. Measurement Results and Validation", evaluation_content),
            ("## 9. Discussion", discussion_content),
            ("## 10. Expected Contributions", write_contributions(package)),
            ("## 11. Threats to Validity", write_threats(package)),
            ("## 12. Conclusion", write_conclusion(package)),
        ]
    if paper_type == "defense":
        return [
            ("## 1. Introduction", write_introduction(package)),
            ("## 2. Threat Model and Context", write_background(package) + "\n\n### Incident Context\n\n" + write_incident_context(package)),
            ("## 3. Problem Statement", write_problem_statement(package)),
            ("## 4. Research Questions", write_research_questions(package)),
            ("## 5. Design Claims and Security Model", write_evidence_and_observations(package)),
            ("## 6. Related Work", related_work_content),
            ("## 7. Methodology", write_methodology(package)),
            ("## 8. Security Evaluation and Counterfactual Validation", evaluation_content),
            ("## 9. Design Discussion", discussion_content),
            ("## 10. Expected Contributions", write_contributions(package)),
            ("## 11. Threats to Validity", write_threats(package)),
            ("## 12. Conclusion", write_conclusion(package)),
        ]
    return [
        ("## 1. Introduction", write_introduction(package)),
        ("## 2. Background and Context", write_background(package) + "\n\n### Incident Context\n\n" + write_incident_context(package)),
        ("## 3. Problem Statement", write_problem_statement(package)),
        ("## 4. Research Questions", write_research_questions(package)),
        ("## 5. Evidence and Observations", write_evidence_and_observations(package)),
        ("## 6. Related Work", related_work_content),
        ("## 7. Methodology", write_methodology(package)),
        ("## 8. Evaluation and Validation Plan", evaluation_content),
        ("## 9. Preliminary Results and Discussion", discussion_content),
        ("## 10. Expected Contributions", write_contributions(package)),
        ("## 11. Threats to Validity", write_threats(package)),
        ("## 12. Conclusion", write_conclusion(package)),
    ]


def render_paper_draft(
    *,
    research_idea: ResearchIdea,
    audit_result: AuditRunResult,
    citations: list[CitationRecord] | None = None,
    experiment_plan: ExperimentPlan | None = None,
    llm_enhancement: LlmResearchEnhancement | None = None,
    contribution_profile: ContributionProfile | None = None,
    claim_evidence_matrix: ClaimEvidenceMatrix | None = None,
    experiment_gap_report: ExperimentGapReport | None = None,
    incident_evidence_packages: list[IncidentEvidencePackage] | None = None,
    manuscript_package: ManuscriptPackage | None = None,
    publication_task_design: PublicationTaskDesign | None = None,
) -> PaperDraft:
    """根据 research package 生成论文初稿。"""

    package = manuscript_package or build_manuscript_package(
        research_idea=research_idea,
        audit_result=audit_result,
        citations=citations or [],
        experiment_plan=experiment_plan,
        contribution_profile=contribution_profile,
        claim_evidence_matrix=claim_evidence_matrix,
        incident_evidence_packages=incident_evidence_packages or [],
        publication_task_design=publication_task_design,
    )
    section_plan = _section_plan(
        package,
        contribution_profile=contribution_profile,
        experiment_gap_report=experiment_gap_report,
        audit_result=audit_result,
    )

    markdown = "\n".join(
        [
            f"# {_paper_title(research_idea, audit_result)}",
            "",
            "## 摘要",
            "",
            write_abstract(package),
            "",
            _keyword_line(package.keywords),
            "",
            *[
                item
                for heading, content in section_plan
                for item in [heading, "", content, ""]
            ],
            "## References",
            "",
            write_references(package),
            "",
        ]
    ).strip() + "\n"

    return PaperDraft(
        title=research_idea.title,
        markdown=markdown,
    )
