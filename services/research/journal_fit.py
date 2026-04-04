"""评估当前稿件与目标期刊风格的适配程度。"""

from __future__ import annotations

import re

from services.research.models import (
    ClaimEvidenceMatrix,
    ContributionProfile,
    JournalFitAssessment,
    JournalFitDimension,
    ReferenceValidationResult,
)


def _section_present(markdown: str, heading: str) -> bool:
    return heading in markdown


def _style_red_flags(markdown: str) -> list[str]:
    """识别明显的模板腔和系统输出味。"""

    flags: list[str] = []
    phrase_count = sum(markdown.count(token) for token in ["当前版本", "当前稿件", "本文当前版本", "证据链条 ", "当前目标 "])
    if phrase_count >= 4:
        flags.append("全文仍有较多模板化提示语与工作流腔调。")
    if "证据链条 1" in markdown or "证据链条 2" in markdown:
        flags.append("证据部分仍保留流水号式系统输出写法。")
    if "### Structured Evidence Chain" in markdown or "### Figure and Table Guide" in markdown:
        flags.append("Evidence 章节仍带有工作流导出式小标题。")
    if "RQ1." in markdown and markdown.count("RQ") >= 3:
        flags.append("研究问题段落仍偏提纲式，未完全过渡到论文叙述。")
    if "来源类型：" in markdown and "支撑级别：" in markdown:
        flags.append("参考文献仍偏内部结构化导出格式，不够接近期刊参考条目。")
    if "本文中的角色：" in markdown:
        flags.append("参考文献仍保留内部角色说明。")
    return flags


def assess_journal_fit(
    *,
    paper_markdown: str,
    contribution_profile: ContributionProfile | None,
    claim_evidence_matrix: ClaimEvidenceMatrix | None,
    reference_validation: ReferenceValidationResult | None,
    has_verification: bool,
) -> JournalFitAssessment:
    """给出更贴近安全研究期刊稿的适配评估。"""

    dimensions: list[JournalFitDimension] = []
    required_structure = all(
        _section_present(paper_markdown, heading)
        for heading in [
            "## 摘要",
            "## 1. Introduction",
            "## 6. Related Work",
            "## 8. Evaluation and Validation Plan",
            "## 11. Threats to Validity",
            "## 12. Conclusion",
            "## References",
        ]
    )
    dimensions.append(
        JournalFitDimension(
            dimension_id="structure",
            label="结构完整性",
            score=9.0 if required_structure else 4.5,
            status="pass" if required_structure else "needs_work",
            evidence="论文主结构已覆盖摘要、引言、相关工作、验证、有效性威胁、结论和参考文献。"
            if required_structure
            else "当前稿件仍缺少部分期刊常见核心章节。",
            gap="" if required_structure else "补齐期刊型论文的核心章节结构。",
            required_action="" if required_structure else "确保所有核心章节在正文中显式出现。",
        )
    )
    contribution_ok = bool(contribution_profile and contribution_profile.entries)
    dimensions.append(
        JournalFitDimension(
            dimension_id="contribution",
            label="贡献清晰度",
            score=8.8 if contribution_ok else 4.0,
            status="pass" if contribution_ok else "needs_work",
            evidence=contribution_profile.summary if contribution_profile else "当前尚未形成明确的贡献提纯结果。",
            gap="" if contribution_ok else "贡献表达仍停留在松散想法层面。",
            required_action="" if contribution_ok else "把贡献压缩为可辩护的核心句并逐条绑定证据。",
        )
    )
    matrix_ok = bool(claim_evidence_matrix and claim_evidence_matrix.covered_count >= 1 and claim_evidence_matrix.missing_count == 0)
    dimensions.append(
        JournalFitDimension(
            dimension_id="evidence_grounding",
            label="主张闭环",
            score=8.8 if matrix_ok else 5.0,
            status="pass" if matrix_ok else "needs_work",
            evidence=claim_evidence_matrix.summary if claim_evidence_matrix else "当前未生成主张-证据矩阵。",
            gap="" if matrix_ok else "核心主张仍有 missing / partial 闭环。",
            required_action="" if matrix_ok else "压缩主张范围，并补齐 claim 对应的证据、引用和验证。",
        )
    )
    counterfactual_written = (
        "### Counterfactual and Failure Conditions" in paper_markdown
        or "failure-path" in paper_markdown.lower()
        or "失败条件" in paper_markdown
    )
    dimensions.append(
        JournalFitDimension(
            dimension_id="reproducibility",
            label="可复现性表达",
            score=8.8 if has_verification and "### Verification Summary" in paper_markdown and counterfactual_written else 4.0,
            status="pass" if has_verification and "### Verification Summary" in paper_markdown and counterfactual_written else "needs_work",
            evidence="正文已显式报告 Verification Summary，并把 failure conditions 写回验证节。"
            if has_verification and "### Verification Summary" in paper_markdown and counterfactual_written
            else "当前稿件对可复现性的正文表达仍不足。",
            gap="" if has_verification and "### Verification Summary" in paper_markdown and counterfactual_written else "最小复现实验、失败条件或反证边界尚未被充分写入正文。",
            required_action="" if has_verification and "### Verification Summary" in paper_markdown and counterfactual_written else "把通过的 fork/PoC 结果、成功判据与 failure-path 一并写进正文。",
        )
    )
    ref_ok = bool(reference_validation and reference_validation.accepted_count >= 3 and reference_validation.rejected_count == 0)
    dimensions.append(
        JournalFitDimension(
            dimension_id="related_work",
            label="相关工作定位",
            score=8.2 if ref_ok else 4.5,
            status="pass" if ref_ok else "needs_work",
            evidence=reference_validation.summary if reference_validation else "当前未生成引用校验结果。",
            gap="" if ref_ok else "相关工作仍存在质量或定位问题。",
            required_action="" if ref_ok else "继续清理参考级材料，确保核心结论不依赖弱引用。",
        )
    )
    boundary_ok = (
        "## 11. Threats to Validity" in paper_markdown
        and "不据此直接推出" in paper_markdown
        and counterfactual_written
    )
    dimensions.append(
        JournalFitDimension(
            dimension_id="boundary",
            label="结论边界控制",
            score=8.6 if boundary_ok else 5.0,
            status="pass" if boundary_ok else "needs_work",
            evidence="正文已显式讨论 Threats to Validity，并限制外推边界。"
            if boundary_ok
            else "当前稿件的边界控制仍不够明确。",
            gap="" if boundary_ok else "仍需进一步压缩主张的适用范围。",
            required_action="" if boundary_ok else "在摘要、结果和结论中继续降低超范围表述强度。",
        )
    )
    style_flags = _style_red_flags(paper_markdown)
    dimensions.append(
        JournalFitDimension(
            dimension_id="manuscript_style",
            label="成稿表达质量",
            score=8.2 if not style_flags else 4.2,
            status="pass" if not style_flags else "needs_work",
            evidence="正文整体已接近期刊论文的连贯叙述风格。"
            if not style_flags
            else "；".join(style_flags),
            gap="" if not style_flags else "文稿仍有明显模板腔与系统输出痕迹。",
            required_action="" if not style_flags else "重写摘要、相关工作、证据和验证段落，去掉流程说明式表达。",
        )
    )

    fit_score = round(sum(item.score for item in dimensions) / max(len(dimensions), 1), 1)
    gaps = [item.gap for item in dimensions if item.gap]
    required_adjustments = [item.required_action for item in dimensions if item.required_action]
    strengths = [item.evidence for item in dimensions if item.status == "pass"]
    overall_fit = (
        "strong_fit"
        if fit_score >= 8.5 and not gaps
        else "workable_fit"
        if fit_score >= 7.0
        else "weak_fit"
    )
    return JournalFitAssessment(
        target_profile="区块链安全 incident-driven case study / systems-style journal manuscript",
        article_type="incident-grounded security case study",
        fit_score=fit_score,
        overall_fit=overall_fit,
        strengths=strengths[:6],
        gaps=gaps[:6],
        required_adjustments=required_adjustments[:6],
        dimensions=dimensions,
    )


def render_journal_fit_markdown(assessment: JournalFitAssessment | dict) -> str:
    """输出期刊适配评估 Markdown。"""

    if isinstance(assessment, dict):
        target_profile = str(assessment.get("target_profile") or "")
        article_type = str(assessment.get("article_type") or "")
        fit_score = assessment.get("fit_score", 0)
        overall_fit = str(assessment.get("overall_fit") or "")
        strengths = assessment.get("strengths") or []
        gaps = assessment.get("gaps") or []
        required_adjustments = assessment.get("required_adjustments") or []
        dimensions = assessment.get("dimensions") or []
    else:
        target_profile = assessment.target_profile
        article_type = assessment.article_type
        fit_score = assessment.fit_score
        overall_fit = assessment.overall_fit
        strengths = assessment.strengths
        gaps = assessment.gaps
        required_adjustments = assessment.required_adjustments
        dimensions = [item.to_dict() for item in assessment.dimensions]

    sections = [
        "# Journal Fit Assessment",
        "",
        f"- Target Profile: {target_profile}",
        f"- Article Type: {article_type}",
        f"- Fit Score: {fit_score}",
        f"- Overall Fit: {overall_fit}",
        "",
        "## Strengths",
        "",
        *([f"- {item}" for item in strengths] or ["- 暂无"]),
        "",
        "## Gaps",
        "",
        *([f"- {item}" for item in gaps] or ["- 暂无"]),
        "",
        "## Required Adjustments",
        "",
        *([f"- {item}" for item in required_adjustments] or ["- 暂无"]),
        "",
    ]
    for item in dimensions:
        sections.extend(
            [
                f"## {item.get('label', '')}",
                "",
                f"- Score: {item.get('score', 0)}",
                f"- Status: {item.get('status', '')}",
                f"- Evidence: {item.get('evidence', '')}",
                f"- Gap: {item.get('gap', '') or '无'}",
                f"- Required Action: {item.get('required_action', '') or '无'}",
                "",
            ]
        )
    return "\n".join(sections).strip() + "\n"
