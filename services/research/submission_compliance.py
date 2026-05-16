"""检查当前稿件是否达到基本投稿合规要求。"""

from __future__ import annotations

import re

from services.research.models import (
    ContributionProfile,
    ReferenceValidationResult,
    SubmissionComplianceCheck,
    SubmissionComplianceReport,
)


def _count_reference_markers(markdown: str) -> int:
    refs_section = markdown.split("## References", 1)[-1] if "## References" in markdown else ""
    return len(re.findall(r"^\[\d+\]\s", refs_section, flags=re.MULTILINE))


def _manuscript_style_problem(markdown: str) -> str:
    """判断文稿是否仍有明显的模板化输出痕迹。"""

    problems: list[str] = []
    if sum(markdown.count(token) for token in ["当前版本", "当前稿件", "本文当前版本", "证据链条 "]) >= 4:
        problems.append("模板化提示语过多")
    if "证据链条 1" in markdown:
        problems.append("证据段落仍像系统导出")
    if "### Structured Evidence Chain" in markdown or "### Figure and Table Guide" in markdown:
        problems.append("Evidence 章节仍保留工作流式小标题")
    if "来源类型：" in markdown and "支撑级别：" in markdown:
        problems.append("参考文献格式仍像内部结构化字段")
    return "；".join(problems)


def _reference_style_problem(markdown: str) -> str:
    refs_section = markdown.split("## References", 1)[-1] if "## References" in markdown else ""
    problems: list[str] = []
    if "本文中的角色：" in refs_section:
        problems.append("参考文献仍保留内部角色说明")
    if "reports/" in refs_section:
        problems.append("参考文献仍暴露内部路径")
    return "；".join(problems)


def evaluate_submission_compliance(
    *,
    paper_markdown: str,
    reference_validation: ReferenceValidationResult | None,
    contribution_profile: ContributionProfile | None,
    has_verification: bool,
) -> SubmissionComplianceReport:
    """执行基础投稿合规检查。"""

    checks: list[SubmissionComplianceCheck] = []

    def add_check(check_id: str, label: str, passed: bool, *, severity: str, details: str, remediation: str, warning: bool = False) -> None:
        checks.append(
            SubmissionComplianceCheck(
                check_id=check_id,
                label=label,
                status="passed" if passed else "warning" if warning else "failed",
                severity=severity,
                details=details,
                remediation=remediation,
            )
        )

    abstract_match = re.search(r"## 摘要\s+([\s\S]*?)(?=\n## )", paper_markdown)
    abstract_text = abstract_match.group(1).strip() if abstract_match else ""
    abstract_length = len(abstract_text)
    add_check(
        "title_present",
        "标题存在",
        paper_markdown.startswith("# "),
        severity="blocker",
        details="稿件已包含标题。" if paper_markdown.startswith("# ") else "稿件缺少一级标题。",
        remediation="补齐论文标题并保持主题边界收敛。",
    )
    add_check(
        "abstract_present",
        "摘要存在",
        bool(abstract_text),
        severity="blocker",
        details="稿件已包含摘要。" if abstract_text else "稿件缺少摘要。",
        remediation="补齐摘要并明确研究问题、方法、证据来源与结论边界。",
    )
    add_check(
        "abstract_length",
        "摘要长度",
        180 <= abstract_length <= 900,
        severity="warning",
        details=f"当前摘要长度约为 {abstract_length} 字符。",
        remediation="将摘要控制在精炼但可辩护的长度范围内，避免过短或过长。",
        warning=True,
    )
    add_check(
        "keywords_present",
        "关键词存在",
        "**关键词：**" in paper_markdown,
        severity="warning",
        details="稿件已包含关键词。" if "**关键词：**" in paper_markdown else "稿件缺少关键词。",
        remediation="补齐关键词，便于索引和投稿格式化。",
        warning="**关键词：**" not in paper_markdown,
    )

    required_sections = [
        "## 1. Introduction",
        "## 6. Related Work",
        "## 8. Evaluation and Validation Plan",
        "## 10. Expected Contributions",
        "## 11. Threats to Validity",
        "## 12. Conclusion",
        "## References",
    ]
    missing_sections = [heading for heading in required_sections if heading not in paper_markdown]
    add_check(
        "required_sections",
        "核心章节完整",
        not missing_sections,
        severity="blocker",
        details="核心章节完整。" if not missing_sections else "缺少章节：" + "；".join(missing_sections),
        remediation="补齐缺失章节，避免投稿结构不完整。",
    )
    add_check(
        "claim_mapping",
        "主张-证据映射存在",
        "### Claim-to-Evidence Mapping" in paper_markdown and "主张 1" in paper_markdown,
        severity="warning",
        details="正文已显式给出 Claim-to-Evidence Mapping。"
        if "### Claim-to-Evidence Mapping" in paper_markdown and "主张 1" in paper_markdown
        else "正文缺少显式的主张-证据映射。",
        remediation="补一节主张-证据映射，避免核心论证难以审查。",
        warning="### Claim-to-Evidence Mapping" not in paper_markdown or "主张 1" not in paper_markdown,
    )
    counterfactual_present = (
        "### Counterfactual and Failure Conditions" in paper_markdown
        or "failure-path" in paper_markdown.lower()
        or "失败条件" in paper_markdown
    )
    add_check(
        "counterfactual_conditions",
        "反证与失败条件入文",
        counterfactual_present,
        severity="blocker",
        details="正文已显式说明 counterfactual / failure conditions。"
        if counterfactual_present
        else "正文仍缺少显式的反证与失败条件说明。",
        remediation="在验证节补写 counterfactual / failure-path，并明确哪些条件成立时路径应失败。",
    )
    add_check(
        "verification_summary",
        "验证摘要入文",
        (not has_verification) or "### Verification Summary" in paper_markdown,
        severity="blocker" if has_verification else "warning",
        details="已通过的验证结果已写入正文。"
        if (not has_verification) or "### Verification Summary" in paper_markdown
        else "存在通过的验证结果，但正文未显式写入 Verification Summary。",
        remediation="把通过的 fork/PoC 结果写入正文，并说明它支持哪条主张。",
        warning=not has_verification,
    )
    reference_count = _count_reference_markers(paper_markdown)
    add_check(
        "references_count",
        "参考文献数量",
        reference_count >= 3,
        severity="blocker",
        details=f"当前参考文献编号条目数为 {reference_count}。",
        remediation="确保 References 至少保留 3 条可辩护条目。",
    )
    add_check(
        "reference_validation",
        "引用校验通过",
        bool(reference_validation and reference_validation.rejected_count == 0),
        severity="blocker",
        details=reference_validation.summary if reference_validation else "当前未提供引用校验结果。",
        remediation="清理被拒绝引用，并确保核心结论仅依赖通过校验的引用。",
    )
    reference_style_problem = _reference_style_problem(paper_markdown)
    add_check(
        "reference_style",
        "参考文献写法达到论文正文标准",
        not reference_style_problem,
        severity="blocker",
        details="参考文献写法已脱离内部字段与路径说明。"
        if not reference_style_problem
        else f"参考文献仍存在明显工作流痕迹：{reference_style_problem}。",
        remediation="重写参考文献条目，删除内部角色说明、字段腔和路径暴露。",
    )
    add_check(
        "contribution_profile",
        "贡献提纯完成",
        bool(contribution_profile and contribution_profile.entries),
        severity="warning",
        details=contribution_profile.summary if contribution_profile else "当前未生成贡献提纯结果。",
        remediation="把贡献压缩为 2-3 条可辩护陈述，并逐条绑定证据与边界。",
        warning=not bool(contribution_profile and contribution_profile.entries),
    )
    noisy_markers = ["reports/", "TODO", "TBD", "FIXME"]
    has_noise = any(marker in paper_markdown for marker in noisy_markers)
    add_check(
        "noise_markers",
        "内部标记清理",
        not has_noise,
        severity="warning",
        details="正文未见内部路径或占位符。"
        if not has_noise
        else "正文仍包含内部路径或占位符标记。",
        remediation="删除 reports/ 路径、TODO/TBD 等内部痕迹。",
        warning=has_noise,
    )
    style_problem = _manuscript_style_problem(paper_markdown)
    add_check(
        "manuscript_style",
        "文稿表达达到投稿风格",
        not style_problem,
        severity="blocker",
        details="文稿整体表达已基本脱离系统输出腔。"
        if not style_problem
        else f"文稿仍存在明显的系统输出痕迹：{style_problem}。",
        remediation="重写摘要、相关工作、证据和参考文献写法，去掉流程说明式表达和内部字段腔调。",
    )

    blocker_count = sum(1 for item in checks if item.status == "failed" and item.severity == "blocker")
    warning_count = sum(1 for item in checks if item.status == "warning" or (item.status == "failed" and item.severity != "blocker"))
    status = "passed" if blocker_count == 0 else "failed"
    summary = (
        "投稿合规检查未发现 blocker。"
        if blocker_count == 0
        else f"投稿合规检查发现 {blocker_count} 个 blocker，当前不宜宣称可投稿。"
    )
    return SubmissionComplianceReport(
        status=status,
        summary=summary,
        blocker_count=blocker_count,
        warning_count=warning_count,
        checks=checks,
    )


def render_submission_compliance_markdown(report: SubmissionComplianceReport | dict) -> str:
    """输出投稿合规报告 Markdown。"""

    if isinstance(report, dict):
        status = str(report.get("status") or "")
        summary = str(report.get("summary") or "")
        blocker_count = int(report.get("blocker_count") or 0)
        warning_count = int(report.get("warning_count") or 0)
        checks = report.get("checks") or []
    else:
        status = report.status
        summary = report.summary
        blocker_count = report.blocker_count
        warning_count = report.warning_count
        checks = [item.to_dict() for item in report.checks]

    sections = [
        "# Submission Compliance Report",
        "",
        f"- Status: {status}",
        f"- Summary: {summary}",
        f"- Blocker Count: {blocker_count}",
        f"- Warning Count: {warning_count}",
        "",
    ]
    for item in checks:
        sections.extend(
            [
                f"## {item.get('label', '')}",
                "",
                f"- Status: {item.get('status', '')}",
                f"- Severity: {item.get('severity', '')}",
                f"- Details: {item.get('details', '')}",
                f"- Remediation: {item.get('remediation', '')}",
                "",
            ]
        )
    return "\n".join(sections).strip() + "\n"
