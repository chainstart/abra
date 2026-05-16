"""综合判断当前稿件是否达到可投稿状态。"""

from __future__ import annotations

from services.research.models import (
    ExperimentGapReport,
    JournalFitAssessment,
    PaperRevisionResult,
    PublicationReadinessReport,
    SubmissionComplianceReport,
)


def assess_publication_readiness(
    *,
    revision_result: PaperRevisionResult | None,
    peer_reviews: list[dict],
    experiment_gap_report: ExperimentGapReport | None,
    journal_fit_assessment: JournalFitAssessment | None,
    submission_compliance: SubmissionComplianceReport | None,
) -> PublicationReadinessReport:
    """基于修稿、审稿、实验缺口和投稿合规做最终门禁。"""

    blockers: list[str] = []
    warnings: list[str] = []
    next_actions: list[str] = []

    if not revision_result or not revision_result.accepted:
        blockers.append("structured revision 尚未通过。")
        next_actions.append("继续根据 structured review 修订正文。")

    for review in peer_reviews or []:
        for item in review.get("blocker_issues") or []:
            blockers.append(f"{review.get('label', 'Reviewer')}: {item}")
        for item in review.get("major_concerns") or []:
            warnings.append(f"{review.get('label', 'Reviewer')}: {item}")

    if experiment_gap_report:
        blockers.extend(item.description for item in experiment_gap_report.blocker_gaps)
        warnings.extend(item.description for item in experiment_gap_report.major_gaps)
        for action in experiment_gap_report.next_best_experiments:
            if action not in next_actions:
                next_actions.append(action)

    if journal_fit_assessment:
        if journal_fit_assessment.fit_score < 7.5:
            blockers.append("期刊适配度仍偏低，结构或主张表达尚未达到稳定投稿水位。")
        warnings.extend(journal_fit_assessment.gaps[:4])
        for action in journal_fit_assessment.required_adjustments:
            if action and action not in next_actions:
                next_actions.append(action)

    if submission_compliance:
        if submission_compliance.blocker_count > 0:
            blockers.append(submission_compliance.summary)
        for item in submission_compliance.checks:
            if item.status != "passed" and item.remediation not in next_actions:
                next_actions.append(item.remediation)
        warnings.extend(
            item.details
            for item in submission_compliance.checks
            if item.status == "warning"
        )

    blockers = list(dict.fromkeys(blockers))
    warnings = list(dict.fromkeys(warnings))
    next_actions = list(dict.fromkeys(next_actions))

    hard_warning_tokens = [
        "counterfactual",
        "failure-path",
        "反证",
        "模板腔",
        "系统输出痕迹",
        "主张-证据映射",
        "参考文献",
    ]
    if any(token in item for token in hard_warning_tokens for item in warnings):
        blockers.append("当前仍存在影响严格期刊稿标准的高优先级 warning，暂不应视为最终可投稿。")

    if journal_fit_assessment:
        if journal_fit_assessment.overall_fit != "strong_fit":
            blockers.append("期刊适配度尚未达到 strong_fit，当前稿件仍应继续收束表达和验证边界。")
        for dimension in journal_fit_assessment.dimensions:
            if dimension.status == "pass":
                continue
            if dimension.dimension_id in {"boundary", "manuscript_style", "reproducibility"}:
                blockers.append(
                    dimension.required_action or dimension.gap or f"{dimension.label} 尚未闭环。"
                )

    if submission_compliance:
        critical_check_ids = {
            "claim_mapping",
            "counterfactual_conditions",
            "reference_style",
            "manuscript_style",
        }
        for item in submission_compliance.checks:
            if item.check_id in critical_check_ids and item.status != "passed":
                blockers.append(item.details)
                if item.remediation not in next_actions:
                    next_actions.append(item.remediation)

    blockers = list(dict.fromkeys(blockers))
    warnings = list(dict.fromkeys(warnings))
    next_actions = list(dict.fromkeys(next_actions))

    revision_score = revision_result.final_score if revision_result else 0.0
    fit_score = journal_fit_assessment.fit_score if journal_fit_assessment else 0.0
    compliance_score = 10.0
    if submission_compliance:
        compliance_score = max(
            0.0,
            10.0 - submission_compliance.blocker_count * 2.5 - submission_compliance.warning_count * 0.5,
        )
    readiness_score = round((revision_score * 0.35 + fit_score * 0.4 + compliance_score * 0.25), 1)

    status = (
        "ready_for_submission"
        if not blockers
        and not warnings
        and readiness_score >= 8.8
        and revision_score >= 8.5
        and fit_score >= 8.5
        and compliance_score >= 9.5
        and journal_fit_assessment is not None
        and journal_fit_assessment.overall_fit == "strong_fit"
        else "needs_revision"
    )
    summary = (
        "当前稿件已通过严格门禁，已达到当前系统下的可投稿阈值。"
        if status == "ready_for_submission"
        else "当前稿件仍存在会影响投稿判断的未闭环问题。"
    )
    return PublicationReadinessReport(
        status=status,
        readiness_score=readiness_score,
        summary=summary,
        blockers=blockers,
        warnings=warnings[:10],
        next_actions=next_actions[:10],
    )


def render_publication_readiness_markdown(report: PublicationReadinessReport | dict) -> str:
    """输出可投稿就绪度 Markdown。"""

    if isinstance(report, dict):
        status = str(report.get("status") or "")
        readiness_score = report.get("readiness_score", 0)
        summary = str(report.get("summary") or "")
        blockers = report.get("blockers") or []
        warnings = report.get("warnings") or []
        next_actions = report.get("next_actions") or []
    else:
        status = report.status
        readiness_score = report.readiness_score
        summary = report.summary
        blockers = report.blockers
        warnings = report.warnings
        next_actions = report.next_actions

    return "\n".join(
        [
            "# Publication Readiness",
            "",
            f"- Status: {status}",
            f"- Readiness Score: {readiness_score}",
            f"- Summary: {summary}",
            "",
            "## Blockers",
            "",
            *([f"- {item}" for item in blockers] or ["- 无"]),
            "",
            "## Warnings",
            "",
            *([f"- {item}" for item in warnings] or ["- 无"]),
            "",
            "## Next Actions",
            "",
            *([f"- {item}" for item in next_actions] or ["- 无"]),
            "",
        ]
    ).strip() + "\n"
