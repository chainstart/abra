"""识别论文当前仍缺哪些验证与实验。"""

from __future__ import annotations

from services.research.models import (
    ClaimEvidenceMatrix,
    ExperimentGapItem,
    ExperimentGapReport,
    ExperimentPlan,
    IncidentEvidencePackage,
)


def analyze_experiment_gaps(
    *,
    claim_evidence_matrix: ClaimEvidenceMatrix,
    experiment_plan: ExperimentPlan | None,
    incident_evidence_packages: list[IncidentEvidencePackage] | None = None,
) -> ExperimentGapReport:
    """根据主张矩阵和实验计划识别实验缺口。"""

    incident_evidence_packages = incident_evidence_packages or []
    blocker_gaps: list[ExperimentGapItem] = []
    major_gaps: list[ExperimentGapItem] = []
    minor_gaps: list[ExperimentGapItem] = []

    passed_verification_count = sum(
        1
        for package in incident_evidence_packages
        for item in package.verification_results
        if item.get("passed")
    )

    for row in claim_evidence_matrix.rows:
        if row.status == "missing":
            blocker_gaps.append(
                ExperimentGapItem(
                    gap_id=f"{row.claim_id}_blocker",
                    severity="blocker",
                    title="核心主张仍缺闭环",
                    description=f"主张“{row.claim}”尚未形成足够的证据、引用或验证闭环。",
                    linked_claims=[row.claim],
                    suggested_actions=[
                        "补齐与该主张直接对应的 incident 级证据或链上锚点。",
                        "为该主张补一条最小复现实验或明确反证条件。",
                    ],
                    unblock_condition="该主张至少形成 evidence + citation + verification 三要素中的强闭环组合。",
                )
            )
            continue
        if not row.experiment_refs and passed_verification_count == 0:
            blocker_gaps.append(
                ExperimentGapItem(
                    gap_id=f"{row.claim_id}_verification",
                    severity="blocker",
                    title="缺少最小复现实验",
                    description=f"主张“{row.claim}”尚未关联可执行的实验或已通过的 fork/PoC 验证。",
                    linked_claims=[row.claim],
                    suggested_actions=[
                        "补充本地主网 fork 或 PoC 验证。",
                        "把成功判据、失败条件和关键断言写成可复验记录。",
                    ],
                    unblock_condition="至少存在一个通过的验证结果，且能明确映射回该主张。",
                )
            )
            continue
        if row.status == "partial" or not row.experiment_refs:
            major_gaps.append(
                ExperimentGapItem(
                    gap_id=f"{row.claim_id}_major",
                    severity="major",
                    title="主张仍需补强验证",
                    description=f"主张“{row.claim}”已有部分证据，但实验或反证链条仍不完整。",
                    linked_claims=[row.claim],
                    suggested_actions=[
                        "增加与该主张一一对应的 counterfactual / negative case。",
                        "把正文中的论证强度收紧到当前验证覆盖范围内。",
                    ],
                    unblock_condition="正文能够说明该主张为何成立、何时失败、以及当前未覆盖什么。",
                )
            )

    if len(incident_evidence_packages) < 2:
        minor_gaps.append(
            ExperimentGapItem(
                gap_id="external_validity",
                severity="minor",
                title="外部有效性仍受单案例限制",
                description="当前研究主要建立在单个主案例或极少数相关 incident 上，外部有效性仍有限。",
                linked_claims=[row.claim for row in claim_evidence_matrix.rows[:2]],
                suggested_actions=[
                    "补充 1-2 个同类 incident 做对照。",
                    "在 Threats to Validity 中继续显式限制外推边界。",
                ],
                unblock_condition="至少形成一个附加对照案例，或把外推范围继续收窄到个案机制研究。",
            )
        )

    if experiment_plan and not any("反证" in step or "counter" in step.lower() for step in experiment_plan.procedures):
        major_gaps.append(
            ExperimentGapItem(
                gap_id="counterfactual_gap",
                severity="major",
                title="反证设计仍不够显式",
                description="当前计划虽包含验证设计，但缺少足够显式的 counterfactual / failure-path 记录。",
                linked_claims=[row.claim for row in claim_evidence_matrix.rows[:2]],
                suggested_actions=[
                    "为每条核心主张写出失败条件和不可复现情形。",
                    "明确哪些防护条件一旦成立，路径就应失败。",
                ],
                unblock_condition="正文和实验记录都能明确回答“什么情况下该主张不成立”。",
            )
        )

    next_best_experiments: list[str] = []
    for bucket in (blocker_gaps, major_gaps, minor_gaps):
        for item in bucket:
            for action in item.suggested_actions:
                if action not in next_best_experiments:
                    next_best_experiments.append(action)

    summary = (
        f"当前实验缺口包含 blocker {len(blocker_gaps)} 项、major {len(major_gaps)} 项、minor {len(minor_gaps)} 项。"
    )
    publishability_note = (
        "若 blocker 仍未关闭，则当前稿件不应宣称达到可投稿状态；"
        "若仅剩 major / minor，则应继续收紧主张边界并补充验证说明。"
    )
    return ExperimentGapReport(
        summary=summary,
        blocker_gaps=blocker_gaps,
        major_gaps=major_gaps,
        minor_gaps=minor_gaps,
        next_best_experiments=next_best_experiments[:8],
        publishability_note=publishability_note,
    )


def render_experiment_gap_report_markdown(report: ExperimentGapReport | dict) -> str:
    """输出实验缺口报告 Markdown。"""

    if isinstance(report, dict):
        summary = str(report.get("summary") or "")
        publishability_note = str(report.get("publishability_note") or "")
        blocker_gaps = report.get("blocker_gaps") or []
        major_gaps = report.get("major_gaps") or []
        minor_gaps = report.get("minor_gaps") or []
        next_best_experiments = report.get("next_best_experiments") or []
    else:
        summary = report.summary
        publishability_note = report.publishability_note
        blocker_gaps = [item.to_dict() for item in report.blocker_gaps]
        major_gaps = [item.to_dict() for item in report.major_gaps]
        minor_gaps = [item.to_dict() for item in report.minor_gaps]
        next_best_experiments = report.next_best_experiments

    sections = [
        "# Experiment Gap Report",
        "",
        f"- Summary: {summary}",
        f"- Publishability Note: {publishability_note}",
        "",
    ]
    for label, items in [
        ("Blocker Gaps", blocker_gaps),
        ("Major Gaps", major_gaps),
        ("Minor Gaps", minor_gaps),
    ]:
        sections.extend([f"## {label}", ""])
        if not items:
            sections.extend(["- None", ""])
            continue
        for item in items:
            sections.extend(
                [
                    f"### {item.get('title', '')}",
                    "",
                    f"- Severity: {item.get('severity', '')}",
                    f"- Description: {item.get('description', '')}",
                    f"- Linked Claims: {'；'.join(item.get('linked_claims', []) or []) or '暂无'}",
                    f"- Suggested Actions: {'；'.join(item.get('suggested_actions', []) or []) or '暂无'}",
                    f"- Unblock Condition: {item.get('unblock_condition', '')}",
                    "",
                ]
            )
    sections.extend(
        [
            "## Next Best Experiments",
            "",
            *([f"- {item}" for item in next_best_experiments] or ["- 暂无"]),
            "",
        ]
    )
    return "\n".join(sections).strip() + "\n"
