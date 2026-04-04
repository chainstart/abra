"""最小任务编排器。

这不是最终的智能 Agent，但它把当前已经完成的能力统一到一个入口，
后续接 LLM、任务规划、工具选择时，不需要再推翻现有服务。
"""

from __future__ import annotations

from tools.analyzers.base import Severity
from services.analysis.presentation import build_audit_presentation
from services.agent.models import AgentTaskResult, TaskStep
from services.analysis.audit_report_writer import render_audit_report
from services.analysis.audit_service import run_audit
from services.research.incident_research_workflow_service import (
    run_discovered_candidate_research_workflow,
    run_event_discovery_research_workflow,
    run_incident_research_workflow,
)
from services.research.journal_fit import assess_journal_fit
from services.research.peer_review_cycle import run_peer_review_cycle
from services.research.presentation import build_research_presentation
from services.research.publication_readiness import assess_publication_readiness
from services.research.rollback_planner import build_rollback_plan
from services.research.review_views import build_peer_review_views, has_blocking_peer_review_issues
from services.research.research_workflow_service import run_research_workflow
from services.research.submission_compliance import evaluate_submission_compliance


def run_audit_task(
    *,
    target: str,
    analyzer_names: list[str] | None = None,
    minimum_severity: Severity = Severity.INFO,
) -> AgentTaskResult:
    """执行审计任务，并返回统一任务结果。"""

    steps = [
        TaskStep(name="contract_ingestion", status="completed", detail="目标接入成功。"),
        TaskStep(name="protocol_classification", status="completed", detail="协议分类成功。"),
        TaskStep(name="static_analysis", status="completed", detail="静态分析完成。"),
        TaskStep(name="incident_retrieval", status="completed", detail="历史案例检索完成。"),
        TaskStep(name="report_writing", status="completed", detail="审计报告已生成。"),
    ]

    audit_result = run_audit(
        target=target,
        analyzer_names=analyzer_names,
        minimum_severity=minimum_severity,
    )
    markdown_report = render_audit_report(audit_result)

    return AgentTaskResult(
        task_type="audit",
        target=target,
        status="completed",
        steps=steps,
        payload={
            "audit_result": audit_result.to_dict(),
            "audit_presentation": build_audit_presentation(audit_result),
            "markdown_report": markdown_report,
        },
    )


def run_research_task(
    *,
    target: str | None = None,
    incident_id: str | None = None,
    candidate_id: str | None = None,
    auto_discover: bool = False,
    analyzer_names: list[str] | None = None,
    minimum_severity: Severity = Severity.INFO,
) -> AgentTaskResult:
    """执行研究任务，并返回统一任务结果。"""

    if incident_id:
        workflow_result = run_incident_research_workflow(incident_id=incident_id)
        task_target = f"incident://{incident_id}"
        steps_prefix = [
            TaskStep(name="incident_load", status="completed", detail="历史攻击事件已加载。"),
            TaskStep(name="incident_hydration", status="completed", detail="攻击交易链上证据已同步。"),
            TaskStep(name="incident_verification", status="completed", detail="可用的本地 fork / PoC 验证已执行。"),
        ]
    elif auto_discover:
        workflow_result = run_event_discovery_research_workflow()
        task_target = "autodiscovery://latest"
        discovery = workflow_result.event_discovery_result
        steps_prefix = [
            TaskStep(
                name="event_discovery",
                status="completed",
                detail=(
                    discovery.summary
                    if discovery
                    else "系统已尝试自动发现最新攻击事件候选。"
                ),
            ),
            TaskStep(name="candidate_load", status="completed", detail="自动发现事件已被转换为统一 incident 模型。"),
            TaskStep(name="incident_hydration", status="completed", detail="攻击交易链上证据已同步。"),
        ]
    elif candidate_id:
        workflow_result = run_discovered_candidate_research_workflow(candidate_id=candidate_id)
        task_target = f"candidate://{candidate_id}"
        steps_prefix = [
            TaskStep(name="candidate_load", status="completed", detail="外部发现事件候选已加载。"),
            TaskStep(name="candidate_research", status="completed", detail="候选事件已进入研究门禁与选题流程。"),
        ]
    else:
        if not target:
            raise ValueError("研究任务需要 target、incident_id 或 candidate_id。")
        workflow_result = run_research_workflow(
            target=target,
            analyzer_names=analyzer_names,
            minimum_severity=minimum_severity,
        )
        task_target = target
        steps_prefix = [
            TaskStep(name="audit_baseline", status="completed", detail="基础审计结果已生成。"),
            TaskStep(name="incident_retrieval", status="completed", detail="历史案例已关联。"),
        ]
    selected_title = (
        workflow_result.selected_idea.title
        if workflow_result.selected_idea
        else "暂无主线方向"
    )
    task_design_steps = [
        TaskStep(
            name=node.task_id,
            status="completed",
            detail=(
                f"{node.goal} "
                f"输出: {'；'.join(node.outputs[:3]) or '暂无'}。"
            ),
        )
        for node in ((workflow_result.publication_task_design.tasks if workflow_result.publication_task_design else [])[:11])
    ]

    steps = steps_prefix + [
        TaskStep(
            name="idea_generation",
            status="completed",
            detail=f"已生成 {len(workflow_result.research_ideas)} 个候选研究方向。",
        ),
        TaskStep(
            name="idea_selection",
            status="completed",
            detail=f"主线研究方向已确定：{selected_title}。",
        ),
        TaskStep(
            name="evidence_gate",
            status=(
                "completed"
                if workflow_result.evidence_assessment
                and workflow_result.evidence_assessment.status == "sufficient"
                else "completed"
                if workflow_result.evidence_assessment
                and workflow_result.evidence_assessment.status == "conditional"
                else "failed"
            ),
            detail=(
                workflow_result.evidence_assessment.summary
                if workflow_result.evidence_assessment
                else "未生成证据充分性评估。"
            ),
        ),
    ] + task_design_steps + [
        TaskStep(
            name="llm_enhancement",
            status=(
                "completed"
                if workflow_result.llm_status == "completed"
                else "fallback"
                if workflow_result.llm_status == "fallback_to_rules"
                else "partial"
                if workflow_result.llm_status == "partial"
                else "blocked"
                if workflow_result.llm_status == "blocked_by_evidence_gate"
                else "failed"
                if workflow_result.llm_status == "failed"
                else "skipped"
            ),
            detail=(
                "已完成证据约束的 AI 研究增强。"
                if workflow_result.llm_status == "completed"
                else f"AI 方向生成失败，系统已回退到规则层：{workflow_result.llm_error}"
                if workflow_result.llm_status == "fallback_to_rules"
                else f"AI 已参与部分研究步骤，但最终摘要阶段未完成：{workflow_result.llm_error}"
                if workflow_result.llm_status == "partial"
                else "AI 最终摘要与论文草案已被证据门禁阻断。"
                if workflow_result.llm_status == "blocked_by_evidence_gate"
                else f"AI 研究增强失败，已回退到本地证据工作流：{workflow_result.llm_error}"
                if workflow_result.llm_status == "failed"
                else "当前未启用或未完成 AI 研究增强，结果来自本地证据驱动工作流。"
            ),
        ),
        TaskStep(
            name="reference_validation",
            status="completed",
            detail=(
                workflow_result.reference_validation.summary
                if workflow_result.reference_validation
                else "未执行引用校验。"
            ),
        ),
        TaskStep(
            name="related_work",
            status="completed",
            detail=f"已整理 {len(workflow_result.citations)} 条相关工作与案例引用。",
        ),
        TaskStep(
            name="contribution_crystallization",
            status="completed",
            detail=(
                workflow_result.contribution_profile.summary
                if workflow_result.contribution_profile
                else "未生成贡献提纯结果。"
            ),
        ),
        TaskStep(
            name="claim_evidence_matrix",
            status="completed",
            detail=(
                workflow_result.claim_evidence_matrix.summary
                if workflow_result.claim_evidence_matrix
                else "未生成主张-证据矩阵。"
            ),
        ),
        TaskStep(name="experiment_plan", status="completed", detail="结构化实验计划已生成。"),
        TaskStep(
            name="experiment_gap_analysis",
            status="completed",
            detail=(
                workflow_result.experiment_gap_report.summary
                if workflow_result.experiment_gap_report
                else "未生成实验缺口报告。"
            ),
        ),
        TaskStep(name="research_memo", status="completed", detail="研究备忘录已生成。"),
        TaskStep(name="paper_draft", status="completed", detail="论文初稿已生成。"),
        TaskStep(
            name="revision",
            status=(
                "completed"
                if workflow_result.revision_result and workflow_result.revision_result.accepted
                else "failed"
                if workflow_result.revision_result
                else "skipped"
            ),
            detail=(
                workflow_result.revision_result.summary
                if workflow_result.revision_result
                else "未执行论文修订评审。"
            ),
        ),
    ]

    effective_paper_draft = workflow_result.paper_draft
    effective_revision_result = workflow_result.revision_result
    peer_review_addressed_changes: list[str] = []
    peer_reviews: list[dict] = []
    if (
        workflow_result.paper_draft
        and workflow_result.revision_result
        and workflow_result.evidence_assessment
        and workflow_result.reference_validation
    ):
        (
            effective_paper_draft,
            effective_revision_result,
            peer_reviews,
            peer_review_addressed_changes,
        ) = run_peer_review_cycle(
            paper_draft=workflow_result.paper_draft,
            revision_result=workflow_result.revision_result,
            evidence_assessment=workflow_result.evidence_assessment.to_dict(),
            reference_validation=workflow_result.reference_validation.to_dict(),
            task_steps=[step.to_dict() for step in steps],
            citations=workflow_result.citations,
            incident_evidence_packages=workflow_result.incident_evidence_packages or [],
            contribution_profile=(
                workflow_result.contribution_profile.to_dict()
                if workflow_result.contribution_profile
                else {}
            ),
            claim_evidence_matrix=(
                workflow_result.claim_evidence_matrix.to_dict()
                if workflow_result.claim_evidence_matrix
                else {}
            ),
            experiment_gap_report=(
                workflow_result.experiment_gap_report.to_dict()
                if workflow_result.experiment_gap_report
                else {}
            ),
            journal_fit_assessment=(
                workflow_result.journal_fit_assessment.to_dict()
                if workflow_result.journal_fit_assessment
                else {}
            ),
            submission_compliance=(
                workflow_result.submission_compliance.to_dict()
                if workflow_result.submission_compliance
                else {}
            ),
        )
    else:
        peer_reviews = build_peer_review_views(
            (
                workflow_result.revision_result.to_dict()
                if workflow_result.revision_result
                else {}
            ),
            evidence_assessment=(
                workflow_result.evidence_assessment.to_dict()
                if workflow_result.evidence_assessment
                else {}
            ),
            reference_validation=(
                workflow_result.reference_validation.to_dict()
                if workflow_result.reference_validation
                else {}
            ),
            task_steps=[step.to_dict() for step in steps],
            contribution_profile=(
                workflow_result.contribution_profile.to_dict()
                if workflow_result.contribution_profile
                else {}
            ),
            claim_evidence_matrix=(
                workflow_result.claim_evidence_matrix.to_dict()
                if workflow_result.claim_evidence_matrix
                else {}
            ),
            experiment_gap_report=(
                workflow_result.experiment_gap_report.to_dict()
                if workflow_result.experiment_gap_report
                else {}
            ),
            journal_fit_assessment=(
                workflow_result.journal_fit_assessment.to_dict()
                if workflow_result.journal_fit_assessment
                else {}
            ),
            submission_compliance=(
                workflow_result.submission_compliance.to_dict()
                if workflow_result.submission_compliance
                else {}
            ),
            paper_markdown=(
                workflow_result.revision_result.revised_markdown
                if workflow_result.revision_result and workflow_result.revision_result.revised_markdown
                else workflow_result.paper_draft.markdown
                if workflow_result.paper_draft
                else ""
            ),
            use_llm=True,
        )
    peer_review_has_blockers = has_blocking_peer_review_issues(peer_reviews)
    effective_markdown = (
        effective_revision_result.revised_markdown
        if effective_revision_result and effective_revision_result.revised_markdown
        else effective_paper_draft.markdown
        if effective_paper_draft
        else ""
    )
    has_verification = any(
        item.get("passed")
        for package in (workflow_result.incident_evidence_packages or [])
        for item in package.verification_results
    )
    final_journal_fit_assessment = (
        assess_journal_fit(
            paper_markdown=effective_markdown,
            contribution_profile=workflow_result.contribution_profile,
            claim_evidence_matrix=workflow_result.claim_evidence_matrix,
            reference_validation=workflow_result.reference_validation,
            has_verification=has_verification,
        )
        if effective_markdown
        else workflow_result.journal_fit_assessment
    )
    final_submission_compliance = (
        evaluate_submission_compliance(
            paper_markdown=effective_markdown,
            reference_validation=workflow_result.reference_validation,
            contribution_profile=workflow_result.contribution_profile,
            has_verification=has_verification,
        )
        if effective_markdown
        else workflow_result.submission_compliance
    )
    final_publication_readiness = assess_publication_readiness(
        revision_result=effective_revision_result,
        peer_reviews=peer_reviews,
        experiment_gap_report=workflow_result.experiment_gap_report,
        journal_fit_assessment=final_journal_fit_assessment,
        submission_compliance=final_submission_compliance,
    )
    final_rollback_plan = build_rollback_plan(
        peer_reviews=peer_reviews,
        publication_readiness=final_publication_readiness.to_dict(),
    )

    revision_step_status = (
        "completed"
        if effective_revision_result and effective_revision_result.accepted
        else "failed"
        if effective_revision_result
        else "skipped"
    )
    steps[-1] = TaskStep(
        name="revision",
        status=revision_step_status,
        detail=(
            effective_revision_result.summary
            if effective_revision_result
            else "未执行论文修订评审。"
        ),
    )
    steps.append(
        TaskStep(
            name="peer_review",
            status=(
                "completed"
                if peer_reviews and not peer_review_has_blockers
                else "partial"
                if peer_reviews
                else "skipped"
            ),
            detail=(
                "AI reviewers 已完成多视角审稿，当前未发现新的 blocker / major issue。"
                if peer_reviews and not peer_review_has_blockers
                else f"AI reviewers 已完成多视角审稿，并提出 {sum(len(review.get('blocker_issues') or []) + len(review.get('major_concerns') or []) for review in peer_reviews)} 条主要问题。"
                if peer_reviews
                else "未生成 peer review。"
            ),
        )
    )
    steps.append(
        TaskStep(
            name="journal_fit",
            status=(
                "completed"
                if final_journal_fit_assessment and final_journal_fit_assessment.overall_fit in {"strong_fit", "workable_fit"}
                else "failed"
            ),
            detail=(
                f"期刊适配度 {final_journal_fit_assessment.fit_score} / 10，状态 {final_journal_fit_assessment.overall_fit}。"
                if final_journal_fit_assessment
                else "未生成期刊适配评估。"
            ),
        )
    )
    steps.append(
        TaskStep(
            name="submission_compliance",
            status=(
                "completed"
                if final_submission_compliance and final_submission_compliance.blocker_count == 0
                else "failed"
            ),
            detail=(
                final_submission_compliance.summary
                if final_submission_compliance
                else "未生成投稿合规检查。"
            ),
        )
    )
    steps.append(
        TaskStep(
            name="publication_readiness",
            status="completed" if final_publication_readiness.status == "ready_for_submission" else "failed",
            detail=final_publication_readiness.summary,
        )
    )

    workflow_result = workflow_result.__class__(
        audit_result=workflow_result.audit_result,
        research_ideas=workflow_result.research_ideas,
        selected_idea=workflow_result.selected_idea,
        event_discovery_result=workflow_result.event_discovery_result,
        citations=workflow_result.citations,
        evidence_assessment=workflow_result.evidence_assessment,
        incident_understanding=workflow_result.incident_understanding,
        mechanism_graph_design=workflow_result.mechanism_graph_design,
        research_program_candidates=workflow_result.research_program_candidates,
        paper_strategy=workflow_result.paper_strategy,
        contribution_profile=workflow_result.contribution_profile,
        publication_task_design=workflow_result.publication_task_design,
        manuscript_package=workflow_result.manuscript_package,
        claim_evidence_matrix=workflow_result.claim_evidence_matrix,
        claim_graph=workflow_result.claim_graph,
        experiment_plan=workflow_result.experiment_plan,
        experiment_gap_report=workflow_result.experiment_gap_report,
        research_memo=workflow_result.research_memo,
        paper_draft=effective_paper_draft,
        incident_evidence_packages=workflow_result.incident_evidence_packages,
        reference_validation=workflow_result.reference_validation,
        revision_result=effective_revision_result,
        journal_fit_assessment=final_journal_fit_assessment,
        submission_compliance=final_submission_compliance,
        publication_readiness=final_publication_readiness,
        rollback_plan=final_rollback_plan,
        llm_enhancement=workflow_result.llm_enhancement,
        llm_status=workflow_result.llm_status,
        llm_error=workflow_result.llm_error,
    )
    research_presentation = build_research_presentation(workflow_result)
    research_presentation["peer_reviews"] = peer_reviews
    research_presentation["peer_review_status"] = (
        "accepted" if peer_reviews and not peer_review_has_blockers else "needs_revision" if peer_reviews else "not_generated"
    )
    research_presentation["paper_ready"] = final_publication_readiness.status == "ready_for_submission"

    return AgentTaskResult(
        task_type="research",
        target=task_target,
        status="completed",
        steps=steps,
        payload={
            "research_result": workflow_result.to_dict(),
            "event_discovery": (
                workflow_result.event_discovery_result.to_dict()
                if workflow_result.event_discovery_result
                else {}
            ),
            "audit_result": workflow_result.audit_result.to_dict(),
            "research_ideas": [idea.to_dict() for idea in workflow_result.research_ideas],
            "citations": [citation.to_dict() for citation in workflow_result.citations],
            "evidence_assessment": (
                workflow_result.evidence_assessment.to_dict()
                if workflow_result.evidence_assessment
                else {}
            ),
            "incident_understanding": (
                workflow_result.incident_understanding.to_dict()
                if workflow_result.incident_understanding
                else {}
            ),
            "mechanism_graph_design": (
                workflow_result.mechanism_graph_design.to_dict()
                if workflow_result.mechanism_graph_design
                else {}
            ),
            "research_program_candidates": [
                item.to_dict() for item in workflow_result.research_program_candidates
            ],
            "paper_strategy": (
                workflow_result.paper_strategy.to_dict()
                if workflow_result.paper_strategy
                else {}
            ),
            "contribution_profile": (
                workflow_result.contribution_profile.to_dict()
                if workflow_result.contribution_profile
                else {}
            ),
            "publication_task_design": (
                workflow_result.publication_task_design.to_dict()
                if workflow_result.publication_task_design
                else {}
            ),
            "manuscript_package": (
                workflow_result.manuscript_package.to_dict()
                if workflow_result.manuscript_package
                else {}
            ),
            "claim_evidence_matrix": (
                workflow_result.claim_evidence_matrix.to_dict()
                if workflow_result.claim_evidence_matrix
                else {}
            ),
            "claim_graph": (
                workflow_result.claim_graph.to_dict()
                if workflow_result.claim_graph
                else {}
            ),
            "incident_evidence_packages": [
                item.to_dict()
                for item in (workflow_result.incident_evidence_packages or [])
            ],
            "reference_validation": (
                workflow_result.reference_validation.to_dict()
                if workflow_result.reference_validation
                else {}
            ),
            "revision_result": (
                workflow_result.revision_result.to_dict()
                if workflow_result.revision_result
                else {}
            ),
            "experiment_plan": workflow_result.experiment_plan.to_dict() if workflow_result.experiment_plan else {},
            "experiment_gap_report": (
                workflow_result.experiment_gap_report.to_dict()
                if workflow_result.experiment_gap_report
                else {}
            ),
            "research_memo": workflow_result.research_memo.to_dict() if workflow_result.research_memo else {},
            "research_presentation": research_presentation,
            "peer_reviews": peer_reviews,
            "peer_review_addressed_changes": peer_review_addressed_changes,
            "paper_draft": workflow_result.paper_draft.to_dict() if workflow_result.paper_draft else {},
            "journal_fit_assessment": (
                workflow_result.journal_fit_assessment.to_dict()
                if workflow_result.journal_fit_assessment
                else {}
            ),
            "submission_compliance": (
                workflow_result.submission_compliance.to_dict()
                if workflow_result.submission_compliance
                else {}
            ),
            "publication_readiness": (
                workflow_result.publication_readiness.to_dict()
                if workflow_result.publication_readiness
                else {}
            ),
            "rollback_plan": (
                workflow_result.rollback_plan.to_dict()
                if workflow_result.rollback_plan
                else {}
            ),
            "llm_enhancement": (
                workflow_result.llm_enhancement.to_dict()
                if workflow_result.llm_enhancement
                else {}
            ),
            "llm_status": workflow_result.llm_status,
            "llm_error": workflow_result.llm_error,
        },
    )
