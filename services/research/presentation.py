"""研究结果展示适配层。

目标：

- 把研究工作流的结构化结果转成真正可读的研究工作台数据
- 避免前端直接消费内部工作流对象
"""

from __future__ import annotations

from typing import Any

from services.research.review_views import build_peer_review_views, has_blocking_peer_review_issues
from services.research.research_workflow_service import ResearchWorkflowResult


def build_research_presentation(result: ResearchWorkflowResult) -> dict[str, Any]:
    """构建研究展示层结果。"""

    selected = result.selected_idea
    if selected is None:
        return {
            "title": "暂无研究结果",
            "summary": "当前没有生成可用的研究想法。",
            "confidence": "unknown",
            "metrics": {
                "idea_count": 0,
                "citation_count": 0,
                "novelty_score": 0,
                "experiment_design_count": 0,
            },
            "highlights": [],
            "candidate_ideas": [],
            "event_discovery": {},
            "selected_direction": {},
            "evidence_chain": [],
            "incident_understanding": {},
            "mechanism_graph_design": {},
            "research_program_candidates": [],
            "paper_strategy": {},
            "incident_packages": [],
            "citations": [],
            "reference_validation": {},
            "revision_result": {},
            "peer_reviews": [],
            "experiments": [],
            "publication_task_design": {},
            "deliverables": [],
            "execution_timeline": [],
            "open_risks": [],
            "generation_mode": "evidence_only",
            "llm_status": result.llm_status,
            "llm_error": result.llm_error,
            "llm_summary": "",
            "draft_abstract": "",
            "memo_preview": "",
            "paper_preview": "",
        }

    experiment_designs = [
        {
            "title": design.title,
            "objective": design.objective,
            "datasets": design.datasets,
            "baselines": design.baselines,
            "metrics": design.metrics,
            "procedures": design.procedures,
            "success_criteria": design.success_criteria,
            "failure_criteria": design.failure_criteria,
            "deliverables": design.deliverables,
        }
        for design in (result.experiment_plan.designs if result.experiment_plan else []) or []
    ]
    event_discovery = result.event_discovery_result
    event_discovery_view = event_discovery.to_dict() if event_discovery else {}

    candidate_ideas = [
        {
            "idea_id": idea.idea_id,
            "title": idea.title,
            "focus_category": idea.focus_category,
            "summary": idea.problem_statement or idea.hypothesis,
            "confidence": idea.confidence,
            "novelty_score": idea.novelty_score,
            "evidence_score": idea.evidence_score,
            "feasibility_score": idea.feasibility_score,
            "impact_score": idea.impact_score,
            "composite_score": idea.composite_score,
            "decision_status": idea.decision_status,
            "selection_reason": idea.selection_reason,
        }
        for idea in result.research_ideas[:5]
    ]

    evidence_chain = [
        {
            "title": evidence.title,
            "evidence_type": evidence.evidence_type,
            "summary": evidence.summary,
            "source_ref": evidence.source_ref,
            "strength": evidence.strength,
            "reasoning": evidence.reasoning,
        }
        for evidence in (selected.evidence_chain or [])
    ]
    incident_understanding = result.incident_understanding
    incident_understanding_view = (
        incident_understanding.to_dict() if incident_understanding else {}
    )
    mechanism_graph_design = result.mechanism_graph_design
    mechanism_graph_design_view = (
        mechanism_graph_design.to_dict() if mechanism_graph_design else {}
    )
    research_program_candidates_view = [
        item.to_dict() for item in result.research_program_candidates
    ]
    paper_strategy = result.paper_strategy
    paper_strategy_view = paper_strategy.to_dict() if paper_strategy else {}

    citations = [
        {
            "title": citation.title,
            "source_type": citation.source_type,
            "snippet": citation.snippet,
            "relevance_score": citation.relevance_score,
            "claim_supported": citation.claim_supported,
            "citation_reason": citation.citation_reason,
            "support_level": citation.support_level,
            "key_takeaway": citation.key_takeaway,
        }
        for citation in result.citations[:12]
    ]
    reference_validation = result.reference_validation
    reference_validation_view = {
        "summary": reference_validation.summary if reference_validation else "",
        "accepted_count": reference_validation.accepted_count if reference_validation else 0,
        "rejected_count": reference_validation.rejected_count if reference_validation else 0,
        "issues": [
            item.to_dict() for item in (reference_validation.issues if reference_validation else [])
        ],
    }
    revision = result.revision_result
    revision_view = {
        "status": revision.status if revision else "not_reviewed",
        "accepted": revision.accepted if revision else False,
        "final_score": revision.final_score if revision else 0,
        "summary": revision.summary if revision else "",
        "rounds": revision.rounds if revision else 0,
        "review_blocks": [item.to_dict() for item in (revision.review_blocks if revision else [])],
        "strengths": revision.strengths if revision else [],
        "weaknesses": revision.weaknesses if revision else [],
        "required_changes": revision.required_changes if revision else [],
        "addressed_changes": revision.addressed_changes if revision else [],
        "revised_markdown": revision.revised_markdown if revision else "",
    }
    peer_reviews = build_peer_review_views(
        revision_view,
        evidence_assessment=(
            result.evidence_assessment.to_dict() if result.evidence_assessment else {}
        ),
        reference_validation=reference_validation_view,
        contribution_profile=(
            result.contribution_profile.to_dict() if result.contribution_profile else {}
        ),
        claim_evidence_matrix=(
            result.claim_evidence_matrix.to_dict() if result.claim_evidence_matrix else {}
        ),
        experiment_gap_report=(
            result.experiment_gap_report.to_dict() if result.experiment_gap_report else {}
        ),
        journal_fit_assessment=(
            result.journal_fit_assessment.to_dict() if result.journal_fit_assessment else {}
        ),
        submission_compliance=(
            result.submission_compliance.to_dict() if result.submission_compliance else {}
        ),
        paper_markdown=(
            revision.revised_markdown
            if revision and revision.revised_markdown
            else result.paper_draft.markdown
            if result.paper_draft
            else ""
        ),
    )
    peer_review_has_blockers = has_blocking_peer_review_issues(peer_reviews)
    incident_packages = [
        {
            "title": package.title,
            "chain": package.chain,
            "loss_summary": package.loss_summary,
            "attack_transactions": [item.to_dict() for item in package.attack_transactions[:3]],
            "key_entities": [item.to_dict() for item in package.key_entities[:6]],
            "affected_components": [item.to_dict() for item in package.affected_components[:6]],
            "timeline": [item.to_dict() for item in package.timeline[:5]],
            "source_reports": package.source_reports,
            "evidence_summary": package.evidence_summary,
            "missing_artifacts": package.missing_artifacts,
            "verification_results": package.verification_results,
            "indexed_transaction_count": package.indexed_transaction_count,
            "indexed_log_count": package.indexed_log_count,
        }
        for package in (result.incident_evidence_packages or [])
    ]
    claim_graph = result.claim_graph
    claim_graph_view = {
        "summary": claim_graph.summary if claim_graph else "暂无图谱。",
        "claim_nodes": [node.to_dict() for node in (claim_graph.claim_nodes if claim_graph else [])],
        "evidence_nodes": [node.to_dict() for node in (claim_graph.evidence_nodes if claim_graph else [])],
        "citation_nodes": [node.to_dict() for node in (claim_graph.citation_nodes if claim_graph else [])],
        "experiment_nodes": [node.to_dict() for node in (claim_graph.experiment_nodes if claim_graph else [])],
        "edges": [edge.to_dict() for edge in (claim_graph.edges if claim_graph else [])],
        "stats": {
            "claim_count": len(claim_graph.claim_nodes) if claim_graph else 0,
            "evidence_count": len(claim_graph.evidence_nodes) if claim_graph else 0,
            "citation_count": len(claim_graph.citation_nodes) if claim_graph else 0,
            "experiment_count": len(claim_graph.experiment_nodes) if claim_graph else 0,
            "edge_count": len(claim_graph.edges) if claim_graph else 0,
        },
    }
    contribution_profile = result.contribution_profile
    contribution_view = {
        "thesis_statement": contribution_profile.thesis_statement if contribution_profile else "",
        "problem_framing": contribution_profile.problem_framing if contribution_profile else "",
        "novelty_positioning": contribution_profile.novelty_positioning if contribution_profile else "",
        "summary": contribution_profile.summary if contribution_profile else "",
        "entries": [item.to_dict() for item in (contribution_profile.entries if contribution_profile else [])],
    }
    publication_task_design = result.publication_task_design
    publication_task_view = {
        "summary": publication_task_design.summary if publication_task_design else "",
        "tasks": [item.to_dict() for item in (publication_task_design.tasks if publication_task_design else [])],
        "claim_units": [item.to_dict() for item in (publication_task_design.claim_units if publication_task_design else [])],
        "related_work_positions": [item.to_dict() for item in (publication_task_design.related_work_positions if publication_task_design else [])],
        "validation_scenarios": [item.to_dict() for item in (publication_task_design.validation_scenarios if publication_task_design else [])],
        "venue_blueprint": [item.to_dict() for item in (publication_task_design.venue_blueprint if publication_task_design else [])],
        "reviewer_lanes": [item.to_dict() for item in (publication_task_design.reviewer_lanes if publication_task_design else [])],
    }
    manuscript_package = result.manuscript_package
    manuscript_view = {
        "title": manuscript_package.title if manuscript_package else "",
        "keywords": manuscript_package.keywords if manuscript_package else [],
        "figures": [item.to_dict() for item in (manuscript_package.figures if manuscript_package else [])],
        "tables": [item.to_dict() for item in (manuscript_package.tables if manuscript_package else [])],
    }
    claim_evidence_matrix = result.claim_evidence_matrix
    claim_evidence_matrix_view = {
        "summary": claim_evidence_matrix.summary if claim_evidence_matrix else "暂无主张-证据矩阵。",
        "rows": [item.to_dict() for item in (claim_evidence_matrix.rows if claim_evidence_matrix else [])],
        "covered_count": claim_evidence_matrix.covered_count if claim_evidence_matrix else 0,
        "partial_count": claim_evidence_matrix.partial_count if claim_evidence_matrix else 0,
        "missing_count": claim_evidence_matrix.missing_count if claim_evidence_matrix else 0,
    }
    experiment_gap_report = result.experiment_gap_report
    experiment_gap_view = {
        "summary": experiment_gap_report.summary if experiment_gap_report else "暂无实验缺口报告。",
        "blocker_gaps": [item.to_dict() for item in (experiment_gap_report.blocker_gaps if experiment_gap_report else [])],
        "major_gaps": [item.to_dict() for item in (experiment_gap_report.major_gaps if experiment_gap_report else [])],
        "minor_gaps": [item.to_dict() for item in (experiment_gap_report.minor_gaps if experiment_gap_report else [])],
        "next_best_experiments": experiment_gap_report.next_best_experiments if experiment_gap_report else [],
        "publishability_note": experiment_gap_report.publishability_note if experiment_gap_report else "",
    }
    journal_fit = result.journal_fit_assessment
    journal_fit_view = {
        "target_profile": journal_fit.target_profile if journal_fit else "",
        "article_type": journal_fit.article_type if journal_fit else "",
        "fit_score": journal_fit.fit_score if journal_fit else 0,
        "overall_fit": journal_fit.overall_fit if journal_fit else "unknown",
        "strengths": journal_fit.strengths if journal_fit else [],
        "gaps": journal_fit.gaps if journal_fit else [],
        "required_adjustments": journal_fit.required_adjustments if journal_fit else [],
        "dimensions": [item.to_dict() for item in (journal_fit.dimensions if journal_fit else [])],
    }
    submission_compliance = result.submission_compliance
    submission_compliance_view = {
        "status": submission_compliance.status if submission_compliance else "unknown",
        "summary": submission_compliance.summary if submission_compliance else "",
        "blocker_count": submission_compliance.blocker_count if submission_compliance else 0,
        "warning_count": submission_compliance.warning_count if submission_compliance else 0,
        "checks": [item.to_dict() for item in (submission_compliance.checks if submission_compliance else [])],
    }
    publication_readiness = result.publication_readiness
    publication_readiness_view = {
        "status": publication_readiness.status if publication_readiness else "unknown",
        "readiness_score": publication_readiness.readiness_score if publication_readiness else 0,
        "summary": publication_readiness.summary if publication_readiness else "",
        "blockers": publication_readiness.blockers if publication_readiness else [],
        "warnings": publication_readiness.warnings if publication_readiness else [],
        "next_actions": publication_readiness.next_actions if publication_readiness else [],
    }
    rollback_plan = result.rollback_plan
    rollback_view = {
        "status": rollback_plan.status if rollback_plan else "unknown",
        "summary": rollback_plan.summary if rollback_plan else "",
        "actions": [item.to_dict() for item in (rollback_plan.actions if rollback_plan else [])],
    }

    memo_preview = ""
    if result.research_memo:
        memo_lines = result.research_memo.markdown.splitlines()
        memo_preview = "\n".join(memo_lines[:30]).strip()

    paper_preview = ""
    if result.revision_result and result.revision_result.revised_markdown.strip():
        paper_lines = result.revision_result.revised_markdown.splitlines()
        paper_preview = "\n".join(paper_lines[:36]).strip()
    elif result.paper_draft:
        paper_lines = result.paper_draft.markdown.splitlines()
        paper_preview = "\n".join(paper_lines[:36]).strip()

    evidence_assessment = result.evidence_assessment
    assessment_view = {
        "status": evidence_assessment.status if evidence_assessment else "unknown",
        "is_sufficient": evidence_assessment.is_sufficient if evidence_assessment else False,
        "confidence": evidence_assessment.confidence if evidence_assessment else "unknown",
        "score": evidence_assessment.score if evidence_assessment else 0,
        "summary": evidence_assessment.summary if evidence_assessment else "暂无证据评估。",
        "assessed_by": evidence_assessment.assessed_by if evidence_assessment else "none",
        "satisfied_dimensions": (
            evidence_assessment.satisfied_dimensions if evidence_assessment else []
        ),
        "missing_dimensions": (
            evidence_assessment.missing_dimensions if evidence_assessment else []
        ),
        "next_actions": evidence_assessment.next_actions if evidence_assessment else [],
        "claim_checks": [
            {
                "claim": item.claim,
                "evidence_count": item.evidence_count,
                "citation_count": item.citation_count,
                "has_experiment": item.has_experiment,
                "status": item.status,
                "reasoning": item.reasoning,
            }
            for item in (evidence_assessment.claim_checks if evidence_assessment else [])
        ],
        "llm_verdict": evidence_assessment.llm_verdict if evidence_assessment else "",
        "llm_summary": evidence_assessment.llm_summary if evidence_assessment else "",
    }

    highlights = [
        f"主线方向: {selected.title}",
        f"方向状态: {selected.decision_status}",
        f"综合评分: {selected.composite_score}",
        f"证据评分: {selected.evidence_score}",
        f"证据门禁: {assessment_view['status']}",
        f"可执行性评分: {selected.feasibility_score}",
        f"引用数量: {len(result.citations)}",
        f"实验设计数: {len(experiment_designs)}",
    ]
    if result.llm_enhancement and result.llm_enhancement.writing_highlights:
        highlights.extend(result.llm_enhancement.writing_highlights[:3])

    return {
        "title": selected.title,
        "summary": selected.problem_statement or selected.hypothesis,
        "motivation": selected.motivation,
        "novelty_rationale": selected.novelty_rationale,
        "confidence": selected.confidence,
        "metrics": {
            "idea_count": len(result.research_ideas),
            "citation_count": len(result.citations),
            "novelty_score": selected.novelty_score,
            "experiment_design_count": len(experiment_designs),
            "evidence_count": len(selected.evidence_chain or []),
            "composite_score": selected.composite_score,
        },
        "highlights": highlights,
        "event_discovery": event_discovery_view,
        "selected_direction": {
            "title": selected.title,
            "problem_statement": selected.problem_statement,
            "hypothesis": selected.hypothesis,
            "selection_reason": selected.selection_reason,
            "research_questions": selected.research_questions or [],
            "key_observations": selected.key_observations or [],
            "expected_contributions": selected.expected_contributions or [],
            "crystallized_thesis": contribution_view["thesis_statement"],
            "contribution_summary": contribution_view["summary"],
            "risks": selected.risks or [],
            "executive_summary": (
                result.llm_enhancement.executive_summary
                if result.llm_enhancement
                else ""
            ),
            "draft_abstract": (
                result.llm_enhancement.draft_abstract
                if result.llm_enhancement
                else ""
            ),
            "scores": {
                "novelty_score": selected.novelty_score,
                "evidence_score": selected.evidence_score,
                "feasibility_score": selected.feasibility_score,
                "impact_score": selected.impact_score,
                "composite_score": selected.composite_score,
            },
        },
        "candidate_ideas": candidate_ideas,
        "evidence_chain": evidence_chain,
        "incident_understanding": incident_understanding_view,
        "mechanism_graph_design": mechanism_graph_design_view,
        "research_program_candidates": research_program_candidates_view,
        "paper_strategy": paper_strategy_view,
        "incident_packages": incident_packages,
        "citations": citations,
        "reference_validation": reference_validation_view,
        "revision_result": revision_view,
        "peer_reviews": peer_reviews,
        "evidence_assessment": assessment_view,
        "contribution_profile": contribution_view,
        "publication_task_design": publication_task_view,
        "manuscript_package": manuscript_view,
        "claim_evidence_matrix": claim_evidence_matrix_view,
        "claim_graph": claim_graph_view,
        "experiments": experiment_designs,
        "experiment_gap_report": experiment_gap_view,
        "journal_fit_assessment": journal_fit_view,
        "submission_compliance": submission_compliance_view,
        "publication_readiness": publication_readiness_view,
        "rollback_plan": rollback_view,
        "deliverables": result.experiment_plan.expected_artifacts if result.experiment_plan else [],
        "execution_timeline": result.experiment_plan.execution_timeline if result.experiment_plan else [],
        "open_risks": result.experiment_plan.open_risks if result.experiment_plan else [],
        "generation_mode": (
            "ai_enhanced"
            if result.llm_enhancement
            else "fallback_to_rules"
            if result.llm_status == "fallback_to_rules"
            else "evidence_only"
        ),
        "llm_status": result.llm_status,
        "llm_error": result.llm_error,
        "llm_summary": (
            result.llm_enhancement.executive_summary
            if result.llm_enhancement
            else ""
        ),
        "draft_abstract": (
            result.llm_enhancement.draft_abstract
            if result.llm_enhancement
            else ""
        ),
        "memo_preview": memo_preview,
        "paper_preview": paper_preview,
        "peer_review_status": (
            "accepted" if peer_reviews and not peer_review_has_blockers else "needs_revision" if peer_reviews else "not_generated"
        ),
        "paper_ready": (
            publication_readiness_view["status"] == "ready_for_submission"
            if publication_readiness
            else bool(result.paper_draft and revision_view["accepted"] and not peer_review_has_blockers)
        ),
    }
