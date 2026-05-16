"""完整研究工作流服务。"""

from __future__ import annotations

from dataclasses import dataclass, replace
from typing import Any

from tools.analyzers.base import Severity
from services.analysis.audit_service import run_audit
from services.analysis.models import AuditRunResult
from services.research.claim_evidence_matrix import build_claim_evidence_matrix
from services.research.claim_graph_builder import build_claim_graph
from services.research.contribution_crystallizer import crystallize_contributions
from services.research.evidence_assessment import assess_research_evidence
from services.research.event_discovery import EventDiscoveryResult
from services.research.experiment_gap_analyzer import analyze_experiment_gaps
from services.research.experiment_planner import build_experiment_plan
from services.research.incident_chain_hydrator import hydrate_incident_chain_evidence
from services.research.incident_evidence_service import build_incident_evidence_packages
from services.research.incident_verification_service import run_incident_local_verifications
from services.research.journal_fit import assess_journal_fit
from services.research.llm_research_enhancer import summarize_research_package_with_llm
from services.research.manuscript_llm_writer import write_manuscript_with_llm
from services.research.manuscript_package_builder import build_manuscript_package
from services.research.rollback_planner import build_rollback_plan
from services.research.models import (
    CitationRecord,
    ClaimGraph,
    ClaimEvidenceMatrix,
    ContributionProfile,
    EvidenceAssessment,
    ExperimentGapReport,
    ExperimentPlan,
    IncidentEvidencePackage,
    JournalFitAssessment,
    LlmResearchEnhancement,
    ManuscriptPackage,
    PaperDraft,
    PaperRevisionResult,
    PublicationReadinessReport,
    ReferenceValidationResult,
    ResearchIdea,
    ResearchMemo,
    RollbackPlan,
    SubmissionComplianceReport,
)
from services.research.paper_revision import run_revision_cycle
from services.research.paper_draft_writer import render_paper_draft
from services.research.publication_task_design import (
    PublicationTaskDesign,
    build_publication_task_design,
)
from services.research.research_object_design import (
    IncidentUnderstandingModel,
    MechanismGraphDesign,
    PaperStrategy,
    ResearchProgramCandidate,
    build_incident_understanding_model,
    build_mechanism_graph_design,
    build_paper_strategy,
    build_research_program_candidates,
)
from services.research.publication_readiness import assess_publication_readiness
from services.research.reference_validation import validate_references
from services.research.related_work_service import retrieve_related_work
from services.research.research_idea_generator import generate_research_ideas
from services.research.research_memo_writer import render_research_memo
from services.research.submission_compliance import evaluate_submission_compliance
from services.shared.settings import ProjectSettings


def _revisit_supporting_materials(
    *,
    selected_idea,
    audit_result,
    incident_evidence_packages,
    reference_validation,
    revision_result,
):
    """当 review 指出证据/验证/相关工作问题时，回到前面补一轮材料。"""

    failing = {
        block.block_id
        for block in (revision_result.review_blocks if revision_result else [])
        if not block.accepted
    }
    updated_citations = reference_validation.validated_citations
    updated_reference_validation = reference_validation
    updated_incident_packages = incident_evidence_packages

    if "related_work" in failing:
        refreshed_citations = retrieve_related_work(selected_idea, audit_result, limit=16)
        updated_reference_validation = validate_references(
            citations=refreshed_citations,
            research_idea=selected_idea,
        )
        updated_citations = updated_reference_validation.validated_citations

    if "evidence" in failing or "validation" in failing:
        verification_results_by_incident: dict[str, list[dict[str, Any]]] = {}
        for match in audit_result.related_incidents[:3]:
            results = run_incident_local_verifications(match.incident)
            if results:
                verification_results_by_incident[match.incident.incident_id] = results
        updated_incident_packages = build_incident_evidence_packages(
            [match.incident for match in audit_result.related_incidents[:3]],
            verification_results_by_incident=verification_results_by_incident,
        )

    return updated_citations, updated_reference_validation, updated_incident_packages


@dataclass(frozen=True)
class ResearchWorkflowResult:
    """完整研究工作流结果。"""

    audit_result: AuditRunResult
    research_ideas: list[ResearchIdea]
    selected_idea: ResearchIdea | None
    event_discovery_result: EventDiscoveryResult | None
    citations: list[CitationRecord]
    evidence_assessment: EvidenceAssessment | None
    incident_understanding: IncidentUnderstandingModel | None
    mechanism_graph_design: MechanismGraphDesign | None
    research_program_candidates: list[ResearchProgramCandidate]
    paper_strategy: PaperStrategy | None
    contribution_profile: ContributionProfile | None
    publication_task_design: PublicationTaskDesign | None
    manuscript_package: ManuscriptPackage | None
    claim_evidence_matrix: ClaimEvidenceMatrix | None
    claim_graph: ClaimGraph | None
    experiment_plan: ExperimentPlan | None
    experiment_gap_report: ExperimentGapReport | None
    research_memo: ResearchMemo | None
    paper_draft: PaperDraft | None
    incident_evidence_packages: list[IncidentEvidencePackage] | None = None
    reference_validation: ReferenceValidationResult | None = None
    revision_result: PaperRevisionResult | None = None
    journal_fit_assessment: JournalFitAssessment | None = None
    submission_compliance: SubmissionComplianceReport | None = None
    publication_readiness: PublicationReadinessReport | None = None
    rollback_plan: RollbackPlan | None = None
    llm_enhancement: LlmResearchEnhancement | None = None
    llm_status: str = "disabled"
    llm_error: str = ""

    def to_dict(self) -> dict[str, Any]:
        """输出可序列化字典。"""

        return {
            "audit_result": self.audit_result.to_dict(),
            "research_ideas": [idea.to_dict() for idea in self.research_ideas],
            "selected_idea": self.selected_idea.to_dict() if self.selected_idea else None,
            "event_discovery_result": (
                self.event_discovery_result.to_dict() if self.event_discovery_result else None
            ),
            "citations": [citation.to_dict() for citation in self.citations],
            "evidence_assessment": (
                self.evidence_assessment.to_dict() if self.evidence_assessment else None
            ),
            "incident_understanding": (
                self.incident_understanding.to_dict() if self.incident_understanding else None
            ),
            "mechanism_graph_design": (
                self.mechanism_graph_design.to_dict() if self.mechanism_graph_design else None
            ),
            "research_program_candidates": [
                item.to_dict() for item in self.research_program_candidates
            ],
            "paper_strategy": self.paper_strategy.to_dict() if self.paper_strategy else None,
            "contribution_profile": (
                self.contribution_profile.to_dict() if self.contribution_profile else None
            ),
            "publication_task_design": (
                self.publication_task_design.to_dict() if self.publication_task_design else None
            ),
            "manuscript_package": (
                self.manuscript_package.to_dict() if self.manuscript_package else None
            ),
            "claim_evidence_matrix": (
                self.claim_evidence_matrix.to_dict() if self.claim_evidence_matrix else None
            ),
            "claim_graph": self.claim_graph.to_dict() if self.claim_graph else None,
            "experiment_plan": self.experiment_plan.to_dict() if self.experiment_plan else None,
            "experiment_gap_report": (
                self.experiment_gap_report.to_dict() if self.experiment_gap_report else None
            ),
            "research_memo": self.research_memo.to_dict() if self.research_memo else None,
            "paper_draft": self.paper_draft.to_dict() if self.paper_draft else None,
            "incident_evidence_packages": [
                item.to_dict() for item in (self.incident_evidence_packages or [])
            ],
            "reference_validation": (
                self.reference_validation.to_dict() if self.reference_validation else None
            ),
            "revision_result": (
                self.revision_result.to_dict() if self.revision_result else None
            ),
            "journal_fit_assessment": (
                self.journal_fit_assessment.to_dict() if self.journal_fit_assessment else None
            ),
            "submission_compliance": (
                self.submission_compliance.to_dict() if self.submission_compliance else None
            ),
            "publication_readiness": (
                self.publication_readiness.to_dict() if self.publication_readiness else None
            ),
            "rollback_plan": self.rollback_plan.to_dict() if self.rollback_plan else None,
            "llm_enhancement": (
                self.llm_enhancement.to_dict() if self.llm_enhancement else None
            ),
            "llm_status": self.llm_status,
            "llm_error": self.llm_error,
        }


def run_research_workflow(
    *,
    target: str,
    analyzer_names: list[str] | None = None,
    minimum_severity: Severity = Severity.INFO,
) -> ResearchWorkflowResult:
    """执行完整研究工作流。"""

    audit_result = run_audit(
        target=target,
        analyzer_names=analyzer_names,
        minimum_severity=minimum_severity,
    )
    research_ideas = generate_research_ideas(audit_result)
    selected_idea = next(
        (idea for idea in research_ideas if idea.decision_status == "selected"),
        research_ideas[0] if research_ideas else None,
    )
    if not selected_idea:
        return ResearchWorkflowResult(
            audit_result=audit_result,
            research_ideas=[],
            selected_idea=None,
            event_discovery_result=None,
            citations=[],
            evidence_assessment=None,
            incident_understanding=None,
            mechanism_graph_design=None,
            research_program_candidates=[],
            paper_strategy=None,
            contribution_profile=None,
            publication_task_design=None,
            manuscript_package=None,
            claim_evidence_matrix=None,
            claim_graph=None,
            experiment_plan=None,
            experiment_gap_report=None,
            research_memo=None,
            paper_draft=None,
            incident_evidence_packages=[],
            reference_validation=None,
            revision_result=None,
            journal_fit_assessment=None,
            submission_compliance=None,
            publication_readiness=None,
            rollback_plan=None,
            llm_enhancement=None,
            llm_status="disabled",
            llm_error="",
        )

    llm_status = "disabled"
    llm_error = ""
    llm_enhancement = None
    settings = ProjectSettings.from_env()
    related_incident_ids = [match.incident.incident_id for match in audit_result.related_incidents]
    if related_incident_ids:
        try:
            hydrate_incident_chain_evidence(incident_ids=related_incident_ids)
        except Exception as exc:  # noqa: BLE001
            if settings.research_llm_available:
                llm_error = f"incident hydration failed: {exc}"

    verification_results_by_incident: dict[str, list[dict[str, Any]]] = {}
    for match in audit_result.related_incidents[:3]:
        results = run_incident_local_verifications(match.incident)
        if results:
            verification_results_by_incident[match.incident.incident_id] = results

    citations = retrieve_related_work(selected_idea, audit_result)
    reference_validation = validate_references(
        citations=citations,
        research_idea=selected_idea,
    )
    citations = reference_validation.validated_citations
    experiment_plan = build_experiment_plan(selected_idea, audit_result)
    incident_evidence_packages = build_incident_evidence_packages(
        [match.incident for match in audit_result.related_incidents[:3]],
        verification_results_by_incident=verification_results_by_incident,
    )
    evidence_assessment = assess_research_evidence(
        selected_idea=selected_idea,
        citations=citations,
        experiment_plan=experiment_plan,
        incident_evidence_packages=incident_evidence_packages,
    )
    incident_understanding = build_incident_understanding_model(
        audit_result=audit_result,
        incident_evidence_packages=incident_evidence_packages,
    )
    mechanism_graph_design = build_mechanism_graph_design(
        incident_model=incident_understanding,
    )
    research_program_candidates = build_research_program_candidates(
        selected_idea=selected_idea,
        incident_model=incident_understanding,
        mechanism_graph=mechanism_graph_design,
        claim_evidence_matrix=None,
        incident_evidence_packages=incident_evidence_packages,
    )
    paper_strategy = build_paper_strategy(
        program_candidates=research_program_candidates,
        contribution_profile=None,
    )

    if not evidence_assessment.is_sufficient:
        selected_idea = replace(
            selected_idea,
            confidence="low" if evidence_assessment.status == "insufficient" else "medium",
            decision_status=(
                "evidence_insufficient"
                if evidence_assessment.status == "insufficient"
                else "selected_with_guardrails"
            ),
            selection_reason=(
                f"{selected_idea.selection_reason} 当前证据门禁状态为 `{evidence_assessment.status}`："
                f"{evidence_assessment.summary}"
            ).strip(),
        )
        research_ideas = [
            selected_idea if idea.idea_id == selected_idea.idea_id else idea
            for idea in research_ideas
        ]
        if settings.research_llm_available:
            llm_status = "blocked_by_evidence_gate"

    if evidence_assessment.is_sufficient and settings.research_llm_available:
        updated_citations, llm_enhancement = summarize_research_package_with_llm(
            selected_idea=selected_idea,
            citations=citations,
            experiment_plan=experiment_plan,
        )
        if llm_enhancement is not None:
            citations = updated_citations
            llm_status = "completed"

    contribution_profile = crystallize_contributions(
        research_idea=selected_idea,
        audit_result=audit_result,
        evidence_assessment=evidence_assessment,
        experiment_plan=experiment_plan,
        incident_evidence_packages=incident_evidence_packages,
    )
    claim_evidence_matrix = build_claim_evidence_matrix(
        research_idea=selected_idea,
        citations=citations,
        experiment_plan=experiment_plan,
        evidence_assessment=evidence_assessment,
    )
    research_program_candidates = build_research_program_candidates(
        selected_idea=selected_idea,
        incident_model=incident_understanding,
        mechanism_graph=mechanism_graph_design,
        claim_evidence_matrix=claim_evidence_matrix,
        incident_evidence_packages=incident_evidence_packages,
    )
    paper_strategy = build_paper_strategy(
        program_candidates=research_program_candidates,
        contribution_profile=contribution_profile,
    )
    publication_task_design = build_publication_task_design(
        selected_idea=selected_idea,
        audit_result=audit_result,
        citations=citations,
        claim_evidence_matrix=claim_evidence_matrix,
        experiment_plan=experiment_plan,
        contribution_profile=contribution_profile,
        incident_evidence_packages=incident_evidence_packages,
    )
    manuscript_package = build_manuscript_package(
        research_idea=selected_idea,
        audit_result=audit_result,
        citations=citations,
        experiment_plan=experiment_plan,
        contribution_profile=contribution_profile,
        claim_evidence_matrix=claim_evidence_matrix,
        incident_evidence_packages=incident_evidence_packages,
        publication_task_design=publication_task_design,
    )
    manuscript_package = build_manuscript_package(
        research_idea=selected_idea,
        audit_result=audit_result,
        citations=citations,
        experiment_plan=experiment_plan,
        contribution_profile=contribution_profile,
        claim_evidence_matrix=claim_evidence_matrix,
        incident_evidence_packages=incident_evidence_packages,
        publication_task_design=publication_task_design,
    )
    experiment_gap_report = analyze_experiment_gaps(
        claim_evidence_matrix=claim_evidence_matrix,
        experiment_plan=experiment_plan,
        incident_evidence_packages=incident_evidence_packages,
    )
    research_memo = render_research_memo(
        research_idea=selected_idea,
        audit_result=audit_result,
        citations=citations,
        experiment_plan=experiment_plan,
        llm_enhancement=llm_enhancement,
    )
    claim_graph = build_claim_graph(
        selected_idea=selected_idea,
        citations=citations,
        experiment_plan=experiment_plan,
        evidence_assessment=evidence_assessment,
    )
    paper_draft = None
    revision_result = None
    if evidence_assessment.is_sufficient:
        paper_draft = render_paper_draft(
            research_idea=selected_idea,
            audit_result=audit_result,
            citations=citations,
            experiment_plan=experiment_plan,
            llm_enhancement=llm_enhancement,
            contribution_profile=contribution_profile,
            claim_evidence_matrix=claim_evidence_matrix,
            experiment_gap_report=experiment_gap_report,
            manuscript_package=manuscript_package,
            publication_task_design=publication_task_design,
        )
        if settings.research_llm_available:
            llm_draft, _ = write_manuscript_with_llm(
                paper_draft=paper_draft,
                package=manuscript_package,
                citations=citations,
                incident_evidence_packages=incident_evidence_packages,
                settings=settings,
            )
            if llm_draft is not None:
                paper_draft = llm_draft
        revision_result = run_revision_cycle(
            paper_draft=paper_draft,
            reference_validation=reference_validation,
            incident_evidence_packages=incident_evidence_packages,
            citations=citations,
        )
        if revision_result and not revision_result.accepted:
            citations, reference_validation, incident_evidence_packages = _revisit_supporting_materials(
                selected_idea=selected_idea,
                audit_result=audit_result,
                incident_evidence_packages=incident_evidence_packages,
                reference_validation=reference_validation,
                revision_result=revision_result,
            )
            publication_task_design = build_publication_task_design(
                selected_idea=selected_idea,
                audit_result=audit_result,
                citations=citations,
                claim_evidence_matrix=claim_evidence_matrix,
                experiment_plan=experiment_plan,
                contribution_profile=contribution_profile,
                incident_evidence_packages=incident_evidence_packages,
            )
            manuscript_package = build_manuscript_package(
                research_idea=selected_idea,
                audit_result=audit_result,
                citations=citations,
                experiment_plan=experiment_plan,
                contribution_profile=contribution_profile,
                claim_evidence_matrix=claim_evidence_matrix,
                incident_evidence_packages=incident_evidence_packages,
                publication_task_design=publication_task_design,
            )
            paper_draft = render_paper_draft(
                research_idea=selected_idea,
                audit_result=audit_result,
                citations=citations,
                experiment_plan=experiment_plan,
                llm_enhancement=llm_enhancement,
                contribution_profile=contribution_profile,
                claim_evidence_matrix=claim_evidence_matrix,
                experiment_gap_report=experiment_gap_report,
                manuscript_package=manuscript_package,
                publication_task_design=publication_task_design,
            )
            if settings.research_llm_available:
                llm_draft, _ = write_manuscript_with_llm(
                    paper_draft=paper_draft,
                    package=manuscript_package,
                    citations=citations,
                    incident_evidence_packages=incident_evidence_packages,
                    settings=settings,
                )
                if llm_draft is not None:
                    paper_draft = llm_draft
            revision_result = run_revision_cycle(
                paper_draft=paper_draft,
                reference_validation=reference_validation,
                incident_evidence_packages=incident_evidence_packages,
                citations=citations,
            )

    final_markdown = (
        revision_result.revised_markdown
        if revision_result and revision_result.revised_markdown
        else paper_draft.markdown
        if paper_draft
        else ""
    )
    has_verification = any(
        item.get("passed")
        for package in incident_evidence_packages
        for item in package.verification_results
    )
    journal_fit_assessment = (
        assess_journal_fit(
            paper_markdown=final_markdown,
            contribution_profile=contribution_profile,
            claim_evidence_matrix=claim_evidence_matrix,
            reference_validation=reference_validation,
            has_verification=has_verification,
        )
        if final_markdown
        else None
    )
    submission_compliance = (
        evaluate_submission_compliance(
            paper_markdown=final_markdown,
            reference_validation=reference_validation,
            contribution_profile=contribution_profile,
            has_verification=has_verification,
        )
        if final_markdown
        else None
    )
    publication_readiness = assess_publication_readiness(
        revision_result=revision_result,
        peer_reviews=[],
        experiment_gap_report=experiment_gap_report,
        journal_fit_assessment=journal_fit_assessment,
        submission_compliance=submission_compliance,
    )
    rollback_plan = build_rollback_plan(
        peer_reviews=[],
        publication_readiness=publication_readiness.to_dict(),
    )

    return ResearchWorkflowResult(
        audit_result=audit_result,
        research_ideas=research_ideas,
        selected_idea=selected_idea,
        event_discovery_result=None,
        citations=citations,
        evidence_assessment=evidence_assessment,
        incident_understanding=incident_understanding,
        mechanism_graph_design=mechanism_graph_design,
        research_program_candidates=research_program_candidates,
        paper_strategy=paper_strategy,
        contribution_profile=contribution_profile,
        publication_task_design=publication_task_design,
        manuscript_package=manuscript_package,
        claim_evidence_matrix=claim_evidence_matrix,
        claim_graph=claim_graph,
        experiment_plan=experiment_plan,
        experiment_gap_report=experiment_gap_report,
        research_memo=research_memo,
        paper_draft=paper_draft,
        incident_evidence_packages=incident_evidence_packages,
        reference_validation=reference_validation,
        revision_result=revision_result,
        journal_fit_assessment=journal_fit_assessment,
        submission_compliance=submission_compliance,
        publication_readiness=publication_readiness,
        rollback_plan=rollback_plan,
        llm_enhancement=llm_enhancement,
        llm_status=llm_status,
        llm_error=llm_error,
    )
