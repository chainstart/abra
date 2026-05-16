"""历史攻击案例相关数据模型。"""

from __future__ import annotations

from dataclasses import dataclass, field
import hashlib
from typing import Any


def _stable_graph_id(prefix: str, *parts: object) -> str:
    """为研究图谱生成稳定 ID。"""

    digest = hashlib.sha1("::".join(map(str, parts)).encode("utf-8")).hexdigest()[:16]
    return f"{prefix}_{digest}"


@dataclass(frozen=True)
class IncidentRecord:
    """结构化历史攻击案例。"""

    incident_id: str
    title: str
    protocol_name: str
    protocol_type: str
    year: int
    summary: str
    root_cause: str
    attack_patterns: list[str]
    affected_categories: list[str]
    keywords: list[str]
    source_reports: list[str]
    evidence_payload: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        """输出可序列化字典。"""

        return {
            "incident_id": self.incident_id,
            "title": self.title,
            "protocol_name": self.protocol_name,
            "protocol_type": self.protocol_type,
            "year": self.year,
            "summary": self.summary,
            "root_cause": self.root_cause,
            "attack_patterns": self.attack_patterns,
            "affected_categories": self.affected_categories,
            "keywords": self.keywords,
            "source_reports": self.source_reports,
            "evidence_payload": self.evidence_payload,
        }


@dataclass(frozen=True)
class IncidentEntityRef:
    """攻击事件中的关键实体引用。"""

    reference: str
    label: str
    role: str
    entity_type: str
    description: str = ""

    def to_dict(self) -> dict[str, Any]:
        """输出可序列化字典。"""

        return {
            "reference": self.reference,
            "label": self.label,
            "role": self.role,
            "entity_type": self.entity_type,
            "description": self.description,
        }


@dataclass(frozen=True)
class IncidentEvidenceTransaction:
    """攻击事件中的关键交易证据。"""

    tx_hash: str
    role: str
    label: str
    description: str
    chain: str
    block_number: int | None = None
    timestamp: str = ""
    from_address: str = ""
    to_address: str = ""
    contract_address: str = ""
    selector: str = ""
    selector_name: str = ""
    value_wei: str = ""
    status: str = "unknown"
    indexed_log_count: int = 0
    indexed: bool = False
    hints: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        """输出可序列化字典。"""

        return {
            "tx_hash": self.tx_hash,
            "role": self.role,
            "label": self.label,
            "description": self.description,
            "chain": self.chain,
            "block_number": self.block_number,
            "timestamp": self.timestamp,
            "from_address": self.from_address,
            "to_address": self.to_address,
            "contract_address": self.contract_address,
            "selector": self.selector,
            "selector_name": self.selector_name,
            "value_wei": self.value_wei,
            "status": self.status,
            "indexed_log_count": self.indexed_log_count,
            "indexed": self.indexed,
            "hints": self.hints,
        }


@dataclass(frozen=True)
class IncidentTimelineStep:
    """攻击事件时间线。"""

    step_id: str
    title: str
    description: str
    tx_hashes: list[str] = field(default_factory=list)
    involved_entities: list[str] = field(default_factory=list)
    evidence_refs: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        """输出可序列化字典。"""

        return {
            "step_id": self.step_id,
            "title": self.title,
            "description": self.description,
            "tx_hashes": self.tx_hashes,
            "involved_entities": self.involved_entities,
            "evidence_refs": self.evidence_refs,
        }


@dataclass(frozen=True)
class IncidentEvidencePackage:
    """面向研究流程的攻击事件结构化证据包。"""

    incident_id: str
    title: str
    protocol_name: str
    protocol_type: str
    chain: str
    root_cause: str
    summary: str
    loss_summary: str
    attack_transactions: list[IncidentEvidenceTransaction]
    key_entities: list[IncidentEntityRef]
    affected_components: list[IncidentEntityRef]
    timeline: list[IncidentTimelineStep]
    source_reports: list[str]
    evidence_summary: list[str]
    missing_artifacts: list[str]
    verification_results: list[dict[str, Any]] = field(default_factory=list)
    indexed_transaction_count: int = 0
    indexed_log_count: int = 0

    def to_dict(self) -> dict[str, Any]:
        """输出可序列化字典。"""

        return {
            "incident_id": self.incident_id,
            "title": self.title,
            "protocol_name": self.protocol_name,
            "protocol_type": self.protocol_type,
            "chain": self.chain,
            "root_cause": self.root_cause,
            "summary": self.summary,
            "loss_summary": self.loss_summary,
            "attack_transactions": [item.to_dict() for item in self.attack_transactions],
            "key_entities": [item.to_dict() for item in self.key_entities],
            "affected_components": [item.to_dict() for item in self.affected_components],
            "timeline": [item.to_dict() for item in self.timeline],
            "source_reports": self.source_reports,
            "evidence_summary": self.evidence_summary,
            "missing_artifacts": self.missing_artifacts,
            "verification_results": self.verification_results,
            "indexed_transaction_count": self.indexed_transaction_count,
            "indexed_log_count": self.indexed_log_count,
        }


@dataclass(frozen=True)
class DiscoveredIncidentCandidate:
    """外部来源发现的攻击事件候选。"""

    candidate_id: str
    source: str
    title: str
    discovered_at: str
    summary: str
    attack_method: str
    loss_text: str
    protocol_name_guess: str
    protocol_type_guess: str
    relevance_score: float
    suggested_categories: list[str]
    tags: list[str]
    reference_url: str = ""

    def to_dict(self) -> dict[str, Any]:
        """输出可序列化字典。"""

        return {
            "candidate_id": self.candidate_id,
            "source": self.source,
            "title": self.title,
            "discovered_at": self.discovered_at,
            "summary": self.summary,
            "attack_method": self.attack_method,
            "loss_text": self.loss_text,
            "protocol_name_guess": self.protocol_name_guess,
            "protocol_type_guess": self.protocol_type_guess,
            "relevance_score": self.relevance_score,
            "suggested_categories": self.suggested_categories,
            "tags": self.tags,
            "reference_url": self.reference_url,
        }


@dataclass(frozen=True)
class RelatedIncidentMatch:
    """与当前审计目标相关的历史案例。"""

    incident: IncidentRecord
    score: int
    reasons: list[str]

    def to_dict(self) -> dict[str, Any]:
        """输出可序列化字典。"""

        return {
            "incident": self.incident.to_dict(),
            "score": self.score,
            "reasons": self.reasons,
        }


@dataclass(frozen=True)
class ResearchIdea:
    """研究想法。"""

    idea_id: str
    title: str
    focus_category: str
    hypothesis: str
    motivation: str
    novelty_rationale: str
    confidence: str
    novelty_score: float
    related_incident_ids: list[str]
    related_work_summary: list[str]
    supporting_evidence: list[str]
    proposed_experiments: list[str]
    problem_statement: str = ""
    research_questions: list[str] | None = None
    key_observations: list[str] | None = None
    expected_contributions: list[str] | None = None
    risks: list[str] | None = None
    evidence_chain: list["ResearchEvidence"] | None = None
    evidence_score: float = 0.0
    feasibility_score: float = 0.0
    impact_score: float = 0.0
    composite_score: float = 0.0
    decision_status: str = "candidate"
    selection_reason: str = ""

    def to_dict(self) -> dict[str, Any]:
        """输出可序列化字典。"""

        return {
            "idea_id": self.idea_id,
            "title": self.title,
            "focus_category": self.focus_category,
            "hypothesis": self.hypothesis,
            "motivation": self.motivation,
            "novelty_rationale": self.novelty_rationale,
            "confidence": self.confidence,
            "novelty_score": self.novelty_score,
            "related_incident_ids": self.related_incident_ids,
            "related_work_summary": self.related_work_summary,
            "supporting_evidence": self.supporting_evidence,
            "proposed_experiments": self.proposed_experiments,
            "problem_statement": self.problem_statement,
            "research_questions": self.research_questions or [],
            "key_observations": self.key_observations or [],
            "expected_contributions": self.expected_contributions or [],
            "risks": self.risks or [],
            "evidence_chain": [
                evidence.to_dict() for evidence in (self.evidence_chain or [])
            ],
            "evidence_score": self.evidence_score,
            "feasibility_score": self.feasibility_score,
            "impact_score": self.impact_score,
            "composite_score": self.composite_score,
            "decision_status": self.decision_status,
            "selection_reason": self.selection_reason,
        }


@dataclass(frozen=True)
class CitationRecord:
    """研究引用与参考来源。"""

    citation_id: str
    title: str
    source_type: str
    source_ref: str
    snippet: str
    relevance_score: int
    claim_supported: str = ""
    citation_reason: str = ""
    support_level: str = "reference"
    key_takeaway: str = ""

    def to_dict(self) -> dict[str, Any]:
        """输出可序列化字典。"""

        return {
            "citation_id": self.citation_id,
            "title": self.title,
            "source_type": self.source_type,
            "source_ref": self.source_ref,
            "snippet": self.snippet,
            "relevance_score": self.relevance_score,
            "claim_supported": self.claim_supported,
            "citation_reason": self.citation_reason,
            "support_level": self.support_level,
            "key_takeaway": self.key_takeaway,
        }


@dataclass(frozen=True)
class ResearchEvidence:
    """研究证据链中的单条证据。"""

    evidence_id: str
    evidence_type: str
    title: str
    summary: str
    source_ref: str
    strength: str
    reasoning: str

    def to_dict(self) -> dict[str, Any]:
        """输出可序列化字典。"""

        return {
            "evidence_id": self.evidence_id,
            "evidence_type": self.evidence_type,
            "title": self.title,
            "summary": self.summary,
            "source_ref": self.source_ref,
            "strength": self.strength,
            "reasoning": self.reasoning,
        }


@dataclass(frozen=True)
class ExperimentDesign:
    """单个实验设计。"""

    design_id: str
    title: str
    objective: str
    datasets: list[str]
    baselines: list[str]
    metrics: list[str]
    procedures: list[str]
    success_criteria: list[str]
    failure_criteria: list[str]
    deliverables: list[str]

    def to_dict(self) -> dict[str, Any]:
        """输出可序列化字典。"""

        return {
            "design_id": self.design_id,
            "title": self.title,
            "objective": self.objective,
            "datasets": self.datasets,
            "baselines": self.baselines,
            "metrics": self.metrics,
            "procedures": self.procedures,
            "success_criteria": self.success_criteria,
            "failure_criteria": self.failure_criteria,
            "deliverables": self.deliverables,
        }


@dataclass(frozen=True)
class ExperimentPlan:
    """结构化实验计划。"""

    title: str
    objective: str
    hypotheses: list[str]
    datasets: list[str]
    metrics: list[str]
    baselines: list[str]
    procedures: list[str]
    expected_artifacts: list[str]
    designs: list[ExperimentDesign] | None = None
    execution_timeline: list[str] | None = None
    open_risks: list[str] | None = None

    def to_dict(self) -> dict[str, Any]:
        """输出可序列化字典。"""

        return {
            "title": self.title,
            "objective": self.objective,
            "hypotheses": self.hypotheses,
            "datasets": self.datasets,
            "metrics": self.metrics,
            "baselines": self.baselines,
            "procedures": self.procedures,
            "expected_artifacts": self.expected_artifacts,
            "designs": [design.to_dict() for design in (self.designs or [])],
            "execution_timeline": self.execution_timeline or [],
            "open_risks": self.open_risks or [],
        }


@dataclass(frozen=True)
class ContributionEntry:
    """单条论文贡献的提纯结果。"""

    contribution_id: str
    label: str
    statement: str
    evidence_anchor: str
    validation_anchor: str
    novelty_anchor: str
    boundary: str
    confidence: str = "medium"

    def to_dict(self) -> dict[str, Any]:
        """输出可序列化字典。"""

        return {
            "contribution_id": self.contribution_id,
            "label": self.label,
            "statement": self.statement,
            "evidence_anchor": self.evidence_anchor,
            "validation_anchor": self.validation_anchor,
            "novelty_anchor": self.novelty_anchor,
            "boundary": self.boundary,
            "confidence": self.confidence,
        }


@dataclass(frozen=True)
class ContributionProfile:
    """贡献提纯结果。"""

    thesis_statement: str
    problem_framing: str
    novelty_positioning: str
    summary: str
    entries: list[ContributionEntry]

    def to_dict(self) -> dict[str, Any]:
        """输出可序列化字典。"""

        return {
            "thesis_statement": self.thesis_statement,
            "problem_framing": self.problem_framing,
            "novelty_positioning": self.novelty_positioning,
            "summary": self.summary,
            "entries": [item.to_dict() for item in self.entries],
        }


@dataclass(frozen=True)
class ClaimEvidenceMatrixRow:
    """单条主张的证据矩阵行。"""

    claim_id: str
    claim: str
    status: str
    evidence_refs: list[str]
    citation_refs: list[str]
    experiment_refs: list[str]
    supporting_points: list[str]
    boundary_notes: list[str]
    primary_gap: str = ""

    def to_dict(self) -> dict[str, Any]:
        """输出可序列化字典。"""

        return {
            "claim_id": self.claim_id,
            "claim": self.claim,
            "status": self.status,
            "evidence_refs": self.evidence_refs,
            "citation_refs": self.citation_refs,
            "experiment_refs": self.experiment_refs,
            "supporting_points": self.supporting_points,
            "boundary_notes": self.boundary_notes,
            "primary_gap": self.primary_gap,
        }


@dataclass(frozen=True)
class ClaimEvidenceMatrix:
    """主张-证据矩阵。"""

    summary: str
    rows: list[ClaimEvidenceMatrixRow]
    covered_count: int
    partial_count: int
    missing_count: int

    def to_dict(self) -> dict[str, Any]:
        """输出可序列化字典。"""

        return {
            "summary": self.summary,
            "rows": [item.to_dict() for item in self.rows],
            "covered_count": self.covered_count,
            "partial_count": self.partial_count,
            "missing_count": self.missing_count,
        }


@dataclass(frozen=True)
class ManuscriptClaim:
    """用于论文成稿的单条主张单元。"""

    claim_id: str
    claim: str
    evidence_summary: str
    citation_titles: list[str]
    validation_summary: str
    boundary: str
    status: str = "supported"

    def to_dict(self) -> dict[str, Any]:
        return {
            "claim_id": self.claim_id,
            "claim": self.claim,
            "evidence_summary": self.evidence_summary,
            "citation_titles": self.citation_titles,
            "validation_summary": self.validation_summary,
            "boundary": self.boundary,
            "status": self.status,
        }


@dataclass(frozen=True)
class ManuscriptReference:
    """用于论文成稿的参考文献条目。"""

    citation_id: str
    title: str
    role: str
    takeaway: str
    citation_reason: str
    source_type: str = ""
    source_ref: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "citation_id": self.citation_id,
            "title": self.title,
            "role": self.role,
            "takeaway": self.takeaway,
            "citation_reason": self.citation_reason,
            "source_type": self.source_type,
            "source_ref": self.source_ref,
        }


@dataclass(frozen=True)
class FigureSpec:
    """论文图规格。"""

    figure_id: str
    title: str
    purpose: str
    caption: str
    source_basis: list[str]
    figure_type: str = "diagram"

    def to_dict(self) -> dict[str, Any]:
        return {
            "figure_id": self.figure_id,
            "title": self.title,
            "purpose": self.purpose,
            "caption": self.caption,
            "source_basis": self.source_basis,
            "figure_type": self.figure_type,
        }


@dataclass(frozen=True)
class TableSpec:
    """论文表规格。"""

    table_id: str
    title: str
    caption: str
    columns: list[str]
    rows: list[list[str]]
    purpose: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "table_id": self.table_id,
            "title": self.title,
            "caption": self.caption,
            "columns": self.columns,
            "rows": self.rows,
            "purpose": self.purpose,
        }


@dataclass(frozen=True)
class ManuscriptPackage:
    """统一供各 section writer 使用的成稿包。"""

    title: str
    paper_type: str
    target_venue_style: str
    article_positioning: str
    section_blueprint: list[str]
    validation_expectations: list[str]
    keywords: list[str]
    abstract_points: list[str]
    introduction_points: list[str]
    background_points: list[str]
    incident_context_points: list[str]
    problem_statement_points: list[str]
    research_questions: list[str]
    evidence_points: list[str]
    observations: list[str]
    incident_anchor_points: list[str]
    validation_anchor_points: list[str]
    counterfactual_points: list[str]
    methodology_points: list[str]
    evaluation_points: list[str]
    discussion_points: list[str]
    contribution_points: list[str]
    threats_points: list[str]
    conclusion_points: list[str]
    claims: list[ManuscriptClaim]
    references: list[ManuscriptReference]
    figures: list[FigureSpec]
    tables: list[TableSpec]

    def to_dict(self) -> dict[str, Any]:
        return {
            "title": self.title,
            "paper_type": self.paper_type,
            "target_venue_style": self.target_venue_style,
            "article_positioning": self.article_positioning,
            "section_blueprint": self.section_blueprint,
            "validation_expectations": self.validation_expectations,
            "keywords": self.keywords,
            "abstract_points": self.abstract_points,
            "introduction_points": self.introduction_points,
            "background_points": self.background_points,
            "incident_context_points": self.incident_context_points,
            "problem_statement_points": self.problem_statement_points,
            "research_questions": self.research_questions,
            "evidence_points": self.evidence_points,
            "observations": self.observations,
            "incident_anchor_points": self.incident_anchor_points,
            "validation_anchor_points": self.validation_anchor_points,
            "counterfactual_points": self.counterfactual_points,
            "methodology_points": self.methodology_points,
            "evaluation_points": self.evaluation_points,
            "discussion_points": self.discussion_points,
            "contribution_points": self.contribution_points,
            "threats_points": self.threats_points,
            "conclusion_points": self.conclusion_points,
            "claims": [item.to_dict() for item in self.claims],
            "references": [item.to_dict() for item in self.references],
            "figures": [item.to_dict() for item in self.figures],
            "tables": [item.to_dict() for item in self.tables],
        }


@dataclass(frozen=True)
class RollbackAction:
    """单条回退动作。"""

    action_id: str
    target_stage: str
    priority: str
    reason: str
    action: str
    expected_effect: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "action_id": self.action_id,
            "target_stage": self.target_stage,
            "priority": self.priority,
            "reason": self.reason,
            "action": self.action,
            "expected_effect": self.expected_effect,
        }


@dataclass(frozen=True)
class RollbackPlan:
    """根据 reviewer / gate 问题生成的回退计划。"""

    status: str
    summary: str
    actions: list[RollbackAction]

    def to_dict(self) -> dict[str, Any]:
        return {
            "status": self.status,
            "summary": self.summary,
            "actions": [item.to_dict() for item in self.actions],
        }


@dataclass(frozen=True)
class ExperimentGapItem:
    """单条实验缺口。"""

    gap_id: str
    severity: str
    title: str
    description: str
    linked_claims: list[str]
    suggested_actions: list[str]
    unblock_condition: str

    def to_dict(self) -> dict[str, Any]:
        """输出可序列化字典。"""

        return {
            "gap_id": self.gap_id,
            "severity": self.severity,
            "title": self.title,
            "description": self.description,
            "linked_claims": self.linked_claims,
            "suggested_actions": self.suggested_actions,
            "unblock_condition": self.unblock_condition,
        }


@dataclass(frozen=True)
class ExperimentGapReport:
    """实验缺口报告。"""

    summary: str
    blocker_gaps: list[ExperimentGapItem]
    major_gaps: list[ExperimentGapItem]
    minor_gaps: list[ExperimentGapItem]
    next_best_experiments: list[str]
    publishability_note: str

    def to_dict(self) -> dict[str, Any]:
        """输出可序列化字典。"""

        return {
            "summary": self.summary,
            "blocker_gaps": [item.to_dict() for item in self.blocker_gaps],
            "major_gaps": [item.to_dict() for item in self.major_gaps],
            "minor_gaps": [item.to_dict() for item in self.minor_gaps],
            "next_best_experiments": self.next_best_experiments,
            "publishability_note": self.publishability_note,
        }


@dataclass(frozen=True)
class JournalFitDimension:
    """期刊适配的单个维度。"""

    dimension_id: str
    label: str
    score: float
    status: str
    evidence: str
    gap: str
    required_action: str

    def to_dict(self) -> dict[str, Any]:
        """输出可序列化字典。"""

        return {
            "dimension_id": self.dimension_id,
            "label": self.label,
            "score": self.score,
            "status": self.status,
            "evidence": self.evidence,
            "gap": self.gap,
            "required_action": self.required_action,
        }


@dataclass(frozen=True)
class JournalFitAssessment:
    """期刊适配评估。"""

    target_profile: str
    article_type: str
    fit_score: float
    overall_fit: str
    strengths: list[str]
    gaps: list[str]
    required_adjustments: list[str]
    dimensions: list[JournalFitDimension]

    def to_dict(self) -> dict[str, Any]:
        """输出可序列化字典。"""

        return {
            "target_profile": self.target_profile,
            "article_type": self.article_type,
            "fit_score": self.fit_score,
            "overall_fit": self.overall_fit,
            "strengths": self.strengths,
            "gaps": self.gaps,
            "required_adjustments": self.required_adjustments,
            "dimensions": [item.to_dict() for item in self.dimensions],
        }


@dataclass(frozen=True)
class SubmissionComplianceCheck:
    """投稿合规检查项。"""

    check_id: str
    label: str
    status: str
    severity: str
    details: str
    remediation: str

    def to_dict(self) -> dict[str, Any]:
        """输出可序列化字典。"""

        return {
            "check_id": self.check_id,
            "label": self.label,
            "status": self.status,
            "severity": self.severity,
            "details": self.details,
            "remediation": self.remediation,
        }


@dataclass(frozen=True)
class SubmissionComplianceReport:
    """投稿合规报告。"""

    status: str
    summary: str
    blocker_count: int
    warning_count: int
    checks: list[SubmissionComplianceCheck]

    def to_dict(self) -> dict[str, Any]:
        """输出可序列化字典。"""

        return {
            "status": self.status,
            "summary": self.summary,
            "blocker_count": self.blocker_count,
            "warning_count": self.warning_count,
            "checks": [item.to_dict() for item in self.checks],
        }


@dataclass(frozen=True)
class PublicationReadinessReport:
    """可投稿就绪度报告。"""

    status: str
    readiness_score: float
    summary: str
    blockers: list[str]
    warnings: list[str]
    next_actions: list[str]

    def to_dict(self) -> dict[str, Any]:
        """输出可序列化字典。"""

        return {
            "status": self.status,
            "readiness_score": self.readiness_score,
            "summary": self.summary,
            "blockers": self.blockers,
            "warnings": self.warnings,
            "next_actions": self.next_actions,
        }


@dataclass(frozen=True)
class EvidenceClaimCheck:
    """单条研究主张的证据覆盖检查。"""

    claim: str
    evidence_count: int
    citation_count: int
    has_experiment: bool
    status: str
    reasoning: str

    def to_dict(self) -> dict[str, Any]:
        """输出可序列化字典。"""

        return {
            "claim": self.claim,
            "evidence_count": self.evidence_count,
            "citation_count": self.citation_count,
            "has_experiment": self.has_experiment,
            "status": self.status,
            "reasoning": self.reasoning,
        }


@dataclass(frozen=True)
class EvidenceAssessment:
    """研究证据充分性评估。"""

    status: str
    is_sufficient: bool
    confidence: str
    score: float
    summary: str
    assessed_by: str
    satisfied_dimensions: list[str]
    missing_dimensions: list[str]
    next_actions: list[str]
    claim_checks: list[EvidenceClaimCheck]
    llm_verdict: str = ""
    llm_summary: str = ""

    def to_dict(self) -> dict[str, Any]:
        """输出可序列化字典。"""

        return {
            "status": self.status,
            "is_sufficient": self.is_sufficient,
            "confidence": self.confidence,
            "score": self.score,
            "summary": self.summary,
            "assessed_by": self.assessed_by,
            "satisfied_dimensions": self.satisfied_dimensions,
            "missing_dimensions": self.missing_dimensions,
            "next_actions": self.next_actions,
            "claim_checks": [item.to_dict() for item in self.claim_checks],
            "llm_verdict": self.llm_verdict,
            "llm_summary": self.llm_summary,
        }


@dataclass(frozen=True)
class ClaimGraphNode:
    """研究主张图谱节点。"""

    node_id: str
    node_type: str
    title: str
    summary: str
    source_ref: str = ""
    status: str = ""
    metadata: dict[str, Any] | None = None

    def to_dict(self) -> dict[str, Any]:
        """输出可序列化字典。"""

        return {
            "node_id": self.node_id,
            "node_type": self.node_type,
            "title": self.title,
            "summary": self.summary,
            "source_ref": self.source_ref,
            "status": self.status,
            "metadata": self.metadata or {},
        }


@dataclass(frozen=True)
class ClaimGraphEdge:
    """研究主张图谱边。"""

    edge_id: str
    from_node_id: str
    to_node_id: str
    relation: str
    reasoning: str = ""

    def to_dict(self) -> dict[str, Any]:
        """输出可序列化字典。"""

        return {
            "edge_id": self.edge_id,
            "from_node_id": self.from_node_id,
            "to_node_id": self.to_node_id,
            "relation": self.relation,
            "reasoning": self.reasoning,
        }


@dataclass(frozen=True)
class ClaimGraph:
    """研究主张-证据图谱。"""

    graph_id: str
    claim_nodes: list[ClaimGraphNode]
    evidence_nodes: list[ClaimGraphNode]
    citation_nodes: list[ClaimGraphNode]
    experiment_nodes: list[ClaimGraphNode]
    edges: list[ClaimGraphEdge]
    summary: str

    def to_dict(self) -> dict[str, Any]:
        """输出可序列化字典。"""

        return {
            "graph_id": self.graph_id,
            "claim_nodes": [node.to_dict() for node in self.claim_nodes],
            "evidence_nodes": [node.to_dict() for node in self.evidence_nodes],
            "citation_nodes": [node.to_dict() for node in self.citation_nodes],
            "experiment_nodes": [node.to_dict() for node in self.experiment_nodes],
            "edges": [edge.to_dict() for edge in self.edges],
            "summary": self.summary,
        }


@dataclass(frozen=True)
class ResearchMemo:
    """研究备忘录。"""

    title: str
    markdown: str

    def to_dict(self) -> dict[str, Any]:
        """输出可序列化字典。"""

        return {
            "title": self.title,
            "markdown": self.markdown,
        }


@dataclass(frozen=True)
class PaperDraft:
    """论文初稿对象。"""

    title: str
    markdown: str

    def to_dict(self) -> dict[str, Any]:
        """输出可序列化字典。"""

        return {
            "title": self.title,
            "markdown": self.markdown,
        }


@dataclass(frozen=True)
class ReferenceValidationIssue:
    """引用校验问题。"""

    citation_id: str
    title: str
    severity: str
    message: str
    suggestion: str

    def to_dict(self) -> dict[str, Any]:
        """输出可序列化字典。"""

        return {
            "citation_id": self.citation_id,
            "title": self.title,
            "severity": self.severity,
            "message": self.message,
            "suggestion": self.suggestion,
        }


@dataclass(frozen=True)
class ReferenceValidationResult:
    """引用校验结果。"""

    accepted_count: int
    rejected_count: int
    summary: str
    validated_citations: list[CitationRecord]
    issues: list[ReferenceValidationIssue]

    def to_dict(self) -> dict[str, Any]:
        """输出可序列化字典。"""

        return {
            "accepted_count": self.accepted_count,
            "rejected_count": self.rejected_count,
            "summary": self.summary,
            "validated_citations": [item.to_dict() for item in self.validated_citations],
            "issues": [item.to_dict() for item in self.issues],
        }


@dataclass(frozen=True)
class ReviewAspectResult:
    """论文评审分块下的单个视角结果。"""

    aspect_id: str
    name: str
    accepted: bool
    score: float
    summary: str
    required_change: str = ""

    def to_dict(self) -> dict[str, Any]:
        """输出可序列化字典。"""

        return {
            "aspect_id": self.aspect_id,
            "name": self.name,
            "accepted": self.accepted,
            "score": self.score,
            "summary": self.summary,
            "required_change": self.required_change,
        }


@dataclass(frozen=True)
class ReviewBlockResult:
    """论文评审分块结果。"""

    block_id: str
    name: str
    accepted: bool
    score: float
    aspects: list[ReviewAspectResult]
    strengths: list[str]
    weaknesses: list[str]
    required_changes: list[str]
    addressed_changes: list[str]

    def to_dict(self) -> dict[str, Any]:
        """输出可序列化字典。"""

        return {
            "block_id": self.block_id,
            "name": self.name,
            "accepted": self.accepted,
            "score": self.score,
            "aspects": [item.to_dict() for item in self.aspects],
            "strengths": self.strengths,
            "weaknesses": self.weaknesses,
            "required_changes": self.required_changes,
            "addressed_changes": self.addressed_changes,
        }


@dataclass(frozen=True)
class PaperRevisionResult:
    """论文修订结果。"""

    status: str
    accepted: bool
    final_score: float
    summary: str
    rounds: int
    review_blocks: list[ReviewBlockResult]
    strengths: list[str]
    weaknesses: list[str]
    required_changes: list[str]
    addressed_changes: list[str]
    revised_markdown: str

    def to_dict(self) -> dict[str, Any]:
        """输出可序列化字典。"""

        return {
            "status": self.status,
            "accepted": self.accepted,
            "final_score": self.final_score,
            "summary": self.summary,
            "rounds": self.rounds,
            "review_blocks": [item.to_dict() for item in self.review_blocks],
            "strengths": self.strengths,
            "weaknesses": self.weaknesses,
            "required_changes": self.required_changes,
            "addressed_changes": self.addressed_changes,
            "revised_markdown": self.revised_markdown,
        }


@dataclass(frozen=True)
class LlmResearchEnhancement:
    """LLM 研究增强结果。"""

    provider: str
    model: str
    status: str
    selected_idea_id: str
    selection_reason: str
    executive_summary: str
    draft_abstract: str
    writing_highlights: list[str]
    used_evidence_ids: list[str]
    used_citation_ids: list[str]
    raw_payload: dict[str, Any]

    def to_dict(self) -> dict[str, Any]:
        """输出可序列化字典。"""

        return {
            "provider": self.provider,
            "model": self.model,
            "status": self.status,
            "selected_idea_id": self.selected_idea_id,
            "selection_reason": self.selection_reason,
            "executive_summary": self.executive_summary,
            "draft_abstract": self.draft_abstract,
            "writing_highlights": self.writing_highlights,
            "used_evidence_ids": self.used_evidence_ids,
            "used_citation_ids": self.used_citation_ids,
            "raw_payload": self.raw_payload,
        }
