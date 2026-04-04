"""面向新事件研究的对象层设计。"""

from __future__ import annotations

from dataclasses import dataclass

from services.analysis.models import AuditRunResult
from services.research.models import (
    ClaimEvidenceMatrix,
    ContributionProfile,
    IncidentEvidencePackage,
    ResearchIdea,
)


def _clean(text: str, *, max_length: int = 220) -> str:
    cleaned = " ".join(str(text or "").replace("\n", " ").split()).strip(" -;:,")
    if not cleaned:
        return ""
    if len(cleaned) > max_length:
        cleaned = cleaned[:max_length].rstrip(" ,;:") + "..."
    if cleaned and cleaned[-1] not in ".。!?？！":
        cleaned += "。"
    return cleaned


def _dedupe(items: list[str], *, limit: int | None = None) -> list[str]:
    results: list[str] = []
    seen: set[str] = set()
    for item in items:
        normalized = _clean(item)
        if not normalized:
            continue
        lowered = normalized.lower()
        if lowered in seen:
            continue
        seen.add(lowered)
        results.append(normalized)
        if limit is not None and len(results) >= limit:
            break
    return results


@dataclass(frozen=True)
class IncidentUnderstandingModel:
    """把 incident 转成可研究的统一对象。"""

    incident_id: str
    protocol_name: str
    chain: str
    event_summary: str
    attack_surface: list[str]
    root_cause_candidates: list[str]
    execution_path: list[str]
    key_transactions: list[str]
    affected_components: list[str]
    evidence_completeness: str
    verification_feasibility: str

    def to_dict(self) -> dict[str, object]:
        return {
            "incident_id": self.incident_id,
            "protocol_name": self.protocol_name,
            "chain": self.chain,
            "event_summary": self.event_summary,
            "attack_surface": self.attack_surface,
            "root_cause_candidates": self.root_cause_candidates,
            "execution_path": self.execution_path,
            "key_transactions": self.key_transactions,
            "affected_components": self.affected_components,
            "evidence_completeness": self.evidence_completeness,
            "verification_feasibility": self.verification_feasibility,
        }


@dataclass(frozen=True)
class MechanismNode:
    """机制图节点。"""

    node_id: str
    label: str
    role: str
    summary: str

    def to_dict(self) -> dict[str, str]:
        return {
            "node_id": self.node_id,
            "label": self.label,
            "role": self.role,
            "summary": self.summary,
        }


@dataclass(frozen=True)
class MechanismEdge:
    """机制图边。"""

    from_node_id: str
    to_node_id: str
    relation: str

    def to_dict(self) -> dict[str, str]:
        return {
            "from_node_id": self.from_node_id,
            "to_node_id": self.to_node_id,
            "relation": self.relation,
        }


@dataclass(frozen=True)
class MechanismGraphDesign:
    """事件机制图。"""

    summary: str
    nodes: list[MechanismNode]
    edges: list[MechanismEdge]
    generalized_mechanism: str

    def to_dict(self) -> dict[str, object]:
        return {
            "summary": self.summary,
            "nodes": [item.to_dict() for item in self.nodes],
            "edges": [item.to_dict() for item in self.edges],
            "generalized_mechanism": self.generalized_mechanism,
        }


@dataclass(frozen=True)
class ResearchProgramCandidate:
    """从新事件里挖出的研究方向候选。"""

    candidate_id: str
    title: str
    paper_type: str
    core_question: str
    testable_claim: str
    required_evidence: list[str]
    required_validation: list[str]
    cross_incident_potential: str
    publication_potential: str
    risk_of_being_trivial: str
    selected: bool = False

    def to_dict(self) -> dict[str, object]:
        return {
            "candidate_id": self.candidate_id,
            "title": self.title,
            "paper_type": self.paper_type,
            "core_question": self.core_question,
            "testable_claim": self.testable_claim,
            "required_evidence": self.required_evidence,
            "required_validation": self.required_validation,
            "cross_incident_potential": self.cross_incident_potential,
            "publication_potential": self.publication_potential,
            "risk_of_being_trivial": self.risk_of_being_trivial,
            "selected": self.selected,
        }


@dataclass(frozen=True)
class PaperStrategy:
    """针对当前研究方向选择的论文策略。"""

    paper_type: str
    target_venue_style: str
    article_positioning: str
    section_blueprint: list[str]
    required_figures: list[str]
    required_tables: list[str]
    validation_expectations: list[str]

    def to_dict(self) -> dict[str, object]:
        return {
            "paper_type": self.paper_type,
            "target_venue_style": self.target_venue_style,
            "article_positioning": self.article_positioning,
            "section_blueprint": self.section_blueprint,
            "required_figures": self.required_figures,
            "required_tables": self.required_tables,
            "validation_expectations": self.validation_expectations,
        }


def build_incident_understanding_model(
    *,
    audit_result: AuditRunResult,
    incident_evidence_packages: list[IncidentEvidencePackage],
) -> IncidentUnderstandingModel | None:
    """从证据包抽出统一事件理解对象。"""

    primary = incident_evidence_packages[0] if incident_evidence_packages else None
    if primary is None:
        return None
    root_cause_candidates = _dedupe(
        [primary.root_cause]
        + [component.description for component in primary.affected_components[:3]],
        limit=4,
    )
    execution_path = _dedupe(
        [step.description for step in primary.timeline[:4]]
        + [tx.description for tx in primary.attack_transactions[:2]],
        limit=5,
    )
    attack_surface = _dedupe(
        [item.role for item in primary.affected_components[:4]]
        + [pattern for pattern in audit_result.classification.dominant_signals[:4]],
        limit=5,
    )
    affected_components = _dedupe(
        [component.label or component.reference for component in primary.affected_components[:5]],
        limit=5,
    )
    verification_feasibility = (
        "high"
        if any(item.get("passed") for item in primary.verification_results)
        else "medium" if primary.verification_results else "low"
    )
    evidence_completeness = (
        "strong"
        if not primary.missing_artifacts
        else "partial"
    )
    return IncidentUnderstandingModel(
        incident_id=primary.incident_id,
        protocol_name=primary.protocol_name,
        chain=primary.chain,
        event_summary=_clean(primary.summary, max_length=220),
        attack_surface=attack_surface,
        root_cause_candidates=root_cause_candidates,
        execution_path=execution_path,
        key_transactions=[tx.tx_hash for tx in primary.attack_transactions[:3]],
        affected_components=affected_components,
        evidence_completeness=evidence_completeness,
        verification_feasibility=verification_feasibility,
    )


def build_mechanism_graph_design(
    *,
    incident_model: IncidentUnderstandingModel | None,
) -> MechanismGraphDesign | None:
    """把事件理解对象提升为机制图。"""

    if incident_model is None:
        return None
    nodes = [
        MechanismNode("entry", "Entry Condition", "entry", incident_model.execution_path[0] if incident_model.execution_path else incident_model.event_summary),
        MechanismNode("pricing", "Price Interpretation", "pricing", incident_model.root_cause_candidates[0] if incident_model.root_cause_candidates else incident_model.event_summary),
        MechanismNode("constraint", "Constraint Acceptance", "constraint", incident_model.execution_path[1] if len(incident_model.execution_path) > 1 else incident_model.event_summary),
        MechanismNode("outcome", "Economic Outcome", "outcome", incident_model.execution_path[-1] if incident_model.execution_path else incident_model.event_summary),
    ]
    edges = [
        MechanismEdge("entry", "pricing", "introduces malformed input"),
        MechanismEdge("pricing", "constraint", "propagates abnormal valuation"),
        MechanismEdge("constraint", "outcome", "permits economic extraction"),
    ]
    generalized_mechanism = _clean(
        "permissionless entry + unchecked semantic normalization + solvency gate acceptance",
        max_length=180,
    )
    return MechanismGraphDesign(
        summary=_clean(
            f"{incident_model.protocol_name} 个案显示，风险并非停留在单点输入错误，而是沿 entry -> pricing -> constraint -> outcome 的链条传播。",
            max_length=220,
        ),
        nodes=nodes,
        edges=edges,
        generalized_mechanism=generalized_mechanism,
    )


def build_research_program_candidates(
    *,
    selected_idea: ResearchIdea,
    incident_model: IncidentUnderstandingModel | None,
    mechanism_graph: MechanismGraphDesign | None,
    claim_evidence_matrix: ClaimEvidenceMatrix | None,
    incident_evidence_packages: list[IncidentEvidencePackage],
) -> list[ResearchProgramCandidate]:
    """从事件理解与机制图中生成研究方案候选。"""

    strong_incident_count = sum(
        1
        for package in incident_evidence_packages
        if package.attack_transactions and not package.missing_artifacts
    )
    measurement_selected = strong_incident_count >= 3
    case_selected = not measurement_selected
    mechanism_summary = mechanism_graph.generalized_mechanism if mechanism_graph else selected_idea.hypothesis
    candidates = [
        ResearchProgramCandidate(
            candidate_id="case_study_program",
            title="Incident-grounded Security Case Study",
            paper_type="case_study",
            core_question=_clean(selected_idea.problem_statement, max_length=200),
            testable_claim=_clean(selected_idea.hypothesis, max_length=180),
            required_evidence=_dedupe(
                ["单事件完整事实包", "链上锚点交易", "fork / PoC 复现结果"],
                limit=4,
            ),
            required_validation=_dedupe(
                ["路径复现", "counterfactual", "boundary discussion"],
                limit=4,
            ),
            cross_incident_potential="medium" if strong_incident_count >= 2 else "low",
            publication_potential="high",
            risk_of_being_trivial="如果只停留在事件复盘而没有主张对象，就会退化成技术报告。",
            selected=case_selected,
        ),
        ResearchProgramCandidate(
            candidate_id="measurement_program",
            title="Cross-incident Security Measurement",
            paper_type="measurement",
            core_question="同类机制是否在多个 DeFi 事件中重复出现，并能被统一测量？",
            testable_claim=f"{mechanism_summary} 可以作为跨事件的测量维度。",
            required_evidence=_dedupe(
                ["至少 2-3 个同类 incident", "统一机制标签", "跨事件对照表"],
                limit=4,
            ),
            required_validation=_dedupe(
                ["case coverage", "category consistency", "measurement table", "baseline comparison"],
                limit=4,
            ),
            cross_incident_potential="high" if strong_incident_count >= 3 else "medium",
            publication_potential="high" if strong_incident_count >= 3 else "medium",
            risk_of_being_trivial="如果事件数量不足，measurement paper 会显得证据基础过窄。",
            selected=measurement_selected,
        ),
        ResearchProgramCandidate(
            candidate_id="defense_program",
            title="Minimal Defense Condition Paper",
            paper_type="defense",
            core_question="哪些最小有效性校验足以阻断这类利用路径？",
            testable_claim="市场准入、价格语义归一化和借款结果约束三类检查共同构成最小防御条件。",
            required_evidence=_dedupe(
                ["机制图", "失败条件", "修复后 counterfactual"],
                limit=4,
            ),
            required_validation=_dedupe(
                ["patched-path validation", "compatibility analysis", "new-risk discussion"],
                limit=4,
            ),
            cross_incident_potential="medium",
            publication_potential="medium",
            risk_of_being_trivial="如果没有展示防御前后差异，这类论文会沦为设计建议清单。",
            selected=False,
        ),
    ]
    return candidates


def build_paper_strategy(
    *,
    program_candidates: list[ResearchProgramCandidate],
    contribution_profile: ContributionProfile | None,
) -> PaperStrategy:
    """根据选中的研究程序确定论文策略。"""

    selected = next((item for item in program_candidates if item.selected), program_candidates[0])
    if selected.paper_type == "measurement":
        return PaperStrategy(
            paper_type="measurement",
            target_venue_style="ieee_tsc_measurement",
            article_positioning=_clean(
                "把新事件提升为跨事件测量对象，强调统一机制、覆盖范围和比较结果。",
                max_length=220,
            ),
            section_blueprint=[
                "Abstract",
                "Introduction",
                "Problem Formulation",
                "Dataset and Incident Modeling",
                "Measurement Method",
                "Results",
                "Threats to Validity",
                "Conclusion",
            ],
            required_figures=[
                "Mechanism family overview",
                "Cross-incident comparison chart",
            ],
            required_tables=[
                "Incident comparison table",
                "Measurement result table",
                "Claim-to-evidence table",
            ],
            validation_expectations=[
                "需要 baseline 和至少一张结果表",
                "需要明确 measurement scope 和 coverage",
            ],
        )
    if selected.paper_type == "defense":
        return PaperStrategy(
            paper_type="defense",
            target_venue_style="acm_defense_design",
            article_positioning=_clean(
                contribution_profile.summary if contribution_profile else "把当前事件抽象为最小防御条件与设计约束问题。",
                max_length=220,
            ),
            section_blueprint=[
                "Abstract",
                "Introduction",
                "Threat Model",
                "Defense Design",
                "Security Analysis",
                "Evaluation",
                "Limitations",
                "Conclusion",
            ],
            required_figures=[
                "Defense insertion points",
                "Patched vs. vulnerable path",
            ],
            required_tables=[
                "Defense rule table",
                "Compatibility and residual risk table",
            ],
            validation_expectations=[
                "需要 patched-path validation",
                "需要 residual risk discussion",
            ],
        )
    return PaperStrategy(
        paper_type="case_study",
        target_venue_style="acm_case_study",
        article_positioning=_clean(
            contribution_profile.summary if contribution_profile else "把单一 incident 提升为可审查的安全机制个案研究。",
            max_length=220,
        ),
        section_blueprint=[
            "Abstract",
            "Introduction",
            "Background",
            "Incident Reconstruction",
            "Claim-Evidence Mapping",
            "Validation",
            "Related Work",
            "Threats to Validity",
            "Conclusion",
        ],
        required_figures=[
            "Attack mechanism chain",
            "Validation boundary map",
        ],
        required_tables=[
            "Incident facts table",
            "Claim-to-evidence table",
            "Validation scenario table",
        ],
        validation_expectations=[
            "每条主张都必须有 direct evidence 和 counterfactual",
            "必须显式写出 boundary",
        ],
    )


def render_incident_understanding_markdown(model: IncidentUnderstandingModel | dict) -> str:
    if isinstance(model, dict):
        payload = model
    else:
        payload = model.to_dict()
    return "\n".join(
        [
            "# Incident Understanding Model",
            "",
            f"- Incident ID: {payload.get('incident_id', '')}",
            f"- Protocol: {payload.get('protocol_name', '')}",
            f"- Chain: {payload.get('chain', '')}",
            f"- Summary: {payload.get('event_summary', '')}",
            f"- Attack Surface: {'；'.join(payload.get('attack_surface', []) or []) or '暂无'}",
            f"- Root Cause Candidates: {'；'.join(payload.get('root_cause_candidates', []) or []) or '暂无'}",
            f"- Execution Path: {'；'.join(payload.get('execution_path', []) or []) or '暂无'}",
            f"- Key Transactions: {'；'.join(payload.get('key_transactions', []) or []) or '暂无'}",
            f"- Components: {'；'.join(payload.get('affected_components', []) or []) or '暂无'}",
            f"- Evidence Completeness: {payload.get('evidence_completeness', '')}",
            f"- Verification Feasibility: {payload.get('verification_feasibility', '')}",
            "",
        ]
    ).strip() + "\n"


def render_mechanism_graph_markdown(graph: MechanismGraphDesign | dict) -> str:
    if isinstance(graph, dict):
        payload = graph
        nodes = payload.get("nodes", []) or []
        edges = payload.get("edges", []) or []
    else:
        payload = graph.to_dict()
        nodes = payload["nodes"]
        edges = payload["edges"]
    lines = [
        "# Mechanism Graph",
        "",
        f"- Summary: {payload.get('summary', '')}",
        f"- Generalized Mechanism: {payload.get('generalized_mechanism', '')}",
        "",
        "## Nodes",
        "",
    ]
    lines.extend(
        f"- {item.get('node_id', '')} | {item.get('role', '')} | {item.get('label', '')} | {item.get('summary', '')}"
        for item in nodes
    )
    lines.extend(["", "## Edges", ""])
    lines.extend(
        f"- {item.get('from_node_id', '')} -> {item.get('to_node_id', '')} | {item.get('relation', '')}"
        for item in edges
    )
    return "\n".join(lines).strip() + "\n"


def render_research_program_markdown(items: list[ResearchProgramCandidate] | list[dict]) -> str:
    payload = [item.to_dict() if hasattr(item, "to_dict") else item for item in items]
    lines = ["# Research Program Candidates", ""]
    for item in payload:
        lines.extend(
            [
                f"## {item.get('title', '')}",
                "",
                f"- Candidate ID: {item.get('candidate_id', '')}",
                f"- Paper Type: {item.get('paper_type', '')}",
                f"- Selected: {item.get('selected', False)}",
                f"- Core Question: {item.get('core_question', '')}",
                f"- Testable Claim: {item.get('testable_claim', '')}",
                f"- Required Evidence: {'；'.join(item.get('required_evidence', []) or []) or '暂无'}",
                f"- Required Validation: {'；'.join(item.get('required_validation', []) or []) or '暂无'}",
                f"- Cross-incident Potential: {item.get('cross_incident_potential', '')}",
                f"- Publication Potential: {item.get('publication_potential', '')}",
                f"- Risk of Being Trivial: {item.get('risk_of_being_trivial', '')}",
                "",
            ]
        )
    return "\n".join(lines).strip() + "\n"


def render_paper_strategy_markdown(strategy: PaperStrategy | dict) -> str:
    payload = strategy.to_dict() if hasattr(strategy, "to_dict") else strategy
    return "\n".join(
        [
            "# Paper Strategy",
            "",
            f"- Paper Type: {payload.get('paper_type', '')}",
            f"- Target Venue Style: {payload.get('target_venue_style', '')}",
            f"- Positioning: {payload.get('article_positioning', '')}",
            f"- Section Blueprint: {'；'.join(payload.get('section_blueprint', []) or []) or '暂无'}",
            f"- Required Figures: {'；'.join(payload.get('required_figures', []) or []) or '暂无'}",
            f"- Required Tables: {'；'.join(payload.get('required_tables', []) or []) or '暂无'}",
            f"- Validation Expectations: {'；'.join(payload.get('validation_expectations', []) or []) or '暂无'}",
            "",
        ]
    ).strip() + "\n"
