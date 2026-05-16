"""构建 claim-to-evidence 图谱。"""

from __future__ import annotations

from services.research.models import (
    _stable_graph_id,
    CitationRecord,
    ClaimGraph,
    ClaimGraphEdge,
    ClaimGraphNode,
    EvidenceAssessment,
    ExperimentPlan,
    ResearchIdea,
)


def _claim_node(claim: str, status: str, reasoning: str) -> ClaimGraphNode:
    """构造主张节点。"""

    return ClaimGraphNode(
        node_id=_stable_graph_id("claim", claim),
        node_type="claim",
        title=claim,
        summary=reasoning,
        status=status,
        metadata={},
    )


def _evidence_node(title: str, summary: str, source_ref: str, status: str = "") -> ClaimGraphNode:
    """构造证据节点。"""

    return ClaimGraphNode(
        node_id=_stable_graph_id("evidence_node", title, source_ref),
        node_type="evidence",
        title=title,
        summary=summary,
        source_ref=source_ref,
        status=status,
        metadata={},
    )


def _citation_node(citation: CitationRecord) -> ClaimGraphNode:
    """构造引用节点。"""

    return ClaimGraphNode(
        node_id=citation.citation_id,
        node_type="citation",
        title=citation.title,
        summary=citation.key_takeaway or citation.snippet,
        source_ref=citation.source_ref,
        status=citation.support_level,
        metadata={
            "claim_supported": citation.claim_supported,
            "citation_reason": citation.citation_reason,
        },
    )


def _experiment_node(title: str, objective: str, status: str = "planned") -> ClaimGraphNode:
    """构造实验节点。"""

    return ClaimGraphNode(
        node_id=_stable_graph_id("experiment_node", title, objective),
        node_type="experiment",
        title=title,
        summary=objective,
        status=status,
        metadata={},
    )


def build_claim_graph(
    *,
    selected_idea: ResearchIdea,
    citations: list[CitationRecord],
    experiment_plan: ExperimentPlan | None,
    evidence_assessment: EvidenceAssessment | None,
) -> ClaimGraph:
    """把研究主张、证据、引用和实验设计组织成图谱。"""

    claim_checks = evidence_assessment.claim_checks if evidence_assessment else []
    evidence_chain = selected_idea.evidence_chain or []
    claim_nodes: list[ClaimGraphNode] = []
    evidence_nodes: list[ClaimGraphNode] = []
    citation_nodes: list[ClaimGraphNode] = []
    experiment_nodes: list[ClaimGraphNode] = []
    edges: list[ClaimGraphEdge] = []

    evidence_node_map: dict[str, ClaimGraphNode] = {}
    for item in evidence_chain:
        node = _evidence_node(
            title=item.title,
            summary=item.summary,
            source_ref=item.source_ref,
            status=item.strength,
        )
        evidence_node_map[item.evidence_id] = node
        evidence_nodes.append(node)

    citation_node_map: dict[str, ClaimGraphNode] = {}
    for citation in citations:
        node = _citation_node(citation)
        citation_node_map[citation.citation_id] = node
        citation_nodes.append(node)

    experiment_designs = (experiment_plan.designs if experiment_plan else []) or []
    experiment_node_map: dict[str, ClaimGraphNode] = {}
    for design in experiment_designs:
        node = _experiment_node(design.title, design.objective)
        experiment_node_map[design.design_id] = node
        experiment_nodes.append(node)

    for check in claim_checks:
        claim_node = _claim_node(check.claim, check.status, check.reasoning)
        claim_nodes.append(claim_node)

        linked_evidence = 0
        for evidence_id, evidence_node in evidence_node_map.items():
            if linked_evidence >= check.evidence_count:
                break
            edges.append(
                ClaimGraphEdge(
                    edge_id=_stable_graph_id("edge", claim_node.node_id, evidence_node.node_id, "supported_by"),
                    from_node_id=claim_node.node_id,
                    to_node_id=evidence_node.node_id,
                    relation="supported_by",
                    reasoning="该证据节点被当前主张引用。",
                )
            )
            linked_evidence += 1

        linked_citations = 0
        for citation in citations:
            if linked_citations >= check.citation_count:
                break
            if citation.claim_supported and citation.claim_supported != check.claim:
                continue
            citation_node = citation_node_map[citation.citation_id]
            edges.append(
                ClaimGraphEdge(
                    edge_id=_stable_graph_id("edge", claim_node.node_id, citation_node.node_id, "cited_by"),
                    from_node_id=claim_node.node_id,
                    to_node_id=citation_node.node_id,
                    relation="cited_by",
                    reasoning="该引用节点被用于支撑当前主张。",
                )
            )
            linked_citations += 1

        if check.has_experiment:
            for design in experiment_designs[:2]:
                experiment_node = experiment_node_map[design.design_id]
                edges.append(
                    ClaimGraphEdge(
                        edge_id=_stable_graph_id("edge", claim_node.node_id, experiment_node.node_id, "validated_by"),
                        from_node_id=claim_node.node_id,
                        to_node_id=experiment_node.node_id,
                        relation="validated_by",
                        reasoning="该实验设计用于验证当前主张。",
                    )
                )

    summary = (
        f"图谱包含 {len(claim_nodes)} 条主张、{len(evidence_nodes)} 条证据、"
        f"{len(citation_nodes)} 条引用和 {len(experiment_nodes)} 个实验设计。"
    )
    return ClaimGraph(
        graph_id=_stable_graph_id("claim_graph", selected_idea.idea_id),
        claim_nodes=claim_nodes,
        evidence_nodes=evidence_nodes,
        citation_nodes=citation_nodes,
        experiment_nodes=experiment_nodes,
        edges=edges,
        summary=summary,
    )
