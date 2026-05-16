"""把研究想法提纯为可投稿的贡献表达。"""

from __future__ import annotations

from services.analysis.models import AuditRunResult
from services.research.models import (
    ContributionEntry,
    ContributionProfile,
    EvidenceAssessment,
    ExperimentPlan,
    IncidentEvidencePackage,
    ResearchIdea,
)


def _clean(text: str, *, max_length: int = 220) -> str:
    normalized = " ".join((text or "").replace("\n", " ").split()).strip(" -;:,")
    if not normalized:
        return ""
    if len(normalized) > max_length:
        normalized = normalized[:max_length].rstrip(" ,;:") + "..."
    if normalized[-1] not in ".。!?？！":
        normalized += "。"
    return normalized


def _joined(items: list[str], limit: int = 3) -> str:
    values = [item.strip() for item in items if str(item).strip()]
    return "；".join(values[:limit])


def crystallize_contributions(
    *,
    research_idea: ResearchIdea,
    audit_result: AuditRunResult,
    evidence_assessment: EvidenceAssessment | None,
    experiment_plan: ExperimentPlan | None,
    incident_evidence_packages: list[IncidentEvidencePackage] | None = None,
) -> ContributionProfile:
    """生成更接近期刊写法的贡献摘要。"""

    incident_evidence_packages = incident_evidence_packages or []
    primary_incident = incident_evidence_packages[0] if incident_evidence_packages else None
    passed_verifications = [
        item
        for package in incident_evidence_packages
        for item in package.verification_results
        if item.get("passed")
    ]
    claim_count = len(evidence_assessment.claim_checks) if evidence_assessment else 0
    protocol_name = audit_result.classification.protocol_name or "目标协议"

    thesis_statement = _clean(
        "本文以 "
        f"{primary_incident.title if primary_incident else protocol_name}"
        " 为 incident 锚点，研究错误 Oracle 参数如何在无许可接入与借贷约束链路中演化为可复现攻击条件，"
        "并把经验事件、链上锚点与最小复现实验收束为受限但可辩护的安全研究结论。"
    )
    problem_framing = _clean(
        research_idea.problem_statement
        or research_idea.hypothesis
        or f"围绕 {protocol_name} 的关键攻击面形成研究问题。"
    )
    novelty_positioning = _clean(
        "本文的新增价值不在于提出全新攻击原语，"
        "而在于把历史事故、链上交易事实、结构化机制解释与最小复现实验合并成同一条 claim-driven 证据链。"
    )

    source_statements = list(research_idea.expected_contributions or [])[:3]
    if not source_statements:
        source_statements = [
            "把真实攻击事件重构为可以直接进入论文主线的 incident-first 证据包。",
            "把无许可市场创建、Oracle 定价传播与借贷约束信任关系抽象为可审查的机制链条。",
            "给出最小复现实验与候选防护条件，使主张不止停留在静态猜想。",
        ]

    evidence_anchor = (
        _joined(primary_incident.evidence_summary, limit=2)
        if primary_incident and primary_incident.evidence_summary
        else _joined([item.title for item in (research_idea.evidence_chain or [])], limit=2)
        or "当前证据链已覆盖核心 incident 背景与结构化机制证据。"
    )
    verification_anchor = (
        _joined([str(item.get("summary") or "").strip() for item in passed_verifications], limit=2)
        or (
            _joined([design.title for design in (experiment_plan.designs or [])], limit=2)
            if experiment_plan and experiment_plan.designs
            else "当前版本已给出最小复现实验目标、步骤、成功标准与失败条件。"
        )
    )
    boundary = _clean(
        "当前主张边界被限定在 "
        f"{primary_incident.title if primary_incident else protocol_name}"
        " 所代表的个案、本文分析的接入模式、以及"
        f" {claim_count or 1} 条核心研究主张的验证覆盖范围内。"
    )

    entries: list[ContributionEntry] = []
    for index, statement in enumerate(source_statements, start=1):
        entries.append(
            ContributionEntry(
                contribution_id=f"contribution_{index}",
                label=f"贡献 {index}",
                statement=_clean(statement),
                evidence_anchor=evidence_anchor,
                validation_anchor=verification_anchor,
                novelty_anchor=novelty_positioning,
                boundary=boundary,
                confidence=(
                    "high"
                    if evidence_assessment and evidence_assessment.is_sufficient and passed_verifications
                    else "medium"
                ),
            )
        )

    summary = _clean(
        f"当前稿件把 {len(entries)} 项核心贡献压缩为统一的论文主线："
        "先用 incident 证据证明问题真实发生，再用机制解释说明风险如何传播，最后用最小复现实验限定结论边界。"
    )
    return ContributionProfile(
        thesis_statement=thesis_statement,
        problem_framing=problem_framing,
        novelty_positioning=novelty_positioning,
        summary=summary,
        entries=entries,
    )


def render_contribution_profile_markdown(profile: ContributionProfile | dict) -> str:
    """输出贡献提纯 Markdown。"""

    if isinstance(profile, dict):
        thesis_statement = str(profile.get("thesis_statement") or "")
        problem_framing = str(profile.get("problem_framing") or "")
        novelty_positioning = str(profile.get("novelty_positioning") or "")
        summary = str(profile.get("summary") or "")
        entries = profile.get("entries") or []
    else:
        thesis_statement = profile.thesis_statement
        problem_framing = profile.problem_framing
        novelty_positioning = profile.novelty_positioning
        summary = profile.summary
        entries = [item.to_dict() for item in profile.entries]

    sections = [
        "# Contribution Profile",
        "",
        f"- Thesis Statement: {thesis_statement}",
        f"- Problem Framing: {problem_framing}",
        f"- Novelty Positioning: {novelty_positioning}",
        f"- Summary: {summary}",
        "",
    ]
    for entry in entries:
        sections.extend(
            [
                f"## {entry.get('label', '')}",
                "",
                f"- Statement: {entry.get('statement', '')}",
                f"- Evidence Anchor: {entry.get('evidence_anchor', '')}",
                f"- Validation Anchor: {entry.get('validation_anchor', '')}",
                f"- Novelty Anchor: {entry.get('novelty_anchor', '')}",
                f"- Boundary: {entry.get('boundary', '')}",
                f"- Confidence: {entry.get('confidence', '')}",
                "",
            ]
        )
    return "\n".join(sections).strip() + "\n"
