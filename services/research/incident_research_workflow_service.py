"""攻击事件驱动的研究工作流。"""

from __future__ import annotations

from collections import Counter

from services.analysis.evidence_aggregator import build_evidence_summary
from services.analysis.models import (
    AuditRunResult,
    AuditSummary,
    IngestionResult,
    ProtocolClassification,
    SemanticSummary,
)
from services.analysis.presentation import build_audit_presentation
from services.research.claim_evidence_matrix import build_claim_evidence_matrix
from services.research.claim_graph_builder import build_claim_graph
from services.research.contribution_crystallizer import crystallize_contributions
from services.research.discovered_incident_repository import load_discovered_incident
from services.research.evidence_assessment import assess_research_evidence
from services.research.event_discovery import run_event_discovery_round
from services.research.experiment_gap_analyzer import analyze_experiment_gaps
from services.research.experiment_planner import build_experiment_plan
from services.research.incident_chain_hydrator import hydrate_incident_chain_evidence
from services.research.incident_evidence_service import build_incident_evidence_packages
from services.research.incident_repository import load_incidents
from services.research.incident_retriever import find_related_incidents
from services.research.incident_verification_service import run_incident_local_verifications
from services.research.journal_fit import assess_journal_fit
from services.research.llm_research_enhancer import summarize_research_package_with_llm
from services.research.manuscript_llm_writer import write_manuscript_with_llm
from services.research.manuscript_package_builder import build_manuscript_package
from services.research.models import IncidentEvidencePackage
from services.research.paper_revision import run_revision_cycle
from services.research.paper_draft_writer import render_paper_draft
from services.research.publication_task_design import build_publication_task_design
from services.research.publication_readiness import assess_publication_readiness
from services.research.research_object_design import (
    build_incident_understanding_model,
    build_mechanism_graph_design,
    build_paper_strategy,
    build_research_program_candidates,
)
from services.research.reference_validation import validate_references
from services.research.related_work_service import retrieve_related_work
from services.research.research_idea_generator import generate_research_ideas
from services.research.research_memo_writer import render_research_memo
from services.research.research_workflow_service import ResearchWorkflowResult
from services.research.rollback_planner import build_rollback_plan
from services.research.submission_compliance import evaluate_submission_compliance
from services.shared.models import AffectedScope, EvidenceRecord, FindingRecord, ScanReport, ScanTarget
from services.shared.settings import ProjectSettings


def _revisit_incident_supporting_materials(
    *,
    selected_idea,
    audit_result,
    incident_evidence_packages,
    reference_validation,
    revision_result,
):
    """当 review 指出证据/验证/相关工作问题时，回到前面补材料。"""

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
        updated_incident_packages = build_incident_evidence_packages(
            [match.incident for match in audit_result.related_incidents[:3]],
            verification_results_by_incident={
                match.incident.incident_id: run_incident_local_verifications(match.incident)
                for match in audit_result.related_incidents[:3]
            },
        )

    return updated_citations, updated_reference_validation, updated_incident_packages


def _select_incident(incident_id: str):
    """读取单个 incident。"""

    settings = ProjectSettings.from_env()
    incidents = load_incidents(settings.research_dir / "incidents")
    for incident in incidents:
        if incident.incident_id == incident_id:
            return incident
    raise ValueError(f"未找到 incident_id={incident_id} 的案例。")


def _candidate_to_incident(candidate_id: str):
    """把外部发现候选事件转换为 research incident 草稿。"""

    candidate = load_discovered_incident(candidate_id)
    if not candidate:
        raise ValueError(f"未找到 candidate_id={candidate_id} 的外部事件候选。")

    from services.research.models import IncidentRecord

    year = 0
    if candidate.discovered_at[:4].isdigit():
        year = int(candidate.discovered_at[:4])
    return IncidentRecord(
        incident_id=candidate.candidate_id,
        title=candidate.title,
        protocol_name=candidate.protocol_name_guess or candidate.title,
        protocol_type=candidate.protocol_type_guess or "unknown",
        year=year or 1970,
        summary=candidate.summary,
        root_cause=candidate.attack_method or "待补充根因",
        attack_patterns=[item for item in [candidate.attack_method.lower().strip()] if item],
        affected_categories=candidate.suggested_categories or ["SC-07: Logic Errors"],
        keywords=candidate.tags[:8],
        source_reports=[candidate.reference_url] if candidate.reference_url else [],
        evidence_payload={
            "chain": "unknown",
            "loss_summary": candidate.loss_text,
            "timeline": [
                {
                    "title": "外部事件发现",
                    "description": candidate.summary,
                }
            ],
            "discovery_source": candidate.source,
            "reference_url": candidate.reference_url,
            "candidate_metadata": candidate.to_dict(),
        },
    )


def _severity_for_category(category: str) -> str:
    """为 incident 类别分配展示严重性。"""

    if category in {"SC-01: Reentrancy", "SC-03: Oracle Manipulation"}:
        return "High"
    if category in {"SC-08: Upgrade Safety", "SC-09: Governance"}:
        return "High"
    return "Medium"


def _default_incident_guardrails(incident) -> list[str]:
    """为特定 incident 类型生成默认最小校验条件。"""

    categories = set(incident.affected_categories)
    if "SC-03: Oracle Manipulation" in categories:
        return [
            "Oracle 地址应可用且 `price()` 不应 revert",
            "价格返回值必须大于 0，且单位 / decimals 一致",
            "base / quote token decimals 需要自动校验或显式约束",
            "市场创建时应验证 Oracle 可用性与价格合理性",
        ]
    if "SC-09: Governance" in categories or "SC-08: Upgrade Safety" in categories:
        return [
            "治理提案上线前应有回归测试和影子演练",
            "参数 / 逻辑升级后应验证关键会计路径",
            "高风险治理变更应有 timelock 期间复核与回滚预案",
        ]
    return []


def _build_synthetic_findings(package: IncidentEvidencePackage, incident) -> list[FindingRecord]:
    """从 incident evidence package 构造研究输入 finding。"""

    findings: list[FindingRecord] = []
    source_ref = package.source_reports[0] if package.source_reports else incident.incident_id

    for index, category in enumerate(incident.affected_categories, start=1):
        evidence_items: list[EvidenceRecord] = [
            EvidenceRecord(
                evidence_id=f"{incident.incident_id}_summary_evidence_{index}",
                source_type="incident_package",
                source_ref=incident.incident_id,
                content_summary="；".join(package.evidence_summary[:4]),
                raw_pointer=incident.incident_id,
                confidence="high",
                derived_by="incident_package",
                reproducible=not package.missing_artifacts,
            )
        ]

        for tx_index, tx in enumerate(package.attack_transactions[:2], start=1):
            evidence_items.append(
                EvidenceRecord(
                    evidence_id=f"{incident.incident_id}_tx_evidence_{index}_{tx_index}",
                    source_type="onchain_transaction",
                    source_ref=tx.tx_hash,
                    content_summary=f"{tx.label} / status={tx.status} / selector={tx.selector_name or tx.selector or 'unknown'}",
                    raw_pointer=tx.tx_hash,
                    confidence="high" if tx.indexed else "medium",
                    derived_by="incident_chain_hydrator",
                    reproducible=tx.indexed,
                )
            )

        for verification_index, verification in enumerate(package.verification_results[:1], start=1):
            evidence_items.append(
                EvidenceRecord(
                    evidence_id=f"{incident.incident_id}_verification_evidence_{index}_{verification_index}",
                    source_type="local_verification",
                    source_ref=verification.get("match_path", ""),
                    content_summary=verification.get("summary", ""),
                    raw_pointer=verification.get("command", ""),
                    confidence="high" if verification.get("passed") else "medium",
                    derived_by="incident_verification_service",
                    reproducible=bool(verification.get("passed")),
                )
            )

        findings.append(
            FindingRecord(
                finding_id=f"{incident.incident_id}_finding_{index}",
                analyzer="incident-analysis",
                title=f"{incident.title} -> {category}",
                severity=_severity_for_category(category),
                category=category,
                description=incident.summary,
                recommendation=incident.root_cause,
                affected_scope=AffectedScope(
                    file_path=source_ref,
                    line_start=1,
                    line_end=1,
                ),
                confidence="high",
                priority="high_priority",
                reasoning_basis=[
                    "研究对象来自真实历史攻击事件",
                    "已整理为结构化 incident evidence package",
                ],
                validation_next_step=(
                    "优先补充或复核本地 fork / PoC 验证结果。"
                    if package.verification_results
                    else "补充本地验证或更多链上证据。"
                ),
                verification_status="confirmed_incident",
                supporting_evidence=evidence_items,
                tags=["incident-analysis", category, incident.protocol_type],
            )
        )

    return findings


def _build_incident_audit_result_from_incident(
    incident,
) -> tuple[AuditRunResult, list[IncidentEvidencePackage]]:
    """把攻击事件证据包提升为研究工作流可消费上下文。"""
    settings = ProjectSettings.from_env()
    try:
        hydrate_incident_chain_evidence(incident_id=incident.incident_id)
    except Exception:
        # discovered candidate 或尚未具备交易锚点时允许继续，
        # 后续由门禁决定是否放行研究稿。
        pass
    seed_verifications = run_incident_local_verifications(incident)

    classification = ProtocolClassification(
        protocol_name=incident.protocol_name,
        protocol_type=incident.protocol_type,
        confidence="high",
        rationale=[
            "当前研究入口直接基于已知历史攻击事件。",
            f"案例类别: {', '.join(incident.affected_categories)}",
        ],
        dominant_signals=incident.attack_patterns[:6],
    )

    provisional_finding = FindingRecord(
        finding_id=f"{incident.incident_id}_seed",
        analyzer="incident-analysis",
        title=incident.title,
        severity="High",
        category=incident.affected_categories[0] if incident.affected_categories else "SC-07: Logic Errors",
        description=incident.summary,
        recommendation=incident.root_cause,
        affected_scope=AffectedScope(
            file_path=incident.source_reports[0] if incident.source_reports else incident.incident_id,
            line_start=1,
            line_end=1,
        ),
    )
    related_incidents = find_related_incidents(
        classification=classification,
        findings=[provisional_finding],
        limit=4,
    )
    try:
        hydrate_incident_chain_evidence(
            incident_ids=[match.incident.incident_id for match in related_incidents],
        )
    except Exception:
        # related incident 的链上富化失败时允许降级继续，
        # 后续由证据门禁决定是否影响成稿与投稿判断。
        pass

    verification_results_by_incident: dict[str, list[dict]] = {}
    if seed_verifications:
        verification_results_by_incident[incident.incident_id] = seed_verifications
    for match in related_incidents:
        if match.incident.incident_id == incident.incident_id:
            continue
        results = run_incident_local_verifications(match.incident)
        if results:
            verification_results_by_incident[match.incident.incident_id] = results

    packages = build_incident_evidence_packages(
        [match.incident for match in related_incidents] or [incident],
        verification_results_by_incident=verification_results_by_incident,
    )
    primary_package = next(
        (package for package in packages if package.incident_id == incident.incident_id),
        packages[0],
    )

    findings = _build_synthetic_findings(primary_package, incident)
    scan_report = ScanReport(
        schema_version="security_scan_report@1.0.0",
        generated_at="",
        tool={
            "name": "incident-research-context-builder",
            "version": "phase24",
            "phase": "24",
        },
        target=ScanTarget(
            path=f"incident://{incident.incident_id}",
            kind="incident",
            analyzers_requested=["incident-analysis"],
            minimum_severity="Informational",
        ),
        stats={
            "files_scanned": 0,
            "analyzers_run": 1,
            "total_findings": len(findings),
            "incident_packages": len(packages),
        },
        findings=findings,
    )
    evidence_summary = build_evidence_summary(findings)

    severity_counts = Counter(finding.severity for finding in findings)
    audit_summary = AuditSummary(
        total_findings=len(findings),
        critical_count=severity_counts.get("Critical", 0),
        high_count=severity_counts.get("High", 0),
        medium_count=severity_counts.get("Medium", 0),
        low_count=severity_counts.get("Low", 0),
        informational_count=severity_counts.get("Informational", 0),
        top_findings=findings[:5],
    )
    semantic_summary = SemanticSummary(
        contract_count=len(primary_package.affected_components),
        function_count=len(primary_package.timeline) + len(primary_package.attack_transactions),
        public_or_external_function_count=len(primary_package.attack_transactions),
        sensitive_function_count=len(primary_package.affected_components),
        external_call_count=len(primary_package.attack_transactions),
        state_variable_count=0,
        event_count=primary_package.indexed_log_count,
        function_names=[item.label for item in primary_package.affected_components[:10]],
        notable_patterns=[
            "真实攻击事件驱动研究",
            "已完成链上交易富化" if not primary_package.missing_artifacts else "证据仍有缺口",
        ],
        ast_summary={
            "incident_entities": [item.to_dict() for item in primary_package.key_entities],
            "incident_timeline": [item.to_dict() for item in primary_package.timeline],
            "incident_verifications": primary_package.verification_results,
            "incident_guardrails": _default_incident_guardrails(incident),
            "public_entrypoints": [item.label for item in primary_package.affected_components],
            "cross_contract_call_edges": [],
            "state_conflicts": [],
            "write_after_external_functions": [],
        },
    )
    ingestion = IngestionResult(
        target_path=f"incident://{incident.incident_id}",
        target_kind="incident",
        source_files=[],
        solidity_file_count=0,
        total_line_count=0,
    )

    return (
        AuditRunResult(
            ingestion=ingestion,
            classification=classification,
            semantic_summary=semantic_summary,
            scan_report=scan_report,
            evidence_summary=evidence_summary,
            audit_summary=audit_summary,
            related_incidents=related_incidents,
        ),
        packages,
    )


def _build_incident_audit_result(
    incident_id: str,
) -> tuple[AuditRunResult, list[IncidentEvidencePackage]]:
    """按本地 incident_id 构建研究上下文。"""

    return _build_incident_audit_result_from_incident(_select_incident(incident_id))


def run_incident_research_workflow(
    *,
    incident_id: str,
) -> ResearchWorkflowResult:
    """按攻击事件直接运行研究工作流。"""

    audit_result, incident_evidence_packages = _build_incident_audit_result(incident_id)
    return _run_research_on_context(audit_result, incident_evidence_packages)


def run_event_discovery_research_workflow(
    *,
    limit: int = 12,
    min_relevance: float = 0.45,
) -> ResearchWorkflowResult:
    """先自动发现新事件，再对最高优先级候选进入研究链。"""

    discovery_result = run_event_discovery_round(
        limit=limit,
        min_relevance=min_relevance,
        refresh=True,
    )
    incident = _candidate_to_incident(discovery_result.selected_candidate_id)
    audit_result, incident_evidence_packages = _build_incident_audit_result_from_incident(incident)
    return _run_research_on_context(
        audit_result,
        incident_evidence_packages,
        event_discovery_result=discovery_result,
    )


def _run_research_on_context(
    audit_result: AuditRunResult,
    incident_evidence_packages: list[IncidentEvidencePackage],
    event_discovery_result=None,
) -> ResearchWorkflowResult:
    """在给定 incident 上下文上运行研究主链。"""

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
            event_discovery_result=event_discovery_result,
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
            incident_evidence_packages=incident_evidence_packages,
            reference_validation=None,
            revision_result=None,
            journal_fit_assessment=None,
            submission_compliance=None,
            publication_readiness=None,
            rollback_plan=None,
            llm_status="disabled",
            llm_error="",
        )

    settings = ProjectSettings.from_env()
    citations = retrieve_related_work(selected_idea, audit_result)
    reference_validation = validate_references(
        citations=citations,
        research_idea=selected_idea,
    )
    citations = reference_validation.validated_citations
    experiment_plan = build_experiment_plan(selected_idea, audit_result)
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

    llm_status = "disabled"
    llm_error = ""
    llm_enhancement = None
    if not evidence_assessment.is_sufficient and settings.research_llm_available:
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
            citations, reference_validation, incident_evidence_packages = _revisit_incident_supporting_materials(
                selected_idea=selected_idea,
                audit_result=audit_result,
                incident_evidence_packages=incident_evidence_packages,
                reference_validation=reference_validation,
                revision_result=revision_result,
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
        event_discovery_result=event_discovery_result,
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


def run_discovered_candidate_research_workflow(
    *,
    candidate_id: str,
) -> ResearchWorkflowResult:
    """按外部发现候选事件直接运行研究。"""

    incident = _candidate_to_incident(candidate_id)
    audit_result, incident_evidence_packages = _build_incident_audit_result_from_incident(incident)
    return _run_research_on_context(audit_result, incident_evidence_packages)
