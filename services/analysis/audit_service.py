"""Phase 1 审计服务编排器。"""

from __future__ import annotations

from collections import Counter
from dataclasses import replace

from tools.analyzers.base import Severity
from services.analysis.contract_ingestion import ingest_contract_target
from services.analysis.evidence_aggregator import build_evidence_summary
from services.analysis.finding_enricher import enrich_findings, normalize_finding_family
from services.analysis.models import (
    AuditRunResult,
    AuditSummary,
)
from services.analysis.protocol_classifier import classify_protocol
from services.analysis.semantic_analyzer import build_semantic_summary
from services.research.incident_retriever import find_related_incidents
from services.analysis.static_analysis_pipeline import run_static_analysis


def _select_top_findings(findings: list, limit: int = 8) -> list:
    """按更接近真实审计判断的方式选重点 finding。"""

    priority_rank = {
        "high_priority": 0,
        "review_recommended": 1,
        "candidate": 2,
    }
    confidence_rank = {
        "high": 0,
        "medium": 1,
        "low": 2,
    }
    severity_rank = {
        "Critical": 0,
        "High": 1,
        "Medium": 2,
        "Low": 3,
        "Informational": 4,
    }
    ranked = sorted(
        findings,
        key=lambda finding: (
            priority_rank.get(finding.priority, 9),
            confidence_rank.get(finding.confidence, 9),
            severity_rank.get(finding.severity, 9),
            finding.affected_scope.file_path,
            finding.affected_scope.line_start,
        ),
    )

    selected: list = []
    seen_families: set[str] = set()
    for finding in ranked:
        family = normalize_finding_family(finding)
        if family in seen_families:
            continue
        seen_families.add(family)
        selected.append(finding)
        if len(selected) >= limit:
            break

    return selected


def _build_audit_summary(audit_result_findings: list) -> AuditSummary:
    """根据 finding 列表生成摘要。"""

    severity_counts = Counter(
        finding.severity for finding in audit_result_findings
    )
    top_findings = _select_top_findings(audit_result_findings, limit=8)

    return AuditSummary(
        total_findings=len(audit_result_findings),
        critical_count=severity_counts.get("Critical", 0),
        high_count=severity_counts.get("High", 0),
        medium_count=severity_counts.get("Medium", 0),
        low_count=severity_counts.get("Low", 0),
        informational_count=severity_counts.get("Informational", 0),
        top_findings=top_findings,
    )


def run_audit(
    *,
    target: str,
    analyzer_names: list[str] | None = None,
    minimum_severity: Severity = Severity.INFO,
) -> AuditRunResult:
    """执行 Phase 1 新合约审计闭环。"""

    ingestion = ingest_contract_target(target)
    classification = classify_protocol(ingestion)
    semantic_summary = build_semantic_summary(ingestion)
    scan_report = run_static_analysis(
        target=target,
        analyzer_names=analyzer_names,
        minimum_severity=minimum_severity,
    )
    related_incidents = find_related_incidents(
        classification=classification,
        findings=scan_report.findings,
    )
    enriched_findings = enrich_findings(
        scan_report.findings,
        ast_summary=semantic_summary.ast_summary,
        related_incidents=related_incidents,
    )
    scan_report = replace(scan_report, findings=enriched_findings)
    evidence_summary = build_evidence_summary(enriched_findings)
    audit_summary = _build_audit_summary(enriched_findings)

    return AuditRunResult(
        ingestion=ingestion,
        classification=classification,
        semantic_summary=semantic_summary,
        scan_report=scan_report,
        evidence_summary=evidence_summary,
        audit_summary=audit_summary,
        related_incidents=related_incidents,
    )
