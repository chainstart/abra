"""Phase 1 审计服务数据模型。

这里定义的是“新合约审计 MVP”这条链路所需的结构化对象，
它们建立在 Phase 0 的统一扫描 schema 之上。
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from services.research.models import RelatedIncidentMatch
from services.shared.models import EvidenceRecord, FindingRecord, ScanReport


@dataclass(frozen=True)
class ContractFile:
    """单个 Solidity 文件的元数据。"""

    path: str
    relative_path: str
    file_name: str
    line_count: int

    def to_dict(self) -> dict[str, Any]:
        """输出可序列化字典。"""

        return {
            "path": self.path,
            "relative_path": self.relative_path,
            "file_name": self.file_name,
            "line_count": self.line_count,
        }


@dataclass(frozen=True)
class IngestionResult:
    """合约接入结果。"""

    target_path: str
    target_kind: str
    source_files: list[ContractFile]
    solidity_file_count: int
    total_line_count: int

    def to_dict(self) -> dict[str, Any]:
        """输出可序列化字典。"""

        return {
            "target_path": self.target_path,
            "target_kind": self.target_kind,
            "source_files": [source_file.to_dict() for source_file in self.source_files],
            "solidity_file_count": self.solidity_file_count,
            "total_line_count": self.total_line_count,
        }


@dataclass(frozen=True)
class ProtocolClassification:
    """协议分类结果。"""

    protocol_name: str
    protocol_type: str
    confidence: str
    rationale: list[str]
    dominant_signals: list[str]

    def to_dict(self) -> dict[str, Any]:
        """输出可序列化字典。"""

        return {
            "protocol_name": self.protocol_name,
            "protocol_type": self.protocol_type,
            "confidence": self.confidence,
            "rationale": self.rationale,
            "dominant_signals": self.dominant_signals,
        }


@dataclass(frozen=True)
class EvidenceSummary:
    """证据聚合摘要。

    这里不是替代原始证据，而是给审计报告层一个更容易消费的聚合视图。
    """

    evidence_count: int
    reproducible_count: int
    source_type_breakdown: dict[str, int]
    analyzer_breakdown: dict[str, int]

    def to_dict(self) -> dict[str, Any]:
        """输出可序列化字典。"""

        return {
            "evidence_count": self.evidence_count,
            "reproducible_count": self.reproducible_count,
            "source_type_breakdown": self.source_type_breakdown,
            "analyzer_breakdown": self.analyzer_breakdown,
        }


@dataclass(frozen=True)
class SemanticSummary:
    """协议语义分析摘要。

    这个对象的目标不是替代完整 AST，而是把审计时最常用的上下文先结构化：

    - 合约数量
    - 函数数量
    - 外部/公开函数数量
    - 敏感函数数量
    - 外部调用数量
    - 事件数量
    - 状态变量数量
    """

    contract_count: int
    function_count: int
    public_or_external_function_count: int
    sensitive_function_count: int
    external_call_count: int
    state_variable_count: int
    event_count: int
    function_names: list[str]
    notable_patterns: list[str] = field(default_factory=list)
    ast_summary: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        """输出可序列化字典。"""

        return {
            "contract_count": self.contract_count,
            "function_count": self.function_count,
            "public_or_external_function_count": self.public_or_external_function_count,
            "sensitive_function_count": self.sensitive_function_count,
            "external_call_count": self.external_call_count,
            "state_variable_count": self.state_variable_count,
            "event_count": self.event_count,
            "function_names": self.function_names,
            "notable_patterns": self.notable_patterns,
            "ast_summary": self.ast_summary,
        }


@dataclass(frozen=True)
class AuditSummary:
    """审计摘要。"""

    total_findings: int
    critical_count: int
    high_count: int
    medium_count: int
    low_count: int
    informational_count: int
    top_findings: list[FindingRecord] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        """输出可序列化字典。"""

        return {
            "total_findings": self.total_findings,
            "critical_count": self.critical_count,
            "high_count": self.high_count,
            "medium_count": self.medium_count,
            "low_count": self.low_count,
            "informational_count": self.informational_count,
            "top_findings": [finding.to_dict() for finding in self.top_findings],
        }


@dataclass(frozen=True)
class AuditRunResult:
    """Phase 1 审计流水线最终结果。"""

    ingestion: IngestionResult
    classification: ProtocolClassification
    semantic_summary: SemanticSummary
    scan_report: ScanReport
    evidence_summary: EvidenceSummary
    audit_summary: AuditSummary
    related_incidents: list[RelatedIncidentMatch] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        """输出可序列化字典。"""

        return {
            "ingestion": self.ingestion.to_dict(),
            "classification": self.classification.to_dict(),
            "semantic_summary": self.semantic_summary.to_dict(),
            "scan_report": self.scan_report.to_dict(),
            "evidence_summary": self.evidence_summary.to_dict(),
            "audit_summary": self.audit_summary.to_dict(),
            "related_incidents": [
                related_incident.to_dict()
                for related_incident in self.related_incidents
            ],
        }


def build_contract_file(root: Path, path: Path) -> ContractFile:
    """从真实文件路径构造 ContractFile。"""

    content = path.read_text(encoding="utf-8")
    return ContractFile(
        path=str(path.resolve()),
        relative_path=str(path.resolve().relative_to(root.resolve())),
        file_name=path.name,
        line_count=len(content.splitlines()),
    )


def select_top_findings(findings: list[FindingRecord], limit: int = 5) -> list[FindingRecord]:
    """挑选最值得展示的 finding。

    当前规则很直接：

    1. 先按严重性排序
    2. 再按标题排序

    Phase 1 先保证稳定可解释，后续再叠加更多评分逻辑。
    """

    severity_order = {
        "Critical": 0,
        "High": 1,
        "Medium": 2,
        "Low": 3,
        "Informational": 4,
    }
    return sorted(
        findings,
        key=lambda finding: (
            severity_order.get(finding.severity, 99),
            finding.title,
            finding.affected_scope.file_path,
            finding.affected_scope.line_start,
        ),
    )[:limit]


def flatten_evidence(findings: list[FindingRecord]) -> list[EvidenceRecord]:
    """从 finding 中提取证据列表。"""

    evidence_items: list[EvidenceRecord] = []
    for finding in findings:
        evidence_items.extend(finding.supporting_evidence)
    return evidence_items
