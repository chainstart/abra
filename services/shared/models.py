"""Phase 0 共用数据模型。

这里放的是当前仓库第一版统一结构，用来把：

1. 规则扫描器输出
2. 报告生成输入
3. 后续知识库与 Agent 编排

连接到同一套数据对象上。
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
from typing import Any


SCAN_OUTPUT_SCHEMA_VERSION = "security_scan_report@1.0.0"


def _stable_id(prefix: str, *parts: object) -> str:
    """生成稳定 ID。

    Phase 0 不引入数据库自增主键，先用稳定哈希保证：

    - 同一 finding / evidence 重复生成时 ID 可预测
    - 测试可以稳定断言
    - 后续入库时便于做去重
    """

    raw = "||".join(str(part) for part in parts)
    digest = hashlib.sha1(raw.encode("utf-8")).hexdigest()[:16]
    return f"{prefix}_{digest}"


@dataclass(frozen=True)
class AffectedScope:
    """受影响代码范围。"""

    file_path: str
    line_start: int
    line_end: int

    def to_dict(self) -> dict[str, Any]:
        """输出可序列化字典。"""

        return {
            "file_path": self.file_path,
            "line_start": self.line_start,
            "line_end": self.line_end,
        }


@dataclass(frozen=True)
class EvidenceRecord:
    """统一证据对象。

    Phase 0 先支持最小必需字段，后续可以继续扩展：

    - trace
    - 文档摘录
    - fork 测试结果
    - 研究实验记录
    """

    evidence_id: str
    source_type: str
    source_ref: str
    content_summary: str
    raw_pointer: str
    confidence: str = "medium"
    derived_by: str = ""
    reproducible: bool = True
    code_snippet: str = ""

    def to_dict(self) -> dict[str, Any]:
        """输出可序列化字典。"""

        return {
            "evidence_id": self.evidence_id,
            "source_type": self.source_type,
            "source_ref": self.source_ref,
            "content_summary": self.content_summary,
            "raw_pointer": self.raw_pointer,
            "confidence": self.confidence,
            "derived_by": self.derived_by,
            "reproducible": self.reproducible,
            "code_snippet": self.code_snippet,
        }


@dataclass(frozen=True)
class FindingRecord:
    """统一 finding 对象。

    这里同时保留了：

    - 结构化字段
    - 与旧报告生成器兼容的扁平字段
    """

    finding_id: str
    analyzer: str
    title: str
    severity: str
    category: str
    description: str
    recommendation: str
    affected_scope: AffectedScope
    confidence: str = "medium"
    priority: str = "review_recommended"
    reasoning_basis: list[str] = field(default_factory=list)
    validation_next_step: str = ""
    verification_status: str = "suspected"
    supporting_evidence: list[EvidenceRecord] = field(default_factory=list)
    tags: list[str] = field(default_factory=list)
    code_snippet: str = ""

    @classmethod
    def from_legacy_finding(cls, finding: Any) -> "FindingRecord":
        """把旧扫描器的 Finding 对象适配成统一结构。"""

        file_path = str(getattr(finding, "file", ""))
        line_num = int(getattr(finding, "line", 0) or 0)
        analyzer = str(getattr(finding, "analyzer", "unknown"))
        title = str(getattr(finding, "title", ""))
        severity_obj = getattr(finding, "severity", "")
        severity = getattr(severity_obj, "value", str(severity_obj))
        category = str(getattr(finding, "category", ""))
        description = str(getattr(finding, "description", ""))
        recommendation = str(getattr(finding, "recommendation", ""))
        code_snippet = str(getattr(finding, "code_snippet", ""))

        scope = AffectedScope(
            file_path=file_path,
            line_start=line_num,
            line_end=line_num,
        )

        evidence = EvidenceRecord(
            evidence_id=_stable_id("evidence", analyzer, file_path, line_num, title),
            source_type="source_code",
            source_ref=f"{file_path}:{line_num}",
            content_summary=f"来自分析器 {analyzer} 的源码证据。",
            raw_pointer=f"{file_path}:{line_num}",
            confidence="medium",
            derived_by=analyzer,
            reproducible=True,
            code_snippet=code_snippet,
        )

        tags = [analyzer]
        if category:
            tags.append(category)

        return cls(
            finding_id=_stable_id("finding", analyzer, file_path, line_num, title),
            analyzer=analyzer,
            title=title,
            severity=severity,
            category=category,
            description=description,
            recommendation=recommendation,
            affected_scope=scope,
            confidence="medium",
            priority="review_recommended",
            reasoning_basis=[],
            validation_next_step="",
            verification_status="suspected",
            supporting_evidence=[evidence],
            tags=tags,
            code_snippet=code_snippet,
        )

    def to_dict(self) -> dict[str, Any]:
        """输出兼容旧工具的 finding 字典。"""

        return {
            "finding_id": self.finding_id,
            "analyzer": self.analyzer,
            "title": self.title,
            "severity": self.severity,
            "category": self.category,
            "description": self.description,
            "recommendation": self.recommendation,
            "confidence": self.confidence,
            "priority": self.priority,
            "reasoning_basis": self.reasoning_basis,
            "validation_next_step": self.validation_next_step,
            # 下面两个字段保留给当前报告生成器直接使用。
            "file": self.affected_scope.file_path,
            "line": self.affected_scope.line_start,
            "code_snippet": self.code_snippet,
            "verification_status": self.verification_status,
            "affected_scope": self.affected_scope.to_dict(),
            "supporting_evidence": [
                evidence.to_dict() for evidence in self.supporting_evidence
            ],
            "tags": self.tags,
        }


@dataclass(frozen=True)
class ScanTarget:
    """扫描目标元数据。"""

    path: str
    kind: str
    analyzers_requested: list[str]
    minimum_severity: str

    @classmethod
    def from_target(
        cls,
        target: str,
        analyzer_names: list[str],
        minimum_severity: str,
    ) -> "ScanTarget":
        """根据传入目标推断目标类型。"""

        resolved = Path(target).resolve()
        if resolved.is_file():
            kind = "file"
        elif resolved.is_dir():
            kind = "directory"
        else:
            kind = "unknown"

        return cls(
            path=str(resolved),
            kind=kind,
            analyzers_requested=analyzer_names,
            minimum_severity=minimum_severity,
        )

    def to_dict(self) -> dict[str, Any]:
        """输出可序列化字典。"""

        return {
            "path": self.path,
            "kind": self.kind,
            "analyzers_requested": self.analyzers_requested,
            "minimum_severity": self.minimum_severity,
        }


@dataclass(frozen=True)
class ScanReport:
    """统一扫描输出对象。"""

    schema_version: str
    generated_at: str
    tool: dict[str, Any]
    target: ScanTarget
    stats: dict[str, Any]
    findings: list[FindingRecord]

    @classmethod
    def from_legacy_scan(
        cls,
        *,
        target: str,
        analyzer_names: list[str],
        minimum_severity: str,
        findings: list[Any],
        stats: dict[str, Any],
    ) -> "ScanReport":
        """把旧扫描结果整体适配成统一结构。"""

        normalized_findings = [
            FindingRecord.from_legacy_finding(finding)
            for finding in findings
        ]

        return cls(
            schema_version=SCAN_OUTPUT_SCHEMA_VERSION,
            generated_at=datetime.now(timezone.utc).isoformat(),
            tool={
                "name": "smart-contract-security-scanner",
                "version": "phase0",
                "phase": "0",
            },
            target=ScanTarget.from_target(
                target=target,
                analyzer_names=analyzer_names,
                minimum_severity=minimum_severity,
            ),
            stats=stats,
            findings=normalized_findings,
        )

    def to_dict(self) -> dict[str, Any]:
        """输出完整扫描结果字典。"""

        return {
            "schema_version": self.schema_version,
            "generated_at": self.generated_at,
            "tool": self.tool,
            "target": self.target.to_dict(),
            "stats": self.stats,
            "findings": [finding.to_dict() for finding in self.findings],
        }

    def to_json(self, *, indent: int = 2) -> str:
        """输出 JSON 字符串。"""

        return json.dumps(self.to_dict(), indent=indent, ensure_ascii=False)
