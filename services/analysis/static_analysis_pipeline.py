"""Phase 1 静态分析流水线。

这里不重复实现分析逻辑，而是把 Phase 0 的扫描器包装成审计服务可消费的接口。
"""

from __future__ import annotations

from tools.analyzers.base import Severity
from tools.scanner import build_scan_report, run_scan
from services.shared.models import ScanReport


def run_static_analysis(
    *,
    target: str,
    analyzer_names: list[str] | None = None,
    minimum_severity: Severity = Severity.INFO,
) -> ScanReport:
    """执行统一静态分析，并返回 ScanReport。"""

    findings, stats = run_scan(
        target=target,
        analyzer_names=analyzer_names,
        min_severity=minimum_severity,
    )
    return build_scan_report(
        target=target,
        analyzer_names=analyzer_names,
        min_severity=minimum_severity,
        findings=findings,
        stats=stats,
    )
