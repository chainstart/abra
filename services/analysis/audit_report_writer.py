"""审计报告写作器。

这一版不再只是把结构化结果逐字段打印出来，而是尽量组织成更接近真实审计交付物的形式：

- 先给一句结论
- 再给风险概览
- 再给攻击面与深分析上下文
- 然后列重点发现
- 最后给修复优先级和边界说明
"""

from __future__ import annotations

from services.analysis.models import AuditRunResult
from services.shared.models import FindingRecord


SEVERITY_RANK = {
    "Critical": 4,
    "High": 3,
    "Medium": 2,
    "Low": 1,
    "Informational": 0,
}


def _severity_label(severity: str) -> str:
    """给严重性加中文说明。"""

    mapping = {
        "Critical": "Critical / 需要立即阻断",
        "High": "High / 上线前必须处理",
        "Medium": "Medium / 应尽快修复或验证",
        "Low": "Low / 可排期优化",
        "Informational": "Informational / 信息提示",
    }
    return mapping.get(severity, severity)


def _protocol_conclusion(audit_result: AuditRunResult) -> str:
    """生成一句话审计结论。"""

    summary = audit_result.audit_summary
    protocol = audit_result.classification.protocol_name
    protocol_type = audit_result.classification.protocol_type

    if summary.critical_count > 0:
        return f"{protocol} 被识别为 `{protocol_type}` 类型协议，当前存在 Critical 风险，不建议直接上线。"
    if summary.high_count > 0:
        return f"{protocol} 被识别为 `{protocol_type}` 类型协议，当前存在 High 风险，建议先完成修复和验证。"
    if summary.medium_count > 0:
        return f"{protocol} 被识别为 `{protocol_type}` 类型协议，当前没有 Critical/High 风险，但仍有若干中风险需要人工复核。"
    if summary.total_findings == 0:
        return f"{protocol} 被识别为 `{protocol_type}` 类型协议，当前未发现明显风险信号，但仍建议结合业务逻辑做人工审查。"
    return f"{protocol} 被识别为 `{protocol_type}` 类型协议，当前主要是低风险和提示项。"


def _risk_temperature(audit_result: AuditRunResult) -> str:
    """生成风险温度。"""

    summary = audit_result.audit_summary
    score = (
        summary.critical_count * 10
        + summary.high_count * 6
        + summary.medium_count * 3
        + summary.low_count
    )
    if score >= 30:
        return "高温"
    if score >= 12:
        return "中温"
    return "低温"


def _finding_interpretation(finding: FindingRecord) -> str:
    """给 finding 生成更自然的中文解释。"""

    title = finding.title.lower()
    analyzer = finding.analyzer
    if analyzer == "access-control":
        if "unprotected sensitive function" in title:
            return "检测到一个具备敏感操作语义的公开函数，但没有看到明确的权限边界或调用者校验，存在未授权调用风险。"
        if "initializer" in title:
            return "初始化逻辑可能缺少一次性保护，部署后可能被重复调用。"
        return "该问题和权限边界、角色控制或特权操作保护不足有关。"
    if analyzer == "reentrancy":
        if "cei violation" in title:
            return "检测到外部交互与状态更新顺序可能不符合 CEI 原则，存在重入时序风险。"
        if "nonreentrant" in title:
            return "检测到存在外部调用但缺少显式重入保护。"
        return "该问题与外部调用、回调路径或重入时序有关。"
    if analyzer == "oracle-dependency":
        return "该问题与价格源、预言机有效性或价格尺度假设有关。"
    if analyzer == "arithmetic":
        return "该问题与精度、舍入、除法顺序或算术边界条件有关。"
    if analyzer == "upgrade-safety":
        return "该问题与升级路径、初始化流程或代理存储布局有关。"
    return "该问题需要结合源码和业务语义做进一步人工复核。"


def _render_finding_table(audit_result: AuditRunResult) -> str:
    """渲染重点发现摘要表。"""

    findings = audit_result.audit_summary.top_findings
    if not findings:
        return "暂无重点发现。"

    lines = [
        "| # | 严重性 | 标题 | 位置 |",
        "|---|--------|------|------|",
    ]
    for index, finding in enumerate(findings, start=1):
        location = f"{finding.affected_scope.file_path}:{finding.affected_scope.line_start}"
        lines.append(
            f"| {index} | {finding.severity} | {finding.title} | `{location}` |"
        )
    return "\n".join(lines)


def _render_top_findings_section(audit_result: AuditRunResult) -> str:
    """渲染重点发现部分。"""

    findings = audit_result.audit_summary.top_findings
    if not findings:
        return "暂无重点发现。"

    lines: list[str] = []
    for index, finding in enumerate(findings, start=1):
        lines.append(f"### {index}. {finding.title}")
        lines.append(f"- 严重性: {_severity_label(finding.severity)}")
        lines.append(f"- 分析器: {finding.analyzer}")
        lines.append(f"- 类别: {finding.category or '未分类'}")
        lines.append(
            f"- 位置: `{finding.affected_scope.file_path}:{finding.affected_scope.line_start}`"
        )
        lines.append(f"- 中文解释: {_finding_interpretation(finding)}")
        lines.append(f"- 原始描述: {finding.description}")
        lines.append(f"- 修复建议: {finding.recommendation}")
        lines.append(f"- 验证状态: {finding.verification_status}")
        if finding.supporting_evidence:
            evidence = finding.supporting_evidence[0]
            lines.append(f"- 证据摘要: {evidence.content_summary}")
            if evidence.code_snippet:
                lines.append("")
                lines.append("```solidity")
                lines.append(evidence.code_snippet)
                lines.append("```")
        lines.append("")
    return "\n".join(lines).rstrip()


def _render_related_incidents_section(audit_result: AuditRunResult) -> str:
    """渲染相似历史案例部分。"""

    if not audit_result.related_incidents:
        return "暂无匹配到的历史案例。"

    lines: list[str] = []
    for index, match in enumerate(audit_result.related_incidents, start=1):
        incident = match.incident
        lines.append(f"### {index}. {incident.title}")
        lines.append(f"- 协议: {incident.protocol_name}")
        lines.append(f"- 类型: {incident.protocol_type}")
        lines.append(f"- 年份: {incident.year}")
        lines.append(f"- 相关性分数: {match.score}")
        lines.append(f"- 根因: {incident.root_cause}")
        lines.append(f"- 摘要: {incident.summary}")
        if match.reasons:
            lines.append(f"- 匹配理由: {'；'.join(match.reasons)}")
        if incident.source_reports:
            lines.append(f"- 参考来源: {', '.join(incident.source_reports)}")
        lines.append("")
    return "\n".join(lines).rstrip()


def _render_attack_surface(audit_result: AuditRunResult) -> str:
    """渲染攻击面摘要。"""

    ast_summary = audit_result.semantic_summary.ast_summary
    public_entrypoints = ast_summary.get("public_entrypoints", [])[:12]
    write_after_external = ast_summary.get("write_after_external_functions", [])[:8]
    cross_edges = ast_summary.get("cross_contract_call_edges", [])[:8]
    state_conflicts = ast_summary.get("state_conflicts", [])[:8]

    lines = ["### 公开入口", ""]
    if public_entrypoints:
        lines.extend(f"- {item}" for item in public_entrypoints)
    else:
        lines.append("- 暂无")

    lines.extend(["", "### 外部交互后再写状态", ""])
    if write_after_external:
        lines.extend(f"- {item}" for item in write_after_external)
    else:
        lines.append("- 暂无")

    lines.extend(["", "### 主要跨合约调用边", ""])

    if cross_edges:
        for edge in cross_edges:
            lines.append(
                f"- {edge['from_contract']}.{edge['from_function']} -> {edge['target_contract']}.{edge['target_function']} (line {edge['line']})"
            )
    else:
        lines.append("- 暂无")

    lines.extend(["", "### 状态冲突热点", ""])
    if state_conflicts:
        for conflict in state_conflicts:
            lines.append(
                f"- {conflict['state_variable']}: {conflict['from_function']} <-> {conflict['to_function']} ({conflict['conflict_type']})"
            )
    else:
        lines.append("- 暂无")

    return "\n".join(lines)


def _render_action_items(audit_result: AuditRunResult) -> str:
    """渲染行动项。"""

    summary = audit_result.audit_summary
    ast_summary = audit_result.semantic_summary.ast_summary
    items: list[str] = []

    if summary.critical_count or summary.high_count:
        items.append("先处理 Critical / High 发现，再考虑上线。")
    if ast_summary.get("write_after_external_functions"):
        items.append("对“外部调用后写状态”函数补做动态验证或重入保护。")
    if ast_summary.get("cross_contract_call_edges"):
        items.append("逐条人工复核跨合约调用边，确认依赖接口和异常路径。")
    if audit_result.related_incidents:
        items.append("把当前结果和相似历史案例对照，检查是否存在相同攻击前提。")
    if not items:
        items.append("当前未见高强度风险信号，但仍建议人工抽查关键函数。")

    return "\n".join(f"- {item}" for item in items)


def render_audit_report(audit_result: AuditRunResult) -> str:
    """生成更像交付物的结构化审计报告。"""

    classification = audit_result.classification
    ingestion = audit_result.ingestion
    semantic_summary = audit_result.semantic_summary
    summary = audit_result.audit_summary
    evidence_summary = audit_result.evidence_summary
    scan_report = audit_result.scan_report

    rationale_lines = "\n".join(f"- {line}" for line in classification.rationale) or "- 暂无"
    signal_lines = "\n".join(f"- {line}" for line in classification.dominant_signals) or "- 暂无"

    lines = [
        f"# {classification.protocol_name} 审计报告",
        "",
        "## 执行摘要",
        "",
        _protocol_conclusion(audit_result),
        "",
        f"- 风险温度: {_risk_temperature(audit_result)}",
        f"- 协议类型: {classification.protocol_type}",
        f"- 置信度: {classification.confidence}",
        f"- 扫描总发现数: {summary.total_findings}",
        f"- High / Critical: {summary.high_count + summary.critical_count}",
        "",
        "## 1. 审计对象概览",
        "",
        f"- 目标路径: `{ingestion.target_path}`",
        f"- 目标类型: {ingestion.target_kind}",
        f"- Solidity 文件数: {ingestion.solidity_file_count}",
        f"- 总代码行数: {ingestion.total_line_count}",
        f"- 输出 Schema: `{scan_report.schema_version}`",
        "",
        "## 2. 协议判断",
        "",
        f"- 协议名称: {classification.protocol_name}",
        f"- 协议类型: {classification.protocol_type}",
        "",
        "### 分类理由",
        "",
        rationale_lines,
        "",
        "### 主要信号",
        "",
        signal_lines,
        "",
        "## 3. 风险分布",
        "",
        f"- Critical: {summary.critical_count}",
        f"- High: {summary.high_count}",
        f"- Medium: {summary.medium_count}",
        f"- Low: {summary.low_count}",
        f"- Informational: {summary.informational_count}",
        "",
        "## 4. 攻击面与程序结构",
        "",
        f"- 合约数量: {semantic_summary.contract_count}",
        f"- 函数数量: {semantic_summary.function_count}",
        f"- public/external 函数数量: {semantic_summary.public_or_external_function_count}",
        f"- 敏感函数数量: {semantic_summary.sensitive_function_count}",
        f"- 外部调用数量: {semantic_summary.external_call_count}",
        f"- 状态变量数量: {semantic_summary.state_variable_count}",
        f"- 事件数量: {semantic_summary.event_count}",
        f"- 语义提示: {', '.join(semantic_summary.notable_patterns) if semantic_summary.notable_patterns else '暂无明显模式'}",
        "",
        _render_attack_surface(audit_result),
        "",
        "## 5. 证据概览",
        "",
        f"- 证据总数: {evidence_summary.evidence_count}",
        f"- 可复现证据数: {evidence_summary.reproducible_count}",
        f"- 证据来源分布: `{evidence_summary.source_type_breakdown}`",
        f"- 分析器分布: `{evidence_summary.analyzer_breakdown}`",
        "",
        "## 6. 重点发现摘要表",
        "",
        _render_finding_table(audit_result),
        "",
        "## 7. 重点发现详情",
        "",
        _render_top_findings_section(audit_result),
        "",
        "## 8. 相似历史案例",
        "",
        _render_related_incidents_section(audit_result),
        "",
        "## 9. 优先行动项",
        "",
        _render_action_items(audit_result),
        "",
        "## 10. 当前结论边界",
        "",
        "- 当前报告主要基于静态分析、AST 深分析和本地案例库。",
        "- 报告中的 `verification_status` 默认仍然是 `suspected`，表示尚未对每个发现逐一做动态验证。",
        "- 如果目标协议准备上线，仍建议对高风险路径做 Foundry / fork / PoC 级验证。",
    ]
    return "\n".join(lines).rstrip() + "\n"
