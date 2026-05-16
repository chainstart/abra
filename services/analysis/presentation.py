"""审计结果展示适配层。

目标：

- 把偏工程结构的原始 finding 转成更适合人阅读的结果
- 给网页和报告提供统一的中文展示数据
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from services.analysis.models import AuditRunResult
from services.analysis.finding_enricher import normalize_finding_family
from services.shared.models import FindingRecord


SEVERITY_DISPLAY = {
    "Critical": "严重",
    "High": "高危",
    "Medium": "中危",
    "Low": "低危",
    "Informational": "提示",
}

PRIORITY_DISPLAY = {
    "high_priority": "优先处理",
    "review_recommended": "建议复核",
    "candidate": "候选问题",
}

CONFIDENCE_DISPLAY = {
    "high": "高置信",
    "medium": "中置信",
    "low": "低置信",
}

CATEGORY_DISPLAY = {
    "SC-01: Reentrancy": "重入风险",
    "SC-02: Access Control": "访问控制",
    "SC-03: Oracle Manipulation": "预言机风险",
    "SC-04: Flash Loan Attacks": "闪电贷攻击面",
    "SC-05: Input Validation": "输入校验",
    "SC-06: Arithmetic": "算术与精度",
    "SC-07: Logic Errors": "业务逻辑",
    "SC-08: Upgrade Safety": "升级安全",
    "SC-09: Governance": "治理风险",
    "SC-10: External Calls": "外部调用",
}

SEVERITY_ORDER = {
    "Critical": 0,
    "High": 1,
    "Medium": 2,
    "Low": 3,
    "Informational": 4,
}

FAMILY_DISPLAY = {
    "cross_function_reentrancy": "跨函数重入风险簇",
    "read_only_reentrancy": "只读重入风险簇",
    "cei_violation": "外部交互顺序风险簇",
    "missing_nonreentrant": "缺少重入保护风险簇",
    "potential_division_by_zero": "潜在除零风险簇",
    "division_before_multiplication": "先除后乘精度风险簇",
    "unsafe_downcast": "不安全类型缩窄风险簇",
    "unsigned_to_signed_conversion": "无符号到有符号转换风险簇",
    "hardcoded_decimals": "硬编码精度假设风险簇",
    "unprotected_sensitive_function": "敏感函数权限边界风险簇",
    "missing_initializer_guard": "初始化保护缺失风险簇",
}


def _display_path(path: str, line: int) -> str:
    """把绝对路径转成更适合展示的形式。"""

    parts = Path(path).parts
    if len(parts) >= 4:
        compact = "/".join(parts[-4:])
    else:
        compact = path
    return f"{compact}:{line}"


def _finding_title_zh(finding: FindingRecord) -> str:
    """生成中文 finding 标题。"""

    title = finding.title
    lower = title.lower()
    if "unprotected sensitive function" in lower:
        func_name = title.split("`")[1] if "`" in title else "未知函数"
        return f"敏感函数 `{func_name}` 缺少访问控制"
    if "initializer" in lower:
        return "初始化函数缺少一次性保护"
    if "cei violation" in lower:
        return "外部交互顺序可能违反 CEI 原则"
    if "nonreentrant" in lower:
        return "存在外部调用但缺少重入保护"
    return title


def _finding_summary_zh(finding: FindingRecord) -> str:
    """生成中文摘要。"""

    analyzer = finding.analyzer
    title = finding.title.lower()
    if analyzer == "access-control":
        if "unprotected sensitive function" in title:
            return "这个函数带有资金、权限或配置语义，但当前没有明确的调用者限制。"
        return "该问题与权限边界或角色控制不足有关。"
    if analyzer == "reentrancy":
        return "这个问题和外部调用时序、回调路径或状态更新顺序有关。"
    if analyzer == "oracle-dependency":
        return "这个问题和价格来源、预言机有效性或价格尺度假设有关。"
    if analyzer == "arithmetic":
        return "这个问题和精度、舍入、除法顺序或边界条件有关。"
    if analyzer == "upgrade-safety":
        return "这个问题和初始化流程、升级路径或代理安全有关。"
    return finding.description


def _impact_zh(finding: FindingRecord) -> str:
    """生成影响说明。"""

    if finding.severity in {"Critical", "High"}:
        return "如果问题成立，可能直接影响上线安全性，建议在修复或完成验证前不要忽视。"
    if finding.severity == "Medium":
        return "问题短期内未必直接导致被利用，但可能在复杂调用或异常条件下放大风险。"
    return "当前更偏向提示或优化项，但仍建议人工确认。"


def _recommendation_zh(finding: FindingRecord) -> str:
    """生成中文修复建议。"""

    title = finding.title.lower()
    analyzer = finding.analyzer
    if analyzer == "access-control" and "unprotected sensitive function" in title:
        return "为该函数增加明确的权限边界，例如 `onlyOwner`、`onlyRole(...)`，或显式校验 `msg.sender`。"
    if analyzer == "reentrancy":
        return "优先检查是否需要把状态更新提前，并结合 `nonReentrant` 或更稳妥的交互顺序重构。"
    if analyzer == "oracle-dependency":
        return "明确价格源假设，补充有效性校验，并尽量减少对单一价格输入的盲目信任。"
    if analyzer == "arithmetic":
        return "重新检查精度路径，避免除法顺序、舍入方向或硬编码精度假设引入偏差。"
    if analyzer == "upgrade-safety":
        return "检查初始化、升级入口和存储布局，避免部署后出现重复初始化或升级冲突。"
    return finding.recommendation


def _evidence_preview(finding: FindingRecord) -> str:
    """返回可读证据摘要。"""

    if not finding.supporting_evidence:
        return "暂无证据摘要。"
    evidence = finding.supporting_evidence[0]
    return evidence.content_summary


def _action_items(audit_result: AuditRunResult) -> list[str]:
    """生成结果页行动项。"""

    items: list[str] = []
    summary = audit_result.audit_summary
    ast_summary = audit_result.semantic_summary.ast_summary
    if summary.critical_count or summary.high_count:
        items.append("优先处理所有严重和高危问题，再考虑上线或对外开放。")
    if ast_summary.get("write_after_external_functions"):
        items.append("对“外部调用后写状态”的函数做定向重入验证。")
    if ast_summary.get("cross_contract_call_edges"):
        items.append("人工复核主要跨合约调用边，确认依赖接口和异常路径。")
    if audit_result.related_incidents:
        items.append("把当前问题与相似历史攻击对照，检查是否满足相同利用前提。")
    if not items:
        items.append("当前未见明显高强度信号，但仍建议人工抽查关键入口函数。")
    return items


def build_audit_presentation(audit_result: AuditRunResult) -> dict[str, Any]:
    """构建网页和报告复用的展示层结果。"""

    summary = audit_result.audit_summary
    protocol = audit_result.classification.protocol_name
    protocol_type = audit_result.classification.protocol_type

    if summary.critical_count > 0:
        conclusion = f"{protocol} 属于 `{protocol_type}` 类型协议，当前存在严重风险，不建议直接上线。"
    elif summary.high_count > 0:
        conclusion = f"{protocol} 属于 `{protocol_type}` 类型协议，当前存在高危问题，建议先修复再继续。"
    elif summary.medium_count > 0:
        conclusion = f"{protocol} 属于 `{protocol_type}` 类型协议，当前无严重/高危问题，但仍有中风险需要人工复核。"
    else:
        conclusion = f"{protocol} 属于 `{protocol_type}` 类型协议，当前未发现明显高优先级问题。"

    risk_score = (
        summary.critical_count * 10
        + summary.high_count * 6
        + summary.medium_count * 3
        + summary.low_count
    )
    if risk_score >= 30:
        temperature = "高温"
    elif risk_score >= 12:
        temperature = "中温"
    else:
        temperature = "低温"

    def to_card(finding: FindingRecord) -> dict[str, Any]:
        return {
            "title_zh": _finding_title_zh(finding),
            "severity_zh": SEVERITY_DISPLAY.get(finding.severity, finding.severity),
            "severity": finding.severity,
            "priority": finding.priority,
            "priority_zh": PRIORITY_DISPLAY.get(finding.priority, finding.priority),
            "confidence": finding.confidence,
            "confidence_zh": CONFIDENCE_DISPLAY.get(finding.confidence, finding.confidence),
            "category_zh": CATEGORY_DISPLAY.get(finding.category, finding.category or "未分类"),
            "location": _display_path(
                finding.affected_scope.file_path,
                finding.affected_scope.line_start,
            ),
            "summary_zh": _finding_summary_zh(finding),
            "impact_zh": _impact_zh(finding),
            "recommendation_zh": _recommendation_zh(finding),
            "evidence_preview": _evidence_preview(finding),
            "reasoning_basis": finding.reasoning_basis,
            "validation_next_step": finding.validation_next_step,
            "code_snippet": finding.code_snippet,
        }

    top_finding_cards = []
    for finding in summary.top_findings:
        top_finding_cards.append(
            to_card(finding)
        )

    all_finding_cards = []
    for finding in audit_result.scan_report.findings:
        all_finding_cards.append(
            {
                **to_card(finding),
                "analyzer": finding.analyzer,
            }
        )

    family_groups: dict[str, dict[str, Any]] = {}
    for card, finding in zip(all_finding_cards, audit_result.scan_report.findings):
        family = normalize_finding_family(finding)
        if family not in family_groups:
            family_groups[family] = {
                "family": family,
                "title_zh": FAMILY_DISPLAY.get(family, card["title_zh"]),
                "severity": card["severity"],
                "severity_zh": card["severity_zh"],
                "priority": card["priority"],
                "priority_zh": card["priority_zh"],
                "confidence": card["confidence"],
                "confidence_zh": card["confidence_zh"],
                "category_zh": card["category_zh"],
                "count": 0,
                "sample_locations": [],
                "sample_summaries": [],
            }
        family_groups[family]["count"] += 1
        if len(family_groups[family]["sample_locations"]) < 5:
            family_groups[family]["sample_locations"].append(card["location"])
        if len(family_groups[family]["sample_summaries"]) < 3:
            family_groups[family]["sample_summaries"].append(card["summary_zh"])

    grouped_findings: dict[str, list[dict[str, Any]]] = {
        "Critical": [],
        "High": [],
        "Medium": [],
        "Low": [],
        "Informational": [],
    }
    for card in all_finding_cards:
        grouped_findings.setdefault(card["severity"], []).append(card)

    grouped_families: dict[str, list[dict[str, Any]]] = {
        "Critical": [],
        "High": [],
        "Medium": [],
        "Low": [],
        "Informational": [],
    }
    for item in family_groups.values():
        grouped_families.setdefault(item["severity"], []).append(item)
    for severity, items in grouped_families.items():
        items.sort(
            key=lambda item: (
                SEVERITY_ORDER.get(item["severity"], 9),
                0 if item["priority"] == "high_priority" else 1 if item["priority"] == "review_recommended" else 2,
                0 if item["confidence"] == "high" else 1 if item["confidence"] == "medium" else 2,
                -item["count"],
                item["title_zh"],
            )
        )

    top_groups: list[dict[str, Any]] = []
    for severity in ["Critical", "High", "Medium", "Low", "Informational"]:
        top_groups.extend(grouped_families.get(severity, [])[:3])
        if len(top_groups) >= 8:
            break

    category_counts: dict[str, int] = {}
    analyzer_counts: dict[str, int] = {}
    for finding in audit_result.scan_report.findings:
        category_name = CATEGORY_DISPLAY.get(finding.category, finding.category or "未分类")
        category_counts[category_name] = category_counts.get(category_name, 0) + 1
        analyzer_counts[finding.analyzer] = analyzer_counts.get(finding.analyzer, 0) + 1

    related_incidents = []
    for match in audit_result.related_incidents:
        if match.score < 3:
            continue
        related_incidents.append(
            {
                "title": match.incident.title,
                "protocol_name": match.incident.protocol_name,
                "year": match.incident.year,
                "score": match.score,
                "summary": match.incident.summary,
                "reasons": match.reasons,
            }
        )

    return {
        "conclusion": conclusion,
        "risk_temperature": temperature,
        "protocol_name": protocol,
        "protocol_type": protocol_type,
        "metrics": {
            "total_findings": summary.total_findings,
            "critical_count": summary.critical_count,
            "high_count": summary.high_count,
            "medium_count": summary.medium_count,
            "low_count": summary.low_count,
            "informational_count": summary.informational_count,
            "public_entrypoints": len(audit_result.semantic_summary.ast_summary.get("public_entrypoints", [])),
            "cross_contract_edges": len(audit_result.semantic_summary.ast_summary.get("cross_contract_call_edges", [])),
        },
        "semantic_highlights": {
            "public_entrypoints": audit_result.semantic_summary.ast_summary.get("public_entrypoints", [])[:12],
            "write_after_external_functions": audit_result.semantic_summary.ast_summary.get("write_after_external_functions", [])[:10],
            "cross_contract_call_edges": audit_result.semantic_summary.ast_summary.get("cross_contract_call_edges", [])[:10],
            "state_conflicts": audit_result.semantic_summary.ast_summary.get("state_conflicts", [])[:10],
        },
        "top_findings": top_finding_cards,
        "top_groups": top_groups[:8],
        "all_findings": all_finding_cards,
        "grouped_findings": grouped_findings,
        "grouped_families": grouped_families,
        "category_counts": dict(sorted(category_counts.items(), key=lambda item: (-item[1], item[0]))),
        "analyzer_counts": dict(sorted(analyzer_counts.items(), key=lambda item: (-item[1], item[0]))),
        "related_incidents": related_incidents,
        "action_items": _action_items(audit_result),
    }
