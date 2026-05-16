"""finding 质量增强层。

目标：

- 给原始 finding 增加 confidence / priority
- 解释为什么这条 finding 值得保留
- 告诉用户下一步应该怎么验证

这一步不直接替换扫描器，而是在扫描器之后做一层“审计筛选”。
"""

from __future__ import annotations

from dataclasses import replace
import re

from services.shared.models import FindingRecord


SEVERITY_WEIGHT = {
    "Critical": 4,
    "High": 3,
    "Medium": 2,
    "Low": 1,
    "Informational": 0,
}


def _containing_function(ast_summary: dict, file_path: str, line: int) -> dict | None:
    """找到某一行所在的函数语义。"""

    for function in ast_summary.get("functions", []):
        if function.get("line_start", 0) <= line <= function.get("line_end", 0):
            return function
    return None


def _incident_overlap(finding: FindingRecord, related_incidents: list) -> list[str]:
    """找和历史案例的重合点。"""

    reasons: list[str] = []
    for match in related_incidents:
        incident = match.incident
        if finding.category and finding.category in incident.affected_categories:
            reasons.append(f"历史案例 `{incident.title}` 出现过同类风险")
            break
    return reasons


def _base_reasoning(finding: FindingRecord, function_info: dict | None) -> list[str]:
    """生成基础 reasoning basis。"""

    reasons: list[str] = []
    if function_info:
        visibility = function_info.get("visibility")
        if visibility in {"public", "external"}:
            reasons.append("问题位于公开入口函数，攻击面更直接")
        if function_info.get("external_call_then_state_write"):
            reasons.append("函数存在外部调用后再写状态的高风险顺序")
        if function_info.get("cross_contract_call_edges"):
            reasons.append("函数所在上下文存在跨合约调用")
        if function_info.get("branch_count", 0) >= 2:
            reasons.append("函数控制流较复杂，人工复核价值更高")
    if finding.supporting_evidence:
        reasons.append("已有源码级证据支撑")
    return reasons


def _cross_function_pair_names(title: str) -> tuple[str, str] | tuple[None, None]:
    """从 cross-function title 里提取函数对。"""

    match = re.search(r"`([^`]+)` and `([^`]+)`", title)
    if not match:
        return None, None
    return match.group(1), match.group(2)


def _confidence_and_priority(
    finding: FindingRecord,
    function_info: dict | None,
    related_incident_reasons: list[str],
) -> tuple[str, str]:
    """计算 confidence 和 priority。"""

    score = SEVERITY_WEIGHT.get(finding.severity, 0)

    if function_info:
        if function_info.get("visibility") in {"public", "external"}:
            score += 1
        if function_info.get("external_call_then_state_write"):
            score += 2
        if function_info.get("external_call_count", 0) > 0:
            score += 1

    if related_incident_reasons:
        score += 1

    title_lower = finding.title.lower()
    func_a, func_b = _cross_function_pair_names(finding.title)
    if finding.analyzer == "arithmetic" and "division before multiplication" in title_lower:
        score -= 1
    if finding.analyzer == "arithmetic" and "potential division by zero" in title_lower:
        if any(token in title_lower for token in ["a_precision", "precision", "fee_denominator", "week", "ray"]):
            score -= 2
        else:
            score -= 1
    if finding.analyzer == "arithmetic" and "unsafe downcast" in title_lower:
        score -= 1
    if finding.analyzer == "reentrancy" and "read-only reentrancy risk" in title_lower:
        score -= 1
    if finding.analyzer == "reentrancy" and "potential cross-function reentrancy" in title_lower:
        if func_a and (func_a.startswith("get_") or func_a in {"balanceOf", "A", "A_precise"}):
            score -= 2
        if func_b and (func_b.startswith("get_") or func_b in {"balanceOf", "A", "A_precise"}):
            score -= 2
    if finding.analyzer == "access-control" and "unprotected sensitive function" in title_lower:
        score += 1
    if finding.analyzer == "reentrancy" and "cei violation" in title_lower:
        score += 2

    if score >= 6:
        confidence = "high"
        priority = "high_priority"
    elif score >= 3:
        confidence = "medium"
        priority = "review_recommended"
    else:
        confidence = "low"
        priority = "candidate"

    return confidence, priority


def _validation_next_step(finding: FindingRecord, function_info: dict | None) -> str:
    """给出下一步验证建议。"""

    title_lower = finding.title.lower()
    if finding.analyzer == "reentrancy":
        return "对该函数构造重入或时序验证，优先做 Foundry 单元测试或 fork 验证。"
    if finding.analyzer == "access-control":
        return "核对调用者边界，确认该函数是否应仅限 owner/role 调用。必要时补一条未授权调用测试。"
    if finding.analyzer == "oracle-dependency":
        return "检查价格源初始化、有效性和异常路径，必要时构造错误价格输入测试。"
    if finding.analyzer == "arithmetic":
        if "division before multiplication" in title_lower:
            return "确认该表达式是否属于有意的舍入逻辑；如果不是，改成乘后除并补边界测试。"
        return "补充边界值和极端输入测试，确认是否存在精度或溢出偏差。"
    if function_info and function_info.get("external_call_then_state_write"):
        return "优先验证外部调用后的状态写入路径是否可被重入或回调影响。"
    return "建议人工复核并结合业务逻辑判断是否需要动态验证。"


def normalize_finding_family(finding: FindingRecord) -> str:
    """把 finding 归一化到“问题家族”。

    目的：

    - 页面里聚合同类问题
    - top findings 排名时避免被同类重复刷屏
    """

    title = finding.title.lower()
    if "potential cross-function reentrancy" in title:
        return "cross_function_reentrancy"
    if "read-only reentrancy risk" in title:
        return "read_only_reentrancy"
    if "cei violation" in title:
        return "cei_violation"
    if "missing `nonreentrant`" in title:
        return "missing_nonreentrant"
    if "potential division by zero" in title:
        return "potential_division_by_zero"
    if "division before multiplication" in title:
        return "division_before_multiplication"
    if "unsafe downcast" in title:
        return "unsafe_downcast"
    if "unsigned to signed integer conversion" in title:
        return "unsigned_to_signed_conversion"
    if "hardcoded 18 decimals assumption" in title or "hardcoded decimal assumption" in title:
        return "hardcoded_decimals"
    if "unprotected sensitive function" in title:
        return "unprotected_sensitive_function"
    if "initialization function without `initializer` modifier" in title:
        return "missing_initializer_guard"
    return f"{finding.analyzer}:{finding.category}:{finding.title}"


def enrich_findings(
    findings: list[FindingRecord],
    *,
    ast_summary: dict,
    related_incidents: list,
) -> list[FindingRecord]:
    """增强 finding 质量字段。"""

    enriched: list[FindingRecord] = []
    for finding in findings:
        function_info = _containing_function(
            ast_summary,
            finding.affected_scope.file_path,
            finding.affected_scope.line_start,
        )
        related_reasons = _incident_overlap(finding, related_incidents)
        base_reasons = _base_reasoning(finding, function_info)
        confidence, priority = _confidence_and_priority(
            finding,
            function_info,
            related_reasons,
        )
        reasoning_basis = base_reasons + related_reasons
        validation_next_step = _validation_next_step(finding, function_info)

        enriched.append(
            replace(
                finding,
                confidence=confidence,
                priority=priority,
                reasoning_basis=reasoning_basis,
                validation_next_step=validation_next_step,
            )
        )
    return enriched
