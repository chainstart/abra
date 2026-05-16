"""协议语义分析层。

当前实现是轻量级结构分析，不依赖外部编译器，
但比简单规则扫描更进一步，能为审计报告提供上下文。
"""

from __future__ import annotations

from pathlib import Path
import re

from services.analysis.ast_semantic_analyzer import parse_ast_semantics
from services.analysis.models import IngestionResult, SemanticSummary


CONTRACT_PATTERN = re.compile(r"\bcontract\s+([A-Za-z_]\w*)")
FUNCTION_PATTERN = re.compile(
    r"\bfunction\s+([A-Za-z_]\w*)\s*\([^)]*\)\s*(?:[^{;]*)\b(public|external|internal|private)?",
    re.MULTILINE,
)
STATE_VARIABLE_PATTERN = re.compile(
    r"^\s*(?:mapping\s*\(|[A-Za-z_]\w*(?:\[[^\]]*\])?)\s+(?:public|private|internal|external\s+)?([A-Za-z_]\w*)\s*(?:=|;)",
    re.MULTILINE,
)
EVENT_PATTERN = re.compile(r"\bevent\s+([A-Za-z_]\w*)\s*\(")
EXTERNAL_CALL_PATTERN = re.compile(
    r"\.call\s*\(|\.delegatecall\s*\(|\.staticcall\s*\(|\.transfer\s*\(|\.send\s*\(|\bI[A-Z]\w+\s*\([^)]*\)\s*\.\w+\s*\(",
)
SENSITIVE_FUNCTION_PATTERN = re.compile(
    r"^(set|update|change|modify|configure|add|remove|delete|grant|revoke|pause|unpause|withdraw|transfer|mint|burn|upgrade|migrate|liquidate|borrow|repay)\w*$",
    re.IGNORECASE,
)


def build_semantic_summary(ingestion: IngestionResult) -> SemanticSummary:
    """根据接入结果生成语义分析摘要。"""

    contract_names: list[str] = []
    function_names: list[str] = []
    public_or_external_count = 0
    sensitive_function_count = 0
    external_call_count = 0
    state_variable_count = 0
    event_count = 0

    for source_file in ingestion.source_files:
        text = Path(source_file.path).read_text(encoding="utf-8")
        contract_names.extend(match.group(1) for match in CONTRACT_PATTERN.finditer(text))

        function_matches = list(FUNCTION_PATTERN.finditer(text))
        for match in function_matches:
            function_name = match.group(1)
            visibility = (match.group(2) or "").strip()
            function_names.append(function_name)
            if visibility in {"public", "external"}:
                public_or_external_count += 1
            if SENSITIVE_FUNCTION_PATTERN.match(function_name):
                sensitive_function_count += 1

        external_call_count += len(EXTERNAL_CALL_PATTERN.findall(text))
        state_variable_count += len(STATE_VARIABLE_PATTERN.findall(text))
        event_count += len(EVENT_PATTERN.findall(text))

    notable_patterns: list[str] = []
    if public_or_external_count >= 10:
        notable_patterns.append("公开接口较多")
    if sensitive_function_count > 0:
        notable_patterns.append("存在敏感函数")
    if external_call_count > 0:
        notable_patterns.append("存在外部调用")
    if event_count == 0:
        notable_patterns.append("几乎没有事件定义")

    ast_summary = parse_ast_semantics(
        [source_file.path for source_file in ingestion.source_files]
    ).to_dict()

    return SemanticSummary(
        contract_count=len(contract_names),
        function_count=len(function_names),
        public_or_external_function_count=public_or_external_count,
        sensitive_function_count=sensitive_function_count,
        external_call_count=external_call_count,
        state_variable_count=state_variable_count,
        event_count=event_count,
        function_names=function_names[:50],
        notable_patterns=notable_patterns,
        ast_summary=ast_summary,
    )
