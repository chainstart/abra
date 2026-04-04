"""深分析服务。

把 AST 深语义分析包装成独立服务，便于：

- 单独调试
- API 暴露
- 页面展示
- 后续和审计流程并行复用
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from services.analysis.ast_semantic_analyzer import parse_ast_semantics
from services.analysis.contract_ingestion import ingest_contract_target


@dataclass(frozen=True)
class DeepAnalysisResult:
    """深分析结果。"""

    target: str
    target_kind: str
    ast_summary: dict[str, Any]
    risk_hints: list[str]

    def to_dict(self) -> dict[str, Any]:
        """输出可序列化字典。"""

        return {
            "target": self.target,
            "target_kind": self.target_kind,
            "ast_summary": self.ast_summary,
            "risk_hints": self.risk_hints,
        }


def _build_risk_hints(ast_summary: dict[str, Any]) -> list[str]:
    """根据深分析结构构造风险提示。"""

    hints: list[str] = []
    if ast_summary.get("write_after_external_functions"):
        hints.append("存在外部调用后再写状态的函数，应优先检查重入与时序风险。")
    if len(ast_summary.get("cross_contract_call_edges", [])) >= 3:
        hints.append("跨合约调用边较多，建议人工检查依赖接口与外部假设。")
    if len(ast_summary.get("state_conflicts", [])) >= 5:
        hints.append("函数间共享状态冲突较多，建议重点检查跨函数影响。")
    if len(ast_summary.get("public_entrypoints", [])) >= 10:
        hints.append("公开入口较多，建议检查攻击面和角色边界。")
    if not hints:
        hints.append("当前未发现特别突出的深语义风险提示，但仍需结合业务逻辑复核。")
    return hints


def run_deep_analysis(target: str) -> DeepAnalysisResult:
    """运行独立深分析。"""

    ingestion = ingest_contract_target(target)
    ast_summary = parse_ast_semantics(
        [source_file.path for source_file in ingestion.source_files]
    ).to_dict()
    return DeepAnalysisResult(
        target=ingestion.target_path,
        target_kind=ingestion.target_kind,
        ast_summary=ast_summary,
        risk_hints=_build_risk_hints(ast_summary),
    )
