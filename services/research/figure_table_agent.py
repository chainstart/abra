"""生成论文图表规格。"""

from __future__ import annotations

from services.analysis.models import AuditRunResult
from services.research.models import (
    ClaimEvidenceMatrix,
    FigureSpec,
    IncidentEvidencePackage,
    ManuscriptPackage,
    TableSpec,
)


def build_figure_and_table_specs(
    *,
    package: ManuscriptPackage,
    audit_result: AuditRunResult,
    claim_evidence_matrix: ClaimEvidenceMatrix | None,
    incident_evidence_packages: list[IncidentEvidencePackage] | None,
) -> tuple[list[FigureSpec], list[TableSpec]]:
    """为论文生成最小必要图表。"""

    incident_evidence_packages = incident_evidence_packages or []
    figures: list[FigureSpec] = [
        FigureSpec(
            figure_id="fig_attack_path",
            title="攻击路径概览",
            purpose="帮助读者快速理解从错误 Oracle 参数到欠抵押借款的传播链。",
            caption="图 1. Morpho Blue 个案中的攻击路径概览：错误 Oracle 参数如何经过市场创建、定价传播与借贷约束链路转化为欠抵押借款结果。",
            source_basis=[
                audit_result.classification.protocol_name,
                *(item.title for item in incident_evidence_packages[:1]),
            ],
            figure_type="mechanism_chain",
        ),
        FigureSpec(
            figure_id="fig_validation_boundary",
            title="验证边界与反证位置",
            purpose="帮助读者理解哪些环节已验证、哪些环节仍属于候选性设计含义。",
            caption="图 2. 验证边界与反证位置：以最小复现实验说明正向路径成立，并标记需要进一步补强的反证条件。",
            source_basis=[item.claim for item in (claim_evidence_matrix.rows if claim_evidence_matrix else [])[:3]],
            figure_type="validation_boundary",
        ),
    ]

    timeline_rows = []
    if incident_evidence_packages:
        for step in incident_evidence_packages[0].timeline[:4]:
            timeline_rows.append(
                [
                    step.title,
                    step.description,
                    "；".join(step.tx_hashes[:2]) or "无显式交易锚点",
                ]
            )

    claim_rows = []
    if claim_evidence_matrix:
        for row in claim_evidence_matrix.rows[:3]:
            claim_rows.append(
                [
                    row.claim,
                    "；".join(row.evidence_refs[:2]) or "无",
                    "；".join(row.experiment_refs[:1]) or "待补验证",
                    "；".join(row.boundary_notes[:1]) or "无",
                ]
            )

    tables = [
        TableSpec(
            table_id="tbl_timeline",
            title="攻击时间线",
            caption="表 1. Morpho Blue 个案的关键时间线阶段与对应链上锚点。",
            columns=["阶段", "关键事实", "链上锚点"],
            rows=timeline_rows or [["未生成", "当前缺少时间线数据", "无"]],
            purpose="以紧凑形式呈现个案时间线。",
        ),
        TableSpec(
            table_id="tbl_claims",
            title="主张-证据-验证对应关系",
            caption="表 2. 核心主张、证据基础、验证基础与边界说明之间的对应关系。",
            columns=["核心主张", "证据基础", "验证基础", "边界"],
            rows=claim_rows or [["未生成", "无", "无", "无"]],
            purpose="以论文表格形式替代内部矩阵腔调。",
        ),
    ]
    return figures, tables
