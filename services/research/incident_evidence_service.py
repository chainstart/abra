"""历史攻击事件结构化证据包构建。

目标：

- 把静态 incident 摘要提升成研究可消费的证据包
- 优先复用仓库中已有的攻击交易、关键地址、时间线与报告线索
- 如果本地索引器已经采集到相关交易 / 日志，则自动富化链上细节
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from services.research.models import (
    IncidentEntityRef,
    IncidentEvidencePackage,
    IncidentEvidenceTransaction,
    IncidentRecord,
    IncidentTimelineStep,
)
from services.storage.task_database import get_indexed_transaction, list_indexed_logs_by_tx_hash


def _payload(incident: IncidentRecord) -> dict[str, Any]:
    """返回 incident 的扩展证据载荷。"""

    return incident.evidence_payload if isinstance(incident.evidence_payload, dict) else {}


def _normalize_text(value: Any) -> str:
    """把任意值稳定转成字符串。"""

    return str(value).strip() if value is not None else ""


def _loss_summary(incident: IncidentRecord) -> str:
    """汇总损失信息。"""

    raw_loss = _payload(incident).get("loss")
    if isinstance(raw_loss, dict):
        estimated = _normalize_text(raw_loss.get("estimated_usd"))
        amount = _normalize_text(raw_loss.get("amount"))
        asset = _normalize_text(raw_loss.get("asset"))
        notes = _normalize_text(raw_loss.get("notes"))
        parts = [item for item in [estimated, f"{amount} {asset}".strip()] if item]
        summary = " / ".join(parts)
        if notes:
            return f"{summary} ({notes})" if summary else notes
        if summary:
            return summary
    return _normalize_text(_payload(incident).get("loss_summary")) or "未显式记录"


def _normalize_entities(
    items: Any,
    *,
    default_entity_type: str,
    default_role: str,
) -> list[IncidentEntityRef]:
    """规范化关键实体列表。"""

    if not isinstance(items, list):
        return []

    normalized: list[IncidentEntityRef] = []
    for item in items:
        if not isinstance(item, dict):
            continue
        reference = _normalize_text(item.get("reference") or item.get("address") or item.get("name"))
        label = _normalize_text(item.get("label") or item.get("name") or reference)
        if not reference and not label:
            continue
        normalized.append(
            IncidentEntityRef(
                reference=reference or label,
                label=label or reference,
                role=_normalize_text(item.get("role")) or default_role,
                entity_type=_normalize_text(item.get("entity_type")) or default_entity_type,
                description=_normalize_text(item.get("description")),
            )
        )
    return normalized


def _transaction_hints(log_rows: list[dict], raw_item: dict[str, Any]) -> list[str]:
    """从日志和原始条目里提取提示。"""

    hints: list[str] = []
    for label in raw_item.get("labels", []) if isinstance(raw_item.get("labels"), list) else []:
        text = _normalize_text(label)
        if text and text not in hints:
            hints.append(text)
    for row in log_rows[:4]:
        text = _normalize_text(row.get("topic0_name"))
        if text and text not in hints:
            hints.append(text)
    return hints


def _normalize_attack_transactions(
    incident: IncidentRecord,
    *,
    db_path: Path | None = None,
    database_url: str | None = None,
) -> tuple[list[IncidentEvidenceTransaction], int, int]:
    """构建攻击交易证据。"""

    raw_items = _payload(incident).get("attack_transactions")
    if not isinstance(raw_items, list):
        raw_items = []

    chain = _normalize_text(_payload(incident).get("chain")) or "ethereum"
    transactions: list[IncidentEvidenceTransaction] = []
    indexed_tx_count = 0
    indexed_log_count = 0

    for item in raw_items:
        if not isinstance(item, dict):
            continue
        tx_hash = _normalize_text(item.get("tx_hash") or item.get("hash"))
        if not tx_hash:
            continue

        indexed_tx = get_indexed_transaction(
            tx_hash,
            db_path=db_path,
            database_url=database_url,
        )
        log_rows = list_indexed_logs_by_tx_hash(
            tx_hash,
            limit=8,
            db_path=db_path,
            database_url=database_url,
        )
        if indexed_tx:
            indexed_tx_count += 1
        indexed_log_count += len(log_rows)

        status_value = (
            indexed_tx.get("status")
            if indexed_tx is not None
            else item.get("status")
        )
        if status_value in {1, "1", "success", "completed"}:
            status = "success"
        elif status_value in {0, "0", "failed", "reverted"}:
            status = "failed"
        else:
            status = _normalize_text(status_value) or "unknown"

        transactions.append(
            IncidentEvidenceTransaction(
                tx_hash=tx_hash,
                role=_normalize_text(item.get("role")) or "exploit",
                label=_normalize_text(item.get("label")) or "关键攻击交易",
                description=_normalize_text(item.get("description")) or incident.summary,
                chain=_normalize_text(item.get("chain")) or chain,
                block_number=(
                    indexed_tx.get("block_number")
                    if indexed_tx is not None
                    else item.get("block_number")
                ),
                timestamp=_normalize_text(item.get("timestamp")),
                from_address=_normalize_text(
                    (indexed_tx or {}).get("from_address") or item.get("from_address")
                ),
                to_address=_normalize_text(
                    (indexed_tx or {}).get("to_address") or item.get("to_address")
                ),
                contract_address=_normalize_text(
                    (indexed_tx or {}).get("contract_address") or item.get("contract_address")
                ),
                selector=_normalize_text(
                    (indexed_tx or {}).get("selector") or item.get("selector")
                ),
                selector_name=_normalize_text(
                    (indexed_tx or {}).get("selector_name") or item.get("selector_name")
                ),
                value_wei=_normalize_text(
                    (indexed_tx or {}).get("value_wei") or item.get("value_wei")
                ),
                status=status,
                indexed_log_count=len(log_rows),
                indexed=bool(indexed_tx),
                hints=_transaction_hints(log_rows, item),
            )
        )

    return transactions, indexed_tx_count, indexed_log_count


def _normalize_timeline(
    incident: IncidentRecord,
    attack_transactions: list[IncidentEvidenceTransaction],
    key_entities: list[IncidentEntityRef],
) -> list[IncidentTimelineStep]:
    """规范化事件时间线。"""

    raw_steps = _payload(incident).get("timeline")
    if not isinstance(raw_steps, list):
        raw_steps = []

    timeline: list[IncidentTimelineStep] = []
    if raw_steps:
        for index, item in enumerate(raw_steps, start=1):
            if not isinstance(item, dict):
                continue
            timeline.append(
                IncidentTimelineStep(
                    step_id=_normalize_text(item.get("step_id")) or f"step_{index}",
                    title=_normalize_text(item.get("title")) or f"阶段 {index}",
                    description=_normalize_text(item.get("description")) or incident.summary,
                    tx_hashes=[
                        _normalize_text(value)
                        for value in item.get("tx_hashes", [])
                        if _normalize_text(value)
                    ],
                    involved_entities=[
                        _normalize_text(value)
                        for value in item.get("involved_entities", [])
                        if _normalize_text(value)
                    ],
                    evidence_refs=[
                        _normalize_text(value)
                        for value in item.get("evidence_refs", [])
                        if _normalize_text(value)
                    ],
                )
            )
        if timeline:
            return timeline

    if attack_transactions:
        for index, tx in enumerate(attack_transactions, start=1):
            timeline.append(
                IncidentTimelineStep(
                    step_id=f"tx_{index}",
                    title=tx.label,
                    description=tx.description,
                    tx_hashes=[tx.tx_hash],
                    involved_entities=[
                        entity.reference
                        for entity in key_entities[:3]
                        if entity.reference
                    ],
                    evidence_refs=[tx.tx_hash],
                )
            )
    else:
        timeline.append(
            IncidentTimelineStep(
                step_id="summary",
                title="攻击摘要",
                description=incident.summary,
                evidence_refs=incident.source_reports[:2],
            )
        )
    return timeline


def _missing_artifacts(
    attack_transactions: list[IncidentEvidenceTransaction],
    key_entities: list[IncidentEntityRef],
    affected_components: list[IncidentEntityRef],
    timeline: list[IncidentTimelineStep],
) -> list[str]:
    """计算当前证据包仍缺少的关键工件。"""

    missing: list[str] = []
    if not attack_transactions:
        missing.append("缺少攻击交易哈希或可验证的链上交易锚点。")
    elif any(not item.indexed for item in attack_transactions):
        missing.append("攻击交易尚未完成链上富化，缺少交易 / receipt / 日志级证据。")
    if not key_entities:
        missing.append("缺少攻击者 / 受害者 / 关键组件的结构化实体列表。")
    if not affected_components:
        missing.append("缺少受影响合约或模块清单。")
    if len(timeline) <= 1 and not attack_transactions:
        missing.append("缺少可复现的攻击时间线。")
    return missing


def build_incident_evidence_package(
    incident: IncidentRecord,
    *,
    db_path: Path | None = None,
    database_url: str | None = None,
    verification_results: list[dict[str, Any]] | None = None,
) -> IncidentEvidencePackage:
    """把 incident 记录构造成研究证据包。"""

    payload = _payload(incident)
    chain = _normalize_text(payload.get("chain")) or "ethereum"
    attack_transactions, indexed_tx_count, indexed_log_count = _normalize_attack_transactions(
        incident,
        db_path=db_path,
        database_url=database_url,
    )
    key_entities = _normalize_entities(
        payload.get("key_entities") or payload.get("key_addresses"),
        default_entity_type="address",
        default_role="actor",
    )
    affected_components = _normalize_entities(
        payload.get("affected_components") or payload.get("affected_contracts"),
        default_entity_type="contract",
        default_role="affected_component",
    )
    timeline = _normalize_timeline(incident, attack_transactions, key_entities + affected_components)
    missing = _missing_artifacts(attack_transactions, key_entities, affected_components, timeline)

    evidence_summary = [
        f"链: {chain}",
        f"关键交易数: {len(attack_transactions)}（已索引 {indexed_tx_count} 笔）",
        f"关键实体数: {len(key_entities)}，受影响组件数: {len(affected_components)}",
        f"根因: {incident.root_cause}",
        f"损失: {_loss_summary(incident)}",
    ]
    if attack_transactions:
        lead_tx = attack_transactions[0]
        evidence_summary.append(
            f"主交易锚点: {lead_tx.tx_hash} ({lead_tx.label}, status={lead_tx.status})"
        )
    if timeline:
        evidence_summary.append(f"攻击时间线阶段数: {len(timeline)}")

    return IncidentEvidencePackage(
        incident_id=incident.incident_id,
        title=incident.title,
        protocol_name=incident.protocol_name,
        protocol_type=incident.protocol_type,
        chain=chain,
        root_cause=incident.root_cause,
        summary=incident.summary,
        loss_summary=_loss_summary(incident),
        attack_transactions=attack_transactions,
        key_entities=key_entities,
        affected_components=affected_components,
        timeline=timeline,
        source_reports=incident.source_reports,
        evidence_summary=evidence_summary,
        missing_artifacts=missing,
        verification_results=verification_results or [],
        indexed_transaction_count=indexed_tx_count,
        indexed_log_count=indexed_log_count,
    )


def build_incident_evidence_packages(
    incidents: list[IncidentRecord],
    *,
    db_path: Path | None = None,
    database_url: str | None = None,
    verification_results_by_incident: dict[str, list[dict[str, Any]]] | None = None,
) -> list[IncidentEvidencePackage]:
    """批量构造攻击事件证据包。"""

    return [
        build_incident_evidence_package(
            incident,
            db_path=db_path,
            database_url=database_url,
            verification_results=(verification_results_by_incident or {}).get(incident.incident_id, []),
        )
        for incident in incidents
    ]
