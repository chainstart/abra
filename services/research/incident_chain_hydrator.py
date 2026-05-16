"""历史攻击事件链上证据富化。

用途：

- 对 incident 中已知的攻击交易哈希做 RPC 拉取
- 将交易、区块和日志写入统一索引库
- 让 incident evidence package 自动拿到更强的链上锚点
"""

from __future__ import annotations

from datetime import datetime, timezone
import json
from pathlib import Path
import time
from typing import Any
from urllib import error, request

from services.monitoring.models import IndexedBlockSummary, IndexedLogSummary, IndexedTransactionSummary
from services.monitoring.signature_resolver import resolve_event_topic, resolve_function_selector
from services.research.incident_evidence_service import build_incident_evidence_packages
from services.research.incident_repository import load_incidents
from services.research.models import IncidentEvidencePackage, IncidentRecord
from services.shared.settings import ProjectSettings
from services.storage.task_database import (
    save_indexed_blocks,
    save_indexed_logs,
    save_indexed_transactions,
)


def _retry_delay_seconds(attempt: int) -> int:
    """返回 RPC 重试等待时间。"""

    return min(2**attempt, 6)


def _rpc_call(rpc_url: str, method: str, params: list[Any]) -> dict[str, Any]:
    """执行 JSON-RPC 调用。"""

    payload = json.dumps(
        {
            "jsonrpc": "2.0",
            "method": method,
            "params": params,
            "id": 1,
        }
    ).encode("utf-8")
    req = request.Request(
        rpc_url,
        data=payload,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    last_error: Exception | None = None
    for attempt in range(4):
        try:
            with request.urlopen(req, timeout=30 + attempt * 10) as response:
                return json.loads(response.read().decode("utf-8"))
        except error.HTTPError as exc:
            last_error = exc
            if exc.code in {408, 429, 500, 502, 503, 504} and attempt < 3:
                time.sleep(_retry_delay_seconds(attempt))
                continue
            raise
        except error.URLError as exc:
            last_error = exc
            if attempt < 3:
                time.sleep(_retry_delay_seconds(attempt))
                continue
            raise

    raise RuntimeError(f"RPC 调用失败: {method} {params} {last_error}")


def _hex_to_int(value: str | None) -> int:
    """16 进制字符串转整数。"""

    if not value:
        return 0
    return int(value, 16)


def _extract_selector(input_data: str | None) -> str | None:
    """提取 4-byte selector。"""

    if not input_data or input_data == "0x" or len(input_data) < 10:
        return None
    return input_data[:10]


def _resolve_rpc_url(rpc_url: str | None) -> str:
    """解析实际使用的 RPC URL。"""

    settings = ProjectSettings.from_env()
    resolved = rpc_url or settings.preferred_mainnet_rpc
    if not resolved:
        raise RuntimeError("缺少 ETH_RPC_URL 或 MAINNET_RPC_URL，无法富化攻击事件链上证据。")
    return resolved


def _payload(incident: IncidentRecord) -> dict[str, Any]:
    """返回 incident 扩展载荷。"""

    return incident.evidence_payload if isinstance(incident.evidence_payload, dict) else {}


def _select_incidents(
    incidents: list[IncidentRecord],
    incident_id: str | None,
    incident_ids: list[str] | None = None,
) -> list[IncidentRecord]:
    """按 incident_id 过滤。"""

    if incident_ids:
        wanted = set(incident_ids)
        selected = [incident for incident in incidents if incident.incident_id in wanted]
        missing = wanted.difference({incident.incident_id for incident in selected})
        if missing:
            raise ValueError(f"未找到 incident_id={sorted(missing)} 的案例。")
        return selected
    if not incident_id:
        return incidents
    selected = [incident for incident in incidents if incident.incident_id == incident_id]
    if not selected:
        raise ValueError(f"未找到 incident_id={incident_id} 的案例。")
    return selected


def _hydrate_transaction(
    *,
    rpc_url: str,
    tx_hash: str,
) -> tuple[IndexedBlockSummary, IndexedTransactionSummary, list[IndexedLogSummary]]:
    """拉取单笔攻击交易并转换成统一索引结构。"""

    tx_payload = _rpc_call(rpc_url, "eth_getTransactionByHash", [tx_hash])
    tx = tx_payload.get("result")
    if not tx:
        raise RuntimeError(f"链上未找到交易: {tx_hash}")

    receipt_payload = _rpc_call(rpc_url, "eth_getTransactionReceipt", [tx_hash])
    receipt = receipt_payload.get("result")
    if not receipt:
        raise RuntimeError(f"链上未找到交易 receipt: {tx_hash}")

    block_number = _hex_to_int(tx.get("blockNumber") or receipt.get("blockNumber"))
    block_payload = _rpc_call(rpc_url, "eth_getBlockByNumber", [hex(block_number), False])
    block = block_payload.get("result")
    if not block:
        raise RuntimeError(f"链上未找到区块: {block_number}")

    indexed_at = datetime.now(timezone.utc).isoformat()
    block_summary = IndexedBlockSummary(
        block_number=block_number,
        block_hash=block.get("hash", ""),
        parent_hash=block.get("parentHash", ""),
        timestamp=_hex_to_int(block.get("timestamp")),
        tx_count=_hex_to_int(block.get("transactionsRoot", "0x0")) if False else len(block.get("transactions", []) or []),
        indexed_at=indexed_at,
    )

    selector = _extract_selector(tx.get("input"))
    tx_summary = IndexedTransactionSummary(
        tx_hash=tx_hash,
        block_number=block_number,
        tx_index=_hex_to_int(tx.get("transactionIndex")),
        from_address=tx.get("from", ""),
        to_address=tx.get("to"),
        contract_address=receipt.get("contractAddress"),
        selector=selector,
        selector_name=resolve_function_selector(selector),
        value_wei=str(_hex_to_int(tx.get("value"))),
        status=_hex_to_int(receipt.get("status")),
        is_contract_creation=1 if receipt.get("contractAddress") else 0,
    )

    logs: list[IndexedLogSummary] = []
    for log in receipt.get("logs", []):
        topics = log.get("topics", [])
        logs.append(
            IndexedLogSummary(
                log_key=f"{tx_hash}:{_hex_to_int(log.get('logIndex'))}",
                tx_hash=tx_hash,
                block_number=block_number,
                log_index=_hex_to_int(log.get("logIndex")),
                address=log.get("address", ""),
                topic0=topics[0] if topics else None,
                topic0_name=resolve_event_topic(topics[0] if topics else None),
                topic_count=len(topics),
            )
        )

    return block_summary, tx_summary, logs


def hydrate_incident_chain_evidence(
    *,
    incident_id: str | None = None,
    incident_ids: list[str] | None = None,
    incident_dir: str | Path | None = None,
    rpc_url: str | None = None,
    save_to_db: bool = True,
    db_path: Path | None = None,
    database_url: str | None = None,
) -> dict[str, Any]:
    """对指定 incident 或全部 incident 的攻击交易做链上富化。"""

    settings = ProjectSettings.from_env()
    incidents = load_incidents(incident_dir or settings.research_dir / "incidents")
    selected_incidents = _select_incidents(incidents, incident_id, incident_ids)
    resolved_rpc = _resolve_rpc_url(rpc_url)

    indexed_blocks: dict[int, IndexedBlockSummary] = {}
    indexed_transactions: dict[str, IndexedTransactionSummary] = {}
    indexed_logs: dict[str, IndexedLogSummary] = {}
    processed_incident_ids: list[str] = []
    skipped_incident_ids: list[str] = []

    for incident in selected_incidents:
        raw_txs = _payload(incident).get("attack_transactions")
        if not isinstance(raw_txs, list) or not raw_txs:
            skipped_incident_ids.append(incident.incident_id)
            continue

        processed_incident_ids.append(incident.incident_id)
        for item in raw_txs:
            if not isinstance(item, dict):
                continue
            tx_hash = str(item.get("tx_hash") or item.get("hash") or "").strip()
            if not tx_hash or tx_hash in indexed_transactions:
                continue
            block_summary, tx_summary, log_rows = _hydrate_transaction(
                rpc_url=resolved_rpc,
                tx_hash=tx_hash,
            )
            indexed_blocks[block_summary.block_number] = block_summary
            indexed_transactions[tx_hash] = tx_summary
            for log in log_rows:
                indexed_logs[log.log_key] = log

    if save_to_db and indexed_transactions:
        save_indexed_blocks(
            [item.to_dict() for item in indexed_blocks.values()],
            db_path=db_path,
            database_url=database_url,
        )
        save_indexed_transactions(
            [item.to_dict() for item in indexed_transactions.values()],
            db_path=db_path,
            database_url=database_url,
        )
        save_indexed_logs(
            [item.to_dict() for item in indexed_logs.values()],
            db_path=db_path,
            database_url=database_url,
        )

    evidence_packages = build_incident_evidence_packages(
        selected_incidents,
        db_path=db_path,
        database_url=database_url,
    )
    return {
        "incident_id": incident_id,
        "incident_ids": incident_ids or [],
        "processed_incident_ids": processed_incident_ids,
        "skipped_incident_ids": skipped_incident_ids,
        "indexed_block_count": len(indexed_blocks),
        "indexed_transaction_count": len(indexed_transactions),
        "indexed_log_count": len(indexed_logs),
        "evidence_packages": [item.to_dict() for item in evidence_packages],
    }
