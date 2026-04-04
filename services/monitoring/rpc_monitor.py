"""链上监控与持续索引。

这一层不再只做“发现新合约”，而是把最近区块中的：

- 区块摘要
- 交易摘要
- 日志摘要
- 合约创建事件

统一索引到数据库，并通过游标持续推进。
"""

from __future__ import annotations

from datetime import datetime, timezone
import json
from pathlib import Path
import time
from urllib import request
import uuid

from services.monitoring.models import (
    DiscoveredContract,
    IndexedBlockSummary,
    IndexedLogSummary,
    IndexedTransactionSummary,
    MonitoringScanResult,
)
from services.monitoring.signature_resolver import (
    resolve_event_topic,
    resolve_function_selector,
)
from services.agent.task_orchestrator import run_audit_task
from services.storage.artifact_store import save_task_result
from services.shared.settings import ProjectSettings
from services.storage.task_database import (
    load_monitor_state,
    save_discovered_contracts,
    save_indexed_blocks,
    save_indexed_logs,
    save_index_run,
    save_indexed_transactions,
    save_monitor_state,
)


def _rpc_call(rpc_url: str, method: str, params: list) -> dict:
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
    with request.urlopen(req, timeout=30) as response:
        return json.loads(response.read().decode("utf-8"))


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
        raise RuntimeError("缺少 ETH_RPC_URL 或 MAINNET_RPC_URL，无法执行链上监控。")
    return resolved


def _index_block(
    *,
    rpc_url: str,
    block_number: int,
) -> tuple[
    IndexedBlockSummary,
    list[IndexedTransactionSummary],
    list[IndexedLogSummary],
    list[DiscoveredContract],
]:
    """索引单个区块。"""

    block_payload = _rpc_call(
        rpc_url,
        "eth_getBlockByNumber",
        [hex(block_number), True],
    )
    block = block_payload["result"]
    if not block:
        raise RuntimeError(f"无法获取区块 {block_number}")

    indexed_at = datetime.now(timezone.utc).isoformat()
    block_summary = IndexedBlockSummary(
        block_number=block_number,
        block_hash=block.get("hash", ""),
        parent_hash=block.get("parentHash", ""),
        timestamp=_hex_to_int(block.get("timestamp")),
        tx_count=len(block.get("transactions", [])),
        indexed_at=indexed_at,
    )

    transactions: list[IndexedTransactionSummary] = []
    logs: list[IndexedLogSummary] = []
    discovered_contracts: list[DiscoveredContract] = []

    for tx in block.get("transactions", []):
        receipt_payload = _rpc_call(
            rpc_url,
            "eth_getTransactionReceipt",
            [tx["hash"]],
        )
        receipt = receipt_payload["result"]
        if not receipt:
            continue

        contract_address = receipt.get("contractAddress")
        tx_summary = IndexedTransactionSummary(
            tx_hash=tx["hash"],
            block_number=block_number,
            tx_index=_hex_to_int(tx.get("transactionIndex")),
            from_address=tx.get("from", ""),
            to_address=tx.get("to"),
            contract_address=contract_address,
            selector=_extract_selector(tx.get("input")),
            selector_name=resolve_function_selector(_extract_selector(tx.get("input"))),
            value_wei=str(_hex_to_int(tx.get("value"))),
            status=_hex_to_int(receipt.get("status")),
            is_contract_creation=1 if contract_address else 0,
        )
        transactions.append(tx_summary)

        if contract_address:
            discovered_contracts.append(
                DiscoveredContract(
                    address=contract_address,
                    block_number=block_number,
                    tx_hash=tx["hash"],
                    creator=tx.get("from", ""),
                    source="chain_indexer",
                    discovered_at=indexed_at,
                )
            )

        for log in receipt.get("logs", []):
            topics = log.get("topics", [])
            log_summary = IndexedLogSummary(
                log_key=f"{tx['hash']}:{_hex_to_int(log.get('logIndex'))}",
                tx_hash=tx["hash"],
                block_number=block_number,
                log_index=_hex_to_int(log.get("logIndex")),
                address=log.get("address", ""),
                topic0=topics[0] if topics else None,
                topic0_name=resolve_event_topic(topics[0] if topics else None),
                topic_count=len(topics),
            )
            logs.append(log_summary)

    return block_summary, transactions, logs, discovered_contracts


def index_block_range(
    *,
    from_block: int,
    to_block: int,
    rpc_url: str | None = None,
    save_to_db: bool = True,
    auto_enqueue_audit: bool = False,
    db_path: Path | None = None,
    database_url: str | None = None,
    mode: str = "range",
) -> MonitoringScanResult:
    """索引一个区块范围。"""

    resolved_rpc = _resolve_rpc_url(rpc_url)
    started_at = datetime.now(timezone.utc).isoformat()
    run_id = f"index_run_{uuid.uuid4().hex[:12]}"
    indexed_blocks: list[IndexedBlockSummary] = []
    indexed_transactions: list[IndexedTransactionSummary] = []
    indexed_logs: list[IndexedLogSummary] = []
    discovered_contracts: list[DiscoveredContract] = []
    auto_audit_task_ids: list[str] = []

    for block_number in range(from_block, to_block + 1):
        block_summary, transactions, logs, creations = _index_block(
            rpc_url=resolved_rpc,
            block_number=block_number,
        )
        indexed_blocks.append(block_summary)
        indexed_transactions.extend(transactions)
        indexed_logs.extend(logs)
        discovered_contracts.extend(creations)

    finished_at = datetime.now(timezone.utc).isoformat()

    if save_to_db:
        save_indexed_blocks(
            [block.to_dict() for block in indexed_blocks],
            db_path=db_path,
            database_url=database_url,
        )
        save_indexed_transactions(
            [tx.to_dict() for tx in indexed_transactions],
            db_path=db_path,
            database_url=database_url,
        )
        save_indexed_logs(
            [log.to_dict() for log in indexed_logs],
            db_path=db_path,
            database_url=database_url,
        )
        if discovered_contracts:
            save_discovered_contracts(
                [contract.to_dict() for contract in discovered_contracts],
                db_path=db_path,
                database_url=database_url,
            )
            if auto_enqueue_audit:
                for contract in discovered_contracts:
                    try:
                        task_result = run_audit_task(target=contract.address)
                        task_dir = save_task_result(task_result)
                        auto_audit_task_ids.append(task_dir.name)
                    except Exception:
                        # 自动送审计失败时不阻断索引主流程。
                        continue
        save_index_run(
            run_id=run_id,
            mode=mode,
            from_block=from_block,
            to_block=to_block,
            indexed_block_count=len(indexed_blocks),
            indexed_transaction_count=len(indexed_transactions),
            indexed_log_count=len(indexed_logs),
            discovered_contract_count=len(discovered_contracts),
            status="completed",
            started_at=started_at,
            finished_at=finished_at,
            db_path=db_path,
            database_url=database_url,
        )

    return MonitoringScanResult(
        from_block=from_block,
        to_block=to_block,
        indexed_blocks=indexed_blocks,
        indexed_transactions=indexed_transactions,
        indexed_logs=indexed_logs,
        discovered_contracts=discovered_contracts,
        auto_audit_task_ids=auto_audit_task_ids,
        cursor_block=to_block,
    )


def scan_recent_contract_creations(
    *,
    block_count: int = 5,
    rpc_url: str | None = None,
    save_to_db: bool = True,
    auto_enqueue_audit: bool = False,
    db_path: Path | None = None,
    database_url: str | None = None,
) -> MonitoringScanResult:
    """扫描最近若干区块里的合约创建交易。"""

    resolved_rpc = _resolve_rpc_url(rpc_url)
    latest_block_payload = _rpc_call(resolved_rpc, "eth_blockNumber", [])
    latest_block = _hex_to_int(latest_block_payload["result"])
    from_block = max(latest_block - block_count + 1, 0)
    return index_block_range(
        from_block=from_block,
        to_block=latest_block,
        rpc_url=resolved_rpc,
        save_to_db=save_to_db,
        auto_enqueue_audit=auto_enqueue_audit,
        db_path=db_path,
        database_url=database_url,
        mode="recent",
    )


def run_monitor_cycle(
    *,
    initial_lookback: int = 5,
    max_blocks_per_cycle: int = 20,
    rpc_url: str | None = None,
    state_key: str = "eth_mainnet_last_scanned_block",
    auto_enqueue_audit: bool = False,
    db_path: Path | None = None,
    database_url: str | None = None,
) -> MonitoringScanResult:
    """执行一轮带游标的监控扫描。"""

    resolved_rpc = _resolve_rpc_url(rpc_url)
    latest_block_payload = _rpc_call(resolved_rpc, "eth_blockNumber", [])
    latest_block = _hex_to_int(latest_block_payload["result"])
    stored_value = load_monitor_state(
        state_key,
        db_path=db_path,
        database_url=database_url,
    )
    if stored_value is None:
        from_block = max(latest_block - initial_lookback + 1, 0)
    else:
        from_block = min(int(stored_value) + 1, latest_block)

    to_block = min(latest_block, from_block + max_blocks_per_cycle - 1)
    result = index_block_range(
        from_block=from_block,
        to_block=to_block,
        rpc_url=resolved_rpc,
        save_to_db=True,
        auto_enqueue_audit=auto_enqueue_audit,
        db_path=db_path,
        database_url=database_url,
        mode="cycle",
    )
    save_monitor_state(
        state_key,
        str(to_block),
        db_path=db_path,
        database_url=database_url,
    )
    return result


def run_monitor_daemon(
    *,
    initial_lookback: int = 5,
    max_blocks_per_cycle: int = 20,
    sleep_seconds: int = 10,
    cycles: int | None = None,
    rpc_url: str | None = None,
    state_key: str = "eth_mainnet_last_scanned_block",
    auto_enqueue_audit: bool = False,
    db_path: Path | None = None,
    database_url: str | None = None,
) -> None:
    """持续运行索引循环。"""

    completed_cycles = 0
    while cycles is None or completed_cycles < cycles:
        result = run_monitor_cycle(
            initial_lookback=initial_lookback,
            max_blocks_per_cycle=max_blocks_per_cycle,
            rpc_url=rpc_url,
            state_key=state_key,
            auto_enqueue_audit=auto_enqueue_audit,
            db_path=db_path,
            database_url=database_url,
        )
        print(
            f"[monitor] blocks={result.from_block}-{result.to_block} "
            f"txs={len(result.indexed_transactions)} logs={len(result.indexed_logs)} "
            f"creations={len(result.discovered_contracts)}"
        )
        completed_cycles += 1
        if cycles is None or completed_cycles < cycles:
            time.sleep(sleep_seconds)
