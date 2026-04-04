"""任务结果数据库访问层。"""

from __future__ import annotations

from datetime import datetime, timezone
import json
from pathlib import Path
from sqlalchemy import or_

from services.agent.models import AgentTaskResult
from services.shared.settings import ProjectSettings
from services.storage.database_backend import (
    DiscoveredContractModel,
    IncidentModel,
    IndexRunModel,
    IndexedBlockModel,
    IndexedLogModel,
    IndexedTransactionModel,
    MonitorStateModel,
    SignatureCacheModel,
    TaskRunModel,
    initialize_database,
    session_scope,
)


def _db_path(db_path: Path | None = None) -> Path:
    """返回 SQLite 数据库路径。"""

    settings = ProjectSettings.from_env()
    return db_path or settings.task_db_path


def _database_url(
    *,
    db_path: Path | None = None,
    database_url: str | None = None,
) -> str:
    """解析数据库 URL。

    优先级：

    1. 显式传入 database_url
    2. 显式传入 db_path（自动转 SQLite URL）
    3. 配置中的 DATABASE_URL
    """

    if database_url:
        return database_url
    if db_path:
        return f"sqlite:///{db_path.resolve()}"
    return ProjectSettings.from_env().database_url


def initialize_task_db(db_path: Path | None = None, database_url: str | None = None) -> Path:
    """初始化数据库。

    兼容旧接口：仍然返回本地 SQLite 路径。
    """

    path = _db_path(db_path)
    initialize_database(_database_url(db_path=db_path, database_url=database_url))
    return path


def save_task_index(
    *,
    task_id: str,
    task_result: AgentTaskResult,
    artifact_dir: Path,
    db_path: Path | None = None,
    database_url: str | None = None,
) -> None:
    """写入任务索引。"""

    initialize_task_db(db_path, database_url)
    with session_scope(_database_url(db_path=db_path, database_url=database_url)) as session:
        row = TaskRunModel(
            task_id=task_id,
            task_type=task_result.task_type,
            target=task_result.target,
            status=task_result.status,
            artifact_dir=str(artifact_dir),
            created_at=datetime.now(timezone.utc).isoformat(),
        )
        session.merge(row)


def list_task_index(
    limit: int = 50,
    db_path: Path | None = None,
    database_url: str | None = None,
) -> list[dict]:
    """读取任务索引列表。"""

    initialize_task_db(db_path, database_url)
    with session_scope(_database_url(db_path=db_path, database_url=database_url)) as session:
        rows = (
            session.query(TaskRunModel)
            .order_by(TaskRunModel.created_at.desc())
            .limit(limit)
            .all()
        )
        return [
            {
                "task_id": row.task_id,
                "task_type": row.task_type,
                "target": row.target,
                "status": row.status,
                "artifact_dir": row.artifact_dir,
                "created_at": row.created_at,
            }
            for row in rows
        ]


def save_discovered_contracts(
    contracts: list[dict],
    *,
    db_path: Path | None = None,
    database_url: str | None = None,
) -> None:
    """写入链上发现的合约。"""

    initialize_task_db(db_path, database_url)
    with session_scope(_database_url(db_path=db_path, database_url=database_url)) as session:
        for contract in contracts:
            row = DiscoveredContractModel(
                address=contract["address"],
                block_number=contract["block_number"],
                tx_hash=contract["tx_hash"],
                creator=contract["creator"],
                source=contract["source"],
                discovered_at=contract["discovered_at"],
            )
            session.merge(row)


def list_discovered_contracts(
    limit: int = 50,
    db_path: Path | None = None,
    database_url: str | None = None,
) -> list[dict]:
    """列出最近发现的链上合约。"""

    initialize_task_db(db_path, database_url)
    with session_scope(_database_url(db_path=db_path, database_url=database_url)) as session:
        rows = (
            session.query(DiscoveredContractModel)
            .order_by(
                DiscoveredContractModel.block_number.desc(),
                DiscoveredContractModel.discovered_at.desc(),
            )
            .limit(limit)
            .all()
        )
        return [
            {
                "address": row.address,
                "block_number": row.block_number,
                "tx_hash": row.tx_hash,
                "creator": row.creator,
                "source": row.source,
                "discovered_at": row.discovered_at,
            }
            for row in rows
        ]


def upsert_incidents(
    incidents: list[dict],
    db_path: Path | None = None,
    database_url: str | None = None,
) -> None:
    """把结构化案例写入数据库。"""

    initialize_task_db(db_path, database_url)
    with session_scope(_database_url(db_path=db_path, database_url=database_url)) as session:
        for incident in incidents:
            row = IncidentModel(
                incident_id=incident["incident_id"],
                title=incident["title"],
                protocol_name=incident["protocol_name"],
                protocol_type=incident["protocol_type"],
                year=incident["year"],
                summary=incident["summary"],
                root_cause=incident["root_cause"],
                attack_patterns=json.dumps(incident["attack_patterns"], ensure_ascii=False),
                affected_categories=json.dumps(incident["affected_categories"], ensure_ascii=False),
                keywords=json.dumps(incident["keywords"], ensure_ascii=False),
                source_reports=json.dumps(incident["source_reports"], ensure_ascii=False),
                evidence_payload=json.dumps(
                    incident.get("evidence_payload", {}),
                    ensure_ascii=False,
                ),
            )
            session.merge(row)


def list_incidents(
    db_path: Path | None = None,
    limit: int = 500,
    database_url: str | None = None,
) -> list[dict]:
    """从数据库中读取案例。"""

    initialize_task_db(db_path, database_url)
    with session_scope(_database_url(db_path=db_path, database_url=database_url)) as session:
        rows = (
            session.query(IncidentModel)
            .order_by(IncidentModel.year.desc(), IncidentModel.incident_id.asc())
            .limit(limit)
            .all()
        )
        return [
            {
                "incident_id": row.incident_id,
                "title": row.title,
                "protocol_name": row.protocol_name,
                "protocol_type": row.protocol_type,
                "year": row.year,
                "summary": row.summary,
                "root_cause": row.root_cause,
                "attack_patterns": json.loads(row.attack_patterns),
                "affected_categories": json.loads(row.affected_categories),
                "keywords": json.loads(row.keywords),
                "source_reports": json.loads(row.source_reports),
                "evidence_payload": json.loads(row.evidence_payload or "{}"),
            }
            for row in rows
        ]


def search_incidents(
    query: str,
    limit: int = 20,
    db_path: Path | None = None,
    database_url: str | None = None,
) -> list[dict]:
    """搜索历史案例。

    这里先实现跨 SQLite / PostgreSQL 都能工作的简单 LIKE 搜索。
    """

    normalized_query = f"%{query.strip()}%"
    initialize_task_db(db_path, database_url)
    with session_scope(_database_url(db_path=db_path, database_url=database_url)) as session:
        rows = (
            session.query(IncidentModel)
            .filter(
                or_(
                    IncidentModel.title.ilike(normalized_query),
                    IncidentModel.protocol_name.ilike(normalized_query),
                    IncidentModel.protocol_type.ilike(normalized_query),
                    IncidentModel.summary.ilike(normalized_query),
                    IncidentModel.root_cause.ilike(normalized_query),
                    IncidentModel.attack_patterns.ilike(normalized_query),
                    IncidentModel.affected_categories.ilike(normalized_query),
                    IncidentModel.keywords.ilike(normalized_query),
                    IncidentModel.evidence_payload.ilike(normalized_query),
                )
            )
            .order_by(IncidentModel.year.desc(), IncidentModel.incident_id.asc())
            .limit(limit)
            .all()
        )
        return [
            {
                "incident_id": row.incident_id,
                "title": row.title,
                "protocol_name": row.protocol_name,
                "protocol_type": row.protocol_type,
                "year": row.year,
                "summary": row.summary,
                "root_cause": row.root_cause,
                "attack_patterns": json.loads(row.attack_patterns),
                "affected_categories": json.loads(row.affected_categories),
                "keywords": json.loads(row.keywords),
                "source_reports": json.loads(row.source_reports),
                "evidence_payload": json.loads(row.evidence_payload or "{}"),
            }
            for row in rows
        ]


def save_monitor_state(
    key: str,
    value: str,
    *,
    db_path: Path | None = None,
    database_url: str | None = None,
) -> None:
    """保存监控游标。"""

    initialize_task_db(db_path, database_url)
    with session_scope(_database_url(db_path=db_path, database_url=database_url)) as session:
        row = MonitorStateModel(
            state_key=key,
            state_value=value,
            updated_at=datetime.now(timezone.utc).isoformat(),
        )
        session.merge(row)


def load_monitor_state(
    key: str,
    *,
    db_path: Path | None = None,
    database_url: str | None = None,
) -> str | None:
    """读取监控游标。"""

    initialize_task_db(db_path, database_url)
    with session_scope(_database_url(db_path=db_path, database_url=database_url)) as session:
        row = session.get(MonitorStateModel, key)
        return row.state_value if row else None


def save_indexed_blocks(
    blocks: list[dict],
    *,
    db_path: Path | None = None,
    database_url: str | None = None,
) -> None:
    """写入区块摘要。"""

    initialize_task_db(db_path, database_url)
    with session_scope(_database_url(db_path=db_path, database_url=database_url)) as session:
        for block in blocks:
            row = IndexedBlockModel(
                block_number=block["block_number"],
                block_hash=block["block_hash"],
                parent_hash=block["parent_hash"],
                timestamp=block["timestamp"],
                tx_count=block["tx_count"],
                indexed_at=block["indexed_at"],
            )
            session.merge(row)


def list_indexed_blocks(
    limit: int = 50,
    *,
    db_path: Path | None = None,
    database_url: str | None = None,
) -> list[dict]:
    """列出最近索引的区块。"""

    initialize_task_db(db_path, database_url)
    with session_scope(_database_url(db_path=db_path, database_url=database_url)) as session:
        rows = (
            session.query(IndexedBlockModel)
            .order_by(IndexedBlockModel.block_number.desc())
            .limit(limit)
            .all()
        )
        return [
            {
                "block_number": row.block_number,
                "block_hash": row.block_hash,
                "parent_hash": row.parent_hash,
                "timestamp": row.timestamp,
                "tx_count": row.tx_count,
                "indexed_at": row.indexed_at,
            }
            for row in rows
        ]


def save_indexed_transactions(
    transactions: list[dict],
    *,
    db_path: Path | None = None,
    database_url: str | None = None,
) -> None:
    """写入交易索引。"""

    initialize_task_db(db_path, database_url)
    with session_scope(_database_url(db_path=db_path, database_url=database_url)) as session:
        for tx in transactions:
            row = IndexedTransactionModel(
                tx_hash=tx["tx_hash"],
                block_number=tx["block_number"],
                tx_index=tx["tx_index"],
                from_address=tx["from_address"],
                to_address=tx.get("to_address"),
                contract_address=tx.get("contract_address"),
                selector=tx.get("selector"),
                selector_name=tx.get("selector_name"),
                value_wei=tx["value_wei"],
                status=tx["status"],
                is_contract_creation=tx["is_contract_creation"],
            )
            session.merge(row)


def list_indexed_transactions(
    limit: int = 100,
    *,
    db_path: Path | None = None,
    database_url: str | None = None,
) -> list[dict]:
    """列出最近索引的交易。"""

    initialize_task_db(db_path, database_url)
    with session_scope(_database_url(db_path=db_path, database_url=database_url)) as session:
        rows = (
            session.query(IndexedTransactionModel)
            .order_by(
                IndexedTransactionModel.block_number.desc(),
                IndexedTransactionModel.tx_index.desc(),
            )
            .limit(limit)
            .all()
        )
        return [
            {
                "tx_hash": row.tx_hash,
                "block_number": row.block_number,
                "tx_index": row.tx_index,
                "from_address": row.from_address,
                "to_address": row.to_address,
                "contract_address": row.contract_address,
                "selector": row.selector,
                "selector_name": row.selector_name,
                "value_wei": row.value_wei,
                "status": row.status,
                "is_contract_creation": row.is_contract_creation,
            }
            for row in rows
        ]


def get_indexed_transaction(
    tx_hash: str,
    *,
    db_path: Path | None = None,
    database_url: str | None = None,
) -> dict | None:
    """按交易哈希读取已索引交易。"""

    initialize_task_db(db_path, database_url)
    with session_scope(_database_url(db_path=db_path, database_url=database_url)) as session:
        row = session.get(IndexedTransactionModel, tx_hash)
        if not row:
            return None
        return {
            "tx_hash": row.tx_hash,
            "block_number": row.block_number,
            "tx_index": row.tx_index,
            "from_address": row.from_address,
            "to_address": row.to_address,
            "contract_address": row.contract_address,
            "selector": row.selector,
            "selector_name": row.selector_name,
            "value_wei": row.value_wei,
            "status": row.status,
            "is_contract_creation": row.is_contract_creation,
        }


def save_indexed_logs(
    logs: list[dict],
    *,
    db_path: Path | None = None,
    database_url: str | None = None,
) -> None:
    """写入日志索引。"""

    initialize_task_db(db_path, database_url)
    with session_scope(_database_url(db_path=db_path, database_url=database_url)) as session:
        for log in logs:
            row = IndexedLogModel(
                log_key=log["log_key"],
                tx_hash=log["tx_hash"],
                block_number=log["block_number"],
                log_index=log["log_index"],
                address=log["address"],
                topic0=log.get("topic0"),
                topic0_name=log.get("topic0_name"),
                topic_count=log["topic_count"],
            )
            session.merge(row)


def list_indexed_logs(
    limit: int = 100,
    *,
    db_path: Path | None = None,
    database_url: str | None = None,
) -> list[dict]:
    """列出最近索引的日志。"""

    initialize_task_db(db_path, database_url)
    with session_scope(_database_url(db_path=db_path, database_url=database_url)) as session:
        rows = (
            session.query(IndexedLogModel)
            .order_by(
                IndexedLogModel.block_number.desc(),
                IndexedLogModel.log_index.desc(),
            )
            .limit(limit)
            .all()
        )
        return [
            {
                "log_key": row.log_key,
                "tx_hash": row.tx_hash,
                "block_number": row.block_number,
                "log_index": row.log_index,
                "address": row.address,
                "topic0": row.topic0,
                "topic0_name": row.topic0_name,
                "topic_count": row.topic_count,
            }
            for row in rows
        ]


def list_indexed_logs_by_tx_hash(
    tx_hash: str,
    limit: int = 50,
    *,
    db_path: Path | None = None,
    database_url: str | None = None,
) -> list[dict]:
    """按交易哈希读取相关日志。"""

    initialize_task_db(db_path, database_url)
    with session_scope(_database_url(db_path=db_path, database_url=database_url)) as session:
        rows = (
            session.query(IndexedLogModel)
            .filter(IndexedLogModel.tx_hash == tx_hash)
            .order_by(IndexedLogModel.log_index.asc())
            .limit(limit)
            .all()
        )
        return [
            {
                "log_key": row.log_key,
                "tx_hash": row.tx_hash,
                "block_number": row.block_number,
                "log_index": row.log_index,
                "address": row.address,
                "topic0": row.topic0,
                "topic0_name": row.topic0_name,
                "topic_count": row.topic_count,
            }
            for row in rows
        ]


def get_indexer_status(
    *,
    state_key: str = "eth_mainnet_last_scanned_block",
    db_path: Path | None = None,
    database_url: str | None = None,
) -> dict:
    """返回索引器状态摘要。"""

    cursor = load_monitor_state(state_key, db_path=db_path, database_url=database_url)
    blocks = list_indexed_blocks(limit=1, db_path=db_path, database_url=database_url)
    txs = list_indexed_transactions(limit=1, db_path=db_path, database_url=database_url)
    logs = list_indexed_logs(limit=1, db_path=db_path, database_url=database_url)
    return {
        "cursor_block": int(cursor) if cursor is not None else None,
        "latest_indexed_block": blocks[0]["block_number"] if blocks else None,
        "latest_indexed_tx_block": txs[0]["block_number"] if txs else None,
        "latest_indexed_log_block": logs[0]["block_number"] if logs else None,
        "indexed_block_count": len(list_indexed_blocks(limit=10000, db_path=db_path, database_url=database_url)),
        "indexed_transaction_count": len(list_indexed_transactions(limit=10000, db_path=db_path, database_url=database_url)),
        "indexed_log_count": len(list_indexed_logs(limit=10000, db_path=db_path, database_url=database_url)),
    }


def save_signature_cache(
    *,
    cache_key: str,
    kind: str,
    text_signature: str,
    source: str,
    db_path: Path | None = None,
    database_url: str | None = None,
) -> None:
    """写入签名缓存。"""

    initialize_task_db(db_path, database_url)
    with session_scope(_database_url(db_path=db_path, database_url=database_url)) as session:
        row = SignatureCacheModel(
            cache_key=cache_key,
            kind=kind,
            text_signature=text_signature,
            source=source,
            updated_at=datetime.now(timezone.utc).isoformat(),
        )
        session.merge(row)


def load_signature_cache(
    cache_key: str,
    *,
    db_path: Path | None = None,
    database_url: str | None = None,
) -> dict | None:
    """读取签名缓存。"""

    initialize_task_db(db_path, database_url)
    with session_scope(_database_url(db_path=db_path, database_url=database_url)) as session:
        row = session.get(SignatureCacheModel, cache_key)
        if not row:
            return None
        return {
            "cache_key": row.cache_key,
            "kind": row.kind,
            "text_signature": row.text_signature,
            "source": row.source,
            "updated_at": row.updated_at,
        }


def save_index_run(
    *,
    run_id: str,
    mode: str,
    from_block: int,
    to_block: int,
    indexed_block_count: int,
    indexed_transaction_count: int,
    indexed_log_count: int,
    discovered_contract_count: int,
    status: str,
    started_at: str,
    finished_at: str,
    error_message: str | None = None,
    db_path: Path | None = None,
    database_url: str | None = None,
) -> None:
    """保存索引运行记录。"""

    initialize_task_db(db_path, database_url)
    with session_scope(_database_url(db_path=db_path, database_url=database_url)) as session:
        row = IndexRunModel(
            run_id=run_id,
            mode=mode,
            from_block=from_block,
            to_block=to_block,
            indexed_block_count=indexed_block_count,
            indexed_transaction_count=indexed_transaction_count,
            indexed_log_count=indexed_log_count,
            discovered_contract_count=discovered_contract_count,
            status=status,
            error_message=error_message,
            started_at=started_at,
            finished_at=finished_at,
        )
        session.merge(row)


def list_index_runs(
    limit: int = 50,
    *,
    db_path: Path | None = None,
    database_url: str | None = None,
) -> list[dict]:
    """读取最近的索引运行记录。"""

    initialize_task_db(db_path, database_url)
    with session_scope(_database_url(db_path=db_path, database_url=database_url)) as session:
        rows = (
            session.query(IndexRunModel)
            .order_by(IndexRunModel.finished_at.desc())
            .limit(limit)
            .all()
        )
        return [
            {
                "run_id": row.run_id,
                "mode": row.mode,
                "from_block": row.from_block,
                "to_block": row.to_block,
                "indexed_block_count": row.indexed_block_count,
                "indexed_transaction_count": row.indexed_transaction_count,
                "indexed_log_count": row.indexed_log_count,
                "discovered_contract_count": row.discovered_contract_count,
                "status": row.status,
                "error_message": row.error_message,
                "started_at": row.started_at,
                "finished_at": row.finished_at,
            }
            for row in rows
        ]
