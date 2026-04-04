"""统一数据库后端。

设计目标：

- 默认用 SQLite，保证本地即开即用
- 配置 `DATABASE_URL` 时可切 PostgreSQL
- 上层不关心具体数据库驱动
"""

from __future__ import annotations

from contextlib import contextmanager
from pathlib import Path
from typing import Iterator

from sqlalchemy import Integer, String, Text, create_engine, text
from sqlalchemy.orm import DeclarativeBase, Mapped, Session, mapped_column, sessionmaker

from services.shared.settings import ProjectSettings


class Base(DeclarativeBase):
    """SQLAlchemy 声明式基类。"""


class TaskRunModel(Base):
    """任务运行索引。"""

    __tablename__ = "task_runs"

    task_id: Mapped[str] = mapped_column(String(255), primary_key=True)
    task_type: Mapped[str] = mapped_column(String(64), nullable=False)
    target: Mapped[str] = mapped_column(Text, nullable=False)
    status: Mapped[str] = mapped_column(String(64), nullable=False)
    artifact_dir: Mapped[str] = mapped_column(Text, nullable=False)
    created_at: Mapped[str] = mapped_column(String(64), nullable=False)


class DiscoveredContractModel(Base):
    """新发现合约索引。"""

    __tablename__ = "discovered_contracts"

    address: Mapped[str] = mapped_column(String(64), primary_key=True)
    block_number: Mapped[int] = mapped_column(Integer, nullable=False)
    tx_hash: Mapped[str] = mapped_column(String(128), nullable=False)
    creator: Mapped[str] = mapped_column(String(64), nullable=False)
    source: Mapped[str] = mapped_column(String(64), nullable=False)
    discovered_at: Mapped[str] = mapped_column(String(64), nullable=False)


class MonitorStateModel(Base):
    """链上监控游标。"""

    __tablename__ = "monitor_state"

    state_key: Mapped[str] = mapped_column(String(64), primary_key=True)
    state_value: Mapped[str] = mapped_column(Text, nullable=False)
    updated_at: Mapped[str] = mapped_column(String(64), nullable=False)


class IndexedBlockModel(Base):
    """已索引区块。"""

    __tablename__ = "indexed_blocks"

    block_number: Mapped[int] = mapped_column(Integer, primary_key=True)
    block_hash: Mapped[str] = mapped_column(String(128), nullable=False)
    parent_hash: Mapped[str] = mapped_column(String(128), nullable=False)
    timestamp: Mapped[int] = mapped_column(Integer, nullable=False)
    tx_count: Mapped[int] = mapped_column(Integer, nullable=False)
    indexed_at: Mapped[str] = mapped_column(String(64), nullable=False)


class IndexedTransactionModel(Base):
    """已索引交易。"""

    __tablename__ = "indexed_transactions"

    tx_hash: Mapped[str] = mapped_column(String(128), primary_key=True)
    block_number: Mapped[int] = mapped_column(Integer, nullable=False)
    tx_index: Mapped[int] = mapped_column(Integer, nullable=False)
    from_address: Mapped[str] = mapped_column(String(64), nullable=False)
    to_address: Mapped[str] = mapped_column(String(64), nullable=True)
    contract_address: Mapped[str] = mapped_column(String(64), nullable=True)
    selector: Mapped[str] = mapped_column(String(16), nullable=True)
    selector_name: Mapped[str] = mapped_column(String(255), nullable=True)
    value_wei: Mapped[str] = mapped_column(String(128), nullable=False)
    status: Mapped[int] = mapped_column(Integer, nullable=False)
    is_contract_creation: Mapped[int] = mapped_column(Integer, nullable=False)


class IndexedLogModel(Base):
    """已索引日志。"""

    __tablename__ = "indexed_logs"

    log_key: Mapped[str] = mapped_column(String(255), primary_key=True)
    tx_hash: Mapped[str] = mapped_column(String(128), nullable=False)
    block_number: Mapped[int] = mapped_column(Integer, nullable=False)
    log_index: Mapped[int] = mapped_column(Integer, nullable=False)
    address: Mapped[str] = mapped_column(String(64), nullable=False)
    topic0: Mapped[str] = mapped_column(String(128), nullable=True)
    topic0_name: Mapped[str] = mapped_column(String(255), nullable=True)
    topic_count: Mapped[int] = mapped_column(Integer, nullable=False)


class SignatureCacheModel(Base):
    """签名缓存。

    用于缓存：

    - 4-byte selector -> 函数签名
    - topic0 -> 事件签名
    """

    __tablename__ = "signature_cache"

    cache_key: Mapped[str] = mapped_column(String(128), primary_key=True)
    kind: Mapped[str] = mapped_column(String(32), nullable=False)
    text_signature: Mapped[str] = mapped_column(Text, nullable=False)
    source: Mapped[str] = mapped_column(String(64), nullable=False)
    updated_at: Mapped[str] = mapped_column(String(64), nullable=False)


class IndexRunModel(Base):
    """索引运行记录。"""

    __tablename__ = "index_runs"

    run_id: Mapped[str] = mapped_column(String(128), primary_key=True)
    mode: Mapped[str] = mapped_column(String(32), nullable=False)
    from_block: Mapped[int] = mapped_column(Integer, nullable=False)
    to_block: Mapped[int] = mapped_column(Integer, nullable=False)
    indexed_block_count: Mapped[int] = mapped_column(Integer, nullable=False)
    indexed_transaction_count: Mapped[int] = mapped_column(Integer, nullable=False)
    indexed_log_count: Mapped[int] = mapped_column(Integer, nullable=False)
    discovered_contract_count: Mapped[int] = mapped_column(Integer, nullable=False)
    status: Mapped[str] = mapped_column(String(32), nullable=False)
    error_message: Mapped[str] = mapped_column(Text, nullable=True)
    started_at: Mapped[str] = mapped_column(String(64), nullable=False)
    finished_at: Mapped[str] = mapped_column(String(64), nullable=False)


class IncidentModel(Base):
    """结构化历史案例。"""

    __tablename__ = "incidents"

    incident_id: Mapped[str] = mapped_column(String(255), primary_key=True)
    title: Mapped[str] = mapped_column(Text, nullable=False)
    protocol_name: Mapped[str] = mapped_column(String(128), nullable=False)
    protocol_type: Mapped[str] = mapped_column(String(64), nullable=False)
    year: Mapped[int] = mapped_column(Integer, nullable=False)
    summary: Mapped[str] = mapped_column(Text, nullable=False)
    root_cause: Mapped[str] = mapped_column(Text, nullable=False)
    attack_patterns: Mapped[str] = mapped_column(Text, nullable=False)
    affected_categories: Mapped[str] = mapped_column(Text, nullable=False)
    keywords: Mapped[str] = mapped_column(Text, nullable=False)
    source_reports: Mapped[str] = mapped_column(Text, nullable=False)
    evidence_payload: Mapped[str] = mapped_column(Text, nullable=False, default="{}")


def _ensure_sqlite_parent(database_url: str) -> None:
    """为 SQLite 路径自动创建父目录。"""

    prefix = "sqlite:///"
    if not database_url.startswith(prefix):
        return
    path = Path(database_url.removeprefix(prefix))
    path.parent.mkdir(parents=True, exist_ok=True)


def get_engine(database_url: str | None = None):
    """返回 SQLAlchemy engine。"""

    settings = ProjectSettings.from_env()
    resolved_url = database_url or settings.database_url
    _ensure_sqlite_parent(resolved_url)
    return create_engine(resolved_url, future=True)


def initialize_database(database_url: str | None = None):
    """初始化数据库表结构。"""

    engine = get_engine(database_url)
    Base.metadata.create_all(engine)
    _run_compat_migrations(engine)
    return engine


def _run_compat_migrations(engine) -> None:
    """执行轻量兼容迁移。

    当前项目已经有历史 SQLite 文件，因此仅依赖 `create_all()` 不够。
    这里补一层最小迁移逻辑，保证新增列和新增表在旧库上也能出现。
    """

    with engine.begin() as conn:
        dialect = conn.dialect.name

        # SQLAlchemy 的 create_all 会创建新表，但不会给旧表补列。
        # 所以下面只处理“旧表缺新列”的情况。
        if dialect == "sqlite":
            existing_columns = {
                row[1]
                for row in conn.exec_driver_sql("PRAGMA table_info(indexed_transactions)")
            }
            if existing_columns and "selector_name" not in existing_columns:
                conn.exec_driver_sql(
                    "ALTER TABLE indexed_transactions ADD COLUMN selector_name VARCHAR(255)"
                )

            existing_columns = {
                row[1]
                for row in conn.exec_driver_sql("PRAGMA table_info(indexed_logs)")
            }
            if existing_columns and "topic0_name" not in existing_columns:
                conn.exec_driver_sql(
                    "ALTER TABLE indexed_logs ADD COLUMN topic0_name VARCHAR(255)"
                )

            existing_columns = {
                row[1]
                for row in conn.exec_driver_sql("PRAGMA table_info(incidents)")
            }
            if existing_columns and "evidence_payload" not in existing_columns:
                conn.exec_driver_sql(
                    "ALTER TABLE incidents ADD COLUMN evidence_payload TEXT NOT NULL DEFAULT '{}'"
                )
        else:
            # PostgreSQL 路径：使用 IF NOT EXISTS，避免重复报错。
            conn.execute(
                text(
                    "ALTER TABLE IF EXISTS indexed_transactions "
                    "ADD COLUMN IF NOT EXISTS selector_name VARCHAR(255)"
                )
            )
            conn.execute(
                text(
                    "ALTER TABLE IF EXISTS indexed_logs "
                    "ADD COLUMN IF NOT EXISTS topic0_name VARCHAR(255)"
                )
            )
            conn.execute(
                text(
                    "ALTER TABLE IF EXISTS incidents "
                    "ADD COLUMN IF NOT EXISTS evidence_payload TEXT NOT NULL DEFAULT '{}'"
                )
            )


@contextmanager
def session_scope(database_url: str | None = None) -> Iterator[Session]:
    """统一 session 生命周期。"""

    engine = initialize_database(database_url)
    session_factory = sessionmaker(bind=engine, future=True)
    session = session_factory()
    try:
        yield session
        session.commit()
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()
