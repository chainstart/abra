"""链上监控数据模型。"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class DiscoveredContract:
    """新发现的链上合约。"""

    address: str
    block_number: int
    tx_hash: str
    creator: str
    source: str
    discovered_at: str

    def to_dict(self) -> dict[str, Any]:
        """输出可序列化字典。"""

        return {
            "address": self.address,
            "block_number": self.block_number,
            "tx_hash": self.tx_hash,
            "creator": self.creator,
            "source": self.source,
            "discovered_at": self.discovered_at,
        }


@dataclass(frozen=True)
class IndexedBlockSummary:
    """已索引区块摘要。"""

    block_number: int
    block_hash: str
    parent_hash: str
    timestamp: int
    tx_count: int
    indexed_at: str

    def to_dict(self) -> dict[str, Any]:
        """输出可序列化字典。"""

        return {
            "block_number": self.block_number,
            "block_hash": self.block_hash,
            "parent_hash": self.parent_hash,
            "timestamp": self.timestamp,
            "tx_count": self.tx_count,
            "indexed_at": self.indexed_at,
        }


@dataclass(frozen=True)
class IndexedTransactionSummary:
    """已索引交易摘要。"""

    tx_hash: str
    block_number: int
    tx_index: int
    from_address: str
    to_address: str | None
    contract_address: str | None
    selector: str | None
    selector_name: str | None
    value_wei: str
    status: int
    is_contract_creation: int

    def to_dict(self) -> dict[str, Any]:
        """输出可序列化字典。"""

        return {
            "tx_hash": self.tx_hash,
            "block_number": self.block_number,
            "tx_index": self.tx_index,
            "from_address": self.from_address,
            "to_address": self.to_address,
            "contract_address": self.contract_address,
            "selector": self.selector,
            "selector_name": self.selector_name,
            "value_wei": self.value_wei,
            "status": self.status,
            "is_contract_creation": self.is_contract_creation,
        }


@dataclass(frozen=True)
class IndexedLogSummary:
    """已索引日志摘要。"""

    log_key: str
    tx_hash: str
    block_number: int
    log_index: int
    address: str
    topic0: str | None
    topic0_name: str | None
    topic_count: int

    def to_dict(self) -> dict[str, Any]:
        """输出可序列化字典。"""

        return {
            "log_key": self.log_key,
            "tx_hash": self.tx_hash,
            "block_number": self.block_number,
            "log_index": self.log_index,
            "address": self.address,
            "topic0": self.topic0,
            "topic0_name": self.topic0_name,
            "topic_count": self.topic_count,
        }


@dataclass(frozen=True)
class MonitoringScanResult:
    """链上监控扫描结果。"""

    from_block: int
    to_block: int
    indexed_blocks: list[IndexedBlockSummary]
    indexed_transactions: list[IndexedTransactionSummary]
    indexed_logs: list[IndexedLogSummary]
    discovered_contracts: list[DiscoveredContract]
    auto_audit_task_ids: list[str]
    cursor_block: int | None = None

    def to_dict(self) -> dict[str, Any]:
        """输出可序列化字典。"""

        return {
            "from_block": self.from_block,
            "to_block": self.to_block,
            "indexed_blocks": [block.to_dict() for block in self.indexed_blocks],
            "indexed_transactions": [tx.to_dict() for tx in self.indexed_transactions],
            "indexed_logs": [log.to_dict() for log in self.indexed_logs],
            "discovered_contracts": [
                contract.to_dict() for contract in self.discovered_contracts
            ],
            "auto_audit_task_ids": self.auto_audit_task_ids,
            "cursor_block": self.cursor_block,
        }
