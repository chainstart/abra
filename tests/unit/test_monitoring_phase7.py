"""链上索引与监控测试。"""

from __future__ import annotations

from pathlib import Path
import shutil
import sys
import unittest
import uuid
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from services.monitoring.rpc_monitor import (  # noqa: E402
    index_block_range,
    run_monitor_cycle,
)
from services.storage.task_database import (  # noqa: E402
    get_indexer_status,
    list_indexed_blocks,
    list_indexed_logs,
    list_indexed_transactions,
    load_monitor_state,
)


class MonitoringPhase7Test(unittest.TestCase):
    """验证持续链上索引。"""

    def setUp(self) -> None:
        self.tmp_dir = ROOT / "tests" / f".tmp_monitor_{uuid.uuid4().hex[:8]}"
        self.tmp_dir.mkdir(parents=True, exist_ok=True)
        self.tmp_db = self.tmp_dir / "monitor.sqlite3"

    def tearDown(self) -> None:
        if self.tmp_dir.exists():
            shutil.rmtree(self.tmp_dir)

    def test_index_block_range_persists_blocks_transactions_and_logs(self) -> None:
        """区块范围索引应写入块、交易和日志。"""

        responses = {
            "eth_getBlockByNumber:0x64": {
                "result": {
                    "hash": "0xblock100",
                    "parentHash": "0xblock99",
                    "timestamp": hex(1710000000),
                    "transactions": [
                        {
                            "hash": "0xabc",
                            "from": "0xcreator",
                            "to": None,
                            "transactionIndex": hex(0),
                            "input": "0x60806040",
                            "value": hex(0),
                        }
                    ],
                }
            },
            "eth_getTransactionReceipt:0xabc": {
                "result": {
                    "status": hex(1),
                    "contractAddress": "0x1234567890abcdef1234567890abcdef12345678",
                    "logs": [
                        {
                            "logIndex": hex(0),
                            "address": "0xfeedfeedfeedfeedfeedfeedfeedfeedfeedfeed",
                            "topics": ["0xtopic0", "0xtopic1"],
                        }
                    ],
                }
            },
        }

        def fake_rpc_call(rpc_url: str, method: str, params: list):
            if method == "eth_getBlockByNumber":
                return responses[f"eth_getBlockByNumber:{params[0]}"]
            if method == "eth_getTransactionReceipt":
                return responses[f"eth_getTransactionReceipt:{params[0]}"]
            raise AssertionError(f"unexpected rpc call: {method}")

        with patch("services.monitoring.rpc_monitor._rpc_call", side_effect=fake_rpc_call):
            result = index_block_range(
                from_block=100,
                to_block=100,
                rpc_url="https://example-rpc",
                save_to_db=True,
                db_path=self.tmp_db,
            )

        self.assertEqual(result.from_block, 100)
        self.assertEqual(result.to_block, 100)
        self.assertEqual(len(result.indexed_blocks), 1)
        self.assertEqual(len(result.indexed_transactions), 1)
        self.assertEqual(len(result.indexed_logs), 1)
        self.assertEqual(len(result.discovered_contracts), 1)

        blocks = list_indexed_blocks(limit=10, db_path=self.tmp_db)
        txs = list_indexed_transactions(limit=10, db_path=self.tmp_db)
        logs = list_indexed_logs(limit=10, db_path=self.tmp_db)
        self.assertEqual(len(blocks), 1)
        self.assertEqual(len(txs), 1)
        self.assertEqual(len(logs), 1)

    def test_run_monitor_cycle_updates_cursor(self) -> None:
        """监控循环应推进游标。"""

        responses = {
            "eth_blockNumber": {"result": hex(100)},
            "eth_getBlockByNumber:0x64": {
                "result": {
                    "hash": "0xblock100",
                    "parentHash": "0xblock99",
                    "timestamp": hex(1710000000),
                    "transactions": [],
                }
            },
        }

        def fake_rpc_call(rpc_url: str, method: str, params: list):
            if method == "eth_blockNumber":
                return responses["eth_blockNumber"]
            if method == "eth_getBlockByNumber":
                return responses[f"eth_getBlockByNumber:{params[0]}"]
            raise AssertionError(f"unexpected rpc call: {method}")

        with patch("services.monitoring.rpc_monitor._rpc_call", side_effect=fake_rpc_call):
            result = run_monitor_cycle(
                initial_lookback=1,
                max_blocks_per_cycle=1,
                rpc_url="https://example-rpc",
                state_key="test_monitor_cursor",
                db_path=self.tmp_db,
            )

        self.assertEqual(result.cursor_block, 100)
        cursor = load_monitor_state("test_monitor_cursor", db_path=self.tmp_db)
        self.assertEqual(cursor, "100")

    def test_index_block_range_can_auto_enqueue_audit(self) -> None:
        """发现新合约时应支持自动送审计。"""

        responses = {
            "eth_getBlockByNumber:0x64": {
                "result": {
                    "hash": "0xblock100",
                    "parentHash": "0xblock99",
                    "timestamp": hex(1710000000),
                    "transactions": [
                        {
                            "hash": "0xabc",
                            "from": "0xcreator",
                            "to": None,
                            "transactionIndex": hex(0),
                            "input": "0x60806040",
                            "value": hex(0),
                        }
                    ],
                }
            },
            "eth_getTransactionReceipt:0xabc": {
                "result": {
                    "status": hex(1),
                    "contractAddress": "0x1234567890abcdef1234567890abcdef12345678",
                    "logs": [],
                }
            },
        }

        def fake_rpc_call(rpc_url: str, method: str, params: list):
            if method == "eth_getBlockByNumber":
                return responses[f"eth_getBlockByNumber:{params[0]}"]
            if method == "eth_getTransactionReceipt":
                return responses[f"eth_getTransactionReceipt:{params[0]}"]
            raise AssertionError(f"unexpected rpc call: {method}")

        fake_task_result = type(
            "TaskResult",
            (),
            {
                "task_type": "audit",
                "target": "0x1234567890abcdef1234567890abcdef12345678",
                "status": "completed",
                "payload": {},
                "steps": [],
                "to_dict": lambda self: {"task_type": "audit"},
            },
        )()

        with patch("services.monitoring.rpc_monitor._rpc_call", side_effect=fake_rpc_call):
            with patch("services.monitoring.rpc_monitor.run_audit_task", return_value=fake_task_result):
                with patch("services.monitoring.rpc_monitor.save_task_result") as save_task_mock:
                    save_task_mock.return_value = ROOT / "artifacts" / "tasks" / "mock_audit_task"
                    result = index_block_range(
                        from_block=100,
                        to_block=100,
                        rpc_url="https://example-rpc",
                        save_to_db=True,
                        auto_enqueue_audit=True,
                        db_path=self.tmp_db,
                    )

        self.assertEqual(result.auto_audit_task_ids, ["mock_audit_task"])


if __name__ == "__main__":
    unittest.main()
