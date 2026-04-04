"""索引器状态接口测试。"""

from __future__ import annotations

from pathlib import Path
import sys
import unittest
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from services.api.handlers import handle_indexer_status_request  # noqa: E402


class IndexerStatusPhase12Test(unittest.TestCase):
    """验证索引器状态接口。"""

    def test_handle_indexer_status_request(self) -> None:
        """应返回状态和最近索引内容。"""

        with patch("services.api.handlers.get_indexer_status", return_value={"cursor_block": 100}):
            with patch("services.api.handlers.list_indexed_blocks", return_value=[{"block_number": 100}]):
                with patch("services.api.handlers.list_indexed_transactions", return_value=[{"tx_hash": "0xabc"}]):
                    with patch("services.api.handlers.list_indexed_logs", return_value=[{"log_key": "0xabc:0"}]):
                        response = handle_indexer_status_request({})

        self.assertIn("status", response)
        self.assertIn("recent_blocks", response)
        self.assertIn("recent_transactions", response)
        self.assertIn("recent_logs", response)


if __name__ == "__main__":
    unittest.main()
