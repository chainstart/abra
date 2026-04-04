"""索引运行记录测试。"""

from __future__ import annotations

from pathlib import Path
import sys
import unittest


ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from services.storage.task_database import list_index_runs  # noqa: E402


class IndexRunsPhase13Test(unittest.TestCase):
    """验证索引运行记录读取接口。"""

    def test_list_index_runs_returns_list(self) -> None:
        """即使为空也应该稳定返回数组。"""

        rows = list_index_runs(limit=10)
        self.assertIsInstance(rows, list)


if __name__ == "__main__":
    unittest.main()
