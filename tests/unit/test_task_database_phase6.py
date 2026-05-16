"""任务数据库测试。"""

from __future__ import annotations

from pathlib import Path
import shutil
import sys
import unittest


ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from services.agent.task_orchestrator import run_audit_task  # noqa: E402
from services.storage.artifact_store import save_task_result  # noqa: E402
from services.storage.task_database import initialize_task_db, list_task_index  # noqa: E402
from tools.analyzers.base import Severity  # noqa: E402


class TaskDatabasePhase6Test(unittest.TestCase):
    """验证 SQLite 任务索引。"""

    def setUp(self) -> None:
        self.tmp_root = ROOT / "tests" / ".tmp_task_db"
        if self.tmp_root.exists():
            shutil.rmtree(self.tmp_root)
        self.tmp_root.mkdir(parents=True, exist_ok=True)
        self.db_path = self.tmp_root / "task_results.sqlite3"

    def tearDown(self) -> None:
        if self.tmp_root.exists():
            shutil.rmtree(self.tmp_root)

    def test_initialize_and_list_task_index(self) -> None:
        """保存任务后应能从数据库读回索引。"""

        initialize_task_db(self.db_path)
        task_result = run_audit_task(
            target=str(ROOT / "tests" / "fixtures" / "LendingPoolPrototype.sol"),
            analyzer_names=["access-control", "reentrancy"],
            minimum_severity=Severity.INFO,
        )
        save_task_result(
            task_result,
            root_dir=self.tmp_root / "artifacts",
            db_path=self.db_path,
        )

        rows = list_task_index(db_path=self.db_path)
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["task_type"], "audit")


if __name__ == "__main__":
    unittest.main()
