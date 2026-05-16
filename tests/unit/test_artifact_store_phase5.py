"""归档服务测试。"""

from __future__ import annotations

from pathlib import Path
import shutil
import sys
import unittest
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from services.agent.task_orchestrator import run_audit_task, run_research_task  # noqa: E402
from services.storage.artifact_store import save_task_result  # noqa: E402
from tools.analyzers.base import Severity  # noqa: E402


class ArtifactStorePhase5Test(unittest.TestCase):
    """验证任务结果可以稳定归档。"""

    def setUp(self) -> None:
        self.tmp_root = ROOT / "tests" / ".tmp_artifacts"
        self.db_path = self.tmp_root / "task_results.sqlite3"
        if self.tmp_root.exists():
            shutil.rmtree(self.tmp_root)

    def tearDown(self) -> None:
        if self.tmp_root.exists():
            shutil.rmtree(self.tmp_root)

    def test_save_task_result_writes_expected_files(self) -> None:
        """默认最小工件模式下，审计任务应只落下主结果 JSON。"""

        task_result = run_audit_task(
            target=str(ROOT / "tests" / "fixtures" / "LendingPoolPrototype.sol"),
            analyzer_names=["access-control", "reentrancy"],
            minimum_severity=Severity.INFO,
        )
        with patch.dict("os.environ", {"SAVE_VERBOSE_ARTIFACTS": "false"}, clear=False):
            task_dir = save_task_result(task_result, root_dir=self.tmp_root, db_path=self.db_path)

        self.assertTrue((task_dir / "task_result.json").exists())
        self.assertFalse((task_dir / "audit_report.md").exists())

    def test_save_research_task_writes_workspace_files(self) -> None:
        """默认最小工件模式下，研究任务不应展开写出一堆派生文件。"""

        with patch.dict("os.environ", {"RESEARCH_LLM_ENABLED": "false"}, clear=False):
            task_result = run_research_task(
                target=str(ROOT / "contracts" / "curve"),
                analyzer_names=["reentrancy"],
                minimum_severity=Severity.INFO,
            )
        with patch.dict("os.environ", {"SAVE_VERBOSE_ARTIFACTS": "false"}, clear=False):
            task_dir = save_task_result(task_result, root_dir=self.tmp_root, db_path=self.db_path)

        self.assertTrue((task_dir / "task_result.json").exists())
        self.assertFalse((task_dir / "research_memo.md").exists())
        self.assertFalse((task_dir / "research_presentation.json").exists())
        self.assertFalse((task_dir / "research_result.json").exists())
        self.assertFalse((task_dir / "evidence_assessment.json").exists())
        self.assertFalse((task_dir / "claim_graph.json").exists())
        self.assertFalse((task_dir / "paper_draft.md").exists())

    def test_save_task_result_can_write_verbose_files_when_enabled(self) -> None:
        """显式开启详细模式时，仍应展开写出派生工件。"""

        task_result = run_audit_task(
            target=str(ROOT / "tests" / "fixtures" / "LendingPoolPrototype.sol"),
            analyzer_names=["access-control", "reentrancy"],
            minimum_severity=Severity.INFO,
        )
        with patch.dict("os.environ", {"SAVE_VERBOSE_ARTIFACTS": "true"}, clear=False):
            task_dir = save_task_result(task_result, root_dir=self.tmp_root, db_path=self.db_path)

        self.assertTrue((task_dir / "task_result.json").exists())
        self.assertTrue((task_dir / "audit_report.md").exists())


if __name__ == "__main__":
    unittest.main()
