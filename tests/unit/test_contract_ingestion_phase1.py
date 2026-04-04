"""Phase 1 合约接入测试。"""

from __future__ import annotations

from pathlib import Path
import sys
import unittest


ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from services.analysis.contract_ingestion import ingest_contract_target  # noqa: E402


class ContractIngestionPhase1Test(unittest.TestCase):
    """验证接入器能稳定处理文件与目录。"""

    def test_ingest_single_contract_file(self) -> None:
        """单文件接入应返回 file 类型。"""

        target = ROOT / "tests" / "fixtures" / "SimpleVault.sol"
        result = ingest_contract_target(str(target))

        self.assertEqual(result.target_kind, "file")
        self.assertEqual(result.solidity_file_count, 1)
        self.assertGreater(result.total_line_count, 0)

    def test_ingest_contract_directory(self) -> None:
        """目录接入应统计多个 Solidity 文件。"""

        target = ROOT / "tests" / "fixtures"
        result = ingest_contract_target(str(target))

        self.assertEqual(result.target_kind, "directory")
        self.assertGreaterEqual(result.solidity_file_count, 3)


if __name__ == "__main__":
    unittest.main()
