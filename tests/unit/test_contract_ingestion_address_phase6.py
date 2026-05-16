"""地址输入接入测试。"""

from __future__ import annotations

from pathlib import Path
import shutil
import sys
import unittest
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from services.analysis.address_source_fetcher import FetchedSourceLayout  # noqa: E402
from services.analysis.contract_ingestion import ingest_contract_target  # noqa: E402


class ContractIngestionAddressPhase6Test(unittest.TestCase):
    """验证输入链上地址时也能走接入逻辑。"""

    def setUp(self) -> None:
        self.tmp_root = ROOT / "tests" / ".tmp_fetched"
        if self.tmp_root.exists():
            shutil.rmtree(self.tmp_root)
        self.tmp_root.mkdir(parents=True, exist_ok=True)
        self.source_file = self.tmp_root / "MockVault.sol"
        self.source_file.write_text(
            "// SPDX-License-Identifier: MIT\npragma solidity ^0.8.20;\ncontract MockVault {}",
            encoding="utf-8",
        )

    def tearDown(self) -> None:
        if self.tmp_root.exists():
            shutil.rmtree(self.tmp_root)

    def test_ingest_address_uses_fetched_source_layout(self) -> None:
        """地址输入应转成 fetched source 的接入结果。"""

        fetched = FetchedSourceLayout(
            address="0x1234567890abcdef1234567890abcdef12345678",
            contract_name="MockVault",
            root_dir=self.tmp_root,
            solidity_files=[self.source_file],
        )
        with patch("services.analysis.contract_ingestion.fetch_contract_source", return_value=fetched):
            result = ingest_contract_target("0x1234567890abcdef1234567890abcdef12345678")

        self.assertEqual(result.target_kind, "address")
        self.assertEqual(result.solidity_file_count, 1)
        self.assertGreater(result.total_line_count, 0)


if __name__ == "__main__":
    unittest.main()
