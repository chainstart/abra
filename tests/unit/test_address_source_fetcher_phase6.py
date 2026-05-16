"""链上地址源码拉取测试。"""

from __future__ import annotations

import json
from pathlib import Path
import shutil
import sys
import unittest
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from services.analysis.address_source_fetcher import (  # noqa: E402
    ADDRESS_PATTERN,
    fetch_contract_source,
    is_contract_address,
)


class _FakeResponse:
    """模拟 urllib 响应。"""

    def __init__(self, payload: dict):
        self.payload = payload

    def read(self) -> bytes:
        return json.dumps(self.payload).encode("utf-8")

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        return False


class AddressSourceFetcherPhase6Test(unittest.TestCase):
    """验证地址源码拉取的最小行为。"""

    def setUp(self) -> None:
        self.output_dir = ROOT / "artifacts" / "fetched_sources" / "0x1234567890abcdef1234567890abcdef12345678"
        if self.output_dir.exists():
            shutil.rmtree(self.output_dir)

    def tearDown(self) -> None:
        if self.output_dir.exists():
            shutil.rmtree(self.output_dir)

    def test_is_contract_address(self) -> None:
        """地址识别应工作正常。"""

        self.assertTrue(is_contract_address("0x1234567890abcdef1234567890abcdef12345678"))
        self.assertFalse(is_contract_address("contracts/curve"))

    def test_fetch_contract_source_can_write_multifile_result(self) -> None:
        """多文件源码应被正确落地。"""

        payload = {
            "status": "1",
            "message": "OK",
            "result": [
                {
                    "ContractName": "MockVault",
                    "SourceCode": json.dumps(
                        {
                            "language": "Solidity",
                            "sources": {
                                "contracts/MockVault.sol": {
                                    "content": "// SPDX-License-Identifier: MIT\npragma solidity ^0.8.20;\ncontract MockVault {}"
                                }
                            }
                        }
                    ),
                }
            ],
        }
        with patch.dict("os.environ", {"ETHERSCAN_API_KEY": "dummy-key"}, clear=True):
            with patch("services.analysis.address_source_fetcher.request.urlopen", return_value=_FakeResponse(payload)):
                result = fetch_contract_source("0x1234567890abcdef1234567890abcdef12345678")

        self.assertEqual(result.contract_name, "MockVault")
        self.assertEqual(len(result.solidity_files), 1)
        self.assertTrue(result.solidity_files[0].exists())


if __name__ == "__main__":
    unittest.main()
