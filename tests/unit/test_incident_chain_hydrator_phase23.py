"""攻击事件链上富化测试。"""

from __future__ import annotations

import io
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from services.research.incident_chain_hydrator import hydrate_incident_chain_evidence  # noqa: E402


class _FakeHttpResponse(io.BytesIO):
    """最小 HTTP 响应桩。"""

    def __enter__(self) -> "_FakeHttpResponse":
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        return None


class IncidentChainHydratorPhase23Test(unittest.TestCase):
    """验证 incident 交易富化。"""

    def test_hydrate_incident_chain_evidence_can_fetch_and_store_transactions(self) -> None:
        """给定攻击交易哈希后，应能通过 RPC 获取交易、receipt 和 block。"""

        tx_hash = "0x256979ae169abb7fbbbbc14188742f4b9debf48b48ad5b5207cadcc99ccb493b"

        def fake_urlopen(req, timeout=0):  # noqa: ANN001
            payload = json.loads(req.data.decode("utf-8"))
            method = payload["method"]
            params = payload["params"]
            if method == "eth_getTransactionByHash":
                body = {
                    "jsonrpc": "2.0",
                    "id": 1,
                    "result": {
                        "hash": tx_hash,
                        "blockNumber": hex(20933123),
                        "transactionIndex": hex(3),
                        "from": "0x02DBe46169fDf6555F2A125eEe3dce49703b13f5",
                        "to": "0xBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB",
                        "input": "0x4b8a352900000000",
                        "value": "0x0",
                    },
                }
            elif method == "eth_getTransactionReceipt":
                body = {
                    "jsonrpc": "2.0",
                    "id": 1,
                    "result": {
                        "transactionHash": tx_hash,
                        "blockNumber": hex(20933123),
                        "status": hex(1),
                        "contractAddress": None,
                        "logs": [
                            {
                                "logIndex": hex(1),
                                "address": "0xCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC",
                                "topics": [
                                    "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef"
                                ],
                            }
                        ],
                    },
                }
            elif method == "eth_getBlockByNumber":
                self.assertEqual(params[0], hex(20933123))
                body = {
                    "jsonrpc": "2.0",
                    "id": 1,
                    "result": {
                        "hash": "0xabc",
                        "parentHash": "0xdef",
                        "timestamp": hex(1728777600),
                        "transactions": [tx_hash],
                    },
                }
            else:
                raise AssertionError(f"unexpected rpc method: {method}")
            return _FakeHttpResponse(json.dumps(body).encode("utf-8"))

        with tempfile.TemporaryDirectory() as tmp_dir, patch.dict(
            "os.environ",
            {
                "RESEARCH_LLM_ENABLED": "false",
                "DATABASE_URL": f"sqlite:///{Path(tmp_dir) / 'task_results.sqlite3'}",
                "ETH_RPC_URL": "https://rpc.example",
            },
            clear=False,
        ), patch("urllib.request.urlopen", side_effect=fake_urlopen), patch(
            "services.research.incident_chain_hydrator.resolve_function_selector",
            return_value="borrow(address,address,uint256,uint256,address,address)",
        ):
            result = hydrate_incident_chain_evidence(
                incident_id="morpho_blue_oracle_misconfig_2024",
                rpc_url="https://rpc.example",
            )

        self.assertEqual(result["indexed_transaction_count"], 1)
        self.assertEqual(result["indexed_log_count"], 1)
        self.assertEqual(result["processed_incident_ids"], ["morpho_blue_oracle_misconfig_2024"])
        self.assertEqual(len(result["evidence_packages"]), 1)
        self.assertEqual(
            result["evidence_packages"][0]["attack_transactions"][0]["selector_name"],
            "borrow(address,address,uint256,uint256,address,address)",
        )


if __name__ == "__main__":
    unittest.main()
