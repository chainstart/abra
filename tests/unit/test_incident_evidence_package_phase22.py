"""攻击事件结构化证据包测试。"""

from __future__ import annotations

import json
from pathlib import Path
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from services.research.incident_evidence_service import build_incident_evidence_package  # noqa: E402
from services.research.incident_repository import normalize_incident_dict  # noqa: E402
from services.research.models import IncidentRecord  # noqa: E402
from services.storage.task_database import save_indexed_logs, save_indexed_transactions  # noqa: E402


class IncidentEvidencePackagePhase22Test(unittest.TestCase):
    """验证 incident -> evidence package 的转换。"""

    def _load_incident(self, file_name: str) -> IncidentRecord:
        path = ROOT / "research" / "incidents" / file_name
        raw = json.loads(path.read_text(encoding="utf-8"))
        normalized = normalize_incident_dict(raw)
        return IncidentRecord(**normalized)

    def test_morpho_incident_keeps_structured_onchain_payload(self) -> None:
        """Morpho 案例应包含链、关键交易和时间线。"""

        incident = self._load_incident("morpho_blue_oracle_misconfig_2024.json")
        package = build_incident_evidence_package(incident)

        self.assertEqual(package.chain, "ethereum")
        self.assertGreaterEqual(len(package.attack_transactions), 1)
        self.assertEqual(
            package.attack_transactions[0].tx_hash,
            "0x256979ae169abb7fbbbbc14188742f4b9debf48b48ad5b5207cadcc99ccb493b",
        )
        self.assertGreaterEqual(len(package.timeline), 3)
        self.assertIn("损失:", " ".join(package.evidence_summary))

    def test_evidence_package_can_enrich_from_indexed_transaction_and_logs(self) -> None:
        """若本地已索引相关交易和日志，证据包应自动补齐链上细节。"""

        incident = self._load_incident("morpho_blue_oracle_misconfig_2024.json")

        with tempfile.TemporaryDirectory() as tmp_dir:
            db_path = Path(tmp_dir) / "task_results.sqlite3"
            save_indexed_transactions(
                [
                    {
                        "tx_hash": "0x256979ae169abb7fbbbbc14188742f4b9debf48b48ad5b5207cadcc99ccb493b",
                        "block_number": 20933123,
                        "tx_index": 3,
                        "from_address": "0x02DBe46169fDf6555F2A125eEe3dce49703b13f5",
                        "to_address": "0xBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB",
                        "contract_address": None,
                        "selector": "0x4b8a3529",
                        "selector_name": "borrow(address,address,uint256,uint256,address,address)",
                        "value_wei": "0",
                        "status": 1,
                        "is_contract_creation": 0,
                    }
                ],
                db_path=db_path,
            )
            save_indexed_logs(
                [
                    {
                        "log_key": "0x256979ae169abb7fbbbbc14188742f4b9debf48b48ad5b5207cadcc99ccb493b:1",
                        "tx_hash": "0x256979ae169abb7fbbbbc14188742f4b9debf48b48ad5b5207cadcc99ccb493b",
                        "block_number": 20933123,
                        "log_index": 1,
                        "address": "0xCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC",
                        "topic0": "0xddf252ad",
                        "topic0_name": "Transfer(address,address,uint256)",
                        "topic_count": 3,
                    }
                ],
                db_path=db_path,
            )

            package = build_incident_evidence_package(incident, db_path=db_path)

        self.assertEqual(package.indexed_transaction_count, 1)
        self.assertEqual(package.indexed_log_count, 1)
        self.assertTrue(package.attack_transactions[0].indexed)
        self.assertEqual(
            package.attack_transactions[0].selector_name,
            "borrow(address,address,uint256,uint256,address,address)",
        )
        self.assertEqual(package.attack_transactions[0].indexed_log_count, 1)


if __name__ == "__main__":
    unittest.main()
