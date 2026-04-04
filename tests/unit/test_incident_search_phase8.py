"""历史案例搜索测试。"""

from __future__ import annotations

from pathlib import Path
import sys
import unittest


ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from services.research.incident_repository import load_incidents  # noqa: E402
from services.storage.task_database import search_incidents  # noqa: E402


class IncidentSearchPhase8Test(unittest.TestCase):
    """验证案例检索层。"""

    def test_search_incidents_can_find_reentrancy_case(self) -> None:
        """搜索 reentrancy 应命中 Curve 案例。"""

        load_incidents(ROOT / "research" / "incidents")
        results = search_incidents("reentrancy", limit=10)
        self.assertGreater(len(results), 0)
        self.assertEqual(results[0]["incident_id"], "curve_reentrancy_2023")

    def test_search_incidents_can_find_attack_transaction_hash(self) -> None:
        """搜索攻击交易哈希应命中对应 incident。"""

        load_incidents(ROOT / "research" / "incidents")
        results = search_incidents(
            "0x256979ae169abb7fbbbbc14188742f4b9debf48b48ad5b5207cadcc99ccb493b",
            limit=10,
        )
        self.assertGreater(len(results), 0)
        self.assertEqual(results[0]["incident_id"], "morpho_blue_oracle_misconfig_2024")


if __name__ == "__main__":
    unittest.main()
