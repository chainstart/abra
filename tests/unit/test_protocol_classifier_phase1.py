"""Phase 1 协议分类测试。"""

from __future__ import annotations

from pathlib import Path
import sys
import unittest


ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from services.analysis.contract_ingestion import ingest_contract_target  # noqa: E402
from services.analysis.protocol_classifier import classify_protocol  # noqa: E402


class ProtocolClassifierPhase1Test(unittest.TestCase):
    """验证当前启发式分类器的基本输出。"""

    def test_lending_fixture_can_be_classified(self) -> None:
        """借贷样例应被归类为 lending。"""

        target = ROOT / "tests" / "fixtures" / "LendingPoolPrototype.sol"
        ingestion = ingest_contract_target(str(target))
        classification = classify_protocol(ingestion)

        self.assertEqual(classification.protocol_type, "lending")
        self.assertIn(classification.confidence, {"medium", "high"})

    def test_amm_fixture_can_be_classified(self) -> None:
        """AMM 样例应被归类为 amm。"""

        target = ROOT / "tests" / "fixtures" / "AmmPoolPrototype.sol"
        ingestion = ingest_contract_target(str(target))
        classification = classify_protocol(ingestion)

        self.assertEqual(classification.protocol_type, "amm")
        self.assertIn(classification.confidence, {"medium", "high"})


if __name__ == "__main__":
    unittest.main()
