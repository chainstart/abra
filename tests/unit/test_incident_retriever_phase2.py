"""历史攻击案例检索测试。"""

from __future__ import annotations

from pathlib import Path
import sys
import unittest


ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from services.analysis.contract_ingestion import ingest_contract_target  # noqa: E402
from services.analysis.protocol_classifier import classify_protocol  # noqa: E402
from services.analysis.static_analysis_pipeline import run_static_analysis  # noqa: E402
from services.research.incident_retriever import find_related_incidents  # noqa: E402
from tools.analyzers.base import Severity  # noqa: E402


class IncidentRetrieverPhase2Test(unittest.TestCase):
    """验证相似案例检索能返回合理结果。"""

    def test_reentrancy_like_target_can_match_curve_case(self) -> None:
        """AMM + 重入信号应优先匹配 Curve 重入案例。"""

        target = ROOT / "contracts" / "curve"
        ingestion = ingest_contract_target(str(target))
        classification = classify_protocol(ingestion)
        scan_report = run_static_analysis(
            target=str(target),
            analyzer_names=["reentrancy"],
            minimum_severity=Severity.INFO,
        )
        matches = find_related_incidents(
            classification=classification,
            findings=scan_report.findings,
        )

        self.assertGreater(len(matches), 0)
        self.assertEqual(matches[0].incident.incident_id, "curve_reentrancy_2023")


if __name__ == "__main__":
    unittest.main()
