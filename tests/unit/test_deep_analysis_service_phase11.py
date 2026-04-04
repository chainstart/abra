"""深分析服务测试。"""

from __future__ import annotations

from pathlib import Path
import sys
import unittest


ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from services.analysis.deep_analysis_service import run_deep_analysis  # noqa: E402


class DeepAnalysisServicePhase11Test(unittest.TestCase):
    """验证深分析服务输出。"""

    def test_run_deep_analysis_returns_risk_hints(self) -> None:
        """深分析结果应包含结构摘要和风险提示。"""

        result = run_deep_analysis(
            str(ROOT / "tests" / "fixtures" / "CrossContractFlowPrototype.sol")
        )
        self.assertEqual(result.target_kind, "file")
        self.assertIn("cross_contract_call_edges", result.ast_summary)
        self.assertGreaterEqual(len(result.risk_hints), 1)


if __name__ == "__main__":
    unittest.main()
