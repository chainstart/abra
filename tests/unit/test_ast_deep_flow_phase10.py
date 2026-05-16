"""深层 AST 数据流/控制流/跨合约分析测试。"""

from __future__ import annotations

from pathlib import Path
import sys
import unittest


ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from services.analysis.ast_semantic_analyzer import parse_ast_semantics  # noqa: E402


class AstDeepFlowPhase10Test(unittest.TestCase):
    """验证更深的分析能力。"""

    def test_cross_contract_call_and_write_after_external_are_detected(self) -> None:
        """应能识别跨合约调用边和外部调用后写状态。"""

        summary = parse_ast_semantics(
            [str(ROOT / "tests" / "fixtures" / "CrossContractFlowPrototype.sol")]
        )

        self.assertGreaterEqual(len(summary.cross_contract_call_edges), 1)
        first_edge = summary.cross_contract_call_edges[0]
        self.assertEqual(first_edge.target_contract, "IERC20Like")
        self.assertEqual(first_edge.target_function, "transfer")
        self.assertIn(
            "CrossContractFlowPrototype.withdraw",
            summary.write_after_external_functions,
        )


if __name__ == "__main__":
    unittest.main()
