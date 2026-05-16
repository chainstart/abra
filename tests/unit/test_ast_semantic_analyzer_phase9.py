"""AST 语义分析测试。"""

from __future__ import annotations

from pathlib import Path
import sys
import unittest


ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from services.analysis.ast_semantic_analyzer import parse_ast_semantics  # noqa: E402


class AstSemanticAnalyzerPhase9Test(unittest.TestCase):
    """验证 AST 级语义分析。"""

    def test_parse_ast_semantics_extracts_function_graph(self) -> None:
        """应能提取合约、函数和状态变量信息。"""

        summary = parse_ast_semantics(
            [str(ROOT / "tests" / "fixtures" / "LendingPoolPrototype.sol")]
        )
        self.assertIn("LendingPoolPrototype", summary.contract_names)
        self.assertIn("collateral", summary.state_variables)
        self.assertGreaterEqual(len(summary.functions), 4)
        function_names = [function.name for function in summary.functions]
        self.assertIn("withdraw", function_names)


if __name__ == "__main__":
    unittest.main()
