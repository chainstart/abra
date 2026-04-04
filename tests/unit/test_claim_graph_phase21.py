"""Claim 图谱测试。"""

from __future__ import annotations

from pathlib import Path
import sys
import unittest
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from tools.analyzers.base import Severity  # noqa: E402
from services.research.research_workflow_service import run_research_workflow  # noqa: E402


class ClaimGraphPhase21Test(unittest.TestCase):
    """验证 claim-to-evidence 图谱。"""

    def test_workflow_contains_claim_graph(self) -> None:
        """研究工作流结果应包含 claim 图谱。"""

        with patch.dict("os.environ", {"RESEARCH_LLM_ENABLED": "false"}, clear=False):
            result = run_research_workflow(
                target=str(ROOT / "contracts" / "curve"),
                analyzer_names=["reentrancy"],
                minimum_severity=Severity.INFO,
            )

        self.assertIsNotNone(result.claim_graph)
        self.assertGreaterEqual(len(result.claim_graph.claim_nodes), 1)
        self.assertGreaterEqual(len(result.claim_graph.edges), 1)
        self.assertTrue(result.claim_graph.summary)


if __name__ == "__main__":
    unittest.main()
