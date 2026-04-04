"""研究工作流测试。"""

from __future__ import annotations

from pathlib import Path
import sys
import unittest
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from tools.analyzers.base import Severity  # noqa: E402
from services.analysis.audit_service import run_audit  # noqa: E402
from services.research.paper_draft_writer import render_paper_draft  # noqa: E402
from services.research.research_idea_generator import generate_research_ideas  # noqa: E402


class ResearchWorkflowPhase4Test(unittest.TestCase):
    """验证最小研究输出链路。"""

    def test_generate_research_idea_from_reentrancy_case(self) -> None:
        """Curve 风格目标应能生成与重入相关的研究想法。"""

        target = ROOT / "contracts" / "curve"
        audit_result = run_audit(
            target=str(target),
            analyzer_names=["reentrancy"],
            minimum_severity=Severity.INFO,
        )

        with patch.dict("os.environ", {"RESEARCH_LLM_ENABLED": "false"}, clear=False):
            ideas = generate_research_ideas(audit_result)
        self.assertGreater(len(ideas), 0)
        self.assertEqual(ideas[0].focus_category, "SC-01: Reentrancy")

        paper = render_paper_draft(
            research_idea=ideas[0],
            audit_result=audit_result,
        )
        self.assertIn("Research Questions", paper.markdown)
        self.assertIn("Methodology", paper.markdown)
        self.assertIn("Curve", paper.markdown)


if __name__ == "__main__":
    unittest.main()
