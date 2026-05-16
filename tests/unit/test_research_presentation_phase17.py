"""研究展示适配层测试。"""

from __future__ import annotations

from pathlib import Path
import sys
import unittest
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from tools.analyzers.base import Severity  # noqa: E402
from services.research.presentation import build_research_presentation  # noqa: E402
from services.research.research_workflow_service import run_research_workflow  # noqa: E402


class ResearchPresentationPhase17Test(unittest.TestCase):
    """验证研究展示层。"""

    def test_build_research_presentation(self) -> None:
        """应返回更适合页面展示的结构。"""

        with patch.dict("os.environ", {"RESEARCH_LLM_ENABLED": "false"}, clear=False):
            result = run_research_workflow(
                target=str(ROOT / "contracts" / "curve"),
                analyzer_names=["reentrancy"],
                minimum_severity=Severity.INFO,
            )
        presentation = build_research_presentation(result)
        self.assertIn("title", presentation)
        self.assertIn("metrics", presentation)
        self.assertIn("highlights", presentation)
        self.assertGreaterEqual(len(presentation["highlights"]), 1)
        self.assertIn("candidate_ideas", presentation)
        self.assertIn("selected_direction", presentation)
        self.assertIn("evidence_chain", presentation)
        self.assertIn("evidence_assessment", presentation)
        self.assertIn("incident_understanding", presentation)
        self.assertIn("mechanism_graph_design", presentation)
        self.assertIn("research_program_candidates", presentation)
        self.assertIn("paper_strategy", presentation)
        self.assertIn("contribution_profile", presentation)
        self.assertIn("publication_task_design", presentation)
        self.assertIn("claim_evidence_matrix", presentation)
        self.assertIn("claim_graph", presentation)
        self.assertIn("experiments", presentation)
        self.assertIn("experiment_gap_report", presentation)
        self.assertIn("journal_fit_assessment", presentation)
        self.assertIn("submission_compliance", presentation)
        self.assertIn("publication_readiness", presentation)
        self.assertIn("peer_reviews", presentation)
        self.assertGreaterEqual(len(presentation["candidate_ideas"]), 3)
        self.assertGreaterEqual(len(presentation["evidence_chain"]), 1)
        self.assertIn("status", presentation["evidence_assessment"])
        self.assertIn("paper_ready", presentation)
        self.assertIn("peer_review_status", presentation)
        self.assertIn("stats", presentation["claim_graph"])
        self.assertIn("summary", presentation["claim_evidence_matrix"])
        self.assertIn("paper_type", presentation["paper_strategy"])
        self.assertIn("tasks", presentation["publication_task_design"])
        self.assertIn("readiness_score", presentation["publication_readiness"])
        self.assertGreaterEqual(len(presentation["peer_reviews"]), 3)


if __name__ == "__main__":
    unittest.main()
