"""incident-first 研究工作流测试。"""

from __future__ import annotations

from pathlib import Path
import sys
import unittest
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from services.research.incident_research_workflow_service import run_incident_research_workflow  # noqa: E402


class IncidentResearchWorkflowPhase25Test(unittest.TestCase):
    """验证按 incident 直接运行研究。"""

    def test_morpho_incident_research_workflow_returns_strong_evidence_result(self) -> None:
        """Morpho 这类带链上锚点与 PoC 的事件，应能形成强证据研究结果。"""

        with patch.dict("os.environ", {"RESEARCH_LLM_ENABLED": "false"}, clear=False):
            result = run_incident_research_workflow(
                incident_id="morpho_blue_oracle_misconfig_2024",
            )

        self.assertIsNotNone(result.selected_idea)
        self.assertGreater(len(result.research_ideas), 0)
        self.assertGreater(len(result.incident_evidence_packages or []), 0)
        self.assertEqual(result.evidence_assessment.status, "sufficient")
        self.assertTrue(result.evidence_assessment.is_sufficient)
        self.assertIsNotNone(result.paper_draft)


if __name__ == "__main__":
    unittest.main()
