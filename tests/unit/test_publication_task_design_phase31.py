"""期刊化任务设计测试。"""

from __future__ import annotations

from pathlib import Path
import sys
import unittest
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from services.research.incident_research_workflow_service import run_incident_research_workflow  # noqa: E402


class PublicationTaskDesignPhase31Test(unittest.TestCase):
    """验证期刊导向任务流已生成。"""

    def test_incident_workflow_exposes_publication_task_design(self) -> None:
        with patch.dict("os.environ", {"RESEARCH_LLM_ENABLED": "false"}, clear=False):
            result = run_incident_research_workflow(
                incident_id="morpho_blue_oracle_misconfig_2024",
            )

        self.assertIsNotNone(result.publication_task_design)
        design = result.publication_task_design
        self.assertGreaterEqual(len(design.tasks), 11)
        self.assertGreaterEqual(len(design.claim_units), 3)
        self.assertGreaterEqual(len(design.validation_scenarios), 3)
        self.assertGreaterEqual(len(design.venue_blueprint), 6)
        self.assertGreaterEqual(len(design.reviewer_lanes), 5)
        self.assertEqual(design.tasks[0].task_id, "event_discovery")
        self.assertTrue(any(item.task_id == "paper_type_selection" for item in design.tasks))
        self.assertEqual(design.tasks[-1].task_id, "submission_packaging")


if __name__ == "__main__":
    unittest.main()
