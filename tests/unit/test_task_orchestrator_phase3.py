"""最小任务编排测试。"""

from __future__ import annotations

from pathlib import Path
import sys
import unittest
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from services.agent.task_orchestrator import run_audit_task, run_research_task  # noqa: E402
from tools.analyzers.base import Severity  # noqa: E402


class TaskOrchestratorPhase3Test(unittest.TestCase):
    """验证统一任务入口已经可用。"""

    def test_run_audit_task_returns_agent_result(self) -> None:
        """审计任务应输出步骤日志和最终 payload。"""

        target = ROOT / "tests" / "fixtures" / "LendingPoolPrototype.sol"
        result = run_audit_task(
            target=str(target),
            analyzer_names=["access-control", "reentrancy"],
            minimum_severity=Severity.INFO,
        )

        self.assertEqual(result.task_type, "audit")
        self.assertEqual(result.status, "completed")
        self.assertGreaterEqual(len(result.steps), 5)
        self.assertIn("audit_result", result.payload)
        self.assertIn("markdown_report", result.payload)

    def test_run_research_task_returns_research_payload(self) -> None:
        """研究任务应返回研究想法与论文骨架。"""

        target = ROOT / "contracts" / "curve"
        with patch.dict("os.environ", {"RESEARCH_LLM_ENABLED": "false"}, clear=False):
            result = run_research_task(
                target=str(target),
                analyzer_names=["reentrancy"],
                minimum_severity=Severity.INFO,
            )

        self.assertEqual(result.task_type, "research")
        self.assertEqual(result.status, "completed")
        self.assertTrue(any(step.name == "peer_review" for step in result.steps))
        self.assertTrue(any(step.name == "publication_readiness" for step in result.steps))
        self.assertIn("research_ideas", result.payload)
        self.assertIn("paper_draft", result.payload)
        self.assertIn("peer_reviews", result.payload)
        self.assertIn("peer_review_addressed_changes", result.payload)
        self.assertIn("contribution_profile", result.payload)
        self.assertIn("incident_understanding", result.payload)
        self.assertIn("mechanism_graph_design", result.payload)
        self.assertIn("research_program_candidates", result.payload)
        self.assertIn("paper_strategy", result.payload)
        self.assertIn("publication_task_design", result.payload)
        self.assertIn("claim_evidence_matrix", result.payload)
        self.assertIn("experiment_gap_report", result.payload)
        self.assertIn("journal_fit_assessment", result.payload)
        self.assertIn("submission_compliance", result.payload)
        self.assertIn("publication_readiness", result.payload)


if __name__ == "__main__":
    unittest.main()
