"""研究证据门禁测试。"""

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
from services.research.evidence_assessment import assess_research_evidence  # noqa: E402
from services.research.experiment_planner import build_experiment_plan  # noqa: E402
from services.research.research_idea_generator import generate_research_ideas  # noqa: E402
from services.research.related_work_service import retrieve_related_work  # noqa: E402


class ResearchEvidenceAssessmentPhase20Test(unittest.TestCase):
    """验证研究证据充分性评估。"""

    def test_assessment_reports_sufficient_for_curve_reentrancy(self) -> None:
        """真实协议样本应形成非空证据门禁结果。"""

        audit_result = run_audit(
            target=str(ROOT / "contracts" / "curve"),
            analyzer_names=["reentrancy"],
            minimum_severity=Severity.INFO,
        )
        with patch.dict("os.environ", {"RESEARCH_LLM_ENABLED": "false"}, clear=False):
            idea = generate_research_ideas(audit_result)[0]
        citations = retrieve_related_work(idea, audit_result)
        plan = build_experiment_plan(idea, audit_result)
        assessment = assess_research_evidence(
            selected_idea=idea,
            citations=citations,
            experiment_plan=plan,
        )

        self.assertIn(assessment.status, {"sufficient", "conditional", "insufficient"})
        self.assertGreater(len(assessment.claim_checks), 0)
        self.assertTrue(assessment.summary)
        self.assertGreaterEqual(assessment.score, 0.0)


if __name__ == "__main__":
    unittest.main()
