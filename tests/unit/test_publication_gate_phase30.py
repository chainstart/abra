"""严格投稿门禁测试。"""

from __future__ import annotations

from pathlib import Path
import sys
import unittest


ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from services.research.models import (  # noqa: E402
    JournalFitAssessment,
    JournalFitDimension,
    PaperRevisionResult,
    PublicationReadinessReport,
    ReviewBlockResult,
    SubmissionComplianceCheck,
    SubmissionComplianceReport,
)
from services.research.publication_readiness import assess_publication_readiness  # noqa: E402
from services.research.submission_compliance import evaluate_submission_compliance  # noqa: E402


class PublicationGatePhase30Test(unittest.TestCase):
    """验证严格期刊稿门禁不会过早放行。"""

    def test_submission_compliance_requires_counterfactual_section(self) -> None:
        markdown = "\n".join(
            [
                "# Demo",
                "",
                "## 摘要",
                "",
                "摘要正文。",
                "",
                "**关键词：** oracle；market；validation",
                "",
                "## 1. Introduction",
                "",
                "x",
                "",
                "## 6. Related Work",
                "",
                "x",
                "",
                "## 8. Evaluation and Validation Plan",
                "",
                "### Validation Setup",
                "",
                "x",
                "",
                "### Observed Outcome",
                "",
                "x",
                "",
                "## 10. Expected Contributions",
                "",
                "x",
                "",
                "## 11. Threats to Validity",
                "",
                "x",
                "",
                "## 12. Conclusion",
                "",
                "x",
                "",
                "## References",
                "",
                "[1] Ref one.",
                "[2] Ref two.",
                "[3] Ref three.",
            ]
        )
        report = evaluate_submission_compliance(
            paper_markdown=markdown,
            reference_validation=None,
            contribution_profile=None,
            has_verification=True,
        )

        counterfactual_check = next(
            item for item in report.checks if item.check_id == "counterfactual_conditions"
        )
        self.assertEqual(counterfactual_check.status, "failed")
        self.assertEqual(counterfactual_check.severity, "blocker")

    def test_publication_readiness_blocks_non_strong_fit_even_if_revision_passed(self) -> None:
        revision_result = PaperRevisionResult(
            status="accepted",
            accepted=True,
            final_score=9.2,
            summary="结构评审通过。",
            rounds=1,
            review_blocks=[
                ReviewBlockResult(
                    block_id="structure",
                    name="Structure",
                    accepted=True,
                    score=9.0,
                    aspects=[],
                    strengths=[],
                    weaknesses=[],
                    required_changes=[],
                    addressed_changes=[],
                )
            ],
            strengths=[],
            weaknesses=[],
            required_changes=[],
            addressed_changes=[],
            revised_markdown="# Demo",
        )
        journal_fit = JournalFitAssessment(
            target_profile="journal",
            article_type="case study",
            fit_score=8.4,
            overall_fit="workable_fit",
            strengths=[],
            gaps=["文稿仍有明显模板腔与系统输出痕迹。"],
            required_adjustments=["重写 Evidence 与 Validation。"],
            dimensions=[
                JournalFitDimension(
                    dimension_id="manuscript_style",
                    label="成稿表达质量",
                    score=4.2,
                    status="needs_work",
                    evidence="模板腔明显。",
                    gap="文稿仍有明显模板腔与系统输出痕迹。",
                    required_action="重写 Evidence 与 Validation。",
                )
            ],
        )
        submission = SubmissionComplianceReport(
            status="passed",
            summary="投稿合规检查未发现 blocker。",
            blocker_count=0,
            warning_count=1,
            checks=[
                SubmissionComplianceCheck(
                    check_id="claim_mapping",
                    label="主张-证据映射存在",
                    status="warning",
                    severity="warning",
                    details="正文缺少显式的主张-证据映射。",
                    remediation="补一节主张-证据映射。",
                )
            ],
        )

        report = assess_publication_readiness(
            revision_result=revision_result,
            peer_reviews=[],
            experiment_gap_report=None,
            journal_fit_assessment=journal_fit,
            submission_compliance=submission,
        )

        self.assertIsInstance(report, PublicationReadinessReport)
        self.assertEqual(report.status, "needs_revision")
        self.assertTrue(report.blockers)


if __name__ == "__main__":
    unittest.main()
