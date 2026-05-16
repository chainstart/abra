"""增强版研究工作流测试。"""

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
from services.research.experiment_planner import build_experiment_plan  # noqa: E402
from services.research.models import EvidenceAssessment, EvidenceClaimCheck, LlmResearchEnhancement  # noqa: E402
from services.research.related_work_service import retrieve_related_work  # noqa: E402
from services.research.research_idea_generator import generate_research_ideas  # noqa: E402
from services.research.research_memo_writer import render_research_memo  # noqa: E402
from services.research.research_workflow_service import run_research_workflow  # noqa: E402


class ResearchWorkflowPhase14Test(unittest.TestCase):
    """验证增强版研究工作流。"""

    def test_full_research_workflow_returns_memo_and_plan(self) -> None:
        """完整研究工作流应返回 citations、memo 和 experiment plan。"""

        with patch.dict("os.environ", {"RESEARCH_LLM_ENABLED": "false"}, clear=False):
            result = run_research_workflow(
                target=str(ROOT / "contracts" / "curve"),
                analyzer_names=["reentrancy"],
                minimum_severity=Severity.INFO,
            )
        self.assertGreaterEqual(len(result.research_ideas), 3)
        self.assertGreater(len(result.citations), 0)
        self.assertIsNotNone(result.experiment_plan)
        self.assertIsNotNone(result.research_memo)
        self.assertIsNotNone(result.evidence_assessment)
        self.assertIsNotNone(result.selected_idea)
        self.assertGreater(len(result.incident_evidence_packages or []), 0)
        self.assertIn(
            result.selected_idea.decision_status,
            {"selected", "selected_with_guardrails", "evidence_insufficient"},
        )
        self.assertGreater(len(result.selected_idea.evidence_chain or []), 0)
        self.assertTrue(result.selected_idea.selection_reason)
        self.assertIn(result.evidence_assessment.status, {"sufficient", "conditional", "insufficient"})
        if result.evidence_assessment.is_sufficient:
            self.assertIsNotNone(result.paper_draft)
        else:
            self.assertIsNone(result.paper_draft)

    def test_related_work_and_memo_generation(self) -> None:
        """related work 和研究备忘录应能正常生成。"""

        with patch.dict("os.environ", {"RESEARCH_LLM_ENABLED": "false"}, clear=False):
            audit_result = run_audit(
                target=str(ROOT / "contracts" / "curve"),
                analyzer_names=["reentrancy"],
                minimum_severity=Severity.INFO,
            )
            idea = generate_research_ideas(audit_result)[0]
        citations = retrieve_related_work(idea, audit_result)
        plan = build_experiment_plan(idea, audit_result)
        memo = render_research_memo(
            research_idea=idea,
            audit_result=audit_result,
            citations=citations,
            experiment_plan=plan,
        )

        self.assertGreater(len(citations), 0)
        self.assertIn("研究备忘录", memo.title)
        self.assertIn("方向选择结论", memo.markdown)
        self.assertIn("Related Work 与引用理由", memo.markdown)
        self.assertIn("实验设计", memo.markdown)

    def test_workflow_can_attach_llm_enhancement(self) -> None:
        """开启配置后，工作流应能带出 AI 增强结果。"""

        with patch.dict("os.environ", {"RESEARCH_LLM_ENABLED": "false"}, clear=False):
            base_result = run_research_workflow(
                target=str(ROOT / "contracts" / "curve"),
                analyzer_names=["reentrancy"],
                minimum_severity=Severity.INFO,
            )
        selected = base_result.selected_idea
        self.assertIsNotNone(selected)

        with patch.dict(
            "os.environ",
            {
                "RESEARCH_LLM_ENABLED": "true",
                "LLM_API_URL": "https://llm.example/v1/chat/completions",
                "LLM_API_KEY": "secret",
                "LLM_MODEL": "demo-model",
            },
            clear=True,
        ), patch(
            "services.research.research_idea_generator._generate_research_ideas_with_llm",
            return_value=base_result.research_ideas,
        ), patch(
            "services.research.research_workflow_service.assess_research_evidence",
            return_value=EvidenceAssessment(
                status="sufficient",
                is_sufficient=True,
                confidence="high",
                score=0.95,
                summary="证据已经足够。",
                assessed_by="test",
                satisfied_dimensions=["存在源码证据", "存在结构证据", "存在实验设计"],
                missing_dimensions=[],
                next_actions=[],
                claim_checks=[],
            ),
        ), patch(
            "services.research.research_workflow_service.summarize_research_package_with_llm"
        ) as summarize_mock:
            summarize_mock.return_value = (
                base_result.citations,
                LlmResearchEnhancement(
                    provider="openai-compatible",
                    model="demo-model",
                    status="completed",
                    selected_idea_id=selected.idea_id,
                    selection_reason=selected.selection_reason,
                    executive_summary="AI summary",
                    draft_abstract="AI abstract",
                    writing_highlights=["亮点一"],
                    used_evidence_ids=[],
                    used_citation_ids=[],
                    raw_payload={},
                ),
            )

            result = run_research_workflow(
                target=str(ROOT / "contracts" / "curve"),
                analyzer_names=["reentrancy"],
                minimum_severity=Severity.INFO,
            )

        self.assertEqual(result.llm_status, "completed")
        self.assertIsNotNone(result.llm_enhancement)
        self.assertEqual(result.llm_enhancement.executive_summary, "AI summary")
        self.assertIsNotNone(result.evidence_assessment)

    def test_conditional_gate_blocks_final_paper(self) -> None:
        """证据门禁为 conditional 时，不应继续生成最终论文初稿。"""

        with patch.dict("os.environ", {"RESEARCH_LLM_ENABLED": "false"}, clear=False):
            base_result = run_research_workflow(
                target=str(ROOT / "contracts" / "curve"),
                analyzer_names=["reentrancy"],
                minimum_severity=Severity.INFO,
            )
        selected = base_result.selected_idea
        self.assertIsNotNone(selected)

        fake_assessment = EvidenceAssessment(
            status="conditional",
            is_sufficient=False,
            confidence="medium",
            score=0.71,
            summary="证据还不够闭环。",
            assessed_by="test",
            satisfied_dimensions=["存在源码证据"],
            missing_dimensions=["关键主张缺少验证闭环"],
            next_actions=["补动态验证"],
            claim_checks=[
                EvidenceClaimCheck(
                    claim="测试主张",
                    evidence_count=1,
                    citation_count=0,
                    has_experiment=True,
                    status="partial",
                    reasoning="还缺引用闭环。",
                )
            ],
        )

        with patch.dict("os.environ", {"RESEARCH_LLM_ENABLED": "false"}, clear=False), patch(
            "services.research.research_workflow_service.assess_research_evidence",
            return_value=fake_assessment,
        ):
            result = run_research_workflow(
                target=str(ROOT / "contracts" / "curve"),
                analyzer_names=["reentrancy"],
                minimum_severity=Severity.INFO,
            )

        self.assertEqual(result.evidence_assessment.status, "conditional")
        self.assertIsNone(result.paper_draft)
        self.assertEqual(result.selected_idea.decision_status, "selected_with_guardrails")


if __name__ == "__main__":
    unittest.main()
