"""引用校验与论文修订测试。"""

from __future__ import annotations

from pathlib import Path
import sys
import unittest
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from services.research.models import (  # noqa: E402
    CitationRecord,
    PaperDraft,
    PaperRevisionResult,
    ReviewAspectResult,
    ReviewBlockResult,
)
from services.research.incident_research_workflow_service import run_incident_research_workflow  # noqa: E402
from services.research.paper_revision import (  # noqa: E402
    revise_paper_draft_with_llm,
    review_paper_draft,
    run_revision_cycle,
)
import services.research.paper_revision as paper_revision_module  # noqa: E402
from services.research.peer_review_cycle import run_peer_review_cycle  # noqa: E402
from services.research.review_views import build_peer_review_views  # noqa: E402
from services.shared.llm_client import LlmJsonResponse  # noqa: E402


class _FakeRevisionClient:
    """最小修订客户端桩。"""

    def complete_json(self, *, system_prompt: str, user_prompt: str) -> LlmJsonResponse:
        updated_sections = [
            {"heading": "## 2. Background and Context", "content": "x"},
            {"heading": "## 3. Problem Statement", "content": "x"},
            {"heading": "## 4. Research Questions", "content": "x"},
            {"heading": "## 5. Evidence and Observations", "content": "x"},
            {"heading": "## 6. Related Work", "content": "x"},
            {"heading": "## 7. Methodology", "content": "x"},
            {"heading": "## 8. Evaluation and Validation Plan", "content": "x"},
            {"heading": "## 9. Preliminary Results and Discussion", "content": "### Verification Summary\nx"},
            {"heading": "## 10. Expected Contributions", "content": "x"},
            {"heading": "## 11. Threats to Validity", "content": "x"},
            {"heading": "## 12. Conclusion", "content": "本文当前版本的核心价值，在于回到 incident、证据和验证结果。"},
            {"heading": "## References", "content": "x"},
        ]
        return LlmJsonResponse(
            provider="openai-compatible",
            model="demo-model",
            content={
                "updated_sections": updated_sections,
                "addressed_changes": ["补齐了 Verification Summary 和 Conclusion。"],
            },
            raw_text="{}",
            finish_reason="stop",
        )


class _FakeReviewerClient:
    """最小 reviewer 客户端桩。"""

    def complete_json(self, *, system_prompt: str, user_prompt: str) -> LlmJsonResponse:
        return LlmJsonResponse(
            provider="openai-compatible",
            model="demo-model",
            content={
                "blocks": [
                    {
                        "block_id": "structure",
                        "accepted": True,
                        "score": 9.0,
                        "aspects": [
                            {
                                "aspect_id": "section_coverage",
                                "name": "Section Coverage",
                                "accepted": True,
                                "score": 9.0,
                                "summary": "结构完整。",
                                "required_change": "",
                            }
                        ],
                        "strengths": ["结构完整。"],
                        "weaknesses": [],
                        "required_changes": [],
                        "addressed_changes": [],
                    },
                    {
                        "block_id": "evidence",
                        "accepted": True,
                        "score": 9.0,
                        "aspects": [
                            {
                                "aspect_id": "incident_grounding",
                                "name": "Incident Grounding",
                                "accepted": True,
                                "score": 9.0,
                                "summary": "证据完整。",
                                "required_change": "",
                            }
                        ],
                        "strengths": ["证据完整。"],
                        "weaknesses": [],
                        "required_changes": [],
                        "addressed_changes": [],
                    },
                    {
                        "block_id": "validation",
                        "accepted": True,
                        "score": 9.0,
                        "aspects": [
                            {
                                "aspect_id": "verification_presence",
                                "name": "Verification Presence",
                                "accepted": True,
                                "score": 9.0,
                                "summary": "验证充分。",
                                "required_change": "",
                            }
                        ],
                        "strengths": ["验证充分。"],
                        "weaknesses": [],
                        "required_changes": [],
                        "addressed_changes": [],
                    },
                    {
                        "block_id": "related_work",
                        "accepted": True,
                        "score": 8.0,
                        "aspects": [
                            {
                                "aspect_id": "citation_quality",
                                "name": "Citation Quality",
                                "accepted": False,
                                "score": 4.0,
                                "summary": "引用角色混乱。",
                                "required_change": "重写 related work。",
                            }
                        ],
                        "strengths": [],
                        "weaknesses": ["引用角色混乱。"],
                        "required_changes": ["重写 related work。"],
                        "addressed_changes": [],
                    },
                    {
                        "block_id": "conclusion",
                        "accepted": True,
                        "score": 9.0,
                        "aspects": [
                            {
                                "aspect_id": "claim_grounding",
                                "name": "Claim Grounding",
                                "accepted": True,
                                "score": 9.0,
                                "summary": "结论落地。",
                                "required_change": "",
                            }
                        ],
                        "strengths": ["结论落地。"],
                        "weaknesses": [],
                        "required_changes": [],
                        "addressed_changes": [],
                    },
                ]
            },
            raw_text="{}",
            finish_reason="stop",
        )


class _FakeValidationRewriteClient:
    """模拟会把验证摘要标题改坏的修订客户端。"""

    def complete_json(self, *, system_prompt: str, user_prompt: str) -> LlmJsonResponse:
        return LlmJsonResponse(
            provider="openai-compatible",
            model="demo-model",
            content={
                "updated_sections": [
                    {
                        "heading": "## 8. Evaluation and Validation Plan",
                        "content": (
                            "## 8. Evaluation and Validation Plan\n"
                            "### A. Verification Summary\n"
                            "- 本地主网 fork 验证已通过。\n"
                            "- 该结果支撑 createMarket 零验证与欠抵押借款路径。"
                        ),
                    }
                ],
                "addressed_changes": ["补充了验证摘要。"],
            },
            raw_text="{}",
            finish_reason="stop",
        )


class _FakePeerReviewClient:
    """最小 AI reviewer 客户端桩。"""

    def complete_json(self, *, system_prompt: str, user_prompt: str) -> LlmJsonResponse:
        return LlmJsonResponse(
            provider="openai-compatible",
            model="demo-model",
            content={
                "reviews": [
                    {
                        "review_id": "reviewer_a",
                        "recommendation": "Accept with Minor Notes",
                        "priority": "low",
                        "overall_comment": "结构清晰，但建议进一步统一术语。",
                        "evidence_basis": ["结构完整。", "结论与问题定义闭环。"],
                        "strengths": ["主线清楚。", "段落组织稳定。"],
                        "blocker_issues": [],
                        "major_concerns": [],
                        "minor_concerns": ["术语尚可进一步统一。"],
                        "acceptance_conditions": ["统一关键术语表述。"],
                        "questions_for_authors": ["是否愿意统一 Oracle 相关术语？"],
                    },
                    {
                        "review_id": "reviewer_b",
                        "recommendation": "Accept",
                        "priority": "info",
                        "overall_comment": "证据与验证链条完整。",
                        "evidence_basis": ["incident 证据完整。", "验证结果已入正文。"],
                        "strengths": ["证据扎实。", "验证可追溯。"],
                        "blocker_issues": [],
                        "major_concerns": [],
                        "minor_concerns": [],
                        "acceptance_conditions": [],
                        "questions_for_authors": ["是否补充更多失败案例对照？"],
                    },
                    {
                        "review_id": "reviewer_c",
                        "recommendation": "Major Revision",
                        "priority": "medium",
                        "overall_comment": "定位基本清楚，但仍需进一步收紧相关工作边界。",
                        "evidence_basis": ["相关工作有明确引用。"],
                        "strengths": ["定位方向清楚。"],
                        "blocker_issues": [],
                        "major_concerns": ["需要进一步压缩 reference 级材料在核心论证中的存在感。"],
                        "minor_concerns": ["建议更明确区分背景与核心证据。"],
                        "acceptance_conditions": ["在正文中进一步收紧 reference 级引用边界。"],
                        "questions_for_authors": ["哪些结论必须只回指 incident 与验证结果？"],
                    },
                ]
            },
            raw_text="{}",
            finish_reason="stop",
        )


class _NeverCalledReviewClient:
    """如果被调用就直接失败，用于验证短路逻辑。"""

    def complete_json(self, *, system_prompt: str, user_prompt: str) -> LlmJsonResponse:
        raise AssertionError("deterministic accepted draft should not trigger reviewer LLM")


class ReferenceRevisionPhase29Test(unittest.TestCase):
    """验证引用校验与修订结果。"""

    def test_incident_first_workflow_contains_reference_validation_and_revision(self) -> None:
        """强证据 incident 研究结果应包含引用校验和修订结果。"""

        with patch.dict("os.environ", {"RESEARCH_LLM_ENABLED": "false"}, clear=False):
            result = run_incident_research_workflow(
                incident_id="morpho_blue_oracle_misconfig_2024",
            )

        self.assertIsNotNone(result.reference_validation)
        self.assertGreaterEqual(result.reference_validation.accepted_count, 1)
        self.assertIsNotNone(result.revision_result)
        self.assertGreater(result.revision_result.final_score, 0)
        self.assertIn(result.revision_result.status, {"accepted", "needs_revision"})
        self.assertGreater(len(result.revision_result.review_blocks), 0)
        self.assertGreater(len(result.revision_result.review_blocks[0].aspects), 0)

    def test_revision_cycle_can_improve_draft_with_llm(self) -> None:
        """review 指出问题后，应能通过修订循环生成更好的版本。"""

        with patch.dict("os.environ", {"RESEARCH_LLM_ENABLED": "false"}, clear=False):
            result = run_incident_research_workflow(
                incident_id="morpho_blue_oracle_misconfig_2024",
            )

        bad_draft = PaperDraft(
            title="Demo",
            markdown="# Demo\n\n## 摘要\nx\n\n## 1. Introduction\nx\n",
        )
        with patch.dict(
            "os.environ",
            {
                "RESEARCH_LLM_ENABLED": "true",
                "LLM_API_URL": "https://llm.example/v1/chat/completions",
                "LLM_API_KEY": "secret",
                "LLM_MODEL": "demo-model",
            },
            clear=True,
        ):
            revision = run_revision_cycle(
                paper_draft=bad_draft,
                reference_validation=result.reference_validation,
                incident_evidence_packages=result.incident_evidence_packages,
                citations=result.citations,
                client=_FakeRevisionClient(),
            )

        self.assertGreaterEqual(revision.rounds, 1)
        self.assertTrue(revision.addressed_changes)
        self.assertIn("## 12. Conclusion", revision.revised_markdown)

    def test_failed_aspect_or_required_change_cannot_be_marked_as_passed(self) -> None:
        """只要 aspect 失败或仍有必改项，block 与整篇论文都不能算通过。"""

        with patch.dict("os.environ", {"RESEARCH_LLM_ENABLED": "false"}, clear=False):
            result = run_incident_research_workflow(
                incident_id="morpho_blue_oracle_misconfig_2024",
            )

        with patch.dict(
            "os.environ",
            {
                "RESEARCH_LLM_ENABLED": "true",
                "LLM_API_URL": "https://llm.example/v1/chat/completions",
                "LLM_API_KEY": "secret",
                "LLM_MODEL": "demo-model",
            },
            clear=True,
        ):
            review = review_paper_draft(
                paper_draft=result.paper_draft,
                reference_validation=result.reference_validation,
                incident_evidence_packages=result.incident_evidence_packages,
                client=_FakeReviewerClient(),
            )

        related_work = next(
            block for block in review.review_blocks if block.block_id == "related_work"
        )
        self.assertFalse(related_work.accepted)
        self.assertFalse(review.accepted)
        self.assertEqual(review.status, "needs_revision")

    def test_strong_deterministic_draft_skips_ai_reviewer_call(self) -> None:
        """当确定性 review 已通过时，不应再发起冗余 AI reviewer 请求。"""

        with patch.dict("os.environ", {"RESEARCH_LLM_ENABLED": "false"}, clear=False):
            result = run_incident_research_workflow(
                incident_id="morpho_blue_oracle_misconfig_2024",
            )

        with patch.object(
            paper_revision_module,
            "review_paper_draft_with_llm",
            side_effect=AssertionError("deterministic accepted draft should not trigger reviewer LLM"),
        ):
            review = review_paper_draft(
                paper_draft=result.paper_draft,
                reference_validation=result.reference_validation,
                incident_evidence_packages=result.incident_evidence_packages,
            )

        self.assertTrue(review.accepted)
        self.assertEqual(review.status, "accepted")

    def test_revision_guard_keeps_verification_summary_anchor(self) -> None:
        """修订结果不应因标题漂移或重复 heading 丢掉验证摘要锚点。"""

        with patch.dict("os.environ", {"RESEARCH_LLM_ENABLED": "false"}, clear=False):
            result = run_incident_research_workflow(
                incident_id="morpho_blue_oracle_misconfig_2024",
            )

        review_result = PaperRevisionResult(
            status="needs_revision",
            accepted=False,
            final_score=6.0,
            summary="validation 需要补强",
            rounds=0,
            review_blocks=[
                ReviewBlockResult(
                    block_id="validation",
                    name="Validation",
                    accepted=False,
                    score=6.0,
                    aspects=[
                        ReviewAspectResult(
                            aspect_id="result_reporting",
                            name="Result Reporting",
                            accepted=False,
                            score=3.0,
                            summary="缺少验证摘要。",
                            required_change="补充 Verification Summary。",
                        )
                    ],
                    strengths=[],
                    weaknesses=["缺少验证摘要。"],
                    required_changes=["补充 Verification Summary。"],
                    addressed_changes=[],
                )
            ],
            strengths=[],
            weaknesses=["缺少验证摘要。"],
            required_changes=["补充 Verification Summary。"],
            addressed_changes=[],
            revised_markdown=result.paper_draft.markdown,
        )

        with patch.dict(
            "os.environ",
            {
                "RESEARCH_LLM_ENABLED": "true",
                "LLM_API_URL": "https://llm.example/v1/chat/completions",
                "LLM_API_KEY": "secret",
                "LLM_MODEL": "demo-model",
            },
            clear=True,
        ):
            revised_draft, addressed = revise_paper_draft_with_llm(
                paper_draft=result.paper_draft,
                review_result=review_result,
                citations=result.citations,
                incident_evidence_packages=result.incident_evidence_packages,
                client=_FakeValidationRewriteClient(),
            )

        self.assertIsNotNone(revised_draft)
        self.assertIn("### Verification Summary", revised_draft.markdown)
        self.assertEqual(
            revised_draft.markdown.count("## 8. Evaluation and Validation Plan"),
            1,
        )
        self.assertTrue(addressed)

    def test_peer_review_views_can_use_ai_reviewers(self) -> None:
        """peer reviewers 在启用时应优先采用 AI reviewer 输出。"""

        with patch.dict("os.environ", {"RESEARCH_LLM_ENABLED": "false"}, clear=False):
            result = run_incident_research_workflow(
                incident_id="morpho_blue_oracle_misconfig_2024",
            )

        with patch.dict(
            "os.environ",
            {
                "RESEARCH_LLM_ENABLED": "true",
                "LLM_API_URL": "https://llm.example/v1/chat/completions",
                "LLM_API_KEY": "secret",
                "LLM_MODEL": "demo-model",
            },
            clear=True,
        ):
            reviews = build_peer_review_views(
                result.revision_result.to_dict(),
                evidence_assessment=result.evidence_assessment.to_dict(),
                reference_validation=result.reference_validation.to_dict(),
                task_steps=[],
                paper_markdown=result.revision_result.revised_markdown,
                use_llm=True,
                client=_FakePeerReviewClient(),
            )

        self.assertEqual(len(reviews), 3)
        self.assertTrue(all(review["mode"] == "ai" for review in reviews))
        self.assertEqual(reviews[0]["recommendation"], "Accept with Minor Notes")
        self.assertEqual(reviews[2]["priority"], "medium")

    def test_peer_review_filters_unreferenced_reference_issues(self) -> None:
        """reviewer 不应反复拿正文未使用的 reference 级材料当主要问题。"""

        revision_result = {
            "status": "accepted",
            "accepted": True,
            "final_score": 9.0,
            "rounds": 0,
            "review_blocks": [
                {
                    "block_id": "related_work",
                    "name": "Related Work",
                    "accepted": True,
                    "score": 9.0,
                    "aspects": [],
                    "strengths": ["相关工作边界清楚。"],
                    "weaknesses": [],
                    "required_changes": [],
                    "addressed_changes": [],
                },
                {
                    "block_id": "conclusion",
                    "name": "Conclusion",
                    "accepted": True,
                    "score": 9.0,
                    "aspects": [],
                    "strengths": ["结论边界清楚。"],
                    "weaknesses": [],
                    "required_changes": [],
                    "addressed_changes": [],
                },
            ],
        }
        reference_validation = {
            "accepted_count": 3,
            "rejected_count": 0,
            "issues": [
                {
                    "title": "unused_reference_report",
                    "message": "该引用仅为参考级，不应成为核心论证支撑。",
                    "severity": "low",
                }
            ],
        }
        reviews = build_peer_review_views(
            revision_result,
            evidence_assessment={},
            reference_validation=reference_validation,
            paper_markdown="## 6. Related Work\n\n本文只引用 incident_anchor。",
            use_llm=False,
        )

        reviewer_c = next(review for review in reviews if review["review_id"] == "reviewer_c")
        self.assertNotIn("unused_reference_report", "；".join(reviewer_c["major_concerns"]))

    def test_peer_review_cycle_downgrades_acceptance_when_major_issues_remain(self) -> None:
        """只要 AI peer review 仍有 major issue，最终稿就不能继续算 accepted。"""

        with patch.dict("os.environ", {"RESEARCH_LLM_ENABLED": "false"}, clear=False):
            result = run_incident_research_workflow(
                incident_id="morpho_blue_oracle_misconfig_2024",
            )

        class _AlwaysCriticalPeerReviewClient:
            def complete_json(self, *, system_prompt: str, user_prompt: str) -> LlmJsonResponse:
                return LlmJsonResponse(
                    provider="openai-compatible",
                    model="demo-model",
                    content={
                        "reviews": [
                            {
                                "review_id": "reviewer_a",
                                "recommendation": "Major Revision",
                                "priority": "medium",
                                "overall_comment": "结构仍需修改。",
                                "evidence_basis": ["结构存在问题。"],
                                "strengths": ["暂无"],
                                "blocker_issues": [],
                                "major_concerns": ["结构主线仍不够稳。"],
                                "minor_concerns": [],
                                "acceptance_conditions": ["重写引言与结论映射。"],
                                "questions_for_authors": ["主线问题如何与结论闭环？"],
                            },
                            {
                                "review_id": "reviewer_b",
                                "recommendation": "Accept",
                                "priority": "info",
                                "overall_comment": "证据可以。",
                                "evidence_basis": ["证据完整。"],
                                "strengths": ["证据好。"],
                                "blocker_issues": [],
                                "major_concerns": [],
                                "minor_concerns": [],
                                "acceptance_conditions": [],
                                "questions_for_authors": ["无"],
                            },
                            {
                                "review_id": "reviewer_c",
                                "recommendation": "Accept",
                                "priority": "info",
                                "overall_comment": "定位可接受。",
                                "evidence_basis": ["定位清楚。"],
                                "strengths": ["定位清楚。"],
                                "blocker_issues": [],
                                "major_concerns": [],
                                "minor_concerns": [],
                                "acceptance_conditions": [],
                                "questions_for_authors": ["无"],
                            },
                        ]
                    },
                    raw_text="{}",
                    finish_reason="stop",
                )

        with patch.dict(
            "os.environ",
            {
                "RESEARCH_LLM_ENABLED": "true",
                "LLM_API_URL": "https://llm.example/v1/chat/completions",
                "LLM_API_KEY": "secret",
                "LLM_MODEL": "demo-model",
            },
            clear=True,
        ):
            paper_draft, revision_result, peer_reviews, _ = run_peer_review_cycle(
                paper_draft=result.paper_draft,
                revision_result=result.revision_result,
                evidence_assessment=result.evidence_assessment.to_dict(),
                reference_validation=result.reference_validation.to_dict(),
                task_steps=[],
                citations=result.citations,
                incident_evidence_packages=result.incident_evidence_packages,
                client=_AlwaysCriticalPeerReviewClient(),
                max_rounds=0,
            )

        self.assertIsNotNone(paper_draft)
        self.assertFalse(revision_result.accepted)
        self.assertEqual(revision_result.status, "needs_revision")
        self.assertTrue(any(review["major_concerns"] for review in peer_reviews))


if __name__ == "__main__":
    unittest.main()
