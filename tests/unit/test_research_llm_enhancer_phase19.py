"""研究 LLM 增强层测试。"""

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
from services.research.llm_research_enhancer import (  # noqa: E402
    summarize_research_package_with_llm,
)
from services.research.research_idea_generator import generate_research_ideas  # noqa: E402
from services.research.related_work_service import retrieve_related_work  # noqa: E402
from services.shared.llm_client import LlmJsonResponse  # noqa: E402


class _FakeLlmClient:
    """返回固定响应的 LLM 客户端桩。"""

    def __init__(self, payloads: list[dict]) -> None:
        self.payloads = payloads
        self.index = 0

    def complete_json(self, *, system_prompt: str, user_prompt: str) -> LlmJsonResponse:
        payload = self.payloads[self.index]
        self.index += 1
        return LlmJsonResponse(
            provider="openai-compatible",
            model="demo-model",
            content=payload,
            raw_text="{}",
            finish_reason="stop",
        )


class _ErrorLlmClient:
    """始终抛错的 LLM 客户端桩。"""

    def complete_json(self, *, system_prompt: str, user_prompt: str) -> LlmJsonResponse:
        raise ValueError("mock llm failure")


class ResearchLlmEnhancerPhase19Test(unittest.TestCase):
    """验证研究增强层。"""

    def setUp(self) -> None:
        self.audit_result = run_audit(
            target=str(ROOT / "contracts" / "curve"),
            analyzer_names=["reentrancy"],
            minimum_severity=Severity.INFO,
        )
        with patch.dict("os.environ", {"RESEARCH_LLM_ENABLED": "false"}, clear=False):
            self.ideas = generate_research_ideas(self.audit_result)

    def test_generate_research_ideas_can_use_llm_as_primary_generator(self) -> None:
        """候选方向生成应支持 AI-first，而不是只走模板。"""

        base = self.ideas[0]
        fake_client = _FakeLlmClient(
            [
                {
                    "candidates": [
                        {
                            "title": "AI 主导生成的研究方向",
                            "focus_category": base.focus_category,
                            "problem_statement": "AI 基于证据包生成的问题定义",
                            "hypothesis": "AI 基于证据包生成的核心假设",
                            "motivation": "AI 给出的研究动机",
                            "novelty_rationale": "AI 给出的新颖性",
                            "research_questions": ["AI 问题一", "AI 问题二"],
                            "expected_contributions": ["AI 贡献一"],
                            "risks": ["AI 风险一"],
                            "proposed_experiments": ["AI 实验一"],
                            "used_evidence_ids": [(base.evidence_chain or [])[0].evidence_id],
                        }
                    ]
                }
            ]
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
            ideas = generate_research_ideas(self.audit_result, client=fake_client)

        self.assertGreaterEqual(len(ideas), 1)
        ai_idea = next((idea for idea in ideas if idea.title == "AI 主导生成的研究方向"), None)
        self.assertIsNotNone(ai_idea)
        self.assertEqual(ai_idea.problem_statement, "AI 基于证据包生成的问题定义")
        self.assertGreaterEqual(len(ai_idea.evidence_chain or []), 1)

    def test_generate_research_ideas_raises_when_llm_fails(self) -> None:
        """AI 已启用时，方向生成失败不应静默回退。"""

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
            with self.assertRaises(ValueError):
                generate_research_ideas(self.audit_result, client=_ErrorLlmClient())

    def test_summarize_research_package_with_llm(self) -> None:
        """LLM 应能补充执行摘要并更新引用解释。"""

        idea = self.ideas[0]
        citations = retrieve_related_work(idea, self.audit_result)
        plan = build_experiment_plan(idea, self.audit_result)
        target_citation_id = citations[0].citation_id
        fake_client = _FakeLlmClient(
            [
                {
                    "executive_summary": "这是 AI 生成的执行摘要。",
                    "draft_abstract": "这是 AI 生成的摘要草案。",
                    "writing_highlights": ["亮点一", "亮点二"],
                    "used_citation_ids": [target_citation_id],
                    "citation_updates": [
                        {
                            "citation_id": target_citation_id,
                            "claim_supported": "支撑主张 A",
                            "citation_reason": "因为它直接对应当前研究问题。",
                            "key_takeaway": "关键结论 A",
                            "support_level": "high",
                        }
                    ],
                }
            ]
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
            updated_citations, enhancement = summarize_research_package_with_llm(
                selected_idea=idea,
                citations=citations,
                experiment_plan=plan,
                client=fake_client,
            )

        self.assertIsNotNone(enhancement)
        self.assertEqual(enhancement.executive_summary, "这是 AI 生成的执行摘要。")
        self.assertEqual(enhancement.draft_abstract, "这是 AI 生成的摘要草案。")
        self.assertIn("亮点一", enhancement.writing_highlights)
        self.assertEqual(updated_citations[0].claim_supported, "支撑主张 A")
        self.assertEqual(updated_citations[0].support_level, "high")


if __name__ == "__main__":
    unittest.main()
