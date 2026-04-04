"""LLM 增强产物写作器测试。"""

from __future__ import annotations

from pathlib import Path
import sys
import unittest


ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from services.research.llm_output_writer import render_llm_enhancement_markdown  # noqa: E402
from services.research.models import LlmResearchEnhancement  # noqa: E402


class LlmOutputWriterPhase19Test(unittest.TestCase):
    """验证 AI 增强摘要文件可读。"""

    def test_render_llm_enhancement_markdown(self) -> None:
        """应能把增强结果写成可读 Markdown。"""

        enhancement = LlmResearchEnhancement(
            provider="openai-compatible",
            model="demo-model",
            status="completed",
            selected_idea_id="idea_demo",
            selection_reason="因为证据更强。",
            executive_summary="执行摘要",
            draft_abstract="摘要草案",
            writing_highlights=["亮点一", "亮点二"],
            used_evidence_ids=["e1"],
            used_citation_ids=["c1"],
            raw_payload={},
        )

        markdown = render_llm_enhancement_markdown(enhancement)
        self.assertIn("AI 研究增强摘要", markdown)
        self.assertIn("Provider: openai-compatible", markdown)
        self.assertIn("执行摘要", markdown)
        self.assertIn("摘要草案", markdown)


if __name__ == "__main__":
    unittest.main()
