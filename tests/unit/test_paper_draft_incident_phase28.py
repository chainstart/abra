"""incident-first 论文初稿测试。"""

from __future__ import annotations

from pathlib import Path
import sys
import unittest
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from services.research.incident_research_workflow_service import run_incident_research_workflow  # noqa: E402


class PaperDraftIncidentPhase28Test(unittest.TestCase):
    """验证 incident-first 成稿结构。"""

    def test_morpho_incident_paper_draft_looks_like_paper(self) -> None:
        """Morpho incident-first 稿件应包含更完整的论文结构。"""

        with patch.dict("os.environ", {"RESEARCH_LLM_ENABLED": "false"}, clear=False):
            result = run_incident_research_workflow(
                incident_id="morpho_blue_oracle_misconfig_2024",
            )

        self.assertIsNotNone(result.paper_draft)
        markdown = result.paper_draft.markdown
        self.assertIn("**关键词：**", markdown)
        self.assertIn("## 2. Background and Context", markdown)
        self.assertIn("### Incident Context", markdown)
        self.assertIn("## 6. Related Work", markdown)
        self.assertIn("第一类材料构成本文的经验锚点", markdown)
        self.assertIn("## 7. Methodology", markdown)
        self.assertIn("## 8. Evaluation and Validation Plan", markdown)
        self.assertIn("### Counterfactual and Failure Conditions", markdown)
        self.assertIn("### Remaining Validation Gaps", markdown)
        self.assertIn("## 9. Preliminary Results and Discussion", markdown)
        self.assertIn("### Claim-to-Evidence Mapping", markdown)
        self.assertIn("主张 1", markdown)
        self.assertIn("## 11. Threats to Validity", markdown)
        self.assertIn("### 内部有效性", markdown)
        self.assertIn("## References", markdown)
        self.assertNotIn("reports/", markdown)
        self.assertNotIn("### Figure and Table Guide", markdown)
        self.assertNotIn("本文中的角色：", markdown)


if __name__ == "__main__":
    unittest.main()
