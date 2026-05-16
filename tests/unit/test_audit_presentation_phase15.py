"""审计展示适配层测试。"""

from __future__ import annotations

from pathlib import Path
import sys
import unittest


ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from tools.analyzers.base import Severity  # noqa: E402
from services.analysis.audit_service import run_audit  # noqa: E402
from services.analysis.presentation import build_audit_presentation  # noqa: E402


class AuditPresentationPhase15Test(unittest.TestCase):
    """验证审计展示层。"""

    def test_build_audit_presentation_is_human_readable(self) -> None:
        """展示层应输出中文可读字段。"""

        result = run_audit(
            target=str(ROOT / "tests" / "fixtures" / "LendingPoolPrototype.sol"),
            analyzer_names=["access-control", "reentrancy"],
            minimum_severity=Severity.INFO,
        )
        presentation = build_audit_presentation(result)

        self.assertIn("conclusion", presentation)
        self.assertIn("top_groups", presentation)
        self.assertGreaterEqual(len(presentation["top_findings"]), 1)
        self.assertGreaterEqual(len(presentation["top_groups"]), 1)
        first = presentation["top_findings"][0]
        self.assertIn("title_zh", first)
        self.assertIn("summary_zh", first)
        self.assertIn("recommendation_zh", first)


if __name__ == "__main__":
    unittest.main()
