"""审计质量增强测试。"""

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


class AuditQualityPhase16Test(unittest.TestCase):
    """验证审计效果增强。"""

    def test_curve_top_findings_are_diversified(self) -> None:
        """真实协议上的 top finding 不应全部是同一家族。"""

        result = run_audit(
            target=str(ROOT / "contracts" / "curve"),
            analyzer_names=None,
            minimum_severity=Severity.INFO,
        )
        titles = [finding.title for finding in result.audit_summary.top_findings]
        self.assertGreater(len(set(titles)), 1)

    def test_presentation_contains_grouped_families(self) -> None:
        """展示层应提供问题家族聚合结果。"""

        result = run_audit(
            target=str(ROOT / "contracts" / "curve"),
            analyzer_names=None,
            minimum_severity=Severity.INFO,
        )
        presentation = build_audit_presentation(result)
        self.assertIn("grouped_families", presentation)
        self.assertTrue(any(presentation["grouped_families"].values()))


if __name__ == "__main__":
    unittest.main()
