"""Phase 0 报告生成测试。"""

from __future__ import annotations

from pathlib import Path
import sys
import unittest


ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
if str(ROOT / "tools") not in sys.path:
    sys.path.insert(0, str(ROOT / "tools"))

from tools.report_generator import generate_report  # noqa: E402
from tools.scanner import build_scan_report, run_scan  # noqa: E402
from tools.analyzers.base import Severity  # noqa: E402


class ReportGeneratorPhase0Test(unittest.TestCase):
    """验证报告生成器可以消费统一扫描输出。"""

    def test_generate_report_from_phase0_scan_output(self) -> None:
        """报告中应包含协议名和 finding 标题。"""

        fixture_contract = ROOT / "tests" / "fixtures" / "SimpleVault.sol"
        findings, stats = run_scan(
            target=str(fixture_contract),
            analyzer_names=["access-control"],
            min_severity=Severity.INFO,
        )

        report = build_scan_report(
            target=str(fixture_contract),
            analyzer_names=["access-control"],
            min_severity=Severity.INFO,
            findings=findings,
            stats=stats,
        )

        markdown = generate_report(
            report.to_dict(),
            protocol_name="SimpleVault",
        )

        self.assertIn("SimpleVault", markdown)
        self.assertIn("Unprotected sensitive function", markdown)
        self.assertIn("Detailed Findings", markdown)


if __name__ == "__main__":
    unittest.main()
