"""Phase 0 扫描器测试。"""

from __future__ import annotations

import json
from pathlib import Path
import sys
import unittest

from jsonschema import Draft202012Validator


ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
if str(ROOT / "tools") not in sys.path:
    sys.path.insert(0, str(ROOT / "tools"))

from tools.scanner import build_scan_report, run_scan  # noqa: E402
from tools.analyzers.base import Severity  # noqa: E402


class ScannerPhase0Test(unittest.TestCase):
    """验证 Phase 0 统一输出是否稳定。"""

    def setUp(self) -> None:
        self.fixture_contract = ROOT / "tests" / "fixtures" / "SimpleVault.sol"
        self.schema_path = ROOT / "data" / "schema" / "security_scan_report.schema.json"

    def test_run_scan_can_find_fixture_issue(self) -> None:
        """最小样例合约应该能触发访问控制告警。"""

        findings, stats = run_scan(
            target=str(self.fixture_contract),
            analyzer_names=["access-control"],
            min_severity=Severity.INFO,
        )

        self.assertGreater(len(findings), 0)
        self.assertEqual(stats["files_scanned"], 1)
        self.assertIn("Unprotected sensitive function", findings[0].title)

    def test_build_scan_report_matches_schema(self) -> None:
        """统一输出必须符合 JSON Schema。"""

        findings, stats = run_scan(
            target=str(self.fixture_contract),
            analyzer_names=["access-control"],
            min_severity=Severity.INFO,
        )

        report = build_scan_report(
            target=str(self.fixture_contract),
            analyzer_names=["access-control"],
            min_severity=Severity.INFO,
            findings=findings,
            stats=stats,
        )
        report_dict = report.to_dict()

        schema = json.loads(self.schema_path.read_text(encoding="utf-8"))
        validator = Draft202012Validator(schema)
        errors = sorted(validator.iter_errors(report_dict), key=lambda error: error.path)

        self.assertEqual(errors, [])
        self.assertEqual(report_dict["schema_version"], "security_scan_report@1.0.0")
        self.assertEqual(report_dict["target"]["kind"], "file")
        self.assertGreater(len(report_dict["findings"][0]["supporting_evidence"]), 0)


if __name__ == "__main__":
    unittest.main()
