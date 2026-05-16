"""Phase 1 审计服务测试。"""

from __future__ import annotations

import json
from pathlib import Path
import sys
import unittest

from jsonschema import Draft202012Validator

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from tools.analyzers.base import Severity  # noqa: E402
from services.analysis.audit_report_writer import render_audit_report  # noqa: E402
from services.analysis.audit_service import run_audit  # noqa: E402


class AuditServicePhase1Test(unittest.TestCase):
    """验证审计 MVP 端到端闭环。"""

    def setUp(self) -> None:
        self.audit_schema_path = ROOT / "data" / "schema" / "audit_run_result.schema.json"

    def test_run_audit_returns_structured_result(self) -> None:
        """审计结果应该同时包含接入、分类、扫描和证据摘要。"""

        target = ROOT / "tests" / "fixtures" / "LendingPoolPrototype.sol"
        result = run_audit(
            target=str(target),
            analyzer_names=["access-control", "reentrancy"],
            minimum_severity=Severity.INFO,
        )

        self.assertEqual(result.classification.protocol_type, "lending")
        self.assertGreater(result.ingestion.solidity_file_count, 0)
        self.assertGreaterEqual(result.audit_summary.total_findings, 1)
        self.assertGreaterEqual(result.evidence_summary.evidence_count, 1)
        self.assertGreaterEqual(len(result.related_incidents), 1)

        schema = json.loads(self.audit_schema_path.read_text(encoding="utf-8"))
        validator = Draft202012Validator(schema)
        errors = sorted(validator.iter_errors(result.to_dict()), key=lambda error: error.path)
        self.assertEqual(errors, [])

    def test_render_audit_report_contains_key_sections(self) -> None:
        """生成的 Markdown 应包含关键章节。"""

        target = ROOT / "tests" / "fixtures" / "LendingPoolPrototype.sol"
        result = run_audit(
            target=str(target),
            analyzer_names=["access-control"],
            minimum_severity=Severity.INFO,
        )
        markdown = render_audit_report(result)

        self.assertIn("审计报告", markdown)
        self.assertIn("执行摘要", markdown)
        self.assertIn("重点发现摘要表", markdown)
        self.assertIn("重点发现详情", markdown)
        self.assertIn("当前结论边界", markdown)
        self.assertIn("相似历史案例", markdown)


if __name__ == "__main__":
    unittest.main()
