"""任务结果 schema 校验测试。"""

from __future__ import annotations

import json
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

from jsonschema import Draft202012Validator


ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from services.agent.task_orchestrator import run_audit_task, run_research_task  # noqa: E402
from tools.analyzers.base import Severity  # noqa: E402


class TaskResultSchemaPhase5Test(unittest.TestCase):
    """验证统一任务结果符合 schema。"""

    def setUp(self) -> None:
        self.schema = json.loads(
            (ROOT / "data" / "schema" / "agent_task_result.schema.json").read_text(encoding="utf-8")
        )
        self.validator = Draft202012Validator(self.schema)

    def test_audit_task_result_matches_schema(self) -> None:
        """审计任务结果应符合 schema。"""

        result = run_audit_task(
            target=str(ROOT / "tests" / "fixtures" / "LendingPoolPrototype.sol"),
            analyzer_names=["access-control", "reentrancy"],
            minimum_severity=Severity.INFO,
        )
        errors = sorted(self.validator.iter_errors(result.to_dict()), key=lambda error: error.path)
        self.assertEqual(errors, [])

    def test_research_task_result_matches_schema(self) -> None:
        """研究任务结果应符合 schema。"""

        with patch.dict("os.environ", {"RESEARCH_LLM_ENABLED": "false"}, clear=False):
            result = run_research_task(
                target=str(ROOT / "contracts" / "curve"),
                analyzer_names=["reentrancy"],
                minimum_severity=Severity.INFO,
            )
        errors = sorted(self.validator.iter_errors(result.to_dict()), key=lambda error: error.path)
        self.assertEqual(errors, [])


if __name__ == "__main__":
    unittest.main()
