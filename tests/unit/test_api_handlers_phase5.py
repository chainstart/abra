"""API 处理函数测试。"""

from __future__ import annotations

import json
from pathlib import Path
import shutil
import sys
import unittest
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from services.api.handlers import (  # noqa: E402
    handle_audit_request,
    handle_deep_analysis_request,
    handle_incident_discovery_request,
    handle_incident_hydration_request,
    handle_incident_search_request,
    handle_indexed_blocks_request,
    handle_indexed_logs_request,
    handle_indexed_transactions_request,
    handle_monitor_request,
    handle_research_request,
)
from services.research.incident_repository import load_incidents  # noqa: E402


class ApiHandlersPhase5Test(unittest.TestCase):
    """验证 API 层核心处理逻辑。"""

    def setUp(self) -> None:
        self.tmp_root = ROOT / "tests" / ".tmp_api_artifacts"
        if self.tmp_root.exists():
            shutil.rmtree(self.tmp_root)

    def tearDown(self) -> None:
        if self.tmp_root.exists():
            shutil.rmtree(self.tmp_root)

    def test_handle_audit_request_can_save_artifacts(self) -> None:
        """审计请求应返回归档目录。"""

        payload = {
            "target": str(ROOT / "tests" / "fixtures" / "LendingPoolPrototype.sol"),
            "analyzers": ["access-control", "reentrancy"],
            "severity": "Informational",
            "save_artifacts": True,
        }
        with patch("services.api.handlers.save_task_result") as save_mock:
            save_mock.return_value = self.tmp_root / "saved"
            response = handle_audit_request(payload)

        self.assertIn("task_result", response)
        self.assertIn("artifact_dir", response)

    def test_handle_research_request_returns_research_payload(self) -> None:
        """研究请求应返回研究任务结果。"""

        payload = {
            "target": str(ROOT / "contracts" / "curve"),
            "analyzers": ["reentrancy"],
            "severity": "Informational",
            "save_artifacts": False,
        }
        with patch.dict("os.environ", {"RESEARCH_LLM_ENABLED": "false"}, clear=False):
            response = handle_research_request(payload)
        self.assertIn("task_result", response)
        self.assertEqual(response["task_result"]["task_type"], "research")

    def test_handle_research_request_accepts_incident_id(self) -> None:
        """研究请求应支持直接按 incident_id 运行。"""

        payload = {
            "incident_id": "morpho_blue_oracle_misconfig_2024",
            "severity": "Informational",
            "save_artifacts": False,
        }
        with patch.dict("os.environ", {"RESEARCH_LLM_ENABLED": "false"}, clear=False):
            response = handle_research_request(payload)

        self.assertIn("task_result", response)
        self.assertEqual(response["task_result"]["task_type"], "research")
        self.assertEqual(
            response["task_result"]["target"],
            "incident://morpho_blue_oracle_misconfig_2024",
        )

    def test_handle_research_request_accepts_candidate_id(self) -> None:
        """研究请求应支持直接按 candidate_id 运行。"""

        with patch(
            "services.api.handlers.run_research_task",
            return_value=type(
                "TaskResult",
                (),
                {
                    "to_dict": lambda self: {
                        "task_type": "research",
                        "target": "candidate://candidate_1",
                        "status": "completed",
                    }
                },
            )(),
        ):
            response = handle_research_request({"candidate_id": "candidate_1", "save_artifacts": False})

        self.assertIn("task_result", response)
        self.assertEqual(response["task_result"]["target"], "candidate://candidate_1")

    def test_handle_research_request_retries_transient_llm_failure(self) -> None:
        """研究请求遇到瞬时 LLM 故障时应自动重试一次。"""

        class _Result:
            def to_dict(self):
                return {"task_type": "research", "target": "incident://demo", "status": "completed"}

        call_count = 0

        def fake_run_research_task(**kwargs):  # noqa: ANN003
            nonlocal call_count
            call_count += 1
            if call_count == 1:
                raise ValueError('LLM 请求失败: HTTP 503 {"error":{"message":"Service temporarily unavailable"}}')
            return _Result()

        with patch("services.api.handlers.run_research_task", side_effect=fake_run_research_task), patch(
            "services.api.handlers.time.sleep",
            return_value=None,
        ):
            response = handle_research_request({"incident_id": "demo", "save_artifacts": False})

        self.assertEqual(call_count, 2)
        self.assertEqual(response["task_result"]["target"], "incident://demo")

    def test_handle_monitor_request_returns_monitor_result(self) -> None:
        """监控请求应返回监控结果。"""

        with patch("services.monitoring.rpc_monitor.run_monitor_cycle") as monitor_mock:
            monitor_mock.return_value = type(
                "Result",
                (),
                {
                    "to_dict": lambda self: {
                        "from_block": 1,
                        "to_block": 2,
                        "indexed_blocks": [],
                        "indexed_transactions": [],
                        "indexed_logs": [],
                        "discovered_contracts": [],
                    }
                },
            )()
            response = handle_monitor_request({"mode": "cycle", "block_count": 2, "save_to_db": False})

        self.assertIn("monitoring_result", response)
        self.assertIn("stored_contracts", response)

    def test_handle_incident_search_request_returns_results(self) -> None:
        """案例搜索请求应返回结果数组。"""

        load_incidents(ROOT / "research" / "incidents")
        response = handle_incident_search_request({"query": "oracle", "limit": 5})
        self.assertEqual(response["query"], "oracle")
        self.assertGreaterEqual(len(response["incidents"]), 1)

    def test_handle_incident_hydration_request_returns_summary(self) -> None:
        """案例链上证据富化接口应返回汇总。"""

        with patch(
            "services.api.handlers.hydrate_incident_chain_evidence",
            return_value={
                "processed_incident_ids": ["morpho_blue_oracle_misconfig_2024"],
                "indexed_transaction_count": 1,
                "indexed_log_count": 2,
                "evidence_packages": [],
            },
        ):
            response = handle_incident_hydration_request({"incident_id": "morpho_blue_oracle_misconfig_2024"})

        self.assertIn("incident_hydration", response)
        self.assertEqual(response["incident_hydration"]["indexed_transaction_count"], 1)

    def test_handle_incident_discovery_request_returns_candidates(self) -> None:
        """外部事件发现接口应返回候选事件。"""

        with patch(
            "services.api.handlers.discover_external_incidents",
            return_value=[
                type(
                    "Candidate",
                    (),
                    {
                        "to_dict": lambda self: {
                            "candidate_id": "candidate_1",
                            "title": "Moonwell",
                            "source": "slowmist_hacked",
                        }
                    },
                )()
            ],
        ):
            response = handle_incident_discovery_request({"limit": 5})

        self.assertIn("candidates", response)
        self.assertEqual(response["candidates"][0]["candidate_id"], "candidate_1")

    def test_handle_deep_analysis_request_returns_summary(self) -> None:
        """深分析请求应返回 AST 摘要。"""

        response = handle_deep_analysis_request(
            {"target": str(ROOT / "tests" / "fixtures" / "CrossContractFlowPrototype.sol")}
        )
        self.assertIn("deep_analysis", response)
        self.assertIn("ast_summary", response["deep_analysis"])

    def test_handle_index_reader_requests(self) -> None:
        """索引读取接口应返回数组结构。"""

        with patch("services.api.handlers.list_indexed_blocks", return_value=[{"block_number": 1}]):
            with patch("services.api.handlers.list_indexed_transactions", return_value=[{"tx_hash": "0xabc"}]):
                with patch("services.api.handlers.list_indexed_logs", return_value=[{"log_key": "0xabc:0"}]):
                    blocks = handle_indexed_blocks_request({"limit": 5})
                    txs = handle_indexed_transactions_request({"limit": 5})
                    logs = handle_indexed_logs_request({"limit": 5})

        self.assertIn("blocks", blocks)
        self.assertIn("transactions", txs)
        self.assertIn("logs", logs)
