"""API 请求处理函数。

这里把 HTTP 层和业务层分开，便于：

- 单元测试
- CLI / API 复用
- 后续替换为 FastAPI 时保留核心逻辑
"""

from __future__ import annotations

from pathlib import Path
import time

from tools.analyzers.base import Severity
from services.agent.task_orchestrator import run_audit_task, run_research_task
from services.analysis.deep_analysis_service import run_deep_analysis
from services.monitoring.rpc_monitor import scan_recent_contract_creations
from services.research.incident_chain_hydrator import hydrate_incident_chain_evidence
from services.research.external_incident_discovery import discover_external_incidents
from services.storage.artifact_store import save_task_result
from services.storage.task_database import (
    get_indexer_status,
    list_discovered_contracts,
    list_indexed_blocks,
    list_indexed_logs,
    list_index_runs,
    list_indexed_transactions,
    search_incidents,
)


def _parse_severity(value: str | None) -> Severity:
    """把请求里的严重性字符串转成枚举。"""

    if not value:
        return Severity.INFO
    mapping = {severity.value.lower(): severity for severity in Severity}
    normalized = value.strip().lower()
    if normalized not in mapping:
        valid = ", ".join(severity.value for severity in Severity)
        raise ValueError(f"无效严重性 `{value}`，可选值: {valid}")
    return mapping[normalized]


def _parse_analyzers(raw: str | list[str] | None) -> list[str] | None:
    """统一解析 analyzers 字段。"""

    if raw is None:
        return None
    if isinstance(raw, list):
        return [item.strip() for item in raw if item and item.strip()]
    if isinstance(raw, str):
        return [item.strip() for item in raw.split(",") if item.strip()]
    raise ValueError("analyzers 必须是字符串或字符串列表。")


def _is_transient_llm_failure(exc: Exception) -> bool:
    """判断是否为可重试的瞬时 LLM 故障。"""

    text = str(exc)
    return any(marker in text for marker in ["HTTP 502", "HTTP 503", "HTTP 504", "Connection reset by peer"])


def handle_audit_request(payload: dict) -> dict:
    """处理审计请求。"""

    target = payload.get("target")
    if not target:
        raise ValueError("缺少 target。")

    task_result = run_audit_task(
        target=target,
        analyzer_names=_parse_analyzers(payload.get("analyzers")),
        minimum_severity=_parse_severity(payload.get("severity")),
    )

    response = {
        "task_result": task_result.to_dict(),
    }
    if payload.get("save_artifacts"):
        task_dir = save_task_result(task_result)
        response["artifact_dir"] = str(task_dir)
    return response


def handle_research_request(payload: dict) -> dict:
    """处理研究请求。"""

    target = payload.get("target")
    incident_id = str(payload.get("incident_id", "")).strip() or None
    candidate_id = str(payload.get("candidate_id", "")).strip() or None
    auto_discover = bool(payload.get("auto_discover"))
    if not target and not incident_id and not candidate_id and not auto_discover:
        raise ValueError("缺少 target、incident_id、candidate_id 或 auto_discover。")

    attempts = 2
    last_error: Exception | None = None
    for attempt in range(attempts):
        try:
            task_result = run_research_task(
                target=target,
                incident_id=incident_id,
                candidate_id=candidate_id,
                auto_discover=auto_discover,
                analyzer_names=_parse_analyzers(payload.get("analyzers")),
                minimum_severity=_parse_severity(payload.get("severity")),
            )
            break
        except Exception as exc:  # noqa: BLE001
            last_error = exc
            if attempt < attempts - 1 and _is_transient_llm_failure(exc):
                time.sleep(8)
                continue
            raise
    else:
        raise RuntimeError(str(last_error))

    response = {
        "task_result": task_result.to_dict(),
    }
    if payload.get("save_artifacts"):
        task_dir = save_task_result(task_result)
        response["artifact_dir"] = str(task_dir)
    return response


def handle_monitor_request(payload: dict) -> dict:
    """处理链上监控请求。"""

    mode = str(payload.get("mode", "cycle"))
    block_count = int(payload.get("block_count", 5))
    rpc_url = payload.get("rpc_url")
    if mode == "recent":
        result = scan_recent_contract_creations(
            block_count=block_count,
            rpc_url=rpc_url,
            save_to_db=bool(payload.get("save_to_db", True)),
            auto_enqueue_audit=bool(payload.get("auto_enqueue_audit", False)),
        )
    elif mode == "cycle":
        from services.monitoring.rpc_monitor import run_monitor_cycle

        result = run_monitor_cycle(
            initial_lookback=int(payload.get("initial_lookback", 5)),
            max_blocks_per_cycle=int(payload.get("max_blocks_per_cycle", 20)),
            rpc_url=rpc_url,
            auto_enqueue_audit=bool(payload.get("auto_enqueue_audit", False)),
        )
    elif mode == "range":
        from services.monitoring.rpc_monitor import index_block_range

        if "from_block" not in payload or "to_block" not in payload:
            raise ValueError("range 模式需要 from_block 和 to_block。")
        result = index_block_range(
            from_block=int(payload["from_block"]),
            to_block=int(payload["to_block"]),
            rpc_url=rpc_url,
            save_to_db=bool(payload.get("save_to_db", True)),
            auto_enqueue_audit=bool(payload.get("auto_enqueue_audit", False)),
            mode="range",
        )
    else:
        raise ValueError(f"未知监控模式: {mode}")

    return {
        "monitoring_result": result.to_dict(),
        "stored_contracts": list_discovered_contracts(limit=20),
    }


def handle_indexer_status_request(_payload: dict | None = None) -> dict:
    """处理索引器状态请求。"""

    return {
        "status": get_indexer_status(),
        "recent_runs": list_index_runs(limit=10),
        "recent_blocks": list_indexed_blocks(limit=10),
        "recent_transactions": list_indexed_transactions(limit=10),
        "recent_logs": list_indexed_logs(limit=10),
    }


def handle_indexed_blocks_request(payload: dict) -> dict:
    """查询最近区块。"""

    return {
        "blocks": list_indexed_blocks(limit=int(payload.get("limit", 20))),
    }


def handle_indexed_transactions_request(payload: dict) -> dict:
    """查询最近交易。"""

    return {
        "transactions": list_indexed_transactions(limit=int(payload.get("limit", 20))),
    }


def handle_indexed_logs_request(payload: dict) -> dict:
    """查询最近日志。"""

    return {
        "logs": list_indexed_logs(limit=int(payload.get("limit", 20))),
    }


def handle_incident_search_request(payload: dict) -> dict:
    """处理历史案例搜索请求。"""

    query = str(payload.get("query", "")).strip()
    if not query:
        raise ValueError("缺少 query。")
    return {
        "query": query,
        "incidents": search_incidents(query, limit=int(payload.get("limit", 10))),
    }


def handle_incident_hydration_request(payload: dict) -> dict:
    """富化历史攻击事件的链上证据。"""

    result = hydrate_incident_chain_evidence(
        incident_id=(str(payload.get("incident_id", "")).strip() or None),
        rpc_url=payload.get("rpc_url"),
        save_to_db=bool(payload.get("save_to_db", True)),
    )
    return {
        "incident_hydration": result,
    }


def handle_incident_discovery_request(payload: dict) -> dict:
    """发现外部攻击事件候选。"""

    candidates = discover_external_incidents(
        limit=int(payload.get("limit", 12)),
        min_relevance=float(payload.get("min_relevance", 0.45)),
    )
    return {
        "candidates": [item.to_dict() for item in candidates],
    }


def handle_deep_analysis_request(payload: dict) -> dict:
    """处理深分析请求。"""

    target = payload.get("target")
    if not target:
        raise ValueError("缺少 target。")
    result = run_deep_analysis(str(target))
    return {
        "deep_analysis": result.to_dict(),
    }
