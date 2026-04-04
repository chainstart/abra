"""历史攻击事件本地验证服务。"""

from __future__ import annotations

from datetime import datetime, timezone
import os
from pathlib import Path
import subprocess
from typing import Any

from services.research.models import IncidentRecord
from services.shared.settings import ProjectSettings


def _payload(incident: IncidentRecord) -> dict[str, Any]:
    """返回 incident 扩展载荷。"""

    return incident.evidence_payload if isinstance(incident.evidence_payload, dict) else {}


def _normalize_verification_configs(incident: IncidentRecord) -> list[dict[str, Any]]:
    """规范化本地验证配置。"""

    raw = _payload(incident).get("local_verification")
    if isinstance(raw, dict):
        return [raw]
    if isinstance(raw, list):
        return [item for item in raw if isinstance(item, dict)]
    return []


def run_incident_local_verifications(
    incident: IncidentRecord,
    *,
    timeout_seconds: int = 240,
) -> list[dict[str, Any]]:
    """执行 incident 配置里的本地验证命令。"""

    configs = _normalize_verification_configs(incident)
    if not configs:
        return []

    settings = ProjectSettings.from_env()
    project_root = settings.project_root
    results: list[dict[str, Any]] = []

    for index, config in enumerate(configs, start=1):
        kind = str(config.get("kind") or "").strip()
        if kind != "forge_test":
            continue

        match_path = str(config.get("match_path") or "").strip()
        if not match_path:
            continue

        command = ["forge", "test", "--match-path", match_path, "-q"]
        env = os.environ.copy()
        env["RUN_MAINNET_FORK_TESTS"] = "true"
        if settings.preferred_mainnet_rpc:
            env["MAINNET_RPC_URL"] = settings.preferred_mainnet_rpc

        started_at = datetime.now(timezone.utc).isoformat()
        try:
            completed = subprocess.run(  # noqa: S603
                command,
                cwd=project_root,
                env=env,
                capture_output=True,
                text=True,
                timeout=timeout_seconds,
                check=False,
            )
            passed = completed.returncode == 0
            summary = (
                str(config.get("success_summary") or "本地 fork / PoC 验证通过。")
                if passed
                else str(config.get("failure_summary") or "本地 fork / PoC 验证失败。")
            )
            results.append(
                {
                    "verification_id": f"{incident.incident_id}_verification_{index}",
                    "kind": kind,
                    "match_path": match_path,
                    "description": str(config.get("description") or "").strip(),
                    "passed": passed,
                    "summary": summary,
                    "command": " ".join(command),
                    "return_code": completed.returncode,
                    "stdout_tail": "\n".join(completed.stdout.splitlines()[-20:]).strip(),
                    "stderr_tail": "\n".join(completed.stderr.splitlines()[-20:]).strip(),
                    "started_at": started_at,
                    "finished_at": datetime.now(timezone.utc).isoformat(),
                }
            )
        except subprocess.TimeoutExpired as exc:
            results.append(
                {
                    "verification_id": f"{incident.incident_id}_verification_{index}",
                    "kind": kind,
                    "match_path": match_path,
                    "description": str(config.get("description") or "").strip(),
                    "passed": False,
                    "summary": "本地 fork / PoC 验证超时。",
                    "command": " ".join(command),
                    "return_code": None,
                    "stdout_tail": "\n".join((exc.stdout or "").splitlines()[-20:]).strip(),
                    "stderr_tail": "\n".join((exc.stderr or "").splitlines()[-20:]).strip(),
                    "started_at": started_at,
                    "finished_at": datetime.now(timezone.utc).isoformat(),
                }
            )

    return results
