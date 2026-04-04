"""最小 LLM 响应缓存。"""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
from typing import Any

from services.shared.settings import ProjectSettings


def _cache_path() -> Path:
    """返回缓存文件路径。"""

    env_path = os.getenv("LLM_CACHE_PATH", "").strip()
    if env_path:
        path = Path(env_path)
        path.parent.mkdir(parents=True, exist_ok=True)
        return path
    settings = ProjectSettings.from_env()
    path = settings.data_dir / "llm_response_cache.json"
    path.parent.mkdir(parents=True, exist_ok=True)
    return path


def build_llm_cache_key(
    *,
    model: str,
    api_mode: str,
    system_prompt: str,
    user_prompt: str,
) -> str:
    """构造稳定缓存键。"""

    raw = json.dumps(
        {
            "model": model,
            "api_mode": api_mode,
            "system_prompt": system_prompt,
            "user_prompt": user_prompt,
        },
        ensure_ascii=False,
        sort_keys=True,
    )
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def _read_cache() -> dict[str, Any]:
    """读取全部缓存。"""

    path = _cache_path()
    if not path.exists():
        return {}
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return {}
    return payload if isinstance(payload, dict) else {}


def load_llm_cache(key: str) -> dict[str, Any] | None:
    """读取单条缓存。"""

    return _read_cache().get(key)


def save_llm_cache(key: str, value: dict[str, Any]) -> None:
    """写入单条缓存。"""

    payload = _read_cache()
    payload[key] = value
    _cache_path().write_text(
        json.dumps(payload, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )
