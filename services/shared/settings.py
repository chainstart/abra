"""Phase 0 配置入口。

这里先做最小配置管理，把后续肯定会反复用到的路径和环境变量集中起来。
"""

from __future__ import annotations

from dataclasses import dataclass
import os
from pathlib import Path
import tomllib


def _read_bool_env(name: str, default: bool = False) -> bool:
    """读取布尔环境变量。"""

    raw = os.getenv(name)
    if raw is None:
        return default
    return raw.strip().lower() in {"1", "true", "yes", "on"}


def _normalize_base_url(url: str) -> str:
    """规范化基础 URL。"""

    return url.strip().rstrip("/")


def _resolve_llm_endpoint(base_or_endpoint: str, api_mode: str) -> str:
    """把基础地址解析成最终端点地址。"""

    normalized = _normalize_base_url(base_or_endpoint)
    if not normalized:
        return ""
    if normalized.endswith("/responses") or normalized.endswith("/chat/completions"):
        return normalized
    suffix = "/responses" if api_mode == "responses" else "/chat/completions"
    return f"{normalized}{suffix}"


def _read_env_file(path: Path) -> dict[str, str]:
    """读取最小 .env 文件。"""

    if not path.exists():
        return {}
    values: dict[str, str] = {}
    for raw_line in path.read_text(encoding="utf-8", errors="ignore").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        key = key.strip()
        value = value.strip().strip('"').strip("'")
        if key:
            values[key] = value
    return values


def _read_codex_provider_defaults() -> dict[str, str]:
    """从 Codex 配置中读取模型提供方默认值。"""

    config_path = Path.home() / ".codex" / "config.toml"
    if not config_path.exists():
        return {}
    try:
        data = tomllib.loads(config_path.read_text(encoding="utf-8"))
    except Exception:
        return {}

    provider_name = str(data.get("model_provider") or "").strip()
    provider_block = (
        data.get("model_providers", {}).get(provider_name, {})
        if provider_name
        else {}
    )
    defaults = {
        "provider_model": str(data.get("model") or "").strip(),
        "provider_base_url": str(provider_block.get("base_url") or "").strip(),
        "provider_wire_api": str(provider_block.get("wire_api") or "").strip(),
        "provider_env_key": str(provider_block.get("env_key") or "").strip(),
    }
    return defaults


@dataclass(frozen=True)
class ProjectSettings:
    """项目级配置。

    Phase 0 只放最基础、最稳定的配置项：

    - 目录路径
    - Foundry fork 开关
    - 常用 RPC 环境变量
    """

    project_root: Path
    data_dir: Path
    schema_dir: Path
    docs_dir: Path
    research_dir: Path
    reports_dir: Path
    tests_dir: Path
    artifacts_dir: Path
    database_dir: Path
    task_db_path: Path
    fetched_sources_dir: Path
    run_mainnet_fork_tests: bool
    mainnet_rpc_url: str
    eth_rpc_url: str
    mainnet_fork_block: int
    etherscan_api_key: str
    database_url: str
    research_llm_enabled: bool
    llm_api_url: str
    llm_api_key: str
    llm_model: str
    llm_api_mode: str
    llm_timeout_seconds: int
    llm_temperature: float
    llm_max_tokens: int
    save_verbose_artifacts: bool

    @classmethod
    def from_env(cls) -> "ProjectSettings":
        """从环境变量与仓库结构生成配置对象。"""

        project_root = Path(__file__).resolve().parents[2]
        file_env = {}
        file_env.update(_read_env_file(project_root / ".env"))
        file_env.update(_read_env_file(project_root / ".env.local"))
        codex_defaults = _read_codex_provider_defaults()

        def env_value(name: str, default: str = "") -> str:
            return os.getenv(name, file_env.get(name, default)).strip()

        provider_env_key = str(codex_defaults.get("provider_env_key") or "").strip()
        provider_base_url = str(codex_defaults.get("provider_base_url") or "").strip()
        provider_api_key = env_value(provider_env_key, "") if provider_env_key else ""
        openai_api_key = env_value("OPENAI_API_KEY", "")
        explicit_openai_base_url = bool(os.getenv("OPENAI_BASE_URL") or file_env.get("OPENAI_BASE_URL"))
        openai_base_url = env_value(
            "OPENAI_BASE_URL",
            provider_base_url or "https://api.openai.com/v1",
        )
        if (
            provider_api_key
            and provider_base_url
            and _normalize_base_url(openai_base_url) == _normalize_base_url(provider_base_url)
        ):
            openai_api_key = provider_api_key
        elif (
            provider_api_key
            and provider_env_key
            and provider_env_key != "OPENAI_API_KEY"
            and explicit_openai_base_url
            and _normalize_base_url(openai_base_url) != "https://api.openai.com/v1"
        ):
            openai_api_key = provider_api_key
        elif not openai_api_key and provider_api_key:
            openai_api_key = provider_api_key
        openai_model = env_value(
            "OPENAI_MODEL",
            str(codex_defaults.get("provider_model") or ""),
        )
        raw_llm_api_mode = env_value("LLM_API_MODE", "").lower()
        if raw_llm_api_mode not in {"responses", "chat_completions", ""}:
            raw_llm_api_mode = "responses"
        llm_api_mode = raw_llm_api_mode or (
            (
                "chat_completions"
                if env_value("LLM_API_URL", "").endswith("/chat/completions")
                else (
                    str(codex_defaults.get("provider_wire_api") or "").lower()
                    or "responses"
                )
            )
        )
        if llm_api_mode not in {"responses", "chat_completions"}:
            llm_api_mode = "responses"
        llm_api_url = env_value("LLM_API_URL", "")
        resolved_llm_api_url = _resolve_llm_endpoint(
            llm_api_url or openai_base_url,
            llm_api_mode,
        )
        resolved_llm_api_key = env_value("LLM_API_KEY", "") or openai_api_key
        resolved_llm_model = env_value("LLM_MODEL", "") or openai_model or "gpt-5.4"
        research_llm_default = bool(resolved_llm_api_key)
        return cls(
            project_root=project_root,
            data_dir=project_root / "data",
            schema_dir=project_root / "data" / "schema",
            docs_dir=project_root / "docs",
            research_dir=project_root / "research",
            reports_dir=project_root / "reports",
            tests_dir=project_root / "tests",
            artifacts_dir=project_root / "artifacts",
            database_dir=project_root / "data" / "db",
            task_db_path=project_root / "data" / "db" / "task_results.sqlite3",
            fetched_sources_dir=project_root / "artifacts" / "fetched_sources",
            run_mainnet_fork_tests=_read_bool_env(
                "RUN_MAINNET_FORK_TESTS",
                file_env.get("RUN_MAINNET_FORK_TESTS", "").lower() in {"1", "true", "yes", "on"},
            ),
            mainnet_rpc_url=env_value("MAINNET_RPC_URL", ""),
            eth_rpc_url=env_value("ETH_RPC_URL", ""),
            mainnet_fork_block=int(env_value("MAINNET_FORK_BLOCK", "24654367")),
            etherscan_api_key=env_value("ETHERSCAN_API_KEY", ""),
            database_url=os.getenv(
                "DATABASE_URL",
                file_env.get(
                    "DATABASE_URL",
                    f"sqlite:///{(project_root / 'data' / 'db' / 'task_results.sqlite3').resolve()}",
                ),
            ),
            research_llm_enabled=_read_bool_env("RESEARCH_LLM_ENABLED", research_llm_default),
            llm_api_url=resolved_llm_api_url,
            llm_api_key=resolved_llm_api_key,
            llm_model=resolved_llm_model,
            llm_api_mode=llm_api_mode,
            llm_timeout_seconds=int(os.getenv("LLM_TIMEOUT_SECONDS", "45")),
            llm_temperature=float(os.getenv("LLM_TEMPERATURE", "0.2")),
            llm_max_tokens=int(os.getenv("LLM_MAX_TOKENS", "2200")),
            save_verbose_artifacts=_read_bool_env(
                "SAVE_VERBOSE_ARTIFACTS",
                file_env.get("SAVE_VERBOSE_ARTIFACTS", "").lower() in {"1", "true", "yes", "on"},
            ),
        )

    @property
    def preferred_mainnet_rpc(self) -> str:
        """优先返回主网 RPC。

        优先级：

        1. MAINNET_RPC_URL
        2. ETH_RPC_URL
        """

        return self.mainnet_rpc_url or self.eth_rpc_url

    @property
    def research_llm_available(self) -> bool:
        """返回研究增强层是否具备可用配置。"""

        return (
            self.research_llm_enabled
            and bool(self.llm_api_url)
            and bool(self.llm_api_key)
            and bool(self.llm_model)
        )
