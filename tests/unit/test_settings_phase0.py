"""Phase 0 配置测试。"""

from __future__ import annotations

from pathlib import Path
import sys
import unittest
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from services.shared.settings import ProjectSettings  # noqa: E402


class SettingsPhase0Test(unittest.TestCase):
    """验证配置入口的默认值和环境变量解析。"""

    def test_default_settings_are_stable(self) -> None:
        """默认配置应该能在无环境变量时稳定工作。"""

        with patch.dict("os.environ", {}, clear=True), patch(
            "services.shared.settings._read_env_file",
            side_effect=[{}, {}],
        ), patch(
            "services.shared.settings._read_codex_provider_defaults",
            return_value={},
        ):
            settings = ProjectSettings.from_env()

        self.assertEqual(settings.project_root, ROOT)
        self.assertEqual(settings.schema_dir, ROOT / "data" / "schema")
        self.assertFalse(settings.run_mainnet_fork_tests)
        self.assertEqual(settings.mainnet_fork_block, 24654367)
        self.assertEqual(settings.preferred_mainnet_rpc, "")
        self.assertFalse(settings.research_llm_enabled)
        self.assertFalse(settings.research_llm_available)
        self.assertEqual(settings.llm_api_mode, "responses")
        self.assertEqual(settings.llm_api_url, "https://api.openai.com/v1/responses")
        self.assertEqual(settings.llm_model, "gpt-5.4")
        self.assertFalse(settings.save_verbose_artifacts)

    def test_env_settings_can_override_defaults(self) -> None:
        """环境变量应该能覆盖默认值。"""

        with patch.dict(
            "os.environ",
            {
                "RUN_MAINNET_FORK_TESTS": "true",
                "MAINNET_RPC_URL": "https://rpc.example",
                "MAINNET_FORK_BLOCK": "12345678",
                "RESEARCH_LLM_ENABLED": "true",
                "LLM_API_URL": "https://llm.example/v1/chat/completions",
                "LLM_API_KEY": "secret",
                "LLM_MODEL": "model-x",
                "LLM_TIMEOUT_SECONDS": "60",
                "LLM_TEMPERATURE": "0.35",
                "LLM_MAX_TOKENS": "4096",
                "SAVE_VERBOSE_ARTIFACTS": "true",
            },
            clear=True,
        ), patch(
            "services.shared.settings._read_env_file",
            side_effect=[{}, {}],
        ), patch(
            "services.shared.settings._read_codex_provider_defaults",
            return_value={},
        ):
            settings = ProjectSettings.from_env()

        self.assertTrue(settings.run_mainnet_fork_tests)
        self.assertEqual(settings.mainnet_rpc_url, "https://rpc.example")
        self.assertEqual(settings.preferred_mainnet_rpc, "https://rpc.example")
        self.assertEqual(settings.mainnet_fork_block, 12345678)
        self.assertTrue(settings.research_llm_enabled)
        self.assertTrue(settings.research_llm_available)
        self.assertEqual(settings.llm_api_url, "https://llm.example/v1/chat/completions")
        self.assertEqual(settings.llm_model, "model-x")
        self.assertEqual(settings.llm_timeout_seconds, 60)
        self.assertEqual(settings.llm_temperature, 0.35)
        self.assertEqual(settings.llm_max_tokens, 4096)
        self.assertEqual(settings.llm_api_mode, "chat_completions")
        self.assertTrue(settings.save_verbose_artifacts)

    def test_openai_envs_can_enable_llm_without_generic_aliases(self) -> None:
        """只配置 OPENAI_* 环境变量时也应自动启用。"""

        with patch.dict(
            "os.environ",
            {
                "OPENAI_API_KEY": "openai-secret",
                "OPENAI_BASE_URL": "https://api.openai.com/v1",
                "OPENAI_MODEL": "gpt-5.4",
            },
            clear=True,
        ), patch(
            "services.shared.settings._read_env_file",
            side_effect=[{}, {}],
        ), patch(
            "services.shared.settings._read_codex_provider_defaults",
            return_value={},
        ):
            settings = ProjectSettings.from_env()

        self.assertTrue(settings.research_llm_enabled)
        self.assertTrue(settings.research_llm_available)
        self.assertEqual(settings.llm_api_url, "https://api.openai.com/v1/responses")
        self.assertEqual(settings.llm_api_key, "openai-secret")
        self.assertEqual(settings.llm_model, "gpt-5.4")
        self.assertEqual(settings.llm_api_mode, "responses")

    def test_llm_api_url_chat_endpoint_can_switch_mode(self) -> None:
        """显式提供 chat/completions 端点时应自动识别模式。"""

        with patch.dict(
            "os.environ",
            {
                "LLM_API_URL": "https://example.com/v1/chat/completions",
                "LLM_API_KEY": "secret",
                "LLM_MODEL": "demo-model",
            },
            clear=True,
        ), patch(
            "services.shared.settings._read_env_file",
            side_effect=[{}, {}],
        ), patch(
            "services.shared.settings._read_codex_provider_defaults",
            return_value={},
        ):
            settings = ProjectSettings.from_env()

        self.assertEqual(settings.llm_api_mode, "chat_completions")
        self.assertEqual(settings.llm_api_url, "https://example.com/v1/chat/completions")

    def test_project_env_file_can_supply_openai_settings(self) -> None:
        """项目根目录的 .env 文件也应能提供 OpenAI 配置。"""

        with patch.dict("os.environ", {}, clear=True), patch(
            "services.shared.settings._read_env_file",
            side_effect=[
                {
                    "OPENAI_API_KEY": "env-file-key",
                    "OPENAI_BASE_URL": "https://relay.example/v1",
                    "OPENAI_MODEL": "gpt-5.4",
                    "RESEARCH_LLM_ENABLED": "true",
                },
                {},
            ],
        ), patch(
            "services.shared.settings._read_codex_provider_defaults",
            return_value={},
        ):
            settings = ProjectSettings.from_env()

        self.assertTrue(settings.research_llm_available)
        self.assertEqual(settings.llm_api_url, "https://relay.example/v1/responses")
        self.assertEqual(settings.llm_api_key, "env-file-key")
        self.assertEqual(settings.llm_model, "gpt-5.4")

    def test_codex_provider_defaults_can_supply_relay_settings(self) -> None:
        """未显式配置时，也应能继承 Codex 当前使用的中转站设置。"""

        with patch.dict("os.environ", {}, clear=True), patch(
            "services.shared.settings._read_env_file",
            side_effect=[{}, {}],
        ), patch(
            "services.shared.settings._read_codex_provider_defaults",
            return_value={
                "provider_model": "gpt-5.4",
                "provider_base_url": "https://api.yescode.cloud/v1",
                "provider_wire_api": "responses",
                "provider_env_key": "OPENAI_API_KEY",
            },
        ), patch.dict(
            "os.environ",
            {"OPENAI_API_KEY": "relay-key"},
            clear=True,
        ):
            settings = ProjectSettings.from_env()

        self.assertTrue(settings.research_llm_enabled)
        self.assertTrue(settings.research_llm_available)
        self.assertEqual(settings.llm_api_url, "https://api.yescode.cloud/v1/responses")
        self.assertEqual(settings.llm_model, "gpt-5.4")
        self.assertEqual(settings.llm_api_mode, "responses")

    def test_explicit_project_relay_url_prefers_provider_key_even_if_provider_default_url_is_stale(self) -> None:
        """项目显式指定新 relay URL 时，不应继续落回旧 OPENAI_API_KEY。"""

        with patch.dict(
            "os.environ",
            {
                "OPENAI_API_KEY": "old-openai-key",
                "DENGTA_API_KEY": "new-relay-key",
            },
            clear=True,
        ), patch(
            "services.shared.settings._read_env_file",
            side_effect=[
                {
                    "OPENAI_BASE_URL": "https://aiapi.dengta-learning.online/v1",
                    "OPENAI_MODEL": "gpt-5.4",
                    "LLM_API_MODE": "chat_completions",
                },
                {},
            ],
        ), patch(
            "services.shared.settings._read_codex_provider_defaults",
            return_value={
                "provider_model": "gpt-5.4",
                "provider_base_url": "https://codexsapinew.shop/v1",
                "provider_wire_api": "responses",
                "provider_env_key": "DENGTA_API_KEY",
            },
        ):
            settings = ProjectSettings.from_env()

        self.assertEqual(
            settings.llm_api_url,
            "https://aiapi.dengta-learning.online/v1/chat/completions",
        )
        self.assertEqual(settings.llm_api_key, "new-relay-key")
        self.assertEqual(settings.llm_api_mode, "chat_completions")


if __name__ == "__main__":
    unittest.main()
