"""LLM 客户端测试。"""

from __future__ import annotations

import io
import json
from pathlib import Path
import sys
import tempfile
import unittest
from urllib import error
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from services.shared.llm_client import OpenAiCompatibleLlmClient  # noqa: E402


class _FakeHttpResponse(io.BytesIO):
    """最小 HTTP 响应桩。"""

    def __enter__(self) -> "_FakeHttpResponse":
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        return None


class LlmClientPhase19Test(unittest.TestCase):
    """验证最小 LLM 客户端。"""

    def setUp(self) -> None:
        self.cache_paths = [
            ROOT / "tests" / ".tmp_llm_cache_responses.json",
            ROOT / "tests" / ".tmp_llm_cache_plain.json",
            ROOT / "tests" / ".tmp_llm_cache_wrapped.json",
            ROOT / "tests" / ".tmp_llm_cache_fallback.json",
            ROOT / "tests" / ".tmp_llm_cache_retry.json",
        ]
        for path in self.cache_paths:
            if path.exists():
                path.unlink()

    def tearDown(self) -> None:
        for path in self.cache_paths:
            if path.exists():
                path.unlink()

    def test_complete_json_can_parse_responses_api_response(self) -> None:
        """应能解析 OpenAI Responses API 结构。"""

        payload = {
            "model": "gpt-5.4",
            "status": "completed",
            "output": [
                {
                    "content": [
                        {
                            "type": "output_text",
                            "text": json.dumps({"mode": "responses"}, ensure_ascii=False),
                        }
                    ]
                }
            ],
        }
        with patch.dict(
            "os.environ",
            {
                "OPENAI_API_KEY": "secret",
                "OPENAI_BASE_URL": "https://api.openai.com/v1",
                "OPENAI_MODEL": "gpt-5.4",
                "LLM_API_MODE": "responses",
                "LLM_CACHE_PATH": str(ROOT / "tests" / ".tmp_llm_cache_responses.json"),
            },
            clear=True,
        ):
            client = OpenAiCompatibleLlmClient()
            with patch(
                "urllib.request.urlopen",
                return_value=_FakeHttpResponse(json.dumps(payload).encode("utf-8")),
            ):
                result = client.complete_json(
                    system_prompt="system",
                    user_prompt="user",
                )

        self.assertEqual(result.model, "gpt-5.4")
        self.assertEqual(result.content["mode"], "responses")
        self.assertEqual(result.finish_reason, "completed")

    def test_complete_json_can_parse_plain_json_response(self) -> None:
        """应能解析 OpenAI 兼容响应。"""

        payload = {
            "model": "demo-model",
            "choices": [
                {
                    "message": {
                        "content": json.dumps({"hello": "world"}, ensure_ascii=False),
                    },
                    "finish_reason": "stop",
                }
            ],
        }
        with patch.dict(
            "os.environ",
            {
                "RESEARCH_LLM_ENABLED": "true",
                "LLM_API_URL": "https://llm.example/v1/chat/completions",
                "LLM_API_KEY": "secret",
                "LLM_MODEL": "demo-model",
                "LLM_API_MODE": "chat_completions",
                "LLM_CACHE_PATH": str(ROOT / "tests" / ".tmp_llm_cache_plain.json"),
            },
            clear=True,
        ):
            client = OpenAiCompatibleLlmClient()
            with patch(
                "urllib.request.urlopen",
                return_value=_FakeHttpResponse(json.dumps(payload).encode("utf-8")),
            ):
                result = client.complete_json(
                    system_prompt="system",
                    user_prompt="user",
                )

        self.assertEqual(result.provider, "openai-compatible")
        self.assertEqual(result.model, "demo-model")
        self.assertEqual(result.content["hello"], "world")

    def test_complete_json_can_extract_json_from_wrapped_text(self) -> None:
        """即使模型把 JSON 包在额外文字里，也应能提取。"""

        payload = {
            "model": "demo-model",
            "choices": [
                {
                    "message": {
                        "content": "下面是结果：\n{\"status\": \"ok\", \"count\": 2}\n请查收。",
                    },
                    "finish_reason": "stop",
                }
            ],
        }
        with patch.dict(
            "os.environ",
            {
                "RESEARCH_LLM_ENABLED": "true",
                "LLM_API_URL": "https://llm.example/v1/chat/completions",
                "LLM_API_KEY": "secret",
                "LLM_MODEL": "demo-model",
                "LLM_API_MODE": "chat_completions",
                "LLM_CACHE_PATH": str(ROOT / "tests" / ".tmp_llm_cache_wrapped.json"),
            },
            clear=True,
        ):
            client = OpenAiCompatibleLlmClient()
            with patch(
                "urllib.request.urlopen",
                return_value=_FakeHttpResponse(json.dumps(payload).encode("utf-8")),
            ):
                result = client.complete_json(
                    system_prompt="system",
                    user_prompt="user",
                )

        self.assertEqual(result.content["status"], "ok")
        self.assertEqual(result.content["count"], 2)

    def test_complete_json_falls_back_to_chat_completions_when_responses_is_incompatible(self) -> None:
        """当中转站不兼容 Responses API 时，应自动回退到 chat/completions。"""

        payload = {
            "model": "gpt-5.4",
            "choices": [
                {
                    "message": {
                        "content": json.dumps({"mode": "chat_fallback"}, ensure_ascii=False),
                    },
                    "finish_reason": "stop",
                }
            ],
        }
        calls: list[str] = []

        def fake_urlopen(req, timeout=0):  # noqa: ANN001
            calls.append(req.full_url)
            if req.full_url.endswith("/responses"):
                raise error.HTTPError(
                    req.full_url,
                    502,
                    "Bad Gateway",
                    hdrs=None,
                    fp=_FakeHttpResponse(b"error code: 502"),
                )
            return _FakeHttpResponse(json.dumps(payload).encode("utf-8"))

        with patch.dict(
            "os.environ",
            {
                "OPENAI_API_KEY": "secret",
                "OPENAI_BASE_URL": "https://relay.example/v1",
                "OPENAI_MODEL": "gpt-5.4",
                "LLM_API_MODE": "responses",
                "LLM_CACHE_PATH": str(ROOT / "tests" / ".tmp_llm_cache_fallback.json"),
            },
            clear=True,
        ):
            client = OpenAiCompatibleLlmClient()
            with patch("urllib.request.urlopen", side_effect=fake_urlopen):
                result = client.complete_json(
                    system_prompt="system",
                    user_prompt="user",
                )

        self.assertEqual(result.content["mode"], "chat_fallback")
        self.assertEqual(
            calls,
            [
                "https://relay.example/v1/responses",
                "https://relay.example/v1/chat/completions",
            ],
        )

    def test_complete_json_retries_transient_chat_completion_error_once(self) -> None:
        """chat/completions 遇到瞬时 503 时，应自动重试一次。"""

        payload = {
            "model": "demo-model",
            "choices": [
                {
                    "message": {
                        "content": json.dumps({"mode": "chat_retry"}, ensure_ascii=False),
                    },
                    "finish_reason": "stop",
                }
            ],
        }
        call_count = 0

        def fake_urlopen(req, timeout=0):  # noqa: ANN001
            nonlocal call_count
            call_count += 1
            if call_count == 1:
                raise error.HTTPError(
                    req.full_url,
                    503,
                    "Service Unavailable",
                    hdrs=None,
                    fp=_FakeHttpResponse(
                        b'{"error":{"message":"Service temporarily unavailable"}}'
                    ),
                )
            return _FakeHttpResponse(json.dumps(payload).encode("utf-8"))

        with patch.dict(
            "os.environ",
            {
                "RESEARCH_LLM_ENABLED": "true",
                "LLM_API_URL": "https://llm.example/v1/chat/completions",
                "LLM_API_KEY": "secret",
                "LLM_MODEL": "demo-model",
                "LLM_API_MODE": "chat_completions",
                "LLM_CACHE_PATH": str(ROOT / "tests" / ".tmp_llm_cache_retry.json"),
            },
            clear=True,
        ):
            client = OpenAiCompatibleLlmClient()
            with patch("urllib.request.urlopen", side_effect=fake_urlopen):
                result = client.complete_json(
                    system_prompt="system",
                    user_prompt="user",
                )

        self.assertEqual(result.content["mode"], "chat_retry")
        self.assertEqual(call_count, 2)

    def test_complete_json_can_reuse_cached_response_when_network_fails(self) -> None:
        """已有缓存时，网络失败也应返回缓存结果。"""

        payload = {
            "model": "demo-model",
            "choices": [
                {
                    "message": {
                        "content": json.dumps({"cached": True}, ensure_ascii=False),
                    },
                    "finish_reason": "stop",
                }
            ],
        }

        with tempfile.TemporaryDirectory() as tmp_dir, patch.dict(
            "os.environ",
            {
                "RESEARCH_LLM_ENABLED": "true",
                "LLM_API_URL": "https://llm.example/v1/chat/completions",
                "LLM_API_KEY": "secret",
                "LLM_MODEL": "demo-model",
                "DATABASE_URL": f"sqlite:///{Path(tmp_dir) / 'task_results.sqlite3'}",
                "LLM_CACHE_PATH": str(Path(tmp_dir) / "llm_cache.json"),
            },
            clear=True,
        ):
            client = OpenAiCompatibleLlmClient()
            with patch(
                "urllib.request.urlopen",
                return_value=_FakeHttpResponse(json.dumps(payload).encode("utf-8")),
            ):
                first = client.complete_json(
                    system_prompt="system",
                    user_prompt="user",
                )
            with patch(
                "urllib.request.urlopen",
                side_effect=error.HTTPError(
                    "https://llm.example/v1/chat/completions",
                    503,
                    "Service Unavailable",
                    hdrs=None,
                    fp=_FakeHttpResponse(
                        b'{"error":{"message":"Service temporarily unavailable"}}'
                    ),
                ),
            ):
                second = client.complete_json(
                    system_prompt="system",
                    user_prompt="user",
                )

        self.assertEqual(first.content["cached"], True)
        self.assertEqual(second.content["cached"], True)


if __name__ == "__main__":
    unittest.main()
