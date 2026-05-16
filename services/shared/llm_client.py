"""最小 OpenAI 兼容 LLM 客户端。

目标：

- 不引入额外 SDK
- 支持 OpenAI `Responses API` 与兼容的 `/chat/completions`
- 返回 JSON 结果，供研究增强层消费
"""

from __future__ import annotations

from dataclasses import dataclass
import json
import socket
from threading import Lock
import time
from typing import Any
from urllib import error, request

from services.shared.llm_cache import build_llm_cache_key, load_llm_cache, save_llm_cache
from services.shared.settings import ProjectSettings


@dataclass(frozen=True)
class LlmJsonResponse:
    """结构化 LLM 响应。"""

    provider: str
    model: str
    content: dict[str, Any]
    raw_text: str
    finish_reason: str


def _extract_text_content(message_content: Any) -> str:
    """兼容不同 content 结构。"""

    if isinstance(message_content, str):
        return message_content.strip()
    if isinstance(message_content, list):
        parts: list[str] = []
        for item in message_content:
            if isinstance(item, dict) and item.get("type") == "text":
                parts.append(str(item.get("text", "")))
        return "\n".join(parts).strip()
    return str(message_content or "").strip()


def _extract_json_block(text: str) -> dict[str, Any]:
    """从模型文本输出里提取 JSON。"""

    text = text.strip()
    if not text:
        raise ValueError("LLM 返回内容为空。")

    try:
        return json.loads(text)
    except json.JSONDecodeError:
        start = text.find("{")
        end = text.rfind("}")
        if start == -1 or end == -1 or end <= start:
            raise ValueError("LLM 返回内容中未找到可解析的 JSON 对象。") from None
        return json.loads(text[start : end + 1])


def _extract_responses_text(payload: dict[str, Any]) -> tuple[str, str]:
    """从 Responses API 响应中提取文本。"""

    output_text = str(payload.get("output_text") or "").strip()
    if output_text:
        return output_text, str(payload.get("status") or "")

    texts: list[str] = []
    for item in payload.get("output") or []:
        for content in item.get("content") or []:
            if content.get("type") in {"output_text", "text"}:
                text = str(content.get("text") or "").strip()
                if text:
                    texts.append(text)
    return "\n".join(texts).strip(), str(payload.get("status") or "")


def _normalize_endpoint(url: str, api_mode: str) -> str:
    """把任意基础地址或端点规范成指定模式的最终端点。"""

    normalized = url.strip().rstrip("/")
    if normalized.endswith("/responses"):
        normalized = normalized.removesuffix("/responses")
    elif normalized.endswith("/chat/completions"):
        normalized = normalized.removesuffix("/chat/completions")

    suffix = "/responses" if api_mode == "responses" else "/chat/completions"
    return f"{normalized}{suffix}"


def _should_fallback_to_chat_completions(status_code: int) -> bool:
    """判断 Responses API 失败后是否值得尝试回退到 chat/completions。"""

    return status_code in {404, 405, 415, 422, 500, 501, 502, 503, 504}


def _is_retryable_http_status(status_code: int) -> bool:
    """判断错误是否适合做一次轻量重试。"""

    return status_code in {408, 429, 500, 502, 503, 504}


def _retry_delay_seconds(attempt: int) -> int:
    """返回第 N 次重试前的等待时间。"""

    # attempt 从 0 开始：
    # 0 -> 1s, 1 -> 2s, 2 -> 4s, 3+ -> 8s
    return min(2**attempt, 8)


_REQUEST_THROTTLE_LOCK = Lock()
_LAST_LLM_REQUEST_FINISHED_AT = 0.0
_MIN_REQUEST_INTERVAL_SECONDS = 3.0


def _respect_request_interval() -> None:
    """控制相邻 LLM 请求的最小时间间隔，减少中转站瞬时拥塞。"""

    global _LAST_LLM_REQUEST_FINISHED_AT

    with _REQUEST_THROTTLE_LOCK:
        elapsed = time.time() - _LAST_LLM_REQUEST_FINISHED_AT
        if _LAST_LLM_REQUEST_FINISHED_AT > 0 and elapsed < _MIN_REQUEST_INTERVAL_SECONDS:
            time.sleep(_MIN_REQUEST_INTERVAL_SECONDS - elapsed)


def _mark_request_finished() -> None:
    """记录最近一次 LLM 请求完成时间。"""

    global _LAST_LLM_REQUEST_FINISHED_AT

    with _REQUEST_THROTTLE_LOCK:
        _LAST_LLM_REQUEST_FINISHED_AT = time.time()


class OpenAiCompatibleLlmClient:
    """最小 OpenAI 兼容聊天客户端。"""

    def __init__(self, settings: ProjectSettings | None = None) -> None:
        self.settings = settings or ProjectSettings.from_env()
        if not self.settings.research_llm_available:
            raise ValueError("当前未配置可用的研究 LLM。")

    def complete_json(
        self,
        *,
        system_prompt: str,
        user_prompt: str,
    ) -> LlmJsonResponse:
        """请求模型并解析 JSON。"""

        cache_key = build_llm_cache_key(
            model=self.settings.llm_model,
            api_mode=self.settings.llm_api_mode,
            system_prompt=system_prompt,
            user_prompt=user_prompt,
        )
        cached = load_llm_cache(cache_key)
        if cached:
            return LlmJsonResponse(
                provider="openai-compatible",
                model=str(cached.get("model") or self.settings.llm_model),
                content=dict(cached.get("content") or {}),
                raw_text=str(cached.get("raw_text") or ""),
                finish_reason=str(cached.get("finish_reason") or ""),
            )

        _respect_request_interval()
        try:
            response_payload, resolved_mode = self._request_with_compatible_fallback(
                system_prompt=system_prompt,
                user_prompt=user_prompt,
            )
        except Exception:
            cached = load_llm_cache(cache_key)
            if cached:
                return LlmJsonResponse(
                    provider="openai-compatible",
                    model=str(cached.get("model") or self.settings.llm_model),
                    content=dict(cached.get("content") or {}),
                    raw_text=str(cached.get("raw_text") or ""),
                    finish_reason=str(cached.get("finish_reason") or ""),
                )
            raise
        finally:
            _mark_request_finished()

        if resolved_mode == "responses":
            raw_text, finish_reason = _extract_responses_text(response_payload)
        else:
            choices = response_payload.get("choices") or []
            if not choices:
                raise ValueError("LLM 响应缺少 choices。")
            first = choices[0]
            raw_text = _extract_text_content((first.get("message") or {}).get("content"))
            finish_reason = str(first.get("finish_reason") or "")

        content = _extract_json_block(raw_text)

        result = LlmJsonResponse(
            provider="openai-compatible",
            model=str(response_payload.get("model") or self.settings.llm_model),
            content=content,
            raw_text=raw_text,
            finish_reason=finish_reason,
        )
        save_llm_cache(
            cache_key,
            {
                "model": result.model,
                "content": result.content,
                "raw_text": result.raw_text,
                "finish_reason": result.finish_reason,
            },
        )
        return result

    def _build_payload(
        self,
        *,
        api_mode: str,
        system_prompt: str,
        user_prompt: str,
    ) -> dict[str, Any]:
        """按不同 API 模式构造请求体。"""

        if api_mode == "responses":
            payload = {
                "model": self.settings.llm_model,
                "instructions": system_prompt,
                "input": user_prompt,
                "temperature": self.settings.llm_temperature,
                "max_output_tokens": self.settings.llm_max_tokens,
                "text": {
                    "format": {
                        "type": "json_object",
                    }
                },
            }
            return payload

        return {
            "model": self.settings.llm_model,
            "temperature": self.settings.llm_temperature,
            "max_tokens": self.settings.llm_max_tokens,
            "messages": [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt},
            ],
        }

    def _perform_request(
        self,
        *,
        api_mode: str,
        endpoint_url: str,
        payload: dict[str, Any],
    ) -> dict[str, Any]:
        """执行单次指定模式的请求。"""

        raw_body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        response_payload: dict[str, Any] | None = None
        last_timeout_error: Exception | None = None
        max_attempts = 8
        for attempt in range(max_attempts):
            req = request.Request(
                endpoint_url,
                data=raw_body,
                headers={
                    "Authorization": f"Bearer {self.settings.llm_api_key}",
                    "Content-Type": "application/json",
                    "Accept": "application/json",
                    "User-Agent": (
                        "Mozilla/5.0 (X11; Linux x86_64) "
                        "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123 Safari/537.36"
                    ),
                    "Origin": "https://platform.openai.com",
                    "Referer": "https://platform.openai.com/",
                },
                method="POST",
            )
            timeout_seconds = self.settings.llm_timeout_seconds + attempt * 15
            try:
                with request.urlopen(req, timeout=timeout_seconds) as response:
                    raw_response = response.read().decode("utf-8", errors="ignore")
                    response_payload = json.loads(raw_response)
                break
            except error.HTTPError as exc:  # noqa: PERF203
                body = exc.read().decode("utf-8", errors="ignore")
                if (
                    api_mode == "responses"
                    and _should_fallback_to_chat_completions(exc.code)
                ):
                    raise RuntimeError(
                        f"responses_fallback_candidate: HTTP {exc.code} {body}"
                    ) from exc
                if _is_retryable_http_status(exc.code) and attempt < max_attempts - 1:
                    time.sleep(_retry_delay_seconds(attempt))
                    continue
                raise ValueError(f"LLM 请求失败: HTTP {exc.code} {body}") from exc
            except (TimeoutError, socket.timeout) as exc:
                last_timeout_error = exc
                if attempt < max_attempts - 1:
                    time.sleep(_retry_delay_seconds(attempt))
                    continue
                continue
            except json.JSONDecodeError as exc:
                raise ValueError(f"LLM 返回了非 JSON 内容，无法解析。") from exc
            except error.URLError as exc:
                if isinstance(exc.reason, (TimeoutError, socket.timeout)):
                    last_timeout_error = exc
                    if attempt < max_attempts - 1:
                        time.sleep(_retry_delay_seconds(attempt))
                        continue
                    continue
                raise ValueError(f"LLM 请求失败: {exc}") from exc

        if response_payload is None:
            raise ValueError(f"LLM 请求超时: {last_timeout_error}")
        return response_payload

    def _request_with_compatible_fallback(
        self,
        *,
        system_prompt: str,
        user_prompt: str,
    ) -> tuple[dict[str, Any], str]:
        """请求 LLM，并在中转站不兼容 Responses API 时自动回退。"""

        primary_mode = self.settings.llm_api_mode
        primary_url = _normalize_endpoint(self.settings.llm_api_url, primary_mode)
        primary_payload = self._build_payload(
            api_mode=primary_mode,
            system_prompt=system_prompt,
            user_prompt=user_prompt,
        )
        try:
            return (
                self._perform_request(
                    api_mode=primary_mode,
                    endpoint_url=primary_url,
                    payload=primary_payload,
                ),
                primary_mode,
            )
        except RuntimeError as exc:
            if primary_mode != "responses":
                raise ValueError(str(exc)) from exc

            fallback_mode = "chat_completions"
            fallback_url = _normalize_endpoint(self.settings.llm_api_url, fallback_mode)
            fallback_payload = self._build_payload(
                api_mode=fallback_mode,
                system_prompt=system_prompt,
                user_prompt=user_prompt,
            )
            try:
                return (
                    self._perform_request(
                        api_mode=fallback_mode,
                        endpoint_url=fallback_url,
                        payload=fallback_payload,
                    ),
                    fallback_mode,
                )
            except Exception as fallback_exc:  # noqa: BLE001
                raise ValueError(
                    "LLM 请求失败，Responses API 不兼容且回退到 chat/completions 也失败: "
                    f"{fallback_exc}"
                ) from fallback_exc
