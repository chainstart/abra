"""函数选择器 / 事件主题解析。

目标：

- 优先使用本地内置常用签名
- 其次使用数据库缓存
- 最后可选调用 4byte.directory 做在线解析
"""

from __future__ import annotations

import json
from urllib import parse, request

from services.storage.task_database import load_signature_cache, save_signature_cache


KNOWN_FUNCTION_SELECTORS = {
    "0xa9059cbb": "transfer(address,uint256)",
    "0x23b872dd": "transferFrom(address,address,uint256)",
    "0x095ea7b3": "approve(address,uint256)",
    "0x70a08231": "balanceOf(address)",
    "0xd0e30db0": "deposit()",
    "0x2e1a7d4d": "withdraw(uint256)",
}

KNOWN_EVENT_TOPICS = {
    "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef": "Transfer(address,address,uint256)",
    "0x8c5be1e5ebec7d5bd14f714f7f5dc6ceecfbd6c52bf6b49a7f7fbc6f5d7d5f6b": "Approval(address,address,uint256)",
}


def _fetch_4byte_signature(hex_signature: str, kind: str) -> str | None:
    """尝试从 4byte.directory 拉签名。

    kind:

    - `function`
    - `event`
    """

    if kind == "function":
        endpoint = "https://www.4byte.directory/api/v1/signatures/"
        query = parse.urlencode({"hex_signature": hex_signature})
        key = "text_signature"
    else:
        endpoint = "https://www.4byte.directory/api/v1/event-signatures/"
        query = parse.urlencode({"hex_signature": hex_signature})
        key = "text_signature"

    url = f"{endpoint}?{query}"
    with request.urlopen(url, timeout=15) as response:
        payload = json.loads(response.read().decode("utf-8"))
    results = payload.get("results", [])
    if not results:
        return None
    return results[0].get(key)


def resolve_function_selector(selector: str | None) -> str | None:
    """解析函数 selector。"""

    if not selector:
        return None
    if selector in KNOWN_FUNCTION_SELECTORS:
        return KNOWN_FUNCTION_SELECTORS[selector]
    cached = load_signature_cache(selector)
    if cached and cached["kind"] == "function":
        return cached["text_signature"]

    try:
        resolved = _fetch_4byte_signature(selector, "function")
    except Exception:  # noqa: BLE001
        resolved = None

    if resolved:
        save_signature_cache(
            cache_key=selector,
            kind="function",
            text_signature=resolved,
            source="4byte",
        )
    return resolved


def resolve_event_topic(topic0: str | None) -> str | None:
    """解析事件 topic0。"""

    if not topic0:
        return None
    if topic0 in KNOWN_EVENT_TOPICS:
        return KNOWN_EVENT_TOPICS[topic0]
    cached = load_signature_cache(topic0)
    if cached and cached["kind"] == "event":
        return cached["text_signature"]

    try:
        resolved = _fetch_4byte_signature(topic0, "event")
    except Exception:  # noqa: BLE001
        resolved = None

    if resolved:
        save_signature_cache(
            cache_key=topic0,
            kind="event",
            text_signature=resolved,
            source="4byte",
        )
    return resolved
