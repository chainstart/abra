"""链上地址源码拉取。

Phase 1 之后，最重要的成品能力之一就是：

- 不只是分析本地目录
- 还能直接输入链上地址

当前实现基于 Etherscan 合约源码接口，使用标准库完成。
"""

from __future__ import annotations

from dataclasses import dataclass
import json
from pathlib import Path
import re
from typing import Any
from urllib import parse, request

from services.shared.settings import ProjectSettings


ADDRESS_PATTERN = re.compile(r"^0x[a-fA-F0-9]{40}$")


@dataclass(frozen=True)
class FetchedSourceLayout:
    """链上源码拉取结果。"""

    address: str
    contract_name: str
    root_dir: Path
    solidity_files: list[Path]


def is_contract_address(target: str) -> bool:
    """判断输入是否像一个合约地址。"""

    return bool(ADDRESS_PATTERN.fullmatch(target.strip()))


def _etherscan_request(address: str, api_key: str) -> dict[str, Any]:
    """调用 Etherscan 合约源码接口。"""

    query = parse.urlencode(
        {
            "module": "contract",
            "action": "getsourcecode",
            "address": address,
            "apikey": api_key,
        }
    )
    url = f"https://api.etherscan.io/api?{query}"
    with request.urlopen(url, timeout=30) as response:
        return json.loads(response.read().decode("utf-8"))


def _normalize_multifile_source(source_code: str) -> dict[str, str]:
    """规范化 Etherscan 返回的源码结构。

    Etherscan 常见 3 种返回形式：

    1. 单文件 Solidity 文本
    2. 多文件 JSON
    3. 多文件 JSON 外层再包一层花括号
    """

    raw = source_code.strip()
    if raw.startswith("{{") and raw.endswith("}}"):
        raw = raw[1:-1]

    if raw.startswith("{"):
        data = json.loads(raw)
        sources = data.get("sources", {})
        normalized: dict[str, str] = {}
        for path, value in sources.items():
            if isinstance(value, dict):
                normalized[path] = value.get("content", "")
            else:
                normalized[path] = str(value)
        return normalized

    return {"Contract.sol": source_code}


def fetch_contract_source(address: str) -> FetchedSourceLayout:
    """根据链上地址拉取并落地源码。"""

    settings = ProjectSettings.from_env()
    if not settings.etherscan_api_key:
        raise RuntimeError("缺少 ETHERSCAN_API_KEY，无法拉取链上源码。")

    payload = _etherscan_request(address, settings.etherscan_api_key)
    if payload.get("status") != "1":
        message = payload.get("message", "unknown error")
        result = payload.get("result", "")
        raise RuntimeError(f"Etherscan 拉取失败: {message} {result}")

    result = payload["result"][0]
    source_code = result.get("SourceCode", "")
    contract_name = result.get("ContractName", "UnknownContract") or "UnknownContract"
    if not source_code:
        raise RuntimeError(f"地址 {address} 没有可用源码。")

    source_map = _normalize_multifile_source(source_code)

    root_dir = settings.fetched_sources_dir / address.lower()
    root_dir.mkdir(parents=True, exist_ok=True)
    solidity_files: list[Path] = []

    for relative_path, content in source_map.items():
        safe_relative = relative_path.lstrip("/").replace("\\", "/")
        if not safe_relative.endswith(".sol"):
            safe_relative = f"{safe_relative}.sol"
        destination = root_dir / safe_relative
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_text(content, encoding="utf-8")
        solidity_files.append(destination)

    return FetchedSourceLayout(
        address=address,
        contract_name=contract_name,
        root_dir=root_dir,
        solidity_files=sorted(solidity_files),
    )
