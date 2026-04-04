"""外部攻击事件发现。

当前优先接入 SlowMist Hacked 首页：

- 首页结构稳定，可直接抓到最新事件
- 包含日期、目标、摘要、损失、攻击方法与参考链接
- 适合作为“自己找事件”的候选入口
"""

from __future__ import annotations

from datetime import datetime, timezone
import hashlib
from html import unescape
import re
from typing import Any
from urllib import request

from services.research.discovered_incident_repository import save_discovered_incidents
from services.research.models import DiscoveredIncidentCandidate


SLOWMIST_HOME_URL = "https://hacked.slowmist.io/"

PROTOCOL_TYPE_HINTS = {
    "lending": ["lending", "borrow", "loan", "vault", "collateral", "comptroller", "market"],
    "amm": ["swap", "pool", "amm", "dex", "liquidity", "pair", "curve", "uniswap"],
    "bridge": ["bridge", "cross-chain", "cross chain", "gateway", "relay"],
    "staking": ["stake", "staking", "restaking", "validator", "lst", "lsd"],
    "governance": ["governance", "proposal", "vote", "quorum", "timelock"],
}

CATEGORY_HINTS = {
    "SC-01: Reentrancy": ["reentrancy", "callback"],
    "SC-02: Access Control": ["access control", "permission", "admin", "arbitrary call", "validation missing"],
    "SC-03: Oracle Manipulation": ["oracle", "price", "twap", "spot price", "price dependency"],
    "SC-04: Flash Loan Attacks": ["flash loan"],
    "SC-08: Upgrade Safety": ["upgrade", "proxy", "implementation"],
    "SC-09: Governance": ["governance", "proposal", "vote", "timelock"],
}

LOW_SIGNAL_ATTACK_METHODS = {
    "phishing",
    "rug pull",
    "private key compromise",
    "social engineering",
}


def _stable_candidate_id(*parts: object) -> str:
    """生成稳定候选事件 ID。"""

    digest = hashlib.sha1("::".join(map(str, parts)).encode("utf-8")).hexdigest()[:16]
    return f"candidate_{digest}"


def _clean_html(text: str) -> str:
    """最小 HTML 清洗。"""

    stripped = re.sub(r"<[^>]+>", "", text)
    stripped = unescape(stripped)
    stripped = re.sub(r"\s+", " ", stripped)
    return stripped.strip()


def _fetch_slowmist_home() -> str:
    """抓取 SlowMist 首页。"""

    req = request.Request(
        SLOWMIST_HOME_URL,
        headers={
            "User-Agent": (
                "Mozilla/5.0 (X11; Linux x86_64) "
                "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0 Safari/537.36"
            )
        },
    )
    with request.urlopen(req, timeout=30) as response:
        return response.read().decode("utf-8", errors="ignore")


def _extract_protocol_name(title: str) -> str:
    """从标题抽一个协议名。"""

    cleaned = title.strip()
    cleaned = re.sub(r"\s+on\s+\w+$", "", cleaned, flags=re.IGNORECASE)
    cleaned = re.sub(r"\s*\([^)]*\)\s*", " ", cleaned).strip()
    return cleaned


def _infer_protocol_type(text: str) -> str:
    """推断协议类型。"""

    lowered = text.lower()
    scored: dict[str, int] = {}
    for protocol_type, hints in PROTOCOL_TYPE_HINTS.items():
        score = sum(1 for hint in hints if hint in lowered)
        if score:
            scored[protocol_type] = score
    if not scored:
        return "unknown"
    return max(scored.items(), key=lambda item: item[1])[0]


def _suggest_categories(text: str, attack_method: str) -> list[str]:
    """基于文本和攻击方法给出研究类别建议。"""

    lowered = f"{text} {attack_method}".lower()
    categories = [
        category
        for category, hints in CATEGORY_HINTS.items()
        if any(hint in lowered for hint in hints)
    ]
    return categories or ["SC-07: Logic Errors"]


def _relevance_score(text: str, attack_method: str, loss_text: str) -> float:
    """计算对“研究事件”的相关性分数。"""

    lowered = f"{text} {attack_method}".lower()
    score = 0.2
    if any(keyword in lowered for keyword in ["oracle", "reentrancy", "flash loan", "governance", "arbitrary call", "bridge"]):
        score += 0.35
    if any(keyword in lowered for keyword in ["pool", "vault", "lending", "market", "dex", "bridge", "staking"]):
        score += 0.2
    if attack_method.lower().strip() and attack_method.lower().strip() not in LOW_SIGNAL_ATTACK_METHODS:
        score += 0.15
    if loss_text and loss_text.strip() not in {"-", ""}:
        score += 0.1
    return round(min(score, 0.99), 2)


def _parse_slowmist_entries(html: str) -> list[DiscoveredIncidentCandidate]:
    """解析 SlowMist 首页中的事件列表。"""

    entries: list[DiscoveredIncidentCandidate] = []
    blocks = re.findall(r"<li>\s*(.*?)\s*</li>", html, flags=re.DOTALL)
    for block in blocks:
        if "Hacked target:" not in block:
            continue
        time_match = re.search(r'<span class="time">(.*?)</span>', block, flags=re.DOTALL)
        target_match = re.search(r'Hacked target:\s*</em>(.*?)</h3>', block, flags=re.DOTALL)
        desc_match = re.search(r'Description of the event:\s*</em>(.*?)</p>', block, flags=re.DOTALL)
        loss_match = re.search(r'Amount of loss:\s*</em>\s*(.*?)\s*</span>', block, flags=re.DOTALL)
        method_match = re.search(r'Attack method:\s*</em>(.*?)</span>', block, flags=re.DOTALL)
        ref_match = re.search(r'<a href="([^"]+)"[^>]*>View Reference Sources</a>', block, flags=re.DOTALL)

        discovered_at = _clean_html(time_match.group(1)) if time_match else ""
        title = _clean_html(target_match.group(1)) if target_match else ""
        summary = _clean_html(desc_match.group(1)) if desc_match else ""
        loss_text = _clean_html(loss_match.group(1)) if loss_match else ""
        attack_method = _clean_html(method_match.group(1)) if method_match else ""
        reference_url = ref_match.group(1).strip() if ref_match else ""

        if not title or not summary:
            continue

        protocol_name_guess = _extract_protocol_name(title)
        protocol_type_guess = _infer_protocol_type(f"{title} {summary}")
        suggested_categories = _suggest_categories(summary, attack_method)
        relevance_score = _relevance_score(summary, attack_method, loss_text)
        tags = sorted(
            {
                protocol_type_guess,
                attack_method.lower().strip(),
                *(category.lower().split(":")[-1].strip() for category in suggested_categories),
            }
            - {""}
        )

        entries.append(
            DiscoveredIncidentCandidate(
                candidate_id=_stable_candidate_id("slowmist", discovered_at, title, reference_url or summary[:80]),
                source="slowmist_hacked",
                title=title,
                discovered_at=discovered_at,
                summary=summary,
                attack_method=attack_method,
                loss_text=loss_text,
                protocol_name_guess=protocol_name_guess,
                protocol_type_guess=protocol_type_guess,
                relevance_score=relevance_score,
                suggested_categories=suggested_categories,
                tags=tags,
                reference_url=reference_url,
            )
        )

    entries.sort(
        key=lambda item: (
            -item.relevance_score,
            item.discovered_at,
            item.title,
        )
    )
    return entries


def discover_external_incidents(
    *,
    limit: int = 20,
    min_relevance: float = 0.45,
    save: bool = True,
) -> list[DiscoveredIncidentCandidate]:
    """发现最新外部攻击事件候选。"""

    html = _fetch_slowmist_home()
    candidates = _parse_slowmist_entries(html)
    filtered = [item for item in candidates if item.relevance_score >= min_relevance]
    selected = filtered[:limit]
    if save:
        save_discovered_incidents(selected)
    return selected
