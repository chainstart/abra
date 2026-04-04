"""Phase 1 协议分类器。

当前分类器是启发式版本，目标不是“绝对聪明”，
而是先给审计 MVP 提供稳定、可解释的协议上下文。
"""

from __future__ import annotations

from collections import Counter
from pathlib import Path

from services.analysis.models import IngestionResult, ProtocolClassification


PROTOCOL_TYPE_RULES = {
    "lending": [
        "borrow",
        "lend",
        "comptroller",
        "ctoken",
        "flashloan",
        "reserve",
        "liquidation",
        "interest",
    ],
    "amm": [
        "swap",
        "pool",
        "tick",
        "liquidity",
        "uniswap",
        "curve",
        "stable",
        "pair",
    ],
    "liquid_staking": [
        "steth",
        "lido",
        "validator",
        "oracle",
        "pooled ether",
        "withdrawal",
    ],
    "vault": [
        "vault",
        "share",
        "asset",
        "deposit",
        "redeem",
        "withdraw",
    ],
    "governance": [
        "governor",
        "proposal",
        "vote",
        "quorum",
        "timelock",
    ],
}


def _humanize_protocol_name(name: str) -> str:
    """把目录名或文件名转换成更适合展示的协议名。"""

    if not name:
        return name

    # 如果已经是驼峰或首字母大写，直接返回，避免破坏原名。
    if any(char.isupper() for char in name):
        return name

    parts = name.replace("-", "_").split("_")
    return " ".join(part.capitalize() for part in parts if part)


def _score_file(file_path: str) -> Counter[str]:
    """对单个 Solidity 文件打协议类型分数。"""

    path = Path(file_path)
    text = path.read_text(encoding="utf-8").lower()
    file_name = path.name.lower()

    score = Counter()
    for protocol_type, keywords in PROTOCOL_TYPE_RULES.items():
        for keyword in keywords:
            if keyword in file_name:
                score[protocol_type] += 3
            if keyword in text:
                score[protocol_type] += 1
    return score


def classify_protocol(ingestion: IngestionResult) -> ProtocolClassification:
    """根据接入结果推断协议类型和名称。"""

    aggregate_score: Counter[str] = Counter()
    dominant_signals: list[str] = []

    for source_file in ingestion.source_files:
        file_score = _score_file(source_file.path)
        aggregate_score.update(file_score)
        for protocol_type, score in file_score.items():
            if score >= 3:
                dominant_signals.append(f"{source_file.file_name}:{protocol_type}:{score}")

    if aggregate_score:
        protocol_type, top_score = aggregate_score.most_common(1)[0]
        total_score = sum(aggregate_score.values())
        if total_score == 0 or top_score <= 2:
            confidence = "low"
        elif top_score / max(total_score, 1) >= 0.5:
            confidence = "high"
        else:
            confidence = "medium"
    else:
        protocol_type = "unknown"
        confidence = "low"
        top_score = 0

    target_path = Path(ingestion.target_path)
    raw_protocol_name = target_path.stem if target_path.is_file() else target_path.name
    protocol_name = _humanize_protocol_name(raw_protocol_name)

    rationale = [
        f"检测到 {ingestion.solidity_file_count} 个 Solidity 文件。",
        f"总行数约 {ingestion.total_line_count} 行。",
    ]
    if aggregate_score:
        rationale.append(f"最高匹配类型为 {protocol_type}，分数 {top_score}。")
    else:
        rationale.append("没有检测到足够强的协议类型关键词，暂时归类为 unknown。")

    return ProtocolClassification(
        protocol_name=protocol_name,
        protocol_type=protocol_type,
        confidence=confidence,
        rationale=rationale,
        dominant_signals=dominant_signals[:10],
    )
