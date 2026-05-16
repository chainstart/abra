"""Phase 1 合约接入服务。"""

from __future__ import annotations

from pathlib import Path

from services.analysis.address_source_fetcher import (
    fetch_contract_source,
    is_contract_address,
)
from services.analysis.models import IngestionResult, build_contract_file


def ingest_contract_target(target: str) -> IngestionResult:
    """接入一个目标路径，并输出标准化结果。

    当前版本支持：

    - 单个 `.sol` 文件
    - 一个包含多个 `.sol` 文件的目录
    """

    if is_contract_address(target):
        fetched = fetch_contract_source(target)
        source_files = [
            build_contract_file(fetched.root_dir, solidity_path)
            for solidity_path in fetched.solidity_files
        ]
        total_line_count = sum(source_file.line_count for source_file in source_files)
        return IngestionResult(
            target_path=target,
            target_kind="address",
            source_files=source_files,
            solidity_file_count=len(source_files),
            total_line_count=total_line_count,
        )

    target_path = Path(target).resolve()
    if not target_path.exists():
        raise FileNotFoundError(f"目标路径不存在: {target}")

    if target_path.is_file():
        if target_path.suffix != ".sol":
            raise ValueError(f"目标不是 Solidity 文件: {target}")
        source_files = [build_contract_file(target_path.parent, target_path)]
        target_kind = "file"
    else:
        solidity_paths = sorted(target_path.rglob("*.sol"))
        if not solidity_paths:
            raise ValueError(f"目录下没有 Solidity 文件: {target}")
        source_files = [
            build_contract_file(target_path, solidity_path)
            for solidity_path in solidity_paths
        ]
        target_kind = "directory"

    total_line_count = sum(source_file.line_count for source_file in source_files)
    return IngestionResult(
        target_path=str(target_path),
        target_kind=target_kind,
        source_files=source_files,
        solidity_file_count=len(source_files),
        total_line_count=total_line_count,
    )
