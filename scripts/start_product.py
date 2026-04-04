#!/usr/bin/env python3
"""一键启动最小成品。

用法：

    python3 scripts/start_product.py

启动后访问：

    http://127.0.0.1:8000
"""

from __future__ import annotations

import argparse
from pathlib import Path
import socket
import sys

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from services.api.server import run_server  # noqa: E402


def _is_port_available(host: str, port: int) -> bool:
    """检查端口是否可用。"""

    with socket.socket() as sock:
        try:
            sock.bind((host, port))
        except OSError:
            return False
    return True


def _pick_port(host: str, preferred_port: int, search_limit: int = 20) -> int:
    """挑选可用端口。

    规则：

    - 优先使用用户指定端口
    - 如果被占用，则向后尝试有限个端口
    """

    for port in range(preferred_port, preferred_port + search_limit):
        if _is_port_available(host, port):
            return port
    raise RuntimeError(
        f"从端口 {preferred_port} 开始连续 {search_limit} 个端口都不可用。"
    )


def main() -> None:
    """脚本入口。"""

    parser = argparse.ArgumentParser(description="启动 DeFi Security Agent MVP。")
    parser.add_argument("--host", default="127.0.0.1", help="监听地址。")
    parser.add_argument("--port", type=int, default=8000, help="监听端口。")
    args = parser.parse_args()

    selected_port = _pick_port(args.host, args.port)
    print("正在启动 DeFi Security Agent MVP ...")
    if selected_port != args.port:
        print(
            f"端口 {args.port} 已被占用，自动切换到可用端口 {selected_port}。"
        )
    print(f"访问地址: http://{args.host}:{selected_port}")
    run_server(host=args.host, port=selected_port)


if __name__ == "__main__":
    main()
