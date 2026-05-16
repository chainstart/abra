"""签名解析测试。"""

from __future__ import annotations

from pathlib import Path
import sys
import unittest


ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from services.monitoring.signature_resolver import (  # noqa: E402
    resolve_event_topic,
    resolve_function_selector,
)


class SignatureResolverPhase13Test(unittest.TestCase):
    """验证本地签名解析。"""

    def test_known_function_selector(self) -> None:
        """常用函数 selector 应能解析。"""

        self.assertEqual(
            resolve_function_selector("0xa9059cbb"),
            "transfer(address,uint256)",
        )

    def test_known_event_topic(self) -> None:
        """常用事件 topic0 应能解析。"""

        self.assertEqual(
            resolve_event_topic("0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef"),
            "Transfer(address,address,uint256)",
        )


if __name__ == "__main__":
    unittest.main()
