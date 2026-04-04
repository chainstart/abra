"""UI 模板与静态资源测试。"""

from __future__ import annotations

from pathlib import Path
import sys
import unittest


ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from services.api.ui_assets import load_static_asset  # noqa: E402
from services.api.web_ui import render_home_page  # noqa: E402


class UiAssetsPhase18Test(unittest.TestCase):
    """验证模板与静态资源已经从 Python 页面逻辑中拆出。"""

    def test_render_home_page_uses_external_assets(self) -> None:
        """首页应引用外部 CSS / JS，而不是内联整页资源。"""

        html = render_home_page()
        self.assertIn("/assets/app.css", html)
        self.assertIn("/assets/home.js", html)
        self.assertNotIn("<style>", html)

    def test_load_static_asset(self) -> None:
        """静态资源加载器应能返回内容类型和内容。"""

        content_type, payload = load_static_asset("app.css")
        self.assertIn("text/css", content_type)
        self.assertIn("--bg:", payload.decode("utf-8"))


if __name__ == "__main__":
    unittest.main()
