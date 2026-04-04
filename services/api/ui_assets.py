"""Web 层模板与静态资源加载。

把模板和静态文件从 Python 业务逻辑中拆出来，便于：

- 前后端职责分离
- 页面样式与交互独立维护
- 服务端代码专注于数据拼装
"""

from __future__ import annotations

from functools import lru_cache
import mimetypes
from pathlib import Path
from string import Template


MODULE_DIR = Path(__file__).resolve().parent
TEMPLATE_DIR = MODULE_DIR / "templates"
STATIC_DIR = MODULE_DIR / "static"

STATIC_ASSET_MAP: dict[str, Path] = {
    "app.css": STATIC_DIR / "app.css",
    "home.js": STATIC_DIR / "home.js",
}


@lru_cache(maxsize=None)
def _read_text(path: Path) -> str:
    """读取 UTF-8 文本文件。"""

    return path.read_text(encoding="utf-8")


@lru_cache(maxsize=None)
def _read_bytes(path: Path) -> bytes:
    """读取二进制文件。"""

    return path.read_bytes()


def asset_url(asset_name: str) -> str:
    """返回静态资源 URL。"""

    if asset_name not in STATIC_ASSET_MAP:
        raise FileNotFoundError(f"未注册的静态资源: {asset_name}")
    return f"/assets/{asset_name}"


def render_template(template_name: str, **context: str) -> str:
    """渲染简单模板。

    这里使用标准库 `string.Template`，避免额外引入模板引擎。
    """

    template_path = TEMPLATE_DIR / template_name
    if not template_path.is_file():
        raise FileNotFoundError(f"模板不存在: {template_name}")
    template = Template(_read_text(template_path))
    return template.safe_substitute(context)


def load_static_asset(asset_name: str) -> tuple[str, bytes]:
    """加载静态资源并返回内容类型和字节内容。"""

    asset_path = STATIC_ASSET_MAP.get(asset_name)
    if asset_path is None or not asset_path.is_file():
        raise FileNotFoundError(f"静态资源不存在: {asset_name}")

    content_type = mimetypes.guess_type(asset_path.name)[0] or "application/octet-stream"
    if content_type.startswith("text/") or content_type in {
        "application/javascript",
        "text/javascript",
    }:
        content_type = f"{content_type}; charset=utf-8"
    return content_type, _read_bytes(asset_path)
