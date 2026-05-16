"""标准库 HTTP API 服务。

当前使用 Python 标准库实现，避免额外依赖。
后续如果切换到 FastAPI，也可以直接复用 `handlers.py` 里的核心逻辑。
"""

from __future__ import annotations

from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
from urllib.parse import urlparse
from typing import Callable

from services.api.handlers import (
    handle_audit_request,
    handle_deep_analysis_request,
    handle_incident_discovery_request,
    handle_incident_hydration_request,
    handle_incident_search_request,
    handle_indexed_blocks_request,
    handle_indexed_logs_request,
    handle_indexed_transactions_request,
    handle_indexer_status_request,
    handle_monitor_request,
    handle_research_request,
)
from services.api.ui_assets import load_static_asset
from services.api.web_ui import (
    render_audit_detail_page,
    render_home_page,
    render_research_detail_page,
)
from services.storage.artifact_repository import (
    load_generated_artifact_file,
    list_task_artifacts,
    load_task_artifact,
    load_task_artifact_file,
)
from services.storage.task_database import list_discovered_contracts


HANDLER_MAP: dict[str, Callable[[dict], dict]] = {
    "/api/v1/audit": handle_audit_request,
    "/api/v1/analysis/deep": handle_deep_analysis_request,
    "/api/v1/incidents/discover": handle_incident_discovery_request,
    "/api/v1/incidents/hydrate": handle_incident_hydration_request,
    "/api/v1/incidents/search": handle_incident_search_request,
    "/api/v1/indexer/blocks": handle_indexed_blocks_request,
    "/api/v1/indexer/logs": handle_indexed_logs_request,
    "/api/v1/indexer/transactions": handle_indexed_transactions_request,
    "/api/v1/indexer/status": handle_indexer_status_request,
    "/api/v1/monitor/scan": handle_monitor_request,
    "/api/v1/research": handle_research_request,
}


class ApiHandler(BaseHTTPRequestHandler):
    """最小 JSON API Handler。"""

    server_version = "defi-security-agent/0.1"

    def _send_json(self, status_code: int, payload: dict) -> None:
        """输出 JSON 响应。"""

        body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        self.send_response(status_code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _send_text(self, status_code: int, body: str, content_type: str) -> None:
        """输出文本响应。"""

        payload = body.encode("utf-8")
        self._send_bytes(status_code, payload, content_type)

    def _send_bytes(self, status_code: int, payload: bytes, content_type: str) -> None:
        """输出字节响应。"""

        self.send_response(status_code)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def do_GET(self) -> None:  # noqa: N802
        """处理 GET 请求。"""

        parsed = urlparse(self.path)
        path = parsed.path

        if path == "/":
            self._send_text(
                HTTPStatus.OK,
                render_home_page(),
                "text/html; charset=utf-8",
            )
            return

        if path == "/health":
            self._send_json(
                HTTPStatus.OK,
                {"status": "ok", "service": "defi-security-agent"},
            )
            return

        if path.startswith("/assets/"):
            asset_name = path.removeprefix("/assets/")
            try:
                content_type, payload = load_static_asset(asset_name)
            except Exception as exc:  # noqa: BLE001
                self._send_json(HTTPStatus.NOT_FOUND, {"error": str(exc)})
                return
            self._send_bytes(HTTPStatus.OK, payload, content_type)
            return

        if path.startswith("/audit/"):
            task_id = path.removeprefix("/audit/")
            try:
                artifact = load_task_artifact(task_id)
            except Exception as exc:  # noqa: BLE001
                self._send_json(HTTPStatus.BAD_REQUEST, {"error": str(exc)})
                return
            self._send_text(
                HTTPStatus.OK,
                render_audit_detail_page(task_id, artifact["task_result"], artifact["files"]),
                "text/html; charset=utf-8",
            )
            return

        if path.startswith("/research/"):
            task_id = path.removeprefix("/research/")
            try:
                artifact = load_task_artifact(task_id)
            except Exception as exc:  # noqa: BLE001
                self._send_json(HTTPStatus.BAD_REQUEST, {"error": str(exc)})
                return
            self._send_text(
                HTTPStatus.OK,
                render_research_detail_page(task_id, artifact["task_result"], artifact["files"]),
                "text/html; charset=utf-8",
            )
            return

        if path == "/api/v1/artifacts":
            self._send_json(
                HTTPStatus.OK,
                {"artifacts": list_task_artifacts()},
            )
            return

        if path == "/api/v1/discoveries":
            self._send_json(
                HTTPStatus.OK,
                {"discoveries": list_discovered_contracts()},
            )
            return

        if path.startswith("/api/v1/artifacts/"):
            task_id = path.removeprefix("/api/v1/artifacts/")
            if "/generated/" in task_id:
                task_prefix, file_name = task_id.split("/generated/", 1)
                try:
                    content_type, body = load_generated_artifact_file(task_prefix, file_name)
                except Exception as exc:  # noqa: BLE001
                    self._send_json(HTTPStatus.BAD_REQUEST, {"error": str(exc)})
                    return
                if isinstance(body, bytes):
                    self._send_bytes(HTTPStatus.OK, body, content_type)
                else:
                    self._send_text(HTTPStatus.OK, body, content_type)
                return
            if "/file/" in task_id:
                task_prefix, file_name = task_id.split("/file/", 1)
                try:
                    content_type, body = load_task_artifact_file(task_prefix, file_name)
                except Exception as exc:  # noqa: BLE001
                    self._send_json(HTTPStatus.BAD_REQUEST, {"error": str(exc)})
                    return
                self._send_text(HTTPStatus.OK, body, content_type)
                return
            try:
                artifact = load_task_artifact(task_id)
            except Exception as exc:  # noqa: BLE001
                self._send_json(HTTPStatus.BAD_REQUEST, {"error": str(exc)})
                return
            self._send_json(HTTPStatus.OK, artifact)
            return

        self._send_json(HTTPStatus.NOT_FOUND, {"error": "not_found"})

    def do_POST(self) -> None:  # noqa: N802
        """处理 POST 请求。"""

        if self.path not in HANDLER_MAP:
            self._send_json(HTTPStatus.NOT_FOUND, {"error": "not_found"})
            return

        try:
            content_length = int(self.headers.get("Content-Length", "0"))
            raw_body = self.rfile.read(content_length) if content_length > 0 else b"{}"
            payload = json.loads(raw_body.decode("utf-8"))
        except json.JSONDecodeError as exc:
            self._send_json(HTTPStatus.BAD_REQUEST, {"error": f"invalid_json: {exc}"})
            return

        try:
            response = HANDLER_MAP[self.path](payload)
        except Exception as exc:  # noqa: BLE001
            self._send_json(HTTPStatus.BAD_REQUEST, {"error": str(exc)})
            return

        self._send_json(HTTPStatus.OK, response)

    def log_message(self, format: str, *args) -> None:  # noqa: A003
        """缩减默认日志噪音。"""

        return


def run_server(host: str = "127.0.0.1", port: int = 8000) -> None:
    """启动 HTTP 服务。"""

    server = ThreadingHTTPServer((host, port), ApiHandler)
    print(f"API 服务已启动: http://{host}:{port}")
    server.serve_forever()


if __name__ == "__main__":
    run_server()
