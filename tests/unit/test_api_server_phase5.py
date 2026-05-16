"""标准库 HTTP API 服务测试。"""

from __future__ import annotations

import io
import json
from pathlib import Path
import socket
import sys
import threading
import time
import unittest
from urllib import request
from unittest.mock import patch
import zipfile


ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from services.api.server import ApiHandler, ThreadingHTTPServer  # noqa: E402


def _pick_free_port() -> int:
    """为测试挑一个空闲端口。"""

    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


class ApiServerPhase5Test(unittest.TestCase):
    """验证 HTTP 服务层真的可访问。"""

    def setUp(self) -> None:
        self.port = _pick_free_port()
        self.env_patch = patch.dict("os.environ", {"RESEARCH_LLM_ENABLED": "false"}, clear=False)
        self.env_patch.start()
        self.server = ThreadingHTTPServer(("127.0.0.1", self.port), ApiHandler)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        time.sleep(0.05)

    def tearDown(self) -> None:
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=1)
        self.env_patch.stop()

    def test_health_endpoint(self) -> None:
        """健康检查接口应返回 ok。"""

        with request.urlopen(f"http://127.0.0.1:{self.port}/health") as response:
            payload = json.loads(response.read().decode("utf-8"))
        self.assertEqual(payload["status"], "ok")

    def test_home_page(self) -> None:
        """首页应返回 HTML。"""

        with request.urlopen(f"http://127.0.0.1:{self.port}/") as response:
            html = response.read().decode("utf-8")
        self.assertIn("DeFi Security Agent MVP", html)
        self.assertIn("提交审计任务", html)
        self.assertIn('/assets/app.css', html)
        self.assertIn('/assets/home.js', html)

    def test_static_assets(self) -> None:
        """静态资源路由应可返回 CSS 与 JS。"""

        with request.urlopen(f"http://127.0.0.1:{self.port}/assets/app.css") as response:
            css = response.read().decode("utf-8")
        self.assertIn("--bg:", css)
        self.assertIn(".metric-grid", css)

        with request.urlopen(f"http://127.0.0.1:{self.port}/assets/home.js") as response:
            script = response.read().decode("utf-8")
        self.assertIn("submitAudit", script)
        self.assertIn("loadArtifacts", script)

    def test_audit_endpoint(self) -> None:
        """审计接口应返回任务结果。"""

        payload = json.dumps(
            {
                "target": str(ROOT / "tests" / "fixtures" / "LendingPoolPrototype.sol"),
                "analyzers": ["access-control", "reentrancy"],
                "severity": "Informational",
                "save_artifacts": False,
            }
        ).encode("utf-8")
        req = request.Request(
            f"http://127.0.0.1:{self.port}/api/v1/audit",
            data=payload,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with request.urlopen(req) as response:
            body = json.loads(response.read().decode("utf-8"))

        self.assertIn("task_result", body)
        self.assertEqual(body["task_result"]["task_type"], "audit")

    def test_artifact_list_endpoint(self) -> None:
        """工件列表接口应至少返回数组结构。"""

        with request.urlopen(f"http://127.0.0.1:{self.port}/api/v1/artifacts") as response:
            body = json.loads(response.read().decode("utf-8"))
        self.assertIn("artifacts", body)
        self.assertIsInstance(body["artifacts"], list)

    def test_artifact_detail_and_file_endpoint(self) -> None:
        """工件详情和文件接口应可访问。"""

        payload = json.dumps(
            {
                "target": str(ROOT / "tests" / "fixtures" / "LendingPoolPrototype.sol"),
                "analyzers": ["access-control", "reentrancy"],
                "severity": "Informational",
                "save_artifacts": True,
            }
        ).encode("utf-8")
        req = request.Request(
            f"http://127.0.0.1:{self.port}/api/v1/audit",
            data=payload,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with request.urlopen(req) as response:
            body = json.loads(response.read().decode("utf-8"))

        artifact_dir = Path(body["artifact_dir"])
        task_id = artifact_dir.name

        with request.urlopen(f"http://127.0.0.1:{self.port}/api/v1/artifacts/{task_id}") as response:
            detail = json.loads(response.read().decode("utf-8"))
        self.assertIn("files", detail)

        with request.urlopen(
            f"http://127.0.0.1:{self.port}/api/v1/artifacts/{task_id}/file/task_result.json"
        ) as response:
            content = response.read().decode("utf-8")
        self.assertIn('"task_type"', content)

        with request.urlopen(
            f"http://127.0.0.1:{self.port}/api/v1/artifacts/{task_id}/generated/audit_report.md"
        ) as response:
            generated_report = response.read().decode("utf-8")
        self.assertIn("#", generated_report)

        with request.urlopen(
            f"http://127.0.0.1:{self.port}/api/v1/artifacts/{task_id}/generated/audit_bundle.zip"
        ) as response:
            audit_bundle = response.read()
        with zipfile.ZipFile(io.BytesIO(audit_bundle)) as archive:
            audit_names = archive.namelist()
        self.assertIn(f"{task_id}/task_result.json", audit_names)
        self.assertIn(f"{task_id}/audit_report.md", audit_names)

        with request.urlopen(f"http://127.0.0.1:{self.port}/audit/{task_id}") as response:
            html = response.read().decode("utf-8")
        self.assertIn("审计详情页", html)
        self.assertIn("下载审计包", html)

        payload = json.dumps(
            {
                "target": str(ROOT / "contracts" / "curve"),
                "analyzers": ["reentrancy"],
                "severity": "Informational",
                "save_artifacts": True,
            }
        ).encode("utf-8")
        req = request.Request(
            f"http://127.0.0.1:{self.port}/api/v1/research",
            data=payload,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with request.urlopen(req) as response:
            research_body = json.loads(response.read().decode("utf-8"))

        research_task_id = Path(research_body["artifact_dir"]).name
        with request.urlopen(
            f"http://127.0.0.1:{self.port}/api/v1/artifacts/{research_task_id}/generated/paper_draft.md"
        ) as response:
            paper = response.read().decode("utf-8")
        self.assertIn("#", paper)

        with request.urlopen(
            f"http://127.0.0.1:{self.port}/api/v1/artifacts/{research_task_id}/generated/paper_draft.pdf"
        ) as response:
            paper_pdf = response.read()
        self.assertTrue(paper_pdf.startswith(b"%PDF"))

        with request.urlopen(
            f"http://127.0.0.1:{self.port}/api/v1/artifacts/{research_task_id}/generated/research_bundle.zip"
        ) as response:
            research_bundle = response.read()
        with zipfile.ZipFile(io.BytesIO(research_bundle)) as archive:
            research_names = archive.namelist()
        self.assertIn(f"{research_task_id}/task_result.json", research_names)
        self.assertIn(f"{research_task_id}/paper_draft.md", research_names)
        self.assertIn(f"{research_task_id}/paper_draft.pdf", research_names)
        self.assertIn(f"{research_task_id}/research_memo.md", research_names)
        self.assertIn(f"{research_task_id}/task_steps.md", research_names)
        self.assertIn(f"{research_task_id}/peer_reviews.md", research_names)

        with request.urlopen(
            f"http://127.0.0.1:{self.port}/api/v1/artifacts/{research_task_id}/generated/task_steps.md"
        ) as response:
            task_steps = response.read().decode("utf-8")
        self.assertIn("Task Steps", task_steps)
        self.assertIn("idea_generation", task_steps)

        with request.urlopen(
            f"http://127.0.0.1:{self.port}/api/v1/artifacts/{research_task_id}/generated/peer_reviews.md"
        ) as response:
            peer_reviews = response.read().decode("utf-8")
        self.assertIn("Peer Reviews", peer_reviews)
        self.assertIn("Reviewer A", peer_reviews)

        with request.urlopen(f"http://127.0.0.1:{self.port}/research/{research_task_id}") as response:
            html = response.read().decode("utf-8")
        self.assertIn("研究详情页", html)
        self.assertIn("运行步骤", html)
        self.assertIn("下载运行步骤", html)
        self.assertIn("下载审稿意见", html)
        self.assertIn("下载论文 PDF", html)
        self.assertIn("多审稿人 Review", html)
        self.assertIn("候选方向对比", html)
        self.assertIn("证据链", html)
        self.assertIn("实验设计", html)
        self.assertIn("证据门禁结论", html)
        self.assertIn("下载研究包", html)


if __name__ == "__main__":
    unittest.main()
