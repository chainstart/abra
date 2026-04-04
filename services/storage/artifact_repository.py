"""任务工件读取服务。

这个模块负责把归档目录重新读回来，供：

- Web UI 展示
- API 查询
- benchmark 检查
"""

from __future__ import annotations

import io
import json
from pathlib import Path
from typing import Any
import zipfile

from services.shared.settings import ProjectSettings
from services.research.claim_evidence_matrix import render_claim_evidence_matrix_markdown
from services.research.contribution_crystallizer import render_contribution_profile_markdown
from services.research.experiment_gap_analyzer import render_experiment_gap_report_markdown
from services.research.event_discovery import render_event_discovery_markdown
from services.research.journal_fit import render_journal_fit_markdown
from services.research.llm_output_writer import render_llm_enhancement_markdown
from services.research.manuscript_package_writer import render_manuscript_package_markdown
from services.research.pdf_renderer import render_markdown_to_pdf_bytes
from services.research.publication_task_design import render_publication_task_design_markdown
from services.research.publication_readiness import render_publication_readiness_markdown
from services.research.research_object_design import (
    render_incident_understanding_markdown,
    render_mechanism_graph_markdown,
    render_paper_strategy_markdown,
    render_research_program_markdown,
)
from services.research.rollback_plan_writer import render_rollback_plan_markdown
from services.research.review_views import build_peer_review_views, render_peer_reviews_markdown
from services.research.submission_compliance import render_submission_compliance_markdown
from services.storage.task_database import list_task_index


def _artifact_root(root_dir: Path | None = None) -> Path:
    """返回任务工件根目录。"""

    settings = ProjectSettings.from_env()
    return root_dir or settings.artifacts_dir / "tasks"


def _generated_artifact_map(task_result: dict[str, Any]) -> dict[str, tuple[str, str | bytes]]:
    """从 task_result payload 现场生成可下载文件。"""

    payload = task_result.get("payload", {})
    steps = task_result.get("steps") or []
    generated: dict[str, tuple[str, str | bytes]] = {}

    if steps:
        generated["task_steps.json"] = (
            "application/json; charset=utf-8",
            json.dumps(steps, indent=2, ensure_ascii=False),
        )
        generated["task_steps.md"] = (
            "text/plain; charset=utf-8",
            "\n".join(
                [
                    "# Task Steps",
                    "",
                    *[
                        f"{index}. [{step.get('status', 'unknown')}] {step.get('name', 'step')}\n\n{step.get('detail', '').strip() or '暂无说明。'}"
                        for index, step in enumerate(steps, start=1)
                    ],
                    "",
                ]
            ).strip()
            + "\n",
        )

    markdown_report = payload.get("markdown_report")
    if isinstance(markdown_report, str) and markdown_report.strip():
        generated["audit_report.md"] = ("text/plain; charset=utf-8", markdown_report)

    revision_markdown = ((payload.get("revision_result") or {}).get("revised_markdown") or "").strip()
    paper_markdown = ((payload.get("paper_draft") or {}).get("markdown") or "").strip()
    final_paper = revision_markdown or paper_markdown
    if final_paper:
        generated["paper_draft.md"] = ("text/plain; charset=utf-8", final_paper)
        generated["paper_draft.pdf"] = ("application/pdf", render_markdown_to_pdf_bytes(final_paper))
    if revision_markdown:
        generated["revised_paper.md"] = ("text/plain; charset=utf-8", revision_markdown)
        generated["revised_paper.pdf"] = ("application/pdf", render_markdown_to_pdf_bytes(revision_markdown))

    memo_markdown = ((payload.get("research_memo") or {}).get("markdown") or "").strip()
    if memo_markdown:
        generated["research_memo.md"] = ("text/plain; charset=utf-8", memo_markdown)

    structured_payloads = {
        "experiment_plan.json": payload.get("experiment_plan"),
        "event_discovery.json": payload.get("event_discovery"),
        "citations.json": payload.get("citations"),
        "research_ideas.json": payload.get("research_ideas"),
        "research_presentation.json": payload.get("research_presentation"),
        "research_result.json": payload.get("research_result"),
        "evidence_assessment.json": payload.get("evidence_assessment"),
        "incident_understanding.json": payload.get("incident_understanding"),
        "mechanism_graph_design.json": payload.get("mechanism_graph_design"),
        "research_program_candidates.json": payload.get("research_program_candidates"),
        "paper_strategy.json": payload.get("paper_strategy"),
        "contribution_profile.json": payload.get("contribution_profile"),
        "publication_task_design.json": payload.get("publication_task_design"),
        "manuscript_package.json": payload.get("manuscript_package"),
        "claim_evidence_matrix.json": payload.get("claim_evidence_matrix"),
        "claim_graph.json": payload.get("claim_graph"),
        "experiment_gap_report.json": payload.get("experiment_gap_report"),
        "incident_evidence_packages.json": payload.get("incident_evidence_packages"),
        "journal_fit_assessment.json": payload.get("journal_fit_assessment"),
        "llm_enhancement.json": payload.get("llm_enhancement"),
        "submission_compliance.json": payload.get("submission_compliance"),
        "publication_readiness.json": payload.get("publication_readiness"),
        "reference_validation.json": payload.get("reference_validation"),
        "revision_result.json": payload.get("revision_result"),
    }
    for file_name, data in structured_payloads.items():
        if data:
            generated[file_name] = (
                "application/json; charset=utf-8",
                json.dumps(data, indent=2, ensure_ascii=False),
            )

    llm_enhancement = payload.get("llm_enhancement")
    if llm_enhancement:
        generated["llm_enhancement.md"] = (
            "text/plain; charset=utf-8",
            render_llm_enhancement_markdown(llm_enhancement),
        )
    event_discovery = payload.get("event_discovery")
    if event_discovery:
        generated["event_discovery.md"] = (
            "text/plain; charset=utf-8",
            render_event_discovery_markdown(event_discovery),
        )
    incident_understanding = payload.get("incident_understanding")
    if incident_understanding:
        generated["incident_understanding.md"] = (
            "text/plain; charset=utf-8",
            render_incident_understanding_markdown(incident_understanding),
        )
    mechanism_graph_design = payload.get("mechanism_graph_design")
    if mechanism_graph_design:
        generated["mechanism_graph_design.md"] = (
            "text/plain; charset=utf-8",
            render_mechanism_graph_markdown(mechanism_graph_design),
        )
    research_program_candidates = payload.get("research_program_candidates")
    if research_program_candidates:
        generated["research_program_candidates.md"] = (
            "text/plain; charset=utf-8",
            render_research_program_markdown(research_program_candidates),
        )
    paper_strategy = payload.get("paper_strategy")
    if paper_strategy:
        generated["paper_strategy.md"] = (
            "text/plain; charset=utf-8",
            render_paper_strategy_markdown(paper_strategy),
        )
    contribution_profile = payload.get("contribution_profile")
    if contribution_profile:
        generated["contribution_profile.md"] = (
            "text/plain; charset=utf-8",
            render_contribution_profile_markdown(contribution_profile),
        )
    publication_task_design = payload.get("publication_task_design")
    if publication_task_design:
        generated["publication_task_design.md"] = (
            "text/plain; charset=utf-8",
            render_publication_task_design_markdown(publication_task_design),
        )
    manuscript_package = payload.get("manuscript_package")
    if manuscript_package:
        generated["manuscript_package.md"] = (
            "text/plain; charset=utf-8",
            render_manuscript_package_markdown(manuscript_package),
        )
    claim_evidence_matrix = payload.get("claim_evidence_matrix")
    if claim_evidence_matrix:
        generated["claim_evidence_matrix.md"] = (
            "text/plain; charset=utf-8",
            render_claim_evidence_matrix_markdown(claim_evidence_matrix),
        )
    experiment_gap_report = payload.get("experiment_gap_report")
    if experiment_gap_report:
        generated["experiment_gap_report.md"] = (
            "text/plain; charset=utf-8",
            render_experiment_gap_report_markdown(experiment_gap_report),
        )
    journal_fit_assessment = payload.get("journal_fit_assessment")
    if journal_fit_assessment:
        generated["journal_fit_assessment.md"] = (
            "text/plain; charset=utf-8",
            render_journal_fit_markdown(journal_fit_assessment),
        )
    submission_compliance = payload.get("submission_compliance")
    if submission_compliance:
        generated["submission_compliance.md"] = (
            "text/plain; charset=utf-8",
            render_submission_compliance_markdown(submission_compliance),
        )
    publication_readiness = payload.get("publication_readiness")
    if publication_readiness:
        generated["publication_readiness.md"] = (
            "text/plain; charset=utf-8",
            render_publication_readiness_markdown(publication_readiness),
        )
    rollback_plan = payload.get("rollback_plan")
    if rollback_plan:
        generated["rollback_plan.md"] = (
            "text/plain; charset=utf-8",
            render_rollback_plan_markdown(rollback_plan),
        )

    revision_result = payload.get("revision_result")
    peer_reviews = payload.get("peer_reviews") or (payload.get("research_presentation") or {}).get("peer_reviews") or build_peer_review_views(
        revision_result,
        evidence_assessment=payload.get("evidence_assessment"),
        reference_validation=payload.get("reference_validation"),
        task_steps=task_result.get("steps"),
    )
    if peer_reviews:
        generated["peer_reviews.json"] = (
            "application/json; charset=utf-8",
            json.dumps(peer_reviews, indent=2, ensure_ascii=False),
        )
        generated["peer_reviews.md"] = (
            "text/plain; charset=utf-8",
            render_peer_reviews_markdown(peer_reviews),
        )
        for review in peer_reviews:
            generated[f"{review['review_id']}.md"] = (
                "text/plain; charset=utf-8",
                render_peer_reviews_markdown([review]),
            )

    return generated


def _generated_bundle_name(task_result: dict[str, Any]) -> str:
    """返回任务类型对应的整包文件名。"""

    task_type = str(task_result.get("task_type") or "").strip().lower()
    if task_type == "research":
        return "research_bundle.zip"
    if task_type == "audit":
        return "audit_bundle.zip"
    return "task_bundle.zip"


def _build_generated_bundle(task_result: dict[str, Any], *, task_id: str) -> bytes:
    """把现场生成工件打成 ZIP。"""

    generated = _generated_artifact_map(task_result)
    folder = f"{task_id}/"
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, mode="w", compression=zipfile.ZIP_DEFLATED) as archive:
        archive.writestr(
            folder + "task_result.json",
            json.dumps(task_result, indent=2, ensure_ascii=False),
        )
        for file_name, (_content_type, content) in generated.items():
            archive.writestr(folder + file_name, content)
    return buffer.getvalue()


def list_generated_artifact_files(task_result: dict[str, Any]) -> list[str]:
    """列出现场可生成的文件名。"""

    generated_files = sorted(_generated_artifact_map(task_result).keys())
    generated_files.append(_generated_bundle_name(task_result))
    return generated_files


def list_task_artifacts(*, root_dir: Path | None = None, limit: int = 50) -> list[dict[str, Any]]:
    """列出最近的任务工件。"""

    # 优先走数据库索引，保证结果顺序稳定。
    indexed_rows = list_task_index(limit=limit)
    if indexed_rows:
        results: list[dict[str, Any]] = []
        for row in indexed_rows:
            task_dir = Path(row["artifact_dir"])
            files = sorted(path.name for path in task_dir.iterdir() if path.is_file()) if task_dir.exists() else []
            results.append(
                {
                    "task_id": row["task_id"],
                    "task_type": row["task_type"],
                    "target": row["target"],
                    "status": row["status"],
                    "created_at": row["created_at"],
                    "files": files,
                    "generated_files": (
                        list_generated_artifact_files(
                            json.loads((task_dir / "task_result.json").read_text(encoding="utf-8"))
                        )
                        if (task_dir / "task_result.json").exists()
                        else []
                    ),
                }
            )
        return results

    task_root = _artifact_root(root_dir)
    if not task_root.exists():
        return []

    results: list[dict[str, Any]] = []
    for task_dir in sorted(
        [path for path in task_root.iterdir() if path.is_dir()],
        key=lambda path: path.name,
        reverse=True,
    )[:limit]:
        task_result_path = task_dir / "task_result.json"
        if not task_result_path.exists():
            continue
        task_result = json.loads(task_result_path.read_text(encoding="utf-8"))
        files = sorted(
            path.name
            for path in task_dir.iterdir()
            if path.is_file()
        )
        results.append(
            {
                "task_id": task_dir.name,
                "task_type": task_result.get("task_type", ""),
                "target": task_result.get("target", ""),
                "status": task_result.get("status", ""),
                "created_at": task_dir.name.split("_", 1)[0],
                "files": files,
                "generated_files": list_generated_artifact_files(task_result),
            }
        )
    return results


def load_task_artifact(task_id: str, *, root_dir: Path | None = None) -> dict[str, Any]:
    """读取单个任务工件。"""

    task_dir = (_artifact_root(root_dir) / task_id).resolve()
    if not task_dir.exists() or not task_dir.is_dir():
        raise FileNotFoundError(f"任务工件不存在: {task_id}")

    task_result_path = task_dir / "task_result.json"
    if not task_result_path.exists():
        raise FileNotFoundError(f"任务结果文件不存在: {task_id}")

    task_result = json.loads(task_result_path.read_text(encoding="utf-8"))
    files = sorted(
        path.name
        for path in task_dir.iterdir()
        if path.is_file()
    )
    return {
        "task_id": task_id,
        "task_result": task_result,
        "files": files,
        "generated_files": list_generated_artifact_files(task_result),
    }


def load_task_artifact_file(
    task_id: str,
    file_name: str,
    *,
    root_dir: Path | None = None,
) -> tuple[str, str]:
    """读取单个任务工件文件。

    返回：

    - MIME 类型
    - 文件文本内容
    """

    if "/" in file_name or ".." in file_name:
        raise ValueError("非法文件名。")

    task_dir = (_artifact_root(root_dir) / task_id).resolve()
    if not task_dir.exists() or not task_dir.is_dir():
        raise FileNotFoundError(f"任务工件不存在: {task_id}")

    file_path = (task_dir / file_name).resolve()
    if file_path.parent != task_dir:
        raise ValueError("非法文件路径。")
    if not file_path.exists() or not file_path.is_file():
        raise FileNotFoundError(f"任务文件不存在: {task_id}/{file_name}")

    if file_path.suffix == ".json":
        mime_type = "application/json; charset=utf-8"
    else:
        mime_type = "text/plain; charset=utf-8"
    return mime_type, file_path.read_text(encoding="utf-8")


def load_generated_artifact_file(
    task_id: str,
    file_name: str,
    *,
    root_dir: Path | None = None,
) -> tuple[str, str | bytes]:
    """读取现场生成的虚拟工件文件。"""

    if "/" in file_name or ".." in file_name:
        raise ValueError("非法文件名。")

    artifact = load_task_artifact(task_id, root_dir=root_dir)
    generated = _generated_artifact_map(artifact["task_result"])
    bundle_name = _generated_bundle_name(artifact["task_result"])
    if file_name == bundle_name:
        return "application/zip", _build_generated_bundle(
            artifact["task_result"],
            task_id=task_id,
        )
    if file_name not in generated:
        raise FileNotFoundError(f"现场生成文件不存在: {task_id}/{file_name}")
    return generated[file_name]
