"""任务工件归档。

默认只落最小必要工件：

- `task_result.json`

网页详情页和 API 会直接从 `task_result.json` 中读取研究 memo、论文初稿、
引用与 incident 证据包，避免在本地额外堆出大量派生文件。

如果需要完整展开工件，可通过 `SAVE_VERBOSE_ARTIFACTS=true` 显式开启。
"""

from __future__ import annotations

from datetime import datetime, timezone
import json
from pathlib import Path

from services.agent.models import AgentTaskResult
from services.research.llm_output_writer import render_llm_enhancement_markdown
from services.shared.settings import ProjectSettings
from services.storage.task_database import save_task_index


def _build_task_dir(task_result: AgentTaskResult, root_dir: Path | None = None) -> Path:
    """生成任务归档目录。"""

    settings = ProjectSettings.from_env()
    base_dir = root_dir or settings.artifacts_dir / "tasks"
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    safe_target = Path(task_result.target).name.replace(" ", "_")
    return base_dir / f"{timestamp}_{task_result.task_type}_{safe_target}"


def save_task_result(
    task_result: AgentTaskResult,
    *,
    root_dir: Path | None = None,
    db_path: Path | None = None,
) -> Path:
    """把统一任务结果保存到磁盘。"""

    settings = ProjectSettings.from_env()
    task_dir = _build_task_dir(task_result, root_dir=root_dir)
    task_dir.mkdir(parents=True, exist_ok=True)

    summary_path = task_dir / "task_result.json"
    summary_path.write_text(
        json.dumps(task_result.to_dict(), indent=2, ensure_ascii=False),
        encoding="utf-8",
    )

    if not settings.save_verbose_artifacts:
        save_task_index(
            task_id=task_dir.name,
            task_result=task_result,
            artifact_dir=task_dir,
            db_path=db_path,
        )
        return task_dir

    payload = task_result.payload
    if "markdown_report" in payload:
        (task_dir / "audit_report.md").write_text(
            payload["markdown_report"],
            encoding="utf-8",
        )
    if "paper_draft" in payload and payload["paper_draft"]:
        paper_payload = payload["paper_draft"]
        markdown = paper_payload.get("markdown", "")
        if markdown:
            (task_dir / "paper_draft.md").write_text(markdown, encoding="utf-8")
    if "research_memo" in payload and payload["research_memo"]:
        memo_payload = payload["research_memo"]
        markdown = memo_payload.get("markdown", "")
        if markdown:
            (task_dir / "research_memo.md").write_text(markdown, encoding="utf-8")
    if "experiment_plan" in payload and payload["experiment_plan"]:
        (task_dir / "experiment_plan.json").write_text(
            json.dumps(payload["experiment_plan"], indent=2, ensure_ascii=False),
            encoding="utf-8",
        )
    if "citations" in payload and payload["citations"]:
        (task_dir / "citations.json").write_text(
            json.dumps(payload["citations"], indent=2, ensure_ascii=False),
            encoding="utf-8",
        )
    if "research_ideas" in payload:
        (task_dir / "research_ideas.json").write_text(
            json.dumps(payload["research_ideas"], indent=2, ensure_ascii=False),
            encoding="utf-8",
        )
    if "research_presentation" in payload and payload["research_presentation"]:
        (task_dir / "research_presentation.json").write_text(
            json.dumps(payload["research_presentation"], indent=2, ensure_ascii=False),
            encoding="utf-8",
        )
    if "event_discovery" in payload and payload["event_discovery"]:
        (task_dir / "event_discovery.json").write_text(
            json.dumps(payload["event_discovery"], indent=2, ensure_ascii=False),
            encoding="utf-8",
        )
    if "research_result" in payload and payload["research_result"]:
        (task_dir / "research_result.json").write_text(
            json.dumps(payload["research_result"], indent=2, ensure_ascii=False),
            encoding="utf-8",
        )
    if "evidence_assessment" in payload and payload["evidence_assessment"]:
        (task_dir / "evidence_assessment.json").write_text(
            json.dumps(payload["evidence_assessment"], indent=2, ensure_ascii=False),
            encoding="utf-8",
        )
    if "incident_understanding" in payload and payload["incident_understanding"]:
        (task_dir / "incident_understanding.json").write_text(
            json.dumps(payload["incident_understanding"], indent=2, ensure_ascii=False),
            encoding="utf-8",
        )
    if "mechanism_graph_design" in payload and payload["mechanism_graph_design"]:
        (task_dir / "mechanism_graph_design.json").write_text(
            json.dumps(payload["mechanism_graph_design"], indent=2, ensure_ascii=False),
            encoding="utf-8",
        )
    if "research_program_candidates" in payload and payload["research_program_candidates"]:
        (task_dir / "research_program_candidates.json").write_text(
            json.dumps(payload["research_program_candidates"], indent=2, ensure_ascii=False),
            encoding="utf-8",
        )
    if "paper_strategy" in payload and payload["paper_strategy"]:
        (task_dir / "paper_strategy.json").write_text(
            json.dumps(payload["paper_strategy"], indent=2, ensure_ascii=False),
            encoding="utf-8",
        )
    if "publication_task_design" in payload and payload["publication_task_design"]:
        (task_dir / "publication_task_design.json").write_text(
            json.dumps(payload["publication_task_design"], indent=2, ensure_ascii=False),
            encoding="utf-8",
        )
    if "claim_graph" in payload and payload["claim_graph"]:
        (task_dir / "claim_graph.json").write_text(
            json.dumps(payload["claim_graph"], indent=2, ensure_ascii=False),
            encoding="utf-8",
        )
    if "incident_evidence_packages" in payload and payload["incident_evidence_packages"]:
        (task_dir / "incident_evidence_packages.json").write_text(
            json.dumps(payload["incident_evidence_packages"], indent=2, ensure_ascii=False),
            encoding="utf-8",
        )
    if "llm_enhancement" in payload and payload["llm_enhancement"]:
        (task_dir / "llm_enhancement.json").write_text(
            json.dumps(payload["llm_enhancement"], indent=2, ensure_ascii=False),
            encoding="utf-8",
        )
        (task_dir / "llm_enhancement.md").write_text(
            render_llm_enhancement_markdown(payload["llm_enhancement"]),
            encoding="utf-8",
        )

    save_task_index(
        task_id=task_dir.name,
        task_result=task_result,
        artifact_dir=task_dir,
        db_path=db_path,
    )

    return task_dir
