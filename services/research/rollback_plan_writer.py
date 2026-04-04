"""导出 rollback 计划。"""

from __future__ import annotations

from services.research.models import RollbackPlan


def render_rollback_plan_markdown(plan: RollbackPlan | dict) -> str:
    if isinstance(plan, dict):
        status = plan.get("status", "")
        summary = plan.get("summary", "")
        actions = plan.get("actions", [])
    else:
        status = plan.status
        summary = plan.summary
        actions = [item.to_dict() for item in plan.actions]
    sections = [
        "# Rollback Plan",
        "",
        f"- Status: {status}",
        f"- Summary: {summary}",
        "",
        "## Actions",
        "",
    ]
    if not actions:
        sections.extend(["- 无", ""])
    else:
        for item in actions:
            sections.extend(
                [
                    f"### {item.get('target_stage', '')}",
                    "",
                    f"- Priority: {item.get('priority', '')}",
                    f"- Reason: {item.get('reason', '')}",
                    f"- Action: {item.get('action', '')}",
                    f"- Expected Effect: {item.get('expected_effect', '')}",
                    "",
                ]
            )
    return "\n".join(sections)
