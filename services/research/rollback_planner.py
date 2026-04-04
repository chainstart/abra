"""根据 reviewer 与 publication gate 生成回退动作。"""

from __future__ import annotations

from services.research.models import RollbackAction, RollbackPlan


def build_rollback_plan(
    *,
    peer_reviews: list[dict],
    publication_readiness: dict,
) -> RollbackPlan:
    """把问题映射为需要回退的 stage。"""

    actions: list[RollbackAction] = []
    blockers = list(publication_readiness.get("blockers") or [])
    warnings = list(publication_readiness.get("warnings") or [])

    def add(stage: str, priority: str, reason: str, action: str, effect: str) -> None:
        actions.append(
            RollbackAction(
                action_id=f"rollback_{len(actions) + 1}",
                target_stage=stage,
                priority=priority,
                reason=reason,
                action=action,
                expected_effect=effect,
            )
        )

    for review in peer_reviews or []:
        focus = review.get("focus", "")
        for item in review.get("blocker_issues") or []:
            stage = "validation" if "验证" in focus or "复现" in focus else "manuscript"
            add(stage, "high", item, f"回退到 {stage} 阶段补强对应问题。", "消除 blocker。")
        for item in review.get("major_concerns") or []:
            lowered = str(item)
            if "反证" in lowered or "失败条件" in lowered:
                add("validation", "high", lowered, "补写反证与失败条件，并回填论文验证节。", "把单向展示改成可证伪的验证叙述。")
            elif "引用" in lowered or "相关工作" in lowered:
                add("related_work", "medium", lowered, "回退到相关工作整理阶段，重新聚合引用脉络。", "减少 citation role 风格的系统味。")
            else:
                add("manuscript", "medium", lowered, "回退到 section writer 重新组织对应章节。", "改善论证表达。")

    for item in blockers + warnings:
        lowered = str(item)
        if "counterfactual" in lowered or "failure-path" in lowered or "反证" in lowered:
            add("validation", "medium", lowered, "补充负向测试、阻断条件与失败路径说明。", "增强 validation 章节。")
        elif "模板" in lowered or "系统输出" in lowered:
            add("manuscript", "medium", lowered, "回退到分节 writer，重写摘要、证据、相关工作和讨论。", "降低工程化口吻。")
        elif "外推" in lowered or "适用范围" in lowered:
            add("claims", "medium", lowered, "收紧 claim 边界并同步到摘要、讨论和结论。", "减少过度泛化。")

    deduped: list[RollbackAction] = []
    seen: set[tuple[str, str]] = set()
    for action in actions:
        key = (action.target_stage, action.reason)
        if key in seen:
            continue
        seen.add(key)
        deduped.append(action)

    status = "no_rollback_needed" if not deduped else "rollback_required"
    summary = (
        "当前没有新的回退动作。"
        if not deduped
        else f"当前共生成 {len(deduped)} 条回退动作，需把问题回退到 evidence / claims / validation / manuscript 对应阶段处理。"
    )
    return RollbackPlan(
        status=status,
        summary=summary,
        actions=deduped[:8],
    )
