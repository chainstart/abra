"""多审稿人视角生成。"""

from __future__ import annotations

from typing import Any

from services.shared.llm_client import OpenAiCompatibleLlmClient
from services.shared.settings import ProjectSettings


REVIEWER_SPECS = [
    {
        "review_id": "reviewer_a",
        "label": "Reviewer A",
        "focus": "问题定义、结构与论证主线",
        "block_ids": ["structure", "conclusion"],
    },
    {
        "review_id": "reviewer_b",
        "label": "Reviewer B",
        "focus": "证据、验证与可复现性",
        "block_ids": ["evidence", "validation"],
    },
    {
        "review_id": "reviewer_c",
        "label": "Reviewer C",
        "focus": "新颖性、相关工作、主张边界与定位",
        "block_ids": ["related_work", "conclusion", "validation"],
    },
]


def _dedupe(items: list[str], limit: int = 6) -> list[str]:
    """去重并截断。"""

    results: list[str] = []
    for item in items:
        normalized = str(item or "").strip()
        if not normalized or normalized in results:
            continue
        results.append(normalized)
        if len(results) >= limit:
            break
    return results


def _section_excerpt(markdown: str, heading: str, max_chars: int = 1500) -> str:
    """抽取指定章节的短摘录。"""

    marker = f"{heading}\n"
    start = markdown.find(marker)
    if start == -1:
        return ""
    remaining = markdown[start:]
    next_index = remaining.find("\n## ", len(marker))
    section = remaining if next_index == -1 else remaining[:next_index]
    section = section.strip()
    if len(section) <= max_chars:
        return section
    return section[:max_chars].rstrip() + "..."


def _paper_review_excerpts(markdown: str) -> str:
    """为 reviewer 提供关键章节摘录，而不是只看开头。"""

    excerpts = []
    for heading in [
        "## 摘要",
        "## 1. Introduction",
        "## 2. Background and Context",
        "## 6. Related Work",
        "## 8. Evaluation and Validation Plan",
        "## 9. Preliminary Results and Discussion",
        "## 12. Conclusion",
    ]:
        excerpt = _section_excerpt(markdown, heading)
        if excerpt:
            excerpts.append(excerpt)
    return "\n\n".join(excerpts) or "- 暂无"


def has_blocking_peer_review_issues(peer_reviews: list[dict[str, Any]] | None) -> bool:
    """判断 peer reviewers 是否仍有 blocker / major issue。"""

    return any(
        (review.get("blocker_issues") or [])
        or str(review.get("recommendation") or "").strip() in {"Major Revision", "Reject"}
        for review in (peer_reviews or [])
        if isinstance(review, dict)
    )


def _paper_relevant_reference_issues(
    reference_validation: dict[str, Any],
    paper_markdown: str,
) -> list[str]:
    """仅保留当前论文正文里真正出现的引用问题。"""

    def _appears_outside_related_work(title: str) -> bool:
        current_heading = "#TITLE"
        for line in paper_markdown.splitlines():
            stripped = line.strip()
            if stripped.startswith("## "):
                current_heading = stripped
                continue
            if title and title in line and current_heading not in {"## 6. Related Work", "## References"}:
                return True
        return False

    issues: list[str] = []
    for item in (reference_validation.get("issues") or []):
        if not isinstance(item, dict):
            continue
        title = str(item.get("title") or "").strip()
        message = str(item.get("message") or "").strip()
        if title and title not in paper_markdown:
            continue
        if (
            title
            and "仅为参考级" in message
            and not _appears_outside_related_work(title)
        ):
            continue
        if title or message:
            issues.append(f"{title or '未命名引用'}：{message or '存在引用问题。'}")
    return _dedupe(issues, limit=4)


def _recommendation(
    *,
    blocker_issues: list[str],
    major_concerns: list[str],
    minor_concerns: list[str],
) -> str:
    """根据当前审稿结果生成建议。"""

    if not blocker_issues and not major_concerns and not minor_concerns:
        return "Accept"
    if not blocker_issues and not major_concerns:
        return "Accept with Minor Notes"
    if blocker_issues or major_concerns:
        return "Major Revision"
    return "Needs Clarification"


def _step_status_map(task_steps: list[dict[str, Any]] | None) -> dict[str, str]:
    """将步骤列表映射为 name -> status。"""

    return {
        str(step.get("name") or "").strip(): str(step.get("status") or "").strip()
        for step in (task_steps or [])
        if isinstance(step, dict)
    }


def _priority_label(blocker_issues: list[str], major_concerns: list[str], minor_concerns: list[str]) -> str:
    """生成审稿优先级。"""

    if blocker_issues:
        return "high"
    if major_concerns:
        return "medium"
    if minor_concerns:
        return "low"
    return "info"


def _compose_overall_comment(
    *,
    label: str,
    focus: str,
    final_score: float,
    blocker_issues: list[str],
    major_concerns: list[str],
    minor_concerns: list[str],
) -> str:
    """生成更像正式审稿的总体意见。"""

    opening = f"{label} 重点审查“{focus}”，当前相关内容与总评分 {final_score} 大体一致。"
    if blocker_issues:
        return opening + " 该视角下存在阻断级问题，当前版本不宜按终稿接受。"
    if major_concerns:
        return opening + " 该视角下没有阻断级缺陷，但仍有需要作者明确回应的主要顾虑。"
    if minor_concerns:
        return opening + " 该视角下总体可接受，但仍建议作者处理若干次要问题以提升可发表性。"
    return opening + " 该视角下未发现新的实质性阻断问题。"


def _build_peer_review_views_fallback(
    revision_result: dict[str, Any] | None,
    *,
    evidence_assessment: dict[str, Any] | None = None,
    reference_validation: dict[str, Any] | None = None,
    task_steps: list[dict[str, Any]] | None = None,
    paper_markdown: str = "",
) -> list[dict[str, Any]]:
    """从 revision result 构造规则兜底版多审稿人视角。"""

    if not revision_result:
        return []

    block_map = {
        str(block.get("block_id") or "").strip(): block
        for block in (revision_result.get("review_blocks") or [])
        if isinstance(block, dict)
    }
    reviews: list[dict[str, Any]] = []
    final_score = revision_result.get("final_score", 0)
    evidence_assessment = evidence_assessment or {}
    reference_validation = reference_validation or {}
    step_map = _step_status_map(task_steps)
    missing_dimensions = _dedupe(list(evidence_assessment.get("missing_dimensions") or []), limit=4)
    next_actions = _dedupe(list(evidence_assessment.get("next_actions") or []), limit=4)
    claim_checks = [
        item for item in (evidence_assessment.get("claim_checks") or [])
        if isinstance(item, dict)
    ]
    weak_claim_checks = _dedupe(
        [
            f"{item.get('claim', '未命名主张')}：{item.get('reasoning', '仍缺少充分支撑。')}"
            for item in claim_checks
            if str(item.get("status") or "").strip().lower() not in {"covered", "strong"}
        ],
        limit=3,
    )
    reference_issues = _paper_relevant_reference_issues(reference_validation, paper_markdown)

    for spec in REVIEWER_SPECS:
        blocks = [block_map[block_id] for block_id in spec["block_ids"] if block_id in block_map]
        if not blocks:
            continue

        strengths = _dedupe(
            [item for block in blocks for item in (block.get("strengths") or [])],
            limit=4,
        )
        concerns = _dedupe(
            [item for block in blocks for item in (block.get("weaknesses") or [])],
            limit=4,
        )
        requested_changes = _dedupe(
            [item for block in blocks for item in (block.get("required_changes") or [])],
            limit=4,
        )
        aspect_summary = _dedupe(
            [
                f"{aspect.get('name', '')}: {'pass' if aspect.get('accepted') else 'fix'}"
                for block in blocks
                for aspect in (block.get("aspects") or [])
                if isinstance(aspect, dict)
            ],
            limit=8,
        )
        blocker_issues = _dedupe(
            [
                item
                for block in blocks
                if not bool(block.get("accepted"))
                for item in (block.get("required_changes") or [])
            ],
            limit=4,
        )
        major_concerns = concerns[:]
        minor_concerns: list[str] = []
        evidence_basis = _dedupe(
            [item for block in blocks for item in (block.get("strengths") or [])],
            limit=5,
        )

        if spec["review_id"] == "reviewer_a":
            minor_concerns.extend(
                [
                    item
                    for item in concerns
                    if "叙事" in item or "结构" in item or "结论" in item
                ]
            )
        elif spec["review_id"] == "reviewer_b":
            if str(evidence_assessment.get("status") or "").strip() in {"insufficient", "conditional"}:
                blocker_issues = _dedupe(blocker_issues + missing_dimensions, limit=4)
                major_concerns = _dedupe(major_concerns + weak_claim_checks + next_actions, limit=4)
            else:
                major_concerns = _dedupe(major_concerns + weak_claim_checks, limit=4)
                minor_concerns = _dedupe(minor_concerns + next_actions, limit=3)
            evidence_basis = _dedupe(
                evidence_basis
                + list(evidence_assessment.get("satisfied_dimensions") or [])
                + [
                    f"{name}: {status}"
                    for name, status in step_map.items()
                    if name in {"incident_hydration", "incident_verification", "experiment_plan", "revision"}
                ],
                limit=5,
            )
        elif spec["review_id"] == "reviewer_c":
            if reference_issues and "## 6. Related Work" in paper_markdown and "不将其用于直接证明" in paper_markdown:
                minor_concerns = _dedupe(minor_concerns + reference_issues, limit=3)
            else:
                major_concerns = _dedupe(major_concerns + reference_issues, limit=4)
                minor_concerns = _dedupe(
                    [item for item in reference_issues if item not in major_concerns],
                    limit=3,
                )

        acceptance_conditions = _dedupe(blocker_issues + requested_changes, limit=4)
        questions_for_authors = _dedupe(
            [
                f"作者是否已经用正文而非后台工件回答：{item}"
                for item in (major_concerns[:2] or minor_concerns[:2])
            ],
            limit=3,
        ) or ["作者是否愿意说明当前结论的适用边界与不可外推部分？"]
        accepted = not blocker_issues and not major_concerns
        recommendation = _recommendation(
            blocker_issues=blocker_issues,
            major_concerns=major_concerns,
            minor_concerns=minor_concerns,
        )

        reviews.append(
            {
                "review_id": spec["review_id"],
                "label": spec["label"],
                "focus": spec["focus"],
                "mode": "fallback",
                "priority": _priority_label(blocker_issues, major_concerns, minor_concerns),
                "recommendation": recommendation,
                "accepted": accepted,
                "overall_comment": _compose_overall_comment(
                    label=spec["label"],
                    focus=spec["focus"],
                    final_score=final_score,
                    blocker_issues=blocker_issues,
                    major_concerns=major_concerns,
                    minor_concerns=minor_concerns,
                ),
                "aspect_summary": aspect_summary,
                "evidence_basis": evidence_basis or ["当前视角下暂无额外证据依据摘要。"],
                "strengths": strengths or ["当前视角下没有额外可列出的优点摘要。"],
                "blocker_issues": blocker_issues,
                "major_concerns": major_concerns,
                "minor_concerns": minor_concerns,
                "acceptance_conditions": acceptance_conditions,
                "questions_for_authors": questions_for_authors,
                "concerns": _dedupe(blocker_issues + major_concerns + minor_concerns, limit=6),
                "requested_changes": acceptance_conditions,
            }
        )
    return reviews


def _safe_lines(items: list[str], limit: int = 6) -> str:
    """把列表渲染成提示词片段。"""

    if not items:
        return "- 暂无"
    return "\n".join(f"- {item}" for item in items[:limit])


def _build_peer_review_system_prompt() -> str:
    """返回 AI reviewer 系统提示词。"""

    return (
        "你是学术论文审稿助手。"
        "请基于给定结构化信息，扮演 3 位审稿人，分别从结构论证、证据验证、定位边界三个角度审稿。"
        "输出必须简洁、挑问题、可执行，不要泛泛夸奖。"
        "每位 reviewer 最多给 2 条主要顾虑、2 条次要顾虑、2 条接受条件、2 个给作者的问题。"
        "如果论文已经明确把结论限定在单个案例、单个接入模式或候选性设计含义上，"
        "则不能仅因为缺少更广样本或参数扰动实验就继续给出阻断级 major revision；此类问题应降为 minor notes 或 future work。"
        "不得捏造未提供的新事实。输出必须是 JSON。"
    )


def _build_peer_review_user_prompt(
    *,
    fallback_reviews: list[dict[str, Any]],
    revision_result: dict[str, Any],
    evidence_assessment: dict[str, Any],
    reference_validation: dict[str, Any],
    task_steps: list[dict[str, Any]] | None,
    paper_markdown: str,
    contribution_profile: dict[str, Any] | None = None,
    claim_evidence_matrix: dict[str, Any] | None = None,
    experiment_gap_report: dict[str, Any] | None = None,
    journal_fit_assessment: dict[str, Any] | None = None,
    submission_compliance: dict[str, Any] | None = None,
) -> str:
    """构造 AI reviewer 用户提示词。"""

    review_specs = _safe_lines(
        [
            f"{item['review_id']} | {item['label']} | {item['focus']}"
            for item in REVIEWER_SPECS
        ],
        limit=6,
    )
    issue_summary = "；".join(
        _paper_relevant_reference_issues(reference_validation, paper_markdown)
    ) or "无"
    fallback_lines = []
    for review in fallback_reviews:
        fallback_lines.extend(
            [
                f"{review['review_id']} | focus={review['focus']} | recommendation={review['recommendation']} | priority={review['priority']}",
                f"major={'; '.join(review['major_concerns'][:2]) or '无'}",
                f"minor={'; '.join(review['minor_concerns'][:2]) or '无'}",
                f"conditions={'; '.join(review['acceptance_conditions'][:2]) or '无'}",
            ]
        )

    return "\n\n".join(
        [
            "请生成多审稿人视角的简洁评审。",
            "",
            "审稿人分工：",
            review_specs,
            "",
            "当前 revision 摘要：",
            f"- status: {revision_result.get('status', 'unknown')}",
            f"- accepted: {revision_result.get('accepted', False)}",
            f"- final_score: {revision_result.get('final_score', 0)}",
            f"- rounds: {revision_result.get('rounds', 0)}",
            "",
            "证据门禁：",
            f"- status: {evidence_assessment.get('status', 'unknown')}",
            f"- summary: {evidence_assessment.get('summary', '暂无')}",
            f"- missing_dimensions: {'；'.join(evidence_assessment.get('missing_dimensions', [])[:4]) or '无'}",
            "",
            "引用校验：",
            f"- accepted_count: {reference_validation.get('accepted_count', 0)}",
            f"- rejected_count: {reference_validation.get('rejected_count', 0)}",
            f"- issues: {issue_summary}",
            "",
            "贡献提纯：",
            f"- thesis: {(contribution_profile or {}).get('thesis_statement', '暂无')}",
            f"- summary: {(contribution_profile or {}).get('summary', '暂无')}",
            "",
            "主张-证据矩阵：",
            f"- summary: {(claim_evidence_matrix or {}).get('summary', '暂无')}",
            f"- covered_count: {(claim_evidence_matrix or {}).get('covered_count', 0)}",
            f"- partial_count: {(claim_evidence_matrix or {}).get('partial_count', 0)}",
            f"- missing_count: {(claim_evidence_matrix or {}).get('missing_count', 0)}",
            "",
            "实验缺口：",
            f"- summary: {(experiment_gap_report or {}).get('summary', '暂无')}",
            f"- blocker_gaps: {'；'.join(item.get('title', '') for item in ((experiment_gap_report or {}).get('blocker_gaps', []) or [])[:3]) or '无'}",
            f"- major_gaps: {'；'.join(item.get('title', '') for item in ((experiment_gap_report or {}).get('major_gaps', []) or [])[:3]) or '无'}",
            "",
            "期刊适配：",
            f"- overall_fit: {(journal_fit_assessment or {}).get('overall_fit', 'unknown')}",
            f"- fit_score: {(journal_fit_assessment or {}).get('fit_score', 0)}",
            f"- gaps: {'；'.join((journal_fit_assessment or {}).get('gaps', [])[:4]) or '无'}",
            "",
            "投稿合规：",
            f"- status: {(submission_compliance or {}).get('status', 'unknown')}",
            f"- blocker_count: {(submission_compliance or {}).get('blocker_count', 0)}",
            f"- warning_count: {(submission_compliance or {}).get('warning_count', 0)}",
            f"- summary: {(submission_compliance or {}).get('summary', '暂无')}",
            "",
            "任务步骤：",
            _safe_lines(
                [
                    f"{step.get('name', 'step')} | {step.get('status', 'unknown')} | {step.get('detail', '')}"
                    for step in (task_steps or [])
                ],
                limit=12,
            ),
            "",
            "规则兜底版 reviewer：",
            _safe_lines(fallback_lines, limit=16),
            "",
            "论文关键章节摘录：",
            _paper_review_excerpts(paper_markdown or ""),
            "",
            "返回 JSON：",
            "{",
            '  "reviews": [',
            "    {",
            '      "review_id": "reviewer_a|reviewer_b|reviewer_c",',
            '      "recommendation": "Accept|Accept with Minor Notes|Major Revision|Reject",',
            '      "priority": "high|medium|low|info",',
            '      "overall_comment": "一段简洁总体意见",',
            '      "evidence_basis": ["最多 3 条"],',
            '      "strengths": ["最多 3 条"],',
            '      "blocker_issues": ["最多 2 条"],',
            '      "major_concerns": ["最多 2 条"],',
            '      "minor_concerns": ["最多 2 条"],',
            '      "acceptance_conditions": ["最多 2 条"],',
            '      "questions_for_authors": ["最多 2 条"]',
            "    }",
            "  ]",
            "}",
        ]
    )


def _normalize_ai_peer_reviews(
    raw_reviews: list[dict[str, Any]] | None,
    *,
    fallback_reviews: list[dict[str, Any]],
) -> list[dict[str, Any]] | None:
    """把 AI 输出归一化为最终 reviewer 结构。"""

    if not isinstance(raw_reviews, list) or not raw_reviews:
        return None

    fallback_map = {item["review_id"]: item for item in fallback_reviews}
    normalized_reviews: list[dict[str, Any]] = []
    for spec in REVIEWER_SPECS:
        matched = next(
            (
                item for item in raw_reviews
                if isinstance(item, dict)
                and str(item.get("review_id", "")).strip() == spec["review_id"]
            ),
            None,
        )
        base = fallback_map.get(spec["review_id"])
        if base is None:
            continue
        if matched is None:
            normalized_reviews.append(base)
            continue

        blocker_issues = _dedupe(
            [str(item).strip() for item in matched.get("blocker_issues", []) if str(item).strip()],
            limit=2,
        )
        major_concerns = _dedupe(
            [str(item).strip() for item in matched.get("major_concerns", []) if str(item).strip()],
            limit=2,
        )
        minor_concerns = _dedupe(
            [str(item).strip() for item in matched.get("minor_concerns", []) if str(item).strip()],
            limit=2,
        )
        acceptance_conditions = _dedupe(
            [str(item).strip() for item in matched.get("acceptance_conditions", []) if str(item).strip()],
            limit=2,
        ) or base["acceptance_conditions"][:2]
        questions_for_authors = _dedupe(
            [str(item).strip() for item in matched.get("questions_for_authors", []) if str(item).strip()],
            limit=2,
        ) or base["questions_for_authors"][:2]
        evidence_basis = _dedupe(
            [str(item).strip() for item in matched.get("evidence_basis", []) if str(item).strip()],
            limit=3,
        ) or base["evidence_basis"][:3]
        strengths = _dedupe(
            [str(item).strip() for item in matched.get("strengths", []) if str(item).strip()],
            limit=3,
        ) or base["strengths"][:3]

        recommendation = str(matched.get("recommendation", "")).strip() or base["recommendation"]
        priority = str(matched.get("priority", "")).strip() or base["priority"]
        if recommendation in {"Accept", "Accept with Minor Notes"} and major_concerns:
            minor_concerns = _dedupe(minor_concerns + major_concerns, limit=4)
            major_concerns = []
        accepted = recommendation in {"Accept", "Accept with Minor Notes"} and not blocker_issues and not major_concerns
        normalized_reviews.append(
            {
                **base,
                "mode": "ai",
                "recommendation": recommendation,
                "priority": priority,
                "accepted": accepted,
                "overall_comment": str(matched.get("overall_comment", "")).strip() or base["overall_comment"],
                "evidence_basis": evidence_basis,
                "strengths": strengths,
                "blocker_issues": blocker_issues,
                "major_concerns": major_concerns or base["major_concerns"][:2],
                "minor_concerns": minor_concerns or base["minor_concerns"][:2],
                "acceptance_conditions": acceptance_conditions,
                "questions_for_authors": questions_for_authors,
                "concerns": _dedupe(blocker_issues + major_concerns + minor_concerns, limit=6) or base["concerns"][:3],
                "requested_changes": acceptance_conditions,
            }
        )
    return normalized_reviews or None


def build_peer_review_views(
    revision_result: dict[str, Any] | None,
    *,
    evidence_assessment: dict[str, Any] | None = None,
    reference_validation: dict[str, Any] | None = None,
    task_steps: list[dict[str, Any]] | None = None,
    paper_markdown: str = "",
    contribution_profile: dict[str, Any] | None = None,
    claim_evidence_matrix: dict[str, Any] | None = None,
    experiment_gap_report: dict[str, Any] | None = None,
    journal_fit_assessment: dict[str, Any] | None = None,
    submission_compliance: dict[str, Any] | None = None,
    settings: ProjectSettings | None = None,
    client: OpenAiCompatibleLlmClient | None = None,
    use_llm: bool = False,
) -> list[dict[str, Any]]:
    """构造多审稿人视角。默认规则兜底，可选 AI reviewer 增强。"""

    fallback_reviews = _build_peer_review_views_fallback(
        revision_result,
        evidence_assessment=evidence_assessment,
        reference_validation=reference_validation,
        task_steps=task_steps,
        paper_markdown=paper_markdown,
    )
    if not use_llm or not revision_result:
        return fallback_reviews

    resolved_settings = settings or ProjectSettings.from_env()
    if not resolved_settings.research_llm_available:
        return fallback_reviews

    llm_client = client or OpenAiCompatibleLlmClient(resolved_settings)
    try:
        response = llm_client.complete_json(
            system_prompt=_build_peer_review_system_prompt(),
            user_prompt=_build_peer_review_user_prompt(
                fallback_reviews=fallback_reviews,
                revision_result=revision_result,
                evidence_assessment=evidence_assessment or {},
                reference_validation=reference_validation or {},
                task_steps=task_steps,
                paper_markdown=paper_markdown,
                contribution_profile=contribution_profile or {},
                claim_evidence_matrix=claim_evidence_matrix or {},
                experiment_gap_report=experiment_gap_report or {},
                journal_fit_assessment=journal_fit_assessment or {},
                submission_compliance=submission_compliance or {},
            ),
        )
        normalized = _normalize_ai_peer_reviews(
            response.content.get("reviews"),
            fallback_reviews=fallback_reviews,
        )
        if normalized:
            return normalized
    except Exception:
        return fallback_reviews
    return fallback_reviews


def render_peer_reviews_markdown(reviews: list[dict[str, Any]]) -> str:
    """渲染合并版审稿意见 Markdown。"""

    if not reviews:
        return "# Peer Reviews\n\n暂无可用的审稿意见。\n"

    sections = ["# Peer Reviews", ""]
    for review in reviews:
        blocker_lines = (
            [f"- {item}" for item in review["blocker_issues"]]
            if review["blocker_issues"]
            else ["- 无"]
        )
        major_lines = [f"- {item}" for item in review["major_concerns"]] or ["- 无"]
        minor_lines = [f"- {item}" for item in review["minor_concerns"]] or ["- 无"]
        acceptance_lines = [f"- {item}" for item in review["acceptance_conditions"]] or ["- 无"]
        question_lines = [f"- {item}" for item in review["questions_for_authors"]] or ["- 无"]
        sections.extend(
            [
                f"## {review['label']}: {review['focus']}",
                "",
                f"- Recommendation: {review['recommendation']}",
                f"- Accepted: {review['accepted']}",
                f"- Priority: {review['priority']}",
                f"- Aspect Summary: {'；'.join(review['aspect_summary']) or '暂无'}",
                "",
                review["overall_comment"],
                "",
                "### Evidence Basis",
                "",
                *[f"- {item}" for item in review["evidence_basis"]],
                "",
                "### Strengths",
                "",
                *[f"- {item}" for item in review["strengths"]],
                "",
                "### Blocker Issues",
                "",
                *blocker_lines,
                "",
                "### Major Concerns",
                "",
                *major_lines,
                "",
                "### Minor Concerns",
                "",
                *minor_lines,
                "",
                "### Acceptance Conditions",
                "",
                *acceptance_lines,
                "",
                "### Questions For Authors",
                "",
                *question_lines,
                "",
            ]
        )
    return "\n".join(sections).strip() + "\n"
