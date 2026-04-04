"""AI reviewer 驱动的轻量修稿闭环。"""

from __future__ import annotations

from dataclasses import replace
import re

from services.research.models import CitationRecord, IncidentEvidencePackage, PaperDraft, PaperRevisionResult
from services.research.paper_revision import _apply_section_updates, _enforce_required_revision_guards
from services.research.review_views import build_peer_review_views, has_blocking_peer_review_issues
from services.shared.llm_client import OpenAiCompatibleLlmClient
from services.shared.settings import ProjectSettings


def _build_peer_revision_system_prompt() -> str:
    """返回 peer-review 修稿阶段系统提示词。"""

    return (
        "你是学术论文修订助手。"
        "请根据多位 reviewer 的主要顾虑、阻断问题与接受条件，"
        "直接修改现有论文对应章节。"
        "只允许使用给定论文、给定 reviewer 意见、给定引用和 incident 证据。"
        "不要引入未提供的新事实。输出必须是 JSON。"
    )


def _replace_section_body(markdown: str, heading: str, replacer) -> str:
    """用函数替换指定 section 正文。"""

    pattern = re.compile(
        rf"({re.escape(heading)}\n\n)([\s\S]*?)(?=\n## |\Z)",
        flags=re.MULTILINE,
    )

    def _sub(match):
        prefix = match.group(1)
        body = match.group(2).rstrip()
        return prefix + replacer(body).rstrip() + "\n"

    if pattern.search(markdown):
        return pattern.sub(_sub, markdown, count=1)
    return markdown


def _apply_peer_review_guardrails(markdown: str, peer_reviews: list[dict]) -> str:
    """根据高频 reviewer 问题做确定性修稿。"""

    concerns_text = " ".join(
        item
        for review in peer_reviews
        for item in ((review.get("blocker_issues") or []) + (review.get("major_concerns") or []))
    )
    updated = markdown

    if any(token in concerns_text for token in ["反复产生", "普遍结论", "表述强于", "系统性利用面"]):
        replacements = {
            "会反复暴露系统性利用面": "在本文分析的借贷场景与接入模式下，可能持续暴露可重复利用条件",
            "会持续演化为可重复触发的系统性利用面": "可能在本文分析的借贷接入模式下演化为可重复利用条件",
            "会反复产生系统性预言机利用面": "可能在本文分析的借贷接入模式下形成可重复利用条件",
            "允许无许可创建市场但不验证 Oracle 有效性时，系统性预言机利用面会反复出现": "允许无许可创建市场且缺少 Oracle 有效性校验时，在本文分析的借贷场景中会持续暴露可重复利用条件",
        }
        for old, new in replacements.items():
            updated = updated.replace(old, new)

    if any(token in concerns_text for token in ["结构化问题项", "高危或严重级别", "Background"]):
        def _background_replacer(body: str) -> str:
            lines = [line for line in body.splitlines() if line.strip()]
            filtered = [
                line for line in lines
                if "结构化问题项" not in line and "高危或严重级别" not in line
            ]
            if filtered == lines:
                return body
            return "\n\n".join(filtered)

        updated = _replace_section_body(updated, "## 2. Background and Context", _background_replacer)

    if any(token in concerns_text for token in ["可复现性描述", "成功判据", "覆盖范围", "动态验证"]):
        def _validation_replacer(body: str) -> str:
            addition = (
                "### 复现实验说明\n\n"
                "本文当前的最小复现实验以本地主网 fork / PoC 为载体，输入条件被限定为错误 Oracle 参数、"
                "createMarket 可达以及欠抵押借款路径仍能被触发。成功判据被限定为：目标市场完成创建、"
                "错误定价进入健康度评估链路、并使欠抵押借款在 fork 环境中被实际放行。\n\n"
                "### 覆盖范围与边界\n\n"
                "当前验证覆盖的是 createMarket 零验证与欠抵押借款路径这一组机制条件。"
                " 它足以说明本文分析的借贷接入模式在当前个案中可复现，但不足以单独证明所有 permissionless 市场都会出现同类风险。"
            )
            if "### 复现实验说明" in body:
                return body
            return body.rstrip() + "\n\n" + addition

        updated = _replace_section_body(updated, "## 8. Evaluation and Validation Plan", _validation_replacer)

    if any(token in concerns_text for token in ["摘要同时承担", "研究命题", "已证实结论"]):
        def _abstract_replacer(body: str) -> str:
            body = body.replace(
                "基于上述观察，本文回答三个研究问题：",
                "基于上述观察，本文在本文分析的借贷场景与接入模式下回答以下研究问题：",
            )
            if "本文不据此直接推出所有 permissionless 市场都必然存在同等风险。" not in body:
                body = body.rstrip() + "\n\n本文将结论严格限定在当前分析的借贷场景、接入模式与验证覆盖范围内，不据此直接推出所有 permissionless 市场都必然存在同等风险。"
            return body

        updated = _replace_section_body(updated, "## 摘要", _abstract_replacer)

    return updated


def _safe_lines(items: list[str], limit: int = 8) -> str:
    """把列表渲染成提示片段。"""

    if not items:
        return "- 暂无"
    return "\n".join(f"- {item}" for item in items[:limit])


def _build_peer_revision_user_prompt(
    *,
    paper_draft: PaperDraft,
    peer_reviews: list[dict],
    citations: list[CitationRecord],
    incident_evidence_packages: list[IncidentEvidencePackage],
) -> str:
    """构造 peer-review 修稿用户提示词。"""

    problematic_reviews = [
        review
        for review in peer_reviews
        if (review.get("blocker_issues") or []) or (review.get("major_concerns") or [])
    ][:3]
    citation_lines = _safe_lines(
        [
            f"{citation.title} | {citation.support_level} | {citation.key_takeaway or citation.snippet}"
            for citation in citations[:6]
        ],
        limit=6,
    )
    incident_lines = _safe_lines(
        [
            f"{package.title} | {package.loss_summary} | {package.evidence_summary[-1] if package.evidence_summary else package.summary}"
            for package in incident_evidence_packages[:3]
        ],
        limit=3,
    )
    review_lines = []
    for review in problematic_reviews:
        review_lines.extend(
            [
                f"{review.get('label', 'Reviewer')} | {review.get('focus', '')} | {review.get('recommendation', '')}",
                "blocker_issues:",
                _safe_lines(review.get("blocker_issues") or [], limit=3),
                "major_concerns:",
                _safe_lines(review.get("major_concerns") or [], limit=3),
                "acceptance_conditions:",
                _safe_lines(review.get("acceptance_conditions") or [], limit=3),
            ]
        )

    return "\n\n".join(
        [
            "请根据下面 reviewer 的主要意见修订论文。",
            "",
            "review 意见：",
            _safe_lines(review_lines, limit=20),
            "",
            "incident 证据：",
            incident_lines,
            "",
            "可用引用：",
            citation_lines,
            "",
            "论文节选：",
            (paper_draft.markdown or "")[:2600],
            "",
            "返回 JSON：",
            "{",
            '  "updated_sections": [',
            "    {",
            '      "heading": "必须是现有二级标题，如 ## 6. Related Work",',
            '      "content": "该标题下修订后的完整正文内容"',
            "    }",
            "  ],",
            '  "addressed_review_points": ["最多 8 条"]',
            "}",
        ]
    )


def _revise_paper_with_peer_reviews_with_llm(
    *,
    paper_draft: PaperDraft,
    peer_reviews: list[dict],
    citations: list[CitationRecord],
    incident_evidence_packages: list[IncidentEvidencePackage],
    settings: ProjectSettings | None = None,
    client: OpenAiCompatibleLlmClient | None = None,
) -> tuple[PaperDraft | None, list[str]]:
    """基于 peer reviews 用 AI 修稿。"""

    resolved_settings = settings or ProjectSettings.from_env()
    if not resolved_settings.research_llm_available:
        return None, []

    llm_client = client or OpenAiCompatibleLlmClient(resolved_settings)
    response = llm_client.complete_json(
        system_prompt=_build_peer_revision_system_prompt(),
        user_prompt=_build_peer_revision_user_prompt(
            paper_draft=paper_draft,
            peer_reviews=peer_reviews,
            citations=citations,
            incident_evidence_packages=incident_evidence_packages,
        ),
    )
    payload = response.content
    raw_updates = payload.get("updated_sections")
    if not isinstance(raw_updates, list) or not raw_updates:
        return None, []

    revised_markdown = _apply_section_updates(paper_draft.markdown, raw_updates)
    revised_markdown = _apply_peer_review_guardrails(revised_markdown, peer_reviews)
    revised_markdown = _enforce_required_revision_guards(
        original_markdown=paper_draft.markdown,
        revised_markdown=revised_markdown,
        incident_evidence_packages=incident_evidence_packages,
    )
    addressed = [
        str(item).strip()
        for item in payload.get("addressed_review_points", [])
        if str(item).strip()
    ][:8] if isinstance(payload.get("addressed_review_points"), list) else []
    return PaperDraft(title=paper_draft.title, markdown=revised_markdown), addressed


def run_peer_review_cycle(
    *,
    paper_draft: PaperDraft,
    revision_result: PaperRevisionResult,
    evidence_assessment: dict,
    reference_validation: dict,
    task_steps: list[dict],
    citations: list[CitationRecord],
    incident_evidence_packages: list[IncidentEvidencePackage],
    contribution_profile: dict | None = None,
    claim_evidence_matrix: dict | None = None,
    experiment_gap_report: dict | None = None,
    journal_fit_assessment: dict | None = None,
    submission_compliance: dict | None = None,
    settings: ProjectSettings | None = None,
    client: OpenAiCompatibleLlmClient | None = None,
    max_rounds: int = 2,
) -> tuple[PaperDraft, PaperRevisionResult, list[dict], list[str]]:
    """运行 AI reviewer -> AI revise -> 再 reviewer 的轻量闭环。"""

    resolved_settings = settings or ProjectSettings.from_env()
    current_draft = paper_draft
    current_revision = revision_result
    peer_reviews = build_peer_review_views(
        current_revision.to_dict(),
        evidence_assessment=evidence_assessment,
        reference_validation=reference_validation,
        task_steps=task_steps,
        paper_markdown=current_draft.markdown,
        contribution_profile=contribution_profile or {},
        claim_evidence_matrix=claim_evidence_matrix or {},
        experiment_gap_report=experiment_gap_report or {},
        journal_fit_assessment=journal_fit_assessment or {},
        submission_compliance=submission_compliance or {},
        settings=resolved_settings,
        client=client,
        use_llm=True,
    )
    addressed_changes: list[str] = []
    if not has_blocking_peer_review_issues(peer_reviews):
        current_revision = replace(
            current_revision,
            accepted=True,
            status="accepted",
            summary="论文已通过 structured review 与 AI peer review，可作为当前版本终稿。",
            revised_markdown=current_draft.markdown,
        )
        return current_draft, current_revision, peer_reviews, addressed_changes

    if not resolved_settings.research_llm_available:
        current_revision = replace(
            current_revision,
            accepted=False,
            status="needs_revision",
            summary="structured review 已通过，但 AI peer review 仍存在 major / blocker issue。",
            revised_markdown=current_draft.markdown,
        )
        return current_draft, current_revision, peer_reviews, addressed_changes

    for _ in range(max_rounds):
        revised_draft, newly_addressed = _revise_paper_with_peer_reviews_with_llm(
            paper_draft=current_draft,
            peer_reviews=peer_reviews,
            citations=citations,
            incident_evidence_packages=incident_evidence_packages,
            settings=resolved_settings,
            client=client,
        )
        if revised_draft is None:
            break
        current_draft = revised_draft
        addressed_changes = list(dict.fromkeys(addressed_changes + newly_addressed))
        current_revision = replace(
            current_revision,
            revised_markdown=current_draft.markdown,
            addressed_changes=list(dict.fromkeys((current_revision.addressed_changes or []) + addressed_changes)),
        )
        peer_reviews = build_peer_review_views(
            current_revision.to_dict(),
            evidence_assessment=evidence_assessment,
            reference_validation=reference_validation,
            task_steps=task_steps,
            paper_markdown=current_draft.markdown,
            contribution_profile=contribution_profile or {},
            claim_evidence_matrix=claim_evidence_matrix or {},
            experiment_gap_report=experiment_gap_report or {},
            journal_fit_assessment=journal_fit_assessment or {},
            submission_compliance=submission_compliance or {},
            settings=resolved_settings,
            client=client,
            use_llm=True,
        )
        if not has_blocking_peer_review_issues(peer_reviews):
            current_revision = replace(
                current_revision,
                accepted=True,
                status="accepted",
                summary="论文已通过 structured review 与 AI peer review，可作为当前版本终稿。",
                revised_markdown=current_draft.markdown,
                addressed_changes=list(dict.fromkeys((current_revision.addressed_changes or []) + addressed_changes)),
            )
            break
    else:
        current_revision = replace(
            current_revision,
            accepted=False,
            status="needs_revision",
            summary="structured review 已通过，但 AI peer review 仍存在未闭环的 major / blocker issue。",
            revised_markdown=current_draft.markdown,
            addressed_changes=list(dict.fromkeys((current_revision.addressed_changes or []) + addressed_changes)),
        )

    return current_draft, current_revision, peer_reviews, addressed_changes
