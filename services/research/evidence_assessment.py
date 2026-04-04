"""研究证据充分性评估。

这层的目标不是替代人工判断，而是先把最低门槛硬编码出来：

- 至少要有源码 / finding 证据
- 至少要有语义结构证据
- 至少要有外部参照证据（历史案例或引用）
- 每条核心主张都要有证据、引用和验证计划
"""

from __future__ import annotations

import re

from services.research.models import (
    CitationRecord,
    EvidenceAssessment,
    EvidenceClaimCheck,
    ExperimentPlan,
    IncidentEvidencePackage,
    ResearchIdea,
)


def _status_from_score(score: float) -> tuple[str, bool, str]:
    """根据评分返回状态。"""

    if score >= 0.8:
        return "sufficient", True, "high"
    if score >= 0.62:
        return "conditional", False, "medium"
    return "insufficient", False, "low"


def _alignment_tokens(text: str) -> set[str]:
    """为中英文混合文本构造更稳健的对齐 token。"""

    lowered = text.lower()
    tokens = set(re.findall(r"[a-z0-9_]{2,}", lowered))
    chinese_phrases = re.findall(r"[\u4e00-\u9fff]{2,}", text)
    stop_phrases = {"哪些", "如何", "什么", "是否", "当前", "这个", "这些", "那些"}
    for phrase in chinese_phrases:
        normalized = phrase.strip()
        if len(normalized) >= 2 and normalized not in stop_phrases:
            tokens.add(normalized)
        for size in (2, 3, 4):
            for index in range(0, max(len(normalized) - size + 1, 0)):
                part = normalized[index : index + size]
                if part not in stop_phrases and len(part) >= 2:
                    tokens.add(part)
    return tokens


def _overlap_score(left: str, right: str) -> int:
    """计算两段文本的 token 重合数。"""

    left_tokens = _alignment_tokens(left)
    right_tokens = _alignment_tokens(right)
    if not left_tokens or not right_tokens:
        return 0
    return len(left_tokens.intersection(right_tokens))


def assess_research_evidence(
    *,
    selected_idea: ResearchIdea,
    citations: list[CitationRecord],
    experiment_plan: ExperimentPlan | None,
    incident_evidence_packages: list[IncidentEvidencePackage] | None = None,
) -> EvidenceAssessment:
    """评估当前研究方向的证据是否足够。"""

    evidence_chain = selected_idea.evidence_chain or []
    research_questions = list(selected_idea.research_questions or [])
    incident_evidence_packages = incident_evidence_packages or []

    finding_count = sum(1 for item in evidence_chain if item.evidence_type == "finding")
    semantic_count = sum(1 for item in evidence_chain if item.evidence_type == "semantic")
    incident_count = sum(1 for item in evidence_chain if item.evidence_type == "incident")
    citation_count = len(citations)
    strong_citation_count = sum(
        1 for citation in citations if citation.support_level in {"high", "medium"}
    )
    has_experiment = bool(experiment_plan and (experiment_plan.designs or experiment_plan.procedures))

    satisfied_dimensions: list[str] = []
    missing_dimensions: list[str] = []
    next_actions: list[str] = []

    if finding_count >= 1:
        satisfied_dimensions.append("存在当前目标上的源码 / finding 证据")
    else:
        missing_dimensions.append("缺少当前目标上的源码 / finding 证据")
        next_actions.append("补充与主研究方向直接相关的源码 finding。")

    if semantic_count >= 1:
        satisfied_dimensions.append("存在 AST / 深语义结构证据")
    else:
        missing_dimensions.append("缺少 AST / 深语义结构证据")
        next_actions.append("补充跨合约边、状态冲突或外部调用顺序等结构信号。")

    if incident_count >= 1 or strong_citation_count >= 2:
        satisfied_dimensions.append("存在外部参照证据（历史案例或强相关引用）")
    else:
        missing_dimensions.append("缺少足够的外部参照证据")
        next_actions.append("补充历史案例或更强相关性的引用。")

    incident_packages_with_gaps = [
        package
        for package in incident_evidence_packages
        if package.missing_artifacts
    ]
    if incident_packages_with_gaps:
        titles = "；".join(package.title for package in incident_packages_with_gaps[:3])
        missing_dimensions.append(f"相关历史攻击事件证据包仍不完整：{titles}")
        next_actions.append("优先补齐相关 incident 的攻击交易、关键实体和时间线链上锚点。")
    elif incident_evidence_packages:
        satisfied_dimensions.append("相关历史攻击事件已形成结构化证据包")

    verification_required_packages = [
        package
        for package in incident_evidence_packages
        if package.verification_results
    ]
    if verification_required_packages:
        unverified_titles = [
            package.title
            for package in verification_required_packages
            if not any(result.get("passed") for result in package.verification_results)
        ]
        if unverified_titles:
            missing_dimensions.append(
                "相关历史攻击事件缺少通过的本地验证结果："
                + "；".join(unverified_titles[:3])
            )
            next_actions.append("补齐 incident 对应的 fork / PoC 本地验证并确认通过。")
        else:
            satisfied_dimensions.append("相关历史攻击事件已完成本地 fork / PoC 验证")

    if has_experiment:
        satisfied_dimensions.append("存在可执行的实验设计")
    else:
        missing_dimensions.append("缺少可执行的实验设计")
        next_actions.append("为主研究方向补充实验设计与验证路径。")

    claim_checks: list[EvidenceClaimCheck] = []
    claim_score_total = 0.0
    questions = research_questions[:4] or [selected_idea.problem_statement or selected_idea.hypothesis]
    for claim in questions:
        evidence_hits = sum(
            1
            for item in evidence_chain
            if _overlap_score(
                claim,
                " ".join([item.title, item.summary, item.reasoning, item.source_ref]),
            ) >= 2
        )
        citation_hits = sum(
            1
            for citation in citations
            if (
                claim == citation.claim_supported
                or _overlap_score(
                    claim,
                    " ".join(
                        [
                            citation.claim_supported,
                            citation.title,
                            citation.snippet,
                            citation.key_takeaway,
                            citation.citation_reason,
                        ]
                    ),
                ) >= 2
            )
        )
        covered = evidence_hits >= 1 and citation_hits >= 1 and has_experiment
        if covered:
            status = "covered"
            reasoning = "当前主张同时具备证据、引用和验证计划。"
            claim_score_total += 1.0
        elif evidence_hits >= 1 and (citation_hits >= 1 or has_experiment):
            status = "partial"
            reasoning = "当前主张已有部分支撑，但仍缺少完整闭环。"
            claim_score_total += 0.6
        else:
            status = "missing"
            reasoning = "当前主张没有形成证据、引用与验证计划的完整闭环。"
            missing_dimensions.append(f"主张 `{claim}` 证据闭环不足")
            next_actions.append(f"补强主张 `{claim}` 的引用或验证计划。")

        claim_checks.append(
            EvidenceClaimCheck(
                claim=claim,
                evidence_count=evidence_hits,
                citation_count=citation_hits,
                has_experiment=has_experiment,
                status=status,
                reasoning=reasoning,
            )
        )

    question_count = max(len(claim_checks), 1)
    missing_claim_count = sum(1 for item in claim_checks if item.status == "missing")
    partial_claim_count = sum(1 for item in claim_checks if item.status == "partial")
    claim_coverage_score = claim_score_total / question_count
    base_score = (
        min(finding_count, 3) * 0.14
        + min(semantic_count, 3) * 0.13
        + min(max(incident_count, strong_citation_count), 3) * 0.12
        + (0.12 if has_experiment else 0.0)
        + claim_coverage_score * 0.25
    )
    score = round(min(base_score, 0.99), 2)
    status, is_sufficient, confidence = _status_from_score(score)

    # 强制门禁：只要主张闭环明显不足，就不能宣称证据充分。
    if missing_claim_count >= max(1, question_count // 2):
        status = "insufficient"
        is_sufficient = False
        confidence = "low"
    elif missing_claim_count > 0 or partial_claim_count > 0:
        status = "conditional"
        is_sufficient = False
        confidence = "medium"

    if missing_dimensions and status == "sufficient":
        status = "conditional"
        is_sufficient = False
        confidence = "medium"

    if status == "sufficient":
        summary = "当前主线研究方向已经具备较完整的证据、引用和验证计划闭环。"
    elif status == "conditional":
        summary = "当前主线研究方向基本成立，但部分主张仍需要补充证据或验证后才能上升到高置信结论。"
    else:
        summary = "当前主线研究方向证据不足，不应直接给出高置信研究结论。"

    if not next_actions:
        next_actions.append("继续做动态验证，提升研究主张的可证实性。")

    dedup_missing = list(dict.fromkeys(missing_dimensions))
    dedup_actions = list(dict.fromkeys(next_actions))
    return EvidenceAssessment(
        status=status,
        is_sufficient=is_sufficient,
        confidence=confidence,
        score=score,
        summary=summary,
        assessed_by="deterministic_gate",
        satisfied_dimensions=satisfied_dimensions,
        missing_dimensions=dedup_missing,
        next_actions=dedup_actions,
        claim_checks=claim_checks,
    )
