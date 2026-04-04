"""分节论文 writer。"""

from __future__ import annotations

from services.research.models import ManuscriptPackage


def _normalize(text: str, *, max_length: int = 360) -> str:
    cleaned = " ".join(str(text or "").replace("\n", " ").split()).strip(" -;:,")
    if not cleaned:
        return ""
    if len(cleaned) > max_length:
        cleaned = cleaned[:max_length].rstrip(" ,;:") + "..."
    if cleaned and cleaned[-1] not in ".。!?？！":
        cleaned += "。"
    return cleaned


def _join_paragraphs(items: list[str]) -> str:
    return "\n\n".join(_normalize(item) for item in items if _normalize(item))


def _inline(text: str, *, max_length: int = 240) -> str:
    return _normalize(text, max_length=max_length).rstrip("。!?？！")


def _reference_index(package: ManuscriptPackage) -> dict[str, int]:
    return {
        item.title: idx
        for idx, item in enumerate(package.references, start=1)
    }


def _citation_marks(package: ManuscriptPackage, titles: list[str]) -> str:
    reference_index = _reference_index(package)
    marks = [
        f"[{reference_index[title]}]"
        for title in titles
        if title in reference_index
    ]
    return "、".join(marks)


def _render_reference_list(package: ManuscriptPackage, items: list) -> str:
    reference_index = _reference_index(package)
    marks = [
        f"[{reference_index[item.title]}]"
        for item in items
        if item.title in reference_index
    ]
    return "、".join(marks)


def _dedupe_notes(items: list[str]) -> str:
    notes: list[str] = []
    seen: set[str] = set()
    for item in items:
        normalized = _inline(item, max_length=220)
        if not normalized or normalized in seen:
            continue
        seen.add(normalized)
        notes.append(normalized)
    return "；".join(notes)


def _reference_bucket(reference) -> str:
    if reference.role == "经验锚点":
        return "incident"
    lowered = reference.title.lower()
    if "verification" in lowered or "on-chain" in lowered or "onchain" in lowered:
        return "verification"
    if "audit" in lowered:
        return "audit"
    return "background"


def _compact_reference_note(reference) -> str:
    note = reference.takeaway or reference.citation_reason
    return _normalize(note, max_length=180)


def write_abstract(package: ManuscriptPackage) -> str:
    return _join_paragraphs(package.abstract_points)


def write_introduction(package: ManuscriptPackage) -> str:
    return _join_paragraphs(package.introduction_points)


def write_background(package: ManuscriptPackage) -> str:
    return _join_paragraphs(package.background_points)


def write_incident_context(package: ManuscriptPackage) -> str:
    return _join_paragraphs(package.incident_context_points)


def write_problem_statement(package: ManuscriptPackage) -> str:
    return _join_paragraphs(package.problem_statement_points)


def write_research_questions(package: ManuscriptPackage) -> str:
    if not package.research_questions:
        return "本文当前未显式抽出研究问题。"
    lines = ["本文围绕以下三个问题展开，它们分别对应系统性利用面、无许可市场放大效应以及最小有效性校验边界。", ""]
    for index, question in enumerate(package.research_questions, start=1):
        lines.append(f"{index}. {_normalize(question, max_length=220)}")
    return "\n".join(lines)


def write_evidence_and_observations(package: ManuscriptPackage) -> str:
    narrative_paragraphs: list[str] = []
    if package.incident_anchor_points:
        anchor_summary = " ".join(
            _normalize(item, max_length=260)
            for item in package.incident_anchor_points[:3]
        )
        narrative_paragraphs.append(
            "本文首先以 incident 本身建立经验边界。"
            f" {anchor_summary}"
        )
    if package.evidence_points:
        evidence_summary = " ".join(
            _normalize(item, max_length=240)
            for item in package.evidence_points[:3]
        )
        narrative_paragraphs.append(
            "在经验边界之上，现有证据将该个案重构为一条连续的传播链："
            f" {evidence_summary}"
        )
    if package.validation_anchor_points:
        validation_summary = " ".join(
            _normalize(item, max_length=220)
            for item in package.validation_anchor_points[:2]
        )
        narrative_paragraphs.append(
            "除链上事实外，当前验证锚点进一步说明该路径并非停留在静态机制推断层面。"
            f" {validation_summary}"
        )
    if not narrative_paragraphs:
        narrative_paragraphs.append("当前尚未形成可稳定写入正文的 incident 证据叙事。")

    observation_paragraphs: list[str] = []
    if package.observations:
        observation_paragraphs.append(
            "基于以上事实与验证锚点，本文保留以下观察："
        )
        for index, item in enumerate(package.observations[:4], start=1):
            observation_paragraphs.append(
                f"观察 {index}：{_normalize(item, max_length=220)}"
            )
    else:
        observation_paragraphs.append("当前尚未形成可稳定写入正文的关键观察。")
    if package.figures or package.tables:
        observation_paragraphs.append(
            "与正文配套的图表仅用于压缩攻击路径、时间线和验证边界，不额外承担核心事实证明责任。"
        )
    return "\n\n".join(
        [
            "### Incident-grounded Evidence Narrative",
            "",
            *narrative_paragraphs,
            "",
            "### Claim-to-Evidence Mapping",
            "",
            write_claim_mapping(package),
            "",
            "### Key Observations and Scope",
            "",
            *observation_paragraphs,
        ]
    )


def write_claim_mapping(package: ManuscriptPackage) -> str:
    if not package.claims:
        return "当前尚未形成可稳定写入正文的主张-证据对应关系。"
    paragraphs = []
    for index, claim in enumerate(package.claims[:3], start=1):
        citations = _citation_marks(package, claim.citation_titles)
        citation_clause = (
            f"相关背景材料可见 {citations}，但这些文献只承担比较与框定作用。"
            if citations
            else "这一主张主要依赖个案证据与验证结果，不再额外引入背景性引用。"
        )
        paragraphs.append(
            f"主张 {index} 可以被表述为：{_inline(claim.claim, max_length=200)}。"
            f" 直接支持这一表述的，是 {_inline(claim.evidence_summary, max_length=220)}。"
            f" {citation_clause}"
            f" 验证层面的最小支撑来自 {_inline(claim.validation_summary, max_length=180)}。"
            f" 因此，该主张仅在 {_inline(claim.boundary, max_length=180)} 的范围内成立。"
        )
    return "\n\n".join(paragraphs)


def write_related_work(package: ManuscriptPackage) -> str:
    incident_refs = [item for item in package.references if _reference_bucket(item) == "incident"]
    audit_refs = [item for item in package.references if _reference_bucket(item) == "audit"]
    verification_refs = [item for item in package.references if _reference_bucket(item) == "verification"]
    background_refs = [
        item
        for item in package.references
        if _reference_bucket(item) == "background"
    ]
    blocks: list[str] = []
    if incident_refs:
        cited = _render_reference_list(package, incident_refs)
        takeaways = "；".join(_compact_reference_note(item) for item in incident_refs[:2] if _compact_reference_note(item))
        blocks.append(
            f"第一类材料构成本文的经验锚点，主要包括 {cited}。"
            " 这些条目用于确认个案确已在真实链上发生，并限定本文可以讨论的事实边界。"
            f" 对本文最直接有用的信息包括：{_normalize(takeaways, max_length=260)}"
        )
    if audit_refs or background_refs:
        grouped = audit_refs + background_refs
        cited = _render_reference_list(package, grouped)
        reasons = _dedupe_notes([
            _compact_reference_note(item)
            for item in grouped[:3]
            if _compact_reference_note(item)
        ])
        blocks.append(
            f"第二类材料主要是审计分析与背景综述，集中在 {cited}。"
            f" 它们更适合被用于解释 Oracle 接入、价格合理性和借贷约束之间的关系，即 {_inline(reasons, max_length=220)}。"
            " 本文使用这些文献来提供比较框架，而不使用它们替代个案事实或损失锚点。"
        )
    if verification_refs:
        cited = _render_reference_list(package, verification_refs)
        reasons = _dedupe_notes([
            _compact_reference_note(item)
            for item in verification_refs[:2]
            if _compact_reference_note(item)
        ])
        blocks.append(
            f"第三类材料对应验证导向的工作，主要包括 {cited}。"
            f" 它们的价值在于把结构性怀疑进一步推进到可执行路径与最小复现实验，即 {_inline(reasons, max_length=220)}。"
        )
    blocks.append(
        "因此，本文对相关工作的使用遵循一个明确边界：经验个案负责锚定现实发生性，审计与综述材料负责提供概念框架，验证导向材料负责补足最小复现语境。"
        " 任何关于个案路径成立与结论边界的最终判断，仍须回到 incident、链上锚点与本地验证本身。"
    )
    return _join_paragraphs(blocks)


def write_methodology(package: ManuscriptPackage) -> str:
    return "\n\n".join(
        [
            "### 证据构造",
            "",
            _join_paragraphs(package.methodology_points[:1]),
            "",
            "### 机制分层",
            "",
            _join_paragraphs(package.methodology_points[1:2]),
            "",
            "### 主张锚定策略",
            "",
            _join_paragraphs(package.methodology_points[2:3]),
            "",
            "### 分析范围",
            "",
            "本文优先回答与机制传播相关的有限研究问题，而不试图把单一个案不加区分地外推为通用行业结论。",
        ]
    )


def write_evaluation(package: ManuscriptPackage) -> str:
    setup_points = package.evaluation_points[:2]
    outcome_points = package.validation_anchor_points or [package.evaluation_points[1]] if len(package.evaluation_points) > 1 else []
    counterfactual_points = package.counterfactual_points or [
        "当前仍需为每条核心主张显式记录失败条件与不可复现情形，避免把未覆盖场景误写为已验证。"
    ]
    scope_points = []
    if package.evaluation_points:
        scope_points.append(package.evaluation_points[-1])
    if package.tables:
        table_notes = "；".join(
            _normalize(table.caption, max_length=160)
            for table in package.tables[:2]
        )
        scope_points.append(f"与验证相关的表格主要用于压缩观察点与边界说明，例如 {table_notes}")
    return "\n\n".join(
        [
            "### Validation Setup",
            "",
            _join_paragraphs(setup_points) or "当前未形成稳定的验证设置说明。",
            "",
            "### Observed Outcome",
            "",
            _join_paragraphs(outcome_points) or "当前尚未形成可稳定写入正文的验证结果。",
            "",
            "### Counterfactual and Failure Conditions",
            "",
            _join_paragraphs(counterfactual_points),
            "",
            "### Scope and Residual Gaps",
            "",
            _join_paragraphs(scope_points)
            or "本文的验证结论只服务于回答个案路径在受限环境下是否成立，不承担跨协议或跨市场的外推证明责任。",
        ]
    )


def write_discussion(package: ManuscriptPackage) -> str:
    return _join_paragraphs(package.discussion_points)


def write_contributions(package: ManuscriptPackage) -> str:
    if not package.contribution_points:
        return "本文当前尚未显式收敛出可稳定写入正文的贡献点。"
    return "\n\n".join(
        f"贡献 {index}：{_normalize(item, max_length=240)}"
        for index, item in enumerate(package.contribution_points[:4], start=1)
    )


def write_threats(package: ManuscriptPackage) -> str:
    labels = ["内部有效性", "外部有效性", "可复现性"]
    sections = []
    for label, item in zip(labels, package.threats_points[:3], strict=False):
        sections.append(f"### {label}\n\n{_normalize(item, max_length=260)}")
    return "\n\n".join(sections)


def write_conclusion(package: ManuscriptPackage) -> str:
    return _join_paragraphs(package.conclusion_points)


def write_references(package: ManuscriptPackage) -> str:
    if not package.references:
        return "- 暂无参考条目。"
    lines = []
    for index, item in enumerate(package.references, start=1):
        reference_kind = {
            "incident": "用于锚定个案事实边界",
            "audit": "用于说明审计与机制分析背景",
            "verification": "用于补足验证语境与复现路径",
            "background": "用于提供背景比较与概念框架",
        }.get(_reference_bucket(item), "参考材料")
        takeaway = _compact_reference_note(item)
        lines.append(
            " ".join(
                part
                for part in [
                    f"[{index}] {item.title}.",
                    f"{reference_kind}。",
                    takeaway,
                ]
                if part
            )
        )
    return "\n".join(lines)
