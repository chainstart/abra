"""面向期刊稿的研究任务设计。"""

from __future__ import annotations

from dataclasses import dataclass

from services.analysis.models import AuditRunResult
from services.research.models import (
    CitationRecord,
    ClaimEvidenceMatrix,
    ContributionProfile,
    ExperimentPlan,
    IncidentEvidencePackage,
    ResearchIdea,
)


def _clean(text: str, *, max_length: int = 220) -> str:
    cleaned = " ".join(str(text or "").replace("\n", " ").split()).strip(" -;:,")
    if not cleaned:
        return ""
    if len(cleaned) > max_length:
        cleaned = cleaned[:max_length].rstrip(" ,;:") + "..."
    if cleaned and cleaned[-1] not in ".。!?？！":
        cleaned += "。"
    return cleaned


def _dedupe(items: list[str], *, limit: int | None = None) -> list[str]:
    results: list[str] = []
    seen: set[str] = set()
    for item in items:
        normalized = _clean(item)
        if not normalized:
            continue
        lowered = normalized.lower()
        if lowered in seen:
            continue
        seen.add(lowered)
        results.append(normalized)
        if limit is not None and len(results) >= limit:
            break
    return results


@dataclass(frozen=True)
class ClaimArgumentUnit:
    """可被逐条审查的论文主张。"""

    claim_id: str
    statement: str
    direct_evidence: str
    validation_anchor: str
    counterfactual: str
    boundary: str

    def to_dict(self) -> dict[str, str]:
        return {
            "claim_id": self.claim_id,
            "statement": self.statement,
            "direct_evidence": self.direct_evidence,
            "validation_anchor": self.validation_anchor,
            "counterfactual": self.counterfactual,
            "boundary": self.boundary,
        }


@dataclass(frozen=True)
class RelatedWorkPosition:
    """文献在论文中的角色定位。"""

    citation_id: str
    title: str
    role: str
    usage: str
    forbidden_usage: str

    def to_dict(self) -> dict[str, str]:
        return {
            "citation_id": self.citation_id,
            "title": self.title,
            "role": self.role,
            "usage": self.usage,
            "forbidden_usage": self.forbidden_usage,
        }


@dataclass(frozen=True)
class ValidationScenario:
    """每条主张对应的验证设计。"""

    claim_id: str
    setup: str
    observable: str
    pass_condition: str
    fail_condition: str
    counterfactual: str

    def to_dict(self) -> dict[str, str]:
        return {
            "claim_id": self.claim_id,
            "setup": self.setup,
            "observable": self.observable,
            "pass_condition": self.pass_condition,
            "fail_condition": self.fail_condition,
            "counterfactual": self.counterfactual,
        }


@dataclass(frozen=True)
class VenueSectionBlueprint:
    """目标期刊体裁蓝图。"""

    section_id: str
    heading: str
    purpose: str
    required_inputs: list[str]
    style_notes: str

    def to_dict(self) -> dict[str, object]:
        return {
            "section_id": self.section_id,
            "heading": self.heading,
            "purpose": self.purpose,
            "required_inputs": self.required_inputs,
            "style_notes": self.style_notes,
        }


@dataclass(frozen=True)
class ReviewerLane:
    """多视角 reviewer 分工。"""

    reviewer_id: str
    label: str
    focus: str
    checklist: list[str]

    def to_dict(self) -> dict[str, object]:
        return {
            "reviewer_id": self.reviewer_id,
            "label": self.label,
            "focus": self.focus,
            "checklist": self.checklist,
        }


@dataclass(frozen=True)
class PublicationTaskNode:
    """研究任务生产线中的单个任务节点。"""

    task_id: str
    title: str
    goal: str
    inputs: list[str]
    outputs: list[str]
    acceptance_criteria: list[str]
    dependencies: list[str]

    def to_dict(self) -> dict[str, object]:
        return {
            "task_id": self.task_id,
            "title": self.title,
            "goal": self.goal,
            "inputs": self.inputs,
            "outputs": self.outputs,
            "acceptance_criteria": self.acceptance_criteria,
            "dependencies": self.dependencies,
        }


@dataclass(frozen=True)
class PublicationTaskDesign:
    """期刊化研究任务设计总览。"""

    summary: str
    tasks: list[PublicationTaskNode]
    claim_units: list[ClaimArgumentUnit]
    related_work_positions: list[RelatedWorkPosition]
    validation_scenarios: list[ValidationScenario]
    venue_blueprint: list[VenueSectionBlueprint]
    reviewer_lanes: list[ReviewerLane]

    def to_dict(self) -> dict[str, object]:
        return {
            "summary": self.summary,
            "tasks": [item.to_dict() for item in self.tasks],
            "claim_units": [item.to_dict() for item in self.claim_units],
            "related_work_positions": [item.to_dict() for item in self.related_work_positions],
            "validation_scenarios": [item.to_dict() for item in self.validation_scenarios],
            "venue_blueprint": [item.to_dict() for item in self.venue_blueprint],
            "reviewer_lanes": [item.to_dict() for item in self.reviewer_lanes],
        }


def _citation_role(citation: CitationRecord) -> str:
    if citation.source_type == "incident":
        return "经验锚点"
    lowered = str(citation.title or "").lower()
    if "verification" in lowered or "onchain" in lowered or "on-chain" in lowered:
        return "验证语境"
    if "audit" in lowered:
        return "审计背景"
    return "机制比较"


def _build_claim_units(
    *,
    selected_idea: ResearchIdea,
    claim_evidence_matrix: ClaimEvidenceMatrix | None,
    incident_evidence_packages: list[IncidentEvidencePackage],
) -> list[ClaimArgumentUnit]:
    primary_incident = incident_evidence_packages[0] if incident_evidence_packages else None
    root_cause = _clean(primary_incident.root_cause) if primary_incident else ""
    primary_verification = _clean(
        next(
            (
                item.get("summary", "")
                for package in incident_evidence_packages
                for item in package.verification_results
                if item.get("passed")
            ),
            "当前未记录通过的主网 fork / PoC 验证结果。",
        ),
        max_length=200,
    )
    rows = (claim_evidence_matrix.rows if claim_evidence_matrix else [])[:3]
    if rows:
        claim_units: list[ClaimArgumentUnit] = []
        for index, row in enumerate(rows, start=1):
            statement = _clean(row.claim, max_length=180)
            if index == 1:
                direct = (
                    "攻击时间线显示，错误 Oracle 参数先在市场创建阶段进入系统，"
                    "随后被价格传播与健康度判断接受，并最终对应到真实借款结果。"
                )
                counter = "若价格输入在市场准入或健康度检查环节被拒绝，则该主张不应继续成立。"
                boundary = "仅限于 Morpho Blue 单一市场与错误 decimals 配置所覆盖的 Oracle 接入场景。"
            elif index == 2:
                direct = (
                    "个案表明无许可市场创建降低了问题市场进入系统的门槛，"
                    "使配置错误能够直接转化为可执行借贷条件。"
                )
                counter = "若 createMarket 在部署时验证 Oracle 有效性，则该放大效应应显著减弱或直接消失。"
                boundary = "仅限于本文个案所展示的 permissionless market creation 机制范围。"
            else:
                direct = (
                    "个案至少暴露出三类必要检查：市场创建时的输入有效性、"
                    "价格传播到健康度判断时的语义一致性，以及借款放行前后的结果约束。"
                )
                counter = "若这些检查中的任一环节被可靠实现，则本文主张的最小校验条件需要重新定义。"
                boundary = "只讨论当前个案所揭示的最小必要条件，不将其视为完备防护清单。"
            claim_units.append(
                ClaimArgumentUnit(
                    claim_id=row.claim_id,
                    statement=statement,
                    direct_evidence=_clean(direct, max_length=220),
                    validation_anchor=primary_verification,
                    counterfactual=_clean(counter, max_length=200),
                    boundary=_clean(boundary, max_length=180),
                )
            )
        return claim_units

    fallback_statements = selected_idea.research_questions or [selected_idea.hypothesis]
    return [
        ClaimArgumentUnit(
            claim_id=f"claim_{index}",
            statement=_clean(item, max_length=180),
            direct_evidence=root_cause or _clean(selected_idea.problem_statement, max_length=200),
            validation_anchor=primary_verification,
            counterfactual="若关键条件在市场准入、价格传播或借款放行阶段被阻断，则该主张应失败。",
            boundary="仅限于当前 incident 与最小复现实验所覆盖的范围。",
        )
        for index, item in enumerate(fallback_statements[:3], start=1)
    ]


def _build_related_work_positions(citations: list[CitationRecord]) -> list[RelatedWorkPosition]:
    positions: list[RelatedWorkPosition] = []
    for citation in citations[:8]:
        role = _citation_role(citation)
        if role == "经验锚点":
            usage = "用于确认事件真实发生、损失存在以及链上路径具备现实锚点。"
            forbidden = "不得把该条目直接扩张为跨协议普适性结论。"
        elif role == "验证语境":
            usage = "用于说明最小复现实验或 on-chain verification 的语境与可复现边界。"
            forbidden = "不得单独承担个案事实或损失规模证明责任。"
        elif role == "审计背景":
            usage = "用于提供审计视角与设计背景，帮助解释价格输入、约束判断与协议边界之间的关系。"
            forbidden = "不得替代当前事件中的 direct evidence。"
        else:
            usage = "用于与本文主张做机制层比较，说明类似风险在何种设计下更容易出现。"
            forbidden = "不得把比较文献写成本文个案已经成立的直接证据。"
        positions.append(
            RelatedWorkPosition(
                citation_id=citation.citation_id,
                title=citation.title,
                role=role,
                usage=_clean(usage, max_length=190),
                forbidden_usage=_clean(forbidden, max_length=190),
            )
        )
    return positions


def _build_validation_scenarios(
    *,
    claim_units: list[ClaimArgumentUnit],
    experiment_plan: ExperimentPlan | None,
) -> list[ValidationScenario]:
    setup = _clean(
        (experiment_plan.objective if experiment_plan else "")
        or "主网 fork / PoC 环境下围绕单一 incident 路径进行最小复现实验。",
        max_length=200,
    )
    observable = _clean(
        "观察问题市场能否进入系统、错误价格是否继续传播到健康度判断，以及借款放行是否形成欠抵押结果。",
        max_length=220,
    )
    scenarios: list[ValidationScenario] = []
    for unit in claim_units:
        scenarios.append(
            ValidationScenario(
                claim_id=unit.claim_id,
                setup=setup,
                observable=observable,
                pass_condition=_clean(
                    f"若观测结果与“{unit.statement.rstrip('。')}”一致，且最小复现实验成功，则本文保留该主张。",
                    max_length=220,
                ),
                fail_condition=_clean(
                    f"若实验无法复现该路径，或关键约束没有被绕过，则“{unit.statement.rstrip('。')}”不应被继续保留。",
                    max_length=220,
                ),
                counterfactual=unit.counterfactual,
            )
        )
    return scenarios


def _build_venue_blueprint() -> list[VenueSectionBlueprint]:
    return [
        VenueSectionBlueprint(
            section_id="abstract",
            heading="摘要",
            purpose="用一段文字交代研究问题、证据来源、验证方式和结论边界。",
            required_inputs=["claim_units", "incident_reconstruction", "validation_design"],
            style_notes="不能写成系统流程摘要，必须像正式期刊摘要。",
        ),
        VenueSectionBlueprint(
            section_id="introduction",
            heading="1. Introduction",
            purpose="说明研究动机、现实性和本文研究对象。",
            required_inputs=["mechanism_abstraction", "incident_reconstruction"],
            style_notes="只提出本文真正回答的问题，不铺陈后台工作流。",
        ),
        VenueSectionBlueprint(
            section_id="evidence",
            heading="5. Evidence and Observations",
            purpose="写出事实叙事、主张-证据映射和边界说明。",
            required_inputs=["incident_reconstruction", "claim_units"],
            style_notes="必须先事实、后主张，避免表格式导出腔。",
        ),
        VenueSectionBlueprint(
            section_id="validation",
            heading="8. Evaluation and Validation Plan",
            purpose="给出实验设置、可观测结果、反证条件和剩余缺口。",
            required_inputs=["validation_design", "claim_units"],
            style_notes="不能只写计划，必须显式写 pass/fail/counterfactual。",
        ),
        VenueSectionBlueprint(
            section_id="related_work",
            heading="6. Related Work",
            purpose="按角色组织文献，而不是列清单。",
            required_inputs=["related_work_positioning", "claim_units"],
            style_notes="每类文献只承担自己的论证责任。",
        ),
        VenueSectionBlueprint(
            section_id="conclusion",
            heading="12. Conclusion",
            purpose="回到已成立的主张，并再次收紧边界。",
            required_inputs=["claim_units", "validation_design"],
            style_notes="结论不得超出 boundary。",
        ),
    ]


def _build_reviewer_lanes() -> list[ReviewerLane]:
    return [
        ReviewerLane(
            reviewer_id="reviewer_evidence",
            label="Reviewer A",
            focus="Evidence",
            checklist=[
                "每条主张是否都有 direct evidence",
                "incident 事实与机制解释是否混写",
                "正文是否仍有报告导出痕迹",
            ],
        ),
        ReviewerLane(
            reviewer_id="reviewer_validation",
            label="Reviewer B",
            focus="Validation",
            checklist=[
                "每条主张是否都有 validation anchor",
                "是否写清 pass / fail condition",
                "counterfactual 是否进入正文",
            ],
        ),
        ReviewerLane(
            reviewer_id="reviewer_related_work",
            label="Reviewer C",
            focus="Related Work",
            checklist=[
                "文献角色是否明确",
                "是否存在越权引用",
                "是否把比较文献误写成直接证据",
            ],
        ),
        ReviewerLane(
            reviewer_id="reviewer_style",
            label="Reviewer D",
            focus="Manuscript Style",
            checklist=[
                "是否还有模板腔和系统输出味",
                "各节衔接是否像论文而非工作流摘要",
                "摘要与结论是否收束",
            ],
        ),
        ReviewerLane(
            reviewer_id="reviewer_venue_fit",
            label="Reviewer E",
            focus="Venue Fit",
            checklist=[
                "版式与章节体裁是否接近期刊稿",
                "References 是否像正式论文而非内部条目",
                "Threats to Validity 是否显式限制外推边界",
            ],
        ),
    ]


def _build_task_nodes(
    *,
    claim_units: list[ClaimArgumentUnit],
    venue_blueprint: list[VenueSectionBlueprint],
) -> list[PublicationTaskNode]:
    claim_inputs = [f"claim::{unit.claim_id}" for unit in claim_units]
    section_outputs = [f"section::{item.section_id}" for item in venue_blueprint]
    return [
        PublicationTaskNode(
            task_id="event_discovery",
            title="Event Discovery",
            goal="从外部披露、链上异常与本地事件库中识别值得进入研究链的新事件候选。",
            inputs=["external disclosures", "incident repository", "onchain anomaly signals"],
            outputs=["raw_event_candidates"],
            acceptance_criteria=[
                "候选事件必须带来源、时间和协议猜测",
            ],
            dependencies=[],
        ),
        PublicationTaskNode(
            task_id="incident_understanding",
            title="Incident Understanding",
            goal="把事件候选提升为统一 incident model，区分攻击面、根因候选、执行路径与验证可行性。",
            inputs=["raw_event_candidates", "incident_evidence_packages", "onchain_transactions"],
            outputs=["incident_model"],
            acceptance_criteria=[
                "必须形成统一事件对象，而不只是新闻摘要",
            ],
            dependencies=["event_discovery"],
        ),
        PublicationTaskNode(
            task_id="mechanism_generalization",
            title="Mechanism Generalization",
            goal="把 incident model 抽象为可迁移的机制图，识别 entry、pricing、constraint 与 outcome 之间的关系。",
            inputs=["incident_model"],
            outputs=["mechanism_graph"],
            acceptance_criteria=[
                "必须给出 generalized mechanism，而不是只复述事故时间线",
            ],
            dependencies=["incident_understanding"],
        ),
        PublicationTaskNode(
            task_id="idea_mining",
            title="Idea Mining",
            goal="从机制图中挖出多个 research program candidate，而不是直接写固定 case-study。",
            inputs=["mechanism_graph", *claim_inputs],
            outputs=["research_program_candidates"],
            acceptance_criteria=[
                "至少形成 case-study / measurement / defense 三类候选",
            ],
            dependencies=["mechanism_generalization"],
        ),
        PublicationTaskNode(
            task_id="paper_type_selection",
            title="Paper Type Selection",
            goal="在研究程序候选中选定 paper type 与目标 venue style。",
            inputs=["research_program_candidates"],
            outputs=["paper_strategy"],
            acceptance_criteria=[
                "论文类型、章节蓝图和验证预期必须显式确定",
            ],
            dependencies=["idea_mining"],
        ),
        PublicationTaskNode(
            task_id="incident_reconstruction",
            title="Incident Reconstruction",
            goal="把真实 incident 重构为只包含事实、时间线、链上锚点与组件对象的事件包。",
            inputs=["incident_model", "onchain_transactions", "timeline"],
            outputs=["incident_reconstruction_bundle"],
            acceptance_criteria=[
                "不能混入设计建议或过度解释",
                "必须可回答发生了什么",
            ],
            dependencies=["paper_type_selection"],
        ),
        PublicationTaskNode(
            task_id="claim_synthesis",
            title="Claim Synthesis",
            goal="生成 2-3 条可逐条审查的论文主张。",
            inputs=["mechanism_graph", *claim_inputs],
            outputs=["claim_units"],
            acceptance_criteria=[
                "每条主张都要包含 evidence / validation / counterfactual / boundary",
            ],
            dependencies=["incident_reconstruction"],
        ),
        PublicationTaskNode(
            task_id="related_work_positioning",
            title="Related Work Positioning",
            goal="为每条文献指定角色与允许用途，防止越权引用。",
            inputs=["citations", "claim_units"],
            outputs=["related_work_positions"],
            acceptance_criteria=[
                "每条文献必须属于经验锚点、审计背景、机制比较或验证语境之一",
            ],
            dependencies=["claim_synthesis"],
        ),
        PublicationTaskNode(
            task_id="validation_design",
            title="Validation Design",
            goal="为每条主张写出 setup、observable、pass/fail 条件和 counterfactual。",
            inputs=["experiment_plan", "claim_units", "paper_strategy"],
            outputs=["validation_scenarios"],
            acceptance_criteria=[
                "必须回答什么结果支持主张，什么结果推翻主张",
            ],
            dependencies=["claim_synthesis", "paper_type_selection"],
        ),
        PublicationTaskNode(
            task_id="venue_blueprint",
            title="Venue Blueprint",
            goal="固定期刊稿体裁与 section blueprint，不允许 writer 自行发明结构。",
            inputs=["paper_strategy"],
            outputs=["venue_blueprint"],
            acceptance_criteria=[
                "章节职责必须先于写作被定义",
            ],
            dependencies=["paper_type_selection"],
        ),
        PublicationTaskNode(
            task_id="section_authoring",
            title="Section Authoring",
            goal="按 blueprint 逐节成稿，而不是由单一 writer 直接拼整篇。",
            inputs=["venue_blueprint", "claim_units", "related_work_positions", "validation_scenarios"],
            outputs=section_outputs,
            acceptance_criteria=[
                "每一节只回答一个明确问题",
            ],
            dependencies=["claim_synthesis", "related_work_positioning", "validation_design", "venue_blueprint"],
        ),
        PublicationTaskNode(
            task_id="cross_section_consistency_review",
            title="Cross-section Consistency Review",
            goal="检查摘要、主张、验证、结论和 references 之间是否一致。",
            inputs=["section::*"],
            outputs=["consistency_issues"],
            acceptance_criteria=[
                "不得出现摘要说得比结论更强",
                "不得出现 claim 与 validation 不对齐",
            ],
            dependencies=["section_authoring"],
        ),
        PublicationTaskNode(
            task_id="adversarial_reviewer_round",
            title="Adversarial Reviewer Round",
            goal="以多视角 reviewer 角色专门挑出 evidence、validation、related work 与 style 问题。",
            inputs=["paper_draft", "reviewer_lanes"],
            outputs=["reviewer_findings"],
            acceptance_criteria=[
                "reviewer 必须按分工给出问题，而不是混合总评",
            ],
            dependencies=["cross_section_consistency_review"],
        ),
        PublicationTaskNode(
            task_id="targeted_revision",
            title="Targeted Revision",
            goal="只修 reviewer 点名的 section，避免全文重写破坏强内容。",
            inputs=["reviewer_findings", "section::*"],
            outputs=["revised_sections", "revised_paper"],
            acceptance_criteria=[
                "修改必须逐项对应 reviewer finding",
            ],
            dependencies=["adversarial_reviewer_round"],
        ),
        PublicationTaskNode(
            task_id="submission_packaging",
            title="Submission Packaging",
            goal="输出网页预览、PDF、下载包与审稿附件，形成可验收成品。",
            inputs=["revised_paper", "publication_readiness", "venue_blueprint"],
            outputs=["paper_preview", "paper_pdf", "research_bundle"],
            acceptance_criteria=[
                "网页、PDF、下载包同时可访问",
                "PDF 版式必须接近期刊稿",
            ],
            dependencies=["targeted_revision"],
        ),
    ]


def build_publication_task_design(
    *,
    selected_idea: ResearchIdea,
    audit_result: AuditRunResult,
    citations: list[CitationRecord],
    claim_evidence_matrix: ClaimEvidenceMatrix | None,
    experiment_plan: ExperimentPlan | None,
    contribution_profile: ContributionProfile | None,
    incident_evidence_packages: list[IncidentEvidencePackage],
) -> PublicationTaskDesign:
    """构造期刊稿导向的研究任务设计。"""

    claim_units = _build_claim_units(
        selected_idea=selected_idea,
        claim_evidence_matrix=claim_evidence_matrix,
        incident_evidence_packages=incident_evidence_packages,
    )
    related_work_positions = _build_related_work_positions(citations)
    validation_scenarios = _build_validation_scenarios(
        claim_units=claim_units,
        experiment_plan=experiment_plan,
    )
    venue_blueprint = _build_venue_blueprint()
    reviewer_lanes = _build_reviewer_lanes()
    tasks = _build_task_nodes(
        claim_units=claim_units,
        venue_blueprint=venue_blueprint,
    )
    summary = _clean(
        f"当前研究任务被重构为一条面向新事件的期刊稿生产线：先做 event discovery，再做 incident understanding 与 mechanism generalization，"
        f"随后从事件中挖出 {len(claim_units)} 条可逐条审查的主张，并按 {len(venue_blueprint)} 个 section blueprint 成稿。"
        + (
            f" 核心贡献主线为：{contribution_profile.summary}"
            if contribution_profile
            else ""
        ),
        max_length=360,
    )
    return PublicationTaskDesign(
        summary=summary,
        tasks=tasks,
        claim_units=claim_units,
        related_work_positions=related_work_positions,
        validation_scenarios=validation_scenarios,
        venue_blueprint=venue_blueprint,
        reviewer_lanes=reviewer_lanes,
    )


def render_publication_task_design_markdown(design: PublicationTaskDesign | dict) -> str:
    """把任务设计渲染成 Markdown。"""

    if isinstance(design, dict):
        summary = str(design.get("summary") or "")
        tasks = design.get("tasks") or []
        claim_units = design.get("claim_units") or []
        related_work_positions = design.get("related_work_positions") or []
        validation_scenarios = design.get("validation_scenarios") or []
        venue_blueprint = design.get("venue_blueprint") or []
        reviewer_lanes = design.get("reviewer_lanes") or []
    else:
        summary = design.summary
        tasks = [item.to_dict() for item in design.tasks]
        claim_units = [item.to_dict() for item in design.claim_units]
        related_work_positions = [item.to_dict() for item in design.related_work_positions]
        validation_scenarios = [item.to_dict() for item in design.validation_scenarios]
        venue_blueprint = [item.to_dict() for item in design.venue_blueprint]
        reviewer_lanes = [item.to_dict() for item in design.reviewer_lanes]

    lines = [
        "# Publication Task Design",
        "",
        f"- Summary: {summary}",
        "",
        "## Task Pipeline",
        "",
    ]
    for index, task in enumerate(tasks, start=1):
        lines.extend(
            [
                f"### {index}. {task.get('title', '')}",
                "",
                f"- Task ID: {task.get('task_id', '')}",
                f"- Goal: {task.get('goal', '')}",
                f"- Inputs: {'；'.join(task.get('inputs', []) or []) or '暂无'}",
                f"- Outputs: {'；'.join(task.get('outputs', []) or []) or '暂无'}",
                f"- Acceptance: {'；'.join(task.get('acceptance_criteria', []) or []) or '暂无'}",
                f"- Dependencies: {'；'.join(task.get('dependencies', []) or []) or '无'}",
                "",
            ]
        )
    lines.extend(["## Claim Units", ""])
    for item in claim_units:
        lines.extend(
            [
                f"### {item.get('claim_id', '')}",
                "",
                f"- Statement: {item.get('statement', '')}",
                f"- Direct Evidence: {item.get('direct_evidence', '')}",
                f"- Validation Anchor: {item.get('validation_anchor', '')}",
                f"- Counterfactual: {item.get('counterfactual', '')}",
                f"- Boundary: {item.get('boundary', '')}",
                "",
            ]
        )
    lines.extend(["## Related Work Positioning", ""])
    for item in related_work_positions:
        lines.extend(
            [
                f"- {item.get('title', '')} | {item.get('role', '')} | usage={item.get('usage', '')} | forbidden={item.get('forbidden_usage', '')}",
            ]
        )
    lines.extend(["", "## Validation Scenarios", ""])
    for item in validation_scenarios:
        lines.extend(
            [
                f"### {item.get('claim_id', '')}",
                "",
                f"- Setup: {item.get('setup', '')}",
                f"- Observable: {item.get('observable', '')}",
                f"- Pass: {item.get('pass_condition', '')}",
                f"- Fail: {item.get('fail_condition', '')}",
                f"- Counterfactual: {item.get('counterfactual', '')}",
                "",
            ]
        )
    lines.extend(["## Venue Blueprint", ""])
    for item in venue_blueprint:
        lines.extend(
            [
                f"- {item.get('heading', '')}: {item.get('purpose', '')} | inputs={'；'.join(item.get('required_inputs', []) or [])} | notes={item.get('style_notes', '')}",
            ]
        )
    lines.extend(["", "## Reviewer Lanes", ""])
    for item in reviewer_lanes:
        lines.extend(
            [
                f"- {item.get('label', '')} ({item.get('focus', '')}): {'；'.join(item.get('checklist', []) or [])}",
            ]
        )
    return "\n".join(lines).strip() + "\n"
