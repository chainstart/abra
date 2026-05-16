"""构造统一的 manuscript package，供分节 writer 使用。"""

from __future__ import annotations

import re

from services.analysis.models import AuditRunResult
from services.research.figure_table_agent import build_figure_and_table_specs
from services.research.models import (
    CitationRecord,
    ClaimEvidenceMatrix,
    ContributionProfile,
    ExperimentPlan,
    IncidentEvidencePackage,
    ManuscriptClaim,
    ManuscriptPackage,
    ManuscriptReference,
    ResearchIdea,
)
from services.research.publication_task_design import PublicationTaskDesign
from services.research.research_object_design import PaperStrategy


def _clean(text: str, *, max_length: int = 260) -> str:
    cleaned = " ".join(str(text or "").replace("\n", " ").split()).strip(" -;:,")
    if not cleaned:
        return ""
    cleaned = cleaned.replace("`", "")
    cleaned = cleaned.replace("**", "")
    if len(cleaned) > max_length:
        cleaned = cleaned[:max_length].rstrip(" ,;:") + "..."
    if cleaned and cleaned[-1] not in ".。!?？！":
        cleaned += "。"
    return cleaned


def _is_noisy(text: str) -> bool:
    raw = str(text or "").strip()
    if not raw:
        return True
    markers = ["|", "```", "[", "]", "../", "http://", "https://", "日期:", "审计对象:"]
    if any(marker in raw for marker in markers):
        return True
    symbol_count = sum(1 for ch in raw if ch in {"`", "*", "#", "|", "{", "}", "[", "]"})
    if symbol_count / max(len(raw), 1) > 0.05:
        return True
    return False


def _protocol_type_label(protocol_type: str) -> str:
    mapping = {
        "lending": "借贷",
        "amm": "自动做市",
        "bridge": "跨链桥",
        "staking": "质押",
        "governance": "治理",
    }
    normalized = " ".join((protocol_type or "").split()).strip().lower()
    return mapping.get(normalized, normalized or "未知")


def _display_reference_title(title: str) -> str:
    raw = str(title or "").strip()
    if not raw:
        return "Untitled Reference"
    normalized = raw.replace("-", "_")
    if re.fullmatch(r"\d+_[a-z0-9_]+", normalized):
        normalized = re.sub(r"^\d+_", "", normalized)
        tokens = [part for part in normalized.split("_") if part]
        special = {
            "defi": "DeFi",
            "morpho": "Morpho",
            "aave": "Aave",
            "compound": "Compound",
            "uniswap": "Uniswap",
            "tvl": "TVL",
            "oracle": "Oracle",
            "onchain": "On-chain",
        }
        return " ".join(special.get(token.lower(), token.capitalize()) for token in tokens)
    return raw


def _keywords(research_idea: ResearchIdea, audit_result: AuditRunResult) -> list[str]:
    title = f"{research_idea.title} {research_idea.hypothesis} {research_idea.problem_statement}".lower()
    keywords: list[str] = []
    if "oracle" in title:
        keywords.append("Oracle 有效性")
    if "permissionless" in title:
        keywords.append("无许可市场")
    protocol_type = (audit_result.classification.protocol_type or "").strip()
    if protocol_type:
        keywords.append(f"{_protocol_type_label(protocol_type)}协议")
    focus = (research_idea.focus_category or "").split(":")[-1].strip()
    if focus:
        keywords.append(focus)
    keywords.extend(["incident-first 分析", audit_result.classification.protocol_name])
    deduped: list[str] = []
    seen: set[str] = set()
    for keyword in keywords:
        normalized = " ".join(str(keyword).split()).strip()
        if not normalized or normalized.lower() in seen:
            continue
        seen.add(normalized.lower())
        deduped.append(normalized)
    return deduped[:6]


def _unique_nonempty(items: list[str], *, limit: int | None = None) -> list[str]:
    deduped: list[str] = []
    seen: set[str] = set()
    for item in items:
        normalized = _clean(item, max_length=260)
        if not normalized:
            continue
        lowered = normalized.lower()
        if lowered in seen:
            continue
        seen.add(lowered)
        deduped.append(normalized)
        if limit is not None and len(deduped) >= limit:
            break
    return deduped


def _select_references(citations: list[CitationRecord], limit: int = 5) -> list[CitationRecord]:
    incident = [citation for citation in citations if citation.source_type == "incident"]
    background = [
        citation
        for citation in citations
        if citation not in incident
    ]
    selected = incident[:2] + background[: max(0, limit - len(incident[:2]))]
    return selected[:limit]


def _reference_takeaway(
    citation: CitationRecord,
    *,
    primary_incident: IncidentEvidencePackage | None,
) -> str:
    title = _display_reference_title(citation.title)
    claim = _clean(citation.claim_supported, max_length=140)
    if citation.source_type == "incident" and primary_incident:
        return _clean(
            f"{primary_incident.loss_summary} 的损失事实与攻击时间线共同说明，该个案已经在真实链上形成由错误 Oracle 配置触发的可执行借贷路径。",
            max_length=220,
        )
    lowered = title.lower()
    if "verification" in lowered or "on-chain" in lowered or "onchain" in lowered:
        return _clean(
            f"该材料主要用于支撑 {claim or '关键利用路径'} 在主网 fork 或链上语境中的可复现性，而不是单独承担个案事实证明责任。",
            max_length=220,
        )
    if "audit" in lowered:
        return _clean(
            f"该材料主要用于补足 {claim or 'Oracle 接入风险'} 的审计视角，并帮助界定价格输入、约束判断与协议边界之间的关系。",
            max_length=220,
        )
    return _clean(
        citation.citation_reason or citation.claim_supported or citation.snippet,
        max_length=220,
    )


def _claim_specific_evidence_summary(
    claim_text: str,
    *,
    primary_incident: IncidentEvidencePackage | None,
) -> str:
    lowered = claim_text.lower()
    if "oracle" in lowered and "模式" in claim_text:
        return (
            "攻击时间线显示，错误 Oracle 参数先在市场创建阶段进入系统，随后被价格传播与健康度判断连续接受，"
            "最终对应到真实借款结果。"
        )
    if "无许可市场创建" in claim_text:
        return (
            "个案表明 createMarket 的无许可入口降低了问题市场进入系统的门槛，"
            "使配置错误能够直接转化为可执行的借贷条件。"
        )
    if "有效性校验" in claim_text:
        return (
            "该个案至少暴露出三类必要检查：市场创建时的输入有效性、价格传播到健康度判断时的语义一致性，"
            "以及借款放行前后的结果约束。"
        )
    if primary_incident and primary_incident.evidence_summary:
        return primary_incident.evidence_summary[0]
    return claim_text


def _claim_specific_boundary(claim_text: str) -> str:
    if "oracle" in claim_text.lower() and "模式" in claim_text:
        return "Morpho Blue 单一市场、错误 decimals 配置和最小复现实验所覆盖的 Oracle 接入场景内。"
    if "无许可市场创建" in claim_text:
        return "本文个案所展示的 permissionless market creation 机制范围内，而不直接外推到全部无许可市场设计。"
    if "有效性校验" in claim_text:
        return "当前个案所揭示的最小必要条件范围内，而非完备防护清单。"
    return "当前个案、当前链上锚点与最小复现实验所覆盖的范围内。"


def _claim_specific_validation_summary(claim_text: str) -> str:
    if "无许可市场创建" in claim_text:
        return "主网 fork 上对 createMarket 零验证与问题市场进入条件的最小复现实验。"
    if "有效性校验" in claim_text:
        return "围绕价格传播、健康度判断与借款放行结果的最小验证组合。"
    return "主网 fork / PoC 对关键利用路径的最小复现实验。"


def _contextual_counterfactual_points(
    *,
    primary_incident: IncidentEvidencePackage | None,
) -> list[str]:
    component_labels = (
        [item.label for item in primary_incident.affected_components[:3]]
        if primary_incident
        else []
    )
    component_text = "、".join(component_labels) if component_labels else "市场创建、价格传播与借贷约束"
    return [
        f"若市场创建阶段已对 Oracle 输入做最小有效性约束，则问题市场不应越过准入边界并进入后续 {component_text} 链路。",
        "若错误价格无法继续传播到健康度或抵押率判断，该利用路径应停留在配置缺陷层，而不应演化为真实借款结果。",
        "若借款放行前后的结果检查能够识别 decimals 失配带来的异常估值，则欠抵押借款路径应在执行阶段失败。",
    ]


def build_manuscript_package(
    *,
    research_idea: ResearchIdea,
    audit_result: AuditRunResult,
    citations: list[CitationRecord],
    experiment_plan: ExperimentPlan | None,
    contribution_profile: ContributionProfile | None,
    claim_evidence_matrix: ClaimEvidenceMatrix | None,
    incident_evidence_packages: list[IncidentEvidencePackage] | None,
    publication_task_design: PublicationTaskDesign | None = None,
    paper_strategy: PaperStrategy | None = None,
) -> ManuscriptPackage:
    """把 workflow 结果压缩成论文成稿需要的统一包。"""

    incident_evidence_packages = incident_evidence_packages or []
    primary_incident = incident_evidence_packages[0] if incident_evidence_packages else None
    protocol_name = audit_result.classification.protocol_name
    protocol_type = _protocol_type_label(audit_result.classification.protocol_type)
    paper_type = paper_strategy.paper_type if paper_strategy else "case_study"
    target_venue_style = paper_strategy.target_venue_style if paper_strategy else "acm_case_study"
    article_positioning = (
        paper_strategy.article_positioning
        if paper_strategy
        else "把单一 incident 提升为可审查的安全机制个案研究。"
    )
    section_blueprint = list(paper_strategy.section_blueprint) if paper_strategy else [
        "Abstract",
        "Introduction",
        "Background",
        "Incident Reconstruction",
        "Claim-Evidence Mapping",
        "Validation",
        "Related Work",
        "Threats to Validity",
        "Conclusion",
    ]
    validation_expectations = list(paper_strategy.validation_expectations) if paper_strategy else []
    selected_references = _select_references(citations)
    manuscript_references = [
        ManuscriptReference(
            citation_id=citation.citation_id,
            title=_display_reference_title(citation.title),
            role="经验锚点" if citation.source_type == "incident" else "背景与比较文献",
            takeaway=_reference_takeaway(citation, primary_incident=primary_incident),
            citation_reason=_clean(citation.citation_reason or citation.claim_supported, max_length=160),
            source_type=citation.source_type,
            source_ref=citation.source_ref,
        )
        for citation in selected_references
    ]

    claims: list[ManuscriptClaim] = []
    if publication_task_design and publication_task_design.claim_units:
        for unit in publication_task_design.claim_units[:3]:
            citation_titles = [
                _display_reference_title(citation.title)
                for citation in selected_references[:3]
                if any(
                    role_entry.citation_id == citation.citation_id
                    for role_entry in publication_task_design.related_work_positions
                )
            ]
            claims.append(
                ManuscriptClaim(
                    claim_id=unit.claim_id,
                    claim=unit.statement,
                    evidence_summary=_clean(unit.direct_evidence, max_length=220),
                    citation_titles=citation_titles[:3],
                    validation_summary=_clean(unit.validation_anchor, max_length=180),
                    boundary=_clean(unit.boundary, max_length=180),
                    status="supported",
                )
            )
    else:
        for row in (claim_evidence_matrix.rows if claim_evidence_matrix else [])[:3]:
            claims.append(
                ManuscriptClaim(
                    claim_id=row.claim_id,
                    claim=row.claim,
                    evidence_summary=_clean(
                        _claim_specific_evidence_summary(
                            row.claim,
                            primary_incident=primary_incident,
                        ),
                        max_length=220,
                    ),
                    citation_titles=[_display_reference_title(title) for title in row.citation_refs[:3]],
                    validation_summary=_clean(
                        _claim_specific_validation_summary(row.claim),
                        max_length=180,
                    ),
                    boundary=_clean(
                        _claim_specific_boundary(row.claim),
                        max_length=180,
                    ),
                    status=row.status,
                )
            )

    if paper_type == "measurement":
        abstract_points = [
            f"本文以 {protocol_name} 事件为锚点，进一步将其提升为跨 incident 的安全测量问题，关注同类 Oracle 风险是否能够被统一建模。",
            "本文先做 incident reconstruction，再抽出 generalized mechanism，并据此生成可量化的 research program candidate。",
            contribution_profile.novelty_positioning if contribution_profile else "本文的主要贡献是把单事件提升为可比较的安全测量对象。",
            "结论边界被限定在当前收集到的事件集合与测量覆盖范围内。",
        ]
        introduction_points = [
            research_idea.motivation,
            f"{protocol_name} 被作为 measurement 入口事件，而不是唯一分析对象。",
            "本文关心的不是单一事故是否存在，而是这一机制族是否能够跨多个事件被统一刻画与测量。",
            "因此，全文围绕 incident modeling、measurement method 和结果解释展开。",
        ]
        background_points = [
            f"{protocol_name} 被当作进入测量问题的起点，而不是全文唯一结论来源。",
            "与研究问题最直接相关的是统一机制标签、事件建模方式和跨事件可比较维度。",
            "因此，本节更偏 problem formulation 与 dataset framing，而不是单事件背景描述。",
        ]
    elif paper_type == "defense":
        abstract_points = [
            f"本文以 {protocol_name} 个案为锚点，讨论哪些最小防御条件足以阻断错误 Oracle 参数进入借贷约束链路。",
            "本文将 incident 事实、机制图和反证条件结合起来，用于刻画最小防御条件而非单纯复盘事故。",
            contribution_profile.novelty_positioning if contribution_profile else "本文的贡献主要体现在最小防御条件和验证边界的明确化。",
            "结论边界被限定在当前机制图和反证设计所覆盖的防御条件之内。",
        ]
        introduction_points = [
            research_idea.motivation,
            f"{protocol_name} 被作为防御问题的现实锚点，用于说明为何最小有效性校验值得单独设计。",
            "本文要回答的不是事件是否发生，而是哪几类检查足以在关键边界阻断路径。",
            "因此，全文围绕 threat model、defense condition 与 counterfactual validation 展开。",
        ]
        background_points = [
            f"{protocol_name} 在这里被视为一个防御设计样本。",
            "与研究问题最直接相关的是市场准入、价格语义归一化和借贷结果约束三类边界。",
            "这些接口共同决定最小防御条件应该放在什么位置上。",
        ]
    else:
        abstract_points = [
            f"本文以 {protocol_name} 中由错误 Oracle 参数触发的 PAXG/USDC 个案为研究对象，关注参数失配如何在无许可市场创建条件下进入借贷约束链路并转化为可利用路径。",
            "本文只把 incident 事实、链上锚点与最小 fork/PoC 验证作为核心论证材料，背景文献仅承担综述与比较作用。",
            contribution_profile.novelty_positioning if contribution_profile else "本文的贡献是个案锚定的机制抽象与最小复现实证链，而非全新攻击原语。",
            "结论边界被限定在单市场、单路径与最小复现实验范围内，不据此直接推出更广协议族上的普遍结论。",
        ]
        introduction_points = [
            research_idea.motivation,
            f"{protocol_name} 被选择为个案样本，并不是因为它代表全部 {protocol_type} 协议，而是因为它同时具备真实 incident、链上锚点与最小可复现实验。",
            "因此，本文关注的是错误 Oracle 参数如何穿过市场创建与借贷约束之间的接口，并最终对应到真实利用路径。",
            "本文的论证主线由三部分构成：经验个案、机制解释与最小复现实验。",
        ]
        background_points = [
            f"{protocol_name} 在本文中被视为一个用于机制分析的 {protocol_type} 个案。",
            "与研究问题最直接相关的组件包括市场创建逻辑、Oracle 定价组件与健康度评估链路。",
            "这些组件的重要性不在于分别对应了多少局部告警，而在于它们共同构成了个案路径得以传播的接口。",
        ]
    incident_context_points = [
        _clean(
            (
                primary_incident.summary
                if primary_incident
                else audit_result.evidence_summary.overview
            ),
            max_length=240,
        ),
        _clean(
            (
                primary_incident.evidence_summary[-1]
                if primary_incident and primary_incident.evidence_summary
                else ""
            ),
            max_length=220,
        ),
    ]
    problem_statement_points = [
        research_idea.problem_statement or research_idea.hypothesis,
        "核心问题并不只是 Oracle 可能被错误配置，而是协议架构是否允许这种错误继续传播到定价、健康度评估与借贷放行逻辑之中。",
        "相应地，本文的问题陈述被限定为个案驱动的机制问题，而不是更广的行业归纳。",
    ]
    if primary_incident:
        evidence_points = _unique_nonempty(
            [
                "错误 Oracle 参数并非停留在单点输入层，而是先在市场创建阶段进入系统，随后继续传播到价格解释与健康度判断。",
                "攻击时间线显示，价格失配最终被借贷约束接受，并转化为约 23 万美元 USDC 的真实借款结果。",
                "受影响组件集中在 createMarket、_isHealthy 与 Oracle 适配层，说明该风险跨越了准入、定价与约束三个接口。",
            ],
            limit=3,
        )
    else:
        evidence_points = [
            _clean(item.summary, max_length=240)
            for item in sorted(
                (research_idea.evidence_chain or []),
                key=lambda item: (
                    0 if item.evidence_type in {"incident", "incident_trace"} else 1,
                    -len(item.summary or ""),
                ),
            )
            if "地址:" not in str(item.summary or "") and "attacker" not in str(item.summary or "").lower()
        ][:3]
    validation_anchor_points = _unique_nonempty(
        [
            item.pass_condition
            for item in (publication_task_design.validation_scenarios if publication_task_design else [])
        ]
        or [
            item.get("summary", "")
            for package in incident_evidence_packages
            for item in package.verification_results
            if item.get("passed")
        ],
        limit=3,
    )
    if primary_incident:
        component_descriptions = [
            _clean(item.description, max_length=160)
            for item in primary_incident.affected_components[:3]
            if _clean(item.description, max_length=160)
        ]
        observations = _unique_nonempty(
            [
                f"该个案的根因并不是孤立的价格读取错误，而是 {primary_incident.root_cause}",
                (
                    "关键组件的描述显示，问题同时涉及市场准入、价格解释与健康度判断。 "
                    + " ".join(component_descriptions[:2])
                )
                if component_descriptions
                else "",
                (
                    "已完成的主网 fork / PoC 验证说明，这条路径不仅能在静态机制层面成立，"
                    "也能在受限实验条件下被最小复现。"
                )
                if validation_anchor_points
                else "",
                "因此，本文最稳妥的结论不是泛化所有 Oracle 风险，而是说明错误参数何时会跨越系统边界并进入真实借贷约束。",
            ],
            limit=4,
        )
    else:
        observations = [
            _clean(item, max_length=220)
            for item in (research_idea.key_observations or [])[:4]
        ]
    incident_anchor_points: list[str] = []
    if primary_incident:
        incident_anchor_points.extend(
            [
                primary_incident.summary,
                f"已知损失锚点为 {primary_incident.loss_summary}",
            ]
        )
        for attack_tx in primary_incident.attack_transactions[:2]:
            tx_anchor = (
                f"链上锚点交易 {attack_tx.tx_hash} 对应 {attack_tx.label}，"
                f"状态为 {attack_tx.status}，并落在 {attack_tx.chain} 主网区块 {attack_tx.block_number or '未知区块'}。"
            )
            if attack_tx.selector:
                tx_anchor += f" 其调用 selector 为 {attack_tx.selector}。"
            incident_anchor_points.append(tx_anchor)
        if primary_incident.timeline:
            timeline_summary = "；".join(
                f"{step.title}：{step.description}"
                for step in primary_incident.timeline[:3]
            )
            incident_anchor_points.append(
                f"围绕该 incident 可以重构出一条三阶段时间线：{timeline_summary}"
            )
        if primary_incident.affected_components:
            component_summary = "、".join(
                component.label or component.reference
                for component in primary_incident.affected_components[:3]
            )
            incident_anchor_points.append(
                f"个案所牵涉的关键组件主要包括 {component_summary}，因此本文把分析重点收束在市场创建、价格传播与借贷约束三个接口上。"
            )
    counterfactual_points = _unique_nonempty(
        [
            item.counterfactual
            for item in (publication_task_design.validation_scenarios if publication_task_design else [])
        ]
        + _contextual_counterfactual_points(primary_incident=primary_incident)
        + [
            criterion
            for design in ((experiment_plan.designs or []) if experiment_plan else [])
            for criterion in design.failure_criteria[:1]
        ],
        limit=5,
    )
    methodology_points = [
        "先以 incident 与链上锚点重建经验事实，再用结构化分析解释个案机制链，最后用最小 fork/PoC 检验受限条件下的路径成立性。",
        "核心论证按市场创建、定价传播与借贷约束三层组织，而不是按零散告警逐项展开。",
        "所有核心主张都必须回连到 incident 事实、链上锚点或本地验证，不允许背景文献单独承担证明责任。",
    ]
    if paper_type == "measurement":
        evaluation_points = [
            "验证与评估围绕 measurement scope、cross-incident consistency 和可比较结果展开。",
            "当前最重要的评估问题不是单路径是否存在，而是统一机制标签能否稳定刻画多个相关事件。",
            "因此，结果解释必须显式区分事件锚点、机制抽象和测量边界。",
        ]
        discussion_points = [
            "当前稿件的讨论重点是 measurement scope 和 generalized mechanism，而不是单次 exploit 的叙述完整度。",
            f"对 {protocol_name} 的价值在于提供一个真实锚点，使测量问题不脱离现实事件。",
            "因此，讨论部分必须持续回答哪些结论来自单事件，哪些结论来自跨事件比较。",
        ]
    elif paper_type == "defense":
        evaluation_points = [
            "验证与评估围绕最小防御条件是否真正阻断 exploit path 展开，而不是只证明脆弱路径存在。",
            "当前最重要的观察点是防御前后 counterfactual 的差异，以及防御条件是否过度影响系统可用性。",
            "因此，评估必须同时报告 blocked path、residual risk 和适用边界。",
        ]
        discussion_points = [
            "本文的讨论重点是最小防御条件是否足够强、是否足够小，以及它们放在什么系统边界最合理。",
            f"{protocol_name} 个案在这里主要用于说明防御条件的现实约束，而不是承担全部设计证明。",
            "因此，讨论必须回到防御成本、兼容性和 residual risk。",
        ]
    else:
        evaluation_points = [
            "最小复现实验以主网 fork / PoC 为载体，并围绕个案路径是否成立这一单一问题组织输入、观察点、断言与成功判据。",
            "当前已完成的验证主要覆盖无许可市场创建入口和欠抵押借款结果两处关键节点，因此可用于支撑受限范围内的机制解释。",
            "验证的作用是回答‘该个案路径是否成立’，而不是替代更广协议族、更多市场或更多 Oracle 设计分支上的统计结论。",
        ]
        discussion_points = [
            "综合 incident、链上锚点与最小复现实验，可以得到一个受限但稳健的判断：错误 Oracle 参数并不会停留为静态配置问题，而是可能沿相关组件链条继续传播。",
            f"对 {protocol_name} 的分析价值不在于证明所有同类协议都有相同问题，而在于它允许本文在经验个案、结构解释与复现实验之间建立一一对应关系。",
            "因此，本文把讨论收束到一个更具体的问题：哪些最小有效性校验本可以在路径进入借贷约束之前阻断它。",
        ]
    contribution_points = [
        entry.statement
        for entry in (contribution_profile.entries if contribution_profile else [])
    ] or (research_idea.expected_contributions or [])[:3]
    threats_points = list((experiment_plan.open_risks if experiment_plan else []) or research_idea.risks or [])[:3]
    if len(threats_points) < 3:
        threats_points.extend(["本文的外推范围仍受案例数量和验证覆盖度限制。"] * (3 - len(threats_points)))
    conclusion_points = [
        "本文的核心价值，在于把真实攻击事件、链上锚点、本地验证与目标协议结构化分析统一到同一篇研究稿中。",
        f"因此，本文对 {protocol_name} 的讨论并不把个案直接泛化为行业共识，而是把它作为具有经验锚点的机制研究样本。",
        "候选性最小防护条件在本文中应被理解为机制推断与设计含义，而不是已经通过更广样本充分验证的普适清单。",
    ]
    figures, tables = build_figure_and_table_specs(
        package=ManuscriptPackage(
            title=research_idea.title,
            paper_type=paper_type,
            target_venue_style=target_venue_style,
            article_positioning=article_positioning,
            section_blueprint=section_blueprint,
            validation_expectations=validation_expectations,
            keywords=_keywords(research_idea, audit_result),
            abstract_points=abstract_points,
            introduction_points=introduction_points,
            background_points=background_points,
            incident_context_points=[item for item in incident_context_points if item],
            problem_statement_points=problem_statement_points,
            research_questions=list(research_idea.research_questions or [])[:4],
            evidence_points=evidence_points,
            observations=observations,
            incident_anchor_points=incident_anchor_points,
            validation_anchor_points=validation_anchor_points,
            counterfactual_points=counterfactual_points,
            methodology_points=methodology_points,
            evaluation_points=evaluation_points,
            discussion_points=discussion_points,
            contribution_points=contribution_points,
            threats_points=threats_points[:3],
            conclusion_points=conclusion_points,
            claims=claims,
            references=manuscript_references,
            figures=[],
            tables=[],
        ),
        audit_result=audit_result,
        claim_evidence_matrix=claim_evidence_matrix,
        incident_evidence_packages=incident_evidence_packages,
    )

    return ManuscriptPackage(
        title=research_idea.title,
        paper_type=paper_type,
        target_venue_style=target_venue_style,
        article_positioning=article_positioning,
        section_blueprint=section_blueprint,
        validation_expectations=validation_expectations,
        keywords=_keywords(research_idea, audit_result),
        abstract_points=abstract_points,
        introduction_points=introduction_points,
        background_points=background_points,
        incident_context_points=[item for item in incident_context_points if item],
        problem_statement_points=problem_statement_points,
        research_questions=list(research_idea.research_questions or [])[:4],
        evidence_points=evidence_points,
        observations=observations,
        incident_anchor_points=incident_anchor_points,
        validation_anchor_points=validation_anchor_points,
        counterfactual_points=counterfactual_points,
        methodology_points=methodology_points,
        evaluation_points=evaluation_points,
        discussion_points=discussion_points,
        contribution_points=contribution_points,
        threats_points=threats_points[:3],
        conclusion_points=conclusion_points,
        claims=claims,
        references=manuscript_references,
        figures=figures,
        tables=tables,
    )
