"""研究问题生成器。

这一层的目标不是“随便给一个题目”，而是围绕当前目标生成：

- 多个候选研究方向
- 每个方向的证据链
- 可比较的评分
- 明确的研究问题、贡献和风险
"""

from __future__ import annotations

from collections import Counter
import hashlib
from typing import Any

from services.analysis.models import AuditRunResult
from services.research.incident_evidence_service import build_incident_evidence_package
from services.shared.llm_client import OpenAiCompatibleLlmClient
from services.shared.settings import ProjectSettings
from services.research.models import ResearchEvidence, ResearchIdea


CATEGORY_VARIANTS: dict[str, list[dict[str, object]]] = {
    "SC-01: Reentrancy": [
        {
            "variant_id": "surface",
            "title": "{protocol_type} 协议中的回调重入攻击面普查研究",
            "problem_statement": "当前审计已经暴露出与外部调用顺序、共享状态更新和回调路径相关的高风险信号，但这些信号在协议层面如何组合成真实攻击面仍然缺乏统一刻画。",
            "hypothesis": "在 {protocol_type} 协议中，外部调用后写状态、跨合约边和共享状态冲突共同构成了可复现的重入攻击面。",
            "motivation": "如果只看单条 finding，很容易把风险理解成局部编码错误；真正高价值的是识别出哪些结构信号在跨协议场景下反复出现。",
            "novelty": "把 AST 深分析、审计 finding 和历史案例对齐到同一套回调重入攻击面描述框架中。",
            "research_questions": [
                "哪些外部调用后写状态模式会在 {protocol_type} 协议里反复出现？",
                "哪些跨合约调用边最容易和共享状态冲突组合成重入利用窗口？",
                "如何用结构化信号提升重入风险判断的稳定性而不是只堆规则？",
            ],
            "contributions": [
                "给出一套面向回调重入的结构化攻击面标签体系。",
                "建立从 finding 到利用前提的证据映射关系。",
                "输出可复用的重入风险评测样本与检查清单。",
            ],
            "risks": [
                "如果缺少动态验证，结论仍可能停留在高风险假设层。",
                "仅依赖单一协议样本会影响结论外推。",
            ],
            "experiments": [
                "统计不同 {protocol_type} 协议中的外部调用后写状态模式。",
                "对高风险函数构造 fork 或 PoC 验证路径。",
                "比较不同防御模式对风险覆盖率和误报率的影响。",
            ],
            "novelty_bonus": 0.08,
        },
        {
            "variant_id": "verification",
            "title": "从静态疑点到可验证结论的 DeFi 重入证据链研究",
            "problem_statement": "很多重入 finding 看起来危险，但真正决定研究价值的是能否把静态疑点推进到可验证结论。",
            "hypothesis": "把静态 finding、历史案例和语义结构信号结合起来，可以显著提高重入研究方向的可验证性与结论可信度。",
            "motivation": "单纯增加 finding 数量不会让研究更强，真正有价值的是构建从“怀疑项”到“可验证结论”的推进框架。",
            "novelty": "把审计环节的怀疑项转化为研究环节的证据链和验证路线。",
            "research_questions": [
                "哪些静态 finding 最值得进入动态验证队列？",
                "历史案例如何帮助缩小验证空间并提升研究置信度？",
                "什么样的证据组合足以支撑“高置信研究问题”的判断？",
            ],
            "contributions": [
                "提出一套研究问题优先级排序与验证触发机制。",
                "沉淀重入类研究的证据链模板。",
                "把研究工作流与审计验证工作流打通。",
            ],
            "risks": [
                "如果验证成本过高，研究进度会被拖慢。",
                "证据链评价仍可能受到样本规模限制。",
            ],
            "experiments": [
                "对比不同证据组合下的研究方向排序结果。",
                "评估历史案例匹配是否能降低验证成本。",
                "记录从静态 finding 到 PoC 成功的转化率。",
            ],
            "novelty_bonus": 0.05,
        },
        {
            "variant_id": "defense",
            "title": "面向 {protocol_type} 协议的重入防御策略效果评测",
            "problem_statement": "协议侧往往知道“要防重入”，但不知道哪些防御模式在复杂回调结构下最稳健。",
            "hypothesis": "仅靠通用 `nonReentrant` 不是最优解，基于状态隔离、交互顺序重构和入口约束的组合防御在 {protocol_type} 协议中更有效。",
            "motivation": "如果研究只能指出风险，而无法比较防御收益，最终价值会停留在描述层。",
            "novelty": "把漏洞发现转化为防御效果评测问题，而不是止步于问题罗列。",
            "research_questions": [
                "不同防御模式对高风险回调路径的覆盖差异是什么？",
                "哪些结构信号能提前提示某类防御策略会失效？",
                "防御收益和实现复杂度之间如何取舍？",
            ],
            "contributions": [
                "给出面向协议开发者的防御策略对照表。",
                "建立防御模式和攻击前提之间的映射关系。",
                "沉淀适合回归测试的重入样本集。",
            ],
            "risks": [
                "如果没有足够多的防御实现样本，比较结果可能偏弱。",
                "真实协议中的业务副作用会影响防御方案评估。",
            ],
            "experiments": [
                "对比 `nonReentrant`、CEI 重构和状态隔离的效果。",
                "在历史案例上回放不同防御策略的阻断能力。",
                "统计防御策略引入的额外复杂度与维护成本。",
            ],
            "novelty_bonus": 0.06,
        },
    ],
    "SC-02: Access Control": [
        {
            "variant_id": "exposure",
            "title": "Permissionless DeFi 中敏感函数暴露面的系统风险研究",
            "problem_statement": "在 permissionless 或半 permissionless 协议里，敏感函数的角色边界往往不是简单的 owner / non-owner 二元问题，而是治理、配置、清算和参数变更边界共同作用的结果。",
            "hypothesis": "敏感函数边界不清晰会在 permissionless DeFi 中持续形成攻击与误配置复合风险。",
            "motivation": "访问控制问题在研究层面经常被低估，但大量历史事故都不是单点失误，而是边界设计不完整。",
            "novelty": "把传统的访问控制检查扩展为 permissionless 经济系统中的角色边界研究。",
            "research_questions": [
                "哪些敏感函数最容易在 permissionless 语义下暴露给错误调用者？",
                "边界缺失与历史事故中的损失模式是否存在稳定对应关系？",
                "如何定义适合 DeFi 协议的最小权限边界模板？",
            ],
            "contributions": [
                "提出适合 DeFi 协议的敏感函数分层模型。",
                "沉淀角色边界缺陷与事故模式的映射。",
                "给出最小权限模板与验证清单。",
            ],
            "risks": [
                "如果协议原本就追求开放调用，误判风险会上升。",
                "角色边界往往依赖业务上下文，自动化提炼存在偏差。",
            ],
            "experiments": [
                "统计借贷与 vault 协议中的敏感函数暴露分布。",
                "分析角色检查缺失与历史资金损失的关联。",
                "在样本协议上验证最小权限模板的适用性。",
            ],
            "novelty_bonus": 0.05,
        },
        {
            "variant_id": "governance",
            "title": "从配置权限到治理风险的 DeFi 边界失效研究",
            "problem_statement": "很多权限问题不是“完全没权限控制”，而是配置变更、治理入口、初始化和运维函数之间存在边界断裂。",
            "hypothesis": "配置与治理边界错位会比简单的公开敏感函数更隐蔽，也更容易导致高影响事故。",
            "motivation": "研究如果只停留在公开函数可调用，会错过更真实的边界失效场景。",
            "novelty": "把访问控制问题提升到治理与配置边界一致性研究。",
            "research_questions": [
                "哪些配置与治理函数最容易形成边界错位？",
                "初始化、升级和治理入口之间如何形成复合风险？",
                "哪些设计模式可以降低边界漂移？",
            ],
            "contributions": [
                "定义 DeFi 配置与治理边界一致性检查框架。",
                "总结边界漂移导致的事故模式。",
                "输出更适合审计与研究联动的检查路径。",
            ],
            "risks": [
                "治理风险通常需要更多上下文，自动分析信息可能不足。",
                "不同协议治理模型差异大，横向比较难度较高。",
            ],
            "experiments": [
                "整理配置/治理函数的语义分类。",
                "在历史事故上分析边界漂移是如何形成的。",
                "比较不同治理保护策略的风险收敛效果。",
            ],
            "novelty_bonus": 0.07,
        },
    ],
    "SC-03: Oracle Manipulation": [
        {
            "variant_id": "oracle_validity",
            "title": "Permissionless 市场中的 Oracle 有效性与价格合理性研究",
            "problem_statement": "无许可市场创建与 Oracle 接入结合时，协议往往缺少足够的有效性约束和价格合理性校验。",
            "hypothesis": "当协议允许无许可创建市场但不验证 Oracle 有效性时，系统性预言机利用面会反复出现。",
            "motivation": "历史案例已经反复证明，错误 Oracle 不是单点输入错误，而是协议设计的系统性风险。",
            "novelty": "把错误 Oracle 事故、市场创建权限和链上校验机制放到同一研究框架下。",
            "research_questions": [
                "哪些 Oracle 接入模式最容易形成系统性利用面？",
                "无许可市场创建如何放大错误 Oracle 的影响？",
                "有效性校验应该覆盖哪些最小条件？",
            ],
            "contributions": [
                "提出 Oracle 有效性最小校验框架。",
                "总结无许可市场与 Oracle 风险的耦合模式。",
                "形成更适合审计和监控联动的研究基线。",
            ],
            "risks": [
                "缺少真实链上价格操纵回放会削弱结论说服力。",
                "不同 Oracle 设计差异较大，统一抽象难度较高。",
            ],
            "experiments": [
                "收集无许可市场协议中的 Oracle 接入模式。",
                "在 fork 环境中验证错误 Oracle 对借贷约束的破坏程度。",
                "比较不同 Oracle 校验策略的安全性与可组合性。",
            ],
            "novelty_bonus": 0.08,
        },
        {
            "variant_id": "oracle_guardrail",
            "title": "DeFi Oracle 防护栏设计与误配置检测研究",
            "problem_statement": "很多系统知道要接 Oracle，但并不知道上线前应该验证哪些 guardrail，导致误配置难以及时发现。",
            "hypothesis": "如果把价格有效性、资产精度、市场权限和回退机制统一成 guardrail 模型，可以显著提升 Oracle 风险的可提前发现性。",
            "motivation": "真正高价值的不只是指出 Oracle 有问题，而是把误配置检测做成可前置执行的研究与审计方法。",
            "novelty": "把 Oracle 风险研究从事故解释推进到上线前 guardrail 设计。",
            "research_questions": [
                "上线前最关键的 Oracle guardrail 应该有哪些？",
                "哪些结构信号足以提前提示误配置风险？",
                "自动化 guardrail 与人工复核如何组合？",
            ],
            "contributions": [
                "形成一套可落地的 Oracle guardrail 清单。",
                "把误配置检测问题结构化。",
                "提升研究输出对工程落地的直接价值。",
            ],
            "risks": [
                "如果样本协议不足，guardrail 通用性会受限。",
                "上线策略差异会影响实验结果一致性。",
            ],
            "experiments": [
                "提取样本协议的 Oracle guardrail 现状。",
                "比较不同 guardrail 组合的风险覆盖率。",
                "分析 guardrail 缺失与历史事故之间的对应关系。",
            ],
            "novelty_bonus": 0.06,
        },
    ],
}

GENERIC_VARIANTS = [
    {
        "variant_id": "pattern",
        "title": "{protocol_name} 风险模式证据链研究",
        "problem_statement": "当前目标呈现出多条安全信号，但这些信号如何聚合为稳定研究问题仍缺少结构化抽象。",
        "hypothesis": "把当前审计发现、程序结构和历史案例对齐成证据链，可以产生稳定且可扩展的研究问题。",
        "motivation": "如果研究工作流不能解释为什么这个方向值得做，它就只能停留在自动摘要层。",
        "novelty": "把审计输出重新组织成研究级证据链。",
        "research_questions": [
            "哪些风险信号最值得提升为系统研究问题？",
            "当前目标的结构特征如何影响风险复发？",
            "如何把审计发现转化为可验证研究命题？",
        ],
        "contributions": [
            "提供一套从审计到研究的问题提升路径。",
            "沉淀证据链组织模板。",
            "增强研究工作流的可解释性。",
        ],
        "risks": [
            "研究主题可能过宽，需要后续进一步收敛。",
        ],
        "experiments": [
            "梳理当前目标的关键风险模式。",
            "构造证据链并检查每条主张的支撑强度。",
            "对比不同研究问题选择策略的质量差异。",
        ],
        "novelty_bonus": 0.04,
    }
]


def _stable_id(prefix: str, *parts: object) -> str:
    """生成稳定 ID。"""

    digest = hashlib.sha1("::".join(map(str, parts)).encode("utf-8")).hexdigest()[:16]
    return f"{prefix}_{digest}"


def _bounded_score(value: float) -> float:
    """约束分数到 0-0.99 区间并保留两位小数。"""

    return round(max(0.0, min(value, 0.99)), 2)


def _severity_weight(audit_result: AuditRunResult) -> float:
    """根据当前审计结果计算风险影响权重。"""

    summary = audit_result.audit_summary
    return (
        summary.critical_count * 1.0
        + summary.high_count * 0.75
        + summary.medium_count * 0.45
        + summary.low_count * 0.15
    )


def _relevant_findings(audit_result: AuditRunResult, category: str) -> list:
    """返回与目标类别最相关的 finding。"""

    findings = [
        finding
        for finding in audit_result.scan_report.findings
        if finding.category == category
    ]
    if findings:
        return findings[:5]
    return audit_result.audit_summary.top_findings[:5]


def _semantic_evidence_items(audit_result: AuditRunResult, category: str) -> list[ResearchEvidence]:
    """基于 AST / 深分析结果生成语义证据。"""

    ast_summary = audit_result.semantic_summary.ast_summary
    protocol_name = audit_result.classification.protocol_name
    evidence: list[ResearchEvidence] = []

    public_entrypoints = ast_summary.get("public_entrypoints", [])
    if public_entrypoints:
        evidence.append(
            ResearchEvidence(
                evidence_id=_stable_id("research_evidence", protocol_name, category, "entrypoints"),
                evidence_type="semantic",
                title="公开入口分布",
                summary=f"检测到 {len(public_entrypoints)} 个公开入口：{', '.join(public_entrypoints[:6])}",
                source_ref=f"{protocol_name}::ast.public_entrypoints",
                strength="moderate",
                reasoning="公开入口决定研究问题的攻击面边界，是后续验证和样本选择的起点。",
            )
        )

    write_after_external = ast_summary.get("write_after_external_functions", [])
    if write_after_external:
        evidence.append(
            ResearchEvidence(
                evidence_id=_stable_id("research_evidence", protocol_name, category, "write_after_external"),
                evidence_type="semantic",
                title="外部调用后写状态信号",
                summary="存在外部调用后写状态函数：" + "，".join(write_after_external[:6]),
                source_ref=f"{protocol_name}::ast.write_after_external",
                strength="strong" if category == "SC-01: Reentrancy" else "moderate",
                reasoning="这种结构信号会直接决定当前研究方向是否具备可验证的高风险路径。",
            )
        )

    cross_edges = ast_summary.get("cross_contract_call_edges", [])
    if cross_edges:
        formatted = "；".join(
            f"{edge['from_contract']}.{edge['from_function']} -> "
            f"{edge['target_contract']}.{edge['target_function']}"
            for edge in cross_edges[:4]
        )
        evidence.append(
            ResearchEvidence(
                evidence_id=_stable_id("research_evidence", protocol_name, category, "cross_edges"),
                evidence_type="semantic",
                title="跨合约调用边",
                summary=formatted,
                source_ref=f"{protocol_name}::ast.cross_contract_call_edges",
                strength="moderate",
                reasoning="跨合约调用边决定了研究是否需要跨模块、跨回调路径去分析利用前提。",
            )
        )

    state_conflicts = ast_summary.get("state_conflicts", [])
    if state_conflicts:
        formatted = "；".join(
            f"{item['state_variable']}:{item['from_function']}<->{item['to_function']}"
            for item in state_conflicts[:4]
        )
        evidence.append(
            ResearchEvidence(
                evidence_id=_stable_id("research_evidence", protocol_name, category, "state_conflicts"),
                evidence_type="semantic",
                title="共享状态冲突热点",
                summary=formatted,
                source_ref=f"{protocol_name}::ast.state_conflicts",
                strength="moderate",
                reasoning="共享状态冲突说明风险可能不是孤立函数问题，而是协议状态机层面的耦合问题。",
            )
        )

    incident_entities = ast_summary.get("incident_entities", [])
    if incident_entities:
        formatted = "；".join(
            f"{item.get('label', item.get('reference', ''))}:{item.get('role', 'actor')}"
            for item in incident_entities[:4]
        )
        evidence.append(
            ResearchEvidence(
                evidence_id=_stable_id("research_evidence", protocol_name, category, "incident_entities"),
                evidence_type="semantic",
                title="攻击关键实体结构",
                summary=formatted,
                source_ref=f"{protocol_name}::incident.entities",
                strength="moderate",
                reasoning="结构化攻击实体有助于把研究问题锚定到真实攻击者、受害方和关键组件。",
            )
        )

    incident_timeline = ast_summary.get("incident_timeline", [])
    if incident_timeline:
        formatted = "；".join(
            f"{item.get('title', '阶段')}:{item.get('description', '')}"
            for item in incident_timeline[:3]
        )
        evidence.append(
            ResearchEvidence(
                evidence_id=_stable_id("research_evidence", protocol_name, category, "incident_timeline"),
                evidence_type="semantic",
                title="攻击时间线结构",
                summary=formatted,
                source_ref=f"{protocol_name}::incident.timeline",
                strength="strong",
                reasoning="攻击时间线提供了从前置条件到利用结果的结构化因果链。",
            )
        )

    incident_verifications = ast_summary.get("incident_verifications", [])
    if incident_verifications:
        formatted = "；".join(
            f"{item.get('description', item.get('match_path', 'verification'))}:{item.get('summary', '')}"
            for item in incident_verifications[:3]
        )
        evidence.append(
            ResearchEvidence(
                evidence_id=_stable_id("research_evidence", protocol_name, category, "incident_verification"),
                evidence_type="semantic",
                title="本地 fork / PoC 验证结果",
                summary=formatted,
                source_ref=f"{protocol_name}::incident.verification",
                strength="strong",
                reasoning="通过的本地 fork / PoC 验证可以显著提高研究主张的可证实性。",
            )
        )

    incident_guardrails = ast_summary.get("incident_guardrails", [])
    if incident_guardrails:
        evidence.append(
            ResearchEvidence(
                evidence_id=_stable_id("research_evidence", protocol_name, category, "incident_guardrails"),
                evidence_type="semantic",
                title="最小校验条件结构",
                summary="；".join(str(item) for item in incident_guardrails[:6]),
                source_ref=f"{protocol_name}::incident.guardrails",
                strength="strong",
                reasoning="把最小校验条件显式列出，有助于将攻击复盘提升为可复用防护框架。",
            )
        )

    return evidence


def _incident_evidence_items(audit_result: AuditRunResult, category: str) -> list[ResearchEvidence]:
    """把历史案例命中转成研究证据。"""

    evidence: list[ResearchEvidence] = []
    related_incidents = [
        match
        for match in audit_result.related_incidents
        if category in match.incident.affected_categories
    ]
    if not related_incidents:
        related_incidents = audit_result.related_incidents[:2]

    for match in related_incidents[:2]:
        incident = match.incident
        evidence_package = build_incident_evidence_package(incident)
        evidence.append(
            ResearchEvidence(
                evidence_id=_stable_id("research_evidence", incident.incident_id, category, "incident"),
                evidence_type="incident",
                title=incident.title,
                summary="；".join(evidence_package.evidence_summary[:3]),
                source_ref=incident.incident_id,
                strength="strong" if match.score >= 6 else "moderate",
                reasoning="历史案例说明该类风险不是理论猜想，而是已有可参照的真实攻击或故障模式。",
            )
        )
        if evidence_package.attack_transactions and all(
            tx.indexed for tx in evidence_package.attack_transactions
        ):
            lead_tx = evidence_package.attack_transactions[0]
            evidence.append(
                ResearchEvidence(
                    evidence_id=_stable_id(
                        "research_evidence",
                        incident.incident_id,
                        category,
                        "incident_tx",
                    ),
                    evidence_type="incident_trace",
                    title=f"{incident.title} 链上锚点",
                    summary=(
                        f"{lead_tx.label}: {lead_tx.tx_hash}；"
                        f"selector={lead_tx.selector_name or lead_tx.selector or 'unknown'}；"
                        f"status={lead_tx.status}"
                    ),
                    source_ref=lead_tx.tx_hash,
                    strength="strong",
                    reasoning="攻击交易哈希为研究主张提供了更强的链上可追溯锚点。",
                )
            )
    return evidence


def _finding_evidence_items(audit_result: AuditRunResult, category: str) -> list[ResearchEvidence]:
    """把当前目标中的 finding 转成研究证据。"""

    evidence: list[ResearchEvidence] = []
    for finding in _relevant_findings(audit_result, category)[:3]:
        location = f"{finding.affected_scope.file_path}:{finding.affected_scope.line_start}"
        evidence.append(
            ResearchEvidence(
                evidence_id=_stable_id("research_evidence", finding.finding_id, category, "finding"),
                evidence_type="finding",
                title=finding.title,
                summary=finding.description,
                source_ref=location,
                strength="strong" if finding.severity in {"Critical", "High"} else "moderate",
                reasoning=(
                    "这是当前目标上最直接的本地证据，决定研究问题是否具备现实落点。"
                ),
            )
        )
    return evidence


def _build_key_observations(
    audit_result: AuditRunResult,
    category: str,
    evidence_chain: list[ResearchEvidence],
) -> list[str]:
    """根据上下文生成关键观察。"""

    summary = audit_result.audit_summary
    semantic_summary = audit_result.semantic_summary
    observations = [
        (
            f"当前目标 `{audit_result.classification.protocol_name}` "
            f"属于 `{audit_result.classification.protocol_type}` 协议，"
            f"总 finding 数为 {summary.total_findings}，其中高危及以上 {summary.high_count + summary.critical_count} 个。"
        ),
        (
            f"程序结构层检测到 {semantic_summary.function_count} 个函数、"
            f"{semantic_summary.sensitive_function_count} 个敏感函数、"
            f"{semantic_summary.external_call_count} 处外部调用。"
        ),
    ]
    if category == "SC-01: Reentrancy":
        observations.append("重入相关研究不能只看函数名，必须结合外部调用顺序、共享状态冲突和跨合约边。")
    if category == "SC-02: Access Control":
        observations.append("访问控制研究真正困难的地方在于区分“本应开放”和“边界设计缺失”，需要结合协议语义。")
    if category == "SC-03: Oracle Manipulation":
        observations.append("预言机研究的价值不在于证明价格会错，而在于说明哪些 guardrail 缺失会让错误价格形成系统性后果。")
    observations.extend(
        f"证据链纳入了 `{item.title}`，说明研究主张可以落到具体源码、结构信号或历史事故上。"
        for item in evidence_chain[:2]
    )
    return observations[:6]


def _score_idea(
    *,
    audit_result: AuditRunResult,
    category: str,
    evidence_chain: list[ResearchEvidence],
    novelty_bonus: float,
) -> tuple[float, float, float, float]:
    """为候选研究方向打分。"""

    finding_count = sum(1 for item in evidence_chain if item.evidence_type == "finding")
    incident_count = sum(1 for item in evidence_chain if item.evidence_type == "incident")
    semantic_count = sum(1 for item in evidence_chain if item.evidence_type == "semantic")

    evidence_score = _bounded_score(
        0.34 + 0.12 * finding_count + 0.1 * incident_count + 0.06 * semantic_count
    )
    feasibility_score = _bounded_score(
        0.42
        + 0.11 * min(incident_count, 2)
        + 0.08 * min(semantic_count, 3)
        + 0.06 * min(finding_count, 3)
        + 0.03 * (1 if audit_result.ingestion.solidity_file_count > 1 else 0)
    )
    impact_score = _bounded_score(
        0.4
        + 0.08 * min(_severity_weight(audit_result), 4.0)
        + 0.05 * (1 if category in {"SC-01: Reentrancy", "SC-03: Oracle Manipulation"} else 0)
    )

    ast_summary = audit_result.semantic_summary.ast_summary
    structural_bonus = 0.02 * (
        bool(ast_summary.get("cross_contract_call_edges"))
        + bool(ast_summary.get("write_after_external_functions"))
        + bool(ast_summary.get("state_conflicts"))
    )
    novelty_score = _bounded_score(
        0.46 + novelty_bonus + structural_bonus + 0.03 * min(incident_count, 2)
    )
    composite_score = _bounded_score(
        evidence_score * 0.3
        + feasibility_score * 0.25
        + impact_score * 0.25
        + novelty_score * 0.2
    )
    return evidence_score, feasibility_score, impact_score, composite_score


def _confidence_label(evidence_score: float, impact_score: float) -> str:
    """根据分数生成研究置信度。"""

    if evidence_score >= 0.78 and impact_score >= 0.7:
        return "high"
    if evidence_score >= 0.58:
        return "medium"
    return "low"


def _build_selection_reason(
    title: str,
    evidence_score: float,
    feasibility_score: float,
    composite_score: float,
    rank: int,
) -> tuple[str, str]:
    """生成候选方向的去留说明。"""

    if rank == 0:
        reason = (
            f"选择 `{title}` 作为主线，因为它在证据强度、可执行性和综合得分上都最稳定"
            f"（综合 {composite_score}，证据 {evidence_score}，可执行性 {feasibility_score}）。"
        )
        return "selected", reason

    reason = (
        f"`{title}` 保留为备选方向。它仍有研究价值，但综合得分 {composite_score} "
        f"略低于主线，更适合作为对照研究或第二阶段延展。"
    )
    return "backup", reason


def _build_variants(category: str) -> list[dict[str, object]]:
    """返回类别对应的候选方向模板。"""

    return CATEGORY_VARIANTS.get(category, GENERIC_VARIANTS)


def _build_category_contexts(audit_result: AuditRunResult) -> list[dict[str, Any]]:
    """为 AI 和规则回退共同构造类别上下文。"""

    category_counter = Counter(
        finding.category for finding in audit_result.scan_report.findings if finding.category
    )
    categories = [category for category, _count in category_counter.most_common()]
    if not categories:
        categories = ["generic"]

    contexts: list[dict[str, Any]] = []
    for category in categories[:3]:
        evidence_chain = (
            _finding_evidence_items(audit_result, category)
            + _semantic_evidence_items(audit_result, category)
            + _incident_evidence_items(audit_result, category)
        )
        contexts.append(
            {
                "category": category,
                "evidence_chain": evidence_chain,
                "key_observations": _build_key_observations(audit_result, category, evidence_chain),
                "related_incident_ids": [
                    evidence.source_ref
                    for evidence in evidence_chain
                    if evidence.evidence_type == "incident"
                ][:4],
                "related_work_summary": [
                    f"{evidence.title}: {evidence.summary}"
                    for evidence in evidence_chain
                    if evidence.evidence_type in {"incident", "semantic"}
                ][:5],
                "supporting_evidence": [
                    f"{evidence.title} @ {evidence.source_ref}"
                    for evidence in evidence_chain[:6]
                ],
            }
        )
    return contexts


def _build_ai_candidate_system_prompt() -> str:
    """返回 AI 方向生成系统提示词。"""

    return (
        "你是 DeFi 安全研究 agent。你的任务不是润色既有答案，而是基于给定证据包生成候选研究方向。"
        "你只能使用给定协议上下文、结构化证据和历史案例，不允许补充外部事实。"
        "输出必须是 JSON。"
    )


def _build_ai_candidate_user_prompt(
    audit_result: AuditRunResult,
    contexts: list[dict[str, Any]],
    limit: int,
) -> str:
    """构造 AI 候选方向生成提示词。"""

    protocol_name = audit_result.classification.protocol_name
    protocol_type = audit_result.classification.protocol_type
    blocks = []
    for context in contexts:
        blocks.append(
            "\n".join(
                [
                    f"category: {context['category']}",
                    "key_observations:",
                    "\n".join(f"- {item}" for item in context["key_observations"][:3]) or "- 暂无",
                    "evidence_chain:",
                    "\n".join(
                        f"- {evidence.evidence_id} | {evidence.evidence_type} | {evidence.title} | "
                        f"{evidence.summary} | {evidence.strength}"
                        for evidence in context["evidence_chain"][:5]
                    ) or "- 暂无",
                ]
            )
        )

    return "\n\n".join(
        [
            "请基于以下证据包，生成最多 3 个候选研究方向。",
            "",
            f"- protocol_name: {protocol_name}",
            f"- protocol_type: {protocol_type}",
            f"- total_findings: {audit_result.audit_summary.total_findings}",
            f"- high_or_critical: {audit_result.audit_summary.high_count + audit_result.audit_summary.critical_count}",
            "",
            "类别上下文：",
            "\n\n---\n\n".join(blocks),
            "",
            "返回 JSON：",
            "{",
            '  "candidates": [',
            "    {",
            '      "title": "研究标题",',
            '      "focus_category": "必须来自给定 category，或 generic",',
            '      "problem_statement": "问题定义",',
            '      "hypothesis": "核心假设",',
            '      "motivation": "研究动机",',
            '      "novelty_rationale": "新颖性说明",',
            '      "research_questions": ["最多 3 条"],',
            '      "expected_contributions": ["最多 3 条"],',
            '      "risks": ["最多 3 条"],',
            '      "proposed_experiments": ["最多 3 条"],',
            '      "used_evidence_ids": ["必须来自给定 evidence_id，最多 5 个"]',
            "    }",
            "  ]",
            "}",
        ]
    )


def _normalize_text_list(value: Any, limit: int) -> list[str]:
    """规范化字符串列表。"""

    if not isinstance(value, list):
        return []
    results: list[str] = []
    for item in value:
        text = str(item).strip()
        if text:
            results.append(text)
    return results[:limit]


def _generate_research_ideas_with_llm(
    audit_result: AuditRunResult,
    contexts: list[dict[str, Any]],
    limit: int,
    *,
    settings: ProjectSettings | None = None,
    client: OpenAiCompatibleLlmClient | None = None,
) -> list[ResearchIdea]:
    """让 AI 基于证据包主导生成候选研究方向。"""

    resolved_settings = settings or ProjectSettings.from_env()
    if not resolved_settings.research_llm_available:
        return []

    llm_client = client or OpenAiCompatibleLlmClient(resolved_settings)
    response = llm_client.complete_json(
        system_prompt=_build_ai_candidate_system_prompt(),
        user_prompt=_build_ai_candidate_user_prompt(audit_result, contexts, limit),
    )
    candidates = response.content.get("candidates")
    if not isinstance(candidates, list):
        return []

    context_map = {context["category"]: context for context in contexts}
    allowed_categories = set(context_map) | {"generic"}
    protocol_name = audit_result.classification.protocol_name
    protocol_type = audit_result.classification.protocol_type
    ideas: list[ResearchIdea] = []
    for raw in candidates[:limit]:
        if not isinstance(raw, dict):
            continue
        title = str(raw.get("title", "")).strip()
        problem_statement = str(raw.get("problem_statement", "")).strip()
        hypothesis = str(raw.get("hypothesis", "")).strip()
        motivation = str(raw.get("motivation", "")).strip()
        novelty_rationale = str(raw.get("novelty_rationale", "")).strip()
        focus_category = str(raw.get("focus_category", "")).strip() or contexts[0]["category"]
        if focus_category not in allowed_categories:
            focus_category = contexts[0]["category"]
        if not title or not problem_statement or not hypothesis:
            continue

        context = context_map.get(focus_category, contexts[0])
        evidence_map = {item.evidence_id: item for item in context["evidence_chain"]}
        used_evidence_ids = [
            evidence_id
            for evidence_id in _normalize_text_list(raw.get("used_evidence_ids"), limit=5)
            if evidence_id in evidence_map
        ]
        chosen_evidence = (
            [evidence_map[evidence_id] for evidence_id in used_evidence_ids]
            if used_evidence_ids
            else context["evidence_chain"]
        )
        related_incident_ids = [
            evidence.source_ref
            for evidence in chosen_evidence
            if evidence.evidence_type == "incident"
        ][:4]
        related_work_summary = [
            f"{evidence.title}: {evidence.summary}"
            for evidence in chosen_evidence
            if evidence.evidence_type in {"incident", "semantic"}
        ][:5]
        supporting_evidence = [
            f"{evidence.title} @ {evidence.source_ref}"
            for evidence in chosen_evidence[:6]
        ]
        evidence_score, feasibility_score, impact_score, composite_score = _score_idea(
            audit_result=audit_result,
            category=focus_category,
            evidence_chain=chosen_evidence,
            novelty_bonus=0.08,
        )
        ideas.append(
            ResearchIdea(
                idea_id=_stable_id("idea", focus_category, title, hypothesis),
                title=title,
                focus_category=focus_category,
                hypothesis=hypothesis,
                motivation=motivation or (
                    f"当前目标 `{protocol_name}` 属于 `{protocol_type}`，该方向由 AI 基于本地证据包生成。"
                ),
                novelty_rationale=novelty_rationale or "AI 基于本地证据包识别出的方向差异点。",
                confidence=_confidence_label(evidence_score, impact_score),
                novelty_score=_bounded_score(0.5 + 0.03 * len(related_incident_ids)),
                related_incident_ids=related_incident_ids,
                related_work_summary=related_work_summary,
                supporting_evidence=supporting_evidence,
                proposed_experiments=_normalize_text_list(raw.get("proposed_experiments"), limit=3),
                problem_statement=problem_statement,
                research_questions=_normalize_text_list(raw.get("research_questions"), limit=3),
                key_observations=context["key_observations"][:3],
                expected_contributions=_normalize_text_list(raw.get("expected_contributions"), limit=3),
                risks=_normalize_text_list(raw.get("risks"), limit=3),
                evidence_chain=chosen_evidence,
                evidence_score=evidence_score,
                feasibility_score=feasibility_score,
                impact_score=impact_score,
                composite_score=composite_score,
            )
        )
    return ideas


def _rank_research_ideas(ideas: list[ResearchIdea], limit: int) -> list[ResearchIdea]:
    """统一排序并补充去留说明。"""

    ideas.sort(
        key=lambda idea: (
            -idea.composite_score,
            -idea.evidence_score,
            -idea.feasibility_score,
            idea.title,
        )
    )

    ranked_ideas: list[ResearchIdea] = []
    for index, idea in enumerate(ideas[:limit]):
        decision_status, selection_reason = _build_selection_reason(
            idea.title,
            idea.evidence_score,
            idea.feasibility_score,
            idea.composite_score,
            index,
        )
        ranked_ideas.append(
            ResearchIdea(
                idea_id=idea.idea_id,
                title=idea.title,
                focus_category=idea.focus_category,
                hypothesis=idea.hypothesis,
                motivation=idea.motivation,
                novelty_rationale=idea.novelty_rationale,
                confidence=idea.confidence,
                novelty_score=idea.novelty_score,
                related_incident_ids=idea.related_incident_ids,
                related_work_summary=idea.related_work_summary,
                supporting_evidence=idea.supporting_evidence,
                proposed_experiments=idea.proposed_experiments,
                problem_statement=idea.problem_statement,
                research_questions=idea.research_questions,
                key_observations=idea.key_observations,
                expected_contributions=idea.expected_contributions,
                risks=idea.risks,
                evidence_chain=idea.evidence_chain,
                evidence_score=idea.evidence_score,
                feasibility_score=idea.feasibility_score,
                impact_score=idea.impact_score,
                composite_score=idea.composite_score,
                decision_status=decision_status,
                selection_reason=selection_reason,
            )
        )
    return ranked_ideas


def _generate_research_ideas_from_templates(
    audit_result: AuditRunResult,
    contexts: list[dict[str, Any]],
    limit: int,
) -> list[ResearchIdea]:
    """规则回退版本的候选方向生成。"""

    protocol_name = audit_result.classification.protocol_name
    protocol_type = audit_result.classification.protocol_type
    ideas: list[ResearchIdea] = []

    for context in contexts:
        category = context["category"]
        evidence_chain = context["evidence_chain"]
        related_incident_ids = context["related_incident_ids"]
        related_work_summary = context["related_work_summary"]
        supporting_evidence = context["supporting_evidence"]
        key_observations = context["key_observations"]

        for variant in _build_variants(category):
            title = str(variant["title"]).format(
                protocol_name=protocol_name,
                protocol_type=protocol_type,
            )
            problem_statement = str(variant["problem_statement"]).format(
                protocol_name=protocol_name,
                protocol_type=protocol_type,
            )
            hypothesis = str(variant["hypothesis"]).format(
                protocol_name=protocol_name,
                protocol_type=protocol_type,
            )
            motivation = str(variant["motivation"]).format(
                protocol_name=protocol_name,
                protocol_type=protocol_type,
            )
            novelty_rationale = str(variant["novelty"]).format(
                protocol_name=protocol_name,
                protocol_type=protocol_type,
            )
            research_questions = [
                str(question).format(
                    protocol_name=protocol_name,
                    protocol_type=protocol_type,
                )
                for question in list(variant["research_questions"])
            ]
            contributions = [
                str(item).format(
                    protocol_name=protocol_name,
                    protocol_type=protocol_type,
                )
                for item in list(variant["contributions"])
            ]
            risks = [
                str(item).format(
                    protocol_name=protocol_name,
                    protocol_type=protocol_type,
                )
                for item in list(variant["risks"])
            ]
            experiments = [
                str(item).format(
                    protocol_name=protocol_name,
                    protocol_type=protocol_type,
                )
                for item in list(variant["experiments"])
            ]
            evidence_score, feasibility_score, impact_score, composite_score = _score_idea(
                audit_result=audit_result,
                category=category,
                evidence_chain=evidence_chain,
                novelty_bonus=float(variant.get("novelty_bonus", 0.0)),
            )
            ideas.append(
                ResearchIdea(
                    idea_id=_stable_id("idea", category, variant["variant_id"], title),
                    title=title,
                    focus_category=category,
                    hypothesis=hypothesis,
                    motivation=motivation,
                    novelty_rationale=novelty_rationale,
                    confidence=_confidence_label(evidence_score, impact_score),
                    novelty_score=_bounded_score(
                        0.46
                        + float(variant.get("novelty_bonus", 0.0))
                        + 0.03 * len(related_incident_ids)
                    ),
                    related_incident_ids=related_incident_ids[:4],
                    related_work_summary=related_work_summary,
                    supporting_evidence=supporting_evidence,
                    proposed_experiments=experiments,
                    problem_statement=problem_statement,
                    research_questions=research_questions,
                    key_observations=key_observations,
                    expected_contributions=contributions,
                    risks=risks,
                    evidence_chain=evidence_chain,
                    evidence_score=evidence_score,
                    feasibility_score=feasibility_score,
                    impact_score=impact_score,
                    composite_score=composite_score,
                )
            )
    return _rank_research_ideas(ideas, limit)


def generate_research_ideas(
    audit_result: AuditRunResult,
    limit: int = 5,
    *,
    settings: ProjectSettings | None = None,
    client: OpenAiCompatibleLlmClient | None = None,
) -> list[ResearchIdea]:
    """根据审计结果和历史案例生成研究想法。"""

    resolved_settings = settings or ProjectSettings.from_env()
    contexts = _build_category_contexts(audit_result)
    template_ideas = _generate_research_ideas_from_templates(audit_result, contexts, limit)

    if not resolved_settings.research_llm_available:
        return template_ideas

    ai_ideas = _generate_research_ideas_with_llm(
        audit_result,
        contexts,
        limit,
        settings=resolved_settings,
        client=client,
    )
    if not ai_ideas:
        raise ValueError("研究 LLM 已启用，但未生成可用候选方向。")

    combined: list[ResearchIdea] = []
    seen_ids: set[str] = set()
    for idea in ai_ideas + template_ideas:
        if idea.idea_id in seen_ids:
            continue
        seen_ids.add(idea.idea_id)
        combined.append(idea)

    return _rank_research_ideas(combined, limit)
