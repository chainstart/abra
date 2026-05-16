"""实验计划生成器。"""

from __future__ import annotations

import hashlib

from services.analysis.models import AuditRunResult
from services.research.models import ExperimentDesign, ExperimentPlan, ResearchIdea


def _stable_design_id(title: str, objective: str) -> str:
    """生成稳定实验设计 ID。"""

    digest = hashlib.sha1(f"{title}::{objective}".encode("utf-8")).hexdigest()[:12]
    return f"exp_{digest}"


def _aggregate_unique(items: list[list[str]]) -> list[str]:
    """合并去重并保持顺序。"""

    merged: list[str] = []
    for group in items:
        for item in group:
            if item not in merged:
                merged.append(item)
    return merged


def build_experiment_plan(
    research_idea: ResearchIdea,
    audit_result: AuditRunResult,
) -> ExperimentPlan:
    """根据研究想法生成结构化实验计划。"""

    protocol_name = audit_result.classification.protocol_name
    protocol_type = audit_result.classification.protocol_type
    top_findings = audit_result.audit_summary.top_findings
    evidence_chain = research_idea.evidence_chain or []

    core_datasets = [
        f"当前目标协议: {protocol_name} ({protocol_type})",
        "本地历史攻击案例库",
        "本地审计报告集合",
    ]
    if top_findings:
        core_datasets.append("高风险 finding 样本")
    if evidence_chain:
        core_datasets.append("研究证据链快照")

    metrics = [
        "研究主张覆盖率",
        "证据链完整度",
        "动态验证成功率",
        "误报率 / 漏报率",
        "引用支撑强度",
    ]
    baselines = [
        "仅使用规则扫描器输出",
        "不接入历史案例的研究想法生成结果",
        "不接入 AST 深分析的审计结果",
    ]

    designs = [
        ExperimentDesign(
            design_id=_stable_design_id("结构信号普查", research_idea.hypothesis),
            title="结构信号普查",
            objective="统计当前研究方向涉及的结构信号在目标协议和本地样本中的出现情况。",
            datasets=core_datasets[:],
            baselines=[
                "仅统计函数名和规则命中结果",
                "忽略跨合约边与共享状态冲突的统计版本",
            ],
            metrics=[
                "结构信号覆盖率",
                "高风险路径命中率",
                "信号与历史案例重合度",
            ],
            procedures=[
                "抽取当前目标中的相关 finding、公开入口、跨合约边和状态冲突。",
                "按协议类型整理本地案例与历史审计报告中的相似信号。",
                "形成结构信号分布表和可疑热点清单。",
            ],
            success_criteria=[
                "至少形成一份结构信号分布表。",
                "能够指出 2 条以上值得深挖的高风险路径。",
            ],
            failure_criteria=[
                "结构信号无法稳定对应到具体研究主张。",
                "输出仍停留在笼统统计，无法指导下一步验证。",
            ],
            deliverables=[
                "结构信号分布表",
                "高风险路径清单",
                "候选验证队列",
            ],
        ),
        ExperimentDesign(
            design_id=_stable_design_id("动态验证与反证", research_idea.problem_statement),
            title="动态验证与反证",
            objective="把高价值研究主张推进到可验证或可反驳状态，避免停留在纸面猜想。",
            datasets=core_datasets[:] + ["Fork / PoC 验证输入"],
            baselines=[
                "只做静态判断、不进入动态验证",
                "不使用历史案例缩小验证范围",
            ],
            metrics=[
                "PoC 成功率",
                "可反证主张占比",
                "验证成本",
            ],
            procedures=[
                "挑选 1-3 条高价值研究主张进入验证队列。",
                "为每条主张明确利用前提、必要输入和失败条件。",
                "为每条主张补写 counterfactual / failure-path 记录，并明确哪些防护条件一旦成立就应阻断路径。",
                "记录验证成功、失败和不确定三类结果。",
            ],
            success_criteria=[
                "至少有一条主张被推进到可验证状态。",
                "每条主张都有明确的失败条件和回退解释。",
            ],
            failure_criteria=[
                "无法明确验证前提，导致实验不可执行。",
                "验证记录不能区分“未验证”和“已被反证”。",
            ],
            deliverables=[
                "验证日志",
                "主张状态表",
                "PoC / fork 输入清单",
            ],
        ),
        ExperimentDesign(
            design_id=_stable_design_id("方法与防御对照", research_idea.title),
            title="方法与防御对照",
            objective="比较不同分析方法或防御策略对当前研究问题的支撑效果。",
            datasets=core_datasets[:],
            baselines=baselines[:],
            metrics=[
                "研究主张稳定性",
                "高价值方向排序一致性",
                "修复或防御建议可执行性",
            ],
            procedures=[
                "比较是否引入 AST 深分析、历史案例和验证信息对研究排序的影响。",
                "对研究主张对应的修复或防御策略做收益与成本对照。",
                "总结哪些输入最能提升研究输出质量。",
            ],
            success_criteria=[
                "能够说明为什么当前主线优于备选方向。",
                "能够给出至少一套明确的工程落地建议。",
            ],
            failure_criteria=[
                "主线与备选方向差异不清晰。",
                "无法把研究产出转回工程动作或评测动作。",
            ],
            deliverables=[
                "主线 / 备选方向对照表",
                "方法输入收益分析",
                "防御建议清单",
            ],
        ),
    ]

    procedures = _aggregate_unique([design.procedures for design in designs])
    expected_artifacts = _aggregate_unique([design.deliverables for design in designs]) + [
        "研究备忘录 Markdown",
        "论文初稿 Markdown",
    ]

    execution_timeline = [
        "阶段 1：整理证据链，确定主线与备选方向。",
        "阶段 2：完成结构信号普查与案例对照。",
        "阶段 3：对主线问题做动态验证与反证。",
        "阶段 4：汇总方法对照、实验结论和论文产物。",
    ]

    open_risks = list(research_idea.risks or [])
    if not audit_result.related_incidents:
        open_risks.append("当前缺少足够多的历史案例支撑，研究结论外推能力有限。")
    if not top_findings:
        open_risks.append("当前缺少高价值 finding，研究问题可能过于依赖结构信号推断。")

    return ExperimentPlan(
        title=f"{research_idea.title} 实验计划",
        objective=research_idea.hypothesis,
        hypotheses=[research_idea.hypothesis] + list(research_idea.research_questions or []),
        datasets=core_datasets,
        metrics=metrics,
        baselines=baselines,
        procedures=procedures,
        expected_artifacts=expected_artifacts,
        designs=designs,
        execution_timeline=execution_timeline,
        open_risks=open_risks,
    )
