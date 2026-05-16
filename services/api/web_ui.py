"""Web 页面渲染。

服务端只负责：

- 组织结果页的数据块
- 对动态内容做转义
- 把内容填入外部模板

样式和首页交互脚本放在 `services/api/static/`，
首页壳子模板放在 `services/api/templates/`。
"""

from __future__ import annotations

from html import escape

from services.api.ui_assets import asset_url, render_template
from services.research.review_views import build_peer_review_views


def _render_layout(
    *,
    title: str,
    content: str,
    body_class: str,
    script_tags: str = "",
    extra_head: str = "",
) -> str:
    """渲染统一布局。"""

    return render_template(
        "layout.html",
        title=escape(title),
        stylesheet_href=asset_url("app.css"),
        body_class=escape(body_class),
        content=content,
        script_tags=script_tags,
        extra_head=extra_head,
    )


def _severity_class(severity: str) -> str:
    """把严重性映射到展示样式。"""

    lower = (severity or "").lower()
    if "critical" in lower:
        return "sev-critical"
    if "high" in lower:
        return "sev-high"
    if "medium" in lower:
        return "sev-medium"
    if "low" in lower:
        return "sev-low"
    return "sev-info"


def _severity_badge(severity: str, label: str) -> str:
    """渲染严重性徽章。"""

    css_class = _severity_class(severity)
    return f'<span class="badge {css_class}">{escape(label)}</span>'


def _plain_badge(label: str) -> str:
    """渲染普通徽章。"""

    return f'<span class="badge plain">{escape(label)}</span>'


def _metric(label: str, value: object) -> str:
    """渲染指标卡片。"""

    return (
        f'<div class="metric"><strong>{escape(str(value))}</strong>'
        f"<span>{escape(label)}</span></div>"
    )


def _button_link(label: str, href: str) -> str:
    """渲染按钮样式链接。"""

    return (
        f'<a class="button-link secondary" href="{escape(href)}">'
        f"{escape(label)}</a>"
    )


def _download_link(label: str, href: str) -> str:
    """渲染下载按钮链接。"""

    return (
        f'<a class="button-link secondary" href="{escape(href)}" download>'
        f"{escape(label)}</a>"
    )


def _render_simple_cards(items: list[str]) -> str:
    """渲染简单文本卡片列表。"""

    if not items:
        return '<div class="muted">暂无内容。</div>'
    return "".join(
        f'<div class="artifact-item"><p>{escape(item)}</p></div>'
        for item in items
    )


def _render_file_links(task_id: str, files: list[str]) -> str:
    """渲染工件文件列表。"""

    links = [
        (
            f'<li><a href="/api/v1/artifacts/{escape(task_id)}/file/{escape(file_name)}" '
            f'target="_blank">{escape(file_name)}</a></li>'
        )
        for file_name in files
        if file_name != "task_result.json"
    ]
    if not links:
        return "<li>暂无工件文件</li>"
    return "".join(links)


def _render_semantic_summary(semantic: dict) -> str:
    """渲染审计语义摘要。"""

    cross_edges = "；".join(
        f"{edge['from_contract']}.{edge['from_function']} -> "
        f"{edge['target_contract']}.{edge['target_function']}"
        for edge in semantic.get("cross_contract_call_edges", [])
    )
    state_conflicts = "；".join(
        f"{item['state_variable']}:{item['from_function']}<->{item['to_function']}"
        for item in semantic.get("state_conflicts", [])
    )
    cards = [
        ("公开入口", "，".join(semantic.get("public_entrypoints", [])) or "暂无"),
        (
            "外部调用后写状态",
            "，".join(semantic.get("write_after_external_functions", [])) or "暂无",
        ),
        ("跨合约调用边", cross_edges or "暂无"),
        ("状态冲突", state_conflicts or "暂无"),
    ]
    return "".join(
        f'<div class="artifact-item"><h4>{escape(name)}</h4><p>{escape(value)}</p></div>'
        for name, value in cards
    )


def render_home_page() -> str:
    """渲染首页 HTML。"""

    return _render_layout(
        title="DeFi Security Agent MVP",
        content=render_template("home.html"),
        body_class="page-home",
        script_tags=f'<script src="{escape(asset_url("home.js"))}" defer></script>',
    )


def render_audit_detail_page(task_id: str, task_result: dict, files: list[str]) -> str:
    """渲染独立审计详情页。"""

    payload = task_result.get("payload", {})
    presentation = payload.get("audit_presentation", {})
    markdown_report = payload.get("markdown_report", "")

    metrics = presentation.get("metrics", {})
    top_findings = presentation.get("top_findings", [])
    grouped_families = presentation.get("grouped_families", {})
    related_incidents = presentation.get("related_incidents", [])
    action_items = presentation.get("action_items", [])
    category_counts = presentation.get("category_counts", {})
    analyzer_counts = presentation.get("analyzer_counts", {})
    semantic = presentation.get("semantic_highlights", {})

    top_finding_html = "".join(
        f"""
        <div class="artifact-item">
          <h3>{index + 1}. {escape(item.get("title_zh", ""))}</h3>
          <div class="toolbar">
            {_severity_badge(item.get("severity", ""), item.get("severity_zh", item.get("severity", "")))}
            {_plain_badge(item.get("priority_zh", "未标记"))}
            {_plain_badge(item.get("confidence_zh", "未知"))}
          </div>
          <p><strong>位置：</strong>{escape(item.get("location", "暂无"))}</p>
          <p><strong>问题说明：</strong>{escape(item.get("summary_zh", "暂无"))}</p>
          <p><strong>潜在影响：</strong>{escape(item.get("impact_zh", "暂无"))}</p>
          <p><strong>证据摘要：</strong>{escape(item.get("evidence_preview", "暂无"))}</p>
          <p><strong>修复建议：</strong>{escape(item.get("recommendation_zh", "暂无"))}</p>
          <p><strong>下一步验证：</strong>{escape(item.get("validation_next_step", "暂无"))}</p>
        </div>
        """
        for index, item in enumerate(top_findings)
    ) or '<div class="muted">暂无重点问题。</div>'

    grouped_html = "".join(
        f"""
        <details class="artifact-item">
          <summary>{escape(severity)}（{len(items)} 类问题）</summary>
          <div class="list section-gap-sm">
            {''.join(
                f'''
                <div class="artifact-item">
                  <h4>{escape(item.get("title_zh", ""))}</h4>
                  <div class="toolbar">
                    {_severity_badge(item.get("severity", ""), item.get("severity_zh", item.get("severity", "")))}
                    {_plain_badge(item.get("priority_zh", "未标记"))}
                    {_plain_badge(item.get("confidence_zh", "未知"))}
                  </div>
                  <p><strong>类别：</strong>{escape(item.get("category_zh", "未分类"))}</p>
                  <p><strong>出现次数：</strong>{escape(str(item.get("count", 0)))}</p>
                  <p><strong>样例位置：</strong>{escape("；".join(item.get("sample_locations", [])))}</p>
                  <p><strong>问题说明：</strong>{escape((item.get("sample_summaries") or ["暂无"])[0])}</p>
                </div>
                '''
                for item in items
            )}
          </div>
        </details>
        """
        for severity, items in grouped_families.items()
        if items
    ) or '<div class="muted">暂无更多发现。</div>'

    related_html = "".join(
        f"""
        <div class="artifact-item">
          <h4>{escape(item.get("title", ""))}</h4>
          <p><strong>协议：</strong>{escape(item.get("protocol_name", ""))}</p>
          <p><strong>年份：</strong>{escape(str(item.get("year", "")))}</p>
          <p><strong>摘要：</strong>{escape(item.get("summary", ""))}</p>
          <p><strong>匹配理由：</strong>{escape("；".join(item.get("reasons", [])))}</p>
        </div>
        """
        for item in related_incidents
    ) or '<div class="muted">暂无相似历史案例。</div>'

    category_html = "".join(
        f'<div class="artifact-item"><h4>{escape(name)}</h4><p>数量: {count}</p></div>'
        for name, count in list(category_counts.items())[:10]
    ) or '<div class="muted">暂无分类统计。</div>'

    analyzer_html = "".join(
        f'<div class="artifact-item"><h4>{escape(name)}</h4><p>数量: {count}</p></div>'
        for name, count in list(analyzer_counts.items())[:10]
    ) or '<div class="muted">暂无分析器统计。</div>'

    content = f"""
    <main class="wrap">
      <section class="card page-header">
        <div>
          <p class="eyebrow">审计详情页</p>
          <h1>{escape(presentation.get("protocol_name", task_id))}</h1>
          <p>{escape(presentation.get("conclusion", "暂无结论。"))}</p>
          <p class="muted">任务 ID: {escape(task_id)}</p>
        </div>
        <div class="toolbar">
          {_plain_badge(presentation.get("protocol_type", "未知类型"))}
          {_plain_badge(presentation.get("risk_temperature", "未知风险"))}
          {_download_link("下载审计包", f"/api/v1/artifacts/{task_id}/generated/audit_bundle.zip")}
          {_download_link("下载审计报告", f"/api/v1/artifacts/{task_id}/generated/audit_report.md")}
          {_button_link("返回首页", "/")}
        </div>
      </section>

      <section class="card section-gap">
        <h2>总体风险</h2>
        <div class="metric-grid">
          {_metric("总发现数", metrics.get("total_findings", 0))}
          {_metric("高优先级问题", metrics.get("high_count", 0) + metrics.get("critical_count", 0))}
          {_metric("风险温度", presentation.get("risk_temperature", "未知"))}
          {_metric("中风险", metrics.get("medium_count", 0))}
          {_metric("低风险", metrics.get("low_count", 0))}
          {_metric("提示项", metrics.get("informational_count", 0))}
        </div>
      </section>

      <section class="grid section-gap">
        <div class="card">
          <h2>重点结论</h2>
          <div class="list">{top_finding_html}</div>
        </div>
        <div class="card">
          <h2>行动项</h2>
          <div class="list">{_render_simple_cards(action_items)}</div>
        </div>
      </section>

      <section class="grid section-gap">
        <div class="card">
          <h2>攻击面与程序结构</h2>
          <div class="list">{_render_semantic_summary(semantic)}</div>
        </div>
        <div class="card">
          <h2>相似历史案例</h2>
          <div class="list">{related_html}</div>
        </div>
      </section>

      <section class="grid section-gap">
        <div class="card">
          <h2>风险热点分类</h2>
          <div class="list">{category_html}</div>
        </div>
        <div class="card">
          <h2>分析器命中分布</h2>
          <div class="list">{analyzer_html}</div>
        </div>
      </section>

      <section class="card section-gap">
        <h2>全部发现（按严重性分组）</h2>
        <div class="list">{grouped_html}</div>
      </section>

      <section class="card section-gap">
        <h2>工件文件</h2>
        <ul class="file-list">{_render_file_links(task_id, files)}</ul>
      </section>

      <details class="card section-gap">
        <summary>查看完整 Markdown 报告</summary>
        <pre>{escape(markdown_report)}</pre>
      </details>
    </main>
    """
    return _render_layout(
        title=f"{presentation.get('protocol_name', task_id)} 审计详情",
        content=content,
        body_class="page-detail",
    )


def render_research_detail_page(task_id: str, task_result: dict, files: list[str]) -> str:
    """渲染独立研究详情页。"""

    payload = task_result.get("payload", {})
    steps = task_result.get("steps", [])
    presentation = payload.get("research_presentation", {})
    memo = payload.get("research_memo", {}).get("markdown", "")
    experiment_plan = payload.get("experiment_plan", {})
    paper_draft = (
        presentation.get("revision_result", {}).get("revised_markdown")
        or payload.get("paper_draft", {}).get("markdown", "")
    )
    selected_direction = presentation.get("selected_direction", {})
    candidate_ideas = presentation.get("candidate_ideas", [])
    event_discovery = presentation.get("event_discovery", {})
    evidence_chain = presentation.get("evidence_chain", [])
    incident_understanding = presentation.get("incident_understanding", {})
    mechanism_graph_design = presentation.get("mechanism_graph_design", {})
    research_program_candidates = presentation.get("research_program_candidates", [])
    paper_strategy = presentation.get("paper_strategy", {})
    incident_packages = presentation.get("incident_packages", [])
    evidence_assessment = presentation.get("evidence_assessment", {})
    reference_validation = presentation.get("reference_validation", {})
    revision_result = presentation.get("revision_result", {})
    contribution_profile = presentation.get("contribution_profile", {})
    publication_task_design = presentation.get("publication_task_design", {})
    peer_reviews = presentation.get("peer_reviews") or build_peer_review_views(
        revision_result,
        evidence_assessment=evidence_assessment,
        reference_validation=reference_validation,
        task_steps=steps,
    )
    claim_evidence_matrix = presentation.get("claim_evidence_matrix", {})
    claim_graph = presentation.get("claim_graph", {})
    citations = presentation.get("citations", [])
    experiments = presentation.get("experiments", [])
    experiment_gap_report = presentation.get("experiment_gap_report", {})
    journal_fit_assessment = presentation.get("journal_fit_assessment", {})
    submission_compliance = presentation.get("submission_compliance", {})
    publication_readiness = presentation.get("publication_readiness", {})
    deliverables = presentation.get("deliverables", [])
    execution_timeline = presentation.get("execution_timeline", [])
    open_risks = presentation.get("open_risks", [])
    step_html = "".join(
        f"""
        <div class="artifact-item">
          <h4>{index}. {escape(item.get("name", ""))}</h4>
          <div class="toolbar">
            {_plain_badge(item.get("status", "unknown"))}
          </div>
          <p>{escape(item.get("detail", "暂无说明。"))}</p>
        </div>
        """
        for index, item in enumerate(steps, start=1)
    ) or '<div class="muted">暂无运行步骤记录。</div>'

    candidate_html = "".join(
        f"""
        <div class="artifact-item">
          <h4>{index + 1}. {escape(item.get("title", ""))}</h4>
          <div class="toolbar">
            {_plain_badge(item.get("decision_status", "candidate"))}
            {_plain_badge(f'综合 {item.get("composite_score", 0)}')}
            {_plain_badge(f'证据 {item.get("evidence_score", 0)}')}
            {_plain_badge(f'可执行性 {item.get("feasibility_score", 0)}')}
          </div>
          <p><strong>方向摘要：</strong>{escape(item.get("summary", "暂无"))}</p>
          <p><strong>选择说明：</strong>{escape(item.get("selection_reason", "暂无"))}</p>
        </div>
        """
        for index, item in enumerate(candidate_ideas[:5])
    ) or '<div class="muted">暂无候选方向。</div>'

    evidence_html = "".join(
        f"""
        <div class="artifact-item">
          <h4>{escape(item.get("title", ""))}</h4>
          <div class="toolbar">
            {_plain_badge(item.get("evidence_type", "evidence"))}
            {_plain_badge(item.get("strength", "reference"))}
          </div>
          <p><strong>证据摘要：</strong>{escape(item.get("summary", "暂无"))}</p>
          <p><strong>来源：</strong>{escape(item.get("source_ref", "暂无"))}</p>
          <p><strong>解释：</strong>{escape(item.get("reasoning", "暂无"))}</p>
        </div>
        """
        for item in evidence_chain
    ) or '<div class="muted">暂无证据链。</div>'

    citations_html = "".join(
        f"""
        <div class="artifact-item">
          <h4>{escape(citation.get("title", ""))}</h4>
          <div class="toolbar">
            {_plain_badge(citation.get("source_type", "reference"))}
            {_plain_badge(citation.get("support_level", "reference"))}
            {_plain_badge(f'相关性 {citation.get("relevance_score", 0)}')}
          </div>
          <p><strong>支撑主张：</strong>{escape(citation.get("claim_supported", "暂无"))}</p>
          <p><strong>采用理由：</strong>{escape(citation.get("citation_reason", "暂无"))}</p>
          <p><strong>关键结论：</strong>{escape(citation.get("key_takeaway", citation.get("snippet", "暂无")))}</p>
        </div>
        """
        for citation in citations[:12]
    ) or '<div class="muted">暂无相关引用。</div>'

    incident_package_html = "".join(
        f"""
        <details class="artifact-item">
          <summary>{escape(item.get("title", ""))} · {escape(item.get("chain", "unknown"))}</summary>
          <div class="list section-gap-sm">
            <div class="artifact-item"><strong>损失：</strong>{escape(item.get("loss_summary", "未显式记录"))}</div>
            <div class="artifact-item"><strong>摘要：</strong>{escape('；'.join(item.get("evidence_summary", [])) or '暂无')}</div>
            <div class="artifact-item"><strong>关键交易：</strong>{escape('；'.join(tx.get("tx_hash", "") for tx in item.get("attack_transactions", [])) or '暂无')}</div>
            <div class="artifact-item"><strong>关键实体：</strong>{escape('；'.join(entity.get("label", "") for entity in item.get("key_entities", [])) or '暂无')}</div>
            <div class="artifact-item"><strong>受影响组件：</strong>{escape('；'.join(entity.get("label", "") for entity in item.get("affected_components", [])) or '暂无')}</div>
            <div class="artifact-item"><strong>时间线：</strong>{escape('；'.join(step.get("title", "") for step in item.get("timeline", [])) or '暂无')}</div>
            <div class="artifact-item"><strong>本地验证：</strong>{escape('；'.join(
              result.get("summary", "")
              for result in item.get("verification_results", [])
            ) or '暂无')}</div>
            <div class="artifact-item"><strong>缺失工件：</strong>{escape('；'.join(item.get("missing_artifacts", [])) or '无')}</div>
          </div>
        </details>
        """
        for item in incident_packages
    ) or '<div class="muted">暂无攻击事件证据包。</div>'

    experiment_html = "".join(
        f"""
        <details class="artifact-item">
          <summary>{escape(design.get("title", ""))}</summary>
          <div class="list section-gap-sm">
            <div class="artifact-item"><strong>目标：</strong>{escape(design.get("objective", "暂无"))}</div>
            <div class="artifact-item"><strong>数据集：</strong>{escape('；'.join(design.get("datasets", [])) or '暂无')}</div>
            <div class="artifact-item"><strong>基线：</strong>{escape('；'.join(design.get("baselines", [])) or '暂无')}</div>
            <div class="artifact-item"><strong>指标：</strong>{escape('；'.join(design.get("metrics", [])) or '暂无')}</div>
            <div class="artifact-item"><strong>步骤：</strong>{escape('；'.join(design.get("procedures", [])) or '暂无')}</div>
            <div class="artifact-item"><strong>成功标准：</strong>{escape('；'.join(design.get("success_criteria", [])) or '暂无')}</div>
            <div class="artifact-item"><strong>失败条件：</strong>{escape('；'.join(design.get("failure_criteria", [])) or '暂无')}</div>
            <div class="artifact-item"><strong>产出：</strong>{escape('；'.join(design.get("deliverables", [])) or '暂无')}</div>
          </div>
        </details>
        """
        for design in experiments
    ) or '<div class="muted">暂无实验计划。</div>'

    selected_questions_html = "".join(
        f'<div class="artifact-item"><p>{escape(item)}</p></div>'
        for item in selected_direction.get("research_questions", [])
    ) or '<div class="muted">暂无研究问题。</div>'

    selected_observation_html = "".join(
        f'<div class="artifact-item"><p>{escape(item)}</p></div>'
        for item in selected_direction.get("key_observations", [])
    ) or '<div class="muted">暂无关键观察。</div>'

    contribution_html = "".join(
        f'<div class="artifact-item"><p>{escape(item)}</p></div>'
        for item in selected_direction.get("expected_contributions", [])
    ) or '<div class="muted">暂无预期贡献。</div>'
    event_discovery_html = "".join(
        f"""
        <div class="artifact-item">
          <h4>{escape(item.get("title", ""))}</h4>
          <p><strong>来源：</strong>{escape(item.get("source", "暂无"))}</p>
          <p><strong>时间：</strong>{escape(item.get("discovered_at", "暂无"))}</p>
          <p><strong>相关性：</strong>{escape(str(item.get("relevance_score", 0)))}</p>
          <p><strong>摘要：</strong>{escape(item.get("summary", "暂无"))}</p>
        </div>
        """
        for item in event_discovery.get("discovered_candidates", [])[:4]
    ) or '<div class="muted">暂无自动发现结果。</div>'
    incident_understanding_html = "".join(
        f'<div class="artifact-item"><strong>{escape(label)}：</strong>{escape(str(value))}</div>'
        for label, value in [
            ("事件摘要", incident_understanding.get("event_summary", "暂无")),
            ("攻击面", "；".join(incident_understanding.get("attack_surface", [])) or "暂无"),
            ("根因候选", "；".join(incident_understanding.get("root_cause_candidates", [])) or "暂无"),
            ("执行路径", "；".join(incident_understanding.get("execution_path", [])) or "暂无"),
            ("关键交易", "；".join(incident_understanding.get("key_transactions", [])) or "暂无"),
            ("证据完整度", incident_understanding.get("evidence_completeness", "暂无")),
            ("验证可行性", incident_understanding.get("verification_feasibility", "暂无")),
        ]
    ) or '<div class="muted">暂无事件理解对象。</div>'
    mechanism_graph_html = "".join(
        f"""
        <div class="artifact-item">
          <h4>{escape(item.get("label", ""))}</h4>
          <p><strong>角色：</strong>{escape(item.get("role", "暂无"))}</p>
          <p>{escape(item.get("summary", "暂无"))}</p>
        </div>
        """
        for item in mechanism_graph_design.get("nodes", [])
    ) or '<div class="muted">暂无机制图。</div>'
    program_candidate_html = "".join(
        f"""
        <div class="artifact-item">
          <h4>{escape(item.get("title", ""))}</h4>
          <div class="toolbar">
            {_plain_badge(item.get("paper_type", "unknown"))}
            {_plain_badge("selected" if item.get("selected") else "candidate")}
          </div>
          <p><strong>核心问题：</strong>{escape(item.get("core_question", "暂无"))}</p>
          <p><strong>可检验主张：</strong>{escape(item.get("testable_claim", "暂无"))}</p>
          <p><strong>所需证据：</strong>{escape('；'.join(item.get("required_evidence", [])) or '暂无')}</p>
          <p><strong>所需验证：</strong>{escape('；'.join(item.get("required_validation", [])) or '暂无')}</p>
        </div>
        """
        for item in research_program_candidates
    ) or '<div class="muted">暂无研究程序候选。</div>'
    paper_strategy_html = "".join(
        f'<div class="artifact-item"><strong>{escape(label)}：</strong>{escape(str(value))}</div>'
        for label, value in [
            ("论文类型", paper_strategy.get("paper_type", "暂无")),
            ("目标版式", paper_strategy.get("target_venue_style", "暂无")),
            ("稿件定位", paper_strategy.get("article_positioning", "暂无")),
            ("章节蓝图", "；".join(paper_strategy.get("section_blueprint", [])) or "暂无"),
            ("必需图", "；".join(paper_strategy.get("required_figures", [])) or "暂无"),
            ("必需表", "；".join(paper_strategy.get("required_tables", [])) or "暂无"),
        ]
    ) or '<div class="muted">暂无论文策略。</div>'
    crystallized_contribution_html = "".join(
        f"""
        <div class="artifact-item">
          <h4>{escape(item.get("label", ""))}</h4>
          <p><strong>贡献陈述：</strong>{escape(item.get("statement", "暂无"))}</p>
          <p><strong>经验锚点：</strong>{escape(item.get("evidence_anchor", "暂无"))}</p>
          <p><strong>验证锚点：</strong>{escape(item.get("validation_anchor", "暂无"))}</p>
          <p><strong>新颖性定位：</strong>{escape(item.get("novelty_anchor", "暂无"))}</p>
          <p><strong>边界：</strong>{escape(item.get("boundary", "暂无"))}</p>
        </div>
        """
        for item in contribution_profile.get("entries", [])
    ) or '<div class="muted">暂无贡献提纯结果。</div>'
    publication_task_html = "".join(
        f"""
        <details class="artifact-item">
          <summary>{escape(item.get("title", ""))}</summary>
          <div class="list section-gap-sm">
            <div class="artifact-item"><strong>任务 ID：</strong>{escape(item.get("task_id", "unknown"))}</div>
            <div class="artifact-item"><strong>目标：</strong>{escape(item.get("goal", "暂无"))}</div>
            <div class="artifact-item"><strong>输入：</strong>{escape('；'.join(item.get("inputs", [])) or '暂无')}</div>
            <div class="artifact-item"><strong>输出：</strong>{escape('；'.join(item.get("outputs", [])) or '暂无')}</div>
            <div class="artifact-item"><strong>验收：</strong>{escape('；'.join(item.get("acceptance_criteria", [])) or '暂无')}</div>
            <div class="artifact-item"><strong>依赖：</strong>{escape('；'.join(item.get("dependencies", [])) or '无')}</div>
          </div>
        </details>
        """
        for item in publication_task_design.get("tasks", [])
    ) or '<div class="muted">暂无期刊化任务设计。</div>'
    publication_claim_html = "".join(
        f"""
        <div class="artifact-item">
          <h4>{escape(item.get("claim_id", ""))}</h4>
          <p><strong>主张：</strong>{escape(item.get("statement", "暂无"))}</p>
          <p><strong>直接证据：</strong>{escape(item.get("direct_evidence", "暂无"))}</p>
          <p><strong>验证锚点：</strong>{escape(item.get("validation_anchor", "暂无"))}</p>
          <p><strong>反证：</strong>{escape(item.get("counterfactual", "暂无"))}</p>
          <p><strong>边界：</strong>{escape(item.get("boundary", "暂无"))}</p>
        </div>
        """
        for item in publication_task_design.get("claim_units", [])
    ) or '<div class="muted">暂无主张对象。</div>'
    publication_lane_html = "".join(
        f"""
        <div class="artifact-item">
          <h4>{escape(item.get("label", ""))} · {escape(item.get("focus", ""))}</h4>
          <p>{escape('；'.join(item.get("checklist", [])) or '暂无')}</p>
        </div>
        """
        for item in publication_task_design.get("reviewer_lanes", [])
    ) or '<div class="muted">暂无 reviewer lanes。</div>'
    venue_blueprint_html = "".join(
        f"""
        <div class="artifact-item">
          <h4>{escape(item.get("heading", ""))}</h4>
          <p><strong>用途：</strong>{escape(item.get("purpose", "暂无"))}</p>
          <p><strong>输入：</strong>{escape('；'.join(item.get("required_inputs", [])) or '暂无')}</p>
          <p><strong>风格要求：</strong>{escape(item.get("style_notes", "暂无"))}</p>
        </div>
        """
        for item in publication_task_design.get("venue_blueprint", [])
    ) or '<div class="muted">暂无 venue blueprint。</div>'

    deliverables_html = "".join(
        f'<div class="artifact-item"><p>{escape(item)}</p></div>'
        for item in deliverables
    ) or '<div class="muted">暂无交付物说明。</div>'

    timeline_html = "".join(
        f'<div class="artifact-item"><p>{escape(item)}</p></div>'
        for item in execution_timeline
    ) or '<div class="muted">暂无执行节奏。</div>'

    risk_html = "".join(
        f'<div class="artifact-item"><p>{escape(item)}</p></div>'
        for item in open_risks
    ) or '<div class="muted">暂无显式风险。</div>'
    assessment_ok_html = "".join(
        f'<div class="artifact-item"><p>{escape(item)}</p></div>'
        for item in evidence_assessment.get("satisfied_dimensions", [])
    ) or '<div class="muted">暂无已满足项。</div>'
    assessment_missing_html = "".join(
        f'<div class="artifact-item"><p>{escape(item)}</p></div>'
        for item in evidence_assessment.get("missing_dimensions", [])
    ) or '<div class="muted">暂无缺口。</div>'
    assessment_action_html = "".join(
        f'<div class="artifact-item"><p>{escape(item)}</p></div>'
        for item in evidence_assessment.get("next_actions", [])
    ) or '<div class="muted">暂无后续动作。</div>'
    claim_check_html = "".join(
        f"""
        <div class="artifact-item">
          <h4>{escape(item.get("claim", ""))}</h4>
          <div class="toolbar">
            {_plain_badge(item.get("status", "unknown"))}
            {_plain_badge(f'证据 {item.get("evidence_count", 0)}')}
            {_plain_badge(f'引用 {item.get("citation_count", 0)}')}
            {_plain_badge('有实验' if item.get("has_experiment") else '缺实验')}
          </div>
          <p>{escape(item.get("reasoning", "暂无"))}</p>
        </div>
        """
        for item in evidence_assessment.get("claim_checks", [])
    ) or '<div class="muted">暂无主张覆盖检查。</div>'
    graph_stats_html = "".join(
        f'<div class="artifact-item"><strong>{escape(label)}：</strong>{escape(str(value))}</div>'
        for label, value in [
            ("主张数", claim_graph.get("stats", {}).get("claim_count", 0)),
            ("证据数", claim_graph.get("stats", {}).get("evidence_count", 0)),
            ("引用数", claim_graph.get("stats", {}).get("citation_count", 0)),
            ("实验数", claim_graph.get("stats", {}).get("experiment_count", 0)),
            ("关系边数", claim_graph.get("stats", {}).get("edge_count", 0)),
        ]
    ) or '<div class="muted">暂无图谱统计。</div>'
    graph_claim_html = "".join(
        f"""
        <details class="artifact-item">
          <summary>{escape(node.get("title", ""))}</summary>
          <div class="list section-gap-sm">
            <div class="artifact-item"><strong>状态：</strong>{escape(node.get("status", "unknown"))}</div>
            <div class="artifact-item"><strong>说明：</strong>{escape(node.get("summary", "暂无"))}</div>
            <div class="artifact-item"><strong>关联边：</strong>{escape('；'.join(
                f"{edge.get('relation')} -> {edge.get('to_node_id')}"
                for edge in claim_graph.get('edges', [])
                if edge.get('from_node_id') == node.get('node_id')
            ) or '暂无')}</div>
          </div>
        </details>
        """
        for node in claim_graph.get("claim_nodes", [])
    ) or '<div class="muted">暂无主张图谱。</div>'
    claim_matrix_html = "".join(
        f"""
        <details class="artifact-item">
          <summary>{escape(item.get("claim", ""))} · {escape(item.get("status", "unknown"))}</summary>
          <div class="list section-gap-sm">
            <div class="artifact-item"><strong>证据：</strong>{escape('；'.join(item.get("evidence_refs", [])) or '暂无')}</div>
            <div class="artifact-item"><strong>引用：</strong>{escape('；'.join(item.get("citation_refs", [])) or '暂无')}</div>
            <div class="artifact-item"><strong>实验：</strong>{escape('；'.join(item.get("experiment_refs", [])) or '暂无')}</div>
            <div class="artifact-item"><strong>支撑点：</strong>{escape('；'.join(item.get("supporting_points", [])) or '暂无')}</div>
            <div class="artifact-item"><strong>边界说明：</strong>{escape('；'.join(item.get("boundary_notes", [])) or '暂无')}</div>
            <div class="artifact-item"><strong>主要缺口：</strong>{escape(item.get("primary_gap", '') or '无')}</div>
          </div>
        </details>
        """
        for item in claim_evidence_matrix.get("rows", [])
    ) or '<div class="muted">暂无主张-证据矩阵。</div>'
    experiment_gap_html = "".join(
        f"""
        <div class="artifact-item">
          <h4>{escape(item.get("title", ""))}</h4>
          <div class="toolbar">
            {_plain_badge(item.get("severity", "info"))}
          </div>
          <p><strong>描述：</strong>{escape(item.get("description", "暂无"))}</p>
          <p><strong>关联主张：</strong>{escape('；'.join(item.get("linked_claims", [])) or '暂无')}</p>
          <p><strong>动作：</strong>{escape('；'.join(item.get("suggested_actions", [])) or '暂无')}</p>
          <p><strong>解除条件：</strong>{escape(item.get("unblock_condition", "暂无"))}</p>
        </div>
        """
        for item in (
            (experiment_gap_report.get("blocker_gaps", []) or [])[:4]
            + (experiment_gap_report.get("major_gaps", []) or [])[:4]
            + (experiment_gap_report.get("minor_gaps", []) or [])[:3]
        )
    ) or '<div class="muted">暂无实验缺口。</div>'
    journal_fit_html = "".join(
        f"""
        <div class="artifact-item">
          <h4>{escape(item.get("label", ""))}</h4>
          <div class="toolbar">
            {_plain_badge(f"score {item.get('score', 0)}")}
            {_plain_badge(item.get("status", "unknown"))}
          </div>
          <p><strong>依据：</strong>{escape(item.get("evidence", "暂无"))}</p>
          <p><strong>缺口：</strong>{escape(item.get("gap", '') or '无')}</p>
          <p><strong>动作：</strong>{escape(item.get("required_action", '') or '无')}</p>
        </div>
        """
        for item in journal_fit_assessment.get("dimensions", [])
    ) or '<div class="muted">暂无期刊适配评估。</div>'
    compliance_html = "".join(
        f"""
        <div class="artifact-item">
          <h4>{escape(item.get("label", ""))}</h4>
          <div class="toolbar">
            {_plain_badge(item.get("status", "unknown"))}
            {_plain_badge(item.get("severity", "info"))}
          </div>
          <p><strong>说明：</strong>{escape(item.get("details", "暂无"))}</p>
          <p><strong>修复：</strong>{escape(item.get("remediation", "暂无"))}</p>
        </div>
        """
        for item in submission_compliance.get("checks", [])
    ) or '<div class="muted">暂无投稿合规结果。</div>'

    generation_mode_label = (
        "AI 增强"
        if presentation.get("generation_mode") == "ai_enhanced"
        else "AI 回退到规则层"
        if presentation.get("generation_mode") == "fallback_to_rules"
        else "本地证据模式"
    )
    llm_summary_block = ""
    if presentation.get("llm_summary"):
        llm_summary_block = (
            f'<div class="artifact-item"><h4>AI 执行摘要</h4>'
            f'<p>{escape(presentation.get("llm_summary", ""))}</p></div>'
        )
    llm_abstract_block = ""
    if selected_direction.get("draft_abstract"):
        llm_abstract_block = (
            f'<div class="artifact-item"><h4>AI 论文摘要草案</h4>'
            f'<p>{escape(selected_direction.get("draft_abstract", ""))}</p></div>'
        )
    elif not presentation.get("paper_ready", False):
        llm_abstract_block = (
            '<div class="artifact-item"><h4>论文初稿状态</h4>'
            '<p>当前证据门禁未通过，系统不会生成最终论文初稿。</p></div>'
        )
    llm_error_block = ""
    if presentation.get("llm_error"):
        llm_error_block = (
            f'<div class="artifact-item"><h4>AI 增强状态</h4>'
            f'<p>{escape(presentation.get("llm_error", ""))}</p></div>'
        )
    reference_issue_html = "".join(
        f'<div class="artifact-item"><p><strong>{escape(item.get("title", ""))}</strong>：{escape(item.get("message", ""))}</p></div>'
        for item in reference_validation.get("issues", [])[:6]
    ) or '<div class="muted">暂无显式引用问题。</div>'
    revision_block_html = "".join(
        f"""
        <details class="artifact-item">
          <summary>{escape(item.get("name", ""))} · score={escape(str(item.get("score", 0)))} · {'pass' if item.get("accepted") else 'needs fix'}</summary>
          <div class="list section-gap-sm">
            <div class="artifact-item"><strong>视角：</strong>{escape('；'.join(
              f"{aspect.get('name', '')}:{'pass' if aspect.get('accepted') else 'fix'}"
              for aspect in item.get("aspects", [])
            ) or '暂无')}</div>
            <div class="artifact-item"><strong>优点：</strong>{escape('；'.join(item.get("strengths", [])) or '暂无')}</div>
            <div class="artifact-item"><strong>问题：</strong>{escape('；'.join(item.get("weaknesses", [])) or '暂无')}</div>
            <div class="artifact-item"><strong>必须修改：</strong>{escape('；'.join(item.get("required_changes", [])) or '暂无')}</div>
            <div class="artifact-item"><strong>已处理：</strong>{escape('；'.join(item.get("addressed_changes", [])) or '暂无')}</div>
            <div class="artifact-item"><strong>视角详情：</strong>{escape('；'.join(
              f"{aspect.get('name', '')}:{aspect.get('summary', '')}"
              for aspect in item.get("aspects", [])
            ) or '暂无')}</div>
          </div>
        </details>
        """
        for item in revision_result.get("review_blocks", [])
    ) or '<div class="muted">暂无分块 review 结果。</div>'
    revision_strength_html = "".join(
        f'<div class="artifact-item"><p>{escape(item)}</p></div>'
        for item in revision_result.get("strengths", [])
    ) or '<div class="muted">暂无修订优点总结。</div>'
    revision_weakness_html = "".join(
        f'<div class="artifact-item"><p>{escape(item)}</p></div>'
        for item in revision_result.get("weaknesses", [])
    ) or '<div class="muted">暂无修订弱点总结。</div>'
    revision_action_html = "".join(
        f'<div class="artifact-item"><p>{escape(item)}</p></div>'
        for item in revision_result.get("required_changes", [])
    ) or '<div class="muted">暂无必须修改项。</div>'
    peer_review_html = "".join(
        f"""
        <details class="artifact-item">
          <summary>{escape(item.get("label", ""))} · {escape(item.get("focus", ""))} · {escape(item.get("recommendation", ""))} · priority={escape(item.get("priority", "info"))}</summary>
          <div class="list section-gap-sm">
            <div class="artifact-item"><strong>总体意见：</strong>{escape(item.get("overall_comment", "暂无"))}</div>
            <div class="artifact-item"><strong>视角摘要：</strong>{escape('；'.join(item.get("aspect_summary", [])) or '暂无')}</div>
            <div class="artifact-item"><strong>证据依据：</strong>{escape('；'.join(item.get("evidence_basis", [])) or '暂无')}</div>
            <div class="artifact-item"><strong>优点：</strong>{escape('；'.join(item.get("strengths", [])) or '暂无')}</div>
            <div class="artifact-item"><strong>阻断问题：</strong>{escape('；'.join(item.get("blocker_issues", [])) or '无')}</div>
            <div class="artifact-item"><strong>主要顾虑：</strong>{escape('；'.join(item.get("major_concerns", [])) or '暂无')}</div>
            <div class="artifact-item"><strong>次要顾虑：</strong>{escape('；'.join(item.get("minor_concerns", [])) or '暂无')}</div>
            <div class="artifact-item"><strong>接受条件：</strong>{escape('；'.join(item.get("acceptance_conditions", [])) or '暂无')}</div>
            <div class="artifact-item"><strong>给作者的问题：</strong>{escape('；'.join(item.get("questions_for_authors", [])) or '暂无')}</div>
          </div>
        </details>
        """
        for item in peer_reviews
    ) or '<div class="muted">暂无多审稿人视角。</div>'

    download_buttons = []
    download_buttons.append(
        _download_link("下载研究包", f"/api/v1/artifacts/{task_id}/generated/research_bundle.zip")
    )
    if peer_reviews:
        download_buttons.append(
            _download_link("下载审稿意见", f"/api/v1/artifacts/{task_id}/generated/peer_reviews.md")
        )
    if steps:
        download_buttons.append(
            _download_link("下载运行步骤", f"/api/v1/artifacts/{task_id}/generated/task_steps.md")
        )
    if paper_draft.strip():
        download_buttons.append(
            _download_link("下载论文初稿", f"/api/v1/artifacts/{task_id}/generated/paper_draft.md")
        )
        download_buttons.append(
            _download_link("下载论文 PDF", f"/api/v1/artifacts/{task_id}/generated/paper_draft.pdf")
        )
    if memo.strip():
        download_buttons.append(
            _download_link("下载研究备忘录", f"/api/v1/artifacts/{task_id}/generated/research_memo.md")
        )
    if citations:
        download_buttons.append(
            _download_link("下载引用 JSON", f"/api/v1/artifacts/{task_id}/generated/citations.json")
        )
    if event_discovery:
        download_buttons.append(
            _download_link("下载事件发现", f"/api/v1/artifacts/{task_id}/generated/event_discovery.md")
        )
    if incident_packages:
        download_buttons.append(
            _download_link("下载事件证据包", f"/api/v1/artifacts/{task_id}/generated/incident_evidence_packages.json")
        )
    if incident_understanding:
        download_buttons.append(
            _download_link("下载事件理解", f"/api/v1/artifacts/{task_id}/generated/incident_understanding.md")
        )
    if mechanism_graph_design:
        download_buttons.append(
            _download_link("下载机制图", f"/api/v1/artifacts/{task_id}/generated/mechanism_graph_design.md")
        )
    if research_program_candidates:
        download_buttons.append(
            _download_link("下载研究程序", f"/api/v1/artifacts/{task_id}/generated/research_program_candidates.md")
        )
    if paper_strategy:
        download_buttons.append(
            _download_link("下载论文策略", f"/api/v1/artifacts/{task_id}/generated/paper_strategy.md")
        )
    if experiment_plan:
        download_buttons.append(
            _download_link("下载实验计划", f"/api/v1/artifacts/{task_id}/generated/experiment_plan.json")
        )
    if contribution_profile:
        download_buttons.append(
            _download_link("下载贡献提纯", f"/api/v1/artifacts/{task_id}/generated/contribution_profile.md")
        )
    if publication_task_design:
        download_buttons.append(
            _download_link("下载任务设计", f"/api/v1/artifacts/{task_id}/generated/publication_task_design.md")
        )
    if claim_evidence_matrix:
        download_buttons.append(
            _download_link("下载主张矩阵", f"/api/v1/artifacts/{task_id}/generated/claim_evidence_matrix.md")
        )
    if experiment_gap_report:
        download_buttons.append(
            _download_link("下载实验缺口", f"/api/v1/artifacts/{task_id}/generated/experiment_gap_report.md")
        )
    if journal_fit_assessment:
        download_buttons.append(
            _download_link("下载期刊适配", f"/api/v1/artifacts/{task_id}/generated/journal_fit_assessment.md")
        )
    if submission_compliance:
        download_buttons.append(
            _download_link("下载投稿合规", f"/api/v1/artifacts/{task_id}/generated/submission_compliance.md")
        )
    if publication_readiness:
        download_buttons.append(
            _download_link("下载就绪度", f"/api/v1/artifacts/{task_id}/generated/publication_readiness.md")
        )

    content = f"""
    <main class="wrap">
      <section class="card page-header">
        <div>
          <p class="eyebrow">研究详情页</p>
          <h1>{escape(presentation.get("title", task_id))}</h1>
          <p>{escape(presentation.get("summary", "暂无研究摘要。"))}</p>
          <p class="muted">任务 ID: {escape(task_id)}</p>
        </div>
        <div class="toolbar">
          {_plain_badge(generation_mode_label)}
          {_plain_badge(f"门禁 {evidence_assessment.get('status', 'unknown')}")}
          {_plain_badge(f"peer-review {presentation.get('peer_review_status', 'unknown')}")}
          {_plain_badge(f"投稿 {publication_readiness.get('status', 'unknown')}")}
          {_plain_badge(f'综合 {presentation.get("metrics", {}).get("composite_score", 0)}')}
          {_plain_badge(f'novelty {presentation.get("metrics", {}).get("novelty_score", 0)}')}
          {''.join(download_buttons)}
          {_button_link("返回首页", "/")}
        </div>
      </section>

      <section class="card section-gap">
        <h2>总体概览</h2>
        <div class="metric-grid">
          {_metric("研究想法数", presentation.get("metrics", {}).get("idea_count", 0))}
          {_metric("引用数", presentation.get("metrics", {}).get("citation_count", 0))}
          {_metric("novelty", presentation.get("metrics", {}).get("novelty_score", 0))}
          {_metric("证据数", presentation.get("metrics", {}).get("evidence_count", 0))}
          {_metric("实验设计数", presentation.get("metrics", {}).get("experiment_design_count", 0))}
          {_metric("综合评分", presentation.get("metrics", {}).get("composite_score", 0))}
          {_metric("投稿就绪度", publication_readiness.get("readiness_score", 0))}
        </div>
      </section>

      <section class="card section-gap">
        <h2>运行步骤</h2>
        <div class="list">{step_html}</div>
      </section>

      <section class="card section-gap">
        <h2>Event Discovery</h2>
        <div class="artifact-item"><strong>摘要：</strong>{escape(event_discovery.get("summary", "暂无"))}</div>
        <div class="artifact-item"><strong>选中候选：</strong>{escape(event_discovery.get("selected_title", "暂无"))}</div>
        <div class="artifact-item"><strong>来源：</strong>{escape('；'.join(event_discovery.get("sources", [])) or '暂无')}</div>
        <div class="list">{event_discovery_html}</div>
      </section>

      <section class="grid section-gap">
        <div class="card">
          <h2>主线研究方向</h2>
          <div class="list">{_render_simple_cards(presentation.get("highlights", []))}</div>
        </div>
        <div class="card">
          <h2>问题定义与选择理由</h2>
          <div class="list">
            <div class="artifact-item"><h4>问题定义</h4><p>{escape(selected_direction.get("problem_statement", presentation.get("summary", "暂无")))}</p></div>
            <div class="artifact-item"><h4>核心假设</h4><p>{escape(selected_direction.get("hypothesis", presentation.get("summary", "暂无")))}</p></div>
            <div class="artifact-item"><h4>选择理由</h4><p>{escape(selected_direction.get("selection_reason", "暂无"))}</p></div>
            <div class="artifact-item"><h4>研究动机</h4><p>{escape(presentation.get("motivation", "暂无"))}</p></div>
            <div class="artifact-item"><h4>新颖性</h4><p>{escape(presentation.get("novelty_rationale", "暂无"))}</p></div>
            {llm_summary_block}
            {llm_abstract_block}
            {llm_error_block}
          </div>
        </div>
      </section>

      <section class="grid section-gap">
        <div class="card">
          <h2>Incident Understanding</h2>
          <div class="list">{incident_understanding_html}</div>
        </div>
        <div class="card">
          <h2>Mechanism Graph 与 Paper Strategy</h2>
          <div class="artifact-item"><strong>机制摘要：</strong>{escape(mechanism_graph_design.get("summary", "暂无"))}</div>
          <div class="artifact-item"><strong>抽象机制：</strong>{escape(mechanism_graph_design.get("generalized_mechanism", "暂无"))}</div>
          <div class="list">{mechanism_graph_html}</div>
          <h3>Paper Strategy</h3>
          <div class="list">{paper_strategy_html}</div>
        </div>
      </section>

      <section class="card section-gap">
        <h2>Research Program Candidates</h2>
        <div class="list">{program_candidate_html}</div>
      </section>

      <section class="grid section-gap">
        <div class="card">
          <h2>候选方向对比</h2>
          <div class="list">{candidate_html}</div>
        </div>
        <div class="card">
          <h2>证据门禁结论</h2>
          <div class="list">
            <div class="artifact-item"><strong>门禁状态：</strong>{escape(evidence_assessment.get("status", "unknown"))}</div>
            <div class="artifact-item"><strong>门禁评分：</strong>{escape(str(evidence_assessment.get("score", 0)))}</div>
            <div class="artifact-item"><strong>结论：</strong>{escape(evidence_assessment.get("summary", "暂无"))}</div>
            <div class="artifact-item"><strong>评估来源：</strong>{escape(evidence_assessment.get("assessed_by", "none"))}</div>
            <div class="artifact-item"><strong>LLM 审查：</strong>{escape(evidence_assessment.get("llm_verdict", "未启用"))}</div>
          </div>
        </div>
      </section>

      <section class="grid section-gap">
        <div class="card">
          <h2>引用校验</h2>
          <div class="list">
            <div class="artifact-item"><strong>摘要：</strong>{escape(reference_validation.get("summary", "暂无"))}</div>
            <div class="artifact-item"><strong>接受：</strong>{escape(str(reference_validation.get("accepted_count", 0)))}</div>
            <div class="artifact-item"><strong>拒绝：</strong>{escape(str(reference_validation.get("rejected_count", 0)))}</div>
            {reference_issue_html}
          </div>
        </div>
        <div class="card">
          <h2>论文修订评审</h2>
          <div class="list">
            <div class="artifact-item"><strong>状态：</strong>{escape(revision_result.get("status", "not_reviewed"))}</div>
            <div class="artifact-item"><strong>接受：</strong>{escape(str(revision_result.get("accepted", False)))}</div>
            <div class="artifact-item"><strong>Peer Review 状态：</strong>{escape(presentation.get("peer_review_status", "unknown"))}</div>
            <div class="artifact-item"><strong>评分：</strong>{escape(str(revision_result.get("final_score", 0)))}</div>
            <div class="artifact-item"><strong>轮数：</strong>{escape(str(revision_result.get("rounds", 0)))}</div>
            <div class="artifact-item"><strong>摘要：</strong>{escape(revision_result.get("summary", "暂无"))}</div>
            <h3>分块 Review</h3>
            {revision_block_html}
            <h3>优点</h3>
            {revision_strength_html}
            <h3>弱点</h3>
            {revision_weakness_html}
            <h3>必须修改项</h3>
            {revision_action_html}
            <h3>已解决问题</h3>
            {''.join(f'<div class="artifact-item"><p>{escape(item)}</p></div>' for item in revision_result.get("addressed_changes", [])) or '<div class="muted">暂无已解决问题。</div>'}
          </div>
        </div>
      </section>

      <section class="card section-gap">
        <h2>多审稿人 Review</h2>
        <div class="list">{peer_review_html}</div>
      </section>

      <section class="grid section-gap">
        <div class="card">
          <h2>Publication Task Design</h2>
          <div class="artifact-item"><strong>摘要：</strong>{escape(publication_task_design.get("summary", "暂无"))}</div>
          <div class="list">{publication_task_html}</div>
        </div>
        <div class="card">
          <h2>Venue Blueprint 与 Reviewer Lanes</h2>
          <h3>Venue Blueprint</h3>
          <div class="list">{venue_blueprint_html}</div>
          <h3>Reviewer Lanes</h3>
          <div class="list">{publication_lane_html}</div>
        </div>
      </section>

      <section class="card section-gap">
        <h2>Claim Objects</h2>
        <div class="list">{publication_claim_html}</div>
      </section>

      <section class="grid section-gap">
        <div class="card">
          <h2>研究问题</h2>
          <div class="list">{selected_questions_html}</div>
        </div>
        <div class="card">
          <h2>主张覆盖检查</h2>
          <div class="list">{claim_check_html}</div>
        </div>
      </section>

      <section class="grid section-gap">
        <div class="card">
          <h2>关键观察</h2>
          <div class="list">{selected_observation_html}</div>
        </div>
        <div class="card">
          <h2>预期贡献</h2>
          <div class="list">{contribution_html}</div>
        </div>
      </section>

      <section class="grid section-gap">
        <div class="card">
          <h2>贡献提纯</h2>
          <div class="list">
            <div class="artifact-item"><strong>核心命题：</strong>{escape(contribution_profile.get("thesis_statement", "暂无"))}</div>
            <div class="artifact-item"><strong>问题框定：</strong>{escape(contribution_profile.get("problem_framing", "暂无"))}</div>
            <div class="artifact-item"><strong>新颖性定位：</strong>{escape(contribution_profile.get("novelty_positioning", "暂无"))}</div>
            <div class="artifact-item"><strong>摘要：</strong>{escape(contribution_profile.get("summary", "暂无"))}</div>
            {crystallized_contribution_html}
          </div>
        </div>
        <div class="card">
          <h2>主张-证据矩阵</h2>
          <div class="list">
            <div class="artifact-item"><strong>摘要：</strong>{escape(claim_evidence_matrix.get("summary", "暂无"))}</div>
            <div class="artifact-item"><strong>Covered：</strong>{escape(str(claim_evidence_matrix.get("covered_count", 0)))}</div>
            <div class="artifact-item"><strong>Partial：</strong>{escape(str(claim_evidence_matrix.get("partial_count", 0)))}</div>
            <div class="artifact-item"><strong>Missing：</strong>{escape(str(claim_evidence_matrix.get("missing_count", 0)))}</div>
            {claim_matrix_html}
          </div>
        </div>
      </section>

      <section class="grid section-gap">
        <div class="card">
          <h2>证据链</h2>
          <div class="list">{evidence_html}</div>
        </div>
        <div class="card">
          <h2>相关引用</h2>
          <div class="list">{citations_html}</div>
        </div>
      </section>

      <section class="card section-gap">
        <h2>攻击事件证据包</h2>
        <div class="list">{incident_package_html}</div>
      </section>

      <section class="grid section-gap">
        <div class="card">
          <h2>Claim 图谱总览</h2>
          <div class="artifact-item"><strong>摘要：</strong>{escape(claim_graph.get("summary", "暂无"))}</div>
          <div class="list">{graph_stats_html}</div>
        </div>
        <div class="card">
          <h2>Claim 图谱节点</h2>
          <div class="list">{graph_claim_html}</div>
        </div>
      </section>

      <section class="grid section-gap">
        <div class="card">
          <h2>实验设计</h2>
          <div class="list">{experiment_html}</div>
        </div>
        <div class="card">
          <h2>交付物与执行节奏</h2>
          <h3>交付物</h3>
          <div class="list">{deliverables_html}</div>
          <h3>执行节奏</h3>
          <div class="list">{timeline_html}</div>
        </div>
      </section>

      <section class="grid section-gap">
        <div class="card">
          <h2>实验缺口</h2>
          <div class="list">
            <div class="artifact-item"><strong>摘要：</strong>{escape(experiment_gap_report.get("summary", "暂无"))}</div>
            <div class="artifact-item"><strong>投稿提示：</strong>{escape(experiment_gap_report.get("publishability_note", "暂无"))}</div>
            <div class="artifact-item"><strong>下一步：</strong>{escape('；'.join(experiment_gap_report.get("next_best_experiments", [])) or '暂无')}</div>
            {experiment_gap_html}
          </div>
        </div>
        <div class="card">
          <h2>投稿就绪度</h2>
          <div class="list">
            <div class="artifact-item"><strong>状态：</strong>{escape(publication_readiness.get("status", "unknown"))}</div>
            <div class="artifact-item"><strong>评分：</strong>{escape(str(publication_readiness.get("readiness_score", 0)))}</div>
            <div class="artifact-item"><strong>摘要：</strong>{escape(publication_readiness.get("summary", "暂无"))}</div>
            <h3>Blockers</h3>
            {''.join(f'<div class="artifact-item"><p>{escape(item)}</p></div>' for item in publication_readiness.get("blockers", [])) or '<div class="muted">无</div>'}
            <h3>Warnings</h3>
            {''.join(f'<div class="artifact-item"><p>{escape(item)}</p></div>' for item in publication_readiness.get("warnings", [])) or '<div class="muted">无</div>'}
            <h3>Next Actions</h3>
            {''.join(f'<div class="artifact-item"><p>{escape(item)}</p></div>' for item in publication_readiness.get("next_actions", [])) or '<div class="muted">无</div>'}
          </div>
        </div>
      </section>

      <section class="grid section-gap">
        <div class="card">
          <h2>风险与边界</h2>
          <div class="list">{risk_html}</div>
        </div>
        <div class="card">
          <h2>证据缺口与后续动作</h2>
          <div class="list">
            <h3>已满足</h3>
            {assessment_ok_html}
            <h3>缺失项</h3>
            {assessment_missing_html}
            <h3>后续动作</h3>
            {assessment_action_html}
          </div>
        </div>
      </section>

      <section class="grid section-gap">
        <div class="card">
          <h2>期刊适配</h2>
          <div class="list">
            <div class="artifact-item"><strong>目标：</strong>{escape(journal_fit_assessment.get("target_profile", "暂无"))}</div>
            <div class="artifact-item"><strong>稿件类型：</strong>{escape(journal_fit_assessment.get("article_type", "暂无"))}</div>
            <div class="artifact-item"><strong>适配度：</strong>{escape(str(journal_fit_assessment.get("fit_score", 0)))}</div>
            <div class="artifact-item"><strong>状态：</strong>{escape(journal_fit_assessment.get("overall_fit", "unknown"))}</div>
            {journal_fit_html}
          </div>
        </div>
        <div class="card">
          <h2>投稿合规</h2>
          <div class="list">
            <div class="artifact-item"><strong>状态：</strong>{escape(submission_compliance.get("status", "unknown"))}</div>
            <div class="artifact-item"><strong>Blocker：</strong>{escape(str(submission_compliance.get("blocker_count", 0)))}</div>
            <div class="artifact-item"><strong>Warning：</strong>{escape(str(submission_compliance.get("warning_count", 0)))}</div>
            <div class="artifact-item"><strong>摘要：</strong>{escape(submission_compliance.get("summary", "暂无"))}</div>
            {compliance_html}
          </div>
        </div>
      </section>

      <section class="card section-gap">
        <h2>工件文件</h2>
        <ul class="file-list">{_render_file_links(task_id, files)}</ul>
      </section>

      <details class="card section-gap">
        <summary>查看研究备忘录</summary>
        <pre>{escape(memo)}</pre>
      </details>

      <details class="card section-gap">
        <summary>查看当前论文稿（优先显示修订稿）</summary>
        <pre>{escape(paper_draft)}</pre>
      </details>
    </main>
    """
    return _render_layout(
        title=f"{presentation.get('title', task_id)} 研究详情",
        content=content,
        body_class="page-detail",
    )
