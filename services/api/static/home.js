(() => {
  "use strict";

  function byId(id) {
    return document.getElementById(id);
  }

  async function requestJson(url, options = {}) {
    const headers = { ...(options.headers || {}) };
    if (options.body && !headers["Content-Type"]) {
      headers["Content-Type"] = "application/json";
    }

    const response = await fetch(url, { ...options, headers });
    const data = await response.json();
    if (!response.ok) {
      throw new Error(data.error || "请求失败");
    }
    return data;
  }

  function escapeHtml(text) {
    return String(text ?? "")
      .replaceAll("&", "&amp;")
      .replaceAll("<", "&lt;")
      .replaceAll(">", "&gt;")
      .replaceAll('"', "&quot;")
      .replaceAll("'", "&#39;");
  }

  function severityBadge(severity, label) {
    const normalized = String(severity || "").toLowerCase();
    let cls = "sev-info";
    if (normalized.includes("critical")) cls = "sev-critical";
    else if (normalized.includes("high")) cls = "sev-high";
    else if (normalized.includes("medium")) cls = "sev-medium";
    else if (normalized.includes("low")) cls = "sev-low";
    return `<span class="severity-badge ${cls}">${escapeHtml(label || severity)}</span>`;
  }

  function plainBadge(text) {
    return `<span class="status">${escapeHtml(text)}</span>`;
  }

  function formatElapsed(elapsedMs) {
    if (elapsedMs === undefined || elapsedMs === null) {
      return "未知";
    }
    return `${(elapsedMs / 1000).toFixed(2)} 秒`;
  }

  function toTaskId(data) {
    if (data?.artifact_dir) {
      const parts = String(data.artifact_dir).split("/");
      return parts[parts.length - 1] || "";
    }
    return data?.task_result?.task_id || "";
  }

  function resultLink(taskType, taskId) {
    if (!taskId) {
      return "";
    }
    const prefix = taskType === "research" ? "/research/" : "/audit/";
    return `<a class="button-link secondary" href="${prefix}${encodeURIComponent(taskId)}" target="_blank">查看详情页</a>`;
  }

  function downloadGeneratedLink(taskId, fileName, label) {
    if (!taskId) {
      return "";
    }
    return `<a class="button-link secondary" href="/api/v1/artifacts/${encodeURIComponent(taskId)}/generated/${encodeURIComponent(fileName)}" download>${escapeHtml(label)}</a>`;
  }

  function showRunningState(title, detail = "任务正在执行，请稍候...") {
    byId("result-viewer").innerHTML = `
      <div class="artifact-item">
        <h3>${escapeHtml(title)}</h3>
        <div class="muted">${escapeHtml(detail)}</div>
      </div>
    `;
    byId("result-raw").textContent = "";
  }

  async function runWithFeedback(buttonId, title, action, progressNotes = []) {
    const button = byId(buttonId);
    const originalText = button ? button.textContent : "";
    const start = performance.now();
    let timerId = null;
    let noteIndex = 0;

    if (button) {
      button.disabled = true;
      button.textContent = "运行中...";
    }
    showRunningState(title, progressNotes[0] || "任务正在执行，请稍候...");
    if (progressNotes.length > 1) {
      timerId = window.setInterval(() => {
        noteIndex = (noteIndex + 1) % progressNotes.length;
        showRunningState(title, progressNotes[noteIndex]);
      }, 900);
    }

    try {
      const data = await action();
      data._elapsed_ms = performance.now() - start;
      showResult(data);
      return data;
    } catch (error) {
      showResult({
        error: String(error),
        _elapsed_ms: performance.now() - start,
      });
      throw error;
    } finally {
      if (timerId !== null) {
        window.clearInterval(timerId);
      }
      if (button) {
        button.disabled = false;
        button.textContent = originalText;
      }
    }
  }

  function renderStatCards(metrics, riskTemperature) {
    return `
      <div class="metric-grid">
        <div class="metric"><strong>${metrics.total_findings || 0}</strong>总发现数</div>
        <div class="metric"><strong>${(metrics.high_count || 0) + (metrics.critical_count || 0)}</strong>高优先级问题</div>
        <div class="metric"><strong>${escapeHtml(riskTemperature || "未知")}</strong>风险温度</div>
        <div class="metric"><strong>${metrics.medium_count || 0}</strong>中风险</div>
        <div class="metric"><strong>${metrics.low_count || 0}</strong>低风险</div>
        <div class="metric"><strong>${metrics.informational_count || 0}</strong>提示项</div>
      </div>
    `;
  }

  function renderAuditResult(data) {
    const presentation = data.task_result?.payload?.audit_presentation || {};
    const taskId = toTaskId(data);
    const topGroups = presentation.top_groups || [];
    const groupedFamilies = presentation.grouped_families || {};
    const related = presentation.related_incidents || [];
    const categoryCounts = presentation.category_counts || {};
    const analyzerCounts = presentation.analyzer_counts || {};
    const semantic = presentation.semantic_highlights || {};
    const actionItems = presentation.action_items || [];

    const categoryBlocks = Object.entries(categoryCounts)
      .slice(0, 8)
      .map(([name, count]) => `
        <div class="artifact-item">
          <h4>${escapeHtml(name)}</h4>
          <div>数量: ${count}</div>
        </div>
      `)
      .join("");

    const analyzerBlocks = Object.entries(analyzerCounts)
      .slice(0, 8)
      .map(([name, count]) => `
        <div class="artifact-item">
          <h4>${escapeHtml(name)}</h4>
          <div>数量: ${count}</div>
        </div>
      `)
      .join("");

    const actionBlocks = actionItems.length
      ? actionItems.map((item) => `<div class="artifact-item">${escapeHtml(item)}</div>`).join("")
      : '<div class="muted">暂无行动项。</div>';

    const semanticBlocks = `
      <div class="artifact-item">
        <h4>公开入口</h4>
        <div>${escapeHtml((semantic.public_entrypoints || []).join("，") || "暂无")}</div>
      </div>
      <div class="artifact-item">
        <h4>外部调用后写状态</h4>
        <div>${escapeHtml((semantic.write_after_external_functions || []).join("，") || "暂无")}</div>
      </div>
      <div class="artifact-item">
        <h4>跨合约调用边</h4>
        <div>${escapeHtml(
          (semantic.cross_contract_call_edges || [])
            .map((edge) => `${edge.from_contract}.${edge.from_function} -> ${edge.target_contract}.${edge.target_function}`)
            .join("；") || "暂无"
        )}</div>
      </div>
      <div class="artifact-item">
        <h4>状态冲突</h4>
        <div>${escapeHtml(
          (semantic.state_conflicts || [])
            .map((conflict) => `${conflict.state_variable}:${conflict.from_function}<->${conflict.to_function}`)
            .join("；") || "暂无"
        )}</div>
      </div>
    `;

    const findingBlocks = topGroups.length
      ? topGroups.map((finding, index) => `
        <div class="artifact-item">
          <h4>${index + 1}. ${escapeHtml(finding.title_zh || "")}</h4>
          <div class="toolbar">
            ${severityBadge(finding.severity, finding.severity_zh)}
            ${plainBadge(finding.priority_zh)}
            ${plainBadge(finding.confidence_zh)}
          </div>
          <div>类别: ${escapeHtml(finding.category_zh || "未分类")}</div>
          <div>出现次数: ${finding.count || 0}</div>
          <div>样例位置: ${escapeHtml((finding.sample_locations || []).join("；"))}</div>
          <div>问题说明: ${escapeHtml((finding.sample_summaries || [])[0] || "暂无")}</div>
        </div>
      `).join("")
      : '<div class="muted">暂无重点发现。</div>';

    const groupedBlocks = Object.entries(groupedFamilies)
      .filter(([, items]) => (items || []).length > 0)
      .map(([severity, items]) => `
        <details class="artifact-item">
          <summary>${escapeHtml(severity)} (${items.length} 类问题)</summary>
          <div class="list section-gap-sm">
            ${items.slice(0, 20).map((finding, index) => `
              <div class="artifact-item">
                <h4>${index + 1}. ${escapeHtml(finding.title_zh || "")}</h4>
                <div class="toolbar">
                  ${severityBadge(finding.severity, finding.severity_zh)}
                  ${plainBadge(finding.priority_zh)}
                  ${plainBadge(finding.confidence_zh)}
                </div>
                <div>类别: ${escapeHtml(finding.category_zh || "未分类")}</div>
                <div>出现次数: ${finding.count || 0}</div>
                <div>样例位置: ${escapeHtml((finding.sample_locations || []).join("；"))}</div>
                <div>问题说明: ${escapeHtml((finding.sample_summaries || [])[0] || "暂无")}</div>
              </div>
            `).join("")}
          </div>
        </details>
      `)
      .join("");

    const relatedBlocks = related.length
      ? related.map((item) => `
        <div class="artifact-item">
          <h4>${escapeHtml(item.title)}</h4>
          <div>协议: ${escapeHtml(item.protocol_name)}</div>
          <div>年份: ${escapeHtml(item.year)}</div>
          <div>摘要: ${escapeHtml(item.summary)}</div>
          <div>匹配理由: ${escapeHtml((item.reasons || []).join("；"))}</div>
        </div>
      `).join("")
      : '<div class="muted">暂无相似历史案例。</div>';

    return `
      <div class="artifact-item">
        <h3>${escapeHtml(presentation.protocol_name || "审计结果")}</h3>
        <div>协议类型: <strong>${escapeHtml(presentation.protocol_type || "未知")}</strong></div>
        <div>一句话结论: ${escapeHtml(presentation.conclusion || "暂无结论")}</div>
        <div>归档目录: ${escapeHtml(data.artifact_dir || "未保存")}</div>
        <div>本次耗时: ${escapeHtml(formatElapsed(data._elapsed_ms))}</div>
        <div class="toolbar">
          ${plainBadge(presentation.risk_temperature || "未知")}
          ${downloadGeneratedLink(taskId, "audit_bundle.zip", "下载审计包")}
          ${resultLink("audit", taskId)}
        </div>
      </div>
      ${renderStatCards(presentation.metrics || {}, presentation.risk_temperature)}
      <div class="artifact-item">
        <h3>攻击面要点</h3>
        <div class="list">${semanticBlocks}</div>
      </div>
      <div class="artifact-item">
        <h3>风险热点分类</h3>
        <div class="list">${categoryBlocks || '<div class="muted">暂无分类统计。</div>'}</div>
      </div>
      <div class="artifact-item">
        <h3>分析器命中分布</h3>
        <div class="list">${analyzerBlocks || '<div class="muted">暂无分析器统计。</div>'}</div>
      </div>
      <div class="artifact-item">
        <h3>优先处理的问题</h3>
        <div class="list">${findingBlocks}</div>
      </div>
      <div class="artifact-item">
        <h3>全部发现（按严重性分组）</h3>
        <div class="list">${groupedBlocks || '<div class="muted">暂无更多发现。</div>'}</div>
      </div>
      <div class="artifact-item">
        <h3>相似历史案例</h3>
        <div class="list">${relatedBlocks}</div>
      </div>
      <div class="artifact-item">
        <h3>行动项</h3>
        <div class="list">${actionBlocks}</div>
      </div>
    `;
  }

  function renderResearchResult(data) {
    const steps = data.task_result?.steps || [];
    const presentation = data.task_result?.payload?.research_presentation || {};
    const selected = presentation.selected_direction || {};
    const candidateIdeas = presentation.candidate_ideas || [];
    const eventDiscovery = presentation.event_discovery || {};
    const evidenceChain = presentation.evidence_chain || [];
    const incidentPackages = presentation.incident_packages || [];
    const evidenceAssessment = presentation.evidence_assessment || {};
    const referenceValidation = presentation.reference_validation || {};
    const revisionResult = presentation.revision_result || {};
    const contributionProfile = presentation.contribution_profile || {};
    const publicationTaskDesign = presentation.publication_task_design || {};
    const peerReviews = presentation.peer_reviews || [];
    const claimEvidenceMatrix = presentation.claim_evidence_matrix || {};
    const claimGraph = presentation.claim_graph || {};
    const citations = presentation.citations || [];
    const experiments = presentation.experiments || [];
    const experimentGapReport = presentation.experiment_gap_report || {};
    const journalFitAssessment = presentation.journal_fit_assessment || {};
    const submissionCompliance = presentation.submission_compliance || {};
    const publicationReadiness = presentation.publication_readiness || {};
    const deliverables = presentation.deliverables || [];
    const openRisks = presentation.open_risks || [];
    const taskId = toTaskId(data);
    const generationMode = presentation.generation_mode === "ai_enhanced"
      ? "AI 增强"
      : presentation.generation_mode === "fallback_to_rules"
        ? "AI 回退到规则层"
        : "本地证据模式";

    const candidateCards = candidateIdeas.length
      ? candidateIdeas.slice(0, 4).map((idea, index) => `
        <div class="artifact-item">
          <h4>${index + 1}. ${escapeHtml(idea.title || "")}</h4>
          <div class="toolbar">
            ${plainBadge(idea.decision_status || "candidate")}
            ${plainBadge(`综合 ${idea.composite_score || 0}`)}
            ${plainBadge(`证据 ${idea.evidence_score || 0}`)}
          </div>
          <div>${escapeHtml(idea.summary || "")}</div>
          <div>选择说明: ${escapeHtml(idea.selection_reason || "暂无")}</div>
        </div>
      `).join("")
      : '<div class="muted">暂无候选方向。</div>';
    const eventDiscoveryCards = (eventDiscovery.discovered_candidates || []).length
      ? (eventDiscovery.discovered_candidates || []).slice(0, 4).map((item) => `
        <div class="artifact-item">
          <h4>${escapeHtml(item.title || "")}</h4>
          <div>来源: ${escapeHtml(item.source || "暂无")}</div>
          <div>时间: ${escapeHtml(item.discovered_at || "暂无")}</div>
          <div>相关性: ${escapeHtml(item.relevance_score || 0)}</div>
          <div>${escapeHtml(item.summary || "暂无")}</div>
        </div>
      `).join("")
      : '<div class="muted">暂无自动发现结果。</div>';

    const evidenceCards = evidenceChain.length
      ? evidenceChain.slice(0, 4).map((evidence) => `
        <div class="artifact-item">
          <h4>${escapeHtml(evidence.title || "")}</h4>
          <div class="toolbar">
            ${plainBadge(evidence.evidence_type || "evidence")}
            ${plainBadge(evidence.strength || "reference")}
          </div>
          <div>${escapeHtml(evidence.summary || "")}</div>
          <div>来源: ${escapeHtml(evidence.source_ref || "")}</div>
          <div>解释: ${escapeHtml(evidence.reasoning || "")}</div>
        </div>
      `).join("")
      : '<div class="muted">暂无证据链。</div>';

    const citationCards = citations.length
      ? citations.slice(0, 3).map((citation) => `
        <div class="artifact-item">
          <h4>${escapeHtml(citation.title || "")}</h4>
          <div class="toolbar">
            ${plainBadge(citation.source_type || "reference")}
            ${plainBadge(citation.support_level || "reference")}
            ${plainBadge(`相关性 ${citation.relevance_score || 0}`)}
          </div>
          <div>支撑主张: ${escapeHtml(citation.claim_supported || "暂无")}</div>
          <div>采用理由: ${escapeHtml(citation.citation_reason || "暂无")}</div>
          <div>${escapeHtml(citation.key_takeaway || citation.snippet || "")}</div>
        </div>
      `).join("")
      : '<div class="muted">暂无关键引用。</div>';

    const incidentPackageCards = incidentPackages.length
      ? incidentPackages.slice(0, 3).map((pkg) => `
        <div class="artifact-item">
          <h4>${escapeHtml(pkg.title || "")}</h4>
          <div class="toolbar">
            ${plainBadge(pkg.chain || "unknown")}
            ${plainBadge(`交易 ${((pkg.attack_transactions || []).length)}`)}
            ${plainBadge(`日志 ${pkg.indexed_log_count || 0}`)}
          </div>
          <div>损失: ${escapeHtml(pkg.loss_summary || "未显式记录")}</div>
          <div>证据摘要: ${escapeHtml((pkg.evidence_summary || []).join("；") || "暂无")}</div>
          <div>关键交易: ${escapeHtml((pkg.attack_transactions || []).map((tx) => tx.tx_hash).join("；") || "暂无")}</div>
          <div>本地验证: ${escapeHtml((pkg.verification_results || []).map((item) => item.summary).join("；") || "暂无")}</div>
        </div>
      `).join("")
      : '<div class="muted">暂无攻击事件证据包。</div>';

    const experimentCards = experiments.length
      ? experiments.slice(0, 3).map((design) => `
        <div class="artifact-item">
          <h4>${escapeHtml(design.title || "")}</h4>
          <div>目标: ${escapeHtml(design.objective || "")}</div>
          <div>指标: ${escapeHtml((design.metrics || []).join("；") || "暂无")}</div>
          <div>产出: ${escapeHtml((design.deliverables || []).join("；") || "暂无")}</div>
        </div>
      `).join("")
      : '<div class="muted">暂无实验计划。</div>';

    const deliverableCards = deliverables.length
      ? deliverables.slice(0, 5).map((item) => `
        <div class="artifact-item">${escapeHtml(item)}</div>
      `).join("")
      : '<div class="muted">暂无交付物说明。</div>';

    const riskCards = openRisks.length
      ? openRisks.slice(0, 4).map((item) => `
        <div class="artifact-item">${escapeHtml(item)}</div>
      `).join("")
      : '<div class="muted">暂无显式风险。</div>';
    const publicationTaskCards = (publicationTaskDesign.tasks || []).length
      ? (publicationTaskDesign.tasks || []).slice(0, 4).map((task) => `
        <div class="artifact-item">
          <h4>${escapeHtml(task.title || "")}</h4>
          <div>${escapeHtml(task.goal || "暂无")}</div>
          <div>输入: ${escapeHtml((task.inputs || []).join("；") || "暂无")}</div>
          <div>输出: ${escapeHtml((task.outputs || []).join("；") || "暂无")}</div>
        </div>
      `).join("")
      : '<div class="muted">暂无期刊化任务设计。</div>';

    const claimCheckCards = (evidenceAssessment.claim_checks || []).length
      ? (evidenceAssessment.claim_checks || []).slice(0, 3).map((item) => `
        <div class="artifact-item">
          <h4>${escapeHtml(item.claim || "")}</h4>
          <div class="toolbar">
            ${plainBadge(item.status || "unknown")}
            ${plainBadge(`证据 ${item.evidence_count || 0}`)}
            ${plainBadge(`引用 ${item.citation_count || 0}`)}
            ${plainBadge(item.has_experiment ? "有实验" : "缺实验")}
          </div>
          <div>${escapeHtml(item.reasoning || "暂无")}</div>
        </div>
      `).join("")
      : '<div class="muted">暂无主张覆盖检查。</div>';

    const revisionBlockCards = (revisionResult.review_blocks || []).length
      ? (revisionResult.review_blocks || []).slice(0, 5).map((block) => `
        <div class="artifact-item">
          <h4>${escapeHtml(block.name || "")}</h4>
          <div class="toolbar">
            ${plainBadge(block.accepted ? "pass" : "needs fix")}
            ${plainBadge(`score ${block.score || 0}`)}
          </div>
          <div>视角: ${escapeHtml((block.aspects || []).map((aspect) => `${aspect.name}:${aspect.accepted ? 'pass' : 'fix'}`).join("；") || "暂无")}</div>
          <div>问题: ${escapeHtml((block.weaknesses || []).join("；") || "暂无")}</div>
          <div>修改项: ${escapeHtml((block.required_changes || []).join("；") || "暂无")}</div>
          <div>已处理: ${escapeHtml((block.addressed_changes || []).join("；") || "暂无")}</div>
        </div>
      `).join("")
      : '<div class="muted">暂无分块 review。</div>';
    const peerReviewCards = peerReviews.length
      ? peerReviews.map((review) => `
        <div class="artifact-item">
          <h4>${escapeHtml(review.label)}: ${escapeHtml(review.focus)}</h4>
          <div class="toolbar">
            ${plainBadge(review.recommendation)}
            ${plainBadge(`priority ${review.priority || "info"}`)}
          </div>
          <div>视角摘要: ${escapeHtml((review.aspect_summary || []).join("；") || "暂无")}</div>
          <div>证据依据: ${escapeHtml((review.evidence_basis || []).join("；") || "暂无")}</div>
          <div>优点: ${escapeHtml((review.strengths || []).join("；") || "暂无")}</div>
          <div>阻断问题: ${escapeHtml((review.blocker_issues || []).join("；") || "无")}</div>
          <div>主要顾虑: ${escapeHtml((review.major_concerns || []).join("；") || "暂无")}</div>
          <div>次要顾虑: ${escapeHtml((review.minor_concerns || []).join("；") || "暂无")}</div>
          <div>接受条件: ${escapeHtml((review.acceptance_conditions || []).join("；") || "暂无")}</div>
          <div>给作者的问题: ${escapeHtml((review.questions_for_authors || []).join("；") || "暂无")}</div>
        </div>
      `).join("")
      : '<div class="muted">暂无多审稿人视角。</div>';

    const missingCards = (evidenceAssessment.missing_dimensions || []).length
      ? (evidenceAssessment.missing_dimensions || []).slice(0, 4).map((item) => `
        <div class="artifact-item">${escapeHtml(item)}</div>
      `).join("")
      : '<div class="muted">暂无显式缺口。</div>';
    const graphClaimCards = (claimGraph.claim_nodes || []).length
      ? (claimGraph.claim_nodes || []).slice(0, 3).map((node) => `
        <div class="artifact-item">
          <h4>${escapeHtml(node.title || "")}</h4>
          <div class="toolbar">
            ${plainBadge(node.status || "unknown")}
          </div>
          <div>${escapeHtml(node.summary || "暂无")}</div>
        </div>
      `).join("")
      : '<div class="muted">暂无 claim 图谱。</div>';

    const stepCards = steps.length
      ? steps.map((step, index) => `
        <div class="artifact-item">
          <h4>${index + 1}. ${escapeHtml(step.name || "step")}</h4>
          <div class="toolbar">
            ${plainBadge(step.status || "unknown")}
          </div>
          <div>${escapeHtml(step.detail || "暂无说明。")}</div>
        </div>
      `).join("")
      : '<div class="muted">暂无运行步骤记录。</div>';

    return `
      <div class="artifact-item">
        <h3>${escapeHtml(presentation.title || "研究工作流结果")}</h3>
        <div>归档目录: ${escapeHtml(data.artifact_dir || "未保存")}</div>
        <div>研究置信度: <strong>${escapeHtml(presentation.confidence || "未知")}</strong></div>
        <div>问题定义: ${escapeHtml(selected.problem_statement || presentation.summary || "暂无")}</div>
        <div>本次耗时: ${escapeHtml(formatElapsed(data._elapsed_ms))}</div>
        <div class="toolbar">
          ${plainBadge(generationMode)}
          ${plainBadge(`门禁 ${evidenceAssessment.status || "unknown"}`)}
          ${plainBadge(`peer-review ${presentation.peer_review_status || "unknown"}`)}
          ${plainBadge(`投稿 ${publicationReadiness.status || "unknown"}`)}
          ${plainBadge(`综合 ${presentation.metrics?.composite_score || 0}`)}
          ${plainBadge(`novelty ${presentation.metrics?.novelty_score || 0}`)}
          ${downloadGeneratedLink(taskId, "peer_reviews.md", "下载审稿意见")}
          ${downloadGeneratedLink(taskId, "task_steps.md", "下载运行步骤")}
          ${downloadGeneratedLink(taskId, "paper_draft.pdf", "下载论文 PDF")}
          ${downloadGeneratedLink(taskId, "publication_readiness.md", "下载就绪度")}
          ${downloadGeneratedLink(taskId, "publication_task_design.md", "下载任务设计")}
          ${downloadGeneratedLink(taskId, "event_discovery.md", "下载事件发现")}
          ${downloadGeneratedLink(taskId, "research_bundle.zip", "下载研究包")}
          ${resultLink("research", taskId)}
        </div>
      </div>
      <div class="metric-grid">
        <div class="metric"><strong>${presentation.metrics?.idea_count || 0}</strong>研究想法数</div>
        <div class="metric"><strong>${presentation.metrics?.citation_count || 0}</strong>引用数</div>
        <div class="metric"><strong>${presentation.metrics?.novelty_score || 0}</strong>novelty</div>
        <div class="metric"><strong>${presentation.metrics?.evidence_count || 0}</strong>证据数</div>
        <div class="metric"><strong>${presentation.metrics?.experiment_design_count || 0}</strong>实验设计数</div>
        <div class="metric"><strong>${presentation.metrics?.composite_score || 0}</strong>综合评分</div>
        <div class="metric"><strong>${publicationReadiness.readiness_score || 0}</strong>投稿就绪度</div>
      </div>
      <div class="artifact-item">
        <h3>运行步骤</h3>
        <div class="list">${stepCards}</div>
      </div>
      <div class="artifact-item">
        <h3>Event Discovery</h3>
        <div>摘要: ${escapeHtml(eventDiscovery.summary || "暂无")}</div>
        <div>选中候选: ${escapeHtml(eventDiscovery.selected_title || "暂无")}</div>
        <div>来源: ${escapeHtml((eventDiscovery.sources || []).join("；") || "暂无")}</div>
        <div class="list">${eventDiscoveryCards}</div>
      </div>
      <div class="artifact-item">
        <h3>主线方向</h3>
        <div>研究假设: ${escapeHtml(selected.hypothesis || presentation.summary || "暂无")}</div>
        <div>选择理由: ${escapeHtml(selected.selection_reason || "暂无")}</div>
        <div>动机: ${escapeHtml(presentation.motivation || "暂无")}</div>
        <div>新颖性: ${escapeHtml(presentation.novelty_rationale || "暂无")}</div>
        <div>核心命题: ${escapeHtml(contributionProfile.thesis_statement || "暂无")}</div>
        ${presentation.llm_summary ? `<div>AI 执行摘要: ${escapeHtml(presentation.llm_summary)}</div>` : ""}
        ${selected.draft_abstract
          ? `<div>AI 论文摘要草案: ${escapeHtml(selected.draft_abstract)}</div>`
          : !presentation.paper_ready
            ? `<div>论文初稿状态: 当前证据门禁未通过，系统不会生成最终论文初稿。</div>`
            : ""
        }
        ${presentation.llm_error ? `<div>AI 增强状态: ${escapeHtml(presentation.llm_error)}</div>` : ""}
      </div>
      <div class="artifact-item">
        <h3>候选方向对比</h3>
        <div class="list">${candidateCards}</div>
      </div>
      <div class="artifact-item">
        <h3>投稿就绪度</h3>
        <div>状态: ${escapeHtml(publicationReadiness.status || "unknown")}</div>
        <div>评分: ${escapeHtml(publicationReadiness.readiness_score || 0)}</div>
        <div>摘要: ${escapeHtml(publicationReadiness.summary || "暂无")}</div>
        <div>Blockers: ${escapeHtml((publicationReadiness.blockers || []).join("；") || "无")}</div>
        <div>Next Actions: ${escapeHtml((publicationReadiness.next_actions || []).join("；") || "无")}</div>
      </div>
      <div class="artifact-item">
        <h3>贡献提纯</h3>
        <div>摘要: ${escapeHtml(contributionProfile.summary || "暂无")}</div>
        <div>新颖性定位: ${escapeHtml(contributionProfile.novelty_positioning || "暂无")}</div>
      </div>
      <div class="artifact-item">
        <h3>主张-证据矩阵</h3>
        <div>摘要: ${escapeHtml(claimEvidenceMatrix.summary || "暂无")}</div>
        <div>Covered: ${escapeHtml(claimEvidenceMatrix.covered_count || 0)}</div>
        <div>Partial: ${escapeHtml(claimEvidenceMatrix.partial_count || 0)}</div>
        <div>Missing: ${escapeHtml(claimEvidenceMatrix.missing_count || 0)}</div>
      </div>
      <div class="artifact-item">
        <h3>实验缺口</h3>
        <div>摘要: ${escapeHtml(experimentGapReport.summary || "暂无")}</div>
        <div>下一步: ${escapeHtml((experimentGapReport.next_best_experiments || []).join("；") || "暂无")}</div>
      </div>
      <div class="artifact-item">
        <h3>期刊适配与合规</h3>
        <div>期刊适配: ${escapeHtml(journalFitAssessment.overall_fit || "unknown")} / ${escapeHtml(journalFitAssessment.fit_score || 0)}</div>
        <div>投稿合规: ${escapeHtml(submissionCompliance.status || "unknown")}</div>
        <div>Blocker: ${escapeHtml(submissionCompliance.blocker_count || 0)}</div>
        <div>Warning: ${escapeHtml(submissionCompliance.warning_count || 0)}</div>
      </div>
      <div class="artifact-item">
        <h3>证据链</h3>
        <div class="list">${evidenceCards}</div>
      </div>
      <div class="artifact-item">
        <h3>主张矩阵摘要</h3>
        <div class="list">${(claimEvidenceMatrix.rows || []).slice(0, 3).map((row) => `
          <div class="artifact-item">
            <h4>${escapeHtml(row.claim || "")}</h4>
            <div class="toolbar">${plainBadge(row.status || "unknown")}</div>
            <div>证据: ${escapeHtml((row.evidence_refs || []).join("；") || "暂无")}</div>
            <div>实验: ${escapeHtml((row.experiment_refs || []).join("；") || "暂无")}</div>
            <div>缺口: ${escapeHtml(row.primary_gap || "无")}</div>
          </div>
        `).join("") || '<div class="muted">暂无主张矩阵。</div>'}</div>
      </div>
      <div class="artifact-item">
        <h3>证据门禁</h3>
        <div>结论: ${escapeHtml(evidenceAssessment.summary || "暂无")}</div>
        <div>评分: ${escapeHtml(String(evidenceAssessment.score || 0))}</div>
        <div>LLM 审查: ${escapeHtml(evidenceAssessment.llm_verdict || "未启用")}</div>
      </div>
      <div class="artifact-item">
        <h3>Claim 图谱摘要</h3>
        <div>${escapeHtml(claimGraph.summary || "暂无")}</div>
        <div>主张: ${escapeHtml(claimGraph.stats?.claim_count || 0)}</div>
        <div>证据: ${escapeHtml(claimGraph.stats?.evidence_count || 0)}</div>
        <div>关系边: ${escapeHtml(claimGraph.stats?.edge_count || 0)}</div>
      </div>
      <div class="artifact-item">
        <h3>主张覆盖检查</h3>
        <div class="list">${claimCheckCards}</div>
      </div>
      <div class="artifact-item">
        <h3>Claim 节点</h3>
        <div class="list">${graphClaimCards}</div>
      </div>
      <div class="artifact-item">
        <h3>关键引用</h3>
        <div class="list">${citationCards}</div>
      </div>
      <div class="artifact-item">
        <h3>攻击事件证据包</h3>
        <div class="list">${incidentPackageCards}</div>
      </div>
      <div class="artifact-item">
        <h3>引用校验</h3>
        <div>摘要: ${escapeHtml(referenceValidation.summary || "暂无")}</div>
        <div>接受: ${escapeHtml(referenceValidation.accepted_count || 0)}</div>
        <div>拒绝: ${escapeHtml(referenceValidation.rejected_count || 0)}</div>
      </div>
      <div class="artifact-item">
        <h3>论文修订评审</h3>
        <div>状态: ${escapeHtml(revisionResult.status || "not_reviewed")}</div>
        <div>评分: ${escapeHtml(revisionResult.final_score || 0)}</div>
        <div>轮数: ${escapeHtml(revisionResult.rounds || 0)}</div>
        <div class="list">${revisionBlockCards}</div>
      </div>
      <div class="artifact-item">
        <h3>多审稿人 Review</h3>
        <div class="list">${peerReviewCards}</div>
      </div>
      <div class="artifact-item">
        <h3>Publication Task Design</h3>
        <div>${escapeHtml(publicationTaskDesign.summary || "暂无")}</div>
        <div class="list">${publicationTaskCards}</div>
      </div>
      <div class="artifact-item">
        <h3>实验设计摘要</h3>
        <div class="list">${experimentCards}</div>
      </div>
      <div class="artifact-item">
        <h3>交付物</h3>
        <div class="list">${deliverableCards}</div>
      </div>
      <div class="artifact-item">
        <h3>风险与边界</h3>
        <div class="list">${riskCards}</div>
      </div>
      <div class="artifact-item">
        <h3>证据缺口</h3>
        <div class="list">${missingCards}</div>
      </div>
    `;
  }

  function renderDeepAnalysisResult(data) {
    const payload = data.deep_analysis || {};
    const summary = payload.ast_summary || {};
    return `
      <div class="artifact-item">
        <h3>深分析结果</h3>
        <div>目标: ${escapeHtml(payload.target || "未知")}</div>
        <div>本次耗时: ${escapeHtml(formatElapsed(data._elapsed_ms))}</div>
        <div>入口函数数: ${(summary.public_entrypoints || []).length}</div>
        <div>跨合约调用边: ${(summary.cross_contract_call_edges || []).length}</div>
        <div>状态冲突: ${(summary.state_conflicts || []).length}</div>
        <div>外部调用后写状态函数: ${escapeHtml((summary.write_after_external_functions || []).join("，") || "暂无")}</div>
        <div>风险提示: ${escapeHtml((payload.risk_hints || []).join("；") || "暂无")}</div>
      </div>
    `;
  }

  function renderMonitoringResult(data) {
    const result = data.monitoring_result || {};
    const discoveries = result.discovered_contracts || [];
    return `
      <div class="artifact-item">
        <h3>链上监控结果</h3>
        <div>扫描范围: ${escapeHtml(`${result.from_block ?? "?"} - ${result.to_block ?? "?"}`)}</div>
        <div>发现合约数: ${discoveries.length}</div>
        <div>自动审计任务: ${(result.auto_audit_task_ids || []).length}</div>
        <div>最新游标: ${escapeHtml(result.cursor_block ?? "暂无")}</div>
      </div>
      <div class="metric-grid">
        <div class="metric"><strong>${(result.indexed_blocks || []).length}</strong>索引区块</div>
        <div class="metric"><strong>${(result.indexed_transactions || []).length}</strong>索引交易</div>
        <div class="metric"><strong>${(result.indexed_logs || []).length}</strong>索引日志</div>
      </div>
    `;
  }

  function showResult(data) {
    byId("result-raw").textContent = JSON.stringify(data, null, 2);

    if (data.error) {
      byId("result-viewer").innerHTML = `
        <div class="artifact-item">
          <h3>任务执行失败</h3>
          <div>${escapeHtml(String(data.error))}</div>
          <div>耗时: ${escapeHtml(formatElapsed(data._elapsed_ms))}</div>
        </div>
      `;
      return;
    }

    if (data.task_result?.task_type === "audit") {
      byId("result-viewer").innerHTML = renderAuditResult(data);
      return;
    }
    if (data.task_result?.task_type === "research") {
      byId("result-viewer").innerHTML = renderResearchResult(data);
      return;
    }
    if (data.deep_analysis) {
      byId("result-viewer").innerHTML = renderDeepAnalysisResult(data);
      return;
    }
    if (data.monitoring_result) {
      byId("result-viewer").innerHTML = renderMonitoringResult(data);
      return;
    }
    byId("result-viewer").innerHTML = `<pre>${escapeHtml(JSON.stringify(data, null, 2))}</pre>`;
  }

  function renderArtifactPreview(fileName, fileText) {
    byId("artifact-preview").innerHTML = `
      <div class="artifact-item">
        <h3>文件预览</h3>
        <div>文件名: ${escapeHtml(fileName)}</div>
      </div>
      <pre>${escapeHtml(fileText)}</pre>
    `;
  }

  async function submitAudit() {
    try {
      await runWithFeedback("audit-submit", "正在运行审计任务", async () =>
        requestJson("/api/v1/audit", {
          method: "POST",
          body: JSON.stringify({
            target: byId("audit-target").value,
            analyzers: byId("audit-analyzers").value,
            severity: byId("audit-severity").value,
            save_artifacts: byId("audit-save").checked,
          }),
        })
      , [
        "正在接入目标合约与目录结构...",
        "正在执行静态分析与深语义分析...",
        "正在聚合历史案例与编写审计结果...",
      ]);
      await loadArtifacts();
    } catch (_error) {
      return;
    }
  }

  async function submitResearch() {
    try {
      await runWithFeedback("research-submit", "正在运行研究任务", async () =>
        requestJson("/api/v1/research", {
          method: "POST",
          body: JSON.stringify({
            incident_id: byId("research-incident-id").value.trim() || null,
            candidate_id: byId("research-candidate-id") ? byId("research-candidate-id").value.trim() || null : null,
            target: byId("research-target").value,
            analyzers: byId("research-analyzers").value,
            severity: byId("research-severity").value,
            save_artifacts: byId("research-save").checked,
          }),
        })
      , [
        "正在生成基础审计结果与结构信号...",
        "正在排序候选研究方向并构建证据链...",
        "正在整理相关工作、实验设计与论文初稿...",
      ]);
      await loadArtifacts();
    } catch (_error) {
      return;
    }
  }

  async function runDeepAnalysis() {
    try {
      const data = await runWithFeedback("deep-submit", "正在运行深分析", async () =>
        requestJson("/api/v1/analysis/deep", {
          method: "POST",
          body: JSON.stringify({
            target: byId("deep-target").value,
          }),
        })
      , [
        "正在解析 AST 结构...",
        "正在提取跨合约边与状态冲突...",
        "正在生成风险提示摘要...",
      ]);
      const summary = data.deep_analysis.ast_summary || {};
      byId("deep-analysis-list").innerHTML = `
        <div class="artifact-item">
          <h4>目标</h4>
          <div>${escapeHtml(data.deep_analysis.target || "未知")}</div>
          <div>入口函数数: ${(summary.public_entrypoints || []).length}</div>
          <div>跨合约调用边: ${(summary.cross_contract_call_edges || []).length}</div>
          <div>状态冲突: ${(summary.state_conflicts || []).length}</div>
          <div>外部调用后写状态函数: ${escapeHtml((summary.write_after_external_functions || []).join("，") || "暂无")}</div>
          <div>风险提示: ${escapeHtml((data.deep_analysis.risk_hints || []).join("；") || "暂无")}</div>
        </div>
      `;
    } catch (_error) {
      return;
    }
  }

  function detailUrl(taskId, taskType) {
    return taskType === "research"
      ? `/research/${encodeURIComponent(taskId)}`
      : `/audit/${encodeURIComponent(taskId)}`;
  }

  async function previewArtifact(taskId) {
    const artifact = await requestJson(`/api/v1/artifacts/${encodeURIComponent(taskId)}`);
    const files = artifact.files || [];
    const generatedFiles = artifact.generated_files || [];
    const priority = [
      "research_memo.md",
      "paper_draft.md",
      "audit_report.md",
      "research_presentation.json",
      "llm_enhancement.json",
      "research_result.json",
      "experiment_plan.json",
      "citations.json",
      "research_ideas.json",
      "incident_evidence_packages.json",
      "task_result.json",
    ];
    const preferredGeneratedFile = priority.find((name) => generatedFiles.includes(name));
    const preferredFile = priority.find((name) => files.includes(name))
      || files.find((name) => name !== "task_result.json")
      || "task_result.json";
    const previewUrl = preferredGeneratedFile
      ? `/api/v1/artifacts/${encodeURIComponent(taskId)}/generated/${encodeURIComponent(preferredGeneratedFile)}`
      : `/api/v1/artifacts/${encodeURIComponent(taskId)}/file/${encodeURIComponent(preferredFile)}`;
    const response = await fetch(previewUrl);
    const fileText = await response.text();
    renderArtifactPreview(preferredGeneratedFile || preferredFile, fileText);
  }

  function openArtifact(taskId, taskType) {
    window.open(detailUrl(taskId, taskType), "_blank");
  }

  async function loadArtifacts() {
    const data = await requestJson("/api/v1/artifacts");
    const container = byId("artifact-list");
    container.innerHTML = "";

    for (const artifact of data.artifacts || []) {
      const div = document.createElement("div");
      div.className = "artifact-item";
      div.innerHTML = `
        <h4>${escapeHtml(artifact.task_id)}</h4>
        <div>类型: ${escapeHtml(artifact.task_type)}</div>
        <div>目标: ${escapeHtml(artifact.target)}</div>
        <div>状态: ${escapeHtml(artifact.status)}</div>
        <div>创建时间: ${escapeHtml(artifact.created_at)}</div>
        <div>文件: ${escapeHtml((artifact.files || []).join(", "))}</div>
        <div>现场生成: ${escapeHtml((artifact.generated_files || []).join(", "))}</div>
        <div class="toolbar">
          <button type="button" data-action="open">查看详情</button>
          <button type="button" data-action="preview">预览工件</button>
        </div>
      `;

      const [openButton, previewButton] = div.querySelectorAll("button");
      openButton.addEventListener("click", () => openArtifact(artifact.task_id, artifact.task_type));
      previewButton.addEventListener("click", async () => {
        try {
          await previewArtifact(artifact.task_id);
        } catch (error) {
          showResult({ error: String(error) });
        }
      });
      container.appendChild(div);
    }

    if (!container.children.length) {
      container.innerHTML = '<div class="muted">暂无归档结果。</div>';
    }
  }

  async function runMonitor() {
    try {
      await runWithFeedback("monitor-submit", "正在运行链上监控", async () =>
        requestJson("/api/v1/monitor/scan", {
          method: "POST",
          body: JSON.stringify({
            mode: byId("monitor-mode").value,
            block_count: Number(byId("monitor-block-count").value || "3"),
            save_to_db: byId("monitor-save-db").checked,
          }),
        })
      , [
        "正在拉取链上区块与交易...",
        "正在解析日志、签名与合约创建记录...",
        "正在写入索引结果并刷新发现列表...",
      ]);
      await loadDiscoveries();
      await loadIndexerStatus();
    } catch (_error) {
      return;
    }
  }

  async function loadDiscoveries() {
    const data = await requestJson("/api/v1/discoveries");
    const container = byId("discovery-list");
    container.innerHTML = "";

    for (const item of data.discoveries || []) {
      const div = document.createElement("div");
      div.className = "artifact-item";
      div.innerHTML = `
        <h4>${escapeHtml(item.address)}</h4>
        <div>区块: ${escapeHtml(item.block_number)}</div>
        <div>创建者: ${escapeHtml(item.creator)}</div>
        <div>交易: ${escapeHtml(item.tx_hash)}</div>
      `;
      container.appendChild(div);
    }

    if (!container.children.length) {
      container.innerHTML = '<div class="muted">暂无链上发现记录。</div>';
    }
  }

  async function loadIndexerStatus() {
    const data = await requestJson("/api/v1/indexer/status", {
      method: "POST",
      body: JSON.stringify({}),
    });

    const status = data.status || {};
    byId("indexer-status").innerHTML = `
      <div class="artifact-item">
        <h4>游标状态</h4>
        <div>cursor_block: ${escapeHtml(status.cursor_block ?? "暂无")}</div>
        <div>latest_indexed_block: ${escapeHtml(status.latest_indexed_block ?? "暂无")}</div>
        <div>indexed_block_count: ${escapeHtml(status.indexed_block_count ?? 0)}</div>
        <div>indexed_transaction_count: ${escapeHtml(status.indexed_transaction_count ?? 0)}</div>
        <div>indexed_log_count: ${escapeHtml(status.indexed_log_count ?? 0)}</div>
      </div>
    `;

    const runContainer = byId("index-run-list");
    runContainer.innerHTML = "";
    for (const run of data.recent_runs || []) {
      const div = document.createElement("div");
      div.className = "artifact-item";
      div.innerHTML = `
        <h4>${escapeHtml(run.run_id)}</h4>
        <div>mode: ${escapeHtml(run.mode)}</div>
        <div>blocks: ${escapeHtml(`${run.from_block} - ${run.to_block}`)}</div>
        <div>tx: ${escapeHtml(run.indexed_transaction_count)}</div>
        <div>logs: ${escapeHtml(run.indexed_log_count)}</div>
        <div>discoveries: ${escapeHtml(run.discovered_contract_count)}</div>
        <div>status: ${escapeHtml(run.status)}</div>
      `;
      runContainer.appendChild(div);
    }
    if (!runContainer.children.length) {
      runContainer.innerHTML = '<div class="muted">暂无索引运行记录。</div>';
    }

    const blockContainer = byId("indexed-block-list");
    blockContainer.innerHTML = "";
    for (const block of data.recent_blocks || []) {
      const div = document.createElement("div");
      div.className = "artifact-item";
      div.innerHTML = `
        <h4>Block #${escapeHtml(block.block_number)}</h4>
        <div>tx_count: ${escapeHtml(block.tx_count)}</div>
        <div>timestamp: ${escapeHtml(block.timestamp)}</div>
      `;
      blockContainer.appendChild(div);
    }
    if (!blockContainer.children.length) {
      blockContainer.innerHTML = '<div class="muted">暂无索引区块。</div>';
    }

    const txContainer = byId("indexed-transaction-list");
    txContainer.innerHTML = "";
    for (const tx of data.recent_transactions || []) {
      const div = document.createElement("div");
      div.className = "artifact-item";
      div.innerHTML = `
        <h4>${escapeHtml(tx.tx_hash)}</h4>
        <div>block: ${escapeHtml(tx.block_number)}</div>
        <div>selector: ${escapeHtml(tx.selector_name || tx.selector || "暂无")}</div>
        <div>contract_creation: ${escapeHtml(tx.is_contract_creation)}</div>
      `;
      txContainer.appendChild(div);
    }
    if (!txContainer.children.length) {
      txContainer.innerHTML = '<div class="muted">暂无索引交易。</div>';
    }

    const logContainer = byId("indexed-log-list");
    logContainer.innerHTML = "";
    for (const log of data.recent_logs || []) {
      const div = document.createElement("div");
      div.className = "artifact-item";
      div.innerHTML = `
        <h4>${escapeHtml(log.address)}</h4>
        <div>block: ${escapeHtml(log.block_number)}</div>
        <div>topic0: ${escapeHtml(log.topic0_name || log.topic0 || "暂无")}</div>
        <div>topic_count: ${escapeHtml(log.topic_count)}</div>
      `;
      logContainer.appendChild(div);
    }
    if (!logContainer.children.length) {
      logContainer.innerHTML = '<div class="muted">暂无索引日志。</div>';
    }
  }

  async function searchIncidents() {
    try {
      const data = await requestJson("/api/v1/incidents/search", {
        method: "POST",
        body: JSON.stringify({
          query: byId("incident-query").value,
          limit: 10,
        }),
      });

      const container = byId("incident-list");
      container.innerHTML = "";
      for (const incident of data.incidents || []) {
        const div = document.createElement("div");
        div.className = "artifact-item";
        div.innerHTML = `
          <h4>${escapeHtml(incident.title)}</h4>
          <div>协议: ${escapeHtml(incident.protocol_name)}</div>
          <div>类型: ${escapeHtml(incident.protocol_type)}</div>
          <div>年份: ${escapeHtml(incident.year)}</div>
          <div>摘要: ${escapeHtml(incident.summary)}</div>
        `;
        container.appendChild(div);
      }

      if (!container.children.length) {
        container.innerHTML = '<div class="muted">没有匹配案例。</div>';
      }

      byId("result-viewer").innerHTML = `
        <div class="artifact-item">
          <h3>历史案例搜索完成</h3>
          <div>关键词: ${escapeHtml(data.query)}</div>
          <div>命中数量: ${(data.incidents || []).length}</div>
        </div>
      `;
      byId("result-raw").textContent = JSON.stringify(data, null, 2);
    } catch (error) {
      showResult({ error: String(error) });
    }
  }

  async function hydrateIncidentEvidence() {
    try {
      const data = await runWithFeedback(
        "incident-hydrate-submit",
        "正在同步历史攻击事件链上证据",
        async () =>
          requestJson("/api/v1/incidents/hydrate", {
            method: "POST",
            body: JSON.stringify({
              incident_id: byId("incident-hydrate-id").value.trim() || null,
              save_to_db: true,
            }),
          }),
        [
          "正在读取已配置的历史攻击案例...",
          "正在通过 RPC 拉取攻击交易、receipt 与日志...",
          "正在写入索引并重建攻击事件证据包...",
        ]
      );

      const result = data.incident_hydration || {};
      const packages = result.evidence_packages || [];
      const container = byId("incident-list");
      container.innerHTML = "";
      for (const pkg of packages) {
        const div = document.createElement("div");
        div.className = "artifact-item";
        div.innerHTML = `
          <h4>${escapeHtml(pkg.title || "")}</h4>
          <div>链: ${escapeHtml(pkg.chain || "unknown")}</div>
          <div>关键交易数: ${escapeHtml((pkg.attack_transactions || []).length)}</div>
          <div>已索引交易: ${escapeHtml(pkg.indexed_transaction_count || 0)}</div>
          <div>已索引日志: ${escapeHtml(pkg.indexed_log_count || 0)}</div>
          <div>缺失工件: ${escapeHtml((pkg.missing_artifacts || []).join("；") || "无")}</div>
        `;
        container.appendChild(div);
      }

      if (!container.children.length) {
        container.innerHTML = '<div class="muted">没有可同步的攻击交易锚点。</div>';
      }
      return data;
    } catch (_error) {
      return;
    }
  }

  async function discoverIncidents() {
    try {
      const data = await runWithFeedback(
        "incident-discover-submit",
        "正在发现外部攻击事件",
        async () =>
          requestJson("/api/v1/incidents/discover", {
            method: "POST",
            body: JSON.stringify({
              limit: Number(byId("discover-limit").value || "10"),
            }),
          }),
        [
          "正在读取 SlowMist 最新事件页...",
          "正在提取目标、摘要、损失与攻击方法...",
          "正在按研究相关性排序候选事件...",
        ]
      );

      const container = byId("incident-discovery-list");
      container.innerHTML = "";
      for (const candidate of data.candidates || []) {
        const div = document.createElement("div");
        div.className = "artifact-item";
        div.innerHTML = `
          <h4>${escapeHtml(candidate.title || "")}</h4>
          <div class="toolbar">
            ${plainBadge(candidate.source || "source")}
            ${plainBadge(`相关性 ${candidate.relevance_score || 0}`)}
            ${plainBadge(candidate.protocol_type_guess || "unknown")}
          </div>
          <div>日期: ${escapeHtml(candidate.discovered_at || "未知")}</div>
          <div>攻击方法: ${escapeHtml(candidate.attack_method || "未知")}</div>
          <div>损失: ${escapeHtml(candidate.loss_text || "未知")}</div>
          <div>建议类别: ${escapeHtml((candidate.suggested_categories || []).join("；") || "暂无")}</div>
          <div>${escapeHtml(candidate.summary || "")}</div>
          ${candidate.reference_url ? `<div><a href="${escapeHtml(candidate.reference_url)}" target="_blank">参考链接</a></div>` : ""}
          <div class="toolbar">
            <button type="button" data-action="candidate-research">用此事件跑研究</button>
          </div>
        `;
        div.querySelector('[data-action="candidate-research"]').addEventListener("click", () => {
          byId("research-candidate-id").value = candidate.candidate_id || "";
          byId("research-incident-id").value = "";
          byId("research-target").value = "";
          byId("research-analyzers").value = "";
          showResult({
            note: `已选择候选事件 ${candidate.candidate_id}，可直接运行研究任务。`,
          });
        });
        container.appendChild(div);
      }

      if (!container.children.length) {
        container.innerHTML = '<div class="muted">没有发现满足阈值的候选事件。</div>';
      }
      return data;
    } catch (_error) {
      return;
    }
  }

  function bindEvents() {
    byId("audit-submit").addEventListener("click", submitAudit);
    byId("research-submit").addEventListener("click", submitResearch);
    byId("deep-submit").addEventListener("click", runDeepAnalysis);
    byId("monitor-submit").addEventListener("click", runMonitor);
    byId("incident-discover-submit").addEventListener("click", discoverIncidents);
    byId("incident-submit").addEventListener("click", searchIncidents);
    byId("incident-hydrate-submit").addEventListener("click", hydrateIncidentEvidence);
    byId("artifact-refresh").addEventListener("click", loadArtifacts);
    byId("discovery-refresh").addEventListener("click", loadDiscoveries);
    byId("indexer-refresh").addEventListener("click", loadIndexerStatus);
  }

  async function init() {
    bindEvents();
    await loadArtifacts();
    await loadDiscoveries();
    await loadIndexerStatus();
  }

  document.addEventListener("DOMContentLoaded", () => {
    init().catch((error) => {
      showResult({ error: String(error) });
    });
  });
})();
