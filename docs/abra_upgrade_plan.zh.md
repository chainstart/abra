# 从 Blockchain-Security 工具箱升级到 ABRA 区块链研究智能体

日期：2026-05-18

状态：草案

## 1. 结论

当前 `abra` 更准确的定位是“区块链安全研究工具箱 / 领域实验室”，还不能算一个完整智能体。

它已经具备：

- Solidity 静态分析工具。
- DeFi incident 数据管线。
- Foundry fork replay 测试。
- 安全报告、事件卡片和论文材料。
- 可被外部 ARA 系统调用的实验能力。

但它还缺少一个真正的 agent 层：

- 没有持续的 plan -> act -> observe -> reflect 循环。
- 没有统一工具注册表。
- 没有 agent 自己维护的长期记忆。
- 没有证据分级 evaluator。
- 没有根据失败结果自动调整研究路线的策略。
- 没有多 agent 分工和资源调度。

因此推荐的升级方向是：

> 保留 `abra` 作为领域实验室仓库，在原仓库内新增 `ABRA` agent 层。短期不建议新建干净仓库，也不建议直接把仓库改名为 `abra`。

`ABRA` 可以作为系统名使用，建议含义为：

> Automated Blockchain Research Agents

## 2. 是否新建仓库

### 2.1 推荐方案：原仓库内重构

短期推荐在 `abra` 原仓库内重构，而不是新建一个干净仓库。

理由：

- 现有工具、数据、报告、replay 测试和 paper artifact 都在这个仓库内，agent 的“环境”就在这里。
- 区块链安全研究强依赖本地 Foundry、合约、事件数据、RPC 配置和 replay 产物；拆到新仓库会增加路径、依赖和 artifact 同步成本。
- 当前最缺的是 agent loop、tool registry、memory 和 evaluator，不是一个空白工程。
- 原仓库已经可以被 `ara` 作为外部实验室调用，继续增强这个边界更自然。
- 新建仓库容易形成“干净但脱离真实实验环境”的 agent 壳。

推荐做法是：

```text
abra/
  abra/                  # 新增：ABRA agent 层
  tools/                 # 保留：领域工具箱
  test/replay/           # 保留：Foundry replay
  data/                  # 保留：事件数据
  reports/               # 保留：研究报告
  findings/              # 保留：审计发现
  paper/                 # 保留：论文材料
  research_lab.yaml      # 新增：供 ARA 等外部系统调用
```

### 2.2 什么时候才适合新建仓库

只有满足以下条件时，才考虑把 ABRA agent 层拆成独立仓库：

- `abra/` agent 层已经稳定，有清楚的 CLI、schema 和 tool protocol。
- `abra` 已经有稳定的 `research_lab.yaml` 和 artifact contract。
- ABRA 需要同时调度多个不同区块链安全实验室，而不只是当前这个仓库。
- ABRA 的 agent 逻辑已经足够通用，可以脱离具体 Foundry 工程和数据目录运行。
- 原仓库中的实验工具和 agent 层出现明显发布节奏冲突。

未来可能演化为：

```text
abra-agent/              # 独立智能体编排层
abra/     # 默认领域实验室
other-security-labs/     # 其他可被 ABRA 调用的实验室
```

但这应该是第二阶段或第三阶段的拆分，不是现在的第一步。

## 3. 目标定义

ABRA 不应该只是把现有脚本包装成 CLI。它应该是一个能够自主开展区块链安全研究的 agent 系统。

一个最小可用 ABRA 应满足：

- 能读取研究目标，例如“复现 Euler incident”或“找出 oracle 依赖高风险协议”。
- 能根据目标制定当前轮计划。
- 能从工具注册表选择工具。
- 能执行工具并观察 stdout、stderr、artifact 和状态码。
- 能根据结果调整下一步动作。
- 能记录中间产物、失败原因、证据级别和后续任务。
- 能区分静态告警、可复现实验、fork replay 和人工审计判断。
- 能输出可被 ARA 写论文或报告使用的 evidence bundle。

目标不是一开始就做完全自主的“黑箱攻击智能体”。更现实的目标是：

> 让 ABRA 成为一个以证据为中心、可复现、可审计的区块链安全研究 agent。

## 4. 目标架构

### 4.1 分层

推荐分为六层：

```text
User / ARA / Scheduler
  -> ABRA CLI
  -> Agent Loop
  -> Tool Registry
  -> Domain Tools
  -> Execution Environment
  -> Evidence / Memory Store
```

各层职责：

- ABRA CLI：接收目标、预算、模式和输出目录。
- Agent Loop：执行 plan -> act -> observe -> reflect 循环。
- Tool Registry：声明工具能力、输入 schema、安全限制、输出 schema。
- Domain Tools：现有 scanner、pipeline、replay runner、report generator。
- Execution Environment：Python、Foundry、RPC、文件系统和外部命令。
- Evidence / Memory Store：长期保存事件、协议、发现、replay、失败原因和可信度。

### 4.2 推荐目录结构

```text
abra/
  abra/
    __init__.py
    cli.py
    agent_loop.py
    state.py
    budgets.py
    tool_registry.py
    command_runner.py
    evidence.py
    memory.py
    schemas.py
    prompts/
      planner.md
      critic.md
      report_writer.md
    agents/
      incident_scout.py
      static_analysis_agent.py
      replay_agent.py
      evidence_reviewer.py
      report_agent.py
    tools/
      scanner_tool.py
      pipeline_tool.py
      replay_tool.py
      report_tool.py
      file_tool.py
    evaluators/
      evidence_evaluator.py
      feasibility_evaluator.py
      novelty_evaluator.py
  tools/
    scanner.py
    replay_runner.py
    analyzers/
    pipeline/
  memory/
    incidents/
    protocols/
    findings/
    replay_runs/
    failed_routes/
  reports/
  findings/
  test/replay/
  research_lab.yaml
  docs/
```

`tools/` 继续是低层工具箱；`abra/` 是智能体层。两者不要混在一起。

## 5. Agent Loop 设计

ABRA 的核心循环应该接近纯 agent，而不是固定流水线。

最小循环：

```text
while budget remains:
  observe current state and artifacts
  plan next useful action
  select tool from registry
  execute tool with guarded runner
  parse observations
  update evidence and memory
  evaluate progress
  decide continue / pivot / stop
```

建议每轮记录：

- 当前目标。
- 当前假设。
- 选择的工具。
- 工具输入。
- 工具输出摘要。
- 新增 artifact。
- 新增 evidence。
- 新 blocker。
- 下一步计划。
- 是否值得继续。

每次运行应产生：

```text
runs/<run-id>/
  run_state.json
  event_log.jsonl
  tool_calls.jsonl
  observations.jsonl
  evidence_bundle.json
  artifact_manifest.json
  final_report.md
```

## 6. 工具注册表

现有工具不应该让 LLM 任意 shell 调用。应先注册成结构化工具。

示例：

```yaml
tools:
  scan_contracts:
    command: "python3 tools/scanner.py"
    description: "Run Solidity static analyzers on selected contract paths."
    inputs:
      contract_path: string
      output_format: ["json", "md"]
    outputs:
      - findings_json
      - findings_markdown
    safety:
      read_only: true

  run_replay:
    command: "forge test --match-path"
    description: "Run a Foundry replay test for a selected incident."
    inputs:
      test_path: string
      rpc_env: string
    outputs:
      - forge_log
      - replay_summary_json
    safety:
      requires_rpc: true
      disallow_broadcast: true
```

第一阶段建议注册这些工具：

- `scan_contracts`
- `run_incident_pipeline`
- `generate_event_cards`
- `select_replay_candidates`
- `run_replay_test`
- `summarize_replay_results`
- `generate_report`
- `read_artifact`
- `write_note`

## 7. 证据模型

ABRA 的关键不是“发现很多问题”，而是准确区分证据等级。

建议 evidence levels：

```text
L0 hypothesis
  只是研究假设或 agent 猜想。

L1 static_alert
  静态分析告警，尚未复现。

L2 source_confirmed
  源码级人工或工具确认，仍未运行复现。

L3 local_reproduced
  本地 deterministic test 复现。

L4 fork_replayed
  使用 fork / archive RPC replay 成功。

L5 externally_correlated
  与链上交易、事件报告或公开资料交叉验证。

L6 audit_ready
  证据、影响、根因、复现和缓解建议完整，可进入审计报告或论文。
```

每条 finding 应至少包含：

```json
{
  "finding_id": "oracle-risk-001",
  "title": "Oracle dependency risk in protocol X",
  "protocol": "Protocol X",
  "evidence_level": "L1 static_alert",
  "claims": [],
  "artifacts": [],
  "reproduction": {
    "status": "not_attempted",
    "commands": []
  },
  "limitations": [],
  "next_actions": []
}
```

这个模型能防止把静态告警误写成真实漏洞。

## 8. 长期记忆

ABRA 的 memory 应服务于未来研究复用，而不是只保存一次运行日志。

建议长期目录：

```text
memory/
  incidents/
    euler-finance.json
    bonqdao.json
  protocols/
    aave.json
    compound.json
    morpho.json
  findings/
    oracle-risk-ledger.jsonl
    reentrancy-ledger.jsonl
  replay_runs/
    replay-run-ledger.jsonl
  failed_routes/
    archive-rpc-blockers.jsonl
    unavailable-contract-state.jsonl
  tool_performance/
    scanner-quality.jsonl
    replay-success-rate.jsonl
```

每个失败也要保存：

- 失败命令。
- 错误输出。
- 环境条件。
- 是否是 RPC 问题。
- 是否是测试设计问题。
- 后续可行替代方案。

这能让 ABRA 下次遇到类似事件时，不再重复走已经失败的路线。

## 9. 多 Agent 分工

ABRA 不应只有一个全能 agent。推荐最小多 agent 分工：

### 9.1 Incident Scout

职责：

- 从 incident 数据中筛选候选事件。
- 估计复现价值、数据可得性和难度。
- 给 replay agent 提供候选清单。

### 9.2 Static Analysis Agent

职责：

- 选择合约或协议。
- 调用 scanner。
- 聚合同类告警。
- 去重和初步排序。

### 9.3 Replay Agent

职责：

- 选择 replay 目标。
- 调用 Foundry 测试。
- 判断失败原因。
- 提出下一轮 replay 修改建议。

### 9.4 Evidence Reviewer

职责：

- 独立评估 finding 的证据等级。
- 拒绝夸大结论。
- 标记缺失证据。
- 判断是否达到 audit-ready 或 paper-ready。

### 9.5 Report Agent

职责：

- 把 verified evidence 组织成报告。
- 生成 artifact manifest。
- 给 ARA 或人工研究者提供 writing brief。

证明器和评估器分离的原则，在这里也适用：发现问题的 agent 容易乐观，reviewer 必须独立。

## 10. 与 ARA 的关系

ARA 仍应是论文和通用科研流程层；ABRA 是区块链安全研究智能体。

推荐关系：

```text
ARA
  -> 调用 ABRA CLI 或 abra/research_lab.yaml
  -> 获取 evidence_bundle.json、artifact_manifest.json、final_report.md
  -> 生成论文、审稿、返修

ABRA
  -> 调用 abra 内部工具
  -> 生成 evidence bundle
  -> 不负责通用论文流水线
```

也就是说，ARA 不需要理解每个 Solidity analyzer 的内部细节；它只需要理解 ABRA 输出的 evidence bundle。

## 11. 开发路线

### 阶段 0：保留现状，建立边界

目标：明确 `abra` 是实验室，ABRA 是新增 agent 层。

任务：

- 保留仓库名 `abra`。
- 在 README 中增加 ABRA roadmap。
- 新增 `docs/abra_upgrade_plan.zh.md`。
- 不移动现有工具、报告和测试。

完成标准：

- 仓库角色清楚。
- 不破坏现有 scanner、pipeline、Foundry replay。

### 阶段 1：加 manifest 和 tool registry

目标：让工具箱具备被 agent 安全调用的接口。

任务：

- 新增 `research_lab.yaml`。
- 新增 `abra/tool_registry.py`。
- 为 scanner、pipeline、replay runner 写 wrapper。
- 定义每个工具的输入、输出、artifact 和安全限制。
- 引入统一 `artifact_manifest.json`。

完成标准：

- ABRA 可以列出可用工具。
- 每个工具调用都有结构化记录。
- ARA 可以读取 manifest 并安全调用实验。

### 阶段 2：实现最小 Agent Loop

目标：从工具箱升级为最小可运行 agent。

任务：

- 新增 `abra/agent_loop.py`。
- 新增 `abra/cli.py`。
- 支持目标、预算、最大轮数、输出目录。
- 每轮执行 observe、plan、act、reflect。
- 每轮写入 `event_log.jsonl` 和 `tool_calls.jsonl`。

示例 CLI：

```bash
python3 -m abra run \
  --goal "Evaluate replay feasibility for Euler Finance incident" \
  --budget-minutes 60 \
  --out runs/euler-feasibility-001
```

完成标准：

- 给定一个目标，ABRA 能自主选择至少 2 类工具并根据结果调整下一步。
- 运行结束后有完整 run state 和 final report。

### 阶段 3：建立证据和记忆系统

目标：让 ABRA 的结论可复用、可审计。

任务：

- 新增 `abra/evidence.py`。
- 新增 `abra/memory.py`。
- 定义 finding schema。
- 定义 evidence level。
- 把 replay 成功、失败、RPC blocker、静态告警都写入长期 ledger。

完成标准：

- 每个 finding 都有 evidence level。
- 每次失败都被分类保存。
- 下一次运行能读取过去 blocker 和成功路线。

### 阶段 4：多 Agent 分工

目标：提升研究质量，避免单一 agent 自我确认。

任务：

- 实现 Incident Scout。
- 实现 Static Analysis Agent。
- 实现 Replay Agent。
- 实现 Evidence Reviewer。
- 实现 Report Agent。
- 让 reviewer 独立读 evidence bundle，不共享 planner 的即时上下文。

完成标准：

- Agent 能并行或串行处理多个 incident。
- Evidence Reviewer 能降级不充分的 claim。
- Report Agent 只写证据支持的结论。

### 阶段 5：与 ARA 稳定集成

目标：让 ARA 调用 ABRA 产出论文级材料。

任务：

- ABRA 输出 `evidence_bundle.json`。
- ABRA 输出 `writing_brief.md`。
- ARA 外部实验模块读取 ABRA artifact。
- ARA 写作阶段区分 evidence level。

完成标准：

- ARA 可以基于 ABRA 结果写论文。
- 论文不会把 L1 静态告警写成 L4 fork replay。
- 每个图表、表格和 claim 都能追溯到 artifact。

### 阶段 6：再评估是否拆仓库

目标：判断 ABRA 是否需要独立发布。

拆分条件：

- ABRA 已经能调度多个实验室。
- 当前仓库内 agent 层和领域工具层发布节奏冲突。
- 其他项目需要复用 ABRA agent，而不需要 `abra` 的具体数据和 Foundry 工程。

如果满足，再新建：

```text
abra-agent/
```

否则继续留在原仓库内。

## 12. 最小可行版本

建议第一个 MVP 不要太大。

MVP 目标：

> 给定一个 DeFi incident，ABRA 自动判断其 replay 可行性，尝试运行现有 replay 测试，生成 evidence bundle 和下一步建议。

MVP 范围：

- 只支持 incident replay feasibility。
- 只注册 replay runner、file reader、report writer 三类工具。
- 只实现单 agent loop + evidence reviewer。
- 不做自动写 Solidity exploit。
- 不做真实链上交易。
- 不做高风险命令。

MVP 输入：

```bash
python3 -m abra run \
  --goal "Assess replay feasibility for BonqDAO incident" \
  --mode replay-feasibility \
  --budget-minutes 30
```

MVP 输出：

```text
runs/bonqdao-replay-feasibility/
  final_report.md
  evidence_bundle.json
  artifact_manifest.json
  event_log.jsonl
  tool_calls.jsonl
```

MVP 成功标准：

- 能自动发现已有 replay 测试。
- 能运行 Foundry replay 或识别缺失 RPC / archive blocker。
- 能生成明确 evidence level。
- 能给出下一步最小可执行任务。

## 13. 命名建议

短期：

- 仓库名继续使用 `abra`。
- 新增 agent 层命名为 `ABRA`。
- README 中写清：
  - `abra` 是领域实验室。
  - `ABRA` 是该实验室上的 agent 层。

中期：

- 如果 ABRA agent 层成熟，可以考虑 CLI 使用 `abra`。
- Python 包可以使用 `abra` 或 `blockchain_security.abra`。

长期：

- 如果 ABRA 脱离当前领域仓库，才新建 `abra-agent` 或 `abra` 仓库。

不建议现在直接把仓库改名为 `abra`，因为当前仓库还主要是工具、数据、报告和 replay 测试，不是完整 agent 产品。

## 14. 关键风险

### 14.1 把静态告警误当漏洞

必须强制 evidence level。没有 replay 或人工确认的结果，不能写成真实漏洞。

### 14.2 让 LLM 任意执行 shell

ABRA 应通过工具注册表和 guarded runner 调用命令。禁止 broadcast、私钥、破坏性文件操作和不受控网络写操作。

### 14.3 过早新建干净仓库

新仓库会让 agent 远离真实工具和数据。第一阶段的重点不是干净，而是让 agent 能在真实研究环境里闭环。

### 14.4 过早抽象通用框架

先把区块链安全 agent 跑通，再考虑是否抽取共享 core。不要一开始就设计大而全的 agent framework。

### 14.5 论文结论不可追溯

ABRA 输出给 ARA 的每个 claim 都必须能追溯到 artifact、命令和 evidence level。

## 15. 推荐下一步

按优先级：

1. 新增 `research_lab.yaml`，声明可调用命令、artifact globs 和安全限制。
2. 新增 `abra/` 包，先实现 tool registry 和 guarded command runner。
3. 把 `tools/replay_runner.py` 包装为第一个 ABRA 工具。
4. 实现 replay feasibility MVP。
5. 引入 `evidence_bundle.json` 和 evidence level。
6. 再扩展 static analysis agent 和 incident scout。
7. 最后再决定是否需要独立 `abra-agent` 仓库。

最终建议：

> 不要从新仓库开始。先在 `abra` 中新增 ABRA agent 层，把真实工具、真实数据、真实 replay 和真实证据闭环跑通。等 agent 层稳定后，再评估是否拆出独立仓库。
