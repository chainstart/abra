# ABRA 全量更名与智能体化重构规格

日期：2026-05-18

状态：草案

相关文档：

- `docs/abra_upgrade_plan.zh.md`
- AMRA / ARA / Blockchain-Security 仓库关系架构文档

## 1. 结论

如果目标已经确定为把 `abra` 升级并更名为 `ABRA`，推荐采用“原仓库内彻底重构，完成后再做物理改名”的方案。

最终目标：

- 仓库名：`abra`
- 系统名：`ABRA`
- 全称：`Automated Blockchain Research Agents`
- Python 包名：`abra`
- CLI：`abra`
- 实验室 ID：`abra`
- 旧名兼容：`abra`、`blockchain_security`

核心判断：

> `ABRA` 这个名字只有在仓库真正具备 agent loop、工具注册表、证据模型、长期记忆、评估器和 ARA 集成之后才是准确的。更名和智能体化应该作为同一次重构目标处理，而不是只改目录名。

## 2. 仓库名使用缩写还是全名

推荐仓库名使用缩写：`abra`。

理由：

- 与 `ARA`、`AMRA` 命名体系一致。
- CLI、Python package、路径和 import 都更短，开发体验更好。
- `automated-blockchain-research-agents` 作为仓库名过长，不适合命令行、路径、artifact 和配置。
- `abra` 适合作为产品名和系统名，容易形成品牌识别。

但需要在可见文档中保留全名和领域说明：

```text
Repository slug: abra
README title: ABRA: Automated Blockchain Research Agents
Short description: Agentic blockchain security research system for static analysis, incident replay, evidence review, and paper-ready reporting.
```

如果未来要公开发布且特别重视搜索可发现性，可以考虑：

- GitHub 仓库名仍用 `abra`。
- README、topics、package description 中写清 `abra`、`DeFi security`、`Foundry replay`。
- 如果组织下已经有重名或冲突，再考虑 `abra-blockchain`。

不推荐仓库名使用完整全称：

```text
automated-blockchain-research-agents
```

它太长，而且会让路径、配置和命令显得笨重。

## 3. 重构目标

本次重构不是简单改名，而是把当前“区块链安全工具箱”升级为“区块链研究智能体系统”。

重构完成后，ABRA 应具备：

- 明确的 agent loop：plan -> act -> observe -> reflect -> decide。
- 统一工具注册表：所有 scanner、pipeline、replay、report 工具都通过注册表调用。
- 受限命令执行：禁止高风险链上写操作、私钥、broadcast 和破坏性命令。
- 证据分级：区分 hypothesis、static alert、local reproduction、fork replay、audit-ready。
- 长期记忆：保存 incident、protocol、finding、replay、失败路线和 blocker。
- 多 agent 分工：scout、static analysis、replay、evidence reviewer、report writer。
- ARA 集成：输出可被 `ara` 消费的 evidence bundle、artifact manifest 和 writing brief。
- 历史兼容：旧的 `abra` 路径、项目 artifact 和 ARA 配置不能一次性失效。

## 4. 当前状态到目标状态

### 4.1 当前状态

当前仓库主要包括：

```text
tools/
  scanner.py
  replay_runner.py
  report_generator.py
  analyzers/
  pipeline/

test/replay/
contracts/
data/
reports/
findings/
paper/
```

它已经具备领域工具和研究材料，但缺少：

- agent package。
- CLI 入口。
- tool registry。
- run state。
- evidence bundle。
- memory ledger。
- manifest 驱动的外部调用接口。

### 4.2 目标状态

目标结构：

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
    ara_export.py
    agents/
      __init__.py
      incident_scout.py
      static_analysis_agent.py
      replay_agent.py
      evidence_reviewer.py
      report_agent.py
    tools/
      __init__.py
      scanner_tool.py
      pipeline_tool.py
      replay_tool.py
      report_tool.py
      artifact_tool.py
    evaluators/
      __init__.py
      evidence_evaluator.py
      feasibility_evaluator.py
      novelty_evaluator.py
    prompts/
      planner.md
      critic.md
      report_writer.md
  tools/
    scanner.py
    replay_runner.py
    report_generator.py
    analyzers/
    pipeline/
  contracts/
  test/replay/
  data/
  reports/
  findings/
  memory/
  runs/
  paper/
  docs/
  research_lab.yaml
  pyproject.toml
  README.md
```

说明：

- 顶层仓库叫 `abra`。
- Python 包叫 `abra/`。
- 原 `tools/` 暂时保留为领域工具箱，不第一轮强行搬进 package。
- `abra/tools/` 是 agent wrapper，不是原始工具本身。
- `memory/` 保存长期研究记忆。
- `runs/` 保存每次 agent 运行状态。

## 5. 命名迁移规范

### 5.1 必须统一的新名字

```text
abra -> abra
Blockchain Security -> ABRA 或 Blockchain Security Research
blockchain_security -> abra
BlockchainSecurity -> ABRA 或 Abra
lab_id: abra -> abra
repo_name: abra -> abra
```

### 5.2 保留旧名的地方

以下位置可以保留旧名作为历史兼容：

- 旧项目 artifact。
- 旧论文文本中描述历史实验环境的部分。
- `legacy_lab_ids`。
- `legacy_repo_names`。
- migration notes。
- ARA 旧配置的 fallback。

示例：

```yaml
lab_id: abra
legacy_lab_ids:
  - abra
legacy_repo_names:
  - abra
```

### 5.3 不建议立即修改的内容

第一轮重构不建议移动这些目录：

- `tools/`
- `contracts/`
- `test/replay/`
- `data/`
- `reports/`
- `findings/`
- `paper/`

这些目录已经被脚本、报告、论文和 Foundry 配置引用。先增加 ABRA agent 层和兼容配置，再考虑后续整理。

## 6. Python 工程化

新增 `pyproject.toml`：

```toml
[project]
name = "abra"
version = "0.1.0"
description = "Automated Blockchain Research Agents"
requires-python = ">=3.10"
dependencies = [
  "pyyaml",
]

[project.scripts]
abra = "abra.cli:main"
```

推荐命令：

```bash
python3 -m abra --help
abra --help
abra tools list
abra run --goal "Assess replay feasibility for Euler Finance incident"
```

旧脚本入口保留：

```bash
python3 tools/scanner.py
python3 tools/replay_runner.py
python3 tools/pipeline/run_phase1.py
```

第一阶段不要要求所有工具都变成 Python import。允许 wrapper 通过受限 command runner 调用旧脚本。

## 7. ABRA Agent Loop

ABRA 的核心是自主循环，而不是固定流水线。

最小循环：

```text
initialize run state
while budget remains:
  observe workspace, memory, artifacts, last tool result
  produce next plan
  select tool from registry
  execute tool with guarded command runner
  parse result and artifacts
  update evidence store
  update memory store
  ask evaluator whether to continue, pivot, or stop
export final report and evidence bundle
```

每轮必须落盘：

```text
runs/<run-id>/
  event_log.jsonl
  tool_calls.jsonl
  observations.jsonl
  plans.jsonl
  evidence_bundle.json
  artifact_manifest.json
  final_report.md
```

不允许只把推理和状态保存在模型上下文里。长时研究必须可恢复、可审计、可继续。

## 8. 工具注册表

所有可被 agent 调用的工具都要进入工具注册表。

工具声明应包含：

- 工具名。
- 领域能力。
- 输入 schema。
- 输出 schema。
- artifact globs。
- 是否只读。
- 是否需要 RPC。
- 命令 allowlist。
- 禁止模式。
- 超时。

示例：

```yaml
tools:
  run_replay_test:
    description: "Run a Foundry replay test for one incident."
    command_prefix: "forge test --match-path"
    inputs:
      test_path: string
    outputs:
      - forge_log
      - replay_summary_json
    artifact_globs:
      - reports/replay_runs/*.json
      - reports/replay_runs/*.md
    safety:
      read_only: true
      requires_rpc: true
      deny_patterns:
        - --broadcast
        - cast send
        - PRIVATE_KEY
        - rm -rf
```

第一批工具：

- `scan_contracts`
- `run_incident_pipeline`
- `generate_event_cards`
- `select_replay_candidates`
- `run_replay_test`
- `summarize_replay_results`
- `generate_report`
- `read_artifact`
- `write_note`

## 9. 安全命令执行

ABRA 必须默认安全。

禁止：

- `cast send`
- `forge script --broadcast`
- 明文私钥。
- `PRIVATE_KEY`。
- `rm -rf`
- `git reset --hard`
- 任意 shell 拼接。
- 未注册命令。

允许：

- 只读扫描。
- Foundry test。
- 数据处理脚本。
- 报告生成脚本。
- 受限文件读写。

所有命令必须记录：

- command。
- cwd。
- env allowlist。
- started_at。
- finished_at。
- exit_code。
- stdout path。
- stderr path。
- produced artifacts。

## 10. 证据模型

ABRA 的输出核心是 evidence，不是“看起来合理的安全故事”。

证据等级：

```text
L0 hypothesis
  agent 假设或研究猜想。

L1 static_alert
  静态分析告警，没有复现。

L2 source_confirmed
  源码级确认，有明确代码依据。

L3 local_reproduced
  本地 deterministic test 复现。

L4 fork_replayed
  fork / archive RPC replay 成功。

L5 externally_correlated
  与链上交易、事件报告或公开资料交叉验证。

L6 audit_ready
  根因、影响、复现、限制和缓解建议完整。
```

finding schema：

```json
{
  "finding_id": "string",
  "title": "string",
  "protocol": "string",
  "incident": "string",
  "evidence_level": "L1 static_alert",
  "claims": [
    {
      "claim": "string",
      "supported_by": ["artifact-id"],
      "limitations": []
    }
  ],
  "artifacts": [],
  "reproduction": {
    "status": "not_attempted",
    "commands": []
  },
  "next_actions": []
}
```

Evidence Reviewer 的职责是降级证据不足的 finding，而不是帮 planner 圆结论。

## 11. 长期记忆

新增：

```text
memory/
  incidents/
  protocols/
  findings/
  replay_runs/
  failed_routes/
  rpc_blockers/
  tool_performance/
```

记忆原则：

- 成功路线要保存。
- 失败路线也要保存。
- RPC blocker 要单独分类。
- 静态告警不能自动升级为漏洞。
- replay 失败不能简单等同于不存在漏洞。
- 每条长期记忆都要带来源 artifact 和时间。

长期记忆应能回答：

- 某个 incident 是否已经尝试 replay。
- 失败原因是 RPC、测试设计、合约状态、还是数据缺失。
- 某类 analyzer 的误报率如何。
- 哪些 protocol 已经审计过。
- 哪些 finding 已达到 L4 或以上。

## 12. 多 Agent 设计

推荐最小多 agent：

```text
Incident Scout
  选择值得研究的 incident。

Static Analysis Agent
  运行 scanner，聚合告警。

Replay Agent
  运行 Foundry replay，诊断失败。

Evidence Reviewer
  独立评估证据等级。

Report Agent
  输出 final_report、writing_brief 和 ARA bundle。
```

多 agent 不要求一开始并行。第一版可以串行执行，但状态和输出要分离。

重要原则：

- 发现者和评估者分离。
- 报告者只能使用 evidence bundle 中已支持的 claim。
- planner 可以乐观探索，reviewer 必须保守。

## 13. ARA 集成

ARA 仍然负责通用科研流程和论文写作；ABRA 负责区块链安全证据生产。

ABRA 对 ARA 输出：

```text
runs/<run-id>/ara_bundle/
  evidence_bundle.json
  artifact_manifest.json
  writing_brief.md
  final_report.md
  limitations.md
```

`writing_brief.md` 必须明确：

- 哪些 claim 可写。
- 每个 claim 的 evidence level。
- 哪些 claim 不能写成已复现。
- 哪些实验受 RPC 或数据限制。
- 哪些表格、图形、报告可以引用。

ARA 配置迁移建议：

```yaml
external_repositories:
  abra:
    path: ../abra
    legacy_paths:
      - ../abra
    manifest: research_lab.yaml
```

短期保留旧 domain：

```yaml
research_domain: blockchain_security
```

同时新增：

```yaml
research_domain: abra
```

ARA 读取时：

1. 优先找 `../abra`。
2. 找不到则回退 `../abra`。
3. 优先读 `research_lab.yaml`。
4. 旧 config 作为 override 或兼容 fallback。

## 14. Manifest 规范

仓库根目录新增 `research_lab.yaml`。

示例：

```yaml
lab_id: abra
name: "ABRA: Automated Blockchain Research Agents"
legacy_lab_ids:
  - abra
legacy_repo_names:
  - abra

commands:
  allow_prefixes:
    - python3 -m abra
    - abra
    - python3 tools/
    - python3 scanner.py
    - python3 tools/scanner.py
    - forge test --match-path test/replay/
    - forge test --match-contract
  deny_patterns:
    - rm -rf
    - git reset --hard
    - cast send
    - --broadcast
    - PRIVATE_KEY

environment:
  optional:
    - ETH_RPC_URL
    - ARCHIVE_RPC_URL

artifacts:
  include:
    - runs/*/evidence_bundle.json
    - runs/*/artifact_manifest.json
    - runs/*/final_report.md
    - reports/*.md
    - reports/events/*.md
    - reports/replay_runs/*.json
    - findings/*.md
    - data/processed/*.csv
    - figures/generated/*
```

## 15. 迁移阶段

### 阶段 0：冻结边界

目标：先定义新名字和兼容策略。

任务：

- 新增本 spec。
- README 增加 ABRA 目标说明。
- 确认仓库最终名为 `abra`。
- 确认旧名只作为兼容名保留。

验收：

- 文档明确 `ABRA` 不是简单改名。
- 迁移范围、旧名兼容、ARA 关系都写清楚。

### 阶段 1：新增 ABRA package，不移动旧工具

目标：在原仓库内建立 agent 层。

任务：

- 新增 `abra/__init__.py`。
- 新增 `abra/cli.py`。
- 新增 `abra/tool_registry.py`。
- 新增 `abra/command_runner.py`。
- 新增 `abra/evidence.py`。
- 新增 `abra/memory.py`。
- 新增 `pyproject.toml`。

验收：

```bash
python3 -m abra --help
python3 -m abra tools list
```

### 阶段 2：包装现有工具

目标：让 agent 能安全调用工具箱。

任务：

- 包装 `tools/scanner.py`。
- 包装 `tools/replay_runner.py`。
- 包装 `tools/pipeline/run_phase1.py`。
- 包装 report generator。
- 生成 `tool_calls.jsonl`。

验收：

```bash
python3 -m abra tools run scan_contracts --help
python3 -m abra tools run run_replay_test --help
```

### 阶段 3：实现最小 agent loop

目标：完成真正智能体化的最小闭环。

任务：

- 实现 `abra/agent_loop.py`。
- 支持 `--goal`、`--mode`、`--budget-minutes`、`--max-rounds`、`--out`。
- 每轮写 event、plan、tool call、observation。
- 支持 stop / continue / pivot。

验收：

```bash
python3 -m abra run \
  --goal "Assess replay feasibility for BonqDAO incident" \
  --mode replay-feasibility \
  --budget-minutes 30 \
  --out runs/bonqdao-feasibility-001
```

输出：

```text
runs/bonqdao-feasibility-001/
  event_log.jsonl
  tool_calls.jsonl
  observations.jsonl
  evidence_bundle.json
  artifact_manifest.json
  final_report.md
```

### 阶段 4：证据和记忆

目标：让 ABRA 研究结果可复用。

任务：

- 定义 finding schema。
- 定义 evidence level。
- 写入 `memory/`。
- 保存 failed routes。
- 保存 RPC blockers。

验收：

- 每个 finding 有 evidence level。
- 每个 replay 失败有分类。
- 下一次运行能读取历史 blocker。

### 阶段 5：多 agent 分工

目标：降低单 agent 自我确认风险。

任务：

- 实现 Incident Scout。
- 实现 Static Analysis Agent。
- 实现 Replay Agent。
- 实现 Evidence Reviewer。
- 实现 Report Agent。

验收：

- Evidence Reviewer 能独立降级 claim。
- Report Agent 不输出没有 evidence 支持的结论。

### 阶段 6：ARA 兼容迁移

目标：让 `ara` 可调用 ABRA。

任务：

- 新增 `research_lab.yaml`。
- ARA 支持 `../abra` 优先路径。
- ARA 保留 `../abra` fallback。
- ARA 支持读取 `evidence_bundle.json`。
- ARA 写作阶段使用 evidence level。

验收：

- ARA 能调用 ABRA。
- ARA 能从 ABRA 输出生成论文材料。
- ARA 不把 L1 静态告警写成 L4 fork replay。

### 阶段 7：物理仓库改名

目标：完成最终路径迁移。

前置条件：

- `python3 -m abra --help` 可运行。
- `research_lab.yaml` 可用。
- ARA fallback 已实现。
- 至少一个 ABRA run 成功生成 evidence bundle。
- 旧工具脚本仍可运行。

执行：

```bash
mv /home/biostar/work/projects/abra \
   /home/biostar/work/projects/abra
```

随后更新：

- ARA 配置。
- README。
- docs。
- shell scripts。
- paper 中的新实验路径。
- Git remote 名称。

验收：

```bash
cd /home/biostar/work/projects/abra
python3 -m abra --help
python3 -m abra tools list
python3 tools/scanner.py --help
python3 tools/replay_runner.py --help
forge test --match-path test/replay/*.t.sol
```

### 阶段 8：清理旧名

目标：逐步减少旧名，但不破坏历史 artifact。

任务：

- 新代码不再使用 `abra`。
- 新配置不再使用 `blockchain_security`。
- 旧配置保留 fallback。
- 历史报告不强行全量改写。
- migration guide 记录旧名到新名映射。

验收：

- `rg "abra|blockchain_security"` 只在 legacy、history、migration 文档中出现。

## 16. 回滚方案

任何阶段如果失败，都应该能回滚。

阶段 1-6：

- 仓库物理名还没改，直接禁用 `abra/` agent 层即可。
- 旧工具仍可使用。

阶段 7 后：

- 如果 ARA 或脚本大量失败，可以创建兼容 symlink：

```bash
ln -s /home/biostar/work/projects/abra \
      /home/biostar/work/projects/abra
```

或者临时恢复旧目录名。

原则：

- 不删除旧 reports。
- 不删除 old artifact。
- 不在迁移早期移动 Foundry test 和 data。

## 17. 测试计划

### 17.1 单元测试

需要覆盖：

- tool registry 加载。
- command allow / deny。
- evidence level 解析。
- artifact manifest 生成。
- memory ledger 写入。
- ARA bundle 生成。

### 17.2 集成测试

需要覆盖：

```bash
python3 -m abra tools list
python3 -m abra run --mode replay-feasibility --max-rounds 2
python3 tools/scanner.py --help
python3 tools/replay_runner.py --help
forge test --match-path test/replay/Phase2Batch1Catalog.t.sol
```

### 17.3 迁移测试

需要覆盖：

- 从 `../abra` 读取 manifest。
- 从 `../abra` fallback。
- 旧 ARA config 可继续运行。
- 新 ARA config 可调用 ABRA。

## 18. 不做事项

本次重构不做：

- 自动生成真实链上交易。
- 使用私钥。
- `forge script --broadcast`。
- 自动攻击真实协议。
- 把所有历史报告强行重写。
- 立刻把 `tools/` 全部迁入 `abra/`。
- 立刻抽取通用 agent framework。
- 立刻新建独立干净仓库。

## 19. 关键风险

### 19.1 名字超前于能力

如果只改名不加 agent loop，`ABRA` 会名不副实。必须把更名和 agent 化绑定。

### 19.2 破坏现有实验

Foundry、reports、paper、ARA 配置都可能依赖当前路径。迁移前必须保留 fallback。

### 19.3 证据夸大

ABRA 输出必须强制 evidence level。静态分析告警不能被写成已复现漏洞。

### 19.4 LLM 权限过大

agent 只能通过工具注册表调用命令。不能给 LLM 任意 shell 写权限。

### 19.5 过早抽象

先完成 ABRA 自身闭环，再考虑抽取共享核心库。

## 20. 推荐实施顺序

最推荐的实际顺序：

1. 保持当前目录名 `abra`。
2. 新增 `abra/` package 和 `pyproject.toml`。
3. 新增 `research_lab.yaml`。
4. 包装 replay runner，先做 replay feasibility MVP。
5. 引入 evidence bundle 和 memory ledger。
6. 接入 ARA 的 manifest / bundle 消费。
7. 跑通一个完整 ABRA run。
8. 再把物理目录和远程仓库改名为 `abra`。
9. 保留旧名 fallback 至少一个开发周期。

## 21. 最终建议

仓库名建议用 `abra`，README 标题和描述中使用完整全称：

```text
ABRA: Automated Blockchain Research Agents
```

这兼顾了命令行简洁性、ARA/AMRA 命名一致性和外部可理解性。

重构方式建议是原仓库内彻底重构，然后再改名。不要新建空白仓库，也不要先改物理仓库名。最关键的是先让 ABRA 在真实的区块链安全实验环境里跑出一个可审计的 agent 闭环：目标、计划、工具调用、观察、证据、记忆、报告、ARA bundle。

## 22. Spec 动态维护规则

ABRA 的重构 spec 不再只作为一次性设计文档使用。后续开发必须同步维护以下文件：

- `.engineering/spec_tasks.yaml`：机器可读任务台账，记录 requirement、任务状态、证据和下一步。
- `docs/abra_implementation_status.zh.md`：人工可读实现状态矩阵，解释哪些 requirement 已完成、部分完成或待开发。
- `docs/decisions/`：架构决策记录，说明为何改变 spec、任务或仓库边界。
- `docs/spec_update_log.jsonl`：由 engineering-harness 或人工工具追加的动态更新日志。

维护要求：

1. 新增需求时，必须先分配稳定的 `REQ-ABRA-*` ID，再进入任务台账。
2. 完成一个任务或阶段后，必须记录可验证证据，例如测试命令、CLI 输出、bundle 路径、报告路径或 replay 结果。
3. 未完成或失败的任务不能只留在聊天记录里，必须写入台账的 blocker、next_action 或后续任务。
4. ARA 或 engineering-harness 调用 ABRA 开发任务时，应在任务结束后运行 spec 同步工具，更新 `.engineering/spec_tasks.yaml` 和 `docs/spec_update_log.jsonl`。
5. 静态分析告警、local replay、fork replay、audit-ready 证据必须继续按 evidence level 区分，不能因为任务完成而提升证据级别。
