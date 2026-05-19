# ABRA Spec 实现状态矩阵

日期：2026-05-19

状态：动态维护中

主 spec：`docs/abra_full_refactor_spec.zh.md`

机器台账：`.engineering/spec_tasks.yaml`

决策记录：`docs/decisions/`

## 状态定义

- `completed`：已有代码、测试或文档证据支撑，可作为当前基线。
- `partial`：已有 MVP 或局部实现，但还不满足最终 spec。
- `pending`：已纳入 spec，但尚未开发或尚无足够证据。
- `blocked`：被外部环境、设计冲突或验证缺口阻塞。

## Requirement 状态

| Requirement ID | 状态 | 当前证据 | 主要缺口 | 下一步 |
| --- | --- | --- | --- | --- |
| `REQ-ABRA-GOV-001` | `completed` | 本文档、`.engineering/spec_tasks.yaml`、决策记录 | 后续任务需持续更新 | 每次任务完成后运行 spec 同步 |
| `REQ-ABRA-MANIFEST-001` | `completed` | `research_lab.yaml`、`python3 -m abra labs inspect --json`、manifest/CLI 测试 | 需随 ARA contract 演进 | 保持 lab manifest 与 ARA 兼容 |
| `REQ-ABRA-BUNDLE-001` | `completed` | `python3 -m abra bundle build/validate`、`tests/test_abra_result_bundle.py` | 增加更多真实报告映射 | 扩展 artifact manifest 和 limitations |
| `REQ-ABRA-EVIDENCE-001` | `completed` | evidence validator、L1/L4/L6 证据级别、replay assessment | L6 audit-ready 证据仍需真实 replay 支撑 | 增加真实 fork replay 证据 |
| `REQ-ABRA-REPLAY-001` | `partial` | bounded replay assessment、replay blocker ledger、deterministic archive-RPC validation plan | 尚未对真实事件执行 live archive RPC replay；不能广播交易或使用私钥 | 在只读 archive RPC 环境中扩展真实 replay |
| `REQ-ABRA-AGENT-001` | `completed` | `python3 -m abra agent run`、agent state、decision/observation/reflection ledgers、evidence review、ARA sidecar | 多 agent 分工仍未作为独立 executor 拆分 | 基于真实 replay fixture 扩展 agent action set |
| `REQ-ABRA-MEMORY-001` | `partial` | 历史 reports/findings/data 已保留；replay run ledger、replay memory、agent run ledger 和 agent memory summary | 尚缺 repo 级 incident/finding 长期 memory 迁移 | 扩展 memory schema 到 incident/finding/replay 跨运行索引 |
| `REQ-ABRA-ARA-001` | `partial` | result/replay bundle 生成 ARA sidecar；`tools/ara_bundle_validate.py` 可调用公开 ARA validate + drafting context | 需要随公开 ARA bundle/drafting contract 持续对齐；真实 replay 仍需只读 archive RPC | 保持跨仓库 ARA smoke |

## ABRA-REPLAY-001 更新

`python3 -m abra replay assess` 现在除 `replay_feasibility_report.json` 和 `evidence_bundle.json` 外，还生成：

- `replay_blocker_ledger.json`：记录 archive RPC state、trace availability、fork block gap、simulation precondition 和 non-broadcast safety decision。
- `archive_rpc_validation.json`：在 `deterministic_local` 模式下描述每个 case 的只读 archive RPC live validation 前提，不接触网络、不广播交易、不使用私钥。
- `memory/replay_run_ledger.jsonl` 和 `memory/replay_memory_ledger.json`：保存 replay run、case 状态、blocker summary 和 evidence level，供后续 agent run 复用。

剩余限制：当前 workflow 仍是 bounded/local evidence。真实 L4 升级必须在只读 archive RPC、已知 fork block、明确 replay test、可保存 trace/log 的环境中完成；任何需要 `--broadcast`、`cast send` 或私钥的步骤都不属于 ABRA replay evidence workflow。

## ABRA-ARA-001 更新

ABRA result bundle 和 replay assessment bundle 现在都会输出公开 ARA 消费所需的 sidecar：

- `bundle_manifest.json`、`claims.json`、`drafting_brief.md`、`limitations.md`。
- `claims.json` 中只有 L4 verified replay claim 标记为 `supported`；L1 static alert / replay-feasibility blocker 标记为 `blocked`。
- `tools/ara_bundle_validate.py` 在本地调用 `/home/biostar/work/projects/ara` 的 `python3 -m ara bundles validate` 和 `python3 -m ara drafting context`，并检查公开 drafting context 不把 L1 blocker 当成成功 replay claim。

本任务的本地证据命令：

- `python3 -m abra replay assess --case-fixture tests/fixtures/replay_case.json --out /tmp/abra_ara_bundle --json >/tmp/abra_ara_assess.json`
- `python3 tools/ara_bundle_validate.py /tmp/abra_ara_bundle --json >/tmp/abra_ara_bundle_validate.json`
- `python3 -m pytest -q tests/test_abra_result_bundle.py tests/test_abra_cli.py`

## ABRA-AGENT-001 更新

`python3 -m abra agent run --case-fixture ... --out ...` 现在会执行 bounded/local 的 plan-act-observe-reflect loop：

- round 1 读取 `research_lab.yaml` 和本地 tool inventory。
- round 2 调用现有 `python3 -m abra replay assess` 等价逻辑，在 `replay_assessment/` 中生成 replay evidence bundle。
- round 3 运行 evidence validation，生成 `evidence_review.json`，保留 L1/L4 evidence level 边界和 open blocker。
- 每轮写入 `memory/agent_decision_ledger.jsonl`、`memory/agent_observation_ledger.jsonl`、`memory/agent_reflection_ledger.jsonl`。
- 每次 run 追加 `memory/agent_run_ledger.jsonl` 并重建 `memory/agent_memory_ledger.json`。
- bundle 根目录输出 `agent_run_state.json`、`final_report.md`、`evidence_bundle.json`、`artifact_manifest.json`、`bundle_manifest.json`、`claims.json`、`drafting_brief.md`、`limitations.md`，供 ARA 消费。

安全边界：agent loop 不使用私钥、不广播交易、不做 live trading、不做 state-changing RPC；真实 replay 升级仍必须沿用只读 archive RPC 和 replay evidence validator。

本任务的本地证据命令：

- `python3 -m abra agent run --case-fixture tests/fixtures/replay_case.json --out /tmp/abra_agent_bundle --json`
- `python3 -m pytest -q tests/test_abra_agent_loop.py tests/test_abra_cli.py`

## 维护流程

1. 开发前检查 `.engineering/spec_tasks.yaml`，确认任务对应的 requirement 和验收证据。
2. 开发后把测试、报告、bundle 或 blocker 写入同一任务的 `evidence`。
3. 若发现 spec 不准确，新增或修改 requirement 时同步写入决策记录。
4. 对无法完成的 replay 或证据任务，记录失败原因，不删除历史 artifact。
