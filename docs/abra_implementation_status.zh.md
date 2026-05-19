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
| `REQ-ABRA-REPLAY-001` | `partial` | bounded replay assessment MVP、fixture replay case | archive RPC、真实事件 replay 环境不稳定 | 建立 replay blocker 台账 |
| `REQ-ABRA-AGENT-001` | `partial` | replay/evidence agent MVP | 完整 plan-act-observe-reflect loop 和多 agent 分工不足 | 增加 agent state、tool registry、memory |
| `REQ-ABRA-MEMORY-001` | `pending` | 历史 reports/findings/data 已保留 | 缺统一 incident/finding/replay ledger | 新建 memory schema 和迁移脚本 |
| `REQ-ABRA-ARA-001` | `partial` | result bundle 可被 ARA 消费 | 需要和公开 ARA drafting/report pipeline 持续对齐 | 增加 ARA bundle smoke |

## 维护流程

1. 开发前检查 `.engineering/spec_tasks.yaml`，确认任务对应的 requirement 和验收证据。
2. 开发后把测试、报告、bundle 或 blocker 写入同一任务的 `evidence`。
3. 若发现 spec 不准确，新增或修改 requirement 时同步写入决策记录。
4. 对无法完成的 replay 或证据任务，记录失败原因，不删除历史 artifact。
