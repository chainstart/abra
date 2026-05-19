# 决策：ABRA 使用动态 spec 维护体系

日期：2026-05-19

状态：接受

## 背景

ABRA 从区块链安全工具箱升级为研究智能体后，任务会跨静态分析、replay、证据分级、报告和 ARA 集成。只靠一次性重构文档无法准确保存每轮开发的完成状态、失败原因和后续任务。

## 决策

ABRA 采用动态 spec 维护体系：

- 主设计仍保存在 `docs/abra_full_refactor_spec.zh.md`。
- 机器可读任务状态保存在 `.engineering/spec_tasks.yaml`。
- 人工状态矩阵保存在 `docs/abra_implementation_status.zh.md`。
- 重要架构变更保存在 `docs/decisions/`。
- engineering-harness 或人工工具在任务完成后追加 `docs/spec_update_log.jsonl`。

## 影响

- 后续 harness 任务必须引用 requirement ID。
- 完成任务后必须记录证据，而不是只更新 roadmap。
- replay 失败、RPC 缺失、证据级别不足等 blocker 必须进入台账。
