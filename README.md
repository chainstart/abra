# DeFi Security Agent MVP

一个面向 DeFi 安全研究与新合约审计的最小成品。

当前仓库已经按工程化方式整理，根目录统一维护：

- `pyproject.toml`：项目元信息与工具配置
- `.editorconfig`：缩进、编码、换行规范
- `Makefile`：安装、测试、启动命令入口
- `docs/工程结构与代码规范.md`：目录职责与代码组织规范

当前版本已经具备：

- 统一扫描结果 schema
- 新合约审计闭环
- 历史攻击案例检索
- 研究想法与论文骨架生成
- 统一任务编排
- HTTP API
- 浏览器页面
- 任务结果归档
- 链上地址源码接入（依赖 Etherscan API）
 - 链上新合约发现监控（依赖主网 RPC）
- 可选的 LLM 研究增强层（默认关闭，开启后会在本地证据链之上做研究方向筛选、摘要与写作增强）

## 最小成品入口

推荐直接使用下面这一条命令启动：

```bash
python3 scripts/start_product.py
```

开发环境依赖安装：

```bash
python3 -m pip install -r requirements-dev.txt
```

## 可选 AI 研究增强

当前项目的研究模块已经支持“本地证据驱动 + 可选 LLM 增强”的混合模式：

- 默认不配置 LLM 时：
  - 仍然可以稳定运行
  - 研究结果来自本地审计、AST 深分析、历史案例和本地报告
  - 优点是可复现、可控、不容易胡编

- 配置 LLM 后：
  - 会在候选研究方向上做证据约束的 AI 复核与重写
  - 会补充 AI 执行摘要、论文摘要草案和更细的引用解释
  - 仍然只能基于本地证据链生成，不允许脱离证据乱写

推荐直接使用 OpenAI 官方变量：

```bash
OPENAI_API_KEY=your_openai_api_key
OPENAI_BASE_URL=https://api.openai.com/v1
OPENAI_MODEL=gpt-5.4
```

如果你要接其他 OpenAI 兼容服务，也可以用通用变量：

```bash
RESEARCH_LLM_ENABLED=true
LLM_API_URL=https://your-provider.example/v1/responses
LLM_API_KEY=your_api_key
LLM_MODEL=your_model_name
LLM_API_MODE=responses
LLM_TIMEOUT_SECONDS=45
LLM_TEMPERATURE=0.2
LLM_MAX_TOKENS=2200
```

说明：

- 现在默认优先支持 OpenAI 官方 `Responses API`
- 如果 `OPENAI_API_KEY` 已配置，研究增强层会自动启用
- 项目根目录的 `.env` / `.env.local` 也会被自动读取
- `LLM_API_URL` 既支持 `/responses`，也兼容 `/chat/completions`
- 没有配置完整时，系统会自动回退到纯本地证据模式
- 研究结果页会明确显示当前是 `AI 增强` 还是 `本地证据模式`

启动后打开：

```text
http://127.0.0.1:8000
```

在页面中你可以直接：

- 提交审计任务
- 提交研究任务
- 查看最近归档工件
- 预览任务结果和输出文件

## 前端文件位置

为了避免前端代码继续混在 Python 里，当前页面相关文件统一放在：

- `services/api/web_ui.py`
  服务端页面装配逻辑，只负责拼接页面数据块

- `services/api/templates/`
  页面模板，例如首页壳子

- `services/api/static/`
  CSS 与浏览器脚本

- `services/api/server.py`
  路由与静态资源输出


## 示例协议样本

| Protocol | TVL | Type | Findings | Report |
|----------|-----|------|----------|--------|
| Lido | ~$38B | Liquid Staking | 17 (2C, 3H, 7M, 5L) | [01_lido_audit.md](reports/01_lido_audit.md) |
| Aave V3 | ~$38B | Lending | 13 (1C, 3H, 6M, 3L) | [02_aave_audit.md](reports/02_aave_audit.md) |
| Uniswap V3/V4 | ~$6B | DEX (AMM) | 26 (2C, 4H, 12M, 8L) | [03_uniswap_audit.md](reports/03_uniswap_audit.md) |
| Curve | ~$2.7B | Stablecoin DEX | 13 (0C, 3H, 7M, 3L) | [04_curve_audit.md](reports/04_curve_audit.md) |
| Compound | ~$2.1B | Lending | 18 (0C, 3H, 10M, 5L) | [05_compound_audit.md](reports/05_compound_audit.md) |

**Total:** 87 unique findings across 15 contracts (~7,700 LOC)

## Project Structure

```
blockchain-security/
├── README.md                          # This file
├── pyproject.toml                     # 项目元信息与工具配置
├── .editorconfig                      # 编辑器统一格式规则
├── Makefile                           # 常用命令入口
├── .env.example                       # Phase 0 环境变量示例
├── .github/workflows/ci.yml           # Phase 0 基础 CI
├── artifacts/                         # 任务归档输出目录（运行时生成）
├── data/
│   ├── db/                            # SQLite 任务索引（运行时生成）
│   └── schema/
│       └── security_scan_report.schema.json
│                                       # 统一扫描结果 Schema
├── docs/                              # Project planning and design docs
│   ├── 文档索引.md                    # 文档导航
│   ├── 项目目标.md                    # AI 驱动 DeFi 安全 Agent 目标
│   ├── 当前不足与能力缺口.md          # 当前底座的差距分析
│   ├── 系统方案设计.md                # 系统架构与方案设计
│   ├── 实施路线图.md                  # 分阶段落地计划
│   └── 工程结构与代码规范.md          # 仓库目录与代码组织规范
├── services/                          # Phase 0 服务层骨架
│   ├── analysis/                      # 分析服务骨架
│   ├── agent/                         # Agent 编排骨架
│   ├── api/                           # 标准库 HTTP API 与前端页面
│   │   ├── static/                    # 前端样式与浏览器脚本
│   │   └── templates/                 # 页面模板
│   ├── research/                      # 研究工作流
│   ├── storage/                       # 结果归档
│   └── shared/                        # 统一数据模型与配置入口
├── reports/                           # Audit reports
│   ├── 00_defi_tvl_landscape.md       # DeFi TVL landscape research
│   ├── 01_lido_audit.md               # Lido security audit
│   ├── 02_aave_audit.md               # Aave V3 security audit
│   ├── 03_uniswap_audit.md            # Uniswap V3/V4 security audit
│   ├── 04_curve_audit.md              # Curve security audit
│   └── 05_compound_audit.md           # Compound security audit
├── research/
│   └── incidents/                     # Phase 2 历史攻击案例库
├── tools/                             # Static analysis toolkit
│   ├── analyzers/                     # Analysis modules
│   │   ├── base.py                    # Base classes (Finding, Severity, BaseAnalyzer)
│   │   ├── access_control.py          # Access control vulnerability detection
│   │   ├── reentrancy.py              # Reentrancy pattern detection
│   │   ├── oracle_dependency.py       # Oracle risk analysis
│   │   ├── arithmetic.py              # Arithmetic safety checks
│   │   └── upgrade_safety.py          # Proxy/upgrade risk detection
│   ├── scanner.py                     # Unified scanning CLI
│   ├── report_generator.py            # Markdown report generator
│   └── requirements.txt               # Python dependencies
├── tests/                             # Phase 0 基础测试
│   ├── fixtures/                      # 测试用 Solidity 样例
│   └── unit/                          # Python 单元测试
├── contracts/                         # Protocol contract sources
│   ├── lido/                          # Lido.sol, WstETH.sol, LidoOracle.sol
│   ├── aave/                          # Pool.sol, AToken.sol, FlashLoanLogic.sol, ...
│   ├── uniswap/                       # UniswapV3Pool.sol, V4PoolManager.sol, TickMath.sol
│   ├── curve/                         # StableSwap.sol, VotingEscrow.sol
│   └── compound/                      # CToken.sol, Comptroller.sol, GovernorBravo.sol
└── findings/
    └── summary.md                     # Cross-protocol findings summary
```

规划和项目级文档统一放在 `docs/` 下，不再散落在仓库根目录。

Key planning documents:

- [docs/文档索引.md](docs/文档索引.md)
- [docs/项目目标.md](docs/项目目标.md)
- [docs/当前不足与能力缺口.md](docs/当前不足与能力缺口.md)
- [docs/系统方案设计.md](docs/系统方案设计.md)
- [docs/实施路线图.md](docs/实施路线图.md)

Phase 0 engineering files:

- [data/schema/security_scan_report.schema.json](data/schema/security_scan_report.schema.json)
- [services/shared/models.py](services/shared/models.py)
- [services/shared/settings.py](services/shared/settings.py)
- [tests/unit/test_scanner_phase0.py](tests/unit/test_scanner_phase0.py)
- [tests/unit/test_report_generator_phase0.py](tests/unit/test_report_generator_phase0.py)
- [tests/unit/test_settings_phase0.py](tests/unit/test_settings_phase0.py)

Phase 1 audit MVP files:

- [services/analysis/contract_ingestion.py](services/analysis/contract_ingestion.py)
- [services/analysis/protocol_classifier.py](services/analysis/protocol_classifier.py)
- [services/analysis/static_analysis_pipeline.py](services/analysis/static_analysis_pipeline.py)
- [services/analysis/evidence_aggregator.py](services/analysis/evidence_aggregator.py)
- [services/analysis/audit_service.py](services/analysis/audit_service.py)
- [services/analysis/audit_report_writer.py](services/analysis/audit_report_writer.py)
- [data/schema/audit_run_result.schema.json](data/schema/audit_run_result.schema.json)
- [tests/unit/test_contract_ingestion_phase1.py](tests/unit/test_contract_ingestion_phase1.py)
- [tests/unit/test_protocol_classifier_phase1.py](tests/unit/test_protocol_classifier_phase1.py)
- [tests/unit/test_audit_service_phase1.py](tests/unit/test_audit_service_phase1.py)

Phase 2 incident knowledge files:

- [services/research/incident_repository.py](services/research/incident_repository.py)
- [services/research/incident_retriever.py](services/research/incident_retriever.py)
- [research/incidents/morpho_blue_oracle_misconfig_2024.json](research/incidents/morpho_blue_oracle_misconfig_2024.json)
- [research/incidents/curve_reentrancy_2023.json](research/incidents/curve_reentrancy_2023.json)
- [research/incidents/compound_governance_bug_2021.json](research/incidents/compound_governance_bug_2021.json)
- [tests/unit/test_incident_retriever_phase2.py](tests/unit/test_incident_retriever_phase2.py)

Phase 3 task orchestration files:

- [services/agent/task_orchestrator.py](services/agent/task_orchestrator.py)
- [services/agent/models.py](services/agent/models.py)
- [tests/unit/test_task_orchestrator_phase3.py](tests/unit/test_task_orchestrator_phase3.py)

Phase 4 research workflow files:

- [services/research/research_idea_generator.py](services/research/research_idea_generator.py)
- [services/research/paper_draft_writer.py](services/research/paper_draft_writer.py)
- [tests/unit/test_research_workflow_phase4.py](tests/unit/test_research_workflow_phase4.py)

Phase 5 API / artifact files:

- [services/api/server.py](services/api/server.py)
- [services/api/handlers.py](services/api/handlers.py)
- [services/api/web_ui.py](services/api/web_ui.py)
- [services/storage/artifact_store.py](services/storage/artifact_store.py)
- [services/storage/artifact_repository.py](services/storage/artifact_repository.py)
- [scripts/start_product.py](scripts/start_product.py)
- [tests/unit/test_api_handlers_phase5.py](tests/unit/test_api_handlers_phase5.py)
- [tests/unit/test_api_server_phase5.py](tests/unit/test_api_server_phase5.py)
- [tests/unit/test_artifact_store_phase5.py](tests/unit/test_artifact_store_phase5.py)
- [tests/unit/test_task_result_schema_phase5.py](tests/unit/test_task_result_schema_phase5.py)

Phase 6 address ingestion / sqlite files:

- [services/analysis/address_source_fetcher.py](services/analysis/address_source_fetcher.py)
- [services/storage/task_database.py](services/storage/task_database.py)
- [tests/unit/test_address_source_fetcher_phase6.py](tests/unit/test_address_source_fetcher_phase6.py)
- [tests/unit/test_task_database_phase6.py](tests/unit/test_task_database_phase6.py)

Phase 7+ monitoring / semantic / retrieval files:

- [services/analysis/semantic_analyzer.py](services/analysis/semantic_analyzer.py)
- [services/analysis/ast_semantic_analyzer.py](services/analysis/ast_semantic_analyzer.py)
- [services/monitoring/rpc_monitor.py](services/monitoring/rpc_monitor.py)
- [tests/unit/test_monitoring_phase7.py](tests/unit/test_monitoring_phase7.py)
- [tests/unit/test_incident_search_phase8.py](tests/unit/test_incident_search_phase8.py)

## Quick Start

### Run the Scanner

```bash
cd tools/

# Scan all contracts
python3 scanner.py --target ../contracts/ --output console

# Scan a specific protocol
python3 scanner.py --target ../contracts/lido/ --output markdown --output-file ../findings/lido_scan.md

# Run specific analyzers with severity filter
python3 scanner.py --target ../contracts/aave/ --analyzers reentrancy,oracle-dependency --severity High

# Output JSON for programmatic use
python3 scanner.py --target ../contracts/ --output json --output-file findings.json
```

Note: `scanner.py` exits with status code `1` when it reports any `Critical` or `High` findings. That is expected behavior and indicates the scan completed successfully with actionable results.

### Generate Reports

```bash
# Generate a formatted audit report from scan results
python3 scanner.py --target ../contracts/lido/ --output json --output-file /tmp/scan.json
python3 report_generator.py --input /tmp/scan.json --protocol-name "Lido" --output ../reports/auto_lido.md
```

### Run the Foundry PoC Tests

```bash
# Default: compile and run locally, skipping mainnet fork tests unless explicitly enabled
forge test -vv

# Enable the Morpho mainnet fork tests
export RUN_MAINNET_FORK_TESTS=true
export MAINNET_RPC_URL="https://your-mainnet-rpc"

# Optional: pin a specific block (default: 24654367)
export MAINNET_FORK_BLOCK=24654367

forge test -vv
```

If `RUN_MAINNET_FORK_TESTS` is not set to `true`, the Morpho fork tests will be skipped so the project remains runnable in offline or restricted environments.

### Run Phase 0 Tests

```bash
python3 -m unittest discover -s tests -p 'test_*.py' -v
forge test -vv
```

If you want the same Python environment as CI:

```bash
pip install -r requirements-dev.txt
```

### Run the HTTP API

```bash
python3 -m services.api.server
```

Available endpoints:

- `GET /health`
- `POST /api/v1/audit`
- `POST /api/v1/research`
- `POST /api/v1/monitor/scan`
- `POST /api/v1/incidents/search`
- `GET /api/v1/discoveries`
- `GET /api/v1/artifacts`

### Start the Product

```bash
python3 scripts/start_product.py
```

## Audit Framework

Based on **OWASP Smart Contract Top 10 (2026)** with protocol-specific business logic analysis:

| # | Category | Description |
|---|----------|-------------|
| SC-01 | Reentrancy | State inconsistency from recursive calls |
| SC-02 | Access Control | Missing/incorrect authorization |
| SC-03 | Oracle Manipulation | Price feed dependency risks |
| SC-04 | Flash Loan Attacks | Flash-loan-amplified exploits |
| SC-05 | Input Validation | Parameter validation gaps |
| SC-06 | Arithmetic | Precision, overflow, rounding issues |
| SC-07 | Logic Errors | Business logic flaws |
| SC-08 | Upgrade Safety | Proxy/upgrade mechanism risks |
| SC-09 | Governance | Governance attack vectors |
| SC-10 | External Calls | Unchecked call return values |

## Analysis Tools

5 specialized analyzers with 50+ detection rules:

- **Access Control** (10 rules): Unprotected functions, tx.origin, zero-address, centralization
- **Reentrancy** (7 rules): CEI violations, cross-function, read-only, callback patterns
- **Oracle Dependency** (10 rules): Staleness, validation, fallback, L2 sequencer, TWAP
- **Arithmetic** (10 rules): Division-before-multiplication, unchecked blocks, unsafe casts, rounding
- **Upgrade Safety** (10 rules): Delegatecall, initializers, storage gaps, selfdestruct, selector clashes

## Key Findings

### Cross-Protocol Patterns

1. **First Depositor Attack** — Lido, Curve, Compound vulnerable to share/exchange rate manipulation
2. **Reentrancy** — Most prevalent category (366 raw findings); real-world precedent: Curve $62M (2023)
3. **Oracle Dependency** — Aave & Compound critically dependent on Chainlink without fallback
4. **Governance Risks** — Historical: Compound $80M COMP bug (2021), Beanstalk $182M (2022)
5. **V4 Hooks** — Uniswap V4's hook system introduces a novel, largely untested attack surface

## Dependencies

- Python 3.10+
- `rich` (colored console output)
- `jinja2` (report templates)
- `pyyaml` (configuration)
- `solidity-parser` (AST 语义分析)
- `sqlalchemy` (数据库抽象)
- `psycopg` (PostgreSQL 驱动，可选)

```bash
pip install -r tools/requirements.txt
```
