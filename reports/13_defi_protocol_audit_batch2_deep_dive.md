# DeFi 协议深度安全审计报告 — 第二批 (7+1 协议)

**日期:** 2026-03-15
**方法论:** 链上合约查询 (cast call) + Web 安全研究 + 历史事件分析 + 源码审查
**覆盖协议:** 9 个协议，总 TVL ~$17.7B

---

## 目录

1. [风险矩阵总览](#1-风险矩阵总览)
2. [JustLend DAO ($3.16B)](#2-justlend-dao-316b---tron)
3. [Maple Finance ($2.3B)](#3-maple-finance-23b---ethereum)
4. [Pendle Finance ($2.2B)](#4-pendle-finance-22b---ethereum)
5. [SparkLend ($1.96B)](#5-sparklend-196b---ethereum)
6. [Kamino Lend ($2.0B)](#6-kamino-lend-20b---solana)
7. [PancakeSwap AMM ($1.65B)](#7-pancakeswap-amm-165b---bnb-chain) *(待补充)*
8. [Venus Protocol ($1.26B)](#8-venus-protocol-126b---bnb-chain)
9. [Compound V3 ($1.29B)](#9-compound-v3-129b---ethereum)
10. [Fluid Lending ($1.03B)](#10-fluid-lending-103b---ethereum) *(部分数据)*
11. [Ondo Finance ($2.5B)](#11-ondo-finance-25b---ethereum)
12. [跨协议比较分析](#12-跨协议比较分析)

---

## 1. 风险矩阵总览

| # | 协议 | TVL | 链 | 类别 | 整体风险 | 最大攻击面 |
|---|------|-----|-----|------|:--------:|-----------|
| 1 | JustLend | $3.16B | Tron | Lending | 🔴 **HIGH-CRITICAL** | Justin Sun 控制 + 假 TVL |
| 2 | Maple Finance | $2.3B | ETH | Lending | 🔴 **HIGH** | 零 first-loss + 信用风险 |
| 3 | Pendle Finance | $2.2B | ETH | Yield | 🟡 **MEDIUM** | 3/5 多签 + 低流动性 Oracle |
| 4 | SparkLend | $1.96B | ETH | Lending | 🟡 **MEDIUM** | D3M 系统耦合 $2.92B |
| 5 | Kamino Lend | $2.0B | Solana | Lending | 🟢 **LOW-MEDIUM** | Solana 宕机风险 |
| 6 | Venus Protocol | $1.26B | BNB | Lending | 🟠 **MEDIUM-HIGH** | 治理攻击成本仅 $1.75M |
| 7 | Compound V3 | $1.29B | ETH | Lending | 🟠 **MEDIUM-HIGH** | 代理升级可 drain 全部 TVL |
| 8 | Fluid | $1.03B | ETH | Lending+DEX | 🟢 **LOW-MEDIUM** | 零历史漏洞, 创新架构 |
| 9 | Ondo Finance | $2.5B | ETH | RWA | 🟡 **MEDIUM** | 中心化控制 + 无 timelock 升级 |

---

## 2. JustLend DAO ($3.16B) — Tron

### 2.1 架构概述

JustLend 是部署在 TRON 上的 **Compound V2 Fork**，2020年12月上线。

| 组件 | 合约地址 |
|------|---------|
| Unitroller (Comptroller proxy) | `TGjYzgCyPobsNS9n6WcbdLVR9dH7mWqFx7` |
| Comptroller (implementation) | `TB23wYojvAsSx6gR8ebHiBqwSeABiBMPAr` |
| Timelock | `TRWNvb15NmfNKNLhQpxefFz7cNjrYjEw7x` |
| GovernorBravoDelegator | `TEqiF5JbhDPD77yjEfnEMncGRZNDt2uogD` |
| PriceOracle | `TD8bq1aFY8yc9nsD2rfqqJGDtkh7aPpEpr` |

### 2.2 关键发现

#### 发现 1: 极端中心化 — CRITICAL (10/10)

- **98.7%** 的 BTC 供应来自仅 3 个钱包
- **99.7%** 的 stUSDT 供应来自单一来源
- Justin Sun 据报控制 85% stUSDT (通过 HTX)
- ChainArgos 调查: stUSDT 资金从未实际投资 RWA，"只是存在 JustLend 里"
- **$3.16B TVL 数字具有误导性** — 大量为 Justin Sun 自存自取的循环 TVL

#### 发现 2: 治理形同虚设 — HIGH (8/10)

- **Timelock 合约仅有 9 笔交易** (5年以来!)
- GovernorBravo 仅 83 笔交易
- 治理门槛: 200M WJST 提案, 600M WJST 通过
- **已放弃 guardian 角色 → 无紧急暂停能力**
- DeFiSafety: "无暂停控制文档"

#### 发现 3: stUSDT 系统性风险 — HIGH (8/10)

- stUSDT 声称 4%+ RWA 收益，但独立调查未发现实际 RWA 部署证据
- HTX 储备大量为 stUSDT — 循环依赖
- 若 stUSDT 信心崩溃 → 挤兑 → JustLend TVL 崩盘 → 级联清算

#### 发现 4: Oracle 已迁移至 Chainlink — 改善

- 2024年10月从 WinkLink 迁移至 Chainlink Data Feeds
- PriceOracle 已有 79,215 笔交易
- Chainlink 在 TRON 上较新，战斗测试不如以太坊

### 2.3 攻击可行性评估

| 攻击向量 | 可行性 | 影响 |
|---------|:------:|------|
| Justin Sun 提取/撤资 | HIGH | 灾难性 — 控制大部分 TVL |
| SEC 监管行动冻结 Sun 资产 | MEDIUM | 灾难性 |
| stUSDT 挤兑 | MEDIUM | 高 — 级联清算 |
| 新市场上线空池攻击 | LOW | 中 |
| 智能合约漏洞 | LOW | 高 — 但代码久经战斗测试 |

### 2.4 审计与赏金

- CertiK 审计 (2022): 16 项发现，**6 项 Major 全部为中心化/特权问题**
- Immunefi 赏金: 最高 **$50,000** — 对 $3B+ 协议极度不足 (行业标准 $500K-$10M+)
- 赏金以 USDD 支付 (非 USD)

**风险评级: 🔴 HIGH-CRITICAL** — 技术风险中等，但中心化/对手方风险极高

---

## 3. Maple Finance ($2.3B) — Ethereum

### 3.1 架构概述

Maple 是机构化欠抵押借贷协议，使用 "Pool Delegate" 模型。

| 合约 | 地址 |
|------|-----|
| MapleGlobals (Proxy) | `0x804a6F5F667170F545Bf14e5DDB48C70B788390C` |
| Governor/Timelock | `0x2eFFf88747EB5a3FF00d4d8d0f0800E306C0426b` |
| DAO Multisig | `0xd6d4Bcde6c816F17889f1Dd3000aF0261B03a196` (4/7) |
| Security Admin | `0x6b1A78C1943b03086F7Ee53360f9b0672bD60818` (3/6) |
| syrupUSDC Pool | `0x80ac24aA929eaF5013f6436cdA2a7ba190f5Cc0b` |
| syrupUSDT Pool | `0x356B8d89c1e1239Cbbb9dE4815c39A1474d5BA7D` |

### 3.2 关键发现

#### ⚠️ 关键发现: Pool Delegate Cover 全部为零 — CRITICAL

**链上验证:**

| 池 | Cover 合约 | 余额 |
|----|-----------|------|
| syrupUSDC ($1.73B) | `0x9e62FE15...` | **0 USDC** |
| syrupUSDT ($933M) | `0x610d99d8...` | **0 USDT** |
| Secured Lending ($83M) | `0x98005A88...` | **0 USDC** |

**所有活跃池的 first-loss capital 为零。** 这意味着:
- Pool delegate 无链上利益捆绑
- 违约事件中 100% 损失由存款人承担
- 与 2022 年改革后承诺的 "first loss capital" 直接矛盾

#### 发现 2: 2022 年信用危机 — $54M+ 违约

- **Orthogonal Trading 违约 $36M** (2022.12): FTX 暴露, 4周虚假陈述
- 受害者: Nexus Mutual, Sherlock (审计平台)
- 活跃贷款从 $900M 暴跌至 $82M
- 两名前池管理者: **Celsius** 和 **Alameda** 已破产

#### 发现 3: Pool Delegate 可半 rug

Pool delegate 无法直接盗窃，但可以:
1. 贷款给同伙 → 同伙违约
2. 损失 100% 由 LP 承担 (cover = 0)
3. delegate 链上零损失

### 3.3 正面发现

- 无历史智能合约漏洞
- 多轮审计 (Spearbit, Sherlock, Code4rena)
- ERC-4626 标准 + bootstrapMint 防操纵
- 提款冷却期防闪电贷攻击

**风险评级: 🔴 HIGH** — 信用风险是根本性的，零 first-loss 是致命缺陷

---

## 4. Pendle Finance ($2.2B) — Ethereum

### 4.1 架构概述

Pendle V2 是收益率代币化协议，将生息资产拆分为 PT (本金) + YT (收益)。

| 合约 | 地址 |
|------|-----|
| Router V4 | `0x888888888889758F76e7103c6CbF23ABbF58F946` |
| Governance Multisig | `0x8119EC16F0573B7dAc7C0CB94EB504FB32456ee1` (3/5) |
| PT/YT/LP Oracle | `0x5542be50420E88dd7D5B4a3D488FA6ED82F6DAc2` |
| PENDLE Token | `0x808507121b80c02388fad14726482e061b8da827` |
| vePENDLE | `0x4f30A9D41B80ecC5B94306AB4364951AE3170210` |
| MarketFactory V6 | `0x6d247b1c044fA1E22e6B04fA9F71Baf99EB29A9f` |

### 4.2 关键发现

#### 发现 1: 下游协议 Oracle 操纵风险 — MEDIUM-HIGH

Pendle Oracle 提供 TWAP 定价，被 Aave ($1.6B+ PT 抵押品), Morpho, Euler 使用。

- **低流动性市场可被操纵**: 持续 15-30 分钟的多区块操纵可移动 TWAP
- **接近到期市场**: PT 接近 1:1 时 AMM 极度敏感，Killswitch 在 96% 触发
- **Oracle 无许可**: 任何 Factory 创建的市场都获得 Oracle 能力

**链上验证**: TWAP 在正常条件下稳定 (1s vs 30min 偏差 < 0.0001%)

#### 发现 2: 治理中心化 — 3/5 Multisig — MEDIUM

- 单个 3/5 多签控制: Router, 所有 Factory, Oracle, MarketFactory
- Dev Multisig 仅 2/5 门槛
- **无 timelock** — 区别于大多数同级协议

**双刃剑**: Penpie 攻击 ($27M) 期间 Pendle 暂停合约保护了 $105M

#### 发现 3: PT 在 Aave 上的集中暴露 — HIGH (下游风险)

- PT-sUSDe 约 2/3 总供应在 Aave 上作为抵押品
- PT 价格下跌 $0.12 → 可能产生 $7M 坏账
- USDe 脱锚 → Aave Oracle 锚定 USDe = $1 → 清算不会触发 → 系统性风险

### 4.3 攻击可行性

| 攻击 | 可行性 | 原因 |
|------|:------:|------|
| 闪电贷操纵主要市场 | VERY LOW | 15分钟 TWAP 抵抗单块操纵 |
| 多块 TWAP 操纵 (稀薄市场) | MEDIUM | 需持续资本, 小市场可行 |
| 3/5 多签妥协 | LOW | 无 timelock 增加风险 |

**风险评级: 🟡 MEDIUM** — 核心协议安全，风险主要在下游集成

---

## 5. SparkLend ($1.96B) — Ethereum

### 5.1 架构概述

SparkLend 是 Aave V3 Fork，由 Sky/MakerDAO SubDAO 治理。

| 合约 | 地址 |
|------|-----|
| Pool (Proxy) | `0xC13e21B648A5Ee794902342038FF3aDAB66BE987` |
| ACL Admin | `0x3300f198988e4C9C63F75dF86De36421f06af8c4` (Spark SubDAO Proxy) |
| Price Oracle (AaveOracle) | `0x8105f69D9C41644c6A0803fDA7D03Aa70996cFD9` |
| SPK Token | `0xc18118dB11D2afCf3318daD9cfFb93AA8fd1CDFb` |

**活跃储备:** 18 种资产 (DAI, sDAI, USDC, WETH, wstETH, WBTC, GNO, rETH, USDT, weETH, cbBTC, sUSDS, USDS, LBTC, tBTC, ezETH, rsETH, PYUSD)

### 5.2 关键发现

#### 发现 1: 三重 Oracle 聚合器 — 行业领先

链上验证 WETH Oracle 描述:
> "Aggregated price feed ETH/USD from Chronicle, Chainlink, and RedStone oracles"

- **Aggor** 聚合三个独立 Oracle 网络
- 消除单点 Oracle 依赖
- 操纵可行性: **极低** — 需同时攻破三个独立网络

**链上验证价格:**
| 资产 | 价格 |
|------|------|
| WETH | $2,066.34 |
| WBTC | $70,414.89 |
| wstETH | $2,540.04 |
| sDAI | $1.1731 |

#### 发现 2: ALLOCATOR-SPARK-A — $2.92B 系统耦合 — MEDIUM-HIGH

- 当前债务: **~$2.92B** (Sky 直接铸造 USDS 进入 SparkLend)
- 债务上限: ~$3.56B (利用率 82%)
- **若 SparkLend 发生大规模清算 → Sky/MakerDAO 直接承受损失**
- **若 USDS 脱锚 → 固定价格 Oracle ($1.00) 不会重新定价 → 欠抵押借款**

缓解: `DIRECT_MOM` 断路器, `gap` 限额 40M DAI, `ttl` 24h 冷却

#### 发现 3: Aave V3 Fork 分叉差异 — MEDIUM

- 分叉自 Aave V3 v3.0.1/3.0.2
- Aave 已发展至 v3.6，包含多项安全改进
- SparkLend 仅在 GitHub 上发布 v1.0.0
- 2024年4月已修补闪电贷-借款漏洞
- 但后续安全修复可能未完全同步

### 5.3 正面发现

- 零历史安全事件 (2023年5月上线至今)
- $5M Immunefi 赏金
- GSM (治理安全模块) 延迟
- 闪电贷-借款功能已禁用

**风险评级: 🟡 MEDIUM** — Oracle 出色, D3M 耦合是最大系统性风险

---

## 6. Kamino Lend ($2.0B) — Solana

### 6.1 架构概述

Kamino 是 Solana 上最大的 DeFi 借贷协议。

| 参数 | 值 |
|------|---|
| Program ID | `KLend2g3cP87fffoy8q1mQqGKjrxjC8boSyAYavgmjD` |
| 升级权限 | Squads v4 Vault PDA (`GzFgdRJX...`) |
| Multisig | `6hhBGCtmg7tPWUSgp3LG6X2rsmYWAc4tNsA6G4CnfQbM` |
| 门槛 | **5-of-10** |
| Timelock | **43,200 秒 (12小时)** |
| 历史升级次数 | 63 次 |

### 6.2 关键发现

#### 发现 1: Scope 多源 Oracle — 行业领先

- **Pyth** (主要, 正在弃用) + **Chainlink Data Streams** (2025年4月集成) + **Switchboard**
- TWAP/EWMA 平滑: 拒绝闪崩价格
- 价格带: 稳定/挂钩资产有预期范围
- 陈旧检查 + 异常价格排除
- **Fail-closed 设计**: 任何 feed 过期或冲突 → 安全失败

#### 发现 2: 零坏账记录 — 行业最佳

| 日期 | 事件 | 清算量 | 坏账 |
|------|------|--------|------|
| 2025-02/03 | SOL -26% | $22.1M | **$0** |
| 2025-04 | SOL -21% (关税) | $16M | **$0** |
| 2025-10 | SOL -14% (1小时) | $25.5M | **$0** |
| 2025-11 | SOL -29% | $26.5M | **$0** |
| 2026-02 | SOL -18% | $19.36M | **$0** |

#### 发现 3: 安全审计覆盖度最高

- **18+ 独立审计** + **4 次 Certora 形式化验证**
- Ackee Blockchain 高级 fuzzing: 数百万指令, 零偿付风险
- **$1.5M Immunefi 赏金** (Solana 最大)
- 发布前 $500K hack 挑战: 无人成功

### 6.3 残余风险

| 风险 | 等级 | 说明 |
|------|:----:|------|
| Solana 宕机 | MEDIUM | 历史宕机期间清算冻结 |
| Jito MEV 清算提取 | MEDIUM | 95%+ 验证者运行 Jito 客户端 |
| 程序可升级 | MEDIUM | 5/10 + 12h timelock |
| 三 Oracle 同时失败 | LOW | 理论可能但极不实际 |

**风险评级: 🟢 LOW-MEDIUM** — Solana 上安全性最佳的 DeFi 协议

---

## 7. PancakeSwap AMM ($1.65B) — BNB Chain

*⚠️ Agent 因 API 限制未完成，待下一批次补充*

**初步评估 (基于公开信息):**
- Uniswap V3 Fork + CAKE 激励
- BNB Chain 21 验证者 → 中心化风险
- 三明治攻击在 BNB Chain 上特别猖獗 (低出块时间)
- 历史: 多次闪电贷攻击事件

**暂定风险评级: 🟡 MEDIUM** *(待深度审计确认)*

---

## 8. Venus Protocol ($1.26B) — BNB Chain

### 8.1 架构概述

Venus 是 BNB Chain 上最大的借贷协议，Diamond Proxy 架构。

| 合约 | 地址 |
|------|-----|
| Comptroller (Diamond) | `0xfD36E2c2a6789Db23113685031d7F16329158384` |
| Timelock | `0x939bD8d64c0A9583A7Dcea9933f7b21697ab6396` (48h) |
| GovernorBravo | `0x2d56dC077072B53571b8252008C60e945108c75a` |
| Resilient Oracle | `0x6592b5DE802159F3E74B2486b091D11a8256ab8A` |
| Pause Guardian | `0x1C2CAc6ec528c20800B2fe734820D87b581eAA6B` (3/5) |

**核心池 TVL:**
- vBNB: ~588K BNB (~$384M)
- vBTC: ~6,725 BTC (~$475M)
- vUSDT: ~$227M
- vUSDC: ~$73M

### 8.2 关键发现

#### 发现 1: 治理攻击成本过低 — MEDIUM

- 提案门槛: 300,000 XVS (~$876K)
- 法定人数: 600,000 XVS (~**$1.75M**)
- **$1.75M 控制 $1.26B 协议 = 0.14% 攻击成本比**
- 对比 Compound: ~$25M+ 法定人数

缓解: 48h timelock + 3/5 guardian 可取消

#### 发现 2: 历史灾难性事件

| 事件 | 日期 | 损失 |
|------|------|------|
| XVS 价格操纵 → 借出 4200 BTC | 2021-05 | **~$100M 坏账** |
| BNB 桥攻击者存入 900K BNB | 2022-10 | $150M 被借走 |
| ERC-4626 Oracle 操纵 (zkSync) | 2025-03 | $902K |
| 钓鱼攻击 → 强制清算追回 | 2025-09 | $13.5M (已追回) |

**2021年后改进:** Supply/borrow caps, Resilient Oracle (多源), Diamond proxy

#### 发现 3: 同一多签控制双重角色 — MEDIUM

Pause Guardian 和 Governor Guardian 是**同一个** 3/5 多签:
- 若 3/5 被攻破 → 可冻结协议 + 阻止防御性治理提案
- 双重角色集中化增加风险

#### 发现 4: XVS 60% 抵押因子仍然激进 — MEDIUM

- 治理代币保持 60% CF (行业中偏高)
- 缓解: Supply cap 1.85M XVS, borrow cap = 0

### 8.3 BNB Chain 平台风险

- 仅 21 个验证者，全部由 Binance 批准
- Binance 可暂停链 (2022年桥攻击中已发生)
- 2025年钓鱼事件显示: Venus 团队可单方面暂停 + 强制清算

**风险评级: 🟠 MEDIUM-HIGH** — 已从 2021 灾难中学习，但治理成本过低

---

## 9. Compound V3 ($1.29B) — Ethereum

### 9.1 架构概述

| 合约 | 地址 |
|------|-----|
| USDC Comet (Proxy) | `0xc3d688B66703497DAA19211EEdff47f25384cdc3` |
| WETH Comet (Proxy) | `0xA17581A9E3356d9A858b789D68B4d866e593aE94` |
| CometProxyAdmin | `0x1EC63B5883C3481134FD50D5DAebc83eCd2E8779` |
| Timelock | `0x6d903f6003cca6255D85CcA4D3B5E5146dC33925` (2天) |
| GovernorBravo | `0x309a862bbC1A00e45506cB8A802D1ff10004c8C0` |

**市场状态:**
- USDC: Supply $412M, Borrow $268M, 利用率 65%
- WETH: Supply 30,686 ETH, Borrow 28,679 ETH, **利用率 93.45%** (极高!)

### 9.2 关键发现

#### 发现 1: 代理升级 = 全部 TVL 风险 — CRITICAL (理论)

**攻击路径:**
1. 积累 25,000 COMP (提案门槛, ~$1.2M)
2. 提交调用 `CometProxyAdmin.upgrade()` 的提案
3. 恶意实现包含 `drain()` 函数
4. 若通过并执行 → **$1.29B 全部可被盗**

**V3 vs V2 对比:**
- V3 使用内部余额追踪 (无 cToken) → 恶意升级**更危险**
- V2 的 cToken 是独立合约，V3 的代理合约直接持有所有资产
- DeFiScan 评级: **Stage 0** (最低去中心化)

**6.5天最低时间线** (投票延迟 + 投票期 + timelock) 提供检测窗口

#### 发现 2: Proposal 289 — 治理攻击已被证实可行 — HIGH

- 2024年7月: 鲸鱼 "Humpy" 积累 COMP → 通过 $24M 国库提案
- 最终通过谈判取消 (以 COMP 质押交易换取)
- **证明治理攻击不是理论，是现实**

#### 发现 3: 无 Oracle 后备 — MEDIUM

- 完全依赖 Chainlink 价格 feed
- 合约内**无价格验证/边界检查**
- **无后备 Oracle** — Chainlink 妥协 = 灾难

#### 发现 4: WETH 市场利用率过高 — MEDIUM

- 93.45% 利用率接近 kink 点
- 仅 ~2,008 ETH 可供提取
- 提款需求激增 → 流动性危机

### 9.3 抵押品风险

新增的 USDe (Ethena) 抵押品:
- 抵押因子 **89%**, 清算因子 94%
- 对合成资产来说过于激进
- USDe 脱锚 → 坏账 → 消耗 $14M 储备

**风险评级: 🟠 MEDIUM-HIGH** — 代理升级是结构性弱点

---

## 10. Fluid Lending ($1.03B) — Ethereum

### 10.1 架构概述

Fluid (前 Instadapp) 使用创新的 **Liquidity Layer** 架构，统一借贷和 DEX。

**核心组件:**
- **Liquidity Layer**: 所有资产集中存储的中心合约
- **Lending Protocol (fToken)**: ERC-4626 vault shares, 仅存款
- **Vault Protocol**: 借款协议，单资产-单债务，LTV 高达 95%
- **DEX Protocol**: Smart Collateral + Smart Debt
- **自动化限额**: 每区块动态调整债务/抵押品上限

### 10.2 关键发现

#### 发现 1: 零历史漏洞 — LOW

- Instadapp 7年**零用户资金损失**
- Fluid 上线近2年无事件
- 发布前 $500K hack 挑战: 无人成功

#### 发现 2: 广泛审计覆盖

- Cantina 竞赛 (2024): 13 项发现 (div-by-zero, Oracle 计算错误)
- MixBytes 审计 (2024): "高安全度"但代码为 gas 优化牺牲了可读性
- Sherlock DEX V2 竞赛: $200K 奖金池
- Certora 形式化验证: $500K 预算
- Immunefi 赏金: 高达 $500K

#### 发现 3: 从团队多签过渡到 DAO 治理

- 最初: 10天锁定多签
- IGP #1: 替换为治理 timelock
- 投票期 ~3天 + 2天 timelock
- 紧急多签保留用于安全暂停

#### 发现 4: 创新安全机制

- **自动化限额**: 按区块动态调整上限，防止鲸鱼闪电操作
- 即使存在代码漏洞，Liquidity Layer 也会限制异常大额操作
- 为社区多签争取响应时间

### 10.3 风险评估

| 风险 | 等级 |
|------|:----:|
| 智能合约 | LOW |
| Oracle | LOW-MEDIUM |
| 治理 | MEDIUM (过渡中) |
| 创新架构风险 | MEDIUM (新设计缺乏长期验证) |
| 历史记录 | LOW (7年零事件) |

**风险评级: 🟢 LOW-MEDIUM** — 创新架构 + 零历史漏洞

---

## 11. Ondo Finance ($2.5B) — Ethereum

### 11.1 架构概述

Ondo Finance 是 RWA (Real World Assets) 代币化协议，将美国国债等传统金融资产代币化。

| 合约 | 地址 |
|------|-----|
| OUSG (Proxy) | `0x1b19c19393e2d034d8ff31ff34c81252fcbbee92` |
| USDY | `0x96F6eF951840721AdBF46Ac996b59E0235CB985C` |
| rOUSG (Rebasing) | `0xb0514a5a3Ed1F0a4F9F40A8a81CE87A42299a0e6` |
| OUSG Multisig | `0xAEd4caF2E535D964165B4392342F71bac77e8367` (4/7) |
| USDY Multisig | `0x1a694A09494E214a3Be3652e4B343B4A81026358` (4/7) |

### 11.2 关键发现

#### 发现 F-01: 无 Timelock 可升级代理 — HIGH

- OUSG 和 USDY 合约均为 TransparentUpgradeableProxy
- proxyAdmin 直接由 4/7 multisig 控制
- **无 timelock** — 升级可立即执行
- 4/7 签名者中任意 4 人合谋可替换合约实现，可能影响全部 TVL

#### 发现 F-02: Off-Chain Oracle 无边界检查 — MEDIUM-HIGH

- OUSG 价格由管理员通过 `setPrice()` 手动设置
- **无上下文检查**: 管理员可设置任何价格
- **无变化幅度限制**: 可一次性将价格从 $100 改为 $0.01
- **无链上验证**: 不与 Chainlink 或其他 Oracle 交叉验证
- 依赖管理员诚实和运营安全

#### 发现 F-03: 转账冻结能力 — MEDIUM

- OUSG 和 USDY 合约包含 `freeze()` / `unfreeze()` 函数
- 管理员可冻结任何持有者的代币
- 虽然这是 RWA 合规的标准功能，但增加了中心化风险
- **与 USDC 的 blacklist 类似，但粒度更细**

#### 发现 F-04: 4 个独立 USDY Minter — MEDIUM

- USDY 有 4 个地址拥有独立铸造权
- 任何一个 minter 被攻破 → 可无限铸造 USDY
- 无铸造速率限制或上限

#### 发现 F-05: 多签签名者重叠 — MEDIUM

- OUSG 4/7 和 USDY 4/7 多签共享 **5 个相同签名者**
- 攻破这 5 人中的 4 人 → 同时控制 OUSG 和 USDY
- 有效降低了安全分离度

#### 发现 F-06: rOUSG Rebasing 价格依赖 — MEDIUM

- rOUSG 通过 `getROUSGByShares()` 计算余额
- 依赖 OUSG Oracle 价格 → 若 F-02 被利用，rOUSG 余额同步失真
- 连锁效应扩大 Oracle 操纵影响

#### 发现 F-07: 无紧急暂停机制 — LOW-MEDIUM

- 未发现独立的 pause guardian 角色
- 紧急情况下需要 4/7 多签共识
- 响应速度受限于签名者可用性

#### 发现 F-08: KYC 绕过风险 — LOW

- OUSG/USDY 有 KYC 白名单检查
- 但二级市场 (DEX) 上的交易可绕过
- Ondo 已通过包装代币 (wOUSG, wUSDY) 管理此问题

### 11.3 攻击可行性评估

| 攻击向量 | 可行性 | 影响 |
|---------|:------:|------|
| 4/7 多签攻破 → 升级合约 drain | LOW | CRITICAL — 全部 TVL |
| Oracle setPrice() 操纵 | LOW-MEDIUM | HIGH — 任意定价 |
| Minter 攻破 → 无限铸造 USDY | LOW | HIGH — 稀释全部持有者 |
| 监管冻结 | MEDIUM | HIGH — 全部资产冻结 |
| 底层 RWA 违约 | VERY LOW | HIGH — 但有美国国债背书 |

### 11.4 正面发现

- 底层资产为美国短期国债 — 信用风险极低
- 多轮审计 (Code4rena, Ackee Blockchain)
- KYC/AML 合规框架完善
- USDY 已通过监管审批
- 资产管理透明度较高 (月度证明)

**风险评级: 🟡 MEDIUM** — RWA 合规性需要中心化，但无 timelock + Oracle 无边界是可改进的

---

## 12. 跨协议比较分析

### 11.1 Oracle 安全性排名

| 排名 | 协议 | Oracle 架构 | 评分 |
|:----:|------|------------|:----:|
| 1 | SparkLend | Aggor (Chronicle + Chainlink + RedStone) | ⭐⭐⭐⭐⭐ |
| 2 | Kamino | Scope (Pyth + Chainlink + Switchboard + EWMA) | ⭐⭐⭐⭐⭐ |
| 3 | Pendle | 内嵌几何均值 TWAP | ⭐⭐⭐⭐ |
| 4 | Venus | Resilient Oracle (多源验证) | ⭐⭐⭐⭐ |
| 5 | JustLend | Chainlink (2024年迁移) | ⭐⭐⭐ |
| 6 | Compound V3 | Chainlink (单源, 无后备) | ⭐⭐⭐ |
| 7 | Maple | Chainlink (有限依赖, 主要是信用风险) | ⭐⭐⭐ |
| 8 | Ondo | Off-chain admin setPrice(), **无边界检查** | ⭐⭐ |

### 11.2 治理安全性排名

| 排名 | 协议 | 治理架构 | 攻击成本 | 评分 |
|:----:|------|---------|---------|:----:|
| 1 | SparkLend | MKR 治理 + GSM 延迟 | 数亿$ | ⭐⭐⭐⭐⭐ |
| 2 | Kamino | 5/10 Squads + 12h timelock | N/A | ⭐⭐⭐⭐ |
| 3 | Maple | 4/7 多签 + timelock | N/A | ⭐⭐⭐⭐ |
| 4 | Compound V3 | GovernorBravo + 2d timelock | ~$1.2M | ⭐⭐⭐ |
| 5 | Venus | GovernorBravo + 48h timelock | ~$1.75M | ⭐⭐⭐ |
| 6 | Pendle | 3/5 多签, **无 timelock** | N/A | ⭐⭐ |
| 7 | Ondo | 4/7 多签, **无 timelock**, 签名者重叠 | N/A | ⭐⭐ |
| 8 | JustLend | GovernorBravo (形同虚设) | N/A | ⭐ |

### 11.3 坏账记录对比

| 协议 | 历史坏账 | TVL | 坏账/TVL |
|------|---------|-----|---------|
| Kamino | **$0** | $2.0B | 0% |
| Fluid | **$0** | $1.03B | 0% |
| SparkLend | **$0** | $1.96B | 0% |
| Pendle | **$0** (核心) | $2.2B | 0% |
| Compound V3 | **~$0** | $1.29B | ~0% |
| JustLend | 未知 | $3.16B | 未知 |
| Maple | **$54M+** | $2.3B | 2.3%+ |
| Venus | **~$100M+** | $1.26B | 7.9%+ |

### 11.4 关键洞察

1. **信用风险 > 智能合约风险**: Maple ($54M) 和 Venus ($100M) 的损失都来自信用/治理失败，非代码漏洞

2. **Oracle 已成行业分水岭**: SparkLend/Kamino 的多源聚合 vs Compound V3 的单源 Chainlink — 差距巨大

3. **Solana vs EVM 安全模型差异**: Kamino 的 Squads multisig + 程序升级 vs EVM 的 proxy + governance — 各有利弊

4. **RWA 协议的根本矛盾**: JustLend/stUSDT 暴露了链上协议依赖链下资产时的验证困境

5. **"Too Cheap to Attack" 问题**: Venus ($1.75M) 和 Compound ($1.2M) 的治理攻击成本相对于 TVL 过低

---

## 数据来源

### 链上验证
- Ethereum: `cast call` via ethereum-rpc.publicnode.com
- BNB Chain: `cast call` via bsc-rpc.publicnode.com
- Solana: `@solana/web3.js` via api.mainnet-beta.solana.com
- TRON: TronScan API

### 审计报告
- CertiK (JustLend), Spearbit/Sherlock/Code4rena (Maple), ChainSecurity (Pendle/SparkLend)
- Certora (Kamino/Fluid), OpenZeppelin (Compound), MixBytes (Fluid)

### 安全研究
- DefiLlama TVL data, Immunefi bug bounties, DeFiSafety ratings
- Rekt.news, ChainArgos investigations, LlamaRisk assessments

---

*本报告用于安全研究和防御目的。所有链上查询为只读操作，未修改任何协议状态。*
*待补充: PancakeSwap 深度审计, BlackRock BUIDL 审计, Falcon Finance 审计*
