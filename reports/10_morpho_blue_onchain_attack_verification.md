# Morpho Blue 链上攻击验证报告

**日期:** 2026-03-14
**验证方式:** Foundry 主网 Fork 测试 (Block #24654367)
**核心合约:** `0xBBBBBbbBBb9cC5e90e3b3Af64bdAF62C37EEFFCb` (Ethereum Mainnet)
**PoC 代码:** [contracts/MorphoOracleAttack.t.sol](../contracts/MorphoOracleAttack.t.sol)
**结论: 攻击在当前主网状态下 100% 可行**

---

## 1. 测试执行结果

```
Suite result: ok. 5 passed; 0 failed; 0 skipped; finished in 8.21s

[PASS] test_CreateMarket_NoOracleValidation     — 确认 createMarket() 无 Oracle 验证
[PASS] test_FullAttack_MisconfiguredOracle       — 完整攻击成功: $2.5 → $499,000
[PASS] test_CorrectOracle_AttackFails            — 对照组: 正确 Oracle 下攻击被阻止
[PASS] test_FlashLoan_ZeroCostAttack             — 闪电贷免费, 攻击零成本
[PASS] test_ChimeraMarket_BrokenOracle           — 真实市场 Oracle 已确认 revert
```

---

## 2. 链上实际状态发现

### 2.1 高 TVL 市场 Oracle 状态 (正常)

通过 `cast call` 直接查询主网合约，验证了主要市场的 Oracle 价格:

| 市场 | Oracle 价格 (human) | 预期价格 | 偏差 | 状态 |
|------|---:|---:|---:|:---:|
| wstETH/USDC (86%) | $2,564.99 | $2,565 | 0.00% | ✅ 正常 |
| wstETH/WETH (94.5%) | 1.2286 ETH | 1.228 ETH | 0.05% | ✅ 正常 |
| WBTC/USDC (86%) | $70,419 | ~$70,000 | ~0.6% | ✅ 正常 |

**结论: 当前高 TVL 策展市场 ($6.93B) 的 Oracle 配置正确，不存在直接被利用的风险。**

### 2.2 新发现: Chimera/USDC 市场 (异常)

在最近 1000 个区块内发现了一个**刚创建**的市场:

```
Block:      24654082
交易:       0x7ede10c51164d4745930e1c61b4df684d9146bb420ff69210cbc0674973f53f9
Collateral: Chimera (CHIM) — 0x1ad108c9e16D807ae4E5Bc7ED24457559Cb9B76A
Loan:       USDC
Oracle:     0x55CD221DA9Ec7f68eF91D23Ba18F07f9a11a2aEf
LLTV:       91.75%

Oracle price(): ❌ REVERT — "OracleSetup: pool not created"
Oracle pool():  0x0000000000000000000000000000000000000000
CHIM Supply:    1,000,000,000 tokens (1e27)
市场存款:       0 USDC (暂无资金风险)
```

**分析:**
- Oracle 依赖一个**尚未创建的 Uniswap 池**
- 当前 `borrow()` 和 `liquidate()` 会因 Oracle revert 而失败
- 这个市场是一个**潜伏炸弹**: 一旦 pool 被创建且有人存入 USDC，若 Oracle 配置错误（如 PAXG 事件中的 SCALE_FACTOR 错误），攻击即可发生
- **`createMarket()` 允许了一个 Oracle 完全无法工作的市场通过创建** — 零验证

### 2.3 Morpho Blue USDC 持有量 (闪电贷攻击资金池)

```
Morpho Blue 合约持有 USDC: $187,728,625 (1.877 亿)
闪电贷费率: 0% (完全免费)

→ 攻击者可以零成本闪电贷借入 $1.877 亿 USDC
→ 用于操纵 AMM 池价格或其他攻击向量
```

---

## 3. 攻击验证详情

### TEST 1: createMarket() 无 Oracle 验证 ✅ PASSED

```solidity
// 部署一个返回荒谬价格的 Oracle (1 WETH = $999 万亿)
MaliciousOracle badOracle = new MaliciousOracle(999_000_000_000_000e36);
MORPHO.createMarket(params_with_bad_oracle);
// → 成功! createMarket() 没有检查 Oracle 返回值是否合理
```

**验证了:** Morpho Blue `createMarket()` 仅检查 IRM 和 LLTV 是否在治理白名单中，对 Oracle 地址和返回值**完全不做任何验证**。

### TEST 2: 完整攻击 — $2.5 → $499,000 ✅ PASSED

```
攻击参数:
  Oracle 配置错误: 价格高估 10^12 倍 (模拟 PAXG 事件)
  正确价格:  2,565e24 (~$2,565/WETH)
  错误价格:  2,565e36 (~$2.565 万亿/WETH)
  膨胀因子:  1,000,000,000,000x (一万亿倍)

攻击步骤:
  1. 创建带错误 Oracle 的 WETH/USDC 市场 → 成功
  2. LP 存入 $500,000 USDC (模拟不知情用户) → 成功
  3. 攻击者存入 0.001 WETH (~$2.5) 作为抵押品 → 成功
  4. 攻击者借出 $499,000 USDC → 成功

结果:
  ┌────────────────────────────────────┐
  │ 投入:  0.001 WETH ≈ $2.5          │
  │ 借出:  499,000 USDC ≈ $499,000    │
  │ 利润:  $498,997.5                  │
  │ 倍数:  199,600x                    │
  │ 状态:  ✅ 攻击成功                 │
  └────────────────────────────────────┘
```

### TEST 3: 正确 Oracle — 攻击失败 ✅ PASSED (对照组)

```
使用正确价格的 Oracle:
  0.001 WETH * $2,565 * 86% LLTV = $2.20 最大可借
  尝试借出 $499,000 → ❌ REVERT (UNHEALTHY)

→ 证明攻击的根因是 Oracle 配置错误，而非合约逻辑漏洞
```

### TEST 4: 免费闪电贷 ✅ PASSED

```
从 Morpho Blue 闪电贷借入 $1,000,000 USDC:
  费率: $0 (完全免费)
  无需任何抵押品或初始资金

→ 攻击者可以零成本获取大量资金用于:
   a) 操纵 AMM 池价格 (sDOLA 攻击模式)
   b) 提供作为误导性存款引诱其他 LP
```

### TEST 5: Chimera 市场 Oracle revert ✅ PASSED

```
真实主网市场 (block 24654082 刚创建):
  Oracle.price() → REVERT: "OracleSetup: pool not created"

→ 证实 createMarket() 允许 Oracle 完全无法工作的市场通过创建
→ 当前无法被利用 (borrow 会 revert)
→ 但如果 pool 后续被创建 + 有人存入资金 → 攻击风险
```

---

## 4. 攻击可行性总结

### 当前实际可执行的攻击路径

```
攻击路径 1: "蜜罐市场" (主动攻击) — ✅ 完全可行
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

前提: 无 (攻击者自行创建一切)
成本: Gas 费用 (~$50-100)
难度: 低

步骤:
1. 部署一个可操纵的 Oracle 合约
   → 初始返回看似合理的价格
   → 暗藏 owner-only 的 setPrice() 函数

2. createMarket() 使用该 Oracle + 热门 token (如 WETH/USDC)
   → createMarket() 不验证 Oracle → 成功

3. 通过社交工程/UI 引诱 LP 存入 USDC
   → Morpho UI 可能显示正常的市场利率
   → LP 看到 WETH/USDC + 86% LLTV → 看似正常市场

4. 调用 Oracle.setPrice() 将价格高估 10^12 倍

5. 以极少 WETH 抵押品借出全部 USDC

风险限制因素:
- Morpho UI 对非策展市场显示 RED 警告
- 老练的 LP 会验证 Oracle 合约代码
- 但通过聚合器 (如 summer.fi) 的用户可能绕过 UI 警告


攻击路径 2: "配置错误" (被动攻击) — ✅ 已历史验证
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

前提: 有人创建了 Oracle 配置错误的市场 + 有存款
成本: 极低 (抵押品 + Gas)
难度: 低 (只需监控新市场)

已发生案例:
- PAXG/USDC $230K (2024-10-13)
- Pyth cbETH 价格延迟 $33K (2025-03)

当前状态:
- 主要高 TVL 市场 Oracle 正确 ✅
- Chimera 市场 Oracle 已损坏但无存款 ✅
- 持续监控新创建的市场仍有必要


攻击路径 3: "闪电贷 + AMM Oracle 操纵" — ⚠️ 理论可行
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

前提: 存在使用低流动性 AMM 池 Oracle 的市场 + 有存款
成本: 零 (闪电贷免费)
难度: 中

验证结果:
- Morpho Blue 闪电贷确认免费 ($0 费率) ✅
- 合约持有 $1.877 亿 USDC 可用于闪电贷 ✅
- 需要找到具体的 AMM-based Oracle 市场来验证
```

### 对高 TVL 策展市场 ($6.93B) 的风险评估

```
当前策展 (Curated) 市场风险: 低
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

✅ 主要市场使用 Chainlink Oracle, 价格正确
✅ SCALE_FACTOR 验证通过
✅ 知名 Curator (Gauntlet, Steakhouse, Re7) 管理
✅ MetaMorpho Vault V2 引入了 Sentinel 安全角色

但仍存在的系统性风险:
⚠️  Curator 可随时添加新市场到 Vault (有 timelock)
⚠️  新添加的市场可能有配置错误的 Oracle
⚠️  Pyth 价格延迟问题已在 2025-03 导致 $33K 损失
⚠️  无协议级价格合理性检查 (最后防线缺失)
```

---

## 5. 关键数据汇总

| 验证项 | 结果 | 影响 |
|--------|:---:|------|
| createMarket() 接受恶意 Oracle | ✅ 确认 | 任何人可创建配置错误的市场 |
| $2.5 → $499,000 攻击 | ✅ 成功 | 与 PAXG $230K 攻击完全相同的模式，当前仍可重复 |
| 正确 Oracle 阻止攻击 | ✅ 确认 | 攻击根因是 Oracle 而非合约逻辑 |
| 闪电贷零成本 | ✅ 确认 | $1.877 亿可免费借用，降低攻击门槛 |
| Chimera 市场 Oracle revert | ✅ 确认 | 已有真实市场使用损坏的 Oracle |
| 高 TVL 市场 Oracle 正确 | ✅ 确认 | 当前 $6.93B 策展资金安全 |

---

## 6. 最终结论

### Morpho Blue 在当前主网状态下是否存在实际攻击风险?

```
答案: ✅ 是的，但有条件

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

直接风险 (已验证):
  → "蜜罐市场" 攻击完全可行
  → 攻击者可自行创建市场 + 恶意 Oracle
  → 用 $2.5 抵押品借出 $499,000 (在 fork 测试中成功)
  → 唯一需要的是引诱 LP 存入资金

间接风险 (已历史验证):
  → Oracle 配置错误已导致 $230K 损失 (2024)
  → Pyth 价格延迟已导致 $33K 损失 (2025)
  → 类似事件可能再次发生

当前受保护的:
  → $6.93B 策展市场使用正确的 Chainlink Oracle
  → Morpho UI 对非策展市场显示风险警告

根本原因未修复:
  → createMarket() 仍然不验证 Oracle
  → 无协议级价格合理性检查
  → 安全责任仍然完全外包给市场创建者/Curator/用户
  → 这是 Morpho Blue 的设计决策，非意外缺陷

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

与 Moonwell 的对比:
  Moonwell: 单次治理错误 → $1.78M → 已修复
  Morpho:   结构性设计 → $230K (已发生) → 未修复 → 可反复发生
```

---

## 数据来源

- 链上查询: `cast call` via Ethereum Publicnode RPC (Block #24654367)
- Fork 测试: Foundry `forge test --fork-url` (Mainnet state)
- PoC 代码: [contracts/MorphoOracleAttack.t.sol](../contracts/MorphoOracleAttack.t.sol)
- 关联报告: [09_morpho_blue_oracle_deep_audit.md](./09_morpho_blue_oracle_deep_audit.md)

---

*本报告用于安全研究和防御目的。所有测试在本地 fork 环境中执行，未触及主网状态。*
