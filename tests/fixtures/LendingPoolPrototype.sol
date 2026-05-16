// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract LendingPoolPrototype {
    mapping(address => uint256) public collateral;
    mapping(address => uint256) public debt;
    mapping(address => uint256) public reserves;

    function depositCollateral() external payable {
        collateral[msg.sender] += msg.value;
        reserves[msg.sender] += msg.value;
    }

    function borrow(uint256 amount) external {
        debt[msg.sender] += amount;
    }

    // 这里故意保留一个未受保护的敏感函数，
    // 方便 Phase 1 审计 MVP 验证整条流水线是否能抓到问题。
    function withdraw(uint256 amount) external {
        reserves[msg.sender] -= amount;
    }

    function liquidate(address user) external {
        debt[user] = 0;
    }
}
