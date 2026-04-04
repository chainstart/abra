// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IERC20Like {
    function transfer(address to, uint256 amount) external returns (bool);
}

contract CrossContractFlowPrototype {
    IERC20Like public token;
    mapping(address => uint256) public balances;

    constructor(IERC20Like _token) {
        token = _token;
    }

    // 这里故意保留“外部调用后写状态”的模式，
    // 方便验证深语义分析器是否能识别执行顺序风险。
    function withdraw(uint256 amount) external {
        token.transfer(msg.sender, amount);
        balances[msg.sender] -= amount;
    }
}
