// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract AmmPoolPrototype {
    uint256 public liquidity;

    function addLiquidity(uint256 amount) external {
        liquidity += amount;
    }

    function swap(uint256 amountIn) external returns (uint256 amountOut) {
        amountOut = amountIn / 2;
    }
}
