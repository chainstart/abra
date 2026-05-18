// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Test.sol";

abstract contract BaseForkTest is Test {
    string internal rpcAlias;
    uint256 internal forkBlock;
    uint256 internal forkId;
    bool internal forkInitialized;

    function _initFork(string memory aliasName, uint256 blockNumber) internal {
        rpcAlias = aliasName;
        forkBlock = blockNumber;
        forkId = vm.createSelectFork(aliasName, blockNumber);
        forkInitialized = true;
    }

    function _assertForkInitialized() internal view {
        require(bytes(rpcAlias).length != 0, "fork alias not configured");
        require(forkBlock != 0, "fork block not configured");
        require(forkInitialized, "fork not initialized");
    }
}
