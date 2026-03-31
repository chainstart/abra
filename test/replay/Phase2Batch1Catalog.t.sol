// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "../helpers/BaseForkTest.t.sol";

contract Phase2Batch1CatalogTest is BaseForkTest {
    struct ReplayTarget {
        string name;
        string family;
        uint256 estimatedLossUsd;
        bool hasConcretePoc;
    }

    ReplayTarget[] internal targets;

    function setUp() public {
        targets.push(ReplayTarget("Euler Finance", "flash_loan", 197_000_000, false));
        targets.push(ReplayTarget("Beanstalk", "flash_loan", 182_000_000, false));
        targets.push(ReplayTarget("Cream Finance", "flash_loan", 130_000_000, false));
        targets.push(ReplayTarget("BonqDAO & AllianceBlock", "oracle_manipulation", 120_000_000, false));
        targets.push(ReplayTarget("Fei Protocol & Rari Capital", "reentrancy", 80_000_000, false));
        targets.push(ReplayTarget("xToken", "oracle_manipulation", 25_000_000, false));
        targets.push(ReplayTarget("Lendf.Me", "reentrancy", 24_696_616, false));
        targets.push(ReplayTarget("UwU Lend", "oracle_manipulation", 19_300_000, false));
        targets.push(ReplayTarget("flash.sx", "reentrancy", 11_742_000, false));
        targets.push(ReplayTarget("Cetus", "contract_bug", 230_000_000, false));
        targets.push(ReplayTarget("Balancer V2", "logic_bug", 121_100_000, false));
        targets.push(ReplayTarget("Mirror Protocol", "contract_bug", 90_000_000, false));
    }

    function test_Batch1CatalogLoaded() public view {
        assertEq(targets.length, 12, "unexpected batch size");
    }

    function test_Batch1ContainsHighValueTargets() public view {
        uint256 largeLossCount = 0;
        for (uint256 i = 0; i < targets.length; i++) {
            if (targets[i].estimatedLossUsd >= 50_000_000) {
                largeLossCount++;
            }
        }
        assertGe(largeLossCount, 7, "insufficient high-value targets");
    }
}

