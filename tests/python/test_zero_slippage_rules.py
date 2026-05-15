"""Tests for the rules/zero_slippage_amm.json rule pack.

These rules target the ``amountOutMin = 0`` / ``amountTokenMin = 0`` /
``addLiquidity*(_,_,0,0,...)`` sandwich-vulnerable shape that the serial
sandwich bot 0xF85e7038DaDf1b7ab97BA71528269d82328B7ba4 repeatedly drained
across multiple tokens in late April 2026 — Archangel (tx
0x1da0e6a3...) being the case scryer was used to triage. The bot also hit
0xb4936c61, 0x8f9ac463, 0xf2b7c1e1, 0xb6c7efee in adjacent days using the
same Flash → swap-with-zero-slippage → Withdraw pattern.

The anchor exploit is Saint Michael the Archangel (Ethereum,
0x08495023d2d331c61195a47f0143ed4c43544ca0). Its ``swapTokensForEth``
passes ``0`` as ``amountOutMin`` to Uniswap V2; every auto-tax swap is a
free sandwich.

Note on coverage: ``run_regex_scan`` is line-by-line — multi-line Solidity
call shapes (Archangel's actual style) are intentionally NOT caught by
these regexes; the LLM stage in audit_contracts.py is responsible for that
(verified in runs/archangel_audit: F-03 was caught by Sonnet 4.6). The
regex pack catches the equally-common single-line shape used by smaller
contracts and serves as a fast pre-filter.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from scanners import load_rules_from_file, run_regex_scan

REPO_ROOT = Path(__file__).resolve().parents[2]
RULES_FILE = REPO_ROOT / "rules" / "zero_slippage_amm.json"


@pytest.fixture(scope="module")
def amm_rules() -> list:
    assert RULES_FILE.exists(), f"rules file missing: {RULES_FILE}"
    return load_rules_from_file(RULES_FILE)


def _scan(tmp_path: Path, body: str, rules: list) -> set[str]:
    p = tmp_path / "Vuln.sol"
    p.write_text(body, encoding="utf-8")
    result = run_regex_scan([p], rules=rules)
    return {f["rule_id"] for f in result["findings"]}


# ---------------------------------------------------------------------------
# Rule loading
# ---------------------------------------------------------------------------


def test_rules_load_and_compile(amm_rules: list) -> None:
    ids = [r.rule_id for r in amm_rules]
    assert len(ids) == len(set(ids)), "duplicate rule_id in zero_slippage rule pack"
    expected = {
        "UNISWAP_SWAP_AMOUNT_OUT_MIN_ZERO",
        "UNISWAP_SWAP_ETH_AMOUNT_OUT_MIN_ZERO",
        "UNISWAP_ADD_LIQUIDITY_ZERO_MIN",
        "UNISWAP_DEADLINE_BLOCK_TIMESTAMP",
    }
    assert expected.issubset(set(ids))


# ---------------------------------------------------------------------------
# Positive — the Archangel exact shape
# ---------------------------------------------------------------------------


def test_archangel_swap_fee_on_transfer_single_line(tmp_path: Path, amm_rules: list) -> None:
    """Single-line collapse of Archangel's swapTokensForEth — regex must catch this."""
    body = (
        "uniswapV2Router.swapExactTokensForETHSupportingFeeOnTransferTokens("
        "tokenAmount, 0, path, address(this), block.timestamp);\n"
    )
    ids = _scan(tmp_path, body, amm_rules)
    assert "UNISWAP_SWAP_AMOUNT_OUT_MIN_ZERO" in ids
    assert "UNISWAP_DEADLINE_BLOCK_TIMESTAMP" in ids


def test_archangel_swap_multiline_is_regex_blindspot(tmp_path: Path, amm_rules: list) -> None:
    """Multi-line form (Archangel's actual on-chain code) is NOT caught by the
    line-by-line regex scanner. This test pins that limitation so anyone who
    later upgrades scanners.py to multi-line mode will see this test break and
    can re-evaluate the rule pack. The audit pipeline relies on the LLM stage
    here — see runs/archangel_audit F-03 for the real catch.
    """
    body = (
        "uniswapV2Router.swapExactTokensForETHSupportingFeeOnTransferTokens(\n"
        "    tokenAmount,\n"
        "    0,\n"
        "    path,\n"
        "    address(this),\n"
        "    block.timestamp\n"
        ");\n"
    )
    ids = _scan(tmp_path, body, amm_rules)
    assert "UNISWAP_SWAP_AMOUNT_OUT_MIN_ZERO" not in ids


def test_swap_exact_tokens_for_tokens_single_line(tmp_path: Path, amm_rules: list) -> None:
    body = "router.swapExactTokensForTokens(amountIn, 0, path, msg.sender, deadline);\n"
    ids = _scan(tmp_path, body, amm_rules)
    assert "UNISWAP_SWAP_AMOUNT_OUT_MIN_ZERO" in ids


def test_swap_exact_eth_for_tokens(tmp_path: Path, amm_rules: list) -> None:
    """amountIn is implicit (msg.value), so amountOutMin is the FIRST positional arg."""
    body = "router.swapExactETHForTokens{value: 1 ether}(0, path, to, block.timestamp);\n"
    ids = _scan(tmp_path, body, amm_rules)
    assert "UNISWAP_SWAP_ETH_AMOUNT_OUT_MIN_ZERO" in ids


def test_swap_exact_eth_for_tokens_supporting_fot(tmp_path: Path, amm_rules: list) -> None:
    body = "router.swapExactETHForTokensSupportingFeeOnTransferTokens(0, path, to, block.timestamp);\n"
    ids = _scan(tmp_path, body, amm_rules)
    assert "UNISWAP_SWAP_ETH_AMOUNT_OUT_MIN_ZERO" in ids


def test_add_liquidity_eth_zero_min(tmp_path: Path, amm_rules: list) -> None:
    """Single-line collapse of Archangel's openTrading() — addLiquidityETH with
    0,0 mins (mirrors F-04 from runs/archangel_audit).
    """
    body = (
        "uniswapV2Router.addLiquidityETH{value: bal}("
        "address(this), balanceOf(address(this)), 0, 0, owner(), block.timestamp);\n"
    )
    ids = _scan(tmp_path, body, amm_rules)
    assert "UNISWAP_ADD_LIQUIDITY_ZERO_MIN" in ids


def test_add_liquidity_pair_zero_min(tmp_path: Path, amm_rules: list) -> None:
    body = (
        "router.addLiquidity(tokenA, tokenB, amtA, amtB, 0, 0, to, block.timestamp);\n"
    )
    ids = _scan(tmp_path, body, amm_rules)
    assert "UNISWAP_ADD_LIQUIDITY_ZERO_MIN" in ids


# ---------------------------------------------------------------------------
# Negative — protected calls must NOT fire the High-severity rules
# ---------------------------------------------------------------------------


def test_protected_swap_nonzero_min_does_not_fire(tmp_path: Path, amm_rules: list) -> None:
    body = "router.swapExactTokensForTokens(amountIn, minOut, path, msg.sender, deadline);\n"
    ids = _scan(tmp_path, body, amm_rules)
    assert "UNISWAP_SWAP_AMOUNT_OUT_MIN_ZERO" not in ids


def test_protected_swap_explicit_min_value(tmp_path: Path, amm_rules: list) -> None:
    body = "router.swapExactTokensForTokens(1000, 950, path, to, deadline);\n"
    ids = _scan(tmp_path, body, amm_rules)
    assert "UNISWAP_SWAP_AMOUNT_OUT_MIN_ZERO" not in ids


def test_protected_add_liquidity_nonzero_mins(tmp_path: Path, amm_rules: list) -> None:
    body = (
        "router.addLiquidityETH{value: ethAmt}(token, tokenAmt, tokenMin, ethMin, to, deadline);\n"
    )
    ids = _scan(tmp_path, body, amm_rules)
    assert "UNISWAP_ADD_LIQUIDITY_ZERO_MIN" not in ids


def test_deadline_with_buffer_does_not_fire(tmp_path: Path, amm_rules: list) -> None:
    """``block.timestamp + 300`` is a legitimate deadline — must NOT trip the deadline rule."""
    body = "router.swapExactTokensForTokens(in_, out, path, to, block.timestamp + 300);\n"
    ids = _scan(tmp_path, body, amm_rules)
    assert "UNISWAP_DEADLINE_BLOCK_TIMESTAMP" not in ids


def test_unrelated_call_with_zero_arg_does_not_fire(tmp_path: Path, amm_rules: list) -> None:
    """A non-swap call with a literal 0 in arg list should not be flagged."""
    body = "oracle.update(price, 0, block.timestamp);\n"
    ids = _scan(tmp_path, body, amm_rules)
    assert "UNISWAP_SWAP_AMOUNT_OUT_MIN_ZERO" not in ids
    assert "UNISWAP_DEADLINE_BLOCK_TIMESTAMP" not in ids


# ---------------------------------------------------------------------------
# End-to-end: a contract with both swap and addLiquidity issues triggers both rules
# (mirrors Archangel's combined F-03 + F-04 exposure)
# ---------------------------------------------------------------------------


def test_end_to_end_archangel_shape(tmp_path: Path, amm_rules: list) -> None:
    """Mini-contract with both F-03 and F-04 single-line — both rules must fire."""
    body = (
        "// SPDX-License-Identifier: MIT\n"
        "pragma solidity ^0.8.20;\n"
        "contract MemeToken {\n"
        "    function openTrading() external {\n"
        "        router.addLiquidityETH{value: bal}(address(this), tokenAmt, 0, 0, owner(), block.timestamp);\n"
        "    }\n"
        "    function swapTokensForEth(uint256 a) private {\n"
        "        router.swapExactTokensForETHSupportingFeeOnTransferTokens(a, 0, path, address(this), block.timestamp);\n"
        "    }\n"
        "}\n"
    )
    ids = _scan(tmp_path, body, amm_rules)
    must_hit = {
        "UNISWAP_SWAP_AMOUNT_OUT_MIN_ZERO",
        "UNISWAP_ADD_LIQUIDITY_ZERO_MIN",
    }
    assert must_hit.issubset(ids), f"expected {must_hit}, got {ids}"
