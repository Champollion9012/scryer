r"""Tests for the rules/zero_slippage_amm.json rule pack.

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

Note on coverage: ``run_regex_scan`` matches each rule against the whole
file (rules_version 3), so ``\s*`` / ``[^,)]+`` inside a rule can cross a
newline and the multi-line call shape that all four April-2026 victims use
is caught by the regex layer directly. Before rules_version 3 the scanner
was line-by-line and this shape was a documented blind spot that only the
LLM stage covered (runs/archangel_audit F-03); the tests below pin the
multi-line catch so a future regression is loud.
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


def test_archangel_swap_multiline_is_caught(tmp_path: Path, amm_rules: list) -> None:
    """Multi-line form (Archangel's actual on-chain code) MUST be caught now
    that the scanner matches whole files. The finding has to point at the
    line where the call starts and extend to the ``0,`` argument line so a
    reviewer can jump straight to it.
    """
    body = (
        "contract T {\n"
        "  function swapTokensForEth(uint256 tokenAmount) private {\n"
        "    uniswapV2Router.swapExactTokensForETHSupportingFeeOnTransferTokens(\n"
        "        tokenAmount,\n"
        "        0,\n"
        "        path,\n"
        "        address(this),\n"
        "        block.timestamp\n"
        "    );\n"
        "  }\n"
        "}\n"
    )
    p = tmp_path / "Vuln.sol"
    p.write_text(body, encoding="utf-8")
    findings = run_regex_scan([p], rules=amm_rules)["findings"]
    hits = [f for f in findings if f["rule_id"] == "UNISWAP_SWAP_AMOUNT_OUT_MIN_ZERO"]
    assert len(hits) == 1, findings
    assert hits[0]["line"] == 3
    assert hits[0]["end_line"] == 5
    assert "0," in hits[0]["excerpt"]
    # Deadline rule must also see through the line breaks and, like the swap
    # rule, anchor on the call (line 3) rather than on the `function` line.
    deadline = [f for f in findings if f["rule_id"] == "UNISWAP_DEADLINE_BLOCK_TIMESTAMP"]
    assert [(f["line"], f["end_line"]) for f in deadline] == [(3, 9)]


def test_upegstr_eth_for_tokens_multiline_is_caught(tmp_path: Path, amm_rules: list) -> None:
    """UPEGSTR (Solady/V4 strategy, 0xd730b101...210c) — amountOutMin is the
    first positional arg and sits on its own line after ``{value: amountIn}(``.
    """
    body = (
        "V2_ROUTER.swapExactETHForTokensSupportingFeeOnTransferTokens{value: amountIn}(\n"
        "    0, path, DEAD, block.timestamp\n"
        ");\n"
    )
    ids = _scan(tmp_path, body, amm_rules)
    assert "UNISWAP_SWAP_ETH_AMOUNT_OUT_MIN_ZERO" in ids


def test_add_liquidity_multiline_zero_min_is_caught(tmp_path: Path, amm_rules: list) -> None:
    """openTrading() written one-arg-per-line — both 0 mins on separate lines."""
    body = (
        "uniswapV2Router.addLiquidityETH{value: address(this).balance}(\n"
        "    address(this),\n"
        "    balanceOf(address(this)),\n"
        "    0,\n"
        "    0,\n"
        "    owner(),\n"
        "    block.timestamp\n"
        ");\n"
    )
    ids = _scan(tmp_path, body, amm_rules)
    assert "UNISWAP_ADD_LIQUIDITY_ZERO_MIN" in ids


def test_swapping_modifier_is_not_treated_as_call_options(tmp_path: Path, amm_rules: list) -> None:
    """SafeMoon-style `function swapBack() internal swapping {`: the `{` after
    the modifier must not be parsed as a `{value: ...}` call-options block
    that swallows the body. Findings have to sit on the router call."""
    body = (
        "contract T {\n"
        "  function swapBack() internal swapping {\n"
        "    uint256 amountETH = address(this).balance;\n"
        "    router.addLiquidityETH{value: amountETH}(\n"
        "        address(this), tokens, 0, 0, owner(), block.timestamp\n"
        "    );\n"
        "  }\n"
        "}\n"
    )
    p = tmp_path / "Vuln.sol"
    p.write_text(body, encoding="utf-8")
    findings = run_regex_scan([p], rules=amm_rules)["findings"]
    deadline = [f for f in findings if f["rule_id"] == "UNISWAP_DEADLINE_BLOCK_TIMESTAMP"]
    assert [(f["line"], f["end_line"]) for f in deadline] == [(4, 6)]
    addliq = [f for f in findings if f["rule_id"] == "UNISWAP_ADD_LIQUIDITY_ZERO_MIN"]
    assert [(f["line"], f["end_line"]) for f in addliq] == [(4, 5)]


def test_call_as_first_statement_after_definition_anchors_on_call(tmp_path: Path, amm_rules: list) -> None:
    """`function addLiquidity(...) private {` immediately followed by the
    router call: the finding must start at the call (line 3), not at the
    definition line, and the call must not be swallowed."""
    body = (
        "contract T {\n"
        "  function addLiquidity(uint256 tokenAmount, uint256 ethAmount) private {\n"
        "    uniswapV2Router.addLiquidityETH{value: ethAmount}("
        "address(this), tokenAmount, 0, 0, owner(), block.timestamp);\n"
        "  }\n"
        "}\n"
    )
    p = tmp_path / "Vuln.sol"
    p.write_text(body, encoding="utf-8")
    findings = run_regex_scan([p], rules=amm_rules)["findings"]
    for rule_id in ("UNISWAP_ADD_LIQUIDITY_ZERO_MIN", "UNISWAP_DEADLINE_BLOCK_TIMESTAMP"):
        hits = [f for f in findings if f["rule_id"] == rule_id]
        assert [(f["line"], f["end_line"]) for f in hits] == [(3, 3)], (rule_id, findings)


def test_commented_out_swap_does_not_shadow_live_swap(tmp_path: Path, amm_rules: list) -> None:
    """A commented-out router call above the live one must neither fire nor
    anchor a span that consumes the live call (comment masking)."""
    body = (
        "// router.swapExactTokensForETHSupportingFeeOnTransferTokens(\n"
        "router.swapExactTokensForETHSupportingFeeOnTransferTokens(amt, 0, path, to, block.timestamp);\n"
    )
    p = tmp_path / "Vuln.sol"
    p.write_text(body, encoding="utf-8")
    findings = run_regex_scan([p], rules=amm_rules)["findings"]
    hits = [f for f in findings if f["rule_id"] == "UNISWAP_SWAP_AMOUNT_OUT_MIN_ZERO"]
    assert [(f["line"], f["end_line"]) for f in hits] == [(2, 2)]


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
    body = "router.addLiquidity(tokenA, tokenB, amtA, amtB, 0, 0, to, block.timestamp);\n"
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
    body = "router.addLiquidityETH{value: ethAmt}(token, tokenAmt, tokenMin, ethMin, to, deadline);\n"
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
