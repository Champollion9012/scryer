r"""Tests for the PAIR_SYNC_SKIM_CALL / BURN_FROM_PAIR default rules.

These two rules target the "token manipulates its own DEX pair" class: an
ERC-20 whose transfer path burns (or moves) the pair's OWN balance and/or
calls ``pair.sync()`` / ``pair.skim()``. Burning the pair's reserve and then
re-syncing resets the Uniswap-V2 constant-product K baseline to a lower value,
so a sell extracts more quote token than the curve should allow and the LP's
quote reserve is drained.

Anchor incident: BigBull Decentralized (BBD), BSC
0x5d52253f42663fe2a12e1775c64df700bb6f3df9. Its ``_update`` hook calls
``_burnForSale()`` on a sell, which ``_burn(dexPair, ..)`` up to 50% of the
pair's BBD and then ``IPairSync(dexPair).sync()``. The USDT/BBD PancakePair
0x9b23887aDAeFFbc40F189Cd8Eb97bDBE262e9Af3 was drained from ~72,326 USDT to
~$0.58 just after block 124359389 (~$72k). A reproducing fork PoC lives at
tests/BBDBurnSync.t.sol.

Unlike the rules/*.json incident packs these two live in
``scanners.DEFAULT_REGEX_RULES`` (always-on) because the shape is a general
DeFi anti-pattern, not a single attacker's campaign. The rules run over the
whole file with comment bodies masked (rules_version 3), so the multi-line
call shape is caught directly and commented-out code cannot fire them.
"""

from __future__ import annotations

from pathlib import Path

from scanners import DEFAULT_REGEX_RULES, run_regex_scan


def _ids(tmp_path: Path, body: str) -> set[str]:
    p = tmp_path / "Tok.sol"
    p.write_text(body, encoding="utf-8")
    return {f["rule_id"] for f in run_regex_scan([p])["findings"]}


# ---------------------------------------------------------------------------
# The rules are present in the always-on default set
# ---------------------------------------------------------------------------


def test_rules_registered_in_defaults() -> None:
    ids = {r.rule_id for r in DEFAULT_REGEX_RULES}
    assert {"PAIR_SYNC_SKIM_CALL", "BURN_FROM_PAIR"}.issubset(ids)


# ---------------------------------------------------------------------------
# Positive — the BBD shape
# ---------------------------------------------------------------------------


def test_burn_from_pair_then_sync_single_line(tmp_path: Path) -> None:
    body = "function _burnForSale() internal { _burn(dexPair, amount); IPairSync(dexPair).sync(); }\n"
    ids = _ids(tmp_path, body)
    assert "BURN_FROM_PAIR" in ids
    assert "PAIR_SYNC_SKIM_CALL" in ids


def test_burn_from_pair_multiline_is_caught(tmp_path: Path) -> None:
    body = (
        "contract T {\n"
        "  function _burnForSale(uint256 value) internal {\n"
        "    uint256 amount = (value * sellBurnBps) / 10_000;\n"
        "    _burn(\n"
        "        dexPair,\n"
        "        amount\n"
        "    );\n"
        "    IPairSync(dexPair).sync();\n"
        "  }\n"
        "}\n"
    )
    p = tmp_path / "Tok.sol"
    p.write_text(body, encoding="utf-8")
    findings = run_regex_scan([p])["findings"]
    burn = [f for f in findings if f["rule_id"] == "BURN_FROM_PAIR"]
    assert len(burn) == 1, findings
    assert burn[0]["line"] == 4  # the `_burn(` call line
    sync = [f for f in findings if f["rule_id"] == "PAIR_SYNC_SKIM_CALL"]
    assert [f["line"] for f in sync] == [8]


def test_skim_call_is_caught(tmp_path: Path) -> None:
    assert "PAIR_SYNC_SKIM_CALL" in _ids(tmp_path, "IPair(dexPair).skim(address(this));\n")


def test_burn_from_pair_address_wrapper(tmp_path: Path) -> None:
    assert "BURN_FROM_PAIR" in _ids(tmp_path, "_burn(address(lpPair), amount);\n")


def test_transferfrom_pair_is_flagged(tmp_path: Path) -> None:
    # Pulling the pair's balance out via allowance is the same drain shape.
    assert "BURN_FROM_PAIR" in _ids(tmp_path, "token.transferFrom(uniswapV2Pair, msg.sender, bal);\n")


def test_end_to_end_bbd_shape(tmp_path: Path) -> None:
    body = (
        "// SPDX-License-Identifier: MIT\n"
        "pragma solidity ^0.8.24;\n"
        "contract BigBullV3 {\n"
        "    address public dexPair;\n"
        "    function _update(address from, address to, uint256 value) internal {\n"
        "        if (to == dexPair) {\n"
        "            _burn(dexPair, value / 2);\n"
        "            IPairSync(dexPair).sync();\n"
        "        }\n"
        "    }\n"
        "}\n"
    )
    ids = _ids(tmp_path, body)
    assert {"BURN_FROM_PAIR", "PAIR_SYNC_SKIM_CALL"}.issubset(ids)


# ---------------------------------------------------------------------------
# Negative — a standard Uniswap-V2 pair and a normal ERC-20 must NOT fire
# ---------------------------------------------------------------------------


def test_standard_pair_definitions_do_not_fire_sync_skim(tmp_path: Path) -> None:
    """A vanilla PancakePair *defines* sync()/skim() but never member-calls
    them (`function sync()` has no leading dot), so the rule must stay quiet."""
    body = (
        "contract PancakePair {\n"
        "    function skim(address to) external lock {\n"
        "        _safeTransfer(token0, to, IERC20(token0).balanceOf(address(this)));\n"
        "    }\n"
        "    function sync() external lock {\n"
        "        _update(IERC20(token0).balanceOf(address(this)), reserve0);\n"
        "    }\n"
        "}\n"
    )
    assert "PAIR_SYNC_SKIM_CALL" not in _ids(tmp_path, body)


def test_normal_erc20_internals_do_not_fire_burn_from_pair(tmp_path: Path) -> None:
    body = (
        "contract Token {\n"
        "    function _burn(address account, uint256 v) internal { balanceOf[account] -= v; }\n"
        "    function _transfer(address from, address to, uint256 v) internal {}\n"
        "    function transferFrom(address sender, address recipient, uint256 v) external {\n"
        "        _transfer(sender, recipient, v);\n"
        "    }\n"
        "}\n"
    )
    assert "BURN_FROM_PAIR" not in _ids(tmp_path, body)


def test_commented_out_burn_and_sync_do_not_fire(tmp_path: Path) -> None:
    body = (
        "contract T {\n    // _burn(dexPair, amount);\n    /* IPairSync(dexPair).sync(); */\n    uint256 public x;\n}\n"
    )
    ids = _ids(tmp_path, body)
    assert "BURN_FROM_PAIR" not in ids
    assert "PAIR_SYNC_SKIM_CALL" not in ids


# ---------------------------------------------------------------------------
# Loosened rule: naming-INDEPENDENT (the point of leaving precision to the LLM)
# ---------------------------------------------------------------------------


def test_burn_from_pair_is_not_keyed_on_variable_name(tmp_path: Path) -> None:
    """The old rule required the var to be named *pair*/*lp*, so renaming evaded it. The lead
    must now fire regardless of what the stored target address is called."""
    for arg in ["uniV2", "poolAddr", "_ammTarget", "lpToken", "reserveHolder", "s.vault"]:
        assert "BURN_FROM_PAIR" in _ids(tmp_path, f"_burn({arg.split('.')[-1]}, amt);\n"), arg
    # mapping / indexed access to the pool, and address-cast of a renamed var
    assert "BURN_FROM_PAIR" in _ids(tmp_path, "_burn(pools[token], amt);\n")
    assert "BURN_FROM_PAIR" in _ids(tmp_path, "_burn(address(uniV2), amt);\n")
    # moving the pool's balance out under a non-pair name
    assert "BURN_FROM_PAIR" in _ids(tmp_path, "_transfer(poolAddr, msg.sender, bal);\n")


# ---------------------------------------------------------------------------
# Negative: ordinary self-burns / normal transfers / definitions must stay quiet
# ---------------------------------------------------------------------------


def test_ordinary_burn_targets_do_not_fire(tmp_path: Path) -> None:
    for arg in ["msg.sender", "from", "_from", "account", "owner", "to", "recipient", "address(0)", "address(this)"]:
        assert "BURN_FROM_PAIR" not in _ids(tmp_path, f"_burn({arg}, amt);\n"), arg


def test_function_definitions_do_not_fire(tmp_path: Path) -> None:
    # `_burn(address account,..)` is a DECLARATION, not a burn of a stored address.
    body = (
        "contract Tok {\n"
        "    function _burn(address account, uint256 v) internal {}\n"
        "    function transferFrom(address sender, address to, uint256 v) external returns (bool) {}\n"
        "}\n"
    )
    assert "BURN_FROM_PAIR" not in _ids(tmp_path, body)


# ---------------------------------------------------------------------------
# These are LEADS, not verdicts — demoted from High so the hunter/PoC decides
# ---------------------------------------------------------------------------


def test_rules_are_medium_leads_not_high() -> None:
    by_id = {r.rule_id: r for r in DEFAULT_REGEX_RULES}
    assert by_id["PAIR_SYNC_SKIM_CALL"].severity == "Medium"
    assert by_id["BURN_FROM_PAIR"].severity == "Medium"
