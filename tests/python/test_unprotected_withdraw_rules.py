"""Tests for the rules/unprotected_withdraw.json rule pack.

These rules target the public-withdraw / caller-controlled-receiver bug class
that drained the yieldcore-style distribution contract on 2026-04 mainnet
(tx 0x6b04344d...). We synthesise minimal vulnerable Solidity snippets and
assert each rule fires.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from scanners import load_rules_from_file, run_regex_scan

REPO_ROOT = Path(__file__).resolve().parents[2]
RULES_FILE = REPO_ROOT / "rules" / "unprotected_withdraw.json"


@pytest.fixture(scope="module")
def custom_rules() -> list:
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


def test_rules_load_and_compile(custom_rules: list) -> None:
    assert len(custom_rules) >= 6
    ids = [r.rule_id for r in custom_rules]
    assert len(ids) == len(set(ids)), "duplicate rule_id in rule pack"
    expected = {
        "CALL_GAS_FORWARD_FULL",
        "PUBLIC_WITHDRAW_FN_PARAM_RECEIVER",
        "TRANSFER_TO_PARAM_RECEIVER",
        "BATCH_TRANSFER_INDEXED_RECEIVER",
        "CALL_VALUE_TO_PARAM",
        "PAYABLE_TO_PARAM_RECEIVER",
    }
    assert expected.issubset(set(ids))


# ---------------------------------------------------------------------------
# Individual rule detections
# ---------------------------------------------------------------------------


def test_call_gas_forward_full_gasleft(tmp_path: Path, custom_rules: list) -> None:
    body = '(bool ok,) = msg.sender.call{value: amount, gas: gasleft()}("");\n'
    assert "CALL_GAS_FORWARD_FULL" in _scan(tmp_path, body, custom_rules)


def test_call_gas_forward_full_msg_gas(tmp_path: Path, custom_rules: list) -> None:
    """The legacy `msg.gas` form (the stackexchange Q's exact phrasing)."""
    body = '(bool ok,) = msg.sender.call{gas: msg.gas}("");\n'
    assert "CALL_GAS_FORWARD_FULL" in _scan(tmp_path, body, custom_rules)


def test_public_withdraw_fn_with_address_param(tmp_path: Path, custom_rules: list) -> None:
    body = "function withdraw(address to, uint256 amount) external { token.transfer(to, amount); }\n"
    ids = _scan(tmp_path, body, custom_rules)
    assert "PUBLIC_WITHDRAW_FN_PARAM_RECEIVER" in ids
    assert "TRANSFER_TO_PARAM_RECEIVER" in ids  # both should fire


def test_batch_distribute_signature(tmp_path: Path, custom_rules: list) -> None:
    """The 0x6b04344d shape: batchClaim(address[] receivers, uint256[] amounts)."""
    body = (
        "function batchClaim(address[] calldata receivers, uint256[] calldata amounts) external {\n"
        "    for (uint256 i; i < receivers.length; ++i) {\n"
        "        IERC20(token).transfer(receivers[i], amounts[i]);\n"
        "    }\n"
        "}\n"
    )
    ids = _scan(tmp_path, body, custom_rules)
    assert "PUBLIC_WITHDRAW_FN_PARAM_RECEIVER" in ids
    assert "BATCH_TRANSFER_INDEXED_RECEIVER" in ids


def test_batch_owners_and_receivers(tmp_path: Path, custom_rules: list) -> None:
    """The harder shape: separate owners + receivers params, no binding check."""
    body = (
        "function claim(address owner, address to, uint256 amount) external {\n"
        "    rewards[owner] -= amount;\n"
        "    IERC20(token).transfer(to, amount);\n"
        "}\n"
    )
    ids = _scan(tmp_path, body, custom_rules)
    # MISSING_OWNER_RECEIVER_BINDING is the canary for this shape
    assert "MISSING_OWNER_RECEIVER_BINDING" in ids
    assert "TRANSFER_TO_PARAM_RECEIVER" in ids


def test_call_value_to_param(tmp_path: Path, custom_rules: list) -> None:
    body = '(bool ok,) = to.call{value: amount}("");\n'
    assert "CALL_VALUE_TO_PARAM" in _scan(tmp_path, body, custom_rules)


def test_payable_to_param_receiver(tmp_path: Path, custom_rules: list) -> None:
    body = "payable(to).transfer(amount);\n"
    assert "PAYABLE_TO_PARAM_RECEIVER" in _scan(tmp_path, body, custom_rules)


def test_payable_recipient_call(tmp_path: Path, custom_rules: list) -> None:
    body = 'payable(recipient).call{value: amount}("");\n'
    ids = _scan(tmp_path, body, custom_rules)
    assert "PAYABLE_TO_PARAM_RECEIVER" in ids


# ---------------------------------------------------------------------------
# Negative cases — these should NOT trigger our high-signal rules
# ---------------------------------------------------------------------------


def test_admin_only_withdraw_still_flagged_for_review(tmp_path: Path, custom_rules: list) -> None:
    """Admin withdraw still flags PUBLIC_WITHDRAW_FN_PARAM_RECEIVER.

    This is by design: regex can't verify modifiers, so we flag for human/LLM
    triage. The reduce step is responsible for filtering down.
    """
    body = (
        "function adminWithdraw(address to, uint256 amount) external onlyOwner {\n    token.transfer(to, amount);\n}\n"
    )
    assert "PUBLIC_WITHDRAW_FN_PARAM_RECEIVER" in _scan(tmp_path, body, custom_rules)


def test_internal_transfer_no_param_match(tmp_path: Path, custom_rules: list) -> None:
    """An internal helper that doesn't use suspicious param names should not fire."""
    body = (
        "function _settle(address counterparty, uint256 fee) internal {\n"
        "    accumulatedFees += fee;\n"
        "    emit Settled(counterparty, fee);\n"
        "}\n"
    )
    ids = _scan(tmp_path, body, custom_rules)
    # No transfer/call/withdraw — none of our rules should fire
    assert "TRANSFER_TO_PARAM_RECEIVER" not in ids
    assert "CALL_GAS_FORWARD_FULL" not in ids
    assert "BATCH_TRANSFER_INDEXED_RECEIVER" not in ids


def test_safe_call_with_capped_gas(tmp_path: Path, custom_rules: list) -> None:
    """A capped-gas call (e.g. gas: 30000) should NOT trigger CALL_GAS_FORWARD_FULL."""
    body = '(bool ok,) = msg.sender.call{value: amount, gas: 30000}("");\n'
    ids = _scan(tmp_path, body, custom_rules)
    assert "CALL_GAS_FORWARD_FULL" not in ids


# ---------------------------------------------------------------------------
# End-to-end: the 0x6b04344d shape gets multiple rule hits
# ---------------------------------------------------------------------------


def test_end_to_end_yieldcore_shape(tmp_path: Path, custom_rules: list) -> None:
    """Synthetic minimization of the 0x6b04344d batch-distribute exploit.

    The real victim contract had:
      - a public/external batch fn
      - taking address[] receivers
      - looping and transferring with no per-receiver auth

    We expect at least 2 distinct rules to fire, giving the LLM stage a strong
    signal that this is not a routine helper.
    """
    body = (
        "// SPDX-License-Identifier: MIT\n"
        "pragma solidity ^0.8.20;\n"
        "contract Yieldcore {\n"
        "    mapping(address => uint256) public rewards;\n"
        "    address public token;\n"
        "    function batchClaim(address[] calldata receivers, uint256[] calldata amounts) external {\n"
        "        for (uint256 i; i < receivers.length; ++i) {\n"
        "            rewards[receivers[i]] -= amounts[i];\n"
        "            IERC20(token).transfer(receivers[i], amounts[i]);\n"
        "        }\n"
        "    }\n"
        "}\n"
    )
    ids = _scan(tmp_path, body, custom_rules)
    high_signal = {"PUBLIC_WITHDRAW_FN_PARAM_RECEIVER", "BATCH_TRANSFER_INDEXED_RECEIVER"}
    assert high_signal.issubset(ids), f"expected {high_signal}, got {ids}"
