"""Tests for rules/ai_authored_drainer.json — the regex pack that flags
contracts that look like LLM-authored token drainers (junk-named methods,
hardcoded raw-bytes selector payloads, per-victim mass-drain loops).

Reference: the 2026-05 Arbitrum USDT0 batch-drainer
(tx 0xcc475432…, contract 0x8144E729…) which the attacker also verified on
Arbiscan, producing the canonical fixture for these heuristics.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from scanners import load_rules_from_file, run_regex_scan

REPO_ROOT = Path(__file__).resolve().parents[2]
RULES_FILE = REPO_ROOT / "rules" / "ai_authored_drainer.json"


@pytest.fixture(scope="module")
def rules() -> list:
    assert RULES_FILE.exists(), f"rules file missing: {RULES_FILE}"
    return load_rules_from_file(RULES_FILE)


def _scan(tmp_path: Path, body: str, rules: list) -> set[str]:
    p = tmp_path / "Drainer.sol"
    p.write_text(body, encoding="utf-8")
    return {f["rule_id"] for f in run_regex_scan([p], rules=rules)["findings"]}


def test_rule_pack_loads(rules: list) -> None:
    assert {r.rule_id for r in rules} >= {
        "RAW_SELECTOR_BYTES_LITERAL",
        "BYTES_CONCAT_BUILDS_CALLDATA",
        "LOOP_OVER_ADDRESS_ARRAY_USER",
        "ALLOWANCE_HARDCODED_SPENDER",
        "JUNK_KEYBOARD_MASH_FN_NAME",
        "HARDCODED_RECEIVER_OWNER_STATE",
        "BLOCK_NUMBER_DEPLOY_FUSE",
    }


def test_raw_selector_bytes_literal(tmp_path: Path, rules: list) -> None:
    body = "bytes memory a = bytes('\\x69\\xde\\xb0\\xb1\\x00\\x00\\x00\\x00\\x00\\x00');\n"
    assert "RAW_SELECTOR_BYTES_LITERAL" in _scan(tmp_path, body, rules)


def test_bytes_concat_multi_arg(tmp_path: Path, rules: list) -> None:
    body = "bytes memory data = bytes.concat(a, user, b, token, bal, owners);\n"
    assert "BYTES_CONCAT_BUILDS_CALLDATA" in _scan(tmp_path, body, rules)


def test_bytes_concat_counts_top_level_args_with_nested_casts(tmp_path: Path, rules: list) -> None:
    """Uniswap-V3 path packing: three top-level args, two levels of casts."""
    body = "bytes memory path = bytes.concat(bytes20(tokenIn), bytes3(uint24(fee)), bytes20(tokenOut));\n"
    assert "BYTES_CONCAT_BUILDS_CALLDATA" in _scan(tmp_path, body, rules)


def test_bytes_concat_two_args_with_nested_commas_does_not_fire(tmp_path: Path, rules: list) -> None:
    """Commas inside a nested call are not argument separators (>=3 args means
    two TOP-LEVEL commas)."""
    body = "bytes memory d = bytes.concat(abi.encode(a, b, c), selector);\n"
    assert "BYTES_CONCAT_BUILDS_CALLDATA" not in _scan(tmp_path, body, rules)


def test_bytes_concat_multiline_three_args(tmp_path: Path, rules: list) -> None:
    body = "bytes memory d = bytes.concat(\n    sel,\n    abi.encode(user, amount),\n    extra\n);\n"
    assert "BYTES_CONCAT_BUILDS_CALLDATA" in _scan(tmp_path, body, rules)


def test_loop_over_users_array(tmp_path: Path, rules: list) -> None:
    body = "for (uint256 i = 0; i < users.length; i++) {\n  drain(users[i]);\n}\n"
    assert "LOOP_OVER_ADDRESS_ARRAY_USER" in _scan(tmp_path, body, rules)


def test_allowance_with_hardcoded_spender(tmp_path: Path, rules: list) -> None:
    body = "uint256 a = IERC20(token).allowance(victim, 0xBEdB227947500b8d12d803C4dB77aC3336Ac4198);\n"
    assert "ALLOWANCE_HARDCODED_SPENDER" in _scan(tmp_path, body, rules)


def test_junk_keyboard_mash_fn_name(tmp_path: Path, rules: list) -> None:
    body = "function asdadasd11dasdas(address t) external { revert(); }\n"
    assert "JUNK_KEYBOARD_MASH_FN_NAME" in _scan(tmp_path, body, rules)


def test_hardcoded_owner_state_variable(tmp_path: Path, rules: list) -> None:
    body = "address owner = 0x0873142E0Fe81C023D35385dAd602A474b00F39D;\n"
    assert "HARDCODED_RECEIVER_OWNER_STATE" in _scan(tmp_path, body, rules)


def test_block_number_deploy_fuse(tmp_path: Path, rules: list) -> None:
    body = "constructor() { require(block.number < 457121292); }\n"
    assert "BLOCK_NUMBER_DEPLOY_FUSE" in _scan(tmp_path, body, rules)


def test_legit_erc20_does_not_trigger(tmp_path: Path, rules: list) -> None:
    """A vanilla ERC20-using helper should not fire any drainer rule."""
    body = (
        "function transfer(address to, uint256 amount) external returns (bool) {\n"
        "    require(amount <= balanceOf[msg.sender], 'insufficient');\n"
        "    balanceOf[msg.sender] -= amount;\n"
        "    balanceOf[to] += amount;\n"
        "    emit Transfer(msg.sender, to, amount);\n"
        "    return true;\n"
        "}\n"
    )
    assert _scan(tmp_path, body, rules) == set()


def test_legit_owner_via_msg_sender_does_not_trigger(tmp_path: Path, rules: list) -> None:
    """The owner-state rule must require a *hardcoded* address literal, not
    a constructor-assigned owner like real protocols use."""
    body = "address public owner;\n  constructor() { owner = msg.sender; }\n"
    assert "HARDCODED_RECEIVER_OWNER_STATE" not in _scan(tmp_path, body, rules)
