"""Tests for scanners.py — regex rule set."""

from __future__ import annotations

from pathlib import Path

from scanners import (
    DEFAULT_REGEX_RULES,
    choose_entry_file,
    infer_contract_root,
    run_regex_scan,
)


def _write(path: Path, body: str) -> Path:
    path.write_text(body, encoding="utf-8")
    return path


def test_rule_ids_unique() -> None:
    ids = [r.rule_id for r in DEFAULT_REGEX_RULES]
    assert len(ids) == len(set(ids)), "duplicate rule_id detected"


def test_rules_have_severity() -> None:
    valid = {"Critical", "High", "Medium", "Low", "Info"}
    for rule in DEFAULT_REGEX_RULES:
        assert rule.severity in valid, f"{rule.rule_id} has bad severity {rule.severity}"


def test_detects_tx_origin(tmp_path: Path) -> None:
    f = _write(
        tmp_path / "BadAuth.sol",
        "contract X { function f() public { require(tx.origin == owner); } }\n",
    )
    result = run_regex_scan([f])
    ids = {finding["rule_id"] for finding in result["findings"]}
    assert "TX_ORIGIN" in ids


def test_detects_selfdestruct(tmp_path: Path) -> None:
    f = _write(
        tmp_path / "Bomb.sol", "contract B { function kill() external { selfdestruct(payable(msg.sender)); } }\n"
    )
    result = run_regex_scan([f])
    ids = {finding["rule_id"] for finding in result["findings"]}
    assert "UNPROTECTED_SELFDESTRUCT" in ids


def test_detects_delegatecall(tmp_path: Path) -> None:
    f = _write(
        tmp_path / "Proxy.sol", "contract P { function f(address t, bytes memory d) external { t.delegatecall(d); } }\n"
    )
    result = run_regex_scan([f])
    ids = {finding["rule_id"] for finding in result["findings"]}
    assert "DELEGATECALL" in ids


def test_detects_weak_randomness(tmp_path: Path) -> None:
    f = _write(
        tmp_path / "R.sol",
        "contract R { function r() external view returns(uint){ return uint(blockhash(block.number-1)); } }\n",
    )
    result = run_regex_scan([f])
    ids = {finding["rule_id"] for finding in result["findings"]}
    assert "WEAK_RANDOMNESS" in ids


def test_no_findings_on_clean_code(tmp_path: Path) -> None:
    f = _write(
        tmp_path / "Safe.sol",
        "// SPDX-License-Identifier: MIT\npragma solidity ^0.8.20;\ncontract Safe { uint256 public x; }\n",
    )
    result = run_regex_scan([f])
    # `pragma solidity` shouldn't trigger any rules.
    assert result["findings_total"] == 0
    assert result["files_scanned"] == 1


def test_max_findings_cap(tmp_path: Path) -> None:
    body = "\n".join(["    require(tx.origin == owner);"] * 100)
    f = _write(tmp_path / "Many.sol", f"contract X {{\n{body}\n}}\n")
    result = run_regex_scan([f], max_findings=5)
    assert result["findings_total"] <= 5


def test_findings_include_location(tmp_path: Path) -> None:
    f = _write(tmp_path / "X.sol", "contract X {\n    selfdestruct(msg.sender);\n}\n")
    result = run_regex_scan([f])
    assert result["findings"], "should have at least one finding"
    finding = result["findings"][0]
    assert finding["line"] == 2
    assert finding["column"] >= 1
    assert "file" in finding


def test_run_regex_scan_handles_missing_file(tmp_path: Path) -> None:
    fake = tmp_path / "does-not-exist.sol"
    result = run_regex_scan([fake])
    assert result["files_scanned"] == 0


def test_choose_entry_file_prefers_combined(tmp_path: Path) -> None:
    a = _write(tmp_path / "small.sol", "x")
    b = _write(tmp_path / "combined_source.sol", "y")
    chosen = choose_entry_file([a, b])
    assert chosen == b


def test_choose_entry_file_falls_back_to_largest(tmp_path: Path) -> None:
    a = _write(tmp_path / "small.sol", "x")
    b = _write(tmp_path / "big.sol", "x" * 1000)
    chosen = choose_entry_file([a, b])
    assert chosen == b


def test_infer_contract_root(tmp_path: Path) -> None:
    sources_root = tmp_path / "sources"
    contract_name = f"56_0x{'ab' * 20}"
    contract_dir = sources_root / contract_name
    contract_dir.mkdir(parents=True)
    f = _write(contract_dir / "Contract.sol", "x")
    inferred = infer_contract_root([f], sources_root)
    assert inferred == contract_dir
