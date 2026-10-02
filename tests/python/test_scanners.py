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


def test_multiline_match_reports_start_and_end_line(tmp_path: Path) -> None:
    """A rule whose ``[^)]*`` spans a line break must report the start line,
    the end line and a whitespace-collapsed excerpt covering the whole span."""
    body = (
        "contract X {\n"
        "    function f(address t) external {\n"
        "        (bool ok, ) = t.call{value: 1}(\n"
        "            payload\n"
        "        );\n"
        "    }\n"
        "}\n"
    )
    f = _write(tmp_path / "Multi.sol", body)
    result = run_regex_scan([f])
    hits = [x for x in result["findings"] if x["rule_id"] == "REENTRANCY_PATTERN"]
    assert len(hits) == 1, result["findings"]
    assert hits[0]["line"] == 3
    assert hits[0]["end_line"] == 5
    assert hits[0]["excerpt"] == "(bool ok, ) = t.call{value: 1}( payload );"
    # Single-line matches keep end_line == line.
    single = [x for x in result["findings"] if x["rule_id"] == "CALL_VALUE"]
    assert single and single[0]["end_line"] == single[0]["line"] == 3


def test_findings_are_line_major_ordered(tmp_path: Path) -> None:
    """Output is sorted by (line, column) regardless of rule order.

    The fixture deliberately inverts rule order vs. position: TX_ORIGIN
    (later in DEFAULT_REGEX_RULES) appears first on line 2 and again on
    line 4, UNPROTECTED_SELFDESTRUCT (earlier in the list) second on line 2
    and alone on line 3. A rule-major or unsorted scanner yields a
    different sequence, as does a column-descending one.
    """
    body = (
        "contract X {\n"
        "    require(tx.origin == owner); selfdestruct(msg.sender);\n"
        "    selfdestruct(msg.sender);\n"
        "    require(tx.origin == owner);\n"
        "}\n"
    )
    f = _write(tmp_path / "Order.sol", body)
    findings = run_regex_scan([f])["findings"]
    assert [(x["rule_id"], x["line"]) for x in findings] == [
        ("TX_ORIGIN", 2),
        ("UNPROTECTED_SELFDESTRUCT", 2),
        ("UNPROTECTED_SELFDESTRUCT", 3),
        ("TX_ORIGIN", 4),
    ]
    assert findings[0]["column"] < findings[1]["column"]


def test_commented_out_code_does_not_fire_code_rules(tmp_path: Path) -> None:
    """Comment bodies are masked: a `// selfdestruct(...)` line and a
    block-comment `tx.origin` must not fire; the live selfdestruct must."""
    body = (
        "contract X {\n"
        "    // selfdestruct(msg.sender); legacy, removed\n"
        "    /* we no longer use tx.origin\n"
        "       anywhere */\n"
        "    function kill() external {\n"
        "        selfdestruct(payable(msg.sender));\n"
        "    }\n"
        "}\n"
    )
    f = _write(tmp_path / "C.sol", body)
    findings = run_regex_scan([f])["findings"]
    assert [(x["rule_id"], x["line"]) for x in findings] == [("UNPROTECTED_SELFDESTRUCT", 6)]


def test_comment_rules_still_see_comments(tmp_path: Path) -> None:
    f = _write(tmp_path / "T.sol", "contract X {\n    // TODO: remove before mainnet\n}\n")
    findings = run_regex_scan([f])["findings"]
    assert [(x["rule_id"], x["line"]) for x in findings] == [("TODO_FIXME", 2)]


def test_string_literal_with_double_slash_is_not_a_comment(tmp_path: Path) -> None:
    """`"https://..."` must not mask the rest of its line."""
    body = (
        'contract X {\n    string u = "https://x.io"; function f() external { selfdestruct(payable(msg.sender)); }\n}\n'
    )
    f = _write(tmp_path / "S.sol", body)
    ids = {x["rule_id"] for x in run_regex_scan([f])["findings"]}
    assert "UNPROTECTED_SELFDESTRUCT" in ids


def test_comment_token_cannot_swallow_real_call(tmp_path: Path) -> None:
    """A commented-out `.call{` on line 3 must not anchor a span that
    consumes the live call on line 4 (whole-file regression guard)."""
    body = (
        "contract X {\n"
        "    function f(address t) external {\n"
        "        // (bool ok, ) = t.call{value: 1}(\n"
        '        (bool ok, ) = t.call{value: 1}("");\n'
        "    }\n"
        "}\n"
    )
    f = _write(tmp_path / "Sw.sol", body)
    hits = [x for x in run_regex_scan([f])["findings"] if x["rule_id"] == "CALL_VALUE"]
    assert [(x["line"], x["end_line"]) for x in hits] == [(4, 4)]


def test_zero_width_rule_never_reports_phantom_line(tmp_path: Path) -> None:
    """`^`/`$` rules must not report a line past lines_scanned for files
    that end with a newline (the split("\\n") phantom tail), nor a line 1
    for an empty file."""
    import re as _re

    from scanners import RegexRule

    rule = RegexRule("EOL", "Info", "every line end", _re.compile(r"$"))
    f = _write(tmp_path / "Z.sol", "a\n\nb\n")
    result = run_regex_scan([f], rules=[rule])
    assert result["lines_scanned"] == 3
    assert [x["line"] for x in result["findings"]] == [1, 2, 3]
    empty = _write(tmp_path / "E.sol", "")
    assert run_regex_scan([empty], rules=[rule])["findings"] == []


def test_max_findings_bounds_work_on_match_dense_line(tmp_path: Path) -> None:
    """A single 1 MB line with 100k hits must return exactly max_findings
    and finish quickly: the cap bounds the work, not just the output."""
    import time as _time

    f = _write(tmp_path / "Dense.sol", "tx.origin " * 100_000 + "\n")
    t0 = _time.perf_counter()
    result = run_regex_scan([f], max_findings=50)
    elapsed = _time.perf_counter() - t0
    assert result["findings_total"] == 50
    assert all(x["rule_id"] == "TX_ORIGIN" for x in result["findings"])
    assert elapsed < 5.0, f"took {elapsed:.1f}s"


def test_all_rule_packs_are_linear_on_hostile_inputs(tmp_path: Path) -> None:
    """Whole-file matching must not turn `[^}]*` / `[^;]*` / `\\s*` windows
    into quadratic scans. Each hostile 100-200 KB input used to exceed 15 s
    on at least one rule; all must now finish in well under a second."""
    import time as _time

    from scanners import load_rules_from_file

    rules = list(DEFAULT_REGEX_RULES)
    for p in sorted((Path(__file__).resolve().parents[2] / "rules").glob("*.json")):
        rules += load_rules_from_file(p)
    cases = {
        "Call.sol": ".call{\n" * 20_000,
        "ToCall.sol": "to.call{\n" * 20_000,
        "For.sol": "for(\n" * 20_000,
        "Fn.sol": "function f( address from\n" * 20_000,
        "AddLiq.sol": "addLiquidity(\n" * 20_000,
        "AddLiqArgs.sol": "addLiquidity(a, b, c,\n" * 20_000,
        "Swap.sol": "swapExactTokensForTokens(\n" * 20_000,
        "SwapWs.sol": "swap" + "\n" * 20_000 + "x",
        "Allow.sol": ".allowance(x\n" * 20_000,
        "Concat.sol": "bytes.concat(a,b\n" * 20_000,
    }
    for name, body in cases.items():
        f = _write(tmp_path / name, body)
        t0 = _time.perf_counter()
        run_regex_scan([f], rules=rules)
        elapsed = _time.perf_counter() - t0
        assert elapsed < 5.0, f"{name} took {elapsed:.1f}s"


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
