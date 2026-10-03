"""P4: vulnerability tagging for UNVERIFIED contracts, keyed by bytecode.

Tags used to be source_hash-only, so a bytecode-only contract (even one Confirmed via a fork
PoC) could not be tagged and its clones could not inherit. These tests cover tagging by the
normalized-runtime hash and clone inheritance.
"""

from __future__ import annotations

from pathlib import Path

import pytest

import bytecode_abi as ba
from contract_registry import ContractRegistry


def _with_trailer(body_hex: str, blob_hex: str) -> str:
    # 'solc' marker (736f6c63) so strip_metadata_trailer treats this as a genuine trailer; see the
    # same helper in test_code_clone_matching for why the marker is required.
    blob = "736f6c63" + blob_hex
    return body_hex + blob + f"{len(blob) // 2:04x}"


# DUP1 PUSH4 <sel> EQ for each selector — the dispatcher shape extract_selectors requires.
BODY = "6080604052" + "8063aaaaaaaa14" + "8063bbbbbbbb14" + "00"
A = "0x" + "a1" * 20
B = "0x" + "b2" * 20  # a byte-clone of A (same source, different metadata trailer)
C = "0x" + "c3" * 20  # unrelated


@pytest.fixture
def reg(tmp_path: Path) -> ContractRegistry:
    return ContractRegistry(tmp_path / "r.db")


def test_tag_by_code_and_list(reg: ContractRegistry) -> None:
    fp = ba.code_fingerprints(_with_trailer(BODY, "aa" * 20))
    reg.record_code_fingerprints(1, A, fp)
    affected = reg.tag_vulnerability_by_code(fp["runtime_norm_hash"], "reentrancy", "High", "classic")
    assert affected == 1

    vuln = reg.get_vulnerable_contracts("reentrancy")
    assert len(vuln) == 1
    assert vuln[0]["address"] == A.lower() and vuln[0]["severity"] == "High"
    assert vuln[0]["matched_via"] == "bytecode"


def test_byte_clone_inherits_the_tag(reg: ContractRegistry) -> None:
    """A tag on one unverified contract must flag its byte-identical clone (diff metadata)."""
    reg.record_code_fingerprints(1, A, ba.code_fingerprints(_with_trailer(BODY, "aa" * 20)))
    reg.record_code_fingerprints(56, B, ba.code_fingerprints(_with_trailer(BODY, "bb" * 20)))  # clone
    reg.record_code_fingerprints(1, C, ba.code_fingerprints("8063dddddddd14" + "00"))  # unrelated

    reg.tag_vulnerability_by_code(
        ba.code_fingerprints(_with_trailer(BODY, "aa" * 20))["runtime_norm_hash"], "bad-access", "Critical"
    )
    addrs = {(v["chain_id"], v["address"]) for v in reg.get_vulnerable_contracts("bad-access")}
    assert addrs == {(1, A.lower()), (56, B.lower())}  # A and its clone B, NOT the unrelated C


def test_code_tags_surface_in_find_code_twins(reg: ContractRegistry) -> None:
    fp = ba.code_fingerprints(_with_trailer(BODY, "aa" * 20))
    reg.record_code_fingerprints(1, A, fp)
    reg.tag_vulnerability_by_code(fp["runtime_norm_hash"], "oracle-manip", "High", "spot price")

    # A different deployment (byte clone) looks itself up -> sees the code tag.
    twins = reg.find_code_twins(56, B, ba.code_fingerprints(_with_trailer(BODY, "bb" * 20)))
    assert any(t["tag"] == "oracle-manip" for t in twins["code_vulnerability_tags"])


def test_source_and_bytecode_tags_both_listed(reg: ContractRegistry) -> None:
    """get_vulnerable_contracts unions source-hash tags and bytecode tags under one tag name."""
    sh = reg.register_contract(chain_id=1, address=A, sources={"X.sol": "contract X{}"}, contract_name="X")
    reg.tag_vulnerability(sh, "dup-bug", "Medium")
    reg.record_code_fingerprints(56, C, ba.code_fingerprints("8063eeeeeeee14" + "00"))
    reg.tag_vulnerability_by_code(
        ba.code_fingerprints("8063eeeeeeee14" + "00")["runtime_norm_hash"], "dup-bug", "Medium"
    )
    rows = reg.get_vulnerable_contracts("dup-bug")
    via = {r["matched_via"] for r in rows}
    assert via == {"source", "bytecode"} and len(rows) == 2


def test_same_contract_tagged_both_ways_is_not_double_counted(reg: ContractRegistry) -> None:
    """A contract tagged under BOTH its source_hash and its own bytecode must appear ONCE, not
    twice. The UNION halves project different columns (name set vs NULL, via 'source' vs
    'bytecode') so they can't fold the dup — the source half is made authoritative via NOT EXISTS.
    """
    sh = reg.register_contract(chain_id=1, address=A, sources={"X.sol": "contract X{}"}, contract_name="X")
    reg.tag_vulnerability(sh, "same-bug", "High")
    fp = ba.code_fingerprints(_with_trailer(BODY, "aa" * 20))
    reg.record_code_fingerprints(1, A, fp)  # same address, now also fingerprinted...
    reg.tag_vulnerability_by_code(fp["runtime_norm_hash"], "same-bug", "High")  # ...and tagged by code

    rows = reg.get_vulnerable_contracts("same-bug")
    assert [r["address"] for r in rows] == [A.lower()]  # exactly once
    assert len(rows) == 1
    assert rows[0]["matched_via"] == "source"  # source wins (higher fidelity)
    assert rows[0]["contract_name"] == "X"  # and carries the name the bytecode half lacks


def test_code_tags_for_empty_hash_is_safe(reg: ContractRegistry) -> None:
    assert reg.code_tags_for(None) == [] and reg.code_tags_for("") == []
