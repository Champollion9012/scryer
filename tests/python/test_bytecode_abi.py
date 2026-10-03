"""Tests for bytecode_abi — recovering a contract's callable surface with no source.

The extraction tests are offline and deterministic; one ground-truth test compiles with a real
solc (skipped when unavailable) because "extracted selectors == keccak(signature) selectors" is
the only check that actually proves the opcode walk is right.
"""

from __future__ import annotations

import pytest
from web3 import Web3

import bytecode_abi as ba
import verify_source as vs
from scryer_http import RateLimitTally


@pytest.fixture(autouse=True)
def _isolate_cache(monkeypatch: pytest.MonkeyPatch):
    """Never touch (or write) the on-disk selector cache from tests."""
    monkeypatch.setattr(ba, "_cache", {})
    monkeypatch.setattr(ba, "_cache_flush", lambda: None)


# --------------------------------------------------------------------------- #
# Opcode walking — the traps that make naive scanners invent selectors
# --------------------------------------------------------------------------- #
def test_push32_constant_is_not_mistaken_for_a_selector() -> None:
    """A PUSH32 constant whose BYTES look like `PUSH4 deadbeef EQ` must yield nothing."""
    trap = "7f" + "63deadbeef14" + "00" * 26 + "00"  # PUSH32 <...63 deadbeef 14...> STOP
    assert ba.extract_selectors(trap) == []


def test_real_push4_compare_is_extracted() -> None:
    assert ba.extract_selectors("63deadbeef14" + "00") == ["0xdeadbeef"]


def test_push4_followed_by_compare_within_window() -> None:
    # PUSH4 <sel> DUP2 EQ  — the comparison is not the immediately next opcode.
    assert ba.extract_selectors("63cafebabe" + "81" + "14" + "00") == ["0xcafebabe"]


def test_push4_without_comparison_is_a_constant_not_a_selector() -> None:
    # PUSH4 <value> ADD  — never compared, so it is a plain constant.
    assert ba.extract_selectors("63cafebabe" + "01" + "00") == []


def test_metadata_trailer_is_not_walked_as_code() -> None:
    """Bytes in the CBOR metadata trailer must not produce phantom selectors."""
    body = "6080604052" + "00"
    fake = "63deadbeef14"  # looks like a selector comparison, but lives in the trailer
    blob = fake + "00" * 10
    trailer_len = len(blob) // 2
    code = body + blob + f"{trailer_len:04x}"
    assert "0xdeadbeef" not in ba.extract_selectors(code)


def test_selectors_are_deduped_and_ordered() -> None:
    code = "63aaaaaaaa14" + "63bbbbbbbb14" + "63aaaaaaaa14" + "00"
    assert ba.extract_selectors(code) == ["0xaaaaaaaa", "0xbbbbbbbb"]


# --------------------------------------------------------------------------- #
# Ground truth: extracted selectors == keccak(signature)[:4] for a real contract
# --------------------------------------------------------------------------- #
@pytest.mark.skipif(vs.find_solc("0.8.20") is None, reason="no solc available")
def test_extraction_matches_keccak_ground_truth() -> None:
    src = """// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;
contract Sample {
    address public owner;
    mapping(address => uint256) private bal;
    uint256 public constant BIG = 0x1122334455667788990011223344556677889900112233445566778899001122;
    function transfer(address to, uint256 amount) external returns (bool) { bal[to]+=amount; return true; }
    function balanceOf(address who) external view returns (uint256) { return bal[who]; }
    function setOwner(address o) external { owner = o; }
    function weirdName_xyz(uint256 a, bytes32 b) external pure returns (uint256) { return a + uint256(b); }
}
"""
    solc = vs.find_solc("0.8.20")
    arts = vs.compile_all_runtime_bytecode(
        {"S.sol": src}, {"optimizer": {"enabled": False, "runs": 200}}, solc_path=solc
    )
    runtime = arts["S.sol:Sample"].bytecode_hex
    expected = {
        "0x" + bytes(Web3.keccak(text=s))[:4].hex()
        for s in (
            "transfer(address,uint256)",
            "balanceOf(address)",
            "setOwner(address)",
            "owner()",
            "BIG()",
            "weirdName_xyz(uint256,bytes32)",
        )
    }
    # Exact: no missing selectors, and no phantoms from the PUSH32 constant.
    assert set(ba.extract_selectors(runtime)) == expected


# --------------------------------------------------------------------------- #
# Shape detection
# --------------------------------------------------------------------------- #
def test_eip1167_minimal_proxy_yields_implementation_and_proxy_like() -> None:
    impl = "be" * 20
    code = "363d3d373d3d3d363d73" + impl + "5af43d82803e903d91602b57fd5bf3"
    info = ba.analyze_bytecode(code)
    assert info["eip1167_implementation"] == "0x" + impl
    assert info["proxy_like"] is True and info["has_delegatecall"] is True
    assert "0x" + impl in ba._shape_note(info)


def test_diamond_loupe_detected() -> None:
    loupe = sorted(ba._DIAMOND_LOUPE)[:2]
    code = "".join("63" + s[2:] + "14" for s in loupe) + "00"
    info = ba.analyze_bytecode(code)
    assert info["diamond_like"] is True
    assert "facet" in ba._shape_note(info).lower()


def test_code_with_no_selectors_gets_its_own_diagnosis() -> None:
    """Real hand-written/assembly contract (Polygon Amoy 0xa60Fa83…): code but no dispatcher.
    Must not be described as 'feed each recovered signature to call_view' — there are none."""
    raw = "60205f8037346020525f51465f5260405f2054585460205114911416366020141615602157005b5f80fd"
    info = ba.analyze_bytecode(raw)
    assert info["code_size"] > 0
    assert info["selector_count"] == 0 and info["proxy_like"] is False and info["has_delegatecall"] is False
    note = ba._shape_note(info)
    assert "NO function selectors" in note and "assembly" in note


def test_fat_contract_is_not_proxy_like() -> None:
    # Many selectors, no delegatecall -> a standalone contract.
    code = "".join(f"63{i:08x}14" for i in range(1, 12)) + "00"
    info = ba.analyze_bytecode(code)
    assert info["proxy_like"] is False and info["has_delegatecall"] is False


# --------------------------------------------------------------------------- #
# Signature resolution + COLLISIONS
# --------------------------------------------------------------------------- #
def test_params_of() -> None:
    assert ba.params_of("transfer(address,uint256)") == "address,uint256"
    assert ba.params_of("owner()") == ""
    assert ba.params_of("not a signature") is None


class _Resp:
    def __init__(self, status_code: int = 200, body: dict | None = None, headers: dict | None = None):
        self.status_code = status_code
        self._body = body if body is not None else {}
        self.headers = headers or {}

    def json(self):
        return self._body


def test_resolve_signatures_keeps_all_candidates(monkeypatch: pytest.MonkeyPatch) -> None:
    body = {
        "ok": True,
        "result": {
            "function": {
                "0xaaaaaaaa": [{"name": "foo(uint256)"}, {"name": "bar(uint256)"}],
                "0xbbbbbbbb": [],
            }
        },
    }
    monkeypatch.setattr(ba._HTTP, "get", lambda *a, **k: _Resp(body=body))
    out = ba.resolve_signatures(["0xaaaaaaaa", "0xbbbbbbbb"], use_fourbyte=False)
    assert out["0xaaaaaaaa"] == ["foo(uint256)", "bar(uint256)"]  # NOT collapsed to one
    assert "0xbbbbbbbb" not in out


def test_resolve_signatures_throttle_is_surfaced_not_silent(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(ba._HTTP, "get", lambda *a, **k: _Resp(status_code=429, headers={"Retry-After": "5"}))
    tally = RateLimitTally()
    out = ba.resolve_signatures(["0xdeadbeef"], tally=tally, use_fourbyte=False)
    assert out == {}  # nothing resolved...
    assert tally.hit and tally.retry_after == 5  # ...but it is a THROTTLE, not "unknown signature"


def _patch_chain(monkeypatch: pytest.MonkeyPatch, runtime_hex: str) -> None:
    class _Eth:
        def get_code(self, addr, block_identifier=None):
            return bytes.fromhex(runtime_hex)

    class _W3:
        eth = _Eth()

    import etherscan_proxy_provider as epp

    monkeypatch.setattr(epp, "make_web3", lambda cid, rpc_url="": (_W3(), "fake-rpc"))


def test_analyze_contract_flags_type_vs_name_collisions(monkeypatch: pytest.MonkeyPatch) -> None:
    """A name-only collision is cosmetic (identical calldata); a TYPE collision is ambiguous."""
    _patch_chain(monkeypatch, "63aaaaaaaa14" + "63bbbbbbbb14" + "00")
    monkeypatch.setattr(
        ba,
        "resolve_signatures",
        lambda sels, **k: {
            "0xaaaaaaaa": ["foo(uint256)", "bar(uint256)"],  # same types -> cosmetic
            "0xbbbbbbbb": ["baz(uint256)", "qux(address,bytes)"],  # different types -> ambiguous
        },
    )
    out = ba.analyze_contract(1, "0x" + "11" * 20)
    by_hex = {e["hex"]: e for e in out["selectors"]}

    a = by_hex["0xaaaaaaaa"]
    assert a["collision"] is True and a["collision_cosmetic"] is True
    assert a["signature"] == "foo(uint256)" and a["candidates"] == ["foo(uint256)", "bar(uint256)"]

    b = by_hex["0xbbbbbbbb"]
    assert b["collision"] is True and b["collision_cosmetic"] is False

    assert out["ambiguous_count"] == 1  # only the type-differing one counts
    assert "COLLISIONS" in out["note"]


def test_analyze_contract_no_code(monkeypatch: pytest.MonkeyPatch) -> None:
    _patch_chain(monkeypatch, "")
    out = ba.analyze_contract(1, "0x" + "11" * 20)
    assert out["code_size"] == 0 and "no code" in out["note"]
