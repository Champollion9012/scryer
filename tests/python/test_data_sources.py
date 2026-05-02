"""Tests for data_sources.extract_ipfs_cid_from_bytecode (offline)."""

from __future__ import annotations

import cbor2
import pytest

from data_sources import extract_ipfs_cid_from_bytecode


def _build_bytecode_with_metadata(metadata: dict) -> str:
    """Wrap a CBOR metadata dict in a fake bytecode tail (CBOR + length)."""
    blob = cbor2.dumps(metadata)
    length = len(blob).to_bytes(2, "big")
    fake_runtime = b"\x60\x80\x60\x40" * 10
    return "0x" + (fake_runtime + blob + length).hex()


def test_extract_returns_cidv0_from_canonical_metadata() -> None:
    multihash = bytes.fromhex("1220" + "00" * 32)  # SHA-256 multihash prefix + 32 zero bytes
    bc = _build_bytecode_with_metadata({"ipfs": multihash, "solc": bytes([0, 8, 20])})
    cid = extract_ipfs_cid_from_bytecode(bc)
    assert cid is not None
    assert cid.startswith("Qm"), f"expected CIDv0, got: {cid!r}"


def test_extract_passes_through_string_ipfs_value() -> None:
    bc = _build_bytecode_with_metadata({"ipfs": "QmAlreadyAStringCID"})
    assert extract_ipfs_cid_from_bytecode(bc) == "QmAlreadyAStringCID"


def test_extract_returns_none_for_swarm_only_metadata() -> None:
    bc = _build_bytecode_with_metadata({"bzzr1": bytes(32)})
    assert extract_ipfs_cid_from_bytecode(bc) is None


@pytest.mark.parametrize(
    "bytecode",
    [
        "",
        "0x",
        "0x60",  # too short for any metadata
        "0xnothex!",  # invalid hex
        "0x" + "ff" * 8,  # length suffix says metadata is huge
    ],
)
def test_extract_returns_none_for_malformed_input(bytecode: str) -> None:
    assert extract_ipfs_cid_from_bytecode(bytecode) is None


def test_extract_handles_bytecode_with_no_0x_prefix() -> None:
    multihash = bytes.fromhex("1220" + "11" * 32)
    bc = _build_bytecode_with_metadata({"ipfs": multihash})
    assert extract_ipfs_cid_from_bytecode(bc[2:]) is not None  # strip 0x
