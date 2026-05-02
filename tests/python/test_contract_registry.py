"""Tests for ContractRegistry (contract_registry.py)."""

from __future__ import annotations

from pathlib import Path

import pytest

from contract_registry import ContractRegistry


@pytest.fixture
def registry(tmp_path: Path) -> ContractRegistry:
    return ContractRegistry(tmp_path / "registry.db")


SAMPLE_SOURCES = {
    "A.sol": "contract A { uint256 x; }\n",
    "B.sol": "contract B is A {}\n",
}


def test_compute_source_hash_deterministic() -> None:
    h1 = ContractRegistry.compute_source_hash(SAMPLE_SOURCES)
    h2 = ContractRegistry.compute_source_hash(dict(reversed(list(SAMPLE_SOURCES.items()))))
    assert h1 == h2
    assert len(h1) == 64


def test_register_contract(registry: ContractRegistry) -> None:
    h = registry.register_contract(
        chain_id=56,
        address="0x" + "ab" * 20,
        sources=SAMPLE_SOURCES,
        contract_name="MyContract",
        compiler_version="0.8.20",
    )
    assert len(h) == 64
    assert registry.exists_contract(56, "0x" + "ab" * 20)


def test_address_normalized_to_lower(registry: ContractRegistry) -> None:
    addr = "0xABCDEF" + "0" * 34
    registry.register_contract(56, addr, SAMPLE_SOURCES)
    assert registry.exists_contract(56, addr.lower())
    assert registry.exists_contract(56, addr.upper())


def test_get_addresses_by_hash(registry: ContractRegistry) -> None:
    addr1 = "0x" + "11" * 20
    addr2 = "0x" + "22" * 20
    registry.register_contract(56, addr1, SAMPLE_SOURCES, contract_name="A")
    registry.register_contract(137, addr2, SAMPLE_SOURCES, contract_name="A")

    h = registry.compute_source_hash(SAMPLE_SOURCES)
    matches = registry.get_addresses_by_hash(h)
    assert len(matches) == 2
    chains = {m["chain_id"] for m in matches}
    assert chains == {56, 137}


def test_find_related_contracts(registry: ContractRegistry) -> None:
    addr1 = "0x" + "11" * 20
    addr2 = "0x" + "22" * 20
    registry.register_contract(56, addr1, SAMPLE_SOURCES)
    registry.register_contract(137, addr2, SAMPLE_SOURCES)

    related = registry.find_related_contracts(56, addr1)
    assert len(related) == 2


def test_tag_vulnerability_and_query(registry: ContractRegistry) -> None:
    addr = "0x" + "11" * 20
    h = registry.register_contract(56, addr, SAMPLE_SOURCES, contract_name="Foo")
    affected = registry.tag_vulnerability(h, "REENTRANCY", severity="High", description="…")
    assert affected == 1

    vulns = registry.get_vulnerable_contracts("REENTRANCY")
    assert len(vulns) == 1
    assert vulns[0]["severity"] == "High"


def test_stats_empty(registry: ContractRegistry) -> None:
    s = registry.stats()
    assert s["total_contracts"] == 0
    assert s["unique_source_hashes"] == 0


def test_stats_after_inserts(registry: ContractRegistry) -> None:
    registry.register_contract(56, "0x" + "11" * 20, SAMPLE_SOURCES)
    registry.register_contract(137, "0x" + "22" * 20, SAMPLE_SOURCES)
    registry.register_contract(56, "0x" + "33" * 20, {"X.sol": "contract X{}"})

    s = registry.stats()
    assert s["total_contracts"] == 3
    assert s["unique_source_hashes"] == 2
    assert s["duplicated_hashes"] == 1


def test_record_and_query_scanned_blocks(registry: ContractRegistry) -> None:
    registry.record_scanned_blocks(56, 100, 200, contracts_found=5)
    registry.record_scanned_blocks(56, 300, 400, contracts_found=2)
    ranges = registry.get_scanned_ranges(56)
    assert ranges == [(100, 200), (300, 400)]
    assert registry.get_last_scanned_block(56) == 400


def test_unscanned_ranges_empty_history(registry: ContractRegistry) -> None:
    gaps = registry.get_unscanned_ranges(56, 100, 200)
    assert gaps == [(100, 200)]


def test_unscanned_ranges_with_gap(registry: ContractRegistry) -> None:
    registry.record_scanned_blocks(56, 100, 150)
    registry.record_scanned_blocks(56, 180, 200)
    gaps = registry.get_unscanned_ranges(56, 100, 250)
    # gap between 150-180 and after 200
    assert (151, 179) in gaps
    assert (201, 250) in gaps


def test_get_top_duplicates(registry: ContractRegistry) -> None:
    # Register 3 contracts with the same source on different chains.
    for chain in (56, 137, 1):
        registry.register_contract(chain, f"0x{chain:040x}", SAMPLE_SOURCES, contract_name="Clone")
    # And one unique.
    registry.register_contract(56, "0x" + "ff" * 20, {"U.sol": "contract U{}"})

    top = registry.get_top_duplicates(limit=10)
    assert len(top) == 1
    assert top[0]["contract_count"] == 3
    assert sorted(top[0]["chains"]) == [1, 56, 137]
