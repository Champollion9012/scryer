"""P1: bytecode-level clone matching — map an UNVERIFIED contract to a verified twin.

The registry is source_hash-keyed, so a contract with no source used to match nothing. These
tests cover the three fingerprint tiers and the payoff: finding a twin that HAS verified source
(go read that), plus inheriting its vulnerability tags.
"""

from __future__ import annotations

from pathlib import Path

import pytest

import bytecode_abi as ba
from contract_registry import ContractRegistry


def _with_trailer(body_hex: str, blob_hex: str) -> str:
    """Append a CBOR-style metadata trailer (blob + its 2-byte length), like solc emits."""
    return body_hex + blob_hex + f"{len(blob_hex) // 2:04x}"


BODY = "6080604052" + "63aaaaaaaa14" + "63bbbbbbbb14" + "00"


# --------------------------------------------------------------------------- #
# Fingerprint tiers
# --------------------------------------------------------------------------- #
def test_fingerprints_have_all_three_tiers() -> None:
    fp = ba.code_fingerprints(_with_trailer(BODY, "de" * 20))
    assert fp["runtime_code_hash"].startswith("0x") and len(fp["runtime_code_hash"]) == 66
    assert fp["runtime_norm_hash"].startswith("0x")
    assert fp["selector_hash"].startswith("0x")
    assert fp["selector_count"] == 2 and fp["code_size"] > 0


def test_normalized_hash_ignores_metadata_trailer() -> None:
    """THE workhorse property: same source compiled elsewhere (different metadata) still matches."""
    a = ba.code_fingerprints(_with_trailer(BODY, "aa" * 20))
    b = ba.code_fingerprints(_with_trailer(BODY, "bb" * 20))
    assert a["runtime_code_hash"] != b["runtime_code_hash"]  # exact tier correctly differs
    assert a["runtime_norm_hash"] == b["runtime_norm_hash"]  # normalized tier matches
    assert a["selector_hash"] == b["selector_hash"]


def test_selector_hash_is_order_independent() -> None:
    """Selector-set identity must not depend on the order the dispatcher happens to emit."""
    one = ba.code_fingerprints("63aaaaaaaa14" + "63bbbbbbbb14" + "00")
    two = ba.code_fingerprints("63bbbbbbbb14" + "63aaaaaaaa14" + "00")
    assert one["selector_hash"] == two["selector_hash"]
    assert one["runtime_norm_hash"] != two["runtime_norm_hash"]  # but the bytecode genuinely differs


def test_different_code_has_different_fingerprints() -> None:
    a = ba.code_fingerprints("63aaaaaaaa14" + "00")
    b = ba.code_fingerprints("63cccccccc14" + "00")
    assert a["runtime_norm_hash"] != b["runtime_norm_hash"]
    assert a["selector_hash"] != b["selector_hash"]


def test_empty_code_has_no_fingerprints() -> None:
    assert ba.code_fingerprints("") == {}


# --------------------------------------------------------------------------- #
# Twin lookup
# --------------------------------------------------------------------------- #
VERIFIED = "0x" + "11" * 20
UNVERIFIED = "0x" + "22" * 20


@pytest.fixture
def reg(tmp_path: Path) -> ContractRegistry:
    return ContractRegistry(tmp_path / "registry.db")


def test_unverified_contract_finds_verified_twin(reg: ContractRegistry) -> None:
    """The payoff: an unverified contract maps to a twin that HAS source to read."""
    src_hash = reg.register_contract(
        chain_id=56, address=VERIFIED, sources={"A.sol": "contract A{}"}, contract_name="AToken"
    )
    code = _with_trailer(BODY, "aa" * 20)
    reg.record_code_fingerprints(56, VERIFIED, ba.code_fingerprints(code))

    # The unverified contract: same source, compiled elsewhere -> different metadata trailer.
    other = ba.code_fingerprints(_with_trailer(BODY, "bb" * 20))
    twins = reg.find_code_twins(1, UNVERIFIED, other)

    assert twins["exact_matches"] == []  # metadata differs, so exact correctly misses
    assert len(twins["normalized_matches"]) == 1
    m = twins["normalized_matches"][0]
    assert m["address"] == VERIFIED.lower() and m["chain_id"] == 56
    assert m["has_verified_source"] is True and m["contract_name"] == "AToken"
    assert m["source_hash"] == src_hash


def test_twin_lookup_excludes_self(reg: ContractRegistry) -> None:
    fp = ba.code_fingerprints(_with_trailer(BODY, "aa" * 20))
    reg.record_code_fingerprints(56, VERIFIED, fp)
    twins = reg.find_code_twins(56, VERIFIED, fp)
    assert twins["exact_matches"] == [] and twins["normalized_matches"] == []


def test_abi_tier_matches_when_immutables_change_the_bytecode(reg: ContractRegistry) -> None:
    """Different bytecode (as `immutable` injection causes) but the same ABI surface."""
    reg.register_contract(chain_id=56, address=VERIFIED, sources={"A.sol": "contract A{}"})
    reg.record_code_fingerprints(56, VERIFIED, ba.code_fingerprints("63aaaaaaaa14" + "63bbbbbbbb14" + "00"))

    # Same two selectors, extra body bytes -> different code hash, same selector set.
    other = ba.code_fingerprints("6080" + "63bbbbbbbb14" + "63aaaaaaaa14" + "00")
    twins = reg.find_code_twins(1, UNVERIFIED, other)
    assert twins["normalized_matches"] == []
    assert len(twins["abi_matches"]) == 1
    assert twins["abi_shared_by"] == 1  # the confidence signal: only one contract shares it


def test_abi_shared_by_exposes_low_confidence(reg: ContractRegistry) -> None:
    """A generic surface shared by many contracts must be self-evidently weak evidence."""
    fp = ba.code_fingerprints("63aaaaaaaa14" + "00")
    for i in range(5):
        reg.record_code_fingerprints(56, "0x" + f"{i:040x}", fp)
    twins = reg.find_code_twins(1, UNVERIFIED, fp)
    assert twins["abi_shared_by"] == 5


def test_vulnerability_tags_are_inherited_from_the_twin(reg: ContractRegistry) -> None:
    """Same code, same bug: a tag on the twin's source applies to the unverified contract."""
    src_hash = reg.register_contract(chain_id=56, address=VERIFIED, sources={"A.sol": "contract A{}"})
    reg.tag_vulnerability(src_hash, "unchecked-transfer", severity="High", description="no return check")
    code = _with_trailer(BODY, "aa" * 20)
    reg.record_code_fingerprints(56, VERIFIED, ba.code_fingerprints(code))

    twins = reg.find_code_twins(1, UNVERIFIED, ba.code_fingerprints(_with_trailer(BODY, "bb" * 20)))
    tags = twins["inherited_vulnerability_tags"]
    assert len(tags) == 1
    assert tags[0]["tag"] == "unchecked-transfer" and tags[0]["severity"] == "High"


# --------------------------------------------------------------------------- #
# Backfill work list (resume support)
# --------------------------------------------------------------------------- #
def test_backfill_worklist_skips_already_fingerprinted(reg: ContractRegistry) -> None:
    reg.register_contract(chain_id=56, address=VERIFIED, sources={"A.sol": "contract A{}"})
    reg.register_contract(chain_id=56, address=UNVERIFIED, sources={"B.sol": "contract B{}"})

    todo = reg.addresses_missing_fingerprints(56)
    assert {a.lower() for _c, a in todo} == {VERIFIED.lower(), UNVERIFIED.lower()}

    reg.record_code_fingerprints(56, VERIFIED, ba.code_fingerprints("63aaaaaaaa14" + "00"))
    todo2 = reg.addresses_missing_fingerprints(56)
    assert {a.lower() for _c, a in todo2} == {UNVERIFIED.lower()}  # resumable: no rework

    assert reg.has_code_fingerprint(56, VERIFIED) is True
    assert reg.has_code_fingerprint(56, UNVERIFIED) is False
