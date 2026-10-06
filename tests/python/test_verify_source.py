"""Tests for verify_source — pure helpers + end-to-end with subprocess + RPC mocked.

We never invoke real solc or hit a real RPC; tests must be fast and offline.
"""

from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import pytest

import verify_source as vs

# ---------------------------------------------------------------------------
# strip_metadata_trailer
# ---------------------------------------------------------------------------


def test_coerce_settings_normalizes_string_optimizer() -> None:
    s = vs._coerce_settings({"optimizer": {"enabled": "1", "runs": "200"}, "evmVersion": "london"})
    assert s["optimizer"]["enabled"] is True and s["optimizer"]["runs"] == 200
    assert s["evmVersion"] == "london"
    s2 = vs._coerce_settings({"optimizer": {"enabled": "0", "runs": "bad"}})
    assert s2["optimizer"]["enabled"] is False and "runs" not in s2["optimizer"]
    # Already-correct types pass through unchanged.
    assert vs._coerce_settings({"optimizer": {"enabled": True, "runs": 1}})["optimizer"] == {"enabled": True, "runs": 1}


def _no_target_meta(contract_name: str = "Bar") -> bytes:
    return json.dumps(
        {
            "metadata": {
                "compiler": {"version": "0.8.20"},
                "settings": {},  # NO compilationTarget — the flattened/legacy case
                "sources": {"Flat.sol": {"content": "pragma solidity ^0.8.0; contract X {}"}},
                "contract": {"contract_name": contract_name},
            }
        }
    ).encode()


def test_verify_no_target_compile_all_recovers_match(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """No compilationTarget -> compile ALL contracts and match on-chain bytecode, recovering the
    deployed contract instead of bailing to indeterminate (the fix for flattened/legacy source)."""
    foo = vs.CompiledArtifact(bytecode_hex="60800bad", immutable_ranges=[])
    bar = vs.CompiledArtifact(bytecode_hex="6080deadbeef", immutable_ranges=[])
    monkeypatch.setattr(vs, "compile_all_runtime_bytecode", lambda *a, **k: {"Flat.sol:Foo": foo, "Flat.sol:Bar": bar})
    monkeypatch.setattr(vs, "fetch_runtime_bytecode", lambda rpc, addr: "6080deadbeef")  # == Bar

    r = vs._verify_contract_uncached(
        chain_id=1,
        address_lower="0x" + "11" * 20,
        meta_bytes=_no_target_meta("Bar"),
        sources_dir=tmp_path,
        rpc_url="http://x",
        solc_path=Path("solc"),
    )
    assert r.verdict == "full_match"
    assert any("Bar" in n and "recovered" in n for n in r.notes)


def test_verify_no_target_recovers_by_bytecode_even_if_hint_absent(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    foo = vs.CompiledArtifact(bytecode_hex="60800bad", immutable_ranges=[])
    bar = vs.CompiledArtifact(bytecode_hex="6080deadbeef", immutable_ranges=[])
    monkeypatch.setattr(vs, "compile_all_runtime_bytecode", lambda *a, **k: {"Flat.sol:Foo": foo, "Flat.sol:Bar": bar})
    monkeypatch.setattr(vs, "fetch_runtime_bytecode", lambda rpc, addr: "60800bad")  # == Foo (not the hint "Bar")

    r = vs._verify_contract_uncached(
        chain_id=1,
        address_lower="0x" + "11" * 20,
        meta_bytes=_no_target_meta("Bar"),
        sources_dir=tmp_path,
        rpc_url="http://x",
        solc_path=Path("solc"),
    )
    assert r.verdict == "full_match" and any("Foo" in n for n in r.notes)  # matched by bytecode, not the hint


def test_verify_no_target_none_match_is_indeterminate_not_mismatch(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    foo = vs.CompiledArtifact(bytecode_hex="60800bad", immutable_ranges=[])
    bar = vs.CompiledArtifact(bytecode_hex="6080deadbeef", immutable_ranges=[])
    monkeypatch.setattr(vs, "compile_all_runtime_bytecode", lambda *a, **k: {"Flat.sol:Foo": foo, "Flat.sol:Bar": bar})
    monkeypatch.setattr(vs, "fetch_runtime_bytecode", lambda rpc, addr: "6080ffffffff")  # matches neither

    r = vs._verify_contract_uncached(
        chain_id=1,
        address_lower="0x" + "11" * 20,
        meta_bytes=_no_target_meta(),
        sources_dir=tmp_path,
        rpc_url="http://x",
        solc_path=Path("solc"),
    )
    assert r.verdict == "indeterminate"  # NOT mismatch — we were guessing the target
    assert any("none matched" in n for n in r.notes)


def _make_bytecode_with_trailer(runtime_hex: str, meta_blob_bytes: int) -> str:
    """Build hex: <runtime> + <meta_blob> + <2-byte length>.

    The blob begins with the ASCII 'solc' marker (736f6c63) so strip_metadata_trailer recognizes
    it as a genuine Solidity metadata trailer — it refuses to strip a trailer with no
    ipfs/bzzr/solc marker (that guard stops it eating real code from Vyper/assembly bytecode).
    """
    marker = "736f6c63"  # 'solc' (4 bytes)
    meta_blob = marker + "ab" * max(0, meta_blob_bytes - 4)  # total = meta_blob_bytes bytes
    length_suffix = format(meta_blob_bytes, "04x")
    return runtime_hex + meta_blob + length_suffix


def test_strip_trailer_removes_exact_length() -> None:
    runtime = "6080604052"
    bc = _make_bytecode_with_trailer(runtime, meta_blob_bytes=10)
    assert vs.strip_metadata_trailer(bc) == runtime


def test_strip_trailer_handles_0x_prefix() -> None:
    runtime = "6080"
    bc = "0x" + _make_bytecode_with_trailer(runtime, meta_blob_bytes=4)
    assert vs.strip_metadata_trailer(bc) == runtime


def test_strip_trailer_passthrough_on_too_short() -> None:
    # Less than 4 chars (i.e. less than the 2-byte length suffix) — return as-is
    assert vs.strip_metadata_trailer("ab") == "ab"
    assert vs.strip_metadata_trailer("0xab") == "ab"


def test_strip_trailer_refuses_to_eat_entire_bytecode() -> None:
    """If the declared trailer is >= total length, return original unchanged."""
    # length suffix = 0x00ff = 255 bytes; but bytecode itself is only 6 bytes.
    bogus = "abcd" + "00ff"
    assert vs.strip_metadata_trailer(bogus) == bogus


def test_strip_trailer_zero_length_passthrough() -> None:
    """A length suffix of 0 would make total_meta_chars=4 == len when there's
    nothing else; we return the original to avoid eating the suffix on empty."""
    assert vs.strip_metadata_trailer("0000") == "0000"


# ---------------------------------------------------------------------------
# _normalize_version
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "raw,expected",
    [
        ("0.8.34+commit.80d5c536", "0.8.34"),
        ("v0.8.20", "0.8.20"),
        ("0.8.20", "0.8.20"),
        ("", None),
        (None, None),
    ],
)
def test_normalize_version(raw: str | None, expected: str | None) -> None:
    assert vs._normalize_version(raw) == expected


# ---------------------------------------------------------------------------
# find_solc precedence
# ---------------------------------------------------------------------------


def test_find_solc_env_path_wins(tmp_path: Path, monkeypatch) -> None:
    fake_solc = tmp_path / "my-solc"
    fake_solc.write_text("")
    monkeypatch.setenv("SOLC_PATH", str(fake_solc))
    monkeypatch.setattr(vs.shutil, "which", lambda _: "/usr/bin/solc")
    assert vs.find_solc("0.8.20") == fake_solc


def test_find_solc_falls_back_to_path(monkeypatch) -> None:
    monkeypatch.delenv("SOLC_PATH", raising=False)
    monkeypatch.setattr(vs.shutil, "which", lambda _: "/usr/local/bin/solc")
    # Stub Path.exists to return False for ~/.svm candidates
    monkeypatch.setattr(Path, "exists", lambda self: str(self) == "/usr/local/bin/solc")
    assert vs.find_solc("0.8.20") == Path("/usr/local/bin/solc")


def test_find_solc_returns_none_if_no_match(monkeypatch) -> None:
    monkeypatch.delenv("SOLC_PATH", raising=False)
    monkeypatch.setattr(vs.shutil, "which", lambda _: None)
    monkeypatch.setattr(Path, "exists", lambda self: False)
    assert vs.find_solc("0.8.20") is None


# ---------------------------------------------------------------------------
# compile_runtime_bytecode (subprocess mocked)
# ---------------------------------------------------------------------------


def _solc_output(deployed_object: str, *, immutable_refs: dict | None = None) -> str:
    deployed: dict = {"object": deployed_object}
    if immutable_refs is not None:
        deployed["immutableReferences"] = immutable_refs
    return json.dumps(
        {
            "errors": [],
            "contracts": {"scripts/1.sol": {"test": {"evm": {"deployedBytecode": deployed}}}},
        }
    )


def test_compile_runtime_bytecode_returns_deployed_object() -> None:
    fake_proc = SimpleNamespace(returncode=0, stdout=_solc_output("60806040DEAD"), stderr="")
    with patch.object(vs.subprocess, "run", return_value=fake_proc) as mock_run:
        artifact = vs.compile_runtime_bytecode(
            sources={"scripts/1.sol": "contract test{}"},
            settings={"optimizer": {"enabled": False}, "evmVersion": "paris"},
            target_file="scripts/1.sol",
            target_contract="test",
            solc_path=Path("/fake/solc"),
        )
    assert artifact.bytecode_hex == "60806040dead"
    assert artifact.immutable_ranges == []
    # standard-json invocation contract
    args, kwargs = mock_run.call_args
    assert args[0] == [str(Path("/fake/solc")), "--standard-json"]
    payload = json.loads(kwargs["input"])
    assert payload["language"] == "Solidity"
    # outputSelection must request both the bytecode object AND immutableReferences
    sel = payload["settings"]["outputSelection"]["*"]["*"]
    assert "evm.deployedBytecode.object" in sel
    assert "evm.deployedBytecode.immutableReferences" in sel


# ---------------------------------------------------------------------------
# Immutable ranges: parse + zero-out helpers
# ---------------------------------------------------------------------------


def test_flatten_immutable_refs_handles_solc_format() -> None:
    """Each AST id maps to a list of {start, length} entries — flatten all of them."""
    refs = {
        "12": [{"start": 100, "length": 32}, {"start": 500, "length": 32}],
        "34": [{"start": 200, "length": 32}],
    }
    out = vs._flatten_immutable_refs(refs)
    assert sorted(out) == [(100, 32), (200, 32), (500, 32)]


def test_flatten_immutable_refs_skips_garbage() -> None:
    refs = {
        "1": [{"start": 10, "length": 32}],
        "2": "not-a-list",
        "3": [None, {}, {"start": 20}],  # missing length
        "4": [{"start": 30, "length": 0}],  # zero-length
        "5": [{"start": "string", "length": 32}],  # wrong type
    }
    assert vs._flatten_immutable_refs(refs) == [(10, 32)]


def test_flatten_immutable_refs_handles_none_or_empty() -> None:
    assert vs._flatten_immutable_refs(None) == []
    assert vs._flatten_immutable_refs({}) == []


def test_zero_immutable_ranges_zeros_specified_bytes() -> None:
    # 8 bytes total: aabbccddeeff1122
    bc = "aabbccddeeff1122"
    # Zero bytes [2,4) — chars [4,8)
    out = vs.zero_immutable_ranges(bc, [(2, 2)])
    assert out == "aabb0000eeff1122"


def test_zero_immutable_ranges_handles_multiple_ranges() -> None:
    bc = "aabbccddeeff1122"
    out = vs.zero_immutable_ranges(bc, [(0, 1), (3, 1), (7, 1)])
    assert out == "00bbcc00eeff1100"


def test_zero_immutable_ranges_no_op_when_empty() -> None:
    bc = "aabbccddeeff"
    assert vs.zero_immutable_ranges(bc, []) == bc


def test_zero_immutable_ranges_skips_out_of_bounds() -> None:
    """An out-of-range entry must NOT crash; valid entries still apply."""
    bc = "aabbccdd"  # 4 bytes
    out = vs.zero_immutable_ranges(bc, [(1, 1), (10, 5)])  # 2nd is out of bounds
    assert out == "aa00ccdd"


def test_zero_immutable_ranges_strips_0x_prefix() -> None:
    out = vs.zero_immutable_ranges("0xaabbccdd", [(0, 1)])
    assert out == "00bbccdd"


def test_compile_raises_on_solc_error() -> None:
    err_out = json.dumps({"errors": [{"severity": "error", "formattedMessage": "ParserError: bad"}]})
    fake_proc = SimpleNamespace(returncode=0, stdout=err_out, stderr="")
    with patch.object(vs.subprocess, "run", return_value=fake_proc), pytest.raises(RuntimeError, match="solc errors"):
        vs.compile_runtime_bytecode(
            sources={"scripts/1.sol": "junk"},
            settings={},
            target_file="scripts/1.sol",
            target_contract="test",
            solc_path=Path("/fake/solc"),
        )


def test_compile_raises_on_non_zero_exit() -> None:
    fake_proc = SimpleNamespace(returncode=1, stdout="", stderr="oom")
    with (
        patch.object(vs.subprocess, "run", return_value=fake_proc),
        pytest.raises(RuntimeError, match="solc returned 1"),
    ):
        vs.compile_runtime_bytecode(
            sources={}, settings={}, target_file="x.sol", target_contract="X", solc_path=Path("/fake/solc")
        )


# ---------------------------------------------------------------------------
# verify_contract — end-to-end with everything mocked
# ---------------------------------------------------------------------------


def _seed_meta_and_source(
    tmp_path: Path,
    *,
    chain_id: int,
    address: str,
    source_content: str = "// SPDX-License-Identifier: MIT\npragma solidity ^0.8.20;\ncontract test{}\n",
    inline_source: bool = True,
    compiler_version: str = "0.8.34+commit.80d5c536",
) -> Path:
    """Write download_meta.json + the flat source file under tmp_path/sources."""
    sources_dir = tmp_path / "sources"
    sources_dir.mkdir()
    address_lower = address.lower()
    meta = {
        "chain_id": chain_id,
        "address": address_lower,
        "metadata": {
            "compiler": {"version": compiler_version},
            "settings": {
                "compilationTarget": {"scripts/1.sol": "test"},
                "evmVersion": "paris",
                "optimizer": {"enabled": False, "runs": 200},
                "metadata": {"bytecodeHash": "ipfs"},
            },
            "sources": {
                "scripts/1.sol": {"content": source_content}
                if inline_source
                else {"keccak256": "0x00", "license": "MIT"}
            },
        },
    }
    (sources_dir / f"{chain_id}_{address_lower}_download_meta.json").write_text(json.dumps(meta))
    if not inline_source:
        # Flat layout: scripts/1.sol -> scripts_1.sol
        (sources_dir / f"{chain_id}_{address_lower}_scripts_1.sol").write_text(source_content, encoding="utf-8")
    return sources_dir


def _fake_rpc_post(deployed_hex: str):
    """Return a fake httpx-style response for eth_getCode."""

    class Resp:
        def __init__(self) -> None:
            self.status_code = 200

        def raise_for_status(self) -> None: ...
        def json(self) -> dict:
            return {"jsonrpc": "2.0", "id": 1, "result": "0x" + deployed_hex}

    class Client:
        def __enter__(self):
            return self

        def __exit__(self, *args):
            pass

        def post(self, url, **kwargs):
            return Resp()

    return Client()


def test_verify_full_match(tmp_path: Path) -> None:
    addr = "0x" + "ab" * 20
    sources_dir = _seed_meta_and_source(tmp_path, chain_id=1, address=addr)
    deployed = "60806040DEAD" + "ff" * 8 + "0008"  # runtime + 8-byte trailer + length 8

    fake_proc = SimpleNamespace(returncode=0, stdout=_solc_output(deployed), stderr="")
    with (
        patch.object(vs.subprocess, "run", return_value=fake_proc),
        patch.object(vs.scryer_http, "sync_client", return_value=_fake_rpc_post(deployed)),
        patch.object(vs, "find_solc", return_value=Path("/fake/solc")),
    ):
        result = vs.verify_contract(1, addr, sources_dir=sources_dir, rpc_url="http://stub")

    assert result.verdict == "full_match"
    assert result.compiler_version == "0.8.34+commit.80d5c536"
    assert result.on_chain_size == result.compiled_size
    assert result.immutables_zeroed == 0  # no immutables in this fixture


def test_verify_full_match_with_immutables_zeroed(tmp_path: Path) -> None:
    """The original Resolv-style failure: same size, single byte differs, due to
    an immutable filled in at construction. solc reports the byte range; we
    mask it out and the contract verifies cleanly.
    """
    addr = "0x" + "fa" * 20
    sources_dir = _seed_meta_and_source(tmp_path, chain_id=1, address=addr)

    # 32 bytes of "code" + 8-byte trailer + 2-byte length suffix.
    # Imagine the 32-byte slot at byte offset 16 is an immutable address.
    runtime_code_compiled = "ff" * 16 + "00" * 32 + "ee" * 4 + "0008"  # immutable = zeros
    runtime_code_on_chain = "ff" * 16 + "ab" * 32 + "ee" * 4 + "0008"  # immutable = real address
    immutable_refs = {"42": [{"start": 16, "length": 32}]}

    fake_proc = SimpleNamespace(
        returncode=0, stdout=_solc_output(runtime_code_compiled, immutable_refs=immutable_refs), stderr=""
    )
    with (
        patch.object(vs.subprocess, "run", return_value=fake_proc),
        patch.object(vs.scryer_http, "sync_client", return_value=_fake_rpc_post(runtime_code_on_chain)),
        patch.object(vs, "find_solc", return_value=Path("/fake/solc")),
    ):
        result = vs.verify_contract(1, addr, sources_dir=sources_dir, rpc_url="http://stub")

    assert result.verdict == "full_match", f"got {result.verdict}: {result.notes}"
    assert result.immutables_zeroed == 1
    assert any("masked 1 immutable" in n for n in result.notes)


def test_verify_mismatch_remains_when_runtime_actually_differs_around_immutables(tmp_path: Path) -> None:
    """If the bytes OUTSIDE immutable ranges differ, masking shouldn't paper over it."""
    addr = "0x" + "fb" * 20
    sources_dir = _seed_meta_and_source(tmp_path, chain_id=1, address=addr)
    # immutable at [16, 48); but we tweak a byte at offset 4 too — that should
    # still produce a real mismatch.
    compiled = "ff" * 4 + "AA" + "ff" * 11 + "00" * 32 + "ee" * 4 + "0008"
    on_chain = "ff" * 4 + "BB" + "ff" * 11 + "ab" * 32 + "ee" * 4 + "0008"
    immutable_refs = {"7": [{"start": 16, "length": 32}]}

    fake_proc = SimpleNamespace(returncode=0, stdout=_solc_output(compiled, immutable_refs=immutable_refs), stderr="")
    with (
        patch.object(vs.subprocess, "run", return_value=fake_proc),
        patch.object(vs.scryer_http, "sync_client", return_value=_fake_rpc_post(on_chain)),
        patch.object(vs, "find_solc", return_value=Path("/fake/solc")),
    ):
        result = vs.verify_contract(1, addr, sources_dir=sources_dir, rpc_url="http://stub")

    assert result.verdict == "mismatch"
    assert result.immutables_zeroed == 1
    # Real diff at hex char 8 (byte 4 -> char 8)
    assert any("first byte differs at hex char index 8" in n for n in result.notes)


def test_verify_partial_match_when_only_trailer_differs(tmp_path: Path) -> None:
    addr = "0x" + "cd" * 20
    sources_dir = _seed_meta_and_source(tmp_path, chain_id=1, address=addr)
    runtime_core = "60806040DEAD"
    # Both trailers carry the 'solc' marker (real solc always does; strip requires it); only the
    # 4 hash bytes after it differ — the metadata-only difference that makes a partial_match.
    deployed_compiled = runtime_core + "736f6c63" + "ffffffff" + "0008"  # what solc produces
    deployed_on_chain = runtime_core + "736f6c63" + "11111111" + "0008"  # different ipfs/meta hash

    fake_proc = SimpleNamespace(returncode=0, stdout=_solc_output(deployed_compiled), stderr="")
    with (
        patch.object(vs.subprocess, "run", return_value=fake_proc),
        patch.object(vs.scryer_http, "sync_client", return_value=_fake_rpc_post(deployed_on_chain)),
        patch.object(vs, "find_solc", return_value=Path("/fake/solc")),
    ):
        result = vs.verify_contract(1, addr, sources_dir=sources_dir, rpc_url="http://stub")

    assert result.verdict == "partial_match"
    assert any("metadata trailer" in n for n in result.notes)


def test_verify_mismatch_when_runtime_differs(tmp_path: Path) -> None:
    addr = "0x" + "ef" * 20
    sources_dir = _seed_meta_and_source(tmp_path, chain_id=1, address=addr)
    deployed_compiled = "AAAA" + "ff" * 8 + "0008"
    deployed_on_chain = "BBBB" + "ff" * 8 + "0008"  # runtime differs

    fake_proc = SimpleNamespace(returncode=0, stdout=_solc_output(deployed_compiled), stderr="")
    with (
        patch.object(vs.subprocess, "run", return_value=fake_proc),
        patch.object(vs.scryer_http, "sync_client", return_value=_fake_rpc_post(deployed_on_chain)),
        patch.object(vs, "find_solc", return_value=Path("/fake/solc")),
    ):
        result = vs.verify_contract(1, addr, sources_dir=sources_dir, rpc_url="http://stub")

    assert result.verdict == "mismatch"
    # Note must point at first differing index (1 = second hex char "A" vs "B")
    assert any("first byte differs" in n for n in result.notes)


def test_verify_no_solc_returns_actionable_message(tmp_path: Path) -> None:
    addr = "0x" + "11" * 20
    sources_dir = _seed_meta_and_source(tmp_path, chain_id=1, address=addr)

    with patch.object(vs, "find_solc", return_value=None):
        result = vs.verify_contract(1, addr, sources_dir=sources_dir, rpc_url="http://stub")

    assert result.verdict == "no_solc"
    assert any("solc-select install 0.8.34" in n for n in result.notes)


def test_verify_no_bytecode_when_eoa(tmp_path: Path) -> None:
    addr = "0x" + "22" * 20
    sources_dir = _seed_meta_and_source(tmp_path, chain_id=1, address=addr)

    fake_proc = SimpleNamespace(returncode=0, stdout=_solc_output("dead"), stderr="")
    with (
        patch.object(vs.subprocess, "run", return_value=fake_proc),
        patch.object(vs.scryer_http, "sync_client", return_value=_fake_rpc_post("")),
        patch.object(vs, "find_solc", return_value=Path("/fake/solc")),
    ):
        result = vs.verify_contract(1, addr, sources_dir=sources_dir, rpc_url="http://stub")

    assert result.verdict == "no_bytecode"


def test_verify_loads_source_from_disk_when_metadata_lacks_inline_content(tmp_path: Path) -> None:
    """If metadata.sources[*].content is missing, fall back to flat-layout disk file."""
    addr = "0x" + "33" * 20
    sources_dir = _seed_meta_and_source(tmp_path, chain_id=1, address=addr, inline_source=False)
    runtime = "abcdef0123456789" + "0001" + "0001"  # non-empty trailer
    fake_proc = SimpleNamespace(returncode=0, stdout=_solc_output(runtime), stderr="")
    with (
        patch.object(vs.subprocess, "run", return_value=fake_proc) as mock_run,
        patch.object(vs.scryer_http, "sync_client", return_value=_fake_rpc_post(runtime)),
        patch.object(vs, "find_solc", return_value=Path("/fake/solc")),
    ):
        result = vs.verify_contract(1, addr, sources_dir=sources_dir, rpc_url="http://stub")

    assert result.verdict == "full_match"
    # Confirm the content fed to solc came from the on-disk file
    payload = json.loads(mock_run.call_args.kwargs["input"])
    assert "scripts/1.sol" in payload["sources"]
    assert "pragma solidity" in payload["sources"]["scripts/1.sol"]["content"]


def test_verify_missing_meta_returns_indeterminate_with_diagnostic(tmp_path: Path) -> None:
    # No meta -> no compile, no compare -> indeterminate (NOT a false "mismatch").
    result = vs.verify_contract(1, "0x" + "44" * 20, sources_dir=tmp_path, rpc_url="http://stub")
    assert result.verdict == "indeterminate"
    assert any("download_meta.json not found" in n for n in result.notes)


# ---------------------------------------------------------------------------
# CLI smoke test: argparse contract
# ---------------------------------------------------------------------------


def test_verify_cache_roundtrip(tmp_path: Path) -> None:
    """Cache stores then retrieves a result with cache_hit=True on read."""
    cache = vs.VerifyCache(tmp_path / "verify.db")
    key = vs.VerifyCache.compute_key(1, "0xabc", b'{"meta": "stuff"}')
    assert cache.get(key) is None  # initially empty

    original = vs.VerifyResult(
        verdict="partial_match",
        chain_id=1,
        address="0xabc",
        compiler_version="0.8.34",
        on_chain_size=4157,
        compiled_size=4157,
        on_chain_no_meta_prefix="6080",
        compiled_no_meta_prefix="6080",
        notes=["only trailer differs"],
        immutables_zeroed=3,
    )
    cache.set(key, original)

    hit = cache.get(key)
    assert hit is not None
    assert hit.verdict == "partial_match"
    assert hit.compiler_version == "0.8.34"
    assert hit.on_chain_size == 4157
    assert hit.notes == ["only trailer differs"]
    assert hit.immutables_zeroed == 3  # persisted across the cache, not reset to 0 on a hit
    assert hit.cache_hit is True  # marker so caller knows it didn't recompile


def test_verify_cache_key_changes_with_meta_bytes() -> None:
    """A different meta.json content must produce a different cache key."""
    k1 = vs.VerifyCache.compute_key(1, "0xabc", b"meta v1")
    k2 = vs.VerifyCache.compute_key(1, "0xabc", b"meta v2")
    k3 = vs.VerifyCache.compute_key(2, "0xabc", b"meta v1")  # different chain
    k4 = vs.VerifyCache.compute_key(1, "0xABC", b"meta v1")  # case differs but lowered
    assert len({k1, k2, k3}) == 3
    assert k1 == k4  # address normalisation


def test_verify_cache_key_changes_with_solc_id() -> None:
    """Different resolved solc binaries → different cache slots, even when
    everything else is equal. Prevents a stale verdict from a previous solc
    serving a request after the user upgrades.
    """
    base_args = (1, "0xabc", b"meta")
    k_no_solc = vs.VerifyCache.compute_key(*base_args, solc_id="")
    k_solc1 = vs.VerifyCache.compute_key(*base_args, solc_id="/usr/local/bin/solc-0.8.20")
    k_solc2 = vs.VerifyCache.compute_key(*base_args, solc_id="/usr/local/bin/solc-0.8.28")
    assert len({k_no_solc, k_solc1, k_solc2}) == 3
    # And changing solc_id alone must NOT match the no-solc-id key
    assert k_solc1 != k_no_solc


def test_verify_contract_uses_cache_on_hit(tmp_path: Path) -> None:
    """Cache hit short-circuits — no solc invocation, no RPC call."""
    addr = "0x" + "ab" * 20
    sources_dir = _seed_meta_and_source(tmp_path, chain_id=1, address=addr)
    cache = vs.VerifyCache(tmp_path / "verify.db")

    # Pre-populate the cache for this exact (chain, addr, meta, solc_id) tuple.
    # The cache key now includes the resolved solc binary identity so that
    # an upgraded compiler invalidates entries.
    meta_path = sources_dir / f"1_{addr}_download_meta.json"
    meta_bytes = meta_path.read_bytes()
    fake_solc = Path("/fake/solc")
    key = vs.VerifyCache.compute_key(1, addr, meta_bytes, solc_id=str(fake_solc))
    cache.set(
        key,
        vs.VerifyResult(verdict="full_match", chain_id=1, address=addr, compiler_version="0.8.34"),
    )

    # If solc or RPC were called, these mocks would fail loudly
    with (
        patch.object(vs.subprocess, "run", side_effect=AssertionError("solc must not run on cache hit")),
        patch.object(vs.scryer_http, "sync_client", side_effect=AssertionError("RPC must not run on cache hit")),
        patch.object(vs, "find_solc", return_value=fake_solc),
    ):
        result = vs.verify_contract(1, addr, sources_dir=sources_dir, cache=cache)

    assert result.verdict == "full_match"
    assert result.cache_hit is True


def test_verify_contract_writes_cacheable_verdicts(tmp_path: Path) -> None:
    """A successful full_match run populates the cache so the next call is free."""
    addr = "0x" + "cd" * 20
    sources_dir = _seed_meta_and_source(tmp_path, chain_id=1, address=addr)
    cache = vs.VerifyCache(tmp_path / "verify.db")
    deployed = "60806040DEAD" + "ff" * 8 + "0008"

    fake_proc = SimpleNamespace(returncode=0, stdout=_solc_output(deployed), stderr="")
    with (
        patch.object(vs.subprocess, "run", return_value=fake_proc),
        patch.object(vs.scryer_http, "sync_client", return_value=_fake_rpc_post(deployed)),
        patch.object(vs, "find_solc", return_value=Path("/fake/solc")),
    ):
        first = vs.verify_contract(1, addr, sources_dir=sources_dir, rpc_url="http://stub", cache=cache)

    assert first.verdict == "full_match"
    assert first.cache_hit is False

    # Second call must hit cache — solc/RPC mocks raise if invoked.
    # find_solc must keep returning the same path so the cache key matches.
    with (
        patch.object(vs.subprocess, "run", side_effect=AssertionError("should not recompile")),
        patch.object(vs.scryer_http, "sync_client", side_effect=AssertionError("should not RPC")),
        patch.object(vs, "find_solc", return_value=Path("/fake/solc")),
    ):
        second = vs.verify_contract(1, addr, sources_dir=sources_dir, rpc_url="http://stub", cache=cache)
    assert second.verdict == "full_match"
    assert second.cache_hit is True


def test_verify_contract_does_not_cache_no_solc(tmp_path: Path) -> None:
    """Infrastructure-error verdicts must NOT poison the cache.

    If we cached `no_solc`, the user couldn't recover by installing solc without
    also clearing the DB. Same logic for `no_bytecode` (transient RPC failure).
    """
    addr = "0x" + "ef" * 20
    sources_dir = _seed_meta_and_source(tmp_path, chain_id=1, address=addr)
    cache = vs.VerifyCache(tmp_path / "verify.db")

    with patch.object(vs, "find_solc", return_value=None):
        first = vs.verify_contract(1, addr, sources_dir=sources_dir, rpc_url="http://stub", cache=cache)
    assert first.verdict == "no_solc"

    # Cache must still be empty — recovery path stays open
    meta_bytes = (sources_dir / f"1_{addr}_download_meta.json").read_bytes()
    key = vs.VerifyCache.compute_key(1, addr, meta_bytes)
    assert cache.get(key) is None


def test_cli_main_returns_no_solc_when_solc_missing(tmp_path: Path, monkeypatch, capsys) -> None:
    """main() should run end-to-end and return exit code 2 when solc is unavailable."""
    addr = "0x" + "55" * 20
    sources_dir = _seed_meta_and_source(tmp_path, chain_id=1, address=addr)
    monkeypatch.setattr(
        vs.sys,
        "argv",
        [
            "verify_source.py",
            "--chain-id",
            "1",
            "--address",
            addr,
            "--sources-dir",
            str(sources_dir),
            "--rpc-url",
            "http://stub",
            "--json",
        ],
    )
    with patch.object(vs, "find_solc", return_value=None):
        rc = vs.main()
    assert rc == vs._EXIT_CODES["no_solc"]
    out = capsys.readouterr().out
    payload = json.loads(out)
    assert payload["verdict"] == "no_solc"
