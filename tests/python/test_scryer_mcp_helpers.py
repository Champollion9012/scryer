"""Regression tests for scryer_mcp helper logic found by the post-rate-limit adversarial review.

Two classes of bug:
  * pseudo-source (decompiled / bytecode-only) leaking into a VERIFIED download's file list and
    registration — a stale ``_decompiled.sol`` left by an earlier decompile() must never count as
    verified source (_verified_src_files / _is_pseudo_src_name).
  * a provider throttle on the live-bytecode read collapsing into a permanent "no twins" / "cannot
    tag" instead of a retryable rate-limit signal (_live_runtime_hex / _bytecode_twins).
"""

from __future__ import annotations

import pytest

import scryer_mcp as m
from scryer_http import RateLimited


# --------------------------------------------------------------------------- #
# Pseudo-source must never be treated as verified source (#13)
# --------------------------------------------------------------------------- #
def test_is_pseudo_src_name() -> None:
    assert m._is_pseudo_src_name("56_0xabc_decompiled.sol")  # decompile() tool output
    assert m._is_pseudo_src_name("56_0xabc_Foo.decompiled.sol")  # download bytecode fallback
    assert m._is_pseudo_src_name("56_0xabc_Foo.BYTECODE_ONLY")
    assert m._is_pseudo_src_name("56_0xabc_Foo.bytecode_only")  # case-insensitive
    assert not m._is_pseudo_src_name("56_0xabc_Token.sol")
    assert not m._is_pseudo_src_name("56_0xabc_Vault.vy")


def test_verified_src_files_drops_stale_decompiled_for_verified_download(tmp_path, monkeypatch) -> None:
    """A later verified download must not list/register a stale _decompiled.sol from a prior
    decompile() of the same address."""
    monkeypatch.setattr(m, "SOURCES_DIR", tmp_path)
    prefix = "56_0xdead"
    (tmp_path / f"{prefix}_Token.sol").write_text("contract T{}", encoding="utf-8")
    (tmp_path / f"{prefix}_decompiled.sol").write_text("// pseudo", encoding="utf-8")

    # Verified meta (no decompiled flag) -> the stale pseudo file is excluded.
    verified = [p.name for p in m._verified_src_files(prefix, {"source_hash": "0x1"})]
    assert verified == [f"{prefix}_Token.sol"]


def test_verified_src_files_keeps_pseudo_when_meta_is_pseudo(tmp_path, monkeypatch) -> None:
    """When the download ITSELF is pseudo (decompiled/bytecode_only), the pseudo file is this
    download's output and must be listed (so the caller can read it)."""
    monkeypatch.setattr(m, "SOURCES_DIR", tmp_path)
    prefix = "56_0xbeef"
    (tmp_path / f"{prefix}_decompiled.sol").write_text("// pseudo", encoding="utf-8")
    files = {p.name for p in m._verified_src_files(prefix, {"decompiled": True})}
    assert f"{prefix}_decompiled.sol" in files


# --------------------------------------------------------------------------- #
# A throttle on the live-bytecode read is surfaced, never a silent miss (#12)
# --------------------------------------------------------------------------- #
def _patch_get_code(monkeypatch, exc: Exception) -> None:
    import etherscan_proxy_provider as epp

    class _Eth:
        def get_code(self, _addr):
            raise exc

    class _W3:
        eth = _Eth()

    monkeypatch.setattr(epp, "make_web3", lambda cid, rpc_url="": (_W3(), "fake-rpc"))


ADDR = "0x" + "11" * 20


def test_live_runtime_hex_surfaces_RateLimited(monkeypatch) -> None:
    _patch_get_code(monkeypatch, RateLimited(provider="rpc", retry_after=7, detail="Max rate limit reached"))
    hexv, err, rl = m._live_runtime_hex(56, ADDR)
    assert hexv is None
    assert rl is not None and rl["retry_after"] == 7
    assert "rate-limited" in err


def test_live_runtime_hex_surfaces_rpc_minus32005(monkeypatch) -> None:
    # The Etherscan-proxy fallback reports a throttle as a -32005 JSON-RPC error string.
    _patch_get_code(monkeypatch, Exception("-32005 rate limit: Max calls per sec rate limit reached (3/sec)"))
    hexv, err, rl = m._live_runtime_hex(56, ADDR)
    assert hexv is None and rl is not None


def test_live_runtime_hex_non_throttle_error_is_not_flagged(monkeypatch) -> None:
    _patch_get_code(monkeypatch, ValueError("boom"))
    hexv, err, rl = m._live_runtime_hex(56, ADDR)
    assert hexv is None and rl is None and "boom" in err


def test_bytecode_twins_propagates_throttle(monkeypatch) -> None:
    """A throttle must make _bytecode_twins report rate_limited (retryable), NOT a confirmed
    'no twins' that the agent would trust as a dead end."""
    _patch_get_code(monkeypatch, RateLimited(provider="rpc", retry_after=5, detail="throttled"))
    out = m._bytecode_twins(56, ADDR)
    assert out.get("rate_limited") is True
    assert out.get("retry_after") == 5
    assert "bytecode_match_error" in out and "exact_matches" not in out
