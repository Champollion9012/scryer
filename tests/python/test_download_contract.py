"""Tests for download_contract.get_sourcify_source — particularly the
match_type plumbing that distinguishes ``perfect`` (1:1) from ``partial_match``
(runtime-equivalent only). Downstream callers need this signal to know whether
to trust source-level cosmetic details (variable names, comments, hex-literal
layout) versus only behavioural conclusions.
"""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import patch

import download_contract as dc


class _FakeResp:
    def __init__(self, *, status_code: int = 200, text: str = "") -> None:
        self.status_code = status_code
        self.text = text


def test_sourcify_returns_partial_match_label_in_message_and_metadata() -> None:
    """A partial-match source must be flagged so the caller doesn't misread it as 1:1."""

    def _fake_get(url: str, params: dict | None = None, **kwargs):
        # 1) check-by-addresses returns "partial"
        if "check-by-addresses" in url:
            return _FakeResp(text='[{"address":"0xabc","status":"partial","chainIds":["42161"]}]')
        # 2) sources.json doesn't exist for partial_match in this fixture
        if url.endswith("/sources.json"):
            return _FakeResp(status_code=404, text="")
        # 3) metadata.json — minimal payload with one source file (content inline)
        if url.endswith("/metadata.json"):
            return _FakeResp(
                text='{"sources":{"a.sol":{"content":"contract X{}"}},"output":{"abi":[]}}',
            )
        return _FakeResp(status_code=404, text="")

    with patch.object(dc.HTTP, "get", side_effect=_fake_get):
        sources, metadata, msg = dc.get_sourcify_source(42161, "0xabc")

    assert sources == {"a.sol": "contract X{}"}
    # The message must surface match_type — silent "Sourcify success" hides
    # whether we got a 1:1 source or only a behavioural twin.
    assert "partial" in msg.lower()
    # And the metadata gets a sourcify_match_type key so download_meta.json
    # persists it on disk.
    assert metadata.get("sourcify_match_type") == "partial"


def test_sourcify_full_match_labelled_as_perfect() -> None:
    def _fake_get(url: str, params: dict | None = None, **kwargs):
        if "check-by-addresses" in url:
            return _FakeResp(text='[{"address":"0xabc","status":"perfect","chainIds":["1"]}]')
        if url.endswith("/sources.json"):
            return _FakeResp(status_code=404, text="")
        if url.endswith("/metadata.json"):
            return _FakeResp(text='{"sources":{"X.sol":{"content":"// noop"}},"output":{"abi":[]}}')
        return _FakeResp(status_code=404, text="")

    with patch.object(dc.HTTP, "get", side_effect=_fake_get):
        _, metadata, msg = dc.get_sourcify_source(1, "0xabc")

    assert "perfect" in msg.lower()
    assert metadata.get("sourcify_match_type") == "perfect"


def test_sourcify_unverified_returns_failure_without_match_type() -> None:
    def _fake_get(url: str, params: dict | None = None, **kwargs):
        if "check-by-addresses" in url:
            return _FakeResp(text='[{"address":"0xabc","status":"false"}]')
        return _FakeResp(status_code=404, text="")

    with patch.object(dc.HTTP, "get", side_effect=_fake_get):
        sources, metadata, msg = dc.get_sourcify_source(1, "0xabc")
    assert sources is None
    assert metadata is None
    assert "Not verified" in msg


def test_bscscan_flattened_metadata_is_verify_ready() -> None:
    """A flattened Etherscan source must yield metadata verify_source can recompile: a synthesized
    compilationTarget (from ContractName), optimizer coerced to bool/int, and logical source keys."""
    src = "// SPDX-License-Identifier: MIT\npragma solidity 0.8.20;\ncontract Token { uint256 x; }"
    etherscan = {
        "status": "1",
        "message": "OK",
        "result": [
            {
                "SourceCode": src,
                "ContractName": "Token",
                "CompilerVersion": "v0.8.20+commit.a1b2c3d4",
                "OptimizationUsed": "1",
                "Runs": "200",
                "EVMVersion": "london",
                "Implementation": "",
                "Proxy": "0",
            }
        ],
    }

    def _fake_get(url: str, params: dict | None = None, **kwargs):
        return _FakeResp(text=json.dumps(etherscan))

    with patch.object(dc, "BSC_SCAN_API_KEY", "DUMMY"), patch.object(dc.HTTP, "get", side_effect=_fake_get):
        sources, metadata, msg = dc.get_bscscan_source(1, "0xabc")

    assert sources == {"combined_source.sol": src}
    s = metadata["settings"]
    assert s["compilationTarget"] == {"combined_source.sol": "Token"}  # synthesized from ContractName
    assert s["optimizer"] == {"enabled": True, "runs": 200}  # coerced from the "1"/"200" strings
    assert s["evmVersion"] == "london"
    assert metadata["sources"] == {"combined_source.sol": {}}  # logical path for disk reload
    assert metadata["compiler"]["version"] == "v0.8.20+commit.a1b2c3d4"


def test_bscscan_multifile_keeps_real_settings_and_no_synthetic_target() -> None:
    std = {
        "language": "Solidity",
        "sources": {"A.sol": {"content": "contract A{}"}, "B.sol": {"content": "contract B{}"}},
        "settings": {"optimizer": {"enabled": True, "runs": 999}, "evmVersion": "paris"},
    }
    etherscan = {
        "status": "1",
        "result": [
            {
                "SourceCode": "{" + json.dumps(std) + "}",  # Etherscan wraps standard-json in {{ }}
                "ContractName": "A",
                "CompilerVersion": "v0.8.20",
                "OptimizationUsed": "1",
                "Runs": "999",
                "EVMVersion": "paris",
            }
        ],
    }

    def _fake_get(url: str, params: dict | None = None, **kwargs):
        return _FakeResp(text=json.dumps(etherscan))

    with patch.object(dc, "BSC_SCAN_API_KEY", "DUMMY"), patch.object(dc.HTTP, "get", side_effect=_fake_get):
        sources, metadata, msg = dc.get_bscscan_source(1, "0xabc")

    assert set(sources) == {"A.sol", "B.sol"}
    s = metadata["settings"]
    assert s["optimizer"] == {"enabled": True, "runs": 999} and s["evmVersion"] == "paris"  # REAL settings kept
    assert "compilationTarget" not in s  # multi-file -> left for verify's compile-all + match-any
    assert set(metadata["sources"]) == {"A.sol", "B.sol"}


# ---------------------------------------------------------------------------
# Decompile fallback: when no verified source exists, try heimdall/panoramix
# ---------------------------------------------------------------------------


def test_decompile_fallback_imports_correctly() -> None:
    """The download_contract module must wire `decompile_with_*` from decompilers.

    A regression here would silently revert to BYTECODE_ONLY for every
    unverified contract, defeating the entire heimdall integration.
    """
    assert hasattr(dc, "decompile_with_heimdall")
    assert hasattr(dc, "decompile_with_panoramix")


def test_fetch_archive_bytecode_no_url_returns_none() -> None:
    """Without an archive RPC URL the helper short-circuits to None — should
    never attempt a network call. Important for offline test runs."""
    result = dc._fetch_archive_bytecode(
        archive_rpc_url="",
        address="0x" + "ab" * 20,
        block_number=10,
        primary_rpc_url="http://unused",
        tx_hash=None,
    )
    assert result is None


def test_fetch_archive_bytecode_no_target_block_or_tx_returns_none() -> None:
    """If neither block_number nor tx_hash is supplied, the helper must bail
    out before touching any RPC."""
    result = dc._fetch_archive_bytecode(
        archive_rpc_url="http://archive.example",
        address="0x" + "ab" * 20,
        block_number=None,
        primary_rpc_url="http://primary.example",
        tx_hash=None,
    )
    assert result is None


def test_fetch_archive_bytecode_cli_flags_present() -> None:
    """The CLI must expose --archive-rpc-url / --archive-tx / --archive-block
    so users can recover self-destructed exploit-tx contracts."""
    import inspect

    src = inspect.getsource(dc)
    assert "--archive-rpc-url" in src
    assert "--archive-tx" in src
    assert "--archive-block" in src
    # And the fetch_contract_source signature must accept them.
    sig = inspect.signature(dc.fetch_contract_source)
    assert {"archive_rpc_url", "archive_tx_hash", "archive_block"}.issubset(sig.parameters.keys())
    # Defaults must be safe (no archive recovery unless explicitly opted in).
    assert sig.parameters["archive_rpc_url"].default == ""
    assert sig.parameters["archive_tx_hash"].default is None
    assert sig.parameters["archive_block"].default is None


def test_decompile_fallback_meta_marker_consumed_by_audit(tmp_path: Path) -> None:
    """When download_contract writes a decompiled source, the meta MUST set
    ``decompiled: True`` and ``decompiler: <name>`` so audit_contracts can
    inject the right LLM hint. We seed the layout that download_contract
    actually produces (flat) and confirm the marker shape.
    """
    addr = "0xabcdef0123456789abcdef0123456789abcdef01"
    sources_dir = tmp_path / "sources"
    sources_dir.mkdir()
    # Write the meta the audit pipeline expects.
    meta_path = sources_dir / f"1_{addr}_download_meta.json"
    meta_path.write_text(
        json.dumps(
            {
                "chain_id": 1,
                "address": addr,
                "download_method": "decompiled_heimdall",
                "decompiled": True,
                "decompiler": "heimdall",
                "files_written": [f"1_{addr}_{addr}.decompiled.sol"],
            }
        )
    )
    # Read and assert the contract: an audit consumer just needs `decompiled`
    # boolean and `decompiler` name.
    meta = json.loads(meta_path.read_text())
    assert meta["decompiled"] is True
    assert meta["decompiler"] == "heimdall"
    assert meta["download_method"].startswith("decompiled_")
