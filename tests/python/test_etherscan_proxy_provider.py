"""Tests for the Etherscan V2 proxy-module web3 provider (niche-chain RPC fallback)."""

from __future__ import annotations

from unittest.mock import patch

import pytest

import etherscan_proxy_provider as epp
from scryer_http import rpc_rate_limit_reason


class _Resp:
    def __init__(self, status_code: int = 200, body: dict | None = None, headers: dict | None = None):
        self.status_code = status_code
        self._body = body if body is not None else {}
        self.headers = headers or {}

    def json(self):
        return self._body


def _provider():
    return epp.EtherscanProxyProvider(80002, "DUMMYKEY")


def test_hexify() -> None:
    assert epp._hexify(True) == "0x1" and epp._hexify(False) == "0x0"  # bool before int
    assert epp._hexify(19) == "0x13"
    assert epp._hexify(b"\x12\x34") == "0x1234"
    assert epp._hexify("latest") == "latest"


def test_eth_getcode_maps_to_proxy_module() -> None:
    captured: dict = {}

    def fake_get(url, params=None):
        captured.update(params or {})
        return _Resp(body={"jsonrpc": "2.0", "id": 1, "result": "0xdeadbeef"})

    with patch.object(epp._HTTP, "get", side_effect=fake_get), patch.object(epp.time, "sleep"):
        resp = _provider().make_request("eth_getCode", ["0xabc", "latest"])

    assert resp["result"] == "0xdeadbeef"
    assert captured["chainid"] == "80002"
    assert captured["module"] == "proxy" and captured["action"] == "eth_getCode"
    assert captured["address"] == "0xabc" and captured["tag"] == "latest"
    assert captured["apikey"] == "DUMMYKEY"


def test_eth_getstorageat_maps_position_and_block() -> None:
    captured: dict = {}

    def fake_get(url, params=None):
        captured.update(params or {})
        return _Resp(body={"jsonrpc": "2.0", "id": 1, "result": "0x" + "00" * 32})

    with patch.object(epp._HTTP, "get", side_effect=fake_get), patch.object(epp.time, "sleep"):
        _provider().make_request("eth_getStorageAt", ["0xabc", 19, 0x1000])  # ints -> hex

    assert captured["action"] == "eth_getStorageAt"
    assert captured["position"] == "0x13" and captured["tag"] == "0x1000"


def test_eth_call_extracts_to_and_data() -> None:
    captured: dict = {}

    def fake_get(url, params=None):
        captured.update(params or {})
        return _Resp(body={"jsonrpc": "2.0", "id": 1, "result": "0x01"})

    with patch.object(epp._HTTP, "get", side_effect=fake_get), patch.object(epp.time, "sleep"):
        resp = _provider().make_request("eth_call", [{"to": "0xc0ffee", "data": "0x8da5cb5b"}, "latest"])

    assert resp["result"] == "0x01"
    assert captured["to"] == "0xc0ffee" and captured["data"] == "0x8da5cb5b" and captured["action"] == "eth_call"


def test_eth_getbalance_uses_account_module_and_hexifies() -> None:
    captured: dict = {}

    def fake_get(url, params=None):
        captured.update(params or {})
        return _Resp(body={"status": "1", "message": "OK", "result": "1500000000000000000"})

    with patch.object(epp._HTTP, "get", side_effect=fake_get), patch.object(epp.time, "sleep"):
        resp = _provider().make_request("eth_getBalance", ["0xabc", "latest"])

    assert captured["module"] == "account" and captured["action"] == "balance"  # NOT proxy
    assert resp["result"] == hex(1500000000000000000)  # decimal wei -> hex


def test_eth_getblockbynumber_maps_tag_and_boolean() -> None:
    captured: dict = {}

    def fake_get(url, params=None):
        captured.update(params or {})
        return _Resp(body={"jsonrpc": "2.0", "id": 1, "result": {"number": "0x10", "timestamp": "0x6543"}})

    with patch.object(epp._HTTP, "get", side_effect=fake_get), patch.object(epp.time, "sleep"):
        resp = _provider().make_request("eth_getBlockByNumber", [0x123456, False])

    assert captured["action"] == "eth_getBlockByNumber"
    assert captured["tag"] == "0x123456" and captured["boolean"] == "false"
    assert resp["result"]["timestamp"] == "0x6543"


def test_canned_metadata_methods_need_no_network() -> None:
    p = _provider()
    with patch.object(epp._HTTP, "get", side_effect=AssertionError("should not hit network")):
        assert p.make_request("eth_chainId", [])["result"] == hex(80002)
        assert p.make_request("net_version", [])["result"] == "80002"
        assert "scryer" in p.make_request("web3_clientVersion", [])["result"]


def test_unsupported_method_returns_method_not_found() -> None:
    p = _provider()
    with patch.object(epp._HTTP, "get", side_effect=AssertionError("should not hit network")):
        resp = p.make_request("eth_sendTransaction", [{}])
    assert resp["error"]["code"] == -32601


def test_throttle_retries_then_surfaces_as_rate_limit_error() -> None:
    calls = {"n": 0}

    def fake_get(url, params=None):
        calls["n"] += 1
        # app-level throttle on BOTH the first try and the single retry
        return _Resp(body={"status": "0", "message": "NOTOK", "result": "Max calls per sec rate limit reached (3/sec)"})

    with patch.object(epp._HTTP, "get", side_effect=fake_get), patch.object(epp.time, "sleep"):
        resp = _provider().make_request("eth_getCode", ["0xabc", "latest"])

    assert calls["n"] == 2  # one retry after the back-off
    assert resp["error"]["code"] == -32005
    # The emitted message must be recognizable by the shared RPC throttle classifier so that
    # _call/get_state surface rate_limited (the P1 integration) rather than reading "absent".
    assert rpc_rate_limit_reason(resp["error"]) is not None


def test_throttle_retry_can_succeed() -> None:
    calls = {"n": 0}

    def fake_get(url, params=None):
        calls["n"] += 1
        if calls["n"] == 1:
            return _Resp(status_code=429, headers={"Retry-After": "1"})
        return _Resp(body={"jsonrpc": "2.0", "id": 1, "result": "0xabcd"})  # retry succeeds

    with patch.object(epp._HTTP, "get", side_effect=fake_get), patch.object(epp.time, "sleep"):
        resp = _provider().make_request("eth_getCode", ["0xabc", "latest"])

    assert calls["n"] == 2 and resp["result"] == "0xabcd" and "error" not in resp


def test_make_web3_selects_native_then_proxy_then_raises(monkeypatch: pytest.MonkeyPatch) -> None:
    # Configured chain (chain 1 always has a public RPC) -> native HTTPProvider, no key needed.
    w3, label = epp.make_web3(1)
    assert label.startswith("http") and type(w3.provider).__name__ == "HTTPProvider"

    # Niche chain + key -> Etherscan proxy provider (NOT a wrong-chain native node).
    monkeypatch.setenv("ETHERSCAN_API_KEY", "DUMMY")
    w3b, labelb = epp.make_web3(80002)
    assert labelb == "etherscan-v2-proxy:80002" and type(w3b.provider).__name__ == "EtherscanProxyProvider"

    # An explicit rpc_url always wins (even for a niche chain).
    w3c, labelc = epp.make_web3(80002, "https://custom.example/rpc")
    assert labelc == "https://custom.example/rpc" and type(w3c.provider).__name__ == "HTTPProvider"

    # Niche chain + no key -> clear error (never a silent wrong-chain fallback).
    monkeypatch.delenv("ETHERSCAN_API_KEY", raising=False)
    with pytest.raises(RuntimeError):
        epp.make_web3(80002)


def test_proxy_jsonrpc_error_passes_through_as_error() -> None:
    # A genuine EVM error (not a throttle) must surface as an error, not be misread.
    def fake_get(url, params=None):
        return _Resp(body={"jsonrpc": "2.0", "id": 1, "error": {"code": -32000, "message": "execution reverted"}})

    with patch.object(epp._HTTP, "get", side_effect=fake_get), patch.object(epp.time, "sleep"):
        resp = _provider().make_request("eth_call", [{"to": "0x1", "data": "0x8da5cb5b"}, "latest"])

    assert "error" in resp
    assert rpc_rate_limit_reason(resp["error"]) is None  # a revert is NOT a throttle
