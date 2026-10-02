"""P2b: rate-limit handling in the whale watcher's RPC choke point."""

from __future__ import annotations

import pytest

import scryer_whale_watcher as ww


class _Resp:
    def __init__(self, status_code: int = 200, body: dict | None = None, text: str = "", headers: dict | None = None):
        self.status_code = status_code
        self._body = body if body is not None else {}
        self.text = text
        self.headers = headers or {}

    def json(self):
        return self._body


class _Client:
    def __init__(self, resp: _Resp):
        self._resp = resp

    def post(self, url, json=None):
        return self._resp

    def close(self):
        pass


def test_rpcclient_http_429_raises_ratelimited() -> None:
    c = ww.RpcClient("http://rpc", client=_Client(_Resp(status_code=429, text="rate limited", headers={"Retry-After": "4"})))
    with pytest.raises(ww.RateLimitedRpcError) as ei:
        c.call("eth_blockNumber", [])
    assert ei.value.retry_after == 4
    assert isinstance(ei.value, ww.RpcError)  # subclass -> existing `except RpcError` still catches it


def test_rpcclient_jsonrpc_capacity_raises_ratelimited() -> None:
    body = {"jsonrpc": "2.0", "id": 1, "error": {"code": -32005, "message": "exceeded compute units per second capacity"}}
    c = ww.RpcClient("http://rpc", client=_Client(_Resp(body=body)))
    with pytest.raises(ww.RateLimitedRpcError):
        c.call("eth_getLogs", [{}])


def test_rpcclient_genuine_error_is_plain_rpcerror_not_throttle() -> None:
    body = {"jsonrpc": "2.0", "id": 1, "error": {"code": -32000, "message": "execution reverted"}}
    c = ww.RpcClient("http://rpc", client=_Client(_Resp(body=body)))
    with pytest.raises(ww.RpcError) as ei:
        c.call("eth_call", [{}])
    assert not isinstance(ei.value, ww.RateLimitedRpcError)  # a revert is not a throttle


def test_rpcclient_success_returns_result() -> None:
    c = ww.RpcClient("http://rpc", client=_Client(_Resp(body={"jsonrpc": "2.0", "id": 1, "result": "0x10"})))
    assert c.call("eth_blockNumber", []) == "0x10"
