"""Tests for scryer_chain — the transaction / logs / fund-flow / deployer layer.

All offline: a fake async httpx client answers canned JSON-RPC, so nothing hits the network. The
async public coroutines are driven with ``asyncio.run`` (no pytest-asyncio dependency).
"""

from __future__ import annotations

import asyncio

import pytest

import scryer_chain as cm

URL = "https://bnb-mainnet.g.alchemy.com/v2/SECRETKEY123456"

PAIR = "0x" + "bb" * 20
TOKEN = "0x" + "aa" * 20
VICTIM = "0x" + "cc" * 20
CONTRACT = "0x" + "dd" * 20
EOA = "0x" + "ee" * 20


# --------------------------------------------------------------------------- #
# Fake JSON-RPC transport
# --------------------------------------------------------------------------- #
class FakeResp:
    def __init__(self, payload: dict, status_code: int = 200, headers: dict | None = None) -> None:
        self._payload = payload
        self.status_code = status_code
        self.headers = headers or {}

    def json(self) -> dict:
        return self._payload

    def raise_for_status(self) -> None:
        if self.status_code >= 400:
            raise RuntimeError(f"HTTP {self.status_code}")


class FakeClient:
    """Async-context fake httpx client; ``handler(request_dict) -> dict`` returns the JSON body."""

    def __init__(self, handler) -> None:
        self.handler = handler
        self.requests: list[dict] = []

    async def __aenter__(self) -> FakeClient:
        return self

    async def __aexit__(self, *exc) -> bool:
        return False

    async def post(self, url: str, json: dict | None = None) -> FakeResp:
        self.requests.append(json or {})
        body = self.handler(json or {})
        if isinstance(body, FakeResp):
            return body
        return FakeResp(body)


def _ok(req: dict, result) -> dict:
    return {"jsonrpc": "2.0", "id": req.get("id", 1), "result": result}


def _err(req: dict, message: str, code: int = -32000) -> dict:
    return {"jsonrpc": "2.0", "id": req.get("id", 1), "error": {"code": code, "message": message}}


def _patch(monkeypatch, handler, url: str = URL) -> FakeClient:
    client = FakeClient(handler)
    monkeypatch.setattr(cm, "async_client", lambda **k: client)
    monkeypatch.setattr(cm.scryer_config, "get_rpc_url", lambda cid: url)
    return client


def _log(block: int, idx: int, tx: str, topics=None, data: str = "0x", address: str = "0xpair") -> dict:
    return {
        "address": address,
        "topics": topics or [],
        "data": data,
        "blockNumber": hex(block),
        "logIndex": hex(idx),
        "transactionHash": tx,
    }


# --------------------------------------------------------------------------- #
# get_logs — auto-chunking
# --------------------------------------------------------------------------- #
def test_get_logs_chunks_and_merges_large_range(monkeypatch) -> None:
    """A range wider than one chunk is split into windows, fetched, and merged — no manual paging."""

    def handler(req: dict) -> dict:
        m = req["method"]
        if m == "eth_blockNumber":
            return _ok(req, "0x18")  # 24
        if m == "eth_getLogs":
            f = req["params"][0]
            a = int(f["fromBlock"], 16)
            return _ok(req, [_log(a, 0, f"0x{a:064x}", topics=[cm.SYNC_TOPIC])])
        raise AssertionError(m)

    _patch(monkeypatch, handler)
    out = asyncio.run(cm.get_logs(56, PAIR, topics=[cm.SYNC_TOPIC], from_block=0, to_block=24, chunk=10))
    assert out["windows"] == 3  # 0-9, 10-19, 20-24
    assert out["count"] == 3
    assert "partial" not in out and "errors" not in out
    assert out["from_block"] == 0 and out["to_block"] == 24
    # key assertion: output carries NO raw key
    assert out["rpc_url"] == "https://bnb-mainnet.g.alchemy.com"
    assert "SECRETKEY" not in str(out)


def test_get_logs_halves_on_provider_range_error(monkeypatch) -> None:
    """A window that trips a provider range/size error is halved and retried down to success."""

    def handler(req: dict) -> dict:
        if req["method"] == "eth_blockNumber":
            return _ok(req, "0x9")
        if req["method"] == "eth_getLogs":
            f = req["params"][0]
            a, b = int(f["fromBlock"], 16), int(f["toBlock"], 16)
            if (b - a + 1) > 5:  # provider refuses a span > 5
                return _err(req, "Log response size exceeded. this block range should work")
            return _ok(req, [_log(a, 0, f"0x{a:064x}", topics=[cm.SYNC_TOPIC])])
        raise AssertionError(req["method"])

    _patch(monkeypatch, handler)
    out = asyncio.run(cm.get_logs(56, PAIR, from_block=0, to_block=9, chunk=10))
    # one window (0-9, span 10) errored -> halved into (0-4) and (5-9), both OK
    assert out["count"] == 2
    assert "errors" not in out and "partial" not in out


def test_get_logs_reports_partial_on_persistent_error(monkeypatch) -> None:
    def handler(req: dict) -> dict:
        if req["method"] == "eth_blockNumber":
            return _ok(req, "0x0")
        if req["method"] == "eth_getLogs":
            return _err(req, "boom non-range error")  # not a range error -> cannot recover
        raise AssertionError(req["method"])

    _patch(monkeypatch, handler)
    out = asyncio.run(cm.get_logs(56, PAIR, from_block=0, to_block=0, chunk=10))
    assert out["partial"] is True
    assert out["errors"] and "boom" in out["errors"][0]["error"]


def test_get_logs_requires_native_rpc(monkeypatch) -> None:
    _patch(monkeypatch, lambda req: _ok(req, None), url="")  # no native RPC
    out = asyncio.run(cm.get_logs(56, PAIR, from_block=0, to_block=5))
    assert "error" in out and "no native RPC" in out["error"]


# --------------------------------------------------------------------------- #
# get_tx — decode + net flows
# --------------------------------------------------------------------------- #
def test_get_tx_decodes_transfer_swap_sync_net_flows(monkeypatch) -> None:
    a1 = "0x" + "00" * 12 + "11" * 20
    a2 = "0x" + "00" * 12 + "22" * 20
    token = TOKEN
    pair = PAIR
    transfer = _log(
        100, 0, "0xtx", topics=[cm.TRANSFER_TOPIC, a1, a2], data="0x" + (1000).to_bytes(32, "big").hex(), address=token
    )
    swap = _log(
        100,
        1,
        "0xtx",
        topics=[cm.SWAP_TOPIC, a1, a2],
        data="0x" + b"".join(x.to_bytes(32, "big") for x in (0, 5, 7, 0)).hex(),
        address=pair,
    )
    sync = _log(
        100,
        2,
        "0xtx",
        topics=[cm.SYNC_TOPIC],
        data="0x" + b"".join(x.to_bytes(32, "big") for x in (500, 700)).hex(),
        address=pair,
    )

    def handler(req: dict) -> dict:
        m = req["method"]
        if m == "eth_getTransactionByHash":
            return _ok(
                req,
                {
                    "from": "0xfromaddr",
                    "to": "0xtoaddr",
                    "input": "0x7ff36ab5deadbeef",
                    "value": "0x0",
                    "blockNumber": "0x64",
                },
            )
        if m == "eth_getTransactionReceipt":
            return _ok(
                req,
                {
                    "status": "0x1",
                    "gasUsed": "0x5208",
                    "effectiveGasPrice": "0x3b9aca00",
                    "logs": [transfer, swap, sync],
                },
            )
        raise AssertionError(m)

    _patch(monkeypatch, handler)
    out = asyncio.run(cm.get_tx(56, "0xtx"))
    assert out["status"] == 1 and out["gas_used"] == 21000
    assert out["selector"] == "0x7ff36ab5"
    assert out["event_count"] == 3
    types = [e["type"] for e in out["events"]]
    assert types == ["Transfer", "Swap", "Sync"]
    nf = out["net_flows"][token]
    assert nf["0x" + "11" * 20] == -1000 and nf["0x" + "22" * 20] == 1000  # decoded 20-byte addrs
    assert "SECRETKEY" not in str(out)


def test_get_tx_not_found(monkeypatch) -> None:
    _patch(monkeypatch, lambda req: _ok(req, None))
    out = asyncio.run(cm.get_tx(56, "0xmissing"))
    assert out["error"] == "transaction not found"


# --------------------------------------------------------------------------- #
# asset_transfers — pageKey pagination
# --------------------------------------------------------------------------- #
def test_asset_transfers_paginates_pagekey(monkeypatch) -> None:
    def handler(req: dict) -> dict:
        assert req["method"] == "alchemy_getAssetTransfers"
        p = req["params"][0]
        if "pageKey" not in p:
            return _ok(
                req,
                {
                    "transfers": [{"from": "0xfunder1", "value": 1.5, "asset": "BNB", "blockNum": "0xa"}],
                    "pageKey": "KEY2",
                },
            )
        return _ok(
            req,
            {
                "transfers": [
                    {"from": "0xfunder1", "value": 2.0, "asset": "BNB", "blockNum": "0x14"},
                    {"from": "0xfunder2", "value": 9.0, "asset": "USDT", "blockNum": "0x1e"},
                ]
            },
        )

    _patch(monkeypatch, handler)
    out = asyncio.run(cm.asset_transfers(56, VICTIM, direction="in"))
    assert out["count"] == 3  # 1 from page one + 2 from page two
    by_addr = {c["address"]: c for c in out["counterparties"]}
    assert by_addr["0xfunder1"]["count"] == 2 and by_addr["0xfunder1"]["value"] == 3.5
    assert out["earliest_block"] == 10  # 0xa
    assert "truncated" not in out


def test_asset_transfers_truncates_at_max_pages(monkeypatch) -> None:
    def handler(req: dict) -> dict:
        return _ok(
            req,
            {"transfers": [{"from": "0xf", "value": 1.0, "asset": "BNB", "blockNum": "0x1"}], "pageKey": "always-more"},
        )

    _patch(monkeypatch, handler)
    out = asyncio.run(cm.asset_transfers(56, VICTIM, direction="in", max_pages=3))
    assert out["truncated"] is True and out["count"] == 3


# --------------------------------------------------------------------------- #
# deployer — eth_getCode binary search + mint-log reverse
# --------------------------------------------------------------------------- #
def test_deployer_binary_search_and_mint_reverse(monkeypatch) -> None:
    deploy_block = 42

    def handler(req: dict) -> dict:
        m = req["method"]
        if m == "eth_blockNumber":
            return _ok(req, "0x64")  # 100
        if m == "eth_getCode":
            blk = int(req["params"][1], 16)
            return _ok(req, "0x60806040" if blk >= deploy_block else "0x")
        if m == "eth_getLogs":
            f = req["params"][0]
            assert int(f["fromBlock"], 16) == deploy_block  # reversed from the deploy block
            return _ok(
                req,
                [
                    _log(
                        deploy_block,
                        0,
                        "0xcreatetx",
                        topics=[cm.TRANSFER_TOPIC, cm.ZERO_TOPIC, "0x" + "00" * 12 + "11" * 20],
                    )
                ],
            )
        if m == "eth_getTransactionByHash":
            assert req["params"][0] == "0xcreatetx"
            return _ok(req, {"from": "0xdeployereoa", "to": None})
        raise AssertionError(m)

    _patch(monkeypatch, handler)
    out = asyncio.run(cm.deployer(56, CONTRACT))
    assert out["deploy_block"] == deploy_block
    assert out["deployer"] == "0xdeployereoa"
    assert out["creation_tx"] == "0xcreatetx"
    assert out["via"] == "direct_create" and out["factory"] is None


def test_deployer_factory_made(monkeypatch) -> None:
    def handler(req: dict) -> dict:
        m = req["method"]
        if m == "eth_blockNumber":
            return _ok(req, "0xa")
        if m == "eth_getCode":
            return _ok(req, "0x6080" if int(req["params"][1], 16) >= 3 else "0x")
        if m == "eth_getLogs":
            return _ok(
                req, [_log(3, 0, "0xctx", topics=[cm.TRANSFER_TOPIC, cm.ZERO_TOPIC, "0x" + "00" * 12 + "11" * 20])]
            )
        if m == "eth_getTransactionByHash":
            return _ok(req, {"from": "0xdeployer", "to": "0xfactory"})
        raise AssertionError(m)

    _patch(monkeypatch, handler)
    out = asyncio.run(cm.deployer(56, CONTRACT))
    assert out["via"] == "factory" and out["factory"] == "0xfactory"
    assert out["deployer"] == "0xdeployer"


def test_deployer_no_code_at_head(monkeypatch) -> None:
    def handler(req: dict) -> dict:
        if req["method"] == "eth_blockNumber":
            return _ok(req, "0x64")
        if req["method"] == "eth_getCode":
            return _ok(req, "0x")
        raise AssertionError(req["method"])

    _patch(monkeypatch, handler)
    out = asyncio.run(cm.deployer(56, EOA))
    assert "note" in out and "no code at head" in out["note"]


# --------------------------------------------------------------------------- #
# Rate-limit surfacing (never a silent empty)
# --------------------------------------------------------------------------- #
def test_get_tx_surfaces_rate_limit(monkeypatch) -> None:
    def handler(req: dict) -> FakeResp:
        return FakeResp({}, status_code=429, headers={"Retry-After": "7"})

    _patch(monkeypatch, handler)
    out = asyncio.run(cm.get_tx(56, "0xtx"))
    assert out["rate_limited"] is True and out.get("retry_after") == 7


# --------------------------------------------------------------------------- #
# redaction unit
# --------------------------------------------------------------------------- #
def test_redact_rpc_url_drops_key() -> None:
    from scryer_http import redact_rpc_url

    assert redact_rpc_url(URL) == "https://bnb-mainnet.g.alchemy.com"
    assert redact_rpc_url("https://h/rpc?apikey=ABC") == "https://h"
    assert redact_rpc_url("etherscan-v2-proxy:56") == "etherscan-v2-proxy:56"
    assert redact_rpc_url("") == ""
