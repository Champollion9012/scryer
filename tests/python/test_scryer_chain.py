"""Tests for scryer_chain — the transaction / logs / fund-flow / deployer layer.

All offline: a fake async httpx client answers canned JSON-RPC, so nothing hits the network. The
async public coroutines are driven with ``asyncio.run`` (no pytest-asyncio dependency).
"""

from __future__ import annotations

import asyncio
import json

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

    @property
    def text(self) -> str:
        return json.dumps(self._payload)

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
        self.urls: list[str] = []  # every url hit, in order (for rotation tests)

    async def __aenter__(self) -> FakeClient:
        return self

    async def __aexit__(self, *exc) -> bool:
        return False

    async def post(self, url: str, json: dict | None = None) -> FakeResp:
        self.requests.append(json or {})
        self.urls.append(url)
        try:
            body = self.handler(json or {}, url)  # url-aware handler (rotation tests)
        except TypeError:
            body = self.handler(json or {})  # back-compat 1-arg handler
        if isinstance(body, FakeResp):
            return body
        return FakeResp(body)


def _ok(req: dict, result) -> dict:
    return {"jsonrpc": "2.0", "id": req.get("id", 1), "result": result}


def _err(req: dict, message: str, code: int = -32000) -> dict:
    return {"jsonrpc": "2.0", "id": req.get("id", 1), "error": {"code": code, "message": message}}


def _patch(monkeypatch, handler, url: str = URL) -> FakeClient:
    cm._dead_urls.clear()
    cm._token_meta_cache.clear()
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


def test_deployer_logless_fallback_to_block_scan(monkeypatch) -> None:
    """A non-token contract emits NO log at deploy — fall back to scanning the block's CREATE txs."""
    deploy_block = 7

    def handler(req: dict) -> dict:
        m = req["method"]
        if m == "eth_blockNumber":
            return _ok(req, "0x14")  # 20
        if m == "eth_getCode":
            return _ok(req, "0x6080" if int(req["params"][1], 16) >= deploy_block else "0x")
        if m == "eth_getLogs":
            return _ok(req, [])  # no deploy-block log (not a token)
        if m == "eth_getBlockByNumber":
            assert int(req["params"][0], 16) == deploy_block and req["params"][1] is True
            return _ok(
                req,
                {
                    "transactions": [
                        {"hash": "0xcall", "to": "0xsomecontract"},  # a plain call (to != null) -> skipped
                        {"hash": "0xcreatetx", "to": None},  # a direct CREATE
                    ]
                },
            )
        if m == "eth_getTransactionReceipt":
            # only the CREATE tx's receipt carries contractAddress == the target
            return _ok(req, {"contractAddress": CONTRACT if req["params"][0] == "0xcreatetx" else None})
        if m == "eth_getTransactionByHash":
            assert req["params"][0] == "0xcreatetx"
            return _ok(req, {"from": "0xdeployereoa", "to": None})
        raise AssertionError(m)

    _patch(monkeypatch, handler)
    out = asyncio.run(cm.deployer(56, CONTRACT))
    assert out["deploy_block"] == deploy_block
    assert out["creation_tx"] == "0xcreatetx"
    assert out["deployer"] == "0xdeployereoa"
    assert out["via"] == "direct_create" and out["factory"] is None


def test_deployed_by_enumerates_creates(monkeypatch) -> None:
    """Enumerate an EOA's deployments by CREATE-address derivation + eth_getCode (no Etherscan)."""
    eoa = "0x" + "ab" * 20
    want = {cm._rlp_create_address(eoa, 0), cm._rlp_create_address(eoa, 2)}  # "deployed" at nonce 0 and 2

    def handler(req: dict) -> dict:
        m = req["method"]
        if m == "eth_getTransactionCount":
            return _ok(req, "0x5")  # nonce 5 -> scan nonces 0..4
        if m == "eth_getCode":
            return _ok(req, "0x6080" if req["params"][0] in want else "0x")  # params[0]=addr, [1]="latest"
        raise AssertionError(m)

    _patch(monkeypatch, handler)
    out = asyncio.run(cm.deployed_by(56, eoa))
    assert out["nonce"] == 5 and out["scanned_nonces"] == 5
    assert out["deployed_count"] == 2
    assert {d["nonce"] for d in out["deployed"]} == {0, 2}
    assert "truncated" not in out


def test_asset_transfers_caps_counterparties_top(monkeypatch) -> None:
    """A pool/hub with many counterparties is capped to top-N; the summary stays exact."""

    def handler(req: dict) -> dict:
        return _ok(
            req,
            {
                "transfers": [
                    {"from": f"0xf{i}", "value": float(i + 1), "asset": "USDT", "blockNum": hex(i + 1)}
                    for i in range(5)
                ]
            },
        )

    _patch(monkeypatch, handler)
    out = asyncio.run(cm.asset_transfers(56, VICTIM, direction="in", top=2))
    assert out["distinct_counterparties"] == 5  # true total (NOT the truncated list length)
    assert len(out["counterparties"]) == 2
    assert out["counterparties_omitted"] == 3


def test_get_tx_net_flows_only_drops_events(monkeypatch) -> None:
    """net_flows_only drops the raw event list but keeps net_flows + the true event_count."""
    tx = "0xabc"
    transfer_log = _log(
        10,
        0,
        tx,
        topics=[cm.TRANSFER_TOPIC, "0x" + "00" * 12 + "aa" * 20, "0x" + "00" * 12 + "bb" * 20],
        data="0x" + "00" * 31 + "64",
        address=TOKEN,  # value 100
    )

    def handler(req: dict) -> dict:
        m = req["method"]
        if m == "eth_getTransactionByHash":
            return _ok(
                req, {"from": "0xsender", "to": "0xtarget", "input": "0xdeadbeef", "value": "0x0", "blockNumber": "0xa"}
            )
        if m == "eth_getTransactionReceipt":
            return _ok(req, {"status": "0x1", "logs": [transfer_log], "gasUsed": "0x1"})
        return _ok(req, "0x")  # enrichment best-effort calls -> no-op

    _patch(monkeypatch, handler)
    out = asyncio.run(cm.get_tx(56, tx, net_flows_only=True))
    assert out["event_count"] == 1
    assert out["events"] == []
    assert out["events_omitted"] == 1
    assert out["net_flows"]  # net flows still computed from the full event list


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


# --------------------------------------------------------------------------- #
# call_view_many — batched eth_call across blocks / signatures
# --------------------------------------------------------------------------- #
def _enc_words(*vals: int) -> str:
    return "0x" + b"".join(v.to_bytes(32, "big") for v in vals).hex()


def test_call_view_many_across_blocks(monkeypatch) -> None:
    """One signature across many blocks runs concurrently and decodes each result."""
    reserves = {100: (10, 20), 200: (30, 40)}

    def handler(req: dict) -> dict:
        assert req["method"] == "eth_call"
        blk = int(req["params"][1], 16)
        r0, r1 = reserves[blk]
        return _ok(req, _enc_words(r0, r1, 1700000000))

    _patch(monkeypatch, handler)
    out = asyncio.run(cm.call_view_many(56, PAIR, "getReserves()", returns="uint112,uint112,uint32", blocks=[100, 200]))
    assert out["count"] == 2
    by_block = {r["block"]: r for r in out["results"]}
    assert by_block[100]["decoded"][:2] == [10, 20]
    assert by_block[200]["decoded"][:2] == [30, 40]
    assert "SECRETKEY" not in str(out)


def test_call_view_many_isolates_a_revert(monkeypatch) -> None:
    """A revert on one signature does not sink the others in the batch."""
    from web3 import Web3

    good = "0x" + bytes(Web3.keccak(text="totalSupply()"))[:4].hex()

    def handler(req: dict) -> dict:
        data = req["params"][0]["data"]
        if data.startswith(good):
            return _ok(req, _enc_words(12345))
        return _err(req, "execution reverted")

    _patch(monkeypatch, handler)
    out = asyncio.run(cm.call_view_many(56, TOKEN, ["totalSupply()", "missingFn()"], returns="uint256"))
    res = {r["signature"]: r for r in out["results"]}
    assert res["totalSupply()"]["decoded"] == [12345]
    assert "error" in res["missingFn()"] and "revert" in res["missingFn()"]["error"]


# --------------------------------------------------------------------------- #
# reserves_history — from Sync logs, and the sampled fallback
# --------------------------------------------------------------------------- #
def test_reserves_history_from_sync_logs(monkeypatch) -> None:
    def handler(req: dict) -> dict:
        if req["method"] == "eth_blockNumber":
            return _ok(req, "0x14")  # 20
        if req["method"] == "eth_getLogs":
            f = req["params"][0]
            a = int(f["fromBlock"], 16)
            # one Sync per window, reserves growing with block
            return _ok(
                req,
                [_log(a, 0, f"0x{a:064x}", topics=[cm.SYNC_TOPIC], data=_enc_words(1000 + a, 2000 + a), address=PAIR)],
            )
        raise AssertionError(req["method"])

    _patch(monkeypatch, handler)
    out = asyncio.run(cm.reserves_history(56, PAIR, from_block=0, to_block=20, points=50))
    assert out["source"] == "sync_logs"
    assert out["points"] >= 2
    assert out["series"][0]["reserve0"] == 1000  # block 0 window


def test_reserves_history_falls_back_to_sampled_getreserves(monkeypatch) -> None:
    def handler(req: dict) -> dict:
        if req["method"] == "eth_blockNumber":
            return _ok(req, "0x64")  # 100
        if req["method"] == "eth_getLogs":
            return _ok(req, [])  # no Sync logs -> force fallback
        if req["method"] == "eth_call":
            blk = int(req["params"][1], 16)
            return _ok(req, _enc_words(blk, blk * 2, 0))
        raise AssertionError(req["method"])

    _patch(monkeypatch, handler)
    out = asyncio.run(cm.reserves_history(56, PAIR, from_block=0, to_block=100, points=5))
    assert out["source"] == "sampled_getReserves"
    assert out["points"] == 5
    assert out["series"][-1]["reserve0"] == 100  # last sampled block


# --------------------------------------------------------------------------- #
# block head
# --------------------------------------------------------------------------- #
def test_block_number(monkeypatch) -> None:
    _patch(monkeypatch, lambda req: _ok(req, "0x2a"))
    out = asyncio.run(cm.block_number(56))
    assert out["block_number"] == 42
    assert out["rpc_url"] == "https://bnb-mainnet.g.alchemy.com"


def test_block_at_binary_search(monkeypatch) -> None:
    head = 100

    def handler(req: dict) -> dict:
        if req["method"] == "eth_blockNumber":
            return _ok(req, hex(head))
        if req["method"] == "eth_getBlockByNumber":
            b = int(req["params"][0], 16)
            return _ok(req, {"timestamp": hex(b * 10)})  # ts = block*10, monotonic
        raise AssertionError(req["method"])

    _patch(monkeypatch, handler)
    out = asyncio.run(cm.block_at(56, 355))
    assert out["block_number"] == 35 and out["block_timestamp"] == 350  # latest block with ts<=355


def test_chain_heads_best_effort(monkeypatch) -> None:
    # chain 1 configured+ok, chain 999 has no RPC -> None
    def handler(req: dict) -> dict:
        return _ok(req, "0x7b")  # 123

    monkeypatch.setattr(cm, "async_client", lambda **k: FakeClient(handler))
    monkeypatch.setattr(cm.scryer_config, "get_rpc_url", lambda cid: URL if cid == 1 else "")
    heads = asyncio.run(cm.chain_heads([1, 999]))
    assert heads[1] == 123 and heads[999] is None


# --------------------------------------------------------------------------- #
# Key-pool round-robin + throttle fallback (ALCHEMY_KEY + ALCHEMY_KEY_2)
# --------------------------------------------------------------------------- #
POOL = ["https://keyA.example/v2/AAA", "https://keyB.example/v2/BBB"]


def _patch_pool(monkeypatch, handler):
    cm._dead_urls.clear()
    cm._token_meta_cache.clear()
    client = FakeClient(handler)
    monkeypatch.setattr(cm, "async_client", lambda **k: client)
    monkeypatch.setattr(cm.scryer_config, "get_rpc_url", lambda cid: POOL[0])
    monkeypatch.setattr(cm.scryer_config, "get_rpc_urls", lambda cid: POOL)
    return client


def test_key_pool_round_robin_spreads_windows(monkeypatch) -> None:
    """Concurrent get_logs windows spread across the key pool (round-robin), not all on one key."""

    def handler(req, url):
        if req["method"] == "eth_blockNumber":
            return _ok(req, "0x13")  # 19
        if req["method"] == "eth_getLogs":
            a = int(req["params"][0]["fromBlock"], 16)
            return _ok(req, [_log(a, 0, f"0x{a:064x}", topics=[cm.SYNC_TOPIC])])
        raise AssertionError(req["method"])

    client = _patch_pool(monkeypatch, handler)
    out = asyncio.run(cm.get_logs(56, PAIR, topics=[cm.SYNC_TOPIC], from_block=0, to_block=19, chunk=10))
    assert out["count"] == 2  # two windows
    log_urls = {u for u, r in zip(client.urls, client.requests, strict=True) if r["method"] == "eth_getLogs"}
    assert log_urls == set(POOL)  # both keys were used


def test_throttle_falls_back_to_other_key(monkeypatch) -> None:
    """A 429 on one key does NOT fail the call — it falls back to the other key and succeeds."""

    def handler(req, url):
        if "keyA" in url:
            return FakeResp({}, status_code=429, headers={"Retry-After": "2"})  # keyA always throttles
        if req["method"] == "eth_getTransactionByHash":
            return _ok(req, {"from": "0xf", "to": None, "input": "0x", "value": "0x0", "blockNumber": "0x1"})
        if req["method"] == "eth_getTransactionReceipt":
            return _ok(req, {"status": "0x1", "gasUsed": "0x1", "logs": []})
        return _ok(req, "0x1")

    client = _patch_pool(monkeypatch, handler)
    out = asyncio.run(cm.get_tx(56, "0xabc"))
    assert out.get("status") == 1 and "rate_limited" not in out  # succeeded via keyB
    assert any("keyA" in u for u in client.urls) and any("keyB" in u for u in client.urls)  # both tried


def test_all_keys_throttled_surfaces_rate_limited(monkeypatch) -> None:
    """When EVERY key in the pool throttles, the throttle is surfaced (not a silent success)."""

    def handler(req, url):
        return FakeResp({}, status_code=429, headers={"Retry-After": "5"})

    _patch_pool(monkeypatch, handler)
    out = asyncio.run(cm.get_tx(56, "0xabc"))
    assert out["rate_limited"] is True and out.get("retry_after") == 5


def test_auth_error_drops_key_and_falls_back(monkeypatch) -> None:
    """A 401/403 (bad key / chain-not-enabled) on one endpoint drops it and falls back — a
    misconfigured key must never break a call another key can serve (the ALCHEMY_KEY_2 case)."""

    def handler(req, url):
        if "keyA" in url:
            return FakeResp({"error": {"code": -32600, "message": "BNB_MAINNET is not enabled"}}, status_code=403)
        if req["method"] == "eth_getTransactionByHash":
            return _ok(req, {"from": "0xf", "to": None, "input": "0x", "value": "0x0", "blockNumber": "0x1"})
        if req["method"] == "eth_getTransactionReceipt":
            return _ok(req, {"status": "0x1", "gasUsed": "0x1", "logs": []})
        return _ok(req, "0x1")

    _patch_pool(monkeypatch, handler)
    out = asyncio.run(cm.get_tx(56, "0xabc"))
    assert out.get("status") == 1 and "error" not in out  # succeeded via keyB
    assert any("keyA" in u for u in cm._dead_urls)  # keyA dropped from rotation
    cm._dead_urls.clear()


# --------------------------------------------------------------------------- #
# Follow-up pass: entity labels, human amounts, victim/beneficiary, reserves extras
# --------------------------------------------------------------------------- #
FIXEDFLOAT = "0x4727250679294802377dd6ca6541b8e459077c95"


def abi_encode_str(s: str) -> str:
    from eth_abi import encode as _enc

    return _enc(["string"], [s]).hex()


def test_labels_known_and_unknown() -> None:
    import scryer_labels

    assert scryer_labels.label_for(FIXEDFLOAT)["category"] == "cex-no-kyc"
    assert scryer_labels.label_for(FIXEDFLOAT.upper())["name"] == "FixedFloat"  # case-insensitive
    assert scryer_labels.label_for("0x" + "ab" * 20) is None
    assert scryer_labels.label_for(None) is None


def test_get_tx_enrichment_human_victim_beneficiary_labels(monkeypatch) -> None:
    tok = "0x" + "aa" * 20
    victim = "0x" + "11" * 20
    ff = FIXEDFLOAT  # a labeled beneficiary
    transfer = _log(
        100,
        0,
        "0xtx",
        topics=[cm.TRANSFER_TOPIC, "0x" + "00" * 12 + victim[2:], "0x" + "00" * 12 + ff[2:]],
        data="0x" + (5 * 10**18).to_bytes(32, "big").hex(),
        address=tok,
    )

    def handler(req, url):
        m = req["method"]
        if m == "eth_getTransactionByHash":
            return _ok(req, {"from": victim, "to": ff, "input": "0xdeadbeef", "value": "0x0", "blockNumber": "0x64"})
        if m == "eth_getTransactionReceipt":
            return _ok(req, {"status": "0x1", "gasUsed": "0x1", "logs": [transfer]})
        if m == "eth_call":
            data = req["params"][0]["data"]
            if data == cm._SYM_SEL:  # symbol() -> "AAA"
                return _ok(req, "0x" + abi_encode_str("AAA"))
            if data == cm._DEC_SEL:  # decimals() -> 18
                return _ok(req, "0x" + (18).to_bytes(32, "big").hex())
        raise AssertionError(m)

    _patch(monkeypatch, handler)
    out = asyncio.run(cm.get_tx(56, "0xtx"))
    assert out["token_meta"][tok]["symbol"] == "AAA" and out["token_meta"][tok]["decimals"] == 18
    assert out["net_flows_human"][tok][ff] == 5.0 and out["net_flows_human"][tok][victim] == -5.0
    fs = out["flow_summary"][0]
    assert fs["beneficiary"]["address"] == ff and fs["beneficiary"]["amount"] == 5.0
    assert fs["beneficiary"]["label"]["name"] == "FixedFloat"
    assert fs["victim"]["address"] == victim and fs["victim"]["amount"] == -5.0
    assert out["labels"][ff]["category"] == "cex-no-kyc"


def test_asset_transfers_labels_first_funder_distinct(monkeypatch) -> None:
    def handler(req, url):
        assert req["method"] == "alchemy_getAssetTransfers"
        return _ok(
            req,
            {
                "transfers": [
                    {"from": FIXEDFLOAT, "value": 5.0, "asset": "BNB", "blockNum": "0x5"},
                    {"from": "0x" + "cc" * 20, "value": 1.0, "asset": "BNB", "blockNum": "0x9"},
                ]
            },
        )

    _patch(monkeypatch, handler)
    out = asyncio.run(cm.asset_transfers(56, VICTIM, direction="in"))
    assert out["distinct_counterparties"] == 2
    assert out["first_funder"]["address"] == FIXEDFLOAT and out["first_funder"]["block"] == 5
    by = {c["address"]: c for c in out["counterparties"]}
    assert by[FIXEDFLOAT]["label"]["name"] == "FixedFloat"
    assert "likely_service_hub" not in out  # only 2 counterparties


def test_asset_transfers_hub_flag(monkeypatch) -> None:
    many = [{"from": "0x" + f"{i:040x}", "value": 1.0, "asset": "BNB", "blockNum": hex(i + 1)} for i in range(45)]

    def handler(req, url):
        return _ok(req, {"transfers": many})

    _patch(monkeypatch, handler)
    out = asyncio.run(cm.asset_transfers(56, VICTIM, direction="in"))
    assert out["distinct_counterparties"] == 45 and out["likely_service_hub"] is True


def test_max_single_step_drop() -> None:
    series = [
        {"block": 1, "reserve0": 100, "reserve1": 1000},
        {"block": 2, "reserve0": 100, "reserve1": 1000},
        {"block": 3, "reserve0": 100, "reserve1": 10},
    ]  # reserve1 collapses 1000->10 at block 3
    md = cm._max_single_step_drop(series)
    assert md["reserve"] == "reserve1" and md["from_block"] == 2 and md["to_block"] == 3 and md["drop_pct"] == 0.99
    assert cm._max_single_step_drop([{"block": 1, "reserve0": 1, "reserve1": 1}]) is None  # single point


def test_reserves_history_large_range_samples(monkeypatch) -> None:
    def handler(req, url):
        if req["method"] == "eth_call":
            blk = int(req["params"][1], 16)
            r1 = 1000 if blk < 5000 else 10  # drain at 5000
            return _ok(req, _enc_words(100, r1, 0))
        raise AssertionError(req["method"])  # must NOT call eth_getLogs for a large range

    _patch(monkeypatch, handler)
    out = asyncio.run(cm.reserves_history(56, PAIR, from_block=0, to_block=10000, points=5))
    assert out["source"] == "sampled_getReserves" and "note" in out
    assert out["max_drop"]["reserve"] == "reserve1" and out["max_drop"]["to"] == 10


def test_dead_key_ttl_controls_reinclusion(monkeypatch) -> None:
    """A dropped endpoint is excluded only within the cooldown, then retried — so a since-fixed key
    (e.g. ALCHEMY_KEY_2 after BNB is enabled) self-recovers without a process restart."""
    cm._dead_urls.clear()
    cm._dead_urls["https://keyA.example/v2/AAA"] = cm.time.monotonic()
    monkeypatch.setattr(cm, "_dead_ttl", lambda: 600.0)
    assert cm._is_dead("https://keyA.example/v2/AAA") is True  # within cooldown -> excluded
    monkeypatch.setattr(cm, "_dead_ttl", lambda: 0.0)
    assert cm._is_dead("https://keyA.example/v2/AAA") is False  # cooldown elapsed -> retried
    cm._dead_urls.clear()


def test_asset_transfers_both_first_funder_ignores_earlier_outgoing(monkeypatch) -> None:
    # direction="both": an earlier OUTGOING transfer's recipient must not be reported as the funder.
    def handler(req: dict) -> dict:
        p = req["params"][0]
        if "toAddress" in p:  # inbound
            return _ok(req, {"transfers": [{"from": "0xfunder", "value": 9.0, "asset": "USDT", "blockNum": "0x9"}]})
        return _ok(req, {"transfers": [{"to": "0xrecipient", "value": 3.0, "asset": "USDT", "blockNum": "0x5"}]})

    _patch(monkeypatch, handler)
    out = asyncio.run(cm.asset_transfers(56, VICTIM, direction="both"))
    assert out["first_funder"]["address"] == "0xfunder" and out["first_funder"]["block"] == 9
    assert out["earliest_block"] == 5  # earliest activity is still reported separately
