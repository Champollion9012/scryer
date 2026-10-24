"""Tests for Tron support — base58 <-> hex addresses, T… result rendering, chain routing, the Tron
getLogs window, the TRC20-log fallback for asset_transfers, and TRX/base58 handling in
token_exposure.

All offline: a fake async client answers canned JSON-RPC and web3 is stubbed.
"""

from __future__ import annotations

import asyncio

import pytest

import onchain_state as oc
import scryer_chain as cm
import scryer_config
import scryer_tron as tr

TRON = tr.TRON_CHAIN_ID
TRONGRID = "https://api.trongrid.io/jsonrpc"
USDT_T = "TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t"  # Tron USDT (public token contract)
USDT_HEX = "0xa614f803b6fd780986a42c78ec9c7f77e6ded13c"
USDC_T = "TEkxiTehnzSmSe2XqrBj4w32RUN966rdz8"  # Tron USDC (public token contract)
USDC_HEX = "0x3487b63d30b5b2c87fb7ffa8bcfade38eaac1abe"
WALLET_HEX = "0x" + "11" * 20  # synthetic accounts; base58 forms computed independently
WALLET_T = "TBXSw8fM4jpQkGc6zZjsVABFpVN7UvXPdV"
PEER_HEX = "0x" + "22" * 20
PEER_T = "TD5gsCwxykWsLN9aPrq2TAfNjByuZKYp4E"
FAKE_USDT_HEX = "0x" + "ab" * 20  # a look-alike token that also answers symbol() == "USDT"
TX_HASH = "0x" + "12" * 32


# --------------------------------------------------------------------------- #
# Address format
# --------------------------------------------------------------------------- #
def test_base58_hex_roundtrip() -> None:
    assert tr.to_hex(USDT_T) == USDT_HEX
    assert tr.to_base58(USDT_HEX) == USDT_T
    assert tr.to_hex(USDC_T) == USDC_HEX and tr.to_base58(USDC_HEX) == USDC_T
    assert tr.to_hex(WALLET_T) == WALLET_HEX
    assert tr.to_base58(PEER_HEX) == PEER_T
    assert tr.to_base58("0x" + "0" * 40) == "T9yD14Nj9j7xAB4dbGeiX9h8unkKHxuWwb"  # Tron zero address


def test_to_hex_rejects_bad_checksum_and_garbage() -> None:
    bad = USDT_T[:-1] + ("u" if USDT_T[-1] != "u" else "v")
    with pytest.raises(ValueError):
        tr.to_hex(bad)
    with pytest.raises(ValueError):
        tr.to_hex("not-an-address")
    assert tr.to_hex(USDT_HEX.upper().replace("0X", "0x")) == USDT_HEX  # hex passes through, lowercased


def test_normalize_only_touches_tron_addresses() -> None:
    assert tr.normalize_address(WALLET_T) == WALLET_HEX
    for untouched in (WALLET_HEX, TX_HASH, "", 42, None, "latest", WALLET_T + "\n"):
        assert tr.normalize_address(untouched) == untouched  # a trailing newline is not an address


def test_typed_conversion_only_at_address_positions() -> None:
    assert tr.normalize_typed("address", WALLET_T) == WALLET_HEX
    assert tr.normalize_typed("address[]", [WALLET_T, PEER_HEX]) == [WALLET_HEX, PEER_HEX]
    assert tr.normalize_typed("string", WALLET_T) == WALLET_T  # a string arg that looks like T… stays text
    assert tr.render_typed("address", WALLET_HEX) == WALLET_T
    assert tr.render_typed("bytes20", WALLET_HEX) == WALLET_HEX  # bytes20 is not an address
    assert tr.render_typed("address[2]", [WALLET_HEX, PEER_HEX]) == [WALLET_T, PEER_T]


def test_tronify_renders_keys_and_values_but_not_hashes() -> None:
    topic = "0x" + "0" * 24 + WALLET_HEX[2:]
    out = tr.tronify(
        {
            "net_flows": {USDT_HEX: {WALLET_HEX: -5, PEER_HEX: 5}},
            "tx_hash": TX_HASH,
            "topics": [topic],
            "selector": "0xa9059cbb",
            "list": [(WALLET_HEX, 1)],
        }
    )
    assert out["net_flows"] == {USDT_T: {WALLET_T: -5, PEER_T: 5}}
    assert out["tx_hash"] == TX_HASH and out["topics"] == [topic] and out["selector"] == "0xa9059cbb"
    assert out["list"] == [(WALLET_T, 1)]


# --------------------------------------------------------------------------- #
# Chain routing
# --------------------------------------------------------------------------- #
def test_tron_rpc_resolution(monkeypatch) -> None:
    monkeypatch.delenv("TRON_URL", raising=False)
    monkeypatch.delenv("TRON_RPC_URL", raising=False)
    assert scryer_config.get_rpc_urls(TRON)[-1] == TRONGRID  # public default always appended
    monkeypatch.setenv("TRON_URL", "https://tron.example.invalid/jsonrpc")
    assert scryer_config.get_rpc_url(TRON) == "https://tron.example.invalid/jsonrpc"


def test_mcp_tron_alias_and_rendering() -> None:
    import scryer_mcp as m

    assert m._resolve_chain("tron") == TRON and m._resolve_chain("TRX") == TRON
    tron_row = next(c for c in m._supported_chains() if c["chain_id"] == TRON)
    assert tron_row["name"] == "Tron" and tron_row["native"] == "TRX" and "tron" in tron_row["aliases"]
    assert m._tron_out(TRON, {"address": WALLET_HEX}) == {"address": WALLET_T}
    assert m._tron_out(56, {"address": WALLET_HEX}) == {"address": WALLET_HEX}  # EVM chains untouched


def test_mcp_refuses_a_tron_address_on_an_evm_chain() -> None:
    # Its 20 bytes would silently resolve to an unrelated EVM account (default chain is BSC).
    import scryer_mcp as m

    assert m._addr(TRON, WALLET_T) == WALLET_HEX
    assert m._addr(56, WALLET_HEX) == WALLET_HEX and m._addr(56, "") == ""
    with pytest.raises(ValueError, match="pass chain='tron'"):
        m._addr(56, WALLET_T)
    out = m.get_state(WALLET_T)  # no chain -> BSC -> refused, not a confident wrong answer
    assert "pass chain='tron'" in out["error"]


def test_mcp_call_args_and_decoded_are_type_aware() -> None:
    import scryer_mcp as m

    assert m._call_args(TRON, "f(address,string)", [WALLET_T, WALLET_T]) == [WALLET_HEX, WALLET_T]
    assert m._call_args(56, "f(address)", [WALLET_HEX]) == [WALLET_HEX]  # EVM unchanged
    res = {"address": USDT_HEX, "raw": "0x" + "00" * 32, "decoded": [WALLET_HEX, WALLET_HEX]}
    out = m._tron_call_out(TRON, res, "address,bytes20")
    assert out["address"] == USDT_T and out["decoded"] == [WALLET_T, WALLET_HEX]
    many = {"results": [{"signature": "f()", "decoded": [PEER_HEX]}]}
    assert m._tron_call_out(TRON, many, "address")["results"][0]["decoded"] == [PEER_T]
    assert m._tron_call_out(56, res, "address,bytes20") is res


def test_logs_chunk_defaults(monkeypatch) -> None:
    monkeypatch.delenv("SCRYER_LOGS_CHUNK", raising=False)
    assert cm._logs_chunk(TRON) == 4800  # TronGrid serves up to 5000 blocks per eth_getLogs
    assert cm._logs_chunk(56) == 10 and cm._logs_chunk() == 10  # Alchemy free-tier default unchanged
    monkeypatch.setenv("SCRYER_LOGS_CHUNK", "50")
    assert cm._logs_chunk(TRON) == 50 and cm._logs_chunk(1) == 50  # explicit override wins everywhere


# --------------------------------------------------------------------------- #
# asset_transfers on Tron — rebuilt from TRC20 Transfer logs
# --------------------------------------------------------------------------- #
class _Resp:
    status_code = 200
    headers: dict = {}

    def __init__(self, payload: dict) -> None:
        self._payload = payload
        self.text = ""

    def json(self) -> dict:
        return self._payload

    def raise_for_status(self) -> None:
        return None


class _Client:
    def __init__(self, handler) -> None:
        self.handler = handler
        self.requests: list[dict] = []

    async def __aenter__(self) -> _Client:
        return self

    async def __aexit__(self, *exc) -> bool:
        return False

    async def post(self, url: str, json: dict | None = None) -> _Resp:
        self.requests.append(json or {})
        body = self.handler(json or {})
        if isinstance(body, _Resp):  # a canned HTTP status / JSON-RPC error
            return body
        return _Resp({"jsonrpc": "2.0", "id": (json or {}).get("id", 1), "result": body})


def _http(status: int) -> _Resp:
    r = _Resp({})
    r.status_code = status
    return r


def _rpc_error(code: int, message: str) -> _Resp:
    return _Resp({"jsonrpc": "2.0", "id": 1, "error": {"code": code, "message": message}})


def _word(n: int) -> str:
    return "0x" + hex(n)[2:].rjust(64, "0")


def _topic(addr_hex: str) -> str:
    return "0x" + "0" * 24 + addr_hex[2:]


def _abi_string(s: str) -> str:
    b = s.encode()
    return "0x" + hex(32)[2:].rjust(64, "0") + hex(len(b))[2:].rjust(64, "0") + b.hex().ljust(64, "0")


HEAD = 1_000_000
LOG_BLOCK = 999_000


def _tron_handler(req: dict):
    method, params = req["method"], req.get("params") or []
    if method == "eth_blockNumber":
        return hex(HEAD)
    if method == "eth_call":
        data = params[0]["data"]
        if data.startswith("0x95d89b41"):  # symbol()
            return _abi_string("USDT")  # both the real and the look-alike token say "USDT"
        return _word(6)  # decimals()
    if method == "eth_getLogs":
        flt = params[0]
        assert "address" not in flt  # topic-only scan across every TRC20 contract
        lo, hi = int(flt["fromBlock"], 16), int(flt["toBlock"], 16)
        assert hi - lo + 1 <= 4800
        if not lo <= LOG_BLOCK <= hi:
            return []
        t = flt["topics"]

        def log(token: str, frm: str, to: str, amount: int, idx: int, extra_topic: bool = False) -> dict:
            topics = [cm.TRANSFER_TOPIC, _topic(frm), _topic(to)] + ([_word(1)] if extra_topic else [])
            return {
                "address": token,
                "topics": topics,
                "data": "0x" if extra_topic else _word(amount),
                "blockNumber": hex(LOG_BLOCK),
                "logIndex": hex(idx),
                "transactionHash": "0x" + f"{idx:02x}" * 32,
            }

        if len(t) == 3 and t[2] == _topic(WALLET_HEX):  # incoming
            return [
                log(USDT_HEX, PEER_HEX, WALLET_HEX, 100 * 10**6, 1),
                log(FAKE_USDT_HEX, PEER_HEX, WALLET_HEX, 0, 2),  # zero-value poisoning spam -> dropped
                log(USDT_HEX, PEER_HEX, WALLET_HEX, 7, 3, extra_topic=True),  # ERC721-style -> dropped
            ]
        if t[1] == _topic(WALLET_HEX):  # outgoing
            return [
                log(USDT_HEX, WALLET_HEX, PEER_HEX, 40 * 10**6, 4),
                log(FAKE_USDT_HEX, WALLET_HEX, PEER_HEX, 5 * 10**6, 5),
            ]
        return []
    raise AssertionError(f"unexpected method {method}")


def _patch_tron(monkeypatch) -> _Client:
    cm._dead_urls.clear()
    cm._token_meta_cache.clear()
    client = _Client(_tron_handler)
    monkeypatch.setattr(cm, "async_client", lambda **k: client)
    monkeypatch.setattr(cm.scryer_config, "get_rpc_url", lambda cid: TRONGRID)
    monkeypatch.setattr(cm.scryer_config, "get_rpc_urls", lambda cid: [TRONGRID])
    monkeypatch.delenv("SCRYER_LOGS_CHUNK", raising=False)
    monkeypatch.delenv("SCRYER_TRON_DEFAULT_BLOCKS", raising=False)
    return client


def test_tron_asset_transfers_from_trc20_logs(monkeypatch) -> None:
    client = _patch_tron(monkeypatch)
    out = asyncio.run(cm.asset_transfers(TRON, WALLET_T, direction="both"))  # T… accepted directly
    assert out["source"] == "trc20_transfer_logs" and out["category"] == ["trc20"]
    assert out["range_capped"] is True and out["from_block"] == HEAD - 201_600 + 1 and out["to_block"] == HEAD
    assert out["count"] == 3  # zero-value spam and the 4-topic log are dropped
    peer = {c["address"]: c for c in out["counterparties"]}[PEER_HEX]
    fake_name = f"USDT@{tr.to_base58(FAKE_USDT_HEX)}"
    assert peer["count"] == 3
    assert peer["by_asset"] == {"USDT": 140.0, fake_name: 5.0}  # look-alike kept apart from real USDT
    assert out["first_funder"]["address"] == PEER_HEX
    assert not any(r["method"] == "alchemy_getAssetTransfers" for r in client.requests)


@pytest.mark.parametrize("open_ended", [0, "0", "0x0", "earliest"])
def test_tron_asset_transfers_caps_every_open_ended_spelling(monkeypatch, open_ended) -> None:
    _patch_tron(monkeypatch)
    out = asyncio.run(cm.asset_transfers(TRON, WALLET_HEX, direction="in", from_block=open_ended))
    assert out["range_capped"] is True and out["from_block"] == HEAD - 201_600 + 1


def test_tron_asset_transfers_explicit_range_is_not_capped(monkeypatch) -> None:
    _patch_tron(monkeypatch)
    out = asyncio.run(cm.asset_transfers(TRON, WALLET_HEX, direction="in", from_block=LOG_BLOCK - 10))
    assert "range_capped" not in out and out["from_block"] == LOG_BLOCK - 10
    assert out["count"] == 1 and out["counterparties"][0]["by_asset"] == {"USDT": 100.0}


def test_tron_asset_transfers_rejects_bad_direction(monkeypatch) -> None:
    _patch_tron(monkeypatch)
    out = asyncio.run(cm.asset_transfers(TRON, WALLET_HEX, direction="sideways"))
    assert "invalid direction" in out["error"]


def test_tron_asset_transfers_uses_alchemy_when_configured(monkeypatch) -> None:
    alchemy = "https://tron-mainnet.g.alchemy.com/v2/KEY"
    cm._dead_urls.clear()
    seen: list[str] = []

    def handler(req: dict):
        seen.append(req["method"])
        return {"transfers": []}

    monkeypatch.setattr(cm, "async_client", lambda **k: _Client(handler))
    monkeypatch.setattr(cm.scryer_config, "get_rpc_url", lambda cid: alchemy)
    monkeypatch.setattr(cm.scryer_config, "get_rpc_urls", lambda cid: [alchemy, TRONGRID])
    out = asyncio.run(cm.asset_transfers(TRON, WALLET_T, direction="in"))
    assert seen == ["alchemy_getAssetTransfers"] and out["count"] == 0


def test_deployer_refuses_tron() -> None:
    out = asyncio.run(cm.deployer(TRON, WALLET_HEX))
    assert "not supported on Tron" in out["error"]


def test_reserves_history_on_tron_never_returns_a_silent_empty(monkeypatch) -> None:
    calls: list[str] = []

    def handler(req: dict):
        calls.append(req["method"])
        if req["method"] == "eth_blockNumber":
            return hex(HEAD)
        if req["method"] == "eth_getLogs":
            return []  # no Sync logs in range
        raise AssertionError(f"historical {req['method']} must not be attempted on Tron")

    cm._dead_urls.clear()
    monkeypatch.setattr(cm, "async_client", lambda **k: _Client(handler))
    monkeypatch.setattr(cm.scryer_config, "get_rpc_url", lambda cid: TRONGRID)
    monkeypatch.setattr(cm.scryer_config, "get_rpc_urls", lambda cid: [TRONGRID])
    big = asyncio.run(cm.reserves_history(TRON, PEER_HEX, from_block=HEAD - 100_000, to_block=HEAD))
    assert "narrow the range" in big["error"]  # large range -> explicit error, no sampling
    small = asyncio.run(cm.reserves_history(TRON, PEER_HEX, from_block=HEAD - 100, to_block=HEAD))
    assert small["series"] == [] and "unavailable on Tron" in small["note"]
    assert "eth_call" not in calls


def test_deployed_by_refuses_tron_instead_of_a_false_empty() -> None:
    # Tron contract addresses are not keccak(rlp([sender, nonce])) — the EVM enumeration would
    # silently report "deployed nothing", so it must refuse with an explicit error.
    out = asyncio.run(cm.deployed_by(TRON, WALLET_HEX))
    assert "not supported on Tron" in out["error"]


# --------------------------------------------------------------------------- #
# token_exposure on Tron — TRX in sun, base58 DeFiLlama keys
# --------------------------------------------------------------------------- #
class _TronW3:
    class eth:  # noqa: N801
        @staticmethod
        def get_balance(addr, block_identifier=None):
            return 12_345_678  # sun -> 12.345678 TRX

        @staticmethod
        def call(tx, block_identifier=None):
            if tx["to"].lower() == USDT_HEX:
                return (100 * 10**6).to_bytes(32, "big")
            return (0).to_bytes(32, "big")


def test_token_exposure_tron_native_decimals_and_base58_price_keys(monkeypatch) -> None:
    seen_keys: list[str] = []

    def prices(keys, timestamp=None, tally=None):
        seen_keys.extend(keys)
        return {"coingecko:tron": 0.5, f"tron:{USDT_T}": 1.0}

    monkeypatch.setattr(oc, "_w3", lambda cid: (_TronW3(), "http://fake"))
    monkeypatch.setattr(oc, "_defillama_prices", prices)
    out = oc.token_exposure(TRON, WALLET_HEX)
    assert out["native"] == {"symbol": "TRX", "amount": 12.345678, "usd": round(12.345678 * 0.5, 2)}
    assert [h["symbol"] for h in out["token_holdings"]] == ["USDT"]
    assert out["token_holdings"][0]["usd"] == 100.0
    assert f"tron:{USDT_T}" in seen_keys and "coingecko:tron" in seen_keys


# --------------------------------------------------------------------------- #
# Review fixes: over-full windows, Tron throttling, unreadable decimals, TRX units, flags
# --------------------------------------------------------------------------- #
def _patch_handler(monkeypatch, handler, chain_url: str = TRONGRID) -> _Client:
    cm._dead_urls.clear()
    cm._token_meta_cache.clear()
    client = _Client(handler)
    monkeypatch.setattr(cm, "async_client", lambda **k: client)
    monkeypatch.setattr(cm.scryer_config, "get_rpc_url", lambda cid: chain_url)
    monkeypatch.setattr(cm.scryer_config, "get_rpc_urls", lambda cid: [chain_url])
    monkeypatch.delenv("SCRYER_LOGS_CHUNK", raising=False)

    async def no_sleep(_s):
        return None

    monkeypatch.setattr(cm.asyncio, "sleep", no_sleep)
    return client


@pytest.mark.parametrize("chain_id", [TRON, 56])
def test_get_logs_splits_a_window_that_returned_too_many_results(monkeypatch, chain_id) -> None:
    # TronGrid / Infura answer an over-full window with -32005, which classifies as a throttle.
    def handler(req: dict):
        if req["method"] == "eth_blockNumber":
            return hex(HEAD)
        lo, hi = int(req["params"][0]["fromBlock"], 16), int(req["params"][0]["toBlock"], 16)
        if hi - lo + 1 > 50:
            return _rpc_error(-32005, "query returned more than 10000 results")
        return [
            {
                "address": USDT_HEX,
                "topics": [],
                "data": "0x",
                "blockNumber": hex(b),
                "logIndex": "0x0",
                "transactionHash": "0x" + f"{b:064x}",
            }
            for b in range(lo, hi + 1)
            if b % 10 == 0
        ]

    _patch_handler(monkeypatch, handler)
    out = asyncio.run(
        cm.get_logs(chain_id, "", topics=[cm.TRANSFER_TOPIC], from_block=HEAD - 199, to_block=HEAD, chunk=200)
    )
    assert out["count"] == 20 and "rate_limited" not in out and "partial" not in out


def test_tron_get_logs_backs_off_and_retries_a_throttle(monkeypatch) -> None:
    hits = {"n": 0}

    def handler(req: dict):
        if req["method"] == "eth_blockNumber":
            return hex(HEAD)
        hits["n"] += 1
        return _http(429) if hits["n"] <= 2 else []  # throttled twice, then served

    _patch_handler(monkeypatch, handler)
    out = asyncio.run(cm.get_logs(TRON, "", topics=[cm.TRANSFER_TOPIC], from_block=HEAD - 10, to_block=HEAD))
    assert "rate_limited" not in out and out["count"] == 0 and hits["n"] == 3


def test_tron_unreadable_decimals_are_unknown_not_guessed(monkeypatch) -> None:
    def handler(req: dict):
        m, p = req["method"], req.get("params") or []
        if m == "eth_blockNumber":
            return hex(HEAD)
        if m == "eth_call":
            return _http(429)  # decimals()/symbol() of the look-alike token throttled every time
        if m == "eth_getLogs":
            lo, hi = int(p[0]["fromBlock"], 16), int(p[0]["toBlock"], 16)
            if not lo <= LOG_BLOCK <= hi:
                return []
            topics = [cm.TRANSFER_TOPIC, _topic(PEER_HEX), _topic(WALLET_HEX)]
            common = {"topics": topics, "blockNumber": hex(LOG_BLOCK), "transactionHash": TX_HASH}
            return [
                {**common, "address": FAKE_USDT_HEX, "data": _word(5 * 10**6), "logIndex": "0x1"},
                {**common, "address": USDT_HEX, "data": _word(7 * 10**6), "logIndex": "0x2"},
            ]
        raise AssertionError(m)

    _patch_handler(monkeypatch, handler)
    out = asyncio.run(cm.asset_transfers(TRON, WALLET_HEX, direction="in", from_block=LOG_BLOCK - 5))
    by_asset = out["counterparties"][0]["by_asset"]
    assert by_asset["USDT"] == 7.0  # canonical USDT needs no RPC for its 6 decimals
    assert by_asset[f"TRC20@{tr.to_base58(FAKE_USDT_HEX)}"] is None  # unknown, never a guessed-18 zero
    assert out["token_meta_failed"] == 1 and out["rate_limited"] is True
    assert (TRON, FAKE_USDT_HEX) not in cm._token_meta_cache  # a failed lookup is not cached


def test_tron_get_tx_reports_trx_in_sun(monkeypatch) -> None:
    def handler(req: dict):
        if req["method"] == "eth_getTransactionByHash":
            value = hex(50_000 * 10**6)
            return {"from": WALLET_HEX, "to": PEER_HEX, "value": value, "input": "0x", "blockNumber": "0x1"}
        if req["method"] == "eth_getTransactionReceipt":
            return {"status": "0x1", "logs": []}
        raise AssertionError(req["method"])

    _patch_handler(monkeypatch, handler)
    out = asyncio.run(cm.get_tx(TRON, TX_HASH))
    assert "value_wei" not in out and out["value_sun"] == 50_000 * 10**6 and out["value_trx"] == 50_000.0


def test_tron_reserves_note_does_not_claim_empty_when_scan_was_partial(monkeypatch) -> None:
    def handler(req: dict):
        if req["method"] == "eth_blockNumber":
            return hex(HEAD)
        return _http(429)  # every getLogs attempt throttled (retries exhausted)

    _patch_handler(monkeypatch, handler)
    out = asyncio.run(cm.reserves_history(TRON, PEER_HEX, from_block=HEAD - 100, to_block=HEAD))
    assert out["rate_limited"] is True and out["note"].startswith("Sync-log scan was PARTIAL")


def test_tron_both_directions_keep_every_failed_window(monkeypatch) -> None:
    def handler(req: dict):
        if req["method"] == "eth_blockNumber":
            return hex(HEAD)
        t = req["params"][0]["topics"]
        return _rpc_error(-32000, "boom-in" if len(t) == 3 else "boom-out")

    _patch_handler(monkeypatch, handler)
    out = asyncio.run(cm.asset_transfers(TRON, WALLET_HEX, direction="both", from_block=HEAD - 10))
    dirs = sorted(e["direction"] for e in out["errors"])
    assert dirs == ["in", "out"] and out["partial"] is True


def test_tron_both_first_funder_ignores_earlier_outgoing(monkeypatch) -> None:
    funder, recipient = "0x" + "f1" * 20, "0x" + "e2" * 20

    def handler(req: dict):
        if req["method"] == "eth_blockNumber":
            return hex(HEAD)
        flt = req["params"][0]
        lo, hi = int(flt["fromBlock"], 16), int(flt["toBlock"], 16)
        incoming = len(flt["topics"]) == 3
        blk = LOG_BLOCK if incoming else LOG_BLOCK - 5  # the outgoing transfer happens first
        if not lo <= blk <= hi:
            return []
        frm, to = (funder, WALLET_HEX) if incoming else (WALLET_HEX, recipient)
        return [
            {
                "address": USDT_HEX,
                "topics": [cm.TRANSFER_TOPIC, _topic(frm), _topic(to)],
                "data": _word(10**6),
                "blockNumber": hex(blk),
                "logIndex": "0x1",
                "transactionHash": TX_HASH,
            }
        ]

    _patch_handler(monkeypatch, handler)
    out = asyncio.run(cm.asset_transfers(TRON, WALLET_HEX, direction="both", from_block=LOG_BLOCK - 10))
    assert out["first_funder"]["address"] == funder and out["first_funder"]["block"] == LOG_BLOCK
    assert out["earliest_block"] == LOG_BLOCK - 5
