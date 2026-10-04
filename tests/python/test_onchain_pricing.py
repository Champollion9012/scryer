"""Tests for the on-chain LP-route pricing fallback (onchain_state).

Pure CREATE2 pair derivation is checked against canonical known pairs; the routing and the
token_exposure wiring are driven with stubbed reserves / price feeds (no network).
"""

from __future__ import annotations

import pytest

import onchain_state as oc

ETH = 1
BSC = 56
TOKEN = "0x" + "ab" * 20


# --------------------------------------------------------------------------- #
# CREATE2 pair derivation (deterministic, no network)
# --------------------------------------------------------------------------- #
def test_v2_pair_matches_known_pairs() -> None:
    uni = oc._DEX_V2[ETH]
    usdc = "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48"
    weth = uni["weth"][0]
    # canonical Uniswap-V2 USDC/WETH pair
    assert (
        oc._v2_pair(uni["factory"], uni["init_code_hash"], usdc, weth).lower()
        == "0xb4e16d0168e52d35cacd2c6185b44281ec28c9dc"
    )

    cake = oc._DEX_V2[BSC]
    wbnb = cake["weth"][0]
    busd = "0xe9e7CEA3DedcA5984780Bafc599bd69ADd087D56"
    assert (
        oc._v2_pair(cake["factory"], cake["init_code_hash"], wbnb, busd).lower()
        == "0x58f876857a02d6762e0101bb5c46a8c1ed44dc16"
    )


# --------------------------------------------------------------------------- #
# _price_via_pair — reserve math + token0/token1 orientation
# --------------------------------------------------------------------------- #
def test_price_via_pair_handles_both_orientations(monkeypatch) -> None:
    cfg = oc._DEX_V2[ETH]
    usd = cfg["usd"][0].lower()
    token = TOKEN  # 18 decimals; usd 6 decimals

    # token is token0: reserve_token=10e18, reserve_usd=20000e6 -> price 2000
    monkeypatch.setattr(
        oc,
        "_pair_state",
        lambda w3, a, block="latest", tally=None: {
            "token0": token,
            "token1": usd,
            "reserve0": 10 * 10**18,
            "reserve1": 20000 * 10**6,
        },
    )
    price, depth = oc._price_via_pair(None, cfg, token, 18, usd, 6, "latest", None)
    assert price == pytest.approx(2000.0) and depth == pytest.approx(20000.0)  # depth = quote reserve

    # swapped: token is token1
    monkeypatch.setattr(
        oc,
        "_pair_state",
        lambda w3, a, block="latest", tally=None: {
            "token0": usd,
            "token1": token,
            "reserve0": 20000 * 10**6,
            "reserve1": 10 * 10**18,
        },
    )
    price, depth = oc._price_via_pair(None, cfg, token, 18, usd, 6, "latest", None)
    assert price == pytest.approx(2000.0) and depth == pytest.approx(20000.0)


def test_price_via_pair_none_when_pair_mismatch_or_empty(monkeypatch) -> None:
    cfg = oc._DEX_V2[ETH]
    usd = cfg["usd"][0].lower()
    # pair holds different tokens than requested
    monkeypatch.setattr(
        oc,
        "_pair_state",
        lambda *a, **k: {"token0": "0x" + "11" * 20, "token1": "0x" + "22" * 20, "reserve0": 1, "reserve1": 1},
    )
    assert oc._price_via_pair(None, cfg, TOKEN, 18, usd, 6, "latest", None) == (None, 0.0)
    # no liquidity
    monkeypatch.setattr(oc, "_pair_state", lambda *a, **k: None)
    assert oc._price_via_pair(None, cfg, TOKEN, 18, usd, 6, "latest", None) == (None, 0.0)


# --------------------------------------------------------------------------- #
# _lp_price_usd — routing
# --------------------------------------------------------------------------- #
def test_lp_price_usd_direct_route(monkeypatch) -> None:
    def fake(w3, cfg, token, td, quote, qd, block, tally):
        usd = cfg["usd"][0].lower()
        return (3.5, 1000.0) if quote == usd else (None, 0.0)

    monkeypatch.setattr(oc, "_price_via_pair", fake)
    price, src = oc._lp_price_usd(None, ETH, TOKEN, 18)
    assert price == pytest.approx(3.5) and src == "lp:token/usd"


def test_lp_price_usd_via_weth(monkeypatch) -> None:
    cfg = oc._DEX_V2[ETH]
    usd = cfg["usd"][0].lower()
    weth = cfg["weth"][0].lower()

    def fake(w3, cfg, token, td, quote, qd, block, tally):
        if token == TOKEN and quote == usd:
            return None, 0.0  # no direct token/USD pair
        if token == TOKEN and quote == weth:
            return 0.01, 500.0  # 1 token = 0.01 WETH, depth 500 WETH
        if token == weth and quote == usd:
            return 2500.0, 1_000_000.0  # 1 WETH = $2500
        return None, 0.0

    monkeypatch.setattr(oc, "_price_via_pair", fake)
    price, src = oc._lp_price_usd(None, ETH, TOKEN, 18)
    assert price == pytest.approx(25.0) and src == "lp:token/weth/usd"  # 0.01 * 2500


def test_lp_price_usd_picks_deepest_route_not_dust(monkeypatch) -> None:
    """The LABUBU bug: a dust token/USD pair ($34) must NOT outvote a deep token/WETH pool ($2.8M).
    Route selection is by liquidity depth, not 'first pair found'."""
    usd = oc._DEX_V2[ETH]["usd"][0].lower()
    weth = oc._DEX_V2[ETH]["weth"][0].lower()

    def fake(w3, cfg, token, td, quote, qd, block, tally):
        if token == TOKEN and quote == usd:
            return 0.066, 34.0  # dust direct pair -> WRONG price, tiny depth
        if token == TOKEN and quote == weth:
            return 0.0072, 4800.0  # the real pool: 4800 WETH deep
        if token == weth and quote == usd:
            return 576.0, 1_000_000.0
        return None, 0.0

    monkeypatch.setattr(oc, "_price_via_pair", fake)
    price, src = oc._lp_price_usd(None, ETH, TOKEN, 18)
    assert src == "lp:token/weth/usd"  # deep route wins (4800*576 >> 34)
    assert price == pytest.approx(0.0072 * 576.0)  # ~4.15, not the 0.066 dust price


def test_lp_price_usd_is_usd_and_unknown() -> None:
    usd = oc._DEX_V2[ETH]["usd"][0]
    price, src = oc._lp_price_usd(None, ETH, usd, 6)
    assert price == 1.0 and src == "lp:is_usd"
    # unknown chain -> no DEX config
    assert oc._lp_price_usd(None, 999999, TOKEN, 18) == (None, None)


# --------------------------------------------------------------------------- #
# price_token — DeFiLlama first, LP fallback
# --------------------------------------------------------------------------- #
class _W3Stub:
    class eth:  # noqa: N801
        @staticmethod
        def get_block(b):
            return {"timestamp": 1_700_000_000}


def test_price_token_prefers_defillama(monkeypatch) -> None:
    monkeypatch.setattr(oc, "_w3", lambda cid: (_W3Stub(), "http://fake"))
    monkeypatch.setattr(oc, "_defillama_prices", lambda keys, timestamp=None, tally=None: {f"ethereum:{TOKEN}": 7.25})
    out = oc.price_token(ETH, TOKEN)
    assert out["price"] == 7.25 and out["price_source"] == "defillama"


def test_price_token_lp_fallback(monkeypatch) -> None:
    monkeypatch.setattr(oc, "_w3", lambda cid: (_W3Stub(), "http://fake"))
    monkeypatch.setattr(oc, "_defillama_prices", lambda keys, timestamp=None, tally=None: {})  # DeFiLlama miss
    monkeypatch.setattr(oc, "_token_decimals", lambda w3, t, b, tally: 18)
    monkeypatch.setattr(oc, "_lp_price_usd", lambda w3, cid, t, td, block="latest", tally=None: (42.0, "lp:token/usd"))
    out = oc.price_token(ETH, TOKEN)
    assert out["price"] == 42.0 and out["price_source"] == "lp:token/usd" and out["decimals"] == 18


def test_price_token_unpriced(monkeypatch) -> None:
    monkeypatch.setattr(oc, "_w3", lambda cid: (_W3Stub(), "http://fake"))
    monkeypatch.setattr(oc, "_defillama_prices", lambda keys, timestamp=None, tally=None: {})
    monkeypatch.setattr(oc, "_token_decimals", lambda w3, t, b, tally: 18)
    monkeypatch.setattr(oc, "_lp_price_usd", lambda *a, **k: (None, None))
    out = oc.price_token(ETH, TOKEN)
    assert out["price"] is None and "no DeFiLlama price" in out["note"]


# --------------------------------------------------------------------------- #
# token_exposure wires the LP fallback for a holding DeFiLlama can't price
# --------------------------------------------------------------------------- #
def test_token_exposure_uses_lp_fallback_for_unpriced_holding(monkeypatch) -> None:
    wbnb = oc._TOKENS[BSC][3][1].lower()  # WBNB in the fixed BSC list

    class _Eth:
        def get_balance(self, addr, block_identifier=None):
            return 0  # no native, keep the math about the token

        def call(self, tx, block_identifier=None):
            to = (tx["to"] or "").lower()
            if to == wbnb:  # balanceOf(WBNB) -> 2 WBNB
                return (2 * 10**18).to_bytes(32, "big")
            raise Exception("revert")  # other major tokens: no balance

    class _W3Holder:
        eth = _Eth()

    monkeypatch.setattr(oc, "_w3", lambda cid: (_W3Holder(), "http://fake-rpc"))
    # DeFiLlama returns nothing (so WBNB is unpriced by the feed) ...
    monkeypatch.setattr(oc, "_defillama_prices", lambda keys, timestamp=None, tally=None: {})
    # ... and the on-chain LP route prices WBNB at $600.
    monkeypatch.setattr(oc, "_lp_price_usd", lambda w3, cid, t, td, block="latest", tally=None: (600.0, "lp:weth/usd"))

    out = oc.token_exposure(BSC, "0x" + "01" * 20)
    holds = {h["token"]: h for h in out["token_holdings"]}
    assert wbnb in holds
    assert holds[wbnb]["price_source"] == "lp:weth/usd"
    assert holds[wbnb]["usd"] == pytest.approx(1200.0)  # 2 WBNB * $600
    assert out["price_source"] == "defillama+lp_route"
    assert out["total_usd"] == pytest.approx(1200.0)


# --------------------------------------------------------------------------- #
# P2 security: state tools must not leak the RPC key in rpc_url
# --------------------------------------------------------------------------- #
def test_state_tools_redact_rpc_url(monkeypatch) -> None:
    class _Eth:
        def get_code(self, addr, block_identifier=None):
            return b""  # EOA -> get_state returns early, exercising the rpc_url field

    class _W3:
        eth = _Eth()

    monkeypatch.setattr(oc, "_w3", lambda cid: (_W3(), "https://bsc.g.alchemy.com/v2/SUPERSECRETKEY"))
    out = oc.get_state(BSC, "0x" + "11" * 20)
    assert out["rpc_url"] == "https://bsc.g.alchemy.com"
    assert "SUPERSECRETKEY" not in str(out)
