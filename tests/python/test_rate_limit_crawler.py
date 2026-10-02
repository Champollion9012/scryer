"""P2a: rate-limit handling in the crawler/discovery pipeline that feeds the registry.

The invariant: a provider/RPC THROTTLE during crawling or discovery must NOT be committed
to the registry as a genuine-miss ("no source" / decompiled / bytecode-only) entry — that
would poison registry_clones / registry_vulnerable with a false record that is never
re-fetched. A throttle instead raises RateLimited so the pipeline skips the address (and the
block range) for a later run. A genuine not-verified must still be the quiet ({}, None) miss.
"""

from __future__ import annotations

from types import SimpleNamespace

import pytest

import contract_crawler as cc
import rpc_contract_discovery as disc
from scryer_http import RateLimited


class _FakeResp:
    def __init__(self, status_code: int = 200, json_data: dict | None = None, headers: dict | None = None):
        self.status_code = status_code
        self._json = json_data if json_data is not None else {}
        self.headers = headers or {}

    def json(self):
        return self._json


class _FakeAsyncClient:
    def __init__(self, resp: _FakeResp):
        self._resp = resp

    async def get(self, url, **kw):
        return self._resp


class _FakeRateLimiter:
    async def wait(self):
        return None


def _eth_chain():
    return cc.ChainConfig(1, "ethereum", True, "https://api.etherscan.io/api", "ETHERSCAN_API_KEY")


# --------------------------------------------------------------------------- #
# Leaf fetchers (shared by both pipelines): raise on throttle, quiet on a real miss
# --------------------------------------------------------------------------- #
async def test_crawler_sourcify_429_raises() -> None:
    client = _FakeAsyncClient(_FakeResp(status_code=429, headers={"Retry-After": "5"}))
    with pytest.raises(RateLimited):
        await cc.fetch_sourcify_source(1, "0xabc", client, _FakeRateLimiter())


async def test_crawler_sourcify_genuine_miss_does_not_raise() -> None:
    client = _FakeAsyncClient(_FakeResp(status_code=200, json_data={"sources": {}}))
    sources, meta = await cc.fetch_sourcify_source(1, "0xabc", client, _FakeRateLimiter())
    assert sources == {} and meta is None  # genuinely not on Sourcify -> quiet miss, no raise


async def test_crawler_explorer_body_throttle_raises(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("ETHERSCAN_API_KEY", "DUMMY")
    resp = _FakeResp(200, {"status": "0", "message": "NOTOK", "result": "Max rate limit reached"})
    with pytest.raises(RateLimited):
        await cc.fetch_explorer_source(_eth_chain(), "0xabc", _FakeAsyncClient(resp), _FakeRateLimiter())


async def test_crawler_explorer_genuine_unverified_does_not_raise(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("ETHERSCAN_API_KEY", "DUMMY")
    resp = _FakeResp(200, {"status": "0", "message": "NOTOK", "result": "Contract source code not verified"})
    sources, meta = await cc.fetch_explorer_source(_eth_chain(), "0xabc", _FakeAsyncClient(resp), _FakeRateLimiter())
    assert sources == {} and meta is None  # genuinely unverified -> quiet miss, not a throttle


async def test_crawler_verified_list_throttle_raises() -> None:
    client = _FakeAsyncClient(_FakeResp(status_code=429, headers={"Retry-After": "9"}))
    with pytest.raises(RateLimited):
        await cc.fetch_sourcify_verified_contracts(1, client, _FakeRateLimiter(), None)


# --------------------------------------------------------------------------- #
# The poisoning fix: _process_contract must NOT register on a throttle
# --------------------------------------------------------------------------- #
async def test_discovery_throttle_skips_registration(monkeypatch: pytest.MonkeyPatch) -> None:
    async def _raise(*a, **k):
        raise RateLimited(provider="sourcify", detail="HTTP 429")

    monkeypatch.setattr(disc, "fetch_sourcify_source", _raise)

    registered: list = []
    fake_self = SimpleNamespace(
        api_rate_limiter=_FakeRateLimiter(),
        stats={"rate_limited": 0, "errors": 0, "decompiled": 0, "from_sourcify": 0, "from_explorer": 0},
        registry=SimpleNamespace(register_contract=lambda **k: registered.append(k)),
    )
    chain = _eth_chain()
    rpc_config = SimpleNamespace(chain_id=1)
    scanner = SimpleNamespace()  # get_bytecode must NOT be reached
    client = _FakeAsyncClient(_FakeResp())

    result = await disc.ContractDiscovery._process_contract(fake_self, chain, rpc_config, "0xabc", scanner, client)

    assert result is False
    assert registered == []  # the throttled contract is NOT registered -> registry not poisoned
    assert fake_self.stats["rate_limited"] == 1


async def test_make_request_raises_on_persistent_429_even_with_socks(monkeypatch: pytest.MonkeyPatch) -> None:
    """A persistent 429 must raise RateLimited after retries REGARDLESS of SOCKS_PROXY — else
    the resulting None is read as an empty block and the range is recorded as scanned (dropping
    the throttled blocks' contracts). Regression test for the proxy-path hole the review caught."""
    monkeypatch.setenv("SOCKS_PROXY", "socks5://127.0.0.1:9050")

    async def _noop_sleep(*a, **k):
        return None

    monkeypatch.setattr(disc.asyncio, "sleep", _noop_sleep)  # no real backoff delay in the test

    class _Resp429:
        status_code = 429
        headers = {"Retry-After": "3"}

        def json(self):
            return {}

    class _Client429:
        async def post(self, url, **kw):
            return _Resp429()

    async def _wait():
        return None

    async def _no_proxy(_p):
        return None  # force the direct path; exercises the socks switching branches

    fake_self = SimpleNamespace(
        rate_limiter=SimpleNamespace(wait=_wait),
        get_rpc_url=lambda: "http://rpc",
        use_proxy=False,
        _get_proxy_client=_no_proxy,
    )
    with pytest.raises(RateLimited):
        await disc.BlockScanner._make_request(fake_self, _Client429(), "eth_blockNumber", [])
