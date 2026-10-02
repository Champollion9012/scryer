"""Integration tests for rate-limit SURFACING across scryer's data layer.

The invariant under test: a provider throttle (HTTP 429 / 403/503+Retry-After /
an app-level "Max rate limit reached" body / a JSON-RPC rate-limit error) must be
reported to the caller as a distinct, retryable signal — never collapsed into a
genuine-miss value (found:false / usd:$0 / no_bytecode / "reverted" / None). And,
just as important, a genuine not-found must NOT be mislabeled as a throttle.
"""

from __future__ import annotations

import json
from unittest.mock import patch

import httpx
import pytest

import download_contract as dc
import onchain_state as oc
import verify_source as vs
from scryer_http import RateLimited, RateLimitTally


class _Resp:
    def __init__(self, *, status_code: int = 200, text: str = "", headers: dict | None = None, body: dict | None = None):
        self.status_code = status_code
        self.text = text if text or body is None else json.dumps(body)
        self.headers = headers or {}
        self._body = body

    def json(self):
        return self._body if self._body is not None else json.loads(self.text)

    def raise_for_status(self):
        if self.status_code >= 400:
            raise httpx.HTTPStatusError("err", request=None, response=None)  # type: ignore[arg-type]


# --------------------------------------------------------------------------- #
# Etherscan V2 — the keystone: HTTP 200 with a throttle BODY
# --------------------------------------------------------------------------- #
def test_etherscan_body_throttle_is_surfaced_not_a_miss() -> None:
    def _fake_get(url, params=None, **kw):
        return _Resp(body={"status": "0", "message": "NOTOK", "result": "Max rate limit reached"})

    tally = RateLimitTally()
    with patch.object(dc, "BSC_SCAN_API_KEY", "DUMMY"), patch.object(dc.HTTP, "get", side_effect=_fake_get):
        sources, meta, msg = dc.get_bscscan_source(1, "0x0000000000000000000000000000000000000001", tally=tally)

    assert sources is None  # still a fetch failure...
    assert tally.hit and "etherscan" in tally.providers  # ...but flagged as a throttle
    assert "Max rate limit reached" in msg  # the throttle detail is preserved, not dropped as "NOTOK"


def test_etherscan_genuine_unverified_is_NOT_a_throttle() -> None:
    """False-positive guard: a real 'not verified' must not be read as a throttle."""

    def _fake_get(url, params=None, **kw):
        return _Resp(body={"status": "0", "message": "NOTOK", "result": "Contract source code not verified"})

    tally = RateLimitTally()
    with patch.object(dc, "BSC_SCAN_API_KEY", "DUMMY"), patch.object(dc.HTTP, "get", side_effect=_fake_get):
        sources, meta, msg = dc.get_bscscan_source(1, "0x0000000000000000000000000000000000000001", tally=tally)

    assert sources is None
    assert not tally.hit  # genuinely unverified — NOT flagged as rate-limited


# --------------------------------------------------------------------------- #
# Sourcify — status-based 429 on the gate
# --------------------------------------------------------------------------- #
def test_sourcify_429_surfaced() -> None:
    def _fake_get(url, params=None, **kw):
        return _Resp(status_code=429, headers={"Retry-After": "12"})

    tally = RateLimitTally()
    with patch.object(dc.HTTP, "get", side_effect=_fake_get):
        sources, meta, msg = dc.get_sourcify_source(1, "0x0000000000000000000000000000000000000001", tally=tally)

    assert sources is None
    assert tally.hit and "sourcify" in tally.providers
    assert tally.retry_after == 12
    assert "rate-limited" in msg.lower()


# --------------------------------------------------------------------------- #
# DeFiLlama — a price throttle must become total_usd=null, never $0
# --------------------------------------------------------------------------- #
def test_defillama_429_recorded() -> None:
    def _fake_get(url, timeout=None, **kw):
        return _Resp(status_code=429, headers={"Retry-After": "9"})

    tally = RateLimitTally()
    with patch.object(oc.httpx, "get", side_effect=_fake_get):
        prices = oc._defillama_prices(["coingecko:ethereum"], tally=tally)

    assert prices == {}
    assert tally.hit and "defillama" in tally.providers and tally.retry_after == 9


def test_token_exposure_throttled_price_is_unknown_not_zero(monkeypatch: pytest.MonkeyPatch) -> None:
    class _Eth:
        def get_balance(self, addr, block_identifier=None):
            return 5 * 10**18  # holds 5 native coins

        def call(self, tx, block_identifier=None):
            raise Exception("revert")  # no ERC20 holdings in this fixture

    class _W3:
        eth = _Eth()

    def _fake_defillama(keys, timestamp=None, tally=None):
        if tally is not None:
            tally.note("HTTP 429 Too Many Requests", provider="defillama", retry_after=15)
        return {}

    monkeypatch.setattr(oc, "_w3", lambda cid: (_W3(), "http://fake-rpc"))
    monkeypatch.setattr(oc, "_defillama_prices", _fake_defillama)

    out = oc.token_exposure(1, "0x0000000000000000000000000000000000000001")

    # The critical invariant: a throttled price fetch is NOT reported as $0 at risk.
    assert out["total_usd"] is None
    assert out["rate_limited"] is True
    assert out["retry_after"] == 15
    assert "UNKNOWN" in out["note"]


# --------------------------------------------------------------------------- #
# RPC eth_call — a throttle must not look like a reverted/absent getter
# --------------------------------------------------------------------------- #
def test_call_records_rpc_throttle() -> None:
    class _Eth:
        def call(self, tx, block_identifier=None):
            raise Exception("429 Client Error: Too Many Requests for url")

    class _W3:
        eth = _Eth()

    tally = RateLimitTally()
    result = oc._call(_W3(), "0x0000000000000000000000000000000000000001", "06fdde03", tally=tally)
    assert result is None  # decode logic unchanged...
    assert tally.hit and "rpc" in tally.providers  # ...but the throttle is recorded


def test_call_genuine_revert_is_NOT_a_throttle() -> None:
    class _Eth:
        def call(self, tx, block_identifier=None):
            raise Exception("execution reverted")

    class _W3:
        eth = _Eth()

    tally = RateLimitTally()
    oc._call(_W3(), "0x0000000000000000000000000000000000000001", "06fdde03", tally=tally)
    assert not tally.hit  # a real revert is not flagged as rate-limited


def test_call_view_revert_with_throttle_word_is_not_rate_limited(monkeypatch: pytest.MonkeyPatch) -> None:
    """End-to-end: a contract that reverts with a reason CONTAINING throttle words (a
    rate-limiter/circuit-breaker) must be reported as a revert, NOT rate_limited — else the
    agent retries a deterministic revert forever. (The review's headline false positive.)"""

    class _Eth:
        def call(self, tx, block_identifier=None):
            raise Exception("execution reverted: RateLimiter: rate limit exceeded")

    class _W3:
        eth = _Eth()

    monkeypatch.setattr(oc, "_w3", lambda cid: (_W3(), "http://fake"))
    out = oc.call_view(1, "0x0000000000000000000000000000000000000001", "latestAnswer()", returns="int256")
    assert "rate_limited" not in out  # NOT mislabeled as a throttle
    assert "reverted" in out["error"].lower()  # correctly reported as a revert


# --------------------------------------------------------------------------- #
# verify_source — a throttle must raise RateLimited, never become no_bytecode
# --------------------------------------------------------------------------- #
def _patch_client(monkeypatch, resp: _Resp) -> None:
    class _Client:
        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

        def post(self, url, json=None, **kw):
            return resp

    monkeypatch.setattr(vs.scryer_http, "sync_client", lambda **kw: _Client())


def test_fetch_bytecode_http_429_raises_ratelimited(monkeypatch: pytest.MonkeyPatch) -> None:
    _patch_client(monkeypatch, _Resp(status_code=429, headers={"Retry-After": "7"}))
    with pytest.raises(RateLimited) as ei:
        vs.fetch_runtime_bytecode("http://rpc", "0x0000000000000000000000000000000000000001")
    assert ei.value.retry_after == 7


def test_fetch_bytecode_jsonrpc_capacity_body_raises_ratelimited(monkeypatch: pytest.MonkeyPatch) -> None:
    # HTTP 200 + a JSON-RPC rate-limit error member (result is absent) — the dangerous
    # path that used to return '' and become a confident "EOA/selfdestructed" verdict.
    body = {"jsonrpc": "2.0", "id": 1, "error": {"code": -32005, "message": "exceeded compute units per second capacity"}}
    _patch_client(monkeypatch, _Resp(status_code=200, body=body))
    with pytest.raises(RateLimited):
        vs.fetch_runtime_bytecode("http://rpc", "0x0000000000000000000000000000000000000001")


def test_fetch_bytecode_real_empty_code_is_not_a_throttle(monkeypatch: pytest.MonkeyPatch) -> None:
    # A genuine EOA: HTTP 200, result "0x". Must NOT raise — returns empty string.
    _patch_client(monkeypatch, _Resp(status_code=200, body={"jsonrpc": "2.0", "id": 1, "result": "0x"}))
    assert vs.fetch_runtime_bytecode("http://rpc", "0x0000000000000000000000000000000000000001") == ""


def test_verify_result_carries_machine_readable_retry_after() -> None:
    """The throttle's retry_after must be a structured field on VerifyResult (not only free
    text in notes) so the caller doesn't have to regex the warning string."""
    r = vs.VerifyResult(verdict="indeterminate", chain_id=1, address="0x1", rate_limited=True, retry_after=7)
    assert r.rate_limited is True and r.retry_after == 7
