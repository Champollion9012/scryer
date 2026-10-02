"""Tests for scryer_http — client factory."""

from __future__ import annotations

import httpx
import pytest

import scryer_http


def test_async_client_is_async_client() -> None:
    client = scryer_http.async_client()
    try:
        assert isinstance(client, httpx.AsyncClient)
        assert client.headers.get("user-agent", "").startswith("scryer/")
    finally:
        # No await needed — close happens in __del__; but be polite.
        pass


def test_sync_client_is_client() -> None:
    with scryer_http.sync_client() as client:
        assert isinstance(client, httpx.Client)
        assert "scryer" in client.headers.get("user-agent", "")


def test_extra_headers_merged() -> None:
    with scryer_http.sync_client(headers={"X-Custom": "1"}) as client:
        assert client.headers.get("user-agent", "").startswith("scryer/")
        assert client.headers.get("x-custom") == "1"


def test_timeout_from_env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("SCRYER_HTTP_TIMEOUT", "5.5")
    # Reset config cache so the new env var takes effect.
    import scryer_config

    scryer_config._LOADED = False  # type: ignore[attr-defined]

    with scryer_http.sync_client() as client:
        # httpx.Timeout has read/write/connect/pool attrs.
        assert client.timeout.read == 5.5


def test_explicit_timeout_overrides_env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("SCRYER_HTTP_TIMEOUT", "5.5")
    with scryer_http.sync_client(timeout=1.0) as client:
        assert client.timeout.read == 1.0


def test_socks_proxy_falls_back_when_unset(monkeypatch: pytest.MonkeyPatch) -> None:
    # SOCKS_PROXY is not set in autouse fixture — verify fallback to direct.
    with scryer_http.sync_client(use_socks_proxy=True) as client:
        # Should still return a usable client, not raise.
        assert isinstance(client, httpx.Client)


# ---------------------------------------------------------------------------
# Rate-limit detection primitives
# ---------------------------------------------------------------------------


class _FakeResp:
    def __init__(self, status_code: int, headers: dict | None = None):
        self.status_code = status_code
        self.headers = httpx.Headers(headers or {})


def test_ratelimited_reason_formatting() -> None:
    e = scryer_http.RateLimited("etherscan", retry_after=12, detail="Max rate limit reached")
    assert e.provider == "etherscan"
    assert e.retry_after == 12
    assert "etherscan" in e.reason and "Max rate limit reached" in e.reason and "12s" in e.reason
    # Minimal form still readable.
    assert scryer_http.RateLimited("rpc:eth").reason == "rpc:eth rate-limited"


def test_retry_after_seconds_parsing() -> None:
    assert scryer_http.retry_after_seconds(_FakeResp(429, {"Retry-After": "30"})) == 30
    assert scryer_http.retry_after_seconds(_FakeResp(429, {"Retry-After": "2.5"})) == 2
    assert scryer_http.retry_after_seconds(_FakeResp(429)) is None
    # HTTP-date form is skipped rather than guessed.
    assert scryer_http.retry_after_seconds(_FakeResp(503, {"Retry-After": "Wed, 21 Oct 2026 07:28:00 GMT"})) is None
    # 'inf'/overflow must degrade to None, not raise OverflowError out of the tool call.
    assert scryer_http.retry_after_seconds(_FakeResp(429, {"Retry-After": "inf"})) is None
    assert scryer_http.retry_after_seconds(_FakeResp(429, {"Retry-After": "infinity"})) is None
    assert scryer_http.retry_after_seconds(_FakeResp(429, {"Retry-After": "1e400"})) is None


def test_rate_limit_reason_status_based() -> None:
    # 429 is always a throttle, with or without a body.
    assert scryer_http.rate_limit_reason(_FakeResp(429)) == "HTTP 429 Too Many Requests"
    # 403/503 only count with Retry-After or a throttle body.
    assert scryer_http.rate_limit_reason(_FakeResp(503, {"Retry-After": "5"})) is not None
    assert scryer_http.rate_limit_reason(_FakeResp(403)) is None  # bare 403 = auth, not throttle
    assert scryer_http.rate_limit_reason(_FakeResp(503)) is None  # bare 503 = outage, not throttle
    # 404 / 200 with no body are not throttles.
    assert scryer_http.rate_limit_reason(_FakeResp(404)) is None
    assert scryer_http.rate_limit_reason(_FakeResp(200)) is None


def test_rate_limit_reason_app_level_body() -> None:
    # Etherscan V2 throttle: HTTP 200 + a "Max rate limit reached" result.
    r = _FakeResp(200)
    assert scryer_http.rate_limit_reason(r, body_text="Max rate limit reached") is not None
    assert scryer_http.rate_limit_reason(r, body_text="NOTOK Max daily rate limit reached") is not None
    # A genuine not-found message must NOT be classified as a throttle.
    assert scryer_http.rate_limit_reason(r, body_text="Contract source code not verified") is None
    assert scryer_http.rate_limit_reason(r, body_text="NOTOK") is None


def test_rate_limit_reason_no_false_positive_on_source() -> None:
    # The classifier never scans the body on its own, so a contract whose SOURCE
    # mentions "rate limit" can never be mis-read as a throttle (body_text=None).
    assert scryer_http.rate_limit_reason(_FakeResp(200)) is None
    # Even a 200 whose text would match is ignored unless passed explicitly.
    assert scryer_http.rate_limit_reason(_FakeResp(200), body_text=None) is None


def test_rpc_rate_limit_reason() -> None:
    assert scryer_http.rpc_rate_limit_reason(
        "{'code': -32005, 'message': 'Your app has exceeded its compute units per second capacity'}"
    )
    assert scryer_http.rpc_rate_limit_reason("429 Client Error: Too Many Requests")
    assert scryer_http.rpc_rate_limit_reason({"code": -32005, "message": "rate limit exceeded"})
    assert scryer_http.rpc_rate_limit_reason(Exception("rate limited, slow down"))
    # A genuine revert / other error is NOT a throttle.
    assert scryer_http.rpc_rate_limit_reason("execution reverted: ERC20: insufficient balance") is None
    assert scryer_http.rpc_rate_limit_reason("connection refused") is None
    assert scryer_http.rpc_rate_limit_reason(None) is None


def test_rpc_rate_limit_reason_revert_is_never_a_throttle() -> None:
    """A contract revert whose REASON contains throttle words (rate-limiter / circuit-breaker /
    anti-bot contracts) must NOT be classified as a node throttle — else the agent retries a
    deterministic revert forever. This is the headline false-positive the review caught."""
    assert scryer_http.rpc_rate_limit_reason("execution reverted: rate limit exceeded") is None
    assert scryer_http.rpc_rate_limit_reason("ContractLogicError: execution reverted: Throttled") is None
    assert scryer_http.rpc_rate_limit_reason("execution reverted: RateLimiter: cooldown active") is None
    assert scryer_http.rpc_rate_limit_reason("execution reverted: max rate limit for this epoch") is None
    # JSON-RPC revert member (code 3) likewise.
    assert scryer_http.rpc_rate_limit_reason({"code": 3, "message": "execution reverted: throttled"}) is None


def test_rpc_rate_limit_reason_no_false_positive_on_benign_substrings() -> None:
    """Anchored alternatives must not match benign text that merely embeds the substrings."""
    assert scryer_http.rpc_rate_limit_reason("ValueError: separate limit exceeded") is None  # sepa|RATE LIMIT
    assert scryer_http.rpc_rate_limit_reason("moderate limit reached") is None
    assert scryer_http.rpc_rate_limit_reason("accurate limit policy") is None
    assert scryer_http.rpc_rate_limit_reason("discover rate of change") is None  # disc|OVER RATE
    assert scryer_http.rpc_rate_limit_reason("takeover rate pending") is None  # take|OVER RATE (no 'limit')
    assert scryer_http.rpc_rate_limit_reason("block 429 not found") is None  # bare 429 token
    assert scryer_http.rpc_rate_limit_reason("transfer amount 4290 tokens") is None


def test_rate_limit_tally() -> None:
    t = scryer_http.RateLimitTally()
    assert not t.hit
    assert t.apply({"found": False}) == {"found": False}  # no-op when clean

    t.note("Max rate limit reached", provider="etherscan", retry_after=5)
    t.note("Max rate limit reached", provider="etherscan", retry_after=10)  # dedup reason, max retry_after
    t.note("capacity exceeded", provider="rpc:eth")
    assert t.hit
    assert t.retry_after == 10
    assert set(t.providers) == {"etherscan", "rpc:eth"}

    out = t.apply({"found": False})
    assert out["rate_limited"] is True
    assert out["retry_after"] == 10
    assert len(out["warnings"]) == 2  # deduped
    assert "etherscan" in out["rate_limited_providers"]


def test_rate_limit_tally_note_exc() -> None:
    t = scryer_http.RateLimitTally()
    t.note_exc(scryer_http.RateLimited("defillama", retry_after=3, detail="HTTP 429"))
    out = t.apply({})
    assert out["rate_limited"] is True
    assert out["retry_after"] == 3
    assert any("defillama" in w for w in out["warnings"])
