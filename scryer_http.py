"""Shared HTTP client factory for Scryer.

Centralizes ``httpx`` client construction so new code gets:

- Consistent timeouts (configurable via ``SCRYER_HTTP_TIMEOUT``).
- Sane connection pool limits.
- Retry on transient errors via :class:`httpx.HTTPTransport(retries=...)`.
- SOCKS proxy fallback (via ``httpx-socks``) when ``SOCKS_PROXY`` is set.
- A consistent ``User-Agent`` header.

Usage
-----

Async::

    from scryer_http import async_client
    async with async_client() as client:
        r = await client.get(url)

Sync::

    from scryer_http import sync_client
    with sync_client() as client:
        r = client.get(url)
"""

from __future__ import annotations

import re
import threading
from typing import Any

import httpx

import scryer_config
from scryer_logging import get_logger

_log = get_logger(__name__)

DEFAULT_USER_AGENT = "scryer/0.2 (+https://github.com/your-org/scryer)"
DEFAULT_TIMEOUT_SECONDS = 30.0
DEFAULT_RETRIES = 2
DEFAULT_MAX_CONNECTIONS = 100
DEFAULT_MAX_KEEPALIVE = 20


def _build_timeout(timeout: float | httpx.Timeout | None) -> httpx.Timeout:
    if isinstance(timeout, httpx.Timeout):
        return timeout
    if timeout is None:
        env = scryer_config.get("SCRYER_HTTP_TIMEOUT")
        timeout = float(env) if env else DEFAULT_TIMEOUT_SECONDS
    return httpx.Timeout(timeout, connect=min(10.0, timeout))


def _build_limits() -> httpx.Limits:
    return httpx.Limits(
        max_connections=DEFAULT_MAX_CONNECTIONS,
        max_keepalive_connections=DEFAULT_MAX_KEEPALIVE,
    )


def _default_headers(extra: dict[str, str] | None = None) -> dict[str, str]:
    headers = {"User-Agent": DEFAULT_USER_AGENT}
    if extra:
        headers.update(extra)
    return headers


def _socks_proxy_url() -> str | None:
    proxy = scryer_config.get("SOCKS_PROXY")
    return proxy.strip() if proxy else None


def async_client(
    *,
    timeout: float | httpx.Timeout | None = None,
    headers: dict[str, str] | None = None,
    follow_redirects: bool = True,
    use_socks_proxy: bool = False,
    retries: int = DEFAULT_RETRIES,
    **kwargs: Any,
) -> httpx.AsyncClient:
    """Construct a configured :class:`httpx.AsyncClient`.

    Args:
        timeout: Per-request timeout in seconds, or an :class:`httpx.Timeout`.
        headers: Extra default headers (merged with ``User-Agent``).
        follow_redirects: Pass-through to httpx.
        use_socks_proxy: If ``True`` and ``SOCKS_PROXY`` is set, route through it.
        retries: Connection-level retries on transient errors.
        **kwargs: Forwarded to :class:`httpx.AsyncClient`.
    """
    transport = _async_transport(use_socks_proxy=use_socks_proxy, retries=retries)
    return httpx.AsyncClient(
        timeout=_build_timeout(timeout),
        limits=_build_limits(),
        headers=_default_headers(headers),
        follow_redirects=follow_redirects,
        transport=transport,
        **kwargs,
    )


def sync_client(
    *,
    timeout: float | httpx.Timeout | None = None,
    headers: dict[str, str] | None = None,
    follow_redirects: bool = True,
    use_socks_proxy: bool = False,
    retries: int = DEFAULT_RETRIES,
    **kwargs: Any,
) -> httpx.Client:
    """Construct a configured :class:`httpx.Client`."""
    transport = _sync_transport(use_socks_proxy=use_socks_proxy, retries=retries)
    return httpx.Client(
        timeout=_build_timeout(timeout),
        limits=_build_limits(),
        headers=_default_headers(headers),
        follow_redirects=follow_redirects,
        transport=transport,
        **kwargs,
    )


def _async_transport(*, use_socks_proxy: bool, retries: int) -> httpx.AsyncBaseTransport:
    if use_socks_proxy:
        proxy = _socks_proxy_url()
        if proxy:
            try:
                from httpx_socks import AsyncProxyTransport
            except ImportError:  # pragma: no cover - optional dep
                _log.warning("httpx-socks not installed; falling back to direct connection")
            else:
                return AsyncProxyTransport.from_url(proxy)
    return httpx.AsyncHTTPTransport(retries=retries)


def _sync_transport(*, use_socks_proxy: bool, retries: int) -> httpx.BaseTransport:
    if use_socks_proxy:
        proxy = _socks_proxy_url()
        if proxy:
            try:
                from httpx_socks import SyncProxyTransport
            except ImportError:  # pragma: no cover - optional dep
                _log.warning("httpx-socks not installed; falling back to direct connection")
            else:
                return SyncProxyTransport.from_url(proxy)
    return httpx.HTTPTransport(retries=retries)


def redact_rpc_url(url: str) -> str:
    """Reduce an RPC endpoint to a non-secret label for inclusion in tool output.

    Provider API keys live in the path (Alchemy ``/v2/<KEY>``), the query (``?apikey=``), or
    occasionally a subdomain; returning ``scheme://host`` drops the path and query, which removes
    the key for every common provider. A value that is not an http(s) URL — e.g. the
    ``etherscan-v2-proxy:56`` label or a test stub like ``fake-rpc`` — carries no secret and is
    returned unchanged. This never returns the key.
    """
    if not url:
        return url
    if "://" not in url:
        return url  # already a non-URL label (e.g. 'etherscan-v2-proxy:56')
    try:
        from urllib.parse import urlsplit

        parts = urlsplit(url)
        host = parts.hostname or ""
        if not host:
            return "<redacted-rpc>"
        return f"{parts.scheme}://{host}"
    except Exception:
        return "<redacted-rpc>"


# ---------------------------------------------------------------------------
# Rate-limit detection & propagation
#
# Every scryer data provider (Etherscan V2, Sourcify, Blockscout, IPFS gateways,
# DeFiLlama, RPC nodes) throttles under load, and each signals it differently:
#   - HTTP 429 (sometimes 403/503 + Retry-After)   -> status-based
#   - Etherscan V2: HTTP 200 + {"status":"0","result":"Max rate limit reached"}
#   - JSON-RPC / web3: an error whose text says "rate limit" / "capacity" /
#     "too many requests" / code -32005
#
# The old code swallowed all of these into the SAME value it uses for a genuine
# miss (found:false / None / {} / verdict:no_bytecode / usd:null), so the caller
# (the hunter agent) could not tell "throttled, retry later" from "genuinely
# absent". These helpers make a throttle a first-class, surfaced signal.
#
# False-positive guard: app-level body matching is OPT-IN (``body_text``). The
# classifier never scans a full response body on its own, so a contract source
# that happens to contain the words "rate limit" can never be mis-read as a
# throttle. Callers pass only the short message/result field they already parsed.
# ---------------------------------------------------------------------------

# Application-level throttle phrasing (Etherscan result/message, gateway bodies).
_RL_BODY_RE = re.compile(
    r"max rate limit|rate limit reached|rate.?limit exceeded|over (the )?rate limit|"
    r"too many requests|max calls per sec|max daily|request limit reached|throttl",
    re.IGNORECASE,
)

# A genuine contract revert is NEVER a transport/RPC throttle. web3's ContractLogicError
# stringifies as "execution reverted: <reason>" and embeds the contract's OWN reason string,
# which may itself contain "rate limit" / "throttled" (rate-limiter / circuit-breaker / bridge
# contracts). Exclude any revert before throttle-matching, or a deterministic revert would be
# mislabeled a throttle and the agent told to retry forever.
_REVERT_RE = re.compile(r"execution reverted|\brevert", re.IGNORECASE)

# JSON-RPC / web3 exception throttle phrasing (Alchemy/public-node/Infura). Alphabetic
# alternatives are \b-anchored so benign text ("sepaRATE LIMIT", "discOVER RATE") cannot match;
# a bare HTTP 429 is caught by the status-based rate_limit_reason, and as web3 exception text a
# 429 always carries "too many requests".
_RPC_RL_RE = re.compile(
    r"too many requests|\brate[ ._-]?limit|compute units? per second|"
    r"exceeded .{0,40}capacity|capacity.{0,20}exceeded|\bover (the )?rate limit|"
    r"\brequest rate limit|throttl|-32005",
    re.IGNORECASE,
)


class RateLimited(Exception):
    """A provider throttled the request.

    Raised (or recorded on a :class:`RateLimitTally`) instead of letting a 429 /
    app-level throttle collapse into a genuine-miss value. ``retry_after`` is in
    seconds when the provider supplied it; ``detail`` is the provider's own
    message. ``reason`` is a ready-to-surface one-liner.
    """

    def __init__(self, provider: str, *, retry_after: int | None = None, detail: str | None = None):
        self.provider = provider
        self.retry_after = retry_after
        self.detail = detail
        reason = f"{provider} rate-limited"
        if detail:
            reason += f": {detail}"
        if retry_after is not None:
            reason += f" (retry after {retry_after}s)"
        self.reason = reason
        super().__init__(reason)


def retry_after_seconds(response: Any) -> int | None:
    """Parse a ``Retry-After`` header (delta-seconds form) to an int, else None.

    HTTP-date form is rare for these JSON APIs and is skipped (returns None)
    rather than guessed."""
    try:
        raw = response.headers.get("Retry-After")
    except Exception:
        return None
    if not raw:
        return None
    try:
        return max(0, int(float(str(raw).strip())))
    except (TypeError, ValueError, OverflowError):
        return None  # non-numeric, HTTP-date, or 'inf'/overflow -> no usable delay


def rate_limit_reason(response: Any, body_text: str | None = None) -> str | None:
    """Classify an HTTP response as rate-limited, returning a reason string or None.

    Status-based: 429 always; 403/503 only with a Retry-After header or a
    throttle body (a bare 403/503 is auth / outage, not a throttle). App-level:
    only when the caller passes ``body_text`` (e.g. Etherscan's short
    ``result``/``message``), which is matched against known throttle phrasing.
    Never scans the full body on its own — see the module note on false positives.
    """
    code = getattr(response, "status_code", None)
    ra = retry_after_seconds(response)

    def _body_hit() -> str | None:
        if body_text and _RL_BODY_RE.search(body_text):
            return body_text.strip()[:160]
        return None

    if code == 429:
        return _body_hit() or "HTTP 429 Too Many Requests"
    if code in (403, 503):
        if ra is not None:
            return _body_hit() or f"HTTP {code} with Retry-After"
        return _body_hit()  # bare 403/503 -> None (not a throttle)
    # Any other status (incl. 200): only an explicit app-level body signals a throttle.
    return _body_hit()


def rpc_rate_limit_reason(err: Any) -> str | None:
    """Classify a web3/JSON-RPC error (exception or text) as a throttle, else None.

    Covers public-node / Alchemy / Infura phrasing and JSON-RPC code -32005.
    """
    if err is None:
        return None
    if isinstance(err, dict):  # a JSON-RPC error member {code, message}
        text = f"{err.get('code', '')} {err.get('message', '')}"
    elif isinstance(err, str):
        text = err
    else:
        text = f"{type(err).__name__}: {err}"
    if _REVERT_RE.search(text):
        return None  # a contract revert is deterministic, never a throttle
    m = _RPC_RL_RE.search(text)
    if not m:
        return None
    # Keep the reason short and informative.
    snippet = text.strip().replace("\n", " ")
    return snippet[:160] if len(snippet) <= 200 else f"RPC throttle ({m.group(0)})"


class RateLimitTally:
    """Collects throttle observations across the many sub-calls of ONE MCP tool
    invocation, so a tool can surface ``rate_limited`` + ``warnings`` without
    every hot helper having to raise and abort mid-loop.

    A state tool probes several getters; a throttled one should be *noted* and
    the loop continued, then reported at the end — distinct from a getter that
    genuinely reverts/absent. ``apply(out)`` stamps the standard fields onto a
    result dict.
    """

    __slots__ = ("reasons", "providers", "retry_after", "_lock")

    def __init__(self) -> None:
        self.reasons: list[str] = []
        self.providers: list[str] = []
        self.retry_after: int | None = None
        # Thread-safe: get_sourcify_source fans file fetches out over a ThreadPoolExecutor.
        self._lock = threading.Lock()

    def note(self, reason: str | None, provider: str | None = None, retry_after: int | None = None) -> None:
        if not reason:
            return
        entry = f"{provider}: {reason}" if provider else reason
        with self._lock:
            if entry not in self.reasons:
                self.reasons.append(entry)
            if provider and provider not in self.providers:
                self.providers.append(provider)
            if retry_after is not None:
                self.retry_after = retry_after if self.retry_after is None else max(self.retry_after, retry_after)

    def note_exc(self, exc: RateLimited) -> None:
        """Record a caught :class:`RateLimited`."""
        self.note(exc.detail or exc.reason, provider=exc.provider, retry_after=exc.retry_after)

    @property
    def hit(self) -> bool:
        return bool(self.reasons)

    def apply(self, out: dict) -> dict:
        """Stamp rate_limited / warnings / retry_after / providers onto a result
        dict when any throttle was seen. Returns the same dict for chaining."""
        if self.hit:
            out["rate_limited"] = True
            out["warnings"] = list(self.reasons)
            if self.retry_after is not None:
                out["retry_after"] = self.retry_after
            if self.providers:
                out["rate_limited_providers"] = list(self.providers)
        return out
