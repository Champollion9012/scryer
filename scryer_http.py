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
