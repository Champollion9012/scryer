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
