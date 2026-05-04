"""Tests for download_contract.get_sourcify_source — particularly the
match_type plumbing that distinguishes ``perfect`` (1:1) from ``partial_match``
(runtime-equivalent only). Downstream callers need this signal to know whether
to trust source-level cosmetic details (variable names, comments, hex-literal
layout) versus only behavioural conclusions.
"""

from __future__ import annotations

from unittest.mock import patch

import download_contract as dc


class _FakeResp:
    def __init__(self, *, status_code: int = 200, text: str = "") -> None:
        self.status_code = status_code
        self.text = text


def test_sourcify_returns_partial_match_label_in_message_and_metadata() -> None:
    """A partial-match source must be flagged so the caller doesn't misread it as 1:1."""

    def _fake_get(url: str, params: dict | None = None, **kwargs):
        # 1) check-by-addresses returns "partial"
        if "check-by-addresses" in url:
            return _FakeResp(text='[{"address":"0xabc","status":"partial","chainIds":["42161"]}]')
        # 2) sources.json doesn't exist for partial_match in this fixture
        if url.endswith("/sources.json"):
            return _FakeResp(status_code=404, text="")
        # 3) metadata.json — minimal payload with one source file (content inline)
        if url.endswith("/metadata.json"):
            return _FakeResp(
                text='{"sources":{"a.sol":{"content":"contract X{}"}},"output":{"abi":[]}}',
            )
        return _FakeResp(status_code=404, text="")

    with patch.object(dc.HTTP, "get", side_effect=_fake_get):
        sources, metadata, msg = dc.get_sourcify_source(42161, "0xabc")

    assert sources == {"a.sol": "contract X{}"}
    # The message must surface match_type — silent "Sourcify success" hides
    # whether we got a 1:1 source or only a behavioural twin.
    assert "partial" in msg.lower()
    # And the metadata gets a sourcify_match_type key so download_meta.json
    # persists it on disk.
    assert metadata.get("sourcify_match_type") == "partial"


def test_sourcify_full_match_labelled_as_perfect() -> None:
    def _fake_get(url: str, params: dict | None = None, **kwargs):
        if "check-by-addresses" in url:
            return _FakeResp(text='[{"address":"0xabc","status":"perfect","chainIds":["1"]}]')
        if url.endswith("/sources.json"):
            return _FakeResp(status_code=404, text="")
        if url.endswith("/metadata.json"):
            return _FakeResp(text='{"sources":{"X.sol":{"content":"// noop"}},"output":{"abi":[]}}')
        return _FakeResp(status_code=404, text="")

    with patch.object(dc.HTTP, "get", side_effect=_fake_get):
        _, metadata, msg = dc.get_sourcify_source(1, "0xabc")

    assert "perfect" in msg.lower()
    assert metadata.get("sourcify_match_type") == "perfect"


def test_sourcify_unverified_returns_failure_without_match_type() -> None:
    def _fake_get(url: str, params: dict | None = None, **kwargs):
        if "check-by-addresses" in url:
            return _FakeResp(text='[{"address":"0xabc","status":"false"}]')
        return _FakeResp(status_code=404, text="")

    with patch.object(dc.HTTP, "get", side_effect=_fake_get):
        sources, metadata, msg = dc.get_sourcify_source(1, "0xabc")
    assert sources is None
    assert metadata is None
    assert "Not verified" in msg
