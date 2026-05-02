"""Tests for llm_providers.get_provider — pure dispatch logic, no network."""

from __future__ import annotations

import pytest

from llm_providers import (
    ClaudeProvider,
    GeminiProvider,
    LLMProvider,
    OpenAIProvider,
    get_provider,
)


def test_get_provider_openai(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("OPENAI_API_KEY", "test-key")
    p = get_provider("openai")
    assert isinstance(p, OpenAIProvider)
    assert isinstance(p, LLMProvider)
    assert p.name.startswith("openai")


def test_get_provider_claude(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("ANTHROPIC_API_KEY", "test-key")
    p = get_provider("claude")
    assert isinstance(p, ClaudeProvider)
    assert p.name.startswith("claude")


def test_get_provider_gemini(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("GOOGLE_API_KEY", "test-key")
    p = get_provider("gemini")
    assert isinstance(p, GeminiProvider)
    assert p.name.startswith("gemini")


def test_get_provider_case_insensitive(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("OPENAI_API_KEY", "x")
    assert isinstance(get_provider("OpenAI"), OpenAIProvider)
    assert isinstance(get_provider("OPENAI"), OpenAIProvider)


def test_get_provider_unknown_raises() -> None:
    with pytest.raises(ValueError, match="Unknown provider"):
        get_provider("not-a-real-provider")


def test_get_provider_overrides(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("OPENAI_API_KEY", "env-key")
    p = get_provider("openai", api_key="explicit-key", model="gpt-x", base_url="https://example.test/v1")
    assert isinstance(p, OpenAIProvider)
    # We don't poke at private attrs, but creation must not raise.


def test_provider_subclasses_implement_interface() -> None:
    for cls in (OpenAIProvider, ClaudeProvider, GeminiProvider):
        assert hasattr(cls, "chat_completion")
        assert hasattr(cls, "name")
