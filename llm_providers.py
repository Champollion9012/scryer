"""
LLM Provider abstraction for multi-model support.
Supports: OpenAI, Claude (Anthropic), Gemini (Google)
"""

from __future__ import annotations

import json
import os
from abc import ABC, abstractmethod
from collections.abc import AsyncIterator, Callable
from typing import Any

import scryer_http

UsageCallback = Callable[[dict], None]


class LLMProvider(ABC):
    """Abstract base class for LLM providers."""

    @property
    @abstractmethod
    def name(self) -> str:
        """Provider name."""
        pass

    @abstractmethod
    async def chat_completion(
        self,
        *,
        system_prompt: str,
        user_prompt: str,
        temperature: float = 0.1,
        max_output_tokens: int = 4000,
        timeout_s: float = 180.0,
        json_mode: bool = True,
    ) -> tuple[str, dict]:
        """
        Send a chat completion request.
        Returns: (content, usage_dict)

        ``usage_dict`` includes a ``"truncated"`` boolean: ``True`` when the
        provider hit ``max_tokens`` and cut the output (OpenAI:
        ``finish_reason=="length"``, Anthropic: ``stop_reason=="max_tokens"``,
        Gemini: ``finishReason=="MAX_TOKENS"``). Callers can use this to
        invoke :meth:`continue_completion` and concatenate the result.
        """
        pass

    async def continue_completion(
        self,
        *,
        system_prompt: str,
        user_prompt: str,
        prior_assistant: str,
        temperature: float = 0.1,
        max_output_tokens: int = 4000,
        timeout_s: float = 180.0,
        json_mode: bool = True,
    ) -> tuple[str, dict]:
        """Continue a truncated assistant turn.

        Default fallback: builds a follow-up user prompt that includes the
        prior partial response and asks the model to continue. Providers can
        override with a more idiomatic mechanism (e.g. Anthropic prefilling).
        """
        raise NotImplementedError("provider must implement continue_completion to support auto-continue")

    async def chat_completion_stream(
        self,
        *,
        system_prompt: str,
        user_prompt: str,
        temperature: float = 0.1,
        max_output_tokens: int = 4000,
        timeout_s: float = 180.0,
        json_mode: bool = True,
        on_usage: UsageCallback | None = None,
    ) -> AsyncIterator[str]:
        """Stream completion text as it arrives.

        Default implementation falls back to the non-streaming path: yields the
        whole content in a single chunk and forwards usage to ``on_usage`` so
        callers don't have to special-case providers that don't override.
        Concrete providers override with real SSE streaming + per-event usage
        capture.
        """
        content, usage = await self.chat_completion(
            system_prompt=system_prompt,
            user_prompt=user_prompt,
            temperature=temperature,
            max_output_tokens=max_output_tokens,
            timeout_s=timeout_s,
            json_mode=json_mode,
        )
        if on_usage and usage:
            on_usage(usage)
        yield content


class OpenAIProvider(LLMProvider):
    """OpenAI API provider (GPT-4, GPT-3.5, etc.)"""

    def __init__(
        self,
        api_key: str | None = None,
        base_url: str = "https://api.openai.com/v1",
        model: str = "gpt-4.1-mini",
    ):
        self.api_key = api_key or os.getenv("OPENAI_API_KEY", "")
        self.base_url = base_url.rstrip("/")
        self.model = model

    @property
    def name(self) -> str:
        return f"openai:{self.model}"

    async def chat_completion(
        self,
        *,
        system_prompt: str,
        user_prompt: str,
        temperature: float = 0.1,
        max_output_tokens: int = 4000,
        timeout_s: float = 180.0,
        json_mode: bool = True,
    ) -> tuple[str, dict]:
        url = f"{self.base_url}/chat/completions"
        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json",
        }
        payload: dict[str, Any] = {
            "model": self.model,
            "messages": [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt},
            ],
            "temperature": temperature,
            "max_tokens": max_output_tokens,
        }
        if json_mode:
            payload["response_format"] = {"type": "json_object"}

        # Disable transport-level retries: LLM calls are billed and we don't
        # want a transient 5xx to silently double-charge.
        async with scryer_http.async_client(timeout=timeout_s, retries=0) as client:
            resp = await client.post(url, headers=headers, json=payload)
            resp.raise_for_status()
            data = resp.json()
            choice = data["choices"][0]
            content = choice["message"]["content"]
            usage = dict(data.get("usage", {}))
            # OpenAI signals "ran out of room" via finish_reason="length".
            usage["truncated"] = choice.get("finish_reason") == "length"
            return content, usage

    async def continue_completion(
        self,
        *,
        system_prompt: str,
        user_prompt: str,
        prior_assistant: str,
        temperature: float = 0.1,
        max_output_tokens: int = 4000,
        timeout_s: float = 180.0,
        json_mode: bool = True,
    ) -> tuple[str, dict]:
        """Resume a truncated response by appending the prior assistant turn
        plus a user "continue" instruction. OpenAI doesn't support raw
        prefilling, so this round-trip costs the original prompt tokens again.
        """
        url = f"{self.base_url}/chat/completions"
        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json",
        }
        payload: dict[str, Any] = {
            "model": self.model,
            "messages": [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt},
                {"role": "assistant", "content": prior_assistant},
                {
                    "role": "user",
                    "content": (
                        "Continue your previous response from EXACTLY where you stopped. "
                        "Do not repeat any prior content. Do not add code fences, preamble, "
                        "or explanation. Output only the next characters of the JSON."
                    ),
                },
            ],
            "temperature": temperature,
            "max_tokens": max_output_tokens,
        }
        if json_mode:
            # NB: response_format="json_object" requires the FULL response to
            # be valid JSON. The continuation alone isn't valid JSON in
            # isolation, so we drop json_mode here and rely on the model's
            # instruction-following.
            pass

        async with scryer_http.async_client(timeout=timeout_s, retries=0) as client:
            resp = await client.post(url, headers=headers, json=payload)
            resp.raise_for_status()
            data = resp.json()
            choice = data["choices"][0]
            content = choice["message"]["content"]
            usage = dict(data.get("usage", {}))
            usage["truncated"] = choice.get("finish_reason") == "length"
            return content, usage

    async def chat_completion_stream(
        self,
        *,
        system_prompt: str,
        user_prompt: str,
        temperature: float = 0.1,
        max_output_tokens: int = 4000,
        timeout_s: float = 180.0,
        json_mode: bool = True,
        on_usage: UsageCallback | None = None,
    ) -> AsyncIterator[str]:
        url = f"{self.base_url}/chat/completions"
        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json",
        }
        payload: dict[str, Any] = {
            "model": self.model,
            "messages": [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt},
            ],
            "temperature": temperature,
            "max_tokens": max_output_tokens,
            "stream": True,
            # Ask the server to emit a final chunk with token counts so callers
            # don't have to fall back to a 4-chars-per-token estimate.
            "stream_options": {"include_usage": True},
        }
        if json_mode:
            payload["response_format"] = {"type": "json_object"}

        async with (
            scryer_http.async_client(timeout=timeout_s, retries=0) as client,
            client.stream("POST", url, headers=headers, json=payload) as resp,
        ):
            resp.raise_for_status()
            async for line in resp.aiter_lines():
                if not line or not line.startswith("data:"):
                    continue
                data = line[5:].strip()
                if data == "[DONE]":
                    break
                try:
                    evt = json.loads(data)
                except json.JSONDecodeError:
                    continue
                # The trailing chunk has empty choices and a populated usage block.
                usage = evt.get("usage")
                if usage and on_usage:
                    on_usage(usage)
                choices = evt.get("choices") or []
                if not choices:
                    continue
                delta = choices[0].get("delta", {}).get("content")
                if delta:
                    yield delta


class ClaudeProvider(LLMProvider):
    """Anthropic Claude API provider."""

    def __init__(
        self,
        api_key: str | None = None,
        model: str = "claude-sonnet-4-6",
    ):
        self.api_key = api_key or os.getenv("ANTHROPIC_API_KEY", "")
        self.model = model
        self.base_url = "https://api.anthropic.com/v1"

    @property
    def name(self) -> str:
        return f"claude:{self.model}"

    def _accepts_temperature(self) -> bool:
        """Anthropic deprecated ``temperature`` on Opus 4.7+; sending it
        returns 400 invalid_request_error. Sonnet and Haiku still accept it.
        Pass-through if accepted, omit otherwise.
        """
        return not self.model.startswith("claude-opus-4-7")

    async def chat_completion(
        self,
        *,
        system_prompt: str,
        user_prompt: str,
        temperature: float = 0.1,
        max_output_tokens: int = 4000,
        timeout_s: float = 180.0,
        json_mode: bool = True,
    ) -> tuple[str, dict]:
        del json_mode  # Anthropic has no JSON-mode toggle; param exists for interface parity
        url = f"{self.base_url}/messages"
        headers = {
            "x-api-key": self.api_key,
            "anthropic-version": "2023-06-01",
            "Content-Type": "application/json",
        }

        # Claude uses system as a top-level param
        payload: dict[str, Any] = {
            "model": self.model,
            "max_tokens": max_output_tokens,
            "system": system_prompt,
            "messages": [{"role": "user", "content": user_prompt}],
        }
        if self._accepts_temperature():
            payload["temperature"] = temperature

        async with scryer_http.async_client(timeout=timeout_s, retries=0) as client:
            resp = await client.post(url, headers=headers, json=payload)
            resp.raise_for_status()
            data = resp.json()
            # Claude returns content as array of blocks
            content_blocks = data.get("content", [])
            content = "".join(b.get("text", "") for b in content_blocks if b.get("type") == "text")
            usage = data.get("usage", {})
            # Normalize usage keys + capture truncation flag.
            # Anthropic stop_reason values: end_turn, max_tokens, stop_sequence, tool_use.
            return content, {
                "prompt_tokens": usage.get("input_tokens", 0),
                "completion_tokens": usage.get("output_tokens", 0),
                "truncated": data.get("stop_reason") == "max_tokens",
            }

    async def continue_completion(
        self,
        *,
        system_prompt: str,
        user_prompt: str,
        prior_assistant: str,
        temperature: float = 0.1,
        max_output_tokens: int = 4000,
        timeout_s: float = 180.0,
        json_mode: bool = True,
    ) -> tuple[str, dict]:
        """Resume a truncated response.

        Older Claude models (3.x) accepted assistant-prefill — sending a
        message list ending in an assistant turn and the model continued from
        that token. Claude 4.x dropped that and requires the conversation to
        end with a user turn ("This model does not support assistant message
        prefill"). We use the OpenAI-style follow-up: include the partial as
        an assistant turn, then a user "continue exactly where you stopped"
        instruction.
        """
        del json_mode  # not honoured for continuations (partial alone is invalid JSON)
        url = f"{self.base_url}/messages"
        headers = {
            "x-api-key": self.api_key,
            "anthropic-version": "2023-06-01",
            "Content-Type": "application/json",
        }
        payload: dict[str, Any] = {
            "model": self.model,
            "max_tokens": max_output_tokens,
            "system": system_prompt,
            "messages": [
                {"role": "user", "content": user_prompt},
                {"role": "assistant", "content": prior_assistant.rstrip() or " "},
                {
                    "role": "user",
                    "content": (
                        "Continue your previous response from EXACTLY where you stopped. "
                        "Do not repeat any prior content. Do not add code fences, preamble, "
                        "or explanation. Output only the next characters of the JSON."
                    ),
                },
            ],
        }
        if self._accepts_temperature():
            payload["temperature"] = temperature

        async with scryer_http.async_client(timeout=timeout_s, retries=0) as client:
            resp = await client.post(url, headers=headers, json=payload)
            resp.raise_for_status()
            data = resp.json()
            content_blocks = data.get("content", [])
            content = "".join(b.get("text", "") for b in content_blocks if b.get("type") == "text")
            usage = data.get("usage", {})
            return content, {
                "prompt_tokens": usage.get("input_tokens", 0),
                "completion_tokens": usage.get("output_tokens", 0),
                "truncated": data.get("stop_reason") == "max_tokens",
            }

    async def chat_completion_stream(
        self,
        *,
        system_prompt: str,
        user_prompt: str,
        temperature: float = 0.1,
        max_output_tokens: int = 4000,
        timeout_s: float = 180.0,
        json_mode: bool = True,
        on_usage: UsageCallback | None = None,
    ) -> AsyncIterator[str]:
        del json_mode  # Anthropic has no JSON-mode toggle; param exists for interface parity
        url = f"{self.base_url}/messages"
        headers = {
            "x-api-key": self.api_key,
            "anthropic-version": "2023-06-01",
            "Content-Type": "application/json",
        }
        payload: dict[str, Any] = {
            "model": self.model,
            "max_tokens": max_output_tokens,
            "system": system_prompt,
            "messages": [{"role": "user", "content": user_prompt}],
            "stream": True,
        }
        if self._accepts_temperature():
            payload["temperature"] = temperature

        # Claude reports input_tokens at message_start and cumulative output
        # tokens in each message_delta. We accumulate and emit once at the end
        # so on_usage matches the OpenAI-style "called once" contract.
        prompt_tokens = 0
        completion_tokens = 0

        async with (
            scryer_http.async_client(timeout=timeout_s, retries=0) as client,
            client.stream("POST", url, headers=headers, json=payload) as resp,
        ):
            resp.raise_for_status()
            async for line in resp.aiter_lines():
                if not line.startswith("data:"):
                    continue
                data = line[5:].strip()
                if not data:
                    continue
                try:
                    evt = json.loads(data)
                except json.JSONDecodeError:
                    continue
                etype = evt.get("type")
                if etype == "content_block_delta":
                    text = evt.get("delta", {}).get("text")
                    if text:
                        yield text
                elif etype == "message_start":
                    msg_usage = evt.get("message", {}).get("usage", {}) or {}
                    prompt_tokens = int(msg_usage.get("input_tokens", 0))
                    completion_tokens = int(msg_usage.get("output_tokens", 0))
                elif etype == "message_delta":
                    delta_usage = evt.get("usage", {}) or {}
                    if "output_tokens" in delta_usage:
                        completion_tokens = int(delta_usage["output_tokens"])
                elif etype == "message_stop":
                    break

        if on_usage and (prompt_tokens or completion_tokens):
            on_usage({"prompt_tokens": prompt_tokens, "completion_tokens": completion_tokens})


class GeminiProvider(LLMProvider):
    """Google Gemini API provider."""

    def __init__(
        self,
        api_key: str | None = None,
        model: str = "gemini-2.5-flash",
    ):
        self.api_key = api_key or os.getenv("GOOGLE_API_KEY", "") or os.getenv("GEMINI_API_KEY", "")
        self.model = model

    @property
    def name(self) -> str:
        return f"gemini:{self.model}"

    async def chat_completion(
        self,
        *,
        system_prompt: str,
        user_prompt: str,
        temperature: float = 0.1,
        max_output_tokens: int = 4000,
        timeout_s: float = 180.0,
        json_mode: bool = True,
    ) -> tuple[str, dict]:
        # Gemini API endpoint
        url = f"https://generativelanguage.googleapis.com/v1beta/models/{self.model}:generateContent?key={self.api_key}"
        headers = {"Content-Type": "application/json"}

        payload: dict[str, Any] = {
            "contents": [{"role": "user", "parts": [{"text": f"{system_prompt}\n\n{user_prompt}"}]}],
            "generationConfig": {
                "temperature": temperature,
                "maxOutputTokens": max_output_tokens,
            },
        }
        if json_mode:
            payload["generationConfig"]["responseMimeType"] = "application/json"

        async with scryer_http.async_client(timeout=timeout_s, retries=0) as client:
            resp = await client.post(url, headers=headers, json=payload)
            resp.raise_for_status()
            data = resp.json()
            # Extract content from Gemini response
            candidates = data.get("candidates", [])
            content = ""
            finish_reason = ""
            if candidates:
                parts = candidates[0].get("content", {}).get("parts", [])
                content = "".join(p.get("text", "") for p in parts)
                finish_reason = candidates[0].get("finishReason", "") or ""
            usage_meta = data.get("usageMetadata", {})
            return content, {
                "prompt_tokens": usage_meta.get("promptTokenCount", 0),
                "completion_tokens": usage_meta.get("candidatesTokenCount", 0),
                "truncated": finish_reason == "MAX_TOKENS",
            }

    async def continue_completion(
        self,
        *,
        system_prompt: str,
        user_prompt: str,
        prior_assistant: str,
        temperature: float = 0.1,
        max_output_tokens: int = 4000,
        timeout_s: float = 180.0,
        json_mode: bool = True,
    ) -> tuple[str, dict]:
        """Resume by sending [user, model(prior), user(continue)] in contents.

        Gemini's role for the assistant is ``"model"``. We disable
        ``responseMimeType`` for the continuation because the partial output
        alone isn't valid JSON and Gemini rejects it under JSON mode.
        """
        # responseMimeType="application/json" rejects continuations (partial
        # alone is not valid JSON), so we ignore json_mode for this path.
        del json_mode
        url = f"https://generativelanguage.googleapis.com/v1beta/models/{self.model}:generateContent?key={self.api_key}"
        headers = {"Content-Type": "application/json"}
        payload: dict[str, Any] = {
            "contents": [
                {"role": "user", "parts": [{"text": f"{system_prompt}\n\n{user_prompt}"}]},
                {"role": "model", "parts": [{"text": prior_assistant}]},
                {
                    "role": "user",
                    "parts": [{"text": (
                        "Continue your previous response from EXACTLY where you stopped. "
                        "Do not repeat any prior content. Output only the next characters of the JSON."
                    )}],
                },
            ],
            "generationConfig": {
                "temperature": temperature,
                "maxOutputTokens": max_output_tokens,
            },
        }
        async with scryer_http.async_client(timeout=timeout_s, retries=0) as client:
            resp = await client.post(url, headers=headers, json=payload)
            resp.raise_for_status()
            data = resp.json()
            candidates = data.get("candidates", [])
            content = ""
            finish_reason = ""
            if candidates:
                parts = candidates[0].get("content", {}).get("parts", [])
                content = "".join(p.get("text", "") for p in parts)
                finish_reason = candidates[0].get("finishReason", "") or ""
            usage_meta = data.get("usageMetadata", {})
            return content, {
                "prompt_tokens": usage_meta.get("promptTokenCount", 0),
                "completion_tokens": usage_meta.get("candidatesTokenCount", 0),
                "truncated": finish_reason == "MAX_TOKENS",
            }

    async def chat_completion_stream(
        self,
        *,
        system_prompt: str,
        user_prompt: str,
        temperature: float = 0.1,
        max_output_tokens: int = 4000,
        timeout_s: float = 180.0,
        json_mode: bool = True,
        on_usage: UsageCallback | None = None,
    ) -> AsyncIterator[str]:
        url = (
            f"https://generativelanguage.googleapis.com/v1beta/models/"
            f"{self.model}:streamGenerateContent?alt=sse&key={self.api_key}"
        )
        headers = {"Content-Type": "application/json"}
        payload: dict[str, Any] = {
            "contents": [{"role": "user", "parts": [{"text": f"{system_prompt}\n\n{user_prompt}"}]}],
            "generationConfig": {
                "temperature": temperature,
                "maxOutputTokens": max_output_tokens,
            },
        }
        if json_mode:
            payload["generationConfig"]["responseMimeType"] = "application/json"

        last_usage: dict | None = None

        async with (
            scryer_http.async_client(timeout=timeout_s, retries=0) as client,
            client.stream("POST", url, headers=headers, json=payload) as resp,
        ):
            resp.raise_for_status()
            async for line in resp.aiter_lines():
                if not line.startswith("data:"):
                    continue
                data = line[5:].strip()
                if not data:
                    continue
                try:
                    evt = json.loads(data)
                except json.JSONDecodeError:
                    continue
                # Gemini accumulates usageMetadata across stream chunks and
                # emits the final totals on the last event.
                meta = evt.get("usageMetadata")
                if meta:
                    last_usage = meta
                candidates = evt.get("candidates") or []
                if not candidates:
                    continue
                parts = candidates[0].get("content", {}).get("parts", [])
                chunk = "".join(p.get("text", "") for p in parts)
                if chunk:
                    yield chunk

        if on_usage and last_usage:
            on_usage(
                {
                    "prompt_tokens": int(last_usage.get("promptTokenCount", 0)),
                    "completion_tokens": int(last_usage.get("candidatesTokenCount", 0)),
                }
            )


# Provider registry
PROVIDERS: dict[str, type[LLMProvider]] = {
    "openai": OpenAIProvider,
    "claude": ClaudeProvider,
    "gemini": GeminiProvider,
}


def get_provider(
    name: str,
    *,
    api_key: str | None = None,
    model: str | None = None,
    base_url: str | None = None,
) -> LLMProvider:
    """
    Get an LLM provider by name.

    Args:
        name: Provider name (openai, claude, gemini)
        api_key: Optional API key override
        model: Optional model override
        base_url: Optional base URL override (OpenAI only)

    Returns:
        LLMProvider instance
    """
    name_lower = name.lower()
    if name_lower not in PROVIDERS:
        raise ValueError(f"Unknown provider: {name}. Available: {list(PROVIDERS.keys())}")

    provider_cls = PROVIDERS[name_lower]
    kwargs: dict[str, Any] = {}
    if api_key:
        kwargs["api_key"] = api_key
    if model:
        kwargs["model"] = model
    if base_url and name_lower == "openai":
        kwargs["base_url"] = base_url

    return provider_cls(**kwargs)
