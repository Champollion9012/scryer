"""Tests for audit_contracts pure helpers and the mocked end-to-end pipeline.

The LLM provider is mocked so these tests run offline. We validate:
  * pure helpers (chunking, file grouping, JSON parsing, retry classification, cache key)
  * the orchestration in main() across single-pass, map-reduce, cache-hit paths
"""

from __future__ import annotations

import json
from pathlib import Path

import httpx
import pytest

import audit_contracts as ac

# ---------------------------------------------------------------------------
# Pure helpers
# ---------------------------------------------------------------------------


def test_estimate_tokens_rough_is_proportional_to_length() -> None:
    assert ac.estimate_tokens_rough("") == 1
    assert ac.estimate_tokens_rough("a" * 4) == 1
    assert ac.estimate_tokens_rough("a" * 40) == 10


def test_estimate_cost_usd_returns_none_when_pricing_missing() -> None:
    assert ac.estimate_cost_usd(1000, 1000, price_in_per_1k=None, price_out_per_1k=None) is None


def test_estimate_cost_usd_computes_total() -> None:
    cost = ac.estimate_cost_usd(2000, 500, price_in_per_1k=0.10, price_out_per_1k=0.30)
    assert cost == pytest.approx(0.10 * 2 + 0.30 * 0.5)


@pytest.mark.parametrize(
    ("filename", "expected"),
    [
        ("56_0xAaBbCcDdEeFf00112233445566778899AaBbCcDd_Token.sol", (56, "0xaabbccddeeff00112233445566778899aabbccdd")),
        ("not_a_match.sol", None),
        ("1_0xshort_X.sol", None),
    ],
)
def test_extract_contract_key_from_filename(filename: str, expected) -> None:
    assert ac.extract_contract_key_from_filename(filename) == expected


def test_group_files_by_contract(tmp_path: Path) -> None:
    sources_root = tmp_path / "sources"
    a_dir = sources_root / ("56_0x" + "aa" * 20)
    b_dir = sources_root / ("1_0x" + "bb" * 20)
    a_dir.mkdir(parents=True)
    b_dir.mkdir(parents=True)
    files = [
        (a_dir / "Token.sol"),
        (a_dir / "Vault.sol"),
        (b_dir / "Strategy.sol"),
    ]
    for f in files:
        f.write_text("// noop")

    groups = ac.group_files(files, sources_root=sources_root, group_by="contract")
    assert len(groups) == 2
    a_key = f"56_0x{'aa' * 20}"
    b_key = f"1_0x{'bb' * 20}"
    assert sorted(p.name for p in groups[a_key]) == ["Token.sol", "Vault.sol"]
    assert [p.name for p in groups[b_key]] == ["Strategy.sol"]


def test_group_files_by_chain(tmp_path: Path) -> None:
    sources_root = tmp_path / "sources"
    a_dir = sources_root / ("56_0x" + "aa" * 20)
    b_dir = sources_root / ("1_0x" + "bb" * 20)
    a_dir.mkdir(parents=True)
    b_dir.mkdir(parents=True)
    fa = a_dir / "X.sol"
    fb = b_dir / "Y.sol"
    fa.write_text("// a")
    fb.write_text("// b")

    groups = ac.group_files([fa, fb], sources_root=sources_root, group_by="chain")
    assert set(groups) == {"chain_56", "chain_1"}


def test_chunk_blocks_respects_max_chars() -> None:
    blocks = ["A" * 100, "B" * 100, "C" * 100]
    chunks = ac.chunk_blocks(blocks, max_chars=210)
    assert len(chunks) == 2
    assert "A" * 100 in chunks[0] and "B" * 100 in chunks[0]
    assert "C" * 100 in chunks[1]


def test_split_text_by_lines_keeps_lines_intact() -> None:
    text = "line1\nline2\nline3\n"
    parts = ac.split_text_by_lines(text, max_chars=10)
    rejoined = "\n".join(parts).replace("\n\n", "\n")
    assert "line1" in rejoined and "line2" in rejoined and "line3" in rejoined
    assert all(len(p) <= 12 for p in parts)  # small slack for line endings


def test_parse_json_response_strips_code_fences() -> None:
    raw = '```json\n{"a": 1}\n```'
    assert ac.parse_json_response(raw) == {"a": 1}


def test_parse_json_response_falls_back_to_brace_extraction() -> None:
    raw = 'Here is the report: {"k": 42} \nThanks!'
    assert ac.parse_json_response(raw) == {"k": 42}


def test_parse_json_response_raises_on_garbage() -> None:
    with pytest.raises(ValueError):
        ac.parse_json_response("not json at all")


def test_make_audit_cache_key_changes_with_model(tmp_path: Path) -> None:
    f = tmp_path / "X.sol"
    f.write_text("contract X {}")
    k1 = ac.make_audit_cache_key([f], model="gpt-4.1-mini", provider="openai")
    k2 = ac.make_audit_cache_key([f], model="claude-sonnet-4-6", provider="claude")
    k3 = ac.make_audit_cache_key([f], model="gpt-4.1-mini", provider="openai")
    assert k1 != k2  # model swap = different key
    assert k1 == k3  # deterministic


def test_make_audit_cache_key_changes_with_prompt_template(tmp_path: Path) -> None:
    """Editing an audit prompt template MUST invalidate cached answers.

    Same source + model + provider, but different prompt text = different
    instructions to the model = a different report. We hash the prompt files
    into the key so cached answers from before a prompt edit don't silently
    serve callers using the new prompt.
    """
    f = tmp_path / "X.sol"
    f.write_text("contract X {}")
    p1 = tmp_path / "audit_v1.txt"
    p1.write_text("Please audit this code.")
    p2 = tmp_path / "audit_v2.txt"
    p2.write_text("Please audit this code AND enumerate trusted-role threats.")

    k_v1 = ac.make_audit_cache_key([f], model="m", provider="p", prompt_files=[p1])
    k_v2 = ac.make_audit_cache_key([f], model="m", provider="p", prompt_files=[p2])
    k_v1_again = ac.make_audit_cache_key([f], model="m", provider="p", prompt_files=[p1])
    k_default = ac.make_audit_cache_key([f], model="m", provider="p")  # no prompt files
    assert k_v1 != k_v2, "different prompt content must produce different keys"
    assert k_v1 == k_v1_again, "same inputs must produce same key"
    assert k_v1 != k_default, "missing-prompt sentinel must not collide with hashed-prompt key"


def test_make_audit_cache_key_treats_missing_prompt_file_distinctly(tmp_path: Path) -> None:
    """A missing prompt file shouldn't collide with an empty-file prompt."""
    f = tmp_path / "X.sol"
    f.write_text("contract X {}")
    empty = tmp_path / "empty.txt"
    empty.write_text("")
    missing = tmp_path / "does-not-exist.txt"
    k_empty = ac.make_audit_cache_key([f], model="m", provider="p", prompt_files=[empty])
    k_missing = ac.make_audit_cache_key([f], model="m", provider="p", prompt_files=[missing])
    assert k_empty != k_missing


# ---------------------------------------------------------------------------
# Retry classification
# ---------------------------------------------------------------------------


def _make_status_error(status_code: int, retry_after: str | None = None) -> httpx.HTTPStatusError:
    request = httpx.Request("POST", "https://api.example/v1/chat")
    headers = {"Retry-After": retry_after} if retry_after else {}
    response = httpx.Response(status_code, request=request, headers=headers)
    return httpx.HTTPStatusError("boom", request=request, response=response)


def test_classify_retry_4xx_bails() -> None:
    retry, hint = ac._classify_retry(_make_status_error(400))
    assert retry is False and hint is None


def test_classify_retry_401_bails() -> None:
    retry, _ = ac._classify_retry(_make_status_error(401))
    assert retry is False


def test_classify_retry_429_with_retry_after() -> None:
    retry, hint = ac._classify_retry(_make_status_error(429, retry_after="12"))
    assert retry is True and hint == 12.0


def test_classify_retry_5xx_retries_without_hint() -> None:
    retry, hint = ac._classify_retry(_make_status_error(503))
    assert retry is True and hint is None


def test_classify_retry_transport_errors_retry() -> None:
    err = httpx.ConnectError("boom")
    retry, _ = ac._classify_retry(err)
    assert retry is True


# ---------------------------------------------------------------------------
# llm_chat_completion auto-continue
# ---------------------------------------------------------------------------


class _TruncatingFakeProvider:
    """Fake provider that returns truncated output the first N times,
    then a complete response. Records calls to chat_completion + continue_completion."""

    def __init__(self, *, truncate_for: int, parts: list[str]) -> None:
        # parts must have len(parts) == truncate_for + 1; first N are partial,
        # last one is the final piece (truncated=False).
        assert len(parts) == truncate_for + 1
        self.truncate_for = truncate_for
        self.parts = parts
        self.chat_calls: list[dict] = []
        self.continue_calls: list[dict] = []

    async def chat_completion(self, **kwargs):
        self.chat_calls.append(kwargs)
        return self.parts[0], {
            "prompt_tokens": 100,
            "completion_tokens": 50,
            "truncated": self.truncate_for > 0,
        }

    async def continue_completion(self, **kwargs):
        self.continue_calls.append(kwargs)
        idx = len(self.continue_calls)  # 1-based
        is_last = idx >= self.truncate_for
        return self.parts[idx], {
            "prompt_tokens": 80,
            "completion_tokens": 25,
            "truncated": not is_last,
        }


def test_llm_chat_completion_concatenates_after_truncation() -> None:
    """One truncated turn + one continuation = stitched response."""
    provider = _TruncatingFakeProvider(truncate_for=1, parts=['{"a":', '1}'])
    raw, usage = ac.llm_chat_completion(
        provider,
        system_prompt="sys",
        user_prompt="usr",
        temperature=0.1,
        max_output_tokens=500,
        timeout_s=30,
        max_retries=1,
        auto_continue_attempts=3,
    )
    assert raw == '{"a":1}'
    assert usage["continue_attempts"] == 1
    assert not usage["truncated"]
    # Tokens summed across the original + continuation
    assert usage["prompt_tokens"] == 180
    assert usage["completion_tokens"] == 75
    assert len(provider.continue_calls) == 1
    # Continuation was given the prior partial as prior_assistant
    assert provider.continue_calls[0]["prior_assistant"] == '{"a":'


def test_llm_chat_completion_caps_continue_attempts() -> None:
    """Provider keeps returning truncated; loop must stop at the configured cap."""
    parts = ['{"a":', '1,', '"b":', "2}"]  # 3 trunc + 1 final = 4 parts
    provider = _TruncatingFakeProvider(truncate_for=3, parts=parts)
    raw, usage = ac.llm_chat_completion(
        provider,
        system_prompt="sys",
        user_prompt="usr",
        temperature=0.1,
        max_output_tokens=500,
        timeout_s=30,
        max_retries=1,
        auto_continue_attempts=2,  # below the 3 needed to fully recover
    )
    # Only 2 continuations consumed → stitched first 3 parts
    assert raw == '{"a":1,"b":'
    assert usage["continue_attempts"] == 2
    # Last continuation reported truncated=True (we hit the cap, not the end)
    assert usage["truncated"] is True
    assert len(provider.continue_calls) == 2


def test_llm_chat_completion_skips_continue_when_disabled() -> None:
    """auto_continue_attempts=0 must NOT call continue_completion even if truncated."""
    provider = _TruncatingFakeProvider(truncate_for=1, parts=['{"a":', '1}'])
    raw, usage = ac.llm_chat_completion(
        provider,
        system_prompt="sys",
        user_prompt="usr",
        temperature=0.1,
        max_output_tokens=500,
        timeout_s=30,
        max_retries=1,
        auto_continue_attempts=0,
    )
    # First call returns the truncated piece; we hand it back as-is.
    assert raw == '{"a":'
    assert usage["truncated"] is True
    assert usage["continue_attempts"] == 0
    assert provider.continue_calls == []


def test_llm_chat_completion_skips_continue_when_not_truncated() -> None:
    """A non-truncated first call short-circuits — no continue_completion call."""
    provider = _TruncatingFakeProvider(truncate_for=0, parts=['{"a":1}'])
    raw, usage = ac.llm_chat_completion(
        provider,
        system_prompt="sys",
        user_prompt="usr",
        temperature=0.1,
        max_output_tokens=500,
        timeout_s=30,
        max_retries=1,
        auto_continue_attempts=3,
    )
    assert raw == '{"a":1}'
    assert usage["continue_attempts"] == 0
    assert provider.continue_calls == []


# ---------------------------------------------------------------------------
# RateLimiter under threads
# ---------------------------------------------------------------------------


def test_rate_limiter_zero_rpm_is_noop() -> None:
    rl = ac.RateLimiter(rpm=None)
    rl.wait()  # should not raise / sleep


def test_rate_limiter_thread_safe_spacing() -> None:
    import threading
    import time

    rl = ac.RateLimiter(rpm=600.0)  # 100ms apart
    slots: list[float] = []

    def hit() -> None:
        rl.wait()
        slots.append(time.time())

    threads = [threading.Thread(target=hit) for _ in range(4)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    diffs = [b - a for a, b in zip(sorted(slots)[:-1], sorted(slots)[1:], strict=True)]
    # Each diff should be ~100ms — tolerate scheduler jitter on Windows CI.
    assert all(d >= 0.08 for d in diffs), f"unexpected diffs: {diffs}"


# ---------------------------------------------------------------------------
# End-to-end main() with a fake provider
# ---------------------------------------------------------------------------


class _FakeProvider:
    """Records calls and returns canned JSON responses.

    Per-prompt routing: the audit prompt template marks the chunked / reduce
    paths with distinctive substrings — we look for them so a single fake
    provider can serve both single-pass and map-reduce flows.
    """

    name = "fake:test"

    def __init__(self, *, single_pass: dict, map_chunk: dict | None = None, reduce: dict | None = None) -> None:
        self.single_pass = single_pass
        self.map_chunk = map_chunk
        self.reduce = reduce
        self.calls: list[dict] = []

    async def chat_completion(self, *, system_prompt, user_prompt, **_) -> tuple[str, dict]:
        self.calls.append({"system": system_prompt, "user": user_prompt})
        if "merge them into a final professional audit" in user_prompt or "<<CHUNK_FINDINGS>>" in user_prompt:
            return json.dumps(self.reduce or self.single_pass), {"prompt_tokens": 50, "completion_tokens": 30}
        if "CHUNK " in user_prompt or "$CHUNK_ID" in user_prompt:
            return json.dumps(self.map_chunk or {"chunk_id": 1, "findings": []}), {
                "prompt_tokens": 40,
                "completion_tokens": 20,
            }
        return json.dumps(self.single_pass), {"prompt_tokens": 100, "completion_tokens": 50}


@pytest.fixture
def fake_provider(monkeypatch):
    """Install a fake provider in place of the real ones."""
    sample_report = {
        "scope": {"chain_id": 56, "address": "0x" + "aa" * 20, "files": ["X.sol"]},
        "executive_summary": "All clear.",
        "findings": [],
    }
    fake = _FakeProvider(single_pass=sample_report, map_chunk={"chunk_id": 1, "findings": []}, reduce=sample_report)
    monkeypatch.setattr(ac, "get_provider", lambda *a, **kw: fake)
    return fake


def _seed_sources(tmp_path: Path, *, big: bool = False) -> Path:
    sources_root = tmp_path / "sources"
    contract_dir = sources_root / ("56_0x" + "aa" * 20)
    contract_dir.mkdir(parents=True)
    code = "// noop\ncontract X {}"
    if big:
        code += "\n// padding\n" + ("// fill\n" * 50000)  # ~400KB to force map-reduce
    (contract_dir / "X.sol").write_text(code)
    return sources_root


def _run_audit(tmp_path: Path, sources_root: Path, *extra_args: str) -> Path:
    out_dir = tmp_path / "out"
    sys_argv = [
        "audit_contracts.py",
        "--sources-dir",
        str(sources_root),
        "--out-dir",
        str(out_dir),
        "--no-cache",  # tests opt in to caching individually
        "--retries",
        "1",
        *extra_args,
    ]

    import argparse
    import sys as _sys

    old = _sys.argv
    _sys.argv = sys_argv
    try:
        rc = ac.main()
    finally:
        _sys.argv = old
    assert rc == 0, "main() failed"
    return out_dir


def test_main_single_pass_writes_expected_artifacts(tmp_path: Path, fake_provider) -> None:
    sources_root = _seed_sources(tmp_path)
    out_dir = _run_audit(tmp_path, sources_root, "--disable-regex-scan")
    runs = list(out_dir.glob("run_*"))
    assert len(runs) == 1
    run_dir = runs[0]
    manifest = json.loads((run_dir / "manifest.json").read_text())
    assert len(manifest["groups"]) == 1
    group = manifest["groups"][0]
    assert group["mode"] == "single_pass"
    assert group["calls"] == 1
    # Each artifact written
    group_dir = run_dir / group["dir"]
    for name in ("report.md", "report.json", "files.md", "analysis.json", "calls.json", "chunks.json"):
        assert (group_dir / name).exists(), f"missing {name}"
    assert "Executive Summary" in (group_dir / "report.md").read_text(encoding="utf-8")


def test_main_map_reduce_path(tmp_path: Path, fake_provider) -> None:
    sources_root = _seed_sources(tmp_path, big=True)
    # Force map-reduce regardless of size to make the test fast
    out_dir = _run_audit(
        tmp_path,
        sources_root,
        "--disable-regex-scan",
        "--force-map-reduce",
        "--max-chunk-chars",
        "2000",
        "--max-input-chars",
        "1500",
    )
    run_dir = next(out_dir.glob("run_*"))
    group = json.loads((run_dir / "manifest.json").read_text())["groups"][0]
    assert group["mode"] == "map_reduce"
    assert group["calls"] >= 2  # at least one map + one reduce
    # Multiple map prompts written + one reduce prompt
    prompts = list((run_dir / group["dir"] / "prompts").glob("*.txt"))
    assert any("reduce" in p.name for p in prompts)
    assert any("map_prompt" in p.name for p in prompts)


def test_main_cache_hit_skips_provider(tmp_path: Path, fake_provider, monkeypatch) -> None:
    sources_root = _seed_sources(tmp_path)
    # AuditCache() defaults to ``.audit_cache.db`` in CWD; chdir keeps the test
    # cache off the real filesystem and lets both runs share it.
    monkeypatch.chdir(tmp_path)
    out_dir = tmp_path / "out"
    run_a = out_dir / "run_a"
    run_b = out_dir / "run_b"

    def _argv(run_dir: Path) -> list[str]:
        return [
            "audit_contracts.py",
            "--sources-dir",
            str(sources_root),
            "--out-dir",
            str(out_dir),
            "--run-dir",
            str(run_dir),
            "--retries",
            "1",
            "--disable-regex-scan",
        ]

    import sys as _sys

    old = _sys.argv
    try:
        _sys.argv = _argv(run_a)
        ac.main()  # populate cache
        first_calls = len(fake_provider.calls)
        _sys.argv = _argv(run_b)
        ac.main()  # second run should hit cache
        second_calls_delta = len(fake_provider.calls) - first_calls
    finally:
        _sys.argv = old

    # Second run should not have hit the provider at all.
    assert first_calls == 1
    assert second_calls_delta == 0

    # The second run's manifest should label the group cache_hit.
    second_manifest = json.loads((run_b / "manifest.json").read_text())
    assert second_manifest["groups"][0]["mode"] == "cache_hit"
    assert second_manifest["groups"][0]["calls"] == 0


# ---------------------------------------------------------------------------
# llm_chat_completion retry/bail logic (pure, no real network)
# ---------------------------------------------------------------------------


class _FailingProvider:
    name = "fake:fail"

    def __init__(self, error: BaseException) -> None:
        self.error = error
        self.attempts = 0

    async def chat_completion(self, **_) -> tuple[str, dict]:
        self.attempts += 1
        raise self.error


def test_llm_chat_completion_bails_immediately_on_4xx() -> None:
    err = _make_status_error(400)
    p = _FailingProvider(err)
    with pytest.raises(RuntimeError, match="non-retryable"):
        ac.llm_chat_completion(
            p,
            system_prompt="s",
            user_prompt="u",
            temperature=0.1,
            max_output_tokens=10,
            timeout_s=1,
            max_retries=5,
        )
    assert p.attempts == 1, "4xx should not retry"


def test_llm_chat_completion_retries_on_5xx_until_max() -> None:
    err = _make_status_error(503)
    p = _FailingProvider(err)
    with pytest.raises(RuntimeError, match="failed after"):
        ac.llm_chat_completion(
            p,
            system_prompt="s",
            user_prompt="u",
            temperature=0.1,
            max_output_tokens=10,
            timeout_s=1,
            max_retries=2,
        )
    assert p.attempts == 2


# ---------------------------------------------------------------------------
# dedupe_findings_across_chunks
# ---------------------------------------------------------------------------


def test_dedupe_keeps_first_and_merges_locations() -> None:
    chunks = [
        {
            "chunk_id": 1,
            "findings": [
                {
                    "id": "F-01",
                    "title": "Reentrancy",
                    "affected_component": "Vault.withdraw",
                    "locations": [{"file": "Vault.sol", "line": 10}],
                }
            ],
        },
        {
            "chunk_id": 2,
            "findings": [
                {
                    "id": "F-02",
                    "title": "REENTRANCY",  # same title, different case
                    "affected_component": "vault.withdraw",  # same component, diff case
                    "locations": [{"file": "Vault.sol", "line": 42}],
                }
            ],
        },
    ]
    out = ac.dedupe_findings_across_chunks(chunks)
    assert len(out) == 1
    locs = out[0]["locations"]
    assert {"file": "Vault.sol", "line": 10} in locs
    assert {"file": "Vault.sol", "line": 42} in locs


def test_dedupe_preserves_distinct_findings() -> None:
    chunks = [
        {"findings": [{"title": "A", "affected_component": "X"}]},
        {"findings": [{"title": "B", "affected_component": "X"}]},
    ]
    out = ac.dedupe_findings_across_chunks(chunks)
    assert len(out) == 2


def test_dedupe_keeps_unrelated_titleless_findings() -> None:
    """Findings without a title can't be safely deduped — keep them all."""
    chunks = [
        {"findings": [{"affected_component": "X"}]},
        {"findings": [{"affected_component": "X"}]},
    ]
    out = ac.dedupe_findings_across_chunks(chunks)
    assert len(out) == 2


def test_dedupe_handles_malformed_inputs() -> None:
    chunks = [
        "not a dict",  # type: ignore[list-item]
        {"findings": "not a list"},
        {"findings": [None, "garbage", {"title": "OK", "affected_component": "X"}]},  # type: ignore[list-item]
    ]
    out = ac.dedupe_findings_across_chunks(chunks)  # type: ignore[arg-type]
    assert len(out) == 1
    assert out[0]["title"] == "OK"


# ---------------------------------------------------------------------------
# Streaming + on_usage callback (default impl falls back to non-streaming)
# ---------------------------------------------------------------------------


def test_llm_chat_completion_stream_captures_usage() -> None:
    """The default streaming path forwards usage from chat_completion to on_usage."""
    import asyncio

    class _StreamProvider:
        name = "fake:stream"

        async def chat_completion(self, **_):
            return '{"k": 1}', {"prompt_tokens": 17, "completion_tokens": 9}

        # Provider-defined stream that emits text and reports usage exactly
        # like the LLMProvider default impl does.
        async def chat_completion_stream(self, *, on_usage=None, **_):
            content, usage = await self.chat_completion()
            if on_usage and usage:
                on_usage(usage)
            yield content

    p = _StreamProvider()
    content, usage = ac.llm_chat_completion(
        p,
        system_prompt="s",
        user_prompt="u",
        temperature=0.1,
        max_output_tokens=10,
        timeout_s=1,
        max_retries=1,
        stream=True,
    )
    assert content == '{"k": 1}'
    assert usage == {"prompt_tokens": 17, "completion_tokens": 9}
    # Sanity: a fresh asyncio loop didn't leak
    assert asyncio.get_event_loop_policy() is not None


# ---------------------------------------------------------------------------
# --estimate-cost: walks groups, prints, exits without provider calls
# ---------------------------------------------------------------------------


def test_estimate_cost_prints_total_and_skips_provider(
    tmp_path: Path, fake_provider, capsys: pytest.CaptureFixture
) -> None:
    sources_root = _seed_sources(tmp_path)
    out_dir = tmp_path / "out"
    sys_argv = [
        "audit_contracts.py",
        "--sources-dir",
        str(sources_root),
        "--out-dir",
        str(out_dir),
        "--no-cache",
        "--retries",
        "1",
        "--disable-regex-scan",
        "--estimate-cost",
        "--price-in-per-1k",
        "0.10",
        "--price-out-per-1k",
        "0.30",
    ]
    import sys as _sys

    old = _sys.argv
    _sys.argv = sys_argv
    try:
        rc = ac.main()
    finally:
        _sys.argv = old

    assert rc == 0
    captured = capsys.readouterr().out
    assert "Cost estimate" in captured
    assert "TOTAL input tokens" in captured
    assert "Projected cost:" in captured
    assert "$" in captured  # pricing was provided
    # Provider must not have been touched
    assert fake_provider.calls == []
    # No run directory should exist either
    assert list(out_dir.glob("run_*")) == []


def test_estimate_cost_without_pricing_skips_dollar_amount(tmp_path: Path, fake_provider, capsys) -> None:
    sources_root = _seed_sources(tmp_path)
    sys_argv = [
        "audit_contracts.py",
        "--sources-dir",
        str(sources_root),
        "--out-dir",
        str(tmp_path / "out"),
        "--no-cache",
        "--retries",
        "1",
        "--disable-regex-scan",
        "--estimate-cost",
    ]
    import sys as _sys

    old = _sys.argv
    _sys.argv = sys_argv
    try:
        rc = ac.main()
    finally:
        _sys.argv = old
    assert rc == 0
    captured = capsys.readouterr().out
    assert "Projected cost:" in captured
    assert "(set --price-in-per-1k" in captured


# ---------------------------------------------------------------------------
# --regex-rules: custom rule file is loaded and appended to defaults
# ---------------------------------------------------------------------------


def test_regex_rules_flag_appends_custom_rules(tmp_path: Path, fake_provider) -> None:
    """A custom rule file fires alongside built-ins; analysis.json records it."""
    # Vulnerable contract: contains a synthetic pattern only the custom rule catches.
    sources_root = tmp_path / "sources"
    contract_dir = sources_root / ("56_0x" + "aa" * 20)
    contract_dir.mkdir(parents=True)
    (contract_dir / "X.sol").write_text(
        "contract X {\n"
        "    function batchClaim(address[] calldata receivers, uint256[] calldata amounts) external {\n"
        "        for (uint256 i; i < receivers.length; ++i) {\n"
        "            IERC20(token).transfer(receivers[i], amounts[i]);\n"
        "        }\n"
        "    }\n"
        "}\n",
        encoding="utf-8",
    )

    rules_path = tmp_path / "custom.json"
    rules_path.write_text(
        json.dumps(
            [
                {
                    "rule_id": "CUSTOM_BATCH_RECV",
                    "severity": "High",
                    "title": "loop-indexed receiver transfer",
                    "pattern": r"\.transfer\s*\(\s*receivers\[",
                }
            ]
        ),
        encoding="utf-8",
    )

    out_dir = _run_audit(tmp_path, sources_root, "--regex-rules", str(rules_path))
    run_dir = next(out_dir.glob("run_*"))
    group = json.loads((run_dir / "manifest.json").read_text())["groups"][0]
    analysis = json.loads((run_dir / group["dir"] / "analysis.json").read_text())
    assert analysis["regex_scan"]["custom_rule_files"] == [str(rules_path)]
    finding_ids = {f["rule_id"] for f in analysis["regex_scan"]["findings"]}
    # Custom rule fired
    assert "CUSTOM_BATCH_RECV" in finding_ids
    # Built-in rules still active (UNSAFE_TRANSFER catches `.transfer(`)
    assert any(rid in finding_ids for rid in ("UNSAFE_TRANSFER", "DOS_UNBOUNDED_LOOP"))


def test_regex_rules_bad_path_warns_but_does_not_crash(tmp_path: Path, fake_provider) -> None:
    """Invalid rules path must not abort the audit — warn and proceed with defaults."""
    sources_root = _seed_sources(tmp_path)
    out_dir = _run_audit(tmp_path, sources_root, "--regex-rules", str(tmp_path / "missing.json"))
    run_dir = next(out_dir.glob("run_*"))
    group = json.loads((run_dir / "manifest.json").read_text())["groups"][0]
    analysis = json.loads((run_dir / group["dir"] / "analysis.json").read_text())
    # File didn't load -> custom_rule_files key absent
    assert "custom_rule_files" not in analysis["regex_scan"]
    # But scan still ran with defaults
    assert "findings" in analysis["regex_scan"]


# ---------------------------------------------------------------------------
# --source-verify: pre-audit bytecode comparison wiring
# ---------------------------------------------------------------------------


def _stub_verify(verdict: str, **extra):
    """Build a stub for verify_contract that returns a canned VerifyResult."""
    from verify_source import VerifyResult

    def _fake(chain_id, address, **kwargs):
        return VerifyResult(
            verdict=verdict,
            chain_id=chain_id,
            address=address.lower(),
            compiler_version="0.8.20+commit.fake",
            on_chain_size=extra.get("on_chain_size", 100),
            compiled_size=extra.get("compiled_size", 100),
            notes=extra.get("notes", []),
        )

    return _fake


def test_source_verify_off_skips_verification(tmp_path: Path, fake_provider, monkeypatch) -> None:
    sources_root = _seed_sources(tmp_path)
    called = []
    monkeypatch.setattr(ac, "verify_contract", lambda *a, **kw: called.append(1) or _stub_verify("full_match")(*a, **kw))

    out_dir = _run_audit(tmp_path, sources_root, "--disable-regex-scan")
    run_dir = next(out_dir.glob("run_*"))
    group = json.loads((run_dir / "manifest.json").read_text())["groups"][0]
    analysis = json.loads((run_dir / group["dir"] / "analysis.json").read_text())

    assert called == []  # verify_contract never invoked
    assert "source_verify" not in analysis


def test_source_verify_warn_records_verdict_in_analysis(tmp_path: Path, fake_provider, monkeypatch) -> None:
    sources_root = _seed_sources(tmp_path)
    monkeypatch.setattr(ac, "verify_contract", _stub_verify("partial_match", notes=["trailer differs"]))

    out_dir = _run_audit(tmp_path, sources_root, "--disable-regex-scan", "--source-verify", "warn")
    run_dir = next(out_dir.glob("run_*"))
    group = json.loads((run_dir / "manifest.json").read_text())["groups"][0]
    analysis = json.loads((run_dir / group["dir"] / "analysis.json").read_text())

    sv = analysis["source_verify"]
    assert sv["verdict"] == "partial_match"
    assert sv["compiler_version"] == "0.8.20+commit.fake"
    assert "trailer differs" in sv["notes"]


def test_source_verify_warn_proceeds_on_mismatch(tmp_path: Path, fake_provider, monkeypatch) -> None:
    """warn: log + record but still produce an audit report."""
    sources_root = _seed_sources(tmp_path)
    monkeypatch.setattr(ac, "verify_contract", _stub_verify("mismatch", notes=["first byte differs at 4/100"]))

    out_dir = _run_audit(tmp_path, sources_root, "--disable-regex-scan", "--source-verify", "warn")
    run_dir = next(out_dir.glob("run_*"))
    manifest = json.loads((run_dir / "manifest.json").read_text())
    # Group still in manifest (audit ran)
    assert len(manifest["groups"]) == 1
    sv = json.loads((run_dir / manifest["groups"][0]["dir"] / "analysis.json").read_text())["source_verify"]
    assert sv["verdict"] == "mismatch"


def test_source_verify_strict_aborts_on_mismatch(tmp_path: Path, fake_provider, monkeypatch) -> None:
    """strict: mismatch returns None from _audit_one_group; group not in manifest."""
    sources_root = _seed_sources(tmp_path)
    monkeypatch.setattr(ac, "verify_contract", _stub_verify("mismatch", notes=["forensic divergence"]))

    out_dir = _run_audit(
        tmp_path, sources_root, "--disable-regex-scan", "--source-verify", "strict", "--no-verify-cache"
    )
    run_dir = next(out_dir.glob("run_*"))
    manifest = json.loads((run_dir / "manifest.json").read_text())
    # Group should not be in `groups` (aborted) but tracked in `aborted_groups`
    assert manifest["groups"] == []
    assert manifest["totals"]["aborted_by_source_verify"] == 1
    assert len(manifest["aborted_groups"]) == 1
    aborted = manifest["aborted_groups"][0]
    assert aborted["reason"] == "source_verify_mismatch"
    assert aborted["verdict"] == "mismatch"
    assert "forensic divergence" in aborted["notes"]
    # Group key should be preserved for traceability
    assert aborted["key"].startswith("56_0x")


def test_source_verify_skipped_when_address_unknown(tmp_path: Path, fake_provider, monkeypatch) -> None:
    """Group keyed without chain_id+address (e.g. group_by=all) records skipped reason."""
    sources_root = _seed_sources(tmp_path)
    called = []
    monkeypatch.setattr(ac, "verify_contract", lambda *a, **kw: called.append(1) or _stub_verify("full_match")(*a, **kw))

    out_dir = _run_audit(
        tmp_path, sources_root, "--disable-regex-scan", "--source-verify", "warn", "--group-by", "all"
    )
    run_dir = next(out_dir.glob("run_*"))
    group = json.loads((run_dir / "manifest.json").read_text())["groups"][0]
    analysis = json.loads((run_dir / group["dir"] / "analysis.json").read_text())

    assert called == []  # not called because chain_id/address weren't extractable
    assert analysis["source_verify"]["verdict"] == "skipped"


def test_partial_match_injects_llm_hint(tmp_path: Path, fake_provider, monkeypatch) -> None:
    """partial_match prepends a behavioural-equivalence note to the LLM context.

    The hint must reach the saved prompt files (so the LLM literally sees it).
    """
    sources_root = _seed_sources(tmp_path)
    monkeypatch.setattr(ac, "verify_contract", _stub_verify("partial_match", notes=["trailer differs"]))

    out_dir = _run_audit(
        tmp_path, sources_root, "--disable-regex-scan", "--source-verify", "warn", "--no-verify-cache"
    )
    run_dir = next(out_dir.glob("run_*"))
    group = json.loads((run_dir / "manifest.json").read_text())["groups"][0]

    # The prompt(s) saved to disk must contain the hint
    prompts_dir = run_dir / group["dir"] / "prompts"
    prompt_files = list(prompts_dir.glob("*.txt"))
    assert prompt_files, "no prompt files written"
    combined = "\n".join(p.read_text(encoding="utf-8") for p in prompt_files)
    assert "[source_verify hint]" in combined
    assert "byte-for-byte identical" in combined
    assert "Variable names" in combined


def test_mismatch_warn_injects_stronger_hint(tmp_path: Path, fake_provider, monkeypatch) -> None:
    """mismatch (warn mode) needs a stronger WARNING hint, not the partial_match wording."""
    sources_root = _seed_sources(tmp_path)
    monkeypatch.setattr(ac, "verify_contract", _stub_verify("mismatch", notes=["differs at index 4"]))

    out_dir = _run_audit(
        tmp_path, sources_root, "--disable-regex-scan", "--source-verify", "warn", "--no-verify-cache"
    )
    run_dir = next(out_dir.glob("run_*"))
    group = json.loads((run_dir / "manifest.json").read_text())["groups"][0]
    prompts_dir = run_dir / group["dir"] / "prompts"
    combined = "\n".join(p.read_text(encoding="utf-8") for p in prompts_dir.glob("*.txt"))
    assert "[source_verify hint] WARNING" in combined
    assert "may have been altered" in combined
    # Must NOT also include the partial_match wording — only one hint
    assert "byte-for-byte identical" not in combined


def test_full_match_does_not_inject_hint(tmp_path: Path, fake_provider, monkeypatch) -> None:
    """full_match is the happy path — no prompt pollution."""
    sources_root = _seed_sources(tmp_path)
    monkeypatch.setattr(ac, "verify_contract", _stub_verify("full_match"))

    out_dir = _run_audit(
        tmp_path, sources_root, "--disable-regex-scan", "--source-verify", "warn", "--no-verify-cache"
    )
    run_dir = next(out_dir.glob("run_*"))
    group = json.loads((run_dir / "manifest.json").read_text())["groups"][0]
    prompts_dir = run_dir / group["dir"] / "prompts"
    combined = "\n".join(p.read_text(encoding="utf-8") for p in prompts_dir.glob("*.txt"))
    assert "[source_verify hint]" not in combined


def test_verify_cache_passed_when_enabled(tmp_path: Path, fake_provider, monkeypatch) -> None:
    """audit_contracts must pass a non-None VerifyCache to verify_contract by default.

    End-to-end cache HIT is exercised in test_verify_source.test_verify_contract_uses_cache_on_hit;
    here we just check the wiring: did audit_contracts plumb the cache through?
    """
    sources_root = _seed_sources(tmp_path)
    monkeypatch.chdir(tmp_path)
    captured: dict = {}

    def _capture(*a, **kw):
        captured["cache"] = kw.get("cache")
        return _stub_verify("full_match")(*a, **kw)

    monkeypatch.setattr(ac, "verify_contract", _capture)
    _run_audit(tmp_path, sources_root, "--disable-regex-scan", "--source-verify", "warn")

    from verify_source import VerifyCache as _VC
    assert isinstance(captured["cache"], _VC), "default behaviour must pass a VerifyCache"
    # And the SQLite file must have been created at the default path
    assert (tmp_path / ".verify_cache.db").exists()


def test_no_verify_cache_flag_disables_persistence(tmp_path: Path, fake_provider, monkeypatch) -> None:
    """--no-verify-cache must not create the SQLite file."""
    sources_root = _seed_sources(tmp_path)
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(ac, "verify_contract", _stub_verify("partial_match"))

    _run_audit(
        tmp_path, sources_root, "--disable-regex-scan", "--source-verify", "warn", "--no-verify-cache"
    )
    assert not (tmp_path / ".verify_cache.db").exists()


def test_source_verify_exception_does_not_crash_audit(tmp_path: Path, fake_provider, monkeypatch) -> None:
    sources_root = _seed_sources(tmp_path)

    def _boom(*a, **kw):
        raise RuntimeError("rpc died")

    monkeypatch.setattr(ac, "verify_contract", _boom)
    out_dir = _run_audit(tmp_path, sources_root, "--disable-regex-scan", "--source-verify", "warn")
    run_dir = next(out_dir.glob("run_*"))
    group = json.loads((run_dir / "manifest.json").read_text())["groups"][0]
    analysis = json.loads((run_dir / group["dir"] / "analysis.json").read_text())
    assert analysis["source_verify"]["verdict"] == "error"
    assert "rpc died" in analysis["source_verify"]["error"]
