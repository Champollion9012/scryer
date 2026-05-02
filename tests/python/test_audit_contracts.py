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
