#!/usr/bin/env python3
from __future__ import annotations

import argparse
import asyncio
import datetime as dt
import hashlib
import json
import os
import random
import re
import threading
import time
from collections.abc import Iterable
from pathlib import Path
from string import Template

import httpx

import scryer_config
from cache import AuditCache
from llm_providers import get_provider
from report_renderer import render_markdown
from scanners import DEFAULT_REGEX_RULES, RegexRule, load_rules_from_file, run_regex_scan, run_slither
from scryer_logging import get_logger
from verify_source import VerifyCache, verify_contract

_log = get_logger(__name__)

DEFAULT_SOURCES_DIR = "sources"
DEFAULT_OUTPUT_DIR = "audit_reports"
DEFAULT_AUDIT_PROMPT_PATH = Path(__file__).with_name("prompts").joinpath("solidity_audit_json_prompt.txt")
DEFAULT_MAP_PROMPT_PATH = Path(__file__).with_name("prompts").joinpath("solidity_map_prompt.txt")
DEFAULT_REDUCE_PROMPT_PATH = Path(__file__).with_name("prompts").joinpath("solidity_reduce_prompt.txt")
DEFAULT_MODEL = "gpt-4.1-mini"

CONTRACT_FILE_RE = re.compile(r"^(?P<chain_id>\d+)_0x(?P<address>[0-9a-fA-F]{40})_")
CONTRACT_DIR_RE = re.compile(r"^(?P<chain_id>\d+)_0x(?P<address>[0-9a-fA-F]{40})$")


def estimate_tokens_rough(text: str) -> int:
    # Rough heuristic: ~4 chars per token for English-ish text.
    return max(1, (len(text) + 3) // 4)


def _float_env(name: str) -> float | None:
    raw = os.getenv(name)
    if raw is None or not raw.strip():
        return None
    try:
        return float(raw)
    except ValueError:
        return None


class RateLimiter:
    """Thread-safe leaky-bucket rate limiter.

    The slot reservation is done under a lock so concurrent threads see a
    consistent ``_next_ok_at``; the actual ``time.sleep`` happens outside the
    lock so threads that already hold reservations don't block each other.
    """

    def __init__(self, rpm: float | None):
        self.min_interval_s = (60.0 / rpm) if rpm and rpm > 0 else 0.0
        self._next_ok_at = 0.0
        self._lock = threading.Lock()

    def wait(self):
        if self.min_interval_s <= 0:
            return
        with self._lock:
            now = time.time()
            slot = max(now, self._next_ok_at)
            self._next_ok_at = slot + self.min_interval_s
            wait_s = slot - now
        if wait_s > 0:
            time.sleep(wait_s)


class AsyncRateLimiter:
    """Async-compatible rate limiter for parallel API calls."""

    def __init__(self, rpm: float | None):
        self.min_interval_s = (60.0 / rpm) if rpm and rpm > 0 else 0.0
        self._lock = asyncio.Lock()
        self._next_ok_at = 0.0

    async def wait(self):
        if self.min_interval_s <= 0:
            return
        async with self._lock:
            now = asyncio.get_event_loop().time()
            if self._next_ok_at > now:
                await asyncio.sleep(self._next_ok_at - now)
            self._next_ok_at = max(now, self._next_ok_at) + self.min_interval_s


def estimate_cost_usd(
    prompt_tokens: int, completion_tokens: int, *, price_in_per_1k: float | None, price_out_per_1k: float | None
) -> float | None:
    if price_in_per_1k is None or price_out_per_1k is None:
        return None
    return (prompt_tokens / 1000.0) * price_in_per_1k + (completion_tokens / 1000.0) * price_out_per_1k


def extract_contract_key_from_filename(filename: str) -> tuple[int, str] | None:
    match = CONTRACT_FILE_RE.match(filename)
    if not match:
        return None
    chain_id = int(match.group("chain_id"))
    address = "0x" + match.group("address").lower()
    return chain_id, address


def extract_contract_key_from_path(path: Path, sources_root: Path) -> tuple[int, str] | None:
    key = extract_contract_key_from_filename(path.name)
    if key:
        return key

    if sources_root in path.parents:
        rel = path.relative_to(sources_root)
        if rel.parts:
            match = CONTRACT_DIR_RE.match(rel.parts[0])
            if match:
                chain_id = int(match.group("chain_id"))
                address = "0x" + match.group("address").lower()
                return chain_id, address

    return None


def iter_solidity_files(root: Path) -> list[Path]:
    if not root.exists():
        return []
    return sorted([p for p in root.rglob("*.sol") if p.is_file()])


def group_files(paths: Iterable[Path], *, sources_root: Path, group_by: str) -> dict[str, list[Path]]:
    groups: dict[str, list[Path]] = {}

    for path in paths:
        if group_by == "all":
            key = "all"
        elif group_by == "file":
            key = path.name
        elif group_by == "chain":
            contract_key = extract_contract_key_from_path(path, sources_root)
            if contract_key:
                chain_id, _address = contract_key
                key = f"chain_{chain_id}"
            else:
                key = "misc"
        else:
            contract_key = extract_contract_key_from_path(path, sources_root)
            if contract_key:
                chain_id, address = contract_key
                key = f"{chain_id}_{address}"
            else:
                key = "misc"
        groups.setdefault(key, []).append(path)

    for key in groups:
        groups[key] = sorted(groups[key])
    return dict(sorted(groups.items(), key=lambda kv: kv[0]))


def read_text(path: Path) -> str:
    return path.read_text(encoding="utf-8", errors="replace")


def add_line_numbers(text: str, *, width: int = 6) -> str:
    lines = text.splitlines()
    out = []
    for i, line in enumerate(lines, start=1):
        out.append(f"{i:>{width}} | {line}")
    return "\n".join(out)


def split_text_by_lines(text: str, *, max_chars: int) -> list[str]:
    if len(text) <= max_chars:
        return [text]
    parts: list[str] = []
    current: list[str] = []
    current_len = 0
    for line in text.splitlines(keepends=True):
        if current and current_len + len(line) > max_chars:
            parts.append("".join(current).rstrip("\n"))
            current = []
            current_len = 0
        current.append(line)
        current_len += len(line)
    if current:
        parts.append("".join(current).rstrip("\n"))
    return parts


def build_file_blocks(
    files: list[Path],
    *,
    sources_root: Path,
    with_line_numbers: bool,
    max_block_chars: int,
) -> tuple[str, list[str]]:
    file_list_lines: list[str] = []
    blocks: list[str] = []

    for file_path in files:
        rel = file_path.relative_to(sources_root) if sources_root in file_path.parents else file_path
        rel_str = rel.as_posix()
        file_list_lines.append(f"- {rel_str}")

        content = read_text(file_path)
        if with_line_numbers:
            content = add_line_numbers(content)

        end_overhead = len("\n<<<<END FILE>>>>")
        part_header_overhead = len(f"<<<<FILE:{rel_str} PART 999/999>>>>\n")
        header_overhead = part_header_overhead + end_overhead
        available = max(1000, max_block_chars - header_overhead)
        parts = split_text_by_lines(content, max_chars=available)

        if len(parts) == 1:
            blocks.append(f"<<<<FILE:{rel_str}>>>>\n{parts[0]}\n<<<<END FILE>>>>")
        else:
            total = len(parts)
            for idx, part in enumerate(parts, start=1):
                blocks.append(f"<<<<FILE:{rel_str} PART {idx}/{total}>>>>\n{part}\n<<<<END FILE>>>>")

    files_md = "\n".join(file_list_lines) if file_list_lines else "- (none)"
    return files_md, blocks


def chunk_blocks(blocks: list[str], *, max_chars: int) -> list[str]:
    chunks: list[str] = []
    current: list[str] = []
    current_len = 0

    for block in blocks:
        block_len = len(block) + 2
        if current and current_len + block_len > max_chars:
            chunks.append("\n\n".join(current))
            current = []
            current_len = 0
        current.append(block)
        current_len += block_len

    if current:
        chunks.append("\n\n".join(current))

    return chunks


def load_prompt_template(prompt_path: Path) -> Template:
    if not prompt_path.exists():
        raise FileNotFoundError(f"Prompt template not found: {prompt_path}")
    return Template(read_text(prompt_path))


def _classify_retry(exc: BaseException) -> tuple[bool, float | None]:
    """Decide whether to retry an LLM call and how long to wait.

    Returns ``(retryable, hint_seconds)``:

    - 4xx (except 408 / 429): bail; the request is malformed or unauthenticated
      and retrying just burns money.
    - 408 (request timeout) and 429 (rate limit): retry; respect ``Retry-After``
      header when present.
    - 5xx and connection-level errors: retry with caller-supplied backoff.
    - Anything else: retry by default — better to be slow than lose work.
    """
    if isinstance(exc, httpx.HTTPStatusError):
        status = exc.response.status_code
        if status in (408, 429):
            ra = exc.response.headers.get("Retry-After")
            try:
                hint = float(ra) if ra is not None else None
            except ValueError:
                hint = None
            return True, hint
        if 400 <= status < 500:
            return False, None
        return True, None  # 5xx
    if isinstance(exc, (httpx.RequestError, asyncio.TimeoutError, TimeoutError)):
        return True, None
    # Unknown exception class — retry with default backoff (preserves current behaviour).
    return True, None


def llm_chat_completion(
    provider,
    *,
    system_prompt: str,
    user_prompt: str,
    temperature: float,
    max_output_tokens: int,
    timeout_s: float,
    max_retries: int,
    rate_limiter: RateLimiter | None = None,
    stream: bool = False,
    on_chunk: callable | None = None,
) -> tuple[str, dict]:
    """Run a single chat completion with retries.

    When ``stream=True``, the provider's streaming API is used and ``on_chunk``
    (if provided) is called with each text delta for live progress feedback.
    Usage tokens are not returned by the stream — callers fall back to the
    rough estimator when ``usage`` is empty.

    Errors are classified before retry: 4xx (other than 408/429) bail
    immediately so a malformed request doesn't burn ``max_retries`` worth of
    billable calls; 429 honours ``Retry-After``; 5xx and transport errors
    use exponential backoff with jitter.
    """
    last_error: str | None = None
    # Single shared usage dict so the streaming callback's closure isn't bound
    # to a per-iteration variable (silenced B023).
    captured_usage: dict = {}

    def _on_usage(u: dict) -> None:
        captured_usage.update(u)

    for attempt in range(1, max_retries + 1):
        try:
            if rate_limiter:
                rate_limiter.wait()

            if stream:
                captured_usage.clear()

                async def _consume() -> str:
                    parts: list[str] = []
                    async for chunk in provider.chat_completion_stream(
                        system_prompt=system_prompt,
                        user_prompt=user_prompt,
                        temperature=temperature,
                        max_output_tokens=max_output_tokens,
                        timeout_s=timeout_s,
                        json_mode=True,
                        on_usage=_on_usage,
                    ):
                        parts.append(chunk)
                        if on_chunk:
                            on_chunk(chunk)
                    return "".join(parts)

                content = asyncio.run(_consume())
                return content, dict(captured_usage)

            content, usage = asyncio.run(
                provider.chat_completion(
                    system_prompt=system_prompt,
                    user_prompt=user_prompt,
                    temperature=temperature,
                    max_output_tokens=max_output_tokens,
                    timeout_s=timeout_s,
                    json_mode=True,
                )
            )
            return content, usage

        except Exception as e:
            last_error = f"{type(e).__name__}: {e}"
            retryable, hint = _classify_retry(e)
            if not retryable:
                raise RuntimeError(f"LLM API non-retryable error: {last_error}") from e
            if attempt >= max_retries:
                break
            # Honour Retry-After when the server tells us to wait, otherwise
            # exponential backoff with jitter to avoid thundering-herd retries
            # when many groups race the same provider after a 5xx burst.
            if hint is not None and hint > 0:
                delay = min(hint, 60.0)
            else:
                delay = min(2**attempt + random.uniform(0, 1), 30.0)
            time.sleep(delay)

    raise RuntimeError(f"LLM API failed after {max_retries} retries: {last_error}")


def _strip_code_fences(text: str) -> str:
    s = (text or "").strip()
    if s.startswith("```"):
        lines = s.splitlines()
        if len(lines) >= 3 and lines[0].startswith("```") and lines[-1].strip() == "```":
            return "\n".join(lines[1:-1]).strip()
    return s


def dedupe_findings_across_chunks(chunk_outputs: list[dict]) -> list[dict]:
    """Cross-chunk deterministic dedup before LLM reduce.

    Map-reduce often produces the same finding from two chunks (overlap on
    contract boundaries, identical patterns flagged twice, etc.). The reduce
    prompt asks the LLM to dedupe, but doing a deterministic pass first
    cuts prompt size, halves the chance the LLM re-introduces a near-duplicate
    with slightly different wording, and gives the LLM cleaner input.

    Findings are matched by case-insensitive ``(affected_component, title)``;
    the first occurrence wins, with ``locations`` lists merged.
    """
    seen: dict[tuple[str, str], dict] = {}
    for chunk in chunk_outputs:
        if not isinstance(chunk, dict):
            continue
        for f in chunk.get("findings") or []:
            if not isinstance(f, dict):
                continue
            key = (
                str(f.get("affected_component") or "").strip().lower(),
                str(f.get("title") or "").strip().lower(),
            )
            if not key[1]:  # skip findings without a title — can't safely dedupe
                seen[(str(id(f)), "")] = dict(f)
                continue
            if key in seen:
                merged_locs = list(seen[key].get("locations") or [])
                for loc in f.get("locations") or []:
                    if loc not in merged_locs:
                        merged_locs.append(loc)
                if merged_locs:
                    seen[key]["locations"] = merged_locs
            else:
                seen[key] = dict(f)
    return list(seen.values())


def make_audit_cache_key(files: list[Path], *, model: str, provider: str) -> str:
    """Combine source-content hash with model+provider identity.

    Reusing :meth:`AuditCache.compute_hash` alone would let a cache populated
    with ``gpt-4.1-mini`` answers serve a ``claude-sonnet-4-6`` request — same
    code, different model = different report. Re-hashing with the model name
    pinned avoids that footgun.
    """
    h = hashlib.sha256()
    h.update(AuditCache.compute_hash(files).encode())
    h.update(b":")
    h.update(model.encode())
    h.update(b":")
    h.update(provider.encode())
    return h.hexdigest()


def parse_json_response(text: str) -> dict:
    s = _strip_code_fences(text)
    try:
        value = json.loads(s)
        if isinstance(value, dict):
            return value
    except Exception:
        pass

    start = s.find("{")
    end = s.rfind("}")
    if start != -1 and end != -1 and end > start:
        candidate = s[start : end + 1]
        value = json.loads(candidate)
        if isinstance(value, dict):
            return value

    raise ValueError("Model output is not valid JSON")


def _print_cost_estimate(groups: dict[str, list[Path]], *, args, sources_root: Path) -> None:
    """Walk the same prompt-build path the real audit takes and report tokens.

    Best-effort: real LLM output length is unbounded, so we treat
    ``--max-output-tokens`` as the upper bound and print a low/high range when
    pricing is available. Static-analysis blobs are conservatively budgeted.
    """
    # Heuristic overhead per call: prompt template + analysis JSON. The
    # built-in templates are ~3 KB each; bump to 5 KB to stay conservative.
    PROMPT_OVERHEAD_CHARS = 5_000

    grand_input_chars = 0
    grand_output_tokens_max = 0
    per_group: list[dict] = []

    for key, files in groups.items():
        _, blocks = build_file_blocks(
            files,
            sources_root=sources_root,
            with_line_numbers=not args.no_line_numbers,
            max_block_chars=args.max_chunk_chars,
        )
        full_text = "\n\n".join(blocks)

        if args.force_map_reduce or len(full_text) > args.max_input_chars:
            chunks = chunk_blocks(blocks, max_chars=args.max_chunk_chars)
            mode = "map_reduce"
            calls = len(chunks) + 1  # N map + 1 reduce
            input_chars = sum(len(c) for c in chunks) + PROMPT_OVERHEAD_CHARS * calls
            # Reduce input also includes the chunk findings text; bound by
            # max_output_tokens × N as a worst case.
            input_chars += args.max_output_tokens * 4 * len(chunks)
            output_tokens_max = args.max_output_tokens * calls
        else:
            mode = "single_pass"
            calls = 1
            input_chars = len(full_text) + PROMPT_OVERHEAD_CHARS
            output_tokens_max = args.max_output_tokens

        in_tokens = max(1, input_chars // 4)
        grand_input_chars += input_chars
        grand_output_tokens_max += output_tokens_max
        per_group.append(
            {
                "key": key,
                "files": len(files),
                "mode": mode,
                "calls": calls,
                "input_tokens_est": in_tokens,
                "output_tokens_max": output_tokens_max,
            }
        )

    grand_in_tokens = max(1, grand_input_chars // 4)
    print()
    print(f"Cost estimate ({len(groups)} groups, model={args.model}, provider={args.provider})")
    print("-" * 72)
    print(f"  {'group':<40s}  {'mode':<11s}  {'calls':>5s}  {'in_tok':>10s}  {'out_max':>9s}")
    for g in per_group:
        print(
            f"  {g['key'][:40]:<40s}  {g['mode']:<11s}  {g['calls']:>5d}  "
            f"{g['input_tokens_est']:>10,d}  {g['output_tokens_max']:>9,d}"
        )
    print("-" * 72)
    print(f"  TOTAL input tokens (est):  {grand_in_tokens:,}")
    print(f"  TOTAL output tokens (max): {grand_output_tokens_max:,}")
    if args.price_in_per_1k is not None and args.price_out_per_1k is not None:
        cost_low = (grand_in_tokens / 1000.0) * args.price_in_per_1k
        cost_high = cost_low + (grand_output_tokens_max / 1000.0) * args.price_out_per_1k
        print(f"  Projected cost:            ${cost_low:.2f}  –  ${cost_high:.2f} (USD)")
    else:
        print("  Projected cost:            (set --price-in-per-1k and --price-out-per-1k)")
    print()


def main() -> int:
    parser = argparse.ArgumentParser(description="Send Solidity sources to OpenAI and generate audit-style reports.")
    parser.add_argument("--sources-dir", default=DEFAULT_SOURCES_DIR, help="Directory containing *.sol files.")
    parser.add_argument("--out-dir", default=DEFAULT_OUTPUT_DIR, help="Output directory for reports.")
    parser.add_argument(
        "--run-dir", default=None, help="Write a full run folder (manifest + per-group artifacts) to this directory."
    )
    parser.add_argument(
        "--group-by",
        choices=["contract", "chain", "all", "file"],
        default="contract",
        help="Group files per contract, per chain, all-in-one, or per file.",
    )
    parser.add_argument(
        "--chain-id", type=int, default=None, help="Only audit a specific chain ID (from filename/dir prefix)."
    )
    parser.add_argument("--address", default=None, help="Only audit a specific address (0x...).")

    parser.add_argument(
        "--audit-prompt", default=str(DEFAULT_AUDIT_PROMPT_PATH), help="Prompt template for single-pass JSON report."
    )
    parser.add_argument(
        "--map-prompt",
        default=str(DEFAULT_MAP_PROMPT_PATH),
        help="Prompt template for map stage (chunk findings JSON).",
    )
    parser.add_argument(
        "--reduce-prompt",
        default=str(DEFAULT_REDUCE_PROMPT_PATH),
        help="Prompt template for reduce stage (final JSON report).",
    )

    parser.add_argument("--model", default=os.getenv("OPENAI_MODEL", DEFAULT_MODEL), help="OpenAI model name.")
    parser.add_argument(
        "--base-url", default=os.getenv("OPENAI_BASE_URL", "https://api.openai.com/v1"), help="OpenAI API base URL."
    )
    parser.add_argument("--temperature", type=float, default=0.1, help="Sampling temperature.")
    parser.add_argument("--max-output-tokens", type=int, default=3500, help="Max tokens for the report output.")
    parser.add_argument("--timeout", type=float, default=180.0, help="Request timeout in seconds.")
    parser.add_argument("--retries", type=int, default=5, help="Max retries for transient API errors.")
    parser.add_argument(
        "--rpm", type=float, default=0.0, help="Rate limit OpenAI requests (requests per minute). 0 disables."
    )
    parser.add_argument(
        "--price-in-per-1k",
        type=float,
        default=_float_env("OPENAI_PRICE_IN_PER_1K"),
        help="Estimated USD price per 1K input tokens (optional).",
    )
    parser.add_argument(
        "--price-out-per-1k",
        type=float,
        default=_float_env("OPENAI_PRICE_OUT_PER_1K"),
        help="Estimated USD price per 1K output tokens (optional).",
    )

    parser.add_argument("--max-input-chars", type=int, default=200_000, help="Max source bundle size before chunking.")
    parser.add_argument("--max-chunk-chars", type=int, default=120_000, help="Max per-chunk source size for map stage.")
    parser.add_argument(
        "--force-map-reduce", action="store_true", help="Always use map-reduce, even if under max-input-chars."
    )
    parser.add_argument(
        "--no-line-numbers", action="store_true", help="Do not add line numbers to sources (less accurate citations)."
    )

    parser.add_argument("--skip-existing", action="store_true", help="Skip if output report already exists.")
    parser.add_argument("--dry-run", action="store_true", help="List what would be audited without calling the API.")
    parser.add_argument(
        "--estimate-cost",
        action="store_true",
        help="Print projected token usage and (if --price-* provided) USD cost; exit without calling the API.",
    )

    parser.add_argument(
        "--disable-regex-scan", action="store_true", help="Disable heuristic regex scan in the prompt context."
    )
    parser.add_argument(
        "--regex-rules",
        action="append",
        default=[],
        metavar="PATH",
        help=(
            "Path to a JSON file with extra regex rules (appended to built-in defaults). "
            "May be passed multiple times. See rules/ for examples."
        ),
    )
    parser.add_argument(
        "--source-verify",
        choices=["off", "warn", "strict"],
        default="off",
        help=(
            "Locally recompile and compare to deployed bytecode before auditing. "
            "'warn' logs verdict; 'strict' aborts the group on mismatch. Requires "
            "matching solc on PATH (or via solc-select)."
        ),
    )
    parser.add_argument(
        "--no-verify-cache",
        action="store_true",
        help="Disable the .verify_cache.db SQLite cache (always re-run RPC + recompile).",
    )
    parser.add_argument(
        "--slither", action="store_true", help="Run slither (if installed) and include results in the prompt context."
    )
    parser.add_argument("--slither-timeout", type=int, default=300, help="Slither timeout in seconds.")
    parser.add_argument(
        "--concurrency",
        type=int,
        default=1,
        help="Max parallel API calls (default: 1 = sequential). Set >1 for parallel auditing.",
    )
    parser.add_argument(
        "--provider", choices=["openai", "claude", "gemini"], default="openai", help="LLM provider to use."
    )
    parser.add_argument("--no-cache", action="store_true", help="Disable audit caching (always re-run).")
    parser.add_argument("--html", action="store_true", help="Generate HTML report in addition to Markdown.")
    parser.add_argument("--mythril", action="store_true", help="Run Mythril symbolic execution (if installed).")
    parser.add_argument(
        "--stream",
        action="store_true",
        help="Stream LLM output and log incremental progress (no usage tokens, falls back to estimation).",
    )

    args = parser.parse_args()

    scryer_config.load()

    try:
        provider = get_provider(
            args.provider,
            model=args.model,
            base_url=args.base_url,
        )
    except Exception as e:
        _log.error("Error initializing provider: %s", e)
        return 2

    sources_root = Path(args.sources_dir)
    out_root = Path(args.out_dir)

    all_files = iter_solidity_files(sources_root)
    if not all_files:
        _log.error("No Solidity files found under: %s", sources_root)
        return 1

    want_addr = args.address.lower() if args.address else None
    if args.chain_id is not None or want_addr:
        selected: list[Path] = []
        for path in all_files:
            contract_key = extract_contract_key_from_path(path, sources_root)
            if not contract_key:
                continue
            chain_id, address = contract_key
            if args.chain_id is not None and chain_id != args.chain_id:
                continue
            if want_addr and address.lower() != want_addr:
                continue
            selected.append(path)
        all_files = selected

    if not all_files:
        _log.error("No matching Solidity files found for the given filters.")
        return 1

    groups = group_files(all_files, sources_root=sources_root, group_by=args.group_by)

    audit_template = load_prompt_template(Path(args.audit_prompt))
    map_template = load_prompt_template(Path(args.map_prompt))
    reduce_template = load_prompt_template(Path(args.reduce_prompt))

    system_prompt = "You are a senior smart contract security auditor. Output ONLY valid JSON."

    out_root.mkdir(parents=True, exist_ok=True)
    run_id = dt.datetime.now(dt.UTC).strftime("run_%Y%m%d_%H%M%SZ")
    run_root = Path(args.run_dir) if args.run_dir else (out_root / run_id)
    groups_root = run_root / "groups"

    audit_cache: AuditCache | None = None if args.no_cache else AuditCache()
    verify_cache: VerifyCache | None = (
        None if args.no_verify_cache or args.source_verify == "off" else VerifyCache()
    )

    if args.dry_run:
        for key, files in groups.items():
            group_dir = groups_root / key
            _log.info("DRY-RUN: %s (%d files) -> %s", key, len(files), group_dir)
        return 0

    if args.estimate_cost:
        _print_cost_estimate(groups, args=args, sources_root=sources_root)
        return 0

    groups_root.mkdir(parents=True, exist_ok=True)

    rate_limiter = RateLimiter(args.rpm)

    cost_enabled = args.price_in_per_1k is not None and args.price_out_per_1k is not None
    manifest: dict = {
        "run_id": run_id,
        "generated_at": dt.datetime.now(dt.UTC).isoformat(),
        "sources_dir": sources_root.as_posix(),
        "run_dir": run_root.as_posix(),
        "model": args.model,
        "base_url": args.base_url,
        "group_by": args.group_by,
        "filters": {"chain_id": args.chain_id, "address": args.address},
        "pricing": {"price_in_per_1k": args.price_in_per_1k, "price_out_per_1k": args.price_out_per_1k},
        "totals": {
            "calls": 0,
            "prompt_tokens": 0,
            "completion_tokens": 0,
            "cost_usd_est": 0.0 if cost_enabled else None,
            "aborted_by_source_verify": 0,
        },
        "aborted_groups": [],
        "groups": [],
    }

    def _audit_one_group(key: str, files: list[Path]) -> dict | None:
        """Audit a single group. Pure function over per-group state — no shared
        mutables besides the rate limiter (thread-safe) and the provider object
        (constructs a fresh httpx client per call inside ``chat_completion``).
        Returns a manifest entry, or ``None`` if the group was skipped/errored.
        """
        group_dir = groups_root / key
        prompts_dir = group_dir / "prompts"
        responses_dir = group_dir / "responses"
        group_dir.mkdir(parents=True, exist_ok=True)
        prompts_dir.mkdir(parents=True, exist_ok=True)
        responses_dir.mkdir(parents=True, exist_ok=True)

        report_md_path = group_dir / "report.md"
        report_json_path = group_dir / "report.json"
        chunks_json_path = group_dir / "chunks.json"
        calls_json_path = group_dir / "calls.json"
        files_md_path = group_dir / "files.md"
        analysis_json_path = group_dir / "analysis.json"
        error_path = group_dir / "error.txt"

        if args.skip_existing and report_md_path.exists():
            _log.info("SKIP (exists): %s", report_md_path)
            return None

        cache_key: str | None = None
        if audit_cache is not None:
            cache_key = make_audit_cache_key(files, model=args.model, provider=args.provider)
            cached_report = audit_cache.get_cached(cache_key)
            if cached_report is not None:
                _log.info("CACHE HIT: %s -> %s", key, report_md_path)
                generated_at = dt.datetime.now(dt.UTC).isoformat()
                report_json_path.write_text(
                    json.dumps(
                        {
                            "generated_at": generated_at,
                            "model": args.model,
                            "scope_key": key,
                            "mode": "cache_hit",
                            "calls": [],
                            "report": cached_report,
                        },
                        ensure_ascii=False,
                        indent=2,
                    )
                    + "\n",
                    encoding="utf-8",
                )
                header = [
                    "# AI-Generated Smart Contract Audit Report",
                    "",
                    f"- Generated: {generated_at}",
                    f"- Model: {args.model}",
                    f"- Scope key: {key}",
                    "- Mode: cache_hit",
                    "",
                    "---",
                    "",
                ]
                report_md_path.write_text("\n".join(header) + render_markdown(cached_report), encoding="utf-8")
                return {
                    "key": key,
                    "dir": group_dir.relative_to(run_root).as_posix(),
                    "files": len(files),
                    "mode": "cache_hit",
                    "calls": 0,
                    "prompt_tokens": 0,
                    "completion_tokens": 0,
                    "cost_usd_est": 0.0 if cost_enabled else None,
                    "report_md": report_md_path.relative_to(run_root).as_posix(),
                }

        def _make_chunk_logger(group_key: str):
            """Build a callback that logs streamed token deltas at ~5KB intervals."""
            state = {"buf": 0, "total": 0}

            def _on_chunk(text: str) -> None:
                state["buf"] += len(text)
                state["total"] += len(text)
                if state["buf"] >= 5000:
                    _log.info("STREAM[%s]: %d chars", group_key, state["total"])
                    state["buf"] = 0

            return _on_chunk

        chain_id_value = "Unknown"
        address_value = "Unknown"
        if key.startswith("chain_"):
            chain_id_value = key.split("_", 1)[1] or "Unknown"
        else:
            m = re.match(r"^(\d+)_0x[0-9a-f]{40}$", key)
            if m:
                chain_id_value, address_value = key.split("_", 1)

        analysis_payload: dict = {}

        # Source verification: recompile & compare to deployed bytecode. Only
        # runs when we can derive a real (chain_id, address) from the group key.
        source_verify_hint: str | None = None
        if args.source_verify != "off":
            if address_value != "Unknown" and chain_id_value != "Unknown":
                try:
                    verify_result = verify_contract(
                        chain_id=int(chain_id_value),
                        address=address_value,
                        sources_dir=sources_root,
                        cache=verify_cache,
                    )
                    verify_dict = {
                        "verdict": verify_result.verdict,
                        "compiler_version": verify_result.compiler_version,
                        "on_chain_size": verify_result.on_chain_size,
                        "compiled_size": verify_result.compiled_size,
                        "notes": list(verify_result.notes or []),
                        "cache_hit": verify_result.cache_hit,
                    }
                    analysis_payload["source_verify"] = verify_dict
                    if verify_result.verdict == "mismatch":
                        if args.source_verify == "strict":
                            _log.error(
                                "STRICT: source_verify=mismatch for %s; aborting group. notes=%s",
                                key,
                                verify_result.notes,
                            )
                            return {
                                "_aborted": True,
                                "key": key,
                                "reason": "source_verify_mismatch",
                                "verdict": "mismatch",
                                "notes": list(verify_result.notes or []),
                            }
                        _log.warning(
                            "source_verify=mismatch for %s — proceeding because --source-verify=warn. notes=%s",
                            key,
                            verify_result.notes,
                        )
                        source_verify_hint = (
                            "[source_verify hint] WARNING: Local recompilation produced bytecode that "
                            "does NOT match the deployed contract. The source you are analyzing may have "
                            "been altered; cite findings carefully and flag any conclusions that depend "
                            "on source-only details (variable names, comments, or string literals)."
                        )
                    elif verify_result.verdict == "partial_match":
                        _log.info("source_verify=partial_match for %s (cache_hit=%s)", key, verify_result.cache_hit)
                        source_verify_hint = (
                            "[source_verify hint] This contract was independently re-compiled. The "
                            "deployed runtime bytecode is byte-for-byte identical to the source EXCEPT "
                            "the metadata trailer (IPFS hash). Variable names, comments, and licence "
                            "headers may differ from what the deployer originally uploaded — focus on "
                            "behavior, not on naming or surface text."
                        )
                    else:
                        _log.info(
                            "source_verify=%s for %s (cache_hit=%s)",
                            verify_result.verdict,
                            key,
                            verify_result.cache_hit,
                        )
                except Exception as e:
                    _log.warning("source_verify exception for %s: %s", key, e)
                    analysis_payload["source_verify"] = {"verdict": "error", "error": str(e)}
            else:
                analysis_payload["source_verify"] = {
                    "verdict": "skipped",
                    "reason": "could not derive chain_id+address from group key",
                }

        if args.disable_regex_scan:
            analysis_payload["regex_scan"] = {"disabled": True}
        else:
            extra_rules: list[RegexRule] = []
            for rules_path in args.regex_rules or []:
                try:
                    extra_rules.extend(load_rules_from_file(Path(rules_path)))
                except Exception as e:
                    _log.warning("Failed to load --regex-rules %s: %s", rules_path, e)
            active_rules = list(DEFAULT_REGEX_RULES) + extra_rules if extra_rules else None
            analysis_payload["regex_scan"] = run_regex_scan(files, root=sources_root, rules=active_rules)
            if extra_rules:
                analysis_payload["regex_scan"]["custom_rule_files"] = list(args.regex_rules)
        if args.slither:
            analysis_payload["slither"] = run_slither(files, sources_root=sources_root, timeout_s=args.slither_timeout)
        else:
            analysis_payload["slither"] = {"disabled": True}

        analysis_json_path.write_text(
            json.dumps(analysis_payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
        )
        analysis_text = json.dumps(analysis_payload, ensure_ascii=False, indent=2)
        # Prepend a plain-text hint when source verification revealed something
        # the LLM should adjust its conclusions for. Goes in front of the JSON
        # so it's seen first regardless of token-budget truncation.
        if source_verify_hint:
            analysis_text = source_verify_hint + "\n\n" + analysis_text

        files_md, blocks = build_file_blocks(
            files,
            sources_root=sources_root,
            with_line_numbers=not args.no_line_numbers,
            max_block_chars=args.max_chunk_chars,
        )
        files_md_path.write_text(files_md + "\n", encoding="utf-8")
        full_sources_text = "\n\n".join(blocks)

        mode = (
            "single_pass"
            if (not args.force_map_reduce and len(full_sources_text) <= args.max_input_chars)
            else "map_reduce"
        )
        _log.info("AUDIT: %s (%d files, %s) -> %s", key, len(files), mode, report_md_path)

        call_summaries: list[dict] = []
        chunk_outputs: list[dict] = []
        report_obj: dict | None = None

        def record_call(call_name: str, *, prompt: str, response: str, usage: dict, duration_s: float) -> None:
            prompt_tokens = (
                usage.get("prompt_tokens")
                if isinstance(usage.get("prompt_tokens"), int)
                else estimate_tokens_rough(system_prompt + prompt)
            )
            completion_tokens = (
                usage.get("completion_tokens")
                if isinstance(usage.get("completion_tokens"), int)
                else estimate_tokens_rough(response)
            )
            cost_est = estimate_cost_usd(
                int(prompt_tokens),
                int(completion_tokens),
                price_in_per_1k=args.price_in_per_1k,
                price_out_per_1k=args.price_out_per_1k,
            )
            call_summaries.append(
                {
                    "call": call_name,
                    "duration_s": duration_s,
                    "prompt_chars": len(prompt),
                    "response_chars": len(response),
                    "usage": usage,
                    "prompt_tokens": int(prompt_tokens),
                    "completion_tokens": int(completion_tokens),
                    "cost_usd_est": cost_est,
                }
            )

        try:
            if mode == "single_pass":
                user_prompt = audit_template.safe_substitute(
                    CHAIN_ID=chain_id_value,
                    ADDRESS=address_value,
                    FILES=files_md,
                    STATIC_ANALYSIS=analysis_text,
                    SOURCES=full_sources_text,
                )
                (prompts_dir / "audit_prompt.txt").write_text(user_prompt + "\n", encoding="utf-8")

                t0 = time.time()
                raw, usage = llm_chat_completion(
                    provider,
                    system_prompt=system_prompt,
                    user_prompt=user_prompt,
                    temperature=args.temperature,
                    max_output_tokens=args.max_output_tokens,
                    timeout_s=args.timeout,
                    max_retries=args.retries,
                    rate_limiter=rate_limiter,
                    stream=args.stream,
                    on_chunk=_make_chunk_logger(key) if args.stream else None,
                )
                duration = time.time() - t0
                (responses_dir / "audit_response.txt").write_text(raw + "\n", encoding="utf-8")
                record_call("audit", prompt=user_prompt, response=raw, usage=usage, duration_s=duration)
                report_obj = parse_json_response(raw)
            else:
                chunks = chunk_blocks(blocks, max_chars=args.max_chunk_chars)
                for i, chunk_text in enumerate(chunks, start=1):
                    user_prompt = map_template.safe_substitute(
                        CHAIN_ID=chain_id_value,
                        ADDRESS=address_value,
                        FILES=files_md,
                        STATIC_ANALYSIS=analysis_text,
                        CHUNK_ID=str(i),
                        CHUNK_TOTAL=str(len(chunks)),
                        SOURCES=chunk_text,
                    )
                    prompt_name = f"map_prompt_{i:02d}.txt"
                    response_name = f"map_response_{i:02d}.txt"
                    (prompts_dir / prompt_name).write_text(user_prompt + "\n", encoding="utf-8")

                    t0 = time.time()
                    raw, usage = llm_chat_completion(
                        provider,
                        system_prompt=system_prompt,
                        user_prompt=user_prompt,
                        temperature=args.temperature,
                        max_output_tokens=args.max_output_tokens,
                        timeout_s=args.timeout,
                        max_retries=args.retries,
                        rate_limiter=rate_limiter,
                    )
                    duration = time.time() - t0
                    (responses_dir / response_name).write_text(raw + "\n", encoding="utf-8")
                    record_call(f"map_{i:02d}", prompt=user_prompt, response=raw, usage=usage, duration_s=duration)
                    chunk_outputs.append(parse_json_response(raw))

                # Deterministic dedup of identical (component, title) pairs
                # before the LLM sees the chunk findings — cleaner input, fewer
                # tokens, fewer near-duplicates re-introduced with slightly
                # different wording.
                deduped = dedupe_findings_across_chunks(chunk_outputs)
                chunk_findings_for_reduce: list[dict] = (
                    [{"chunk_id": "deduped", "chunk_total": len(chunk_outputs), "findings": deduped}]
                    if len(chunk_outputs) > 1
                    else chunk_outputs
                )
                reduce_prompt = reduce_template.safe_substitute(
                    CHAIN_ID=chain_id_value,
                    ADDRESS=address_value,
                    FILES=files_md,
                    STATIC_ANALYSIS=analysis_text,
                    CHUNK_FINDINGS=json.dumps(chunk_findings_for_reduce, ensure_ascii=False, indent=2),
                )
                (prompts_dir / "reduce_prompt.txt").write_text(reduce_prompt + "\n", encoding="utf-8")

                t0 = time.time()
                raw, usage = llm_chat_completion(
                    provider,
                    system_prompt=system_prompt,
                    user_prompt=reduce_prompt,
                    temperature=args.temperature,
                    max_output_tokens=args.max_output_tokens,
                    timeout_s=args.timeout,
                    max_retries=args.retries,
                    rate_limiter=rate_limiter,
                )
                duration = time.time() - t0
                (responses_dir / "reduce_response.txt").write_text(raw + "\n", encoding="utf-8")
                record_call("reduce", prompt=reduce_prompt, response=raw, usage=usage, duration_s=duration)
                report_obj = parse_json_response(raw)

        except Exception as e:
            error_path.write_text(f"{type(e).__name__}: {e}\n", encoding="utf-8")
            _log.error("ERROR: %s: %s: %s", key, type(e).__name__, e)
            return None

        generated_at = dt.datetime.now(dt.UTC).isoformat()

        chunks_json_path.write_text(json.dumps(chunk_outputs, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        calls_json_path.write_text(json.dumps(call_summaries, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        report_json_path.write_text(
            json.dumps(
                {
                    "generated_at": generated_at,
                    "model": args.model,
                    "scope_key": key,
                    "mode": mode,
                    "calls": call_summaries,
                    "report": report_obj,
                },
                ensure_ascii=False,
                indent=2,
            )
            + "\n",
            encoding="utf-8",
        )

        header = [
            "# AI-Generated Smart Contract Audit Report",
            "",
            f"- Generated: {generated_at}",
            f"- Model: {args.model}",
            f"- Scope key: {key}",
            f"- Mode: {mode}",
            "",
            "---",
            "",
        ]
        report_md_path.write_text("\n".join(header) + render_markdown(report_obj or {}), encoding="utf-8")

        if audit_cache is not None and cache_key is not None and report_obj:
            try:
                audit_cache.set_cached(
                    cache_key,
                    report_obj,
                    model=args.model,
                    provider=args.provider,
                    files_count=len(files),
                    total_chars=len(full_sources_text),
                )
            except Exception as e:  # cache failure must never block a real audit
                _log.warning("Failed to write audit cache for %s: %s", key, e)

        group_prompt_tokens = sum(c.get("prompt_tokens", 0) for c in call_summaries)
        group_completion_tokens = sum(c.get("completion_tokens", 0) for c in call_summaries)
        group_cost = None if not cost_enabled else float(sum((c.get("cost_usd_est") or 0.0) for c in call_summaries))

        return {
            "key": key,
            "dir": group_dir.relative_to(run_root).as_posix(),
            "files": len(files),
            "mode": mode,
            "calls": len(call_summaries),
            "prompt_tokens": group_prompt_tokens,
            "completion_tokens": group_completion_tokens,
            "cost_usd_est": group_cost,
            "report_md": report_md_path.relative_to(run_root).as_posix(),
        }

    concurrency = max(1, args.concurrency)
    if concurrency == 1 or len(groups) <= 1:
        results: list[dict | None] = [_audit_one_group(k, f) for k, f in groups.items()]
    else:
        _log.info("Running %d audits with concurrency=%d", len(groups), concurrency)

        async def _run_all() -> list[dict | None]:
            sem = asyncio.Semaphore(concurrency)

            async def _run_one(k: str, fs: list[Path]) -> dict | None:
                async with sem:
                    return await asyncio.to_thread(_audit_one_group, k, fs)

            return await asyncio.gather(*[_run_one(k, f) for k, f in groups.items()])

        results = asyncio.run(_run_all())

    # Aggregate results into the manifest single-threaded — keeps it simple
    # and ensures deterministic output ordering (sorted by group key).
    for entry in results:
        if entry is None:
            continue
        if entry.get("_aborted"):
            # strict --source-verify mismatch: track separately so the user
            # can see what got skipped without it disappearing silently.
            manifest["aborted_groups"].append(
                {k: v for k, v in entry.items() if k != "_aborted"}
            )
            manifest["totals"]["aborted_by_source_verify"] += 1
            continue
        manifest["groups"].append(entry)
        manifest["totals"]["calls"] += entry["calls"]
        manifest["totals"]["prompt_tokens"] += entry["prompt_tokens"]
        manifest["totals"]["completion_tokens"] += entry["completion_tokens"]
        if entry["cost_usd_est"] is not None and manifest["totals"]["cost_usd_est"] is not None:
            manifest["totals"]["cost_usd_est"] += float(entry["cost_usd_est"])

    manifest["groups"].sort(key=lambda g: g["key"])
    manifest["aborted_groups"].sort(key=lambda g: g["key"])

    (run_root / "manifest.json").write_text(json.dumps(manifest, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
