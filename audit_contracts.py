#!/usr/bin/env python3
from __future__ import annotations

import argparse
import asyncio
import datetime as dt
import json
import os
import re
import sys
import time
from pathlib import Path
from string import Template
from typing import Iterable

import httpx

from report_renderer import render_markdown
from scanners import run_regex_scan, run_slither
from llm_providers import get_provider

try:
    from dotenv import load_dotenv
except ImportError:  # pragma: no cover
    load_dotenv = None


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
    def __init__(self, rpm: float | None):
        self.min_interval_s = (60.0 / rpm) if rpm and rpm > 0 else 0.0
        self._next_ok_at = 0.0

    def wait(self):
        if self.min_interval_s <= 0:
            return
        now = time.time()
        if self._next_ok_at > now:
            time.sleep(self._next_ok_at - now)
        self._next_ok_at = max(now, self._next_ok_at) + self.min_interval_s


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


def estimate_cost_usd(prompt_tokens: int, completion_tokens: int, *, price_in_per_1k: float | None, price_out_per_1k: float | None) -> float | None:
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
) -> tuple[str, dict]:
    last_error: str | None = None
    for attempt in range(1, max_retries + 1):
        try:
            if rate_limiter:
                rate_limiter.wait()
            
            # Run async chat_completion synchronously
            content, usage = asyncio.run(provider.chat_completion(
                system_prompt=system_prompt,
                user_prompt=user_prompt,
                temperature=temperature,
                max_output_tokens=max_output_tokens,
                timeout_s=timeout_s,
                json_mode=True
            ))
            return content, usage

        except Exception as e:
            last_error = f"{type(e).__name__}: {e}"
            # Check for rate limits or fatal errors if possible, 
            # but for now we just retry on everything except maybe some obvious ones.
            # Simple retry backoff
            time.sleep(min(2**attempt, 30))

    raise RuntimeError(f"LLM API failed after {max_retries} retries: {last_error}")


def _strip_code_fences(text: str) -> str:
    s = (text or "").strip()
    if s.startswith("```"):
        lines = s.splitlines()
        if len(lines) >= 3 and lines[0].startswith("```") and lines[-1].strip() == "```":
            return "\n".join(lines[1:-1]).strip()
    return s


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


def main() -> int:
    parser = argparse.ArgumentParser(description="Send Solidity sources to OpenAI and generate audit-style reports.")
    parser.add_argument("--sources-dir", default=DEFAULT_SOURCES_DIR, help="Directory containing *.sol files.")
    parser.add_argument("--out-dir", default=DEFAULT_OUTPUT_DIR, help="Output directory for reports.")
    parser.add_argument("--run-dir", default=None, help="Write a full run folder (manifest + per-group artifacts) to this directory.")
    parser.add_argument(
        "--group-by",
        choices=["contract", "chain", "all", "file"],
        default="contract",
        help="Group files per contract, per chain, all-in-one, or per file.",
    )
    parser.add_argument("--chain-id", type=int, default=None, help="Only audit a specific chain ID (from filename/dir prefix).")
    parser.add_argument("--address", default=None, help="Only audit a specific address (0x...).")

    parser.add_argument("--audit-prompt", default=str(DEFAULT_AUDIT_PROMPT_PATH), help="Prompt template for single-pass JSON report.")
    parser.add_argument("--map-prompt", default=str(DEFAULT_MAP_PROMPT_PATH), help="Prompt template for map stage (chunk findings JSON).")
    parser.add_argument("--reduce-prompt", default=str(DEFAULT_REDUCE_PROMPT_PATH), help="Prompt template for reduce stage (final JSON report).")

    parser.add_argument("--model", default=os.getenv("OPENAI_MODEL", DEFAULT_MODEL), help="OpenAI model name.")
    parser.add_argument("--base-url", default=os.getenv("OPENAI_BASE_URL", "https://api.openai.com/v1"), help="OpenAI API base URL.")
    parser.add_argument("--temperature", type=float, default=0.1, help="Sampling temperature.")
    parser.add_argument("--max-output-tokens", type=int, default=3500, help="Max tokens for the report output.")
    parser.add_argument("--timeout", type=float, default=180.0, help="Request timeout in seconds.")
    parser.add_argument("--retries", type=int, default=5, help="Max retries for transient API errors.")
    parser.add_argument("--rpm", type=float, default=0.0, help="Rate limit OpenAI requests (requests per minute). 0 disables.")
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
    parser.add_argument("--force-map-reduce", action="store_true", help="Always use map-reduce, even if under max-input-chars.")
    parser.add_argument("--no-line-numbers", action="store_true", help="Do not add line numbers to sources (less accurate citations).")

    parser.add_argument("--skip-existing", action="store_true", help="Skip if output report already exists.")
    parser.add_argument("--dry-run", action="store_true", help="List what would be audited without calling the API.")

    parser.add_argument("--disable-regex-scan", action="store_true", help="Disable heuristic regex scan in the prompt context.")
    parser.add_argument("--slither", action="store_true", help="Run slither (if installed) and include results in the prompt context.")
    parser.add_argument("--slither-timeout", type=int, default=300, help="Slither timeout in seconds.")
    parser.add_argument("--concurrency", type=int, default=1, help="Max parallel API calls (default: 1 = sequential). Set >1 for parallel auditing.")
    parser.add_argument("--provider", choices=["openai", "claude", "gemini"], default="openai", help="LLM provider to use.")
    parser.add_argument("--no-cache", action="store_true", help="Disable audit caching (always re-run).")
    parser.add_argument("--html", action="store_true", help="Generate HTML report in addition to Markdown.")
    parser.add_argument("--mythril", action="store_true", help="Run Mythril symbolic execution (if installed).")

    args = parser.parse_args()

    if load_dotenv:
        load_dotenv(dotenv_path=Path(__file__).with_name(".env"), override=False)

    try:
        provider = get_provider(
            args.provider,
            model=args.model,
            base_url=args.base_url,
        )
    except Exception as e:
        print(f"Error initializing provider: {e}", file=sys.stderr)
        return 2

    sources_root = Path(args.sources_dir)
    out_root = Path(args.out_dir)

    all_files = iter_solidity_files(sources_root)
    if not all_files:
        print(f"No Solidity files found under: {sources_root}", file=sys.stderr)
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
        print("No matching Solidity files found for the given filters.", file=sys.stderr)
        return 1

    groups = group_files(all_files, sources_root=sources_root, group_by=args.group_by)

    audit_template = load_prompt_template(Path(args.audit_prompt))
    map_template = load_prompt_template(Path(args.map_prompt))
    reduce_template = load_prompt_template(Path(args.reduce_prompt))

    system_prompt = "You are a senior smart contract security auditor. Output ONLY valid JSON."

    out_root.mkdir(parents=True, exist_ok=True)
    run_id = dt.datetime.now(dt.timezone.utc).strftime("run_%Y%m%d_%H%M%SZ")
    run_root = Path(args.run_dir) if args.run_dir else (out_root / run_id)
    groups_root = run_root / "groups"

    if args.dry_run:
        for key, files in groups.items():
            group_dir = groups_root / key
            print(f"DRY-RUN: {key} ({len(files)} files) -> {group_dir}")
        return 0

    groups_root.mkdir(parents=True, exist_ok=True)

    rate_limiter = RateLimiter(args.rpm)

    cost_enabled = args.price_in_per_1k is not None and args.price_out_per_1k is not None
    manifest: dict = {
        "run_id": run_id,
        "generated_at": dt.datetime.now(dt.timezone.utc).isoformat(),
        "sources_dir": sources_root.as_posix(),
        "run_dir": run_root.as_posix(),
        "model": args.model,
        "base_url": args.base_url,
        "group_by": args.group_by,
        "filters": {"chain_id": args.chain_id, "address": args.address},
        "pricing": {"price_in_per_1k": args.price_in_per_1k, "price_out_per_1k": args.price_out_per_1k},
        "totals": {"calls": 0, "prompt_tokens": 0, "completion_tokens": 0, "cost_usd_est": 0.0 if cost_enabled else None},
        "groups": [],
    }

    for key, files in groups.items():
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
            print(f"SKIP (exists): {report_md_path}")
            continue

        chain_id_value = "Unknown"
        address_value = "Unknown"
        if key.startswith("chain_"):
            chain_id_value = key.split("_", 1)[1] or "Unknown"
        else:
            m = re.match(r"^(\\d+)_0x[0-9a-f]{40}$", key)
            if m:
                chain_id_value, address_value = key.split("_", 1)

        analysis_payload: dict = {}
        if args.disable_regex_scan:
            analysis_payload["regex_scan"] = {"disabled": True}
        else:
            analysis_payload["regex_scan"] = run_regex_scan(files, root=sources_root)
        if args.slither:
            analysis_payload["slither"] = run_slither(files, sources_root=sources_root, timeout_s=args.slither_timeout)
        else:
            analysis_payload["slither"] = {"disabled": True}

        analysis_json_path.write_text(json.dumps(analysis_payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        analysis_text = json.dumps(analysis_payload, ensure_ascii=False, indent=2)

        files_md, blocks = build_file_blocks(
            files,
            sources_root=sources_root,
            with_line_numbers=not args.no_line_numbers,
            max_block_chars=args.max_chunk_chars,
        )
        files_md_path.write_text(files_md + "\n", encoding="utf-8")
        full_sources_text = "\n\n".join(blocks)

        mode = "single_pass" if (not args.force_map_reduce and len(full_sources_text) <= args.max_input_chars) else "map_reduce"
        print(f"AUDIT: {key} ({len(files)} files, {mode}) -> {report_md_path}")

        call_summaries: list[dict] = []
        chunk_outputs: list[dict] = []
        report_obj: dict | None = None

        def record_call(call_name: str, *, prompt: str, response: str, usage: dict, duration_s: float) -> None:
            prompt_tokens = usage.get("prompt_tokens") if isinstance(usage.get("prompt_tokens"), int) else estimate_tokens_rough(system_prompt + prompt)
            completion_tokens = usage.get("completion_tokens") if isinstance(usage.get("completion_tokens"), int) else estimate_tokens_rough(response)
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

            manifest["totals"]["calls"] += 1
            manifest["totals"]["prompt_tokens"] += int(prompt_tokens)
            manifest["totals"]["completion_tokens"] += int(completion_tokens)
            if cost_est is not None and manifest["totals"]["cost_usd_est"] is not None:
                manifest["totals"]["cost_usd_est"] += float(cost_est)

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

                reduce_prompt = reduce_template.safe_substitute(
                    CHAIN_ID=chain_id_value,
                    ADDRESS=address_value,
                    FILES=files_md,
                    STATIC_ANALYSIS=analysis_text,
                    CHUNK_FINDINGS=json.dumps(chunk_outputs, ensure_ascii=False, indent=2),
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
            print(f"ERROR: {key}: {type(e).__name__}: {e}", file=sys.stderr)
            continue

        generated_at = dt.datetime.now(dt.timezone.utc).isoformat()

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

        group_prompt_tokens = sum(c.get("prompt_tokens", 0) for c in call_summaries)
        group_completion_tokens = sum(c.get("completion_tokens", 0) for c in call_summaries)
        group_cost = None if not cost_enabled else float(sum((c.get("cost_usd_est") or 0.0) for c in call_summaries))

        manifest["groups"].append(
            {
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
        )

    (run_root / "manifest.json").write_text(json.dumps(manifest, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
