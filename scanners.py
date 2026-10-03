from __future__ import annotations

import bisect
import itertools
import json
import re
import shutil
import subprocess
import tempfile
from collections.abc import Iterable, Sequence
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path


@dataclass(frozen=True)
class RegexRule:
    rule_id: str
    severity: str
    title: str
    pattern: re.Pattern[str]
    # "code" (default): match against the source with comment bodies blanked
    # out, so commented-out code cannot fire the rule or anchor a span that
    # swallows a real statement. "all": match the raw text — for rules that
    # deliberately target comments (e.g. TODO_FIXME).
    match_in: str = "code"

    @classmethod
    def from_dict(cls, payload: dict) -> RegexRule:
        """Build a rule from JSON-friendly dict, e.g. loaded from disk.

        Expected keys: ``rule_id``, ``severity``, ``title``, ``pattern``.
        Optional ``flags`` (e.g. ``"IGNORECASE"``) maps to :mod:`re` constants;
        optional ``match_in`` is ``"code"`` (default) or ``"all"``.
        """
        flags = 0
        for name in (payload.get("flags") or "").split("|"):
            name = name.strip().upper()
            if name:
                flags |= getattr(re, name)
        match_in = str(payload.get("match_in") or "code")
        if match_in not in ("code", "all"):
            raise ValueError(f"rule {payload.get('rule_id')!r}: match_in must be 'code' or 'all', got {match_in!r}")
        return cls(
            rule_id=str(payload["rule_id"]),
            severity=str(payload["severity"]),
            title=str(payload["title"]),
            pattern=re.compile(str(payload["pattern"]), flags),
            match_in=match_in,
        )


def load_rules_from_file(path: Path) -> list[RegexRule]:
    """Load a list of regex rules from a JSON file (array of dicts).

    Lets users carry custom in-house rules without forking this module.
    """
    payload = json.loads(Path(path).read_text(encoding="utf-8"))
    if not isinstance(payload, list):
        raise ValueError(f"Expected a JSON list of rules, got {type(payload).__name__}")
    return [RegexRule.from_dict(item) for item in payload]


DEFAULT_REGEX_RULES: list[RegexRule] = [
    # === Critical ===
    RegexRule("DEPRECATED_SUICIDE", "Critical", "Deprecated suicide() function", re.compile(r"\bsuicide\s*\(")),
    RegexRule(
        "UNPROTECTED_SELFDESTRUCT",
        "Critical",
        "selfdestruct may lack access control",
        re.compile(r"\bselfdestruct\s*\("),
    ),
    # === High ===
    RegexRule("TX_ORIGIN", "High", "Use of tx.origin for authorization", re.compile(r"\btx\.origin\b")),
    RegexRule(
        "REENTRANCY_PATTERN",
        "High",
        "Potential reentrancy (external call before state change)",
        # `{...}` never contains braces and an argument list is bounded, so
        # neither window can run away across a whole file.
        re.compile(r"\.call\s*\{[^{}]*\}\s*\([^)]{0,500}\)"),
    ),
    RegexRule(
        "DELEGATECALL", "High", "Use of delegatecall (storage collision risk)", re.compile(r"\.delegatecall\s*\(")
    ),
    RegexRule(
        "UNSAFE_TRANSFER",
        "High",
        "transfer()/send() may fail silently on contracts",
        re.compile(r"\.(transfer|send)\s*\("),
    ),
    RegexRule("ARBITRARY_JUMP", "High", "Arbitrary jump in assembly", re.compile(r"\bjump\s*\(")),
    RegexRule(
        "WEAK_RANDOMNESS",
        "High",
        "Weak randomness source (blockhash/prevrandao)",
        re.compile(r"\b(blockhash|block\.prevrandao|block\.difficulty)\b"),
    ),
    RegexRule(
        "SIGNATURE_REPLAY", "High", "ecrecover without nonce (replay attack risk)", re.compile(r"\becrecover\s*\(")
    ),
    RegexRule(
        "STORAGE_COLLISION",
        "High",
        "delegatecall with storage access",
        re.compile(r"delegatecall.*storage|storage.*delegatecall", re.IGNORECASE),
    ),
    # Loose LEADS (not verdicts) for the "token manipulates its own DEX pair" class — e.g.
    # BigBull/BBD (BSC 0x5d52..3df9, ~$72k, Sep 2026): a transfer hook burns the pair's own
    # balance then calls pair.sync(), resetting the constant-product K to drain LP reserves.
    # Tuned for RECALL and deliberately naming-INDEPENDENT. The co-occurrence that actually
    # confirms it (sync/skim reached FROM a transfer hook, targeting the real pair) is left to
    # the LLM/hunter, and a fork PoC is the final proof — so these are Medium and expect false
    # positives by design. Provenance: tests/python/test_pair_reserve_manipulation_rules.py
    RegexRule(
        "PAIR_SYNC_SKIM_CALL",
        "Medium",
        "Suspected: member-calls a DEX pair sync()/skim() — reserve/K manipulation IF reachable "
        "from a transfer hook. Review the call path; confirm with a fork PoC.",
        re.compile(r"\.(?:sync|skim)\s*\("),
    ),
    RegexRule(
        "BURN_FROM_PAIR",
        "Medium",
        "Suspected: burns/moves tokens FROM a stored (non-sender) address — an LP/reserve drain if "
        "that address is the DEX pair. Naming-independent lead; confirm the target and reachability.",
        # Flags _burn/_transfer/transferFrom whose SOURCE arg is some stored address, EXCLUDING the
        # ordinary self-burn / normal-transfer targets (msg.sender, from, account, this, 0, ...) and
        # type keywords (so function *definitions* like `_burn(address account,..)` don't fire). A
        # cast `address(x)` is unwrapped first so the real target x is judged. No longer keyed on the
        # var being named *pair*/*lp* — that was trivially evaded by renaming.
        re.compile(
            r"\b(?:_burn|burnFrom|_transfer|transferFrom)\s*\(\s*(?:address\s*\(\s*)?"
            r"(?!(?:msg\.sender|_?from|account|owner|sender|holder|recipient|spender|to|this|0"
            r"|address|uint\d*|int\d*|bool|bytes\d*|string|mapping)\b)\w+",
            re.IGNORECASE,
        ),
    ),
    # === Medium ===
    RegexRule("CALL_VALUE", "Medium", "Low-level call with value", re.compile(r"\.call\s*\{[^{}]*\bvalue\s*:")),
    RegexRule(
        "TIMESTAMP_DEPENDENCE",
        "Medium",
        "Timestamp used in condition (miner manipulation)",
        re.compile(r"(if|require|while|for).*block\.timestamp"),
    ),
    RegexRule(
        "UNCHECKED_RETURN",
        "Medium",
        "Unchecked return value from low-level call",
        re.compile(r"\.call\s*\{[^{}]*\}\s*\([^)]{0,500}\)\s*;"),
    ),
    RegexRule(
        "DOS_UNBOUNDED_LOOP",
        "Medium",
        "Potentially unbounded loop",
        # A real `for` header never contains braces before its second `;`.
        re.compile(r"\bfor\s*\([^;{}]{0,500};\s*[^;{}]{0,500}\.length\s*;"),
    ),
    RegexRule(
        "FRONT_RUNNING",
        "Medium",
        "Price-sensitive operation without slippage protection",
        re.compile(r"(swap|exchange|trade).*amount(?!.*slippage|.*minOut|.*deadline)", re.IGNORECASE),
    ),
    RegexRule("HARDCODED_ADDRESS", "Medium", "Hardcoded address in code", re.compile(r"=\s*0x[a-fA-F0-9]{40}\b")),
    # === Low / Informational ===
    RegexRule("INLINE_ASSEMBLY", "Info", "Inline assembly usage", re.compile(r"\bassembly\s*\{")),
    RegexRule("UNCHECKED_BLOCK", "Info", "Unchecked arithmetic block", re.compile(r"\bunchecked\s*\{")),
    RegexRule(
        "FLASH_LOAN_INDICATOR",
        "Info",
        "Flash loan pattern detected",
        re.compile(r"\b(flashLoan|onFlashLoan|executeOperation)\b"),
    ),
    RegexRule(
        "TODO_FIXME",
        "Info",
        "TODO/FIXME comment in code",
        re.compile(r"//[ \t]*(TODO|FIXME|XXX|HACK)", re.IGNORECASE),
        match_in="all",
    ),
]

# Bump when scanner semantics change in a way that alters findings for the
# same rule set (v3: whole-file matching + comment masking; v2: per-line).
RULES_VERSION = 3


@lru_cache(maxsize=512)
def _as_multiline(pattern: re.Pattern[str]) -> re.Pattern[str]:
    """Return ``pattern`` recompiled with :data:`re.MULTILINE` so ``^``/``$``
    keep their per-line meaning now that rules run over whole files."""
    if pattern.flags & re.MULTILINE:
        return pattern
    return re.compile(pattern.pattern, pattern.flags | re.MULTILINE)


_COMMENT_OR_STRING_RE = re.compile(r"//|/\*|\"|'")
_NON_NEWLINE_RE = re.compile(r"[^\n]")


def _mask_comments(text: str) -> str:
    """Blank out ``//`` and ``/* */`` comment bodies, preserving length.

    Every comment character becomes a space (newlines are kept), so offsets
    on the masked text map 1:1 onto the original — ``line``, ``column`` and
    ``excerpt`` are still taken from the real source. String literals are
    copied verbatim so a ``//`` inside ``"https://..."`` is not mistaken for a
    comment start.

    Rules run against the masked text by default (``RegexRule.match_in ==
    "code"``). This keeps commented-out code from firing rules and, more
    importantly under whole-file matching, keeps a token inside a comment
    from anchoring a span that swallows the real call on a later line.
    """
    if "//" not in text and "/*" not in text:
        return text
    n = len(text)
    parts: list[str] = []
    i = 0
    while i < n:
        m = _COMMENT_OR_STRING_RE.search(text, i)
        if m is None:
            parts.append(text[i:])
            break
        j = m.start()
        parts.append(text[i:j])
        tok = m.group()
        if tok == "//":
            end = text.find("\n", j)
            end = n if end == -1 else end
            parts.append(" " * (end - j))
        elif tok == "/*":
            close = text.find("*/", j + 2)
            end = n if close == -1 else close + 2
            parts.append(_NON_NEWLINE_RE.sub(" ", text[j:end]))
        else:  # string literal — copy through the closing quote (or end of line)
            k = j + 1
            while k < n:
                c = text[k]
                if c == "\\":
                    k += 2
                    continue
                if c == tok or c == "\n":
                    break
                k += 1
            end = min(k + 1, n)
            parts.append(text[j:end])
        i = end
    return "".join(parts)


def _line_index(text: str) -> tuple[list[str], list[int]]:
    """Split ``text`` into lines and return ``(lines, line_start_offsets)``.

    Offsets are 0-based character positions of each line's first character,
    which lets a whole-file regex match be mapped back to ``(line, column)``
    with a single :func:`bisect.bisect_right`.
    """
    lines = text.split("\n")
    starts = [0]
    for line in lines[:-1]:
        starts.append(starts[-1] + len(line) + 1)
    return lines, starts


def _excerpt(lines: list[str], start_idx: int, end_idx: int, *, limit: int = 300) -> str:
    """Excerpt for a match spanning ``lines[start_idx:end_idx + 1]``.

    Single-line matches return the stripped source line (unchanged from the
    per-line scanner); multi-line matches are whitespace-collapsed into one
    line. Work is bounded by ``limit`` so a huge span costs O(limit).
    """
    if end_idx == start_idx:
        return lines[start_idx].strip()[:limit]
    out: list[str] = []
    total = 0
    for ln in lines[start_idx : end_idx + 1]:
        s = ln.strip()
        if not s:
            continue
        out.append(s)
        total += len(s) + 1
        if total >= limit:
            break
    return " ".join(out)[:limit]


def _scan_text(text: str, rules: Sequence[RegexRule], rel: Path, *, max_findings: int) -> list[dict]:
    r"""Run every rule over the whole file text (not line-by-line).

    Whole-file matching is what lets ``\s*`` / ``[^,)]+`` in a rule cross a
    newline, so multi-line call shapes such as::

        router.swapExactTokensForETHSupportingFeeOnTransferTokens(
            amount,
            0,
            path, address(this), block.timestamp
        );

    are caught by the same ``,\s*0\s*,`` rule that already matched the
    single-line collapse. Patterns that rely on ``.*`` still stay within one
    line because :data:`re.DOTALL` is never added.

    Comment bodies are masked first (see :func:`_mask_comments`) for every
    rule except those with ``match_in == "all"``.

    Findings are ordered by ``(line, column, rule order)`` so the output is
    stable and line-major like the historical per-line scanner, and at most
    ``max_findings`` are returned.
    """
    if max_findings <= 0:
        return []
    lines, starts = _line_index(text)
    text_len = len(text)
    # ``text.split("\n")`` leaves a trailing "" after a final newline; a
    # zero-width match (``^``, ``$``) at EOF would otherwise land on that
    # phantom line, one past ``lines_scanned``.
    phantom_tail = not text or text.endswith("\n")
    masked: str | None = None
    excerpts: dict[tuple[int, int], str] = {}
    found: list[tuple[int, int, int, dict]] = []
    for rule_idx, rule in enumerate(rules):
        if rule.match_in == "all":
            haystack = text
        else:
            if masked is None:
                masked = _mask_comments(text)
            haystack = masked
        # finditer yields in offset order, so a rule's matches beyond the
        # first ``max_findings`` can never survive the final (line, column)
        # sort + cap. Capping here keeps work O(max_findings) per rule instead
        # of O(all matches) on match-dense (e.g. minified) files.
        matches = itertools.islice(_as_multiline(rule.pattern).finditer(haystack), max_findings)
        for match in matches:
            start_off = match.start()
            if start_off >= text_len and phantom_tail:
                continue
            end_off = max(match.end() - 1, start_off)
            line_idx = bisect.bisect_right(starts, start_off) - 1
            end_line_idx = bisect.bisect_right(starts, end_off) - 1
            key = (line_idx, end_line_idx)
            excerpt = excerpts.get(key)
            if excerpt is None:
                excerpt = excerpts[key] = _excerpt(lines, line_idx, end_line_idx)
            column = start_off - starts[line_idx] + 1
            found.append(
                (
                    line_idx,
                    column,
                    rule_idx,
                    {
                        "rule_id": rule.rule_id,
                        "severity": rule.severity,
                        "title": rule.title,
                        "file": rel.as_posix(),
                        "line": line_idx + 1,
                        "end_line": end_line_idx + 1,
                        "column": column,
                        "excerpt": excerpt,
                    },
                )
            )
    found.sort(key=lambda item: item[:3])
    return [item[3] for item in found[:max_findings]]


def run_regex_scan(
    files: Iterable[Path],
    *,
    root: Path | None = None,
    max_findings: int = 500,
    rules: Sequence[RegexRule] | None = None,
) -> dict:
    """Scan ``files`` against a set of heuristic regex rules.

    By default the built-in :data:`DEFAULT_REGEX_RULES` are used. Callers can
    pass their own ``rules`` (e.g. extended with project-specific patterns
    loaded via :func:`load_rules_from_file`) without monkey-patching the
    module-level list.

    Each rule is applied to the whole file text with comment bodies masked
    (unless the rule sets ``match_in="all"``), so a rule may match across
    line breaks; every finding carries ``line`` (where the match starts) and
    ``end_line`` (where it ends — equal to ``line`` for single-line matches).
    ``max_findings`` bounds both the output and the work done per file.
    """
    active_rules: Sequence[RegexRule] = rules if rules is not None else DEFAULT_REGEX_RULES
    max_findings = int(max_findings)  # islice needs an int; callers historically passed floats like 1e9
    findings: list[dict] = []
    files_scanned = 0
    lines_scanned = 0

    for path in files:
        remaining = max_findings - len(findings)
        if remaining <= 0:
            break
        if not path.exists() or not path.is_file():
            continue
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except Exception:
            continue

        files_scanned += 1
        lines_scanned += len(text.splitlines())
        rel = path
        if root and root in path.parents:
            rel = path.relative_to(root)

        findings.extend(_scan_text(text, active_rules, rel, max_findings=remaining))

    by_severity: dict[str, int] = {}
    for f in findings:
        by_severity[f["severity"]] = by_severity.get(f["severity"], 0) + 1

    return {
        "tool": "regex_scan",
        "rules_version": RULES_VERSION,
        "files_scanned": files_scanned,
        "lines_scanned": lines_scanned,
        "findings_total": len(findings),
        "findings_by_severity": dict(sorted(by_severity.items(), key=lambda kv: kv[0])),
        "findings": findings,
        "notes": [
            "Heuristic scan only; high false-positive/false-negative risk.",
            "Rules match across line breaks (whole-file regex); `line`..`end_line` bound each hit.",
            "Comment bodies are masked before matching (except rules with match_in='all'), so commented-out code does not fire.",
            "Do not treat as a substitute for compilation-based analysis.",
        ],
    }


def choose_entry_file(files: Iterable[Path]) -> Path | None:
    files = [p for p in files if p.exists() and p.is_file()]
    if not files:
        return None
    for p in files:
        if p.name.endswith("combined_source.sol"):
            return p
    return max(files, key=lambda p: p.stat().st_size)


def infer_contract_root(files: Iterable[Path], sources_root: Path) -> Path | None:
    files = [p for p in files if p.exists() and p.is_file()]
    if not files:
        return None

    rels: list[Path] = []
    for p in files:
        if sources_root in p.parents:
            rels.append(p.relative_to(sources_root))
        else:
            rels.append(p)

    top = {r.parts[0] for r in rels if r.parts}
    if len(top) != 1:
        return None
    top_dir = sources_root / next(iter(top))
    if not top_dir.exists() or not top_dir.is_dir():
        return None
    if re.match(r"^\d+_0x[0-9a-fA-F]{40}$", top_dir.name):
        return top_dir
    return None


def prepare_slither_workspace(files: Iterable[Path], *, sources_root: Path) -> tuple[Path, Path] | None:
    entry = choose_entry_file(files)
    if not entry:
        return None

    contract_root = infer_contract_root(files, sources_root) or sources_root
    temp_dir = Path(tempfile.mkdtemp(prefix="slither_workspace_"))

    for p in files:
        if not p.exists() or not p.is_file():
            continue
        if contract_root in p.parents:
            rel = p.relative_to(contract_root)
        else:
            rel = Path(p.name)
        dest = temp_dir / rel
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_text(p.read_text(encoding="utf-8", errors="replace"), encoding="utf-8")

    entry_rel = entry.relative_to(contract_root) if contract_root in entry.parents else Path(entry.name)
    return temp_dir, temp_dir / entry_rel


def _slither_summarize(json_text: str, *, max_detectors: int = 50) -> dict:
    try:
        data = json.loads(json_text)
    except Exception:
        return {"parsed": False, "raw_json_tail": json_text[-20000:]}

    detectors = data.get("results", {}).get("detectors", []) if isinstance(data, dict) else []
    summarized: list[dict] = []
    if isinstance(detectors, list):
        for det in detectors[:max_detectors]:
            if not isinstance(det, dict):
                continue
            item: dict = {
                "check": det.get("check"),
                "impact": det.get("impact"),
                "confidence": det.get("confidence"),
                "description": (det.get("description") or "")[:800],
            }
            elements = det.get("elements")
            if isinstance(elements, list) and elements:
                src = elements[0].get("source_mapping") if isinstance(elements[0], dict) else None
                if isinstance(src, dict):
                    item["location"] = {
                        "file": src.get("filename_relative") or src.get("filename_short") or src.get("filename"),
                        "lines": src.get("lines"),
                    }
            summarized.append(item)

    return {
        "parsed": True,
        "detectors_total": len(detectors) if isinstance(detectors, list) else 0,
        "detectors": summarized,
    }


def run_slither(
    files: Iterable[Path], *, sources_root: Path, timeout_s: int = 300, keep_workspace: bool = False
) -> dict:
    slither_bin = shutil.which("slither")
    if not slither_bin:
        return {"tool": "slither", "available": False, "reason": "slither not found in PATH"}

    prepared = prepare_slither_workspace(files, sources_root=sources_root)
    if not prepared:
        return {"tool": "slither", "available": False, "reason": "no files to analyze"}

    workdir, entry_path = prepared
    out_json = workdir / "slither.json"
    cmd = [slither_bin, entry_path.as_posix(), "--json", out_json.as_posix()]

    try:
        proc = subprocess.run(
            cmd,
            cwd=workdir,
            capture_output=True,
            text=True,
            timeout=timeout_s,
        )
    except subprocess.TimeoutExpired:
        if keep_workspace:
            return {
                "tool": "slither",
                "available": True,
                "ok": False,
                "command": cmd,
                "error": "timeout",
                "workdir": workdir.as_posix(),
            }
        shutil.rmtree(workdir, ignore_errors=True)
        return {"tool": "slither", "available": True, "ok": False, "command": cmd, "error": "timeout"}
    except Exception as e:  # pragma: no cover
        if keep_workspace:
            return {
                "tool": "slither",
                "available": True,
                "ok": False,
                "command": cmd,
                "error": f"{type(e).__name__}: {e}",
                "workdir": workdir.as_posix(),
            }
        shutil.rmtree(workdir, ignore_errors=True)
        return {"tool": "slither", "available": True, "ok": False, "command": cmd, "error": f"{type(e).__name__}: {e}"}

    slither_json_text = ""
    if out_json.exists():
        try:
            slither_json_text = out_json.read_text(encoding="utf-8", errors="replace")
        except Exception:
            slither_json_text = ""

    result = {
        "tool": "slither",
        "available": True,
        "ok": proc.returncode == 0,
        "returncode": proc.returncode,
        "command": cmd,
        "workdir": workdir.as_posix() if keep_workspace else None,
        "json_summary": _slither_summarize(slither_json_text)
        if slither_json_text
        else {"parsed": False, "raw_json_tail": ""},
        "stdout": (proc.stdout or "")[-20000:],
        "stderr": (proc.stderr or "")[-20000:],
        "notes": [
            "Compilation-based analysis; may fail if solc is missing or sources are incomplete.",
            "Summary only; inspect full output when available.",
        ],
    }

    if not keep_workspace:
        shutil.rmtree(workdir, ignore_errors=True)

    return result


def run_mythril(
    files: list[Path],
    *,
    timeout: int = 300,
    max_depth: int = 22,
) -> dict:
    """
    Run Mythril symbolic execution on Solidity files.

    Requires: pip install mythril
    """
    mythril_path = shutil.which("myth")
    if not mythril_path:
        return {
            "tool": "mythril",
            "available": False,
            "notes": ["Mythril not found. Install with: pip install mythril"],
        }

    results: list[dict] = []

    for file_path in files:
        if not file_path.exists() or file_path.suffix != ".sol":
            continue

        try:
            proc = subprocess.run(
                [
                    mythril_path,
                    "analyze",
                    str(file_path),
                    "--max-depth",
                    str(max_depth),
                    "-o",
                    "json",
                ],
                capture_output=True,
                text=True,
                timeout=timeout,
            )

            output = proc.stdout
            try:
                data = json.loads(output) if output.strip() else {}
            except json.JSONDecodeError:
                data = {"raw_output": output[:5000]}

            results.append(
                {
                    "file": file_path.name,
                    "returncode": proc.returncode,
                    "issues": data.get("issues", []) if isinstance(data, dict) else [],
                    "error": proc.stderr[:1000] if proc.returncode != 0 else None,
                }
            )

        except subprocess.TimeoutExpired:
            results.append(
                {
                    "file": file_path.name,
                    "error": f"Timeout after {timeout}s",
                }
            )
        except Exception as e:
            results.append(
                {
                    "file": file_path.name,
                    "error": str(e),
                }
            )

    # Summarize issues
    total_issues = sum(len(r.get("issues", [])) for r in results)

    return {
        "tool": "mythril",
        "available": True,
        "files_analyzed": len(results),
        "total_issues": total_issues,
        "results": results,
        "notes": ["Symbolic execution analysis. May have false positives."],
    }


def run_forge_test(
    project_dir: Path,
    *,
    timeout: int = 300,
) -> dict:
    """
    Run Foundry forge tests if available.

    Requires: foundry installed (curl -L https://foundry.paradigm.xyz | bash)
    """
    forge_path = shutil.which("forge")
    if not forge_path:
        return {
            "tool": "forge",
            "available": False,
            "notes": ["Foundry not found. Install from: https://getfoundry.sh"],
        }

    # Check if this is a Foundry project
    foundry_toml = project_dir / "foundry.toml"
    if not foundry_toml.exists():
        return {
            "tool": "forge",
            "available": True,
            "ok": False,
            "notes": ["No foundry.toml found. Not a Foundry project."],
        }

    try:
        proc = subprocess.run(
            [forge_path, "test", "--json"],
            cwd=project_dir,
            capture_output=True,
            text=True,
            timeout=timeout,
        )

        output = proc.stdout
        test_results: list[dict] = []

        # Parse NDJSON output
        for line in output.splitlines():
            if line.strip().startswith("{"):
                try:
                    data = json.loads(line)
                    test_results.append(data)
                except json.JSONDecodeError:
                    pass

        # Count pass/fail
        passed = sum(1 for r in test_results if r.get("status") == "Success")
        failed = sum(1 for r in test_results if r.get("status") == "Failure")

        return {
            "tool": "forge",
            "available": True,
            "ok": proc.returncode == 0,
            "returncode": proc.returncode,
            "tests_passed": passed,
            "tests_failed": failed,
            "results": test_results[:50],  # Limit results
            "stderr": proc.stderr[:2000] if proc.stderr else None,
        }

    except subprocess.TimeoutExpired:
        return {
            "tool": "forge",
            "available": True,
            "ok": False,
            "error": f"Timeout after {timeout}s",
        }
    except Exception as e:
        return {
            "tool": "forge",
            "available": True,
            "ok": False,
            "error": str(e),
        }
