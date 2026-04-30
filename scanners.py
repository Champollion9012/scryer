from __future__ import annotations

import re
import shutil
import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable
import json


@dataclass(frozen=True)
class RegexRule:
    rule_id: str
    severity: str
    title: str
    pattern: re.Pattern[str]


DEFAULT_REGEX_RULES: list[RegexRule] = [
    # === Critical ===
    RegexRule("DEPRECATED_SUICIDE", "Critical", "Deprecated suicide() function", re.compile(r"\bsuicide\s*\(")),
    RegexRule("UNPROTECTED_SELFDESTRUCT", "Critical", "selfdestruct may lack access control", re.compile(r"\bselfdestruct\s*\(")),
    
    # === High ===
    RegexRule("TX_ORIGIN", "High", "Use of tx.origin for authorization", re.compile(r"\btx\.origin\b")),
    RegexRule("REENTRANCY_PATTERN", "High", "Potential reentrancy (external call before state change)", re.compile(r"\.call\s*\{[^}]*\}\s*\([^)]*\)")),
    RegexRule("DELEGATECALL", "High", "Use of delegatecall (storage collision risk)", re.compile(r"\.delegatecall\s*\(")),
    RegexRule("UNSAFE_TRANSFER", "High", "transfer()/send() may fail silently on contracts", re.compile(r"\.(transfer|send)\s*\(")),
    RegexRule("ARBITRARY_JUMP", "High", "Arbitrary jump in assembly", re.compile(r"\bjump\s*\(")),
    RegexRule("WEAK_RANDOMNESS", "High", "Weak randomness source (blockhash/prevrandao)", re.compile(r"\b(blockhash|block\.prevrandao|block\.difficulty)\b")),
    RegexRule("SIGNATURE_REPLAY", "High", "ecrecover without nonce (replay attack risk)", re.compile(r"\becrecover\s*\(")),
    RegexRule("STORAGE_COLLISION", "High", "delegatecall with storage access", re.compile(r"delegatecall.*storage|storage.*delegatecall", re.IGNORECASE)),
    
    # === Medium ===
    RegexRule("CALL_VALUE", "Medium", "Low-level call with value", re.compile(r"\.call\s*\{[^}]*\bvalue\s*:")),
    RegexRule("TIMESTAMP_DEPENDENCE", "Medium", "Timestamp used in condition (miner manipulation)", re.compile(r"(if|require|while|for).*block\.timestamp")),
    RegexRule("UNCHECKED_RETURN", "Medium", "Unchecked return value from low-level call", re.compile(r"\.call\s*\{[^}]*\}\s*\([^)]*\)\s*;")),
    RegexRule("DOS_UNBOUNDED_LOOP", "Medium", "Potentially unbounded loop", re.compile(r"for\s*\([^;]*;\s*[^;]*\.length\s*;")),
    RegexRule("FRONT_RUNNING", "Medium", "Price-sensitive operation without slippage protection", re.compile(r"(swap|exchange|trade).*amount(?!.*slippage|.*minOut|.*deadline)", re.IGNORECASE)),
    RegexRule("HARDCODED_ADDRESS", "Medium", "Hardcoded address in code", re.compile(r"=\s*0x[a-fA-F0-9]{40}\b")),
    
    # === Low / Informational ===
    RegexRule("INLINE_ASSEMBLY", "Info", "Inline assembly usage", re.compile(r"\bassembly\s*\{")),
    RegexRule("UNCHECKED_BLOCK", "Info", "Unchecked arithmetic block", re.compile(r"\bunchecked\s*\{")),
    RegexRule("FLASH_LOAN_INDICATOR", "Info", "Flash loan pattern detected", re.compile(r"\b(flashLoan|onFlashLoan|executeOperation)\b")),
    RegexRule("TODO_FIXME", "Info", "TODO/FIXME comment in code", re.compile(r"//\s*(TODO|FIXME|XXX|HACK)", re.IGNORECASE)),
]



def _iter_lines(text: str):
    for i, line in enumerate(text.splitlines(), start=1):
        yield i, line


def run_regex_scan(files: Iterable[Path], *, root: Path | None = None, max_findings: int = 500) -> dict:
    findings: list[dict] = []
    files_scanned = 0
    lines_scanned = 0

    for path in files:
        if not path.exists() or not path.is_file():
            continue
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except Exception:
            continue

        files_scanned += 1
        rel = path
        if root and root in path.parents:
            rel = path.relative_to(root)

        for line_no, line in _iter_lines(text):
            lines_scanned += 1
            for rule in DEFAULT_REGEX_RULES:
                for match in rule.pattern.finditer(line):
                    findings.append(
                        {
                            "rule_id": rule.rule_id,
                            "severity": rule.severity,
                            "title": rule.title,
                            "file": rel.as_posix(),
                            "line": line_no,
                            "column": match.start() + 1,
                            "excerpt": line.strip()[:300],
                        }
                    )
                    if len(findings) >= max_findings:
                        break
                if len(findings) >= max_findings:
                    break
            if len(findings) >= max_findings:
                break
        if len(findings) >= max_findings:
            break

    by_severity: dict[str, int] = {}
    for f in findings:
        by_severity[f["severity"]] = by_severity.get(f["severity"], 0) + 1

    return {
        "tool": "regex_scan",
        "rules_version": 2,
        "files_scanned": files_scanned,
        "lines_scanned": lines_scanned,
        "findings_total": len(findings),
        "findings_by_severity": dict(sorted(by_severity.items(), key=lambda kv: kv[0])),
        "findings": findings,
        "notes": [
            "Heuristic scan only; high false-positive/false-negative risk.",
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

    detectors = (
        data.get("results", {}).get("detectors", [])
        if isinstance(data, dict)
        else []
    )
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


def run_slither(files: Iterable[Path], *, sources_root: Path, timeout_s: int = 300, keep_workspace: bool = False) -> dict:
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
        "json_summary": _slither_summarize(slither_json_text) if slither_json_text else {"parsed": False, "raw_json_tail": ""},
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
        if not file_path.exists() or not file_path.suffix == ".sol":
            continue
        
        try:
            proc = subprocess.run(
                [
                    mythril_path, "analyze",
                    str(file_path),
                    "--max-depth", str(max_depth),
                    "-o", "json",
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
            
            results.append({
                "file": file_path.name,
                "returncode": proc.returncode,
                "issues": data.get("issues", []) if isinstance(data, dict) else [],
                "error": proc.stderr[:1000] if proc.returncode != 0 else None,
            })
            
        except subprocess.TimeoutExpired:
            results.append({
                "file": file_path.name,
                "error": f"Timeout after {timeout}s",
            })
        except Exception as e:
            results.append({
                "file": file_path.name,
                "error": str(e),
            })
    
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
