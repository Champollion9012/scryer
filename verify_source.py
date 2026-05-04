#!/usr/bin/env python3
"""Verify that downloaded source compiles to deployed runtime bytecode.

Trust model
-----------
Sourcify / Etherscan / Blockscout self-classify verification (``perfect`` /
``partial_match`` / ``full_match``). This module re-runs the verification
*locally*: recompile the source with the metadata-recorded compiler, then
compare to ``eth_getCode``. That removes the explorer from the trust chain.

Verdicts
--------
- ``full_match`` — runtime bytecode matches byte-for-byte (incl. metadata trailer).
- ``partial_match`` — runtime matches after stripping the trailer; only
  cosmetic differences (variable names, comments, ipfs hash).
- ``mismatch`` — compiled bytecode does not match deployed; either source has
  been altered or compiler/settings differ.
- ``no_solc`` — required compiler not available locally; can't verify.
- ``no_bytecode`` — RPC failure / EOA / selfdestructed contract.

CLI
---
::

    python verify_source.py --chain-id 42161 --address 0x8144...
    python verify_source.py --chain-id 1 --address 0x... --solc-path /usr/local/bin/solc-0.8.34
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import sqlite3
import subprocess
import sys
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Literal

import scryer_config
import scryer_http
from scryer_logging import get_logger

_log = get_logger(__name__)

VerifyVerdict = Literal["full_match", "partial_match", "mismatch", "no_solc", "no_bytecode"]


@dataclass
class VerifyResult:
    verdict: VerifyVerdict
    chain_id: int
    address: str
    compiler_version: str | None = None
    on_chain_size: int | None = None
    compiled_size: int | None = None
    on_chain_no_meta_prefix: str | None = None
    compiled_no_meta_prefix: str | None = None
    notes: list[str] = field(default_factory=list)
    cache_hit: bool = False


# ---------------------------------------------------------------------------
# Cache
# ---------------------------------------------------------------------------


class VerifyCache:
    """SQLite cache keyed by ``(chain_id, address, meta.json hash)``.

    Caveats:
      - Cache key does NOT include the on-chain bytecode (would require an RPC
        round-trip to compute, defeating the cache). If a contract upgrades or
        selfdestructs the cached verdict goes stale; callers can pass
        ``cache=None`` or delete the DB to invalidate.
      - meta.json hash is stable as long as ``download_contract`` doesn't
        re-fetch new bytes from the explorer. If you re-download, expect
        a cache miss.
    """

    def __init__(self, db_path: str | Path = ".verify_cache.db") -> None:
        self.db_path = Path(db_path)
        self._init_db()

    def _init_db(self) -> None:
        with sqlite3.connect(self.db_path) as conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS verify_cache (
                    cache_key TEXT PRIMARY KEY,
                    chain_id INTEGER NOT NULL,
                    address TEXT NOT NULL,
                    verdict TEXT NOT NULL,
                    compiler_version TEXT,
                    on_chain_size INTEGER,
                    compiled_size INTEGER,
                    on_chain_no_meta_prefix TEXT,
                    compiled_no_meta_prefix TEXT,
                    notes_json TEXT,
                    created_at TEXT DEFAULT CURRENT_TIMESTAMP
                )
                """
            )
            conn.commit()

    @staticmethod
    def compute_key(chain_id: int, address: str, meta_bytes: bytes) -> str:
        h = hashlib.sha256()
        h.update(f"{chain_id}:{address.lower()}".encode("ascii"))
        h.update(b"\x00")
        h.update(meta_bytes)
        return h.hexdigest()

    def get(self, key: str) -> VerifyResult | None:
        with sqlite3.connect(self.db_path) as conn:
            row = conn.execute(
                """
                SELECT chain_id, address, verdict, compiler_version, on_chain_size,
                       compiled_size, on_chain_no_meta_prefix, compiled_no_meta_prefix, notes_json
                FROM verify_cache WHERE cache_key = ?
                """,
                (key,),
            ).fetchone()
        if not row:
            return None
        notes = json.loads(row[8]) if row[8] else []
        return VerifyResult(
            verdict=row[2],  # type: ignore[arg-type]
            chain_id=int(row[0]),
            address=str(row[1]),
            compiler_version=row[3],
            on_chain_size=row[4],
            compiled_size=row[5],
            on_chain_no_meta_prefix=row[6],
            compiled_no_meta_prefix=row[7],
            notes=list(notes),
            cache_hit=True,
        )

    def set(self, key: str, result: VerifyResult) -> None:
        with sqlite3.connect(self.db_path) as conn:
            conn.execute(
                """
                INSERT OR REPLACE INTO verify_cache
                (cache_key, chain_id, address, verdict, compiler_version, on_chain_size,
                 compiled_size, on_chain_no_meta_prefix, compiled_no_meta_prefix, notes_json)
                VALUES(?,?,?,?,?,?,?,?,?,?)
                """,
                (
                    key,
                    result.chain_id,
                    result.address,
                    result.verdict,
                    result.compiler_version,
                    result.on_chain_size,
                    result.compiled_size,
                    result.on_chain_no_meta_prefix,
                    result.compiled_no_meta_prefix,
                    json.dumps(result.notes or []),
                ),
            )
            conn.commit()


# ---------------------------------------------------------------------------
# Bytecode helpers
# ---------------------------------------------------------------------------


def strip_metadata_trailer(bytecode_hex: str) -> str:
    """Strip the Solidity metadata trailer from a runtime bytecode hex string.

    Solidity 0.6+ appends a CBOR-encoded metadata blob at the very end of
    runtime bytecode, followed by a 2-byte big-endian length suffix. The
    total trailer is ``length + 2`` bytes; this strips it.

    Returns the bytecode hex (without leading ``0x``); silently returns the
    input as-is if the bytecode is too short to have a trailer.
    """
    bc = bytecode_hex.lower()
    if bc.startswith("0x"):
        bc = bc[2:]
    if len(bc) < 4:
        return bc
    try:
        meta_len = int(bc[-4:], 16)  # 2 bytes = 4 hex chars
    except ValueError:
        return bc
    total_meta_chars = (meta_len + 2) * 2  # +2 for the length suffix itself
    if total_meta_chars >= len(bc) or total_meta_chars <= 0:
        return bc
    return bc[: len(bc) - total_meta_chars]


def fetch_runtime_bytecode(rpc_url: str, address: str) -> str:
    """``eth_getCode @ latest``; returns lowercase hex without ``0x``."""
    with scryer_http.sync_client() as client:
        resp = client.post(
            rpc_url,
            json={"jsonrpc": "2.0", "id": 1, "method": "eth_getCode", "params": [address, "latest"]},
        )
    resp.raise_for_status()
    body = resp.json()
    code = body.get("result") or "0x"
    return code[2:].lower() if code.startswith("0x") else code.lower()


# ---------------------------------------------------------------------------
# solc location
# ---------------------------------------------------------------------------


def _normalize_version(version: str | None) -> str | None:
    """``0.8.34+commit.80d5c536`` -> ``0.8.34``; strip leading ``v``."""
    if not version:
        return None
    return version.split("+", 1)[0].lstrip("v").strip() or None


def find_solc(version: str | None = None) -> Path | None:
    """Locate a usable solc binary.

    Search order:
      1. ``$SOLC_PATH`` env var (overrides everything)
      2. solc-select managed install at ``~/.svm/<version>/solc(.exe)``
      3. ``solc`` on ``$PATH``
    """
    env_path = os.getenv("SOLC_PATH")
    if env_path:
        p = Path(env_path)
        if p.exists():
            return p

    short = _normalize_version(version)
    if short:
        for candidate in (
            Path.home() / ".svm" / short / "solc",
            Path.home() / ".svm" / short / "solc.exe",
            Path.home() / ".solc-select" / "artifacts" / f"solc-{short}" / f"solc-{short}",
            Path.home() / ".solc-select" / "artifacts" / f"solc-{short}" / f"solc-{short}.exe",
        ):
            if candidate.exists():
                return candidate

    on_path = shutil.which("solc")
    return Path(on_path) if on_path else None


# ---------------------------------------------------------------------------
# Compilation
# ---------------------------------------------------------------------------


def compile_runtime_bytecode(
    sources: dict[str, str],
    settings: dict,
    *,
    target_file: str,
    target_contract: str,
    solc_path: Path,
    timeout_s: int = 120,
) -> str:
    """Compile via ``solc --standard-json`` and return runtime bytecode hex.

    ``settings`` should mirror what was in the metadata (optimizer, evmVersion,
    libraries, remappings); ``outputSelection`` is overridden to ensure
    ``deployedBytecode`` is emitted.
    """
    # Strip metadata-only keys solc's standard-json rejects (compilationTarget
    # is a Sourcify breadcrumb, not a compiler setting). Override outputSelection
    # to make sure deployedBytecode is emitted.
    _SETTINGS_BLOCKLIST = {"compilationTarget", "outputSelection"}
    full_settings = {k: v for k, v in settings.items() if k not in _SETTINGS_BLOCKLIST}
    full_settings["outputSelection"] = {"*": {"*": ["evm.deployedBytecode.object"]}}

    standard_input = {
        "language": "Solidity",
        "sources": {p: {"content": c} for p, c in sources.items()},
        "settings": full_settings,
    }

    proc = subprocess.run(
        [str(solc_path), "--standard-json"],
        input=json.dumps(standard_input),
        capture_output=True,
        text=True,
        timeout=timeout_s,
    )
    if proc.returncode != 0:
        raise RuntimeError(f"solc returned {proc.returncode}: {proc.stderr[:500]}")
    try:
        out = json.loads(proc.stdout)
    except json.JSONDecodeError as e:
        raise RuntimeError(f"solc output not JSON: {e}; stdout={proc.stdout[:200]}") from e

    errors = [e for e in out.get("errors", []) if e.get("severity") == "error"]
    if errors:
        msg = "; ".join(e.get("formattedMessage", str(e))[:200] for e in errors)
        raise RuntimeError(f"solc errors: {msg}")

    contracts = out.get("contracts", {}) or {}
    file_out = contracts.get(target_file) or {}
    contract_out = file_out.get(target_contract) or {}
    deployed = ((contract_out.get("evm") or {}).get("deployedBytecode") or {}).get("object", "") or ""
    if not deployed:
        available = [f"{f}:{c}" for f, cs in contracts.items() for c in (cs or {})]
        raise RuntimeError(f"no deployedBytecode for {target_file}:{target_contract}; available={available}")
    return deployed.lower()


# ---------------------------------------------------------------------------
# Source loading
# ---------------------------------------------------------------------------


def _load_sources_from_disk(
    *,
    chain_id: int,
    address: str,
    sources_dir: Path,
    logical_paths: list[str],
) -> dict[str, str]:
    """Reverse the layout naming used by ``download_contract.save_sources``.

    Tree layout:  ``{chain}_{addr}/{logical_path}``.
    Flat layout:  ``{chain}_{addr}_{logical_path_with_/_replaced_by__}``.
    """
    out: dict[str, str] = {}
    addr_lower = address.lower()
    flat_prefix = f"{chain_id}_{addr_lower}_"
    tree_root = sources_dir / f"{chain_id}_{addr_lower}"

    for logical in logical_paths:
        tree_candidate = tree_root / logical
        if tree_candidate.exists() and tree_candidate.is_file():
            out[logical] = tree_candidate.read_text(encoding="utf-8", errors="replace")
            continue
        flat_name = logical.replace("/", "_").replace("\\", "_")
        if not Path(flat_name).suffix:
            flat_name += ".sol"
        flat_candidate = sources_dir / f"{flat_prefix}{flat_name}"
        if flat_candidate.exists() and flat_candidate.is_file():
            out[logical] = flat_candidate.read_text(encoding="utf-8", errors="replace")
    return out


# ---------------------------------------------------------------------------
# Main verification
# ---------------------------------------------------------------------------


def _default_rpc_for(chain_id: int) -> str | None:
    env_keys = {
        1: "ETH_RPC_URL",
        56: "BSC_RPC_URL",
        137: "POLYGON_RPC_URL",
        42161: "ARBITRUM_RPC_URL",
        10: "OPTIMISM_RPC_URL",
        8453: "BASE_RPC_URL",
    }
    fallbacks = {
        1: "https://eth.llamarpc.com",
        56: "https://bsc-dataseed.bnbchain.org",
        137: "https://polygon-rpc.com",
        42161: "https://arb1.arbitrum.io/rpc",
        10: "https://mainnet.optimism.io",
        8453: "https://mainnet.base.org",
    }
    env_key = env_keys.get(chain_id)
    if env_key and (override := scryer_config.get(env_key)):
        return override
    return fallbacks.get(chain_id)


# Verdicts safe to cache: deterministic given (meta + sources + compiler).
# ``no_solc`` / ``no_bytecode`` are infrastructure errors — caching them would
# make the cache "sticky" against the user fixing their environment.
_CACHEABLE_VERDICTS: set[str] = {"full_match", "partial_match", "mismatch"}


def verify_contract(
    chain_id: int,
    address: str,
    *,
    sources_dir: Path | None = None,
    meta_path: Path | None = None,
    rpc_url: str | None = None,
    solc_path: Path | None = None,
    cache: VerifyCache | None = None,
) -> VerifyResult:
    """End-to-end: locate sources + meta, compile, fetch bytecode, compare.

    Both sources_dir and meta_path are optional; if omitted we use the
    ``download_contract`` flat-layout convention under ``./sources``.

    When ``cache`` is provided, lookup is keyed on
    ``(chain_id, address, sha256(meta.json bytes))`` — see :class:`VerifyCache`
    for staleness caveats.
    """
    address_lower = address.lower()
    if sources_dir is None:
        sources_dir = Path("sources")
    if meta_path is None:
        flat = sources_dir / f"{chain_id}_{address_lower}_download_meta.json"
        tree = sources_dir / f"{chain_id}_{address_lower}" / "download_meta.json"
        meta_path = flat if flat.exists() else tree

    if not meta_path.exists():
        return VerifyResult(
            verdict="mismatch",
            chain_id=chain_id,
            address=address_lower,
            notes=[f"download_meta.json not found (looked for {meta_path})"],
        )

    meta_bytes = meta_path.read_bytes()
    cache_key: str | None = None
    if cache is not None:
        cache_key = VerifyCache.compute_key(chain_id, address_lower, meta_bytes)
        hit = cache.get(cache_key)
        if hit is not None:
            return hit

    result = _verify_contract_uncached(
        chain_id=chain_id,
        address_lower=address_lower,
        meta_bytes=meta_bytes,
        sources_dir=sources_dir,
        rpc_url=rpc_url,
        solc_path=solc_path,
    )

    if cache is not None and cache_key is not None and result.verdict in _CACHEABLE_VERDICTS:
        cache.set(cache_key, result)

    return result


def _verify_contract_uncached(
    *,
    chain_id: int,
    address_lower: str,
    meta_bytes: bytes,
    sources_dir: Path,
    rpc_url: str | None,
    solc_path: Path | None,
) -> VerifyResult:
    """Inner: parse meta, compile, fetch, compare. No cache awareness."""
    meta = json.loads(meta_bytes.decode("utf-8"))
    embedded_meta = meta.get("metadata") or {}
    compiler_version = (embedded_meta.get("compiler") or {}).get("version") or embedded_meta.get("compilerVersion")
    settings = embedded_meta.get("settings") or {}
    target_map = settings.get("compilationTarget") or {}
    if not target_map:
        return VerifyResult(
            verdict="mismatch",
            chain_id=chain_id,
            address=address_lower,
            compiler_version=compiler_version,
            notes=["metadata.settings.compilationTarget missing — can't pick contract to compile"],
        )
    target_file, target_contract = next(iter(target_map.items()))

    # Sources: prefer inline content from metadata; fall back to disk.
    sources: dict[str, str] = {}
    for path, info in (embedded_meta.get("sources") or {}).items():
        if isinstance(info, dict) and isinstance(info.get("content"), str):
            sources[path] = info["content"]
    if not sources:
        logical = list((embedded_meta.get("sources") or {}).keys()) or [target_file]
        sources = _load_sources_from_disk(
            chain_id=chain_id, address=address_lower, sources_dir=sources_dir, logical_paths=logical
        )
    if not sources:
        return VerifyResult(
            verdict="mismatch",
            chain_id=chain_id,
            address=address_lower,
            compiler_version=compiler_version,
            notes=["no source files found (neither inline nor on disk)"],
        )

    if solc_path is None:
        solc_path = find_solc(compiler_version)
    if solc_path is None:
        short = _normalize_version(compiler_version)
        return VerifyResult(
            verdict="no_solc",
            chain_id=chain_id,
            address=address_lower,
            compiler_version=compiler_version,
            notes=[
                "solc not found (checked $SOLC_PATH, ~/.svm, $PATH)",
                f"install: solc-select install {short}" if short else "install: solc-select install <version>",
            ],
        )

    # Compile
    try:
        compiled = compile_runtime_bytecode(
            sources,
            settings,
            target_file=target_file,
            target_contract=target_contract,
            solc_path=solc_path,
        )
    except Exception as e:
        return VerifyResult(
            verdict="mismatch",
            chain_id=chain_id,
            address=address_lower,
            compiler_version=compiler_version,
            notes=[f"compile failed: {e}"],
        )

    # Fetch on-chain
    if rpc_url is None:
        rpc_url = _default_rpc_for(chain_id)
    if not rpc_url:
        return VerifyResult(
            verdict="no_bytecode",
            chain_id=chain_id,
            address=address_lower,
            compiler_version=compiler_version,
            notes=[f"no RPC URL for chain {chain_id}"],
        )
    try:
        on_chain = fetch_runtime_bytecode(rpc_url, address_lower)
    except Exception as e:
        return VerifyResult(
            verdict="no_bytecode",
            chain_id=chain_id,
            address=address_lower,
            compiler_version=compiler_version,
            notes=[f"eth_getCode failed: {e}"],
        )
    if not on_chain:
        return VerifyResult(
            verdict="no_bytecode",
            chain_id=chain_id,
            address=address_lower,
            compiler_version=compiler_version,
            notes=["empty bytecode (EOA or selfdestructed?)"],
        )

    # Compare
    on_chain_no_meta = strip_metadata_trailer(on_chain)
    compiled_no_meta = strip_metadata_trailer(compiled)

    notes: list[str] = []
    if on_chain == compiled:
        verdict: VerifyVerdict = "full_match"
    elif on_chain_no_meta == compiled_no_meta and on_chain_no_meta:
        verdict = "partial_match"
        notes.append(
            "runtime bytecode identical excluding metadata trailer; "
            "cosmetic differences only (variable names / comments / ipfs hash)"
        )
    else:
        verdict = "mismatch"
        n = min(len(on_chain_no_meta), len(compiled_no_meta))
        diff_at = next((i for i in range(n) if on_chain_no_meta[i] != compiled_no_meta[i]), n)
        notes.append(f"first byte differs at hex char index {diff_at}/{n}")
        if len(on_chain_no_meta) != len(compiled_no_meta):
            notes.append(
                f"runtime sizes differ: on-chain={len(on_chain_no_meta) // 2} compiled={len(compiled_no_meta) // 2}"
            )

    return VerifyResult(
        verdict=verdict,
        chain_id=chain_id,
        address=address_lower,
        compiler_version=compiler_version,
        on_chain_size=len(on_chain) // 2,
        compiled_size=len(compiled) // 2,
        on_chain_no_meta_prefix=on_chain_no_meta[:64],
        compiled_no_meta_prefix=compiled_no_meta[:64],
        notes=notes,
    )


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


_EXIT_CODES: dict[str, int] = {
    "full_match": 0,
    "partial_match": 0,
    "mismatch": 1,
    "no_solc": 2,
    "no_bytecode": 3,
}


def _print_human(result: VerifyResult) -> None:
    print(f"verdict: {result.verdict}")
    print(f"chain  : {result.chain_id}")
    print(f"address: {result.address}")
    if result.compiler_version:
        print(f"solc   : {result.compiler_version}")
    if result.on_chain_size is not None:
        print(f"sizes  : on-chain={result.on_chain_size} bytes  compiled={result.compiled_size} bytes")
    if result.notes:
        print("notes:")
        for n in result.notes:
            print(f"  - {n}")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--chain-id", type=int, required=True)
    parser.add_argument("--address", required=True)
    parser.add_argument("--sources-dir", type=Path, default=Path("sources"))
    parser.add_argument("--meta-path", type=Path)
    parser.add_argument("--rpc-url")
    parser.add_argument("--solc-path", type=Path)
    parser.add_argument("--json", action="store_true", help="emit JSON result instead of human text")
    args = parser.parse_args()

    scryer_config.load()
    result = verify_contract(
        chain_id=args.chain_id,
        address=args.address,
        sources_dir=args.sources_dir,
        meta_path=args.meta_path,
        rpc_url=args.rpc_url,
        solc_path=args.solc_path,
    )

    if args.json:
        print(json.dumps(asdict(result), indent=2))
    else:
        _print_human(result)
    return _EXIT_CODES.get(result.verdict, 4)


if __name__ == "__main__":
    sys.exit(main())
