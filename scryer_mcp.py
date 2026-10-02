#!/usr/bin/env python3
"""Scryer MCP server — a lean DATA / RETRIEVAL layer for AI-driven EVM security analysis.

Philosophy: this server does NOT analyze contracts. It does three things the
connecting agent cannot do for itself: (1) fetch verified source across multiple
providers with proxy resolution, (2) confirm the on-chain bytecode matches that
source, (3) relate a contract to its clones in the local registry (and persist
verdicts). The agent reads the downloaded source from disk and performs all
vulnerability reasoning itself.

Tools return structured metadata + on-disk paths + small previews; the agent
reads full source from the returned paths.

Run:  python scryer_mcp.py            # stdio transport (for Claude Code / MCP clients)

Relative paths (sources/, .contract_registry.db) resolve against the repo root,
so this reuses scryer's existing data stores.
"""
from __future__ import annotations

import os
import sys
from pathlib import Path
from shutil import which

# --- make scryer's flat-layout modules importable & reuse its data stores ----
REPO = Path(__file__).resolve().parent
if str(REPO) not in sys.path:
    sys.path.insert(0, str(REPO))
os.chdir(REPO)

try:
    from dotenv import load_dotenv

    load_dotenv(REPO / ".env")
except Exception:
    pass

from mcp.server.fastmcp import FastMCP  # noqa: E402

import download_contract as dc  # noqa: E402
import verify_source as vs  # noqa: E402
from contract_registry import ContractRegistry  # noqa: E402

mcp = FastMCP("scryer")
SOURCES_DIR = REPO / "sources"


def _err(e: Exception) -> dict:
    return {"error": f"{type(e).__name__}: {e}"}


# --------------------------------------------------------------------------- #
# Capability probe (the one meta-call the agent can't introspect itself)
# --------------------------------------------------------------------------- #
@mcp.tool()
def health() -> dict:
    """What this retrieval layer can do right now: explorer keys (fetch), solc (verify), registry size.

    Call first when planning. Analysis is the agent's job; the agent knows chain
    ids itself (1=Ethereum, 56=BSC, 137=Polygon, 42161=Arbitrum, 10=Optimism,
    43114=Avalanche, 250=Fantom, 8453=Base).
    """
    try:
        reg = ContractRegistry().stats()
    except Exception:
        reg = None
    return {
        "repo": str(REPO),
        "python": sys.version.split()[0],
        "role": "data/retrieval layer - analysis is performed by the connecting agent",
        "explorer_keys": {
            k: bool(os.getenv(k))
            for k in ("ETHERSCAN_API_KEY", "BSCSCAN_API_KEY", "POLYGONSCAN_API_KEY",
                      "ARBISCAN_API_KEY", "BASESCAN_API_KEY")
        },
        "solc": bool(which("solc")),
        "registry": reg,
    }


# --------------------------------------------------------------------------- #
# Fetch
# --------------------------------------------------------------------------- #
def _collect_download(chain_id: int, address: str) -> dict:
    addr = dc.normalize_address(address)
    prefix = f"{chain_id}_{addr}"
    sol_files = sorted(SOURCES_DIR.glob(f"{prefix}_*.sol"))
    meta_path = SOURCES_DIR / f"{prefix}_download_meta.json"
    sources: dict[str, str] = {}
    for f in sol_files:
        try:
            sources[f.name] = f.read_text(encoding="utf-8", errors="replace")
        except Exception:
            sources[f.name] = ""
    return {
        "chain_id": chain_id,
        "address": addr,
        "files": [
            {"path": str(f), "name": f.name, "bytes": f.stat().st_size, "preview": sources[f.name][:600]}
            for f in sol_files
        ],
        "file_count": len(sol_files),
        "total_bytes": sum(f.stat().st_size for f in sol_files),
        "source_hash": ContractRegistry.compute_source_hash(sources) if sources else None,
        "meta_path": str(meta_path) if meta_path.exists() else None,
        "sources_dir": str(SOURCES_DIR),
    }


@mcp.tool()
def download_contract(address: str, chain_id: int = 56, follow_proxy: bool = True) -> dict:
    """Fetch verified source for a contract (Sourcify -> Blockscout -> explorer -> IPFS metadata).

    Resolves EIP-1967/EIP-1167 proxies when follow_proxy=True (default). Writes
    .sol files to sources/ and returns their on-disk paths + a short preview of
    each + the source_hash. **Read the full source from the returned paths and
    analyze it yourself** — this server does not scan or audit. Feed the
    source_hash to registry_clones to find the same code deployed elsewhere.

    Returns {found: false} if no verified source exists on any provider (only
    runtime bytecode is on-chain — you cannot analyze what you can't read).
    """
    try:
        ok = dc.fetch_contract_source(
            chain_id, address, follow_proxy=follow_proxy, output_dir=str(SOURCES_DIR), layout="flat", quiet=True
        )
        out = _collect_download(chain_id, address)
        out["found"] = bool(ok and out["file_count"] > 0)
        if not out["found"]:
            out["note"] = "No verified source from any provider — only runtime bytecode exists on-chain."
        return out
    except Exception as e:
        return _err(e)


# --------------------------------------------------------------------------- #
# Verify (trust: on-chain bytecode == published source?)
# --------------------------------------------------------------------------- #
@mcp.tool()
def verify_source(chain_id: int, address: str) -> dict:
    """Confirm the explorer's 'verified' claim: recompile local source, compare to on-chain bytecode.

    Run this before trusting the source you're about to analyze. Requires the
    source already downloaded (download_contract) and a matching `solc` on PATH.
    Verdicts: full_match / partial_match / mismatch / no_solc / no_bytecode.
    **A `mismatch` means the deployed code is NOT what the source says — treat
    that as a Critical finding on its own and stop.**
    """
    try:
        r = vs.verify_contract(chain_id, address, cache=vs.VerifyCache())
        return {
            "verdict": r.verdict,
            "chain_id": r.chain_id,
            "address": r.address,
            "compiler_version": r.compiler_version,
            "on_chain_size": r.on_chain_size,
            "compiled_size": r.compiled_size,
            "immutables_zeroed": r.immutables_zeroed,
            "cache_hit": r.cache_hit,
            "notes": r.notes,
        }
    except Exception as e:
        return _err(e)


# --------------------------------------------------------------------------- #
# Relate + persist (clone discovery / vuln knowledge base over the local registry)
# --------------------------------------------------------------------------- #
@mcp.tool()
def registry_clones(chain_id: int = 0, address: str = "", source_hash: str = "") -> dict:
    """Find every address sharing this contract's exact source — by (chain_id, address) OR by source_hash.

    A bug confirmed in one contract is confirmed in all its clones, so this sizes
    the blast radius. Pass source_hash (from download_contract) for a direct hash
    lookup, or chain_id+address to resolve the hash first.
    """
    try:
        reg = ContractRegistry()
        if source_hash:
            return {"source_hash": source_hash, "addresses": reg.get_addresses_by_hash(source_hash)}
        if not address:
            return {"error": "provide either source_hash, or chain_id + address"}
        return {"query": {"chain_id": chain_id, "address": address.lower()},
                "related": reg.find_related_contracts(chain_id, address)}
    except Exception as e:
        return _err(e)


@mcp.tool()
def registry_tag_vulnerability(source_hash: str, tag: str, severity: str = "", description: str = "") -> dict:
    """Record a confirmed vuln against a source_hash, so every clone of that code auto-flags later.

    Call AFTER you have confirmed a vulnerability (not for speculative hits). Pairs
    with registry_vulnerable to turn the local registry into a bug knowledge base.
    """
    try:
        ContractRegistry().tag_vulnerability(source_hash, tag, severity=severity or None,
                                             description=description or None)
        return {"ok": True, "source_hash": source_hash, "tag": tag}
    except Exception as e:
        return _err(e)


@mcp.tool()
def registry_vulnerable(tag: str) -> dict:
    """List contracts previously tagged with a given vuln tag (and thus their clones)."""
    try:
        return {"tag": tag, "contracts": ContractRegistry().get_vulnerable_contracts(tag)}
    except Exception as e:
        return _err(e)


if __name__ == "__main__":
    mcp.run()
