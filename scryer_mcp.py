#!/usr/bin/env python3
"""Scryer MCP server - a lean DATA / RETRIEVAL layer for AI-driven EVM security analysis.

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

import json
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
import onchain_state as oc  # noqa: E402
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
            for k in (
                "ETHERSCAN_API_KEY",
                "BSCSCAN_API_KEY",
                "POLYGONSCAN_API_KEY",
                "ARBISCAN_API_KEY",
                "BASESCAN_API_KEY",
            )
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


_PROXY_SCHEMES = (
    "eip1167_minimal_proxy",
    "eip1967_implementation_slot",
    "zeppelinos_implementation_slot",
    "eip1967_beacon_slot",
    "implementation_method",
)


def _proxy_block(chain_id: int, meta_path: str | None, requested: bool) -> dict:
    """Summarize proxy resolution AND surface the implementation's source files.

    For a proxy, the top-level `files` are only the proxy shell; the real logic is
    saved under the implementation address. This makes that explicit so the agent
    analyzes the right code (or knows to fetch it).
    """
    block: dict = {"requested": bool(requested), "is_proxy": False}
    if not meta_path:
        return block
    try:
        meta = json.loads(Path(meta_path).read_text(encoding="utf-8"))
    except Exception:
        return block
    pr = (meta.get("proxy_resolution") or {}).get("proxy") or {}
    if pr.get("error"):
        block["error"] = pr["error"]
    scheme = next((k for k in _PROXY_SCHEMES if pr.get(k)), None)
    impl = pr.get("implementation")
    if not scheme and not impl:
        return block  # not a proxy, or detected:false
    block["is_proxy"] = True
    if scheme:
        block["scheme"] = scheme
    if pr.get("beacon"):
        block["beacon"] = pr["beacon"]
    if impl:
        impl = impl.lower()
        block["implementation"] = impl
        impl_files = sorted(SOURCES_DIR.glob(f"{chain_id}_{impl}_*.sol"))
        srcs: dict[str, str] = {}
        for f in impl_files:
            try:
                srcs[f.name] = f.read_text(encoding="utf-8", errors="replace")
            except Exception:
                srcs[f.name] = ""
        block["implementation_files"] = [
            {"path": str(f), "name": f.name, "bytes": f.stat().st_size} for f in impl_files
        ]
        block["implementation_source_fetched"] = bool(impl_files)
        block["implementation_source_hash"] = ContractRegistry.compute_source_hash(srcs) if srcs else None
        block["note"] = (
            "PROXY: analyze implementation_files (the real logic); top-level `files` are just the proxy shell."
            if impl_files
            else f"PROXY: implementation detected but source not fetched; call "
            f"download_contract(address='{impl}', chain_id={chain_id})."
        )
    return block


def _register_from_disk(chain_id: int, address: str) -> str | None:
    """Register a just-downloaded contract into the local registry, keyed by its
    source hash. Grows scryer's corpus memory from use, so registry_clones finds
    this contract and any future clones of the same code. Best-effort; never raises.
    Returns the source_hash on success.
    """
    addr = address.lower()
    srcs: dict[str, str] = {}
    for f in sorted(SOURCES_DIR.glob(f"{chain_id}_{addr}_*.sol")):
        try:
            srcs[f.name] = f.read_text(encoding="utf-8", errors="replace")
        except Exception:
            pass
    if not srcs:
        return None
    try:
        return ContractRegistry().register_contract(chain_id, addr, srcs)
    except Exception:
        return None


@mcp.tool()
def download_contract(address: str, chain_id: int = 56, follow_proxy: bool = True) -> dict:
    """Fetch verified source for a contract (Sourcify -> Blockscout -> explorer -> IPFS metadata).

    Resolves proxies when follow_proxy=True (default): EIP-1967, EIP-1167 minimal,
    beacon, and legacy zeppelinos slots. Writes .sol files to sources/ and returns
    their on-disk paths + a short preview of each + the source_hash. **Read the full
    source from the returned paths and analyze it yourself** - this server does not
    scan or audit. Feed the source_hash to registry_clones to find the same code
    deployed elsewhere. Downloaded contracts (and any followed implementation) are
    registered into the local registry, so registry_clones finds them and their clones.

    For a proxy, the top-level `files` are only the proxy shell - the `proxy` field
    reports the implementation address and its `implementation_files` (that's the
    real logic to analyze). If a proxy's implementation wasn't auto-fetched, `proxy`
    tells you the address to download.

    Returns {found: false} if no verified source exists on any provider (only
    runtime bytecode is on-chain - you cannot analyze what you can't read).
    """
    try:
        ok = dc.fetch_contract_source(
            chain_id, address, follow_proxy=follow_proxy, output_dir=str(SOURCES_DIR), layout="flat", quiet=True
        )
        out = _collect_download(chain_id, address)
        out["found"] = bool(ok and out["file_count"] > 0)
        if not out["found"]:
            out["note"] = "No verified source from any provider - only runtime bytecode exists on-chain."
        if out["found"]:
            out["registered"] = _register_from_disk(chain_id, out["address"]) is not None
        if follow_proxy:
            out["proxy"] = _proxy_block(chain_id, out.get("meta_path"), follow_proxy)
            impl = out["proxy"].get("implementation")
            if impl and out["proxy"].get("implementation_source_fetched"):
                out["proxy"]["implementation_registered"] = _register_from_disk(chain_id, impl) is not None
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
    Verdicts: full_match / partial_match / mismatch / indeterminate / no_solc /
    no_bytecode. **A `mismatch` means the deployed code is NOT what the source says
    - treat that as a Critical finding on its own and stop.** `indeterminate` means
    verification could not be completed (e.g. legacy flattened source with no
    compile target) - it is NOT a mismatch, do not treat it as one.
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
# Live on-chain state (ground truth the agent can't derive — grounds exploitability + severity)
# --------------------------------------------------------------------------- #
@mcp.tool()
def get_state(chain_id: int, address: str) -> dict:
    """Read a contract's LIVE state: owner/admin/pause, proxy implementation, ERC20 meta.

    Source tells you what COULD happen; this tells you what's true NOW. Use it to
    decide if a bug is actually reachable: is it paused? who is owner/admin (can a
    privileged path be triggered)? Best-effort eth_call against common getters —
    only the ones that answer are returned.
    """
    try:
        return oc.get_state(chain_id, address)
    except Exception as e:
        return _err(e)


@mcp.tool()
def read_storage(chain_id: int, address: str, slot: str) -> dict:
    """Read a raw storage slot (eth_getStorageAt), decoded as uint and address.

    For values no getter exposes: custom/legacy proxy slots, packed flags, a role
    mapping entry, an uninitialized-vs-set check. `slot` is an int or 0x-hex string.
    """
    try:
        return oc.read_storage(chain_id, address, slot)
    except Exception as e:
        return _err(e)


@mcp.tool()
def token_exposure(chain_id: int, address: str) -> dict:
    """How much value the contract holds right now — the $-at-risk input to severity.

    Reads native-coin balance + balanceOf for major tokens; sums stablecoins as an
    approximate USD figure. Turns "theoretical bug" into "N dollars at risk", which
    is what actually sets a finding's severity. Empty holdings don't prove safety,
    but real balances quantify impact.
    """
    try:
        return oc.token_exposure(chain_id, address)
    except Exception as e:
        return _err(e)


# --------------------------------------------------------------------------- #
# Relate + persist (clone discovery / vuln knowledge base over the local registry)
# --------------------------------------------------------------------------- #
@mcp.tool()
def registry_clones(chain_id: int = 0, address: str = "", source_hash: str = "") -> dict:
    """Find every address sharing this contract's exact source - by (chain_id, address) OR by source_hash.

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
        return {
            "query": {"chain_id": chain_id, "address": address.lower()},
            "related": reg.find_related_contracts(chain_id, address),
        }
    except Exception as e:
        return _err(e)


@mcp.tool()
def registry_tag_vulnerability(source_hash: str, tag: str, severity: str = "", description: str = "") -> dict:
    """Record a confirmed vuln against a source_hash, so every clone of that code auto-flags later.

    Call AFTER you have confirmed a vulnerability (not for speculative hits). Pairs
    with registry_vulnerable to turn the local registry into a bug knowledge base.
    """
    try:
        ContractRegistry().tag_vulnerability(
            source_hash, tag, severity=severity or "Unknown", description=description or ""
        )
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
