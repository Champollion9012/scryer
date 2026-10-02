#!/usr/bin/env python3
"""Scryer MCP server - a lean DATA / RETRIEVAL layer for AI-driven EVM security analysis.

Philosophy: this server does NOT analyze contracts. It does things the connecting
agent cannot do for itself: fetch verified source across providers with proxy
resolution, confirm the on-chain bytecode matches that source, read live on-chain
state, and relate a contract to its clones in the local registry. The agent reads
the downloaded source and performs all vulnerability reasoning itself.

Every chain-taking tool accepts EITHER `chain` (an alias like "bsc"/"eth") OR
`chain_id` (int); both resolve the same way (default BSC / 56).

Run:  python scryer_mcp.py            # stdio transport (for Claude Code / MCP clients)

Relative paths (sources/, .contract_registry.db) resolve against the repo root.
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


# One chain convention for every tool: alias OR numeric id, default BSC.
_CHAIN_ALIASES = {
    "eth": 1, "ethereum": 1, "mainnet": 1,
    "bsc": 56, "bnb": 56, "binance": 56,
    "polygon": 137, "matic": 137, "pol": 137,
    "arb": 42161, "arbitrum": 42161,
    "op": 10, "optimism": 10,
    "base": 8453,
    "avax": 43114, "avalanche": 43114,
    "ftm": 250, "fantom": 250,
    "linea": 59144,
    "scroll": 534352,
    "blast": 81457,
    "mantle": 5000, "mnt": 5000,
    "gnosis": 100, "xdai": 100,
    "zksync": 324, "era": 324,
    "zkevm": 1101, "polygonzkevm": 1101, "polygon_zkevm": 1101,
    "opbnb": 204,
    "celo": 42220,
    "cronos": 25, "cro": 25,
    "moonbeam": 1284, "glmr": 1284,
    "metis": 1088,
}

# Display names for the supported chains (surfaced by health so callers know what's queryable).
_CHAIN_NAMES = {
    1: "Ethereum", 10: "Optimism", 56: "BSC", 137: "Polygon", 250: "Fantom",
    8453: "Base", 42161: "Arbitrum", 43114: "Avalanche",
    59144: "Linea", 534352: "Scroll", 81457: "Blast", 5000: "Mantle", 100: "Gnosis",
    324: "zkSync Era", 1101: "Polygon zkEVM", 204: "opBNB", 42220: "Celo", 25: "Cronos",
    1284: "Moonbeam", 1088: "Metis",
}


def _supported_chains() -> list[dict]:
    """The chains callers can query, with their accepted aliases and native coin."""
    aliases_by_id: dict[int, list[str]] = {}
    for a, cid in _CHAIN_ALIASES.items():
        aliases_by_id.setdefault(cid, []).append(a)
    return [
        {
            "chain_id": cid,
            "name": _CHAIN_NAMES[cid],
            "aliases": sorted(aliases_by_id.get(cid, [])),
            "native": oc._NATIVE.get(cid),
        }
        for cid in sorted(_CHAIN_NAMES)
    ]


def _resolve_chain(chain: str = "", chain_id: int = 0) -> int:
    """Accept a chain alias ('bsc','eth',...) OR a numeric chain_id; default BSC (56)."""
    if chain:
        c = str(chain).strip().lower()
        if c in _CHAIN_ALIASES:
            return _CHAIN_ALIASES[c]
        if c.isdigit():
            return int(c)
        raise ValueError(f"unknown chain {chain!r}; use a chain_id or one of {sorted(set(_CHAIN_ALIASES))}")
    return chain_id or 56


def _src_files(prefix: str) -> list[Path]:
    """All downloaded source files for a {chain}_{addr} prefix — .sol AND .vy (Vyper)."""
    files: list[Path] = []
    for ext in ("sol", "vy"):
        files.extend(SOURCES_DIR.glob(f"{prefix}_*.{ext}"))
    return sorted(files)


def _read_meta(meta_path: Path) -> dict | None:
    try:
        return json.loads(Path(meta_path).read_text(encoding="utf-8"))
    except Exception:
        return None


# --------------------------------------------------------------------------- #
# Capability probe
# --------------------------------------------------------------------------- #
@mcp.tool()
def health() -> dict:
    """What this retrieval layer can do: Etherscan V2 key (fetch), solc (verify), registry
    size, and the queryable chains (`chains`: id + name + aliases + native).

    Call first when planning. Every chain-taking tool accepts `chain` (an alias from the
    chains list) or `chain_id` (int), plus `block` (number/tag; historical needs an archive
    RPC). Analysis is the agent's job.
    """
    try:
        reg = ContractRegistry().stats()
    except Exception:
        reg = None
    return {
        "repo": str(REPO),
        "python": sys.version.split()[0],
        "role": "data/retrieval layer - analysis is performed by the connecting agent",
        "etherscan_v2_key": bool(os.getenv("ETHERSCAN_API_KEY")),  # one V2 key covers all chains
        "solc": bool(which("solc")),
        "registry": reg,
        "chains": _supported_chains(),
    }


# --------------------------------------------------------------------------- #
# Fetch
# --------------------------------------------------------------------------- #
def _collect_download(chain_id: int, address: str) -> dict:
    addr = dc.normalize_address(address)
    prefix = f"{chain_id}_{addr}"
    src_files = _src_files(prefix)
    meta_path = SOURCES_DIR / f"{prefix}_download_meta.json"
    sources: dict[str, str] = {}
    for f in src_files:
        try:
            sources[f.name] = f.read_text(encoding="utf-8", errors="replace")
        except Exception:
            sources[f.name] = ""
    meta = _read_meta(meta_path)
    # Prefer the logical-path hash recorded at download time (matches the crawler's
    # registry rows); only fall back to a flat-filename hash for legacy downloads.
    source_hash = (meta.get("source_hash") if meta else None) or (
        ContractRegistry.compute_source_hash(sources) if sources else None
    )
    return {
        "chain_id": chain_id,
        "address": addr,
        "files": [
            {"path": str(f), "name": f.name, "bytes": f.stat().st_size, "preview": sources[f.name][:600]}
            for f in src_files
        ],
        "file_count": len(src_files),
        "total_bytes": sum(f.stat().st_size for f in src_files),
        "source_hash": source_hash,
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
    meta = _read_meta(Path(meta_path))
    if not meta:
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
        impl_files = _src_files(f"{chain_id}_{impl}")
        srcs: dict[str, str] = {}
        for f in impl_files:
            try:
                srcs[f.name] = f.read_text(encoding="utf-8", errors="replace")
            except Exception:
                srcs[f.name] = ""
        impl_meta = _read_meta(SOURCES_DIR / f"{chain_id}_{impl}_download_meta.json")
        block["implementation_files"] = [{"path": str(f), "name": f.name, "bytes": f.stat().st_size} for f in impl_files]
        block["implementation_source_fetched"] = bool(impl_files)
        block["implementation_source_hash"] = (impl_meta.get("source_hash") if impl_meta else None) or (
            ContractRegistry.compute_source_hash(srcs) if srcs else None
        )
        block["note"] = (
            "PROXY: analyze implementation_files (the real logic); top-level `files` are just the proxy shell."
            if impl_files
            else f"PROXY: implementation detected but source not fetched; call "
            f"download_contract(address='{impl}', chain_id={chain_id})."
        )
    return block


def _register_from_disk(chain_id: int, address: str) -> str | None:
    """Register a just-downloaded contract into the local registry, keyed by its LOGICAL
    source_hash (read from the download meta, so it matches the crawler's rows). Grows the
    corpus from use so registry_clones finds this contract and its clones. Best-effort.
    """
    addr = address.lower()
    prefix = f"{chain_id}_{addr}"
    srcs: dict[str, str] = {}
    for f in _src_files(prefix):
        try:
            srcs[f.name] = f.read_text(encoding="utf-8", errors="replace")
        except Exception:
            pass
    if not srcs:
        return None
    meta = _read_meta(SOURCES_DIR / f"{prefix}_download_meta.json")
    logical_hash = meta.get("source_hash") if meta else None
    try:
        return ContractRegistry().register_contract(chain_id, addr, srcs, source_hash=logical_hash)
    except Exception:
        return None


@mcp.tool()
def download_contract(address: str, chain: str = "", chain_id: int = 0, follow_proxy: bool = True, refresh: bool = False) -> dict:
    """Fetch verified source for a contract (Sourcify -> Blockscout -> explorer -> IPFS metadata).

    chain/chain_id: pass either (alias like "bsc" or the int; default BSC). Resolves
    proxies when follow_proxy=True: EIP-1967, EIP-1167 minimal, beacon, and legacy
    zeppelinos slots. Writes .sol/.vy files to sources/ and returns their on-disk
    paths + a short preview of each + the source_hash. **Read the full source from
    the returned paths and analyze it yourself.** Feed the source_hash to
    registry_clones to find the same code elsewhere; downloads auto-register into the
    local corpus. An already-downloaded contract is served from the on-disk cache
    instantly (verified source is immutable; look for `cached:true`); pass refresh=True
    to force a re-fetch (e.g. an upgradeable proxy whose implementation may have changed).

    For a proxy, the top-level `files` are only the proxy shell - the `proxy` field
    reports the implementation address and its `implementation_files` (the real logic).
    If the proxy shell itself is unverified but the implementation WAS fetched, found
    is still true (the implementation source is analyzable).

    Returns {found: false} only when no verified source exists anywhere (shell and,
    if a proxy, the implementation) - i.e. only runtime bytecode is on-chain.
    """
    try:
        cid = _resolve_chain(chain, chain_id)
        # On-disk cache: verified source is immutable, so if we already have it (files +
        # meta) we skip the network fetch and return instantly. refresh=True forces a
        # re-fetch (e.g. an upgradeable proxy whose implementation address may have changed).
        if not refresh:
            cached = _collect_download(cid, address)
            if cached["file_count"] > 0 and cached["meta_path"]:
                cached["found"] = True
                cached["cached"] = True
                if follow_proxy:
                    cached["proxy"] = _proxy_block(cid, cached.get("meta_path"), follow_proxy)
                return cached
        ok = dc.fetch_contract_source(
            cid, address, follow_proxy=follow_proxy, output_dir=str(SOURCES_DIR), layout="flat", quiet=True
        )
        out = _collect_download(cid, address)
        out["cached"] = False
        out["found"] = bool(ok and out["file_count"] > 0)
        if out["found"]:
            out["registered"] = _register_from_disk(cid, out["address"]) is not None
        if follow_proxy:
            out["proxy"] = _proxy_block(cid, out.get("meta_path"), follow_proxy)
            impl = out["proxy"].get("implementation")
            if impl and out["proxy"].get("implementation_source_fetched"):
                out["proxy"]["implementation_registered"] = _register_from_disk(cid, impl) is not None
                # The proxy SHELL may be unverified (found:false), but the implementation
                # source WAS fetched and is analyzable - don't claim "only bytecode".
                if not out["found"]:
                    out["found"] = True
                    out["note"] = (
                        "Proxy shell has no verified source of its own, but the implementation "
                        "source WAS fetched - analyze proxy.implementation_files."
                    )
        if not out["found"] and "note" not in out:
            out["note"] = "No verified source from any provider - only runtime bytecode exists on-chain."
        return out
    except Exception as e:
        return _err(e)


# --------------------------------------------------------------------------- #
# Verify (trust: on-chain bytecode == published source?)
# --------------------------------------------------------------------------- #
@mcp.tool()
def verify_source(address: str, chain: str = "", chain_id: int = 0) -> dict:
    """Confirm the explorer's 'verified' claim: recompile local source, compare to on-chain bytecode.

    Run this before trusting source you're about to analyze. Requires the source
    already downloaded (download_contract) and a matching `solc` on PATH. Verdicts:
    full_match / partial_match / mismatch / indeterminate / no_solc / no_bytecode.
    **A `mismatch` means the deployed code is NOT what the source says - a Critical
    finding on its own.** `indeterminate` means verification could not be completed
    (no compile target / no sources / no meta) - it is NOT a mismatch.
    """
    try:
        cid = _resolve_chain(chain, chain_id)
        r = vs.verify_contract(cid, address, cache=vs.VerifyCache())
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
# Live on-chain state (ground truth the agent can't derive)
# --------------------------------------------------------------------------- #
@mcp.tool()
def get_state(address: str, chain: str = "", chain_id: int = 0, block: str = "latest") -> dict:
    """Read a contract's LIVE state: owner/admin/pause, proxy impl, ERC20 meta, and (if it
    is a UniswapV2-style pair) token0/token1/reserves.

    Source says what COULD happen; this says what's true NOW - is it paused, who is
    owner/admin (is a privileged path reachable), is ownership renounced (owner==0x0
    is reported, not dropped). Best-effort eth_call; only getters that answer appear.
    For anything not covered, use call_view.
    """
    try:
        return oc.get_state(_resolve_chain(chain, chain_id), address, block=block)
    except Exception as e:
        return _err(e)


@mcp.tool()
def call_view(address: str, signature: str, args: list | None = None, returns: str = "",
              chain: str = "", chain_id: int = 0, block: str = "latest") -> dict:
    """Call any view/pure function and decode the return - no manual slot math.

    signature: e.g. "token0()", "getReserves()", "balanceOf(address)".
    args: argument values matching the signature's input types.
    returns: comma-separated output types to decode, e.g. "address" or
             "uint112,uint112,uint32". Omit to get only the raw hex.
    This replaces hand-reading storage slots for anything exposed as a getter.
    """
    try:
        return oc.call_view(_resolve_chain(chain, chain_id), address, signature, args or [], returns, block=block)
    except Exception as e:
        return _err(e)


@mcp.tool()
def read_storage(address: str, slot: str, chain: str = "", chain_id: int = 0, decode_as: str = "", block: str = "latest") -> dict:
    """Read a raw storage slot (eth_getStorageAt) and decode it.

    For values no getter exposes: custom/legacy proxy slots, packed flags, a role
    mapping entry, an init flag. `slot` is an int, decimal string, or hex string
    (0x-prefixed or bare like 'ff'). `as_address` is reported ONLY when the upper 96
    bits are zero (so a packed word isn't mistaken for an address). Pass `decode_as`
    (e.g. 'uint112,uint112,uint32') to unpack a packed word, first field = low bits.
    Prefer call_view when a getter exists.
    """
    try:
        return oc.read_storage(_resolve_chain(chain, chain_id), address, slot, decode_as=decode_as, block=block)
    except Exception as e:
        return _err(e)


@mcp.tool()
def token_exposure(address: str, chain: str = "", chain_id: int = 0, block: str = "latest") -> dict:
    """How much value the contract holds right now, in USD - the $-at-risk input to severity.

    Reads native-coin + major-token balances and prices them via DeFiLlama (free, no
    key); total_usd is a FLOOR (fixed major-token list per chain), not exhaustive TVL.
    Turns a theoretical bug into "N dollars at risk". Empty holdings don't prove safety.
    """
    try:
        return oc.token_exposure(_resolve_chain(chain, chain_id), address, block=block)
    except Exception as e:
        return _err(e)


# --------------------------------------------------------------------------- #
# Relate + persist (clone discovery / vuln knowledge base over the local registry)
# --------------------------------------------------------------------------- #
@mcp.tool()
def registry_clones(address: str = "", chain: str = "", chain_id: int = 0, source_hash: str = "") -> dict:
    """Find every address sharing this contract's exact source - by source_hash OR (address + chain).

    A bug confirmed in one contract is confirmed in all its clones, so this sizes the
    blast radius. Pass source_hash (from download_contract) for a direct lookup, or an
    address (+ chain/chain_id; default BSC) to resolve the hash first.
    """
    try:
        reg = ContractRegistry()
        if source_hash:
            return {"source_hash": source_hash, "addresses": reg.get_addresses_by_hash(source_hash)}
        if not address:
            return {"error": "provide either source_hash, or address (+ chain/chain_id)"}
        cid = _resolve_chain(chain, chain_id)
        return {
            "query": {"chain_id": cid, "address": address.lower()},
            "related": reg.find_related_contracts(cid, address),
        }
    except Exception as e:
        return _err(e)


@mcp.tool()
def registry_tag_vulnerability(tag: str, source_hash: str = "", address: str = "", chain: str = "",
                               chain_id: int = 0, severity: str = "", description: str = "") -> dict:
    """Record a confirmed vuln so every clone of that code auto-flags later.

    Key it by `source_hash` OR by `address` (+ chain/chain_id; resolved to the hash
    internally). Call AFTER confirming a vuln. Echoes back the resolved source_hash
    and the severity/description actually stored, so you can confirm it landed.
    """
    try:
        reg = ContractRegistry()
        sh = source_hash
        resolved_from = "source_hash"
        if not sh:
            if not address:
                return {"error": "provide source_hash, or address (+ chain/chain_id)"}
            cid = _resolve_chain(chain, chain_id)
            sh = reg.get_hash_by_address(cid, address)
            resolved_from = f"address {address.lower()} @ chain {cid}"
            if not sh:
                return {"error": f"{resolved_from} not in registry - download_contract it first, or pass source_hash"}
        sev = severity or "Unknown"
        desc = description or ""
        reg.tag_vulnerability(sh, tag, severity=sev, description=desc)
        return {"ok": True, "source_hash": sh, "tag": tag, "resolved_from": resolved_from,
                "stored": {"severity": sev, "description": desc}}
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
