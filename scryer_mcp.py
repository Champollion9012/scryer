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

import contextlib
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

import bytecode_abi as ba  # noqa: E402
import download_contract as dc  # noqa: E402
import onchain_state as oc  # noqa: E402
import scryer_chain as cm  # noqa: E402
import verify_source as vs  # noqa: E402
from contract_registry import ContractRegistry  # noqa: E402
from scryer_http import RateLimited, RateLimitTally, rpc_rate_limit_reason  # noqa: E402

mcp = FastMCP("scryer")
SOURCES_DIR = REPO / "sources"


def _err(e: Exception) -> dict:
    out = {"error": f"{type(e).__name__}: {e}"}
    # Backstop: if a throttle ever slips through as a raw exception, flag it so the caller
    # (the hunter agent) can tell "rate-limited, retry later" from a permanent failure.
    if isinstance(e, RateLimited):
        out["rate_limited"] = True
        out["warnings"] = [e.reason]
        if e.retry_after is not None:
            out["retry_after"] = e.retry_after
    else:
        reason = rpc_rate_limit_reason(e)
        if reason:
            out["rate_limited"] = True
            out["warnings"] = [reason]
    return out


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


def _is_pseudo_src_name(name: str) -> bool:
    """A decompiled/bytecode-only pseudo-source file (by naming convention): decompile() writes
    `{prefix}_decompiled.sol` and the bytecode fallback writes `..._{target}.decompiled.sol` /
    `..._{target}.BYTECODE_ONLY`. These are the only files that carry invented names, never
    verified source."""
    n = name.lower()
    return n.endswith("decompiled.sol") or n.endswith(".bytecode_only")


def _verified_src_files(prefix: str, meta: dict | None) -> list[Path]:
    """Source files that are VERIFIED source. When the download meta is pseudo (decompiled /
    bytecode_only) the pseudo files ARE this download's output — keep them so the caller can list
    them. When the meta is verified, any pseudo file on disk is a STALE leftover from a prior
    decompile()/fallback for the same address, so drop it: a later verified download must never
    list or register a stale `_decompiled.sol` as if it were real source."""
    files = _src_files(prefix)
    meta_pseudo = bool(meta and (meta.get("decompiled") or meta.get("bytecode_only")))
    if meta_pseudo:
        return files
    return [f for f in files if not _is_pseudo_src_name(f.name)]


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
    RPC). The `chains` list is the chains with a native RPC, BUT the live-state tools also
    reach any other Etherscan-V2 chain via a proxy fallback (see `state_rpc_fallback`).
    Analysis is the agent's job.
    """
    try:
        reg = ContractRegistry().stats()
    except Exception:
        reg = None
    has_key = bool(os.getenv("ETHERSCAN_API_KEY"))
    return {
        "repo": str(REPO),
        "python": sys.version.split()[0],
        "role": "data/retrieval layer - analysis is performed by the connecting agent",
        "etherscan_v2_key": has_key,  # one V2 key covers all chains
        "solc": bool(which("solc")),
        "registry": reg,
        "chains": _supported_chains(),
        "state_rpc_fallback": (
            "get_state/call_view/read_storage/token_exposure also work on ANY Etherscan-V2-supported "
            "chain (70+) with no native RPC in `chains` — pass its chain_id and reads fall back to the "
            "Etherscan V2 proxy module (eth_getCode/eth_call/eth_getStorageAt), paced to the key's "
            "per-sec limit (a multi-getter read takes a few seconds; tune via SCRYER_ETHERSCAN_MIN_INTERVAL)."
            if has_key
            else "set ETHERSCAN_API_KEY to query state on chains without a native RPC (proxy fallback)"
        ),
    }


# --------------------------------------------------------------------------- #
# Fetch
# --------------------------------------------------------------------------- #
_PSEUDO_NOTE = (
    "Only PSEUDO-SOURCE is on disk (decompiled or bytecode-only), so found:false — it is NOT "
    "verified source and is deliberately not registered (a decompiled hash would pollute clone "
    "matching). Read it for structure, but trust the opcodes and never the invented names. Use "
    "bytecode_abi(address) for the authoritative selector surface, decompile(address) to "
    "regenerate readable logic, and registry_clones(address) to look for a verified twin."
)


def _collect_download(chain_id: int, address: str) -> dict:
    addr = dc.normalize_address(address)
    prefix = f"{chain_id}_{addr}"
    meta_path = SOURCES_DIR / f"{prefix}_download_meta.json"
    meta = _read_meta(meta_path)
    # Meta-aware: a verified download drops any stale `_decompiled.sol` left by a prior decompile().
    src_files = _verified_src_files(prefix, meta)
    sources: dict[str, str] = {}
    for f in src_files:
        try:
            sources[f.name] = f.read_text(encoding="utf-8", errors="replace")
        except Exception:
            sources[f.name] = ""
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
        # Decompiled / bytecode-only output is pseudo-source, not verified source — callers
        # must not treat it as `found`.
        "pseudo_source": bool(meta and (meta.get("decompiled") or meta.get("bytecode_only"))),
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
        impl_meta = _read_meta(SOURCES_DIR / f"{chain_id}_{impl}_download_meta.json")
        # Meta-aware: keep pseudo files when the impl meta IS pseudo (so we can flag it), but drop
        # a stale `_decompiled.sol` when the impl has real verified source.
        impl_files = _verified_src_files(f"{chain_id}_{impl}", impl_meta)
        srcs: dict[str, str] = {}
        for f in impl_files:
            try:
                srcs[f.name] = f.read_text(encoding="utf-8", errors="replace")
            except Exception:
                srcs[f.name] = ""
        # The impl files may be pseudo-source (decompiled / bytecode-only). That is NOT verified
        # source, so it must not count as "source fetched" — otherwise download_contract flips
        # found:true for a proxy whose implementation is only decompiler output (invented names).
        impl_pseudo = bool(impl_meta and (impl_meta.get("decompiled") or impl_meta.get("bytecode_only")))
        verified_impl_files = impl_files and not impl_pseudo
        block["implementation_files"] = [{"path": str(f), "name": f.name, "bytes": f.stat().st_size} for f in impl_files]
        block["implementation_source_fetched"] = bool(verified_impl_files)
        block["implementation_pseudo_source"] = impl_pseudo
        block["implementation_source_hash"] = (
            None if impl_pseudo else (impl_meta.get("source_hash") if impl_meta else None)
        ) or (ContractRegistry.compute_source_hash(srcs) if srcs and not impl_pseudo else None)
        block["note"] = (
            "PROXY: analyze implementation_files (the real logic); top-level `files` are just the proxy shell."
            if verified_impl_files
            else "PROXY: implementation is only PSEUDO-source (decompiled/bytecode-only) — trust opcodes, not "
            "names; it is NOT verified source."
            if impl_pseudo
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
    meta = _read_meta(SOURCES_DIR / f"{prefix}_download_meta.json")
    if meta and (meta.get("decompiled") or meta.get("bytecode_only")):
        # Decompiler output is PSEUDO-source: its hash shifts with the decompiler version, so
        # registering it would pollute clone matching with phantom "source" that matches nothing.
        return None
    srcs: dict[str, str] = {}
    for f in _verified_src_files(prefix, meta):  # excludes any stale `_decompiled.sol`
        with contextlib.suppress(Exception):
            srcs[f.name] = f.read_text(encoding="utf-8", errors="replace")
    if not srcs:
        return None
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
                # Pseudo-source on disk is NOT a verified-source hit.
                cached["found"] = not cached.get("pseudo_source")
                cached["cached"] = True
                if cached.get("pseudo_source"):
                    cached["note"] = _PSEUDO_NOTE
                if follow_proxy:
                    cached["proxy"] = _proxy_block(cid, cached.get("meta_path"), follow_proxy)
                return cached
        tally = RateLimitTally()
        ok = dc.fetch_contract_source(
            cid, address, follow_proxy=follow_proxy, output_dir=str(SOURCES_DIR), layout="flat", quiet=True, tally=tally
        )
        out = _collect_download(cid, address)
        out["cached"] = False
        # Decompiled / bytecode-only output lands as a .sol on disk, but it is pseudo-source:
        # `found` must mean VERIFIED source, or the agent analyzes invented names as fact.
        out["found"] = bool(ok and out["file_count"] > 0 and not out.get("pseudo_source"))
        if out.get("pseudo_source") and "note" not in out:
            out["note"] = _PSEUDO_NOTE
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
        if not out["found"]:
            if "note" not in out:
                # A throttle must not be asserted as a confirmed miss — the source may well
                # exist; the agent should retry rather than conclude "only bytecode".
                if tally.hit:
                    out["note"] = (
                        "No source returned, but a provider was RATE-LIMITED - this is NOT a confirmed miss; "
                        "retry (see warnings/retry_after)."
                    )
                else:
                    out["note"] = (
                        "No verified source from any provider - only runtime bytecode exists on-chain. "
                        "This is NOT a dead end: registry_clones(address) may find a VERIFIED twin by "
                        "bytecode, bytecode_abi(address) recovers the callable surface (selectors -> "
                        "signatures) + proxy shape, and decompile(address) produces readable pseudo-source."
                    )
            # found:false -> stamp the full retry signal (rate_limited + retry_after).
            tally.apply(out)
        elif tally.hit:
            # found:true: the returned SOURCE is complete (a later provider succeeded after an
            # earlier one throttled). Surface the throttle as INFORMATIONAL only — do NOT set
            # rate_limited/retry_after, which would wrongly tell the agent to retry a success.
            # (Proxy-resolution throttles are signalled separately via out["proxy"]["rate_limited"].)
            out["warnings"] = list(tally.reasons)
            out.setdefault("note", "Source obtained (complete); an earlier provider was throttled - see warnings, no retry needed.")
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
        out = {
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
        if r.rate_limited:
            # verdict is 'indeterminate' here, NOT no_bytecode/mismatch — the throttle is
            # surfaced so the agent retries instead of trusting a code verdict.
            out["rate_limited"] = True
            out["warnings"] = list(r.notes)
            if r.retry_after is not None:
                out["retry_after"] = r.retry_after
        return out
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
# Chain activity: transactions, logs, fund flow, deployer (native RPC only)
# --------------------------------------------------------------------------- #
@mcp.tool()
async def get_logs(address: str = "", topics: list[str] | None = None, from_block: str = "0",
                   to_block: str = "latest", chain: str = "", chain_id: int = 0, chunk: int = 0) -> dict:
    """eth_getLogs over ANY block range — auto-chunked past the provider's max-range cap.

    No manual chunking: the range is split into windows (default 10 blocks, the Alchemy free-tier
    cap) fetched concurrently, and a window that still trips a range/size error is halved and
    retried down to one block. `address` filters by emitter; `topics` is the raw topic filter
    (topic0 is the event signature hash, e.g. the Sync/Transfer/Swap topic). `from_block`/`to_block`
    accept a number, 0x-hex, or a tag. Results are merged + de-duplicated; `count` is the total and
    `partial:true` (+ `errors`/`rate_limited`) flags any window that could not be fully read — it
    NEVER silently truncates. Uses the chain's native RPC (logs are paywalled on Etherscan's free
    tier for non-ETH chains), so the chain needs a *_URL in .env.
    """
    try:
        return await cm.get_logs(
            _resolve_chain(chain, chain_id), address, topics=topics,
            from_block=from_block, to_block=to_block, chunk=(chunk or None),
        )
    except Exception as e:
        return _err(e)


@mcp.tool()
async def get_tx(tx_hash: str, chain: str = "", chain_id: int = 0) -> dict:
    """Decode a transaction's token movements — from/to/selector/status/gas + events + net flows.

    Fetches the tx + receipt and decodes ERC20 Transfer, UniswapV2 Swap/Sync, and WETH/WBNB
    Deposit/Withdrawal logs. `net_flows` is a per-token {address: net} summary (received - sent) —
    the fast read on "what moved and to whom" without hand-parsing receipts. Native RPC only.
    """
    try:
        return await cm.get_tx(_resolve_chain(chain, chain_id), tx_hash)
    except Exception as e:
        return _err(e)


@mcp.tool()
async def asset_transfers(address: str, direction: str = "in", category: list[str] | None = None,
                          from_block: str = "0", to_block: str = "latest",
                          chain: str = "", chain_id: int = 0, max_pages: int = 20) -> dict:
    """Trace an address's fund flow (who funded it / where value went) via Alchemy asset transfers.

    `direction`: "in" (received — the "who funded X" primitive), "out" (sent), or "both".
    `category`: Alchemy categories, default ["external","erc20"] (native + token). Paginates the
    provider's pageKey automatically and returns counterparties (count/value/assets) + the earliest
    block seen. `truncated:true` means more pages exist beyond `max_pages`. Needs an Alchemy-family
    native RPC for the chain.
    """
    try:
        return await cm.asset_transfers(
            _resolve_chain(chain, chain_id), address, direction=direction, category=category,
            from_block=from_block, to_block=to_block, max_pages=max_pages,
        )
    except Exception as e:
        return _err(e)


@mcp.tool()
async def deployer(address: str, chain: str = "", chain_id: int = 0) -> dict:
    """Resolve a contract's deployer EOA, creation tx, and factory (if factory-made).

    Native-RPC only (Etherscan's getcontractcreation is paywalled on BSC): binary-searches
    eth_getCode for the deploy block, reverses the creation tx from the first mint/log at that
    block, and reports `deployer` (tx.from), `creation_tx`, and `factory` (tx.to — null => a direct
    CREATE, an address => the factory that deployed it; `via` says which). Historical eth_getCode
    needs an archive RPC.
    """
    try:
        return await cm.deployer(_resolve_chain(chain, chain_id), address)
    except Exception as e:
        return _err(e)


@mcp.tool()
def bytecode_abi(address: str, chain: str = "", chain_id: int = 0, block: str = "latest", resolve: bool = True) -> dict:
    """Recover a contract's callable surface from RUNTIME BYTECODE — works with NO source.

    **This is the way into an unverified / bytecode-only contract.** The function selectors are
    physically present in the dispatcher: this extracts them (walking opcodes, so PUSH constants
    are never mistaken for selectors) and reverse-looks-up each to a readable signature
    (`transfer(address,uint256)`) via openchain/4byte. Feed a recovered `signature` straight into
    `call_view` to read live values: bytecode -> selector -> signature -> value.

    The shape flags tell you WHERE to analyze — do not skip them:
    - `eip1167_implementation` set: EIP-1167 minimal proxy; the real logic is at that address.
    - `diamond_like`: EIP-2535; `call_view facetAddresses()` to enumerate facets, analyze each.
    - `proxy_like` true while download_contract reported `proxy.detected:false`: a NON-STANDARD
      proxy shell — hunt the implementation slot (`read_storage`), don't analyze this bytecode.
    - none set: a standalone contract; use the selectors.

    `unresolved` = selectors absent from public signature DBs. They are still callable (fuzz
    them); absence of a name is NOT absence of a function. A throttle surfaces as `rate_limited`
    rather than silently looking like "no signatures found".

    **Collisions**: `hex` is FACT (read from bytecode); `signature` is a GUESS (4-byte selectors
    collide and public DBs carry spam collisions). When `collision:true`, read `candidates`:
    `collision_cosmetic:true` means they differ only in NAME and encode identical calldata (safe
    to call any). `collision_cosmetic:false` means the PARAMETER TYPES differ — call_view each
    candidate's types and keep the one that decodes sensibly before trusting a name.
    """
    try:
        return ba.analyze_contract(_resolve_chain(chain, chain_id), address, block=block, resolve=resolve)
    except Exception as e:
        return _err(e)


@mcp.tool()
def decompile(address: str, chain: str = "", chain_id: int = 0, block: str = "latest", timeout: int = 180) -> dict:
    """Decompile an UNVERIFIED contract's bytecode into readable pseudo-Solidity (Heimdall-rs).

    Use when `download_contract` found no verified source and you need to read LOGIC, not just
    the callable surface. Writes the result to `sources/` and returns its path + a preview —
    **Read the file** for the full text.

    **This is PSEUDO-SOURCE, not the original.** Trust the opcodes and control flow; do NOT
    trust the names — every function/variable name is invented by the decompiler, and selectors
    it cannot resolve appear as `Unresolved_xxxxxxxx`. Never feed it to `verify_source` (it is
    not the deployed source and will not compile). It is deliberately NOT registered in the
    registry: a decompiled hash is unstable and would pollute clone matching.

    Pair it with `bytecode_abi` (the authoritative selector list, with real signatures) and
    `call_view` (actual live values). `status` says exactly what happened: ok / not_installed
    (with the install command) / timeout (raise `timeout`) / failed / too_short.

    **Heimdall is slow on real contracts** — measured ~136s for a 7 KB contract — so expect a
    long call and raise `timeout` (default 180s) for anything larger. If you only need the
    callable surface, `bytecode_abi` answers in seconds instead.
    """
    try:
        from web3 import Web3

        import decompilers
        from etherscan_proxy_provider import make_web3

        cid = _resolve_chain(chain, chain_id)
        blk, berr = oc._parse_block(block)
        if berr:
            return {"error": berr}
        w3, _label = make_web3(cid)
        code = bytes(w3.eth.get_code(Web3.to_checksum_address(address), block_identifier=blk))
        out: dict = {"chain_id": cid, "address": address.lower(), "block": blk, "code_size": len(code)}
        if not code:
            out["status"] = "no_code"
            out["error"] = "no code at this address at this block (EOA, not yet deployed, or self-destructed)"
            return out

        res = decompilers.decompile_with_heimdall_detailed(code.hex(), timeout=timeout)
        out["decompiler"] = res["decompiler"]
        out["status"] = res["status"]
        if res["status"] != "ok":
            out["error"] = res["detail"]
            return out

        src = res["source"] or ""
        addr_l = address.lower()
        path = SOURCES_DIR / f"{cid}_{addr_l}_decompiled.sol"
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(src, encoding="utf-8")
        # Write a meta sidecar flagged decompiled:true so the pseudo-source guards (which key off
        # meta, not filename) see this file. Without it, a later VERIFIED download_contract of the
        # same address would list this .sol among its verified files and fold it into the registry.
        with contextlib.suppress(Exception):
            (SOURCES_DIR / f"{cid}_{addr_l}_download_meta.json").write_text(
                json.dumps({"decompiled": True, "decompiler": res["decompiler"], "source": "decompile_tool"}),
                encoding="utf-8",
            )
        out.update(
            {
                "path": str(path),
                "line_count": src.count("\n") + 1,
                "char_count": len(src),
                "preview": src[:2000],
                "pseudo_source": True,
                "registered": False,
                "note": (
                    "PSEUDO-SOURCE from bytecode — NOT the original source. Trust the opcodes and control "
                    "flow, never the names (they are invented; unresolved selectors show as "
                    "Unresolved_xxxxxxxx). Do not pass this to verify_source. Not registered, so it cannot "
                    "pollute clone matching. Cross-check the real surface with bytecode_abi and read live "
                    "values with call_view."
                ),
            }
        )
        return out
    except Exception as e:
        return _err(e)


# --------------------------------------------------------------------------- #
# Relate + persist (clone discovery / vuln knowledge base over the local registry)
# --------------------------------------------------------------------------- #
def _live_runtime_hex(chain_id: int, address: str) -> tuple[str | None, str | None, dict | None]:
    """Fetch live runtime bytecode (hex, no 0x) at HEAD.

    Returns (hex, error, rate_limit). On a provider throttle the third element is
    ``{"reason": str, "retry_after": int|None}`` so the caller surfaces a RETRYABLE condition
    instead of asserting a permanent "no code" / "cannot tag". A throttle must never collapse
    into a genuine-miss value — the same caller-facing rate-limit contract the rest of the
    toolkit follows (the Etherscan-proxy fallback reports its throttle as a -32005 JSON-RPC
    error, which ``rpc_rate_limit_reason`` recognizes; a native RPC raises ``RateLimited``).
    """
    from web3 import Web3

    from etherscan_proxy_provider import make_web3
    from scryer_http import RateLimited, rpc_rate_limit_reason

    try:
        w3, _label = make_web3(chain_id)
        code = bytes(w3.eth.get_code(Web3.to_checksum_address(address)))
    except RateLimited as e:
        return None, e.reason, {"reason": e.reason, "retry_after": e.retry_after}
    except Exception as e:
        reason = rpc_rate_limit_reason(e)
        if reason:
            return None, reason, {"reason": reason, "retry_after": None}
        return None, f"{type(e).__name__}: {e}", None
    if not code:
        return None, "no code at this address (EOA or self-destructed)", None
    return code.hex(), None, None


def _rl_fields(out: dict, rl: dict, note: str) -> dict:
    """Stamp the retryable rate-limit signal onto a tool result so the agent retries instead of
    treating a throttle as a confirmed miss."""
    out["rate_limited"] = True
    if rl.get("retry_after") is not None:
        out["retry_after"] = rl["retry_after"]
    out["note"] = note
    return out


def _bytecode_twins(chain_id: int, address: str) -> dict:
    """Fingerprint the live bytecode and look for twins — the unverified-contract path."""
    runtime_hex, err, rl = _live_runtime_hex(chain_id, address)
    if err:
        out = {"bytecode_match_error": err}
        if rl:
            _rl_fields(out, rl, "RPC was RATE-LIMITED — this is NOT a confirmed 'no twins'; retry (see retry_after).")
        return out
    fp = ba.code_fingerprints(runtime_hex)
    ba.record_fingerprints(chain_id, address, runtime_hex)  # index the query contract too
    twins = ContractRegistry().find_code_twins(chain_id, address, fp)
    twins["fingerprints"] = fp
    return twins



@mcp.tool()
def registry_clones(
    address: str = "", chain: str = "", chain_id: int = 0, source_hash: str = "", bytecode: bool = True
) -> dict:
    """Find every address sharing this contract's code - by source_hash, or by BYTECODE.

    A bug confirmed in one contract is confirmed in all its clones, so this sizes the blast
    radius. Pass source_hash (from download_contract) for a direct source-level lookup, or an
    address (+ chain/chain_id; default BSC).

    **For an UNVERIFIED contract this is often the whole game**: with no source_hash it falls
    back to bytecode matching and can map the contract to a VERIFIED twin whose source you then
    download and read. Matches are tiered by precision:
    - `exact_matches` - identical runtime bytecode.
    - `normalized_matches` - identical except the metadata trailer (same source compiled
      elsewhere). The workhorse tier.
    - `abi_matches` - identical selector set; survives `immutable`/library differences that
      change the bytecode. Judge with `abi_shared_by`: 2 means a real twin, thousands means a
      generic interface (vanilla ERC20) and the match is meaningless.

    Each match flags `has_verified_source` - go `download_contract` THAT address to read real
    source. `inherited_vulnerability_tags` are tags on a twin's source: same code, same bug.
    """
    try:
        reg = ContractRegistry()
        if source_hash:
            return {"source_hash": source_hash, "addresses": reg.get_addresses_by_hash(source_hash)}
        if not address:
            return {"error": "provide either source_hash, or address (+ chain/chain_id)"}
        cid = _resolve_chain(chain, chain_id)
        out = {
            "query": {"chain_id": cid, "address": address.lower()},
            "related": reg.find_related_contracts(cid, address),
        }
        if bytecode:
            out.update(_bytecode_twins(cid, address))
        return out
    except Exception as e:
        return _err(e)


@mcp.tool()
def registry_tag_vulnerability(tag: str, source_hash: str = "", address: str = "", chain: str = "",
                               chain_id: int = 0, severity: str = "", description: str = "") -> dict:
    """Record a confirmed vuln so every clone of that code auto-flags later.

    Key it by `source_hash`, or by `address` (+ chain/chain_id). For a VERIFIED contract the
    tag is keyed by source_hash (source clones inherit it). For an UNVERIFIED / bytecode-only
    contract — e.g. one you just Confirmed with a fork PoC — it falls back to tagging by
    BYTECODE (the normalized runtime hash), so its byte-identical clones inherit it too. Call
    AFTER confirming. Echoes what was stored so you can confirm it landed.
    """
    try:
        reg = ContractRegistry()
        sev = severity or "Unknown"
        desc = description or ""
        if source_hash:
            reg.tag_vulnerability(source_hash, tag, severity=sev, description=desc)
            return {"ok": True, "source_hash": source_hash, "tag": tag, "keyed_by": "source_hash",
                    "stored": {"severity": sev, "description": desc}}
        if not address:
            return {"error": "provide source_hash, or address (+ chain/chain_id)"}
        cid = _resolve_chain(chain, chain_id)
        sh = reg.get_hash_by_address(cid, address)
        if sh:  # verified contract we have source for -> tag by source
            reg.tag_vulnerability(sh, tag, severity=sev, description=desc)
            return {"ok": True, "source_hash": sh, "tag": tag,
                    "keyed_by": f"source_hash (resolved from {address.lower()} @ chain {cid})",
                    "stored": {"severity": sev, "description": desc}}
        # Unverified / not in registry -> tag by bytecode.
        runtime_hex, err, rl = _live_runtime_hex(cid, address)
        if err:
            out = {"error": f"{address.lower()} @ chain {cid}: {err} — cannot tag"}
            if rl:
                _rl_fields(out, rl, "RPC was RATE-LIMITED — the tag was NOT stored; this is not a "
                                    "permanent failure, retry (see retry_after).")
            return out
        fp = ba.code_fingerprints(runtime_hex)
        norm = fp.get("runtime_norm_hash")
        if not norm:
            return {"error": "could not fingerprint bytecode; nothing to tag"}
        ba.record_fingerprints(cid, address, runtime_hex)  # index it so it appears in registry_vulnerable
        affected = reg.tag_vulnerability_by_code(norm, tag, severity=sev, description=desc)
        return {
            "ok": True, "runtime_norm_hash": norm, "tag": tag,
            "keyed_by": f"bytecode (unverified {address.lower()} @ chain {cid})",
            "stored": {"severity": sev, "description": desc},
            "affected_known_contracts": affected,
            "note": "tagged by BYTECODE — byte-identical clones (same normalized runtime) inherit this tag.",
        }
    except Exception as e:
        return _err(e)


@mcp.tool()
def registry_vulnerable(tag: str) -> dict:
    """List contracts tagged with a vuln tag (and their clones). Each row's `matched_via` is
    "source" (source-hash clones of a verified contract) or "bytecode" (byte-identical clones of
    an unverified one)."""
    try:
        return {"tag": tag, "contracts": ContractRegistry().get_vulnerable_contracts(tag)}
    except Exception as e:
        return _err(e)


if __name__ == "__main__":
    mcp.run()
