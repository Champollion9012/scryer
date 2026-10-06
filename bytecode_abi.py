"""Recover a contract's callable surface from runtime bytecode alone.

For an UNVERIFIED contract there is no source and no ABI, but the function
selectors are still physically present in the dispatcher at the top of the
runtime bytecode. This module:

1. Walks the bytecode opcode-by-opcode (respecting PUSH immediates) and pulls out
   the 4-byte selectors the dispatcher compares against.
2. Reverse-looks-up each selector to a human-readable *function signature*
   (``transfer(address,uint256)``) via openchain.xyz (batched) with a bounded
   4byte.directory fallback. selector = first 4 bytes of keccak(signature), which
   is one-way, so a lookup table is the only way back.
3. Reports the contract's *shape* — delegatecall present, EIP-1167 minimal proxy,
   Diamond (EIP-2535) loupe, and a ``proxy_like`` heuristic — so a caller can tell
   "this is a proxy shell, go find the implementation" from "this is a real
   contract with non-standard function names".

The recovered signature feeds straight into ``call_view(address, signature=...)``,
closing the loop: bytecode -> selector -> signature -> live value.

Walking opcodes correctly matters: a PUSH32 constant can easily contain bytes that
look like ``PUSH4 <sel> EQ``. Naive scanning invents selectors that do not exist.
"""

from __future__ import annotations

import atexit
import json
import threading
from pathlib import Path
from typing import Any

from web3 import Web3

import scryer_http
from scryer_http import RateLimitTally, rate_limit_reason, redact_rpc_url, retry_after_seconds, rpc_rate_limit_reason
from scryer_logging import get_logger
from verify_source import strip_metadata_trailer

_log = get_logger(__name__)

_HTTP = scryer_http.sync_client(timeout=20.0, headers={"User-Agent": "scryer-bytecode-abi/1.0"})
atexit.register(_HTTP.close)

_OPENCHAIN = "https://api.openchain.xyz/signature-database/v1/lookup"
_FOURBYTE = "https://www.4byte.directory/api/v1/signatures/"

# --- EVM opcodes we care about ---------------------------------------------- #
_PUSH1, _PUSH32 = 0x60, 0x7F
_PUSH4 = 0x63
_DUP1, _DUP16 = 0x80, 0x8F
_LT, _GT, _EQ = 0x10, 0x11, 0x14
_DELEGATECALL = 0xF4

# A dispatcher compares the incoming selector; the comparison opcode follows the
# PUSH4 within a couple of instructions (EQ for a linear dispatcher, GT/LT for the
# binary-search pivots an optimized dispatcher emits — pivots are real selectors too).
_COMPARE_OPS = frozenset({_EQ, _GT, _LT})
_COMPARE_WINDOW = 3
# ...AND the dispatcher DUPs the cached selector right before each comparison (DUP1 PUSH4 <sel>
# EQ ...). Requiring a DUP just before the PUSH4 is what separates a real selector from an ordinary
# 4-byte constant compare in business logic (e.g. `require(block.timestamp < 0x5f5e1000)` is
# PUSH4 <const> LT with no preceding DUP) — otherwise such constants become PHANTOM selectors that
# corrupt selector_count and the selector_hash fingerprint.
_LOOKBACK = 2


def _sig_selector(signature: str) -> str:
    """first 4 bytes of keccak256(signature) — the on-chain selector."""
    return "0x" + bytes(Web3.keccak(text=signature))[:4].hex()


# Computed (not hardcoded) so they can never drift from the real signatures.
_DIAMOND_LOUPE = frozenset(
    _sig_selector(s)
    for s in ("facets()", "facetFunctionSelectors(address)", "facetAddresses()", "facetAddress(bytes4)")
)

# EIP-1167 minimal proxy runtime: 363d3d373d3d3d363d73<20-byte impl>5af43d82803e903d91602b57fd5bf3
_EIP1167_PREFIX = bytes.fromhex("363d3d373d3d3d363d73")
_EIP1167_SUFFIX = bytes.fromhex("5af43d82803e903d91602b57fd5bf3")


# --------------------------------------------------------------------------- #
# Pure bytecode analysis (no network)
# --------------------------------------------------------------------------- #
def _hex_to_bytes(runtime_hex: str) -> bytes:
    h = (runtime_hex or "").strip().lower()
    if h.startswith("0x"):
        h = h[2:]
    if len(h) % 2:
        h = h[:-1]
    try:
        return bytes.fromhex(h)
    except ValueError:
        return b""


def _strip_meta_bytes(full: bytes) -> bytes:
    """Drop the Solidity CBOR metadata trailer so it is not walked as code."""
    if not full:
        return full
    stripped_hex = strip_metadata_trailer(full.hex())
    return _hex_to_bytes(stripped_hex)


def _walk(code: bytes):
    """Yield ``(pc, opcode, immediate)``, skipping PUSH immediates properly.

    This is what separates a real selector from four bytes that merely live inside
    a PUSH32 constant.
    """
    i, n = 0, len(code)
    while i < n:
        op = code[i]
        if _PUSH1 <= op <= _PUSH32:
            size = op - 0x5F  # PUSH1 -> 1 ... PUSH32 -> 32
            yield i, op, code[i + 1 : i + 1 + size]
            i += 1 + size
        else:
            yield i, op, b""
            i += 1


def extract_selectors(runtime_hex: str) -> list[str]:
    """Selectors the dispatcher compares against, in first-seen order."""
    code = _strip_meta_bytes(_hex_to_bytes(runtime_hex))
    ops = list(_walk(code))
    out: list[str] = []
    seen: set[str] = set()
    for idx, (_pc, op, imm) in enumerate(ops):
        if op != _PUSH4 or len(imm) != 4:
            continue
        after = ops[idx + 1 : idx + 1 + _COMPARE_WINDOW]
        if not any(w_op in _COMPARE_OPS for _pc2, w_op, _imm2 in after):
            continue  # a PUSH4 that is not compared is a constant, not a selector
        before = ops[max(0, idx - _LOOKBACK) : idx]
        if not any(_DUP1 <= b_op <= _DUP16 for _pc3, b_op, _imm3 in before):
            continue  # no DUP of the cached selector before it -> a business-logic constant, not a selector
        sel = "0x" + imm.hex()
        if sel not in seen:
            seen.add(sel)
            out.append(sel)
    return out


def extract_eip1167_implementation(full: bytes) -> str | None:
    """Implementation address read straight out of an EIP-1167 minimal proxy."""
    if (
        len(full) == len(_EIP1167_PREFIX) + 20 + len(_EIP1167_SUFFIX)
        and full.startswith(_EIP1167_PREFIX)
        and full.endswith(_EIP1167_SUFFIX)
    ):
        return "0x" + full[len(_EIP1167_PREFIX) : len(_EIP1167_PREFIX) + 20].hex()
    return None


def analyze_bytecode(runtime_hex: str) -> dict:
    """Pure shape + selector analysis of runtime bytecode (no network)."""
    full = _hex_to_bytes(runtime_hex)
    code = _strip_meta_bytes(full)
    selectors = extract_selectors(runtime_hex)
    has_delegatecall = any(op == _DELEGATECALL for _pc, op, _imm in _walk(code))
    eip1167 = extract_eip1167_implementation(full)
    diamond_like = len(_DIAMOND_LOUPE.intersection(selectors)) >= 2
    # A proxy shell forwards everything: it has delegatecall but almost no logic
    # or surface of its own. EIP-1167 is a proxy by definition.
    proxy_like = bool(eip1167) or (has_delegatecall and (len(selectors) <= 5 or len(code) <= 800))
    return {
        "code_size": len(full),
        "code_size_stripped": len(code),
        "selectors": selectors,
        "selector_count": len(selectors),
        "has_delegatecall": has_delegatecall,
        "eip1167_implementation": eip1167,
        "diamond_like": diamond_like,
        "proxy_like": proxy_like,
    }


def code_fingerprints(runtime_hex: str) -> dict:
    """Three-tier bytecode identity, for matching an unverified contract to a verified twin.

    The same source does NOT always produce the same runtime bytecode, so one hash is not
    enough:

    - ``runtime_code_hash`` — keccak of the exact runtime. Highest precision; only matches an
      identical redeployment.
    - ``runtime_norm_hash`` — keccak of the runtime with the CBOR metadata trailer removed, so
      the same source compiled on another machine (different metadata / IPFS hash) still
      matches. This is the workhorse tier.
    - ``selector_hash`` — keccak of the sorted selector set: an ABI-surface fingerprint that
      still matches when ``immutable`` values (injected at construction time) or linked library
      addresses make the bytecode itself differ. Lower precision by nature — a vanilla ERC20
      surface is shared by thousands — so callers must weigh it against how many contracts
      share the same hash.
    """
    full = _hex_to_bytes(runtime_hex)
    if not full:
        return {}
    norm = _strip_meta_bytes(full)
    selectors = extract_selectors(runtime_hex)
    out: dict[str, Any] = {
        "runtime_code_hash": "0x" + bytes(Web3.keccak(full)).hex(),
        "runtime_norm_hash": "0x" + bytes(Web3.keccak(norm)).hex(),
        "selector_count": len(selectors),
        "code_size": len(full),
    }
    if selectors:
        out["selector_hash"] = "0x" + bytes(Web3.keccak(text=",".join(sorted(selectors)))).hex()
    return out


def record_fingerprints(chain_id: int, address: str, runtime_hex: str) -> None:
    """Opportunistic backfill: stash this contract's bytecode fingerprints in the registry.

    Called from tools that already hold the runtime bytecode, so the clone index fills with the
    contracts you actually touch at zero extra network cost. Strictly best-effort — a registry
    problem must never break the calling tool.
    """
    try:
        fp = code_fingerprints(runtime_hex)
        if not fp:
            return
        from contract_registry import ContractRegistry

        ContractRegistry().record_code_fingerprints(chain_id, address, fp)
    except Exception as e:  # pragma: no cover - advisory
        _log.debug("fingerprint record failed for %s/%s: %s", chain_id, address, e)


# --------------------------------------------------------------------------- #
# Signature reverse-lookup (selector -> "name(type,type)")
# --------------------------------------------------------------------------- #
_CACHE_PATH = Path(__file__).resolve().parent / ".selector_cache.json"
_cache: dict[str, str] | None = None
_cache_lock = threading.Lock()
_cache_dirty = False


def _cache_load() -> dict[str, str]:
    global _cache
    if _cache is None:
        try:
            _cache = json.loads(_CACHE_PATH.read_text(encoding="utf-8")) if _CACHE_PATH.is_file() else {}
        except Exception:
            _cache = {}
    return _cache


def _cache_flush() -> None:
    """Persist best-effort; a cache failure must never break a lookup."""
    global _cache_dirty
    with _cache_lock:
        if not _cache_dirty or _cache is None:
            return
        try:
            tmp = _CACHE_PATH.with_suffix(".json.tmp")
            tmp.write_text(json.dumps(_cache), encoding="utf-8")
            tmp.replace(_CACHE_PATH)
            _cache_dirty = False
        except Exception as e:  # pragma: no cover - cache is advisory
            _log.debug("selector cache flush failed: %s", e)


def _chunks(items: list[str], size: int):
    for i in range(0, len(items), size):
        yield items[i : i + size]


def params_of(signature: str) -> str | None:
    """The parameter-type list of a signature: ``transfer(address,uint256)`` -> ``address,uint256``.

    This is what decides collision severity: a selector is only 4 bytes, so several signature
    strings can hash to it, but the SELECTOR decides which function is called — the signature
    only decides how arguments are encoded and returns decoded. Candidates that differ only in
    NAME produce identical calldata (cosmetic); candidates that differ in TYPES do not.
    """
    i, j = signature.find("("), signature.rfind(")")
    return signature[i + 1 : j] if 0 <= i < j else None


def resolve_signatures(
    selectors: list[str],
    *,
    tally: RateLimitTally | None = None,
    use_fourbyte: bool = True,
    throttled: set[str] | None = None,
) -> dict[str, list[str]]:
    """Map selector -> ALL candidate signature strings (best-ranked first).

    Deliberately does not collapse to one answer: 4-byte selectors collide, and public
    databases carry deliberately-crafted spam collisions on popular selectors. Returning the
    full candidate list lets the caller see the ambiguity instead of trusting a guess.

    A throttle is recorded on ``tally`` rather than being swallowed into "no signature found" —
    the caller must be able to tell "unknown" from "rate-limited".
    """
    global _cache_dirty
    resolved: dict[str, list[str]] = {}
    cache = _cache_load()
    pending: list[str] = []
    for sel in selectors:
        hit = cache.get(sel)
        if hit:
            resolved[sel] = [hit] if isinstance(hit, str) else list(hit)
        else:
            pending.append(sel)

    # openchain: batched, so N selectors cost ONE request.
    for chunk in _chunks(pending, 50):
        try:
            r = _HTTP.get(_OPENCHAIN, params={"function": ",".join(chunk), "filter": "true"})
            reason = rate_limit_reason(r)
            if reason:
                if tally is not None:
                    tally.note(reason, provider="openchain", retry_after=retry_after_seconds(r))
                if throttled is not None:
                    throttled.update(chunk)  # these are unknown-because-throttled, not unknown
                continue
            fn = ((r.json().get("result") or {}).get("function") or {}) if r.status_code == 200 else {}
            for sel in chunk:
                entries = fn.get(sel) or []
                # Keep EVERY candidate (filter=true already drops openchain's known-junk entries).
                names = [e["name"] for e in entries if isinstance(e, dict) and e.get("name")]
                if names:
                    resolved[sel] = names
                    with _cache_lock:
                        cache[sel] = names
                        _cache_dirty = True
        except Exception as e:
            _log.debug("openchain lookup failed: %s", e)

    # 4byte fallback, bounded: it is one request per selector, so only for a short tail.
    remaining = [s for s in pending if s not in resolved]
    if use_fourbyte and remaining and len(remaining) <= 20:
        for sel in remaining:
            try:
                r = _HTTP.get(_FOURBYTE, params={"hex_signature": sel})
                reason = rate_limit_reason(r)
                if reason:
                    if tally is not None:
                        tally.note(reason, provider="4byte", retry_after=retry_after_seconds(r))
                    if throttled is not None:
                        throttled.update(s for s in remaining if s not in resolved)  # this one + the unreached tail
                    break
                if r.status_code != 200:
                    continue
                results = r.json().get("results") or []
                # Rank by ascending id: the earliest submission predates the spam-collision era,
                # so it is the least likely to be a deliberately crafted fake.
                names = [
                    x["text_signature"]
                    for x in sorted(results, key=lambda x: x.get("id", 1 << 62))
                    if isinstance(x, dict) and x.get("text_signature")
                ]
                if names:
                    resolved[sel] = names
                    with _cache_lock:
                        cache[sel] = names
                        _cache_dirty = True
            except Exception as e:
                _log.debug("4byte lookup failed for %s: %s", sel, e)

    _cache_flush()
    return resolved


# --------------------------------------------------------------------------- #
# Orchestrator: fetch code -> analyze -> resolve
# --------------------------------------------------------------------------- #
def analyze_contract(chain_id: int, address: str, block: object = "latest", *, resolve: bool = True) -> dict:
    """Recover the callable surface + shape of a (possibly unverified) contract."""
    from etherscan_proxy_provider import make_web3
    from onchain_state import _parse_block

    blk, berr = _parse_block(block)
    if berr:
        return {"chain_id": chain_id, "address": address.lower(), "error": berr}

    out: dict[str, Any] = {"chain_id": chain_id, "address": address.lower(), "block": blk}
    tally = RateLimitTally()
    try:
        w3, rpc_label = make_web3(chain_id)
        raw = w3.eth.get_code(Web3.to_checksum_address(address), block_identifier=blk)
    except Exception as e:
        reason = rpc_rate_limit_reason(e)
        if reason:
            return {**out, "rate_limited": True, "warnings": [f"rpc: {reason}"], "error": f"rpc rate-limited: {reason}"}
        return {**out, "error": f"rpc: {type(e).__name__}: {e}"}

    out["rpc_url"] = redact_rpc_url(rpc_label)
    runtime_hex = bytes(raw).hex()
    if not runtime_hex:
        out["code_size"] = 0
        out["note"] = "no code at this address at this block (EOA, not yet deployed, or self-destructed)"
        return out

    out.update(analyze_bytecode(runtime_hex))
    if blk == "latest":
        # Opportunistic backfill (B): we already hold the code, so index it for clone matching.
        # Only at HEAD — a historical read would record a fingerprint for the wrong code.
        record_fingerprints(chain_id, address, runtime_hex)

    selectors: list[str] = out.get("selectors", [])
    if resolve and selectors:
        throttled: set[str] = set()
        sigs = resolve_signatures(selectors, tally=tally, throttled=throttled)
        entries: list[dict] = []
        ambiguous = 0
        for s in selectors:
            cands = sigs.get(s) or []
            entry: dict[str, Any] = {"hex": s}
            if cands:
                entry["signature"] = cands[0]  # best-ranked candidate, NOT a fact
                if len(cands) > 1:
                    entry["candidates"] = cands
                    # Only a TYPE difference changes the calldata encoding; a name-only
                    # difference is cosmetic and safe to call with any candidate.
                    entry["collision"] = True
                    entry["collision_cosmetic"] = len({params_of(c) for c in cands}) == 1
                    if not entry["collision_cosmetic"]:
                        ambiguous += 1
            entries.append(entry)
        out["selectors"] = entries
        out["resolved_count"] = sum(1 for e in entries if "signature" in e)
        # Keep "genuinely unknown" separate from "unknown because the lookup was throttled" —
        # otherwise a 429 masquerades as "not in any signature DB" (the swallow this guards against).
        out["unresolved"] = [s for s in selectors if s not in sigs and s not in throttled]
        if throttled:
            out["rate_limited_selectors"] = [s for s in selectors if s in throttled]
        if ambiguous:
            out["ambiguous_count"] = ambiguous
    else:
        out["selectors"] = [{"hex": s} for s in selectors]
        out["unresolved"] = list(selectors)

    note = _shape_note(out)
    if out.get("ambiguous_count"):
        note += (
            f" COLLISIONS: {out['ambiguous_count']} selector(s) have candidates with DIFFERENT parameter "
            "types (collision_cosmetic:false). A 4-byte selector collides by design and public databases "
            "carry deliberately-crafted spam collisions — the `hex` selector is FACT, the `signature` is a "
            "GUESS. Disambiguate by call_view-ing each candidate's types and keeping the one that decodes "
            "sensibly. Candidates differing only in NAME (collision_cosmetic:true) encode identical "
            "calldata, so any of them is safe to call."
        )
    out["note"] = note
    return tally.apply(out)


def _shape_note(info: dict) -> str:
    if info.get("eip1167_implementation"):
        return (
            f"EIP-1167 minimal proxy — the real logic is at {info['eip1167_implementation']}. "
            "Analyze THAT address, not this shell."
        )
    if info.get("diamond_like"):
        return (
            "Diamond (EIP-2535) detected — logic is split across facets. "
            "call_view facetAddresses()/facets() to enumerate them, then analyze each facet."
        )
    if info.get("proxy_like"):
        return (
            "Looks like a PROXY SHELL (delegatecall + almost no surface of its own) but no standard "
            "implementation slot was found — it is a non-standard proxy. Hunt the implementation "
            "(read_storage across candidate slots) instead of analyzing this bytecode."
        )
    if info.get("code_size") and not info.get("selector_count"):
        return (
            "Code exists but NO function selectors were found — there is no standard Solidity "
            "dispatcher here. Likely a hand-written/assembly contract, a Vyper contract (different "
            "dispatcher shape, which this extractor reads less reliably), a data-only/SSTORE2 blob, or "
            "an obfuscated dispatcher. There is no ABI to call: probe with raw calldata, read storage "
            "slots, and check the disassembly for CALLDATASIZE/CALLVALUE gating."
        )
    return (
        "Standalone contract. Feed each recovered signature to call_view to read live values; "
        "`unresolved` selectors exist but are not in any public signature database."
    )
