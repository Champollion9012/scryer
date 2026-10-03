"""On-chain state reads — the ground truth an LLM cannot derive from source alone.

An agent can reason about Solidity, but it cannot know the *current* chain state:
who owns the contract, whether it is paused, what a storage slot holds, or how
much money is actually at risk right now. Those facts decide whether a bug is
reachable and how severe it is. This module is scryer's "live sensor": it reads
that state so the connecting agent can ground exploitability and severity in
reality instead of guessing.

RPC endpoints come from scryer_config.get_rpc_url (the unified per-chain resolver).
All functions are best-effort and never raise — they return an ``error`` key.
"""

from __future__ import annotations

import re

import httpx
from eth_abi import decode as abi_decode
from eth_abi import encode as abi_encode
from web3 import Web3

import scryer_config
from scryer_http import RateLimitTally, rate_limit_reason, retry_after_seconds, rpc_rate_limit_reason

# No-argument view selectors worth probing on an unknown contract.
_VIEWS: dict[str, str] = {
    "owner": "8da5cb5b",  # owner()
    "getOwner": "893d20e8",  # getOwner()  (common on BEP20)
    "admin": "f851a440",  # admin()
    "pendingOwner": "e30c3978",  # pendingOwner()
    "paused": "5c975abb",  # paused()
    "implementation": "5c60da1b",  # implementation()
    "name": "06fdde03",  # name()
    "symbol": "95d89b41",  # symbol()
    "decimals": "313ce567",  # decimals()
    "totalSupply": "18160ddd",  # totalSupply()
}
_ADDR = {"owner", "getOwner", "admin", "pendingOwner", "implementation"}
_BOOL = {"paused"}
_UINT = {"decimals", "totalSupply"}
_STR = {"name", "symbol"}

_NATIVE = {
    1: "ETH", 10: "ETH", 56: "BNB", 137: "MATIC", 250: "FTM", 8453: "ETH", 42161: "ETH", 43114: "AVAX",
    59144: "ETH", 534352: "ETH", 81457: "ETH", 5000: "MNT", 100: "xDAI", 324: "ETH", 1101: "ETH",
    204: "BNB", 42220: "CELO", 25: "CRO", 1284: "GLMR", 1088: "METIS",
}

# DeFiLlama (free, no API key) price API: per-chain prefix for tokens, and the
# coingecko id used to price each chain's native coin.
_DL_CHAIN = {
    1: "ethereum", 10: "optimism", 56: "bsc", 137: "polygon", 250: "fantom", 8453: "base",
    42161: "arbitrum", 43114: "avax", 59144: "linea", 534352: "scroll", 81457: "blast", 5000: "mantle",
    100: "xdai", 324: "era", 1101: "polygon_zkevm", 204: "op_bnb", 42220: "celo", 25: "cronos",
    1284: "moonbeam", 1088: "metis",
}
_DL_NATIVE_CGID = {
    1: "ethereum", 10: "ethereum", 42161: "ethereum", 8453: "ethereum", 56: "binancecoin",
    137: "matic-network", 250: "fantom", 43114: "avalanche-2", 59144: "ethereum", 534352: "ethereum",
    81457: "ethereum", 324: "ethereum", 1101: "ethereum", 5000: "mantle", 100: "xdai",
    204: "binancecoin", 42220: "celo", 25: "crypto-com-chain", 1284: "moonbeam", 1088: "metis-token",
}

# Major tokens per chain: (symbol, address, decimals, is_stable). Stablecoin
# balances approximate USD at risk; non-stables are reported unpriced.
_TOKENS: dict[int, list[tuple[str, str, int, bool]]] = {
    1: [
        ("USDT", "0xdAC17F958D2ee523a2206206994597C13D831ec7", 6, True),
        ("USDC", "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48", 6, True),
        ("DAI", "0x6B175474E89094C44Da98b954EedeAC495271d0F", 18, True),
        ("WETH", "0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2", 18, False),
    ],
    56: [
        ("USDT", "0x55d398326f99059fF775485246999027B3197955", 18, True),
        ("USDC", "0x8AC76a51cc950d9822D68b83fE1Ad97B32Cd580d", 18, True),
        ("BUSD", "0xe9e7CEA3DedcA5984780Bafc599bd69ADd087D56", 18, True),
        ("WBNB", "0xbb4CdB9CBd36B01bD1cBaEBF2De08d9173bc095c", 18, False),
    ],
    137: [
        ("USDT", "0xc2132D05D31c914a87C6611C10748AEb04B58e8F", 6, True),
        ("USDC.e", "0x2791Bca1f2de4661ED88A30C99A7a9449Aa84174", 6, True),
    ],
    42161: [
        ("USDT", "0xFd086bC7CD5C481DCC9C85ebE478A1C0b69FCbb9", 6, True),
        ("USDC", "0xaf88d065e77c8cC2239327C5EDb3A432268e5831", 6, True),
    ],
}


def _w3(chain_id: int) -> tuple[Web3, str]:
    # Native RPC if configured, else the Etherscan V2 proxy fallback for niche chains.
    # make_web3 is the single source of truth (shared with download_contract) and injects
    # the POA middleware that POA chains (BSC/Polygon/L2s) need for get_block.
    from etherscan_proxy_provider import make_web3

    return make_web3(chain_id)


def _parse_block(block) -> tuple[object, str | None]:
    """Normalize a block arg to a web3 block_identifier. Returns (block_id, error).

    Accepts None/"latest" (default), an int block number, a decimal or 0x-hex string,
    or a tag (latest/earliest/pending/safe/finalized). Historical blocks need an
    archive RPC.
    """
    if block in (None, "", "latest"):
        return "latest", None
    if isinstance(block, int):
        return block, None
    s = str(block).strip().lower()
    if s in ("latest", "earliest", "pending", "safe", "finalized"):
        return s, None
    try:
        return (int(s, 16) if s.startswith("0x") else int(s)), None
    except ValueError:
        return None, f"invalid block: {block!r} (use a block number, 0x-hex, or a tag like 'latest')"


def _call(
    w3: Web3, address: str, selector: str, suffix: str = "", block: object = "latest", tally: RateLimitTally | None = None
) -> bytes | None:
    try:
        raw = w3.eth.call(
            {"to": Web3.to_checksum_address(address), "data": bytes.fromhex(selector + suffix)},
            block_identifier=block,
        )
        return bytes(raw)
    except Exception as e:
        # A throttled eth_call must not look like a reverted/absent getter. Record it
        # (don't abort — callers probe several selectors) so the tool can surface it.
        if tally is not None:
            tally.note(rpc_rate_limit_reason(e), provider="rpc")
        return None


def _as_str(b: bytes) -> str | None:
    try:
        if len(b) >= 64:  # ABI dynamic string: [offset][length][data]
            length = int.from_bytes(b[32:64], "big")
            if length == 0:
                return None  # a valid empty string -> no value to report
            if 0 < length <= 4096 and len(b) >= 64 + length:
                return b[64 : 64 + length].decode("utf-8", "replace") or None
            return None  # truncated/malformed dynamic string -> don't emit NUL garbage
        if len(b) == 32:  # bytes32-style name/symbol (old tokens like MKR)
            s = b.rstrip(b"\x00").decode("utf-8", "replace").strip()
            return s or None
        return None
    except Exception:
        return None


_PAIR_TOKEN0 = "0dfe1681"  # token0()
_PAIR_TOKEN1 = "d21220a7"  # token1()
_PAIR_RESERVES = "0902f1ac"  # getReserves()


def _pair_state(w3: Web3, address: str, block: object = "latest", tally: RateLimitTally | None = None) -> dict | None:
    """UniswapV2-style pair state (token0/token1/reserves) — the most useful state for a
    pair, which the generic ERC20 getters don't surface. None if it isn't a pair."""
    t0 = _call(w3, address, _PAIR_TOKEN0, block=block, tally=tally)
    t1 = _call(w3, address, _PAIR_TOKEN1, block=block, tally=tally)
    res = _call(w3, address, _PAIR_RESERVES, block=block, tally=tally)
    if not (t0 and t1 and res and len(res) >= 96):
        return None
    out: dict = {}
    if len(t0) >= 20:
        out["token0"] = "0x" + t0[-20:].hex()
    if len(t1) >= 20:
        out["token1"] = "0x" + t1[-20:].hex()
    out["reserve0"] = int.from_bytes(res[0:32], "big")
    out["reserve1"] = int.from_bytes(res[32:64], "big")
    out["blockTimestampLast"] = int.from_bytes(res[64:96], "big")
    return out


def get_state(chain_id: int, address: str, block: object = "latest") -> dict:
    """Probe an unknown contract's live state: owner/admin/pause, proxy impl, ERC20 meta.

    Best-effort eth_call against common no-arg getters — only the ones that answer
    are returned. Tells the agent whether a bug is reachable NOW (e.g. paused,
    who's owner) rather than in theory.
    """
    w3, url = _w3(chain_id)
    blk, berr = _parse_block(block)
    if berr:
        return {"chain_id": chain_id, "address": address.lower(), "error": berr}
    out: dict = {"chain_id": chain_id, "address": address.lower(), "rpc_url": url, "block": blk, "state": {}}
    tally = RateLimitTally()
    try:
        _code = w3.eth.get_code(Web3.to_checksum_address(address), block_identifier=blk)
        out["has_code"] = len(_code) > 0
    except Exception as e:
        reason = rpc_rate_limit_reason(e)
        if reason:
            # Throttled: NOT a factual "no code / not a contract" claim. Surface it and
            # drop the misleading archive-RPC hint so the agent retries instead of concluding EOA.
            return {**out, "rate_limited": True, "warnings": [f"rpc: {reason}"], "error": f"rpc rate-limited: {reason}"}
        return {**out, "error": f"rpc: {type(e).__name__}: {e} (historical reads need an archive RPC)"}
    if not out["has_code"]:
        out["note"] = "no contract code at this address at this block (EOA, not-yet-deployed, or self-destructed)"
        return out
    if blk == "latest":
        # Opportunistic backfill (B): get_state is the highest-traffic tool and already holds the
        # code, so index its bytecode fingerprints for clone matching at zero extra network cost.
        # HEAD only — a historical read would fingerprint the wrong code. Never fatal.
        try:
            from bytecode_abi import record_fingerprints

            record_fingerprints(chain_id, address, bytes(_code).hex())
        except Exception:
            pass
    for name, sel in _VIEWS.items():
        b = _call(w3, address, sel, block=blk, tally=tally)
        if not b:
            continue
        v: str | bool | int | None
        if name in _ADDR:
            # The call succeeded, so report the address even if it is 0x0 — a renounced
            # owner()/admin() (== address(0)) is meaningful and must be distinguishable
            # from a contract that has no such getter (where the call reverts -> b is None).
            v = "0x" + b[-20:].hex() if len(b) >= 20 else None
        elif name in _BOOL:
            v = bool(int.from_bytes(b[-32:], "big"))
        elif name in _UINT:
            v = int.from_bytes(b[-32:], "big")
        elif name in _STR:
            v = _as_str(b)
        else:
            v = None
        if v is not None:
            out["state"][name] = v

    pair = _pair_state(w3, address, block=blk, tally=tally)
    if pair:
        out["pair"] = pair
    if not out["state"] and not pair:
        # Every standard getter reverted. That is ambiguous on its own (non-standard naming vs a
        # proxy shell), so point the caller at the bytecode route instead of returning a bare {}.
        out["note"] = (
            "no standard getter answered (owner/admin/paused/implementation/ERC20...). Either this "
            "contract uses non-standard names or it is a proxy shell — call bytecode_abi(address) to "
            "recover its REAL selectors from bytecode (and its proxy shape), then call_view them."
        )
    return tally.apply(out)


def _parse_slot(slot: int | str) -> int | None:
    if isinstance(slot, int):
        return slot
    s = str(slot).strip()
    try:
        return int(s, 16) if s.lower().startswith("0x") else int(s)  # 0x-hex, else decimal
    except ValueError:
        try:
            return int(s, 16)  # bare hex like 'ff'
        except ValueError:
            return None


_INT_TYPE_RE = re.compile(r"u?int(\d+)$")


def _type_bits(t: str) -> int | None:
    t = t.strip()
    if t == "address":
        return 160
    if t == "bool":
        return 8
    m = _INT_TYPE_RE.match(t)
    return int(m.group(1)) if m else None


def _decode_packed(raw: bytes, decode_as: str):
    """Unpack a 32-byte storage word into Solidity-packed fields (first field = LOW bits)."""
    val = int.from_bytes(raw, "big")
    out = []
    for t in (p.strip() for p in decode_as.split(",")):
        if not t:
            continue
        bits = _type_bits(t)
        if bits is None:
            return {"error": f"unsupported packed type: {t!r} (use uintN/intN/bool/address)"}
        piece = val & ((1 << bits) - 1)
        if t == "address":
            out.append("0x" + format(piece, "040x"))
        elif t == "bool":
            out.append(bool(piece))
        else:
            out.append(piece)
        val >>= bits
    return out


def read_storage(chain_id: int, address: str, slot: int | str, decode_as: str = "", block: object = "latest") -> dict:
    """Read a raw storage slot (eth_getStorageAt) and decode it.

    `slot` accepts an int, a decimal string, or a hex string (0x-prefixed or bare like
    'ff'). `as_address` is reported ONLY when the upper 96 bits are zero (otherwise the
    word is packed, not an address). Pass `decode_as` (e.g. 'uint112,uint112,uint32' for
    a UniV2 reserves slot) to unpack a packed word into fields (first field = low bits).
    `block` pins the read to a historical block (needs an archive RPC); default latest.
    """
    w3, url = _w3(chain_id)
    s = _parse_slot(slot)
    if s is None:
        return {"error": f"invalid slot: {slot!r}"}
    blk, berr = _parse_block(block)
    if berr:
        return {"error": berr}
    try:
        raw = bytes(w3.eth.get_storage_at(Web3.to_checksum_address(address), s, block_identifier=blk))
    except Exception as e:
        reason = rpc_rate_limit_reason(e)
        if reason:
            return {
                "chain_id": chain_id, "address": address.lower(), "slot": hex(s), "block": blk,
                "rate_limited": True, "warnings": [f"rpc: {reason}"], "error": f"rpc rate-limited: {reason}",
            }
        return {"error": f"rpc: {type(e).__name__}: {e} (historical reads need an archive RPC)"}
    out: dict = {
        "chain_id": chain_id,
        "address": address.lower(),
        "slot": hex(s),
        "block": blk,
        "raw": "0x" + raw.hex(),
        "as_uint": int.from_bytes(raw, "big"),
    }
    # Only a clean word whose upper 96 bits are zero (and lower 160 nonzero) is an address.
    if len(raw) >= 32 and int.from_bytes(raw[:12], "big") == 0 and int.from_bytes(raw[12:], "big") != 0:
        out["as_address"] = "0x" + raw[-20:].hex()
    if decode_as:
        out["decoded"] = _decode_packed(raw, decode_as)
    return out


def _sig_input_types(signature: str) -> list[str]:
    i, j = signature.find("("), signature.rfind(")")
    if i < 0 or j < i:
        raise ValueError(f"bad signature {signature!r} (expected e.g. 'getReserves()')")
    inner = signature[i + 1 : j].strip()
    return [t for t in (p.strip() for p in inner.split(",")) if t] if inner else []


def _jsonable(v):
    if isinstance(v, (list, tuple)):
        return [_jsonable(x) for x in v]
    if isinstance(v, (bytes, bytearray)):
        return "0x" + bytes(v).hex()
    return v


def call_view(
    chain_id: int, address: str, signature: str, args: list | None = None, returns: str = "", block: object = "latest"
) -> dict:
    """Call a view/pure function and (optionally) decode the return — no manual slot math.

    signature: e.g. "token0()", "getReserves()", "balanceOf(address)".
    args: argument values matching the signature's input types (ignored if none).
    returns: comma-separated output types for decoding, e.g. "address" or
             "uint112,uint112,uint32". Omit to get only the raw hex.
    block: pin to a historical block (needs an archive RPC); default latest.
    """
    args = args or []
    w3, url = _w3(chain_id)
    blk, berr = _parse_block(block)
    if berr:
        return {"error": berr}
    sig = signature.strip().replace(" ", "")
    try:
        in_types = _sig_input_types(sig)
        selector = Web3.keccak(text=sig)[:4]
        data = selector + (abi_encode(in_types, args) if in_types else b"")
    except Exception as e:
        return {"error": f"encode failed: {type(e).__name__}: {e}"}
    try:
        raw = bytes(
            w3.eth.call({"to": Web3.to_checksum_address(address), "data": "0x" + data.hex()}, block_identifier=blk)
        )
    except Exception as e:
        reason = rpc_rate_limit_reason(e)
        if reason:
            # A throttle is NOT a revert — the view may well return a value; retry, don't conclude "no value".
            return {
                "chain_id": chain_id, "address": address.lower(), "signature": sig, "block": blk,
                "rate_limited": True, "warnings": [f"rpc: {reason}"], "error": f"rpc rate-limited: {reason} (not a revert)",
            }
        return {"error": f"eth_call failed/reverted: {type(e).__name__}: {e}"}
    out: dict = {
        "chain_id": chain_id,
        "address": address.lower(),
        "signature": sig,
        "block": blk,
        "raw": "0x" + raw.hex(),
        "rpc_url": url,
    }
    out_types = [t for t in (p.strip() for p in returns.split(",")) if t] if returns else []
    if out_types:
        try:
            out["decoded"] = _jsonable(abi_decode(out_types, raw))
        except Exception as e:
            out["decode_error"] = f"{type(e).__name__}: {e}"
    return out


def _defillama_prices(
    keys: list[str], timestamp: int | None = None, tally: RateLimitTally | None = None
) -> dict[str, float]:
    """Batch USD prices from DeFiLlama (free, no key). Keys like 'ethereum:0x..' or
    'coingecko:ethereum'. With a unix `timestamp`, uses the historical endpoint so
    prices match a pinned block. Returns {key: price}; empty on any failure. A DeFiLlama
    throttle (429/403/503) is recorded on `tally` so the caller can tell 'throttled'
    (retry for real $-at-risk) from 'no price available'."""
    keys = [k for k in keys if k]
    if not keys:
        return {}
    try:
        base = (
            f"https://coins.llama.fi/prices/historical/{int(timestamp)}/"
            if timestamp
            else "https://coins.llama.fi/prices/current/"
        )
        r = httpx.get(base + ",".join(keys), timeout=15)
        reason = rate_limit_reason(r)  # DeFiLlama throttles are status-based (429/403/503)
        if reason:
            if tally is not None:
                tally.note(reason, provider="defillama", retry_after=retry_after_seconds(r))
            return {}
        coins = r.json().get("coins", {})
        return {k: v["price"] for k, v in coins.items() if isinstance(v, dict) and "price" in v}
    except Exception:
        return {}


def token_exposure(chain_id: int, address: str, block: object = "latest") -> dict:
    """How much value the contract holds right now, in USD — the $-at-risk input to severity.

    Reads native-coin balance + balanceOf for major tokens, then prices everything via
    DeFiLlama (free, no key). total_usd is the quantified impact; each holding carries
    its own usd. Prices are best-effort — usd=null just means DeFiLlama had no price.
    Checks a fixed major-token list per chain, so total_usd is a FLOOR, not exhaustive TVL.
    """
    w3, url = _w3(chain_id)
    blk, berr = _parse_block(block)
    if berr:
        return {"chain_id": chain_id, "address": address.lower(), "error": berr}
    out: dict = {"chain_id": chain_id, "address": address.lower(), "rpc_url": url, "block": blk}
    tally = RateLimitTally()
    checks = Web3.to_checksum_address(address)
    try:
        native = w3.eth.get_balance(checks, block_identifier=blk)
    except Exception as e:
        reason = rpc_rate_limit_reason(e)
        if reason:
            return {**out, "rate_limited": True, "warnings": [f"rpc: {reason}"], "error": f"rpc rate-limited: {reason}"}
        return {**out, "error": f"rpc: {type(e).__name__}: {e} (historical reads need an archive RPC)"}
    native_amt = native / 1e18
    suffix = checks[2:].lower().rjust(64, "0")
    holdings: list[dict] = []
    for sym, taddr, dec, stable in _TOKENS.get(chain_id, []):
        b = _call(w3, taddr, "70a08231", suffix, block=blk, tally=tally)  # balanceOf(address)
        if not b:
            continue
        bal = int.from_bytes(b[-32:], "big")
        if bal == 0:
            continue
        holdings.append({"symbol": sym, "amount": bal / (10**dec), "token": taddr.lower(), "stable": stable})

    # Price native + every held token. If a specific block was pinned, price it at that
    # block's timestamp so balances AND prices are historical (correct $-at-risk for repro).
    ts = None
    if blk != "latest":
        try:
            ts = w3.eth.get_block(blk)["timestamp"]
        except Exception as e:
            ts = None
            reason = rpc_rate_limit_reason(e)
            if reason:
                # Throttled: we fall back to CURRENT pricing for a historical balance — warn
                # rather than silently mis-pricing at the wrong epoch.
                tally.note(f"historical price timestamp unavailable: {reason}", provider="rpc")
    dl_chain = _DL_CHAIN.get(chain_id)
    cgid = _DL_NATIVE_CGID.get(chain_id)
    native_key = f"coingecko:{cgid}" if cgid else ""
    token_keys = {h["token"]: f"{dl_chain}:{h['token']}" for h in holdings} if dl_chain else {}
    prices = _defillama_prices([native_key, *token_keys.values()], timestamp=ts, tally=tally)
    price_throttled = "defillama" in tally.providers

    native_price = prices.get(native_key)
    native_usd = round(native_amt * native_price, 2) if native_price else None
    total = native_usd or 0.0
    for h in holdings:
        p = prices.get(token_keys.get(h["token"], ""))
        h["usd"] = round(h["amount"] * p, 2) if p else None
        if h["usd"]:
            total += h["usd"]

    out["native"] = {"symbol": _NATIVE.get(chain_id, "NATIVE"), "amount": native_amt, "usd": native_usd}
    out["token_holdings"] = holdings
    # A throttled price fetch must NOT be reported as an authoritative $0 — that would deflate
    # the $-at-risk severity input. Report total_usd as UNKNOWN (null) when pricing was throttled.
    out["total_usd"] = None if price_throttled else round(total, 2)
    out["price_source"] = "defillama"
    out["price_block_timestamp"] = ts
    out["note"] = (
        "DeFiLlama pricing was rate-limited: total_usd is UNKNOWN (null), NOT $0 - retry for the real $-at-risk."
        if price_throttled
        else (
            "total_usd = native + priced tokens (DeFiLlama, best-effort; usd=null means no price). "
            "Fixed major-token list per chain, not the full token set - total_usd is a floor, not exhaustive TVL."
        )
    )
    return tally.apply(out)
