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

import scryer_tron
from scryer_http import RateLimitTally, rate_limit_reason, redact_rpc_url, retry_after_seconds, rpc_rate_limit_reason

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
    1: "ETH",
    10: "ETH",
    56: "BNB",
    137: "MATIC",
    250: "FTM",
    8453: "ETH",
    42161: "ETH",
    43114: "AVAX",
    59144: "ETH",
    534352: "ETH",
    81457: "ETH",
    5000: "MNT",
    100: "xDAI",
    324: "ETH",
    1101: "ETH",
    204: "BNB",
    42220: "CELO",
    25: "CRO",
    1284: "GLMR",
    1088: "METIS",
    728126428: "TRX",
}

# DeFiLlama (free, no API key) price API: per-chain prefix for tokens, and the
# coingecko id used to price each chain's native coin.
_DL_CHAIN = {
    1: "ethereum",
    10: "optimism",
    56: "bsc",
    137: "polygon",
    250: "fantom",
    8453: "base",
    42161: "arbitrum",
    43114: "avax",
    59144: "linea",
    534352: "scroll",
    81457: "blast",
    5000: "mantle",
    100: "xdai",
    324: "era",
    1101: "polygon_zkevm",
    204: "op_bnb",
    42220: "celo",
    25: "cronos",
    1284: "moonbeam",
    1088: "metis",
    728126428: "tron",  # DeFiLlama keys Tron tokens by base58 ("tron:T…"), see token_exposure
}
_DL_NATIVE_CGID = {
    1: "ethereum",
    10: "ethereum",
    42161: "ethereum",
    8453: "ethereum",
    56: "binancecoin",
    137: "matic-network",
    250: "fantom",
    43114: "avalanche-2",
    59144: "ethereum",
    534352: "ethereum",
    81457: "ethereum",
    324: "ethereum",
    1101: "ethereum",
    5000: "mantle",
    100: "xdai",
    204: "binancecoin",
    42220: "celo",
    25: "crypto-com-chain",
    1284: "moonbeam",
    1088: "metis-token",
    728126428: "tron",
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
    # Tron TRC20 (the JSON-RPC speaks the 20-byte hex form of the T… address)
    728126428: [
        ("USDT", scryer_tron.to_hex("TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t"), 6, True),
        ("USDC", scryer_tron.to_hex("TEkxiTehnzSmSe2XqrBj4w32RUN966rdz8"), 6, True),
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
    w3: Web3,
    address: str,
    selector: str,
    suffix: str = "",
    block: object = "latest",
    tally: RateLimitTally | None = None,
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
    out: dict = {
        "chain_id": chain_id,
        "address": address.lower(),
        "rpc_url": redact_rpc_url(url),
        "block": blk,
        "state": {},
    }
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
                "chain_id": chain_id,
                "address": address.lower(),
                "slot": hex(s),
                "block": blk,
                "rate_limited": True,
                "warnings": [f"rpc: {reason}"],
                "error": f"rpc rate-limited: {reason}",
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
                "chain_id": chain_id,
                "address": address.lower(),
                "signature": sig,
                "block": blk,
                "rate_limited": True,
                "warnings": [f"rpc: {reason}"],
                "error": f"rpc rate-limited: {reason} (not a revert)",
            }
        return {"error": f"eth_call failed/reverted: {type(e).__name__}: {e}"}
    out: dict = {
        "chain_id": chain_id,
        "address": address.lower(),
        "signature": sig,
        "block": blk,
        "raw": "0x" + raw.hex(),
        "rpc_url": redact_rpc_url(url),
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


# UniswapV2-style DEX per chain, for the on-chain LP pricing fallback: (factory, CREATE2 pair
# init-code hash, WETH/wrapped-native (addr, decimals), USD stable (addr, decimals)). The pair
# address is derived deterministically (no factory call), reserves give the price. Verified against
# the canonical Uniswap-V2 USDC/WETH and PancakeSwap-V2 WBNB/BUSD pair addresses.
_DEX_V2: dict[int, dict] = {
    1: {
        "factory": "0x5C69bEe701ef814a2B6a3EDD4B1652CB9cc5aA6f",
        "init_code_hash": "0x96e8ac4277198ff8b6f785478aa9a39f403cb768dd02cbee326c3e7da348845f",
        "weth": ("0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2", 18),
        "usd": ("0xdAC17F958D2ee523a2206206994597C13D831ec7", 6),  # USDT
    },
    56: {
        "factory": "0xcA143Ce32Fe78f1f7019d7d551a6402fC5350c73",
        "init_code_hash": "0x00fb7f630766e6a796048ea87d01acd3068e8ff67d078148a3fa3f4a84f69bd5",
        "weth": ("0xbb4CdB9CBd36B01bD1cBaEBF2De08d9173bc095c", 18),  # WBNB
        "usd": ("0x55d398326f99059fF775485246999027B3197955", 18),  # USDT (18 on BSC)
    },
}


def _v2_pair(factory: str, init_code_hash: str, token_a: str, token_b: str) -> str:
    """CREATE2 address of the UniswapV2 pair for (token_a, token_b) — no factory call needed."""
    a = bytes.fromhex(token_a[2:])
    b = bytes.fromhex(token_b[2:])
    t0, t1 = (a, b) if a < b else (b, a)
    salt = Web3.keccak(t0 + t1)
    pre = b"\xff" + bytes.fromhex(factory[2:]) + salt + bytes.fromhex(init_code_hash[2:])
    return "0x" + bytes(Web3.keccak(pre))[-20:].hex()


def _price_via_pair(
    w3: Web3,
    cfg: dict,
    token: str,
    token_dec: int,
    quote: str,
    quote_dec: int,
    block: object,
    tally: RateLimitTally | None,
) -> tuple[float | None, float]:
    """``(price_of_token_in_quote, quote_side_depth)`` from the derived pair's reserves — the depth
    (quote reserve in whole units) lets the caller compare routes and reject a dust pool. Returns
    ``(None, 0.0)`` if the pair has no liquidity or does not hold this exact token/quote pair."""
    pair = _v2_pair(cfg["factory"], cfg["init_code_hash"], token, quote)
    st = _pair_state(w3, pair, block=block, tally=tally)
    if not st:
        return None, 0.0
    t0 = (st.get("token0") or "").lower()
    t1 = (st.get("token1") or "").lower()
    if token == t0 and quote == t1:
        r_token, r_quote = st["reserve0"], st["reserve1"]
    elif token == t1 and quote == t0:
        r_token, r_quote = st["reserve1"], st["reserve0"]
    else:
        return None, 0.0  # derived pair isn't this token/quote (collision / not deployed)
    if r_token == 0:
        return None, 0.0
    quote_depth = r_quote / 10**quote_dec
    return quote_depth / (r_token / 10**token_dec), quote_depth


def _lp_price_usd(
    w3: Web3, chain_id: int, token: str, token_dec: int, block: object = "latest", tally: RateLimitTally | None = None
) -> tuple[float | None, str | None]:
    """Best-effort USD price of ``token`` from on-chain LP reserves, via whichever route has the
    DEEPEST liquidity: token/USD direct, or token/WETH x WETH/USD. Picking by depth (not "first
    pair found") is essential — a dust/attacker-seeded token/USD pair ($34) must never outvote the
    real token/WETH pool ($2.8M). Returns (price, source) or (None, None). The route for meme/
    non-major tokens that price feeds don't cover."""
    cfg = _DEX_V2.get(chain_id)
    if not cfg:
        return None, None
    token = token.lower()
    usd_addr, usd_dec = cfg["usd"][0].lower(), cfg["usd"][1]
    weth_addr, weth_dec = cfg["weth"][0].lower(), cfg["weth"][1]
    if token == usd_addr:
        return 1.0, "lp:is_usd"

    # (depth_in_usd, price_in_usd, source) for each viable route; pick the deepest.
    candidates: list[tuple[float, float, str]] = []

    p_usd, depth_usd = _price_via_pair(w3, cfg, token, token_dec, usd_addr, usd_dec, block, tally)
    if p_usd is not None:
        candidates.append((depth_usd, p_usd, "lp:token/usd"))  # USD depth ~ quote reserve in USD

    weth_usd, _wd = (
        (1.0, 0.0)
        if weth_addr == usd_addr
        else _price_via_pair(w3, cfg, weth_addr, weth_dec, usd_addr, usd_dec, block, tally)
    )
    if token == weth_addr:
        return (weth_usd, "lp:weth/usd") if weth_usd is not None else (None, None)
    if weth_usd is not None:
        p_weth, depth_weth = _price_via_pair(w3, cfg, token, token_dec, weth_addr, weth_dec, block, tally)
        if p_weth is not None:
            candidates.append((depth_weth * weth_usd, p_weth * weth_usd, "lp:token/weth/usd"))

    if not candidates:
        return None, None
    _depth, price, source = max(candidates, key=lambda c: c[0])
    return price, source


def _token_decimals(w3: Web3, token: str, block: object, tally: RateLimitTally | None) -> int:
    """ERC20 decimals(), defaulting to 18 if the getter is absent/reverts."""
    b = _call(w3, token, "313ce567", block=block, tally=tally)  # decimals()
    if b:
        d = int.from_bytes(b[-32:], "big")
        if 0 < d <= 36:
            return d
    return 18


def price_token(chain_id: int, token: str, block: object = "latest") -> dict:
    """USD price of any token: DeFiLlama first, then the on-chain LP route (so meme/non-major
    tokens still get a figure). ``price_source`` says which produced it; price is null if neither
    could. The LP route needs a known DEX for the chain (see ``_DEX_V2``)."""
    w3, url = _w3(chain_id)
    blk, berr = _parse_block(block)
    if berr:
        return {"chain_id": chain_id, "token": token.lower(), "error": berr}
    tally = RateLimitTally()
    taddr = token.lower()
    out: dict = {"chain_id": chain_id, "token": taddr, "rpc_url": redact_rpc_url(url), "block": blk}
    dl_chain = _DL_CHAIN.get(chain_id)
    ts = None
    if blk != "latest":
        try:
            ts = w3.eth.get_block(blk)["timestamp"]  # type: ignore[arg-type]  # blk validated by _parse_block
        except Exception:
            ts = None
    if dl_chain:
        dl_key = f"{dl_chain}:{scryer_tron.to_base58(taddr) if scryer_tron.is_tron(chain_id) else taddr}"
        dl = _defillama_prices([dl_key], timestamp=ts, tally=tally)
        p = dl.get(dl_key)
        if p:
            out.update(price=p, price_source="defillama")
            return tally.apply(out)
    dec = _token_decimals(w3, taddr, blk, tally)
    lp_price, lp_src = _lp_price_usd(w3, chain_id, taddr, dec, block=blk, tally=tally)
    out.update(price=lp_price, price_source=lp_src, decimals=dec)
    if lp_price is None and "defillama" in tally.providers:
        out["note"] = "DeFiLlama was rate-limited and no LP route priced it — price UNKNOWN (null), retry."
    elif lp_price is None:
        out["note"] = "no DeFiLlama price and no on-chain LP route found for this token on this chain."
    return tally.apply(out)


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
    out: dict = {"chain_id": chain_id, "address": address.lower(), "rpc_url": redact_rpc_url(url), "block": blk}
    tally = RateLimitTally()
    checks = Web3.to_checksum_address(address)
    try:
        native = w3.eth.get_balance(checks, block_identifier=blk)
    except Exception as e:
        reason = rpc_rate_limit_reason(e)
        if reason:
            return {**out, "rate_limited": True, "warnings": [f"rpc: {reason}"], "error": f"rpc rate-limited: {reason}"}
        return {**out, "error": f"rpc: {type(e).__name__}: {e} (historical reads need an archive RPC)"}
    tron = scryer_tron.is_tron(chain_id)
    native_amt = native / 10 ** (scryer_tron.TRON_NATIVE_DECIMALS if tron else 18)  # TRX is in sun, not wei
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
    token_keys = (
        {h["token"]: f"{dl_chain}:{scryer_tron.to_base58(h['token']) if tron else h['token']}" for h in holdings}
        if dl_chain
        else {}
    )
    prices = _defillama_prices([native_key, *token_keys.values()], timestamp=ts, tally=tally)
    price_throttled = "defillama" in tally.providers

    dec_by_token = {addr.lower(): dec for _s, addr, dec, _st in _TOKENS.get(chain_id, [])}
    native_price = prices.get(native_key)
    native_usd = round(native_amt * native_price, 2) if native_price else None
    total = native_usd or 0.0
    used_lp = False
    for h in holdings:
        p = prices.get(token_keys.get(h["token"], ""))
        if p:
            h["price_source"] = "defillama"
        elif not price_throttled:
            # DeFiLlama had no price -> derive one from on-chain LP reserves (meme/non-major tokens).
            lp_p, lp_src = _lp_price_usd(
                w3, chain_id, h["token"], dec_by_token.get(h["token"], 18), block=blk, tally=tally
            )
            if lp_p is not None:
                p, h["price_source"], used_lp = lp_p, lp_src, True
            else:
                h["price_source"] = None
        else:
            h["price_source"] = None
        h["usd"] = round(h["amount"] * p, 2) if p else None
        if h["usd"]:
            total += h["usd"]

    out["native"] = {"symbol": _NATIVE.get(chain_id, "NATIVE"), "amount": native_amt, "usd": native_usd}
    out["token_holdings"] = holdings
    # A throttled price fetch must NOT be reported as an authoritative $0 — that would deflate
    # the $-at-risk severity input. Report total_usd as UNKNOWN (null) when pricing was throttled.
    out["total_usd"] = None if price_throttled else round(total, 2)
    out["price_source"] = "defillama+lp_route" if used_lp else "defillama"
    out["price_block_timestamp"] = ts
    out["note"] = (
        "DeFiLlama pricing was rate-limited: total_usd is UNKNOWN (null), NOT $0 - retry for the real $-at-risk."
        if price_throttled
        else (
            "total_usd = native + priced tokens (DeFiLlama, then on-chain LP route as fallback; each holding's "
            "price_source says which, usd=null means neither priced it). Fixed major-token list per chain, not the "
            "full token set - total_usd is a floor, not exhaustive TVL."
        )
    )
    return tally.apply(out)
