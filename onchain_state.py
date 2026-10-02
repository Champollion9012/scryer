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

from web3 import Web3

import scryer_config

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

_NATIVE = {1: "ETH", 10: "ETH", 56: "BNB", 137: "MATIC", 250: "FTM", 8453: "ETH", 42161: "ETH", 43114: "AVAX"}

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
    url = scryer_config.get_rpc_url(chain_id)
    return Web3(Web3.HTTPProvider(url)), url


def _call(w3: Web3, address: str, selector: str, suffix: str = "") -> bytes | None:
    try:
        raw = w3.eth.call({"to": Web3.to_checksum_address(address), "data": bytes.fromhex(selector + suffix)})
        return bytes(raw)
    except Exception:
        return None


def _as_addr(b: bytes) -> str | None:
    if not b or len(b) < 20:
        return None
    a = b[-20:]
    return "0x" + a.hex() if int.from_bytes(a, "big") else None


def _as_str(b: bytes) -> str | None:
    try:
        if len(b) >= 64:
            length = int.from_bytes(b[32:64], "big")
            if 0 < length <= 256 and len(b) >= 64 + length:
                return b[64 : 64 + length].decode("utf-8", "replace") or None
        s = b.rstrip(b"\x00").decode("utf-8", "replace").strip()  # bytes32-style (old tokens)
        return s or None
    except Exception:
        return None


def get_state(chain_id: int, address: str) -> dict:
    """Probe an unknown contract's live state: owner/admin/pause, proxy impl, ERC20 meta.

    Best-effort eth_call against common no-arg getters — only the ones that answer
    are returned. Tells the agent whether a bug is reachable NOW (e.g. paused,
    who's owner) rather than in theory.
    """
    w3, url = _w3(chain_id)
    out: dict = {"chain_id": chain_id, "address": address.lower(), "rpc_url": url, "state": {}}
    try:
        out["has_code"] = len(w3.eth.get_code(Web3.to_checksum_address(address))) > 0
    except Exception as e:
        return {**out, "error": f"rpc: {type(e).__name__}: {e}"}
    if not out["has_code"]:
        out["note"] = "no contract code at this address (EOA or self-destructed)"
        return out
    for name, sel in _VIEWS.items():
        b = _call(w3, address, sel)
        if not b:
            continue
        v: str | bool | int | None
        if name in _ADDR:
            v = _as_addr(b)
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
    return out


def read_storage(chain_id: int, address: str, slot: int | str) -> dict:
    """Read a raw storage slot (eth_getStorageAt) and decode it as uint/address.

    For confirming the actual stored value behind getters, custom proxy slots,
    packed flags, role mappings, etc. `slot` accepts an int or a hex string.
    """
    w3, url = _w3(chain_id)
    try:
        s = int(slot, 16) if isinstance(slot, str) and slot.startswith("0x") else int(slot)
    except Exception:
        return {"error": f"invalid slot: {slot!r}"}
    try:
        raw = bytes(w3.eth.get_storage_at(Web3.to_checksum_address(address), s))
    except Exception as e:
        return {"error": f"rpc: {type(e).__name__}: {e}"}
    return {
        "chain_id": chain_id,
        "address": address.lower(),
        "slot": hex(s),
        "raw": "0x" + raw.hex(),
        "as_uint": int.from_bytes(raw, "big"),
        "as_address": _as_addr(raw),
    }


def token_exposure(chain_id: int, address: str) -> dict:
    """How much value this contract currently holds — the $-at-risk input to severity.

    Reads native-coin balance + balanceOf for major tokens. Stablecoin balances
    are summed as an approximate USD figure; native and non-stables are reported
    unpriced (add a price feed for exact TVL). Empty holdings ≠ harmless, but real
    balances turn a theoretical bug into a quantified one.
    """
    w3, url = _w3(chain_id)
    out: dict = {"chain_id": chain_id, "address": address.lower(), "rpc_url": url}
    checks = Web3.to_checksum_address(address)
    try:
        native = w3.eth.get_balance(checks)
    except Exception as e:
        return {**out, "error": f"rpc: {type(e).__name__}: {e}"}
    out["native"] = {"symbol": _NATIVE.get(chain_id, "NATIVE"), "wei": native, "amount": native / 1e18}
    suffix = checks[2:].lower().rjust(64, "0")
    holdings: list[dict] = []
    stable_usd = 0.0
    for sym, taddr, dec, stable in _TOKENS.get(chain_id, []):
        b = _call(w3, taddr, "70a08231", suffix)  # balanceOf(address)
        if not b:
            continue
        bal = int.from_bytes(b[-32:], "big")
        if bal == 0:
            continue
        amt = bal / (10**dec)
        holdings.append({"symbol": sym, "amount": amt, "token": taddr.lower(), "stable": stable})
        if stable:
            stable_usd += amt
    out["token_holdings"] = holdings
    out["stablecoin_usd_approx"] = round(stable_usd, 2)
    out["note"] = (
        "stablecoin_usd_approx ~ USD held in major stables; native coin and non-stable tokens are "
        "unpriced here. Checked a fixed major-token list per chain, not the full token set."
    )
    return out
