"""Tron support for Scryer.

Tron is EVM-compatible over TronGrid's JSON-RPC (chain id 728126428 / 0x2b6653dc): eth_call,
eth_getLogs (5000-block range cap), receipts and block headers all answer like an EVM node. What
differs is the address format: humans, explorers and every Tron tool write accounts as base58check
``T…`` strings, which are just ``0x41`` + the same 20-byte account the JSON-RPC speaks as ``0x…``.

These helpers let every chain-taking tool accept ``T…`` addresses (converted to the 20-byte hex the
node expects) and render results back in ``T…`` form, so output lines up with TronScan. TRC20 token
amounts are ordinary ERC20 Transfer logs; native TRX balances are in sun (6 decimals), not wei.
"""

from __future__ import annotations

import hashlib
import re
from typing import Any

TRON_CHAIN_ID = 728126428
TRON_NATIVE_DECIMALS = 6

_B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
_TRON_RE = re.compile(r"^T[1-9A-HJ-NP-Za-km-z]{33}$")
_HEX_ADDR_RE = re.compile(r"^0x[0-9a-fA-F]{40}$")


def is_tron(chain_id: int) -> bool:
    return int(chain_id or 0) == TRON_CHAIN_ID


def is_tron_address(value: Any) -> bool:
    return isinstance(value, str) and bool(_TRON_RE.fullmatch(value))


def _checksum(payload: bytes) -> bytes:
    return hashlib.sha256(hashlib.sha256(payload).digest()).digest()[:4]


def to_hex(address: str) -> str:
    """``T…`` base58check -> ``0x`` + 20-byte hex (lowercase). A ``0x`` address passes through."""
    if _HEX_ADDR_RE.fullmatch(address or ""):
        return address.lower()
    if not is_tron_address(address):
        raise ValueError(f"not a Tron base58 address: {address!r}")
    n = 0
    for ch in address:
        n = n * 58 + _B58.index(ch)
    raw = n.to_bytes(25, "big")
    if raw[0] != 0x41 or _checksum(raw[:21]) != raw[21:]:
        raise ValueError(f"bad Tron address checksum: {address!r}")
    return "0x" + raw[1:21].hex()


def to_base58(hex_address: str) -> str:
    """``0x`` + 20-byte hex -> ``T…`` base58check."""
    if not _HEX_ADDR_RE.fullmatch(hex_address or ""):
        raise ValueError(f"not a 20-byte hex address: {hex_address!r}")
    payload = bytes.fromhex("41" + hex_address[2:])
    n = int.from_bytes(payload + _checksum(payload), "big")
    out = ""
    while n:
        n, r = divmod(n, 58)
        out = _B58[r] + out
    return out


def normalize_address(value: Any) -> Any:
    """A ``T…`` address becomes the 20-byte hex the JSON-RPC expects; anything else is unchanged.
    Callers apply it only on Tron — on an EVM chain the same 20 bytes are an unrelated account."""
    return to_hex(value) if is_tron_address(value) else value


def _is_address_type(abi_type: str) -> tuple[bool, bool]:
    """(is an address, is an address array) for an ABI type string."""
    t = abi_type.replace(" ", "")
    return t == "address", t.startswith("address[")


def normalize_typed(abi_type: str, value: Any) -> Any:
    """Convert ``T…`` only where the ABI type is ``address`` / ``address[…]``. A string or bytes
    argument that happens to look like a Tron address is passed through untouched."""
    single, array = _is_address_type(abi_type)
    if single:
        return normalize_address(value)
    if array and isinstance(value, (list, tuple)):
        return [normalize_address(v) for v in value]
    return value


def render_typed(abi_type: str, value: Any) -> Any:
    """Decoded-return counterpart of ``normalize_typed``: address-typed values become ``T…``; a
    bytes20 / uint160 / string that merely looks like an address is left alone."""
    single, array = _is_address_type(abi_type)
    if single and isinstance(value, str) and _HEX_ADDR_RE.fullmatch(value):
        return to_base58(value)
    if array and isinstance(value, (list, tuple)):
        return [to_base58(v) if isinstance(v, str) and _HEX_ADDR_RE.fullmatch(v) else v for v in value]
    return value


def tronify(obj: Any, skip_keys: tuple[str, ...] = ()) -> Any:
    """Render every 20-byte hex address in a result (dict keys and values, nested) as ``T…``.

    Only strings that are exactly ``0x`` + 40 hex chars are touched — tx hashes, topics, selectors
    and raw call data keep their hex form. Values under ``skip_keys`` (e.g. ABI-decoded returns,
    which must be rendered by type) are left as they are."""
    if isinstance(obj, dict):
        return {tronify(k): (v if k in skip_keys else tronify(v, skip_keys)) for k, v in obj.items()}
    if isinstance(obj, list):
        return [tronify(v, skip_keys) for v in obj]
    if isinstance(obj, tuple):
        return tuple(tronify(v, skip_keys) for v in obj)
    if isinstance(obj, str) and _HEX_ADDR_RE.fullmatch(obj):
        return to_base58(obj)
    return obj
