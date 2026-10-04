"""Known-address labels for forensic attribution.

Annotates counterparties / deployers / flow participants with a human label + category (CEX,
mixer, bridge, router, zero/burn, …) from an extensible data file (``known_addresses.json``), so an
analyst isn't left guessing whether ``0x4727…`` is a private wallet or a no-KYC exchange. A wrong
label is worse than none (it was a mislabel that caused a FixedFloat misID), so the seed set is
small and high-confidence; grow the JSON rather than guessing in code.

Most entries are chain-agnostic service addresses (the same address serves many EVM chains), so the
lookup is keyed by address alone.
"""

from __future__ import annotations

import json
from functools import lru_cache
from pathlib import Path

from scryer_logging import get_logger

_log = get_logger(__name__)
_DATA = Path(__file__).resolve().parent / "known_addresses.json"


@lru_cache(maxsize=1)
def _table() -> dict[str, dict]:
    try:
        raw = json.loads(_DATA.read_text(encoding="utf-8"))
    except Exception as e:  # pragma: no cover - missing/broken data file must never break a tool
        _log.warning("known_addresses.json unreadable (%s); labels disabled", e)
        return {}
    out: dict[str, dict] = {}
    for k, v in raw.items():
        if isinstance(k, str) and k.startswith("0x") and isinstance(v, dict):
            out[k.lower()] = {"name": v.get("name"), "category": v.get("category")}
    return out


def label_for(address: str | None) -> dict | None:
    """``{"name", "category"}`` for a known address, else ``None``."""
    if not address:
        return None
    return _table().get(address.lower())
