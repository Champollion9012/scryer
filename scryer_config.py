"""Centralized configuration / environment loading for Scryer.

Single entry point: ``scryer_config.load()`` is idempotent and safe to call
from any module. After calling it, env vars from the repo's ``.env`` are
available via :func:`os.getenv` or :func:`scryer_config.get`.

Why this module exists
----------------------
Three different modules used to call ``load_dotenv()`` with slightly
different paths and override semantics. This caused subtle bugs where
``.env`` values were loaded only when a specific entry point ran first.
Routing all loads through this module fixes that.

Migration
~~~~~~~~~
Old::

    from dotenv import load_dotenv
    load_dotenv()

New::

    import scryer_config
    scryer_config.load()
    api_key = scryer_config.get("OPENAI_API_KEY")
"""

from __future__ import annotations

import os
import re
from pathlib import Path
from threading import Lock

try:
    from dotenv import load_dotenv as _dotenv_load
except ImportError:  # pragma: no cover - dotenv is a runtime dep
    _dotenv_load = None  # type: ignore[assignment]


_LOAD_LOCK = Lock()
_LOADED: bool = False
_LOADED_FROM: Path | None = None


def _default_env_path() -> Path:
    """Return the canonical .env path next to this module (repo root)."""
    return Path(__file__).resolve().parent / ".env"


def load(
    dotenv_path: str | Path | None = None,
    *,
    override: bool = False,
    force_reload: bool = False,
) -> bool:
    """Load environment variables from ``.env`` if not already loaded.

    Args:
        dotenv_path: Optional explicit path. Defaults to ``<repo>/.env``.
        override: If ``True``, values in the file override existing env vars.
        force_reload: If ``True``, reload even if already loaded once.

    Returns:
        ``True`` if loading happened (file existed and was processed),
        ``False`` if the file was missing or python-dotenv is unavailable.

    Notes:
        - Idempotent: subsequent calls are no-ops unless ``force_reload`` is set.
        - Thread-safe.
        - Never raises on a missing ``.env`` — that's the common case in CI.
    """
    global _LOADED, _LOADED_FROM

    with _LOAD_LOCK:
        if _LOADED and not force_reload:
            return True

        if _dotenv_load is None:
            return False

        path = Path(dotenv_path) if dotenv_path else _default_env_path()
        if not path.is_file():
            # Mark as loaded anyway so we don't re-stat on every call.
            _LOADED = True
            _LOADED_FROM = None
            return False

        _dotenv_load(dotenv_path=str(path), override=override)
        _LOADED = True
        _LOADED_FROM = path
        return True


def loaded_from() -> Path | None:
    """Return the path that was loaded, or ``None`` if no file was found."""
    return _LOADED_FROM


def get(key: str, default: str | None = None) -> str | None:
    """Fetch an env var, auto-loading ``.env`` on first call."""
    if not _LOADED:
        load()
    return os.getenv(key, default)


def get_required(key: str) -> str:
    """Fetch a required env var or raise ``RuntimeError``.

    Useful at CLI entry points so you fail fast instead of deep in a
    request stack with a confusing 401.
    """
    value = get(key)
    if not value:
        raise RuntimeError(
            f"Required environment variable {key!r} is not set. Add it to your .env file or export it in the shell."
        )
    return value


def get_int(key: str, default: int | None = None) -> int | None:
    """Fetch an env var coerced to ``int``."""
    raw = get(key)
    if raw is None or raw == "":
        return default
    try:
        return int(raw)
    except ValueError as exc:
        raise ValueError(f"Env var {key}={raw!r} is not a valid int") from exc


def get_bool(key: str, default: bool = False) -> bool:
    """Fetch an env var coerced to ``bool``.

    Truthy values: ``1``, ``true``, ``yes``, ``on`` (case-insensitive).
    Falsy values: ``0``, ``false``, ``no``, ``off``, empty string.
    """
    raw = get(key)
    if raw is None:
        return default
    return raw.strip().lower() in {"1", "true", "yes", "on"}


def get_list(key: str, separator: str = ",") -> list[str]:
    """Fetch an env var split on a separator (default comma).

    Empty entries are dropped and surrounding whitespace stripped.
    """
    raw = get(key)
    if not raw:
        return []
    return [item.strip() for item in raw.split(separator) if item.strip()]


# --------------------------------------------------------------------------- #
# Per-chain RPC resolution (single source of truth)
# --------------------------------------------------------------------------- #
# The codebase used to carry two RPC conventions: download_contract/data_sources
# read ``RPC_URL`` (single-chain), while rpc_contract_discovery read the
# documented per-chain ``<CHAIN>_URL`` names. These helpers unify both so that
# setting ``BSC_URL`` / ``POLYGON_URL`` / ``ETH_URL`` / … works everywhere.
#
# Resolution order per chain: the per-chain env names (``<CHAIN>_URL`` first,
# then legacy ``*_RPC_URL`` aliases) -> generic ``RPC_URL`` (back-compat) ->
# a public endpoint. Each env value may be a comma- OR whitespace/newline-
# separated list of URLs; first entry is the primary.
_RPC_ENV_NAMES: dict[int, list[str]] = {
    1: ["ETH_URL", "ETH_RPC_URL"],
    10: ["OPTIMISM_URL", "OP_URL", "OPTIMISM_RPC_URL"],
    56: ["BSC_URL", "BSC_RPC_URL"],
    137: ["POLYGON_URL", "POLYGON_RPC_URL"],
    250: ["FANTOM_URL", "FTM_URL", "FANTOM_RPC_URL"],
    8453: ["BASE_URL", "BASE_RPC_URL"],
    42161: ["ARB_URL", "ARBITRUM_RPC_URL", "ARB_RPC_URL"],
    43114: ["AVALANCHE_URL", "AVAX_URL", "AVALANCHE_RPC_URL"],
    # extended EVM chains
    59144: ["LINEA_URL", "LINEA_RPC_URL"],
    534352: ["SCROLL_URL", "SCROLL_RPC_URL"],
    81457: ["BLAST_URL", "BLAST_RPC_URL"],
    5000: ["MANTLE_URL", "MANTLE_RPC_URL"],
    100: ["GNOSIS_URL", "XDAI_URL", "GNOSIS_RPC_URL"],
    324: ["ZKSYNC_URL", "ZKSYNC_RPC_URL"],
    1101: ["POLYGON_ZKEVM_URL", "ZKEVM_URL", "POLYGON_ZKEVM_RPC_URL"],
    204: ["OPBNB_URL", "OPBNB_RPC_URL"],
    42220: ["CELO_URL", "CELO_RPC_URL"],
    25: ["CRONOS_URL", "CRONOS_RPC_URL"],
    1284: ["MOONBEAM_URL", "MOONBEAM_RPC_URL"],
    1088: ["METIS_URL", "METIS_RPC_URL"],
    # Tron: EVM-compatible JSON-RPC (TronGrid /jsonrpc or any Tron JSON-RPC provider)
    728126428: ["TRON_URL", "TRON_RPC_URL"],
}

_PUBLIC_RPC: dict[int, str] = {
    1: "https://ethereum-rpc.publicnode.com",
    10: "https://mainnet.optimism.io",
    56: "https://bsc-dataseed.binance.org",
    137: "https://polygon-rpc.com",
    250: "https://rpc.ftm.tools",
    8453: "https://mainnet.base.org",
    42161: "https://arb1.arbitrum.io/rpc",
    43114: "https://api.avax.network/ext/bc/C/rpc",
    59144: "https://rpc.linea.build",
    534352: "https://rpc.scroll.io",
    81457: "https://rpc.blast.io",
    5000: "https://rpc.mantle.xyz",
    100: "https://rpc.gnosischain.com",
    324: "https://mainnet.era.zksync.io",
    1101: "https://zkevm-rpc.com",
    204: "https://opbnb-mainnet-rpc.bnbchain.org",
    42220: "https://forno.celo.org",
    25: "https://evm.cronos.org",
    1284: "https://rpc.api.moonbeam.network",
    1088: "https://andromeda.metis.io/?owner=1088",
    728126428: "https://api.trongrid.io/jsonrpc",
}

_RPC_SPLIT = re.compile(r"[,\s]+")


def _split_urls(raw: str | None) -> list[str]:
    """Split a comma/whitespace/newline-separated env value into http(s) URLs."""
    if not raw:
        return []
    return [u.strip() for u in _RPC_SPLIT.split(raw.strip()) if u.strip().startswith(("http://", "https://"))]


def rpc_env_names(chain_id: int) -> list[str]:
    """The per-chain RPC env var names honored for ``chain_id`` (documented first)."""
    return list(_RPC_ENV_NAMES.get(chain_id, []))


def get_rpc_urls(chain_id: int) -> list[str]:
    """Ordered, de-duplicated RPC URLs for ``chain_id`` (see resolution order above).

    Always returns at least the public endpoint for a known chain, so callers get
    a working URL even with no env configured.
    """
    out: list[str] = []
    seen: set[str] = set()
    # RPC_URL is the legacy chain-agnostic default; historically it was the BSC/primary
    # node (see DEFAULT_RPC_URL in download_contract). It carries no chain binding, so
    # only honor it for BSC — otherwise a single chain's node leaks into EVERY other
    # chain's RPC list and causes wrong-chain queries.
    names = list(_RPC_ENV_NAMES.get(chain_id, []))
    if chain_id == 56:
        names.append("RPC_URL")
    for name in names:
        for u in _split_urls(get(name)):
            if u not in seen:
                seen.add(u)
                out.append(u)
    pub = _PUBLIC_RPC.get(chain_id)
    if pub and pub not in seen:
        out.append(pub)
    return out


def get_rpc_url(chain_id: int) -> str:
    """Primary RPC URL for ``chain_id`` (first of :func:`get_rpc_urls`), or ``""``."""
    urls = get_rpc_urls(chain_id)
    return urls[0] if urls else ""


# Auto-load on import so legacy modules continue to work without explicit
# load() calls. New code should still call load() at entry points so the
# behaviour is obvious.
load()
