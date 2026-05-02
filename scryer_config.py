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


# Auto-load on import so legacy modules continue to work without explicit
# load() calls. New code should still call load() at entry points so the
# behaviour is obvious.
load()
