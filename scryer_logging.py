"""Structured logging for Scryer.

Wraps the stdlib :mod:`logging` module with sensible defaults so new
modules can do::

    from scryer_logging import get_logger
    log = get_logger(__name__)
    log.info("downloaded %d contracts", n)

instead of ``print()``.

Configuration is driven by env vars (read via :mod:`scryer_config`):

- ``SCRYER_LOG_LEVEL``: ``DEBUG``, ``INFO`` (default), ``WARNING``, ``ERROR``.
- ``SCRYER_LOG_FORMAT``: ``plain`` (default) or ``json``.
- ``SCRYER_LOG_FILE``: optional file path to also write logs to.
"""

from __future__ import annotations

import json
import logging
import sys
from logging import Logger
from pathlib import Path
from threading import Lock

import scryer_config

_CONFIG_LOCK = Lock()
_CONFIGURED: bool = False

_DEFAULT_FORMAT = "%(asctime)s [%(levelname)-7s] %(name)s: %(message)s"
_DEFAULT_DATEFMT = "%Y-%m-%dT%H:%M:%S%z"


class _JsonFormatter(logging.Formatter):
    """Minimal JSON line formatter for log aggregators."""

    def format(self, record: logging.LogRecord) -> str:
        payload: dict[str, object] = {
            "ts": self.formatTime(record, _DEFAULT_DATEFMT),
            "level": record.levelname,
            "logger": record.name,
            "msg": record.getMessage(),
        }
        if record.exc_info:
            payload["exc"] = self.formatException(record.exc_info)
        for key, value in record.__dict__.items():
            if key.startswith("_") or key in _STD_LOG_KEYS:
                continue
            # Only attach JSON-serializable extras. Strings always work.
            try:
                json.dumps(value)
            except (TypeError, ValueError):
                value = repr(value)
            payload[key] = value
        return json.dumps(payload, ensure_ascii=False)


_STD_LOG_KEYS = frozenset(
    {
        "name",
        "msg",
        "args",
        "levelname",
        "levelno",
        "pathname",
        "filename",
        "module",
        "exc_info",
        "exc_text",
        "stack_info",
        "lineno",
        "funcName",
        "created",
        "msecs",
        "relativeCreated",
        "thread",
        "threadName",
        "processName",
        "process",
        "message",
        "asctime",
        "taskName",
    }
)


def configure(
    *,
    level: str | None = None,
    fmt: str | None = None,
    log_file: str | Path | None = None,
    force: bool = False,
) -> None:
    """Configure root logging. Idempotent unless ``force=True``.

    Args:
        level: Override SCRYER_LOG_LEVEL.
        fmt: Override SCRYER_LOG_FORMAT (``plain`` or ``json``).
        log_file: Override SCRYER_LOG_FILE.
        force: Re-apply config even if already configured.
    """
    global _CONFIGURED
    with _CONFIG_LOCK:
        if _CONFIGURED and not force:
            return

        scryer_config.load()
        level_name = (level or scryer_config.get("SCRYER_LOG_LEVEL", "INFO") or "INFO").upper()
        fmt_kind = (fmt or scryer_config.get("SCRYER_LOG_FORMAT", "plain") or "plain").lower()
        file_target = log_file or scryer_config.get("SCRYER_LOG_FILE")

        root = logging.getLogger()
        # Clear handlers if forcing a reconfigure.
        if force:
            for h in list(root.handlers):
                root.removeHandler(h)
        if root.handlers:
            # Something else (Flask / pytest) already configured logging — don't fight it.
            _CONFIGURED = True
            return

        formatter: logging.Formatter
        if fmt_kind == "json":
            formatter = _JsonFormatter()
        else:
            formatter = logging.Formatter(_DEFAULT_FORMAT, datefmt=_DEFAULT_DATEFMT)

        stream_handler = logging.StreamHandler(stream=sys.stderr)
        stream_handler.setFormatter(formatter)
        root.addHandler(stream_handler)

        if file_target:
            file_path = Path(file_target)
            file_path.parent.mkdir(parents=True, exist_ok=True)
            file_handler = logging.FileHandler(file_path, encoding="utf-8")
            file_handler.setFormatter(formatter)
            root.addHandler(file_handler)

        root.setLevel(getattr(logging, level_name, logging.INFO))
        # Tame noisy third-party libs unless the user explicitly wants DEBUG.
        if level_name != "DEBUG":
            for noisy in ("httpx", "httpcore", "urllib3", "chromadb", "asyncio"):
                logging.getLogger(noisy).setLevel(logging.WARNING)

        _CONFIGURED = True


def get_logger(name: str | None = None) -> Logger:
    """Return a configured logger.

    First call also configures the root logger from env vars.
    """
    if not _CONFIGURED:
        configure()
    return logging.getLogger(name)
