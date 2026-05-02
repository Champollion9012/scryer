"""Tests for scryer_logging."""

from __future__ import annotations

import json
import logging
from pathlib import Path

import pytest

import scryer_logging


def test_get_logger_returns_logger() -> None:
    log = scryer_logging.get_logger("scryer.test")
    assert isinstance(log, logging.Logger)
    assert log.name == "scryer.test"


def test_configure_is_idempotent() -> None:
    scryer_logging.configure(level="WARNING")
    handler_count = len(logging.getLogger().handlers)
    scryer_logging.configure(level="DEBUG")  # second call is a no-op
    assert len(logging.getLogger().handlers) == handler_count


def test_configure_force_reapplies(monkeypatch: pytest.MonkeyPatch) -> None:
    scryer_logging.configure(level="WARNING", force=True)
    assert logging.getLogger().level == logging.WARNING
    scryer_logging.configure(level="DEBUG", force=True)
    assert logging.getLogger().level == logging.DEBUG


def test_log_to_file(tmp_path: Path) -> None:
    log_file = tmp_path / "scryer.log"
    scryer_logging.configure(level="INFO", log_file=log_file, force=True)
    log = scryer_logging.get_logger("scryer.filetest")
    log.info("hello %s", "world")
    # Flush / close handlers so Windows can read the file.
    for h in logging.getLogger().handlers:
        h.flush()
    contents = log_file.read_text(encoding="utf-8")
    assert "hello world" in contents
    assert "scryer.filetest" in contents


def test_json_format(tmp_path: Path) -> None:
    log_file = tmp_path / "scryer.log"
    scryer_logging.configure(level="INFO", fmt="json", log_file=log_file, force=True)
    log = scryer_logging.get_logger("scryer.jsontest")
    log.info("structured message")
    for h in logging.getLogger().handlers:
        h.flush()
    line = log_file.read_text(encoding="utf-8").strip().splitlines()[-1]
    payload = json.loads(line)
    assert payload["msg"] == "structured message"
    assert payload["level"] == "INFO"
    assert payload["logger"] == "scryer.jsontest"


def test_env_drives_level(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("SCRYER_LOG_LEVEL", "ERROR")
    scryer_logging.configure(force=True)
    assert logging.getLogger().level == logging.ERROR
