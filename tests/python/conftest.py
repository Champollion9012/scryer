"""Shared pytest fixtures for Scryer.

The tests intentionally avoid network access and external binaries
(slither / forge / heimdall). Anything that would touch those is either
skipped or stubbed.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

# Ensure the repo root is importable when pytest is run from anywhere.
REPO_ROOT = Path(__file__).resolve().parents[2]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))


@pytest.fixture
def repo_root() -> Path:
    return REPO_ROOT


@pytest.fixture(autouse=True)
def _isolate_env(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    """Prevent tests from picking up the developer's real .env / API keys.

    - Strip any pre-existing API keys from os.environ.
    - Reset scryer_config / scryer_logging singletons between tests.
    """
    for key in (
        "OPENAI_API_KEY",
        "ANTHROPIC_API_KEY",
        "GOOGLE_API_KEY",
        "GEMINI_API_KEY",
        "BSCSCAN_API_KEY",
        "ETHERSCAN_API_KEY",
        "SOCKS_PROXY",
        "SCRYER_LOG_LEVEL",
        "SCRYER_LOG_FORMAT",
        "SCRYER_LOG_FILE",
    ):
        monkeypatch.delenv(key, raising=False)

    # Reset the dotenv-loaded flag in scryer_config so tests don't share state.
    try:
        import scryer_config  # noqa: WPS433 — local import is the point
    except ImportError:
        pass
    else:
        scryer_config._LOADED = False  # type: ignore[attr-defined]
        scryer_config._LOADED_FROM = None  # type: ignore[attr-defined]

    # Force scryer_logging to reconfigure on next get_logger() call.
    try:
        import scryer_logging
    except ImportError:
        pass
    else:
        scryer_logging._CONFIGURED = False  # type: ignore[attr-defined]
