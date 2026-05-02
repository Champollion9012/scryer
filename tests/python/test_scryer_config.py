"""Tests for scryer_config — env / dotenv loading helpers."""

from __future__ import annotations

from pathlib import Path

import pytest

import scryer_config


def _force_reload(env_path: Path) -> bool:
    return scryer_config.load(dotenv_path=env_path, override=True, force_reload=True)


def test_load_returns_false_for_missing_file(tmp_path: Path) -> None:
    assert _force_reload(tmp_path / "missing.env") is False


def test_load_returns_true_for_existing_file(tmp_path: Path) -> None:
    env = tmp_path / ".env"
    env.write_text("FOO=bar\n", encoding="utf-8")
    assert _force_reload(env) is True
    assert scryer_config.get("FOO") == "bar"


def test_load_is_idempotent(tmp_path: Path) -> None:
    env = tmp_path / ".env"
    env.write_text("FOO=first\n", encoding="utf-8")
    _force_reload(env)

    # Mutating the file should NOT take effect on a non-forced reload.
    env.write_text("FOO=second\n", encoding="utf-8")
    scryer_config.load(dotenv_path=env)  # not forced — early return
    assert scryer_config.get("FOO") == "first"


def test_force_reload_picks_up_new_values(tmp_path: Path) -> None:
    env = tmp_path / ".env"
    env.write_text("FOO=first\n", encoding="utf-8")
    _force_reload(env)
    env.write_text("FOO=second\n", encoding="utf-8")
    _force_reload(env)
    assert scryer_config.get("FOO") == "second"


def test_get_with_default() -> None:
    assert scryer_config.get("DEFINITELY_NOT_SET_xyz") is None
    assert scryer_config.get("DEFINITELY_NOT_SET_xyz", "fallback") == "fallback"


def test_get_required_raises_for_missing() -> None:
    with pytest.raises(RuntimeError, match="DEFINITELY_NOT_SET_xyz"):
        scryer_config.get_required("DEFINITELY_NOT_SET_xyz")


def test_get_required_returns_value(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("MY_KEY", "secret")
    assert scryer_config.get_required("MY_KEY") == "secret"


def test_get_int_parses(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("PORT", "8080")
    assert scryer_config.get_int("PORT") == 8080
    assert scryer_config.get_int("MISSING", default=99) == 99


def test_get_int_raises_on_invalid(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("PORT", "not-a-number")
    with pytest.raises(ValueError):
        scryer_config.get_int("PORT")


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("1", True),
        ("true", True),
        ("True", True),
        ("YES", True),
        ("on", True),
        ("0", False),
        ("false", False),
        ("no", False),
        ("", False),
    ],
)
def test_get_bool(monkeypatch: pytest.MonkeyPatch, raw: str, expected: bool) -> None:
    monkeypatch.setenv("FLAG", raw)
    assert scryer_config.get_bool("FLAG") is expected


def test_get_bool_default(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("FLAG", raising=False)
    assert scryer_config.get_bool("FLAG") is False
    assert scryer_config.get_bool("FLAG", default=True) is True


def test_get_list_splits_and_strips(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("URLS", " a , b ,, c ")
    assert scryer_config.get_list("URLS") == ["a", "b", "c"]


def test_get_list_empty_returns_empty(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("URLS", raising=False)
    assert scryer_config.get_list("URLS") == []


def test_loaded_from_after_load(tmp_path: Path) -> None:
    env = tmp_path / ".env"
    env.write_text("X=y\n", encoding="utf-8")
    _force_reload(env)
    assert scryer_config.loaded_from() == env
