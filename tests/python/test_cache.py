"""Tests for the AuditCache (cache.py)."""

from __future__ import annotations

from pathlib import Path

from cache import AuditCache


def test_init_creates_db(tmp_path: Path) -> None:
    db = tmp_path / "audit.db"
    AuditCache(db)
    assert db.exists()


def test_set_and_get_roundtrip(tmp_path: Path) -> None:
    cache = AuditCache(tmp_path / "audit.db")
    report = {"summary": "ok", "issues": [{"id": 1}]}
    cache.set_cached("hash-abc", report, model="gpt-4.1-mini", provider="openai")

    got = cache.get_cached("hash-abc")
    assert got == report


def test_get_missing_returns_none(tmp_path: Path) -> None:
    cache = AuditCache(tmp_path / "audit.db")
    assert cache.get_cached("nope") is None


def test_has_cached(tmp_path: Path) -> None:
    cache = AuditCache(tmp_path / "audit.db")
    cache.set_cached("h1", {"x": 1})
    assert cache.has_cached("h1")
    assert not cache.has_cached("h2")


def test_compute_hash_is_deterministic(tmp_path: Path) -> None:
    a = tmp_path / "A.sol"
    b = tmp_path / "B.sol"
    a.write_text("contract A {}\n", encoding="utf-8")
    b.write_text("contract B {}\n", encoding="utf-8")

    h1 = AuditCache.compute_hash([a, b])
    h2 = AuditCache.compute_hash([b, a])  # order shouldn't matter
    assert h1 == h2
    assert len(h1) == 64  # sha256 hex


def test_compute_hash_changes_with_content(tmp_path: Path) -> None:
    a = tmp_path / "A.sol"
    a.write_text("contract A {}\n", encoding="utf-8")
    h1 = AuditCache.compute_hash([a])
    a.write_text("contract A { uint x; }\n", encoding="utf-8")
    h2 = AuditCache.compute_hash([a])
    assert h1 != h2


def test_compute_hash_includes_path(tmp_path: Path) -> None:
    """Renaming a file with the same content must produce a different hash."""
    a = tmp_path / "A.sol"
    b = tmp_path / "B.sol"
    a.write_text("contract X {}\n", encoding="utf-8")
    h1 = AuditCache.compute_hash([a])
    a.rename(b)
    h2 = AuditCache.compute_hash([b])
    assert h1 != h2


def test_clear(tmp_path: Path) -> None:
    cache = AuditCache(tmp_path / "audit.db")
    cache.set_cached("h1", {"x": 1})
    cache.set_cached("h2", {"x": 2})
    deleted = cache.clear()
    assert deleted == 2
    assert cache.get_cached("h1") is None


def test_stats(tmp_path: Path) -> None:
    db = tmp_path / "audit.db"
    cache = AuditCache(db)
    cache.set_cached("h1", {"x": 1}, files_count=3, total_chars=1000)
    cache.set_cached("h2", {"x": 2}, files_count=2, total_chars=500)

    stats = cache.stats()
    assert stats["total_entries"] == 2
    assert stats["total_files_cached"] == 5
    assert stats["total_chars_cached"] == 1500
    assert stats["db_path"] == str(db)
    assert stats["db_size_bytes"] > 0


def test_overwrite_existing_hash(tmp_path: Path) -> None:
    cache = AuditCache(tmp_path / "audit.db")
    cache.set_cached("h1", {"version": 1})
    cache.set_cached("h1", {"version": 2})
    assert cache.get_cached("h1") == {"version": 2}
    assert cache.stats()["total_entries"] == 1
