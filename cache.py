"""
SQLite-based cache for incremental auditing.
Stores audit results keyed by source file content hash.
"""
from __future__ import annotations

import hashlib
import json
import sqlite3
from pathlib import Path
from typing import Any


class AuditCache:
    """
    Cache for audit results using SQLite.
    Key = SHA256 hash of concatenated source file contents.
    """
    
    def __init__(self, db_path: str | Path = ".audit_cache.db"):
        self.db_path = Path(db_path)
        self._init_db()
    
    def _init_db(self) -> None:
        """Initialize the database schema."""
        conn = sqlite3.connect(self.db_path)
        try:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS audits (
                    content_hash TEXT PRIMARY KEY,
                    report_json TEXT NOT NULL,
                    model TEXT,
                    provider TEXT,
                    created_at TEXT DEFAULT CURRENT_TIMESTAMP,
                    files_count INTEGER,
                    total_chars INTEGER
                )
            """)
            conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_created_at ON audits(created_at)
            """)
            conn.commit()
        finally:
            conn.close()
    
    @staticmethod
    def compute_hash(files: list[Path]) -> str:
        """
        Compute SHA256 hash of concatenated file contents.
        Files are sorted by path for deterministic ordering.
        """
        hasher = hashlib.sha256()
        for file_path in sorted(files, key=lambda p: p.as_posix()):
            if file_path.exists() and file_path.is_file():
                try:
                    content = file_path.read_bytes()
                    # Include path in hash to detect renames
                    hasher.update(file_path.as_posix().encode("utf-8"))
                    hasher.update(b"\x00")
                    hasher.update(content)
                    hasher.update(b"\x00")
                except Exception:
                    pass
        return hasher.hexdigest()
    
    def get_cached(self, content_hash: str) -> dict | None:
        """
        Retrieve cached audit result by content hash.
        Returns None if not found.
        """
        conn = sqlite3.connect(self.db_path)
        try:
            cursor = conn.execute(
                "SELECT report_json FROM audits WHERE content_hash = ?",
                (content_hash,)
            )
            row = cursor.fetchone()
            if row:
                return json.loads(row[0])
            return None
        finally:
            conn.close()
    
    def set_cached(
        self,
        content_hash: str,
        report: dict,
        *,
        model: str = "",
        provider: str = "",
        files_count: int = 0,
        total_chars: int = 0,
    ) -> None:
        """Store audit result in cache."""
        conn = sqlite3.connect(self.db_path)
        try:
            conn.execute(
                """
                INSERT OR REPLACE INTO audits 
                (content_hash, report_json, model, provider, files_count, total_chars)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (content_hash, json.dumps(report, ensure_ascii=False), model, provider, files_count, total_chars)
            )
            conn.commit()
        finally:
            conn.close()
    
    def has_cached(self, content_hash: str) -> bool:
        """Check if a hash exists in cache."""
        conn = sqlite3.connect(self.db_path)
        try:
            cursor = conn.execute(
                "SELECT 1 FROM audits WHERE content_hash = ?",
                (content_hash,)
            )
            return cursor.fetchone() is not None
        finally:
            conn.close()
    
    def clear(self) -> int:
        """Clear all cached entries. Returns number of entries deleted."""
        conn = sqlite3.connect(self.db_path)
        try:
            cursor = conn.execute("DELETE FROM audits")
            count = cursor.rowcount
            conn.commit()
            return count
        finally:
            conn.close()
    
    def stats(self) -> dict[str, Any]:
        """Get cache statistics."""
        conn = sqlite3.connect(self.db_path)
        try:
            cursor = conn.execute("SELECT COUNT(*), SUM(files_count), SUM(total_chars) FROM audits")
            row = cursor.fetchone()
            return {
                "total_entries": row[0] or 0,
                "total_files_cached": row[1] or 0,
                "total_chars_cached": row[2] or 0,
                "db_path": str(self.db_path),
                "db_size_bytes": self.db_path.stat().st_size if self.db_path.exists() else 0,
            }
        finally:
            conn.close()
