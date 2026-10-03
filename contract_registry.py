"""
Contract Registry - Maps bytecode hashes to contract addresses.
Used for vulnerability correlation: find all contracts affected by the same issue.
"""

from __future__ import annotations

import hashlib
import json
import sqlite3
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path


def _utc_now_iso() -> str:
    """Return current UTC time as ISO 8601 string (replacement for utcnow())."""
    return datetime.now(UTC).replace(tzinfo=None).isoformat()


@dataclass
class ContractInfo:
    chain_id: int
    address: str
    source_hash: str
    contract_name: str | None = None
    created_at: str | None = None


class ContractRegistry:
    """
    SQLite registry mapping source code hashes to contract addresses.

    Use case: When a vulnerability is found, query all addresses with the same hash.
    """

    def __init__(self, db_path: str | Path = ".contract_registry.db"):
        self.db_path = Path(db_path)
        self._init_db()

    def _init_db(self) -> None:
        """Initialize database schema."""
        conn = sqlite3.connect(self.db_path)
        try:
            conn.executescript("""
                -- Main contracts table
                CREATE TABLE IF NOT EXISTS contracts (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    chain_id INTEGER NOT NULL,
                    address TEXT NOT NULL,
                    source_hash TEXT NOT NULL,
                    contract_name TEXT,
                    compiler_version TEXT,
                    source_files_count INTEGER,
                    total_lines INTEGER,
                    crawled_at TEXT DEFAULT CURRENT_TIMESTAMP,
                    UNIQUE(chain_id, address)
                );

                -- Index for fast hash lookups
                CREATE INDEX IF NOT EXISTS idx_source_hash ON contracts(source_hash);
                CREATE INDEX IF NOT EXISTS idx_chain_address ON contracts(chain_id, address);

                -- Hash summary table (for quick stats)
                CREATE TABLE IF NOT EXISTS hash_stats (
                    source_hash TEXT PRIMARY KEY,
                    first_seen TEXT,
                    last_seen TEXT,
                    contract_count INTEGER DEFAULT 0,
                    chains TEXT,  -- JSON array of chain_ids
                    sample_name TEXT
                );

                -- Vulnerability tags (optional, for marking known issues)
                CREATE TABLE IF NOT EXISTS vulnerability_tags (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    source_hash TEXT NOT NULL,
                    tag TEXT NOT NULL,
                    severity TEXT,
                    description TEXT,
                    created_at TEXT DEFAULT CURRENT_TIMESTAMP,
                    UNIQUE(source_hash, tag)
                );

                -- Scanned blocks tracking (for resume support)
                CREATE TABLE IF NOT EXISTS scanned_blocks (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    chain_id INTEGER NOT NULL,
                    from_block INTEGER NOT NULL,
                    to_block INTEGER NOT NULL,
                    contracts_found INTEGER DEFAULT 0,
                    scanned_at TEXT DEFAULT CURRENT_TIMESTAMP,
                    UNIQUE(chain_id, from_block, to_block)
                );
                CREATE INDEX IF NOT EXISTS idx_scanned_chain ON scanned_blocks(chain_id);

                -- Bytecode identity, for matching an UNVERIFIED contract to a verified twin.
                -- Kept in its own table (not on `contracts`) because a bytecode-only contract
                -- has no source_hash, and `contracts.source_hash` is NOT NULL: `contracts`
                -- means "has verified source", this means "we have seen its code".
                CREATE TABLE IF NOT EXISTS code_fingerprints (
                    chain_id INTEGER NOT NULL,
                    address TEXT NOT NULL,
                    runtime_code_hash TEXT,   -- exact runtime
                    runtime_norm_hash TEXT,   -- runtime minus CBOR metadata trailer (workhorse)
                    selector_hash TEXT,       -- sorted selector set (survives immutables)
                    selector_count INTEGER,
                    code_size INTEGER,
                    seen_at TEXT DEFAULT CURRENT_TIMESTAMP,
                    PRIMARY KEY (chain_id, address)
                );
                CREATE INDEX IF NOT EXISTS idx_fp_exact ON code_fingerprints(runtime_code_hash);
                CREATE INDEX IF NOT EXISTS idx_fp_norm ON code_fingerprints(runtime_norm_hash);
                CREATE INDEX IF NOT EXISTS idx_fp_sel ON code_fingerprints(selector_hash);

                -- Vulnerability tags keyed by BYTECODE, for contracts with no verified source.
                -- Parallels vulnerability_tags (which is keyed by source_hash). Keyed on the
                -- normalized runtime (metadata-trailer stripped) so a confirmed bug on one
                -- unverified deployment auto-flags every byte-identical clone.
                CREATE TABLE IF NOT EXISTS code_vulnerability_tags (
                    runtime_norm_hash TEXT NOT NULL,
                    tag TEXT NOT NULL,
                    severity TEXT,
                    description TEXT,
                    created_at TEXT DEFAULT CURRENT_TIMESTAMP,
                    UNIQUE(runtime_norm_hash, tag)
                );
                CREATE INDEX IF NOT EXISTS idx_codevuln_hash ON code_vulnerability_tags(runtime_norm_hash);
                CREATE INDEX IF NOT EXISTS idx_codevuln_tag ON code_vulnerability_tags(tag);
            """)
            conn.commit()
        finally:
            conn.close()

    @staticmethod
    def compute_source_hash(sources: dict[str, str]) -> str:
        """Compute SHA256 hash of concatenated source files."""
        # Sort by filename for deterministic ordering
        combined = "".join(sources[k] for k in sorted(sources.keys()))
        return hashlib.sha256(combined.encode()).hexdigest()

    def register_contract(
        self,
        chain_id: int,
        address: str,
        sources: dict[str, str],
        contract_name: str | None = None,
        compiler_version: str | None = None,
        source_hash: str | None = None,
    ) -> str:
        """
        Register a contract and return its source hash.
        If address already exists, updates the record.

        Pass ``source_hash`` to register a precomputed hash (e.g. derived from the
        ORIGINAL logical source paths) instead of recomputing from ``sources`` —
        needed when ``sources`` is keyed by mangled flat filenames whose sort order,
        and therefore the content-concatenation hash, differs from the logical keys.
        """
        source_hash = source_hash or self.compute_source_hash(sources)
        address_lower = address.lower()
        now = _utc_now_iso()

        total_lines = sum(s.count("\n") + 1 for s in sources.values())

        conn = sqlite3.connect(self.db_path)
        try:
            # Insert or update contract
            conn.execute(
                """
                INSERT INTO contracts (chain_id, address, source_hash, contract_name,
                                       compiler_version, source_files_count, total_lines, crawled_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(chain_id, address) DO UPDATE SET
                    source_hash = excluded.source_hash,
                    contract_name = excluded.contract_name,
                    compiler_version = excluded.compiler_version,
                    source_files_count = excluded.source_files_count,
                    total_lines = excluded.total_lines,
                    crawled_at = excluded.crawled_at
            """,
                (chain_id, address_lower, source_hash, contract_name, compiler_version, len(sources), total_lines, now),
            )

            # Update hash stats
            self._update_hash_stats(conn, source_hash, contract_name)

            conn.commit()
        finally:
            conn.close()

        return source_hash

    def _update_hash_stats(self, conn: sqlite3.Connection, source_hash: str, sample_name: str | None):
        """Update aggregated hash statistics."""
        now = _utc_now_iso()

        # Get current stats
        cursor = conn.execute(
            """
            SELECT chain_id FROM contracts WHERE source_hash = ?
        """,
            (source_hash,),
        )
        chains = list({row[0] for row in cursor.fetchall()})

        cursor = conn.execute(
            """
            SELECT COUNT(*) FROM contracts WHERE source_hash = ?
        """,
            (source_hash,),
        )
        count = cursor.fetchone()[0]

        # Upsert hash stats
        conn.execute(
            """
            INSERT INTO hash_stats (source_hash, first_seen, last_seen, contract_count, chains, sample_name)
            VALUES (?, ?, ?, ?, ?, ?)
            ON CONFLICT(source_hash) DO UPDATE SET
                last_seen = excluded.last_seen,
                contract_count = excluded.contract_count,
                chains = excluded.chains,
                sample_name = COALESCE(hash_stats.sample_name, excluded.sample_name)
        """,
            (source_hash, now, now, count, json.dumps(chains), sample_name),
        )

    def get_addresses_by_hash(self, source_hash: str) -> list[dict]:
        """Get all contract addresses with the same source hash."""
        conn = sqlite3.connect(self.db_path)
        try:
            cursor = conn.execute(
                """
                SELECT chain_id, address, contract_name, compiler_version, crawled_at
                FROM contracts
                WHERE source_hash = ?
                ORDER BY chain_id, address
            """,
                (source_hash,),
            )

            return [
                {
                    "chain_id": row[0],
                    "address": row[1],
                    "contract_name": row[2],
                    "compiler_version": row[3],
                    "crawled_at": row[4],
                }
                for row in cursor.fetchall()
            ]
        finally:
            conn.close()

    # ----------------------------------------------------------------- #
    # Bytecode identity (clone matching for contracts with no source)
    # ----------------------------------------------------------------- #
    def record_code_fingerprints(self, chain_id: int, address: str, fp: dict) -> None:
        """Store/refresh one contract's bytecode fingerprints (opportunistic backfill)."""
        conn = sqlite3.connect(self.db_path)
        try:
            conn.execute(
                """
                INSERT INTO code_fingerprints
                    (chain_id, address, runtime_code_hash, runtime_norm_hash,
                     selector_hash, selector_count, code_size, seen_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
                ON CONFLICT(chain_id, address) DO UPDATE SET
                    runtime_code_hash = excluded.runtime_code_hash,
                    runtime_norm_hash = excluded.runtime_norm_hash,
                    selector_hash     = excluded.selector_hash,
                    selector_count    = excluded.selector_count,
                    code_size         = excluded.code_size,
                    seen_at           = excluded.seen_at
                """,
                (
                    chain_id,
                    address.lower(),
                    fp.get("runtime_code_hash"),
                    fp.get("runtime_norm_hash"),
                    fp.get("selector_hash"),
                    fp.get("selector_count"),
                    fp.get("code_size"),
                ),
            )
            conn.commit()
        finally:
            conn.close()

    def tag_vulnerability_by_code(
        self, runtime_norm_hash: str, tag: str, severity: str = "Unknown", description: str = ""
    ) -> int:
        """Tag a vuln keyed by BYTECODE (normalized runtime), for a contract with no verified
        source. Every contract whose bytecode matches inherits it. Returns how many known
        contracts share that hash (i.e. how many this flags)."""
        conn = sqlite3.connect(self.db_path)
        try:
            conn.execute(
                """
                INSERT INTO code_vulnerability_tags (runtime_norm_hash, tag, severity, description)
                VALUES (?, ?, ?, ?)
                ON CONFLICT(runtime_norm_hash, tag) DO UPDATE SET
                    severity = excluded.severity,
                    description = excluded.description
                """,
                (runtime_norm_hash, tag, severity, description),
            )
            conn.commit()
            return conn.execute(
                "SELECT COUNT(*) FROM code_fingerprints WHERE runtime_norm_hash = ?", (runtime_norm_hash,)
            ).fetchone()[0]
        finally:
            conn.close()

    def code_tags_for(self, runtime_norm_hash: str | None) -> list[dict]:
        """Bytecode-keyed vuln tags for a given normalized-runtime hash."""
        if not runtime_norm_hash:
            return []
        conn = sqlite3.connect(self.db_path)
        try:
            return [
                {"tag": r[0], "severity": r[1], "description": r[2], "runtime_norm_hash": runtime_norm_hash}
                for r in conn.execute(
                    "SELECT tag, severity, description FROM code_vulnerability_tags WHERE runtime_norm_hash = ?",
                    (runtime_norm_hash,),
                ).fetchall()
            ]
        finally:
            conn.close()

    def has_code_fingerprint(self, chain_id: int, address: str) -> bool:
        conn = sqlite3.connect(self.db_path)
        try:
            row = conn.execute(
                "SELECT 1 FROM code_fingerprints WHERE chain_id = ? AND address = ?",
                (chain_id, address.lower()),
            ).fetchone()
            return row is not None
        finally:
            conn.close()

    def _match_tier(self, conn, column: str, value: str, chain_id: int, address: str, limit: int) -> list[dict]:
        """Addresses sharing one fingerprint, annotated with whether they have verified source."""
        cursor = conn.execute(
            f"""
            SELECT f.chain_id, f.address, c.contract_name, c.source_hash, c.compiler_version
            FROM code_fingerprints f
            LEFT JOIN contracts c
                   ON c.chain_id = f.chain_id AND LOWER(c.address) = f.address
            WHERE f.{column} = ?
              AND NOT (f.chain_id = ? AND f.address = ?)
            ORDER BY (c.source_hash IS NULL), f.chain_id, f.address
            LIMIT ?
            """,  # noqa: S608 - `column` is never user input (fixed tier names)
            (value, chain_id, address.lower(), limit),
        )
        return [
            {
                "chain_id": r[0],
                "address": r[1],
                "contract_name": r[2],
                "source_hash": r[3],
                "compiler_version": r[4],
                "has_verified_source": r[3] is not None,
            }
            for r in cursor.fetchall()
        ]

    def find_code_twins(self, chain_id: int, address: str, fp: dict, *, limit: int = 25) -> dict:
        """Match bytecode fingerprints against the registry, tiered by precision.

        ``abi_matches`` additionally reports ``shared_by`` — how many contracts in the registry
        share that selector set. That count IS the confidence signal: 2 means a real twin,
        thousands means a generic interface (e.g. a vanilla ERC20) and the match is worthless.
        """
        out: dict = {"exact_matches": [], "normalized_matches": [], "abi_matches": []}
        conn = sqlite3.connect(self.db_path)
        try:
            if fp.get("runtime_code_hash"):
                out["exact_matches"] = self._match_tier(
                    conn, "runtime_code_hash", fp["runtime_code_hash"], chain_id, address, limit
                )
            if fp.get("runtime_norm_hash"):
                out["normalized_matches"] = self._match_tier(
                    conn, "runtime_norm_hash", fp["runtime_norm_hash"], chain_id, address, limit
                )
            if fp.get("selector_hash"):
                shared = conn.execute(
                    "SELECT COUNT(*) FROM code_fingerprints WHERE selector_hash = ?",
                    (fp["selector_hash"],),
                ).fetchone()[0]
                out["abi_shared_by"] = shared
                out["abi_matches"] = self._match_tier(
                    conn, "selector_hash", fp["selector_hash"], chain_id, address, limit
                )

            # Inherit vulnerability knowledge: any tag on a matched twin's source_hash applies
            # to this contract too, because it is the same code.
            hashes = {
                m["source_hash"]
                for tier in ("exact_matches", "normalized_matches", "abi_matches")
                for m in out[tier]
                if m.get("source_hash")
            }
            tags: list[dict] = []
            for h in hashes:
                for r in conn.execute(
                    "SELECT source_hash, tag, severity, description FROM vulnerability_tags WHERE source_hash = ?",
                    (h,),
                ).fetchall():
                    tags.append({"source_hash": r[0], "tag": r[1], "severity": r[2], "description": r[3]})
            out["inherited_vulnerability_tags"] = tags
            # Tags recorded directly against THIS bytecode (e.g. a prior unverified confirm).
            norm = fp.get("runtime_norm_hash")
            if norm:
                out["code_vulnerability_tags"] = [
                    {"tag": r[0], "severity": r[1], "description": r[2]}
                    for r in conn.execute(
                        "SELECT tag, severity, description FROM code_vulnerability_tags WHERE runtime_norm_hash = ?",
                        (norm,),
                    ).fetchall()
                ]
        finally:
            conn.close()
        return out

    def addresses_missing_fingerprints(self, chain_id: int | None = None, limit: int = 500) -> list[tuple[int, str]]:
        """Registered contracts with no bytecode fingerprint yet — the backfill work list."""
        conn = sqlite3.connect(self.db_path)
        try:
            sql = """
                SELECT c.chain_id, c.address FROM contracts c
                LEFT JOIN code_fingerprints f
                       ON f.chain_id = c.chain_id AND f.address = LOWER(c.address)
                WHERE f.address IS NULL
            """
            params: list = []
            if chain_id is not None:
                sql += " AND c.chain_id = ?"
                params.append(chain_id)
            sql += " ORDER BY c.chain_id, c.address LIMIT ?"
            params.append(limit)
            return [(r[0], r[1]) for r in conn.execute(sql, params).fetchall()]
        finally:
            conn.close()

    def get_hash_by_address(self, chain_id: int, address: str) -> str | None:
        """Get source hash for a specific contract address."""
        conn = sqlite3.connect(self.db_path)
        try:
            cursor = conn.execute(
                """
                SELECT source_hash FROM contracts
                WHERE chain_id = ? AND address = ?
            """,
                (chain_id, address.lower()),
            )
            row = cursor.fetchone()
            return row[0] if row else None
        finally:
            conn.close()

    def exists_contract(self, chain_id: int, address: str) -> bool:
        """Check if a contract address has already been crawled."""
        return self.get_hash_by_address(chain_id, address) is not None

    def get_crawled_addresses(self, chain_id: int) -> set[str]:
        """Get all *successfully* crawled addresses for a chain.

        Placeholder rows inserted by :meth:`claim_addresses_for_crawl` (which
        carry ``source_hash = ''``) are excluded so resume retries them.
        """
        conn = sqlite3.connect(self.db_path)
        try:
            cursor = conn.execute(
                """
                SELECT address FROM contracts
                WHERE chain_id = ? AND source_hash IS NOT NULL AND source_hash != ''
                """,
                (chain_id,),
            )
            return {row[0].lower() for row in cursor.fetchall()}
        finally:
            conn.close()

    def claim_addresses_for_crawl(self, chain_id: int, addresses: list[str]) -> list[str]:
        """Atomically claim ``addresses`` for crawling.

        Each address is inserted as a placeholder row (empty ``source_hash``);
        SQLite's ``INSERT OR IGNORE`` makes the claim collision-free, so two
        crawlers running against the same DB never end up double-fetching the
        same contract. Returns the subset of addresses that this call newly
        claimed (lower-cased). Placeholders are filled in by
        :meth:`register_contract` once the source is fetched.
        """
        if not addresses:
            return []

        now = _utc_now_iso()
        claimed: list[str] = []
        conn = sqlite3.connect(self.db_path)
        try:
            for addr in addresses:
                addr_lower = addr.lower()
                cur = conn.execute(
                    """
                    INSERT OR IGNORE INTO contracts
                      (chain_id, address, source_hash, contract_name, compiler_version,
                       source_files_count, total_lines, crawled_at)
                    VALUES (?, ?, '', NULL, NULL, 0, 0, ?)
                    """,
                    (chain_id, addr_lower, now),
                )
                if cur.rowcount > 0:
                    claimed.append(addr_lower)
            conn.commit()
        finally:
            conn.close()
        return claimed

    def release_stale_claims(self, chain_id: int, *, older_than_iso: str | None = None) -> int:
        """Drop placeholder claims that never got filled in.

        Useful as a periodic cleanup if a crawler dies without registering.
        Returns the number of placeholder rows deleted.
        """
        conn = sqlite3.connect(self.db_path)
        try:
            if older_than_iso:
                cur = conn.execute(
                    "DELETE FROM contracts WHERE chain_id = ? AND source_hash = '' AND crawled_at < ?",
                    (chain_id, older_than_iso),
                )
            else:
                cur = conn.execute(
                    "DELETE FROM contracts WHERE chain_id = ? AND source_hash = ''",
                    (chain_id,),
                )
            conn.commit()
            return cur.rowcount
        finally:
            conn.close()

    def find_related_contracts(self, chain_id: int, address: str) -> list[dict]:
        """Find all contracts with the same source code as the given address."""
        source_hash = self.get_hash_by_address(chain_id, address)
        if not source_hash:
            return []
        return self.get_addresses_by_hash(source_hash)

    def tag_vulnerability(
        self,
        source_hash: str,
        tag: str,
        severity: str = "Unknown",
        description: str = "",
    ) -> int:
        """
        Tag a source hash with a vulnerability.
        Returns the number of affected contracts.
        """
        conn = sqlite3.connect(self.db_path)
        try:
            conn.execute(
                """
                INSERT INTO vulnerability_tags (source_hash, tag, severity, description)
                VALUES (?, ?, ?, ?)
                ON CONFLICT(source_hash, tag) DO UPDATE SET
                    severity = excluded.severity,
                    description = excluded.description
            """,
                (source_hash, tag, severity, description),
            )
            conn.commit()

            # Return affected count
            cursor = conn.execute(
                """
                SELECT COUNT(*) FROM contracts WHERE source_hash = ?
            """,
                (source_hash,),
            )
            return cursor.fetchone()[0]
        finally:
            conn.close()

    def get_vulnerable_contracts(self, tag: str) -> list[dict]:
        """Every contract affected by a tag — both source-hash-tagged (verified contracts and
        their source clones) and bytecode-tagged (unverified contracts and their byte clones)."""
        conn = sqlite3.connect(self.db_path)
        try:
            cursor = conn.execute(
                """
                SELECT c.chain_id, c.address, c.contract_name, v.severity, v.description, 'source' AS via
                FROM contracts c
                JOIN vulnerability_tags v ON c.source_hash = v.source_hash
                WHERE v.tag = ?
                UNION
                SELECT f.chain_id, f.address, NULL, cv.severity, cv.description, 'bytecode' AS via
                FROM code_fingerprints f
                JOIN code_vulnerability_tags cv ON f.runtime_norm_hash = cv.runtime_norm_hash
                WHERE cv.tag = ?
                ORDER BY chain_id, address
                """,
                (tag, tag),
            )

            return [
                {
                    "chain_id": row[0],
                    "address": row[1],
                    "contract_name": row[2],
                    "severity": row[3],
                    "description": row[4],
                    "matched_via": row[5],
                }
                for row in cursor.fetchall()
            ]
        finally:
            conn.close()

    def get_top_duplicates(self, limit: int = 50) -> list[dict]:
        """Get source hashes with the most contract instances."""
        conn = sqlite3.connect(self.db_path)
        try:
            cursor = conn.execute(
                """
                SELECT source_hash, contract_count, chains, sample_name, first_seen
                FROM hash_stats
                WHERE contract_count > 1
                ORDER BY contract_count DESC
                LIMIT ?
            """,
                (limit,),
            )

            return [
                {
                    "source_hash": row[0],
                    "contract_count": row[1],
                    "chains": json.loads(row[2]) if row[2] else [],
                    "sample_name": row[3],
                    "first_seen": row[4],
                }
                for row in cursor.fetchall()
            ]
        finally:
            conn.close()

    def stats(self) -> dict:
        """Get registry statistics."""
        conn = sqlite3.connect(self.db_path)
        try:
            cursor = conn.execute("SELECT COUNT(*) FROM contracts")
            total_contracts = cursor.fetchone()[0]

            cursor = conn.execute("SELECT COUNT(DISTINCT source_hash) FROM contracts")
            unique_hashes = cursor.fetchone()[0]

            cursor = conn.execute("SELECT COUNT(*) FROM vulnerability_tags")
            vuln_tags = cursor.fetchone()[0]

            cursor = conn.execute("SELECT COUNT(*) FROM hash_stats WHERE contract_count > 1")
            duplicated_hashes = cursor.fetchone()[0]

            return {
                "total_contracts": total_contracts,
                "unique_source_hashes": unique_hashes,
                "duplicated_hashes": duplicated_hashes,
                "vulnerability_tags": vuln_tags,
                "db_path": str(self.db_path),
            }
        finally:
            conn.close()

    # =========================================================================
    # Block Scan Tracking
    # =========================================================================

    def record_scanned_blocks(
        self,
        chain_id: int,
        from_block: int,
        to_block: int,
        contracts_found: int = 0,
    ) -> None:
        """Record a range of blocks that have been scanned."""
        conn = sqlite3.connect(self.db_path)
        try:
            conn.execute(
                """
                INSERT INTO scanned_blocks (chain_id, from_block, to_block, contracts_found)
                VALUES (?, ?, ?, ?)
                ON CONFLICT(chain_id, from_block, to_block) DO UPDATE SET
                    contracts_found = excluded.contracts_found,
                    scanned_at = CURRENT_TIMESTAMP
            """,
                (chain_id, from_block, to_block, contracts_found),
            )
            conn.commit()
        finally:
            conn.close()

    def get_scanned_ranges(self, chain_id: int) -> list[tuple[int, int]]:
        """Get all scanned block ranges for a chain, sorted by from_block."""
        conn = sqlite3.connect(self.db_path)
        try:
            cursor = conn.execute(
                """
                SELECT from_block, to_block FROM scanned_blocks
                WHERE chain_id = ?
                ORDER BY from_block
            """,
                (chain_id,),
            )
            return [(row[0], row[1]) for row in cursor.fetchall()]
        finally:
            conn.close()

    def get_unscanned_ranges(
        self,
        chain_id: int,
        from_block: int,
        to_block: int,
    ) -> list[tuple[int, int]]:
        """
        Calculate which block ranges still need to be scanned.
        Returns a list of (from, to) tuples representing gaps.
        """
        scanned = self.get_scanned_ranges(chain_id)
        if not scanned:
            return [(from_block, to_block)]

        # Merge overlapping ranges and find gaps
        gaps = []
        current_start = from_block

        for scan_from, scan_to in scanned:
            # Skip ranges entirely before our target
            if scan_to < from_block:
                continue
            # Stop if we've passed our target
            if scan_from > to_block:
                break

            # If there's a gap before this scanned range
            if current_start < scan_from:
                gap_end = min(scan_from - 1, to_block)
                if gap_end >= current_start:
                    gaps.append((current_start, gap_end))

            # Move current_start past this scanned range
            current_start = max(current_start, scan_to + 1)

        # Check if there's a gap at the end
        if current_start <= to_block:
            gaps.append((current_start, to_block))

        return gaps

    def get_last_scanned_block(self, chain_id: int) -> int | None:
        """Get the highest block number that has been scanned for a chain."""
        conn = sqlite3.connect(self.db_path)
        try:
            cursor = conn.execute(
                """
                SELECT MAX(to_block) FROM scanned_blocks
                WHERE chain_id = ?
            """,
                (chain_id,),
            )
            row = cursor.fetchone()
            return row[0] if row and row[0] is not None else None
        finally:
            conn.close()
