#!/usr/bin/env python3
"""Whale watcher: poll major-stablecoin Transfer events and surface large
caller-controlled deposits to fresh contracts.

Motivation
----------
Most exploit chains start with attackers funnelling stablecoins into a
shiny new contract - token launchpads, vault wrappers, custom routers.
By watching ``Transfer(USDT|USDC|...)`` logs and filtering to *contract*
receivers above a value threshold, we get a real-time feed of recently
funded shitcoin/launch contracts - high-yield candidates for an
automated audit pass.

Architecture
------------
- Synchronous (no asyncio) — short polling intervals are fine.
- Per-chain RPC, configurable via env (``ETH_RPC_URL``, ``BSC_RPC_URL``).
- Stores hits + per-chain block cursors in a dedicated SQLite DB
  (``.whale_watcher.db``); idempotent via ``UNIQUE(chain_id, tx_hash, log_index)``.
- ``--once`` for a single sweep (cron-friendly), ``--daemon`` for a loop.
- No on-disk source download here — that's what ``bounty_pipeline`` is for.
  The ``--enqueue`` flag (TODO) will write a targets.json snapshot.

Schema
------
``whale_hits``::

    id chain_id block_number block_time tx_hash log_index
    token_address token_symbol token_decimals
    from_address to_address amount_raw amount_normalized
    receiver_is_contract seen_at

``whale_cursors``::

    chain_id last_block_scanned updated_at
"""

from __future__ import annotations

import argparse
import json
import sqlite3
import sys
import time
from collections.abc import Iterable
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import httpx

import scryer_config
import scryer_http
from scryer_logging import get_logger

_log = get_logger(__name__)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

# keccak256("Transfer(address,address,uint256)")
TRANSFER_TOPIC = "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef"


@dataclass(frozen=True)
class TokenSpec:
    """A stablecoin/major-asset to watch."""

    chain_id: int
    address: str  # lowercase hex
    symbol: str
    decimals: int


# Defaults — kept short on purpose. Add more via --tokens-file.
DEFAULT_TOKENS: list[TokenSpec] = [
    # Ethereum mainnet
    TokenSpec(1, "0xdac17f958d2ee523a2206206994597c13d831ec7", "USDT", 6),
    TokenSpec(1, "0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48", "USDC", 6),
    TokenSpec(1, "0x6b175474e89094c44da98b954eedeac495271d0f", "DAI", 18),
    # BSC
    TokenSpec(56, "0x55d398326f99059ff775485246999027b3197955", "USDT", 18),
    TokenSpec(56, "0x8ac76a51cc950d9822d68b83fe1ad97b32cd580d", "USDC", 18),
    TokenSpec(56, "0xe9e7cea3dedca5984780bafc599bd69add087d56", "BUSD", 18),
]


@dataclass
class Config:
    chains: list[int]
    tokens: list[TokenSpec]
    rpc_urls: dict[int, str]
    threshold_usd: float = 50_000.0
    chunk_blocks: int = 100
    poll_interval_s: float = 30.0
    db_path: Path = Path(".whale_watcher.db")
    lookback_blocks: int = 200
    confirmations: int = 3
    max_chunks_per_tick: int = 20  # cap work per tick so daemon stays responsive
    extra: dict[str, Any] = field(default_factory=dict)


# ---------------------------------------------------------------------------
# Token + RPC helpers
# ---------------------------------------------------------------------------


def load_tokens_from_file(path: Path) -> list[TokenSpec]:
    """Load extra tokens from JSON. Schema: list of {chain_id, address, symbol, decimals}."""
    payload = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(payload, list):
        raise ValueError(f"{path} must contain a JSON array")
    out: list[TokenSpec] = []
    for entry in payload:
        if not isinstance(entry, dict):
            continue
        out.append(
            TokenSpec(
                chain_id=int(entry["chain_id"]),
                address=str(entry["address"]).lower(),
                symbol=str(entry.get("symbol", "?")),
                decimals=int(entry.get("decimals", 18)),
            )
        )
    return out


def default_rpc_urls() -> dict[int, str]:
    """Pull per-chain RPC URLs from env, with public fallbacks for ETH/BSC."""
    return {
        1: scryer_config.get("ETH_RPC_URL") or "https://eth.llamarpc.com",
        56: scryer_config.get("BSC_RPC_URL") or "https://bsc-dataseed.bnbchain.org",
        137: scryer_config.get("POLYGON_RPC_URL") or "https://polygon-rpc.com",
        42161: scryer_config.get("ARBITRUM_RPC_URL") or "https://arb1.arbitrum.io/rpc",
        10: scryer_config.get("OPTIMISM_RPC_URL") or "https://mainnet.optimism.io",
        8453: scryer_config.get("BASE_RPC_URL") or "https://mainnet.base.org",
    }


# ---------------------------------------------------------------------------
# Log parsing
# ---------------------------------------------------------------------------


def _topic_to_address(topic: str) -> str:
    """Convert a 32-byte topic hex (with leading 0x) to a 20-byte lowercase address."""
    if not isinstance(topic, str) or not topic.startswith("0x") or len(topic) != 66:
        raise ValueError(f"bad topic: {topic!r}")
    return "0x" + topic[-40:].lower()


def _hex_to_int(value: str) -> int:
    if not isinstance(value, str):
        raise ValueError(f"expected hex string, got {type(value).__name__}")
    return int(value, 16) if value.startswith("0x") else int(value, 16)


@dataclass
class TransferLog:
    chain_id: int
    block_number: int
    tx_hash: str
    log_index: int
    token_address: str
    from_address: str
    to_address: str
    amount_raw: int

    def normalized(self, decimals: int) -> float:
        scale = 10**decimals
        return self.amount_raw / scale


def parse_transfer_log(chain_id: int, raw: dict) -> TransferLog | None:
    """Parse a single eth_getLogs result into a TransferLog.

    Returns None for malformed entries — caller should skip silently.
    """
    try:
        topics = raw.get("topics") or []
        # topic[0] = Transfer signature; topic[1] = from; topic[2] = to
        if len(topics) < 3 or topics[0].lower() != TRANSFER_TOPIC:
            return None
        return TransferLog(
            chain_id=chain_id,
            block_number=_hex_to_int(raw["blockNumber"]),
            tx_hash=str(raw["transactionHash"]),
            log_index=_hex_to_int(raw["logIndex"]),
            token_address=str(raw["address"]).lower(),
            from_address=_topic_to_address(topics[1]),
            to_address=_topic_to_address(topics[2]),
            amount_raw=_hex_to_int(raw.get("data", "0x0") or "0x0"),
        )
    except Exception as e:
        _log.debug("skip malformed log: %s (%s)", e, raw)
        return None


# ---------------------------------------------------------------------------
# RPC layer
# ---------------------------------------------------------------------------


class RpcError(RuntimeError):
    pass


class RpcClient:
    """Tiny synchronous JSON-RPC wrapper around httpx.Client."""

    def __init__(self, url: str, *, client: httpx.Client | None = None) -> None:
        self.url = url
        self._client = client or scryer_http.sync_client()
        self._owns_client = client is None
        self._req_id = 0

    def close(self) -> None:
        if self._owns_client:
            self._client.close()

    def __enter__(self) -> RpcClient:
        return self

    def __exit__(self, *args: object) -> None:
        self.close()

    def call(self, method: str, params: list[Any]) -> Any:
        self._req_id += 1
        payload = {"jsonrpc": "2.0", "id": self._req_id, "method": method, "params": params}
        resp = self._client.post(self.url, json=payload)
        if resp.status_code != 200:
            raise RpcError(f"{method} -> HTTP {resp.status_code}: {resp.text[:200]}")
        body = resp.json()
        if "error" in body:
            raise RpcError(f"{method} -> RPC error: {body['error']}")
        return body.get("result")

    def block_number(self) -> int:
        return _hex_to_int(self.call("eth_blockNumber", []))

    def get_logs(
        self,
        *,
        from_block: int,
        to_block: int,
        addresses: list[str],
        topics: list[Any],
    ) -> list[dict]:
        params = [
            {
                "fromBlock": hex(from_block),
                "toBlock": hex(to_block),
                "address": addresses,
                "topics": topics,
            }
        ]
        result = self.call("eth_getLogs", params)
        return result if isinstance(result, list) else []

    def get_code(self, address: str) -> str:
        return str(self.call("eth_getCode", [address, "latest"]) or "0x")


# ---------------------------------------------------------------------------
# Storage
# ---------------------------------------------------------------------------


class WhaleStore:
    """SQLite-backed persistence for hits and per-chain cursors."""

    def __init__(self, db_path: Path) -> None:
        self.db_path = db_path
        self._init()

    def _conn(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        return conn

    def _init(self) -> None:
        with self._conn() as conn:
            conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS whale_hits (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    chain_id INTEGER NOT NULL,
                    block_number INTEGER NOT NULL,
                    tx_hash TEXT NOT NULL,
                    log_index INTEGER NOT NULL,
                    token_address TEXT NOT NULL,
                    token_symbol TEXT,
                    token_decimals INTEGER,
                    from_address TEXT NOT NULL,
                    to_address TEXT NOT NULL,
                    amount_raw TEXT NOT NULL,
                    amount_normalized REAL,
                    receiver_is_contract INTEGER,
                    seen_at TEXT DEFAULT CURRENT_TIMESTAMP,
                    UNIQUE(chain_id, tx_hash, log_index)
                );
                CREATE INDEX IF NOT EXISTS idx_whale_chain_block ON whale_hits(chain_id, block_number);
                CREATE INDEX IF NOT EXISTS idx_whale_to ON whale_hits(to_address);
                CREATE INDEX IF NOT EXISTS idx_whale_seen ON whale_hits(seen_at);

                CREATE TABLE IF NOT EXISTS whale_cursors (
                    chain_id INTEGER PRIMARY KEY,
                    last_block_scanned INTEGER NOT NULL,
                    updated_at TEXT DEFAULT CURRENT_TIMESTAMP
                );
                """
            )
            conn.commit()

    def get_cursor(self, chain_id: int) -> int | None:
        with self._conn() as conn:
            row = conn.execute(
                "SELECT last_block_scanned FROM whale_cursors WHERE chain_id = ?", (chain_id,)
            ).fetchone()
            return int(row["last_block_scanned"]) if row else None

    def set_cursor(self, chain_id: int, block: int) -> None:
        with self._conn() as conn:
            conn.execute(
                """
                INSERT INTO whale_cursors(chain_id, last_block_scanned, updated_at)
                VALUES(?, ?, ?)
                ON CONFLICT(chain_id) DO UPDATE SET
                    last_block_scanned = excluded.last_block_scanned,
                    updated_at = excluded.updated_at
                """,
                (chain_id, block, datetime.now(UTC).isoformat()),
            )
            conn.commit()

    def insert_hit(
        self,
        log: TransferLog,
        *,
        symbol: str,
        decimals: int,
        receiver_is_contract: bool,
    ) -> bool:
        """Insert a hit; returns True if newly inserted, False if duplicate."""
        with self._conn() as conn:
            try:
                conn.execute(
                    """
                    INSERT INTO whale_hits(
                        chain_id, block_number, tx_hash, log_index,
                        token_address, token_symbol, token_decimals,
                        from_address, to_address, amount_raw, amount_normalized,
                        receiver_is_contract
                    ) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)
                    """,
                    (
                        log.chain_id,
                        log.block_number,
                        log.tx_hash,
                        log.log_index,
                        log.token_address,
                        symbol,
                        decimals,
                        log.from_address,
                        log.to_address,
                        str(log.amount_raw),
                        log.normalized(decimals),
                        int(bool(receiver_is_contract)),
                    ),
                )
                conn.commit()
                return True
            except sqlite3.IntegrityError:
                return False

    def recent_hits(self, *, limit: int = 100, chain_id: int | None = None) -> list[dict]:
        with self._conn() as conn:
            if chain_id is not None:
                rows = conn.execute(
                    "SELECT * FROM whale_hits WHERE chain_id = ? ORDER BY id DESC LIMIT ?",
                    (chain_id, limit),
                ).fetchall()
            else:
                rows = conn.execute("SELECT * FROM whale_hits ORDER BY id DESC LIMIT ?", (limit,)).fetchall()
            return [dict(r) for r in rows]


# ---------------------------------------------------------------------------
# Watcher
# ---------------------------------------------------------------------------


@dataclass
class TickStats:
    chain_id: int
    chunks_scanned: int = 0
    logs_seen: int = 0
    hits_kept: int = 0
    new_hits: int = 0
    cursor_advanced_to: int | None = None
    error: str | None = None


def _is_contract_code(code: str) -> bool:
    """An EOA returns ``"0x"`` (or empty); a contract returns bytecode."""
    if not code or not code.startswith("0x"):
        return False
    return len(code) > 2  # anything beyond "0x" indicates code


def _amount_passes_threshold(amount_raw: int, decimals: int, threshold_usd: float) -> bool:
    """Stablecoin assumption: 1 unit = 1 USD. Caller must filter token list to stables."""
    if threshold_usd <= 0:
        return True
    return amount_raw >= int(threshold_usd * (10**decimals))


def scan_chain(
    rpc: RpcClient,
    store: WhaleStore,
    *,
    chain_id: int,
    tokens: list[TokenSpec],
    config: Config,
) -> TickStats:
    """Scan one chain forward from its cursor up to (head - confirmations)."""
    stats = TickStats(chain_id=chain_id)

    if not tokens:
        return stats

    try:
        head = rpc.block_number()
    except Exception as e:
        stats.error = f"block_number failed: {e}"
        return stats

    safe_head = max(0, head - config.confirmations)
    cursor = store.get_cursor(chain_id)
    if cursor is None:
        cursor = max(0, safe_head - config.lookback_blocks)
        _log.info("[chain %d] no cursor; starting at block %d (head=%d)", chain_id, cursor, head)

    if cursor >= safe_head:
        return stats

    addresses = [t.address for t in tokens]
    decimals_by_addr = {t.address: t.decimals for t in tokens}
    symbol_by_addr = {t.address: t.symbol for t in tokens}

    chunks_left = config.max_chunks_per_tick
    next_block = cursor + 1
    while next_block <= safe_head and chunks_left > 0:
        chunk_to = min(safe_head, next_block + config.chunk_blocks - 1)
        try:
            raw_logs = rpc.get_logs(
                from_block=next_block,
                to_block=chunk_to,
                addresses=addresses,
                topics=[TRANSFER_TOPIC],
            )
        except Exception as e:
            stats.error = f"getLogs {next_block}->{chunk_to} failed: {e}"
            break

        stats.chunks_scanned += 1
        stats.logs_seen += len(raw_logs)

        for raw in raw_logs:
            log = parse_transfer_log(chain_id, raw)
            if not log:
                continue
            decimals = decimals_by_addr.get(log.token_address, 18)
            if not _amount_passes_threshold(log.amount_raw, decimals, config.threshold_usd):
                continue
            # Filter to contract recipients only (the user's stated criterion).
            try:
                code = rpc.get_code(log.to_address)
            except Exception as e:
                _log.debug("[chain %d] eth_getCode failed for %s: %s", chain_id, log.to_address, e)
                continue
            if not _is_contract_code(code):
                continue

            stats.hits_kept += 1
            inserted = store.insert_hit(
                log,
                symbol=symbol_by_addr.get(log.token_address, "?"),
                decimals=decimals,
                receiver_is_contract=True,
            )
            if inserted:
                stats.new_hits += 1
                _log.info(
                    "[chain %d] hit: %s %s -> %s @ block %d (tx %s)",
                    chain_id,
                    log.normalized(decimals),
                    symbol_by_addr.get(log.token_address, "?"),
                    log.to_address,
                    log.block_number,
                    log.tx_hash[:18],
                )

        store.set_cursor(chain_id, chunk_to)
        stats.cursor_advanced_to = chunk_to
        next_block = chunk_to + 1
        chunks_left -= 1

    return stats


def run_once(config: Config) -> dict[int, TickStats]:
    """Run a single sweep across all configured chains."""
    store = WhaleStore(config.db_path)
    results: dict[int, TickStats] = {}
    for chain_id in config.chains:
        rpc_url = config.rpc_urls.get(chain_id)
        if not rpc_url:
            _log.warning("no RPC URL for chain %d; skipping", chain_id)
            continue
        chain_tokens = [t for t in config.tokens if t.chain_id == chain_id]
        if not chain_tokens:
            _log.warning("no tokens configured for chain %d; skipping", chain_id)
            continue
        with RpcClient(rpc_url) as rpc:
            stats = scan_chain(rpc, store, chain_id=chain_id, tokens=chain_tokens, config=config)
        results[chain_id] = stats
        if stats.error:
            _log.warning("[chain %d] error: %s", chain_id, stats.error)
        elif stats.new_hits:
            _log.info(
                "[chain %d] +%d hits (scanned %d chunks, %d logs)",
                chain_id,
                stats.new_hits,
                stats.chunks_scanned,
                stats.logs_seen,
            )
    return results


def run_daemon(config: Config) -> None:
    _log.info("whale watcher daemon starting (chains=%s, threshold=$%.0f)", config.chains, config.threshold_usd)
    while True:
        try:
            run_once(config)
        except KeyboardInterrupt:
            _log.info("daemon stopped by user")
            return
        except Exception as e:  # pragma: no cover — defensive
            _log.exception("daemon tick failed: %s", e)
        time.sleep(config.poll_interval_s)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def _parse_int_list(value: str) -> list[int]:
    return [int(x) for x in value.replace(",", " ").split() if x.strip()]


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument(
        "--chains",
        type=_parse_int_list,
        default=[1, 56],
        help="Comma-separated chain IDs to watch (default: 1,56 = ETH+BSC).",
    )
    parser.add_argument(
        "--threshold-usd",
        type=float,
        default=50_000.0,
        help="Minimum stablecoin amount to record (default: 50000).",
    )
    parser.add_argument("--chunk-blocks", type=int, default=100, help="Blocks per eth_getLogs request (default: 100).")
    parser.add_argument(
        "--lookback-blocks",
        type=int,
        default=200,
        help="On first run for a chain, scan this many blocks back from head.",
    )
    parser.add_argument(
        "--confirmations", type=int, default=3, help="Block confirmations before considering safe (default: 3)."
    )
    parser.add_argument(
        "--max-chunks-per-tick",
        type=int,
        default=20,
        help="Max getLogs chunks per chain per tick (caps daemon work).",
    )
    parser.add_argument("--poll-interval-s", type=float, default=30.0, help="Seconds between daemon ticks.")
    parser.add_argument("--db-path", type=Path, default=Path(".whale_watcher.db"), help="SQLite path.")
    parser.add_argument("--tokens-file", type=Path, help="Extra tokens JSON (appended to defaults).")
    parser.add_argument(
        "--mode",
        choices=["once", "daemon"],
        default="once",
        help="'once' for a single sweep (default), 'daemon' for a loop.",
    )
    parser.add_argument(
        "--print-recent",
        type=int,
        default=0,
        metavar="N",
        help="After scan, print the N most-recent hits as JSONL.",
    )
    return parser


def build_config(args: argparse.Namespace) -> Config:
    tokens = list(DEFAULT_TOKENS)
    if args.tokens_file:
        tokens.extend(load_tokens_from_file(args.tokens_file))
    return Config(
        chains=list(args.chains),
        tokens=tokens,
        rpc_urls=default_rpc_urls(),
        threshold_usd=args.threshold_usd,
        chunk_blocks=args.chunk_blocks,
        poll_interval_s=args.poll_interval_s,
        db_path=args.db_path,
        lookback_blocks=args.lookback_blocks,
        confirmations=args.confirmations,
        max_chunks_per_tick=args.max_chunks_per_tick,
    )


def _print_recent(store: WhaleStore, n: int, chains: Iterable[int]) -> None:
    chain_set = set(chains)
    rows = store.recent_hits(limit=n)
    for row in rows:
        if row["chain_id"] not in chain_set:
            continue
        print(json.dumps(row, ensure_ascii=False))


def main() -> int:
    scryer_config.load()
    args = build_arg_parser().parse_args()
    config = build_config(args)

    if args.mode == "daemon":
        run_daemon(config)
        return 0

    results = run_once(config)
    total_new = sum(s.new_hits for s in results.values())
    _log.info("done. total new hits: %d", total_new)

    if args.print_recent > 0:
        store = WhaleStore(config.db_path)
        _print_recent(store, args.print_recent, args.chains)

    # Non-zero return if every chain errored — useful for cron alerting.
    if results and all(s.error for s in results.values()):
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
