"""Tests for scryer_whale_watcher: log parsing, threshold filter, store dedup,
and a fake-RPC end-to-end of scan_chain.

No real network. Tests substitute a stub RpcClient that returns canned logs.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path

import pytest

import scryer_whale_watcher as ww

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _hex32(value: int) -> str:
    return "0x" + format(value, "064x")


def _addr_to_topic(addr: str) -> str:
    a = addr.lower().removeprefix("0x")
    return "0x" + ("00" * 12) + a


def _make_raw_log(
    *,
    block: int,
    log_index: int,
    token: str,
    sender: str,
    receiver: str,
    amount: int,
    tx_hash: str | None = None,
) -> dict:
    return {
        "address": token.lower(),
        "topics": [
            ww.TRANSFER_TOPIC,
            _addr_to_topic(sender),
            _addr_to_topic(receiver),
        ],
        "data": _hex32(amount),
        "blockNumber": hex(block),
        "logIndex": hex(log_index),
        "transactionHash": tx_hash or ("0x" + "ab" * 32),
    }


# ---------------------------------------------------------------------------
# parse_transfer_log
# ---------------------------------------------------------------------------


def test_parse_transfer_log_extracts_addresses_and_amount() -> None:
    raw = _make_raw_log(
        block=123,
        log_index=4,
        token="0xdAC17F958D2ee523a2206206994597C13D831ec7",
        sender="0x" + "11" * 20,
        receiver="0x" + "22" * 20,
        amount=1_000_000,
    )
    log = ww.parse_transfer_log(1, raw)
    assert log is not None
    assert log.chain_id == 1
    assert log.block_number == 123
    assert log.log_index == 4
    assert log.token_address == "0xdac17f958d2ee523a2206206994597c13d831ec7"
    assert log.from_address == "0x" + "11" * 20
    assert log.to_address == "0x" + "22" * 20
    assert log.amount_raw == 1_000_000


def test_parse_skips_non_transfer_topic() -> None:
    raw = _make_raw_log(
        block=1,
        log_index=0,
        token="0x" + "00" * 19 + "01",
        sender="0x" + "11" * 20,
        receiver="0x" + "22" * 20,
        amount=1,
    )
    raw["topics"][0] = "0x" + "00" * 32  # not Transfer
    assert ww.parse_transfer_log(1, raw) is None


def test_parse_skips_short_topic_list() -> None:
    raw = _make_raw_log(
        block=1, log_index=0, token="0x" + "00" * 20, sender="0x" + "11" * 20, receiver="0x" + "22" * 20, amount=1
    )
    raw["topics"] = [ww.TRANSFER_TOPIC]
    assert ww.parse_transfer_log(1, raw) is None


def test_parse_returns_none_on_garbage() -> None:
    assert ww.parse_transfer_log(1, {"junk": True}) is None


def test_normalized_amount() -> None:
    log = ww.TransferLog(
        chain_id=1,
        block_number=1,
        tx_hash="0x" + "0" * 64,
        log_index=0,
        token_address="0x" + "0" * 40,
        from_address="0x" + "1" * 40,
        to_address="0x" + "2" * 40,
        amount_raw=12_345_678,
    )
    assert log.normalized(decimals=6) == pytest.approx(12.345678)


# ---------------------------------------------------------------------------
# threshold filter
# ---------------------------------------------------------------------------


def test_amount_passes_threshold_stablecoin_at_or_above() -> None:
    # 50000 USDC at 6 decimals = 50_000_000_000
    assert ww._amount_passes_threshold(50_000 * 10**6, decimals=6, threshold_usd=50_000.0)
    # one wei below threshold should fail
    assert not ww._amount_passes_threshold(50_000 * 10**6 - 1, decimals=6, threshold_usd=50_000.0)


def test_amount_passes_threshold_zero_threshold_means_all() -> None:
    assert ww._amount_passes_threshold(1, decimals=18, threshold_usd=0.0)


# ---------------------------------------------------------------------------
# is_contract heuristic
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "code,expected",
    [
        ("0x", False),
        ("", False),
        ("0xff", True),
        ("0x6080604052...", True),
        (None, False),
    ],
)
def test_is_contract_code(code: str, expected: bool) -> None:
    assert ww._is_contract_code(code) is expected


# ---------------------------------------------------------------------------
# WhaleStore: cursors and idempotent inserts
# ---------------------------------------------------------------------------


def test_store_cursor_roundtrip(tmp_path: Path) -> None:
    store = ww.WhaleStore(tmp_path / "w.db")
    assert store.get_cursor(1) is None
    store.set_cursor(1, 100)
    assert store.get_cursor(1) == 100
    store.set_cursor(1, 200)
    assert store.get_cursor(1) == 200


def test_store_insert_idempotent(tmp_path: Path) -> None:
    store = ww.WhaleStore(tmp_path / "w.db")
    log = ww.TransferLog(
        chain_id=1,
        block_number=1,
        tx_hash="0xabc",
        log_index=7,
        token_address="0xdac17f958d2ee523a2206206994597c13d831ec7",
        from_address="0x" + "1" * 40,
        to_address="0x" + "2" * 40,
        amount_raw=50_000 * 10**6,
    )
    assert store.insert_hit(log, symbol="USDT", decimals=6, receiver_is_contract=True) is True
    # Same (chain_id, tx_hash, log_index) -> rejected
    assert store.insert_hit(log, symbol="USDT", decimals=6, receiver_is_contract=True) is False

    rows = store.recent_hits(limit=10)
    assert len(rows) == 1
    assert rows[0]["token_symbol"] == "USDT"
    assert rows[0]["receiver_is_contract"] == 1


def test_store_recent_hits_filtered_by_chain(tmp_path: Path) -> None:
    store = ww.WhaleStore(tmp_path / "w.db")
    base = {
        "token_address": "0xt",
        "from_address": "0xf",
        "to_address": "0xrec",
        "log_index": 0,
    }
    for i, chain_id in enumerate([1, 1, 56, 56, 56]):
        log = ww.TransferLog(chain_id=chain_id, block_number=i, tx_hash=f"0x{i:064x}", amount_raw=10**18, **base)
        store.insert_hit(log, symbol="X", decimals=18, receiver_is_contract=True)
    assert len(store.recent_hits(limit=10, chain_id=1)) == 2
    assert len(store.recent_hits(limit=10, chain_id=56)) == 3
    assert len(store.recent_hits(limit=10)) == 5


# ---------------------------------------------------------------------------
# load_tokens_from_file
# ---------------------------------------------------------------------------


def test_load_tokens_from_file(tmp_path: Path) -> None:
    p = tmp_path / "extra.json"
    p.write_text(
        json.dumps(
            [
                {
                    "chain_id": 137,
                    "address": "0xC2132D05D31c914a87C6611C10748AEb04B58e8F",
                    "symbol": "USDT",
                    "decimals": 6,
                },
                {
                    "chain_id": 42161,
                    "address": "0xFF970A61A04b1cA14834A43f5dE4533eBDDB5CC8",
                    "symbol": "USDC",
                    "decimals": 6,
                },
            ]
        ),
        encoding="utf-8",
    )
    tokens = ww.load_tokens_from_file(p)
    assert {t.chain_id for t in tokens} == {137, 42161}
    assert tokens[0].address == "0xc2132d05d31c914a87c6611c10748aeb04b58e8f"


def test_load_tokens_from_file_rejects_non_array(tmp_path: Path) -> None:
    p = tmp_path / "bad.json"
    p.write_text(json.dumps({"not": "array"}))
    with pytest.raises(ValueError, match="JSON array"):
        ww.load_tokens_from_file(p)


# ---------------------------------------------------------------------------
# scan_chain end-to-end with a stub RPC
# ---------------------------------------------------------------------------


@dataclass
class StubRpc:
    head: int
    logs_by_chunk: list[list[dict]]
    code_by_addr: dict[str, str]
    chunk_idx: int = 0
    last_get_logs_call: dict | None = None

    def block_number(self) -> int:
        return self.head

    def get_logs(self, *, from_block: int, to_block: int, addresses, topics) -> list[dict]:
        self.last_get_logs_call = {"from": from_block, "to": to_block, "addresses": addresses, "topics": topics}
        if self.chunk_idx >= len(self.logs_by_chunk):
            return []
        out = self.logs_by_chunk[self.chunk_idx]
        self.chunk_idx += 1
        return out

    def get_code(self, address: str) -> str:
        return self.code_by_addr.get(address.lower(), "0x")


def test_scan_chain_filters_eoa_keeps_contracts(tmp_path: Path) -> None:
    """Two transfers in the same chunk: one to EOA, one to contract.

    Only the contract-receiver hit should be persisted.
    """
    contract_recv = "0x" + "33" * 20
    eoa_recv = "0x" + "44" * 20
    token = "0xdac17f958d2ee523a2206206994597c13d831ec7"
    logs = [
        _make_raw_log(
            block=900,
            log_index=0,
            token=token,
            sender="0x" + "11" * 20,
            receiver=contract_recv,
            amount=80_000 * 10**6,  # $80k -> above threshold
            tx_hash="0x" + "aa" * 32,
        ),
        _make_raw_log(
            block=900,
            log_index=1,
            token=token,
            sender="0x" + "11" * 20,
            receiver=eoa_recv,
            amount=80_000 * 10**6,
            tx_hash="0x" + "bb" * 32,
        ),
    ]
    rpc = StubRpc(
        head=1000,
        logs_by_chunk=[logs],
        code_by_addr={contract_recv: "0x6080604052"},  # contract
    )
    store = ww.WhaleStore(tmp_path / "w.db")
    cfg = ww.Config(
        chains=[1],
        tokens=[ww.TokenSpec(1, token, "USDT", 6)],
        rpc_urls={1: "http://stub"},
        threshold_usd=50_000.0,
        chunk_blocks=200,
        confirmations=3,
        lookback_blocks=200,
        max_chunks_per_tick=10,
        db_path=tmp_path / "w.db",
    )
    stats = ww.scan_chain(rpc, store, chain_id=1, tokens=cfg.tokens, config=cfg)
    assert stats.error is None
    assert stats.logs_seen == 2
    assert stats.hits_kept == 1  # only the contract receiver
    assert stats.new_hits == 1
    rows = store.recent_hits(limit=5)
    assert len(rows) == 1
    assert rows[0]["to_address"] == contract_recv
    assert rows[0]["amount_normalized"] == pytest.approx(80_000.0)


def test_scan_chain_drops_below_threshold(tmp_path: Path) -> None:
    contract_recv = "0x" + "33" * 20
    token = "0xdac17f958d2ee523a2206206994597c13d831ec7"
    logs = [
        _make_raw_log(
            block=900,
            log_index=0,
            token=token,
            sender="0x" + "11" * 20,
            receiver=contract_recv,
            amount=10_000 * 10**6,  # $10k < threshold
        ),
    ]
    rpc = StubRpc(head=1000, logs_by_chunk=[logs], code_by_addr={contract_recv: "0xff"})
    store = ww.WhaleStore(tmp_path / "w.db")
    cfg = ww.Config(
        chains=[1],
        tokens=[ww.TokenSpec(1, token, "USDT", 6)],
        rpc_urls={1: "http://stub"},
        threshold_usd=50_000.0,
        chunk_blocks=200,
        confirmations=3,
        lookback_blocks=200,
        max_chunks_per_tick=10,
        db_path=tmp_path / "w.db",
    )
    stats = ww.scan_chain(rpc, store, chain_id=1, tokens=cfg.tokens, config=cfg)
    assert stats.logs_seen == 1
    assert stats.hits_kept == 0


def test_scan_chain_advances_cursor_across_ticks(tmp_path: Path) -> None:
    """Two consecutive scan_chain calls should not re-process old logs."""
    contract_recv = "0x" + "33" * 20
    token = "0xdac17f958d2ee523a2206206994597c13d831ec7"
    log = _make_raw_log(
        block=900, log_index=0, token=token, sender="0x" + "11" * 20, receiver=contract_recv, amount=80_000 * 10**6
    )
    store = ww.WhaleStore(tmp_path / "w.db")
    cfg = ww.Config(
        chains=[1],
        tokens=[ww.TokenSpec(1, token, "USDT", 6)],
        rpc_urls={1: "http://stub"},
        threshold_usd=50_000.0,
        chunk_blocks=200,
        confirmations=3,
        lookback_blocks=200,
        max_chunks_per_tick=10,
        db_path=tmp_path / "w.db",
    )

    rpc = StubRpc(head=1000, logs_by_chunk=[[log]], code_by_addr={contract_recv: "0xff"})
    s1 = ww.scan_chain(rpc, store, chain_id=1, tokens=cfg.tokens, config=cfg)
    assert s1.new_hits == 1
    cursor_after_tick1 = store.get_cursor(1)
    assert cursor_after_tick1 is not None and cursor_after_tick1 >= 900

    # Tick 2: head moved forward but no new logs in the new range.
    rpc2 = StubRpc(head=1100, logs_by_chunk=[[]], code_by_addr={})
    s2 = ww.scan_chain(rpc2, store, chain_id=1, tokens=cfg.tokens, config=cfg)
    assert s2.new_hits == 0
    # We must have asked for blocks AFTER cursor_after_tick1, never re-asked the old chunk.
    assert rpc2.last_get_logs_call is not None
    assert rpc2.last_get_logs_call["from"] == cursor_after_tick1 + 1


def test_scan_chain_handles_block_number_failure(tmp_path: Path) -> None:
    class BrokenRpc:
        def block_number(self) -> int:
            raise RuntimeError("network down")

        def get_logs(self, **kwargs) -> list[dict]:
            return []

        def get_code(self, address: str) -> str:
            return "0x"

    store = ww.WhaleStore(tmp_path / "w.db")
    cfg = ww.Config(
        chains=[1],
        tokens=[ww.TokenSpec(1, "0xdac17f958d2ee523a2206206994597c13d831ec7", "USDT", 6)],
        rpc_urls={1: "http://stub"},
        db_path=tmp_path / "w.db",
    )
    stats = ww.scan_chain(BrokenRpc(), store, chain_id=1, tokens=cfg.tokens, config=cfg)
    assert stats.error is not None and "block_number" in stats.error
    assert stats.new_hits == 0


# ---------------------------------------------------------------------------
# CLI argparse smoke
# ---------------------------------------------------------------------------


def test_build_arg_parser_accepts_expected_flags() -> None:
    parser = ww.build_arg_parser()
    args = parser.parse_args(
        [
            "--chains",
            "1,56",
            "--threshold-usd",
            "10000",
            "--mode",
            "once",
            "--db-path",
            "x.db",
            "--print-recent",
            "5",
        ]
    )
    assert args.chains == [1, 56]
    assert args.threshold_usd == 10_000.0
    assert args.mode == "once"
    assert args.print_recent == 5


def test_build_arg_parser_accepts_scan_on_hit_flags() -> None:
    parser = ww.build_arg_parser()
    args = parser.parse_args(
        [
            "--scan-on-hit",
            "--scan-rule-file",
            "rules/unprotected_withdraw.json",
            "--scan-rule-file",
            "rules/ai_authored_drainer.json",
            "--scan-sources-dir",
            "tmp_sources",
        ]
    )
    assert args.scan_on_hit is True
    assert [p.as_posix() for p in args.scan_rule_file] == [
        "rules/unprotected_withdraw.json",
        "rules/ai_authored_drainer.json",
    ]
    assert args.scan_sources_dir.as_posix() == "tmp_sources"


def test_store_update_scan_summary_persists(tmp_path: Path) -> None:
    store = ww.WhaleStore(tmp_path / "w.db")
    log = ww.TransferLog(
        chain_id=1,
        block_number=42,
        tx_hash="0xfeed",
        log_index=3,
        token_address="0xdac17f958d2ee523a2206206994597c13d831ec7",
        from_address="0x" + "1" * 40,
        to_address="0x" + "2" * 40,
        amount_raw=10**6,
    )
    store.insert_hit(log, symbol="USDT", decimals=6, receiver_is_contract=True)
    store.update_scan_summary(chain_id=1, tx_hash="0xfeed", log_index=3, summary='{"total":3}')
    rows = store.recent_hits(limit=10)
    assert rows[0]["scan_summary"] == '{"total":3}'


def test_store_migrates_existing_db_without_scan_summary_column(tmp_path: Path) -> None:
    """Older .whale_watcher.db files predate the scan_summary column;
    the WhaleStore init must ALTER TABLE rather than fail."""
    import sqlite3

    db = tmp_path / "legacy.db"
    with sqlite3.connect(db) as conn:
        conn.executescript(
            """
            CREATE TABLE whale_hits (
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
            """
        )
        conn.commit()
    # Should not raise
    ww.WhaleStore(db)
    with sqlite3.connect(db) as conn:
        cols = {row[1] for row in conn.execute("PRAGMA table_info(whale_hits)").fetchall()}
    assert "scan_summary" in cols
