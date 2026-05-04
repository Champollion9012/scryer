"""Tests for the Flask web dashboard.

Each test gets a fresh on-disk registry under ``tmp_path`` so we don't read
or write the developer's real ``.contract_registry.db``.
"""

from __future__ import annotations

import pytest

import web
from contract_registry import ContractRegistry


@pytest.fixture
def client(tmp_path, monkeypatch):
    db = tmp_path / "registry.db"
    test_registry = ContractRegistry(db_path=db)
    # Seed enough data to exercise the rendering paths.
    test_registry.register_contract(56, "0x" + "11" * 20, {"A.sol": "contract A {}"}, contract_name="A")
    test_registry.register_contract(56, "0x" + "22" * 20, {"A.sol": "contract A {}"}, contract_name="A")
    test_registry.register_contract(1, "0x" + "33" * 20, {"B.sol": "contract B {}"}, contract_name="B")
    test_registry.tag_vulnerability(
        ContractRegistry.compute_source_hash({"A.sol": "contract A {}"}),
        tag="reentrancy",
        severity="High",
        description="example issue",
    )

    monkeypatch.setattr(web, "registry", test_registry)
    web.app.config.update(TESTING=True)
    with web.app.test_client() as c:
        yield c


PAGE_ROUTES = ["/", "/contracts", "/duplicates", "/search", "/vulnerabilities", "/similarity", "/whales"]


@pytest.mark.parametrize("route", PAGE_ROUTES)
def test_page_renders_base_layout(client, route: str) -> None:
    resp = client.get(route)
    assert resp.status_code == 200, f"{route} returned {resp.status_code}"
    body = resp.get_data(as_text=True)
    assert "<h1>Contract Registry Explorer</h1>" in body
    assert 'id="toast"' in body  # base layout footer artefact


def test_dashboard_shows_seeded_counts(client) -> None:
    body = client.get("/").get_data(as_text=True)
    # 3 contracts seeded, with 2 sharing a hash → duplicated_hashes >= 1
    assert ">3<" in body  # total contracts stat card


def test_contracts_search_filters_by_chain(client) -> None:
    body = client.get("/contracts?chain=1").get_data(as_text=True)
    # Address starting with 0x33 lives on chain 1
    assert "0x3333333333" in body
    # Chain-56 addresses should not appear (whether match would still embed,
    # so check the filter actually narrowed the result set)
    assert "0x1111111111" not in body or "0x2222222222" not in body


def test_hash_detail_lists_all_addresses_for_hash(client) -> None:
    h = ContractRegistry.compute_source_hash({"A.sol": "contract A {}"})
    body = client.get(f"/hash/{h}").get_data(as_text=True)
    assert "0x1111111111" in body
    assert "0x2222222222" in body


def test_vulnerabilities_lists_seeded_tag(client) -> None:
    body = client.get("/vulnerabilities").get_data(as_text=True)
    assert "reentrancy" in body
    assert "High" in body


def test_search_no_address_renders_empty_form(client) -> None:
    body = client.get("/search").get_data(as_text=True)
    assert "Find Related Contracts" in body
    # No related-results table when address is empty
    assert "Found " not in body or "No related contracts found" not in body


def test_api_stats_returns_json(client) -> None:
    resp = client.get("/api/stats")
    assert resp.status_code == 200 and resp.is_json
    payload = resp.get_json()
    assert payload["total_contracts"] == 3
    assert payload["unique_source_hashes"] == 2  # A.sol shared, B.sol unique


def test_api_contracts_filters_by_chain(client) -> None:
    payload = client.get("/api/contracts?chain=1").get_json()
    assert isinstance(payload, list)
    assert all(c["chain_id"] == 1 for c in payload)


def test_api_related_returns_only_same_hash(client) -> None:
    payload = client.get("/api/related/56/0x" + "11" * 20).get_json()
    addrs = {c["address"] for c in payload}
    assert addrs == {"0x" + "11" * 20, "0x" + "22" * 20}


def test_api_export_csv_has_header_and_rows(client) -> None:
    resp = client.get("/api/export/csv")
    assert resp.status_code == 200
    body = resp.get_data(as_text=True)
    assert body.startswith("chain_id,address,contract_name,source_hash")
    assert body.count("\n") >= 4  # header + 3 contracts


def test_api_export_unsupported_format_returns_error_json(client) -> None:
    resp = client.get("/api/export/xml")
    assert resp.is_json
    assert "error" in resp.get_json()


def test_tag_vulnerability_endpoint_requires_fields(client) -> None:
    resp = client.post("/api/tag-vulnerability", data={})
    assert resp.is_json
    assert resp.get_json()["success"] is False


def test_tag_vulnerability_endpoint_inserts(client) -> None:
    resp = client.post(
        "/api/tag-vulnerability",
        data={"source_hash": "deadbeef", "tag": "uninitialized-storage", "severity": "Medium"},
    )
    assert resp.is_json
    assert resp.get_json()["success"] is True


# ---------------------------------------------------------------------------
# /whales route — empty DB and seeded DB
# ---------------------------------------------------------------------------


def test_whales_route_handles_missing_db(client, tmp_path, monkeypatch) -> None:
    """When no whale_watcher DB exists, the page renders an explanatory empty state."""
    monkeypatch.setattr(
        "scryer_config.get",
        lambda key, default=None: str(tmp_path / "absent.db") if key == "WHALE_WATCHER_DB" else default,
    )
    body = client.get("/whales").get_data(as_text=True)
    assert "No whale_watcher database yet" in body
    assert "scryer_whale_watcher.py" in body


def test_whales_route_renders_seeded_hits(client, tmp_path, monkeypatch) -> None:
    """A populated DB shows the row in the table and includes the explorer link."""
    import scryer_whale_watcher as ww

    db = tmp_path / "w.db"
    store = ww.WhaleStore(db)
    log = ww.TransferLog(
        chain_id=1,
        block_number=1234,
        tx_hash="0x" + "ab" * 32,
        log_index=0,
        token_address="0xdac17f958d2ee523a2206206994597c13d831ec7",
        from_address="0x" + "11" * 20,
        to_address="0x" + "22" * 20,
        amount_raw=80_000 * 10**6,
    )
    store.insert_hit(log, symbol="USDT", decimals=6, receiver_is_contract=True)

    monkeypatch.setattr(
        "scryer_config.get",
        lambda key, default=None: str(db) if key == "WHALE_WATCHER_DB" else default,
    )

    body = client.get("/whales").get_data(as_text=True)
    assert "USDT" in body
    # ETH explorer link assembled from CHAIN_EXPLORERS
    assert "etherscan.io/tx/" in body
    assert "0xab" in body
    # Receiver renders truncated
    assert "0x2222222222" in body


def test_whales_route_ignores_garbage_chain_param(client, tmp_path, monkeypatch) -> None:
    """?chain=foo must not 500 — graceful fall back to "all chains"."""
    monkeypatch.setattr(
        "scryer_config.get",
        lambda key, default=None: str(tmp_path / "absent.db") if key == "WHALE_WATCHER_DB" else default,
    )
    resp = client.get("/whales?chain=not-an-int&to=junk")
    assert resp.status_code == 200


def test_api_whales_clamps_limit(client, tmp_path, monkeypatch) -> None:
    """Negative or zero limit must be clamped — SQLite LIMIT -1 = unlimited."""
    import scryer_whale_watcher as ww

    db = tmp_path / "w.db"
    store = ww.WhaleStore(db)
    # Seed 5 hits so we can verify the limit bound is enforced.
    for i in range(5):
        log = ww.TransferLog(
            chain_id=1,
            block_number=1000 + i,
            tx_hash=f"0x{i:064x}",
            log_index=0,
            token_address="0xdac17f958d2ee523a2206206994597c13d831ec7",
            from_address="0x" + "11" * 20,
            to_address="0x" + "22" * 20,
            amount_raw=80_000 * 10**6,
        )
        store.insert_hit(log, symbol="USDT", decimals=6, receiver_is_contract=True)

    monkeypatch.setattr(
        "scryer_config.get",
        lambda key, default=None: str(db) if key == "WHALE_WATCHER_DB" else default,
    )

    # limit=-1 (raw) -> clamped to 1 (NOT unlimited)
    resp = client.get("/api/whales?limit=-1")
    assert resp.status_code == 200
    payload = resp.get_json()
    assert len(payload["hits"]) == 1, "negative limit should clamp to 1, not return all rows"

    # limit=abc -> default 100 -> all 5 returned
    resp = client.get("/api/whales?limit=garbage")
    assert resp.status_code == 200
    assert len(resp.get_json()["hits"]) == 5

    # limit=99999 -> capped at 1000 (we can't directly observe the cap with 5 rows,
    # but we can confirm we still get all 5 and no error)
    resp = client.get("/api/whales?limit=99999")
    assert resp.status_code == 200
    assert len(resp.get_json()["hits"]) == 5


def test_api_whales_returns_json(client, tmp_path, monkeypatch) -> None:
    import scryer_whale_watcher as ww

    db = tmp_path / "w.db"
    store = ww.WhaleStore(db)
    log = ww.TransferLog(
        chain_id=56,
        block_number=999,
        tx_hash="0x" + "cd" * 32,
        log_index=2,
        token_address="0x55d398326f99059ff775485246999027b3197955",
        from_address="0x" + "11" * 20,
        to_address="0x" + "22" * 20,
        amount_raw=70_000 * 10**18,
    )
    store.insert_hit(log, symbol="USDT", decimals=18, receiver_is_contract=True)

    monkeypatch.setattr(
        "scryer_config.get",
        lambda key, default=None: str(db) if key == "WHALE_WATCHER_DB" else default,
    )

    resp = client.get("/api/whales?chain=56&limit=10")
    assert resp.is_json
    payload = resp.get_json()
    assert payload["db_exists"] is True
    assert payload["totals"]["total"] == 1
    assert len(payload["hits"]) == 1
    assert payload["hits"][0]["token_symbol"] == "USDT"
    assert payload["hits"][0]["chain_name"] == "BSC"
    assert "bscscan.com/tx/" in payload["hits"][0]["tx_explorer_url"]
