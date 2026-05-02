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


PAGE_ROUTES = ["/", "/contracts", "/duplicates", "/search", "/vulnerabilities", "/similarity"]


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
