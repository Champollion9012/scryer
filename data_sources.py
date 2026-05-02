"""
Additional Contract Data Sources.
Provides Blockscout, on-chain traversal, and BigQuery integrations.
"""

from __future__ import annotations

import asyncio
import os
from dataclasses import dataclass
from datetime import datetime

import httpx

from scryer_logging import get_logger

_log = get_logger(__name__)

# ============================================================================
# Blockscout API
# ============================================================================

# Blockscout instances for various chains
BLOCKSCOUT_CHAINS: dict[int, str] = {
    1: "https://eth.blockscout.com/api/v2",
    10: "https://optimism.blockscout.com/api/v2",
    56: "https://bscscan.blockscout.com/api/v2",  # Note: may not exist
    137: "https://polygon.blockscout.com/api/v2",
    42161: "https://arbitrum.blockscout.com/api/v2",
    8453: "https://base.blockscout.com/api/v2",
    43114: "https://snowtrace.io/api/v2",  # Avalanche uses blockscout
    250: "https://ftmscan.blockscout.com/api/v2",
}


async def fetch_blockscout_verified_contracts(
    chain_id: int,
    client: httpx.AsyncClient,
    min_date: datetime | None = None,
    max_results: int = 5000,
) -> list[str]:
    """Fetch verified contract addresses from Blockscout API."""
    base_url = BLOCKSCOUT_CHAINS.get(chain_id)
    if not base_url:
        return []

    addresses: list[str] = []
    next_page_params: dict | None = None

    while len(addresses) < max_results:
        url = f"{base_url}/smart-contracts"
        if next_page_params:
            url += "?" + "&".join(f"{k}={v}" for k, v in next_page_params.items())

        try:
            resp = await client.get(url, timeout=30.0)
            if resp.status_code != 200:
                break

            data = resp.json()
            items = data.get("items", [])

            if not items:
                break

            for item in items:
                addr = item.get("address", {}).get("hash", "")
                verified_at = item.get("verified_at", "")

                # Filter by date if specified
                if min_date and verified_at:
                    try:
                        contract_date = datetime.fromisoformat(verified_at.replace("Z", "+00:00"))
                        if contract_date.replace(tzinfo=None) < min_date:
                            return addresses
                    except:
                        pass

                if addr:
                    addresses.append(addr.lower())

            next_page_params = data.get("next_page_params")
            if not next_page_params:
                break

        except Exception as e:
            _log.warning("  Blockscout error: %s", e)
            break

    return addresses


async def fetch_blockscout_source(
    chain_id: int,
    address: str,
    client: httpx.AsyncClient,
) -> tuple[dict[str, str], dict | None]:
    """Fetch contract source from Blockscout API."""
    base_url = BLOCKSCOUT_CHAINS.get(chain_id)
    if not base_url:
        return {}, None

    url = f"{base_url}/smart-contracts/{address}"

    try:
        resp = await client.get(url, timeout=30.0)
        if resp.status_code != 200:
            return {}, None

        data = resp.json()

        sources: dict[str, str] = {}
        contract_name = data.get("name", "Contract")

        # Main source
        source_code = data.get("source_code", "")
        if source_code:
            sources[f"{contract_name}.sol"] = source_code

        # Additional sources
        additional = data.get("additional_sources", [])
        for item in additional:
            name = item.get("file_path", "")
            content = item.get("source_code", "")
            if name and content:
                sources[name] = content

        metadata = {
            "ContractName": contract_name,
            "CompilerVersion": data.get("compiler_version"),
            "OptimizationUsed": data.get("optimization_enabled"),
            "Runs": data.get("optimization_runs"),
            "EVMVersion": data.get("evm_version"),
        }

        return sources, metadata

    except Exception as e:
        _log.warning("  Blockscout source error for %s: %s", address, e)
        return {}, None


# ============================================================================
# On-chain Traversal + IPFS
# ============================================================================

# IPFS Gateways (try in order)
IPFS_GATEWAYS = [
    "https://ipfs.io/ipfs/",
    "https://cloudflare-ipfs.com/ipfs/",
    "https://gateway.pinata.cloud/ipfs/",
    "https://dweb.link/ipfs/",
]


def extract_ipfs_cid_from_bytecode(bytecode: str) -> str | None:
    """
    Extract IPFS CID (CIDv0, ``Qm...``) from Solidity bytecode metadata.

    Solidity appends a CBOR-encoded metadata blob at the end of bytecode,
    with the last 2 bytes being the blob's length (big-endian). The blob
    is a CBOR map that may contain an ``ipfs`` key holding the raw 34-byte
    multihash (0x12 0x20 + 32 bytes of SHA-256). The CIDv0 is the base58
    encoding of that multihash.

    Returns ``None`` if bytecode is missing, malformed, or only contains a
    Swarm hash (bzzr0 / bzzr1) instead of IPFS.
    """
    if not bytecode or len(bytecode) < 4:
        return None

    # Reuse the canonical implementation from download_contract to avoid
    # drift between two slightly-different IPFS extractors.
    from download_contract import ipfs_cid_from_multihash

    try:
        import cbor2  # local import: data_sources stays import-safe even if cbor2 missing
    except ImportError:
        _log.debug("cbor2 not installed; cannot parse bytecode metadata")
        return None

    hex_str = bytecode[2:] if bytecode.startswith("0x") else bytecode
    try:
        raw = bytes.fromhex(hex_str)
    except ValueError:
        return None

    if len(raw) < 4:
        return None

    metadata_length = int.from_bytes(raw[-2:], "big")
    if metadata_length <= 0 or metadata_length + 2 > len(raw):
        return None

    blob = raw[-(2 + metadata_length) : -2]
    try:
        decoded = cbor2.loads(blob)
    except Exception:
        return None

    if not isinstance(decoded, dict):
        return None

    ipfs_val = decoded.get("ipfs")
    if isinstance(ipfs_val, (bytes, bytearray)):
        return ipfs_cid_from_multihash(bytes(ipfs_val))
    if isinstance(ipfs_val, str) and ipfs_val:
        return ipfs_val

    # Swarm-only metadata — caller should fall back to other sources.
    return None


async def fetch_ipfs_metadata(
    cid: str,
    client: httpx.AsyncClient,
) -> dict | None:
    """Fetch metadata.json from IPFS."""
    for gateway in IPFS_GATEWAYS:
        url = f"{gateway}{cid}"
        try:
            resp = await client.get(url, timeout=30.0)
            if resp.status_code == 200:
                return resp.json()
        except:
            continue
    return None


async def fetch_contracts_from_blocks(
    rpc_url: str,
    start_block: int,
    end_block: int,
    client: httpx.AsyncClient,
) -> list[dict]:
    """
    Fetch contract creation transactions from block range.
    Returns list of {address, bytecode, block_number, tx_hash}.
    """
    contracts: list[dict] = []

    for block_num in range(start_block, end_block + 1):
        # Get block with transactions
        payload = {
            "jsonrpc": "2.0",
            "method": "eth_getBlockByNumber",
            "params": [hex(block_num), True],
            "id": 1,
        }

        try:
            resp = await client.post(rpc_url, json=payload, timeout=30.0)
            data = resp.json()
            block = data.get("result")

            if not block:
                continue

            for tx in block.get("transactions", []):
                # Contract creation: to is None/null
                if tx.get("to") is None:
                    # Get contract address from receipt
                    receipt_payload = {
                        "jsonrpc": "2.0",
                        "method": "eth_getTransactionReceipt",
                        "params": [tx["hash"]],
                        "id": 2,
                    }

                    receipt_resp = await client.post(rpc_url, json=receipt_payload, timeout=30.0)
                    receipt_data = receipt_resp.json()
                    receipt = receipt_data.get("result", {})

                    contract_address = receipt.get("contractAddress")
                    if contract_address:
                        contracts.append(
                            {
                                "address": contract_address.lower(),
                                "bytecode": tx.get("input", ""),
                                "block_number": block_num,
                                "tx_hash": tx["hash"],
                            }
                        )

        except Exception as e:
            _log.warning("  Block %s error: %s", block_num, e)
            continue

        if block_num % 100 == 0:
            _log.info("  Scanned block %s, found %d contracts", block_num, len(contracts))

    return contracts


# ============================================================================
# Google BigQuery
# ============================================================================

BIGQUERY_DATASETS = {
    1: "bigquery-public-data.crypto_ethereum",
    # BSC and others may not be public
}


async def fetch_contracts_from_bigquery(
    chain_id: int,
    days_back: int = 30,
    max_results: int = 10000,
) -> list[dict]:
    """
    Fetch contract addresses from Google BigQuery public datasets.

    Requires:
        pip install google-cloud-bigquery
        GOOGLE_APPLICATION_CREDENTIALS env var or gcloud auth
    """
    try:
        from google.cloud import bigquery
    except ImportError:
        _log.warning("  BigQuery not available. Install: pip install google-cloud-bigquery")
        return []

    dataset = BIGQUERY_DATASETS.get(chain_id)
    if not dataset:
        _log.warning("  No BigQuery dataset for chain %s", chain_id)
        return []

    client = bigquery.Client()

    query = f"""
    SELECT 
        address,
        bytecode,
        block_timestamp,
        block_number
    FROM `{dataset}.contracts`
    WHERE block_timestamp > TIMESTAMP_SUB(CURRENT_TIMESTAMP(), INTERVAL {days_back} DAY)
    ORDER BY block_timestamp DESC
    LIMIT {max_results}
    """

    try:
        query_job = client.query(query)
        results = query_job.result()

        contracts = []
        for row in results:
            contracts.append(
                {
                    "address": row.address.lower() if row.address else "",
                    "bytecode": row.bytecode or "",
                    "block_number": row.block_number,
                    "timestamp": row.block_timestamp.isoformat() if row.block_timestamp else None,
                }
            )

        return contracts

    except Exception as e:
        _log.warning("  BigQuery error: %s", e)
        return []


# ============================================================================
# Unified Interface
# ============================================================================


@dataclass
class DataSourceConfig:
    name: str
    enabled: bool = True
    priority: int = 0  # Lower = higher priority


class MultiSourceCrawler:
    """
    Crawler that uses multiple data sources with fallback.
    """

    def __init__(
        self,
        sources: list[str] | None = None,
        rpc_url: str | None = None,
    ):
        # Default source order: sourcify -> blockscout -> explorer
        self.sources = sources or ["sourcify", "blockscout", "explorer"]
        self.rpc_url = rpc_url or os.getenv("RPC_URL")

    async def get_verified_contracts(
        self,
        chain_id: int,
        client: httpx.AsyncClient,
        min_date: datetime | None = None,
        max_results: int = 5000,
    ) -> list[str]:
        """Get verified contract addresses from multiple sources."""
        all_addresses: set[str] = set()

        for source in self.sources:
            if source == "sourcify":
                # Import from contract_crawler
                from contract_crawler import AsyncRateLimiter, fetch_sourcify_verified_contracts

                rate_limiter = AsyncRateLimiter(3.0)
                addrs = await fetch_sourcify_verified_contracts(chain_id, client, rate_limiter, min_date)
                all_addresses.update(addrs)
                _log.info("  Sourcify: %d contracts", len(addrs))

            elif source == "blockscout":
                addrs = await fetch_blockscout_verified_contracts(chain_id, client, min_date, max_results)
                all_addresses.update(addrs)
                _log.info("  Blockscout: %d contracts", len(addrs))

            elif source == "bigquery":
                days = 365 if not min_date else (datetime.now() - min_date).days
                contracts = await asyncio.get_event_loop().run_in_executor(
                    None, fetch_contracts_from_bigquery, chain_id, days, max_results
                )
                all_addresses.update(c["address"] for c in contracts)
                _log.info("  BigQuery: %d contracts", len(contracts))

        return list(all_addresses)[:max_results]

    async def get_source_code(
        self,
        chain_id: int,
        address: str,
        client: httpx.AsyncClient,
    ) -> tuple[dict[str, str], dict | None]:
        """Get source code from multiple sources with fallback."""

        for source in self.sources:
            sources: dict[str, str] = {}
            metadata: dict | None = None

            if source == "sourcify":
                from contract_crawler import AsyncRateLimiter, fetch_sourcify_source

                rate_limiter = AsyncRateLimiter(3.0)
                sources, metadata = await fetch_sourcify_source(chain_id, address, client, rate_limiter)

            elif source == "blockscout":
                sources, metadata = await fetch_blockscout_source(chain_id, address, client)

            elif source == "explorer":
                from contract_crawler import AsyncRateLimiter, fetch_explorer_source, get_chain_by_id

                chain = get_chain_by_id(chain_id)
                if chain:
                    rate_limiter = AsyncRateLimiter(3.0)
                    sources, metadata = await fetch_explorer_source(chain, address, client, rate_limiter)

            if sources:
                return sources, metadata

        return {}, None
