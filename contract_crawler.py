"""
Multi-chain Smart Contract Crawler.
Fetches verified contracts from the past year across EVM-compatible chains.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import os
import time
from dataclasses import dataclass
from datetime import datetime, timedelta
from pathlib import Path

import httpx

import scryer_http
from scryer_http import RateLimited, rate_limit_reason, retry_after_seconds
from contract_registry import ContractRegistry
from scryer_logging import get_logger

_log = get_logger(__name__)

# ============================================================================
# Chain Configuration
# ============================================================================


@dataclass
class ChainConfig:
    chain_id: int
    name: str
    sourcify_supported: bool
    explorer_api: str | None  # Etherscan-like API base URL
    explorer_api_key_env: str | None  # Environment variable for API key


CHAINS: list[ChainConfig] = [
    ChainConfig(1, "ethereum", True, "https://api.etherscan.io/api", "ETHERSCAN_API_KEY"),
    ChainConfig(56, "bsc", True, "https://api.bscscan.com/api", "BSCSCAN_API_KEY"),
    ChainConfig(137, "polygon", True, "https://api.polygonscan.com/api", "POLYGONSCAN_API_KEY"),
    ChainConfig(42161, "arbitrum", True, "https://api.arbiscan.io/api", "ARBISCAN_API_KEY"),
    ChainConfig(10, "optimism", True, "https://api-optimistic.etherscan.io/api", "OPTIMISM_API_KEY"),
    ChainConfig(43114, "avalanche", True, "https://api.snowtrace.io/api", "SNOWTRACE_API_KEY"),
    ChainConfig(250, "fantom", True, "https://api.ftmscan.com/api", "FTMSCAN_API_KEY"),
    ChainConfig(8453, "base", True, "https://api.basescan.org/api", "BASESCAN_API_KEY"),
]


def get_chain_by_id(chain_id: int) -> ChainConfig | None:
    for chain in CHAINS:
        if chain.chain_id == chain_id:
            return chain
    return None


# ============================================================================
# Rate Limiter
# ============================================================================


class AsyncRateLimiter:
    def __init__(self, requests_per_second: float = 3.0):
        self.min_interval = 1.0 / requests_per_second
        self._lock = asyncio.Lock()
        self._last_request = 0.0

    async def wait(self):
        async with self._lock:
            now = time.time()
            wait_time = self._last_request + self.min_interval - now
            if wait_time > 0:
                await asyncio.sleep(wait_time)
            self._last_request = time.time()


# ============================================================================
# Sourcify API
# ============================================================================

SOURCIFY_API = "https://sourcify.dev/server"


async def fetch_sourcify_verified_contracts(
    chain_id: int,
    client: httpx.AsyncClient,
    rate_limiter: AsyncRateLimiter,
    min_date: datetime | None = None,
) -> list[str]:
    """Fetch list of verified contract addresses from Sourcify APIv2."""
    addresses: list[str] = []
    after_match_id: str | None = None
    limit = 200
    page = 0

    while True:
        await rate_limiter.wait()

        # Sourcify APIv2 endpoint
        url = f"{SOURCIFY_API}/v2/contracts/{chain_id}?limit={limit}&sort=desc"
        if after_match_id:
            url += f"&afterMatchId={after_match_id}"

        try:
            resp = await client.get(url, timeout=30.0)
            if resp.status_code != 200:
                reason = rate_limit_reason(resp)
                if reason:
                    # Throttled mid-pagination: the list is INCOMPLETE. Raise so the caller does
                    # not treat a truncated list as the full set of verified contracts (which
                    # would leave the un-paginated remainder permanently un-crawled).
                    raise RateLimited(provider="sourcify", retry_after=retry_after_seconds(resp), detail=reason)
                _log.warning("  Sourcify API error: %s", resp.status_code)
                break

            data = resp.json()
            results = data.get("results", [])

            if not results:
                break

            for contract in results:
                addr = contract.get("address", "")
                verified_at = contract.get("verifiedAt", "")

                # Filter by date if specified
                if min_date and verified_at:
                    try:
                        contract_date = datetime.fromisoformat(verified_at.replace("Z", "+00:00"))
                        if contract_date.replace(tzinfo=None) < min_date:
                            # Stop if we've gone past the min date (sorted desc)
                            return addresses
                    except (ValueError, TypeError):
                        pass

                if addr:
                    addresses.append(addr.lower())
                    after_match_id = contract.get("matchId")

            page += 1
            _log.info("  Sourcify page %d: %d contracts (total: %d)", page, len(results), len(addresses))

            # Safety limit
            if page > 500 or len(addresses) >= 100000:
                break

        except RateLimited:
            raise  # propagate so the chain is not marked fully listed off a truncated page
        except Exception as e:
            _log.warning("  Sourcify error: %s", e)
            break

    return addresses


async def fetch_sourcify_source(
    chain_id: int,
    address: str,
    client: httpx.AsyncClient,
    rate_limiter: AsyncRateLimiter,
) -> tuple[dict[str, str], dict | None]:
    """Fetch contract source files from Sourcify APIv2."""
    await rate_limiter.wait()

    # Sourcify APIv2: Get contract details including source files
    url = f"{SOURCIFY_API}/v2/contract/{chain_id}/{address}?fields=sources"
    try:
        resp = await client.get(url, timeout=30.0)
        reason = rate_limit_reason(resp)
        if reason:
            # A throttle must not be swallowed as "not on Sourcify" — that would fall through
            # to the explorer/decompile path and register a throttled contract as source-less.
            raise RateLimited(provider="sourcify", retry_after=retry_after_seconds(resp), detail=reason)
        if resp.status_code == 200:
            data = resp.json()
            sources: dict[str, str] = {}
            metadata: dict | None = None

            # v2 API returns sources in different format
            source_data = data.get("sources") or data.get("sourceFiles") or {}

            if isinstance(source_data, dict):
                for path, content in source_data.items():
                    if isinstance(content, str):
                        if path.endswith(".sol"):
                            sources[path] = content
                    elif isinstance(content, dict):
                        src = content.get("content", "")
                        if path.endswith(".sol") and src:
                            sources[path] = src

            # Try to get metadata
            meta = data.get("metadata")
            if meta and isinstance(meta, dict):
                metadata = {
                    "ContractName": data.get("name") or meta.get("settings", {}).get("compilationTarget", {}),
                    "CompilerVersion": meta.get("compiler", {}).get("version"),
                }

            if sources:
                return sources, metadata
    except RateLimited:
        raise
    except Exception:
        # Silent fail, will try fallback
        pass

    return {}, None


# ============================================================================
# Etherscan-like API
# ============================================================================


async def fetch_explorer_recent_contracts(
    chain: ChainConfig,
    client: httpx.AsyncClient,
    rate_limiter: AsyncRateLimiter,
    min_timestamp: int,
    max_results: int = 10000,
) -> list[dict]:
    """
    Fetch recently verified contracts from Etherscan-like explorer.
    Uses contract verification list endpoint if available.
    """
    if not chain.explorer_api:
        return []

    api_key = os.getenv(chain.explorer_api_key_env or "", "")
    if not api_key:
        _log.warning("  No API key for %s, skipping explorer API", chain.name)
        return []

    contracts: list[dict] = []

    # Note: Most Etherscan APIs don't have a "list all verified contracts" endpoint
    # We'll use the "get verified source code" for known addresses instead
    # This is a limitation - need contract addresses from somewhere else

    return contracts


async def fetch_explorer_source(
    chain: ChainConfig,
    address: str,
    client: httpx.AsyncClient,
    rate_limiter: AsyncRateLimiter,
) -> tuple[dict[str, str], dict | None]:
    """Fetch contract source from Etherscan-like explorer."""
    if not chain.explorer_api:
        return {}, None

    api_key = os.getenv(chain.explorer_api_key_env or "", "")
    if not api_key:
        return {}, None

    await rate_limiter.wait()

    url = f"{chain.explorer_api}?module=contract&action=getsourcecode&address={address}&apikey={api_key}"

    try:
        resp = await client.get(url, timeout=30.0)
        reason = rate_limit_reason(resp)
        if reason:
            raise RateLimited(provider=f"etherscan:{chain.name}", retry_after=retry_after_seconds(resp), detail=reason)
        if resp.status_code != 200:
            return {}, None

        data = resp.json()
        if data.get("status") != "1":
            # Etherscan V2 signals a throttle as HTTP 200 + status:"0" with "Max rate limit
            # reached"/daily-limit in message/result — classify from those SHORT fields only
            # (never SourceCode) so it is not mistaken for a genuinely-unverified contract.
            result_field = data.get("result")
            result_text = result_field if isinstance(result_field, str) else ""
            body_reason = rate_limit_reason(resp, body_text=f"{data.get('message') or ''} {result_text}")
            if body_reason:
                raise RateLimited(
                    provider=f"etherscan:{chain.name}", retry_after=retry_after_seconds(resp), detail=body_reason
                )
            return {}, None

        result = data.get("result", [])
        if not result or not isinstance(result, list):
            return {}, None

        item = result[0]
        source_code = item.get("SourceCode", "")
        contract_name = item.get("ContractName", "Contract")

        if not source_code:
            return {}, None

        sources: dict[str, str] = {}

        # Handle multi-file format (starts with {{ or {)
        if source_code.startswith("{{"):
            # Double-brace format: {{sources: {...}}}
            try:
                inner = source_code[1:-1]  # Remove outer braces
                parsed = json.loads(inner)
                for path, content in parsed.get("sources", {}).items():
                    sources[path] = content.get("content", "")
            except (json.JSONDecodeError, AttributeError, TypeError):
                sources[f"{contract_name}.sol"] = source_code
        elif source_code.startswith("{"):
            # Single-brace format: {path: {content: ...}}
            try:
                parsed = json.loads(source_code)
                for path, content in parsed.items():
                    if isinstance(content, dict):
                        sources[path] = content.get("content", "")
                    else:
                        sources[path] = str(content)
            except (json.JSONDecodeError, AttributeError, TypeError):
                sources[f"{contract_name}.sol"] = source_code
        else:
            # Plain source code
            sources[f"{contract_name}.sol"] = source_code

        metadata = {
            "ContractName": item.get("ContractName"),
            "CompilerVersion": item.get("CompilerVersion"),
            "OptimizationUsed": item.get("OptimizationUsed"),
            "Runs": item.get("Runs"),
            "EVMVersion": item.get("EVMVersion"),
        }

        return sources, metadata

    except RateLimited:
        raise  # don't fold a throttle into "no source" (which triggers decompile+register)
    except Exception as e:
        _log.warning("    Explorer error for %s: %s", address, e)
        return {}, None


# ============================================================================
# Contract Storage
# ============================================================================


def save_contract(
    chain_id: int,
    address: str,
    sources: dict[str, str],
    metadata: dict | None,
    output_dir: Path,
) -> Path:
    """Save contract sources to disk."""
    addr_lower = address.lower()
    contract_dir = output_dir / f"{chain_id}_{addr_lower}"
    contract_dir.mkdir(parents=True, exist_ok=True)

    for filename, content in sources.items():
        # Flatten path for simplicity
        safe_name = filename.replace("/", "_").replace("\\", "_")
        if safe_name.startswith("_"):
            safe_name = safe_name[1:]

        file_path = contract_dir / safe_name
        file_path.write_text(content, encoding="utf-8")

    if metadata:
        meta_path = contract_dir / "metadata.json"
        meta_path.write_text(json.dumps(metadata, indent=2), encoding="utf-8")

    return contract_dir


def compute_bytecode_hash(sources: dict[str, str]) -> str:
    """Compute hash of all source files for deduplication."""
    combined = "".join(sorted(sources.values()))
    return hashlib.sha256(combined.encode()).hexdigest()[:16]


# ============================================================================
# Main Crawler
# ============================================================================


class ContractCrawler:
    def __init__(
        self,
        output_dir: Path = Path("sources"),
        chains: list[int] | None = None,
        days_back: int = 365,
        max_per_chain: int = 5000,
        requests_per_second: float = 3.0,
        registry_path: str = ".contract_registry.db",
        concurrency: int = 30,
    ):
        self.output_dir = output_dir
        self.chain_ids = chains or [c.chain_id for c in CHAINS]
        self.min_date = datetime.now() - timedelta(days=days_back)
        self.min_timestamp = int(self.min_date.timestamp())
        self.max_per_chain = max_per_chain
        self.rate_limiter = AsyncRateLimiter(requests_per_second)
        self.registry = ContractRegistry(registry_path)
        self.concurrency = concurrency
        self.seen_hashes: set[str] = set()
        self._lock = asyncio.Lock()
        self.stats = {
            "total_fetched": 0,
            "total_saved": 0,
            "total_registered": 0,
            "duplicates_source_skipped": 0,
            "errors": 0,
            "rate_limited": 0,
            "from_sourcify": 0,
            "from_explorer": 0,
        }

    async def crawl_chain(self, chain_id: int, client: httpx.AsyncClient) -> int:
        """Crawl a single chain."""
        chain = get_chain_by_id(chain_id)
        if not chain:
            _log.error("Unknown chain ID: %s", chain_id)
            return 0

        _log.info("Crawling %s (chain_id=%s)", chain.name, chain_id)

        saved_count = 0

        # Step 1: Get verified contract addresses from Sourcify
        _log.info("Fetching verified contracts from Sourcify...")
        try:
            addresses = await fetch_sourcify_verified_contracts(chain_id, client, self.rate_limiter, self.min_date)
        except RateLimited as e:
            # Listing was throttled -> the set is incomplete. Skip this chain for THIS run (don't
            # crawl a truncated list as if complete); a later run resumes. Not a poison, a deferral.
            _log.warning("  Sourcify listing rate-limited for %s (%s); skipping chain this run, retry later", chain.name, e.reason)
            self.stats["rate_limited"] = self.stats.get("rate_limited", 0) + 1
            return 0
        _log.info("Found %d verified contracts on Sourcify", len(addresses))

        # Limit per chain
        addresses = addresses[: self.max_per_chain]

        # Resume + multi-process safety: atomically claim each address by
        # inserting a placeholder row. Anything we don't claim is either
        # already fully registered or being crawled by another worker.
        original_count = len(addresses)
        addresses = self.registry.claim_addresses_for_crawl(chain_id, addresses)
        skipped = original_count - len(addresses)
        if skipped > 0:
            _log.info("  Resume: skipped %d addresses already crawled or claimed by another worker", skipped)

        if not addresses:
            _log.info("  All contracts already crawled!")
            return 0

        # Step 2: Fetch source code in parallel with semaphore
        _log.info("Fetching %d contracts (concurrency=%d)...", len(addresses), self.concurrency)
        semaphore = asyncio.Semaphore(self.concurrency)

        async def fetch_one(addr: str) -> tuple[str, dict[str, str], dict | None, str]:
            async with semaphore:
                # Try Sourcify first
                sources, metadata = await fetch_sourcify_source(chain_id, addr, client, self.rate_limiter)
                source_origin = "sourcify"
                # Fallback to Explorer
                if not sources and chain.explorer_api:
                    sources, metadata = await fetch_explorer_source(chain, addr, client, self.rate_limiter)
                    source_origin = "explorer"
                return addr, sources, metadata, source_origin

        # Parallel fetch all contracts
        results = await asyncio.gather(*[fetch_one(addr) for addr in addresses], return_exceptions=True)

        # Process results
        for i, result in enumerate(results):
            if i > 0 and i % 100 == 0:
                _log.info("  Progress: %d/%d (%d saved)", i, len(addresses), saved_count)

            if isinstance(result, BaseException):
                async with self._lock:
                    # A throttled fetch is skipped (never registered -> no poison), but counted
                    # distinctly from a genuine error so the operator sees the chain is incomplete.
                    if isinstance(result, RateLimited):
                        self.stats["rate_limited"] = self.stats.get("rate_limited", 0) + 1
                    else:
                        self.stats["errors"] += 1
                continue

            addr, sources, metadata, source_origin = result

            if not sources:
                async with self._lock:
                    self.stats["errors"] += 1
                continue

            async with self._lock:
                self.stats["total_fetched"] += 1
                if source_origin == "sourcify":
                    self.stats["from_sourcify"] += 1
                else:
                    self.stats["from_explorer"] += 1

            # Get metadata info
            contract_name = None
            compiler_version = None
            if metadata:
                contract_name = metadata.get("ContractName")
                compiler_version = metadata.get("CompilerVersion")

            # Register in registry (stores hash → address mapping)
            src_hash = self.registry.register_contract(
                chain_id=chain_id,
                address=addr,
                sources=sources,
                contract_name=contract_name,
                compiler_version=compiler_version,
            )

            async with self._lock:
                self.stats["total_registered"] += 1

                # Only save source files if hash is new (dedupe disk storage)
                if src_hash in self.seen_hashes:
                    self.stats["duplicates_source_skipped"] += 1
                    continue
                self.seen_hashes.add(src_hash)

            # Save source files to disk
            try:
                save_contract(chain_id, addr, sources, metadata, self.output_dir)
                async with self._lock:
                    saved_count += 1
                    self.stats["total_saved"] += 1
            except Exception as e:
                _log.warning("    Error saving %s: %s", addr, e)
                async with self._lock:
                    self.stats["errors"] += 1

        _log.info("%s: Saved %d unique contracts", chain.name, saved_count)
        return saved_count

    async def crawl_all(self) -> dict:
        """Crawl all configured chains."""
        self.output_dir.mkdir(parents=True, exist_ok=True)

        print("Contract Crawler")
        print("================")
        print(f"Output: {self.output_dir}")
        print(f"Chains: {self.chain_ids}")
        print(f"Date range: {self.min_date.date()} to now")
        print(f"Max per chain: {self.max_per_chain}")
        print(f"Concurrency: {self.concurrency}")

        async with scryer_http.async_client() as client:
            # Parallel chain crawling
            tasks = [self.crawl_chain(chain_id, client) for chain_id in self.chain_ids]
            await asyncio.gather(*tasks, return_exceptions=True)

        print(f"\n{'=' * 60}")
        print("Crawl Complete!")
        print(f"{'=' * 60}")
        print(f"Total fetched: {self.stats['total_fetched']}")
        print(f"  - From Sourcify: {self.stats['from_sourcify']}")
        print(f"  - From Explorer: {self.stats['from_explorer']}")
        print(f"Total registered: {self.stats['total_registered']}")
        print(f"Total saved (unique): {self.stats['total_saved']}")
        print(f"Duplicates (source skipped): {self.stats['duplicates_source_skipped']}")
        print(f"Errors: {self.stats['errors']}")
        print(f"Rate-limited (skipped, retry later): {self.stats.get('rate_limited', 0)}")
        print(f"\nRegistry stats: {self.registry.stats()}")

        return self.stats


# ============================================================================
# CLI
# ============================================================================


async def main_async():
    import argparse

    parser = argparse.ArgumentParser(description="Multi-chain Contract Crawler")
    parser.add_argument("--output-dir", default="sources", help="Output directory")
    parser.add_argument("--chains", type=str, default="", help="Comma-separated chain IDs (default: all)")
    parser.add_argument("--days", type=int, default=365, help="Days back to fetch (default: 365)")
    parser.add_argument("--max-per-chain", type=int, default=5000, help="Max contracts per chain")
    parser.add_argument("--rps", type=float, default=3.0, help="Requests per second")
    parser.add_argument("--concurrency", type=int, default=10, help="Parallel fetch concurrency")
    parser.add_argument(
        "--sources",
        type=str,
        default="sourcify,blockscout,explorer",
        help="Data sources (comma-separated): sourcify,blockscout,explorer,bigquery",
    )

    args = parser.parse_args()

    chain_ids = None
    if args.chains:
        chain_ids = [int(x.strip()) for x in args.chains.split(",")]

    sources = [s.strip() for s in args.sources.split(",")]

    crawler = ContractCrawler(
        output_dir=Path(args.output_dir),
        chains=chain_ids,
        days_back=args.days,
        max_per_chain=args.max_per_chain,
        requests_per_second=args.rps,
        concurrency=args.concurrency,
    )

    # Use multi-source if requested
    if "blockscout" in sources or "bigquery" in sources:
        from data_sources import MultiSourceCrawler

        crawler.multi_source = MultiSourceCrawler(sources=sources)

    await crawler.crawl_all()


def main():
    asyncio.run(main_async())


if __name__ == "__main__":
    main()
