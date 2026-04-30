"""
RPC-Based Contract Discovery System.
Discovers contracts from blockchain RPC, retrieves source from Sourcify/Explorer,
with decompilation fallback for unverified contracts.
"""
from __future__ import annotations

import asyncio
import os
import time
from dataclasses import dataclass
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any

import httpx
from dotenv import load_dotenv

from contract_crawler import (
    CHAINS,
    ChainConfig,
    AsyncRateLimiter,
    fetch_sourcify_source,
    fetch_explorer_source,
    save_contract,
    get_chain_by_id,
)
from contract_registry import ContractRegistry
from decompilers import decompile_bytecode

load_dotenv()


# ============================================================================
# RPC Configuration
# ============================================================================


@dataclass
class RPCConfig:
    chain_id: int
    name: str
    rpc_urls: list[str]
    block_time_seconds: float  # Average block time
    blocks_per_day: int


def get_rpc_configs() -> list[RPCConfig]:
    """Get RPC configurations from environment."""
    configs = []
    
    import re
    # BSC
    bsc_env = os.getenv("BSC_URL") or os.getenv("RPC_URL", "https://bsc-dataseed.binance.org")
    bsc_urls = [url.strip() for url in re.split(r'[,\s]+', bsc_env) if url.strip()]
    
    configs.append(RPCConfig(
        chain_id=56,
        name="bsc",
        rpc_urls=bsc_urls,
        block_time_seconds=3.0,
        blocks_per_day=28800,
    ))
    
    # Polygon
    polygon_env = os.getenv("POLYGON_URL")
    if polygon_env:
        polygon_urls = [url.strip() for url in polygon_env.split(",") if url.strip()]
        configs.append(RPCConfig(
            chain_id=137,
            name="polygon",
            rpc_urls=polygon_urls,
            block_time_seconds=2.0,
            blocks_per_day=43200,
        ))
    
    # Arbitrum
    arb_env = os.getenv("ARB_URL")
    if arb_env:
        arb_urls = [url.strip() for url in arb_env.split(",") if url.strip()]
        configs.append(RPCConfig(
            chain_id=42161,
            name="arbitrum",
            rpc_urls=arb_urls,
            block_time_seconds=0.25,
            blocks_per_day=345600,
        ))
    
    return configs


# ============================================================================
# Block Scanner
# ============================================================================

class BlockScanner:
    """Scan blockchain blocks for contract creation transactions."""
    
    def __init__(
        self,
        rpc_config: RPCConfig,
        rate_limiter: AsyncRateLimiter | None = None,
    ):
        self.config = rpc_config
        self.rate_limiter = rate_limiter or AsyncRateLimiter(requests_per_second=50.0)
        self._rpc_index = 0
        self.use_proxy = False
        self.proxy_client = None
        self._proxy_lock = asyncio.Lock()
        
    def get_rpc_url(self) -> str:
        """Get next RPC URL (Round-Robin)."""
        if not self.config.rpc_urls:
            raise ValueError(f"No RPC URLs configured for {self.config.name}")
        
        url = self.config.rpc_urls[self._rpc_index]
        self._rpc_index = (self._rpc_index + 1) % len(self.config.rpc_urls)
        return url
    
    async def _get_proxy_client(self, socks_proxy: str) -> httpx.AsyncClient | None:
        """Get or create a proxy client."""
        if self.proxy_client:
            return self.proxy_client
            
        async with self._proxy_lock:
            # Check again after acquiring lock
            if self.proxy_client:
                return self.proxy_client
                
            try:
                import httpx_socks
                print(f"  🔄 Creating SOCKS proxy client: {socks_proxy}")
                self.proxy_client = httpx.AsyncClient(
                    transport=httpx_socks.AsyncProxyTransport.from_url(socks_proxy)
                )
                return self.proxy_client
            except ImportError:
                print("  ⚠️ httpx_socks not installed. Run: pip install httpx-socks")
                return None
            except Exception as e:
                print(f"  ⚠️ Failed to create proxy client: {e}")
                return None

    async def _make_request(self, client: httpx.AsyncClient, method: str, params: list[Any]) -> Any:
        """Make RPC request with rate limit handling and retries."""
        retries = 3
        base_delay = 10.0
        
        # Get SOCKS proxy from environment
        socks_proxy = os.getenv("SOCKS_PROXY") or os.getenv("socks_proxy")
        
        for attempt in range(retries):
            await self.rate_limiter.wait()
            url = self.get_rpc_url()
            
            # Choose which client to use based on persistent state
            current_client = client
            using_proxy = False
            
            if self.use_proxy and socks_proxy:
                p_client = await self._get_proxy_client(socks_proxy)
                if p_client:
                    current_client = p_client
                    using_proxy = True
                else:
                    # Failed to get proxy client, fallback to direct
                    self.use_proxy = False
            
            try:
                resp = await current_client.post(
                    url,
                    json={
                        "jsonrpc": "2.0",
                        "method": method,
                        "params": params,
                        "id": 1,
                    },
                    timeout=30.0,
                )
                
                if resp.status_code == 429:
                    delay = base_delay * (2 ** attempt)
                    
                    if socks_proxy:
                        if not using_proxy:
                            # We failed on direct connection
                            if not self.use_proxy:
                                # Only switch if not already switched by someone else
                                print(f"  Rate limit (429) on {url}. Switching to SOCKS proxy...")
                                self.use_proxy = True
                            else:
                                # Already switched, just retry
                                pass
                            continue
                        else:
                            # We failed on proxy connection
                            if self.use_proxy:
                                # Only switch back if not already switched back
                                print(f"  ❌ Proxy request failed with 429 on {url}. Switching back to direct IP...")
                                self.use_proxy = False
                            else:
                                # Already switched back, just retry
                                pass
                                
                            print(f"  Retrying in {delay}s...")
                            await asyncio.sleep(delay)
                            continue
                    else:
                        print(f"  Rate limit exceeded (429) on {url}. Retrying in {delay}s...")
                        await asyncio.sleep(delay)
                        continue
                
                if resp.status_code != 200:
                    msg = f"HTTP {resp.status_code}"
                    if using_proxy:
                        print(f"  ❌ Proxy request failed: {msg}")
                    else:
                        print(f"  RPC Error on {url}: {msg}")
                    return None
                    
                data = resp.json()
                if "error" in data:
                    err_msg = data['error'].get('message')
                    if using_proxy:
                        print(f"  ❌ Proxy request returned RPC error: {err_msg}")
                    else:
                        print(f"  RPC Error on {url}: {err_msg}")
                    return None
                
                # Log if using proxy successfully (verbose)
                # if using_proxy:
                #    print(f"  ✅ Proxy request successful")
                    
                return data.get("result")
                
            except httpx.RequestError as e:
                if using_proxy:
                    print(f"  ❌ Proxy connection error: {e}")
                    # If proxy fails, maybe switch back to direct?
                    # For now, just retry
                else:
                    print(f"  Request error on {url}: {e}")
                    
                if attempt < retries - 1:
                    await asyncio.sleep(1)
                continue
                
        print("  Max retries exceeded")
        return None

    async def get_latest_block(self, client: httpx.AsyncClient) -> int:
        """Get the latest block number."""
        result = await self._make_request(client, "eth_blockNumber", [])
        if result:
            return int(result, 16)
        raise Exception("Failed to get latest block")
    
    async def get_block_with_receipts(
        self,
        block_number: int,
        client: httpx.AsyncClient,
    ) -> list[str]:
        """Get contract addresses created in a block."""
        # Get block with transactions
        block_data = await self._make_request(client, "eth_getBlockByNumber", [hex(block_number), True])
        
        if not block_data:
            return []
        
        # Find contract creation transactions (to == null)
        contract_creations = []
        for tx in block_data.get("transactions", []):
            if tx.get("to") is None:
                # This is a contract creation transaction
                tx_hash = tx.get("hash")
                if tx_hash:
                    contract_creations.append(tx_hash)
        
        if not contract_creations:
            return []
        
        # Get receipts to find created contract addresses
        contracts = []
        for tx_hash in contract_creations:
            receipt = await self._make_request(client, "eth_getTransactionReceipt", [tx_hash])
            
            if receipt and receipt.get("status") == "0x1":
                contract_address = receipt.get("contractAddress")
                if contract_address:
                    contracts.append(contract_address.lower())
        
        return contracts
    
    async def scan_blocks(
        self,
        from_block: int,
        to_block: int,
        client: httpx.AsyncClient,
        progress_callback: callable | None = None,
        concurrency: int = 10,
        queue: asyncio.Queue | None = None,
        stop_event: asyncio.Event | None = None,
        limit: int | None = None,
    ) -> list[str]:
        """Scan a range of blocks for contract creations concurrently."""
        all_contracts = []
        total_blocks = to_block - from_block + 1
        blocks_processed = 0
        contracts_found = 0
        
        semaphore = asyncio.Semaphore(concurrency)
        
        async def scan_one(block_num: int) -> list[str]:
            nonlocal blocks_processed, contracts_found
            
            # Check stop event
            if stop_event and stop_event.is_set():
                return []
                
            async with semaphore:
                # Check again after acquiring semaphore
                if stop_event and stop_event.is_set():
                    return []
                
                # Check limit
                if limit and contracts_found >= limit:
                    if stop_event and not stop_event.is_set():
                        stop_event.set()
                    return []
                    
                try:
                    contracts = await self.get_block_with_receipts(block_num, client)
                    
                    # Update stats safely (running in single thread event loop)
                    blocks_processed += 1
                    contracts_found += len(contracts)
                    
                    if contracts and queue:
                        for contract in contracts:
                            await queue.put(contract)
                            
                    # Check limit after finding
                    if limit and contracts_found >= limit:
                        if stop_event and not stop_event.is_set():
                            stop_event.set()
                    
                    if progress_callback and blocks_processed % 10 == 0:
                        progress_callback(blocks_processed, total_blocks, contracts_found)
                        
                    return contracts
                except Exception as e:
                    # Error is already logged in _make_request usually, but catch top level here
                    # print(f"  Error scanning block {block_num}: {e}")
                    blocks_processed += 1
                    return []

        # Create tasks for all blocks
        tasks = [scan_one(b) for b in range(from_block, to_block + 1)]
        
        # Run concurrently
        results = await asyncio.gather(*tasks)
        
        # Flatten results
        for res in results:
            all_contracts.extend(res)
            
        return all_contracts
    
    async def get_bytecode(self, address: str, client: httpx.AsyncClient) -> str:
        """Get contract bytecode using eth_getCode."""
        await self.rate_limiter.wait()
        
        resp = await client.post(
            self.get_rpc_url(),
            json={
                "jsonrpc": "2.0",
                "method": "eth_getCode",
                "params": [address, "latest"],
                "id": 1,
            },
            timeout=30.0,
        )
        
        result = resp.json().get("result", "0x")
        return result if result != "0x" else ""
    
    async def close(self):
        """Close any open connections (e.g., proxy client)."""
        if self.proxy_client:
            try:
                await self.proxy_client.aclose()
            except Exception:
                pass
            self.proxy_client = None


# ============================================================================
# Contract Discovery Pipeline
# ============================================================================

class ContractDiscovery:
    """Main discovery pipeline: RPC -> Sourcify -> Explorer -> Decompile."""
    
    def __init__(
        self,
        output_dir: Path = Path("sources"),
        registry_path: str = ".contract_registry.db",
        days_back: int = 30,
        concurrency: int = 30,
        rpc_rate_limit: float = 50.0,
        api_rate_limit: float = 5.0,
    ):
        self.output_dir = output_dir
        self.days_back = days_back
        self.concurrency = concurrency
        self.registry = ContractRegistry(registry_path)
        self.rpc_rate_limiter = AsyncRateLimiter(rpc_rate_limit)
        self.api_rate_limiter = AsyncRateLimiter(api_rate_limit)
        
        self.stats = {
            "blocks_scanned": 0,
            "contracts_discovered": 0,
            "from_sourcify": 0,
            "from_explorer": 0,
            "decompiled": 0,
            "already_crawled": 0,
            "errors": 0,
        }
    
    async def discover_chain(
        self,
        rpc_config: RPCConfig,
        client: httpx.AsyncClient,
        limit: int | None = None,
        dry_run: bool = False,
    ) -> int:
        """Discover contracts on a single chain."""
        chain = get_chain_by_id(rpc_config.chain_id)
        if not chain:
            print(f"Unknown chain ID: {rpc_config.chain_id}")
            return 0
        
        print(f"\n{'='*60}")
        print(f"Discovering contracts on {rpc_config.name} (chain_id={rpc_config.chain_id})")
        print(f"RPC Nodes ({len(rpc_config.rpc_urls)}):")
        for url in rpc_config.rpc_urls:
            print(f"  - {url}")
        print(f"{'='*60}")
        
        scanner = BlockScanner(rpc_config, self.rpc_rate_limiter)
        
        # Calculate block range
        latest_block = await scanner.get_latest_block(client)
        blocks_to_scan = self.days_back * rpc_config.blocks_per_day
        from_block = max(1, latest_block - blocks_to_scan)
        
        # Check for already scanned blocks
        unscanned_ranges = self.registry.get_unscanned_ranges(
            rpc_config.chain_id, from_block, latest_block
        )
        
        if not unscanned_ranges:
            print(f"All blocks {from_block:,} to {latest_block:,} already scanned. Skipping.")
            return 0
        
        # Calculate how many blocks we're skipping
        total_requested = latest_block - from_block + 1
        total_unscanned = sum(end - start + 1 for start, end in unscanned_ranges)
        skipped = total_requested - total_unscanned
        
        if skipped > 0:
            print(f"Skipping {skipped:,} already scanned blocks")
        
        print(f"Scanning {len(unscanned_ranges)} range(s), {total_unscanned:,} blocks total:")
        for start, end in unscanned_ranges:
            print(f"  - Blocks {start:,} to {end:,} ({end - start + 1:,} blocks)")
        
        # Queue for streaming contracts
        queue = asyncio.Queue()
        stop_event = asyncio.Event()
        
        # Progress callback
        def progress(current, total, found):
            print(f"  Progress: {current:,}/{total:,} blocks, {found} contracts found", end="\r")
        
        # Start consumer workers
        workers = []
        if not dry_run:
            for _ in range(self.concurrency):
                worker = asyncio.create_task(self._worker(queue, chain, rpc_config, scanner, client, limit, stop_event))
                workers.append(worker)
        
        # Scan each unscanned range
        all_contracts = []
        for range_from, range_to in unscanned_ranges:
            print(f"\nScanning blocks {range_from:,} to {range_to:,}...")
            
            # Start producer (scanner)
            contracts = await scanner.scan_blocks(
                range_from, range_to, client, progress, self.concurrency, 
                queue if not dry_run else None, stop_event, limit
            )
            print()  # New line after progress
            
            all_contracts.extend(contracts)
            
            # Record this range as scanned
            if not dry_run:
                self.registry.record_scanned_blocks(
                    rpc_config.chain_id, range_from, range_to, len(contracts)
                )
            
            self.stats["blocks_scanned"] += range_to - range_from + 1
        
        self.stats["contracts_discovered"] += len(all_contracts)
        
        print(f"Found {len(all_contracts)} contract creations")
        
        if dry_run:
            print("Dry run - skipping source retrieval")
            for addr in all_contracts[:10]:
                print(f"  - {addr}")
            if len(all_contracts) > 10:
                print(f"  ... and {len(all_contracts) - 10} more")
            return len(all_contracts)
        
        # Wait for queue to be processed
        await queue.join()
        
        # Cancel workers
        for w in workers:
            w.cancel()
            
        await scanner.close()
            
        print(f"\n{rpc_config.name}: Processing complete")
        return len(all_contracts)

    async def _worker(
        self,
        queue: asyncio.Queue,
        chain: ChainConfig,
        rpc_config: RPCConfig,
        scanner: BlockScanner,
        client: httpx.AsyncClient,
        limit: int | None,
        stop_event: asyncio.Event | None = None,
    ):
        """Worker to process contracts from queue."""
        
        while True:
            # Check stop event
            if stop_event and stop_event.is_set() and queue.empty():
                break
                
            try:
                address = await queue.get()
            except asyncio.CancelledError:
                break
            
            try:
                # Check global limit
                if limit and self.stats.get("contracts_saved", 0) >= limit:
                    if stop_event and not stop_event.is_set():
                        print(f"\nLimit of {limit} contracts reached. Stopping scan...")
                        stop_event.set()
                    continue
                
                # Filter already crawled
                if self.registry.exists_contract(rpc_config.chain_id, address):
                    self.stats["already_crawled"] += 1
                    continue
                
                # Process contract
                success = await self._process_contract(chain, rpc_config, address, scanner, client)
                if success:
                    self.stats["contracts_saved"] = self.stats.get("contracts_saved", 0) + 1
                
                # Check limit again after processing
                if limit and self.stats.get("contracts_saved", 0) >= limit:
                    if stop_event and not stop_event.is_set():
                        print(f"\nLimit of {limit} contracts reached. Stopping scan...")
                        stop_event.set()
                
            except Exception as e:
                print(f"  Worker error: {e}")
                self.stats["errors"] += 1
            finally:
                queue.task_done()
    
    async def _process_contract(
        self,
        chain: ChainConfig,
        rpc_config: RPCConfig,
        address: str,
        scanner: BlockScanner,
        client: httpx.AsyncClient,
    ) -> bool:
        """Process a single contract: try Sourcify -> Explorer -> Decompile."""
        
        # Try Sourcify first
        sources, metadata = await fetch_sourcify_source(
            rpc_config.chain_id, address, client, self.api_rate_limiter
        )
        source_origin = "sourcify"
        
        # Fallback to Explorer
        if not sources and chain.explorer_api:
            sources, metadata = await fetch_explorer_source(
                chain, address, client, self.api_rate_limiter
            )
            source_origin = "explorer"
        
        # Fallback to decompilation
        if not sources:
            bytecode = await scanner.get_bytecode(address, client)
            if bytecode:
                # Try to decompile
                # Run in thread to avoid blocking event loop with subprocess
                decompiled = await asyncio.to_thread(decompile_bytecode, bytecode)
                if decompiled:
                    sources = {"Contract_DECOMPILED.sol": decompiled}
                    metadata = {
                        "decompiled": True,
                        "ContractName": "Decompiled",
                    }
                else:
                    # Save raw bytecode if decompilation fails
                    sources = {"bytecode.txt": bytecode}
                    metadata = {"needs_decompilation": True}
                source_origin = "decompiled"
                self.stats["decompiled"] += 1
            else:
                self.stats["errors"] += 1
                return False
        
        # Update stats
        if source_origin == "sourcify":
            self.stats["from_sourcify"] += 1
        elif source_origin == "explorer":
            self.stats["from_explorer"] += 1
        # decompiled is already counted above
        
        # Get contract name
        contract_name = None
        compiler_version = None
        if metadata and not metadata.get("needs_decompilation"):
            contract_name = metadata.get("ContractName")
            compiler_version = metadata.get("CompilerVersion")
        
        # Register in registry
        self.registry.register_contract(
            chain_id=rpc_config.chain_id,
            address=address,
            sources=sources,
            contract_name=contract_name,
            compiler_version=compiler_version,
        )
        
        # Save to disk
        try:
            save_contract(rpc_config.chain_id, address, sources, metadata, self.output_dir)
            return True
        except Exception as e:
            print(f"  Error saving {address}: {e}")
            self.stats["errors"] += 1
            return False
    
    async def discover_all(
        self,
        chain_ids: list[int] | None = None,
        limit: int | None = None,
        dry_run: bool = False,
    ) -> dict:
        """Discover contracts on all configured chains."""
        self.output_dir.mkdir(parents=True, exist_ok=True)
        
        rpc_configs = get_rpc_configs()
        if chain_ids:
            rpc_configs = [c for c in rpc_configs if c.chain_id in chain_ids]
        
        print(f"RPC Contract Discovery")
        print(f"======================")
        print(f"Output: {self.output_dir}")
        print(f"Chains: {[c.name for c in rpc_configs]}")
        print(f"Days back: {self.days_back}")
        print(f"Concurrency: {self.concurrency}")
        
        async with httpx.AsyncClient() as client:
            for config in rpc_configs:
                try:
                    await self.discover_chain(config, client, limit, dry_run)
                except Exception as e:
                    print(f"Error on {config.name}: {e}")
                    self.stats["errors"] += 1
        
        print(f"\n{'='*60}")
        print(f"Discovery Complete!")
        print(f"{'='*60}")
        print(f"Blocks scanned: {self.stats['blocks_scanned']:,}")
        print(f"Contracts discovered: {self.stats['contracts_discovered']}")
        print(f"  - From Sourcify: {self.stats['from_sourcify']}")
        print(f"  - From Explorer: {self.stats['from_explorer']}")
        print(f"  - Bytecode only: {self.stats['decompiled']}")
        print(f"Already crawled: {self.stats['already_crawled']}")
        print(f"Errors: {self.stats['errors']}")
        
        return self.stats


# ============================================================================
# CLI
# ============================================================================

async def main_async():
    import argparse
    
    parser = argparse.ArgumentParser(description="RPC-Based Contract Discovery")
    parser.add_argument("--output-dir", default="sources", help="Output directory")
    parser.add_argument("--chain", type=int, default=56, help="Chain ID (default: 56 for BSC)")
    parser.add_argument("--days", type=int, default=30, help="Days back to scan (default: 30)")
    parser.add_argument("--limit", type=int, default=None, help="Limit contracts to process")
    parser.add_argument("--dry-run", action="store_true", help="Only scan, don't fetch sources")
    parser.add_argument("--concurrency", type=int, default=30, help="Parallel processing")
    parser.add_argument("--rpc-rps", type=float, default=50.0, help="RPC requests per second")
    parser.add_argument("--api-rps", type=float, default=5.0, help="API requests per second")
    parser.add_argument("--decompile", type=str, help="Decompile a specific contract address")
    
    args = parser.parse_args()
    
    # Single contract processing mode
    if args.decompile:
        address = args.decompile
        print(f"Processing contract {address} on chain {args.chain}...")
        
        discovery = ContractDiscovery(
            output_dir=Path(args.output_dir),
            days_back=args.days,
            concurrency=1,
            rpc_rate_limit=args.rpc_rps,
            api_rate_limit=args.api_rps,
        )
        
        # Setup client and scanner
        rpc_configs = get_rpc_configs()
        rpc_config = next((c for c in rpc_configs if c.chain_id == args.chain), None)
        
        if not rpc_config:
            print(f"Error: Chain {args.chain} not found in configuration")
            return
            
        scanner = BlockScanner(rpc_config)
        chain_config = next((c for c in CHAINS if c.chain_id == args.chain), None)
        if not chain_config:
             # Fallback if not in CHAINS (shouldn't happen for BSC)
             from contract_crawler import ChainConfig
             chain_config = ChainConfig(args.chain, "unknown", None, None)

        async with httpx.AsyncClient() as client:
            print("Fetching and processing...")
            success = await discovery._process_contract(chain_config, rpc_config, address, scanner, client)
            
            if success:
                print("\n" + "="*60)
                print("SUCCESS: Contract processed and registered!")
                print("="*60 + "\n")
                # Print the saved location
                save_path = discovery.output_dir / rpc_config.name / address
                print(f"Saved to: {save_path}")
            else:
                print("Failed to process contract.")
        return

    discovery = ContractDiscovery(
        output_dir=Path(args.output_dir),
        days_back=args.days,
        concurrency=args.concurrency,
        rpc_rate_limit=args.rpc_rps,
        api_rate_limit=args.api_rps,
    )
    
    await discovery.discover_all(
        chain_ids=[args.chain],
        limit=args.limit,
        dry_run=args.dry_run,
    )


def main():
    import signal
    import sys
    
    # Windows-specific: ensure Ctrl+C works properly
    if sys.platform == "win32":
        # This helps with Ctrl+C on Windows
        signal.signal(signal.SIGINT, signal.SIG_DFL)
    
    try:
        asyncio.run(main_async())
    except KeyboardInterrupt:
        print("\n\n⚠️  Interrupted by user (Ctrl+C). Shutting down...")
        sys.exit(0)


if __name__ == "__main__":
    main()
