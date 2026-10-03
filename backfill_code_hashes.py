#!/usr/bin/env python3
"""Bulk-backfill bytecode fingerprints for contracts already in the registry.

Opportunistic backfill (in get_state / bytecode_abi / registry_clones) fills the clone index
with the contracts you actually touch, for free. This fills it in bulk so an unverified
contract can be matched against the whole corpus from day one.

Safe to interrupt and re-run: it only looks at rows that have no fingerprint yet, so progress
is never lost and nothing is recomputed. Addresses with no code are recorded with code_size=0
so they are not retried forever. A provider throttle stops the run cleanly (resume later)
rather than hammering.

    python backfill_code_hashes.py --chain 56 --limit 2000
    python backfill_code_hashes.py --limit 500 --sleep 0.05      # all chains, gentler
"""

from __future__ import annotations

import argparse
import sys
import time

from web3 import Web3

from bytecode_abi import code_fingerprints
from contract_registry import ContractRegistry
from etherscan_proxy_provider import make_web3
from scryer_http import rpc_rate_limit_reason
from scryer_logging import get_logger

_log = get_logger(__name__)


def backfill(
    *,
    chain_id: int | None = None,
    limit: int = 1000,
    batch: int = 500,
    sleep_s: float = 0.0,
    db_path: str = ".contract_registry.db",
) -> dict:
    reg = ContractRegistry(db_path)
    stats = {"fingerprinted": 0, "no_code": 0, "failed": 0, "rate_limited": False, "dead_chains": []}
    w3_cache: dict[int, object] = {}
    dead_chains: set[int] = set()

    while stats["fingerprinted"] + stats["no_code"] + stats["failed"] < limit:
        remaining = limit - stats["fingerprinted"] - stats["no_code"] - stats["failed"]
        # Exclude chains already found unreachable this run: their rows will never fingerprint, and
        # since the work list is ordered by chain_id, leaving them in would make every pass re-serve
        # the same dead rows and never reach chains that sort after them (starvation).
        todo = reg.addresses_missing_fingerprints(chain_id, min(batch, remaining), exclude_chains=dead_chains)
        if not todo:
            break

        new_dead = False
        for cid, addr in todo:
            if cid in dead_chains:
                continue
            if cid not in w3_cache:
                try:
                    w3_cache[cid], _label = make_web3(cid)
                except Exception as e:
                    _log.warning("chain %s unreachable (%s); excluding it this run", cid, e)
                    w3_cache[cid] = None
            w3 = w3_cache[cid]
            if w3 is None:
                # Don't burn the limit budget on a dead chain's rows — mark it and re-query the
                # work list with it excluded (the remaining rows in this batch may be other chains).
                dead_chains.add(cid)
                stats["dead_chains"] = sorted(dead_chains)
                new_dead = True
                break

            try:
                code = bytes(w3.eth.get_code(Web3.to_checksum_address(addr)))
            except Exception as e:
                reason = rpc_rate_limit_reason(e)
                if reason:
                    # Stop cleanly: the run is resumable, so backing off beats hammering.
                    _log.warning("rate-limited on chain %s (%s) — stopping; re-run to resume", cid, reason)
                    stats["rate_limited"] = True
                    return stats
                _log.debug("get_code failed for %s/%s: %s", cid, addr, e)
                stats["failed"] += 1
                continue

            if code:
                reg.record_code_fingerprints(cid, addr, code_fingerprints(code.hex()))
                stats["fingerprinted"] += 1
            else:
                # Record a marker so resume does not retry an EOA/self-destructed address forever.
                reg.record_code_fingerprints(cid, addr, {"code_size": 0})
                stats["no_code"] += 1

            done = stats["fingerprinted"] + stats["no_code"] + stats["failed"]
            if done % 100 == 0:
                _log.info("… %d processed (%d fingerprinted, %d no-code, %d failed)",
                          done, stats["fingerprinted"], stats["no_code"], stats["failed"])
            if sleep_s:
                time.sleep(sleep_s)

        if new_dead:
            # A chain was just marked dead mid-batch; re-query so its remaining rows are skipped.
            continue

    return stats


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--chain", type=int, default=None, help="only this chain_id (default: all)")
    p.add_argument("--limit", type=int, default=1000, help="max addresses to process this run")
    p.add_argument("--batch", type=int, default=500, help="rows fetched from the registry per pass")
    p.add_argument("--sleep", type=float, default=0.0, help="extra seconds between RPC calls")
    p.add_argument("--db", default=".contract_registry.db")
    args = p.parse_args()

    stats = backfill(
        chain_id=args.chain, limit=args.limit, batch=args.batch, sleep_s=args.sleep, db_path=args.db
    )
    print(
        f"fingerprinted={stats['fingerprinted']} no_code={stats['no_code']} "
        f"failed={stats['failed']} rate_limited={stats['rate_limited']} "
        f"dead_chains={stats['dead_chains']}"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
