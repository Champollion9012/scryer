"""Chain-data layer for Scryer: transactions, logs, fund flow, and deployer resolution.

Scryer already reads verified source, live/historical state (``call_view``/``get_state``/
``read_storage``) and the clone registry. What it lacked was the *chain-activity* layer that a
real investigation needs: decode a transaction's token movements, pull an address's logs over an
arbitrary block range, trace who funded an address, and resolve a contract's deployer. Without it
the user hand-rolls raw-RPC scripts. This module adds that layer natively.

Provider routing
----------------
Transactions, logs, fund flow and creation are read ONLY through a chain's native RPC
(``scryer_config.get_rpc_url``). Etherscan V2's free tier serves only ``getsourcecode`` on
non-Ethereum chains — proxy/account/logs/getcontractcreation are paywalled — so routing these
through Etherscan would simply fail on BSC/L2s. When a chain has no native RPC configured these
tools return a clear error rather than a wrong or empty answer; Etherscan stays source-only.

Design
------
Reuses the shared primitives rather than a second RPC stack: ``scryer_config.get_rpc_url`` for
endpoint resolution (same resolver ``make_web3`` uses), ``scryer_http.async_client`` for transport,
and the ``scryer_http`` rate-limit classifiers so a throttle is surfaced, never swallowed into an
empty result. Fan-out (chunked ``eth_getLogs``, batch ``eth_call``) uses ``asyncio.gather`` under an
explicit concurrency cap. Public coroutines are async; ``run()`` executes one from sync code.
"""

from __future__ import annotations

import asyncio
import re
from collections.abc import Sequence
from typing import Any

import httpx
from web3 import Web3

import scryer_config
from scryer_http import (
    RateLimited,
    async_client,
    rate_limit_reason,
    redact_rpc_url,
    retry_after_seconds,
    rpc_rate_limit_reason,
)
from scryer_logging import get_logger

_log = get_logger(__name__)


# --------------------------------------------------------------------------- #
# Tunables (env-overridable)
# --------------------------------------------------------------------------- #
def _concurrency() -> int:
    return scryer_config.get_int("SCRYER_RPC_CONCURRENCY", 8) or 8


def _logs_chunk() -> int:
    # Alchemy's free tier serves at most 10 blocks per eth_getLogs; default to that so the common
    # endpoint works out of the box. A permissive node can raise it via SCRYER_LOGS_CHUNK.
    return scryer_config.get_int("SCRYER_LOGS_CHUNK", 10) or 10


# --------------------------------------------------------------------------- #
# Event signatures (topic0) we decode
# --------------------------------------------------------------------------- #
def _topic(sig: str) -> str:
    return "0x" + bytes(Web3.keccak(text=sig)).hex()


TRANSFER_TOPIC = _topic("Transfer(address,address,uint256)")
SWAP_TOPIC = _topic("Swap(address,uint256,uint256,uint256,uint256,address)")
SYNC_TOPIC = _topic("Sync(uint112,uint112)")
DEPOSIT_TOPIC = _topic("Deposit(address,uint256)")  # WETH/WBNB wrap
WITHDRAWAL_TOPIC = _topic("Withdrawal(address,uint256)")  # WETH/WBNB unwrap
ZERO_TOPIC = "0x" + "0" * 64


# --------------------------------------------------------------------------- #
# JSON-RPC core
# --------------------------------------------------------------------------- #
class RpcError(Exception):
    """A JSON-RPC error that is NOT a throttle (throttles raise ``RateLimited``)."""


def _rpc_url(chain_id: int) -> str:
    """Native RPC URL for ``chain_id``, or ``""``.

    tx/logs/funding/creation MUST use a native RPC — the Etherscan V2 free tier paywalls these on
    non-ETH chains — so callers treat ``""`` as a hard error and never fall back to the proxy.
    """
    return scryer_config.get_rpc_url(chain_id)


def _err_text(err: Any) -> str:
    if isinstance(err, dict):
        return str(err.get("message") or err)
    return str(err)


async def _rpc(client: httpx.AsyncClient, url: str, method: str, params: Sequence[Any], *, req_id: int = 1) -> Any:
    """One JSON-RPC call. Raises ``RateLimited`` on a throttle, ``RpcError`` on any other RPC error."""
    resp = await client.post(url, json={"jsonrpc": "2.0", "id": req_id, "method": method, "params": list(params)})
    reason = rate_limit_reason(resp)  # status-based (429/403/503)
    if reason:
        raise RateLimited(provider=f"rpc:{method}", retry_after=retry_after_seconds(resp), detail=reason)
    resp.raise_for_status()
    body = resp.json()
    err = body.get("error")
    if err is not None:
        rr = rpc_rate_limit_reason(err)  # app-level throttle (e.g. -32005 / "rate limit")
        if rr:
            raise RateLimited(provider=f"rpc:{method}", detail=rr)
        raise RpcError(f"{method}: {_err_text(err)}")
    return body.get("result")


def _rl_out(base: dict, exc: RateLimited) -> dict:
    """Stamp a result with the retryable rate-limit signal (never a silent empty/miss)."""
    base["rate_limited"] = True
    base["warnings"] = [exc.reason]
    if exc.retry_after is not None:
        base["retry_after"] = exc.retry_after
    base["error"] = f"rate-limited: {exc.reason}"
    return base


# Provider "range too large" / "too many results" phrasing → shrink the window and retry.
_RANGE_ERR_RE = re.compile(
    r"block range|up to a maximum|query returned more than|too many results|more than 10000|"
    r"range is too large|response size|exceeds|limit exceeded|query timeout|logs matched",
    re.IGNORECASE,
)


def _is_range_error(exc: Exception) -> bool:
    return bool(_RANGE_ERR_RE.search(str(exc)))


def _int(h: Any, default: int = 0) -> int:
    if h is None:
        return default
    if isinstance(h, int):
        return h
    s = str(h)
    try:
        return int(s, 16) if s.startswith("0x") else int(s)
    except ValueError:
        return default


async def _resolve_block(client: httpx.AsyncClient, url: str, block: Any) -> int:
    """Normalize a block arg to an absolute block number (resolving tags via eth_blockNumber)."""
    if isinstance(block, int):
        return block
    s = str(block).strip().lower()
    if s in ("", "latest", "pending", "safe", "finalized"):
        return _int(await _rpc(client, url, "eth_blockNumber", []))
    if s == "earliest":
        return 0
    return int(s, 16) if s.startswith("0x") else int(s)


def run(coro: Any) -> Any:
    """Run an async coroutine from sync code (e.g. a sync MCP tool / health()).

    Uses ``asyncio.run`` when no loop is active; if a loop IS already running (unusual for the MCP
    sync-tool path, which runs in a worker thread), it executes on a fresh loop in a helper thread
    so we never attach to a foreign loop.
    """
    try:
        asyncio.get_running_loop()
    except RuntimeError:
        return asyncio.run(coro)
    import concurrent.futures

    with concurrent.futures.ThreadPoolExecutor(max_workers=1) as ex:
        return ex.submit(lambda: asyncio.run(coro)).result()


# --------------------------------------------------------------------------- #
# Log / event decoding
# --------------------------------------------------------------------------- #
def _topic_addr(topic: str) -> str:
    """The 20-byte address packed in the low bytes of a 32-byte indexed topic."""
    return "0x" + topic[-40:]


def _data_word(data: str, i: int) -> int:
    h = data[2:] if data.startswith("0x") else data
    seg = h[i * 64 : (i + 1) * 64]
    return int(seg, 16) if seg else 0


def _decode_events(logs: list[dict]) -> list[dict]:
    """Decode the event shapes that matter for fund-flow forensics: ERC20 Transfer, UniV2
    Swap/Sync, and WETH/WBNB Deposit/Withdrawal. Everything else is kept as ``type:"unknown"``
    (its topic0) so nothing is silently dropped."""
    out: list[dict] = []
    for lg in logs:
        topics = lg.get("topics") or []
        if not topics:
            continue
        t0 = str(topics[0]).lower()
        data = lg.get("data") or "0x"
        addr = (lg.get("address") or "").lower()
        ev: dict = {"address": addr, "block_number": _int(lg.get("blockNumber")), "log_index": _int(lg.get("logIndex"))}
        if t0 == TRANSFER_TOPIC and len(topics) >= 3:
            ev.update(
                type="Transfer",
                token=addr,
                **{"from": _topic_addr(topics[1]), "to": _topic_addr(topics[2]), "value": _data_word(data, 0)},
            )
        elif t0 == SWAP_TOPIC and len(topics) >= 3:
            ev.update(
                type="Swap",
                pair=addr,
                sender=_topic_addr(topics[1]),
                to=_topic_addr(topics[2]),
                amount0In=_data_word(data, 0),
                amount1In=_data_word(data, 1),
                amount0Out=_data_word(data, 2),
                amount1Out=_data_word(data, 3),
            )
        elif t0 == SYNC_TOPIC:
            ev.update(type="Sync", pair=addr, reserve0=_data_word(data, 0), reserve1=_data_word(data, 1))
        elif t0 == DEPOSIT_TOPIC and len(topics) >= 2:
            ev.update(type="Deposit", token=addr, dst=_topic_addr(topics[1]), value=_data_word(data, 0))
        elif t0 == WITHDRAWAL_TOPIC and len(topics) >= 2:
            ev.update(type="Withdrawal", token=addr, src=_topic_addr(topics[1]), value=_data_word(data, 0))
        else:
            ev.update(type="unknown", topic0=t0)
        out.append(ev)
    return out


def _net_flows(events: list[dict]) -> dict[str, dict[str, int]]:
    """Per-token net movement {token: {address: net}} where net = received - sent. Transfers move
    value from->to; a WETH/WBNB Deposit credits dst, a Withdrawal debits src. Zero nets dropped."""
    flows: dict[str, dict[str, int]] = {}

    def _add(token: str, addr: str, delta: int) -> None:
        d = flows.setdefault(token, {})
        d[addr] = d.get(addr, 0) + delta

    for ev in events:
        et = ev.get("type")
        if et == "Transfer":
            _add(ev["token"], ev["from"], -ev["value"])
            _add(ev["token"], ev["to"], ev["value"])
        elif et == "Deposit":
            _add(ev["token"], ev["dst"], ev["value"])
        elif et == "Withdrawal":
            _add(ev["token"], ev["src"], -ev["value"])
    return {tok: {a: v for a, v in d.items() if v != 0} for tok, d in flows.items() if any(v != 0 for v in d.values())}


# --------------------------------------------------------------------------- #
# P0: logs (auto-chunked)
# --------------------------------------------------------------------------- #
async def get_logs(
    chain_id: int,
    address: str = "",
    *,
    topics: list[Any] | None = None,
    from_block: Any = 0,
    to_block: Any = "latest",
    chunk: int | None = None,
    concurrency: int | None = None,
) -> dict:
    """``eth_getLogs`` over an arbitrary block range, auto-chunked to beat the provider range cap.

    The range is split into windows of ``chunk`` blocks (default :func:`_logs_chunk`, 10 for
    Alchemy's free tier) fetched concurrently; a window that still trips a provider range/size
    error is halved and retried down to a single block. Logs are merged, de-duplicated and sorted.
    The result never silently truncates: ``count`` is the total, and ``partial:true`` with
    ``errors``/``rate_limited`` is set if any window could not be fully read.
    """
    url = _rpc_url(chain_id)
    if not url:
        return {
            "chain_id": chain_id,
            "error": f"no native RPC configured for chain {chain_id}; eth_getLogs requires one "
            "(Etherscan logs are paywalled on non-ETH chains). Set the chain's *_URL in .env.",
        }
    chunk = int(chunk or _logs_chunk())
    if chunk < 1:
        chunk = 1
    sem = asyncio.Semaphore(int(concurrency or _concurrency()))
    base: dict[str, Any] = {}
    if address:
        base["address"] = Web3.to_checksum_address(address)
    if topics:
        base["topics"] = topics

    errors: list[dict] = []
    rl: dict[str, Any] = {"hit": False, "retry_after": None, "reason": None}

    async with async_client() as client:
        try:
            lo = await _resolve_block(client, url, from_block)
            hi = await _resolve_block(client, url, to_block)
        except RateLimited as e:
            return _rl_out({"chain_id": chain_id, "address": address.lower() or None}, e)
        except Exception as e:  # noqa: BLE001
            return {"chain_id": chain_id, "error": f"block resolve failed: {type(e).__name__}: {e}"}
        if hi < lo:
            return {"chain_id": chain_id, "error": f"to_block ({hi}) < from_block ({lo})"}

        async def fetch(a: int, b: int) -> list[dict] | None:
            flt = {**base, "fromBlock": hex(a), "toBlock": hex(b)}
            try:
                async with sem:
                    res = await _rpc(client, url, "eth_getLogs", [flt])
                return list(res or [])
            except RateLimited as e:
                rl["hit"] = True
                rl["retry_after"] = e.retry_after
                rl["reason"] = e.reason
                return None  # a throttle is retryable — do NOT recurse (it is not a range problem)
            except Exception as e:  # noqa: BLE001
                if _is_range_error(e) and b > a:
                    mid = (a + b) // 2
                    left = await fetch(a, mid)
                    right = await fetch(mid + 1, b)
                    if left is None or right is None:
                        return None
                    return left + right
                errors.append({"from": a, "to": b, "error": str(e)[:200]})
                return []

        windows = [(s, min(s + chunk - 1, hi)) for s in range(lo, hi + 1, chunk)]
        gathered = await asyncio.gather(*(fetch(a, b) for a, b in windows))

    merged: list[dict] = []
    seen: set[tuple[Any, Any]] = set()
    collected = [lg for part in gathered if part for lg in part]
    for lg in sorted(collected, key=lambda x: (_int(x.get("blockNumber")), _int(x.get("logIndex")))):
        key = (lg.get("transactionHash"), lg.get("logIndex"))
        if key in seen:
            continue
        seen.add(key)
        merged.append(lg)

    out: dict = {
        "chain_id": chain_id,
        "address": address.lower() or None,
        "from_block": lo,
        "to_block": hi,
        "chunk": chunk,
        "windows": len(windows),
        "count": len(merged),
        "logs": merged,
        "rpc_url": redact_rpc_url(url),
    }
    if errors:
        out["errors"] = errors
        out["partial"] = True
        out["note"] = "some windows failed — results are PARTIAL (not a clean empty); see errors."
    if rl["hit"]:
        out["rate_limited"] = True
        out["partial"] = True
        if rl["retry_after"] is not None:
            out["retry_after"] = rl["retry_after"]
        out["note"] = "RATE-LIMITED mid-scan — logs are PARTIAL; retry (see retry_after)."
    return out


# --------------------------------------------------------------------------- #
# P0: transaction decode
# --------------------------------------------------------------------------- #
async def get_tx(chain_id: int, tx_hash: str) -> dict:
    """Fetch a transaction + receipt and decode its token movements.

    Returns from/to/selector/status/gas plus the decoded event list (ERC20 Transfer, UniV2
    Swap/Sync, WETH/WBNB Deposit/Withdrawal) and a per-token NET-FLOW summary
    ({token: {address: net}}), which is the fast read on "what moved, and where to".
    """
    url = _rpc_url(chain_id)
    if not url:
        return {"chain_id": chain_id, "tx_hash": tx_hash, "error": f"no native RPC configured for chain {chain_id}"}
    async with async_client() as client:
        try:
            tx, receipt = await asyncio.gather(
                _rpc(client, url, "eth_getTransactionByHash", [tx_hash]),
                _rpc(client, url, "eth_getTransactionReceipt", [tx_hash]),
            )
        except RateLimited as e:
            return _rl_out({"chain_id": chain_id, "tx_hash": tx_hash}, e)
        except Exception as e:  # noqa: BLE001
            return {"chain_id": chain_id, "tx_hash": tx_hash, "error": f"{type(e).__name__}: {e}"}
    if not tx:
        return {"chain_id": chain_id, "tx_hash": tx_hash, "error": "transaction not found"}
    logs = (receipt or {}).get("logs", []) or []
    events = _decode_events(logs)
    inp = tx.get("input") or "0x"
    status_raw = (receipt or {}).get("status")
    to = tx.get("to")
    return {
        "chain_id": chain_id,
        "tx_hash": tx_hash,
        "from": (tx.get("from") or "").lower() or None,
        "to": (to or "").lower() or None,
        "selector": inp[:10] if len(inp) >= 10 and inp != "0x" else None,
        "value_wei": _int(tx.get("value")),
        "block_number": _int(tx.get("blockNumber")) if tx.get("blockNumber") is not None else None,
        "status": (_int(status_raw) if status_raw is not None else None),
        "gas_used": _int((receipt or {}).get("gasUsed")) if receipt and receipt.get("gasUsed") is not None else None,
        "effective_gas_price": (
            _int(receipt.get("effectiveGasPrice")) if receipt and receipt.get("effectiveGasPrice") is not None else None
        ),
        "event_count": len(events),
        "events": events,
        "net_flows": _net_flows(events),
        "rpc_url": redact_rpc_url(url),
    }


# --------------------------------------------------------------------------- #
# P0: asset transfers (fund flow) — Alchemy getAssetTransfers w/ pagination
# --------------------------------------------------------------------------- #
def _block_tag(b: Any) -> str:
    if isinstance(b, int):
        return hex(b)
    s = str(b).strip().lower()
    if s in ("", "latest"):
        return "latest"
    if s in ("earliest", "pending", "safe", "finalized"):
        return s
    return s if s.startswith("0x") else hex(int(s))


async def asset_transfers(
    chain_id: int,
    address: str,
    *,
    direction: str = "in",
    category: list[str] | None = None,
    from_block: Any = 0,
    to_block: Any = "latest",
    max_pages: int = 20,
) -> dict:
    """Trace an address's value flow via ``alchemy_getAssetTransfers`` (pageKey-paginated).

    ``direction``: "in" (received — the "who funded X" primitive), "out" (sent), or "both".
    ``category``: Alchemy categories, default ["external","erc20"]. Returns counterparties with
    per-counterparty count/value/assets and the earliest block seen. Needs an Alchemy-family RPC.
    """
    url = _rpc_url(chain_id)
    if not url:
        return {
            "chain_id": chain_id,
            "address": address.lower(),
            "error": f"no native RPC configured for chain {chain_id}",
        }
    category = category or ["external", "erc20"]
    checks = Web3.to_checksum_address(address)
    base = {
        "fromBlock": _block_tag(from_block),
        "toBlock": _block_tag(to_block),
        "category": category,
        "withMetadata": False,
        "excludeZeroValue": True,
        "maxCount": "0x3e8",  # 1000 — Alchemy's per-page cap
        "order": "asc",
    }
    queries: list[tuple[str, dict]] = []
    if direction in ("in", "both"):
        queries.append(("in", {**base, "toAddress": checks}))
    if direction in ("out", "both"):
        queries.append(("out", {**base, "fromAddress": checks}))
    if not queries:
        return {
            "chain_id": chain_id,
            "address": address.lower(),
            "error": f"invalid direction {direction!r} (in|out|both)",
        }

    transfers: list[dict] = []
    truncated = False
    async with async_client() as client:
        try:
            for dname, params in queries:
                page = dict(params)
                pages = 0
                while True:
                    res = await _rpc(client, url, "alchemy_getAssetTransfers", [page])
                    batch = (res or {}).get("transfers", []) or []
                    for t in batch:
                        t["_direction"] = dname
                    transfers.extend(batch)
                    pages += 1
                    page_key = (res or {}).get("pageKey")
                    if not page_key or pages >= max_pages:
                        truncated = truncated or bool(page_key)
                        break
                    page = {**params, "pageKey": page_key}
        except RateLimited as e:
            return _rl_out({"chain_id": chain_id, "address": address.lower()}, e)
        except RpcError as e:
            msg = str(e)
            hint = " (alchemy_getAssetTransfers needs an Alchemy-family RPC)" if "method" in msg.lower() else ""
            return {"chain_id": chain_id, "address": address.lower(), "error": f"{msg}{hint}"}
        except Exception as e:  # noqa: BLE001
            return {"chain_id": chain_id, "address": address.lower(), "error": f"{type(e).__name__}: {e}"}

    counterparties: dict[str, dict] = {}
    earliest: int | None = None
    for t in transfers:
        cp = ((t.get("from") if t.get("_direction") == "in" else t.get("to")) or "").lower()
        c = counterparties.setdefault(cp, {"count": 0, "value": 0.0, "assets": set()})
        c["count"] += 1
        if isinstance(t.get("value"), (int, float)):
            c["value"] += float(t["value"])
        if t.get("asset"):
            c["assets"].add(t["asset"])
        bn = _int(t.get("blockNum")) if t.get("blockNum") else None
        if bn is not None:
            earliest = bn if earliest is None else min(earliest, bn)

    cps = [
        {"address": a, "count": c["count"], "value": round(c["value"], 8), "assets": sorted(c["assets"])}
        for a, c in counterparties.items()
    ]
    cps.sort(key=lambda x: (-x["count"], x["address"]))

    out: dict = {
        "chain_id": chain_id,
        "address": address.lower(),
        "direction": direction,
        "category": category,
        "count": len(transfers),
        "counterparties": cps,
        "earliest_block": earliest,
        "rpc_url": redact_rpc_url(url),
    }
    if truncated:
        out["truncated"] = True
        out["note"] = f"stopped at max_pages={max_pages}; MORE transfers exist (raise max_pages)."
    return out


# --------------------------------------------------------------------------- #
# P0: deployer resolution (native RPC only — getcontractcreation is paywalled on BSC)
# --------------------------------------------------------------------------- #
async def _first_log_tx_at(client: httpx.AsyncClient, url: str, checks: str, block: int) -> str | None:
    """The tx hash of the contract's first log at ``block`` — preferring a mint ``Transfer(from=0)``
    (emitted in the creation tx for a token), else any log the contract emitted at deploy."""
    mint = {"address": checks, "fromBlock": hex(block), "toBlock": hex(block), "topics": [TRANSFER_TOPIC, ZERO_TOPIC]}
    logs = await _rpc(client, url, "eth_getLogs", [mint]) or []
    if not logs:
        anylog = {"address": checks, "fromBlock": hex(block), "toBlock": hex(block)}
        logs = await _rpc(client, url, "eth_getLogs", [anylog]) or []
    if not logs:
        return None
    logs.sort(key=lambda lg: _int(lg.get("logIndex")))
    return logs[0].get("transactionHash")


async def deployer(chain_id: int, address: str) -> dict:
    """Resolve a contract's deployer EOA, creation tx, and factory (if factory-made).

    Native-RPC only (Etherscan ``getcontractcreation`` is paywalled on BSC): binary-search
    ``eth_getCode`` for the deploy block, reverse the creation tx from the first mint/log at that
    block, then read that tx's from (deployer EOA) and to (``null`` => direct CREATE; an address =>
    the factory that created it).
    """
    url = _rpc_url(chain_id)
    if not url:
        return {
            "chain_id": chain_id,
            "address": address.lower(),
            "error": f"no native RPC configured for chain {chain_id}",
        }
    checks = Web3.to_checksum_address(address)
    out: dict = {"chain_id": chain_id, "address": address.lower(), "rpc_url": redact_rpc_url(url)}
    async with async_client() as client:
        try:
            head = _int(await _rpc(client, url, "eth_blockNumber", []))
            code_now = await _rpc(client, url, "eth_getCode", [checks, hex(head)])
            if not code_now or code_now == "0x":
                out["note"] = "no code at head (EOA or self-destructed) — cannot binary-search a deploy block"
                return out
            lo, hi = 0, head
            while lo < hi:  # smallest block whose getCode is non-empty == deploy block
                mid = (lo + hi) // 2
                code = await _rpc(client, url, "eth_getCode", [checks, hex(mid)])
                if code and code != "0x":
                    hi = mid
                else:
                    lo = mid + 1
            out["deploy_block"] = lo
            creation = await _first_log_tx_at(client, url, checks, lo)
            tx = await _rpc(client, url, "eth_getTransactionByHash", [creation]) if creation else None
        except RateLimited as e:
            return _rl_out(out, e)
        except Exception as e:  # noqa: BLE001
            out["error"] = f"{type(e).__name__}: {e} (historical eth_getCode needs an archive RPC)"
            return out
    if tx:
        to = tx.get("to")
        to_l = (to or "").lower() or None
        out["creation_tx"] = creation
        out["deployer"] = (tx.get("from") or "").lower() or None
        out["factory"] = to_l
        out["via"] = "factory" if to_l else "direct_create"
    else:
        out["note"] = "deploy block located, but no mint/log at that block to reverse the creation tx from"
    return out
