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
import itertools
import re
from collections.abc import Sequence
from typing import Any

import httpx
from eth_abi import decode as abi_decode
from eth_abi import encode as abi_encode
from web3 import Web3

import onchain_state as oc
import scryer_config
import scryer_labels
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


def _hub_threshold() -> int:
    # An address transacting with more than this many distinct counterparties is likely a
    # service/hub (exchange, router, bridge) rather than a private wallet.
    return scryer_config.get_int("SCRYER_HUB_MIN_COUNTERPARTIES", 40) or 40


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


class _EndpointError(Exception):
    """This endpoint/key is unusable (HTTP 401/403 — bad key, or chain not enabled on the app).
    Not a throttle and not node-independent: rotate to the next key AND drop this one for the run."""


_dead_urls: set[str] = set()  # endpoints that auth-failed this process — excluded from rotation


def _rpc_url(chain_id: int) -> str:
    """Primary native RPC URL for ``chain_id``, or ``""`` — the no-RPC guard + the redacted
    ``rpc_url`` field both key off this.

    tx/logs/funding/creation MUST use a native RPC — the Etherscan V2 free tier paywalls these on
    non-ETH chains — so callers treat ``""`` as a hard error and never fall back to the proxy.
    """
    return scryer_config.get_rpc_url(chain_id)


_rr_counter = itertools.count()  # process-wide round-robin cursor (GIL-atomic next())

# Archive-capable, keyed provider endpoints — the only ones safe to rotate scryer_chain over. The
# tools here do HISTORICAL reads (getCode/eth_call/getLogs at old blocks); a public shared node is
# non-archive and answers those with "missing trie node" / empty, so mixing public nodes into the
# rotation silently breaks historical reads. A keyed provider URL (/v2|/v3 path or a known
# archive host) is the signal; bare public hosts (bsc-dataseed, *.publicnode.com, llamarpc, 1rpc…)
# are excluded from rotation (they remain in get_rpc_urls for other consumers / as last resort).
_PREMIUM_RPC_RE = re.compile(
    r"alchemy|infura|quiknode|quicknode|chainstack|nodereal|blastapi|blockpi|drpc\.org|"
    r"ankr\.com/[a-z]+/|/v2/|/v3/|[?&]apikey=",
    re.IGNORECASE,
)


def _rpc_urls(chain_id: int, *, alchemy_only: bool = False) -> list[str]:
    """The round-robin pool for ``chain_id`` — the archive-capable provider endpoints only.

    Rotating the concurrent fan-out across the keyed provider endpoints (e.g. ALCHEMY_KEY +
    ALCHEMY_KEY_2) is the throughput lever against a single key's limits. Public shared nodes are
    deliberately EXCLUDED: they are non-archive, so a historical getCode/eth_call/getLogs round-robined
    onto one fails with "missing trie node" / empty and breaks the read. If no keyed provider is
    configured we fall back to whatever URLs exist (best effort). ``alchemy_only`` narrows further to
    Alchemy endpoints, for a method only Alchemy serves (alchemy_getAssetTransfers)."""
    urls = scryer_config.get_rpc_urls(chain_id)
    if not urls:
        one = _rpc_url(chain_id)
        urls = [one] if one else []
    urls = [u for u in urls if u not in _dead_urls]  # drop endpoints that auth-failed this run
    if alchemy_only:
        alc = [u for u in urls if "alchemy" in u.lower()]
        return alc or urls
    premium = [u for u in urls if _PREMIUM_RPC_RE.search(u)]
    return premium or urls


async def _rpc_rotating(
    client: httpx.AsyncClient,
    urls: Sequence[str],
    method: str,
    params: Sequence[Any],
    *,
    start: int = 0,
    req_id: int = 1,
) -> Any:
    """``_rpc`` with key-pool round-robin + throttle fallback.

    Starts at ``urls[start % n]`` (so concurrent callers spread across keys) and falls back to the
    next URL/key when THIS key can't serve the request: a throttle (``RateLimited``) or an auth/
    not-enabled failure (``_EndpointError`` — HTTP 401/403; the bad key is also dropped from the pool
    for the rest of the run so it isn't retried). A plain ``RpcError`` (e.g. a getLogs range error)
    propagates immediately: it is node-independent, so another key would not help and the caller needs
    to see it (to halve the window). Raises only when EVERY key failed that way.
    """
    pool = [u for u in urls if u not in _dead_urls] or list(urls)
    if not pool:
        raise RpcError(f"{method}: no RPC url configured")
    n = len(pool)
    last_exc: Exception | None = None
    for i in range(n):
        u = pool[(start + i) % n]
        try:
            return await _rpc(client, u, method, params, req_id=req_id)
        except RateLimited as e:
            last_exc = e  # this key is throttled — try the next one
        except _EndpointError as e:
            if u not in _dead_urls:
                _dead_urls.add(u)  # bad key / chain-not-enabled — stop using it this run
                _log.warning("RPC endpoint dropped (auth/not-enabled), falling back: %s", e)
            last_exc = e
    assert last_exc is not None  # the loop ran at least once
    raise last_exc


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
    # 401/403 that isn't a throttle = a bad key or a chain not enabled on this app — rotate off it.
    if resp.status_code in (401, 403):
        raise _EndpointError(f"HTTP {resp.status_code}: {(resp.text or '').strip()[:140]}")
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
# Token symbol/decimals (for human amounts) — cached per (chain, token)
# --------------------------------------------------------------------------- #
_SYM_SEL = "0x95d89b41"  # symbol()
_DEC_SEL = "0x313ce567"  # decimals()
_token_meta_cache: dict[tuple[int, str], dict] = {}


def _decode_string(raw: str | None) -> str | None:
    """Decode an ABI string (or legacy bytes32) return value; None if undecodable/empty."""
    if not raw or raw == "0x":
        return None
    b = bytes.fromhex(raw[2:] if raw.startswith("0x") else raw)
    try:
        s = abi_decode(["string"], b)[0]
        return s or None
    except Exception:
        pass
    try:  # legacy bytes32 symbol (e.g. MKR)
        return b.rstrip(b"\x00").decode("utf-8", "replace").strip() or None
    except Exception:
        return None


async def _token_meta(client: httpx.AsyncClient, urls: Sequence[str], chain_id: int, token: str) -> dict:
    """``{"symbol", "decimals"}`` for an ERC20, cached. decimals defaults to 18, symbol to None."""
    key = (chain_id, token.lower())
    if key in _token_meta_cache:
        return _token_meta_cache[key]
    checks = Web3.to_checksum_address(token)
    start = next(_rr_counter)
    meta: dict = {"symbol": None, "decimals": 18}
    try:
        res: Any = await asyncio.gather(
            _rpc_rotating(client, urls, "eth_call", [{"to": checks, "data": _SYM_SEL}, "latest"], start=start),
            _rpc_rotating(client, urls, "eth_call", [{"to": checks, "data": _DEC_SEL}, "latest"], start=start + 1),
            return_exceptions=True,
        )
        sym_raw, dec_raw = res[0], res[1]
        if isinstance(sym_raw, str):
            meta["symbol"] = _decode_string(sym_raw)
        if isinstance(dec_raw, str) and dec_raw not in ("", "0x"):
            d = int(dec_raw, 16)
            if 0 < d <= 36:
                meta["decimals"] = d
    except Exception:  # noqa: BLE001 - metadata is best-effort
        pass
    _token_meta_cache[key] = meta
    return meta


def _human(raw: int, decimals: int) -> float:
    return raw / (10**decimals)


async def _enrich_get_tx(client: httpx.AsyncClient, urls: Sequence[str], chain_id: int, out: dict) -> None:
    """Add forensic readability to a get_tx result (in place): per-token symbol/decimals, human
    net-flow amounts, a per-token biggest-gainer/biggest-loser (victim/beneficiary) summary, and
    known-entity labels for every address that moved. Best-effort — never raises."""
    net = out.get("net_flows") or {}
    tokens = list(net.keys())
    metas = await asyncio.gather(*(_token_meta(client, urls, chain_id, t) for t in tokens)) if tokens else []
    token_meta = dict(zip(tokens, metas, strict=True))

    labels: dict[str, dict] = {}

    def _lab(addr: str) -> None:
        lab = scryer_labels.label_for(addr)
        if lab:
            labels[addr] = lab

    net_human: dict[str, dict] = {}
    flow_summary: list[dict] = []
    for tok, moves in net.items():
        dec = token_meta.get(tok, {}).get("decimals", 18)
        sym = token_meta.get(tok, {}).get("symbol")
        net_human[tok] = {a: _human(v, dec) for a, v in moves.items()}
        for a in moves:
            _lab(a)
        _lab(tok)
        gain_a = max(moves, key=lambda a: moves[a])
        loss_a = min(moves, key=lambda a: moves[a])
        flow_summary.append(
            {
                "token": tok,
                "symbol": sym,
                "beneficiary": {
                    "address": gain_a,
                    "amount": _human(moves[gain_a], dec),
                    "label": scryer_labels.label_for(gain_a),
                },
                "victim": {
                    "address": loss_a,
                    "amount": _human(moves[loss_a], dec),
                    "label": scryer_labels.label_for(loss_a),
                },
            }
        )
    for a in (out.get("from"), out.get("to")):
        if a:
            _lab(a)

    out["token_meta"] = token_meta
    out["net_flows_human"] = net_human
    out["flow_summary"] = flow_summary
    if labels:
        out["labels"] = labels


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
    urls = _rpc_urls(chain_id)  # spread the concurrent windows across the key pool
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

        async def fetch(a: int, b: int, start: int) -> list[dict] | None:
            flt = {**base, "fromBlock": hex(a), "toBlock": hex(b)}
            try:
                async with sem:
                    res = await _rpc_rotating(client, urls, "eth_getLogs", [flt], start=start)
                return list(res or [])
            except RateLimited as e:
                # every key in the pool throttled — retryable; do NOT recurse (not a range problem)
                rl["hit"] = True
                rl["retry_after"] = e.retry_after
                rl["reason"] = e.reason
                return None
            except Exception as e:  # noqa: BLE001
                if _is_range_error(e) and b > a:
                    mid = (a + b) // 2
                    left = await fetch(a, mid, start)
                    right = await fetch(mid + 1, b, start + 1)
                    if left is None or right is None:
                        return None
                    return left + right
                errors.append({"from": a, "to": b, "error": str(e)[:200]})
                return []

        base_rr = next(_rr_counter)
        windows = [(s, min(s + chunk - 1, hi)) for s in range(lo, hi + 1, chunk)]
        gathered = await asyncio.gather(*(fetch(a, b, base_rr + i) for i, (a, b) in enumerate(windows)))

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
    urls = _rpc_urls(chain_id)
    base_rr = next(_rr_counter)
    async with async_client() as client:
        try:
            tx, receipt = await asyncio.gather(
                _rpc_rotating(client, urls, "eth_getTransactionByHash", [tx_hash], start=base_rr),
                _rpc_rotating(client, urls, "eth_getTransactionReceipt", [tx_hash], start=base_rr + 1),
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
    out = {
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
    try:  # best-effort enrichment: symbol/decimals, human amounts, victim/beneficiary, labels
        async with async_client() as client:
            await _enrich_get_tx(client, urls, chain_id, out)
    except Exception as e:  # noqa: BLE001
        out["enrich_error"] = f"{type(e).__name__}: {e}"
    return out


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
    # One Alchemy endpoint per invocation, round-robin across the key pool — spreads load across
    # calls while keeping a single key for the whole pageKey sequence (pageKeys are provider-scoped).
    alc = _rpc_urls(chain_id, alchemy_only=True)
    url_pick = alc[next(_rr_counter) % len(alc)] if alc else url
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
                    res = await _rpc(client, url_pick, "alchemy_getAssetTransfers", [page])
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
        {
            "address": a,
            "count": c["count"],
            "value": round(c["value"], 8),
            "assets": sorted(c["assets"]),
            "label": scryer_labels.label_for(a),  # known-entity annotation (CEX/mixer/router/…)
        }
        for a, c in counterparties.items()
    ]
    cps.sort(key=lambda x: (-x["count"], x["address"]))
    # earliest-seen counterparty = the FIRST funder (attribution start point)
    first_funder = None
    if transfers:
        first_t = min(transfers, key=lambda t: _int(t.get("blockNum")) if t.get("blockNum") else 1 << 62)
        fa = ((first_t.get("from") if first_t.get("_direction") == "in" else first_t.get("to")) or "").lower() or None
        if fa:
            first_funder = {"address": fa, "label": scryer_labels.label_for(fa), "block": earliest}

    out: dict = {
        "chain_id": chain_id,
        "address": address.lower(),
        "direction": direction,
        "category": category,
        "count": len(transfers),
        "distinct_counterparties": len(cps),
        "first_funder": first_funder,
        "counterparties": cps,
        "earliest_block": earliest,
        "rpc_url": redact_rpc_url(url),
    }
    # Cheap hub heuristic: an address with many distinct counterparties is likely a service/hub
    # (exchange/router/bridge), not a private wallet — flag it so it isn't read as the attacker.
    if len(cps) >= _hub_threshold():
        out["likely_service_hub"] = True
    if truncated:
        out["truncated"] = True
        out["note"] = f"stopped at max_pages={max_pages}; MORE transfers exist (raise max_pages)."
    return out


# --------------------------------------------------------------------------- #
# P0: deployer resolution (native RPC only — getcontractcreation is paywalled on BSC)
# --------------------------------------------------------------------------- #
async def _first_log_tx_at(
    client: httpx.AsyncClient, urls: Sequence[str], checks: str, block: int, *, start: int = 0
) -> str | None:
    """The tx hash of the contract's first log at ``block`` — preferring a mint ``Transfer(from=0)``
    (emitted in the creation tx for a token), else any log the contract emitted at deploy."""
    mint = {"address": checks, "fromBlock": hex(block), "toBlock": hex(block), "topics": [TRANSFER_TOPIC, ZERO_TOPIC]}
    logs = await _rpc_rotating(client, urls, "eth_getLogs", [mint], start=start) or []
    if not logs:
        anylog = {"address": checks, "fromBlock": hex(block), "toBlock": hex(block)}
        logs = await _rpc_rotating(client, urls, "eth_getLogs", [anylog], start=start + 1) or []
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
    urls = _rpc_urls(chain_id)
    base_rr = next(_rr_counter)
    checks = Web3.to_checksum_address(address)
    out: dict = {"chain_id": chain_id, "address": address.lower(), "rpc_url": redact_rpc_url(url)}
    async with async_client() as client:
        try:
            head = _int(await _rpc_rotating(client, urls, "eth_blockNumber", [], start=base_rr))
            code_now = await _rpc_rotating(client, urls, "eth_getCode", [checks, hex(head)], start=base_rr)
            if not code_now or code_now == "0x":
                out["note"] = "no code at head (EOA or self-destructed) — cannot binary-search a deploy block"
                return out
            lo, hi, step = 0, head, 0
            while lo < hi:  # smallest block whose getCode is non-empty == deploy block
                mid = (lo + hi) // 2
                code = await _rpc_rotating(client, urls, "eth_getCode", [checks, hex(mid)], start=base_rr + step)
                step += 1
                if code and code != "0x":
                    hi = mid
                else:
                    lo = mid + 1
            out["deploy_block"] = lo
            creation = await _first_log_tx_at(client, urls, checks, lo, start=base_rr)
            tx = (
                await _rpc_rotating(client, urls, "eth_getTransactionByHash", [creation], start=base_rr)
                if creation
                else None
            )
        except RateLimited as e:
            return _rl_out(out, e)
        except Exception as e:  # noqa: BLE001
            out["error"] = f"{type(e).__name__}: {e} (historical eth_getCode needs an archive RPC)"
            return out
    if tx:
        to = tx.get("to")
        to_l = (to or "").lower() or None
        frm = (tx.get("from") or "").lower() or None
        out["creation_tx"] = creation
        out["deployer"] = frm
        out["factory"] = to_l
        out["via"] = "factory" if to_l else "direct_create"
        out["deployer_label"] = scryer_labels.label_for(frm)  # e.g. a CEX-funded deployer
        out["factory_label"] = scryer_labels.label_for(to_l)
    else:
        out["note"] = "deploy block located, but no mint/log at that block to reverse the creation tx from"
    return out


# --------------------------------------------------------------------------- #
# P1: chain head helpers
# --------------------------------------------------------------------------- #
async def block_number(chain_id: int) -> dict:
    """Current head block for ``chain_id`` (native RPC)."""
    url = _rpc_url(chain_id)
    if not url:
        return {"chain_id": chain_id, "error": f"no native RPC configured for chain {chain_id}"}
    urls = _rpc_urls(chain_id)
    async with async_client() as client:
        try:
            bn = _int(await _rpc_rotating(client, urls, "eth_blockNumber", [], start=next(_rr_counter)))
        except RateLimited as e:
            return _rl_out({"chain_id": chain_id}, e)
        except Exception as e:  # noqa: BLE001
            return {"chain_id": chain_id, "error": f"{type(e).__name__}: {e}"}
    return {"chain_id": chain_id, "block_number": bn, "rpc_url": redact_rpc_url(url)}


async def block_at(chain_id: int, timestamp: int) -> dict:
    """The latest block whose timestamp is <= ``timestamp`` (binary search over block timestamps).

    The standard "what block was it at time T" primitive for pinning a historical read/log scan to
    a wall-clock moment. Clamps to [genesis, head]. Needs the node to serve block headers by number.
    """
    url = _rpc_url(chain_id)
    if not url:
        return {"chain_id": chain_id, "error": f"no native RPC configured for chain {chain_id}"}
    urls = _rpc_urls(chain_id)
    base_rr = next(_rr_counter)
    target = int(timestamp)
    async with async_client() as client:
        try:

            async def ts_of(b: int) -> int:
                blk = await _rpc_rotating(
                    client, urls, "eth_getBlockByNumber", [hex(b), False], start=next(_rr_counter)
                )
                if not blk:
                    raise RpcError(f"block {b} not found")
                return _int(blk.get("timestamp"))

            head = _int(await _rpc_rotating(client, urls, "eth_blockNumber", [], start=base_rr))
            lo_ts = await ts_of(0)
            if target <= lo_ts:
                return {
                    "chain_id": chain_id,
                    "timestamp": target,
                    "block_number": 0,
                    "block_timestamp": lo_ts,
                    "rpc_url": redact_rpc_url(url),
                }
            head_ts = await ts_of(head)
            if target >= head_ts:
                return {
                    "chain_id": chain_id,
                    "timestamp": target,
                    "block_number": head,
                    "block_timestamp": head_ts,
                    "rpc_url": redact_rpc_url(url),
                }
            lo, hi = 0, head
            while lo < hi:  # largest block with timestamp <= target
                mid = (lo + hi + 1) // 2
                if await ts_of(mid) <= target:
                    lo = mid
                else:
                    hi = mid - 1
            found_ts = await ts_of(lo)
        except RateLimited as e:
            return _rl_out({"chain_id": chain_id, "timestamp": target}, e)
        except Exception as e:  # noqa: BLE001
            return {"chain_id": chain_id, "timestamp": target, "error": f"{type(e).__name__}: {e}"}
    return {
        "chain_id": chain_id,
        "timestamp": target,
        "block_number": lo,
        "block_timestamp": found_ts,
        "rpc_url": redact_rpc_url(url),
    }


async def chain_heads(chain_ids: Sequence[int]) -> dict[int, int | None]:
    """Best-effort current head for several chains concurrently (for health()).

    Only chains with a configured native RPC are queried; a chain with no RPC, or one that errors
    or times out, maps to ``None`` so a slow/missing node never breaks the caller.
    """

    async def one(cid: int) -> tuple[int, int | None]:
        url = scryer_config.get_rpc_url(cid)
        if not url:
            return cid, None
        try:
            async with async_client(timeout=8) as client:
                return cid, _int(await _rpc(client, url, "eth_blockNumber", []))
        except Exception:  # noqa: BLE001 - head probe is advisory
            return cid, None

    pairs = await asyncio.gather(*(one(c) for c in chain_ids))
    return dict(pairs)


# --------------------------------------------------------------------------- #
# P1: batch view calls
# --------------------------------------------------------------------------- #
def _args_for(args: Any, idx: int, n_sigs: int) -> list:
    """Resolve the argument list for signature #idx. ``args`` is either a single arg list applied
    to every signature, or (when there are multiple signatures) a list-of-lists aligned per
    signature."""
    if not args:
        return []
    if n_sigs > 1 and len(args) == n_sigs and all(isinstance(a, (list, tuple)) for a in args):
        return list(args[idx])
    return list(args)


async def call_view_many(
    chain_id: int,
    address: str,
    signatures: Any,
    *,
    args: Any = None,
    returns: str = "",
    blocks: Any = None,
    concurrency: int | None = None,
) -> dict:
    """Call one or many view signatures across one or many blocks, concurrently.

    Runs the full (signature x block) cross product under a concurrency cap — the fast path for the
    repeated forensic reads call_view does one-at-a-time (e.g. getReserves() across 50 blocks, or a
    batch of getters at one block). ``args``: a single arg list for all signatures, or a list-of-
    lists aligned per signature. ``returns``: shared output types to decode each result. Each entry
    carries its own signature/block and raw/decoded or error, so one revert never sinks the batch.
    """
    url = _rpc_url(chain_id)
    if not url:
        return {
            "chain_id": chain_id,
            "address": address.lower(),
            "error": f"no native RPC configured for chain {chain_id}",
        }
    urls = _rpc_urls(chain_id)  # spread the batch across the key pool
    if isinstance(signatures, str):
        signatures = [signatures]
    signatures = list(signatures)
    if not signatures:
        return {"chain_id": chain_id, "address": address.lower(), "error": "no signatures given"}
    if blocks is None:
        blocks = ["latest"]
    elif not isinstance(blocks, (list, tuple)):
        blocks = [blocks]
    blocks = list(blocks)
    checks = Web3.to_checksum_address(address)
    out_types = [t for t in (p.strip() for p in returns.split(",")) if t] if returns else []

    prepared: list[tuple[str, str | None, str | None]] = []  # (sig, calldata, encode_error)
    for i, raw_sig in enumerate(signatures):
        s = str(raw_sig).strip().replace(" ", "")
        try:
            in_types = oc._sig_input_types(s)
            selector = bytes(Web3.keccak(text=s))[:4]
            data = (
                "0x"
                + (selector + (abi_encode(in_types, _args_for(args, i, len(signatures))) if in_types else b"")).hex()
            )
            prepared.append((s, data, None))
        except Exception as e:  # noqa: BLE001
            prepared.append((s, None, f"encode failed: {type(e).__name__}: {e}"))

    sem = asyncio.Semaphore(int(concurrency or _concurrency()))
    rl: dict[str, Any] = {"hit": False, "retry_after": None}

    async with async_client() as client:

        async def one(sig: str, data: str | None, enc_err: str | None, blk: Any, start: int) -> dict:
            base = {"signature": sig, "block": blk}
            if enc_err:
                return {**base, "error": enc_err}
            try:
                async with sem:
                    raw = await _rpc_rotating(
                        client, urls, "eth_call", [{"to": checks, "data": data}, _block_tag(blk)], start=start
                    )
                res: dict = {**base, "raw": raw}
                if out_types:
                    try:
                        rawb = bytes.fromhex(raw[2:] if isinstance(raw, str) and raw.startswith("0x") else (raw or ""))
                        res["decoded"] = oc._jsonable(abi_decode(out_types, rawb))
                    except Exception as e:  # noqa: BLE001
                        res["decode_error"] = f"{type(e).__name__}: {e}"
                return res
            except RateLimited as e:
                rl["hit"] = True
                rl["retry_after"] = e.retry_after
                return {**base, "rate_limited": True, "error": e.reason}
            except Exception as e:  # noqa: BLE001
                return {**base, "error": f"eth_call failed/reverted: {type(e).__name__}: {e}"}

        base_rr = next(_rr_counter)
        tasks = [
            one(sig, data, err, blk, base_rr + i)
            for i, ((sig, data, err), blk) in enumerate((p, b) for p in prepared for b in blocks)
        ]
        results = await asyncio.gather(*tasks)

    out: dict = {
        "chain_id": chain_id,
        "address": address.lower(),
        "signatures": signatures,
        "blocks": blocks,
        "count": len(results),
        "results": results,
        "rpc_url": redact_rpc_url(url),
    }
    if rl["hit"]:
        out["rate_limited"] = True
        if rl["retry_after"] is not None:
            out["retry_after"] = rl["retry_after"]
        out["note"] = "some eth_call(s) were RATE-LIMITED; those entries are incomplete — retry them."
    return out


# --------------------------------------------------------------------------- #
# P1: reserve history (the single most-repeated forensic pattern)
# --------------------------------------------------------------------------- #
def _spread(lo: int, hi: int, n: int) -> list[int]:
    """``n`` evenly-spaced block numbers across [lo, hi] inclusive (deduped, ascending)."""
    if hi <= lo or n <= 1:
        return [lo] if n >= 1 else []
    n = min(n, hi - lo + 1)
    step = (hi - lo) / (n - 1)
    return sorted({lo + round(i * step) for i in range(n)})


def _downsample(series: list[dict], n: int) -> list[dict]:
    """Keep at most ``n`` points, evenly spaced, preserving order and always the first and last."""
    if n <= 0 or len(series) <= n:
        return series
    if n == 1:
        return [series[-1]]
    step = (len(series) - 1) / (n - 1)
    idxs = sorted({round(i * step) for i in range(n)})
    return [series[i] for i in idxs]


def _max_single_step_drop(series: list[dict]) -> dict | None:
    """The largest single-step reserve DROP between consecutive points — the drain moment. Scans
    both reserve sides and returns the biggest fractional decrease, or None if reserves only grew."""
    worst: dict | None = None
    for a, b in zip(series, series[1:], strict=False):
        for side in ("reserve0", "reserve1"):
            pa, pb = a.get(side), b.get(side)
            if pa and pb is not None and pb < pa:
                pct = (pa - pb) / pa
                if worst is None or pct > worst["drop_pct"]:
                    worst = {
                        "from_block": a["block"],
                        "to_block": b["block"],
                        "reserve": side,
                        "from": pa,
                        "to": pb,
                        "drop_pct": round(pct, 6),
                    }
    return worst


def _reserves_max_scan() -> int:
    # Above this block span, scanning Sync logs (10-block windows) is too many requests — sample
    # getReserves across the range instead (points calls, archive).
    return scryer_config.get_int("SCRYER_RESERVES_MAX_SCAN", 5000) or 5000


async def reserves_history(
    chain_id: int, pair: str, *, from_block: Any = 0, to_block: Any = "latest", points: int = 50
) -> dict:
    """Reserve trajectory of a UniV2-style pair over a block range — the most-repeated forensic read.

    For a SMALL range it reads the pair's own ``Sync`` logs (exact reserves at each change). For a
    LARGE range (> SCRYER_RESERVES_MAX_SCAN blocks, default 5000) a Sync scan would be thousands of
    10-block getLogs windows, so it SAMPLES ``getReserves()`` at ``points`` evenly-spaced blocks
    instead (also the fallback when a small range has no Sync logs). ``source`` says which path ran,
    and ``max_drop`` flags the biggest single-step reserve collapse (the drain block).
    """
    url = _rpc_url(chain_id)
    if not url:
        return {"chain_id": chain_id, "pair": pair.lower(), "error": f"no native RPC configured for chain {chain_id}"}
    async with async_client() as client:
        try:
            lo = await _resolve_block(client, url, from_block)
            hi = await _resolve_block(client, url, to_block)
        except RateLimited as e:
            return _rl_out({"chain_id": chain_id, "pair": pair.lower()}, e)
        except Exception as e:  # noqa: BLE001
            return {
                "chain_id": chain_id,
                "pair": pair.lower(),
                "error": f"block resolve failed: {type(e).__name__}: {e}",
            }
    if hi < lo:
        return {"chain_id": chain_id, "pair": pair.lower(), "error": f"to_block ({hi}) < from_block ({lo})"}

    large = (hi - lo) > _reserves_max_scan()
    series: list[dict] = []
    source = ""
    extra: dict = {}

    if not large:
        logs_out = await get_logs(chain_id, pair, topics=[SYNC_TOPIC], from_block=lo, to_block=hi)
        if logs_out.get("error"):
            return logs_out
        series = [
            {"block": ev["block_number"], "reserve0": ev["reserve0"], "reserve1": ev["reserve1"]}
            for ev in _decode_events(logs_out.get("logs", []))
            if ev.get("type") == "Sync"
        ]
        source = "sync_logs"
        for k in ("partial", "rate_limited", "retry_after"):
            if k in logs_out:
                extra[k] = logs_out[k]

    if large or not series:
        cv = await call_view_many(
            chain_id, pair, "getReserves()", returns="uint112,uint112,uint32", blocks=_spread(lo, hi, points)
        )
        series = [
            {"block": r["block"], "reserve0": r["decoded"][0], "reserve1": r["decoded"][1]}
            for r in cv.get("results", [])
            if r.get("decoded") and len(r["decoded"]) >= 2
        ]
        source = "sampled_getReserves"
        if cv.get("rate_limited"):
            extra["rate_limited"] = True

    sampled = _downsample(series, points)
    out: dict = {
        "chain_id": chain_id,
        "pair": pair.lower(),
        "from_block": lo,
        "to_block": hi,
        "points": len(sampled),
        "source": source,
        "series": sampled,
        "max_drop": _max_single_step_drop(sampled),
    }
    out.update(extra)
    if large:
        out["note"] = (
            f"range {hi - lo} blocks > {_reserves_max_scan()}: sampled getReserves at {points} points "
            f"(a Sync-log scan would be ~{(hi - lo) // max(1, _logs_chunk())} getLogs windows). "
            "max_drop locates the drain between samples; narrow the range for exact Sync-log reserves."
        )
    return out
