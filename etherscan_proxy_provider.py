"""A read-only web3.py provider backed by Etherscan V2's ``proxy`` module.

Etherscan V2 exposes JSON-RPC-equivalent reads (eth_getCode, eth_getStorageAt,
eth_call, eth_getBlockByNumber, ...) for 70+ chains under ONE api key:

    GET https://api.etherscan.io/v2/api?chainid=N&module=proxy&action=eth_X&...&apikey=

This lets scryer's live-state tools (get_state / call_view / read_storage /
token_exposure) reach chains for which no native RPC URL is configured — the
"niche chain" case (e.g. Polygon Amoy 80002). Because this is a drop-in web3
provider, every existing web3-based read in onchain_state works unchanged; only
the transport differs.

Caveats:
- Native balance uses the ``account`` module (the proxy module has no
  eth_getBalance) and is adapted to JSON-RPC shape. account/balance is
  latest-only, so a pinned-block native balance falls back to latest (token
  balances via eth_call DO honor a historical ``tag`` where the node supports it).
- Read-only: send/estimate are not mapped.
- A throttle is turned into a JSON-RPC rate-limit error whose message the shared
  ``rpc_rate_limit_reason`` recognizes, so get_state/_call surface rate_limited
  instead of reading a throttle as "absent".
"""

from __future__ import annotations

import atexit
import contextlib
import itertools
import threading
import time
from typing import Any

from web3 import Web3
from web3.middleware import ExtraDataToPOAMiddleware
from web3.providers.base import JSONBaseProvider
from web3.types import RPCEndpoint, RPCResponse

import scryer_config
import scryer_http
from scryer_http import rate_limit_reason, retry_after_seconds
from scryer_logging import get_logger

_log = get_logger(__name__)

_ETHERSCAN_V2 = "https://api.etherscan.io/v2/api"

# Module-level shared client (avoid a socket leak from a per-provider client; one
# provider is built per tool call).
_HTTP = scryer_http.sync_client(timeout=20.0, headers={"User-Agent": "scryer-etherscan-proxy/1.0"})
atexit.register(_HTTP.close)

# Client-side pacing: the Etherscan free tier is 5 req/s per key, and a single
# get_state/token_exposure fans out ~14 eth_calls. Without pacing those burst past the
# limit and come back throttled (empty state). Serialize to <5/s across ALL providers
# sharing this process/key. (SCRYER_ETHERSCAN_MIN_INTERVAL overrides, e.g. for a Pro key.)
_RATE_LOCK = threading.Lock()
_last_request = [0.0]


def _min_interval() -> float:
    raw = scryer_config.get("SCRYER_ETHERSCAN_MIN_INTERVAL")
    try:
        # Default ~2.8 req/s: safely under the observed 3/s free-tier limit (some keys are
        # 3/s, not 5/s). Lower it via the env var for a Pro key (e.g. 0.05 for ~20/s).
        return max(0.0, float(raw)) if raw else 0.35
    except (TypeError, ValueError):
        return 0.35


def _pace() -> None:
    interval = _min_interval()
    with _RATE_LOCK:
        wait = interval - (time.monotonic() - _last_request[0])
        if wait > 0:
            time.sleep(wait)
        _last_request[0] = time.monotonic()


class _ProxyThrottle(Exception):
    def __init__(self, reason: str, retry_after: int | None):
        super().__init__(reason)
        self.reason = reason
        self.retry_after = retry_after


class _Unsupported(Exception):
    pass


def _hexify(v: Any) -> str:
    """Normalize a web3 block/position param to the hex string Etherscan expects."""
    if isinstance(v, bool):  # guard: bool is an int subclass
        return "0x1" if v else "0x0"
    if isinstance(v, int):
        return hex(v)
    if isinstance(v, (bytes, bytearray)):
        return "0x" + bytes(v).hex()
    return str(v)


class EtherscanProxyProvider(JSONBaseProvider):
    """Minimal read-only web3 provider over Etherscan V2's proxy/account modules."""

    def __init__(self, chain_id: int, api_key: str):
        super().__init__()
        self.chain_id = int(chain_id)
        self._api_key = api_key
        self._ids = itertools.count(1)
        self.endpoint_uri = f"etherscan-v2-proxy://chainid/{self.chain_id}"

    def is_connected(self, show_traceback: bool = False) -> bool:
        return bool(self._api_key)

    # -- HTTP --------------------------------------------------------------- #
    def _get(self, params: dict, _retry: bool = True) -> Any:
        q = {"chainid": str(self.chain_id), "apikey": self._api_key, **params}
        _pace()  # stay under the key's per-sec limit so fan-out reads aren't throttled
        r = _HTTP.get(_ETHERSCAN_V2, params=q)
        reason = rate_limit_reason(r)  # status-based (429/403/503)
        ra = retry_after_seconds(r)
        body: Any = None
        if not reason:
            body = r.json()
            # App-level throttle: the account/proxy modules report it as an HTTP-200
            # status:"0" wrapper with throttle phrasing ("Max calls per sec rate limit reached").
            if isinstance(body, dict) and str(body.get("status")) == "0":
                res = body.get("result")
                text = f"{body.get('message') or ''} {res if isinstance(res, str) else ''}"
                reason = rate_limit_reason(r, body_text=text)
        if reason:
            if _retry:
                time.sleep(max(_min_interval(), float(ra or 0)))  # back off once, then retry
                return self._get(params, _retry=False)
            raise _ProxyThrottle(reason, ra)
        return body

    # -- web3 provider interface ------------------------------------------- #
    def make_request(self, method: RPCEndpoint, params: Any) -> RPCResponse:
        rid = next(self._ids)
        try:
            result = self._dispatch(str(method), list(params or []))
        except _ProxyThrottle as t:
            # -32005 + "rate limit" so rpc_rate_limit_reason matches when web3 raises.
            return {"jsonrpc": "2.0", "id": rid, "error": {"code": -32005, "message": f"rate limit: {t.reason}"}}
        except _Unsupported as u:
            return {"jsonrpc": "2.0", "id": rid, "error": {"code": -32601, "message": str(u)}}
        except Exception as e:  # noqa: BLE001 - surface as a JSON-RPC error, web3 will raise
            return {"jsonrpc": "2.0", "id": rid, "error": {"code": -32000, "message": f"etherscan-proxy: {e}"}}
        return {"jsonrpc": "2.0", "id": rid, "result": result}

    def _dispatch(self, method: str, params: list) -> Any:
        # Canned metadata web3 asks for during setup/formatting (no network needed).
        if method == "eth_chainId":
            return hex(self.chain_id)
        if method == "net_version":
            return str(self.chain_id)
        if method == "web3_clientVersion":
            return "scryer-etherscan-proxy/1.0"

        # Native balance: the proxy module has no eth_getBalance -> use the account module.
        if method == "eth_getBalance":
            body = self._get({"module": "account", "action": "balance", "address": params[0], "tag": "latest"})
            result = body.get("result") if isinstance(body, dict) else None
            if str(body.get("status")) == "1" and isinstance(result, str) and result.isdigit():
                return hex(int(result))
            raise RuntimeError((result if isinstance(result, str) else None) or "balance unavailable")

        # Everything else -> the proxy module. Map params positionally per action.
        builder = _PROXY_ACTIONS.get(method)
        if builder is None:
            raise _Unsupported(f"{method} not supported by the Etherscan proxy provider")
        body = self._get({"module": "proxy", "action": method, **builder(params)})
        if isinstance(body, dict):
            if body.get("error"):
                err = body["error"]
                raise RuntimeError(err.get("message") if isinstance(err, dict) else str(err))
            if "result" in body:
                return body["result"]
            if str(body.get("status")) == "0":
                res = body.get("result")
                raise RuntimeError((res if isinstance(res, str) else None) or body.get("message") or "proxy error")
        return body


def _call_params(p: list) -> dict:
    tx = p[0] if p and isinstance(p[0], dict) else {}
    return {
        "to": tx.get("to"),
        "data": tx.get("data") or tx.get("input") or "0x",
        "tag": _hexify(p[1]) if len(p) > 1 else "latest",
    }


def make_web3(chain_id: int, rpc_url: str = "") -> tuple[Web3, str]:
    """Build a read-only Web3 for ``chain_id``, with the niche-chain proxy fallback.

    Resolution: an explicit ``rpc_url`` -> the configured native RPC -> the Etherscan V2
    proxy provider (needs ETHERSCAN_API_KEY) for chains with no native node. POA middleware
    is injected so get_block works on POA chains. Returns ``(w3, label)``. Raises if there is
    no native RPC and no API key.

    This is the single source of truth shared by onchain_state._w3 and download_contract's
    RPC paths, so a niche chain never silently falls back to the wrong (default BSC) node.
    """
    url = rpc_url or scryer_config.get_rpc_url(chain_id)
    if url:
        provider: Any = Web3.HTTPProvider(url)
        label = url
    else:
        key = scryer_config.get("ETHERSCAN_API_KEY")
        if not key:
            raise RuntimeError(
                f"no RPC configured for chain {chain_id} and no ETHERSCAN_API_KEY for the Etherscan-proxy fallback"
            )
        provider = EtherscanProxyProvider(chain_id, key)
        label = f"etherscan-v2-proxy:{chain_id}"
    w3 = Web3(provider)
    with contextlib.suppress(Exception):
        w3.middleware_onion.inject(ExtraDataToPOAMiddleware, layer=0)
    return w3, label


# method -> (params -> Etherscan proxy query fields)
_PROXY_ACTIONS: dict[str, Any] = {
    "eth_getCode": lambda p: {"address": p[0], "tag": _hexify(p[1]) if len(p) > 1 else "latest"},
    "eth_getStorageAt": lambda p: {
        "address": p[0],
        "position": _hexify(p[1]),
        "tag": _hexify(p[2]) if len(p) > 2 else "latest",
    },
    "eth_call": _call_params,
    "eth_getBlockByNumber": lambda p: {"tag": _hexify(p[0]), "boolean": "true" if (len(p) > 1 and p[1]) else "false"},
    "eth_blockNumber": lambda p: {},
    "eth_gasPrice": lambda p: {},
    "eth_getTransactionCount": lambda p: {"address": p[0], "tag": _hexify(p[1]) if len(p) > 1 else "latest"},
    "eth_getTransactionReceipt": lambda p: {"txhash": p[0]},
    "eth_getTransactionByHash": lambda p: {"txhash": p[0]},
}
