import argparse
import atexit
import datetime as dt
import os
import re
import sys
from pathlib import Path
from typing import Any

import cbor2  # pip install cbor2 (for metadata parsing)
import httpx
import orjson
from hexbytes import HexBytes
from web3 import Web3

import scryer_config
import scryer_http
from decompilers import decompile_with_heimdall, decompile_with_panoramix
from scryer_logging import get_logger

_log = get_logger(__name__)

# Loads .env once for the whole process (idempotent, safe in tests).
scryer_config.load()

# Module-level shared sync client. Preserves the historical 20s timeout
# and bespoke User-Agent while picking up retries / pool limits from
# scryer_http.
HTTP = scryer_http.sync_client(
    timeout=20.0,
    headers={"User-Agent": "bscscan-contract-downloader/1.0"},
)
atexit.register(HTTP.close)

BASE58_ALPHABET = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"

IPFS_GATEWAYS = [
    "https://w3s.link",
    "https://dweb.link",
    "https://ipfs.io",
    "https://gateway.pinata.cloud",
    "https://cloudflare-ipfs.com",
]

# Default RPC URL (can be overridden by env/CLI)
DEFAULT_RPC_URL = os.getenv("RPC_URL") or os.getenv("BSC_RPC_URL") or "https://bsc-dataseed.binance.org"

# Optional archive RPC for recovering bytecode of contracts that self-destructed
# in the same tx as the exploit. Live RPCs return b"" / "0x" for these addresses;
# an archive node serves the historic state. Configure via CLI or env.
DEFAULT_ARCHIVE_RPC_URL = os.getenv("ARCHIVE_RPC_URL") or ""


def _fetch_archive_bytecode(
    *,
    archive_rpc_url: str,
    address: str,
    block_number: int | None,
    primary_rpc_url: str,
    tx_hash: str | None,
) -> tuple[str, int] | None:
    """Try to fetch historic bytecode for ``address`` against an archive node.

    Returns ``(bytecode_hex, resolved_block)`` on success (``bytecode_hex``
    starts with ``0x`` and is non-empty), or ``None`` if recovery fails.

    Exactly one of ``block_number`` or ``tx_hash`` should be set. When a tx
    hash is supplied, the resolved block is ``txBlock - 1`` (read from the
    primary RPC, since the archive node is typically not used for routine
    reads).
    """
    if not archive_rpc_url:
        return None
    if block_number is None and not tx_hash:
        return None
    try:
        target_block: int
        if tx_hash:
            primary = Web3(Web3.HTTPProvider(primary_rpc_url))
            tx = primary.eth.get_transaction(HexBytes(tx_hash))
            tx_block = tx.get("blockNumber") if isinstance(tx, dict) else getattr(tx, "blockNumber", None)
            if tx_block is None:
                _log.warning("Archive recovery: tx %s has no blockNumber yet", tx_hash)
                return None
            target_block = tx_block - 1
        else:
            assert block_number is not None
            target_block = block_number

        archive = Web3(Web3.HTTPProvider(archive_rpc_url))
        raw = archive.eth.get_code(Web3.to_checksum_address(address), block_identifier=target_block)
        bytecode_hex = raw.hex() if isinstance(raw, (bytes, bytearray)) else str(raw)
        if not bytecode_hex.startswith("0x"):
            bytecode_hex = "0x" + bytecode_hex
        if bytecode_hex == "0x" or len(bytecode_hex) < 4:
            _log.warning("Archive recovery: empty bytecode at block %s for %s", target_block, address)
            return None
        return bytecode_hex, target_block
    except Exception as e:
        _log.warning("Archive recovery failed (%s): %s", type(e).__name__, e)
        return None


def normalize_address(address: str) -> str:
    address = extract_address(address)
    if isinstance(address, str) and address.startswith("0x") and len(address) == 42:
        return "0x" + address[2:].lower()
    return address


def eip1967_slot(tag: str) -> int:
    return int.from_bytes(Web3.keccak(text=tag), "big") - 1


EIP1967_IMPLEMENTATION_SLOT = eip1967_slot("eip1967.proxy.implementation")
EIP1967_BEACON_SLOT = eip1967_slot("eip1967.proxy.beacon")
# Legacy OpenZeppelin / zeppelinos proxies (e.g. USDC's FiatTokenProxy) store the
# implementation at keccak256("org.zeppelinos.proxy.implementation") — note: NO
# minus-1, unlike the EIP-1967 scheme above.
ZOS_IMPLEMENTATION_SLOT = int.from_bytes(Web3.keccak(text="org.zeppelinos.proxy.implementation"), "big")


def _parse_storage_address(value: bytes) -> str | None:
    if not value:
        return None
    if len(value) < 20:
        return None
    addr_bytes = value[-20:]
    if int.from_bytes(addr_bytes, "big") == 0:
        return None
    return "0x" + addr_bytes.hex()


def try_get_storage_address(w3: Web3, address: str, slot: int) -> str | None:
    try:
        raw = w3.eth.get_storage_at(Web3.to_checksum_address(address), slot)
    except Exception:
        return None
    return _parse_storage_address(raw)


def try_call_implementation(w3: Web3, address: str) -> str | None:
    # bytes4(keccak256("implementation()")) == 0x5c60da1b
    data = bytes.fromhex("5c60da1b")
    try:
        raw = w3.eth.call({"to": Web3.to_checksum_address(address), "data": data})
    except Exception:
        return None
    if not isinstance(raw, (bytes, bytearray)) or len(raw) < 32:
        return None
    return _parse_storage_address(bytes(raw))


def try_extract_eip1167_implementation(bytecode: bytes) -> str | None:
    # EIP-1167 minimal proxy runtime code:
    # 0x363d3d373d3d3d363d73<20-byte impl>5af43d82803e903d91602b57fd5bf3
    prefix = bytes.fromhex("363d3d373d3d3d363d73")
    suffix = bytes.fromhex("5af43d82803e903d91602b57fd5bf3")
    if len(bytecode) == len(prefix) + 20 + len(suffix) and bytecode.startswith(prefix) and bytecode.endswith(suffix):
        return "0x" + bytecode[len(prefix) : len(prefix) + 20].hex()
    return None


def resolve_proxy_targets(chain_id: int, address: str, rpc_url: str) -> tuple[list[str], dict]:
    """
    Best-effort proxy resolution:
    - EIP-1967 implementation slot
    - EIP-1967 beacon slot + beacon.implementation()
    - EIP-1167 minimal proxy runtime code
    """
    address = normalize_address(address)
    w3 = Web3(Web3.HTTPProvider(rpc_url))
    result: dict = {"chain_id": chain_id, "address": address, "rpc_url": rpc_url, "proxy": {}}

    try:
        code = w3.eth.get_code(Web3.to_checksum_address(address))
    except Exception as e:
        result["proxy"]["error"] = f"get_code failed: {type(e).__name__}"
        return [address], result

    eip1167_impl = try_extract_eip1167_implementation(bytes(code))
    if eip1167_impl:
        result["proxy"]["eip1167_minimal_proxy"] = True
        result["proxy"]["implementation"] = normalize_address(eip1167_impl)
        return [address, normalize_address(eip1167_impl)], result

    eip1967_impl = try_get_storage_address(w3, address, EIP1967_IMPLEMENTATION_SLOT)
    if eip1967_impl:
        result["proxy"]["eip1967_implementation_slot"] = True
        result["proxy"]["implementation"] = normalize_address(eip1967_impl)
        return [address, normalize_address(eip1967_impl)], result

    # Legacy zeppelinos implementation slot (pre-EIP-1967; e.g. USDC FiatTokenProxy).
    zos_impl = try_get_storage_address(w3, address, ZOS_IMPLEMENTATION_SLOT)
    if zos_impl:
        result["proxy"]["zeppelinos_implementation_slot"] = True
        result["proxy"]["implementation"] = normalize_address(zos_impl)
        return [address, normalize_address(zos_impl)], result

    beacon = try_get_storage_address(w3, address, EIP1967_BEACON_SLOT)
    if beacon:
        result["proxy"]["eip1967_beacon_slot"] = True
        result["proxy"]["beacon"] = normalize_address(beacon)
        beacon_impl = try_call_implementation(w3, beacon) or try_get_storage_address(
            w3, beacon, EIP1967_IMPLEMENTATION_SLOT
        )
        if beacon_impl:
            result["proxy"]["implementation"] = normalize_address(beacon_impl)
            return [address, normalize_address(beacon_impl)], result

    # Some proxies expose implementation() directly (non-standard but common).
    direct_impl = try_call_implementation(w3, address)
    if direct_impl:
        result["proxy"]["implementation_method"] = "implementation()"
        result["proxy"]["implementation"] = normalize_address(direct_impl)
        return [address, normalize_address(direct_impl)], result

    result["proxy"]["detected"] = False
    return [address], result


def json_dumps(data, *, indent: int | None = 2) -> str:
    option = orjson.OPT_INDENT_2 if indent else 0
    return orjson.dumps(data, option=option).decode("utf-8")


def json_loads(data: str):
    return orjson.loads(data)


def base58_encode(data: bytes) -> str:
    if not data:
        return ""
    num = int.from_bytes(data, "big")
    encoded = bytearray()
    while num:
        num, rem = divmod(num, 58)
        encoded.append(BASE58_ALPHABET[rem])
    # preserve leading zeros
    n_pad = len(data) - len(data.lstrip(b"\x00"))
    encoded.extend(BASE58_ALPHABET[0] for _ in range(n_pad))
    encoded.reverse()
    return encoded.decode("ascii")


def ipfs_cid_from_multihash(multihash: bytes) -> str:
    return base58_encode(multihash)


def expand_content_urls(url: str) -> list[str]:
    if not isinstance(url, str) or not url:
        return []
    url = url.strip()

    if url.startswith("dweb:/ipfs/"):
        cid = url[len("dweb:/ipfs/") :]
        return [f"{gw}/ipfs/{cid}" for gw in IPFS_GATEWAYS]
    if url.startswith("ipfs://"):
        rest = url[len("ipfs://") :]
        if rest.startswith("ipfs/"):
            rest = rest[len("ipfs/") :]
        return [f"{gw}/ipfs/{rest}" for gw in IPFS_GATEWAYS]
    if url.startswith("/ipfs/"):
        cid = url[len("/ipfs/") :]
        return [f"{gw}/ipfs/{cid}" for gw in IPFS_GATEWAYS]
    if url.startswith("http://") or url.startswith("https://"):
        return [url]
    return []


def extract_address(value: str) -> str:
    if not isinstance(value, str):
        return value
    match = re.search(r"0x[a-fA-F0-9]{40}", value)
    return match.group(0) if match else value


# 允許使用 BscScan API key (環境變量)
BSC_SCAN_API_KEY = os.getenv("BSCSCAN_API_KEY") or os.getenv("BSC_SCAN_API_KEY")


def get_sourcify_source(chain_id: int, address: str):
    """優先 Sourcify API 抓取源碼"""
    address = address.lower()

    # 1. 檢查狀態
    check_url = "https://sourcify.dev/server/check-by-addresses"
    params = {"addresses": address, "chainIds": str(chain_id)}
    response = HTTP.get(check_url, params=params)
    if response.status_code != 200:
        return None, None, "Sourcify check failed"

    status = json_loads(response.text) if response.text else None
    match_type = None
    # 新版 API 回傳 list，舊版可能回 dict
    if isinstance(status, list):
        for item in status:
            if item.get("address", "").lower() == address and item.get("status") in ["perfect", "partial"]:
                match_type = item.get("status")
                break
    elif (
        isinstance(status, dict)
        and address in status
        and status[address]
        and status[address][0].get("status") in ["perfect", "partial"]
    ):
        match_type = status[address][0].get("status")
    if not match_type:
        return None, None, f"Not verified on Sourcify: {status}"

    # 2. 下載 sources (新版 API 使用 full_match/partial_match 路徑)
    repo_match_type = "full_match" if match_type in ["perfect", "full_match"] else "partial_match"
    base_url = f"https://repo.sourcify.dev/contracts/{repo_match_type}/{chain_id}/{address}"

    sources = {}

    # 2a. 嘗試 sources.json (若存在會包含 content)
    sources_url = f"{base_url}/sources.json"
    r_sources = HTTP.get(sources_url)
    if r_sources.status_code == 200 and r_sources.text.strip():
        try:
            sources_data = json_loads(r_sources.text)
            sources = {
                path: data["content"] for path, data in sources_data.get("sources", {}).items() if "content" in data
            }
        except Exception:
            pass  # 若解析失敗，退回 metadata 模式

    # 2b. 下載 metadata（總會存在），並用其中的檔名去 /sources/{path} 拉檔案
    metadata_url = f"{base_url}/metadata.json"
    metadata_r = HTTP.get(metadata_url)
    metadata = json_loads(metadata_r.text) if metadata_r.status_code == 200 and metadata_r.text else {}

    if not sources and metadata.get("sources"):
        for path, info in metadata["sources"].items():
            if "content" in info:
                sources[path] = info["content"]
                continue
            file_url = f"{base_url}/sources/{path}"
            file_r = HTTP.get(file_url)
            if file_r.status_code == 200:
                sources[path] = file_r.text
                continue
            # fallback: 若 metadata.urls 有其他位置，可再嘗試
            for url in info.get("urls", []):
                try:
                    alt_r = HTTP.get(url)
                    if alt_r.status_code == 200:
                        sources[path] = alt_r.text
                        break
                except Exception:
                    continue

    if sources:
        # Stash match_type into metadata so download_meta.json persists it.
        # "perfect" / "full_match" means deployed bytecode (incl. metadata
        # trailer) matches source 1:1. "partial_match" only guarantees runtime
        # behavior — variable names, comments, hex-literal layout may differ.
        # Downstream LLM/regex analysis should treat partial as "trustworthy
        # for behavior, not for cosmetic specifics".
        if isinstance(metadata, dict):
            metadata.setdefault("sourcify_match_type", match_type)
        return sources, metadata, f"Sourcify success ({match_type})"
    return None, None, "Sourcify download failed"


_BLOCKSCOUT_BASE_URLS: dict[int, list[str]] = {
    1: ["https://eth.blockscout.com/api/v2"],
    10: ["https://optimism.blockscout.com/api/v2"],
    56: [
        "https://bsc.blockscout.com/api/v2",
        "https://blockscout.com/bnb/mainnet/api/v2",
    ],
    137: ["https://polygon.blockscout.com/api/v2"],
    250: ["https://ftmscan.blockscout.com/api/v2"],
    8453: ["https://base.blockscout.com/api/v2"],
    42161: ["https://arbitrum.blockscout.com/api/v2"],
    43114: ["https://snowtrace.io/api/v2"],
}


def get_blockscout_source(chain_id: int, address: str):
    """Fallback: per-chain Blockscout instance API."""
    bases = _BLOCKSCOUT_BASE_URLS.get(chain_id, [])
    if not bases:
        return None, None, f"no Blockscout base URL configured for chain_id={chain_id}"
    api_urls = [f"{base}/smart-contracts/{address.lower()}" for base in bases]
    errors = []
    for api_url in api_urls:
        r = HTTP.get(api_url)
        if r.status_code != 200:
            errors.append(f"{api_url} -> HTTP {r.status_code}")
            continue
        data = json_loads(r.text) if r.text else {}
        # 提取 verified_source_code (如果有)
        source_code = data.get("verified_source_code", {})
        if source_code:
            # 解析成 dict (可能多文件)
            sources = {file["name"]: file["source_code"] for file in source_code.get("files", [])}
            metadata = {
                "compiler": {"version": source_code.get("compiler_version", "")},
                "settings": {"optimizer": {"runs": source_code.get("optimization_used", False)}},
            }
            return sources, metadata, f"Blockscout success ({api_url})"
        errors.append(f"{api_url} -> no verified_source_code")
    return None, None, " ; ".join(errors) if errors else "Blockscout failed"


def get_bscscan_source(chain_id: int, address: str):
    """使用 Etherscan API V2 / BscScan API 抓取源碼 (需要 API Key)"""
    if not BSC_SCAN_API_KEY:
        return None, None, "BscScan API key not provided (set BSCSCAN_API_KEY in .env)"

    address = extract_address(address)

    candidates: list[tuple[str, dict, str]] = [
        (
            "https://api.etherscan.io/v2/api",
            {
                "chainid": str(chain_id),
                "module": "contract",
                "action": "getsourcecode",
                "address": address,
                "apikey": BSC_SCAN_API_KEY,
            },
            "Etherscan API V2",
        ),
        (
            "https://api.bscscan.com/api",
            {
                "module": "contract",
                "action": "getsourcecode",
                "address": address,
                "apikey": BSC_SCAN_API_KEY,
            },
            "BscScan API (legacy)",
        ),
    ]

    errors: list[str] = []
    for api_url, params, label in candidates:
        r = HTTP.get(api_url, params=params)
        if r.status_code != 200:
            errors.append(f"{label}: HTTP {r.status_code}")
            continue

        try:
            resp = json_loads(r.text) if r.text else {}
        except Exception:
            errors.append(f"{label}: invalid JSON")
            continue

        if resp.get("status") != "1" or not resp.get("result"):
            errors.append(f"{label}: {resp.get('message')}")
            continue

        result = resp["result"][0] if isinstance(resp["result"], list) else resp["result"]
        if not isinstance(result, dict):
            errors.append(f"{label}: unexpected result type {type(result)}")
            continue

        source_code_raw = result.get("SourceCode") or result.get("sourceCode") or ""
        if not isinstance(source_code_raw, str):
            source_code_raw = str(source_code_raw)

        source_code_str = source_code_raw.strip()
        sources = {}

        # 多文件：常見格式是 {{ ...json... }}（外面多包一層大括號）
        if source_code_str.startswith("{{") and source_code_str.endswith("}}") and len(source_code_str) >= 4:
            json_str = source_code_str[1:-1]
            try:
                parsed = json_loads(json_str)
                if isinstance(parsed, dict) and isinstance(parsed.get("sources"), dict):
                    sources = {
                        path: data.get("content", "")
                        for path, data in parsed["sources"].items()
                        if isinstance(data, dict) and isinstance(data.get("content"), str)
                    }
            except Exception:
                pass
        elif source_code_str.startswith("{") and source_code_str.endswith("}"):
            try:
                parsed = json_loads(source_code_str)
                if isinstance(parsed, dict) and isinstance(parsed.get("sources"), dict):
                    sources = {
                        path: data.get("content", "")
                        for path, data in parsed["sources"].items()
                        if isinstance(data, dict) and isinstance(data.get("content"), str)
                    }
            except Exception:
                pass

        if not sources:
            sources = {"combined_source.sol": source_code_raw}

        # Etherscan returns an empty SourceCode when the contract is not
        # verified — don't treat that as success or we silently write 0-byte
        # files and downstream tools (regex/slither/LLM) get nothing.
        if not any((content or "").strip() for content in sources.values()):
            return None, None, f"contract not verified on {label} (empty SourceCode)"

        metadata = {
            "compiler": {"version": result.get("CompilerVersion", "")},
            "settings": {
                "optimizer": {
                    "enabled": result.get("OptimizationUsed", ""),
                    "runs": result.get("Runs", ""),
                }
            },
            "contract": {
                "contract_name": result.get("ContractName", ""),
                "implementation": result.get("Implementation", ""),
                "proxy": result.get("Proxy", ""),
            },
        }
        return sources, metadata, f"BscScan success ({label})"

    return None, None, " ; ".join(errors) if errors else "BscScan failed"


def extract_from_bytecode_metadata(chain_id: int, address: str, rpc_url: str = DEFAULT_RPC_URL):
    """最後手段: 從鏈上 bytecode 解析 metadata → IPFS/Swarm"""
    w3 = Web3(Web3.HTTPProvider(rpc_url))
    bytecode = w3.eth.get_code(Web3.to_checksum_address(address)).hex()

    # 提取 metadata (Solidity metadata 在 bytecode 結尾，CBOR 編碼)
    # 最後 2 bytes 是 offset (通常 0x00 0xA1)，然後 CBOR data
    if len(bytecode) < 4:
        return None, None, "Invalid bytecode"

    # 移除 0x prefix，轉 bytes
    bytecode_bytes = bytes.fromhex(bytecode[2:])
    # 找 metadata 長度 (最後 2 bytes)
    metadata_length = int.from_bytes(bytecode_bytes[-2:], "big")
    if metadata_length <= 0:
        return None, None, "No metadata length marker"
    if metadata_length + 2 > len(bytecode_bytes):
        return None, None, f"Metadata length {metadata_length} exceeds bytecode length {len(bytecode_bytes)}"

    metadata_start = len(bytecode_bytes) - 2 - metadata_length
    metadata_bytes = bytecode_bytes[metadata_start:-2]

    try:
        metadata_decoded = cbor2.loads(metadata_bytes)
        if not isinstance(metadata_decoded, dict):
            return None, None, f"Unexpected metadata type {type(metadata_decoded)}"
        ipfs_val = metadata_decoded.get("ipfs")
        ipfs_cid = None
        if isinstance(ipfs_val, (bytes, bytearray)):
            ipfs_cid = ipfs_cid_from_multihash(bytes(ipfs_val))
        elif isinstance(ipfs_val, str):
            ipfs_cid = ipfs_val

        cbor_meta = {}
        solc_val = metadata_decoded.get("solc")
        if isinstance(solc_val, (bytes, bytearray)) and len(solc_val) == 3:
            cbor_meta["solc"] = f"{solc_val[0]}.{solc_val[1]}.{solc_val[2]}"
        elif solc_val is not None:
            cbor_meta["solc"] = solc_val.hex() if isinstance(solc_val, (bytes, bytearray)) else str(solc_val)
        if ipfs_cid:
            cbor_meta["ipfs"] = ipfs_cid

        if not ipfs_cid:
            return None, {"cbor": cbor_meta}, "No IPFS hash in metadata"

        metadata_json = None
        metadata_url = None
        gateway_errors = []
        for gateway in IPFS_GATEWAYS:
            url = f"{gateway}/ipfs/{ipfs_cid}"
            try:
                r = HTTP.get(url, timeout=60.0)
            except httpx.RequestError as e:
                gateway_errors.append(f"{gateway}: {type(e).__name__}")
                continue
            if r.status_code != 200 or not r.text:
                msg = r.text.strip() if r.text else ""
                gateway_errors.append(f"{gateway}: HTTP {r.status_code}{' ' + msg[:120] if msg else ''}")
                continue
            try:
                metadata_json = json_loads(r.text)
                metadata_url = url
                break
            except Exception:
                gateway_errors.append(f"{gateway}: invalid JSON")
                continue

        if not isinstance(metadata_json, dict):
            detail = "; ".join(gateway_errors) if gateway_errors else "unknown"
            return None, {"cbor": cbor_meta}, f"IPFS metadata unavailable: {ipfs_cid} ({detail})"

        sources = {}
        sources_info = metadata_json.get("sources", {})
        if isinstance(sources_info, dict):
            for path, info in sources_info.items():
                if isinstance(info, dict) and isinstance(info.get("content"), str):
                    sources[path] = info["content"]
                    continue
                urls = info.get("urls", []) if isinstance(info, dict) else []
                for u in urls:
                    for http_url in expand_content_urls(u):
                        try:
                            fr = HTTP.get(http_url, timeout=60.0)
                        except httpx.RequestError:
                            continue
                        if fr.status_code == 200 and fr.text is not None:
                            sources[path] = fr.text
                            break
                    if path in sources:
                        break

        metadata_out: dict[str, Any] = {"cbor": cbor_meta, "metadata": metadata_json}
        if metadata_url:
            metadata_out["metadata_url"] = metadata_url

        if sources:
            return sources, metadata_out, "Metadata IPFS success"
        return None, metadata_out, "IPFS metadata fetched but no sources downloaded"
    except Exception as e:
        return None, None, f"Metadata parse error: {e}"


def sanitize_relpath(relpath: str) -> Path:
    relpath = (relpath or "").strip().replace("\\", "/")
    relpath = relpath.lstrip("/")
    parts: list[str] = []
    for part in relpath.split("/"):
        if part in {"", "."}:
            continue
        if part == "..":
            parts.append("__")
            continue
        safe = re.sub(r'[<>:"|?*\x00-\x1f]', "_", part)
        parts.append(safe)
    return Path(*parts) if parts else Path("combined_source.sol")


def save_sources(
    sources: dict,
    chain_id: int,
    address: str,
    *,
    output_dir: str = "sources",
    layout: str = "flat",
    extra_metadata: dict | None = None,
):
    """存源碼到文件 (flat 或 tree layout)"""
    output_root = Path(output_dir)
    output_root.mkdir(parents=True, exist_ok=True)

    address = normalize_address(address)
    written: list[str] = []

    if layout == "tree":
        contract_root = output_root / f"{chain_id}_{address}"
        contract_root.mkdir(parents=True, exist_ok=True)
        for relpath, code in sources.items():
            rel = sanitize_relpath(str(relpath))
            out_path = contract_root / rel
            if out_path.suffix == "":
                out_path = out_path.with_suffix(".sol")
            out_path.parent.mkdir(parents=True, exist_ok=True)
            out_path.write_text(code or "", encoding="utf-8")
            written.append(out_path.relative_to(output_root).as_posix())

        meta = {
            "chain_id": chain_id,
            "address": address,
            "generated_at": dt.datetime.now(dt.UTC).isoformat(),
            "files_written": written,
        }
        if extra_metadata:
            meta.update(extra_metadata)
        (contract_root / "download_meta.json").write_text(json_dumps(meta, indent=2) + "\n", encoding="utf-8")
    else:
        for relpath, code in sources.items():
            safe_path = str(relpath).replace("/", "_").replace("\\", "_")
            filename = f"{chain_id}_{address}_{safe_path}"
            if not Path(filename).suffix:
                filename += ".sol"
            out_path = output_root / filename
            out_path.write_text(code or "", encoding="utf-8")
            written.append(out_path.relative_to(output_root).as_posix())

        meta = {
            "chain_id": chain_id,
            "address": address,
            "generated_at": dt.datetime.now(dt.UTC).isoformat(),
            "files_written": written,
        }
        if extra_metadata:
            meta.update(extra_metadata)
        (output_root / f"{chain_id}_{address}_download_meta.json").write_text(
            json_dumps(meta, indent=2) + "\n",
            encoding="utf-8",
        )

    _log.info("源碼已存到 ./%s/", output_dir)


# 主函數：針對你的合約一鍵抓取
def fetch_contract_source(
    chain_id: int,
    address: str,
    *,
    rpc_url: str = DEFAULT_RPC_URL,
    follow_proxy: bool = False,
    output_dir: str = "sources",
    layout: str = "flat",
    quiet: bool = False,
    archive_rpc_url: str = "",
    archive_tx_hash: str | None = None,
    archive_block: int | None = None,
) -> bool:
    root_address = normalize_address(address)
    _log.info("開始抓取 chainId=%s, 地址=%s 的源碼...", chain_id, root_address)

    # Honor the documented per-chain RPC env names (BSC_URL / POLYGON_URL / ETH_URL / …)
    # when the caller left the default — one RPC convention shared with
    # rpc_contract_discovery, and the correct chain's node instead of a single global.
    if rpc_url == DEFAULT_RPC_URL:
        rpc_url = scryer_config.get_rpc_url(chain_id) or rpc_url

    proxy_info = None
    targets = [root_address]
    if follow_proxy:
        targets, proxy_info = resolve_proxy_targets(chain_id, root_address, rpc_url)
        targets = [normalize_address(a) for a in targets]
        targets = list(dict.fromkeys(targets))  # preserve order, de-dup
        if len(targets) > 1:
            _log.info("🔎 Proxy detected, will also fetch implementation: %s", targets[1])
        else:
            _log.info("🔎 Proxy resolution: no implementation detected")

    def _dump_source(path: str, code: str) -> None:
        # quiet=False mode dumps fetched sources to stdout — this is the
        # data the user asked for, so it stays on print(). Re-encode through
        # stdout's codec with errors='replace' so a cp1252-only Windows
        # console can't raise UnicodeEncodeError mid-print and abort the
        # whole fetch (which used to leave sources/ empty despite a
        # "success" log line).
        encoding = getattr(sys.stdout, "encoding", None) or "utf-8"
        body = code[:1000] + "..." if len(code) > 1000 else code

        def _safe(text: str) -> str:
            return text.encode(encoding, errors="replace").decode(encoding, errors="replace")

        print(_safe(f"\n{'=' * 60}\n{path}\n{'=' * 60}"))
        print(_safe(body))

    def fetch_one(target: str):
        # 步驟 1: Sourcify
        sources, metadata, msg = get_sourcify_source(chain_id, target)
        if sources:
            _log.info("✅ %s", msg)
            if not quiet:
                metadata_str = json_dumps(metadata, indent=2)
                print("Metadata:", metadata_str[:500] + "..." if len(metadata_str) > 500 else metadata_str)
                for path, code in sources.items():
                    _dump_source(path, code)
            return sources, metadata, msg, "sourcify"
        _log.warning("Sourcify 失敗: %s", msg)

        # 步驟 2: Blockscout
        _log.info("Sourcify 無，嘗試 Blockscout...")
        sources, metadata, msg = get_blockscout_source(chain_id, target)
        if sources:
            _log.info("✅ %s", msg)
            if not quiet:
                print("Metadata:", json_dumps(metadata, indent=2))
                for path, code in sources.items():
                    _dump_source(path, code)
            return sources, metadata, msg, "blockscout"
        _log.warning("Blockscout 失敗: %s", msg)

        # 步驟 2b: BscScan (需 API key)
        _log.info("嘗試 BscScan API...")
        sources, metadata, msg = get_bscscan_source(chain_id, target)
        if sources:
            _log.info("✅ %s", msg)
            if not quiet:
                print("Metadata:", json_dumps(metadata, indent=2))
                for path, code in sources.items():
                    _dump_source(path, code)
            return sources, metadata, msg, "bscscan"
        _log.warning("BscScan 失敗: %s", msg)

        # 步驟 3: Bytecode metadata
        _log.info("Blockscout 無，嘗試從 bytecode 解析...")
        try:
            sources, metadata, msg = extract_from_bytecode_metadata(chain_id, target, rpc_url=rpc_url)
        except Exception as e:
            # A dead/unreachable RPC must not crash the whole fetch — degrade to
            # "no source via this method" so the caller gets a clean found:false
            # (e.g. an EOA, or a transient RPC outage) instead of a raw exception.
            _log.warning("bytecode-metadata 解析失敗 (RPC 問題?): %s", e)
            sources, metadata, msg = None, None, f"bytecode-metadata RPC failed: {e}"
        if sources:
            _log.info("✅ %s", msg)
            if not quiet:
                print("Metadata:", json_dumps(metadata, indent=2))
                for path, code in sources.items():
                    _dump_source(path, code)
            return sources, metadata, msg, "bytecode_metadata"

        return None, None, msg, None

    any_success = False
    for target in targets:
        target = normalize_address(target)
        if target != root_address:
            _log.info("跟隨下載 implementation: %s", target)

        sources, metadata, msg, method = fetch_one(target)
        if not sources:
            _log.warning("❌ 所有途徑失敗 (%s)，嘗試保存原始 bytecode...", msg)
            # Save bytecode-only with marker, optionally with a decompiled
            # pseudo-source if Heimdall/Panoramix is available locally.
            try:
                w3 = Web3(Web3.HTTPProvider(rpc_url))
                bytecode = w3.eth.get_code(Web3.to_checksum_address(target)).hex()
                recovered_from_archive_block: int | None = None
                if (not bytecode or bytecode == "0x") and archive_rpc_url:
                    _log.info(
                        "Live bytecode empty (likely self-destructed). "
                        "Attempting archive RPC recovery (tx=%s, block=%s)…",
                        archive_tx_hash,
                        archive_block,
                    )
                    archive_result = _fetch_archive_bytecode(
                        archive_rpc_url=archive_rpc_url,
                        address=target,
                        block_number=archive_block,
                        primary_rpc_url=rpc_url,
                        tx_hash=archive_tx_hash,
                    )
                    if archive_result:
                        bytecode, recovered_from_archive_block = archive_result
                        _log.info(
                            "✅ Archive RPC recovered bytecode at block %s (%d hex chars)",
                            recovered_from_archive_block,
                            len(bytecode),
                        )
                if bytecode and bytecode != "0x":
                    decompiled_text: str | None = None
                    decompiler_name: str | None = None
                    # Heimdall is generally higher-quality on modern bytecode;
                    # Panoramix is the Linux-only fallback. Either is "better
                    # than nothing" for unverified contracts.
                    decompiled_text = decompile_with_heimdall(bytecode)
                    if decompiled_text:
                        decompiler_name = "heimdall"
                    else:
                        decompiled_text = decompile_with_panoramix(bytecode)
                        if decompiled_text:
                            decompiler_name = "panoramix"

                    if decompiled_text:
                        _log.info("✅ Decompiled via %s (%d chars)", decompiler_name, len(decompiled_text))
                        # Tree layout puts decompiled .sol next to bytecode for
                        # downstream tooling that expects a .sol filename.
                        decompiled_sources = {
                            f"{target}.decompiled.sol": decompiled_text,
                            f"{target}.bytecode.hex": bytecode,
                        }
                        save_sources(
                            decompiled_sources,
                            chain_id,
                            target,
                            output_dir=output_dir,
                            layout=layout,
                            extra_metadata={
                                "root_address": root_address,
                                "download_method": f"decompiled_{decompiler_name}",
                                "decompiled": True,
                                "decompiler": decompiler_name,
                                "reason": msg,
                                "proxy_resolution": proxy_info,
                                "archive_recovered_block": recovered_from_archive_block,
                            },
                        )
                        _log.info("✅ Saved decompiled source — DOWNSTREAM CONSUMERS MUST TRUST OPCODES, NOT NAMING")
                        any_success = True
                        continue

                    # No decompiler available — fall through to BYTECODE_ONLY.
                    bytecode_sources = {
                        f"{target}.bytecode.hex": bytecode,
                        f"{target}.BYTECODE_ONLY": (
                            "# ⚠️ BYTECODE ONLY - NO VERIFIED SOURCE CODE\n"
                            "#\n"
                            f"# Contract: {target}\n"
                            f"# Chain ID: {chain_id}\n"
                            f"# Reason: {msg}\n"
                            "#\n"
                            "# Source code is not verified on Sourcify / Blockscout /\n"
                            "# Etherscan / IPFS metadata, AND no decompiler\n"
                            "# (Heimdall via WSL, Panoramix on Linux) is available\n"
                            "# locally to produce a pseudo-source.\n"
                            "#\n"
                            "# Install Heimdall:\n"
                            "#   wsl.exe -- bash -c 'curl -L https://get.bifrost.sh | bash && bifrost'\n"
                            "# Then re-run this download to populate {addr}.decompiled.sol.\n"
                        ),
                    }
                    save_sources(
                        bytecode_sources,
                        chain_id,
                        target,
                        output_dir=output_dir,
                        layout=layout,
                        extra_metadata={
                            "root_address": root_address,
                            "download_method": "bytecode_only",
                            "bytecode_only": True,
                            "reason": msg,
                            "proxy_resolution": proxy_info,
                            "archive_recovered_block": recovered_from_archive_block,
                        },
                    )
                    _log.info("✅ 已保存 bytecode (標記為 BYTECODE_ONLY)")
                    any_success = True
                else:
                    if archive_rpc_url:
                        _log.error(
                            "❌ 無法取得 bytecode (live + archive RPC both empty — verify --archive-tx/--archive-block)"
                        )
                    else:
                        _log.error(
                            "❌ 無法取得 bytecode (可能是 EOA 或已自毀的合約; 設定 ARCHIVE_RPC_URL "
                            "並提供 --archive-tx <hash> 可嘗試 recover)"
                        )
            except Exception as e:
                _log.error("❌ 保存 bytecode 失敗: %s", e)
            continue

        any_success = True
        save_sources(
            sources,
            chain_id,
            target,
            output_dir=output_dir,
            layout=layout,
            extra_metadata={
                "root_address": root_address,
                "download_method": method,
                "proxy_resolution": proxy_info,
                "metadata": metadata,
            },
        )

    return any_success


# 針對你的合約運行（BSC chainId 56）
if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Download verified contract source code via Sourcify/Blockscout/BscScan."
    )
    parser.add_argument("address", nargs="?", help="Contract address (0x...)")
    parser.add_argument("--chain-id", type=int, default=56, help="Chain ID (default: 56 for BSC)")
    parser.add_argument("--rpc-url", default=DEFAULT_RPC_URL, help="RPC URL for bytecode/proxy resolution.")
    parser.add_argument(
        "--follow-proxy", action="store_true", help="If address is a proxy, also download the implementation."
    )
    parser.add_argument("--output-dir", default="sources", help="Output directory (default: sources)")
    parser.add_argument(
        "--layout", choices=["flat", "tree"], default="flat", help="Save layout: flat filenames or tree per contract."
    )
    parser.add_argument("--quiet", action="store_true", help="Reduce output (do not print sources/metadata previews).")
    parser.add_argument(
        "--archive-rpc-url",
        default=DEFAULT_ARCHIVE_RPC_URL,
        help="Archive node URL for recovering bytecode of self-destructed contracts (env: ARCHIVE_RPC_URL).",
    )
    parser.add_argument(
        "--archive-tx",
        default=None,
        help="Tx hash whose blockNumber-1 will be queried on the archive node (typical exploit-tx use).",
    )
    parser.add_argument(
        "--archive-block",
        type=int,
        default=None,
        help="Explicit block number for archive bytecode recovery (overridden by --archive-tx if both set).",
    )
    args = parser.parse_args()

    chain_id = args.chain_id
    address = extract_address(
        args.address or os.getenv("CONTRACT_ADDRESS") or "0x3358758d8E362e4672fF2c63D65bdb35A7824451"
    )
    fetch_contract_source(
        chain_id,
        address,
        rpc_url=args.rpc_url,
        follow_proxy=args.follow_proxy,
        output_dir=args.output_dir,
        layout=args.layout,
        quiet=args.quiet,
        archive_rpc_url=args.archive_rpc_url,
        archive_tx_hash=args.archive_tx,
        archive_block=args.archive_block,
    )
