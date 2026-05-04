#!/usr/bin/env python3
from __future__ import annotations

import argparse
import datetime as dt
import json
import os
import subprocess
import sys
from pathlib import Path

from download_contract import DEFAULT_RPC_URL, fetch_contract_source
from scryer_logging import get_logger

_log = get_logger(__name__)


def read_targets(path: Path) -> list[dict]:
    data = json.loads(path.read_text(encoding="utf-8"))
    if isinstance(data, list):
        return [x for x in data if isinstance(x, dict)]
    raise ValueError("targets file must be a JSON array of objects")


def main() -> int:
    parser = argparse.ArgumentParser(description="Download contract sources for a target list and run audits.")
    parser.add_argument("--targets", required=True, help="Path to targets JSON (array).")
    parser.add_argument("--run-dir", default=None, help="Run directory (default: runs/run_<timestamp>).")

    parser.add_argument(
        "--rpc-url", default=os.getenv("RPC_URL") or DEFAULT_RPC_URL, help="Default RPC URL (per-target can override)."
    )
    parser.add_argument("--default-chain-id", type=int, default=56, help="Default chain id if missing in targets.")
    parser.add_argument("--follow-proxy", action="store_true", help="Follow proxy implementation by default.")
    parser.add_argument("--layout", choices=["flat", "tree"], default="tree", help="Downloader save layout.")
    parser.add_argument("--quiet", action="store_true", help="Reduce downloader output.")

    parser.add_argument("--download-only", action="store_true", help="Only download sources, do not run audits.")
    parser.add_argument("--audit-only", action="store_true", help="Only run audits (skip downloads).")

    # Audit options (passed to audit_contracts.py)
    parser.add_argument("--audit-group-by", choices=["contract", "chain", "all", "file"], default="contract")
    parser.add_argument("--model", default=os.getenv("OPENAI_MODEL", "gpt-4.1-mini"))
    parser.add_argument("--base-url", default=os.getenv("OPENAI_BASE_URL", "https://api.openai.com/v1"))
    parser.add_argument("--rpm", type=float, default=0.0, help="Rate limit OpenAI requests (requests per minute).")
    parser.add_argument("--max-input-chars", type=int, default=200_000)
    parser.add_argument("--max-chunk-chars", type=int, default=120_000)
    parser.add_argument("--force-map-reduce", action="store_true")
    parser.add_argument("--slither", action="store_true")
    parser.add_argument("--disable-regex-scan", action="store_true")
    parser.add_argument(
        "--regex-rules",
        action="append",
        default=[],
        metavar="PATH",
        help="Forward extra regex-rule JSON file(s) to audit_contracts.py.",
    )
    parser.add_argument(
        "--source-verify",
        choices=["off", "warn", "strict"],
        default="off",
        help="Forward --source-verify to audit_contracts.py.",
    )

    args = parser.parse_args()

    targets_path = Path(args.targets)
    targets = read_targets(targets_path)
    if not targets:
        _log.error("No targets found in: %s", targets_path)
        return 2

    run_id = dt.datetime.now(dt.UTC).strftime("run_%Y%m%d_%H%M%SZ")
    run_root = Path(args.run_dir) if args.run_dir else Path("runs") / run_id
    sources_dir = run_root / "sources"
    audit_dir = run_root / "audit"
    run_root.mkdir(parents=True, exist_ok=True)

    manifest: dict = {
        "run_id": run_id,
        "generated_at": dt.datetime.now(dt.UTC).isoformat(),
        "targets_file": targets_path.as_posix(),
        "run_dir": run_root.as_posix(),
        "sources_dir": sources_dir.as_posix(),
        "audit_dir": audit_dir.as_posix(),
        "download": {"layout": args.layout, "follow_proxy_default": args.follow_proxy, "rpc_url_default": args.rpc_url},
        "targets": [],
        "audit_command": None,
    }

    if not args.audit_only:
        sources_dir.mkdir(parents=True, exist_ok=True)
        for t in targets:
            addr = t.get("address") or t.get("addr")
            if not isinstance(addr, str) or not addr.strip():
                continue
            chain_id = int(t.get("chain_id") or t.get("chainId") or args.default_chain_id)
            rpc_url = t.get("rpc_url") or t.get("rpcUrl") or args.rpc_url
            follow_proxy = bool(t.get("follow_proxy")) if "follow_proxy" in t else args.follow_proxy

            ok = fetch_contract_source(
                chain_id,
                addr,
                rpc_url=str(rpc_url),
                follow_proxy=follow_proxy,
                output_dir=str(sources_dir),
                layout=args.layout,
                quiet=args.quiet,
            )
            manifest["targets"].append(
                {
                    "chain_id": chain_id,
                    "address": addr,
                    "rpc_url": rpc_url,
                    "follow_proxy": follow_proxy,
                    "download_ok": bool(ok),
                }
            )

    if args.download_only:
        (run_root / "pipeline_manifest.json").write_text(
            json.dumps(manifest, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
        )
        _log.info("Done (download-only). Run dir: %s", run_root)
        return 0

    audit_dir.mkdir(parents=True, exist_ok=True)
    cmd = [
        sys.executable,
        str(Path(__file__).with_name("audit_contracts.py")),
        "--sources-dir",
        str(sources_dir),
        "--out-dir",
        str(audit_dir),
        "--run-dir",
        str(audit_dir),
        "--group-by",
        args.audit_group_by,
        "--model",
        args.model,
        "--base-url",
        args.base_url,
        "--rpm",
        str(args.rpm),
        "--max-input-chars",
        str(args.max_input_chars),
        "--max-chunk-chars",
        str(args.max_chunk_chars),
    ]
    if args.force_map_reduce:
        cmd.append("--force-map-reduce")
    if args.slither:
        cmd.append("--slither")
    if args.disable_regex_scan:
        cmd.append("--disable-regex-scan")
    for rules_path in args.regex_rules or []:
        cmd.extend(["--regex-rules", str(rules_path)])
    if args.source_verify and args.source_verify != "off":
        cmd.extend(["--source-verify", args.source_verify])

    manifest["audit_command"] = cmd
    (run_root / "pipeline_manifest.json").write_text(
        json.dumps(manifest, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )

    _log.info("Running audit: %s", " ".join(cmd))
    proc = subprocess.run(cmd)
    return int(proc.returncode)


if __name__ == "__main__":
    raise SystemExit(main())
