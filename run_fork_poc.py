#!/usr/bin/env python3
"""Run a Foundry fork test as a LOCAL proof-of-concept — safely.

This is how the hunter turns a `Likely` finding into `Confirmed`: write the exploit as a
Foundry test, run it against a local fork of the chain, and let the pass/fail (an assertion
on attacker profit / protocol loss) decide.

WHY THIS IS SAFE — it only ever runs `forge test`:
  `forge test` executes entirely in a local REVM. `vm.createSelectFork(rpc, block)` pulls chain
  state in READ-ONLY (plain eth_call/eth_getStorageAt), and deploying the exploit deploys to the
  LOCAL fork, never to the real chain. There is no mechanism in `forge test` to send a
  transaction on-chain — broadcasting is exclusively a `forge script --broadcast` / `cast send`
  feature, which this runner never invokes and refuses in the test source. So a fork PoC never
  deploys to mainnet, never sends a tx, never touches live state.

RESIDUAL (accepted): `vm.createSelectFork(url)` is the mechanism of a fork test, so a test may
name an ARBITRARY url — the WSL host then issues JSON-RPC GET/POSTs to it. That is an SSRF vector
(a prompt-injected test could aim it at an internal endpoint), but it is bounded: forge test has no
channel to send the response anywhere (ffi off, fs_permissions empty, vm.rpc/writeFile blocked), so
it can only probe a reachable URL, not exfiltrate what it reads; stdout is redacted before return.
We do NOT block createSelectFork (it is the whole point) — the boundary is "forge test can read, not
write/escape", enforced by _FORBIDDEN + _HARDENED_TOML. Run PoCs only from contract source you trust.

Foundry lives in WSL here (/root/.foundry/bin), so forge is invoked through wsl.exe, and the
sandbox project is WSL-native (ext4) rather than /mnt/* for compile speed.

Usage (the hunter calls this via Bash):
    python run_fork_poc.py --test exploit.t.sol --chain 1 --fork-block 18000000
Output: a JSON object on stdout {status, passed, failed, ...}. Exit 0 iff a test passed.
"""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
from pathlib import Path

import scryer_config

# Patterns that would mean "send a real transaction". forge test cannot broadcast, so these are
# defense-in-depth: refuse them outright (also stops a prompt-injected test from even trying).
_FORBIDDEN = [
    # The real in-test escape is vm.ffi (arbitrary host shell) — block it first. Whitespace is
    # allowed around the `.` because Solidity is not whitespace-sensitive (`vm . ffi(` is valid).
    (r"\bvm\s*\.\s*ffi\s*\(", "vm.ffi (arbitrary host-shell execution — never allowed)"),
    (
        r"\bvm\s*\.\s*(?:writeFile|writeLine|readFile|removeFile|createDir|closeFile)\s*\(",
        "vm filesystem cheatcode (host FS access — not needed for a fork test)",
    ),
    (r"\bvm\s*\.\s*(?:setEnv)\s*\(", "vm.setEnv (mutates host env)"),
    (r"\bvm\s*\.\s*(?:start)?[Bb]roadcast\b", "vm.broadcast/startBroadcast (real-tx cheatcode — use a pure fork test)"),
    (r"--broadcast\b", "--broadcast flag"),
    (r"\bforge\s+script\b", "forge script (can broadcast — only forge test is allowed)"),
    (r"\bcast\s+send\b", "cast send (sends a real tx)"),
    (r"\bvm\s*\.\s*rpc\s*\(", "vm.rpc (raw RPC call — not needed for a fork test)"),
]

_SANDBOX_NAME = ".scryer_poc"
_home_cache: str | None = None


def _shq(s: str) -> str:
    return "'" + s.replace("'", "'\\''") + "'"


def _wsl_home() -> str | None:
    """Resolve the WSL home as a LITERAL path. We never use shell variables in the WSL
    commands — under this Windows->wsl.exe->bash path, a shell-assigned var reads back empty
    (only inherited env like $HOME expands), so `SB=$HOME/x; ... "$SB"` silently breaks. Tilde
    via `cd ~ && pwd` is resolved from the password database and works reliably."""
    global _home_cache
    if _home_cache is None:
        try:
            r = _wsl("cd ~ && pwd", 30)
            lines = [ln for ln in (r.stdout or "").splitlines() if ln.strip().startswith("/")]
            _home_cache = lines[-1].strip() if lines else ""
        except Exception:
            _home_cache = ""
    return _home_cache or None


def scan_forbidden(src: str) -> str | None:
    for pat, why in _FORBIDDEN:
        if re.search(pat, src):
            return why
    return None


def _wslify(win_path: str) -> str:
    """C:\\Users\\x -> /mnt/c/Users/x ; D:\\a -> /mnt/d/a (same mapping decompile uses)."""
    p = str(Path(win_path).resolve())
    drive, rest = p[0], p[2:]
    return f"/mnt/{drive.lower()}{rest}".replace("\\", "/")


def _wsl(script: str, timeout: int) -> subprocess.CompletedProcess:
    return subprocess.run(
        ["wsl.exe", "--", "bash", "-lc", script],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=timeout,
    )


def _ensure_sandbox(timeout: int = 180) -> tuple[str | None, str | None]:
    """Create the persistent WSL sandbox foundry project once (installs forge-std).
    Returns (sandbox_path, error)."""
    home = _wsl_home()
    if not home:
        return None, "could not resolve the WSL home directory (is WSL running?)"
    sb = f"{home}/{_SANDBOX_NAME}"
    sbq = _shq(sb)
    # forge-std is installed once (needs network). The hardened foundry.toml is (re)written on
    # EVERY run so ffi / fs access can never drift on (a prior edit to) the persistent sandbox —
    # this is the real sandbox boundary, belt-and-suspenders with scan_forbidden: ffi=false makes
    # vm.ffi fail even if a test slips one past the scan, and empty fs_permissions blocks host FS.
    hardened = _shq(_HARDENED_TOML)
    setup = (
        f"if [ ! -d {sbq}/lib/forge-std ]; then "
        f"mkdir -p {sbq} && cd {sbq} && forge init --no-git --force . >/dev/null 2>&1; fi; "
        f"printf '%s' {hardened} > {sbq}/foundry.toml; "
        f"test -f {sbq}/foundry.toml && test -d {sbq}/lib/forge-std && echo OK"
    )
    try:
        r = _wsl(setup, timeout)
    except subprocess.TimeoutExpired:
        return None, f"sandbox setup timed out after {timeout}s (forge init needs network for forge-std)"
    if "OK" not in (r.stdout or ""):
        return None, f"sandbox setup failed: {(r.stderr or r.stdout or '').strip()[:300]}"
    return sb, None


# The sandbox's compiler/test config. ffi disabled and NO fs_permissions / rpc_endpoints: a fork
# test needs none of them, so this removes every host-side side-effect channel from `forge test`.
_HARDENED_TOML = (
    "[profile.default]\nsrc = 'src'\nout = 'out'\nlibs = ['lib']\ntest = 'test'\nffi = false\nfs_permissions = []\n"
)


_SUITE_RE = re.compile(r"Suite result:.*", re.IGNORECASE)
# Authoritative counts from forge's own summary ("… N passed; M failed; K skipped"), not a count
# of [PASS]/[FAIL] substrings — those also appear in -vvv traces a contract can emit.
_RESULT_RE = re.compile(r"(\d+)\s+passed;\s*(\d+)\s+failed", re.IGNORECASE)
_COMPILE_FAIL_RE = re.compile(r"Compiler run failed|Error \(\d+\)|error\[", re.IGNORECASE)


def _redact(text: str, rpc: str) -> str:
    """Strip the fork RPC's API key from forge output before it is returned/persisted — forge
    prints the fork URL verbatim on a fork error, and these URLs embed provider secrets."""
    if not text or not rpc:
        return text
    try:
        from urllib.parse import urlparse

        u = urlparse(rpc)
        text = text.replace(rpc, f"{u.scheme}://{u.netloc}/<redacted>")
    except Exception:
        text = text.replace(rpc, "<redacted-rpc>")
    key = rpc.rstrip("/").split("/")[-1]  # the key is usually the last path segment
    if len(key) >= 12:
        text = text.replace(key, "<redacted>")
    return text


def run_fork_poc(
    test_path: str, chain_id: int, *, fork_block: int | None = None, rpc: str | None = None, timeout: int = 300
) -> dict:
    src = Path(test_path).read_text(encoding="utf-8", errors="replace")
    bad = scan_forbidden(src)
    if bad:
        return {"status": "rejected", "reason": f"forbidden pattern: {bad}", "safe": True}

    rpc = rpc or scryer_config.get_rpc_url(chain_id)
    if not rpc or not rpc.startswith(("http://", "https://")):
        return {
            "status": "no_rpc",
            "reason": (
                f"no forkable JSON-RPC for chain {chain_id}. A fork PoC needs a real (ideally archive) "
                f"RPC endpoint — set {' or '.join(scryer_config.rpc_env_names(chain_id)) or '<CHAIN>_URL'} "
                "in .env. The Etherscan-proxy fallback is NOT forkable."
            ),
        }

    sb, setup_err = _ensure_sandbox(timeout=min(timeout, 180))
    if setup_err:
        return {"status": "error", "reason": setup_err}
    sbq = _shq(sb)

    wsl_test = _wslify(test_path)
    rpc_q = _shq(rpc)  # inert even if the key has shell-special chars
    block_flag = f"--fork-block-number {int(fork_block)}" if fork_block else ""
    # Command-PREFIX env (VAR=val cmd) — a standalone `VAR=val; ...` assignment reads back empty
    # on this interop path, but a prefix populates the child's env reliably. forge gets the RPC
    # via both this env (for tests that createSelectFork) and --fork-url (the default fork).
    env_prefix = f"FORK_RPC={rpc_q} " + (f"FORK_BLOCK={int(fork_block)} " if fork_block else "")
    run = (
        f"cp {_shq(wsl_test)} {sbq}/test/PoC.t.sol && cd {sbq} && "
        f"{env_prefix}timeout {int(timeout)} forge test --match-path test/PoC.t.sol "
        f"--fork-url {rpc_q} {block_flag} -vvv"
    )
    try:
        r = _wsl(run, timeout=timeout + 30)
    except subprocess.TimeoutExpired:
        return {"status": "timeout", "reason": f"forge test exceeded {timeout}s"}

    out = _redact((r.stdout or "") + ("\n" + r.stderr if r.stderr else ""), rpc)
    tail = out[-4000:]

    m = _RESULT_RE.search(out)
    passed = int(m.group(1)) if m else 0
    failed = int(m.group(2)) if m else 0
    ran = m is not None  # the summary line only prints once compilation + the run actually happened

    if not ran and _COMPILE_FAIL_RE.search(out):
        status = "compile_error"
    elif not ran or (passed == 0 and failed == 0):
        status = "no_tests"
    elif failed > 0:
        status = "fail"
    else:
        status = "pass"

    suite = _SUITE_RE.search(out)
    return {
        "status": status,
        "passed": passed,
        "failed": failed,
        "chain_id": chain_id,
        "fork_block": fork_block,
        "suite_result": suite.group(0).strip() if suite else None,
        "output_tail": tail,
        # A passing fork test is the Confirmed signal; anything else is not. NOTE: a test that
        # passes WITHOUT asserting economic impact is not a real exploit — the hunter must make the
        # PoC assert attacker gain / protocol loss (enforced by the hunter prompt, not here).
        "confirmed": status == "pass",
    }


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--test", required=True, help="path to the Foundry test file (.t.sol)")
    ap.add_argument("--chain", type=int, required=True, help="chain id (resolves the fork RPC from .env)")
    ap.add_argument("--fork-block", type=int, default=None, help="block to fork at (archive RPC needed for old blocks)")
    ap.add_argument("--rpc", default=None, help="override the fork RPC URL")
    ap.add_argument("--timeout", type=int, default=300)
    args = ap.parse_args()

    if not Path(args.test).is_file():
        print(json.dumps({"status": "error", "reason": f"no such test file: {args.test}"}))
        return 1
    result = run_fork_poc(args.test, args.chain, fork_block=args.fork_block, rpc=args.rpc, timeout=args.timeout)
    print(json.dumps(result, indent=2))
    return 0 if result.get("confirmed") else 1


if __name__ == "__main__":
    sys.exit(main())
