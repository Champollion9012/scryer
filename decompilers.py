"""
Bytecode Decompilers for EVM Smart Contracts.

Supports multiple decompilation backends:
- Heimdall-rs (via WSL on Windows)
- Panoramix (Linux only, requires SIGALRM)
"""

from __future__ import annotations

import contextlib
import os
import shlex
import subprocess
import sys
import tempfile
import warnings
from pathlib import Path

from scryer_logging import get_logger

_log = get_logger(__name__)

# ============================================================================
# Constants
# ============================================================================

DECOMPILED_HEADER = """// ============================================================================
// DECOMPILED SOURCE - NOT ORIGINAL CODE
// ============================================================================
// This file was automatically decompiled from bytecode using {decompiler}.
// It may not accurately represent the original source code.
// Use with caution for analysis purposes only.
// ============================================================================

"""


# Default Heimdall path: allow override via env, otherwise fall back to the
# canonical bifrost-installed location under the *current* user's home, not a
# specific developer's hardcoded path.
def _default_heimdall_path() -> str:
    env_override = os.getenv("HEIMDALL_PATH")
    if env_override:
        return env_override
    # On Windows we shell out via WSL, so use the Linux-side $HOME.
    if sys.platform == "win32":
        wsl_home = os.getenv("WSL_HOME") or "$HOME"
        return f"{wsl_home}/.bifrost/bin/heimdall"
    return str(Path.home() / ".bifrost" / "bin" / "heimdall")


HEIMDALL_PATH = _default_heimdall_path()


# ============================================================================
# Heimdall Decompiler (via WSL)
# ============================================================================


INSTALL_HINT = (
    "install: wsl.exe -- bash -lc 'curl -L https://get.bifrost.sh | bash && ~/.bifrost/bin/bifrost'"
    if sys.platform == "win32"
    else "install: curl -L https://get.bifrost.sh | bash && ~/.bifrost/bin/bifrost"
)


def decompile_with_heimdall_detailed(bytecode: str, timeout: int = 180) -> dict:
    """Decompile via Heimdall-rs, reporting WHY it failed.

    ``decompile_with_heimdall`` collapses every failure mode to ``None``, so a caller cannot
    tell "Heimdall is not installed" (actionable — go install it) from "this bytecode defeated
    the decompiler" (not actionable) from "it timed out" (raise the timeout). This returns
    ``{status, source, detail, decompiler}`` with status one of:
    ``ok`` | ``not_installed`` | ``timeout`` | ``failed`` | ``too_short``.
    """
    if bytecode.startswith("0x"):
        bytecode = bytecode[2:]
    if len(bytecode) < 10:
        return {
            "status": "too_short",
            "source": None,
            "detail": f"only {len(bytecode) // 2} bytes of code — nothing to decompile",
            "decompiler": "heimdall",
        }

    temp_path: str | None = None
    try:
        with tempfile.NamedTemporaryFile(mode="w", suffix=".bin", delete=False) as f:
            f.write(bytecode)
            temp_path = f.name

        if sys.platform == "win32":
            # Convert the Windows temp path for WSL, and wrap in `bash -lc` so (a) $HOME in
            # HEIMDALL_PATH expands inside WSL and (b) login files set PATH. Without the
            # wrapper, Git Bash mangles /root/... into C:/Program Files/Git/root/...
            target = temp_path.replace("\\", "/").replace("C:", "/mnt/c")
            cmd = ["wsl.exe", "--", "bash", "-lc",
                   f"{HEIMDALL_PATH} decompile {shlex.quote(target)} --output print --include-sol"]
        else:
            cmd = ["bash", "-lc",
                   f"{HEIMDALL_PATH} decompile {shlex.quote(temp_path)} --output print --include-sol"]

        result = subprocess.run(
            cmd, capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=timeout
        )
    except subprocess.TimeoutExpired:
        return {
            "status": "timeout",
            "source": None,
            "detail": f"heimdall exceeded {timeout}s — a large contract may just need a bigger timeout",
            "decompiler": "heimdall",
        }
    except FileNotFoundError:
        return {
            "status": "not_installed",
            "source": None,
            "detail": f"{'wsl.exe' if sys.platform == 'win32' else 'bash'} not found — {INSTALL_HINT}",
            "decompiler": "heimdall",
        }
    except (KeyboardInterrupt, SystemExit):
        raise
    except Exception as e:
        return {"status": "failed", "source": None, "detail": f"{type(e).__name__}: {e}", "decompiler": "heimdall"}
    finally:
        if temp_path:
            with contextlib.suppress(OSError):
                Path(temp_path).unlink()

    stderr = (result.stderr or "").strip()
    if result.returncode != 0 or not (result.stdout or "").strip():
        low = stderr.lower()
        if "no such file" in low or "command not found" in low:
            return {
                "status": "not_installed",
                "source": None,
                "detail": f"{stderr[:200]} — {INSTALL_HINT}",
                "decompiler": "heimdall",
            }
        return {
            "status": "failed",
            "source": None,
            "detail": stderr[:400] or f"heimdall exited {result.returncode} with no output",
            "decompiler": "heimdall",
        }

    output = result.stdout
    if "Source:" in output:  # heimdall prints a banner before the Solidity
        output = output.split("Source:", 1)[1].strip()
    return {
        "status": "ok",
        "source": DECOMPILED_HEADER.format(decompiler="Heimdall-rs") + output,
        "detail": "",
        "decompiler": "heimdall",
    }


def decompile_with_heimdall(bytecode: str, timeout: int = 120) -> str | None:
    """Decompile bytecode using Heimdall-rs. Returns the source, or None on any failure.

    Thin back-compat wrapper; prefer :func:`decompile_with_heimdall_detailed`, which says why.
    """
    return decompile_with_heimdall_detailed(bytecode, timeout=timeout).get("source")


# ============================================================================
# Panoramix Decompiler
# ============================================================================


def decompile_with_panoramix(bytecode: str) -> str | None:
    """
    Decompile bytecode using Panoramix.

    Note: Does not work on Windows (requires SIGALRM signal which is Unix-only).

    Args:
        bytecode: EVM bytecode (with or without 0x prefix)

    Returns:
        Decompiled Solidity source code, or None if decompilation fails
    """
    # Panoramix uses SIGALRM which is not available on Windows
    if sys.platform == "win32":
        return None

    # Suppress warnings from panoramix
    warnings.filterwarnings("ignore")

    try:
        from panoramix.decompiler import decompile_bytecode as panoramix_decompile

        # Remove 0x prefix if present
        if bytecode.startswith("0x"):
            bytecode = bytecode[2:]

        result = panoramix_decompile(bytecode)
        if result:
            # Handle case where result might not be a string
            result_str = str(result) if hasattr(result, "__str__") else result
            return DECOMPILED_HEADER.format(decompiler="Panoramix") + result_str

        return None
    except ImportError:
        # Panoramix not installed
        return None
    except AttributeError as e:
        # Handle SIGALRM not available
        if "SIGALRM" in str(e):
            return None
        return None
    except (KeyboardInterrupt, SystemExit):
        raise
    except Exception:
        return None


# ============================================================================
# Main Decompiler Interface
# ============================================================================


def decompile_bytecode(bytecode: str) -> str | None:
    """
    Decompile EVM bytecode to Solidity source code.

    Tries multiple decompilers in order of preference:
    1. Heimdall-rs (via WSL on Windows)
    2. Panoramix (Linux only)

    Args:
        bytecode: EVM bytecode (with or without 0x prefix)

    Returns:
        Decompiled Solidity source code with header comment,
        or None if all decompilers fail
    """
    try:
        # Try Heimdall first (better quality)
        result = decompile_with_heimdall(bytecode)
        if result:
            return result

        # Fallback to Panoramix
        result = decompile_with_panoramix(bytecode)
        if result:
            return result

        return None
    except (KeyboardInterrupt, SystemExit):
        raise
    except Exception:
        return None


# ============================================================================
# CLI for testing
# ============================================================================


def main():
    """CLI entry point for testing decompilation."""
    import argparse
    from pathlib import Path

    parser = argparse.ArgumentParser(description="Decompile EVM bytecode")
    parser.add_argument("input", help="Bytecode file or hex string")
    parser.add_argument("-o", "--output", help="Output file (default: stdout)")
    parser.add_argument("--heimdall", action="store_true", help="Use only Heimdall")
    parser.add_argument("--panoramix", action="store_true", help="Use only Panoramix")

    args = parser.parse_args()

    # Read bytecode
    input_path = Path(args.input)
    if input_path.exists():
        bytecode = input_path.read_text().strip()
    else:
        bytecode = args.input

    # Decompile
    if args.heimdall:
        result = decompile_with_heimdall(bytecode)
    elif args.panoramix:
        result = decompile_with_panoramix(bytecode)
    else:
        result = decompile_bytecode(bytecode)

    if result:
        if args.output:
            Path(args.output).write_text(result, encoding="utf-8")
            _log.info("Saved to %s", args.output)
        else:
            # Decompiled source IS the user-requested result; stdout is correct.
            print(result)
    else:
        _log.error("Decompilation failed")
        sys.exit(1)


if __name__ == "__main__":
    main()
