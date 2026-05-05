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


def decompile_with_heimdall(bytecode: str, timeout: int = 120) -> str | None:
    """
    Decompile bytecode using Heimdall-rs via WSL.

    Args:
        bytecode: EVM bytecode (with or without 0x prefix)
        timeout: Maximum time in seconds to wait for decompilation

    Returns:
        Decompiled Solidity source code, or None if decompilation fails
    """
    # Remove 0x prefix if present
    if bytecode.startswith("0x"):
        bytecode = bytecode[2:]

    # Skip if bytecode is too short
    if len(bytecode) < 10:
        return None

    try:
        # Write bytecode to temp file
        with tempfile.NamedTemporaryFile(mode="w", suffix=".bin", delete=False) as f:
            f.write(bytecode)
            temp_path = f.name

        # Convert Windows path to WSL path
        wsl_path = temp_path.replace("\\", "/").replace("C:", "/mnt/c")

        # Wrap in `bash -lc` so:
        #   (a) ``$HOME`` / ``~`` in HEIMDALL_PATH expands inside WSL (the
        #       default path uses ``$HOME/.bifrost/bin/heimdall`` for portability)
        #   (b) zsh/bash startup files load PATH so users with custom rust
        #       toolchain locations still work
        # Without this wrapper, Windows-side Git Bash mangles ``/root/...`` →
        # ``C:/Program Files/Git/root/...`` because of MSYS path translation.
        heimdall_cmd = f"{HEIMDALL_PATH} decompile {shlex.quote(wsl_path)} --output print --include-sol"
        cmd = ["wsl.exe", "--", "bash", "-lc", heimdall_cmd]

        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=timeout,
        )

        # Clean up temp file
        with contextlib.suppress(OSError):
            Path(temp_path).unlink()

        if result.returncode == 0 and result.stdout.strip():
            output = result.stdout

            # Extract only Solidity source if present
            if "Source:" in output:
                parts = output.split("Source:", 1)
                if len(parts) > 1:
                    return DECOMPILED_HEADER.format(decompiler="Heimdall-rs") + parts[1].strip()

            # Fallback to full output if Source marker not found
            return DECOMPILED_HEADER.format(decompiler="Heimdall-rs") + output

        return None

    except subprocess.TimeoutExpired:
        # Clean up on timeout
        with contextlib.suppress(OSError, NameError):
            Path(temp_path).unlink()
        return None
    except FileNotFoundError:
        # wsl.exe not found
        return None
    except (KeyboardInterrupt, SystemExit):
        raise
    except Exception:
        return None


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
