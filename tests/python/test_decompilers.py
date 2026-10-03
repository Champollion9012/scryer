"""P3: Heimdall decompilation with a reported failure REASON.

`decompile_with_heimdall` collapses every failure to None, so a caller cannot tell "not
installed" (go install it) from "this bytecode defeated the decompiler" from "it timed out".
These tests pin the status machine. All offline — subprocess is mocked.
"""

from __future__ import annotations

import subprocess
from unittest.mock import patch

import pytest

import decompilers as dc

SOME_CODE = "60806040" + "00" * 40


class _Proc:
    def __init__(self, returncode: int = 0, stdout: str = "", stderr: str = ""):
        self.returncode = returncode
        self.stdout = stdout
        self.stderr = stderr


def test_too_short_is_reported_not_silently_none() -> None:
    res = dc.decompile_with_heimdall_detailed("0x1234")
    assert res["status"] == "too_short" and res["source"] is None
    assert "bytes" in res["detail"]


def test_ok_strips_banner_and_adds_header() -> None:
    stdout = "heimdall banner noise\nSource:\ncontract Decompiled { function f() public {} }"
    with patch.object(dc.subprocess, "run", return_value=_Proc(stdout=stdout)):
        res = dc.decompile_with_heimdall_detailed(SOME_CODE)
    assert res["status"] == "ok"
    assert "DECOMPILED SOURCE - NOT ORIGINAL CODE" in res["source"]  # the loud header survives
    assert "contract Decompiled" in res["source"]
    assert "banner noise" not in res["source"]  # pre-`Source:` banner is dropped


def test_missing_binary_is_not_installed_with_install_hint() -> None:
    err = "bash: line 1: /root/.bifrost/bin/heimdall: No such file or directory"
    with patch.object(dc.subprocess, "run", return_value=_Proc(returncode=127, stderr=err)):
        res = dc.decompile_with_heimdall_detailed(SOME_CODE)
    assert res["status"] == "not_installed"
    assert "bifrost" in res["detail"]  # actionable install command, not a bare failure


def test_missing_wsl_is_not_installed() -> None:
    with patch.object(dc.subprocess, "run", side_effect=FileNotFoundError("wsl.exe")):
        res = dc.decompile_with_heimdall_detailed(SOME_CODE)
    assert res["status"] == "not_installed" and "bifrost" in res["detail"]


def test_timeout_is_reported_as_timeout() -> None:
    with patch.object(dc.subprocess, "run", side_effect=subprocess.TimeoutExpired("heimdall", 5)):
        res = dc.decompile_with_heimdall_detailed(SOME_CODE, timeout=5)
    assert res["status"] == "timeout" and "5s" in res["detail"]


def test_genuine_failure_is_distinct_from_not_installed() -> None:
    with patch.object(dc.subprocess, "run", return_value=_Proc(returncode=1, stderr="panic: bad opcode stream")):
        res = dc.decompile_with_heimdall_detailed(SOME_CODE)
    assert res["status"] == "failed" and "panic" in res["detail"]


def test_empty_output_is_failure_not_ok() -> None:
    with patch.object(dc.subprocess, "run", return_value=_Proc(returncode=0, stdout="   ")):
        res = dc.decompile_with_heimdall_detailed(SOME_CODE)
    assert res["status"] == "failed"


def test_backcompat_wrapper_returns_source_or_none() -> None:
    stdout = "Source:\ncontract X {}"
    with patch.object(dc.subprocess, "run", return_value=_Proc(stdout=stdout)):
        assert "contract X {}" in dc.decompile_with_heimdall(SOME_CODE)
    with patch.object(dc.subprocess, "run", return_value=_Proc(returncode=1, stderr="boom")):
        assert dc.decompile_with_heimdall(SOME_CODE) is None


@pytest.mark.parametrize("status", ["not_installed", "timeout", "failed", "too_short"])
def test_failure_statuses_never_return_a_source(status: str) -> None:
    """A failed decompile must never hand back text that could be mistaken for source."""
    mapping = {
        "not_installed": (FileNotFoundError("wsl"), None),
        "timeout": (subprocess.TimeoutExpired("h", 1), None),
        "failed": (None, _Proc(returncode=1, stderr="x")),
        "too_short": (None, None),
    }
    side, ret = mapping[status]
    if status == "too_short":
        res = dc.decompile_with_heimdall_detailed("0x00")
    elif side is not None:
        with patch.object(dc.subprocess, "run", side_effect=side):
            res = dc.decompile_with_heimdall_detailed(SOME_CODE)
    else:
        with patch.object(dc.subprocess, "run", return_value=ret):
            res = dc.decompile_with_heimdall_detailed(SOME_CODE)
    assert res["status"] == status and res["source"] is None
