"""Tests for the fork-PoC runner — the harness that turns a Likely finding into Confirmed.

Offline: WSL/forge are mocked. The one thing that MUST hold is safety — only `forge test` ever
runs, and anything that could send a real transaction is refused before WSL is touched.
"""

from __future__ import annotations

from pathlib import Path

import pytest

import run_fork_poc as rp


# --------------------------------------------------------------------------- #
# Safety: refuse anything that could broadcast a real tx
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize(
    "snippet",
    [
        "vm.startBroadcast();",
        "vm.broadcast();",
        "vm. startBroadcast ( ) ;".replace(" ", ""),
        'string memory x = "--broadcast";',
        "// run: forge script Foo --broadcast",
        "cast send 0xabc 'f()'",
        "vm.rpc('eth_sendRawTransaction', params);",
    ],
)
def test_scan_forbidden_catches_broadcast_vectors(snippet: str) -> None:
    assert rp.scan_forbidden(f"contract P {{ function t() public {{ {snippet} }} }}") is not None


def test_scan_forbidden_allows_a_clean_fork_test() -> None:
    clean = """
    import "forge-std/Test.sol";
    contract PoC is Test {
        function test_exploit() public {
            vm.createSelectFork(vm.envString("FORK_RPC"), 18000000);
            vm.prank(attacker);
            assertGt(gainAfter, gainBefore);
        }
    }
    """
    assert rp.scan_forbidden(clean) is None


def test_run_rejects_before_touching_wsl(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(rp, "_wsl", lambda *a, **k: pytest.fail("WSL must not run for a rejected test"))
    t = tmp_path / "evil.t.sol"
    t.write_text("contract P { function t() public { vm.startBroadcast(); } }", encoding="utf-8")
    out = rp.run_fork_poc(str(t), 1)
    assert out["status"] == "rejected" and out.get("safe") is True


# --------------------------------------------------------------------------- #
# Path + RPC plumbing
# --------------------------------------------------------------------------- #
def test_wslify_maps_drives() -> None:
    assert rp._wslify(r"C:\Users\dev\x.sol") == "/mnt/c/Users/dev/x.sol"
    assert rp._wslify(r"D:\proj\scryer\t.sol") == "/mnt/d/proj/scryer/t.sol"


def test_no_forkable_rpc_is_reported(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(rp.scryer_config, "get_rpc_url", lambda cid: "")  # niche chain, no native RPC
    monkeypatch.setattr(rp, "_wsl", lambda *a, **k: pytest.fail("must not reach WSL without an RPC"))
    t = tmp_path / "ok.t.sol"
    t.write_text("contract P is Test { function t() public {} }", encoding="utf-8")
    out = rp.run_fork_poc(str(t), 80002)
    assert out["status"] == "no_rpc" and "forkable" in out["reason"]


# --------------------------------------------------------------------------- #
# Output parsing / verdict mapping (mock forge output)
# --------------------------------------------------------------------------- #
class _Proc:
    def __init__(self, stdout: str = "", stderr: str = ""):
        self.stdout = stdout
        self.stderr = stderr
        self.returncode = 0


def _run_with_forge_output(tmp_path, monkeypatch, forge_stdout: str) -> dict:
    monkeypatch.setattr(rp.scryer_config, "get_rpc_url", lambda cid: "https://rpc.example/key")
    monkeypatch.setattr(rp, "_ensure_sandbox", lambda timeout=180: ("/root/.scryer_poc", None))
    monkeypatch.setattr(rp, "_wsl", lambda script, timeout: _Proc(stdout=forge_stdout))
    t = tmp_path / "poc.t.sol"
    t.write_text("contract P is Test { function test_x() public { assertTrue(true); } }", encoding="utf-8")
    return rp.run_fork_poc(str(t), 1, fork_block=18_000_000)


def test_pass_maps_to_confirmed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    out = _run_with_forge_output(
        tmp_path,
        monkeypatch,
        "[PASS] test_x() (gas: 123)\nSuite result: ok. 1 passed; 0 failed; 0 skipped",
    )
    assert out["status"] == "pass" and out["confirmed"] is True and out["passed"] == 1


def test_fail_is_not_confirmed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    out = _run_with_forge_output(
        tmp_path,
        monkeypatch,
        "[FAIL: no profit => not exploitable] test_x() (gas: 99)\nSuite result: FAILED. 0 passed; 1 failed",
    )
    assert out["status"] == "fail" and out["confirmed"] is False and out["failed"] == 1


def test_compile_error_is_distinct(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    out = _run_with_forge_output(tmp_path, monkeypatch, "Error (7576): Undeclared identifier.\nCompiler run failed")
    assert out["status"] == "compile_error" and out["confirmed"] is False


def test_no_tests_is_distinct(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    out = _run_with_forge_output(tmp_path, monkeypatch, "No tests to run\n")
    assert out["status"] == "no_tests" and out["confirmed"] is False
