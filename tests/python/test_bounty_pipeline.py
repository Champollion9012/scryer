"""Tests for the bounty_pipeline orchestrator (offline)."""

from __future__ import annotations

import json
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

import bounty_pipeline as bp

# ---------------------------------------------------------------------------
# read_targets
# ---------------------------------------------------------------------------


def test_read_targets_filters_non_dict_entries(tmp_path: Path) -> None:
    p = tmp_path / "t.json"
    p.write_text(json.dumps([{"address": "0xa"}, "garbage", 42, {"address": "0xb"}]))
    assert bp.read_targets(p) == [{"address": "0xa"}, {"address": "0xb"}]


def test_read_targets_rejects_non_array(tmp_path: Path) -> None:
    p = tmp_path / "t.json"
    p.write_text(json.dumps({"not": "an array"}))
    with pytest.raises(ValueError, match="JSON array"):
        bp.read_targets(p)


# ---------------------------------------------------------------------------
# main(): mock fetch_contract_source + subprocess.run so no network/audits run
# ---------------------------------------------------------------------------


@pytest.fixture
def fake_downloader(monkeypatch):
    """Replace download_contract.fetch_contract_source with a recorder."""
    calls: list[dict] = []

    def _fake(chain_id, addr, *, rpc_url, follow_proxy, output_dir, layout, quiet):
        calls.append(
            {
                "chain_id": chain_id,
                "address": addr,
                "rpc_url": rpc_url,
                "follow_proxy": follow_proxy,
                "output_dir": output_dir,
                "layout": layout,
            }
        )
        # pretend we wrote one file
        Path(output_dir).mkdir(parents=True, exist_ok=True)
        return True

    monkeypatch.setattr(bp, "fetch_contract_source", _fake)
    return calls


@pytest.fixture
def fake_subprocess(monkeypatch):
    """Replace subprocess.run with a no-op recorder so we never actually shell out."""
    invocations: list[list[str]] = []

    def _fake_run(cmd, **kwargs):
        invocations.append(cmd)
        return SimpleNamespace(returncode=0)

    monkeypatch.setattr(bp.subprocess, "run", _fake_run)
    return invocations


def _write_targets(tmp_path: Path, entries: list[dict]) -> Path:
    p = tmp_path / "targets.json"
    p.write_text(json.dumps(entries))
    return p


def _run_main(*argv: str) -> int:
    old = sys.argv
    sys.argv = ["bounty_pipeline.py", *argv]
    try:
        return bp.main()
    finally:
        sys.argv = old


def test_main_download_only_skips_audit(tmp_path: Path, fake_downloader, fake_subprocess) -> None:
    targets = _write_targets(
        tmp_path,
        [
            {"chain_id": 56, "address": "0x" + "aa" * 20},
            {"chain_id": 1, "address": "0x" + "bb" * 20, "follow_proxy": True},
        ],
    )
    run_dir = tmp_path / "runs" / "test_run"
    rc = _run_main("--targets", str(targets), "--run-dir", str(run_dir), "--download-only")
    assert rc == 0
    assert len(fake_downloader) == 2
    # Audit subprocess should never have been invoked in download-only mode
    assert fake_subprocess == []
    manifest = json.loads((run_dir / "pipeline_manifest.json").read_text())
    assert len(manifest["targets"]) == 2
    assert manifest["audit_command"] is None
    # Per-target follow_proxy override flows through
    by_addr = {t["address"]: t for t in manifest["targets"]}
    assert by_addr["0x" + "bb" * 20]["follow_proxy"] is True
    assert by_addr["0x" + "aa" * 20]["follow_proxy"] is False
    assert all(t["download_ok"] for t in manifest["targets"])


def test_main_audit_only_skips_download(tmp_path: Path, fake_downloader, fake_subprocess) -> None:
    targets = _write_targets(tmp_path, [{"chain_id": 56, "address": "0x" + "aa" * 20}])
    run_dir = tmp_path / "runs" / "audit_only"
    rc = _run_main("--targets", str(targets), "--run-dir", str(run_dir), "--audit-only")
    assert rc == 0
    assert fake_downloader == []
    assert len(fake_subprocess) == 1
    cmd = fake_subprocess[0]
    # The forwarded subprocess command targets the audit script
    assert any(arg.endswith("audit_contracts.py") for arg in cmd)
    assert "--sources-dir" in cmd and "--out-dir" in cmd and "--run-dir" in cmd


def test_main_full_run_passes_audit_options(tmp_path: Path, fake_downloader, fake_subprocess) -> None:
    targets = _write_targets(tmp_path, [{"chain_id": 56, "address": "0x" + "aa" * 20}])
    run_dir = tmp_path / "runs" / "full_run"
    rc = _run_main(
        "--targets",
        str(targets),
        "--run-dir",
        str(run_dir),
        "--model",
        "test-model",
        "--rpm",
        "60",
        "--force-map-reduce",
        "--slither",
        "--disable-regex-scan",
    )
    assert rc == 0
    cmd = fake_subprocess[0]
    # Forwarded options end up in the audit subprocess
    assert "--model" in cmd and "test-model" in cmd
    assert "--rpm" in cmd and "60.0" in cmd  # argparse parses --rpm as float
    assert "--force-map-reduce" in cmd
    assert "--slither" in cmd
    assert "--disable-regex-scan" in cmd


def test_main_skips_targets_without_address(tmp_path: Path, fake_downloader, fake_subprocess) -> None:
    targets = _write_targets(
        tmp_path,
        [
            {"chain_id": 56},  # no address
            {"chain_id": 56, "address": "  "},  # whitespace
            {"chain_id": 56, "address": "0x" + "aa" * 20},
        ],
    )
    run_dir = tmp_path / "runs" / "skip"
    _run_main("--targets", str(targets), "--run-dir", str(run_dir), "--download-only")
    # Only the third entry produced a downloader call
    assert len(fake_downloader) == 1


def test_main_returns_2_when_targets_empty(tmp_path: Path, fake_downloader, fake_subprocess) -> None:
    targets = _write_targets(tmp_path, [])
    rc = _run_main("--targets", str(targets), "--run-dir", str(tmp_path / "runs" / "empty"))
    assert rc == 2
    assert fake_downloader == []
    assert fake_subprocess == []
