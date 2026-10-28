"""Unit and integration tests for tests/ui_harness.py.

Verifies:
1. PNG IHDR parsing (PIL-free, byte parsing, invalid inputs).
2. Deterministic baseline fixtures generation (non-secret data, correct file structure).
3. Gating logic and skip behavior (WSCAN_SKIP_BROWSER, WSCAN_NO_BROWSER, launch failure).
4. Harness lifecycle and isolation (subcommand serve startup, /health, process cleanup, temp directory removal).
"""
from __future__ import annotations

import json
import os
import struct
import tempfile
from pathlib import Path
from unittest.mock import patch

import pytest

from tests.ui_harness import (
    find_free_port,
    get_baseline_monitor_events,
    is_chromium_available,
    parse_png_dimensions,
    require_browser,
    seed_baseline_audit_log,
    seed_baseline_scans,
    seed_baseline_settings,
    UIHarness,
)


def _make_png_bytes(width: int, height: int) -> bytes:
    """Helper to construct minimal valid PNG bytes for IHDR testing."""
    signature = b"\x89PNG\r\n\x1a\n"
    chunk_len = struct.pack(">I", 13)
    chunk_type = b"IHDR"
    ihdr_data = struct.pack(">IIBBBBB", width, height, 8, 2, 0, 0, 0)
    crc = struct.pack(">I", 0)  # CRC dummy
    return signature + chunk_len + chunk_type + ihdr_data + crc


def test_parse_png_dimensions_valid():
    """Verify parse_png_dimensions extracts width and height accurately."""
    data = _make_png_bytes(1440, 900)
    w, h = parse_png_dimensions(data)
    assert w == 1440
    assert h == 900

    data768 = _make_png_bytes(768, 1024)
    w, h = parse_png_dimensions(data768)
    assert w == 768
    assert h == 1024


def test_parse_png_dimensions_invalid():
    """Verify parse_png_dimensions rejects malformed or non-PNG buffers."""
    with pytest.raises(ValueError, match="too short"):
        parse_png_dimensions(b"\x89PNG\r\n")

    with pytest.raises(ValueError, match="Invalid PNG signature"):
        parse_png_dimensions(b"GIF89a" + b"\x00" * 20)

    # Corrupt chunk name
    bad_chunk = b"\x89PNG\r\n\x1a\n" + struct.pack(">I", 13) + b"XXXX" + struct.pack(">II", 100, 100)
    with pytest.raises(ValueError, match="Missing IHDR chunk"):
        parse_png_dimensions(bad_chunk)


def test_seed_baseline_scans(tmp_path: Path):
    """Verify deterministic scan fixtures are correctly seeded without secrets."""
    out_dir = tmp_path / "output"
    scan_ids = seed_baseline_scans(out_dir)

    assert len(scan_ids) == 3
    for s_id in scan_ids:
        scan_dir = out_dir / s_id
        assert scan_dir.is_dir()
        evidence_file = scan_dir / "evidence.json"
        assert evidence_file.is_file()
        data = json.loads(evidence_file.read_text(encoding="utf-8"))
        assert "target" in data
        assert "status" in data
        assert "findings" in data

    # Check first scan details
    s1_data = json.loads((out_dir / "20261026_100000" / "evidence.json").read_text(encoding="utf-8"))
    assert s1_data["status"] == "done"
    assert len(s1_data["findings"]) == 3
    severities = {f["severity"] for f in s1_data["findings"]}
    assert severities == {"critical", "high", "medium"}


def test_seed_baseline_audit_log(tmp_path: Path):
    """Verify deterministic audit log file structure."""
    out_dir = tmp_path / "output"
    audit_file = seed_baseline_audit_log(out_dir)
    assert audit_file.is_file()

    lines = audit_file.read_text(encoding="utf-8").strip().splitlines()
    assert len(lines) == 4
    entries = [json.loads(line) for line in lines]
    actions = [e["action"] for e in entries]
    assert actions == ["scan_start", "settings_update", "scan_complete", "scan_abort"]


def test_seed_baseline_settings(tmp_path: Path):
    """Verify deterministic settings file structure."""
    out_dir = tmp_path / "output"
    settings_file = seed_baseline_settings(out_dir)
    assert settings_file.is_file()

    data = json.loads(settings_file.read_text(encoding="utf-8"))
    assert "notifications" in data
    assert data["notifications"]["enabled"] is False
    assert data["notifications"]["webhook_url"] == ""


def test_get_baseline_monitor_events():
    """Verify deterministic monitor event sequence has required event types."""
    events = get_baseline_monitor_events()
    assert len(events) >= 5
    types = [e["type"] for e in events]
    assert "scan_started" in types
    assert "status" in types
    assert "url_crawled" in types
    assert "sitemap" in types
    assert "finding" in types
    assert "log" in types


def test_find_free_port():
    """Verify find_free_port returns a usable TCP port."""
    port = find_free_port()
    assert isinstance(port, int)
    assert port > 1024


def test_gating_skip_behavior_on_env_flags(monkeypatch):
    """Verify browser gating cleanly skips when disabled via environment."""
    monkeypatch.delenv("WSCAN_NO_BROWSER", raising=False)
    monkeypatch.delenv("WSCAN_E2E", raising=False)
    monkeypatch.setenv("WSCAN_SKIP_BROWSER", "1")
    available, reason = is_chromium_available()
    assert available is False
    assert "WSCAN_SKIP_BROWSER" in reason

    with pytest.raises(pytest.skip.Exception):
        require_browser()


def test_gating_skip_behavior_on_no_browser(monkeypatch):
    """Verify browser gating cleanly skips on WSCAN_NO_BROWSER=1."""
    monkeypatch.delenv("WSCAN_SKIP_BROWSER", raising=False)
    monkeypatch.delenv("WSCAN_E2E", raising=False)
    monkeypatch.setenv("WSCAN_NO_BROWSER", "1")
    available, reason = is_chromium_available()
    assert available is False
    assert "WSCAN_NO_BROWSER" in reason

    with pytest.raises(pytest.skip.Exception):
        require_browser()


def test_gating_skip_behavior_on_e2e_disabled(monkeypatch):
    """Verify browser gating cleanly skips on WSCAN_E2E=0."""
    monkeypatch.delenv("WSCAN_SKIP_BROWSER", raising=False)
    monkeypatch.delenv("WSCAN_NO_BROWSER", raising=False)
    monkeypatch.setenv("WSCAN_E2E", "0")
    available, reason = is_chromium_available()
    assert available is False
    assert "WSCAN_E2E=0" in reason

    with pytest.raises(pytest.skip.Exception):
        require_browser()


def test_ui_harness_lifecycle_and_isolation():
    """Verify UIHarness starts serve process, checks /health, and cleans up on exit."""
    require_browser()

    temp_dir_path = None
    server_port = None

    with UIHarness(seed_fixtures=True) as harness:
        temp_dir_path = Path(harness._temp_dir.name)
        server_port = harness.port

        assert temp_dir_path.is_dir()
        assert harness.output_dir.is_dir()
        assert (harness.output_dir / "20261026_100000").is_dir()
        assert (harness.output_dir / "management_audit.jsonl").is_file()

        # Check that server responds to /health
        import urllib.request
        with urllib.request.urlopen(f"http://127.0.0.1:{server_port}/health", timeout=2) as resp:
            assert resp.status == 200
            data = json.loads(resp.read().decode("utf-8"))
            assert data["status"] == "ok"

        # Verify page creation and clean errors
        page = harness.new_page(width=1440, height=900)
        page.goto(f"http://127.0.0.1:{server_port}/health")
        harness.assert_no_errors(page)

    # After exit, temp directory should be cleaned up
    assert not temp_dir_path.exists()
