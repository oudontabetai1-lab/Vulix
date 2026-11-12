"""履歴一覧の件数: evidence / checkpoint のみ（途中） / batch_summary / 何も無い。"""
import json
import time

from wscan import monitor
from wscan.monitor import MonitorServer


def _scans(tmp_path, monkeypatch):
    monkeypatch.setattr(monitor, "OUTPUT_BASE", tmp_path)
    return {s["id"]: s for s in MonitorServer()._list_scans()}


def test_history_count_sources(tmp_path, monkeypatch):
    (tmp_path / "ev").mkdir()
    (tmp_path / "ev" / "evidence.json").write_text(json.dumps(
        {"target": "http://t", "status": "done", "findings": [{"severity": "high"}]}))
    (tmp_path / "cp").mkdir()
    (tmp_path / "cp" / "checkpoint.json").write_text(json.dumps(
        {"findings": [{"severity": "high"}, {"severity": "low"}]}))
    (tmp_path / "batch_1").mkdir()
    (tmp_path / "batch_1" / "batch_summary.json").write_text(json.dumps(
        {"total_findings": 7, "total_critical": 1, "total_high": 2}))
    (tmp_path / "none").mkdir()
    (tmp_path / "bad").mkdir()
    (tmp_path / "bad" / "checkpoint.json").write_text("{broken")
    s = _scans(tmp_path, monkeypatch)

    assert (s["ev"]["findings_count"], s["ev"]["status"], s["ev"]["partial"]) == (1, "done", False)
    assert (s["cp"]["findings_count"], s["cp"]["status"], s["cp"]["partial"]) == (2, "interrupted", True)
    assert s["cp"]["severity"]["high"] == 1
    assert (s["batch_1"]["findings_count"], s["batch_1"]["status"], s["batch_1"]["batch"]) == (7, "done", True)
    assert s["none"]["findings_count"] is None and s["none"]["status"] == "incomplete"
    assert s["bad"]["findings_count"] is None and not s["bad"]["partial"]


def test_listing_time_1000_dirs(tmp_path, monkeypatch):
    for i in range(1000):
        d = tmp_path / f"d{i}"
        d.mkdir()
        (d / "checkpoint.json").write_text(json.dumps({"findings": [{"severity": "low"}] * 5}))
    t = time.perf_counter()
    _scans(tmp_path, monkeypatch)
    print("list 1000 dirs: %.2fs" % (time.perf_counter() - t))
