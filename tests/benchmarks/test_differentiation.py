"""A/B は未実行・不整合を lift に混ぜず、両経路の安全側を会計する。"""
from pathlib import Path

import pytest
import yaml
from fastapi.testclient import TestClient

from tests.fixtures.differentiation_lab import create_app
from wscan.benchmark_model import (
    compute_differentiation, differentiation_to_markdown, load_manifest_file,
    load_manifest, ManifestError,
)
from wscan.scanners import SCANNERS
from wscan.benchmark_scan import ScanEngineScanRunner

ROOT = Path(__file__).resolve().parents[2]


def card(classification, *, expected="vulnerable", capability="reward_search", gate="observed"):
    return {"cases": [{"case_id": "case", "expected": expected,
        "capability": capability, "gate": gate,
        "classification": {"candidate": classification, "confirmed": None}}]}


@pytest.mark.parametrize("before,after,bucket", [
    ("fn", "tp", "differentiated"), ("tp", "fn", "vulix_regression"),
    ("tp", "tp", "parity_detected"), ("fn", "fn", "both_missed"),
])
def test_vulnerable_transitions(before, after, bucket):
    out = compute_differentiation(card(before), card(after))
    assert out[bucket] == ["case"]
    assert out["capabilities"]["reward_search"][bucket] == ["case"]
    assert out["measured_vulnerable"] == 1


@pytest.mark.parametrize("before,after,bucket", [
    ("tn", "fp", "new_false_positive"), ("fp", "fp", "shared_false_positive"),
    ("fp", "tn", "cleared_false_positive"), ("tn", "tn", "parity_clean"),
])
def test_safe_transitions(before, after, bucket):
    out = compute_differentiation(card(before, expected="safe"), card(after, expected="safe"))
    assert out[bucket] == ["case"]
    assert out["differentiation_rate"] is None
    assert "safe FP (either route)" in differentiation_to_markdown(out)


def test_missing_case_and_gap_are_unmeasured():
    for before in ({"cases": []}, card(None), card("fn", gate="gap")):
        out = compute_differentiation(before, card("tp"))
        assert out["unmeasured"] == ["case"]
        assert out["differentiation_rate"] is None
        assert out["capabilities"]["reward_search"]["lift"] is None
    assert compute_differentiation(card("fn"), card("tp"), tier="confirmed")["unmeasured"] == ["case"]


def test_incompatible_rows_are_rejected():
    for after in (card("tn", expected="safe"), card("fp"), card("tp", capability="state_graph")):
        with pytest.raises(ValueError):
            compute_differentiation(card("fn"), after)
    duplicate = card("fn")
    duplicate["cases"] *= 2
    with pytest.raises(ValueError, match="duplicate"):
        compute_differentiation(duplicate, card("tp"))


def test_baseline_expectation_and_provenance():
    before, after = card("fn"), card("tp")
    for out in (before, after):
        out["cases"][0]["baseline_expected"] = "safe"
    assert compute_differentiation(before, after)["baseline_mismatch"] == []
    before["cases"][0]["classification"]["candidate"] = "tp"
    assert compute_differentiation(before, after)["baseline_mismatch"] == ["case"]
    before["source_sha"], after["source_sha"] = "a", "b"
    with pytest.raises(ValueError, match="source_sha"):
        compute_differentiation(before, after)


def test_manifest_capability_and_legacy_defaults():
    suite = load_manifest_file(ROOT / "benchmarks/manifests/differentiation_frontier.yaml", registry_keys=SCANNERS)
    assert {c.capability for c in suite.cases} == {"", "transformation_graph", "reward_search", "state_graph"}
    assert all(c.gate.value == "gap" for c in suite.cases)
    legacy = load_manifest_file(ROOT / "benchmarks/manifests/realistic_site_xss.yaml", registry_keys=SCANNERS)
    assert all(c.capability == "" and c.baseline_expected == c.expected for c in legacy.cases)


@pytest.mark.parametrize("capability", ["transformation_graph", "reward_search", "state_graph", "dom_taint"])
def test_all_capability_names_require_matching_twins(capability):
    raw = yaml.safe_load((ROOT / "benchmarks/manifests/differentiation_bypass.yaml").read_text())
    raw["cases"][0]["capability"] = raw["cases"][1]["capability"] = capability
    assert load_manifest(raw, registry_keys=SCANNERS).cases[0].capability == capability
    raw["cases"][1]["capability"] = ""
    with pytest.raises(ManifestError, match="same capability"):
        load_manifest(raw, registry_keys=SCANNERS)
    raw["cases"][0]["capability"] = "unknown"
    with pytest.raises(ManifestError, match="unknown"):
        load_manifest(raw, registry_keys=SCANNERS)


def test_suite_mismatch_or_run_error_cannot_report_lift():
    before, after = card("fn"), card("tp")
    before["suite"], after["suite"] = {"suite_id": "a"}, {"suite_id": "b"}
    with pytest.raises(ValueError, match="suite"):
        compute_differentiation(before, after)
    after["suite"] = before["suite"]
    after["run_error"] = "scan_failed"
    out = compute_differentiation(before, after)
    assert out["unmeasured"] == ["case"] and out["differentiation_count"] == 0
    with pytest.raises(ValueError, match="variant"):
        ScanEngineScanRunner(variant="state_graph")


def test_fixture_ground_truth_and_safe_twins():
    with TestClient(create_app()) as client:
        home = client.get("/").text
        assert '<a href="/vault/download?file=sample">' in home
        assert "root:x:" not in client.get("/vault/download", params={"file": "../../../../etc/passwd"}).text
        bypass = "%2e%2e%2f" * 4 + "etc%2fpasswd"
        assert "root:x:" in client.get("/vault/download", params={"file": bypass}).text
        assert "root:x:" not in client.get("/vault/fetch", params={"file": bypass}).text
        assert "uid=0" in client.get("/net/ping", params={"target": ";${IFS}id"}).text
        assert "uid=0" not in client.get("/net/resolve", params={"target": ";${IFS}id"}).text
        assert "SQLite error" in client.get("/orders/lookup", params={"ref": "%27"}).text
        assert "SQLite error" not in client.get("/orders/status", params={"ref": "%27"}).text
        body = '<img src=x onerror="alert(1)">'
        client.post("/notes/save", data={"body": body})
        assert body in client.get("/notes/view").text
        assert body not in client.get("/notes/view-safe").text
        assert client.get("/api/invoice", params={"id": "2"}).status_code == 401
        assert client.post("/session", data={"user": "alice", "password": "alice-password"}).status_code == 200
        assert client.get("/api/invoice", params={"id": "2"}).json()["owner"] == "bob"
        assert client.get("/api/invoice-safe", params={"id": "2", "user": "bob"}).status_code == 403
        assert client.get("/api/invoice-safe", params={"id": "1"}).status_code == 200
        client.cookies.set("session", "bob-session")
        assert client.get("/api/invoice-safe", params={"id": "2"}).status_code == 401
        payload = "' OR 1=1 -- "
        assert "rows: 2" in client.get("/search/fuzzy", params={"q": payload}).text
        assert "rows: 0" in client.get("/search/strict", params={"q": payload}).text
