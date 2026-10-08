"""実スキャナの既存 bypass 波を A/B 採点する。優位ゼロも測定結果として保存する。"""
import hashlib
import json
import os
from pathlib import Path
import subprocess

import pytest

from wscan.benchmark_fixtures import UvicornFixtureLauncher
from wscan.benchmark_model import (
    compute_differentiation, differentiation_to_markdown, load_manifest_file,
)
from wscan.benchmark_runner import run_scanned_suite, write_scorecard
from wscan.benchmark_scan import ScanEngineScanRunner
from wscan.scanners import SCANNERS

pytestmark = pytest.mark.skipif(
    os.environ.get("WSCAN_E2E", "").lower() not in {"1", "true", "yes", "on"},
    reason="WSCAN_E2E opt-in required",
)


def test_bypass_ab_records_measurement_and_guards_safe_twins(tmp_path):
    root = Path(__file__).resolve().parents[2]
    path = root / "benchmarks/manifests/differentiation_bypass.yaml"
    suite = load_manifest_file(path, registry_keys=SCANNERS)
    sha = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=root, text=True).strip()
    dirty = bool(subprocess.check_output(["git", "status", "--porcelain"], cwd=root))
    cards = {}
    for variant in ("conventional", "vulix"):
        cards[variant] = run_scanned_suite(
            suite, launcher=UvicornFixtureLauncher(),
            scan_runner=ScanEngineScanRunner(variant=variant), run_id=variant,
            source_sha=sha, manifest_digest=hashlib.sha256(path.read_bytes()).hexdigest(),
            registry_digest=hashlib.sha256("\n".join(sorted(SCANNERS)).encode()).hexdigest(),
            environment={"variant": variant, "source_dirty": dirty},
        )
        write_scorecard(cards[variant], tmp_path / variant)
        assert "run_error" not in cards[variant], cards[variant]
        assert cards[variant]["case_counts"] == {"planned": 4, "completed": 4, "incomplete": 0}
        safe = [row for row in cards[variant]["cases"] if row["expected"] == "safe"]
        assert len(safe) == 2
        assert all(row["classification"]["candidate"] == "tn" for row in safe), safe
    diff = compute_differentiation(**cards)
    (tmp_path / "differentiation.json").write_text(json.dumps(diff, indent=2), encoding="utf-8")
    (tmp_path / "differentiation.md").write_text(differentiation_to_markdown(diff), encoding="utf-8")
    assert diff["measured_vulnerable"] == 2 and diff["unmeasured"] == []
    assert diff["new_false_positive"] == diff["shared_false_positive"] == []
    print(f"A/B: {diff['differentiation_count']}/2 lift; artifacts: {tmp_path}")
