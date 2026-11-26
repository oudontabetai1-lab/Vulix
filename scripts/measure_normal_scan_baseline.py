#!/usr/bin/env python3
"""Empirical baseline measurement script for normal scan on realistic_site.

Runs an end-to-end browser scan against tests.fixtures.realistic_site with deterministic
configuration (llm=none, concurrency=4, fast_mode=True, depth=2, max_payloads=8),
records probe ledger attempts and findings, builds the canonical scorecard, and updates
benchmarks/baselines/normal_scan_realistic_site.json.
"""

from __future__ import annotations

import asyncio
import json
import os
import sys
import tempfile
import threading
from pathlib import Path

# Add project root to path
_ROOT = Path(__file__).resolve().parents[1]
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

import uvicorn
from tests.fixtures.realistic_site import EXPECTED_FINDINGS, SAFE_ENDPOINTS, create_app
from tests.test_end_to_end_scan import CHECKS, _free_port, _run_scan, _wait_until_serving
from wscan.normal_scan_scorecard import (
    build_normal_scan_scorecard,
    evaluate_normal_scan_gate,
    save_normal_scorecard_file,
)


def measure_baseline(output_path: Path | None = None) -> int:
    if output_path is None:
        output_path = _ROOT / "benchmarks" / "baselines" / "normal_scan_realistic_site.json"

    port = _free_port()
    server = uvicorn.Server(
        uvicorn.Config(create_app(), host="127.0.0.1", port=port, log_level="error")
    )
    server_thread = threading.Thread(target=server.run, daemon=True)
    server_thread.start()
    _wait_until_serving(port)
    print(f"[measure] realistic_site server running on port {port}", flush=True)

    tmp_dir = tempfile.TemporaryDirectory()
    try:
        print("[measure] Starting measured scan...", flush=True)
        engine = asyncio.run(_run_scan(port, tmp_dir.name))
        print(f"[measure] Scan finished. Findings={len(engine.all_findings)} WaveErrors={len(engine.wave_errors)}", flush=True)

        ledger_path = Path(tmp_dir.name) / "probe_attempts.jsonl"
        records = []
        if ledger_path.is_file():
            for line in ledger_path.read_text(encoding="utf-8").splitlines():
                if line.strip():
                    try:
                        records.append(json.loads(line))
                    except Exception:
                        pass
        print(f"[measure] Loaded {len(records)} probe ledger records", flush=True)

        logger = getattr(engine, "request_logger", None)
        ledger = getattr(logger, "probe_ledger", None) if logger else None
        manifest = getattr(ledger, "manifest", None) if ledger else None
        if manifest is None:
            manifest_path = Path(tmp_dir.name) / "probe_attempts_manifest.json"
            if manifest_path.is_file():
                try:
                    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
                except Exception:
                    pass

        scorecard = build_normal_scan_scorecard(
            findings=engine.all_findings,
            expected_findings=EXPECTED_FINDINGS,
            safe_endpoints=SAFE_ENDPOINTS,
            target_checks=CHECKS,
            ledger_records=records,
            ledger_manifest=manifest,
            wave_errors=getattr(engine, "wave_errors", []),
            fixture_id="realistic_site",
            metadata={
                "measured_by": "scripts/measure_normal_scan_baseline.py",
                "fixture": "tests.fixtures.realistic_site",
                "concurrency": 4,
                "fast_mode": True,
                "max_payloads": 8,
                "depth": 2,
                "llm_provider": "none",
            },
        )

        print(f"[measure] Scorecard built: overall_status={scorecard.overall_status} "
              f"total_attempts={scorecard.total_attempts} "
              f"recall={scorecard.ground_truth_recall.get('recall')} "
              f"fpr={scorecard.safe_twin_precision.get('fpr')} "
              f"valid={scorecard.ledger_integrity.get('valid')}", flush=True)

        for ch, cnt in sorted(scorecard.attempt_counts.items()):
            print(f"  check '{ch}': {cnt} attempts", flush=True)

        save_normal_scorecard_file(scorecard, output_path)
        print(f"[measure] Saved baseline scorecard to {output_path}", flush=True)

        verdict = evaluate_normal_scan_gate(scorecard, baseline=scorecard, require_baseline=True)
        print("\n" + verdict.describe(), flush=True)
        if not verdict.passed:
            print("[measure] ERROR: Baseline failed self-validation!", file=sys.stderr)
            return 1

        print("[measure] Baseline self-validation PASSED", flush=True)
        return 0

    finally:
        server.should_exit = True
        server_thread.join(timeout=5)
        tmp_dir.cleanup()


if __name__ == "__main__":
    sys.exit(measure_baseline())
