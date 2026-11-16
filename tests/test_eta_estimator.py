"""tests/test_eta_estimator.py

Comprehensive unit, benchmark, and monitor integration tests for
wscan's Monotonic Phase-Weighted Scan ETA Estimator & Confidence Model.
"""

from __future__ import annotations

import asyncio
from typing import Any
import pytest
from starlette.testclient import TestClient

from wscan.eta_estimator import (
    DEFAULT_PHASE_WEIGHTS,
    DEFAULT_CHECK_WEIGHTS,
    EtaSample,
    PhaseProgressState,
    EtaEstimate,
    EtaEstimator,
    evaluate_eta_accuracy,
    generate_synthetic_trace,
)
from wscan.monitor import MonitorServer


class MockClock:
    """Deterministic monotonic clock for testing."""

    def __init__(self, start: float = 100.0) -> None:
        self._time = float(start)

    def __call__(self) -> float:
        return self._time

    def advance(self, seconds: float) -> None:
        self._time += max(0.0, float(seconds))


class TestEtaEstimatorUnit:
    """Unit tests for EtaEstimator core logic and mathematical invariants."""

    def test_monotonic_clock_accounting_across_pause_resume(self):
        clock = MockClock(start=100.0)
        estimator = EtaEstimator(clock=clock)
        estimator.start()

        # Advance 10s active
        clock.advance(10.0)
        estimator.record_progress(current=5, total=50, phase="attack")
        est = estimator.estimate()
        assert est.elapsed_seconds == 10.0

        # Pause at t=110
        estimator.pause()
        assert estimator.is_paused is True

        # Advance 25s while paused
        clock.advance(25.0)
        est_paused = estimator.estimate()
        assert est_paused.status_label == "paused"
        assert est_paused.reason_code == "paused"
        assert est_paused.confidence == "indeterminate"
        assert est_paused.eta_seconds is None
        assert est_paused.eta_range_seconds is None
        # Active elapsed should strictly be 10.0s (not 35.0s)
        assert est_paused.elapsed_seconds == 10.0

        # Resume at t=135
        estimator.resume()
        assert estimator.is_paused is False

        # Advance 15s further active
        clock.advance(15.0)
        estimator.record_progress(current=15, total=50, phase="attack")
        est_resumed = estimator.estimate()
        assert est_resumed.status_label != "paused"
        # Total active elapsed: 10 + 15 = 25.0s
        assert est_resumed.elapsed_seconds == 25.0

    def test_calibration_state_when_insufficient_samples(self):
        clock = MockClock(start=50.0)
        estimator = EtaEstimator(clock=clock, min_calibration_samples=3, min_calibration_seconds=2.0)
        estimator.start()

        # Sample 1: only 0.5s elapsed, 1 sample
        clock.advance(0.5)
        estimator.record_progress(current=1, total=20, phase="crawl")
        est1 = estimator.estimate()
        assert est1.status_label == "calibrating"
        assert est1.confidence == "calibrating"
        assert est1.reason_code == "insufficient_samples"
        assert est1.eta_seconds is None
        assert est1.eta_range_seconds is None

        # Sample 2: 1.0s elapsed, 2 samples
        clock.advance(0.5)
        estimator.record_progress(current=2, total=20, phase="crawl")
        est2 = estimator.estimate()
        assert est2.status_label == "calibrating"
        assert est2.eta_seconds is None

        # Sample 3: 2.5s elapsed, 3 samples -> transitions to estimating
        clock.advance(1.5)
        estimator.record_progress(current=4, total=20, phase="crawl")
        est3 = estimator.estimate()
        assert est3.status_label == "estimating"
        assert est3.confidence in ("high", "medium")
        assert est3.eta_seconds is not None
        assert est3.eta_seconds >= 1
        assert est3.eta_range_seconds is not None

    def test_invariants_while_running_and_upon_completion(self):
        clock = MockClock(start=0.0)
        estimator = EtaEstimator(clock=clock)
        estimator.start()

        for i in range(1, 4):
            clock.advance(1.0)
            estimator.record_progress(current=i * 3, total=10, phase="crawl")
        est = estimator.estimate()

        # Invariant 1: progress_percent < 100.0 while scan is still running!
        assert est.progress_percent < 100.0
        # Invariant 2: eta_seconds is strictly >= 1 while still running!
        assert est.eta_seconds is not None
        assert est.eta_seconds >= 1

        # Advance into attack phase
        clock.advance(5.0)
        estimator.record_progress(current=50, total=50, phase="attack")
        est_attack_end = estimator.estimate()
        assert est_attack_end.progress_percent < 100.0
        assert est_attack_end.eta_seconds >= 1

        # Mark completed
        clock.advance(1.0)
        estimator.record_terminal("completed")
        est_done = estimator.estimate()

        # Invariant 3: progress_percent == 100.0 upon completion
        assert est_done.progress_percent == 100.0
        # Invariant 4: eta_seconds == 0 upon completion
        assert est_done.eta_seconds == 0
        assert est_done.status_label == "completed"
        assert est_done.reason_code == "terminal_state"
        assert est_done.confidence == "high"

        # Aborted scan invariant
        estimator.reset()
        estimator.start()
        clock.advance(4.0)
        estimator.record_progress(current=5, total=20, phase="attack")
        estimator.record_terminal("aborted")
        est_aborted = estimator.estimate()
        assert est_aborted.status_label == "aborted"
        assert est_aborted.eta_seconds is None
        assert est_aborted.reason_code == "terminal_state"

    def test_dynamic_queue_growth_detection(self):
        clock = MockClock(start=100.0)
        estimator = EtaEstimator(clock=clock)
        estimator.start()

        clock.advance(2.0)
        estimator.record_progress(current=5, total=10, phase="crawl")
        clock.advance(2.0)
        estimator.record_progress(current=8, total=10, phase="crawl")
        clock.advance(2.0)
        # Dynamic discovery expands queue from 10 to 30
        estimator.record_progress(current=10, total=30, phase="crawl", dynamic_units_added=20)
        est = estimator.estimate()

        assert est.reason_code == "dynamic_queue_growth"
        assert est.confidence == "medium"
        assert est.eta_range_seconds is not None
        low, high = est.eta_range_seconds
        assert low <= est.eta_seconds <= high

    def test_timeout_and_retry_variance_detection(self):
        clock = MockClock(start=100.0)
        estimator = EtaEstimator(clock=clock)
        estimator.start()

        for i in range(1, 4):
            clock.advance(2.0)
            estimator.record_progress(current=i, total=30, phase="attack")

        # Spikes in timeout / retries
        clock.advance(10.0)
        estimator.record_progress(
            current=4,
            total=30,
            phase="attack",
            retry_or_timeout_events=3,
        )
        est = estimator.estimate()

        assert est.reason_code == "high_timeout_variance"
        assert est.confidence == "low"
        assert est.eta_range_seconds is not None
        low, high = est.eta_range_seconds
        assert low <= est.eta_seconds <= high

    def test_concurrency_adaptation(self):
        clock = MockClock(start=100.0)
        estimator = EtaEstimator(clock=clock)
        estimator.start()

        # Run 5 units at concurrency 1
        for i in range(1, 6):
            clock.advance(2.0)
            estimator.record_progress(current=i, total=40, phase="attack", concurrency=1)
        est_c1 = estimator.estimate()

        # Scale up concurrency to 4 workers
        clock.advance(2.0)
        estimator.record_progress(current=9, total=40, phase="attack", concurrency=4)
        est_c4 = estimator.estimate()

        # Scaling concurrency up should lower the projected remaining time
        assert est_c4.eta_seconds < est_c1.eta_seconds


class TestEtaBenchmarkAccuracy:
    """Benchmark tests validating quantitative error reduction against naive linear baseline."""

    @pytest.mark.parametrize("scenario", [
        "small_site",
        "medium_site",
        "large_site",
        "dynamic_discovery",
        "timeout_spikes",
        "pause_resume",
    ])
    def test_synthetic_scenario_metrics_and_zero_violations(self, scenario: str):
        trace = generate_synthetic_trace(scenario)
        result = evaluate_eta_accuracy(trace)

        baseline = result["baseline"]
        estimator = result["estimator"]

        # Invariant: ZERO violations in EtaEstimator across every scenario
        assert estimator["zero_while_running_violations"] == 0, (
            f"{scenario}: estimator had zero_while_running_violations"
        )
        assert estimator["hundred_percent_before_done_violations"] == 0, (
            f"{scenario}: estimator had hundred_percent_before_done_violations"
        )

        # Baseline naive linear should suffer from invariant violations
        assert (
            baseline["zero_while_running_violations"] > 0
            or baseline["hundred_percent_before_done_violations"] > 0
        ), f"{scenario}: expected naive baseline to suffer from violations"

    def test_overall_benchmark_suite_accuracy_improvement(self):
        scenarios = [
            "small_site",
            "medium_site",
            "large_site",
            "dynamic_discovery",
            "timeout_spikes",
            "pause_resume",
        ]

        total_baseline_mae = 0.0
        total_estimator_mae = 0.0
        total_baseline_p90 = 0.0
        total_estimator_p90 = 0.0
        total_baseline_violations = 0
        total_estimator_violations = 0

        for sc in scenarios:
            trace = generate_synthetic_trace(sc)
            res = evaluate_eta_accuracy(trace)
            b = res["baseline"]
            e = res["estimator"]

            total_baseline_mae += b["mae_seconds"]
            total_estimator_mae += e["mae_seconds"]
            total_baseline_p90 += b["p90_abs_error_seconds"]
            total_estimator_p90 += e["p90_abs_error_seconds"]
            total_baseline_violations += (
                b["zero_while_running_violations"] + b["hundred_percent_before_done_violations"]
            )
            total_estimator_violations += (
                e["zero_while_running_violations"] + e["hundred_percent_before_done_violations"]
            )

        mean_baseline_mae = total_baseline_mae / len(scenarios)
        mean_estimator_mae = total_estimator_mae / len(scenarios)
        mean_baseline_p90 = total_baseline_p90 / len(scenarios)
        mean_estimator_p90 = total_estimator_p90 / len(scenarios)

        overall_mae_improvement = (
            (mean_baseline_mae - mean_estimator_mae) / mean_baseline_mae * 100.0
        )
        overall_p90_improvement = (
            (mean_baseline_p90 - mean_estimator_p90) / mean_baseline_p90 * 100.0
        )

        # Assert substantial overall accuracy improvements
        assert overall_mae_improvement > 40.0, (
            f"Expected overall MAE improvement > 40%, got {overall_mae_improvement:.2f}%"
        )
        assert overall_p90_improvement > 40.0, (
            f"Expected overall P90 improvement > 40%, got {overall_p90_improvement:.2f}%"
        )
        assert total_estimator_violations == 0
        assert total_baseline_violations > 10


class TestMonitorServerIntegration:
    """Integration tests verifying MonitorServer expose and emit ETA data cleanly."""

    def test_monitor_server_status_and_api_alias_endpoints(self):
        monitor = MonitorServer(port=0)
        client = TestClient(monitor.app)

        # 1. Check /api/v1/scan/status initial idle state
        resp1 = client.get("/api/v1/scan/status")
        assert resp1.status_code == 200
        data1 = resp1.json()
        assert "eta" in data1
        assert data1["eta"]["status_label"] == "indeterminate"
        assert data1["eta"]["eta_seconds"] is None

        # 2. Check /api/status alias endpoint
        resp_alias = client.get("/api/status")
        assert resp_alias.status_code == 200
        data_alias = resp_alias.json()
        assert data_alias["status"] == data1["status"]
        assert "eta" in data_alias

    def test_monitor_server_emit_progress_and_snapshot(self):
        monitor = MonitorServer(port=0)
        monitor.api_scan_id = "test-eta-scan"
        monitor._begin_scan_snapshot()

        asyncio.run(monitor.emit_phase("crawl"))
        asyncio.run(monitor.emit_progress(
            current=3,
            total=10,
            message="Crawling",
            phase="crawl",
            unit="url",
        ))

        # Check that api_progress contains additive ETA metadata
        assert monitor.api_progress["current"] == 3
        assert monitor.api_progress["total"] == 10
        assert monitor.api_progress["percent"] == 30
        assert "eta_seconds" in monitor.api_progress
        assert "eta_confidence" in monitor.api_progress
        assert "progress_percent" in monitor.api_progress

        # Check snapshot event
        snapshot = monitor._scan_snapshot_event()
        assert "eta" in snapshot["data"]
        eta_data = snapshot["data"]["eta"]
        assert "elapsed_seconds" in eta_data
        assert "progress_percent" in eta_data
        assert "confidence" in eta_data

    def test_monitor_server_pause_resume_and_terminal(self):
        monitor = MonitorServer(port=0)
        monitor.mark_scan_started()

        asyncio.run(monitor.emit_progress(current=4, total=20, phase="attack"))
        assert monitor.get_eta_estimate().status_label in ("calibrating", "estimating")

        # Pause
        asyncio.run(monitor.emit_intervention_state(paused=True))
        assert monitor.get_eta_estimate().status_label == "paused"
        assert monitor.get_eta_estimate().eta_seconds is None

        # Resume
        asyncio.run(monitor.emit_intervention_state(paused=False))
        assert monitor.get_eta_estimate().status_label != "paused"

        # Complete
        asyncio.run(monitor.emit("scan_complete", {"status": "done"}))
        done_est = monitor.get_eta_estimate()
        assert done_est.status_label == "completed"
        assert done_est.eta_seconds == 0
        assert done_est.progress_percent == 100.0
