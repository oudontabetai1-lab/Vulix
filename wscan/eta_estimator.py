"""wscan/eta_estimator.py

Monotonic Phase-Weighted Scan ETA Estimator & Confidence Model.
Provides deterministic, monotonic-clock-based progress and ETA estimation
with phase-weighted throughput, EWMA smoothing, dynamic queue growth adaptation,
timeout variance tracking, and monotonic pause/resume interval accounting.
"""

from __future__ import annotations

import math
import time
from dataclasses import dataclass, field
from typing import Any, Callable, Optional


# Nominal phase weights for standard vulnerability scanning lifecycle.
# In web application security scanning, Attack constitutes the bulk of execution time,
# Crawl discovers attack surfaces, and Verify confirms high-severity findings.
DEFAULT_PHASE_WEIGHTS: dict[str, float] = {
    "crawl": 0.30,
    "plan": 0.05,
    "attack": 0.60,
    "verify": 0.04,
    "report": 0.01,
}

# Standard check weights representing relative expected execution cost.
DEFAULT_CHECK_WEIGHTS: dict[str, float] = {
    "header": 0.2,
    "static": 0.3,
    "standard": 1.0,
    "xss": 1.0,
    "sqli": 1.5,
    "nosql": 1.2,
    "time_based": 3.5,
    "llm": 4.0,
    "browser": 2.5,
    "oob_email": 3.0,
}

# Standard phase ordering for web scans
PHASE_ORDER: list[str] = ["crawl", "plan", "attack", "verify", "report"]


@dataclass
class EtaSample:
    """Snapshot sample recorded during scan progression."""
    phase: str
    completed_units: float = 0.0
    total_units: float = 0.0
    dynamic_units_added: float = 0.0
    concurrency: int = 1
    retry_or_timeout_events: int = 0
    paused_duration_seconds: float = 0.0
    check_weights: dict[str, float] = field(default_factory=dict)
    timestamp: float = 0.0


@dataclass
class PhaseProgressState:
    """Tracks state and progression within a single scan phase."""
    phase: str
    completed_units: float = 0.0
    total_units: float = 0.0
    dynamic_units_added: float = 0.0
    concurrency: int = 1
    retry_or_timeout_events: int = 0
    paused_duration_seconds: float = 0.0
    check_weights: dict[str, float] = field(default_factory=dict)
    last_updated: float = 0.0


@dataclass
class EtaEstimate:
    """Deterministic ETA estimate and confidence output."""
    elapsed_seconds: float
    eta_seconds: Optional[int]
    eta_range_seconds: Optional[tuple[int, int]]
    progress_percent: float
    confidence: str  # "high" | "medium" | "low" | "calibrating" | "indeterminate"
    status_label: str  # "estimating" | "calibrating" | "indeterminate" | "paused" | "completed" | "aborted"
    reason_code: str  # "insufficient_samples" | "dynamic_queue_growth" | "high_timeout_variance" | "paused" | "steady_rate" | "terminal_state"

    def to_dict(self) -> dict[str, Any]:
        return {
            "elapsed_seconds": self.elapsed_seconds,
            "eta_seconds": self.eta_seconds,
            "eta_range_seconds": list(self.eta_range_seconds) if self.eta_range_seconds is not None else None,
            "progress_percent": self.progress_percent,
            "confidence": self.confidence,
            "status_label": self.status_label,
            "reason_code": self.reason_code,
        }


class EtaEstimator:
    """Monotonic clock-based phase-weighted ETA estimator with EWMA smoothing.

    Invariants maintained:
    1. progress_percent is strictly < 100.0 until phase == "completed" (100% never appears while work runs).
    2. progress_percent == 100.0 upon completion.
    3. eta_seconds is strictly >= 1 (or None) while work runs (never 0 or negative while running).
    4. eta_seconds == 0 upon completion.
    5. elapsed_seconds accounts strictly for active monotonic time, subtracting paused duration.
    """

    def __init__(
        self,
        clock: Callable[[], float] = time.monotonic,
        phase_weights: Optional[dict[str, float]] = None,
        check_weights: Optional[dict[str, float]] = None,
        ewma_alpha: float = 0.10,
        min_calibration_samples: int = 3,
        min_calibration_seconds: float = 2.0,
    ) -> None:
        self.clock = clock
        self.phase_weights = dict(phase_weights or DEFAULT_PHASE_WEIGHTS)
        self.check_weights = dict(check_weights or DEFAULT_CHECK_WEIGHTS)
        self.ewma_alpha = max(0.01, min(0.99, float(ewma_alpha)))
        self.min_calibration_samples = max(1, int(min_calibration_samples))
        self.min_calibration_seconds = max(0.0, float(min_calibration_seconds))

        self.reset()

    def reset(self) -> None:
        """Reset estimator to pristine initial state."""
        self.start_time: Optional[float] = None
        self.terminal_status: Optional[str] = None
        self.terminal_timestamp: Optional[float] = None

        self.is_paused: bool = False
        self.pause_start_time: Optional[float] = None
        self.accumulated_paused_seconds: float = 0.0

        self.current_phase: str = "crawl"
        self.phase_states: dict[str, PhaseProgressState] = {}
        self.samples: list[EtaSample] = []

        # EWMA rate state (completed units per second per concurrency worker)
        self.ewma_unit_rate: Optional[float] = None
        self.recent_rates: list[float] = []

        # Dynamics tracking
        self.total_dynamic_units_added: float = 0.0
        self.recent_dynamic_additions: list[float] = []
        self.total_timeout_events: int = 0
        self.recent_timeout_events: list[int] = []

    def start(self, timestamp: Optional[float] = None) -> None:
        """Record scan start timestamp using monotonic clock."""
        now = self.clock() if timestamp is None else float(timestamp)
        self.start_time = now
        self.terminal_status = None
        self.terminal_timestamp = None
        self.is_paused = False
        self.pause_start_time = None
        self.accumulated_paused_seconds = 0.0

    def pause(self, timestamp: Optional[float] = None) -> None:
        """Pause scan progression; suspends monotonic active elapsed timer."""
        if self.is_paused:
            return
        now = self.clock() if timestamp is None else float(timestamp)
        if self.start_time is None:
            self.start_time = now
        self.is_paused = True
        self.pause_start_time = now

    def resume(self, timestamp: Optional[float] = None) -> None:
        """Resume scan progression after pause."""
        if not self.is_paused:
            return
        now = self.clock() if timestamp is None else float(timestamp)
        if self.pause_start_time is not None:
            self.accumulated_paused_seconds += max(0.0, now - self.pause_start_time)
            self.pause_start_time = None
        self.is_paused = False

    def set_paused(self, paused: bool, timestamp: Optional[float] = None) -> None:
        """Synchronize pause/resume status."""
        if paused:
            self.pause(timestamp=timestamp)
        else:
            self.resume(timestamp=timestamp)

    def record_phase(
        self,
        phase: str,
        total_units: Optional[float] = None,
        timestamp: Optional[float] = None,
    ) -> None:
        """Switch current phase."""
        now = self.clock() if timestamp is None else float(timestamp)
        if self.start_time is None:
            self.start_time = now
        clean_phase = str(phase or "crawl").strip().lower()
        self.current_phase = clean_phase
        if clean_phase not in self.phase_states:
            self.phase_states[clean_phase] = PhaseProgressState(
                phase=clean_phase,
                total_units=float(total_units) if total_units is not None else 0.0,
                last_updated=now,
            )
        elif total_units is not None:
            self.phase_states[clean_phase].total_units = float(total_units)
            self.phase_states[clean_phase].last_updated = now

    def record_progress(
        self,
        current: float,
        total: float,
        phase: Optional[str] = None,
        concurrency: Optional[int] = None,
        dynamic_units_added: float = 0.0,
        retry_or_timeout_events: Optional[int] = None,
        timestamp: Optional[float] = None,
    ) -> None:
        """Record a progress update sample."""
        now = self.clock() if timestamp is None else float(timestamp)
        if self.start_time is None:
            self.start_time = now

        p = str(phase or self.current_phase or "crawl").strip().lower()
        self.current_phase = p
        curr_val = max(0.0, float(current))
        total_val = max(curr_val, float(total))
        conc = max(1, int(concurrency if concurrency is not None else 1))
        dyn_added = max(0.0, float(dynamic_units_added))
        timeouts = max(0, int(retry_or_timeout_events if retry_or_timeout_events is not None else 0))

        if p not in self.phase_states:
            self.phase_states[p] = PhaseProgressState(
                phase=p,
                completed_units=curr_val,
                total_units=total_val,
                dynamic_units_added=dyn_added,
                concurrency=conc,
                retry_or_timeout_events=timeouts,
                last_updated=now,
            )
        else:
            st = self.phase_states[p]
            # Detect dynamic growth if total increased beyond previously known total
            if total_val > st.total_units and dyn_added == 0.0:
                dyn_added = total_val - st.total_units
            st.completed_units = curr_val
            st.total_units = total_val
            st.dynamic_units_added += dyn_added
            st.concurrency = conc
            st.retry_or_timeout_events = timeouts
            st.last_updated = now

        if dyn_added > 0.0:
            self.total_dynamic_units_added += dyn_added
            self.recent_dynamic_additions.append(dyn_added)
            if len(self.recent_dynamic_additions) > 10:
                self.recent_dynamic_additions.pop(0)

        if timeouts > self.total_timeout_events:
            diff = timeouts - self.total_timeout_events
            self.total_timeout_events = timeouts
            self.recent_timeout_events.append(diff)
            if len(self.recent_timeout_events) > 10:
                self.recent_timeout_events.pop(0)

        sample = EtaSample(
            phase=p,
            completed_units=curr_val,
            total_units=total_val,
            dynamic_units_added=dyn_added,
            concurrency=conc,
            retry_or_timeout_events=timeouts,
            paused_duration_seconds=self._get_total_paused_duration(now),
            timestamp=now,
        )
        self.add_sample(sample)

    def add_sample(self, sample: EtaSample) -> None:
        """Add an EtaSample directly and update EWMA throughput."""
        now = sample.timestamp
        if self.start_time is None:
            self.start_time = now

        if self.samples:
            prev = self.samples[-1]
            dt = now - prev.timestamp
            du = sample.completed_units - prev.completed_units
            # If phase changed, don't take negative or cross-phase du as instant rate
            if sample.phase == prev.phase and dt >= 0.05 and du >= 0.0:
                inst_throughput = du / dt
                # Rate normalized per worker concurrency
                per_worker_rate = inst_throughput / max(1, sample.concurrency)
                if self.ewma_unit_rate is None:
                    self.ewma_unit_rate = per_worker_rate
                else:
                    self.ewma_unit_rate = (
                        self.ewma_alpha * per_worker_rate
                        + (1.0 - self.ewma_alpha) * self.ewma_unit_rate
                    )
                self.recent_rates.append(inst_throughput)
                if len(self.recent_rates) > 15:
                    self.recent_rates.pop(0)

        self.samples.append(sample)

    def record_terminal(
        self,
        status: str = "completed",
        timestamp: Optional[float] = None,
    ) -> None:
        """Mark scan finished with terminal status ('completed', 'failed', 'aborted')."""
        now = self.clock() if timestamp is None else float(timestamp)
        if self.start_time is None:
            self.start_time = now
        st = str(status or "completed").strip().lower()
        if st not in ("completed", "failed", "aborted"):
            st = "completed"
        self.terminal_status = st
        self.terminal_timestamp = now

    def _get_total_paused_duration(self, current_time: float) -> float:
        """Compute accumulated paused duration including active pause if any."""
        paused = self.accumulated_paused_seconds
        if self.is_paused and self.pause_start_time is not None:
            paused += max(0.0, current_time - self.pause_start_time)
        return paused

    def _get_active_elapsed_seconds(self, current_time: float) -> float:
        """Compute active (non-paused) elapsed time in seconds."""
        if self.start_time is None:
            return 0.0
        ref_time = self.terminal_timestamp if self.terminal_timestamp is not None else current_time
        total_span = max(0.0, ref_time - self.start_time)
        paused = self._get_total_paused_duration(ref_time)
        return max(0.0, total_span - paused)

    def _calculate_phase_weighted_progress(self) -> float:
        """Compute overall progress ratio in [0.0, 1.0] across all lifecycle phases."""
        curr_phase = self.current_phase
        weights = self.phase_weights

        # Determine active phases in order
        order = [p for p in PHASE_ORDER if p in weights]
        if curr_phase not in order:
            order.append(curr_phase)

        # Filter out prior phases that never ran (were skipped)
        active_order: list[str] = []
        for p in order:
            if p in self.phase_states or p == curr_phase:
                active_order.append(p)
            elif active_order:  # Subsequent phase after first recorded phase
                active_order.append(p)

        if not active_order:
            active_order = [curr_phase]

        total_weight = sum(weights.get(p, 0.1) for p in active_order)
        if total_weight <= 0:
            total_weight = 1.0

        accumulated_progress = 0.0
        seen_curr = False

        for p in active_order:
            w = weights.get(p, 0.1) / total_weight
            if p == curr_phase:
                seen_curr = True
                st = self.phase_states.get(p)
                if st and st.total_units > 0:
                    intra_progress = min(1.0, max(0.0, st.completed_units / st.total_units))
                else:
                    intra_progress = 0.0
                accumulated_progress += w * intra_progress
            elif not seen_curr:
                # Prior phase that actually ran
                accumulated_progress += w * 1.0
            else:
                # Future phase not started
                pass

        return min(1.0, max(0.0, accumulated_progress))

    def estimate(self, timestamp: Optional[float] = None) -> EtaEstimate:
        """Produce deterministic, monotonic-clock-based EtaEstimate."""
        now = self.clock() if timestamp is None else float(timestamp)
        active_elapsed = self._get_active_elapsed_seconds(now)
        elapsed_rounded = round(active_elapsed, 2)

        # 0. Unstarted state handling
        if self.start_time is None and self.terminal_status is None:
            return EtaEstimate(
                elapsed_seconds=0.0,
                eta_seconds=None,
                eta_range_seconds=None,
                progress_percent=0.0,
                confidence="indeterminate",
                status_label="indeterminate",
                reason_code="insufficient_samples",
            )

        # 1. Terminal state handling
        if self.terminal_status is not None:
            if self.terminal_status == "completed":
                return EtaEstimate(
                    elapsed_seconds=elapsed_rounded,
                    eta_seconds=0,
                    eta_range_seconds=None,
                    progress_percent=100.0,
                    confidence="high",
                    status_label="completed",
                    reason_code="terminal_state",
                )
            else:
                # aborted or failed
                pct = min(99.9, round(self._calculate_phase_weighted_progress() * 100.0, 1))
                return EtaEstimate(
                    elapsed_seconds=elapsed_rounded,
                    eta_seconds=None,
                    eta_range_seconds=None,
                    progress_percent=pct,
                    confidence="indeterminate",
                    status_label=self.terminal_status,
                    reason_code="terminal_state",
                )

        # 2. Paused state handling
        if self.is_paused:
            raw_pct = self._calculate_phase_weighted_progress() * 100.0
            pct = min(99.9, max(0.0, round(raw_pct, 1)))
            return EtaEstimate(
                elapsed_seconds=elapsed_rounded,
                eta_seconds=None,
                eta_range_seconds=None,
                progress_percent=pct,
                confidence="indeterminate",
                status_label="paused",
                reason_code="paused",
            )

        # 3. Calibration state handling (insufficient samples or initial time)
        st = self.phase_states.get(self.current_phase)
        total_completed_all_phases = sum(s.completed_units for s in self.phase_states.values())

        if (
            len(self.samples) < self.min_calibration_samples
            or active_elapsed < self.min_calibration_seconds
            or total_completed_all_phases <= 0.0
        ):
            raw_pct = self._calculate_phase_weighted_progress() * 100.0
            pct = min(99.9, max(0.0, round(raw_pct, 1)))
            return EtaEstimate(
                elapsed_seconds=elapsed_rounded,
                eta_seconds=None,
                eta_range_seconds=None,
                progress_percent=pct,
                confidence="calibrating",
                status_label="calibrating",
                reason_code="insufficient_samples",
            )

        # 4. Active Estimation Calculation
        overall_prog = self._calculate_phase_weighted_progress()
        raw_pct = overall_prog * 100.0
        # Invariant: progress_percent < 100.0 while scan is still running!
        pct = min(99.9, max(0.0, round(raw_pct, 1)))

        # Determine effective throughput (units per second)
        concurrency = st.concurrency if st else 1
        concurrency = max(1, concurrency)

        # Base worker rate from EWMA or fallback to overall average
        if self.ewma_unit_rate is not None and self.ewma_unit_rate > 0.0001:
            worker_rate = self.ewma_unit_rate
        else:
            avg_rate = total_completed_all_phases / max(0.1, active_elapsed)
            worker_rate = avg_rate / concurrency

        effective_rate = max(0.001, worker_rate * concurrency)

        # Estimate remaining units in current phase
        if st and st.total_units > st.completed_units:
            rem_units_curr = st.total_units - st.completed_units
        else:
            rem_units_curr = 0.0

        t_rem_curr = rem_units_curr / effective_rate

        # Estimate remaining time for subsequent phases
        weights = self.phase_weights
        order = [p for p in PHASE_ORDER if p in weights]
        curr_phase = self.current_phase
        if curr_phase not in order:
            order.append(curr_phase)

        active_order = []
        for p in order:
            if p in self.phase_states or p == curr_phase:
                active_order.append(p)
            elif active_order:
                active_order.append(p)

        if not active_order:
            active_order = [curr_phase]

        tot_active_w = sum(weights.get(p, 0.1) for p in active_order)
        curr_weight = weights.get(curr_phase, 0.5)
        curr_norm_w = curr_weight / max(0.001, tot_active_w)

        future_weight = 0.0
        seen_curr = False
        for p in active_order:
            if p == curr_phase:
                seen_curr = True
            elif seen_curr:
                future_weight += weights.get(p, 0.0)
        future_norm_w = future_weight / max(0.001, tot_active_w)

        if curr_norm_w > 0 and (t_rem_curr > 0 or (st and st.completed_units > 0)):
            if st and st.total_units > 0:
                est_full_curr = st.total_units / effective_rate
            else:
                est_full_curr = max(active_elapsed, t_rem_curr)
            t_rem_future = est_full_curr * (future_norm_w / max(0.05, curr_norm_w))
        else:
            t_rem_future = 0.0

        unit_rem_sec = t_rem_curr + t_rem_future

        # Blended with overall progress-rate projection
        if overall_prog > 0.02 and active_elapsed > 2.0:
            prog_rem_sec = active_elapsed * ((1.0 - overall_prog) / max(0.001, overall_prog))
            total_rem_sec = 0.5 * prog_rem_sec + 0.5 * unit_rem_sec
        else:
            total_rem_sec = unit_rem_sec

        # Invariant: eta_seconds is strictly >= 1 while scan is running
        eta_sec = max(1, int(round(total_rem_sec)))

        # Assess confidence, reason_code, and range based on dynamics
        is_dynamic_growth = bool(
            self.recent_dynamic_additions and sum(self.recent_dynamic_additions) > 0.0
        )
        has_timeout_variance = bool(
            self.recent_timeout_events and sum(self.recent_timeout_events) > 0
        )

        # Check rate variance if we have recent rates
        rate_variance_high = False
        if len(self.recent_rates) >= 4:
            mean_r = sum(self.recent_rates) / len(self.recent_rates)
            if mean_r > 0.001:
                variance = sum((r - mean_r) ** 2 for r in self.recent_rates) / len(self.recent_rates)
                cv = math.sqrt(variance) / mean_r
                if cv > 0.5:
                    rate_variance_high = True

        if has_timeout_variance or rate_variance_high:
            confidence = "low"
            reason_code = "high_timeout_variance"
            low_bound = max(1, int(round(eta_sec * 0.55)))
            high_bound = max(low_bound + 1, int(round(eta_sec * 1.85)))
        elif is_dynamic_growth:
            confidence = "medium"
            reason_code = "dynamic_queue_growth"
            low_bound = max(1, int(round(eta_sec * 0.75)))
            high_bound = max(low_bound + 1, int(round(eta_sec * 1.50)))
        else:
            confidence = "high"
            reason_code = "steady_rate"
            low_bound = max(1, int(round(eta_sec * 0.85)))
            high_bound = max(low_bound, int(round(eta_sec * 1.20)))

        return EtaEstimate(
            elapsed_seconds=elapsed_rounded,
            eta_seconds=eta_sec,
            eta_range_seconds=(low_bound, high_bound),
            progress_percent=pct,
            confidence=confidence,
            status_label="estimating",
            reason_code=reason_code,
        )


def evaluate_eta_accuracy(trace: list[dict[str, Any]]) -> dict[str, Any]:
    """Compare baseline naive linear ETA vs EtaEstimator over a synthetic or real trace.

    Returns MAE, Median AE, P90 AE, relative error, zero-while-running violations,
    and 100%-before-done violations for both methods, along with improvement percentages.
    """
    if not trace:
        raise ValueError("Trace must contain at least one event.")

    # 1. Determine finish timestamp
    t_finish = None
    for event in reversed(trace):
        if event.get("phase") == "completed" or event.get("is_completed"):
            t_finish = float(event["timestamp"])
            break
    if t_finish is None:
        t_finish = float(trace[-1]["timestamp"])

    estimator = EtaEstimator()
    start_time = float(trace[0]["timestamp"])
    estimator.start(timestamp=start_time)

    baseline_errors: list[float] = []
    estimator_errors: list[float] = []
    baseline_rel_errors: list[float] = []
    estimator_rel_errors: list[float] = []

    baseline_zero_violations = 0
    estimator_zero_violations = 0
    baseline_hundred_violations = 0
    estimator_hundred_violations = 0

    for event in trace:
        ts = float(event["timestamp"])
        phase = str(event.get("phase", "attack")).strip().lower()
        completed = float(event.get("completed_units", 0.0))
        total = float(event.get("total_units", 0.0))
        concurrency = int(event.get("concurrency", 1))
        paused = bool(event.get("is_paused") or event.get("paused", False))
        dyn_added = float(event.get("dynamic_units_added", 0.0))
        timeouts = int(event.get("retry_or_timeout_events", 0))

        # Check if terminal
        if phase == "completed" or event.get("is_completed"):
            estimator.record_terminal("completed", timestamp=ts)
            continue

        actual_remaining = max(0.0, t_finish - ts)

        # Update estimator
        estimator.set_paused(paused, timestamp=ts)
        estimator.record_progress(
            current=completed,
            total=total,
            phase=phase,
            concurrency=concurrency,
            dynamic_units_added=dyn_added,
            retry_or_timeout_events=timeouts,
            timestamp=ts,
        )
        est = estimator.estimate(timestamp=ts)

        # Estimator invariants & error tracking
        if est.progress_percent >= 100.0:
            estimator_hundred_violations += 1
        if est.eta_seconds == 0:
            estimator_zero_violations += 1

        if est.eta_seconds is not None:
            est_err = abs(est.eta_seconds - actual_remaining)
            estimator_errors.append(est_err)
            if actual_remaining > 0:
                estimator_rel_errors.append(est_err / actual_remaining)

        # Baseline Naive Linear Estimator
        elapsed = max(0.001, ts - start_time)
        naive_pct = (completed / total * 100.0) if total > 0 else 0.0
        if naive_pct >= 100.0:
            baseline_hundred_violations += 1

        if completed > 0 and elapsed > 0:
            naive_rate = completed / elapsed
            naive_rem_sec = max(0.0, (total - completed) / naive_rate)
            naive_eta = int(round(naive_rem_sec))
        else:
            naive_eta = None

        if naive_eta == 0:
            baseline_zero_violations += 1

        if naive_eta is not None:
            base_err = abs(naive_eta - actual_remaining)
            baseline_errors.append(base_err)
            if actual_remaining > 0:
                baseline_rel_errors.append(base_err / actual_remaining)

    def _stats(errors: list[float], rel_errors: list[float]) -> tuple[float, float, float, float]:
        if not errors:
            return 0.0, 0.0, 0.0, 0.0
        s_errors = sorted(errors)
        n = len(s_errors)
        mae = sum(s_errors) / n
        median = s_errors[n // 2]
        p90_idx = min(n - 1, int(math.ceil(0.90 * n)) - 1)
        p90 = s_errors[p90_idx]
        rel = (sum(rel_errors) / len(rel_errors)) if rel_errors else 0.0
        return round(mae, 2), round(median, 2), round(p90, 2), round(rel, 4)

    b_mae, b_med, b_p90, b_rel = _stats(baseline_errors, baseline_rel_errors)
    e_mae, e_med, e_p90, e_rel = _stats(estimator_errors, estimator_rel_errors)

    imp_mae = round(((b_mae - e_mae) / b_mae * 100.0), 2) if b_mae > 0 else 0.0
    imp_p90 = round(((b_p90 - e_p90) / b_p90 * 100.0), 2) if b_p90 > 0 else 0.0

    return {
        "sample_count": len(trace),
        "evaluated_predictions": len(estimator_errors),
        "baseline": {
            "mae_seconds": b_mae,
            "median_abs_error_seconds": b_med,
            "p90_abs_error_seconds": b_p90,
            "relative_error": b_rel,
            "zero_while_running_violations": baseline_zero_violations,
            "hundred_percent_before_done_violations": baseline_hundred_violations,
        },
        "estimator": {
            "mae_seconds": e_mae,
            "median_abs_error_seconds": e_med,
            "p90_abs_error_seconds": e_p90,
            "relative_error": e_rel,
            "zero_while_running_violations": estimator_zero_violations,
            "hundred_percent_before_done_violations": estimator_hundred_violations,
        },
        "improvement_percent_mae": imp_mae,
        "improvement_percent_p90": imp_p90,
    }


def generate_synthetic_trace(
    scenario: str,
    step_interval: float = 2.0,
) -> list[dict[str, Any]]:
    """Generate realistic deterministic event traces for synthetic benchmark scenarios.

    Scenarios:
    - 'small_site': crawl (5 URLs) -> attack (15 fields) -> report -> completed
    - 'medium_site': crawl (20 URLs) -> plan -> attack (60 fields) -> verify (4 findings) -> report -> completed
    - 'large_site': crawl (60 URLs) -> plan -> attack (180 fields) -> verify (10 findings) -> report -> completed
    - 'dynamic_discovery': crawl and attack expand their totals dynamically during scanning
    - 'timeout_spikes': probes hit slow responses / network timeouts causing rate drops & retries
    - 'pause_resume': user pauses scan during execution for an interval then resumes
    """
    clean_scenario = str(scenario or "medium_site").strip().lower()
    events: list[dict[str, Any]] = []
    t = 100.0  # Monotonic base

    if clean_scenario == "small_site":
        # Crawl: 5 URLs, 1 per 2 sec
        for i in range(1, 6):
            t += step_interval
            events.append({
                "timestamp": t,
                "phase": "crawl",
                "completed_units": i,
                "total_units": 5,
                "concurrency": 1,
            })
        # Attack: 15 fields, 1.5 per 2 sec
        for i in range(1, 16):
            t += step_interval
            events.append({
                "timestamp": t,
                "phase": "attack",
                "completed_units": i,
                "total_units": 15,
                "concurrency": 2,
            })
        # Report
        t += step_interval
        events.append({"timestamp": t, "phase": "report", "completed_units": 1, "total_units": 1})
        t += step_interval
        events.append({"timestamp": t, "phase": "completed", "completed_units": 1, "total_units": 1})

    elif clean_scenario == "medium_site":
        # Crawl: 20 URLs
        for i in range(1, 21):
            t += step_interval
            events.append({
                "timestamp": t,
                "phase": "crawl",
                "completed_units": i,
                "total_units": 20,
                "concurrency": 1,
            })
        # Plan: 5 units
        for i in range(1, 6):
            t += step_interval
            events.append({
                "timestamp": t,
                "phase": "plan",
                "completed_units": i,
                "total_units": 5,
                "concurrency": 1,
            })
        # Attack: 60 fields, concurrency 4
        for i in range(2, 61, 2):
            t += step_interval
            events.append({
                "timestamp": t,
                "phase": "attack",
                "completed_units": i,
                "total_units": 60,
                "concurrency": 4,
            })
        # Verify: 4 findings
        for i in range(1, 5):
            t += step_interval
            events.append({
                "timestamp": t,
                "phase": "verify",
                "completed_units": i,
                "total_units": 4,
                "concurrency": 1,
            })
        t += step_interval
        events.append({"timestamp": t, "phase": "report", "completed_units": 1, "total_units": 1})
        t += step_interval
        events.append({"timestamp": t, "phase": "completed", "completed_units": 1, "total_units": 1})

    elif clean_scenario == "large_site":
        # Crawl: 60 URLs
        for i in range(3, 61, 3):
            t += step_interval
            events.append({
                "timestamp": t,
                "phase": "crawl",
                "completed_units": i,
                "total_units": 60,
                "concurrency": 2,
            })
        # Attack: 180 fields, concurrency 8
        for i in range(6, 181, 6):
            t += step_interval
            events.append({
                "timestamp": t,
                "phase": "attack",
                "completed_units": i,
                "total_units": 180,
                "concurrency": 8,
            })
        # Verify: 10 findings
        for i in range(2, 11, 2):
            t += step_interval
            events.append({
                "timestamp": t,
                "phase": "verify",
                "completed_units": i,
                "total_units": 10,
                "concurrency": 2,
            })
        t += step_interval
        events.append({"timestamp": t, "phase": "report", "completed_units": 1, "total_units": 1})
        t += step_interval
        events.append({"timestamp": t, "phase": "completed", "completed_units": 1, "total_units": 1})

    elif clean_scenario == "dynamic_discovery":
        # Crawl starts with 5 URLs, expands to 15, then 25
        total_crawl = 5
        for i in range(1, 26):
            t += step_interval
            if i == 5:
                total_crawl = 15
            elif i == 14:
                total_crawl = 25
            events.append({
                "timestamp": t,
                "phase": "crawl",
                "completed_units": i,
                "total_units": total_crawl,
                "dynamic_units_added": 10 if i in (5, 14) else 0,
                "concurrency": 2,
            })
        # Attack starts with 20 fields, discovers 30 more, then 20 more
        total_attack = 20
        for i in range(2, 71, 2):
            t += step_interval
            dyn = 0
            if i == 18:
                total_attack = 50
                dyn = 30
            elif i == 46:
                total_attack = 70
                dyn = 20
            events.append({
                "timestamp": t,
                "phase": "attack",
                "completed_units": i,
                "total_units": total_attack,
                "dynamic_units_added": dyn,
                "concurrency": 4,
            })
        t += step_interval
        events.append({"timestamp": t, "phase": "completed", "completed_units": 70, "total_units": 70})

    elif clean_scenario == "timeout_spikes":
        # Attack with timeout spikes and retry events
        total_attack = 50
        timeouts = 0
        for i in range(1, 51):
            if 15 <= i <= 25:
                # Slow timeout period
                t += step_interval * 3.0
                timeouts += 1
            else:
                t += step_interval
            events.append({
                "timestamp": t,
                "phase": "attack",
                "completed_units": i,
                "total_units": total_attack,
                "retry_or_timeout_events": timeouts,
                "concurrency": 2,
            })
        t += step_interval
        events.append({"timestamp": t, "phase": "completed", "completed_units": 50, "total_units": 50})

    elif clean_scenario == "pause_resume":
        # Scan executes 10 units, pauses for 20 seconds, then resumes
        total_attack = 30
        for i in range(1, 11):
            t += step_interval
            events.append({
                "timestamp": t,
                "phase": "attack",
                "completed_units": i,
                "total_units": total_attack,
                "is_paused": False,
            })
        # Paused period (progress does not advance)
        for _ in range(5):
            t += 4.0
            events.append({
                "timestamp": t,
                "phase": "attack",
                "completed_units": 10,
                "total_units": total_attack,
                "is_paused": True,
            })
        # Resumed period
        for i in range(11, 31):
            t += step_interval
            events.append({
                "timestamp": t,
                "phase": "attack",
                "completed_units": i,
                "total_units": total_attack,
                "is_paused": False,
            })
        t += step_interval
        events.append({"timestamp": t, "phase": "completed", "completed_units": 30, "total_units": 30})

    else:
        raise ValueError(f"Unknown synthetic scenario: {scenario}")

    return events
