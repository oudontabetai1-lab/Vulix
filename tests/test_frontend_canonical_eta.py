"""Integration and unit verification for frontend canonical server ETA consumers.

Tests:
1. Server ETA extraction from varied payload envelopes.
2. Canonical ETA DOM rendering in dashboard.html (running, paused, calibrating, indeterminate, done, aborted).
3. Confidence and reason badges (low confidence / dynamic_queue_growth -> '推定困難', range in tooltip/DOM).
4. Strict invariant adherence: progress < 100% while running, ETA >= 1s while running, no fabricated values.
5. Reconnection / snapshot handling and scan reset state cleanup.
6. Fallback to legacy linear estimation when server ETA is absent.
7. /app header status bar (.scan-progress-badge, .scan-eta-badge, metadata attributes and tooltips).
8. Event-stream wire event validation with canonical ETA fields.
"""
from __future__ import annotations

import json
import subprocess
import pytest
from pathlib import Path
from typing import Any

from tests.ui_harness import UIHarness, require_browser, ui_harness

ROOT = Path(__file__).resolve().parents[1]
EVENT_STREAM_JS = ROOT / "templates" / "ui" / "event-stream.js"


@pytest.mark.parametrize("mode", ["normal", "agent", "hybrid"])
def test_actual_monitor_bridge_eta_and_reconnect(ui_harness: UIHarness, mode: str):
    """Wire events and contradictory snapshots cross the real iframe message boundary."""
    require_browser()
    page = ui_harness.new_page()
    try:
        page.goto(f"{ui_harness.server_url}/app#/monitor", wait_until="domcontentloaded")
        page.wait_for_function("() => Boolean(document.querySelector('#monitorModule')?.shadowRoot?.querySelector('#statRemain'))")
        frame = next(f for f in page.frames if f != page.main_frame and '/monitor' in f.url)
        # Isolate injected wire traffic from the harness server's idle snapshots.
        frame.evaluate("() => initEventStream().stop()")
        page.wait_for_timeout(100)
        frame.evaluate("""mode => {
          resetLiveScanState();
          state.mode = mode;
          handleEvent({type: 'progress', timestamp: 1000, data: {
            current: 1, total: 10, percent: 10,
            eta: {eta_seconds: 90, progress_percent: 33.3, confidence: 'medium',
              status_label: 'estimating', reason_code: 'steady_rate', eta_range_seconds: [70, 120]}
          }});
        }""", mode)
        page.wait_for_function("() => document.querySelector('#scanContext .scan-eta-badge')?.textContent === 'ETA: 1分30秒'")
        assert page.locator('#scanContext .scan-progress-badge').inner_text() == '33.3%'
        assert '範囲: 1分10秒〜2分00秒' in page.locator('#scanContext .scan-eta-badge').get_attribute('title')
        frame.evaluate("() => handleEvent({type: 'intervention_state', data: {paused: true}})")
        page.wait_for_function("() => document.querySelector('#scanContext .scan-eta-badge')?.textContent === 'ETA: 一時停止'")
        page.wait_for_timeout(200)
        assert page.locator('#scanContext .scan-eta-badge').inner_text() == 'ETA: 一時停止'
        frame.evaluate("() => handleEvent({type: 'intervention_state', data: {paused: false}})")
        page.wait_for_function("() => document.querySelector('#scanContext .scan-eta-badge')?.textContent === 'ETA: 1分30秒'")
        for paused, label, seconds, expected in [
            (True, 'paused', None, 'ETA: 一時停止'),
            (False, 'calibrating', None, 'ETA: 算出中…'),
            (False, 'estimating', 12, 'ETA: 12秒'),
        ]:
            result = frame.evaluate("""args => {
              const [paused, label, seconds] = args;
              applyScanSnapshot({server_id: 'bridge-server', run_id: 'bridge-run', sequence: 20,
                data: {status: 'scanning', paused,
                  progress: {current: 1, total: 10, percent: 10, eta_seconds: 999,
                    progress_percent: 10, eta_confidence: 'low', eta_status: 'estimating',
                    reason_code: 'stale', eta_range_seconds: [900, 1000], elapsed_seconds: 1},
                  eta: {eta_seconds: seconds, progress_percent: 44, confidence: 'high',
                    status_label: label, reason_code: null, eta_range_seconds: null, elapsed_seconds: 50}}});
              return state.serverEta;
            }""", [paused, label, seconds])
            assert result == dict(etaSeconds=seconds, progressPercent=44, confidence='high',
                                 statusLabel=label, reasonCode=None, range=None, elapsedSeconds=50)
            page.wait_for_function("expected => document.querySelector('#scanContext .scan-eta-badge')?.textContent === expected", arg=expected)
            assert page.locator('#scanContext .scan-progress-badge').inner_text() == '44%'
            assert '900' not in page.locator('#scanContext .scan-eta-badge').get_attribute('title')
            if paused:
                # A paused snapshot can cache paused ETA; live resume must clear it.
                frame.evaluate("() => handleEvent({type: 'intervention_state', data: {paused: false}})")
                page.wait_for_function("() => document.querySelector('#scanContext .scan-eta-badge')?.textContent === 'ETA: 算出中…'")
                frame.evaluate("""() => handleEvent({type: 'progress', timestamp: 1100, data: {
                  current: 2, total: 10, eta: {eta_seconds: 25, progress_percent: 45,
                    confidence: 'high', status_label: 'estimating'}
                }})""")
                page.wait_for_function("() => document.querySelector('#scanContext .scan-eta-badge')?.textContent === 'ETA: 25秒'")
        frame.evaluate("() => { handleEvent({type: 'intervention_state', data: {paused: true}}); resetLiveScanState(); publishAppScanContext(); }")
        assert frame.evaluate("() => state.paused") is False
        page.wait_for_function("() => !document.querySelector('#scanContext .scan-eta-badge')")
        assert page.locator('#scanContext .scan-progress-badge').count() == 0
    finally:
        page.close()


def _run_node_script(script: str) -> dict[str, Any]:
    """Execute a Node.js script in the workspace context."""
    res = subprocess.run(
        ["node", "-"],
        cwd=ROOT,
        check=True,
        capture_output=True,
        text=True,
        input=script,
    )
    return json.loads(res.stdout)


def test_snapshot_eta_present_fields_override_cached_aliases():
    source = (ROOT / 'templates/dashboard.html').read_text()
    helper = source.split('function extractServerEta(payload) {', 1)[1].split('\nfunction updateETA(', 1)[0]
    result = _run_node_script('function extractServerEta(payload) {' + helper + """
      const stale = {eta_seconds: 999, progress_percent: 1, eta_confidence: 'low',
        eta_status: 'estimating', reason_code: 'stale', eta_range_seconds: [900,1000], elapsed_seconds: 1};
      const fresh = {eta_seconds: null, progress_percent: null, confidence: null,
        status_label: 'paused', reason_code: null, eta_range_seconds: null, elapsed_seconds: null};
      console.log(JSON.stringify({fresh: extractServerEta({eta: fresh, progress: stale}),
        fallback: extractServerEta({progress: stale}),
        nested: extractServerEta({progress: {...stale, eta: fresh}})}));
    """)
    expected = dict(etaSeconds=None, progressPercent=None, confidence=None,
                    statusLabel='paused', reasonCode=None, range=None, elapsedSeconds=None)
    assert result['fresh'] == expected
    assert result['nested'] == expected
    assert result['fallback']['etaSeconds'] == 999
    assert result['fallback']['confidence'] == 'low'


def test_event_stream_wire_validation_accepts_canonical_eta():
    """EventStream wire event validation accepts canonical ETA contracts and rejects malformed values."""
    script = f"""
    const {{ validateWireEvent }} = require('{EVENT_STREAM_JS}');
    const validProgress = {{
      type: 'progress',
      server_id: 'srv-1',
      run_id: 'run-1',
      sequence: 1,
      data: {{
        percent: 42,
        current: 42,
        total: 100,
        progress_percent: 42.5,
        eta_seconds: 120,
        eta_confidence: 'high',
        eta_status: 'estimating',
        eta: {{
          elapsed_seconds: 35.0,
          eta_seconds: 120,
          eta_range_seconds: [90, 150],
          progress_percent: 42.5,
          confidence: 'high',
          status_label: 'estimating',
          reason_code: 'steady_rate',
        }}
      }}
    }};
    const validRes = validateWireEvent(validProgress);
    
    const invalidEtaSeconds = {{
      type: 'progress',
      server_id: 'srv-1',
      run_id: 'run-1',
      sequence: 2,
      data: {{
        percent: 42,
        current: 42,
        total: 100,
        eta_seconds: 'not-a-number'
      }}
    }};
    const invalidRes = validateWireEvent(invalidEtaSeconds);
    
    console.log(JSON.stringify({{ valid: validRes.valid, invalid: invalidRes.valid }}));
    """
    res = _run_node_script(script)
    assert res["valid"] is True
    assert res["invalid"] is False


def test_extract_server_eta_helper(ui_harness: UIHarness):
    """Test extractServerEta correctly handles varied nested and flat payload shapes."""
    require_browser()
    page = ui_harness.new_page()
    try:
        page.goto(f"{ui_harness.server_url}/monitor", wait_until="domcontentloaded")
        page.wait_for_selector("#scanConfigOverlay")
        res = page.evaluate("""() => {
          const nested = extractServerEta({
            eta: {
              eta_seconds: 45,
              progress_percent: 65.4,
              confidence: 'medium',
              status_label: 'estimating',
              reason_code: 'steady_rate',
              eta_range_seconds: [30, 60],
              elapsed_seconds: 15.2
            }
          });
          const flat = extractServerEta({
            eta_seconds: 80,
            progress_percent: 30.0,
            eta_confidence: 'low',
            eta_status: 'estimating',
            reason_code: 'dynamic_queue_growth',
            eta_range_seconds: [50, 120],
            elapsed_seconds: 22.0
          });
          const empty = extractServerEta({ percent: 10, current: 1, total: 10 });
          return { nested, flat, empty };
        }""")
        assert res["nested"]["etaSeconds"] == 45
        assert res["nested"]["progressPercent"] == 65.4
        assert res["nested"]["confidence"] == "medium"
        assert res["nested"]["range"] == [30, 60]
        assert res["flat"]["confidence"] == "low"
        assert res["flat"]["reasonCode"] == "dynamic_queue_growth"
        assert res["empty"] is None
    finally:
        page.close()


def test_canonical_eta_estimating_state_rendering(ui_harness: UIHarness):
    """Estimating state renders formatted duration >= 1s, clock, range, and high confidence."""
    require_browser()
    page = ui_harness.new_page()
    try:
        page.goto(f"{ui_harness.server_url}/monitor", wait_until="domcontentloaded")
        page.wait_for_selector("#scanConfigOverlay")
        page.evaluate("() => document.getElementById('scanConfigOverlay').classList.remove('active')")
        dom = page.evaluate("""() => {
          state.scanDone = false;
          state.scanStartTime = null;
          handleEvent({
            type: 'progress',
            data: {
              current: 10,
              total: 20,
              percent: 50,
              eta: {
                elapsed_seconds: 25.0,
                eta_seconds: 75,
                eta_range_seconds: [60, 95],
                progress_percent: 50.0,
                confidence: 'high',
                status_label: 'estimating',
                reason_code: 'steady_rate'
              }
            },
            timestamp: 1000
          });
          return {
            remain: document.getElementById('statRemain').textContent,
            remainTitle: document.getElementById('statRemain').title,
            etaClock: document.getElementById('statETA').textContent,
            metaText: document.getElementById('statEtaMeta').textContent,
            metaClass: document.getElementById('statEtaMeta').className,
            rangeText: document.getElementById('statEtaRange').textContent,
            pctText: document.getElementById('statPct').textContent,
            progressBarWidth: document.getElementById('progressBar').style.width
          };
        }""")
        assert dom["remain"] == "1分15秒"
        assert "残り推定: 1分15秒" in dom["remainTitle"]
        assert "予想範囲: 1分00秒〜1分35秒" in dom["remainTitle"]
        assert dom["etaClock"] != "—"
        assert dom["metaText"] == "高信頼度"
        assert "eta-high" in dom["metaClass"]
        assert "1分00秒〜1分35秒" in dom["rangeText"]
        assert dom["pctText"] == "50%"
        assert dom["progressBarWidth"] == "50%"
    finally:
        page.close()


def test_low_confidence_and_dynamic_queue_growth_badge(ui_harness: UIHarness):
    """Low confidence and dynamic queue growth display '推定困難' badge and uncertainty range."""
    require_browser()
    page = ui_harness.new_page()
    try:
        page.goto(f"{ui_harness.server_url}/monitor", wait_until="domcontentloaded")
        page.wait_for_selector("#scanConfigOverlay")
        page.evaluate("() => document.getElementById('scanConfigOverlay').classList.remove('active')")
        dom = page.evaluate("""() => {
          state.scanDone = false;
          handleEvent({
            type: 'progress',
            data: {
              current: 5,
              total: 30,
              percent: 16,
              eta: {
                elapsed_seconds: 10.0,
                eta_seconds: 180,
                eta_range_seconds: [120, 260],
                progress_percent: 16.7,
                confidence: 'low',
                status_label: 'estimating',
                reason_code: 'dynamic_queue_growth'
              }
            },
            timestamp: 1000
          });
          return {
            remain: document.getElementById('statRemain').textContent,
            remainTitle: document.getElementById('statRemain').title,
            metaText: document.getElementById('statEtaMeta').textContent,
            metaClass: document.getElementById('statEtaMeta').className,
            metaTitle: document.getElementById('statEtaMeta').title,
            rangeText: document.getElementById('statEtaRange').textContent,
            pctText: document.getElementById('statPct').textContent
          };
        }""")
        assert dom["remain"] == "3分00秒"
        assert "推定困難" in dom["remainTitle"]
        assert "動的キュー増加" in dom["remainTitle"]
        assert dom["metaText"] == "推定困難"
        assert "eta-low" in dom["metaClass"]
        assert "動的キュー増加" in dom["metaTitle"]
        assert "2分00秒〜4分20秒" in dom["rangeText"]
        assert dom["pctText"] == "16.7%"
    finally:
        page.close()


def test_calibrating_and_insufficient_samples_honest_state(ui_harness: UIHarness):
    """Calibrating state renders '計測中…' / '算出中…', never fabricating 0s or false countdown."""
    require_browser()
    page = ui_harness.new_page()
    try:
        page.goto(f"{ui_harness.server_url}/monitor", wait_until="domcontentloaded")
        page.wait_for_selector("#scanConfigOverlay")
        page.evaluate("() => document.getElementById('scanConfigOverlay').classList.remove('active')")
        dom = page.evaluate("""() => {
          state.scanDone = false;
          handleEvent({
            type: 'progress',
            data: {
              current: 1,
              total: 20,
              percent: 5,
              eta: {
                elapsed_seconds: 2.0,
                eta_seconds: null,
                eta_range_seconds: null,
                progress_percent: 5.0,
                confidence: 'calibrating',
                status_label: 'calibrating',
                reason_code: 'insufficient_samples'
              }
            },
            timestamp: 1000
          });
          return {
            remain: document.getElementById('statRemain').textContent,
            etaClock: document.getElementById('statETA').textContent,
            metaText: document.getElementById('statEtaMeta').textContent,
            metaClass: document.getElementById('statEtaMeta').className,
            pctText: document.getElementById('statPct').textContent
          };
        }""")
        assert dom["remain"] == "計測中…"
        assert dom["etaClock"] == "—"
        assert dom["metaText"] == "算出中…"
        assert "eta-calibrating" in dom["metaClass"]
        assert dom["pctText"] == "5%"
    finally:
        page.close()


def test_indeterminate_state_rendering(ui_harness: UIHarness):
    """Indeterminate state renders '残量未確定' and '—'."""
    require_browser()
    page = ui_harness.new_page()
    try:
        page.goto(f"{ui_harness.server_url}/monitor", wait_until="domcontentloaded")
        page.wait_for_selector("#scanConfigOverlay")
        page.evaluate("() => document.getElementById('scanConfigOverlay').classList.remove('active')")
        dom = page.evaluate("""() => {
          state.scanDone = false;
          handleEvent({
            type: 'progress',
            data: {
              current: 2,
              total: 0,
              total_known: false,
              percent: 0,
              eta: {
                elapsed_seconds: 5.0,
                eta_seconds: null,
                eta_range_seconds: null,
                progress_percent: 2.0,
                confidence: 'indeterminate',
                status_label: 'indeterminate',
                reason_code: 'insufficient_samples'
              }
            },
            timestamp: 1000
          });
          return {
            remain: document.getElementById('statRemain').textContent,
            etaClock: document.getElementById('statETA').textContent,
            metaText: document.getElementById('statEtaMeta').textContent
          };
        }""")
        assert dom["remain"] == "残量未確定"
        assert dom["etaClock"] == "—"
        assert dom["metaText"] == "残量未確定"
    finally:
        page.close()


def test_paused_state_freezes_eta_without_negative_countdown(ui_harness: UIHarness):
    """Paused state renders '一時停止', freezes countdown, and resets cleanly on resume via real events."""
    require_browser()
    page = ui_harness.new_page()
    try:
        page.goto(f"{ui_harness.server_url}/monitor", wait_until="domcontentloaded")
        page.wait_for_selector("#scanConfigOverlay")
        page.evaluate("() => document.getElementById('scanConfigOverlay').classList.remove('active')")
        dom = page.evaluate("""() => {
          state.scanDone = false;
          // Step 1: Initial running progress event
          handleEvent({
            type: 'progress',
            data: {
              current: 5,
              total: 20,
              percent: 25,
              eta: {
                elapsed_seconds: 15.0,
                eta_seconds: 45,
                progress_percent: 25.0,
                confidence: 'high',
                status_label: 'estimating',
                reason_code: 'steady_rate'
              }
            },
            timestamp: 1000
          });

          // Step 2: Real pause event received from backend intervention stream
          handleEvent({
            type: 'intervention_state',
            data: { paused: true }
          });
          const pausedRemain = document.getElementById('statRemain').textContent;
          const pausedETA = document.getElementById('statETA').textContent;
          const pausedMeta = document.getElementById('statEtaMeta').textContent;
          const isPauseBadgeVisible = document.getElementById('ibPauseState').classList.contains('visible');

          // Step 3: Real resume event received from backend intervention stream
          handleEvent({
            type: 'intervention_state',
            data: { paused: false }
          });

          // Step 4: Subsequent progress event after resume
          handleEvent({
            type: 'progress',
            data: {
              current: 10,
              total: 20,
              percent: 50,
              eta: {
                elapsed_seconds: 30.0,
                eta_seconds: 50,
                progress_percent: 50.0,
                confidence: 'high',
                status_label: 'estimating',
                reason_code: 'steady_rate'
              }
            },
            timestamp: 2000
          });

          return {
            pausedRemain,
            pausedETA,
            pausedMeta,
            isPauseBadgeVisible,
            resumedRemain: document.getElementById('statRemain').textContent,
            resumedMeta: document.getElementById('statEtaMeta').textContent
          };
        }""")
        assert dom["pausedRemain"] == "一時停止"
        assert dom["pausedETA"] == "—"
        assert dom["pausedMeta"] == "一時停止"
        assert dom["isPauseBadgeVisible"] is True
        assert dom["resumedRemain"] == "50秒"
        assert dom["resumedMeta"] == "高信頼度"
    finally:
        page.close()


def test_aborted_and_done_terminal_states(ui_harness: UIHarness):
    """Aborted state renders '中断' (never 100%); done state renders '完了' and 100%."""
    require_browser()
    page = ui_harness.new_page()
    try:
        page.goto(f"{ui_harness.server_url}/monitor", wait_until="domcontentloaded")
        page.wait_for_selector("#scanConfigOverlay")
        page.evaluate("() => document.getElementById('scanConfigOverlay').classList.remove('active')")
        dom = page.evaluate("""() => {
          state.scanDone = false;
          handleEvent({
            type: 'scan_complete',
            data: {
              status: 'aborted',
              aborted: true,
              total_findings: 1,
              findings: [],
              report_path: '/tmp/report.html'
            },
            timestamp: 1000
          });
          const abortedRemain = document.getElementById('statRemain').textContent;
          const abortedETA = document.getElementById('statETA').textContent;
          const abortedPct = document.getElementById('statPct').textContent;

          state.scanDone = false;
          handleEvent({
            type: 'scan_complete',
            data: {
              status: 'done',
              total_findings: 2,
              findings: [],
              report_path: '/tmp/report.html'
            },
            timestamp: 2000
          });
          return {
            abortedRemain,
            abortedETA,
            abortedPct,
            doneRemain: document.getElementById('statRemain').textContent,
            doneETA: document.getElementById('statETA').textContent,
            donePct: document.getElementById('statPct').textContent,
            doneBar: document.getElementById('progressBar').style.width
          };
        }""")
        assert dom["abortedRemain"] == "中断"
        assert dom["abortedETA"] == "—"
        assert dom["abortedPct"] != "100%"
        assert dom["doneRemain"] == "完了"
        assert dom["doneETA"] == "—"
        assert dom["donePct"] == "100%"
        assert dom["doneBar"] == "100%"
    finally:
        page.close()


def test_snapshot_application_and_scan_reset(ui_harness: UIHarness):
    """Snapshot updates canonical ETA; resetLiveScanState clears all badges, tooltips, and state."""
    require_browser()
    page = ui_harness.new_page()
    try:
        page.goto(f"{ui_harness.server_url}/monitor", wait_until="domcontentloaded")
        page.wait_for_selector("#scanConfigOverlay")
        page.evaluate("() => document.getElementById('scanConfigOverlay').classList.remove('active')")
        dom = page.evaluate("""() => {
          applyScanSnapshot({
            server_id: 'srv-1',
            run_id: 'run-1',
            scan_id: 'scan-1',
            sequence: 15,
            data: {
              status: 'scanning',
              progress: {
                current: 25,
                total: 50,
                percent: 50,
                progress_percent: 50.0,
                eta_seconds: 60,
                eta_confidence: 'medium',
                eta_status: 'estimating'
              },
              eta: {
                elapsed_seconds: 40.0,
                eta_seconds: 60,
                eta_range_seconds: [45, 80],
                progress_percent: 50.0,
                confidence: 'medium',
                status_label: 'estimating',
                reason_code: 'steady_rate'
              }
            }
          });
          const snapRemain = document.getElementById('statRemain').textContent;
          const snapMeta = document.getElementById('statEtaMeta').textContent;
          const snapRange = document.getElementById('statEtaRange').textContent;

          resetLiveScanState();
          return {
            snapRemain,
            snapMeta,
            snapRange,
            resetRemain: document.getElementById('statRemain').textContent,
            resetETA: document.getElementById('statETA').textContent,
            resetMetaVisible: document.getElementById('statEtaMeta').style.display,
            resetRangeVisible: document.getElementById('statEtaRange').style.display,
            resetRemainTitle: document.getElementById('statRemain').title
          };
        }""")
        assert dom["snapRemain"] == "1分00秒"
        assert dom["snapMeta"] == "中信頼度"
        assert "45秒〜1分20秒" in dom["snapRange"]
        assert dom["resetRemain"] == "—"
        assert dom["resetETA"] == "—"
        assert dom["resetMetaVisible"] == "none"
        assert dom["resetRangeVisible"] == "none"
        assert dom["resetRemainTitle"] == ""
    finally:
        page.close()


def test_legacy_linear_fallback_when_server_eta_omitted(ui_harness: UIHarness):
    """When server ETA payload is omitted, local series linear rate is computed."""
    require_browser()
    page = ui_harness.new_page()
    try:
        page.goto(f"{ui_harness.server_url}/monitor", wait_until="domcontentloaded")
        page.wait_for_selector("#scanConfigOverlay")
        page.evaluate("() => document.getElementById('scanConfigOverlay').classList.remove('active')")
        dom = page.evaluate("""() => {
          state.scanDone = false;
          state.scanStartTime = null;
          state.etaSeries = null;
          state.serverEta = null;
          updateETA(0, 10, 10, 'attack', 'field', true);
          const initial = document.getElementById('statRemain').textContent;
          updateETA(2, 10, 12, 'attack', 'field', true);
          const computed = document.getElementById('statRemain').textContent;
          const metaVisible = document.getElementById('statEtaMeta').style.display;
          return { initial, computed, metaVisible };
        }""")
        assert dom["initial"] == "計測中…"
        # 2 items in 2 seconds = 1 item/sec; 8 items remaining = 8 seconds
        assert dom["computed"] == "8秒"
        assert dom["metaVisible"] == "none"
    finally:
        page.close()


def test_app_scan_status_bar_canonical_eta_badges(ui_harness: UIHarness):
    """Verify /app header scan-status-bar renders ETA badge and progress badge."""
    require_browser()
    page = ui_harness.new_page()
    try:
        page.goto(f"{ui_harness.server_url}/app", wait_until="domcontentloaded")
        page.wait_for_selector("#viewTitle")
        
        # Test rendering status bar with canonical ETA
        dom = page.evaluate("""() => {
          VulixAppShell.renderScanStatus({
            scan_id: 'scan-eta-test',
            status: 'scanning',
            mode: 'normal',
            target: 'https://test.example.com',
            phase: 'attack',
            connection: 'connected',
            freshness: 'fresh',
            eta: {
              elapsed_seconds: 20.0,
              eta_seconds: 90,
              eta_range_seconds: [70, 120],
              progress_percent: 33.3,
              confidence: 'medium',
              status_label: 'estimating',
              reason_code: 'steady_rate'
            }
          });
          const bar = document.querySelector('#scanContext .scan-status-bar');
          const progBadge = bar.querySelector('.scan-progress-badge');
          const etaBadge = bar.querySelector('.scan-eta-badge');
          return {
            barText: bar.textContent,
            progText: progBadge ? progBadge.textContent : null,
            etaText: etaBadge ? etaBadge.textContent : null,
            etaConfidence: etaBadge ? etaBadge.getAttribute('data-confidence') : null,
            etaTitle: etaBadge ? etaBadge.title : null
          };
        }""")
        assert "Scan scan-eta-test · scanning" in dom["barText"]
        assert dom["progText"] == "33.3%"
        assert dom["etaText"] == "ETA: 1分30秒"
        assert dom["etaConfidence"] == "medium"
        assert "範囲: 1分10秒〜2分00秒" in dom["etaTitle"]
        assert "信頼度: medium" in dom["etaTitle"]

        # Test paused state in /app
        pausedDom = page.evaluate("""() => {
          VulixAppShell.renderScanStatus({
            scan_id: 'scan-eta-test',
            status: 'paused',
            eta: {
              status_label: 'paused',
              progress_percent: 33.3
            }
          });
          const etaBadge = document.querySelector('#scanContext .scan-eta-badge');
          return {
            etaText: etaBadge ? etaBadge.textContent : null,
            statusLabel: etaBadge ? etaBadge.getAttribute('data-status-label') : null
          };
        }""")
        assert pausedDom["etaText"] == "ETA: 一時停止"
        assert pausedDom["statusLabel"] == "paused"

        # Test fallback when ETA is absent: renders cleanly without ETA badge
        fallbackDom = page.evaluate("""() => {
          VulixAppShell.renderScanStatus({
            scan_id: 'scan-eta-test',
            status: 'scanning',
            mode: 'normal'
          });
          const etaBadge = document.querySelector('#scanContext .scan-eta-badge');
          const progBadge = document.querySelector('#scanContext .scan-progress-badge');
          return {
            hasEta: etaBadge !== null,
            hasProg: progBadge !== null
          };
        }""")
        assert fallbackDom["hasEta"] is False
        assert fallbackDom["hasProg"] is False
    finally:
        page.close()
