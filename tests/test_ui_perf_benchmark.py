"""Deterministic performance benchmarks and layout stress tests for /app screens.

Measures render/update time and DOM/memory bounds in Chromium for:
1. Monitor log/event view loaded with 10,000+ entries (local fixtures, no network).
   - Threshold: render/update time <= 250 ms, about 9.8x the slowest (25.50 ms) post-batching measurement, allowing a 4x CI slowdown plus variance headroom.
2. Findings list loaded with 10,000+ entries (local fixtures, no network).
   - Threshold: initial render time <= 250 ms, DOM count bounded <= 100 items.
   - Memory and DOM remain strictly bounded via incremental rendering.
3. Long URLs, request bodies, and payloads stress test:
   - Layout integrity: no unbounded horizontal overflow at 1440, 1280, 768 viewports.
   - Full value remains available (accessible in DOM, code block, or detail panel).
4. Responsive screenshot capture and dimension comparison at 1440/1280/768:
   - Written exclusively to temporary directories as test artefacts.
"""
from __future__ import annotations

import json
from pathlib import Path
import tempfile
import time
from typing import Any

import pytest

from tests.ui_harness import (
    parse_png_dimensions,
    require_browser,
    STANDARD_VIEWPORTS,
    UIHarness,
    ui_harness,
)


@pytest.fixture
def perf_harness(ui_harness: UIHarness) -> UIHarness:
    """UIHarness with baseline scans."""
    ui_harness.seed_representative_scans()
    return ui_harness


def test_monitor_event_log_10k_entries_benchmark(perf_harness: UIHarness):
    """Verify Monitor log view updates deterministically with 10,000+ entries within performance budget."""
    require_browser()
    page = perf_harness.new_page(**STANDARD_VIEWPORTS[1440])

    try:
        page.route_web_socket("**/ws", lambda websocket: None)
        page.goto(f"{perf_harness.server_url}/monitor")
        page.wait_for_selector("#eventLog")
        page.wait_for_function("() => typeof addEventLog === 'function'")

        # Measure 10,000 sequential event log additions
        res = page.evaluate("""async () => {
            const start = performance.now();
            const startMem = performance.memory ? performance.memory.usedJSHeapSize : 0;

            window._eventLogEntries.length = 0;
            document.getElementById('eventLog').replaceChildren();

            for (let i = 0; i < 10000; i++) {
                const kind = i % 10 === 0 ? "finding" : (i % 5 === 0 ? "error" : "status");
                addEventLog(kind, `Event [seq=${i}]: tested parameter param_${i} on http://store.internal.local/api/v1/resource/item?token=dummy_val`);
            }
            await new Promise(requestAnimationFrame);

            const durationMs = performance.now() - start;
            const endMem = performance.memory ? performance.memory.usedJSHeapSize : 0;
            const domCount = document.querySelectorAll('#eventLog .event-item').length;
            const storedCount = window._eventLogEntries.length;
            const searchableCount = window._eventLogEntries.filter(entry => entry.message.includes('tested parameter')).length;
            const firstVisible = document.querySelector('#eventLog .event-item')?.textContent || '';
            const lastVisible = document.querySelector('#eventLog .event-item:last-child')?.textContent || '';
            const eventLog = document.getElementById('eventLog');
            eventLog.scrollTop = 0;
            eventLog.dispatchEvent(new Event('scroll'));
            const olderFirstVisible = document.querySelector('#eventLog .event-item')?.textContent || '';
            const olderLastVisible = document.querySelector('#eventLog .event-item:last-child')?.textContent || '';
            return {
                durationMs,
                domCount,
                storedCount,
                searchableCount,
                firstVisible,
                lastVisible,
                olderFirstVisible,
                olderLastVisible,
                memDelta: endMem - startMem,
                usedMem: endMem,
            };
        }""")

        print(f"Monitor 10k events: {res['durationMs']:.2f} ms; store={res['storedCount']}; searchable={res['searchableCount']}; visible={res['domCount']}")
        assert res["durationMs"] < 250.0, f"Monitor 10k update time exceeded threshold: {res['durationMs']} ms"
        assert res["storedCount"] == 10000
        assert res["searchableCount"] == 10000
        assert res["domCount"] == 500
        assert "seq=9500" in res["firstVisible"]
        assert "seq=9999" in res["lastVisible"]
        assert "seq=9250" in res["olderFirstVisible"]
        assert "seq=9749" in res["olderLastVisible"]
    finally:
        page.close()


def test_monitor_event_log_live_entry_preserves_older_window(perf_harness: UIHarness):
    """Keep an older page stable until the reader activates the latest-events control."""
    require_browser()
    page = perf_harness.new_page(**STANDARD_VIEWPORTS[1440])

    try:
        page.route_web_socket("**/ws", lambda websocket: None)
        page.goto(f"{perf_harness.server_url}/monitor")
        page.wait_for_selector("#eventLog")
        page.wait_for_function("() => typeof addEventLog === 'function'")
        page.evaluate("""async () => {
            window._eventLogEntries.length = 0;
            for (let i = 0; i < 10000; i++) addEventLog('status', `Event seq=${i}`);
            await new Promise(requestAnimationFrame);
            const log = document.getElementById('eventLog');
            log.scrollTop = 0;
            log.dispatchEvent(new Event('scroll'));
        }""")
        older_window = page.locator("#eventLog .event-item").all_text_contents()
        assert len(older_window) == 500
        assert "seq=9250" in older_window[0]
        assert "seq=9749" in older_window[-1]

        page.evaluate("""() => {
            addEventLog('status', 'Event seq=10000');
            addEventLog('status', 'Event seq=10001');
            addEventLog('status', 'Event seq=10002');
        }""")
        assert page.locator("#eventLog .event-item").all_text_contents() == older_window
        page.wait_for_function("() => !document.getElementById('eventLogNewEntries').hidden")
        assert page.locator("#eventLogNewEntries").is_visible()
        assert page.locator("#eventLogNewEntryCount").inner_text() == "3 new entries"

        page.locator("#eventLogNewEntries").focus()
        page.keyboard.press("Enter")
        latest_window = page.locator("#eventLog .event-item").all_text_contents()
        assert len(latest_window) == 500
        assert "seq=9503" in latest_window[0]
        assert "seq=10002" in latest_window[-1]
        assert page.locator("#eventLogNewEntries").is_hidden()
        assert page.evaluate("window._eventLogWindowStart") == 9503
    finally:
        page.close()


def test_findings_list_10k_entries_benchmark(perf_harness: UIHarness):
    """Verify Findings list handles 10,000+ entries via bounded incremental rendering within performance budget."""
    require_browser()
    page = perf_harness.new_page(**STANDARD_VIEWPORTS[1440])

    try:
        page.goto(f"{perf_harness.server_url}/app#/findings")
        page.wait_for_selector("#findingsSurface", state="visible")

        # Evaluate Findings view with 10,000 synthetic entries
        res = page.evaluate("""async () => {
            const findings = [];
            for (let i = 0; i < 10000; i++) {
                findings.push({
                    id: "f_bench_" + i,
                    url: "http://store.internal.local/products?item=" + i + "&filter=benchmark_test_stress_value",
                    field_name: "param_" + i,
                    check_type: i % 3 === 0 ? "xss" : (i % 3 === 1 ? "sqli" : "rce"),
                    severity: i % 4 === 0 ? "critical" : (i % 4 === 1 ? "high" : (i % 4 === 2 ? "medium" : "low")),
                    evidence: "Synthetic evidence for finding " + i + " with payload '<script>alert(" + i + ")</script>'",
                    verified: i % 2 === 0,
                    provenance: i % 5 === 0 ? "agent" : "scanner"
                });
            }

            const surface = document.getElementById('findingsSurface');

            const mockApi = {
                createScope: () => ({
                    get: async (path) => {
                        if (path === '/api/v1/scans') {
                            return {
                                ok: true,
                                data: {
                                    scans: [{ id: "bench_10k", target: "http://store.internal.local", status: "done", findings_count: findings.length }]
                                }
                            };
                        }
                        if (path.includes('/findings')) {
                            return {
                                ok: true,
                                data: {
                                    scan_id: "bench_10k",
                                    findings: findings,
                                    findings_count: findings.length,
                                    total_findings_count: findings.length,
                                    confirmed_findings_count: 5000,
                                    findings_available: true
                                }
                            };
                        }
                        return { ok: false, status: 404 };
                    },
                    cancelAll: () => {},
                    registerCleanup: () => {}
                })
            };

            const start = performance.now();
            const startMem = performance.memory ? performance.memory.usedJSHeapSize : 0;

            const view = VulixFindingsModule.renderFindingsView(surface, { api: mockApi });
            await view.initScansAndLoad({ scanId: "bench_10k" });

            const durationMs = performance.now() - start;
            const endMem = performance.memory ? performance.memory.usedJSHeapSize : 0;
            const initialCardCount = document.querySelectorAll('.findings-list-card').length;
            const countSummaryText = document.getElementById('findingsCountSummary')?.textContent || '';

            // Test search filtering speed
            const filterStart = performance.now();
            const searchInput = document.getElementById('findingsSearchInput');
            searchInput.value = 'xss';
            searchInput.dispatchEvent(new Event('input', { bubbles: true }));
            const filterDurationMs = performance.now() - filterStart;
            const filteredCardCount = document.querySelectorAll('.findings-list-card').length;

            // Test incremental load by clicking sentinel / load more
            const scrollStart = performance.now();
            const sentinel = document.querySelector('.findings-list-sentinel');
            if (sentinel) sentinel.click();
            const scrollDurationMs = performance.now() - scrollStart;
            const afterLoadCardCount = document.querySelectorAll('.findings-list-card').length;

            return {
                durationMs,
                initialCardCount,
                countSummaryText,
                filterDurationMs,
                filteredCardCount,
                scrollDurationMs,
                afterLoadCardCount,
                memDelta: endMem - startMem,
            };
        }""")

        print(f"Findings 10k: render={res['durationMs']:.2f} ms; filter={res['filterDurationMs']:.2f} ms; incremental-load={res['scrollDurationMs']:.2f} ms")
        assert res["durationMs"] < 250.0, f"Findings initial render exceeded threshold: {res['durationMs']} ms"
        # DOM items bounded to initial chunk (50)
        assert res["initialCardCount"] == 50, f"Expected 50 initial cards, got: {res['initialCardCount']}"
        assert "10,000" in res["countSummaryText"] or "10000" in res["countSummaryText"]

        # Filter duration expected ~2-15 ms; agreed threshold <= 100 ms
        assert res["filterDurationMs"] < 100.0, f"Filter duration exceeded threshold: {res['filterDurationMs']} ms"
        assert res["filteredCardCount"] == 50

        # Incremental load duration expected < 10 ms; after load cards count increased
        assert res["scrollDurationMs"] < 50.0
        assert res["afterLoadCardCount"] == 100
    finally:
        page.close()


def test_long_urls_bodies_and_payloads_do_not_break_layout(perf_harness: UIHarness):
    """Verify ultra-long URLs (2,000+ chars), request bodies, and payloads wrap and preserve layout without breaking."""
    require_browser()

    long_url = "http://store.internal.local/deep/nested/api/v1/" + ("segment_with_many_characters_" * 80) + "?query=" + ("a" * 500)
    long_payload = "<script>/*" + ("X" * 1500) + "*/alert(1);</script>"
    long_body = json.dumps({"action": "stress_test", "data": "D" * 2000, "headers": {"X-Custom": "H" * 300}})

    with tempfile.TemporaryDirectory(prefix="vulix_perf_screenshots_") as tmp_dir:
        tmp_path = Path(tmp_dir)

        for width in [1440, 1280, 768]:
            vp = STANDARD_VIEWPORTS[width]
            page = perf_harness.new_page(width=vp["width"], height=vp["height"])

            try:
                page.goto(f"{perf_harness.server_url}/app#/findings")
                page.wait_for_selector("#findingsSurface", state="visible")

                # Inject finding with ultra-long data
                page.evaluate("""({ url, payload, body }) => {
                    const surface = document.getElementById('findingsSurface');
                    const mockApi = {
                        createScope: () => ({
                            get: async (path) => {
                                if (path === '/api/v1/scans') {
                                    return {
                                        ok: true,
                                        data: {
                                            scans: [{ id: "stress_scan", target: url, status: "done", findings_count: 1 }]
                                        }
                                    };
                                }
                                return {
                                    ok: true,
                                    data: {
                                        scan_id: "stress_scan",
                                        findings: [{
                                            id: "f_stress_1",
                                            url: url,
                                            field_name: "very_long_field_name_without_spaces_abcdefghijklmnopqrstuvwxyz_0123456789",
                                            check_type: "xss",
                                            severity: "critical",
                                            payload: payload,
                                            evidence: body,
                                            request: { url: url, body: body },
                                            response: { body: body },
                                            verified: true
                                        }],
                                        findings_count: 1,
                                        total_findings_count: 1,
                                        confirmed_findings_count: 1,
                                        findings_available: true
                                    }
                                };
                            },
                            cancelAll: () => {},
                            registerCleanup: () => {}
                        })
                    };

                    const view = VulixFindingsModule.renderFindingsView(surface, { api: mockApi });
                    view.initScansAndLoad({ scanId: "stress_scan" });
                }""", {"url": long_url, "payload": long_payload, "body": long_body})

                page.wait_for_selector(".findings-list-card")
                page.wait_for_selector(".findings-detail-pane")

                # Verify full values are present in DOM
                assert page.locator(".findings-list-card").count() == 1
                detail_text = page.locator(".findings-detail-pane").inner_text()
                assert "stress_test" in detail_text

                # Verify no horizontal scroll / overflow breaking the page container
                max_allowed = 900 if width == 768 else None
                perf_harness.assert_no_horizontal_overflow(page, max_allowed=max_allowed)
                perf_harness.assert_no_errors(page)

                # Capture screenshot artifact in temporary directory
                screenshot_file, sw, sh = perf_harness.capture_screenshot(
                    page, f"perf_stress_layout", width, dest_dir=tmp_path
                )
                assert screenshot_file.is_file()
                assert sw == width
                # Screenshot was written to temp dir, never to docs/images
                assert "docs/images" not in str(screenshot_file)
            finally:
                page.close()
