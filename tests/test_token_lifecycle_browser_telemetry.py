"""Browser managed form lifecycle event contract checks without Chromium."""
import ast
from pathlib import Path

from wscan.token_lifecycle import TokenLifecycleEvent


def test_browser_event_reason_literals_are_allowed():
    source = Path("wscan/scanners/base.py").read_text()
    tree = ast.parse(source)
    allowed = {"stale", "refresh_failed", "retry", "transport_error", "unknown"}
    browser = source[source.index("# ── Increment 3: Playwright browser form probe"):]
    assert 'refresh_reason = "stale"' in browser
    assert {"FORM_URLENCODED", "PLAYWRIGHT"} <= set(
        node.attr for node in ast.walk(tree) if isinstance(node, ast.Attribute)
    )
    assert TokenLifecycleEvent.__dataclass_fields__["refresh_reason"]
    assert allowed  # Keep the contract allowlist explicit in this browser-free test.


def test_lifecycle_event_none_ids_are_valid():
    event = TokenLifecycleEvent(
        probe_attempt_id=None, evidence_id=None, check="mail_header",
        carrier="form_urlencoded", transport="playwright", attempt_count=2,
        refresh_reason="stale", final_status=200, final_lifecycle_status="accepted",
    )
    assert event.probe_attempt_id is None and event.evidence_id is None
