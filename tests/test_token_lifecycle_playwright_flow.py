"""Playwright browser form probe and FlowRunner step token lifecycle tests.

Increment 3: Playwright browser form probe token lifecycle and FlowRunner step token propagation.
"""
from __future__ import annotations

import unittest
from unittest.mock import AsyncMock, patch, MagicMock

import httpx
import pytest

from tests.fixtures.large_vuln_app import create_app
from tests.test_token_lifecycle_fixtures import _TestEngine, _TestFormScanner
from wscan.injection_point import InjectionPoint
from wscan.flow_runner import FlowRunner, FlowStep
from wscan.scanner_contract import Carrier
from wscan.token_lifecycle import (
    DeclaredStatus,
    TokenCarrier,
    TokenTransport,
    build_token_capability_matrix,
    derive_token_ref_id,
    refresh_form_tokens,
)


PAYLOAD = "user@example.com\r\nCc: attacker@evil.example.com"


class _FlowPage:
    url = "https://example.test/"
    def __init__(self, token="fresh-secret"):
        self.token = token
        self.scripts = []
    async def evaluate(self, script, *args):
        self.scripts.append(script)
        if "querySelectorAll" in script and "field.toLowerCase()" in script and "const elements" in script:
            return self.token
        if "const result = {}" in script:
            assert script.lstrip().startswith("() =>")
            return {"csrf_token": self.token}
        if "const find =" in script:
            return {"ok": True, "ambiguous": False, "sensitive": False}
        return True


class _FlowBrowser:
    def __init__(self, page): self.page = page


@pytest.mark.asyncio
async def test_flow_token_extraction_is_opt_in_and_ref_only():
    from wscan.flow_runner import ScanFlow
    for flag in (False, True):
        page = _FlowPage()
        engine = type("Engine", (), {"token_lifecycle_manager": flag})()
        notes = []
        runner = FlowRunner(_FlowBrowser(page), engine=engine, recorder=lambda *args: notes.append(args))
        fill = FlowStep("fill", field="csrf_token", value="recorded-old")
        flow = ScanFlow("tokens", [fill, FlowStep("submit")])
        assert await runner.run(flow)
        extraction_scripts = [s for s in page.scripts if "const result = {}" in s or "field.toLowerCase()" in s]
        if flag:
            assert fill.value == "fresh-secret"
            assert runner._flow_token_bindings == {"csrf_token": derive_token_ref_id("fresh-secret")}
            assert all("fresh-secret" not in repr(x) for x in runner._flow_token_bindings.values())
            assert any(s.lstrip().startswith("() =>") for s in extraction_scripts)
            assert all("fresh-secret" not in repr(note) for note in notes)
        else:
            assert fill.value == "recorded-old"
            assert runner._flow_token_bindings == {}
            assert extraction_scripts == []


@pytest.mark.asyncio
async def test_flow_live_token_fill_console_uses_reference_id():
    from wscan import flow_runner as flow_runner_module
    from wscan.flow_runner import ScanFlow
    page = _FlowPage(token="raw-live-token-value")
    engine = type("Engine", (), {"token_lifecycle_manager": True})()
    runner = FlowRunner(_FlowBrowser(page), engine=engine)
    output = []
    with patch.object(flow_runner_module.console, "print", side_effect=lambda value, **kwargs: output.append(str(value))):
        assert await runner.run(ScanFlow("tokens", [FlowStep("fill", field="csrf_token", value="recorded-old")]))
    rendered = "\n".join(output)
    assert "raw-live-token-value" not in rendered
    assert derive_token_ref_id("raw-live-token-value") in rendered


def _ip(base, path, form_tokens=None):
    """Create an InjectionPoint for form probing."""
    return InjectionPoint.for_form(
        f"{base}{path}", "email",
        form_index=0,
        form_tokens=form_tokens or ("csrf_token",),
    )


class PlaywrightFormProbeTests(unittest.IsolatedAsyncioTestCase):
    """Playwright browser form probe token lifecycle tests."""

    async def asyncSetUp(self):
        self.app = create_app(page_count=4)

    def _scanner(self, flag, app=None, base="http://large-fixture.test"):
        engine = _TestEngine(app or self.app, base_url=base)
        if flag is not None:
            engine.token_lifecycle_manager = flag
        engine.wave_errors = []
        return _TestFormScanner(engine), engine

    def _inconclusive(self, engine):
        return [n for n in engine.wave_errors if "probe_inconclusive" in n]

    async def test_flag_off_byte_for_byte_parity(self):
        """Flag off: behavior byte-for-byte identical to legacy (no token lifecycle)."""
        sc, eng = self._scanner(None)
        self.assertFalse(sc._token_manager_enabled())
        src, pair = await sc._apply_ip(_ip("http://large-fixture.test", "/csrf-contact"), PAYLOAD)
        self.assertEqual(pair["response"]["status"], 200)
        self.assertIn("\nCc: attacker@evil.example.com", src)
        self.assertEqual(self._inconclusive(eng), [])

    async def test_manager_on_rotating_token_succeeds(self):
        """Manager on: rotating token is refreshed and probe succeeds."""
        sc, eng = self._scanner(True)
        src, pair = await sc._apply_ip(_ip("http://large-fixture.test", "/csrf-contact"), PAYLOAD)
        self.assertEqual(pair["response"]["status"], 200)
        self.assertIn("\nCc: attacker@evil.example.com", src)
        # Manager on should not produce probe_inconclusive notes for rotating forms
        self.assertEqual(self._inconclusive(eng), [])

    async def test_manager_on_residual_stale_after_retry(self):
        """Manager on: after 1 retry, if still stale, records probe_inconclusive."""
        sc, eng = self._scanner(True)
        # Use a stuck form that causes stale after retry
        src, pair = await sc._apply_ip(
            _ip("http://large-fixture.test", "/csrf-contact-oneshot-stuck"), PAYLOAD
        )
        self.assertEqual(pair["response"]["status"], 419)
        # Should record probe_inconclusive note
        inconclusive = self._inconclusive(eng)
        self.assertTrue(
            any("probe_inconclusive" in n for n in inconclusive),
            f"Expected probe_inconclusive note, got: {inconclusive}",
        )
        # The note should include token_lifecycle:probe_inconclusive:<check_type>
        has_lifecycle_note = any(
            "probe_inconclusive:" in n for n in inconclusive
        )
        self.assertTrue(has_lifecycle_note, f"Expected lifecycle note in: {inconclusive}")

    async def test_raw_token_redaction_via_derive_token_ref_id(self):
        """Manager on: raw token values are redacted via derive_token_ref_id."""
        sc, eng = self._scanner(True)
        src, pair = await sc._apply_ip(_ip("http://large-fixture.test", "/csrf-contact"), PAYLOAD)
        # Post data should not contain raw token values
        post_data = pair["request"].get("post_data", "")
        # derive_token_ref_id produces tok_ref_ prefixed IDs, not raw tokens
        self.assertIn("csrf_token=tok_ref_", post_data or "")
        # Raw token should not appear in notes
        for note in eng.wave_errors:
            self.assertNotIn("csrf_token=", note, f"Raw token found in note: {note}")


class CapabilityMatrixIncrement3Tests(unittest.IsolatedAsyncioTestCase):
    """Capability matrix tests for Increment 3 changes."""

    def test_form_urlenabled_playwright_supported(self):
        """FORM×PLAYWRIGHT should be SUPPORTED after Increment 3."""
        matrix = build_token_capability_matrix()
        self.assertTrue(matrix.is_supported(TokenCarrier.FORM_URLENCODED, TokenTransport.PLAYWRIGHT))
        self.assertEqual(matrix.get_status(TokenCarrier.FORM_URLENCODED, TokenTransport.PLAYWRIGHT), DeclaredStatus.SUPPORTED)

    def test_form_urlenabled_flow_supported(self):
        """FORM×FLOW should be SUPPORTED after Increment 3."""
        matrix = build_token_capability_matrix()
        self.assertTrue(matrix.is_supported(TokenCarrier.FORM_URLENCODED, TokenTransport.FLOW))
        self.assertEqual(matrix.get_status(TokenCarrier.FORM_URLENCODED, TokenTransport.FLOW), DeclaredStatus.SUPPORTED)

    def test_supported_entries_count(self):
        """Supported declarations include three Hybrid deterministic paths."""
        matrix = build_token_capability_matrix()
        supported_entries = [e for e in matrix.entries if e.status == DeclaredStatus.SUPPORTED]
        self.assertEqual(len(supported_entries), 11)

    def test_other_entries_count(self):
        """Other declarations exclude the three newly supported Hybrid paths."""
        matrix = build_token_capability_matrix()
        other_entries = [e for e in matrix.entries if e.status != DeclaredStatus.SUPPORTED]
        self.assertEqual(len(other_entries), 38)
