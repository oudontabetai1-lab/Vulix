"""
CSRF (Cross-Site Request Forgery) Scanner
Detects missing CSRF token protection in POST forms (IPA: 1.6 CSRF).
"""
from html.parser import HTMLParser
from typing import TYPE_CHECKING
from urllib.parse import urljoin

from wscan.scanner_contract import (
    CapabilityState, Carrier, CarrierCapability, CostClass, ExecutionKind,
    PayloadShape, Prerequisite, ScannerContract, StateChangeClass, TransportKind,
    ValueKind,
)

from .base import BaseScanner, Finding

if TYPE_CHECKING:
    from wscan.engine import ScanEngine


# Lowercase token field name patterns that indicate a CSRF protection token
CSRF_TOKEN_NAMES = {
    "csrf", "csrftoken", "csrf_token", "_csrf", "_token", "token",
    "authenticity_token", "__requestverificationtoken", "_wpnonce",
    "xsrf", "xsrftoken", "_xsrf", "anti_csrf", "verification_token",
    "form_token", "formtoken", "nonce", "security_token", "sec_token",
    "requesttoken", "request_token",
}


class _FormCollector(HTMLParser):
    """HTML から <form> と name 付き入力を集める（form の入れ子は想定しない）。"""

    def __init__(self):
        super().__init__()
        self.forms: list[dict] = []
        self._cur: dict | None = None

    def handle_starttag(self, tag, attrs):
        a = dict(attrs)
        if tag == "form":
            self._cur = {
                "index": len(self.forms),
                "method": (a.get("method") or "GET").upper(),
                "action": a.get("action") or "",
                "inputs": [],
            }
            self.forms.append(self._cur)
        elif tag in ("input", "textarea", "select") and self._cur and a.get("name"):
            self._cur["inputs"].append(a["name"].lower())

    def handle_endtag(self, tag):
        if tag == "form":
            self._cur = None


def unprotected_post_forms(html: str) -> list[dict]:
    """CSRF token 入力を持たない POST フォームを返す（純粋関数）。"""
    collector = _FormCollector()
    try:
        collector.feed(html or "")
    except Exception:
        pass
    return [
        f for f in collector.forms
        if f["method"] == "POST"
        and not any(
            n.replace("-", "_").replace(" ", "_") in CSRF_TOKEN_NAMES
            for n in f["inputs"]
        )
    ]


class CSRFScanner(BaseScanner):
    """CSRF vulnerability scanner — checks POST forms for missing CSRF tokens (IPA 1.6)."""

    HAS_PAGE_LEVEL = True
    CHECK_TYPE = "csrf"
    CONTRACT = ScannerContract(
        execution_kinds=frozenset({ExecutionKind.PAGE_ANALYSIS}),
        capabilities=(
            CarrierCapability(
                carrier=Carrier.QUERY, state=CapabilityState.UNSUPPORTED,
                reason="page/response 解析でありパラメータ注入をしない",
            ),
            CarrierCapability(
                carrier=Carrier.FORM, state=CapabilityState.UNSUPPORTED,
                reason="page/response 解析でありパラメータ注入をしない",
            ),
            CarrierCapability(
                carrier=Carrier.JSON, state=CapabilityState.UNSUPPORTED,
                reason="page/response 解析でありパラメータ注入をしない",
            ),
            CarrierCapability(
                carrier=Carrier.XML, state=CapabilityState.UNSUPPORTED,
                reason="page/response 解析でありパラメータ注入をしない",
            ),
            CarrierCapability(
                carrier=Carrier.MULTIPART, state=CapabilityState.UNSUPPORTED,
                reason="page/response 解析でありパラメータ注入をしない",
            ),
            CarrierCapability(
                carrier=Carrier.HEADER, state=CapabilityState.UNSUPPORTED,
                reason="page/response 解析でありパラメータ注入をしない",
            ),
            CarrierCapability(
                carrier=Carrier.COOKIE, state=CapabilityState.UNSUPPORTED,
                reason="page/response 解析でありパラメータ注入をしない",
            ),
            CarrierCapability(
                carrier=Carrier.PATH, state=CapabilityState.UNSUPPORTED,
                reason="page/response 解析でありパラメータ注入をしない",
            ),
            CarrierCapability(
                carrier=Carrier.GRAPHQL, state=CapabilityState.UNSUPPORTED,
                reason="page/response 解析でありパラメータ注入をしない",
            ),
            CarrierCapability(
                carrier=Carrier.WEBSOCKET, state=CapabilityState.UNSUPPORTED,
                reason="page/response 解析でありパラメータ注入をしない",
            ),
        ),
        state_change=StateChangeClass.READ_ONLY,
        # 既定は crawl 済み page.html（scan_page_context）。フォールバックの scan_page は
        # browser.page.content のみで browser 無しでは空になるため browser 必須のまま。
        prerequisites=frozenset({Prerequisite.BROWSER}),
        cost=CostClass.LOW,
    )

    SEVERITY = "medium"

    async def scan_field(
        self,
        url: str,
        form_index: int,
        field: dict,
        is_url_param: bool = False,
    ) -> list[Finding]:
        # CSRF is a page-level check; no per-field scan needed.
        return []

    async def scan_page_context(self, page) -> list[Finding]:
        """クロール時に保持した ``page.html`` を解析する（推奨経路）。

        scan_page_context 非採用だと現在タブの DOM を読むため、engine が攻撃前に
        navigate しない通常ページでは別ページを解析し、対象ページの token 無し
        POST フォームを見逃す（FN）。js_static/sri と同じくクロール確定 HTML を使う。
        """
        return await self._scan(
            getattr(page, "url", "") or "", getattr(page, "html", "") or ""
        )

    async def scan_page(self, url: str) -> list[Finding]:
        # scan_page_context が使えない経路向けのフォールバック（現在タブの DOM）。
        try:
            html = await self.browser.page.content()
        except Exception:
            return []
        return await self._scan(url, html)

    async def _scan(self, url: str, html: str) -> list[Finding]:
        """token 無しの POST フォームごとに finding を記録する。"""
        findings = []

        if self.monitor:
            await self.monitor.emit_status(f"CSRF check on {url}")

        for form in unprotected_post_forms(html):
            pair = self.current_page_pair(url)
            action = urljoin(url, form["action"]) if form["action"] else url
            findings.append(await self.record_finding(
                url=url,
                field_name=f"form[{form['index']}]",
                payload="(no payload — structural analysis)",
                evidence=(
                    f"POST form (action: {action}) has no CSRF token field. "
                    "State-changing requests may be forgeable from attacker-controlled pages."
                ),
                pair=pair,
                severity="medium",
            ))

        return findings
