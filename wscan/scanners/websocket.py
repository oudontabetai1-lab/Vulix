"""
WebSocket Injection Scanner
============================
Playwright の WebSocket イベントフックを使い、WS エンドポイントへの
メッセージにペイロードを注入してインジェクション脆弱性を検査する。

検査パターン:
  - XSS ペイロード (反射型 / 蓄積型)
  - SQLi ペイロード (エラー応答)
  - OSコマンドインジェクション (タイムディレイ)
  - JSONフィールドへのネスト注入

動作:
  1. scan_page() でページをナビゲートし、WS 接続を観測する
  2. 接続されたメッセージの JSON 構造を解析
  3. 各フィールドにペイロードを注入したメッセージを送信
  4. WS レスポンスをパターンマッチで検査
"""
from __future__ import annotations

import asyncio
import json
import re
import time
from typing import TYPE_CHECKING

from wscan.probe_ledger import ProbeOutcome, ProbeRole, Transport, sha256_hex
from wscan.scanner_contract import (
    CapabilityState, Carrier, CarrierCapability, CostClass, ExecutionKind,
    PayloadShape, Prerequisite, ScannerContract, StateChangeClass, TransportKind,
    ValueKind,
)
from wscan.websocket_evidence import DISCOVERY, RULES, VERIFY_RULES, subject

from .base import BaseScanner, Finding

if TYPE_CHECKING:
    from wscan.engine import ScanEngine

# 検査ペイロード — (underlying_type, payload, detection_pattern, evidence_type)
_WS_PAYLOADS: list[tuple[str, str, str, str]] = [
    # XSS
    ("xss", "<script>alert('wsxss')</script>",    r"<script>alert\('wsxss'\)</script>", "websocket_xss_reflection"),
    ("xss", "<img src=x onerror=alert('wsxss')>", r"onerror=alert\('wsxss'\)", "websocket_xss_reflection"),
    # SQLi (エラーベース)
    ("sqli", "' OR '1'='1",                       r"(?i)(sql|syntax|mysql|sqlite|postgres|ora-[0-9]+)", "websocket_sqli_error"),
    ("sqli", "1 UNION SELECT NULL--",             r"(?i)(sql|syntax|union|select)", "websocket_sqli_error"),
    # OS インジェクション (エコーベース)
    ("os",   "; echo wsostest123;",               r"wsostest123", "websocket_os_echo"),
    ("os",   "| echo wsostest123",                r"wsostest123", "websocket_os_echo"),
    # SSTI
    ("ssti", "{{7*7}}",                           r"49", "websocket_ssti_eval"),
    ("ssti", "${7*7}",                            r"49", "websocket_ssti_eval"),
]

# JSON フィールド注入対象 (よく使われる WS メッセージキー)
_INJECT_KEYS = {
    "message", "msg", "text", "content", "data", "input",
    "query", "q", "search", "cmd", "command", "action",
    "id", "user", "username", "name", "value",
}


class WebSocketScanner(BaseScanner):
    """WebSocket エンドポイントへのインジェクション脆弱性を検査するスキャナー。"""

    HAS_PAGE_LEVEL = True
    CHECK_TYPE = "websocket"
    CONTRACT = ScannerContract(
        execution_kinds=frozenset({ExecutionKind.PAGE_ANALYSIS, ExecutionKind.PROTOCOL_MESSAGE}),
        capabilities=(
            CarrierCapability(
                carrier=Carrier.QUERY, state=CapabilityState.UNSUPPORTED,
                reason="WS message 特化",
            ),
            CarrierCapability(
                carrier=Carrier.FORM, state=CapabilityState.UNSUPPORTED,
                reason="WS message 特化",
            ),
            CarrierCapability(
                carrier=Carrier.JSON, state=CapabilityState.UNSUPPORTED,
                reason="WS message 特化",
            ),
            CarrierCapability(
                carrier=Carrier.XML, state=CapabilityState.UNSUPPORTED,
                reason="WS message 特化",
            ),
            CarrierCapability(
                carrier=Carrier.MULTIPART, state=CapabilityState.UNSUPPORTED,
                reason="WS message 特化",
            ),
            CarrierCapability(
                carrier=Carrier.HEADER, state=CapabilityState.UNSUPPORTED,
                reason="WS message 特化",
            ),
            CarrierCapability(
                carrier=Carrier.COOKIE, state=CapabilityState.UNSUPPORTED,
                reason="WS message 特化",
            ),
            CarrierCapability(
                carrier=Carrier.PATH, state=CapabilityState.UNSUPPORTED,
                reason="WS message 特化",
            ),
            CarrierCapability(
                carrier=Carrier.GRAPHQL, state=CapabilityState.UNSUPPORTED,
                reason="WS message 特化",
            ),
            CarrierCapability(
                # scan_page が browser.page で WS を観測し page.evaluate() で socket を張って
                # メッセージを送るため browser 必須。_build_inject_messages() は観測 JSON frame を
                # clone して field を差し替えた object（json.dumps）も送るため OBJECT/STRUCTURED も含む。
                carrier=Carrier.WEBSOCKET, state=CapabilityState.SUPPORTED,
                value_kinds=frozenset({ValueKind.STRING, ValueKind.OBJECT}),
                transports=frozenset({TransportKind.PLAYWRIGHT, TransportKind.WEBSOCKET}),
                browser_required=True,
                payload_shapes=frozenset({PayloadShape.SCALAR, PayloadShape.STRUCTURED}),
                structured_payload=True,
            ),
        ),
        state_change=StateChangeClass.CONDITIONAL,
        cost=CostClass.HIGH,
    )

    SEVERITY = "high"
    PASSIVE_RULES = (DISCOVERY, *RULES)

    def __init__(self, engine: "ScanEngine"):
        super().__init__(engine)
        self._ws_urls: set[str] = set()
        self._observed_messages: list[str] = []
        self._replay_map: dict[str, tuple[str, str, str]] = {}
        self.last_decision_id: str = ""
        self.last_decision_subject: str = ""
        self.last_outcome: str = ""

    def record_evidence_skip(self, endpoint: str, *, rules=PASSIVE_RULES, role="attack", reason="state_profile_policy"):
        for rule in rules:
            disc_subj = sha256_hex(f"skip:{endpoint}:{rule}")
            self._record_probe_evidence(
                role=role, check=self.CHECK_TYPE, actor="websocket_oracle",
                decision_version="1", decision_rule=rule, decision_subject=disc_subj,
                field=sha256_hex(endpoint), record_kind="websocket_decision",
                parent_id="", request_attempt_id="",
                rationale=f"terminal={reason};frames=0;close_error=0",
                outcome="skipped" if reason == "state_profile_policy" else "unexecutable",
            )

    # ──────────────────────────────────────────────────────────────────────────
    # BaseScanner interface
    # ──────────────────────────────────────────────────────────────────────────

    async def scan_field(self, url: str, form_index: int, field: dict,
                         is_url_param: bool = False) -> list[Finding]:
        return []  # WebSocket はフィールドスキャンではなくページスキャンで動作

    async def scan_page(self, url: str) -> list[Finding]:
        """
        WS 接続を観測し、ペイロードを注入して脆弱性を検査する。
        WS エンドポイントが検出されなかった場合は空リストを返す。
        """
        findings: list[Finding] = []

        ws_messages: list[dict] = []  # {"ws": WS object, "data": str}
        ws_endpoints: list = []

        page = self.browser.page

        def on_websocket(ws):
            ws_endpoints.append(ws)
            self._ws_urls.add(ws.url)

            def on_message(data):
                payload = data.get("payload", "") if isinstance(data, dict) else str(data)
                ws_messages.append({"ws": ws, "data": payload, "ts": time.time()})

            ws.on("framereceived", on_message)

        page.on("websocket", on_websocket)

        remove_error = False
        try:
            await self.browser.navigate(url)
            # WS 接続が確立されるまで最大 3 秒待機
            await asyncio.sleep(3.0 * self.sleep_factor)
        finally:
            try:
                page.remove_listener("websocket", on_websocket)
            except Exception:
                remove_error = True

        disc_subj = sha256_hex(f"discovery:{url}:{DISCOVERY}")
        disc_ids: list[str] = []

        for ws in ws_endpoints:
            d_id = self._record_probe_evidence(
                role=ProbeRole.DISCOVER,
                check=self.CHECK_TYPE,
                actor="websocket_oracle",
                decision_version="1",
                decision_rule=DISCOVERY,
                decision_subject=disc_subj,
                field=sha256_hex(url),
                record_kind="websocket_discovery",
                parent_id="",
                request_attempt_id="",
                rationale="endpoint_observed",
                outcome=None,
            )
            if d_id:
                disc_ids.append(d_id)

        for m in ws_messages[:5]:
            f_id = self._record_probe_evidence(
                role=ProbeRole.DISCOVER,
                check=self.CHECK_TYPE,
                actor="websocket_oracle",
                decision_version="1",
                decision_rule=DISCOVERY,
                decision_subject=disc_subj,
                field=sha256_hex(url),
                record_kind="websocket_discovery",
                parent_id="",
                request_attempt_id="",
                rationale="frame_observed",
                outcome=None,
            )
            if f_id:
                disc_ids.append(f_id)

        cleanup_id = self._record_probe_evidence(
            role=ProbeRole.CLEANUP,
            check=self.CHECK_TYPE,
            actor="websocket_oracle",
            decision_version="1",
            decision_rule=DISCOVERY,
            decision_subject=disc_subj,
            field=sha256_hex(url),
            record_kind="websocket_cleanup",
            parent_id="",
            request_attempt_id="",
            rationale="page_listener_removed" if not remove_error else "page_listener_remove_error",
            outcome=None if not remove_error else ProbeOutcome.TRANSPORT_ERROR.value,
        )

        linked_disc = disc_ids + ([cleanup_id] if cleanup_id else [])
        self._record_probe_evidence(
            role=ProbeRole.DISCOVER,
            check=self.CHECK_TYPE,
            actor="websocket_oracle",
            decision_version="1",
            decision_rule=DISCOVERY,
            decision_subject=disc_subj,
            field=sha256_hex(url),
            record_kind="websocket_decision",
            parent_id="",
            request_attempt_id="",
            related_attempt_ids=tuple(linked_disc),
            rationale=f"terminal={'received' if ws_endpoints else 'closed'};frames={len(ws_messages)};close_error={1 if remove_error else 0}",
            outcome=ProbeOutcome.MATCHED.value if ws_endpoints else ProbeOutcome.NO_MATCH.value,
        )

        if not ws_endpoints:
            return []  # WS 接続なし

        # 観測されたメッセージから JSON 構造を推定
        sample_json: dict | None = None
        for m in ws_messages[:5]:
            try:
                parsed = json.loads(m.get("data", ""))
                if isinstance(parsed, dict):
                    sample_json = parsed
                    break
            except (json.JSONDecodeError, TypeError):
                pass

        # 各 WS エンドポイントに対してペイロードを注入
        for ws in ws_endpoints[:3]:  # 最大 3 エンドポイントを検査
            ws_findings = await self._test_websocket(ws, url, sample_json, ws_messages)
            findings.extend(ws_findings)

        return findings

    # ──────────────────────────────────────────────────────────────────────────
    # Internal
    # ──────────────────────────────────────────────────────────────────────────

    async def _test_websocket(
        self,
        ws,
        page_url: str,
        sample_json: dict | None,
        baseline_messages: list[dict],
    ) -> list[Finding]:
        """1つの WebSocket エンドポイントに対してペイロードを注入する。"""
        findings: list[Finding] = []
        ws_url = ws.url

        for underlying_type, payload, detection_pattern, evidence_type in self._active_payloads():
            if any(
                f.evidence_type == evidence_type
                and f.evidence_details.get("underlying_type") == underlying_type
                for f in findings
            ):
                continue

            # 注入メッセージを構築
            inject_messages = self._build_inject_messages(payload, sample_json)

            for inject_msg, inject_key in inject_messages:
                endpoint_hash = sha256_hex(ws_url)
                message_hash = sha256_hex(inject_msg)
                subj = subject(endpoint_hash, message_hash, evidence_type)
                self._replay_map[subj] = (ws_url, inject_msg, detection_pattern)

                responses = await self._send_ws_message(
                    ws_url, inject_msg,
                    role=ProbeRole.ATTACK, rule=evidence_type, pattern=detection_pattern
                )

                # レスポンスをパターンマッチ
                for resp in responses:
                    if self._response_matches(resp, detection_pattern):
                        finding = Finding(
                            check_type=self.CHECK_TYPE,
                            severity=self.SEVERITY,
                            url=page_url,
                            field_name=f"ws:{inject_key or 'message'}",
                            payload=inject_msg[:200],
                            evidence=(
                                f"WebSocket ({ws_url}) がペイロードに応答: "
                                f"{resp[:200]}"
                            ),
                            request={"ws_url": ws_url, "sent": inject_msg[:500]},
                            response={"ws_url": ws_url, "received": resp[:500]},
                            confidence="likely",
                            evidence_type=evidence_type,
                            evidence_details={
                                "ws_url": ws_url,
                                "underlying_type": underlying_type,
                                "inject_key": inject_key,
                                "pattern": detection_pattern,
                                "sent": inject_msg,
                                "decision_subject": subj,
                                "source_decision_id": self.last_decision_id,
                                "attempt_ids": (self.last_decision_id,) if self.last_decision_id else (),
                            },
                        )
                        findings.append(finding)
                        break  # このペイロードは確認済み、次へ

                if any(f.evidence_type == evidence_type for f in findings):
                    # 1件でも検出されたら次のペイロードへ
                    break

        return findings

    def _active_payloads(self) -> list[tuple[str, str, str, str]]:
        checks = set(getattr(self.engine, "checks", []) or [])
        if self.CHECK_TYPE in checks:
            return list(_WS_PAYLOADS)
        return [entry for entry in _WS_PAYLOADS if entry[0] in checks]

    def _response_matches(self, response: str, pattern: str) -> bool:
        return bool(re.search(pattern, response or ""))

    async def _send_ws_message(
        self,
        ws_url: str,
        message: str,
        *,
        role=None,
        rule: str = "websocket_xss_reflection",
        pattern: str = "",
        source_decision_id: str | None = None,
    ) -> list[str]:
        role = role or ProbeRole.ATTACK
        endpoint_hash = sha256_hex(ws_url)
        message_hash = sha256_hex(message)
        subj = subject(endpoint_hash, message_hash, rule)
        key = f"endpoint_sha256={endpoint_hash};message_sha256={message_hash}"

        attempt_id = self._record_probe_evidence(
            role=role,
            check=self.CHECK_TYPE,
            actor="websocket_oracle",
            decision_version="1",
            decision_rule=rule,
            decision_subject=subj,
            field=key,
            record_kind="websocket_attempt",
            parent_id="",
            request_attempt_id="",
            rationale="started",
            outcome=None,
        )

        wait_ms = max(250, int(1000 * self.sleep_factor))
        terminal = "evaluation_error"
        sent = False
        frames: list[str] = []
        close_error = False

        try:
            result = await self.browser.page.evaluate(
                """
                ({ wsUrl, message, waitMs }) => new Promise((resolve) => {
                  let socket;
                  let done = false;
                  let sent = false;
                  let closeError = false;
                  const frames = [];

                  const finish = (terminalReason) => {
                    if (done) return;
                    done = true;
                    if (socket) {
                      try {
                        socket.close();
                      } catch (_) {
                        closeError = true;
                      }
                    }
                    resolve({
                      terminal: terminalReason,
                      sent: sent,
                      frames: frames,
                      close_error: closeError,
                    });
                  };

                  try {
                    socket = new WebSocket(wsUrl);
                  } catch (_) {
                    finish("open_error");
                    return;
                  }

                  socket.onmessage = (event) => {
                    try {
                      frames.push(String(event.data));
                    } catch (_) {}
                  };

                  socket.onerror = (e) => {
                    finish(sent ? "socket_error" : "open_error");
                  };

                  socket.onclose = () => {
                    if (!done) {
                      finish(sent ? (frames.length > 0 ? "received" : "closed") : "open_error");
                    }
                  };

                  socket.onopen = () => {
                    try {
                      socket.send(message);
                      sent = true;
                    } catch (_) {
                      finish("send_error");
                      return;
                    }
                    setTimeout(() => {
                      if (!done) {
                        finish(frames.length > 0 ? "received" : "timeout");
                      }
                    }, waitMs);
                  };

                  setTimeout(() => {
                    if (!done) {
                      finish(sent ? (frames.length > 0 ? "received" : "timeout") : "open_error");
                    }
                  }, waitMs + 2000);
                })
                """,
                {"wsUrl": ws_url, "message": message, "waitMs": wait_ms},
            )
            if isinstance(result, dict):
                terminal = str(result.get("terminal", "evaluation_error"))
                sent = bool(result.get("sent", False))
                frames = [str(item) for item in (result.get("frames") or [])]
                close_error = bool(result.get("close_error", False))
            elif isinstance(result, list):
                frames = [str(item) for item in result]
                sent = True
                terminal = "received" if frames else "timeout"
                close_error = False
        except Exception as exc:
            self._record_scan_note(f"websocket_observation_error:{type(exc).__name__}")
            terminal = "evaluation_error"
            sent = False
            frames = []
            close_error = False

        req_id = ""
        if sent:
            req_id = self._record_probe_evidence(
                role=role,
                transport=Transport.WEBSOCKET,
                check=self.CHECK_TYPE,
                actor="websocket_oracle",
                decision_version="1",
                decision_rule=rule,
                decision_subject=subj,
                field=key,
                record_kind="websocket_request",
                parent_id=attempt_id or "",
                request_attempt_id="",
                pair={"request": {
                    "method": "SEND",
                    "url": "",
                    "transport": "websocket",
                    "sent": True,
                    "post_data": message,
                }},
                sent=True,
                rationale="",
                outcome=None,
            ) or ""

        observation_ids: list[str] = []
        for frame in frames:
            is_match = self._response_matches(frame, pattern) if pattern else False
            obs_outcome = ProbeOutcome.MATCHED.value if is_match else ProbeOutcome.NO_MATCH.value
            obs_id = self._record_probe_evidence(
                role=role,
                transport=Transport.WEBSOCKET,
                check=self.CHECK_TYPE,
                actor="websocket_oracle",
                decision_version="1",
                decision_rule=rule,
                decision_subject=subj,
                field=key,
                record_kind="websocket_observation",
                parent_id=req_id,
                request_attempt_id=req_id,
                pair={
                    "request": {
                        "method": "SEND",
                        "url": "",
                        "transport": "websocket",
                        "sent": True,
                        "post_data": message,
                    },
                    "response": {
                        "url": "",
                        "body": frame,
                    },
                },
                sent=True,
                rationale="captured_frame",
                outcome=obs_outcome,
            )
            if obs_id:
                observation_ids.append(obs_id)

        cleanup_id = self._record_probe_evidence(
            role=ProbeRole.CLEANUP,
            check=self.CHECK_TYPE,
            actor="websocket_oracle",
            decision_version="1",
            decision_rule=rule,
            decision_subject=subj,
            field=key,
            record_kind="websocket_cleanup",
            parent_id=attempt_id or "",
            request_attempt_id="",
            rationale="socket_close_requested" if not close_error else "socket_close_error",
            outcome=None if not close_error else ProbeOutcome.TRANSPORT_ERROR.value,
        )

        if sent:
            if any(self._response_matches(f, pattern) for f in frames) if pattern else False:
                dec_outcome = ProbeOutcome.MATCHED.value
            elif frames:
                dec_outcome = ProbeOutcome.NO_MATCH.value
            elif terminal == "timeout":
                dec_outcome = ProbeOutcome.TIMEOUT.value
            elif terminal in {"socket_error", "open_error", "send_error"}:
                dec_outcome = ProbeOutcome.TRANSPORT_ERROR.value
            elif terminal in {"evaluation_error", "malformed"}:
                dec_outcome = ProbeOutcome.VERIFICATION_ERROR.value
            else:
                dec_outcome = ProbeOutcome.NO_MATCH.value
        else:
            if terminal in {"open_error", "send_error"}:
                dec_outcome = ProbeOutcome.TRANSPORT_ERROR.value
            elif terminal == "timeout":
                dec_outcome = ProbeOutcome.TIMEOUT.value
            elif terminal in {"evaluation_error", "malformed"}:
                dec_outcome = ProbeOutcome.VERIFICATION_ERROR.value
            elif terminal == "state_profile_policy":
                dec_outcome = ProbeOutcome.SKIPPED.value
            elif terminal in {"missing_replay_context", "no_endpoint", "endpoint_limit"}:
                dec_outcome = ProbeOutcome.UNEXECUTABLE.value
            else:
                dec_outcome = ProbeOutcome.TRANSPORT_ERROR.value

        source_ids = [source_decision_id] if (role == ProbeRole.VERIFY or str(role) == "verify") and source_decision_id else []
        cleanup_ids = [cleanup_id] if cleanup_id else []
        related_ids = tuple(observation_ids + cleanup_ids + source_ids)

        dec_id = self._record_probe_evidence(
            role=role,
            check=self.CHECK_TYPE,
            actor="websocket_oracle",
            decision_version="1",
            decision_rule=rule,
            decision_subject=subj,
            field=key,
            record_kind="websocket_decision",
            parent_id=attempt_id or "",
            request_attempt_id=req_id if sent else "",
            related_attempt_ids=related_ids,
            rationale=f"terminal={terminal};frames={len(observation_ids)};close_error={1 if close_error else 0}",
            outcome=dec_outcome,
        )
        self.last_decision_id = dec_id or ""
        self.last_decision_subject = subj
        self.last_outcome = dec_outcome
        return frames

    async def verify_finding(self, finding: Finding) -> bool | None:
        details = getattr(finding, "evidence_details", {}) or {}
        subj = details.get("decision_subject")
        ws_url = details.get("ws_url") or (finding.request or {}).get("ws_url")
        pattern = details.get("pattern")
        sent = details.get("sent") or finding.payload
        source_decision_id = details.get("source_decision_id")
        rule = getattr(finding, "evidence_type", None) or "websocket_xss_reflection"

        if subj and subj in self._replay_map:
            replay_url, replay_sent, replay_pattern = self._replay_map[subj]
            responses = await self._send_ws_message(
                replay_url, replay_sent,
                role=ProbeRole.VERIFY, rule=rule, pattern=replay_pattern,
                source_decision_id=source_decision_id,
            )
            if self.last_decision_id:
                finding.evidence_details["verification_attempt_ids"] = (self.last_decision_id,)
            return self.last_outcome == ProbeOutcome.MATCHED.value

        # Replay map is missing
        ledger = getattr(getattr(self.engine, "request_logger", None), "probe_ledger", None)
        if ledger is not None:
            # Active ledger scan with missing replay context -> cannot fabricate replay
            self.record_evidence_skip(
                finding.url, rules=(rule,), role="verify", reason="missing_replay_context"
            )
            return None

        # Fallback for simple unit tests without ledger
        if not ws_url or not pattern or not sent:
            return None
        responses = await self._send_ws_message(ws_url, sent, role=ProbeRole.VERIFY, rule=rule, pattern=pattern)
        return any(self._response_matches(resp, pattern) for resp in responses)

    def _build_inject_messages(
        self,
        payload: str,
        sample_json: dict | None,
    ) -> list[tuple[str, str]]:
        """
        注入メッセージのリストを生成する。
        JSON の場合は各フィールドを個別に注入した変種も生成する。
        """
        messages: list[tuple[str, str]] = []

        if sample_json is not None:
            # JSON フォーマット: 注入対象キーを1つずつ置換
            for key in sample_json:
                if key.lower() in _INJECT_KEYS or len(messages) < 3:
                    injected = dict(sample_json)
                    injected[key] = payload
                    messages.append((json.dumps(injected), key))
                    if len(messages) >= 3:
                        break
        else:
            # プレーンテキスト: ペイロードをそのまま送信
            messages.append((payload, ""))
            # JSON フォーマットも試みる
            for key in list(_INJECT_KEYS)[:3]:
                messages.append((json.dumps({key: payload}), key))

        return messages[:5]  # 最大 5 パターン
