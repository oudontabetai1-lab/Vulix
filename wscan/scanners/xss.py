"""
XSS (Cross-Site Scripting) Scanner
Detects reflected and DOM-based XSS vulnerabilities.
"""
import asyncio
import re
import uuid
from contextvars import ContextVar
from typing import TYPE_CHECKING

from wscan.injection_point import InjectionPoint
from wscan.json_body_detect import XSS_MARKERS, analyze_xss_reflection, renderable_html_body

from wscan.scanner_contract import (
    CapabilityState, Carrier, CarrierCapability, CostClass, ExecutionKind,
    PayloadShape, Prerequisite, ScannerContract, StateChangeClass, TransportKind,
    ValueKind,
)

from .base import BaseScanner, Finding

if TYPE_CHECKING:
    from wscan.engine import ScanEngine


# 発火トリガの baseline 用の中立値（英数字のみ・payload とも既存ハンドラ値とも一致
# しない）。この値を payload と同じ経路（URL パラメータ／フォーム action）で投入した
# 応答 DOM からダイアログハンドラを採取し、「新規に増えたハンドラ」判定の基準にする。
_XSS_BASELINE = ContextVar("xss_baseline_attempt", default=None)

_HANDLER_BASELINE_VALUE = "wscanxssbaseline"

# 型付き入力（HTML5 validation）で中立値がフォームに弾かれると、baseline 送信が
# フォームページに留まり action 応答（payload が到達するページ）のハンドラを採れない。
# フィールド型ごとに *検証を通る* 中立値を用意し、payload と同じ応答ブランチへ確実に
# 到達させる（英数字トークン wscanbaseline を各型の妥当な形に埋め込む）。
_TYPED_BASELINE_VALUES = {
    "url": "https://wscanbaseline.example/x",
    "email": "wscanbaseline@example.com",
    "number": "1",
    "range": "1",
    "tel": "0000000000",
    "date": "2000-01-01",
    "datetime-local": "2000-01-01T00:00",
    "time": "12:00",
    "month": "2000-01",
    "week": "2000-W01",
    "color": "#000000",
}


# alert/confirm/prompt 呼び出し（引数は括弧の入れ子を1段許容）を捉える。
_DIALOG_CALL_RE = re.compile(r"(?:alert|confirm|prompt)\s*\((?:[^()]|\([^()]*\))*\)", re.IGNORECASE)


def _make_fire_token() -> str:
    """発火確認用の一意 **数値** トークンを返す（10桁）。

    数値なのでクォート不要（``alert(<token>)``）。引用符を除去/エンコードする入力
    フィルタ下でも実行でき、``alert(1)`` 等ページ本来のハンドラとは一致しない。
    """
    return str(1000000000 + uuid.uuid4().int % 9000000000)


def _tokenize_dialog_calls(payload: str, token: str) -> str:
    """payload 内の alert/confirm/prompt 呼び出しを ``alert(<token>)`` へ置換する（純粋）。

    発火トリガ層で投入するペイロードに一意トークンを埋めることで、注入したハンドラ値が
    payload 固有になる。これにより ``trigger_injected_handlers`` の「ハンドラ値が payload に
    含まれるか」判定が、ページ本来の ``alert(1)`` 等（トークンを含まない）を確実に除外でき、
    値依存の同一パス分岐で正規ハンドラだけが現れるケースでも誤発火しない。発火の確証は
    ダイアログ文言に ``token`` が出ることで裏取りする（dom_xss と同じ一意マーカー方式）。

    トークンは**数値**にしてクォートを使わない（``alert(<token>)``）。引用符を除去する
    フィルタ（``" onmouseover=alert(1) x="`` は通すが ``'`` を消す等）でも実行可能な形を
    保ち、本物の属性ブレイクアウト XSS の confirmed シグナルを失わないため。ダイアログ
    呼び出しが無い payload はそのまま返す。
    """
    if not token:
        return payload
    return _DIALOG_CALL_RE.sub(f"alert({token})", payload)


# NetworkCapture.enrich_response が response.body を 50KB で打ち切る上限。生反射ガードは
# 本文がこの上限に達している（＝切り詰められている可能性がある）ときは「生 payload 非在」を
# 否定証拠に使わない（上限超の位置に反射したブレイクアウトを取りこぼさないため）。
_RESP_BODY_CAP = 50000


def _neutral_baseline_value(field_type: str) -> str:
    """フィールド型に対して HTML5 検証を通る中立 baseline 値を返す。

    未知/テキスト系は ``_HANDLER_BASELINE_VALUE``。型付きは検証を通る妥当値を返し、
    baseline 送信が payload と同じ応答ブランチへ到達できるようにする（さもないと
    型検証で中立値だけフォームに留まり、action 応答固有の正規ハンドラを baseline に
    採れず誤発火＝誤検知の原因になる）。純粋関数。
    """
    return _TYPED_BASELINE_VALUES.get((field_type or "text").lower(), _HANDLER_BASELINE_VALUE)


class XSSScanner(BaseScanner):
    """XSS vulnerability scanner."""

    CHECK_TYPE = "xss"
    CONTRACT = ScannerContract(
        execution_kinds=frozenset({ExecutionKind.FIELD_INJECTION}),
        capabilities=(
            CarrierCapability(
                carrier=Carrier.QUERY, state=CapabilityState.SUPPORTED,
                value_kinds=frozenset({ValueKind.STRING}),
                transports=frozenset({TransportKind.PLAYWRIGHT}),
                browser_required=True,
                payload_shapes=frozenset({PayloadShape.SCALAR}),
            ),
            CarrierCapability(
                carrier=Carrier.FORM, state=CapabilityState.SUPPORTED,
                value_kinds=frozenset({ValueKind.STRING}),
                transports=frozenset({TransportKind.PLAYWRIGHT}),
                browser_required=True,
                payload_shapes=frozenset({PayloadShape.SCALAR}),
            ),
            CarrierCapability(
                # JSON 値の反射のうち、応答が HTML として描画されるものだけを検出（dialog 確証は無し）。
                carrier=Carrier.JSON, state=CapabilityState.SUPPORTED,
                value_kinds=frozenset({ValueKind.STRING}),
                transports=frozenset({TransportKind.HTTPX}),
                payload_shapes=frozenset({PayloadShape.SCALAR}),
            ),
            CarrierCapability(
                carrier=Carrier.XML, state=CapabilityState.SUPPORTED,
                value_kinds=frozenset({ValueKind.STRING}),
                transports=frozenset({TransportKind.HTTPX}),
                payload_shapes=frozenset({PayloadShape.SCALAR}),
            ),
            CarrierCapability(
                carrier=Carrier.MULTIPART, state=CapabilityState.PLANNED,
                reason="carrier 別 dispatcher は未接続",
                task="0035-D",
            ),
            CarrierCapability(
                carrier=Carrier.HEADER, state=CapabilityState.PLANNED,
                reason="carrier 別 dispatcher は未接続",
                task="0035-D",
            ),
            CarrierCapability(
                carrier=Carrier.COOKIE, state=CapabilityState.PLANNED,
                reason="carrier 別 dispatcher は未接続",
                task="0035-D",
            ),
            CarrierCapability(
                carrier=Carrier.PATH, state=CapabilityState.PLANNED,
                reason="carrier 別 dispatcher は未接続",
                task="0035-D",
            ),
            CarrierCapability(
                carrier=Carrier.GRAPHQL, state=CapabilityState.PLANNED,
                reason="carrier 別 dispatcher は未接続",
                task="0035-D",
            ),
            CarrierCapability(
                carrier=Carrier.WEBSOCKET, state=CapabilityState.PLANNED,
                reason="carrier 別 dispatcher は未接続",
                task="0035-D",
            ),
        ),
    )

    SEVERITY = "high"
    SUPPORTS_JSON_BODY = True
    SUPPORTS_XML_BODY = True

    async def scan_injection_point(
        self,
        ip: InjectionPoint,
        field: dict,
    ) -> list[Finding]:
        """Scan a form field or URL parameter for XSS vulnerabilities."""
        # JSON / XML 注入はブラウザ遷移しない（dialog 確証なし）。HTML 応答への生反射だけを検出する。
        if ip.location in ("json_body", "xml_body"):
            return await self._scan_json_reflection(ip, field)

        # baseline も browser を直叩きする（_apply_ip 非経由）ため時間ボックス gate を先に通す。
        # 超過なら alert-flooding sink を再訪せず truncated 記録して未完扱い（SQLi baseline と同流儀）。
        if self._field_budget_gate():
            return []

        findings = []
        field_name = ip.parameter_id
        payloads = await self.get_payloads(field_name, ip.url, ip=ip)

        if self.monitor:
            await self.monitor.emit_status(f"XSS testing: {field_name} on {ip.url}")

        # Capture baseline before injecting any payload. Reflection analysis
        # runs on the raw HTTP response body (where the server's escaping is
        # visible as &lt; / &quot;), not the serialised DOM — the browser
        # re-serialises attribute values with raw < / >, which makes an escaped
        # payload inside value="…" look like a live tag and yields false
        # positives. The DOM (page.content()) is the fallback for DOM-only
        # reflections that never appear in the response body.
        baseline_source = ""
        try:
            await self.browser.navigate(ip.url)
            baseline_source = await self.browser.get_page_source()
            body = self._response_body_for(ip.url)
            if body:
                baseline_source = body
        except Exception as exc:
            if self.monitor:
                await self.monitor.emit_status(
                    f"[warn] xss: baseline fetch failed on {ip.url}: {exc}"
                )

        # baseline（ハンドラ＋リフレクション本文）は「payload と同じ経路を中立値で
        # 開いた応答」から採る。フォームは pre-submit のフォームページと action 応答で
        # 構成が異なるため、中立投入の応答本文を baseline にしないと、結果ページ固有の
        # onclick="alert(1)" 等を新規注入と誤認してリフレクション・発火の双方で誤検知する。
        token = _XSS_BASELINE.set((self, ""))
        try:
            baseline_handlers, baseline_path, baseline_submit_source = await self._baseline_handlers(
                ip,
                neutral_value=_neutral_baseline_value(field.get("type", "text")),
            )
            baseline_ids = (_XSS_BASELINE.get()[1],)
        finally:
            _XSS_BASELINE.reset(token)
        if baseline_submit_source:
            baseline_source = baseline_submit_source

        async def _test_payload(
            payload: str,
            check_label: str = "xss",
            fire: bool = False,
            expect_token: str = "",
        ) -> bool:
            await self.log_payload_test(field_name, payload, check_label, ip.url)

            # Reset dialog detector
            self.browser.reset_dialog()

            # Apply payload
            source, pair = await self._apply_ip(
                ip, payload, baseline_attempt_ids=baseline_ids,
                probe_wave={"xss": "standard", "xss_evolved": "evolution"}.get(check_label, "auxiliary"))

            await asyncio.sleep(0.5 * self.sleep_factor)  # Wait for any JS execution

            # Interaction-required handlers (onmouseover / onclick / onfocus) and
            # javascript: URLs do not fire on their own, so a genuine attribute-
            # breakout payload like `" onmouseover=alert('<token>') x="` reflects but
            # never triggers a dialog. Actively dispatch the matching events — only
            # for the evolution wave, whose payloads carry a unique alert token so a
            # page's own alert(1) handler is never fired or mis-confirmed. Additive
            # and exception-guarded; on failure the scan falls back to reflection.
            # 生反射ガード用に **捕捉した生応答本文のみ**を使う（DOM(page.content)は
            # 属性を再直列化して onmouseover="…" にするため生 payload が一致せず、
            # 本文が取れない実ブレイクアウトを誤って抑止してしまう）。本文が無ければ
            # ガードは適用せず従来フォールバック。
            _raw_body = (pair.get("response", {}) or {}).get("body") or ""
            if fire:
                await self._fire_if_baseline_matches(
                    payload, baseline_handlers, baseline_path, _raw_body
                )

            # --- Check 1: Alert dialog fired (confirmed XSS) ---
            # When an expect_token is set (evolution wave), only treat the dialog as
            # ours if the token appears in its message — a pre-existing handler's
            # dialog (e.g. "1") is then never attributed to the payload.
            if self.browser.dialog_fired and (
                not expect_token or expect_token in (self.browser.dialog_message or "")
            ):
                self._probe_decision(pair, True, "xss_payload_oracle", baseline_attempt_ids=baseline_ids,
                                     rationale="existing browser dialog attribution oracle matched")
                finding = await self.record_finding(
                    url=ip.url,
                    field_name=field_name,
                    payload=payload,
                    evidence=f"JavaScript alert() dialog triggered: '{self.browser.dialog_message}'",
                    pair=pair,
                    severity="critical",
                    dialog_confirmed=True,
                    dialog_message=self.browser.dialog_message,
                    confidence="confirmed",
                    evidence_type="xss_dialog",
                    evidence_details={
                        "execution_signal": "browser_dialog",
                        "dialog_message": self.browser.dialog_message,
                        # verify_finding が type-valid な中立 baseline を再現し、
                        # トークンでダイアログ帰属を裏取りするために保持する。
                        "field_type": field.get("type", "text"),
                        "fire_token": expect_token,
                    },
                    reproduction_steps=[
                        f"Open {ip.url}",
                        f"Submit the payload to '{field_name}'",
                        "Observe that the browser fires a JavaScript dialog.",
                    ],
                    injection_point=ip,
                )
                # record_finding は重複 evidence_type のとき None を返す。None を
                # findings へ積むと後段の any(f.dialog_confirmed ...) が AttributeError。
                if finding:
                    findings.append(finding)
                self.browser.reset_dialog()
                return True

            # --- Check 2: Payload reflected without HTML encoding ---
            reflect_source = _raw_body or source
            # fire=True（evolution）payload は、生反射（本物のブレイクアウト）が生応答本文に
            # 確認できないなら reflection も採らない。サニタイズ後にアプリ自前テンプレの
            # 同名ハンドラへトークンをエコーしただけの値を xss_reflection と誤認しないため
            # （発火の生反射ガードと同じ証拠を要求）。本文が取れないときは従来どおり判定。
            if fire and _raw_body and len(_raw_body) < _RESP_BODY_CAP:
                _npl = re.sub(r"\s+", "", payload or "")
                if _npl and _npl not in re.sub(r"\s+", "", _raw_body):
                    reflect_source = ""
            if reflect_source:
                reflection = self._analyze_reflection(reflect_source, payload, baseline_source)
                if reflection:
                    context = reflection.get("context", "unknown")
                    confidence = reflection.get("confidence", "tentative")
                    severity = "high" if confidence == "likely" else "medium"
                    self._probe_decision(pair, True, "xss_payload_oracle", baseline_attempt_ids=baseline_ids,
                                         rationale="unencoded reflection compared with neutral baseline")
                    finding = await self.record_finding(
                        url=ip.url,
                        field_name=field_name,
                        payload=payload,
                        evidence=(
                            f"XSS payload reflected unencoded in {context} context: "
                            f"'{reflection.get('snippet', '')[:100]}'"
                        ),
                        pair=pair,
                        severity=severity,
                        confidence=confidence,
                        evidence_type="xss_reflection",
                        evidence_details=reflection,
                        reproduction_steps=[
                            f"Open {ip.url}",
                            f"Submit the payload to '{field_name}'",
                            f"Confirm the payload is reflected in {context} context without complete encoding.",
                            "Escalate manually with a context-specific event or script payload if no dialog fires.",
                        ],
                        injection_point=ip,
                    )
                    if finding:
                        findings.append(finding)
                    return True

            self._probe_decision(pair, False, "xss_payload_oracle", baseline_attempt_ids=baseline_ids,
                                 rationale="no attributed dialog or unencoded reflection signal")
            await asyncio.sleep(0.2 * self.sleep_factor)
            return False

        for payload in payloads:
            if await _test_payload(payload):
                break  # Found vulnerability, move to next field

        # --- Check 3: deterministic context-aware evolution wave ---
        # 走らせる条件は次のいずれか（かつ dialog 未確証のとき）:
        #   (a) 何も見つかっていない（従来どおりの探索）。
        #   (b) 既存 finding が属性系文脈の tentative 反射である。反射ヒューリスティック
        #       は「実際に発火するか」を判定できず、messy な quote-break payload で弱い
        #       tentative が立って本当に実行可能な clean breakout
        #       （例: `" onmouseover=alert(1) x="`）を試さずに終わることがあるため、
        #       clean breakout を合成→投入し発火トリガ層で confirmed 昇格を狙う。
        # html_text 等の非属性文脈の tentative では追加しない: `<` が生存するなら標準
        # 掃射の tag 系 payload で既に発火機会があり、`<` がエスケープ済みなら属性
        # breakout も成立しないため、無駄な wave を避ける（誤検知ゼロ＋実行時間の両立）。
        _ATTR_CTX = {"html_attribute", "event_handler_attribute", "url_attribute"}
        have_confirmed = any(f.dialog_confirmed for f in findings)
        attr_ctx_tentative = any(
            (not f.dialog_confirmed)
            and (f.evidence_details or {}).get("context") in _ATTR_CTX
            for f in findings
        )
        if not have_confirmed and (not findings or attr_ctx_tentative):
            extra_payloads = await self.evolved_payloads(
                ip.url,
                ip.form_index,
                ip.parameter_id,
                ip.legacy_is_url_param(),
                dom_index=ip.submit_index,
            )
            # 発火トリガで投入するペイロードには一意トークンを埋め、注入ハンドラ値を
            # payload 固有にする（ページ本来の alert(1) 等を発火・確証しないため）。
            fire_token = _make_fire_token()
            for payload in extra_payloads:
                tok_payload = _tokenize_dialog_calls(payload, fire_token)
                await _test_payload(
                    tok_payload, "xss_evolved", fire=True, expect_token=fire_token
                )
                if any(f.dialog_confirmed for f in findings):
                    break

        # --- Check 4: String-concatenation / quote-break equivalence probe ---
        # When direct reflection checks find nothing, probe whether the input is
        # embedded in a quoted HTML attribute or JS string that can be split with
        # matching quotes (e.g. AA" "BB / 'AA'+'BB'). A collapse to the marker
        # proves the quote breaks the surrounding context — a strong XSS signal.
        if not findings:
            for ctx in ("html_attr", "js_string"):
                probe = await self.run_equivalence_probe(
                    ip.url,
                    ip.form_index,
                    ip.parameter_id,
                    ip.legacy_is_url_param(),
                    context=ctx,
                    dom_index=ip.submit_index,
                )
                if not probe:
                    continue
                verdict, pair = probe
                finding = await self.record_finding(
                    url=ip.url,
                    field_name=field_name,
                    payload=verdict.details.get("matched_payload", ""),
                    evidence=(
                        "String-concatenation/quote-break equivalence XSS: "
                        + verdict.rationale
                    ),
                    pair=pair,
                    severity="medium",
                    confidence="likely" if verdict.confidence >= 0.85 else "tentative",
                    evidence_type="xss_concat_equivalence",
                    evidence_details={
                        "matched_dialect": verdict.matched_dialect,
                        "matched_probe": verdict.matched_probe,
                        "probe_confidence": round(verdict.confidence, 3),
                        **verdict.details,
                    },
                    reproduction_steps=[
                        f"Open {ip.url}",
                        f"Submit the quote-splitting payload to '{field_name}': "
                        f"{verdict.details.get('matched_payload', '')}",
                        "Confirm the response collapses to the marker, proving the "
                        "injected quote breaks the surrounding attribute/JS context.",
                        "Escalate manually with a context-appropriate event/script payload.",
                    ],
                    injection_point=ip,
                )
                if finding:
                    findings.append(finding)
                break

        return findings

    async def _scan_json_reflection(self, ip: InjectionPoint, field: dict) -> list[Finding]:
        """JSON 値の反射を、応答が HTML として描画される場合に限って検出する。

        application/json 等の応答は生 `<script>` を含んでもブラウザが実行しないため採らない
        （`renderable_html_body`）。反射の文脈判定は form/URL 経路と同じ `_analyze_reflection`。
        """
        field_name = field.get("name") or ip.display_name or ip.parameter_id
        await self.log_payload_test(field_name, "baseline_value_wscan", "xss_baseline", ip.url)
        try:
            baseline_source, baseline_pair = await self._apply_ip(ip, "baseline_value_wscan", probe_role="baseline")
        except Exception as exc:
            self._record_scan_note(f"probe_error:{self.CHECK_TYPE}:{type(exc).__name__}")
            return []
        if not baseline_pair:
            return []  # 送信不能（flag は transport 側が立てる）。比較対象が無いので陰性。
        baseline_body = (baseline_pair.get("response") or {}).get("body") or baseline_source or ""

        baseline_ids = (self._probe_id(baseline_pair),)
        for payload in await self.get_payloads(field_name, ip.url, ip=ip):
            await self.log_payload_test(field_name, payload, "xss", ip.url)
            try:
                _source, pair = await self._apply_ip(ip, payload, baseline_attempt_ids=baseline_ids)
            except Exception as exc:
                self._record_scan_note(
                    f"probe_error:{self.CHECK_TYPE}:{type(exc).__name__}"
                )
                continue
            body = renderable_html_body(pair)
            reflection = self._analyze_reflection(body, payload, baseline_body) if body else {}
            self._probe_decision(pair, bool(reflection), "xss_payload_oracle", baseline_attempt_ids=baseline_ids,
                                 rationale="HTML-renderable JSON response reflection comparison")
            if reflection:
                context = reflection.get("context", "unknown")
                confidence = reflection.get("confidence", "tentative")
                finding = await self.record_finding(
                    url=ip.url,
                    field_name=field_name,
                    payload=payload,
                    evidence=(
                        f"XSS payload from JSON body reflected unencoded in an HTML response "
                        f"({context} context): '{reflection.get('snippet', '')[:100]}'"
                    ),
                    pair=pair,
                    severity="high" if confidence == "likely" else "medium",
                    confidence=confidence,
                    evidence_type="xss_reflection",
                    evidence_details=reflection,
                    injection_point=ip,
                )
                return [finding] if finding else []
            await asyncio.sleep(0.2 * self.sleep_factor)
        return []

    async def run_equivalence_probe(
        self,
        url: str,
        form_index: int,
        field_name: str,
        is_url_param: bool,
        *,
        context: str = "sql",
        dom_index: int | None = None,
    ) -> tuple | None:
        """等価性 probe の判定を保ち、送信だけ InjectionPoint 経由にする。"""
        from wscan import equivalence_probe as eqp

        builders = {
            "sql": eqp.sql_probe_set,
            "html_attr": eqp.html_attr_probe_set,
            "js_string": eqp.js_string_probe_set,
        }
        builder = builders.get(context)
        if builder is None:
            return None

        ip = (
            InjectionPoint.for_url_param(url, field_name)
            if is_url_param
            else InjectionPoint.for_form(
                url,
                field_name,
                form_index,
                dom_index=form_index if dom_index is None else dom_index,
            )
        )
        probe_set = builder()
        responses: dict[str, str] = {}
        pairs: dict[str, dict] = {}
        baseline_ids = ()
        for probe in probe_set.probes:
            await self.log_payload_test(
                field_name, probe.value, f"{self.CHECK_TYPE}_equiv", url
            )
            try:
                source, pair = await self._apply_ip(
                    ip, probe.value, probe_role={"baseline": "baseline", "broken": "control", "equivalent": "attack"}[probe.role],
                    probe_wave=f"equivalence:{context}", baseline_attempt_ids=baseline_ids,
                    parent_attempt_id=baseline_ids[0] if baseline_ids else "")
            except Exception as exc:
                self._record_scan_note(
                    f"probe_error:{self.CHECK_TYPE}:{type(exc).__name__}"
                )
                continue
            pairs[probe.name] = pair or {}
            if probe.role == "baseline":
                baseline_ids = (self._probe_id(pair),)
            body = (pair.get("response", {}) or {}).get("body") or source or ""
            responses[probe.name] = body

        verdict = eqp.evaluate(probe_set, responses)
        control_ids = tuple(self._probe_id(pairs.get(p.name)) for p in probe_set.by_role("broken"))
        applicable = bool(probe_set.baseline and probe_set.marker in responses.get(probe_set.baseline.name, ""))
        for probe in probe_set.by_role("equivalent"):
            comparison = {p.name: responses[p.name] for p in probe_set.probes
                          if p.name in responses and (p.role in {"baseline", "broken"} or p is probe)}
            result = eqp.evaluate(probe_set, comparison)
            self._probe_decision(pairs.get(probe.name), result.injectable, "xss_payload_oracle",
                                 baseline_attempt_ids=baseline_ids, control_attempt_ids=control_ids,
                                 outcome=None if applicable else "skipped",
                                 rationale=f"equivalence:{context}; {result.rationale}")
        if verdict.injectable:
            return verdict, pairs.get(verdict.matched_probe, {})
        return None

    async def _evolution_probe(
        self,
        url: str,
        form_index: int,
        field_name: str,
        is_url_param: bool,
        *,
        dom_index: int | None = None,
    ) -> tuple[str, set[str], dict]:
        """文脈 probe の判定を保ち、送信だけ InjectionPoint 経由にする。"""
        try:
            from wscan import context_mutator

            marker = context_mutator.make_marker()
            probe = context_mutator.make_char_probe(marker)
            await self.log_payload_test(
                field_name,
                probe,
                f"{self.CHECK_TYPE}_evolution_probe",
                url,
            )
            ip = (
                InjectionPoint.for_url_param(url, field_name)
                if is_url_param
                else InjectionPoint.for_form(
                    url,
                    field_name,
                    form_index,
                    dom_index=form_index if dom_index is None else dom_index,
                )
            )
            source, pair = await self._apply_ip(ip, probe)
            response_source = (
                (pair.get("response", {}) or {}).get("body") or source or ""
            )
            surviving = context_mutator.surviving_chars(response_source, marker)
            detected_context = context_mutator.detect_context(response_source, marker)
            detected_context["marker"] = marker
            return response_source, surviving, detected_context
        except Exception as exc:
            self._note_wave_degradation("evolution_probe", exc)
            return "", set(), {}

    async def scan_field(
        self,
        url: str,
        form_index: int,
        field: dict,
        is_url_param: bool = False,
    ) -> list[Finding]:
        """従来 API を InjectionPoint 駆動へ接続する互換 wrapper。"""
        name = field.get("name", "unknown")
        ip = (
            InjectionPoint.for_url_param(url, name)
            if is_url_param
            else InjectionPoint.for_form(url, name, form_index)
        )
        return await self.scan_injection_point(ip, field)

    def _check_reflected(self, source: str, payload: str, baseline_source: str = "") -> str:
        """
        Check if the payload is reflected in the source without HTML encoding.
        Uses baseline comparison to avoid false positives from pre-existing page content.
        Returns the matched snippet or empty string.
        """
        reflection = self._analyze_reflection(source, payload, baseline_source)
        if reflection:
            return reflection.get("snippet", "")
        return ""

    _analyze_reflection = staticmethod(analyze_xss_reflection)

    def _response_body_for(self, url: str) -> str:
        """Raw HTTP response body captured for ``url`` (empty when unavailable).

        Reflection analysis prefers this over the serialised DOM because the
        server's escaping (``&lt;`` / ``&quot;``) is visible here, whereas the
        browser re-emits attribute values with raw ``<`` / ``>``.
        """
        net = getattr(self.browser, "network", None)
        if not net:
            return ""
        try:
            pair = net.latest_for_url(url) or net.latest() or {}
        except Exception:
            return ""
        return pair.get("response", {}).get("body") or ""

    async def _baseline_handlers(
        self,
        ip: InjectionPoint,
        neutral_value: str = _HANDLER_BASELINE_VALUE,
    ) -> tuple[list, str | None, str]:
        """発火トリガ層とリフレクション判定の baseline を **中立投入の応答**から採る。

        中立値（型付きは検証を通る値）を **payload と同じ経路**で投入し、その応答から
        (1) ダイアログハンドラ一覧、(2) 着地パス、(3) 応答本文（リフレクション baseline）
        を返す。フォームは pre-submit のフォームページと action 応答でハンドラ/本文が
        異なるため、応答本文を baseline にしないと action 応答固有の正規 onclick=alert(1)
        等を「payload が入れた新規」と誤認して発火・リフレクション双方で誤検知する。

        着地パスは payload の着地と一致するときだけ発火するために使う（型検証で中立値が
        フォームに留まり payload だけ別ページへ到達した場合の誤発火防止）。戻り値は
        ``(handlers, landing_path, source)``。失敗時は ``([], None, "")``。中立投入で
        立ったダイアログは後続 payload に持ち越さないよう reset する。
        """
        from urllib.parse import urlparse

        try:
            await self.log_payload_test(
                ip.parameter_id, neutral_value, "xss_handler_baseline", ip.url
            )
            self.browser.reset_dialog()
            src, pair = await self._apply_ip(ip, neutral_value, probe_role="baseline")
            context = _XSS_BASELINE.get()
            if context is not None and context[0] is self:
                _XSS_BASELINE.set((self, self._probe_id(pair)))
            await asyncio.sleep(0.2 * self.sleep_factor)
            handlers = await self.browser.snapshot_dialog_handlers()
            landing_path = urlparse(self.browser.page.url).path
            body = (pair.get("response", {}) or {}).get("body") or src or ""
            return handlers, landing_path, body
        except Exception:
            return [], None, ""
        finally:
            self.browser.reset_dialog()

    def _current_path(self) -> str | None:
        """発火判定用に、いま browser がいるページの URL パスを返す（失敗時 None）。"""
        from urllib.parse import urlparse

        try:
            return urlparse(self.browser.page.url).path
        except Exception:
            return None

    async def _fire_if_baseline_matches(
        self,
        payload: str,
        baseline_handlers: list,
        baseline_path: str | None,
        raw_body: str = "",
    ) -> None:
        """baseline を採れた着地ページと同じ場所にいるときだけ発火トリガを撃つ。

        発火の前提として **payload の生の構造が応答本文にそのまま反射している**ことを
        要求する。本物の属性ブレイクアウトは payload を丸ごと生反射する（例:
        ``value="" onmouseover=alert(<t>) x="">``）が、アプリが入力をサニタイズして
        自前テンプレの同名ハンドラ（``onmouseover="alert(<echoed>)"``）に埋め込んだ場合は
        属性が再構築され生 payload は本文に現れない。これにより、値/トークン/DOM 構造が
        一致してもアプリ生成 UI の値エコーを confirmed 化しない。

        着地パスが一致しない（中立 baseline が別ページに落ちた）／baseline 不確実
        （``baseline_path is None``）／生反射が確認できない場合は発火を見送り、従来の
        反射ヒューリスティックに委ねる。加算的・例外保護。
        """
        if self.browser.dialog_fired:
            return
        try:
            if baseline_path is None:
                return
            if self._current_path() != baseline_path:
                return
            # 生反射の確認（応答本文が **完全に取れている** ときのみ否定証拠に使う。
            # 50KB 上限に達している本文は切り詰められている可能性があり、上限超に反射した
            # ブレイクアウトを取りこぼさないよう、非在でも抑止せず従来経路へフォールバック）。
            if raw_body and len(raw_body) < _RESP_BODY_CAP:
                nb = re.sub(r"\s+", "", raw_body)
                npl = re.sub(r"\s+", "", payload or "")
                if npl and npl not in nb:
                    return
            if await self.browser.trigger_injected_handlers(payload, baseline_handlers):
                await asyncio.sleep(0.3 * self.sleep_factor)
        except Exception as exc:
            self._record_scan_note(
                f"probe_error:{self.CHECK_TYPE}:{type(exc).__name__}"
            )

    async def verify_finding(self, finding: Finding) -> bool | None:
        from urllib.parse import parse_qs, urlparse
        is_url_param = finding.field_name in parse_qs(
            urlparse(finding.url).query, keep_blank_values=True
        )
        ip = self._verify_injection_point(finding, is_url_param)
        if ip is None:
            return None
        if ip.location == "json_body":
            return await self._verify_json_reflection(finding, ip)
        baseline_source = ""
        try:
            self.browser.reset_dialog()
            await self.browser.navigate(finding.url)
            baseline_source = await self.browser.get_page_source()
            body = self._response_body_for(finding.url)
            if body:
                baseline_source = body
        except Exception:
            baseline_source = ""
        # baseline（ハンドラ＋リフレクション本文）は payload と同じ経路を中立値で開いた
        # 応答から採る（フォーム action 応答固有の正規ハンドラを誤発火/誤検知しないため）。
        # 型付きフィールドは検知時と同じ **type-valid な中立値** を使う（そうしないと
        # type=url 等で中立値が検証に落ち baseline がフォームに留まり、着地パス不一致で
        # 本物の confirmed XSS を未確証扱いにしてしまう）。
        _details = finding.evidence_details or {}
        baseline_handlers, baseline_path, baseline_submit_source = await self._baseline_handlers(
            ip,
            neutral_value=_neutral_baseline_value(_details.get("field_type", "text")),
        )
        if baseline_submit_source:
            baseline_source = baseline_submit_source
        self.browser.reset_dialog()
        await self.log_payload_test(
            finding.field_name, finding.payload, "xss_verify", finding.url
        )
        source, pair = await self._apply_ip(ip, finding.payload)
        await asyncio.sleep(0.5 * self.sleep_factor)
        # 発火は dialog 由来の finding のみ再現（その payload は一意トークン付きなので
        # ページ本来の alert(1) 等を発火・誤確証しない）。reflection 由来は下で反射を
        # 再判定するため、能動発火はしない（無関係な既存ハンドラを撃たないため）。
        token = ""
        if getattr(finding, "evidence_type", "") == "xss_dialog":
            token = str(_details.get("fire_token", "") or "")
            # 生反射ガードには捕捉した生応答本文のみ渡す（DOM 直列化で生 payload が
            # 一致せず、本文欠落時に本物の確証 XSS を未確証化しないため）。
            _raw = (pair.get("response", {}) or {}).get("body") or ""
            await self._fire_if_baseline_matches(
                finding.payload, baseline_handlers, baseline_path, _raw
            )
        if self.browser.dialog_fired and (
            not token or token in (self.browser.dialog_message or "")
        ):
            return True
        if getattr(finding, "evidence_type", "") == "xss_dialog":
            return False
        reflect_source = pair.get("response", {}).get("body") or source
        return bool(reflect_source and self._analyze_reflection(reflect_source, finding.payload, baseline_source))

    async def _verify_json_reflection(self, finding: Finding, ip: InjectionPoint) -> bool | None:
        """JSON 注入点の再現確認。検出時と同じ判定（HTML 応答への生反射）を再評価する。"""
        name = finding.field_name
        try:
            await self.log_payload_test(name, "baseline_value_wscan", "xss_verify_baseline", finding.url)
            baseline_source, baseline_pair = await self._apply_ip(ip, "baseline_value_wscan")
            await self.log_payload_test(name, finding.payload, "xss_verify", finding.url)
            _source, pair = await self._apply_ip(ip, finding.payload)
        except Exception:
            return None
        if not baseline_pair or not pair:
            return None  # 送信不能を陰性（unreproduced）と誤認しない
        baseline_body = (baseline_pair.get("response") or {}).get("body") or baseline_source or ""
        body = renderable_html_body(pair)
        return bool(body and self._analyze_reflection(body, finding.payload, baseline_body))

    async def _apply_payload(
        self,
        url: str,
        form_index: int,
        field_name: str,
        payload: str,
        is_url_param: bool,
    ) -> tuple[str, dict]:
        try:
            if is_url_param:
                return await self.browser.test_url_param(url, field_name, payload)
            else:
                await self.browser.navigate(url)
                return await self.browser.fill_and_submit_form(
                    form_index, field_name, payload
                )
        except Exception as exc:
            self._probe_failure(self._probe_exception_outcome(exc))
            self._record_scan_note(
                f"transport_error:{self.CHECK_TYPE}:{type(exc).__name__}"
            )
            if self.monitor:
                await self.monitor.emit_status(
                    f"[warn] xss: _apply_payload failed on {field_name} @ {url}: {exc}"
                )
            return "", {}
