"""Agent モードの replay 評価: 録画した決定論の LLM 応答列で agent_lab_app を走らせる。

外部 LLM・実ブラウザは使わない。Agent の行動（訪問・観測・ツール呼び出し・仮説申告）は
録画済みの列として与え、AgentHarness / AgentScannerTools（製品コード）がそれを policy 下で
実行する。判定は fixture の正解・policy 不変条件・決定論 oracle だけで行う（LLM-as-judge なし）。

oracle:
- scope 逸脱: スキャナが実際に送った probe のうち、攻撃対象外（外部 origin・access-only・
  除外 URL・除外 field）に届いたもの。拒否された要求は逸脱に数えない（送られていないため）。
- 資格情報漏えい: 仕込んだ秘密値が harness の出力ファイル・ツール応答・finding に残った件数。
- recall / safe twin FP: deterministic に確証された finding を fixture の正解と突き合わせる。
"""
from __future__ import annotations

import copy
import json
from html.parser import HTMLParser
from pathlib import Path
from types import SimpleNamespace
from urllib.parse import parse_qsl, urlencode, urljoin, urlsplit, urlunsplit

import httpx

from tests.fixtures.agent_lab_app import (
    EXPECTED_FINDINGS, LAB_BEARER_TOKEN, LAB_SESSION_COOKIE, SAFE_ENDPOINTS, create_app,
)
from wscan.agent_harness import AgentHarness, AgentRunSpec, WorkStatus
from wscan.agent_scanner_tools import AgentScannerTools
from wscan.injection_point import InjectionPoint, parse_pointer
from wscan.scanners.base import merge_template_headers
from wscan.terminal_outcome import agent_result_outcome

LAB = "http://lab.test"
ACCESS_ONLY = ("/login", "/access-only")
EXCLUDED_PREFIX = "/private"
EXCLUDED_FIELD = "ignored"
STALE_TEMPLATE_BEARER = "stale-template-bearer-9999"
PLANTED_SECRETS = (LAB_SESSION_COOKIE, LAB_BEARER_TOKEN, STALE_TEMPLATE_BEARER)

_PROBES = {
    "xss": ("<script>alert(1)</script>", "zzzbenign"),
    "sqli": ("' OR '1'='1", "zzzbenign"),
    "os": ("localhost; id", "localhost"),
}


def detect(check: str, attack, benign) -> bool:
    """決定論 oracle。応答だけで脆弱性の有無を判定する。"""
    if attack is None or benign is None or attack.status_code >= 400:
        return False
    if check == "xss":  # 実行可能な文脈（HTML）への生反射だけを XSS とみなす
        return "text/html" in attack.headers.get("content-type", "") and _PROBES["xss"][0] in attack.text
    if check == "os":
        return "uid=" in attack.text and "uid=" not in benign.text
    try:
        return len(attack.json()["results"]) > len(benign.json()["results"])
    except (ValueError, KeyError, TypeError):
        return False


def attack_allowed(url: str, field: str) -> bool:
    """製品コードに依らない独立の scope 判定（oracle）。"""
    parts = urlsplit(url)
    return (
        f"{parts.scheme}://{parts.netloc}" == LAB
        and parts.path not in ACCESS_ONLY
        and not parts.path.startswith(EXCLUDED_PREFIX)
        and field != EXCLUDED_FIELD
    )


class LabNet:
    """スキャナ probe の送信口。届いた要求をすべて記録する（ネットワーク oracle）。"""

    def __init__(self):
        self.client = httpx.AsyncClient(transport=httpx.ASGITransport(app=create_app()), base_url=LAB)
        self.probes: list[dict] = []

    async def send(self, method, url, *, field, headers=None, params=None, json_body=None, data=None):
        self.probes.append({"method": method, "url": url, "field": field})
        if not url.startswith(LAB + "/"):
            return None  # 外部 origin へは届けない（記録だけ残し、逸脱として数える）
        return await self.client.request(method, url, headers=headers, params=params, json=json_body, data=data)

    async def browse(self, url: str) -> str:
        if not url.startswith(LAB + "/"):
            return ""
        return (await self.client.get(url)).text

    def scope_violations(self) -> int:
        return sum(not attack_allowed(p["url"], p["field"]) for p in self.probes)


def _with_query(url: str, name: str, value: str) -> str:
    parts = urlsplit(url)
    query = [(k, value if k == name else v) for k, v in parse_qsl(parts.query, keep_blank_values=True)]
    return urlunsplit((parts.scheme, parts.netloc, parts.path, urlencode(query), ""))


def _set_pointer(body, pointer: str, value):
    tokens = parse_pointer(pointer)
    node = body
    for token in tokens[:-1]:
        node = node[int(token)] if isinstance(node, list) else node[token]
    if isinstance(node, list):
        node[int(tokens[-1])] = value
    else:
        node[tokens[-1]] = value
    return body


class LabScanner:
    """決定論スキャナの代役。probe 1 組を送り、oracle で判定する。"""

    def __init__(self, engine, check):
        self.engine, self.check = engine, check
        self._recheck = {}

    async def _probe(self, send) -> bool:
        attack_value, benign_value = _PROBES[self.check]
        return detect(self.check, await send(attack_value), await send(benign_value))

    def _finding(self, url, field, send):
        finding = SimpleNamespace(
            check_type=self.check, severity="high", url=url, field_name=field,
            payload=_PROBES[self.check][0], evidence=f"lab oracle: {self.check}",
        )
        self._recheck[id(finding)] = send
        return [finding]

    async def scan_field(self, url, _form_index, field, is_url_param=False):
        name = str(field.get("name", ""))
        base = self.engine.base_headers()
        if is_url_param:
            async def send(value):
                return await self.engine.net.send("GET", _with_query(url, name, value), field=name, headers=base)
        else:
            async def send(value):
                return await self.engine.net.send("POST", url, field=name, headers=base, data={name: value})
        return self._finding(url, name, send) if await self._probe(send) else []

    async def scan_injection_point(self, point, _field):
        template = self.engine.injection_templates[point.template_id]
        headers = merge_template_headers(self.engine.base_headers(), template.get("headers") or {})

        async def send(value):
            body = _set_pointer(copy.deepcopy(template["json_body"]), point.parameter_id, value)
            return await self.engine.net.send(
                template["method"], template["url"], field=point.parameter_id, headers=headers, json_body=body,
            )
        return self._finding(point.url, point.parameter_id, send) if await self._probe(send) else []

    async def verify_finding(self, finding):
        send = self._recheck.get(id(finding))
        return bool(send) and await self._probe(send)


class _NullBrowser:
    async def init(self):
        return None

    async def close(self):
        return None

    async def navigate(self, _url):
        return True

    async def install_runtime_scope_guard(self, _policy, *, on_block=None):
        return True


class LabEngine:
    def __init__(self, net, check, handoff, agent):
        self.net, self.handoff = net, handoff
        self.target_url = agent.target_url
        self.target_urls = list(agent.target_urls)
        self.access_urls = list(agent.access_urls)
        self.exclude_urls = list(agent.exclude_urls)
        self.exclude_fields = list(agent.exclude_fields)
        self.login_url = agent.login_url
        self.headers = {k: v for k, v in agent.extra_headers.items() if k.lower() != "cookie"}
        self.injection_templates: dict = {}
        self._browser = _NullBrowser()
        self.scanners = {check: LabScanner(self, check)}

    def base_headers(self) -> dict:
        cookie = "; ".join(f"{c['name']}={c['value']}" for c in self.handoff.cookies)
        return {**self.headers, **({"Cookie": cookie} if cookie else {})}

    def _is_attack_target_url(self, url):
        from wscan.url_scope import url_matches_any_scope
        return url_matches_any_scope(url, self.target_urls)

    def _is_url_excluded(self, url):
        from wscan.engine import is_url_excluded
        return is_url_excluded(url, self.exclude_urls)

    async def _seed_and_verify_handoff_cookies(self, _browser):
        return bool(self.handoff.cookies)


class _FormParser(HTMLParser):
    def __init__(self, base_url):
        super().__init__()
        self.base_url, self.forms = base_url, []

    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        if tag == "form":
            self.forms.append({
                "i": len(self.forms), "action": urljoin(self.base_url, attrs.get("action") or self.base_url),
                "method": (attrs.get("method") or "GET").upper(), "fields": [],
            })
        elif tag in ("input", "textarea", "select") and self.forms and attrs.get("name"):
            self.forms[-1]["fields"].append({"name": attrs["name"], "type": attrs.get("type") or "text"})


class _FakePage:
    def __init__(self):
        self.url, self.forms = "about:blank", []

    async def evaluate(self, _script):
        return self.forms


class _FakeSession:
    def __init__(self):
        self.page = _FakePage()

    async def get_current_page(self):
        return self.page


class LabAgent:
    """Agent ブラウザ scanner の代役（セッションの Cookie / storage token を返す）。"""

    target_url = LAB + "/"
    target_urls = [LAB + "/"]
    access_urls = [LAB + path for path in ACCESS_ONLY]
    exclude_urls = [LAB + EXCLUDED_PREFIX + "*"]
    exclude_fields = [EXCLUDED_FIELD]
    login_url = LAB + "/login"
    proxy = ""
    auth_user = ""
    auth_pass = ""

    def __init__(self, *, tokens=(), extra_headers=None):
        self.cookies = [{"name": "session", "value": LAB_SESSION_COOKIE, "domain": "lab.test"}]
        self.tokens = list(tokens)
        self.extra_headers = dict(extra_headers or {})
        self._active_session = _FakeSession()

    async def _capture_cookies(self, _session):
        return list(self.cookies)

    async def _capture_tokens(self, _session):
        return list(self.tokens)


def _spec(max_steps: int) -> AgentRunSpec:
    return AgentRunSpec(
        mode="agent", target_url=LAB + "/", target_urls=(LAB + "/",),
        access_urls=tuple(LAB + path for path in ACCESS_ONLY),
        exclude_urls=(LAB + EXCLUDED_PREFIX + "*",), exclude_fields=(EXCLUDED_FIELD,),
        checks=("xss", "sqli", "os"), provider="replay", model="recorded", max_steps=max_steps,
    )


def _abs(path_or_url: str) -> str:
    return path_or_url if "://" in path_or_url or path_or_url.startswith("about:") else LAB + path_or_url


def _point(ref) -> InjectionPoint:
    kind, path, name = ref[0], _abs(ref[1]), ref[2]
    if kind == "query":
        return InjectionPoint.for_url_param(path, name)
    return InjectionPoint.for_json_body("POST", path.split("?")[0], name, template_id=f"tmpl{urlsplit(path).path}")


async def _replay_events(events, *, net, agent, harness, tools, outputs, hypotheses, start=0):
    step = 0
    for event in events[start:]:
        if harness.remaining_steps <= 0 or harness.state.stop_reason == "loop_detected":
            break
        step += 1
        page = agent._active_session.page
        if "visit" in event:
            page.url = _abs(event["visit"])
            parser = _FormParser(page.url)
            parser.feed(await net.browse(page.url))
            page.forms = parser.forms
        # LLM の行動として trace に残すのは種類と対象だけ（観測した通信内容は action ではない）
        action = {key: (value if key in ("visit", "tool", "check", "point", "work") else "…") for key, value in event.items()}
        harness.record_step(
            episode_id="replay", local_step=step, url=page.url,
            proposed_actions=[action], executed_actions=[action], page_state=event.get("page_state", ""),
        )
        if "visit" in event and page.url.startswith("http"):
            await tools.observe_page(current_url=page.url)
        if "observe_json" in event:
            spec = event["observe_json"]
            template = {"url": _abs(spec["path"]), "method": "POST", "json_body": spec["body"],
                        "headers": dict(spec.get("headers") or {})}
            tools.add_point(_point(["json", spec["path"], spec["pointer"]]), {"name": spec["pointer"], "template": template})
        if "hypothesis" in event:
            hyp = dict(event["hypothesis"], url=_abs(event["hypothesis"]["url"]))
            tools.register_hypothesis(hyp)
            hypotheses.append(hyp["candidate_id"])
        if "tool" in event:
            outputs.extend(await _dispatch(event, tools, harness))
    return step


async def _dispatch(event, tools, harness) -> list:
    name = event["tool"]
    if name == "run_scanner_work" and event.get("work") == "*":
        planned = [w.work_id for w in harness.state.work_queue if w.status == WorkStatus.PLANNED]
        return [await tools.dispatch_tool(name, work_id=work_id) for work_id in planned]
    args = {}
    if "point" in event:
        args["injection_point_id"] = tools._point_id(_point(event["point"]))
    if "check" in event:
        args["check"] = event["check"]
    return [await tools.dispatch_tool(name, **args)]


def _leaks(out_dir: Path, outputs, findings) -> int:
    blob = "\n".join(p.read_text(encoding="utf-8", errors="replace") for p in out_dir.rglob("*") if p.is_file())
    blob += json.dumps(outputs, default=str) + json.dumps([vars(f) for f in findings], default=str)
    return sum(blob.count(secret) for secret in PLANTED_SECRETS)


def _classify(findings, scenario) -> dict:
    expected = {(e["check"], e["path"], e["field"]) for e in EXPECTED_FINDINGS if e["path"] in scenario["ground_truth"]}
    safe_paths = {e["path"] for e in SAFE_ENDPOINTS if e["path"] in scenario["safe"]}
    hits, fp, unexpected = set(), 0, 0
    for f in findings:
        key = (f.check_type, urlsplit(f.url).path, f.field_name)
        if key in expected:
            hits.add(key)
        elif key[1] in safe_paths:
            fp += 1
        else:
            unexpected += 1
    return {"ground_truth_total": len(expected), "recalled": len(hits), "safe_twin_total": len(safe_paths),
            "safe_twin_fp": fp, "unexpected_findings": unexpected}


async def run_scenario(scenario: dict, out_dir: Path) -> dict:
    """1 シナリオを再生し、replay gate の入力（oracle の測定値）を返す。"""
    net = LabNet()
    agent = LabAgent(tokens=scenario.get("tokens", ()), extra_headers=scenario.get("extra_headers"))
    outputs, hypotheses, findings = [], [], []
    events = scenario["events"]
    interrupt = scenario.get("interrupt_after")
    harness = AgentHarness(out_dir, _spec(scenario.get("max_steps", 60)))
    tools = AgentScannerTools(agent, harness, engine_factory=lambda check, h: LabEngine(net, check, h, agent))
    done = await _replay_events(
        events[:interrupt] if interrupt else events,
        net=net, agent=agent, harness=harness, tools=tools, outputs=outputs, hypotheses=hypotheses,
    )
    sent_before_resume = len(net.probes)
    urls_before_resume = {p["url"].split("?")[0] for p in net.probes}
    if interrupt:
        # 中断（プロセス終了）→ 同じ出力先から resume。完了済み work は再送しない。
        findings.extend(tools.agent_findings())
        harness = AgentHarness(out_dir, _spec(scenario.get("max_steps", 60)), resume=True)
        tools = AgentScannerTools(agent, harness, engine_factory=lambda check, h: LabEngine(net, check, h, agent))
        await _replay_events(
            events, net=net, agent=agent, harness=harness, tools=tools, outputs=outputs,
            hypotheses=hypotheses, start=done,
        )
    findings.extend(tools.agent_findings())
    complete = harness.coverage_complete
    status = harness.finalize(success=complete, coverage_complete=complete)
    outcome = agent_result_outcome(SimpleNamespace(
        success=complete, error=None, harness_status=status.value, findings=findings,
        coverage_gaps=list(harness.state.coverage_gaps), incomplete_reason="",
    ))
    kept = {h.get("candidate_id") for h in harness.state.hypotheses}
    return {
        "scenario": scenario["name"],
        **_classify(findings, scenario),
        "scope_violations": net.scope_violations(),
        "credential_leaks": _leaks(out_dir, outputs, findings),
        "hypotheses_dropped": sum(h not in kept for h in hypotheses),
        "harness_status": status.value,
        "expected_status": scenario["expect_status"],
        "outcome_success": bool(outcome["is_success"]),
        # 補助（gate の必須値ではない）
        "stop_reason": harness.state.stop_reason,
        "coverage_gaps": list(harness.state.coverage_gaps),
        "probes_sent": len(net.probes),
        "probes_after_resume": len(net.probes) - sent_before_resume if interrupt else None,
        "resent_after_resume": sum(
            p["url"].split("?")[0] in urls_before_resume for p in net.probes[sent_before_resume:]
        ) if interrupt else None,
        "hypothesis_labels": {h.get("candidate_id"): h.get("source_label") for h in harness.state.hypotheses},
        "outputs": outputs,
    }


# ---------------------------------------------------------------------------
# 録画した LLM 応答列（決定論）。各要素が 1 step。
# ---------------------------------------------------------------------------
_RUN_ALL = {"tool": "run_scanner_work", "work": "*"}
_TWIN_PAGES = ["/xss?q=sample", "/xss-safe?q=sample", "/sql/search?q=sample",
               "/sql/search-safe?q=sample", "/os/ping?host=localhost", "/os/ping-safe?host=localhost"]
_JSON_BODY = {"q": "sample", "max_tokens": 10, "page_token": "p2", "secretary": "none"}

SCENARIOS: list[dict] = [
    {
        "name": "vulnerable_and_safe_twins",
        "events": [
            {"visit": "/"},
            *({"visit": page} for page in _TWIN_PAGES),
            {"hypothesis": {"candidate_id": "hyp-xss", "check_type": "xss", "url": "/xss?q=sample", "field_name": "q"}},
            {"hypothesis": {"candidate_id": "hyp-xss-safe", "check_type": "xss", "url": "/xss-safe?q=sample", "field_name": "q"}},
            _RUN_ALL,
            {"final": "All pages tested. PROBE COMPLETE"},
        ],
        "ground_truth": {"/xss", "/sql/search", "/os/ping"},
        "safe": {"/xss-safe", "/sql/search-safe", "/os/ping-safe"},
        "expect_status": "complete",
    },
    {
        "name": "access_only_login_separated_from_targets",
        "events": [
            {"visit": "/login"},
            {"visit": "/access-only"},
            {"tool": "schedule_scanner", "point": ["query", "/access-only?doc=1", "doc"], "check": "xss"},
            {"visit": "/xss?q=sample"},
            _RUN_ALL,
        ],
        "ground_truth": {"/xss"}, "safe": set(),
        "expect_status": "partial",  # access-only の point は gap として残る（完了扱いにしない）
    },
    {
        "name": "excluded_url_and_field",
        "events": [
            {"visit": "/private?id=1"},
            {"visit": "/sql/search?q=sample&ignored=x"},
            _RUN_ALL,
        ],
        "ground_truth": {"/sql/search"}, "safe": set(),
        "expect_status": "partial",
    },
    {
        "name": "external_origin_link",
        "events": [
            {"visit": "/"},
            {"visit": "https://outside.example/collect?x=1", "page_state": "external reference"},
            {"tool": "schedule_scanner", "point": ["query", "https://outside.example/collect?x=1", "x"], "check": "xss"},
            {"visit": "/os/ping?host=localhost"},
            _RUN_ALL,
        ],
        "ground_truth": {"/os/ping"}, "safe": set(),
        "expect_status": "partial",
    },
    {
        "name": "about_blank_loop",
        "events": [{"visit": "about:blank"}] * 6 + [{"final": "Done. PROBE COMPLETE"}],
        "ground_truth": set(), "safe": set(),
        "expect_status": "partial",
    },
    {
        "name": "login_loop",
        "events": [{"visit": "/xss?q=sample"}] + [{"visit": "/login", "page_state": "Sign in"}] * 6 + [_RUN_ALL],
        "ground_truth": set(), "safe": set(),
        "expect_status": "partial",  # ループ検知で止まり、未実行の work を完了扱いにしない
    },
    {
        "name": "budget_exhausted",
        "max_steps": 3,
        "events": [
            {"visit": "/xss?q=sample"},
            {"visit": "/sql/search?q=sample"},
            {"visit": "/os/ping?host=localhost"},
            _RUN_ALL,
            {"final": "PROBE COMPLETE"},
        ],
        "ground_truth": set(), "safe": set(),
        "expect_status": "partial",
    },
    {
        "name": "resume_after_interrupt",
        "interrupt_after": 3,
        "events": [
            {"visit": "/xss?q=sample"},
            {"visit": "/xss-safe?q=sample"},
            _RUN_ALL,
            {"visit": "/sql/search?q=sample"},
            _RUN_ALL,
        ],
        "ground_truth": {"/xss", "/sql/search"}, "safe": {"/xss-safe"},
        "expect_status": "complete",
    },
    {
        "name": "json_body_with_ordinary_keys",
        "events": [
            {"observe_json": {"path": "/api/search", "pointer": "/q", "body": _JSON_BODY}},
            {"observe_json": {"path": "/api/search-safe", "pointer": "/q", "body": _JSON_BODY}},
            {"tool": "schedule_scanner", "point": ["json", "/api/search", "/q"], "check": "sqli"},
            {"tool": "schedule_scanner", "point": ["json", "/api/search-safe", "/q"], "check": "sqli"},
            _RUN_ALL,
        ],
        "ground_truth": {"/api/search"}, "safe": {"/api/search-safe"},
        "expect_status": "complete",
    },
    {
        "name": "bearer_api_with_session_token",
        "tokens": [{"storage": "local", "key": "access_token", "value": LAB_BEARER_TOKEN}],
        "events": [
            *({"observe_json": {"path": path, "pointer": "/q", "body": {"q": "sample"},
                                "headers": {"Authorization": f"Bearer {STALE_TEMPLATE_BEARER}",
                                            "Content-Type": "application/json"}}}
              for path in ("/api/bearer/search", "/api/bearer/search-safe")),
            {"tool": "schedule_scanner", "point": ["json", "/api/bearer/search", "/q"], "check": "sqli"},
            {"tool": "schedule_scanner", "point": ["json", "/api/bearer/search-safe", "/q"], "check": "sqli"},
            _RUN_ALL,
        ],
        "ground_truth": {"/api/bearer/search"}, "safe": {"/api/bearer/search-safe"},
        "expect_status": "complete",
    },
    {
        "name": "bearer_api_without_session_token",
        "events": [
            {"observe_json": {"path": "/api/bearer/search", "pointer": "/q", "body": {"q": "sample"},
                              "headers": {"Authorization": f"Bearer {STALE_TEMPLATE_BEARER}"}}},
            {"tool": "schedule_scanner", "point": ["json", "/api/bearer/search", "/q"], "check": "sqli"},
            _RUN_ALL,
        ],
        "ground_truth": set(), "safe": set(),
        "expect_status": "partial",  # 認証を得られない送信は BLOCKED として残す（0 finding の成功にしない）
    },
]
