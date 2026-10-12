import asyncio
from types import SimpleNamespace
from unittest.mock import AsyncMock, Mock

from wscan.api_spec_importer import RequestTemplate
from wscan.attack_planner import FieldAttackPlan, PageAttackPlan
from wscan.engine import (
    CrawledPage,
    ScanEngine,
    _api_plan_field_name,
)
from wscan.injection_point import InjectionPoint


def _planner_engine(*, pages=(), seeds=(), points=(), forms=(), url_params=()):
    engine = ScanEngine.__new__(ScanEngine)
    engine.use_planner = True
    engine.interactive_plan = False
    engine.max_forms = 5
    engine.waf_detector = None
    engine.detected_cms = None
    engine._cms_origin = None
    engine.detected_tech_headers = {}
    engine.json_injection_points = list(points)
    engine.api_seed_requests = list(seeds)
    engine.attack_plans = []
    engine.monitor = None
    engine._llm_semaphore = asyncio.Semaphore(1)
    engine.llm_concurrency = 1
    engine.payload_gen = SimpleNamespace(provider="none")
    engine._print_all_plans = Mock()
    captured = []

    async def analyze_page(**kwargs):
        captured.append(kwargs)
        fields = []
        for form_index, form in enumerate(kwargs["forms"]):
            for item in form.get("inputs", []):
                fields.append(FieldAttackPlan(
                    name=item["name"], form_index=form_index, is_url_param=False,
                    risk_score=5, priority_checks=["os", "sqli"], rationale="test",
                ))
        return PageAttackPlan(
            url=kwargs["url"], page_purpose="API operation", planned_by="llm", fields=fields
        )

    engine.attack_planner = SimpleNamespace(analyze_page=AsyncMock(side_effect=analyze_page))
    if not pages and (forms or url_params):
        pages = [CrawledPage(
            url="https://api.example.test/items", html="", forms=forms,
            url_params=url_params, depth=0,
        )]
    return engine, captured, list(pages)


def test_body_only_api_seeds_create_plan_and_preserve_method_identity():
    url = "https://api.example.test/items"
    seeds = [
        RequestTemplate("POST", url, json_body={"name": "x"}),
        RequestTemplate("PUT", url, json_body={"status": "open"}),
    ]
    page = CrawledPage(url=url, html="", forms=[], url_params=[], depth=0)
    engine, calls, pages = _planner_engine(pages=[page], seeds=seeds)

    plans = asyncio.run(engine._phase_plan(pages))

    assert list(plans) == ["https://api.example.test/items"]
    assert len(calls) == 1
    api_inputs = calls[0]["forms"][-1]["inputs"]
    assert [item["name"] for item in api_inputs] == [
        _api_plan_field_name("POST", url, "/name"),
        _api_plan_field_name("PUT", url, "/status"),
    ]
    assert "POST /items" in calls[0]["fingerprint"]
    assert "PUT /items" in calls[0]["fingerprint"]
    assert plans[url].fields[0].name == api_inputs[0]["name"]


def test_harvested_json_points_also_create_api_plan_inputs():
    url = "https://api.example.test/profile"
    point = InjectionPoint.for_json_body("PATCH", url, "/email", source="spa")
    page = CrawledPage(url=url, html="", forms=[], url_params=[], depth=0)
    engine, calls, pages = _planner_engine(pages=[page], points=[point])

    plans = asyncio.run(engine._phase_plan(pages))

    assert list(plans) == [url]
    assert calls[0]["forms"][-1]["inputs"][0]["name"] == _api_plan_field_name(
        "PATCH", url, "/email"
    )
    assert "PATCH /profile" in calls[0]["fingerprint"]


def test_api_seed_without_crawl_page_uses_exact_operation_url_for_plan_key():
    url = "https://api.example.test/v1/orders?tenant=blue"
    engine, calls, pages = _planner_engine(
        seeds=[RequestTemplate("POST", url, json_body={"id": 1})]
    )

    plans = asyncio.run(engine._phase_plan(pages))

    assert list(plans) == [url]
    assert calls[0]["url"] == url


def test_api_schema_and_plan_inputs_stay_scoped_to_each_origin():
    urls = ["https://one.example.test/items", "https://two.example.test/items"]
    seeds = [
        RequestTemplate("POST", urls[0], json_body={"one": "x"}),
        RequestTemplate("POST", urls[1], json_body={"two": "x"}),
    ]
    pages = [CrawledPage(url=url, html="", forms=[], url_params=[], depth=0) for url in urls]
    engine, calls, pages = _planner_engine(pages=pages, seeds=seeds)

    plans = asyncio.run(engine._phase_plan(pages))

    assert set(plans) == set(urls)
    fingerprints = {call["url"]: call["fingerprint"] for call in calls}
    assert "/one" in fingerprints[urls[0]] and "/two" not in fingerprints[urls[0]]
    assert "/two" in fingerprints[urls[1]] and "/one" not in fingerprints[urls[1]]


def test_no_input_without_api_still_skips_and_existing_form_plan_is_unchanged():
    url = "https://api.example.test/search"
    no_input = CrawledPage(url=url, html="", forms=[], url_params=[], depth=0)
    engine, calls, pages = _planner_engine(pages=[no_input])
    assert asyncio.run(engine._phase_plan(pages)) == {}
    assert calls == []

    forms = [{"inputs": [{"name": "q", "type": "text"}]}]
    engine, calls, pages = _planner_engine(forms=forms)
    plans = asyncio.run(engine._phase_plan(pages))
    assert list(plans) == ["https://api.example.test/items"]
    assert calls[0]["forms"] == forms


def test_json_scanner_consumes_matching_operation_plan_priority():
    url = "https://api.example.test/items"
    points = [
        InjectionPoint.for_json_body("POST", url, "/name", source="spa"),
        InjectionPoint.for_json_body("PUT", url, "/name", source="spa"),
    ]
    order = []
    engine = ScanEngine.__new__(ScanEngine)
    engine.json_injection_points = points
    engine.scanners = {
        name: SimpleNamespace(
            SUPPORTS_JSON_BODY=True,
            scan_injection_point=AsyncMock(side_effect=lambda _ip, _field, n=name: order.append(n) or []),
        )
        for name in ("sqli", "os")
    }
    engine.controller = SimpleNamespace(checkpoint=AsyncMock())
    engine._checkpoint_is_done_ip = Mock(return_value=False)
    engine._maybe_relogin_for_page = AsyncMock()
    engine._sync_cookies_from_browser = AsyncMock()
    engine._api_session_looks_expired = AsyncMock(return_value=False)
    engine._force_relogin = AsyncMock(return_value=False)
    engine._browser = None
    engine.all_findings = []
    engine.injection_templates = {}
    engine._save_checkpoint = Mock()
    engine._record_finding = Mock()
    engine._record_scan_matrix = Mock()
    engine._checkpoint_mark_done_ip = Mock()
    fields = [FieldAttackPlan(
        name=_api_plan_field_name("POST", url, "/name"), form_index=0,
        is_url_param=False, risk_score=5, priority_checks=["os", "sqli"], rationale="test",
    ), FieldAttackPlan(
        name=_api_plan_field_name("PUT", url, "/name"), form_index=0,
        is_url_param=False, risk_score=5, priority_checks=["sqli", "os"], rationale="test",
    )]
    plan = PageAttackPlan(url, "API", "llm", fields)

    asyncio.run(engine._run_json_injection_checks({url: plan}))

    assert order == ["os", "sqli", "sqli", "os"]


def test_api_template_consumer_uses_seed_operation_plan_priority():
    url = "https://api.example.test/items"
    seed = RequestTemplate("POST", url, json_body={"name": "x"})
    order = []
    engine = ScanEngine.__new__(ScanEngine)
    engine.api_seed_requests = [seed]
    engine.target_url = url
    engine.controller = SimpleNamespace(checkpoint=AsyncMock())
    engine._maybe_relogin_for_page = AsyncMock()
    engine._sync_cookies_from_browser = AsyncMock()
    engine._browser = None
    engine._api_session_looks_expired = AsyncMock(return_value=False)
    engine._force_relogin = AsyncMock(return_value=False)
    engine.scanners = {
        name: SimpleNamespace(
            HAS_PAGE_LEVEL=True,
            scan_page=AsyncMock(side_effect=lambda _url, n=name: order.append(n) or []),
        )
        for name in ("sqli", "mass_assignment")
    }
    engine.all_findings = []
    engine._checkpoint_is_done = Mock(return_value=False)
    engine._record_finding = Mock()
    engine._record_scan_matrix = Mock()
    engine._checkpoint_mark_done = Mock()
    engine._save_checkpoint = Mock()
    field = FieldAttackPlan(
        name=_api_plan_field_name("POST", url, "/name"), form_index=0,
        is_url_param=False, risk_score=5,
        priority_checks=["mass_assignment", "sqli"], rationale="test",
    )
    plan = PageAttackPlan(url, "API", "llm", [field])

    asyncio.run(engine._run_api_template_checks({url: plan}))

    assert order == ["mass_assignment", "sqli"]
