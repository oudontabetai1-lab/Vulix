"""PR 検出回帰ゲート（Recall / FPR / ゼロ試行抑止 / Nightly 有効期限ゲート）の高速検証。

PR CI の標準テストスイート（pytest -q --ignore=tests/test_end_to_end_scan.py）の一部として
Chromium を起動せずにミリ秒オーダーで高速実行し、コア検査（XSS, SQLi, SSTI, OS injection,
Open Redirect）に対する決定論スキャナの検知・非検知、および受入条件（偽陰性0・偽陽性0・
ゼロ試行拒絶・計測脱落検知・Nightly有効期限）を固定する。
"""
from __future__ import annotations

import asyncio
from contextlib import contextmanager
import json
from pathlib import Path
import tempfile
from types import SimpleNamespace

import httpx
import pytest

from tests.fixtures.realistic_intranet import create_app as create_intranet_app
from tests.fixtures.realistic_site import create_app as create_site_app
from wscan import benchmark_runner as br
from wscan.benchmark_model import (
    BenchmarkCase,
    BenchmarkSuite,
    CaseExecutionState,
    CaseResult,
    ExpectedOutcome,
    GateKind,
    InjectionSpec,
    MatchSpec,
    RequestSpec,
    SourceKind,
    ValueKind,
    build_scorecard,
    scorecard_to_markdown,
)
from wscan.recall_gate import (
    DetectionGateVerdict,
    NightlyFreshnessVerdict,
    evaluate_detection_gate,
    evaluate_nightly_freshness,
)
from wscan.reproduction import write_reproduction_package
from wscan.scanner_contract import Carrier
from wscan.scanners.base import Finding
from wscan import url_scope


def _build_core_twin_suite() -> BenchmarkSuite:
    """コア検査（XSS, SQLi, SSTI, Open Redirect, OS）の vulnerable と safe twin のペア。"""
    cases = [
        # XSS
        BenchmarkCase(
            case_id="core.xss.search.q.vulnerable",
            expected=ExpectedOutcome.VULNERABLE,
            check="xss",
            gate=GateKind.REQUIRED,
            request=RequestSpec("GET", "/search"),
            injection=InjectionSpec(Carrier.QUERY, "q", ValueKind.STRING),
            match=MatchSpec("/search", "q", "url_param"),
            twin_id="core.xss.help.query.safe",
        ),
        BenchmarkCase(
            case_id="core.xss.help.query.safe",
            expected=ExpectedOutcome.SAFE,
            check="xss",
            gate=GateKind.REQUIRED,
            request=RequestSpec("GET", "/help"),
            injection=InjectionSpec(Carrier.QUERY, "query", ValueKind.STRING),
            match=MatchSpec("/help", "query", "url_param"),
            twin_id="core.xss.search.q.vulnerable",
        ),
        # SQLi
        BenchmarkCase(
            case_id="core.sqli.products.category.vulnerable",
            expected=ExpectedOutcome.VULNERABLE,
            check="sqli",
            gate=GateKind.REQUIRED,
            request=RequestSpec("GET", "/products"),
            injection=InjectionSpec(Carrier.QUERY, "category", ValueKind.STRING),
            match=MatchSpec("/products", "category", "url_param"),
            twin_id="core.sqli.catalog.category.safe",
        ),
        BenchmarkCase(
            case_id="core.sqli.catalog.category.safe",
            expected=ExpectedOutcome.SAFE,
            check="sqli",
            gate=GateKind.REQUIRED,
            request=RequestSpec("GET", "/catalog"),
            injection=InjectionSpec(Carrier.QUERY, "category", ValueKind.STRING),
            match=MatchSpec("/catalog", "category", "url_param"),
            twin_id="core.sqli.products.category.vulnerable",
        ),
        # SSTI
        BenchmarkCase(
            case_id="core.ssti.greeting.name.vulnerable",
            expected=ExpectedOutcome.VULNERABLE,
            check="ssti",
            gate=GateKind.REQUIRED,
            request=RequestSpec("GET", "/greeting"),
            injection=InjectionSpec(Carrier.QUERY, "name", ValueKind.STRING),
            match=MatchSpec("/greeting", "name", "url_param"),
            twin_id="core.ssti.welcome.name.safe",
        ),
        BenchmarkCase(
            case_id="core.ssti.welcome.name.safe",
            expected=ExpectedOutcome.SAFE,
            check="ssti",
            gate=GateKind.REQUIRED,
            request=RequestSpec("GET", "/welcome"),
            injection=InjectionSpec(Carrier.QUERY, "name", ValueKind.STRING),
            match=MatchSpec("/welcome", "name", "url_param"),
            twin_id="core.ssti.greeting.name.vulnerable",
        ),
        # Open Redirect
        BenchmarkCase(
            case_id="core.open_redirect.redirect.url.vulnerable",
            expected=ExpectedOutcome.VULNERABLE,
            check="open_redirect",
            gate=GateKind.REQUIRED,
            request=RequestSpec("GET", "/redirect"),
            injection=InjectionSpec(Carrier.QUERY, "url", ValueKind.STRING),
            match=MatchSpec("/redirect", "url", "url_param"),
            twin_id="core.open_redirect.continue.next.safe",
        ),
        BenchmarkCase(
            case_id="core.open_redirect.continue.next.safe",
            expected=ExpectedOutcome.SAFE,
            check="open_redirect",
            gate=GateKind.REQUIRED,
            request=RequestSpec("GET", "/account/continue"),
            injection=InjectionSpec(Carrier.QUERY, "next", ValueKind.STRING),
            match=MatchSpec("/account/continue", "next", "url_param"),
            twin_id="core.open_redirect.redirect.url.vulnerable",
        ),
        # OS Injection
        BenchmarkCase(
            case_id="core.os.ping.host.vulnerable",
            expected=ExpectedOutcome.VULNERABLE,
            check="os",
            gate=GateKind.REQUIRED,
            request=RequestSpec("GET", "/tools/ping"),
            injection=InjectionSpec(Carrier.QUERY, "host", ValueKind.STRING),
            match=MatchSpec("/tools/ping", "host", "url_param"),
            twin_id="core.os.dns.host.safe",
        ),
        BenchmarkCase(
            case_id="core.os.dns.host.safe",
            expected=ExpectedOutcome.SAFE,
            check="os",
            gate=GateKind.REQUIRED,
            request=RequestSpec("GET", "/tools/dns"),
            injection=InjectionSpec(Carrier.QUERY, "host", ValueKind.STRING),
            match=MatchSpec("/tools/dns", "host", "url_param"),
            twin_id="core.os.ping.host.vulnerable",
        ),
    ]
    return BenchmarkSuite(
        schema_version=1,
        suite_id="pr_core_detection_twin_suite",
        fixture_id="composite_fast_fixtures",
        runner_profile="scan_engine",
        mode="normal-deterministic",
        source_kind=SourceKind.FIRST_PARTY,
        cases=tuple(cases),
    )


async def _execute_fixture_checks(base_url: str = "http://fixture.local") -> br.ScanOutcome:
    """高速 ASGI クライアント経由で実フィクスチャへ probe を投入し、実証結果を収集する。"""
    site_client = httpx.AsyncClient(
        transport=httpx.ASGITransport(app=create_site_app()),
        base_url=base_url,
    )
    intranet_client = httpx.AsyncClient(
        transport=httpx.ASGITransport(app=create_intranet_app()),
        base_url=base_url,
    )

    findings = []
    exercised = set()

    try:
        # 1. XSS (/search vs /help)
        exercised.add(("xss", "/search", "q", "url_param"))
        rx_v = await site_client.get("/search", params={"q": "<script>alert(1)</script>"})
        if "<script>alert(1)</script>" in rx_v.text:
            findings.append(
                SimpleNamespace(
                    check_type="xss",
                    url=f"{base_url}/search",
                    field_name="q",
                    injection_location="url_param",
                    verified=True,
                )
            )

        exercised.add(("xss", "/help", "query", "url_param"))
        rx_s = await site_client.get("/help", params={"query": "<script>alert(1)</script>"})
        if "<script>alert(1)</script>" in rx_s.text:
            findings.append(
                SimpleNamespace(
                    check_type="xss",
                    url=f"{base_url}/help",
                    field_name="query",
                    injection_location="url_param",
                    verified=True,
                )
            )

        # 2. SQLi (/products vs /catalog)
        exercised.add(("sqli", "/products", "category", "url_param"))
        rsq_v = await site_client.get(
            "/products",
            params={"category": "Electronics' UNION SELECT 'hacked', 'cat', 10--"},
        )
        if "hacked" in rsq_v.text:
            findings.append(
                SimpleNamespace(
                    check_type="sqli",
                    url=f"{base_url}/products",
                    field_name="category",
                    injection_location="url_param",
                    verified=True,
                )
            )

        exercised.add(("sqli", "/catalog", "category", "url_param"))
        rsq_s = await site_client.get(
            "/catalog",
            params={"category": "Electronics' UNION SELECT 'hacked', 'cat', 10--"},
        )
        if "hacked" in rsq_s.text:
            findings.append(
                SimpleNamespace(
                    check_type="sqli",
                    url=f"{base_url}/catalog",
                    field_name="category",
                    injection_location="url_param",
                    verified=True,
                )
            )

        # 3. SSTI (/greeting vs /welcome)
        exercised.add(("ssti", "/greeting", "name", "url_param"))
        rsst_v = await site_client.get("/greeting", params={"name": "{{2654435761*2654435761}}"})
        if "7046029209275649121" in rsst_v.text:
            findings.append(
                SimpleNamespace(
                    check_type="ssti",
                    url=f"{base_url}/greeting",
                    field_name="name",
                    injection_location="url_param",
                    verified=True,
                )
            )

        exercised.add(("ssti", "/welcome", "name", "url_param"))
        rsst_s = await site_client.get("/welcome", params={"name": "{{2654435761*2654435761}}"})
        if "7046029209275649121" in rsst_s.text:
            findings.append(
                SimpleNamespace(
                    check_type="ssti",
                    url=f"{base_url}/welcome",
                    field_name="name",
                    injection_location="url_param",
                    verified=True,
                )
            )

        # 4. Open Redirect (/redirect vs /account/continue)
        exercised.add(("open_redirect", "/redirect", "url", "url_param"))
        rred_v = await site_client.get("/redirect", params={"url": "https://evil.com"})
        if "evil.com" in rred_v.headers.get("location", ""):
            findings.append(
                SimpleNamespace(
                    check_type="open_redirect",
                    url=f"{base_url}/redirect",
                    field_name="url",
                    injection_location="url_param",
                    verified=True,
                )
            )

        exercised.add(("open_redirect", "/account/continue", "next", "url_param"))
        rred_s = await site_client.get("/account/continue", params={"next": "https://evil.com"})
        if "evil.com" in rred_s.headers.get("location", ""):
            findings.append(
                SimpleNamespace(
                    check_type="open_redirect",
                    url=f"{base_url}/account/continue",
                    field_name="next",
                    injection_location="url_param",
                    verified=True,
                )
            )

        # 5. OS Injection (/tools/ping vs /tools/dns)
        exercised.add(("os", "/tools/ping", "host", "url_param"))
        ros_v = await intranet_client.get(
            "/tools/ping", params={"host": "127.0.0.1; echo WSCAN_CMD_INJECT_CONFIRMED"}
        )
        if "WSCAN_CMD_INJECT_CONFIRMED" in ros_v.text:
            findings.append(
                SimpleNamespace(
                    check_type="os",
                    url=f"{base_url}/tools/ping",
                    field_name="host",
                    injection_location="url_param",
                    verified=True,
                )
            )

        exercised.add(("os", "/tools/dns", "host", "url_param"))
        ros_s = await intranet_client.get(
            "/tools/dns", params={"host": "127.0.0.1; echo WSCAN_CMD_INJECT_CONFIRMED"}
        )
        if "WSCAN_CMD_INJECT_CONFIRMED" in ros_s.text:
            findings.append(
                SimpleNamespace(
                    check_type="os",
                    url=f"{base_url}/tools/dns",
                    field_name="host",
                    injection_location="url_param",
                    verified=True,
                )
            )

    finally:
        await site_client.aclose()
        await intranet_client.aclose()

    return br.ScanOutcome(findings=findings, exercised=frozenset(exercised))


def test_pr_detection_gate_fast_twin_fixtures_pass():
    """実フィクスチャに対するコア5検査の検出でゲートが100% recall・0% FPRで合格することを確認。"""
    suite = _build_core_twin_suite()
    outcome = asyncio.run(_execute_fixture_checks())

    # 全 vulnerable(5) が検出され、全 safe(5) が非検出（TN）
    assert len(outcome.findings) == 5
    results = br.score_cases(
        suite,
        outcome,
        ran_checks={"xss", "sqli", "ssti", "open_redirect", "os"},
    )
    assert len(results) == 10
    assert all(r.state == CaseExecutionState.COMPLETED for r in results)

    scorecard = build_scorecard(
        suite,
        results,
        run_id="pr-fast-gate-run",
        source_sha="commit-sha",
        manifest_digest="man-digest",
        registry_digest="reg-digest",
    )
    assert scorecard["overall_status"] == "COMPLETE"
    assert scorecard["case_counts"] == {"planned": 10, "completed": 10, "incomplete": 0}
    assert scorecard["metrics"]["confirmed"]["tp"] == 5
    assert scorecard["metrics"]["confirmed"]["fn"] == 0
    assert scorecard["metrics"]["confirmed"]["fp"] == 0
    assert scorecard["metrics"]["confirmed"]["tn"] == 5
    assert scorecard["metrics"]["confirmed"]["recall"] == 1.0
    assert scorecard["metrics"]["confirmed"]["precision"] == 1.0

    verdict = evaluate_detection_gate(scorecard, tier="confirmed")
    assert verdict.passed is True
    assert verdict.reasons == ()
    assert verdict.recall == 1.0
    assert verdict.fpr == 0.0
    assert verdict.fn == 0
    assert verdict.fp == 0
    assert verdict.expected_total == 5
    assert verdict.attempted_cases == 10
    assert verdict.incomplete_cases == 0


def test_pr_detection_gate_rejects_simulated_false_negative():
    """偽陰性（FN: 脆弱性の取りこぼし）が1件でも発生するとゲートが RED (False) になること。"""
    suite = _build_core_twin_suite()
    outcome = asyncio.run(_execute_fixture_checks())

    # 1件（例: ssti）の finding を除外して偽陰性を模倣
    degraded_findings = [f for f in outcome.findings if f.check_type != "ssti"]
    degraded_outcome = br.ScanOutcome(findings=degraded_findings, exercised=outcome.exercised)

    results = br.score_cases(
        suite,
        degraded_outcome,
        ran_checks={"xss", "sqli", "ssti", "open_redirect", "os"},
    )
    scorecard = build_scorecard(
        suite,
        results,
        run_id="fn-run",
        source_sha="sha",
        manifest_digest="man",
        registry_digest="reg",
    )

    verdict = evaluate_detection_gate(scorecard, tier="confirmed")
    assert verdict.passed is False
    assert verdict.fn >= 1
    assert any("False negative regression" in r for r in verdict.reasons)


def test_pr_detection_gate_rejects_simulated_false_positive():
    """安全ツインでの誤検知（FP）が1件でも発生するとゲートが RED (False) になること。"""
    suite = _build_core_twin_suite()
    outcome = asyncio.run(_execute_fixture_checks())

    # 安全ツイン (/help query) に偽の finding を注入
    false_alarm = SimpleNamespace(
        check_type="xss",
        url="http://fixture.local/help",
        field_name="query",
        injection_location="url_param",
        verified=True,
    )
    polluted_outcome = br.ScanOutcome(
        findings=list(outcome.findings) + [false_alarm],
        exercised=outcome.exercised,
    )

    results = br.score_cases(
        suite,
        polluted_outcome,
        ran_checks={"xss", "sqli", "ssti", "open_redirect", "os"},
    )
    scorecard = build_scorecard(
        suite,
        results,
        run_id="fp-run",
        source_sha="sha",
        manifest_digest="man",
        registry_digest="reg",
    )

    verdict = evaluate_detection_gate(scorecard, tier="confirmed")
    assert verdict.passed is False
    assert verdict.fp >= 1
    assert any("False positive on safe twin" in r for r in verdict.reasons)


def test_pr_detection_gate_rejects_empty_denominator_and_zero_attempts():
    """試行0件や期待値0件の空虚合格（vacuous pass）を拒絶すること。"""
    empty_scorecard = {
        "overall_status": "COMPLETE",
        "case_counts": {"planned": 0, "completed": 0, "incomplete": 0},
        "metrics": {"confirmed": {"tp": 0, "fn": 0, "fp": 0, "tn": 0, "recall_denominator": 0}},
        "cases": [],
    }
    verdict = evaluate_detection_gate(empty_scorecard)
    assert verdict.passed is False
    assert any("expected_total == 0" in r for r in verdict.reasons)
    assert any("attempted_cases == 0" in r for r in verdict.reasons)


def test_pr_detection_gate_rejects_dropouts_timeouts_and_incomplete():
    """タイムアウト・未到達・未対応等の計測脱落（incomplete_cases > 0）を拒絶すること。"""
    suite = _build_core_twin_suite()
    outcome = asyncio.run(_execute_fixture_checks())
    results = br.score_cases(
        suite,
        outcome,
        ran_checks={"xss", "sqli", "ssti", "open_redirect", "os"},
    )

    # 1ケースを TIMEOUT に差し替え
    mutated_results = [
        CaseResult(r.case_id, CaseExecutionState.TIMEOUT) if i == 0 else r
        for i, r in enumerate(results)
    ]
    scorecard = build_scorecard(
        suite,
        mutated_results,
        run_id="timeout-run",
        source_sha="sha",
        manifest_digest="man",
        registry_digest="reg",
    )

    verdict = evaluate_detection_gate(scorecard, tier="confirmed")
    assert verdict.passed is False
    assert verdict.incomplete_cases >= 1
    assert any("Incomplete measurement" in r for r in verdict.reasons)


def test_pr_detection_gate_rejects_baseline_case_regression():
    """baseline 比で良(TP/TN)から悪(FN/FP)への悪化、または既存ケースの消失を検出すること。"""
    suite = _build_core_twin_suite()
    outcome = asyncio.run(_execute_fixture_checks())
    results = br.score_cases(
        suite,
        outcome,
        ran_checks={"xss", "sqli", "ssti", "open_redirect", "os"},
    )
    baseline_scorecard = build_scorecard(
        suite,
        results,
        run_id="base-run",
        source_sha="base-sha",
        manifest_digest="base-man",
        registry_digest="base-reg",
    )

    # current で 1 件回帰
    regressed_results = [
        CaseResult(r.case_id, CaseExecutionState.COMPLETED, candidate_match=False, confirmed_match=False)
        if r.case_id == "core.xss.search.q.vulnerable" else r
        for r in results
    ]
    current_scorecard = build_scorecard(
        suite,
        regressed_results,
        run_id="cur-run",
        source_sha="cur-sha",
        manifest_digest="base-man",
        registry_digest="base-reg",
    )

    verdict = evaluate_detection_gate(current_scorecard, baseline=baseline_scorecard, tier="confirmed")
    assert verdict.passed is False
    assert "core.xss.search.q.vulnerable" in verdict.regressed_cases
    assert any("Baseline case regression" in r for r in verdict.reasons)


def test_pr_detection_gate_nightly_freshness_acceptance():
    """Nightly 有効期限・結果判定ゲート（正常時合格、期限切れ・失敗・別ブランチ時拒絶）の検証。"""
    now_ts = 1763260000.0

    # 正常（有効期限内、main ブランチ、全件成功）
    valid_record = {
        "conclusion": "success",
        "recall_complete": True,
        "attempted_total": 50,
        "branch": "main",
        "completed_at": now_ts - (12 * 3600),  # 12時間前
    }
    v_ok = evaluate_nightly_freshness(valid_record, now_ts=now_ts)
    assert v_ok.ready is True
    assert v_ok.age_seconds == 12 * 3600
    assert v_ok.reasons == ()

    # 期限切れ（38時間前 > 36時間上限）
    stale_record = dict(valid_record, completed_at=now_ts - (38 * 3600))
    v_stale = evaluate_nightly_freshness(stale_record, now_ts=now_ts)
    assert v_stale.ready is False
    assert any("stale" in r for r in v_stale.reasons)

    # 失敗 conclusion
    failed_record = dict(valid_record, conclusion="failure")
    v_failed = evaluate_nightly_freshness(failed_record, now_ts=now_ts)
    assert v_failed.ready is False
    assert any("conclusion is 'failure'" in r for r in v_failed.reasons)

    # 異なるブランチ
    wrong_branch = dict(valid_record, branch="experimental/feature")
    v_branch = evaluate_nightly_freshness(wrong_branch, now_ts=now_ts, expected_branch="main")
    assert v_branch.ready is False
    assert any("branch is 'experimental/feature'" in r for r in v_branch.reasons)


def test_scorecard_and_reproduction_clean_serialization_without_secret_leak(tmp_path):
    """scorecard JSON・Markdown サマリ・再現コマンドの直列化で認証秘密値が漏洩しないこと。"""
    secret_token = "vulix_auth_secret_token_9876543210"
    secret_key = "apikey_super_private_value_abcdef"

    url_scope.register_secret_values([("test_token", secret_token), ("test_key", secret_key)])

    finding = Finding(
        check_type="xss",
        url=f"http://example.local/api/search?q=%3Cscript%3E&token={secret_token}",
        field_name="q",
        payload="<script>alert(1)</script>",
        evidence="<script>alert(1)</script>",
        severity="high",
        request={
            "method": "GET",
            "url": f"http://example.local/api/search?q=%3Cscript%3E&token={secret_token}",
            "headers": {
                "authorization": f"Bearer {secret_token}",
                "x-api-key": secret_key,
                "user-agent": "WScan/1.0",
            },
        },
    )

    # 1. 再現パッケージ（reproduction.json / reproduce.sh）
    repro_res = write_reproduction_package([finding], tmp_path)
    json_text = Path(repro_res["json"]).read_text(encoding="utf-8")
    sh_text = Path(repro_res["shell"]).read_text(encoding="utf-8")

    assert secret_token not in json_text
    assert secret_key not in json_text
    assert secret_token not in sh_text
    assert secret_key not in sh_text

    # 2. Scorecard および Markdown サマリ
    scorecard = {
        "run_id": "run-test-secrets",
        "overall_status": "COMPLETE",
        "case_counts": {"planned": 1, "completed": 1, "incomplete": 0},
        "metrics": {"candidate": {"tp": 1, "fn": 0, "fp": 0, "tn": 0, "recall": 1.0, "precision": 1.0, "recall_denominator": 1, "precision_denominator": 1},
                    "confirmed": {"tp": 1, "fn": 0, "fp": 0, "tn": 0, "recall": 1.0, "precision": 1.0, "recall_denominator": 1, "precision_denominator": 1}},
        "breakdowns": {"check": {}, "carrier": {}, "taxonomy": {}, "mode": {}},
        "cases": [
            {
                "case_id": "safe-case-id",
                "expected": "vulnerable",
                "state": "completed",
                "classification": {"candidate": "tp", "confirmed": "tp"},
            }
        ],
        "environment": {"target": "http://example.local/api/search"},
    }
    card_json = json.dumps(scorecard)
    card_md = scorecard_to_markdown(scorecard)

    assert secret_token not in card_json
    assert secret_token not in card_md
    assert secret_key not in card_json
    assert secret_key not in card_md

    # 3. 検出ゲート判定のサマリ出力
    verdict = evaluate_detection_gate(scorecard)
    assert verdict.passed is True
    desc = verdict.describe()
    assert secret_token not in desc
    assert secret_key not in desc
