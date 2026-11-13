"""通常スキャンの並列認証をサーバー側の記録で検証する。"""
import asyncio
import os

import httpx
import pytest

from tests.fixtures import login_matrix_app as fx
from tests.test_login_matrix_e2e import serving
from wscan.engine import ScanEngine

pytestmark = pytest.mark.skipif(os.environ.get("WSCAN_E2E") != "1", reason="WSCAN_E2E=1")


async def scan(base, bearer, concurrency, output):
    variant = 4 if bearer else 1
    engine = ScanEngine(
        f"{base}/v{variant}/protected", login_url=f"{base}/v{variant}/login",
        auth_user=fx.USERNAME, auth_pass=fx.PASSWORD, concurrency=concurrency,
        checks=["xss"], llm_provider="none", headless=True, output_dir=str(output),
        open_report=False, enable_waf_detection=False, enable_ai_analysis=False,
        enable_payload_learning=False, enable_adaptive_payloads=False,
        enable_sitemap_crawl=False, depth=2, fast_mode=True, max_payloads=1,
        request_delay=0, use_planner=False, sarif=False, timeout=8, navigation_retries=0,
    )
    await asyncio.wait_for(engine.run(), timeout=90)
    async with httpx.AsyncClient() as client:
        stats = (await client.get(f"{base}/test/stats")).json()
    return engine, stats


def findings(engine):
    return {(f.url.split("/protected", 1)[-1].split("?", 1)[0], f.field_name)
            for f in engine.all_findings if f.check_type == "xss"}


@pytest.mark.parametrize("bearer", [False, pytest.param(True, marks=pytest.mark.xfail(
    strict=True, reason="SPA login verifies API access but Bearer is absent on protected crawl navigation"))], ids=["cookie", "bearer"])
@pytest.mark.parametrize("concurrency", [1, pytest.param(3, marks=pytest.mark.xfail(
    strict=True, reason="Parallel cookie scan loses reflected XSS findings present in serial scan"))])
def test_serial_parallel_authentication(bearer, concurrency, tmp_path, monkeypatch):
    monkeypatch.setenv("WSCAN_STATE_DIR", str(tmp_path / "state"))
    with serving(fx.create_parallel_app(bearer)) as base:
        engine, stats = asyncio.run(scan(base, bearer, concurrency, tmp_path / str(concurrency)))
    assert engine.authentication_state["protected_access"] == "verified"
    assert all(r["valid"] for r in stats["records"] if r["logged_in"])
    assert not any("auth_lost" in str(e) or "authentication_unverified" in str(e)
                   for e in engine.wave_errors)
    attacks = {r["path"] for r in stats["records"] if r["attack"]}
    assert len(attacks) >= 4
    found = findings(engine)
    assert found == {(suffix, "q") for suffix in ("", "/1", "/2", "/3")}


@pytest.mark.parametrize("bearer", [False, pytest.param(True, marks=pytest.mark.xfail(
    strict=True, reason="SPA login verifies API access but Bearer is absent on protected crawl navigation"))], ids=["cookie", "bearer"])
@pytest.mark.xfail(strict=True, reason="Cloned login sessions expire across workers; complete isolated recovery is not guaranteed")
def test_parallel_session_expiry(bearer, tmp_path, monkeypatch):
    monkeypatch.setenv("WSCAN_STATE_DIR", str(tmp_path / "state"))
    with serving(fx.create_parallel_app(bearer, expire=True)) as base:
        engine, stats = asyncio.run(scan(base, bearer, 3, tmp_path / "expiry"))
    assert len(stats["expired"]) == 1
    assert stats["logins"] > 1
    # 失効を検出した要求以外では、同じ失効セッションの攻撃を継続しない。
    denied = [r for r in stats["records"] if r["attack"] and not r["valid"]]
    assert len(denied) == 1
    assert findings(engine) == {(suffix, "q") for suffix in ("", "/1", "/2", "/3")}
