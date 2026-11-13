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
        enable_payload_evolution=False, enable_payload_mutation=False,
        enable_sitemap_crawl=False, depth=2, fast_mode=not bearer, max_payloads=1,
        request_delay=0, use_planner=False, sarif=False, timeout=8, navigation_retries=0,
    )
    workers = []
    create_worker = engine._browser.create_worker

    async def tracked_worker():
        worker = await create_worker()
        assert worker._context is not engine._browser._context
        assert all(worker._context is not other._context for other in workers)
        workers.append(worker)
        return worker

    engine._browser.create_worker = tracked_worker
    await asyncio.wait_for(engine.run(), timeout=90)
    assert len(workers) == concurrency - 1
    assert all(sum(worker.network.status_counts.values()) > 0 for worker in workers)
    async with httpx.AsyncClient() as client:
        stats = (await client.get(f"{base}/test/stats")).json()
    return engine, stats


def findings(engine):
    return {(f.url.split("/protected", 1)[-1].split("?", 1)[0], f.field_name)
            for f in engine.all_findings if f.check_type == "xss"}


@pytest.mark.parametrize("bearer", [False, True], ids=["cookie", "bearer"])
@pytest.mark.parametrize("concurrency", [1, 3])
def test_serial_parallel_authentication(bearer, concurrency, tmp_path, monkeypatch):
    monkeypatch.setenv("WSCAN_STATE_DIR", str(tmp_path / "state"))
    with serving(fx.create_parallel_app(bearer)) as base:
        engine, stats = asyncio.run(scan(base, bearer, concurrency, tmp_path / str(concurrency)))
    assert engine.authentication_state["protected_access"] == "verified"
    assert all(r["valid"] for r in stats["records"] if r["attack"] or r["session"])
    assert not any("auth_lost" in str(e) or "authentication_unverified" in str(e)
                   for e in engine.wave_errors)
    attacks = {r["path"] for r in stats["records"] if r["attack"]}
    assert len(attacks) >= 4
    found = findings(engine)
    assert found == {(suffix, "q") for suffix in ("", "/1", "/2", "/3")}


@pytest.mark.parametrize("bearer", [False, True], ids=["cookie", "bearer"])
def test_parallel_session_expiry(bearer, tmp_path, monkeypatch):
    monkeypatch.setenv("WSCAN_STATE_DIR", str(tmp_path / "state"))
    with serving(fx.create_parallel_app(bearer, expire=True)) as base:
        engine, stats = asyncio.run(scan(base, bearer, 3, tmp_path / "expiry"))
    assert len(stats["expired"]) == 1
    found = findings(engine)
    assert all(field == "q" for _, field in found)
    for suffix in ("", "/1", "/2", "/3"):
        if (suffix, "q") in found:
            continue
        url = f"{base}/v{4 if bearer else 1}/protected{suffix}"
        rows = [r for r in engine.scan_matrix if r["url"] == url
                and r["field_name"] == "q" and r["check"] == "xss"]
        assert rows and all(r["status"] == "error" and "incomplete" in r["note"] for r in rows)
        from wscan.injection_point import InjectionPoint
        assert not engine.checkpoint.is_done_ip(InjectionPoint.for_form(url, "q", 0), "xss")
    assert found or any(r["status"] == "error" for r in engine.scan_matrix)
