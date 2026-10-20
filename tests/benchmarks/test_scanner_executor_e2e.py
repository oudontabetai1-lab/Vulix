"""実 XSSScanner の採点回帰。WSCAN_E2E opt-in で suite を一度だけ走らせる。"""
import os
from pathlib import Path

import pytest

from wscan.benchmark_fixtures import UvicornFixtureLauncher
from wscan.benchmark_model import load_manifest_file
from wscan.benchmark_runner import run_scanned_suite
from wscan.benchmark_scan import ScanEngineScanRunner

pytestmark = pytest.mark.skipif(
    os.environ.get("WSCAN_E2E", "").strip().lower() not in {"1", "true", "yes", "on"},
    reason="WSCAN_E2E opt-in required",
)


def _require_chromium():
    from playwright.sync_api import sync_playwright

    with sync_playwright() as pw:
        if not Path(pw.chromium.executable_path).is_file():
            pytest.skip("Chromium is not installed (playwright install chromium)")
        # バイナリが存在しても起動できない場合は失敗として報告する。
        browser = pw.chromium.launch(headless=True)
        browser.close()


def _run_manifest(name: str, checks: set[str]):
    path = Path(__file__).resolve().parents[2] / "benchmarks/manifests" / name
    suite = load_manifest_file(path, registry_keys=checks)
    return run_scanned_suite(
        suite, launcher=UvicornFixtureLauncher(), scan_runner=ScanEngineScanRunner(),
        run_id="scanner-e2e", source_sha="test", manifest_digest="test",
        registry_digest="test", scan_timeout=900,
    )


def test_realistic_site_xss_scanner_scorecard():
    _require_chromium()
    out = _run_manifest("realistic_site_xss.yaml", {"xss"})
    assert "run_error" not in out, out
    assert out["case_counts"] == {"planned": 2, "completed": 2, "incomplete": 0}
    assert [c["classification"]["candidate"] for c in out["cases"]] == ["tp", "tn"], out


def test_realistic_site_sqli_scanner_scorecard():
    """実 SQLiScanner が /products=TP・/catalog=TN を採点する。"""
    _require_chromium()
    out = _run_manifest("realistic_site_sqli.yaml", {"sqli"})
    assert "run_error" not in out, out
    assert out["case_counts"] == {"planned": 2, "completed": 2, "incomplete": 0}
    assert [c["classification"]["candidate"] for c in out["cases"]] == ["tp", "tn"], out


def test_realistic_intranet_injection_scanner_scorecard():
    """realistic_intranet の HTTP 注入系 4 scanner（os/ssrf/nosql/dom_xss）を実採点する。

    各 check の vulnerable=TP・safe twin=TN を確認し、recall/precision 100% を固定する。
    manifest 順（os→ssrf→nosql→dom_xss、各 vulnerable→safe）に tp/tn が並ぶ。
    """
    _require_chromium()
    out = _run_manifest(
        "realistic_intranet_injection.yaml", {"os", "ssrf", "nosql", "dom_xss"}
    )
    assert "run_error" not in out, out
    assert out["case_counts"] == {"planned": 8, "completed": 8, "incomplete": 0}
    assert [c["classification"]["candidate"] for c in out["cases"]] == [
        "tp", "tn", "tp", "tn", "tp", "tn", "tp", "tn",
    ], out


def test_realistic_site_injection_scanner_scorecard():
    """ssti/path_traversal/open_redirect を実 scanner で採点（各 vuln=TP・safe twin=TN）。"""
    _require_chromium()
    out = _run_manifest(
        "realistic_site_injection.yaml", {"ssti", "path_traversal", "open_redirect"}
    )
    assert "run_error" not in out, out
    assert out["case_counts"] == {"planned": 6, "completed": 6, "incomplete": 0}
    # manifest 順: 各 check の vulnerable→safe twin。
    assert [c["classification"]["candidate"] for c in out["cases"]] == [
        "tp", "tn", "tp", "tn", "tp", "tn",
    ], out


def test_realistic_site_header_injection_scanner_scorecard():
    """header_injection（CRLF レスポンスヘッダ注入）を実 scanner で採点。

    /locale?lang=（脆弱）=TP・/locale-safe?lang=（allow-list 検証の安全ツイン）=TN。
    """
    _require_chromium()
    out = _run_manifest("realistic_site_header_injection.yaml", {"header_injection"})
    assert "run_error" not in out, out
    assert out["case_counts"] == {"planned": 2, "completed": 2, "incomplete": 0}
    assert [c["classification"]["candidate"] for c in out["cases"]] == ["tp", "tn"], out


def test_realistic_healthcare_ldap_scanner_scorecard():
    """realistic_healthcare の LDAP 注入を実 scanner で採点する。

    /directory/lookup?user=（uid フィルタへ生展開）=TP・/directory/search?name=
    （RFC4515 エスケープの安全ツイン）=TN。
    """
    _require_chromium()
    out = _run_manifest("realistic_healthcare_ldap.yaml", {"ldap"})
    assert "run_error" not in out, out
    assert out["case_counts"] == {"planned": 2, "completed": 2, "incomplete": 0}
    assert [c["classification"]["candidate"] for c in out["cases"]] == ["tp", "tn"], out


def test_realistic_healthcare_security_headers_scanner_scorecard():
    """realistic_healthcare の security_headers（page 観測系＝passive）を実採点する。

    /legacy/status（セキュリティヘッダ欠落）=TP・/legacy/status-secure（全付与の安全ツイン）=TN。
    注入点を持たない passive check を (check, path) で採点する scorer 拡張の回帰でもある。
    """
    _require_chromium()
    out = _run_manifest("realistic_healthcare_security_headers.yaml", {"security_headers"})
    assert "run_error" not in out, out
    assert out["case_counts"] == {"planned": 2, "completed": 2, "incomplete": 0}
    assert [c["classification"]["candidate"] for c in out["cases"]] == ["tp", "tn"], out


def test_realistic_healthcare_page_observation_scanner_scorecard():
    """realistic_healthcare の clickjacking / js_static（page 観測系＝passive）を実採点する。

    clickjacking /portal/embed=TP・/portal/embed-safe（XFO DENY + frame-ancestors 'none'）=TN、
    js_static /portal/notice（location.search→innerHTML）=TP・/portal/notice-safe=TN。
    clickjacking の安全ツイン TN は、ヘッダ取得を current_page_pair から直接 GET(_response_pair)へ
    変えて FP を解消した回帰ガードでもある。manifest 順（clickjacking→js_static、各 vuln→safe）。
    """
    _require_chromium()
    out = _run_manifest(
        "realistic_healthcare_page_observation.yaml",
        {"clickjacking", "js_static", "sri", "secret_leak"},
    )
    assert "run_error" not in out, out
    assert out["case_counts"] == {"planned": 10, "completed": 10, "incomplete": 0}
    # manifest 順: sri, secret_leak(vendor), secret_leak(script-only), clickjacking, js_static (vuln→safe)。
    assert [c["classification"]["candidate"] for c in out["cases"]] == [
        "tp", "tn", "tp", "tn", "tp", "tn", "tp", "tn", "tp", "tn",
    ], out


def test_realistic_healthcare_page_batch2_scanner_scorecard():
    """realistic_healthcare の cors / host_header（page 観測系＝passive）を実採点する。

    cors /api/v1/records/export=TP・export-safe=TN、host_header /account/reset=TP・reset-safe=TN。
    manifest 順（cors vuln→safe, host_header vuln→safe）に並ぶ。
    """
    _require_chromium()
    out = _run_manifest("realistic_healthcare_page_batch2.yaml", {"cors", "host_header"})
    assert "run_error" not in out, out
    assert out["case_counts"] == {"planned": 4, "completed": 4, "incomplete": 0}
    assert [c["classification"]["candidate"] for c in out["cases"]] == ["tp", "tn", "tp", "tn"], out


def test_realistic_intranet_file_upload_scanner_scorecard():
    """multipart file_upload を脆弱=TP・allow-list 安全ツイン=TN で実採点する。"""
    _require_chromium()
    out = _run_manifest("realistic_intranet_file_upload.yaml", {"file_upload"})
    assert "run_error" not in out, out
    assert out["case_counts"] == {"planned": 2, "completed": 2, "incomplete": 0}
    assert [c["classification"]["candidate"] for c in out["cases"]] == ["tp", "tn"], out


def test_realistic_api_page_observation_scanner_scorecard():
    """realistic_api の jwt（page 観測系＝passive）を実採点する。

    /api/v1/session/bootstrap（弱秘密鍵 HS256）=TP・/bootstrap-safe（十分長い鍵）=TN。
    csrf / info_disclosure は DOM 依存で navigation 前に scan_page が走るため gap 維持（manifest 参照）。
    """
    _require_chromium()
    out = _run_manifest("realistic_api_page_observation.yaml", {"jwt"})
    assert "run_error" not in out, out
    assert out["case_counts"] == {"planned": 2, "completed": 2, "incomplete": 0}
    assert [c["classification"]["candidate"] for c in out["cases"]] == ["tp", "tn"], out


def test_realistic_healthcare_stored_xss_scanner_scorecard():
    """格納型 XSS を脆弱=TP・エスケープ安全ツイン=TN で実採点する。

    xxe は XML carrier が採点不能のため gap（E2E 対象外）。

    脆弱ケースの TP は、単独の格納型 XSS スキャナが、注入フォームのページとは別 URL のクロール済み
    クエリパラメータ変種（posts ページ）で注入 marker を観測して得る（ページ跨ぎの second-order 要件を
    満たす）。chain スキャナ由来ではない（stored_xss のみ有効時は同一ページ probe は実行されない）。
    エスケープ済み安全ツインは実 DOM 要素が生成されず finding にならない。
    """
    _require_chromium()
    out = _run_manifest("realistic_healthcare_stored_xss.yaml", {"stored_xss"})
    assert "run_error" not in out, out
    assert out["case_counts"] == {"planned": 2, "completed": 2, "incomplete": 0}
    assert [c["classification"]["candidate"] for c in out["cases"]] == ["tp", "tn"], out


def test_directory_artifacts_root_listing_scanner_scorecard():
    """Root listing is confirmed while its reachable safe twin is rejected on re-verification."""
    _require_chromium()
    out = _run_manifest("directory_artifacts.yaml", {"directory_artifacts"})
    assert "run_error" not in out, out
    assert out["case_counts"] == {"planned": 2, "completed": 2, "incomplete": 0}
    assert [c["classification"]["candidate"] for c in out["cases"]] == ["tp", "fp"], out
    assert [c["classification"]["confirmed"] for c in out["cases"]] == ["tp", "tn"], out
    assert out["metrics"]["candidate"] == {
        "tp": 1, "fn": 0, "fp": 1, "tn": 0,
        "recall": 1.0, "precision": 0.5,
        "recall_denominator": 1, "precision_denominator": 2,
    }, out
    assert out["metrics"]["confirmed"] == {
        "tp": 1, "fn": 0, "fp": 0, "tn": 1,
        "recall": 1.0, "precision": 1.0,
        "recall_denominator": 1, "precision_denominator": 1,
    }, out
