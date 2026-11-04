"""Agent login secret の prompt 非混入と domain scope 契約。"""
import json

from wscan.llm_agent_browser import AgentBrowserScanner, build_agent_sensitive_data
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch

import pytest


def test_auth_secrets_are_placeholders_in_task():
    scanner = AgentBrowserScanner(
        "https://app.example.test",
        auth_user="real-user",
        auth_pass="real-password",
        login_url="https://login.example.test/sign-in",
        totp_secret="JBSWY3DPEHPK3PXP",
    )
    task = scanner._build_task()
    assert "real-user" not in task
    assert "real-password" not in task
    assert "JBSWY3DPEHPK3PXP" not in task
    assert "WSCAN_AUTH_USER" in task
    assert "WSCAN_bu_2fa_code" in task


def test_sensitive_data_is_domain_scoped_and_totp_named_for_browser_use():
    data = build_agent_sensitive_data(
        "https://login.example.test/sign-in", "user", "pass", "totp-secret"
    )
    assert data == {
        "login.example.test": {
            "WSCAN_AUTH_USER": "user",
            "WSCAN_AUTH_PASS": "pass",
            "WSCAN_bu_2fa_code": "totp-secret",
        }
    }


def test_storage_state_auth_task_does_not_request_missing_placeholders():
    scanner = AgentBrowserScanner(
        "https://app.example.test",
        login_url="https://app.example.test/login",
        storage_state="state.json",
    )
    from wscan.agent_harness import AgentRole, AgentWorkItem

    work = AgentWorkItem("auth", AgentRole.AUTHENTICATOR, scanner.login_url)
    task = scanner._build_work_task(work, [])
    assert "WSCAN_AUTH_USER" not in task
    assert "AUTH COMPLETE" in task


def test_resume_auth_fingerprint_covers_credentials_headers_and_storage(tmp_path):
    # 非秘密（login_url/storage/header 名）は spec 用 context hash、秘密（user/pass/TOTP/header 値）は
    # 永続化しない material を harness が per-run salt 付き scrypt で照合する。
    from wscan.agent_harness import AgentHarness, AgentRunSpec

    storage = tmp_path / "storage.json"
    storage.write_text('{"cookies":[]}', encoding="utf-8")
    base = dict(
        target_url="https://app.example.test",
        login_url="https://app.example.test/login",
        auth_user="account-a",
        auth_pass="password-a",
        totp_secret="totp-a",
        extra_headers={"Authorization": "Bearer a"},
        storage_state=str(storage),
    )
    original = AgentBrowserScanner(**base)._auth_context_hash()
    assert len(original) == 64
    assert AgentBrowserScanner(
        **(base | {"login_url": "https://app.example.test/other-login"})
    )._auth_context_hash() != original

    def run_spec(ctx):
        return AgentRunSpec("agent", "https://app.example.test", (), (), (), (), ("xss",),
                            "none", "m", 5, auth_context_hash=ctx)

    material = AgentBrowserScanner(**base)._auth_secret_material()
    out = tmp_path / "run"
    AgentHarness(out, run_spec(original), auth_secret_material=material)
    persisted = (out / "agent_state.json").read_text()
    for secret in ("account-a", "password-a", "totp-a", "Bearer a"):
        assert secret not in persisted
    # 同一認証なら resume 可。
    AgentHarness(out, run_spec(original), resume=True, auth_secret_material=material)
    for change in (
        {"auth_user": "account-b"},
        {"auth_pass": "password-b"},
        {"totp_secret": "totp-b"},
        {"extra_headers": {"Authorization": "Bearer b"}},
    ):
        scanner = AgentBrowserScanner(**(base | change))
        with pytest.raises(ValueError, match="auth mismatch|spec mismatch"):
            AgentHarness(out, run_spec(scanner._auth_context_hash()), resume=True,
                         auth_secret_material=scanner._auth_secret_material())
    storage.write_text('{"cookies":[{"name":"session","value":"b"}]}', encoding="utf-8")
    assert AgentBrowserScanner(**base)._auth_context_hash() != original


def test_auth_context_hash_uses_resolved_openai_compatible_endpoint(monkeypatch):
    # env で解決される実効エンドポイントの変更も resume 同一性に反映する。
    monkeypatch.setenv("WSCAN_LLM_BASE_URL", "http://llm-a.test/v1")
    a = AgentBrowserScanner("https://app.example.test", llm_provider="openai_compatible")._auth_context_hash()
    monkeypatch.setenv("WSCAN_LLM_BASE_URL", "http://llm-b.test/v1")
    b = AgentBrowserScanner("https://app.example.test", llm_provider="openai_compatible")._auth_context_hash()
    assert a != b


def test_auth_context_hash_includes_normalized_proxy_without_credentials():
    # プロキシ設定の有無・エンドポイント変更を resume 同一性に反映し、パスワードなどの資格情報は含めない。
    hash_no_proxy = AgentBrowserScanner("https://app.example.test")._auth_context_hash()
    hash_proxy = AgentBrowserScanner(
        "https://app.example.test", proxy="http://127.0.0.1:8080"
    )._auth_context_hash()
    hash_auth_proxy = AgentBrowserScanner(
        "https://app.example.test", proxy="http://user:secret-pass@127.0.0.1:8080"
    )._auth_context_hash()
    hash_other_creds = AgentBrowserScanner(
        "https://app.example.test", proxy="http://admin:different-pass@127.0.0.1:8080"
    )._auth_context_hash()
    hash_diff_port = AgentBrowserScanner(
        "https://app.example.test", proxy="http://127.0.0.1:9090"
    )._auth_context_hash()

    # プロキシ有無で hash が異なる
    assert hash_no_proxy != hash_proxy
    # 異なるプロキシエンドポイントで hash が異なる
    assert hash_proxy != hash_diff_port
    # 資格情報のみが異なる同一エンドポイントは同一の hash（資格情報は hash に含めない）
    assert hash_proxy == hash_auth_proxy == hash_other_creds
    # パスワードが hash 文字列に漏洩しない
    assert "secret-pass" not in hash_auth_proxy
    assert "user" not in hash_auth_proxy


def test_agent_resume_safe_twins_proxy_identity(tmp_path):
    # safe twins: no-proxy resume, same-proxy resume, changed-proxy resume
    from wscan.agent_harness import AgentHarness, AgentRunSpec

    def make_scanner(proxy=""):
        return AgentBrowserScanner("https://app.example.test", proxy=proxy)

    def make_spec(scanner):
        return AgentRunSpec(
            "agent",
            "https://app.example.test",
            (),
            (),
            (),
            (),
            ("xss",),
            "none",
            "m",
            5,
            auth_context_hash=scanner._auth_context_hash(),
            proxy=scanner.proxy,
        )

    scanner_none = make_scanner("")
    spec_none = make_spec(scanner_none)

    scanner_proxy_a = make_scanner("http://user:secret@127.0.0.1:8080")
    spec_proxy_a = make_spec(scanner_proxy_a)

    scanner_proxy_b = make_scanner("http://127.0.0.1:9090")
    spec_proxy_b = make_spec(scanner_proxy_b)

    # AgentRunSpec の proxy は資格情報が除外され正規化される
    assert spec_proxy_a.proxy == "http://127.0.0.1:8080"
    assert "secret" not in spec_proxy_a.proxy
    assert "user" not in spec_proxy_a.proxy

    # Safe Twin 1: no-proxy 初回実行 -> no-proxy での再開は成功
    out_none = tmp_path / "run_no_proxy"
    AgentHarness(out_none, spec_none, auth_secret_material=scanner_none._auth_secret_material())
    AgentHarness(out_none, spec_none, resume=True, auth_secret_material=scanner_none._auth_secret_material())

    # Safe Twin 2: proxy 設定での初回実行 -> 同一 proxy（資格情報変更含む）での再開は成功
    out_proxy = tmp_path / "run_proxy"
    harness_proxy = AgentHarness(
        out_proxy, spec_proxy_a, auth_secret_material=scanner_proxy_a._auth_secret_material()
    )
    harness_proxy._write_manifest(coverage_complete=False)

    # 永続化された state/manifest にプロキシパスワードが漏洩しない
    persisted_state = (out_proxy / "agent_state.json").read_text(encoding="utf-8")
    assert "secret" not in persisted_state
    assert (out_proxy / "agent_manifest.json").exists()
    persisted_manifest = (out_proxy / "agent_manifest.json").read_text(encoding="utf-8")
    assert "secret" not in persisted_manifest

    # 同一エンドポイント（資格情報なし表記含む）での再開
    scanner_proxy_same_ep = make_scanner("http://127.0.0.1:8080")
    spec_proxy_same = make_spec(scanner_proxy_same_ep)
    AgentHarness(
        out_proxy,
        spec_proxy_same,
        resume=True,
        auth_secret_material=scanner_proxy_same_ep._auth_secret_material(),
    )

    # Safe Twin 3: proxy 変更または proxy 欠落での再開は拒否（spec mismatch）
    # (a) proxy 有り run を proxy 無しで再開
    with pytest.raises(ValueError, match="spec mismatch"):
        AgentHarness(
            out_proxy,
            spec_none,
            resume=True,
            auth_secret_material=scanner_none._auth_secret_material(),
        )

    # (b) proxy 有り run を別エンドポイント proxy で再開
    with pytest.raises(ValueError, match="spec mismatch"):
        AgentHarness(
            out_proxy,
            spec_proxy_b,
            resume=True,
            auth_secret_material=scanner_proxy_b._auth_secret_material(),
        )

    # (c) proxy 無し run を proxy 有りで再開
    with pytest.raises(ValueError, match="spec mismatch"):
        AgentHarness(
            out_none,
            spec_proxy_a,
            resume=True,
            auth_secret_material=scanner_proxy_a._auth_secret_material(),
        )


@pytest.mark.asyncio
async def test_engine_redacts_reflected_login_secrets_from_artifacts(tmp_path):
    from wscan.agent_engine import AgentEngine

    result = SimpleNamespace(
        findings=[], steps_taken=1, success=False, error="",
        final_summary="target echoed user-secret and password-secret",
        harness_status="partial", coverage_gaps=["auth incomplete"],
    )
    with patch("wscan.llm_agent_browser.AgentBrowserScanner") as scanner:
        scanner.return_value.run = AsyncMock(return_value=result)
        engine = AgentEngine(
            "https://app.example.test", auth_user="user-secret",
            auth_pass="password-secret", output_dir=str(tmp_path), open_report=False,
        )
        await engine.run()

    artifacts = (tmp_path / "evidence.json").read_text() + (tmp_path / "agent_summary.md").read_text()
    assert "user-secret" not in artifacts
    assert "password-secret" not in artifacts
    assert "<redacted>" in artifacts


@pytest.mark.asyncio
async def test_engine_redacts_values_without_corrupting_evidence_json(tmp_path):
    from wscan.agent_engine import AgentEngine

    result = SimpleNamespace(
        findings=[], steps_taken=1, success=False, error="",
        final_summary='a says "hello"', harness_status="partial",
        coverage_gaps=['a " gap'],
    )
    with patch("wscan.llm_agent_browser.AgentBrowserScanner") as scanner:
        scanner.return_value.run = AsyncMock(return_value=result)
        engine = AgentEngine(
            "https://app.example.test/a", auth_user="a", auth_pass='"',
            output_dir=str(tmp_path), open_report=False,
        )
        await engine.run()

    evidence = json.loads((tmp_path / "evidence.json").read_text())
    assert set(evidence) >= {"target", "final_summary", "coverage_gaps", "findings"}
    assert evidence["final_summary"] == (
        "<redacted> s<redacted>ys <redacted>hello<redacted>"
    )


@pytest.mark.asyncio
async def test_rejected_non_resume_invocation_preserves_existing_artifacts(tmp_path):
    from wscan.agent_engine import AgentEngine

    evidence = tmp_path / "evidence.json"
    reproduction = tmp_path / "reproduction.json"
    evidence.write_text("original evidence")
    reproduction.write_text("original reproduction")
    result = SimpleNamespace(
        findings=[], steps_taken=0, success=False,
        error="Agent output already contains harness state",
        final_summary="", preserve_existing_artifacts=True,
    )
    with patch("wscan.llm_agent_browser.AgentBrowserScanner") as scanner:
        scanner.return_value.run = AsyncMock(return_value=result)
        engine = AgentEngine(
            "https://app.example.test", output_dir=str(tmp_path), open_report=False
        )
        returned = await engine.run()

    assert returned is result
    assert evidence.read_text() == "original evidence"
    assert reproduction.read_text() == "original reproduction"


@pytest.mark.asyncio
@pytest.mark.parametrize("failure", [RuntimeError("missing API key"), ModuleNotFoundError("missing dependency")])
@pytest.mark.parametrize("resume,existing", [(True, True), (False, True), (True, False)])
async def test_llm_initialization_failure_preserves_only_existing_resume_artifacts(
    tmp_path, failure, resume, existing,
):
    from wscan.agent_engine import AgentEngine

    output_dir = tmp_path / "run"
    originals = {
        "evidence.json": b"original evidence",
        "reproduction.json": b"original reproduction",
        "agent_summary.md": b"original summary",
    }
    if existing:
        output_dir.mkdir()
        for name, content in originals.items():
            (output_dir / name).write_bytes(content)

    with patch(
        "wscan.llm_agent_browser._build_llm", side_effect=failure,
    ), patch(
        "wscan.llm_agent_browser.check_agent_config_directory", return_value=(True, ""),
    ):
        engine = AgentEngine(
            "https://app.example.test", output_dir=str(output_dir),
            open_report=False, resume=resume,
        )
        result = await engine.run()

    assert result.error == str(failure)
    assert result.success is False
    assert result.preserve_existing_artifacts is (resume and existing)
    if resume and existing:
        assert {p.name: p.read_bytes() for p in output_dir.iterdir()} == originals
    else:
        evidence = json.loads((output_dir / "evidence.json").read_text())
        assert evidence["findings"] == []
