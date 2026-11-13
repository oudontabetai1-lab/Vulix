import asyncio
import json
import unittest

import main

USER = "alice.admin@example.test"
PASSWORD = "Zx9-very-secret"


class RedactSecretsTests(unittest.TestCase):
    def test_redacts_password_like_keys(self):
        cfg = {
            "mfa_email_imap_password": "app-secret",
            "tls_client_cert_password": "pfxpass",
            "openai_api_key": "sk-xxx",
            "session_token": "tok",
        }
        out = main._redact_secrets(cfg)
        for key in cfg:
            self.assertEqual(out[key], "***REDACTED***", key)

    def test_keeps_non_secret_and_empty_values(self):
        cfg = {
            "depth": 2,
            "url": "http://x.test/",
            "mfa_email_imap_password": "",  # 空は伏字にしない（送信なしと区別不要）
            "login_pass_field": "password",  # フィールド名であり秘匿値ではない
        }
        out = main._redact_secrets(cfg)
        self.assertEqual(out["depth"], 2)
        self.assertEqual(out["url"], "http://x.test/")
        self.assertEqual(out["mfa_email_imap_password"], "")
        # キー名は "pass_field" で "password" を含まないため伏字にしない
        # （これは秘匿値ではなく入力欄名）。
        self.assertEqual(out["login_pass_field"], "password")

    def test_does_not_mutate_input(self):
        cfg = {"mfa_email_imap_password": "s3cret"}
        main._redact_secrets(cfg)
        self.assertEqual(cfg["mfa_email_imap_password"], "s3cret")

    def test_redacts_dashboard_totp_bearer_and_header_values(self):
        cfg = {
            "mfa_totp_uri": "otpauth://totp/x?secret=BASE32",
            "mfa_totp_secret": "BASE32",
            "bearer": "access-token",
            "headers": {"Authorization": "Bearer access-token", "X-Tenant": "acme"},
        }
        out = main._redact_secrets(cfg)
        self.assertEqual(out["mfa_totp_uri"], "***REDACTED***")
        self.assertEqual(out["mfa_totp_secret"], "***REDACTED***")
        self.assertEqual(out["bearer"], "***REDACTED***")
        self.assertEqual(
            out["headers"],
            {"Authorization": "***REDACTED***", "X-Tenant": "***REDACTED***"},
        )

    def test_placeholder_blank_for_served_defaults(self):
        # /api/config/defaults 用: 秘匿値は空文字にし、非秘匿フィールドは残す。
        # （"***REDACTED***" だとフォーム欄にその文字列が入ってしまうため空にする）
        cfg = {
            "mfa_totp_secret": "BASE32",
            "mfa_totp_uri": "otpauth://totp/x?secret=BASE32",
            "bearer": "tok",
            "auth_pass": "pw",
            "cookies": "session=abc",
            "headers": {"Authorization": "Bearer x"},
            # 非秘匿は保持
            "mfa_totp_digits": 8,
            "mfa_totp_period": 45,
            "mfa_totp_algorithm": "SHA256",
            "url": "http://x.test/",
        }
        out = main._redact_secrets(cfg, placeholder="")
        self.assertEqual(out["mfa_totp_secret"], "")
        self.assertEqual(out["mfa_totp_uri"], "")
        self.assertEqual(out["bearer"], "")
        self.assertEqual(out["auth_pass"], "")
        self.assertEqual(out["cookies"], "")
        self.assertEqual(out["headers"], {"Authorization": ""})
        self.assertEqual(out["mfa_totp_digits"], 8)
        self.assertEqual(out["mfa_totp_period"], 45)
        self.assertEqual(out["mfa_totp_algorithm"], "SHA256")
        self.assertEqual(out["url"], "http://x.test/")

    def test_redacts_totp_qr_path(self):
        # QR 画像パスはシークレットを符号化した画像の所在を示すため、defaults/snapshot
        # 双方で伏字化する（/api/config/defaults は未認証 serve で読まれ得る）。
        cfg = {"mfa_totp_qr": "/srv/output/uploads/abc_totp.png"}
        self.assertEqual(main._redact_secrets(cfg)["mfa_totp_qr"], "***REDACTED***")
        self.assertEqual(main._redact_secrets(cfg, placeholder="")["mfa_totp_qr"], "")
        self.assertEqual(main._redact_secrets({"mfa_totp_qr": ""})["mfa_totp_qr"], "")

    def test_redacts_string_form_headers(self):
        # headers_text（config 由来）は "Name: Value" の文字列。dict と同様に
        # 認証情報が入り得るため、defaults/snapshot 双方で丸ごと伏字化する。
        cfg = {"headers": "Authorization: Bearer leak\nX-Api-Key: k"}
        self.assertEqual(main._redact_secrets(cfg)["headers"], "***REDACTED***")
        self.assertEqual(main._redact_secrets(cfg, placeholder="")["headers"], "")
        # 空文字列はそのまま（送信なしと区別不要）。
        self.assertEqual(main._redact_secrets({"headers": ""})["headers"], "")

    def test_redacts_login_credentials_and_cookies_exact_keys(self):
        # 部分一致では拾えない明示キー。scan_started の再生・snapshot 経由で
        # ログイン PW / セッション Cookie が別クライアントへ漏れないようにする。
        cfg = {
            "auth_user": "alice",
            "auth_pass": "hunter2",
            "cookies": "session=abc; token=xyz",
            "low_priv_cookies": "session=low",
            # フィールド名は秘匿値ではないため伏字にしない
            "login_pass_field": "password",
            "login_user_field": "username",
        }
        out = main._redact_secrets(cfg)
        self.assertEqual(out["auth_user"], "***REDACTED***")
        self.assertEqual(out["auth_pass"], "***REDACTED***")
        self.assertEqual(out["cookies"], "***REDACTED***")
        self.assertEqual(out["low_priv_cookies"], "***REDACTED***")
        self.assertEqual(out["login_pass_field"], "password")
        self.assertEqual(out["login_user_field"], "username")


class ScanConfigSnapshotTests(unittest.TestCase):
    """output/<scan>/scan_config.json の内容（ダッシュボード送信設定の保存物）。"""

    def test_snapshot_masks_configured_username_and_password(self):
        # 資格情報はパスワードだけでなくユーザー名も保存しない（コード/レポートへ
        # 平文で残さない）。フィールド名・対象 URL は診断のため残す。
        cfg = {
            "url": "http://t.test/",
            "auth_user": USER,
            "auth_pass": PASSWORD,
            "login_user_field": "username",
            "login_pass_field": "password",
            "checks": ["xss"],
        }
        snapshot = main.scan_config_snapshot(cfg, "2026-01-02T03:04:05")
        blob = json.dumps(snapshot, ensure_ascii=False)
        self.assertNotIn(USER, blob)
        self.assertNotIn(PASSWORD, blob)
        self.assertEqual(snapshot["config"]["auth_user"], "***REDACTED***")
        self.assertEqual(snapshot["config"]["auth_pass"], "***REDACTED***")
        self.assertEqual(snapshot["config"]["login_user_field"], "username")
        self.assertEqual(snapshot["config"]["url"], "http://t.test/")
        self.assertEqual(snapshot["submitted_at"], "2026-01-02T03:04:05")


class ScanStartedRedactionTests(unittest.TestCase):
    """serve の最初のイベント（scan_started）も他イベントと同じ伏字を通る。"""

    def _emit(self, cfg):
        from wscan import url_scope
        from wscan.monitor import MonitorServer

        url_scope.clear_secret_values()
        try:
            monitor = MonitorServer()
            asyncio.run(main.emit_scan_started(monitor, cfg))
            self.assertEqual(monitor.event_history[-1]["type"], "scan_started")
            return monitor.event_history[-1]["data"]
        finally:
            url_scope.clear_secret_values()

    def test_scan_started_masks_username_before_engine_registration(self):
        # scan_started はどのエンジンよりも先に配信されるため、エンジン構築時の
        # 値ベース登録に頼れない。登録前だと auth_user が平文で漏れる。
        data = self._emit({
            "url": "http://t.test/",
            "auth_user": USER,
            "auth_pass": PASSWORD,
            "login_user_field": "username",
            "login_pass_field": "password",
        })
        blob = json.dumps(data, ensure_ascii=False)
        self.assertNotIn(USER, blob)
        self.assertNotIn(PASSWORD, blob)
        # 配信の形（キー・識別子）は保つ: ダッシュボードは非秘匿フィールドを読む。
        self.assertEqual(data["url"], "http://t.test/")
        self.assertEqual(data["login_user_field"], "username")
        self.assertEqual(data["login_pass_field"], "password")

    def test_scan_started_masks_cookie_and_header_values(self):
        data = self._emit({
            "url": "http://t.test/",
            "cookies": "sid=cookie-value-777",
            "headers": {"Authorization": "Bearer header-token-123"},
        })
        blob = json.dumps(data, ensure_ascii=False)
        self.assertNotIn("cookie-value-777", blob)
        self.assertNotIn("header-token-123", blob)

    def test_scan_started_registers_bearer_and_string_headers(self):
        # serve は bearer / 文字列 headers を正規化してから engine へ渡す。scan_started の
        # 登録も同じ有効ヘッダから作るため、キー名では伏せられない自由文へ同じ値が
        # 現れても伏字になる（登録が engine と非同等だとここが漏れる）。
        token = "tok-bearer-abc123"
        header = "hdr-secret-9999"
        data = self._emit({
            "url": "http://t.test/",
            "bearer": token,
            "headers": f"X-Api-Auth: {header}",
            # 非秘匿キー（キー基準では伏字対象外）に同じ値が現れるケース。
            "login_success_indicator": f"{token} {header}",
        })
        blob = json.dumps(data, ensure_ascii=False)
        self.assertNotIn(token, blob)
        self.assertNotIn(header, blob)

    def test_registration_matches_effective_headers_for_engine(self):
        # 値集合は engine と共有する純粋関数から作る。文字列ヘッダ＋Bearer の
        # 正規化結果（Authorization / 元ヘッダ）が両方とも登録対象になる。
        from wscan import url_scope

        url_scope.clear_secret_values()
        try:
            items, names = main._configured_secret_values({
                "auth_user": USER,
                "bearer": "tok-bearer-abc123",
                "headers": "X-Api-Auth: hdr-secret-9999",
                "cookies": "sid=cookie-value-777",
            })
        finally:
            url_scope.clear_secret_values()
        self.assertIn(("auth_user", USER), items)
        self.assertIn(("header:X-Api-Auth", "hdr-secret-9999"), items)
        self.assertIn(("header:Authorization", "Bearer tok-bearer-abc123"), items)
        self.assertIn("sid", names)


class ConfigSecretFallbackTests(unittest.TestCase):
    def test_username_falls_back_to_config_when_blank(self):
        # 画面へユーザー名を配信しない代償として、空で戻った値は config で補う
        # （パスワードと同じ扱い。ダッシュボードからのスキャンは従来どおり認証できる）。
        out = main.apply_config_secret_fallback(
            {"auth_user": "", "auth_pass": ""},
            {"auth_user": "config-user", "auth_pass": "config-password"},
        )
        self.assertEqual(out["auth_user"], "config-user")
        self.assertEqual(out["auth_pass"], "config-password")

    def test_blank_served_defaults_hide_username(self):
        # /api/config/defaults は未認証 serve でも読めるため、config のユーザー名も
        # フォーム初期値として配信しない。
        out = main._redact_secrets({"auth_user": "config-user"}, placeholder="")
        self.assertEqual(out["auth_user"], "")

    def test_empty_values_fall_back_to_config_keys(self):
        cfg = {
            "auth_pass": "",
            "bearer": "",
            "mfa_totp_secret": "",
            "headers": {},
        }
        defaults = {
            "auth_pass": "config-password",
            "bearer_token": "config-bearer",
            "mfa_totp_secret": "config-totp",
            "headers_text": "Authorization: config-header",
        }

        out = main.apply_config_secret_fallback(cfg, defaults)

        self.assertEqual(out["auth_pass"], "config-password")
        self.assertEqual(out["bearer"], "config-bearer")
        self.assertEqual(out["mfa_totp_secret"], "config-totp")
        self.assertEqual(out["headers"], "Authorization: config-header")

    def test_non_empty_dashboard_values_win(self):
        cfg = {
            "auth_pass": "dashboard-password",
            "bearer": "dashboard-bearer",
            "headers": {"Authorization": "dashboard-header"},
        }
        defaults = {
            "auth_pass": "config-password",
            "bearer_token": "config-bearer",
            "headers_text": "Authorization: config-header",
        }

        out = main.apply_config_secret_fallback(cfg, defaults)

        self.assertEqual(out, cfg)

    def test_missing_config_value_keeps_dashboard_value_empty(self):
        cfg = {"auth_pass": "", "headers": ""}

        out = main.apply_config_secret_fallback(cfg, {})

        self.assertEqual(out["auth_pass"], "")
        self.assertEqual(out["headers"], "")

    def test_does_not_mutate_input(self):
        cfg = {"auth_pass": "", "headers": {}}
        original = {"auth_pass": "", "headers": {}}

        out = main.apply_config_secret_fallback(
            cfg,
            {"auth_pass": "config-password", "headers_text": "X-Test: config"},
        )

        self.assertEqual(cfg, original)
        self.assertIsNot(out, cfg)


class SubmittedTotpSourceTests(unittest.TestCase):
    def test_dashboard_secret_suppresses_config_uri(self):
        sources = main.resolve_submitted_totp_sources(
            {
                "mfa_totp_uri": "",
                "mfa_totp_secret": "submitted-secret",
                "mfa_totp_qr": "",
            },
            {"mfa_totp_uri": "config-uri"},
        )

        self.assertEqual(sources, ("", "submitted-secret", ""))

    def test_empty_dashboard_sources_use_config_values(self):
        sources = main.resolve_submitted_totp_sources(
            {
                "mfa_totp_uri": "",
                "mfa_totp_secret": "",
                "mfa_totp_qr": "",
            },
            {
                "mfa_totp_uri": "config-uri",
                "mfa_totp_secret": "config-secret",
                "mfa_totp_qr": "config-qr",
            },
        )

        self.assertEqual(
            sources,
            ("config-uri", "config-secret", "config-qr"),
        )

    def test_dashboard_uri_is_used_without_other_fallbacks(self):
        sources = main.resolve_submitted_totp_sources(
            {"mfa_totp_uri": "submitted-uri"},
            {
                "mfa_totp_secret": "config-secret",
                "mfa_totp_qr": "config-qr",
            },
        )

        self.assertEqual(sources, ("submitted-uri", "", ""))

    def test_secret_fallback_applies_same_exclusive_rule(self):
        resolved = main.apply_config_secret_fallback(
            {"mfa_totp_secret": "submitted-secret"},
            {"mfa_totp_uri": "config-uri"},
        )

        self.assertEqual(resolved["mfa_totp_uri"], "")
        self.assertEqual(resolved["mfa_totp_secret"], "submitted-secret")
        self.assertEqual(resolved["mfa_totp_qr"], "")


if __name__ == "__main__":
    unittest.main()
