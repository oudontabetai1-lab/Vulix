"""サーバー設定(通知/スケジュール/OOB)の永続化と API のテスト。

回帰防止:
- 設定ファイルの atomic write と破損時の退避（データ消失防止）。
- POSIX での設定ファイルパーミッション (0600)。
- 通知設定および OOB メール設定のマスク返却・既存値維持・機微情報非漏洩。
- OOB 環境変数優先度（環境変数有効時は編集拒否、エンジン構築時の優先）。
"""
import imaplib
import json
import os
import poplib
import socket
import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock

import wscan.engine as engine_mod
import wscan.monitor as monitor_mod
import wscan.oob_email as oob_mod
from wscan.monitor import MonitorServer
from fastapi.testclient import TestClient


class ServerSettingsTests(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self._orig_base = monitor_mod.OUTPUT_BASE
        monitor_mod.OUTPUT_BASE = self.tmp
        self._orig_engine_base = engine_mod.OUTPUT_BASE
        engine_mod.OUTPUT_BASE = self.tmp

        # テスト実行前の WSCAN_OOB_* 環境変数を退避・初期化
        self._orig_env = {k: os.environ[k] for k in list(os.environ) if k.startswith("WSCAN_OOB_")}
        for k in list(os.environ):
            if k.startswith("WSCAN_OOB_"):
                del os.environ[k]

        self.srv = MonitorServer(port=0, auth_token="")
        self.client = TestClient(self.srv.app)

    def tearDown(self):
        for k in list(os.environ):
            if k.startswith("WSCAN_OOB_"):
                del os.environ[k]
        for k, v in self._orig_env.items():
            os.environ[k] = v

        monitor_mod.OUTPUT_BASE = self._orig_base
        engine_mod.OUTPUT_BASE = self._orig_engine_base

    def test_atomic_save_leaves_no_tmp_and_roundtrips(self):
        self.srv._save_settings({"notifications": {"webhook_url": "u"}, "schedules": [{"id": "x"}]})
        self.assertFalse((self.tmp / "wscan_settings.json.tmp").exists())
        self.assertEqual(self.srv._load_settings()["schedules"][0]["id"], "x")

    def test_corrupt_file_is_quarantined_not_swallowed(self):
        (self.tmp / "wscan_settings.json").write_text("{ broken json")
        self.assertEqual(self.srv._load_settings(), {})
        self.assertTrue((self.tmp / "wscan_settings.json.corrupt").exists())

    def test_settings_webhook_masked_and_preserved(self):
        self.client.post("/api/v1/settings", json={"notifications": {
            "webhook_url": "https://hooks.slack.com/services/AAA/BBB/secret", "enabled": True}})
        got = self.client.get("/api/v1/settings").json()["notifications"]
        self.assertTrue(got["webhook_set"])
        self.assertNotIn("secret", got["webhook_hint"])  # マスクされている
        # webhook_url 未指定の更新は既存値を維持
        self.client.post("/api/v1/settings", json={"notifications": {"enabled": False}})
        self.assertTrue(self.client.get("/api/v1/settings").json()["notifications"]["webhook_set"])

    def test_schedule_crud(self):
        r = self.client.post("/api/v1/schedules", json={"url": "http://t", "interval_hours": 6})
        sid = r.json()["schedule"]["id"]
        self.assertEqual(len(self.client.get("/api/v1/schedules").json()["schedules"]), 1)
        self.client.post(f"/api/v1/schedules/{sid}/toggle")
        self.assertFalse(self.srv.list_schedules()[0]["enabled"])
        self.assertEqual(
            self.client.request("DELETE", f"/api/v1/schedules/{sid}").status_code, 200
        )
        self.assertEqual(self.client.get("/api/v1/schedules").json()["schedules"], [])

    def test_settings_file_not_listed_as_scan(self):
        self.srv._save_settings({"notifications": {"webhook_url": "u"}})
        self.assertEqual(self.client.get("/api/v1/scans").json()["scans"], [])

    def test_management_actions_are_audited(self):
        self.client.post("/api/v1/scan", json={"url": "http://t"})
        self.client.post("/api/v1/schedules", json={"url": "http://s", "interval_hours": 2})
        self.client.post("/api/v1/settings", json={"notifications": {"enabled": True}})
        actions = [a["action"] for a in self.client.get("/api/v1/audit").json()["audit"]]
        self.assertIn("scan_start", actions)
        self.assertIn("schedule_add", actions)
        self.assertIn("settings_update", actions)
        # 監査ログファイルもスキャン履歴には現れない
        ids = [s["id"] for s in self.client.get("/api/v1/scans").json()["scans"]]
        self.assertNotIn("management_audit.jsonl", ids)

    def test_settings_file_permissions_0600_posix(self):
        """POSIX 環境で設定ファイルが 0600 (所有者のみ読み書き) で書き出されることを確認。"""
        self.srv._save_settings({"notifications": {"enabled": True}})
        p = self.tmp / "wscan_settings.json"
        self.assertTrue(p.is_file())
        if os.name == "posix":
            mode = p.stat().st_mode & 0o777
            self.assertEqual(mode, 0o600)

    def test_oob_settings_get_never_contains_password(self):
        """OOB 設定取得 API がパスワード生値を決して返さず、マスクヒントのみ返すことを確認。"""
        secret_pw = "SuperSecret_OOB_Pass_12345!"
        self.srv._save_settings({
            "oob": {
                "protocol": "imap",
                "host": "imap.example.com",
                "port": 993,
                "username": "scanner@example.com",
                "password": secret_pw,
                "use_ssl": True,
                "mailbox": "INBOX",
                "domain": "oob.example.com",
            }
        })
        res = self.client.get("/api/v1/settings/oob")
        self.assertEqual(res.status_code, 200)
        data = res.json()
        self.assertNotIn("password", data)
        self.assertTrue(data["password_set"])
        self.assertNotIn(secret_pw, data["password_hint"])
        self.assertEqual(data["source"], "dashboard")

        def _assert_no_secret(val):
            if isinstance(val, dict):
                for k, v in val.items():
                    self.assertNotEqual(k, "password")
                    _assert_no_secret(v)
            elif isinstance(val, list):
                for item in val:
                    _assert_no_secret(item)
            elif isinstance(val, str):
                self.assertNotIn(secret_pw, val)

        _assert_no_secret(data)

    def test_oob_settings_post_keeps_existing_password_on_empty(self):
        """POST でパスワードが空文字列または未指定の場合、既存のパスワードを保持することを確認。"""
        res = self.client.post("/api/v1/settings/oob", json={
            "protocol": "imap",
            "host": "imap.example.com",
            "username": "user1",
            "password": "initial_password_123",
        })
        self.assertEqual(res.status_code, 200)
        saved = self.srv._saved_oob_dict()
        self.assertEqual(saved["password"], "initial_password_123")

        # 空パスワードでホストのみ更新
        res = self.client.post("/api/v1/settings/oob", json={
            "protocol": "imap",
            "host": "imap-updated.example.com",
            "username": "user1",
            "password": "",
        })
        self.assertEqual(res.status_code, 200)
        saved = self.srv._saved_oob_dict()
        self.assertEqual(saved["host"], "imap-updated.example.com")
        self.assertEqual(saved["password"], "initial_password_123")

        # password 未指定で更新
        res = self.client.post("/api/v1/settings/oob", json={
            "protocol": "imap",
            "host": "imap-updated2.example.com",
            "username": "user1",
        })
        self.assertEqual(res.status_code, 200)
        saved = self.srv._saved_oob_dict()
        self.assertEqual(saved["host"], "imap-updated2.example.com")
        self.assertEqual(saved["password"], "initial_password_123")

    def test_oob_settings_env_source_rejects_edits(self):
        """環境変数で OOB 設定が有効なとき、設定変更 (POST/DELETE) が 409 で拒否されることを確認。"""
        os.environ["WSCAN_OOB_HOST"] = "env.mail.example.com"
        os.environ["WSCAN_OOB_USERNAME"] = "envuser"
        os.environ["WSCAN_OOB_PASSWORD"] = "env_secret"

        get_res = self.client.get("/api/v1/settings/oob")
        self.assertEqual(get_res.status_code, 200)
        self.assertEqual(get_res.json()["source"], "environment")

        mock_imap = MagicMock()
        mock_imap.login.return_value = ("OK", [])
        mock_imap.select.return_value = ("OK", [])
        with unittest.mock.patch.object(oob_mod.imaplib, "IMAP4_SSL", return_value=mock_imap) as client:
            test_res = self.client.post("/api/v1/settings/oob/test", json={
                "protocol": "imap", "host": "request.mail.test", "username": "request-user",
                "password": "request_secret",
            })
        self.assertTrue(test_res.json()["ok"])
        self.assertEqual(client.call_args.args[0], "env.mail.example.com")
        mock_imap.login.assert_called_once_with("envuser", "env_secret")
        mock_imap.select.assert_called_once_with("INBOX", readonly=True)
        mock_imap.list.assert_called_once_with()
        audit = (self.tmp / "management_audit.jsonl").read_text(encoding="utf-8")
        self.assertNotIn("env_secret", audit)
        self.assertNotIn("request_secret", audit)

        post_res = self.client.post("/api/v1/settings/oob", json={
            "protocol": "imap",
            "host": "new.mail.test",
        })
        self.assertEqual(post_res.status_code, 409)

        del_res = self.client.delete("/api/v1/settings/oob")
        self.assertEqual(del_res.status_code, 409)

    def test_oob_settings_delete_clears(self):
        """DELETE で保存された OOB 設定が削除されることを確認。"""
        self.client.post("/api/v1/settings/oob", json={
            "protocol": "imap",
            "host": "imap.example.com",
            "password": "secret_to_delete",
        })
        self.assertTrue("oob" in self.srv._load_settings())

        del_res = self.client.delete("/api/v1/settings/oob")
        self.assertEqual(del_res.status_code, 200)
        self.assertFalse("oob" in self.srv._load_settings())

        get_res = self.client.get("/api/v1/settings/oob")
        self.assertEqual(get_res.status_code, 200)
        self.assertFalse(get_res.json()["password_set"])
        self.assertEqual(get_res.json()["source"], "unset")

    def test_oob_test_connection_fake_clients(self):
        """接続テストエンドポイントの動作（成功・認証失敗・タイムアウト）および秘匿値非漏洩の検証。"""
        secret_pw = "super_classified_pw_999"

        # 1. IMAP 成功
        mock_imap_inst = MagicMock()
        mock_imap_inst.login.return_value = ("OK", [b"Logged in"])
        mock_imap_inst.select.return_value = ("OK", [b"1"])
        mock_imap_cls = MagicMock(return_value=mock_imap_inst)

        orig_imap = oob_mod.imaplib.IMAP4_SSL
        oob_mod.imaplib.IMAP4_SSL = mock_imap_cls
        try:
            res = self.client.post("/api/v1/settings/oob/test", json={
                "protocol": "imap",
                "host": "imap.test",
                "username": "user",
                "password": secret_pw,
                "use_ssl": True,
            })
            self.assertEqual(res.status_code, 200)
            data = res.json()
            self.assertTrue(data["ok"])
            self.assertEqual(data["stage"], "done")
            self.assertIsNone(data["error_kind"])
            mock_imap_inst.select.assert_called_once_with("INBOX", readonly=True)
            mock_imap_inst.list.assert_called_once_with()
        finally:
            oob_mod.imaplib.IMAP4_SSL = orig_imap

        # 2. IMAP 認証失敗（サーバーエラー文字列にパスワードが含まれるケース）
        mock_imap_auth_fail = MagicMock()
        mock_imap_auth_fail.login.side_effect = imaplib.IMAP4.error(f"AUTHENTICATIONFAILED bad password {secret_pw}")
        mock_imap_fail_cls = MagicMock(return_value=mock_imap_auth_fail)

        oob_mod.imaplib.IMAP4_SSL = mock_imap_fail_cls
        try:
            res = self.client.post("/api/v1/settings/oob/test", json={
                "protocol": "imap",
                "host": "imap.test",
                "username": "user",
                "password": secret_pw,
                "use_ssl": True,
            })
            self.assertEqual(res.status_code, 200)
            data = res.json()
            self.assertFalse(data["ok"])
            self.assertEqual(data["stage"], "login")
            self.assertEqual(data["error_kind"], "auth")
            self.assertNotIn(secret_pw, data["message"])
            self.assertNotIn("AUTHENTICATIONFAILED", data["message"])

            # 監査ログにもパスワードが含まれていないことを確認
            audit_lines = (self.tmp / "management_audit.jsonl").read_text(encoding="utf-8")
            self.assertNotIn(secret_pw, audit_lines)
        finally:
            oob_mod.imaplib.IMAP4_SSL = orig_imap

        # 3. IMAP 接続タイムアウト
        mock_imap_timeout = MagicMock()
        mock_imap_timeout.side_effect = socket.timeout("timed out connecting to server")
        oob_mod.imaplib.IMAP4_SSL = mock_imap_timeout
        try:
            res = self.client.post("/api/v1/settings/oob/test", json={
                "protocol": "imap",
                "host": "imap.test",
                "username": "user",
                "password": secret_pw,
            })
            self.assertEqual(res.status_code, 200)
            data = res.json()
            self.assertFalse(data["ok"])
            self.assertEqual(data["stage"], "connect")
            self.assertEqual(data["error_kind"], "timeout")
            self.assertNotIn(secret_pw, data["message"])
        finally:
            oob_mod.imaplib.IMAP4_SSL = orig_imap

        # 4. POP3 成功
        mock_pop_inst = MagicMock()
        mock_pop_inst.user.return_value = b"+OK User accepted"
        mock_pop_inst.pass_.return_value = b"+OK Pass accepted"
        mock_pop_inst.list.return_value = (b"+OK", [b"1 100"], 10)
        mock_pop_cls = MagicMock(return_value=mock_pop_inst)

        orig_pop = oob_mod.poplib.POP3_SSL
        oob_mod.poplib.POP3_SSL = mock_pop_cls
        try:
            res = self.client.post("/api/v1/settings/oob/test", json={
                "protocol": "pop3",
                "host": "pop.test",
                "username": "user",
                "password": secret_pw,
                "use_ssl": True,
            })
            self.assertEqual(res.status_code, 200)
            data = res.json()
            self.assertTrue(data["ok"])
            self.assertEqual(data["stage"], "done")
        finally:
            oob_mod.poplib.POP3_SSL = orig_pop

        # 5. POP3 認証失敗
        mock_pop_fail = MagicMock()
        mock_pop_fail.user.return_value = b"+OK"
        mock_pop_fail.pass_.side_effect = poplib.error_proto(f"-ERR [AUTH] invalid password {secret_pw}")
        mock_pop_fail_cls = MagicMock(return_value=mock_pop_fail)

        oob_mod.poplib.POP3_SSL = mock_pop_fail_cls
        try:
            res = self.client.post("/api/v1/settings/oob/test", json={
                "protocol": "pop3",
                "host": "pop.test",
                "username": "user",
                "password": secret_pw,
                "use_ssl": True,
            })
            self.assertEqual(res.status_code, 200)
            data = res.json()
            self.assertFalse(data["ok"])
            self.assertEqual(data["stage"], "login")
            self.assertEqual(data["error_kind"], "auth")
            self.assertNotIn(secret_pw, data["message"])

            audit_lines = (self.tmp / "management_audit.jsonl").read_text(encoding="utf-8")
            self.assertNotIn(secret_pw, audit_lines)
        finally:
            oob_mod.poplib.POP3_SSL = orig_pop

    def test_engine_oob_precedence(self):
        """ScanEngine での OOB 設定の優先順位（環境変数 > ダッシュボード保存設定 > 未設定）を確認。"""
        # 1. 環境変数が設定されている場合（環境変数が最優先）
        os.environ["WSCAN_OOB_HOST"] = "env.imap.test"
        os.environ["WSCAN_OOB_USERNAME"] = "env_user"
        os.environ["WSCAN_OOB_PASSWORD"] = "env_pass"

        # ダッシュボード設定にも値を保存
        self.srv._save_settings({
            "oob": {
                "host": "dash.imap.test",
                "username": "dash_user",
                "password": "dash_password",
            }
        })
        e1 = engine_mod.ScanEngine("http://127.0.0.1:8000", checks=["sqli"])
        self.assertEqual(e1.oob_source, "environment")
        self.assertEqual(e1.oob_config.host, "env.imap.test")
        self.assertIsNotNone(e1.oob_sink)

        # 2. 環境変数は未設定で、ダッシュボード保存設定がある場合
        del os.environ["WSCAN_OOB_HOST"]
        del os.environ["WSCAN_OOB_USERNAME"]
        del os.environ["WSCAN_OOB_PASSWORD"]

        e2 = engine_mod.ScanEngine("http://127.0.0.1:8000", checks=["sqli"])
        self.assertEqual(e2.oob_source, "dashboard")
        self.assertEqual(e2.oob_config.host, "dash.imap.test")
        self.assertEqual(e2.oob_config.username, "dash_user")
        self.assertIsNotNone(e2.oob_sink)

        # 3. 環境変数もダッシュボード保存設定も未設定の場合
        self.srv._save_settings({})
        e3 = engine_mod.ScanEngine("http://127.0.0.1:8000", checks=["sqli"])
        self.assertEqual(e3.oob_source, "unset")
        self.assertFalse(e3.oob_config.configured)
        self.assertIsNone(e3.oob_sink)


if __name__ == "__main__":
    unittest.main()
