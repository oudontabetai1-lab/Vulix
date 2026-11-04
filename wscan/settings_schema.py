"""Setup の版付き設定宣言。実行結果・実行時環境の解決は主張しない。"""
from __future__ import annotations

from copy import deepcopy
import json
import math
from typing import Any, Mapping

from wscan.state_profile import VALID_PROFILES

SCHEMA_VERSION = "1.0.0"
ALL_MODES = ("normal", "agent", "hybrid")
SCAN_MODES = ("normal", "hybrid")

# 既存 applyScanProfile の宣言と完全一致を実行テストで固定する。
PROFILES = {'triage': {'label': '高速トリアージ',
            'applicable_modes': ['normal', 'hybrid'],
            'overrides': {'checks': ['sqli', 'xss', 'os', 'security_headers', 'info_disclosure'],
                          'depth': 1,
                          'concurrency': 1,
                          'llm': 'none',
                          'max_payloads': 8,
                          'toggles.fast_mode': True,
                          'toggles.headless': True,
                          'toggles.use_planner': False,
                          'toggles.interactive_plan': False,
                          'toggles.enable_ai_analysis': False,
                          'toggles.enable_waf_detection': False,
                          'toggles.enable_payload_learning': False,
                          'toggles.spa_crawl': False,
                          'toggles.auto_spa_crawl': True,
                          'toggles.ctf_mode': False,
                          'toggles.allow_state_changing_probes': False}},
 'standard': {'label': '標準Web診断',
              'applicable_modes': ['normal', 'hybrid'],
              'overrides': {'checks': ['sqli',
                                       'xss',
                                       'os',
                                       'path_traversal',
                                       'csrf',
                                       'open_redirect',
                                       'clickjacking',
                                       'session',
                                       'cors',
                                       'security_headers',
                                       'info_disclosure'],
                            'depth': 2,
                            'concurrency': 1,
                            'llm': 'ollama',
                            'max_payloads': 0,
                            'toggles.fast_mode': False,
                            'toggles.headless': True,
                            'toggles.use_planner': True,
                            'toggles.interactive_plan': False,
                            'toggles.enable_ai_analysis': True,
                            'toggles.enable_waf_detection': True,
                            'toggles.enable_payload_learning': True,
                            'toggles.enable_sitemap_crawl': True,
                            'toggles.spa_crawl': False,
                            'toggles.auto_spa_crawl': True,
                            'toggles.ctf_mode': False,
                            'toggles.allow_state_changing_probes': False}},
 'auth': {'label': '認証あり診断',
          'applicable_modes': ['normal', 'hybrid'],
          'overrides': {'checks': ['sqli',
                                   'xss',
                                   'csrf',
                                   'session',
                                   'privesc',
                                   'open_redirect',
                                   'cors',
                                   'security_headers',
                                   'jwt'],
                        'depth': 2,
                        'concurrency': 1,
                        'llm': 'ollama',
                        'max_payloads': 0,
                        'toggles.fast_mode': False,
                        'toggles.headless': True,
                        'toggles.use_planner': True,
                        'toggles.interactive_plan': True,
                        'toggles.enable_ai_analysis': True,
                        'toggles.enable_waf_detection': True,
                        'toggles.enable_payload_learning': True,
                        'toggles.enable_sitemap_crawl': True,
                        'toggles.spa_crawl': False,
                        'toggles.auto_spa_crawl': True,
                        'toggles.ctf_mode': False,
                        'toggles.allow_state_changing_probes': False}},
 'precision': {'label': '精度重視診断',
               'applicable_modes': ['normal', 'hybrid'],
               'overrides': {'checks': ['sqli',
                                        'xss',
                                        'dom_xss',
                                        'stored_xss',
                                        'os',
                                        'ssti',
                                        'path_traversal',
                                        'csrf',
                                        'header_injection',
                                        'open_redirect',
                                        'session',
                                        'privesc',
                                        'cors',
                                        'security_headers',
                                        'info_disclosure',
                                        'ssrf',
                                        'graphql',
                                        'jwt'],
                             'depth': 3,
                             'concurrency': 1,
                             'llm': 'ollama',
                             'max_payloads': 0,
                             'toggles.fast_mode': False,
                             'toggles.headless': True,
                             'toggles.use_planner': True,
                             'toggles.interactive_plan': True,
                             'toggles.enable_ai_analysis': True,
                             'toggles.enable_waf_detection': True,
                             'toggles.enable_payload_learning': True,
                             'toggles.enable_sitemap_crawl': True,
                             'toggles.spa_crawl': True,
                             'toggles.auto_spa_crawl': True,
                             'toggles.ctf_mode': False,
                             'toggles.allow_state_changing_probes': False}},
 'ctf': {'label': 'CTF/演習',
         'applicable_modes': ['normal', 'hybrid'],
         'overrides': {'checks': ['xss',
                                  'sqli',
                                  'ssti',
                                  'os',
                                  'path_traversal',
                                  'ssrf',
                                  'open_redirect'],
                       'depth': 1,
                       'concurrency': 1,
                       'llm': 'none',
                       'max_payloads': 12,
                       'toggles.fast_mode': True,
                       'toggles.headless': True,
                       'toggles.use_planner': False,
                       'toggles.interactive_plan': False,
                       'toggles.enable_ai_analysis': False,
                       'toggles.enable_waf_detection': False,
                       'toggles.enable_payload_learning': False,
                       'toggles.enable_sitemap_crawl': True,
                       'toggles.spa_crawl': False,
                       'toggles.auto_spa_crawl': True,
                       'toggles.ctf_mode': True,
                       'toggles.allow_state_changing_probes': False}}}


def _field(key, label, default, *, modes=SCAN_MODES, redacted=False, constraints=None):
    # 自由入力には URL 埋込資格情報も入るため、許可した列挙値以外は全体を伏せる。
    kind = {bool: "boolean", int: "integer", float: "number", str: "string",
            list: "array", dict: "object"}[type(default)]
    return {"key": key, "type": kind, "label": label,
            "applicable_modes": list(modes),
            "profiles": list(PROFILES) if set(modes) & set(SCAN_MODES) else [],
            "default": None if redacted else default, "redacted": redacted,
            "constraints": constraints or {},
            "category": "general", "description": label,
            "ui_exposed": True, "editable": True, "sensitive": redacted,
            "dangerous": False, "choices": tuple((constraints or {}).get("enum", ())),
            "validation": constraints or {}, "restart_required": False,
            "scope": "scan"}


# serve のフォーム初期値と同じキー。toggles はドット区切りで宣言する。
FIELDS = (
    _field('report_lang', 'レポート言語', 'ja', modes=ALL_MODES, constraints={"enum": ['ja', 'en']}),
    _field('checks', '検査項目', ['sqli', 'xss', 'os'], modes=ALL_MODES, constraints={"items": "scanner_id"}),
    _field('depth', 'クロール深度', 2, constraints={'minimum': 0}),
    _field('timeout', 'HTTP タイムアウト秒', 30.0, modes=ALL_MODES, constraints={'exclusiveMinimum': 0}),
    _field('max_forms', '最大フォーム数', 50, constraints={'minimum': 0}),
    _field('request_delay', 'リクエスト待機秒', 0.5, constraints={'minimum': 0}),
    _field('navigation_retries', 'ページ遷移再試行回数', 2, constraints={'minimum': 0}),
    _field('allowed_hours', 'allowed_hours', [], redacted=True, modes=ALL_MODES),
    _field('forbidden_hours', 'forbidden_hours', [], redacted=True, modes=ALL_MODES),
    _field('proxy', 'proxy', '', redacted=True, modes=ALL_MODES),
    _field('tls_client_cert', 'tls_client_cert', '', redacted=True),
    _field('tls_client_key', 'tls_client_key', '', redacted=True),
    _field('tls_client_pfx', 'tls_client_pfx', '', redacted=True),
    _field('tls_client_cert_password', 'tls_client_cert_password', '', redacted=True),
    _field('tls_ca_cert', 'tls_ca_cert', '', redacted=True),
    _field('tls_verify', 'tls_verify', False),
    _field('header_scope_enforce', 'header_scope_enforce', True),
    _field('popup_header_intercept', 'popup_header_intercept', False),
    _field('llm', 'LLM プロバイダー', 'ollama', modes=ALL_MODES, constraints={"enum": ['ollama', 'claude', 'openai', 'openai_compatible', 'gemini', 'none']}),
    _field('ollama_model', 'ollama_model', 'llama3', redacted=True),
    _field('openai_model', 'openai_model', 'gpt-4o-mini', redacted=True),
    _field('gemini_model', 'gemini_model', 'gemini-2.0-flash', redacted=True),
    _field('claude_model', 'claude_model', 'claude-haiku-4-5-20251001', redacted=True),
    _field('openai_base_url', 'openai_base_url', '', redacted=True, modes=ALL_MODES),
    _field('role_models', 'role_models', {}, redacted=True),
    _field('llm_timeout_seconds', 'llm_timeout_seconds', 30.0, modes=ALL_MODES, constraints={'exclusiveMinimum': 0}),
    _field('llm_stream_timeout_seconds', 'llm_stream_timeout_seconds', 90.0, constraints={'exclusiveMinimum': 0}),
    _field('llm_max_retries', 'llm_max_retries', 2, constraints={'minimum': 0}),
    _field('auth_user', 'auth_user', '', redacted=True, modes=ALL_MODES),
    _field('auth_pass', 'auth_pass', '', redacted=True, modes=ALL_MODES),
    _field('login_url', 'login_url', '', redacted=True, modes=ALL_MODES),
    _field('login_user_field', 'login_user_field', 'username', redacted=True),
    _field('login_pass_field', 'login_pass_field', 'password', redacted=True),
    _field('login_success_indicator', 'login_success_indicator', '', redacted=True),
    _field('mfa_type', 'mfa_type', '', redacted=True),
    _field('mfa_field', 'mfa_field', '', redacted=True),
    _field('mfa_selector', 'mfa_selector', '', redacted=True),
    _field('mfa_email_account', 'mfa_email_account', '', redacted=True),
    _field('mfa_email_address', 'mfa_email_address', '', redacted=True),
    _field('mfa_email_imap_host', 'mfa_email_imap_host', '', redacted=True),
    _field('mfa_email_imap_port', 'mfa_email_imap_port', '', redacted=True),
    _field('mfa_email_imap_user', 'mfa_email_imap_user', '', redacted=True),
    _field('mfa_email_imap_ssl', 'mfa_email_imap_ssl', '', redacted=True),
    _field('mfa_totp_uri', 'mfa_totp_uri', '', redacted=True),
    _field('mfa_totp_secret', 'mfa_totp_secret', '', redacted=True),
    _field('mfa_totp_qr', 'mfa_totp_qr', '', redacted=True),
    _field('mfa_totp_digits', 'mfa_totp_digits', '', redacted=True),
    _field('mfa_totp_period', 'mfa_totp_period', '', redacted=True),
    _field('mfa_totp_algorithm', 'mfa_totp_algorithm', '', redacted=True),
    _field('bearer', 'bearer', '', redacted=True, modes=ALL_MODES),
    _field('headers', 'headers', '', redacted=True, modes=ALL_MODES),
    _field('exclude_fields', 'exclude_fields', '', redacted=True),
    _field('exclude_urls', 'exclude_urls', '', redacted=True),
    _field('target_urls', 'target_urls', '', redacted=True),
    _field('access_urls', 'access_urls', '', redacted=True),
    _field('manual_crawl_file', 'manual_crawl_file', '', redacted=True),
    _field('state_profile', '状態変更プロファイル', 'unrestricted', constraints={"enum": list(VALID_PROFILES)}),
    _field('toggles.headless', 'toggles.headless', False, modes=ALL_MODES),
    _field('toggles.skip_registration', 'toggles.skip_registration', True),
    _field('toggles.open_report', 'toggles.open_report', True, modes=ALL_MODES),
    _field('toggles.use_planner', 'toggles.use_planner', True),
    _field('toggles.interactive_plan', 'toggles.interactive_plan', False),
    _field('toggles.enable_ai_analysis', 'toggles.enable_ai_analysis', True),
    _field('toggles.enable_waf_detection', 'toggles.enable_waf_detection', True),
    _field('toggles.enable_payload_learning', 'toggles.enable_payload_learning', True),
    _field('toggles.community_payloads', 'toggles.community_payloads', True),
    _field('toggles.component_intel', 'toggles.component_intel', False),
    _field('toggles.tls_scan', 'toggles.tls_scan', False),
    _field('toggles.enable_sitemap_crawl', 'toggles.enable_sitemap_crawl', True),
    _field('toggles.spa_crawl', 'toggles.spa_crawl', False),
    _field('toggles.auto_spa_crawl', 'toggles.auto_spa_crawl', True),
    _field('toggles.interactive_crawl_review', 'toggles.interactive_crawl_review', False),
    _field('toggles.ctf_mode', 'toggles.ctf_mode', False),
    _field('toggles.tls_verify', 'toggles.tls_verify', False),
    _field('toggles.allow_state_changing_probes', 'toggles.allow_state_changing_probes', False),
    _field("concurrency", "ブラウザ並列数", 1, constraints={"minimum": 0}),
    _field("max_payloads", "最大ペイロード数", 0, constraints={"minimum": 0}),
    _field("toggles.fast_mode", "高速モード", False),
    _field("toggles.auto_register", "自動アカウント登録", False),
    _field("auto_register_count", "登録アカウント数", 2, constraints={"minimum": 0}),
    _field("toggles.enable_llm_web_browsing", "LLM Web 閲覧", False),
    _field("ctf_flag_pattern", "CTF フラグ形式", "", redacted=True),
    _field("output_dir", "出力先", "", redacted=True),
    _field("payloads_file", "ペイロードファイル", "", redacted=True),
    _field("flows", "複数ステップフロー", [], redacted=True),
    _field("agent_mode", "Agent モード選択", True, modes=("agent",)),
    _field("hybrid_mode", "Hybrid モード選択", True, modes=("hybrid",)),
    _field("url", "対象 URL", "", modes=ALL_MODES, redacted=True),
    _field("agent_model", "Agent モデル", "", modes=("agent",), redacted=True),
    _field("agent_ollama_url", "Agent Ollama URL", "", modes=("agent",), redacted=True),
    _field("agent_max_steps", "Agent 最大ステップ", 50, modes=("agent",), constraints={"minimum": 0}),
    _field("hybrid_llm", "Hybrid 偵察 LLM", "claude", modes=("hybrid",),
           constraints={"enum": ["ollama", "claude", "openai", "openai_compatible", "gemini", "none"]}),
    _field("hybrid_model", "Hybrid 偵察モデル", "", modes=("hybrid",), redacted=True),
    _field("hybrid_ollama_url", "Hybrid Ollama URL", "", modes=("hybrid",), redacted=True),
    _field("hybrid_max_steps", "Hybrid 最大ステップ", 30, modes=("hybrid",), constraints={"minimum": 0}),
    _field("cookies", "Cookie", "", redacted=True),
    _field("low_priv_cookies", "低権限 Cookie", "", redacted=True),
    _field("mfa_email_imap_password", "IMAP パスワード", "", redacted=True),
    _field("accounts", "アカウント", [], redacted=True),
)

# Metadata extends the existing form declarations while preserving their legacy shape.
_NORMALIZED = {
    "depth": {"category": "scan", "description": "Maximum crawl depth", "type": "integer",
              "default": 2, "validation": {"minimum": 0}, "scope": "scan"},
    "auth_pass": {"category": "profile", "description": "Login password", "type": "secret",
                  "default": "", "sensitive": True, "scope": "profile"},
    "toggles.allow_state_changing_probes": {
        "key": "allow_state_changing_probes", "category": "safety",
        "description": "Permit state-changing probes", "type": "boolean",
        "default": False, "dangerous": True, "scope": "scan"},
    "llm": {"category": "analysis", "description": "LLM provider", "type": "choice",
            "default": "ollama", "choices": ("ollama", "claude", "openai", "openai_compatible", "gemini", "none"),
            "validation": {"enum": ["ollama", "claude", "openai", "openai_compatible", "gemini", "none"]},
            "scope": "instance"},
}
for _decl in FIELDS:
    _meta = {**{k: _decl[k] for k in (
        "key", "type", "default", "category", "description", "ui_exposed", "editable",
        "sensitive", "dangerous", "choices", "validation", "restart_required", "scope")},
        **_NORMALIZED.get(_decl["key"], {})}
    # Keep the legacy default/type consumed by existing form validation unchanged.
    _decl["metadata"] = {k: _meta[k] for k in (
        "key", "type", "default", "category", "description", "ui_exposed", "editable",
        "sensitive", "dangerous", "choices", "validation", "restart_required", "scope")}


def _envelope(kind: str) -> dict:
    return {"schema_version": SCHEMA_VERSION, "manifest_kind": kind,
            "declaration_only": True, "execution_coverage_claimed": False}


def build_settings_schema() -> dict:
    """個別 config や環境変数を読まず宣言から生成する。"""
    return {**_envelope("settings_schema"), "modes": list(ALL_MODES),
            "profiles": deepcopy(PROFILES),
            "fields": deepcopy(list(FIELDS))}


def validate_settings_schema(schema: Any, *, expected_schema_version=SCHEMA_VERSION) -> list[str]:
    """未知版・欠落・宣言の改変を拒否し、入力値はエラーへ反射しない。"""
    if not isinstance(schema, dict):
        return ["Schema must be an object"]
    if "schema_version" not in schema:
        return ["Missing schema_version"]
    if schema["schema_version"] != expected_schema_version:
        return ["Schema version mismatch"]
    # Python の等値比較では False == 0 になるため、JSON の型も照合する。
    try:
        valid = json.dumps(schema, sort_keys=True, allow_nan=False) == json.dumps(
            build_settings_schema(), sort_keys=True, allow_nan=False)
    except (TypeError, ValueError):
        valid = False
    return [] if valid else ["Missing or invalid settings declarations"]


def validate_ui_exposure(fields) -> list[str]:
    """Unexposed declarations must explain why the UI omits them."""
    return [field.get("key", "<unknown>") for field in fields
            if field.get("metadata", {}).get("ui_exposed") is False
            and not field.get("metadata", {}).get("ui_exposure_reason", "").strip()]


def _valid(value: Any, field: dict) -> bool:
    kind = field["type"]
    types = {"boolean": (bool,), "integer": (int,), "number": (int, float),
             "string": (str,), "array": (list,), "object": (dict,)}
    if type(value) not in types[kind]:
        return False
    constraints = field["constraints"]
    if "enum" in constraints and value not in constraints["enum"]:
        return False
    if kind in ("integer", "number"):
        if isinstance(value, float) and not math.isfinite(value):
            return False
        if "minimum" in constraints and value < constraints["minimum"]:
            return False
        if "exclusiveMinimum" in constraints and value <= constraints["exclusiveMinimum"]:
            return False
    if field["key"] == "checks":
        from wscan.scanners import SCANNERS
        return all(isinstance(v, str) and v in SCANNERS for v in value)
    return True


def build_effective_config(defaults: Mapping | None = None, *, mode="normal", profile=None) -> dict:
    """フォーム初期値→profile の宣言解決。起動引数・環境変数の最終値ではない。"""
    if mode not in ALL_MODES:
        raise ValueError("Unknown mode")
    if profile is not None and profile not in PROFILES:
        raise ValueError("Unknown profile")
    if mode == "agent" and profile is not None:
        raise ValueError("Scan profile is unavailable in agent mode")
    source = defaults if isinstance(defaults, Mapping) else {}
    values, redacted, invalid = {}, [], []
    for field in FIELDS:
        if mode not in field["applicable_modes"]:
            continue
        key = field["key"]
        if field["redacted"]:
            values[key] = None
            redacted.append(key)
            continue
        section, dot, leaf = key.partition(".")
        parent = source.get(section, {}) if dot else source
        value = parent.get(leaf if dot else key, field["default"]) if isinstance(parent, Mapping) else field["default"]
        if not _valid(value, field):
            invalid.append(key)
            value = field["default"]
        values[key] = deepcopy(value)
    diff = {}
    if profile is not None:
        for key, value in PROFILES[profile]["overrides"].items():
            if key in values and key not in redacted and values[key] != value:
                diff[key] = {"before": deepcopy(values[key]), "after": deepcopy(value)}
                values[key] = deepcopy(value)
    return {**_envelope("effective_config"), "mode": mode,
            "profile": profile, "values": values, "diff": diff,
            "redacted_keys": redacted, "invalid_keys": invalid,
            "resolution_scope": "serve_form_defaults_then_scan_profile"}
