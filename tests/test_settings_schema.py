"""設定宣言の完全性・版・秘密値境界と既存フォーム契約を固定する。"""
import ast
from copy import deepcopy
import json
import re
import subprocess
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

import main
from wscan.monitor import MonitorServer
from wscan.settings_schema import (
    ALL_MODES, FIELDS, PROFILES, SCHEMA_VERSION, build_effective_config,
    build_settings_schema, validate_settings_schema, validate_ui_exposure,
)


def serve_defaults(cfg):
    # serve を起動せず、既存の初期値構築そのものを最小 config でも評価する。
    tree = ast.parse(Path(main.__file__).read_text())
    declaration = next(
        n.value for n in ast.walk(tree)
        if isinstance(n, ast.Assign) and isinstance(n.value, ast.Dict)
        and any(isinstance(t, ast.Attribute) and t.attr == "default_scan_cfg" for t in n.targets)
    )
    return eval(compile(ast.Expression(declaration), "serve_defaults", "eval"),
                {"_CFG": cfg, "_popup_header_intercept_default": lambda: False})


def test_complete_form_declarations_and_defaults():
    defaults = serve_defaults({})
    expected = set(defaults) - {"toggles"}
    expected.update("toggles." + k for k in defaults["toggles"])
    fields = {f["key"]: f for f in FIELDS}
    assert len(fields) == len(FIELDS)
    assert expected <= fields.keys()
    for key in expected:
        f = fields[key]
        value = defaults["toggles"][key[8:]] if key.startswith("toggles.") else defaults[key]
        assert f["default"] == (None if f["redacted"] else value), key
        assert f["label"] and f["type"] and f["applicable_modes"] and f["profiles"]
        assert isinstance(f["constraints"], dict)
    assert set(build_settings_schema()["profiles"]) == set(PROFILES)
    assert validate_settings_schema(build_settings_schema()) == []


def test_representative_normalized_metadata():
    fields = {f["key"]: f["metadata"] for f in FIELDS}
    assert (fields["depth"]["type"], fields["depth"]["default"], fields["depth"]["scope"]) == ("integer", 2, "scan")
    assert (fields["auth_pass"]["type"], fields["auth_pass"]["default"], fields["auth_pass"]["sensitive"], fields["auth_pass"]["scope"]) == ("secret", "", True, "profile")
    assert (fields["toggles.allow_state_changing_probes"]["key"], fields["toggles.allow_state_changing_probes"]["type"], fields["toggles.allow_state_changing_probes"]["dangerous"]) == ("allow_state_changing_probes", "boolean", True)
    assert (fields["llm"]["type"], fields["llm"]["default"], fields["llm"]["scope"]) == ("choice", "ollama", "instance")
    bad = deepcopy(list(FIELDS[:1]))
    bad[0]["metadata"]["ui_exposed"] = False
    assert validate_ui_exposure(bad) == ["report_lang"]
    bad[0]["metadata"]["ui_exposure_reason"] = "CLI only"
    assert validate_ui_exposure(bad) == []


def test_settings_parity_pure_alias_and_resolution():
    from scripts.check_settings_parity import ALIASES, parity_warnings, resolve
    keys = {f["metadata"]["key"] for f in FIELDS}
    assert ALIASES["include_registration"] == "toggles.skip_registration"
    assert ALIASES["browser.header_scope_enforce"] == "header_scope_enforce"
    assert resolve("allow_state_changing_probes", keys) == "allow_state_changing_probes"
    assert any("unresolved setting absent" in warning for warning in parity_warnings({"cli": ["absent"]}, keys))


@pytest.mark.parametrize("mutation", ["missing_version", "version", "field", "constraint", "claim", "extra", "wrong_type"])
def test_invalid_schema_is_rejected(mutation):
    schema = build_settings_schema()
    if mutation == "missing_version":
        del schema["schema_version"]
    elif mutation == "version":
        schema["schema_version"] = "99.0.0"
    elif mutation == "field":
        schema["fields"].pop()
    elif mutation == "constraint":
        del schema["fields"][0]["constraints"]
    elif mutation == "claim":
        schema["execution_coverage_claimed"] = True
    elif mutation == "wrong_type":
        schema["execution_coverage_claimed"] = 0
    else:
        schema["runtime_tested"] = True
    assert validate_settings_schema(schema)


@pytest.mark.parametrize("text", ["", "{}", "scan: {checks: [xss]}", "features: {unknown: true}"])
def test_old_config_defaults(tmp_path, text):
    config = tmp_path / "wscan.yaml"
    config.write_text(text)
    result = build_effective_config(serve_defaults(main._load_config(config)))
    assert result["values"]["depth"] == 2
    assert result["values"]["toggles.enable_waf_detection"] is True
    assert result["values"]["checks"] == (["xss"] if "xss" in text else ["sqli", "xss", "os"])
    assert result["invalid_keys"] == []


@pytest.mark.parametrize("mode", ALL_MODES)
def test_schema_and_effective_never_expose_secret_sentinels(mode):
    sentinel = "SECRET_SENTINEL_119"
    defaults = {f["key"]: sentinel for f in FIELDS if not f["key"].startswith("toggles.")}
    defaults["checks"] = [sentinel]
    defaults["role_models"] = {sentinel: sentinel}
    defaults["toggles"] = {f["key"][8:]: sentinel for f in FIELDS if f["key"].startswith("toggles.")}
    defaults.update({"Authorization": sentinel, "auth_token": sentinel, "cookie": sentinel,
                     "unknown": {sentinel: sentinel}})
    before = deepcopy(defaults)
    srv = MonitorServer(port=0)
    srv.default_scan_cfg = defaults
    with TestClient(srv.app) as client:
        for path in ("schema", "effective"):
            response = client.get(f"/api/v1/settings/{path}", params={"mode": mode})
            assert response.status_code == 200
            assert sentinel not in response.text
            assert response.json()["execution_coverage_claimed"] is False
    assert defaults == before
    assert not srv.scan_request_event.is_set()
    assert not srv.scan_request_data
    assert build_effective_config(defaults, mode=mode)["diff"] == {}


@pytest.mark.parametrize("profile", list(PROFILES))
@pytest.mark.parametrize("mode", ["normal", "hybrid"])
def test_profile_diff_is_declaration_only(mode, profile):
    source = {"depth": 4, "state_profile": "controlled-write"}
    before = build_effective_config(source, mode=mode)["values"]
    result = build_effective_config(source, mode=mode, profile=profile)
    for key, value in PROFILES[profile]["overrides"].items():
        assert result["values"][key] == value
    assert result["diff"] == {key: {"before": before[key], "after": value}
                              for key, value in result["values"].items() if before[key] != value}
    assert result["values"]["state_profile"] == "controlled-write"
    assert source == {"depth": 4, "state_profile": "controlled-write"}
    assert result["declaration_only"] is True
    # 同じ preset を再適用しても追加差分は無い。
    reapplied = dict(result["values"])
    reapplied["toggles"] = {k[8:]: v for k, v in reapplied.items() if k.startswith("toggles.")}
    assert build_effective_config(reapplied, mode=mode, profile=profile)["diff"] == {}


def test_mutation_cannot_corrupt_declarations():
    schema = build_settings_schema()
    schema["fields"][1]["default"].append("bad")
    result = build_effective_config()
    result["values"]["checks"].append("bad")
    assert "bad" not in build_settings_schema()["fields"][1]["default"]
    assert "bad" not in build_effective_config()["values"]["checks"]


def test_agent_profile_and_cookie_applicability():
    fields = {f["key"]: f for f in FIELDS}
    assert fields["agent_max_steps"]["profiles"] == []
    assert fields["agent_model"]["profiles"] == []
    assert fields["cookies"]["applicable_modes"] == ["normal", "hybrid"]
    assert "cookies" not in build_effective_config(mode="agent")["values"]


def test_fractional_timeouts_are_preserved():
    result = build_effective_config({"timeout": 1.25, "llm_timeout_seconds": 2.5})
    assert result["values"]["timeout"] == 1.25
    assert result["values"]["llm_timeout_seconds"] == 2.5
    assert result["invalid_keys"] == []


@pytest.mark.parametrize("value", [None, "secret", True, -1, float("nan"), float("inf"), {}, []])
def test_invalid_numeric_values_fall_back_without_echo(value):
    result = build_effective_config({"timeout": value})
    assert result["values"]["timeout"] == 30
    assert result["invalid_keys"] == ["timeout"]
    json.dumps(result, allow_nan=False)


def test_endpoints_versions_auth_readonly_and_legacy():
    srv = MonitorServer(port=0, auth_token="test-token")
    srv.default_scan_cfg = {"depth": 4, "toggles": {"headless": True}}
    with TestClient(srv.app) as client:
        for path in ("schema", "effective"):
            url = f"/api/v1/settings/{path}"
            assert client.get(url).status_code == 401
            headers = {"X-Auth-Token": "test-token"}
            assert client.get(url, headers=headers).status_code == 200
            assert client.get(url, headers=headers, params={"schema_version": SCHEMA_VERSION}).status_code == 200
            mismatch = client.get(url, headers=headers, params={"schema_version": "secret-sentinel"})
            assert mismatch.status_code == 409
            assert "secret-sentinel" not in mismatch.text
            assert client.post(url, headers=headers, json={}).status_code == 405
        for params in ({"mode": "unknown"}, {"profile": "unknown"}, {"mode": "agent", "profile": "read-only"}):
            assert client.get("/api/v1/settings/effective", headers=headers, params=params).status_code == 400
        assert client.get("/api/config/defaults", headers=headers).json() == srv.default_scan_cfg
        assert set(client.get("/api/v1/settings", headers=headers).json()) == {"notifications"}
        result = client.get("/api/v1/settings/effective", headers=headers).json()
        assert result["values"]["depth"] == 4
        assert result["values"]["toggles.headless"] is True
        agent = client.get("/api/v1/settings/effective?mode=agent", headers=headers).json()
        assert "state_profile" not in agent["values"]
        assert agent["profile"] is None


def _dashboard_function(name):
    html = (Path(main.__file__).parent / "templates/dashboard.html").read_text()
    return re.search(r"function " + name + r"\([^)]*\) \{.*?^\}", html, re.S | re.M).group()


def test_profiles_match_existing_dashboard_declarations():
    function = _dashboard_function("applyScanProfile")
    declaration = function.split("const profiles = ", 1)[1].split("\n  const p =", 1)[0].rstrip().rstrip(";")
    completed = subprocess.run(["node", "-e", "process.stdout.write(JSON.stringify(" + declaration + "))"],
                               check=True, capture_output=True, text=True)
    profiles = json.loads(completed.stdout)
    assert set(profiles) == set(PROFILES)
    for name, source in profiles.items():
        values = {k: source[k] for k in ("checks", "depth", "concurrency", "llm")}
        values["max_payloads"] = source["maxPayloads"]
        values.update({"toggles." + k: v for k, v in source["toggles"].items()})
        assert PROFILES[name]["overrides"] == values
        assert PROFILES[name]["label"] == source["label"]
        # 全 preset の上書き対象は公開可能な宣言キーである。
        fields = {f["key"]: f for f in FIELDS}
        assert all(k in fields and not fields[k]["redacted"] for k in values)


@pytest.mark.parametrize("mode,function", [("normal", "submitScanConfig"), ("agent", "submitAgentScan"),
                                            ("hybrid", "submitHybridScan")])
def test_schema_covers_actual_form_submission(mode, function):
    # 実際の送信関数を DOM stub で実行し、spread で加わる認証入力も含めて照合する。
    script = r"""
const cfgToggles = new Proxy({}, {get: () => false});
const document = {
  getElementById: id => ({value: id === 'cfgInputUrl' ? 'https://example.test' :
    id === 'cfgHeaders' ? 'Authorization: sentinel' : 'sentinel',
    style: {}, classList: {remove() {}}}),
  querySelectorAll: () => [{value: 'xss'}],
};
let sent;
const WebSocket = {OPEN: 1};
const state = {ws: {readyState: 1, send: value => {sent = JSON.parse(value).config;}}};
const VulixCapabilityReader = {defaultReader: {isReady: () => true, isScannerApplicable: () => true}};
const getSelectedChecks = () => ['xss'];
const validateTotpReadiness = () => true;
const collectRoleModels = () => ({});
const collectAccounts = () => [];
const collectFlows = () => [];
function _markOwnScan() {}
function saveConfigToStorage() {}
function setStatus() {}
function alert(message) {throw new Error(message);}
"""
    for helper in ("mfaImapFields", "mfaTotpFields", "parseHeaderText", "authHeaderFields",
                   "timeWindowFields", "mfaImapPassword", function):
        script += "\n" + _dashboard_function(helper)
    script += f"\n{function}(); process.stdout.write(JSON.stringify(Object.keys(sent)));"
    completed = subprocess.run(["node", "-e", script], check=True, capture_output=True, text=True)
    submitted = set(json.loads(completed.stdout))
    aliases = {"community_payloads": "enable_community_payloads", "component_intel": "enable_component_intel",
               "tls_scan": "enable_tls_scan"}
    declared = {aliases.get(f["key"][8:], f["key"][8:]) if f["key"].startswith("toggles.") else f["key"]
                for f in FIELDS if mode in f["applicable_modes"]}
    assert submitted <= declared, submitted - declared
