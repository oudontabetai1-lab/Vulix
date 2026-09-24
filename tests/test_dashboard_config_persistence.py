from pathlib import Path


SOURCE = (Path(__file__).parents[1] / "templates" / "dashboard.html").read_text()


def test_persistence_allowlist_includes_numeric_scan_controls():
    allowlist = SOURCE.split("const CONFIG_SAVE_ALLOWLIST = [", 1)[1].split("];", 1)[0]
    assert "'max_payloads'" in allowlist
    assert "'auto_register_count'" in allowlist
    assert "max_payloads: document.getElementById('cfgMaxPayloads').value" in SOURCE
    assert "auto_register_count: document.getElementById('cfgAutoRegisterCount').value" in SOURCE


def test_all_scan_start_paths_persist_non_secret_config():
    for name, following in (
        ("submitScanConfig", "_collectFullConfigForExport"),
        ("submitAgentScan", "CONFIG_SAVE_ALLOWLIST"),
        ("submitHybridScan", "handleWafDetected"),
    ):
        body = SOURCE.split(f"function {name}()", 1)[1].split(following, 1)[0]
        assert "saveConfigToStorage();" in body


def test_url_bearing_fields_pass_through_secret_filter_before_storage():
    assert "if (parsed.username || parsed.password) return undefined;" in SOURCE
    assert "CONFIG_SENSITIVE_URL_KEY.test(key)" in SOURCE
    for field in ("cfgInputUrl", "cfgProxy", "cfgLlmBaseUrl", "cfgLoginUrl"):
        assert f"safeUrlForStorage(document.getElementById('{field}').value)" in SOURCE
    for field in ("cfgTargetUrls", "cfgAccessUrls"):
        assert f"safeUrlListForStorage(document.getElementById('{field}').value)" in SOURCE
