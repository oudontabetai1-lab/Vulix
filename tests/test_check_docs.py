import json
from pathlib import Path
import shutil
import subprocess

import httpx
import pytest

import scripts.check_docs as check_docs
from scripts.check_docs import validate


FIXTURES = Path(__file__).parent / "fixtures" / "docs_validation"


def test_valid_markdown_references_and_cli_examples_are_offline_and_inert(monkeypatch):
    root = FIXTURES / "valid"
    monkeypatch.setattr(check_docs.subprocess, "run",
                        lambda *args, **kwargs: pytest.fail("Markdown shell text must never execute"))
    findings = validate(root, [Path("README.md"), Path("docs/guide.md"),
                               Path("docs/space file.md")])
    assert findings == []


def test_missing_files_images_anchors_and_cli_options_are_actionable():
    findings = validate(FIXTURES / "invalid", [Path("README.md"), Path("docs/target.md")])
    rendered = "\n".join(map(str, findings))
    assert "README.md:3: absent.md: local target does not exist" in rendered
    assert "README.md:4: absent.png: local target does not exist" in rendered
    assert "README.md:5: docs/target.md#absent: anchor #absent does not exist" in rendered
    assert "README.md:8: --not-a-vulix-option: option is not defined" in rendered
    assert "README.md:11: --not-inline: option is not defined" in rendered


def test_malformed_and_undefined_reference_syntax_fails_explicitly():
    findings = validate(FIXTURES / "malformed", [Path("README.md")])
    reasons = "\n".join(item.reason for item in findings)
    assert "malformed or unsupported link syntax" in reasons
    assert "image is missing a Markdown destination" in reasons
    assert "undefined Markdown reference" in reasons
    assert "malformed CLI example" in reasons


def test_traversal_and_symlinks_outside_repo_are_rejected_without_reading(tmp_path):
    root = tmp_path / "repo"
    root.mkdir()
    outside = tmp_path / "private.md"
    outside.write_text("# private", encoding="utf-8")
    (root / "README.md").write_text(
        "[traversal](../private.md) [symlink](docs/escape.md)\n", encoding="utf-8")
    docs = root / "docs"
    docs.mkdir()
    (docs / "escape.md").symlink_to(outside)

    findings = validate(root, [Path("README.md")])
    assert len(findings) == 2
    assert all("escapes repository root" in item.reason for item in findings)


def test_unsupported_link_schemes_and_symlink_loops_fail_closed(tmp_path):
    root = tmp_path / "repo"
    root.mkdir()
    (root / "README.md").write_text(
        "[script](javascript:alert(1)) [loop](loop.md)\n", encoding="utf-8")
    (root / "loop.md").symlink_to(root / "loop.md")
    findings = validate(root, [Path("README.md")])
    assert any("unsupported link scheme" in item.reason for item in findings)
    assert any("cannot safely resolve local target" in item.reason for item in findings)


def test_outside_symlink_cannot_be_selected_as_a_markdown_document(tmp_path):
    root = tmp_path / "repo"
    root.mkdir()
    outside = tmp_path / "private.md"
    outside.write_text("# private", encoding="utf-8")
    (root / "README.md").symlink_to(outside)
    findings = validate(root, [Path("README.md")])
    assert len(findings) == 1
    assert "Markdown document escapes repository root" in findings[0].reason


def test_real_cli_command_returns_nonzero_with_location_for_broken_fixture(tmp_path, capsys):
    repo = tmp_path / "repo"
    shutil.copytree(FIXTURES / "invalid", repo)
    subprocess.run(["git", "init", "-q", str(repo)], check=True)
    subprocess.run(["git", "-C", str(repo), "add", "README.md", "docs/target.md"], check=True)

    from scripts.check_docs import main
    assert main(["--root", str(repo)]) == 1
    output = capsys.readouterr().err
    assert "README.md:3: absent.md" in output
    assert "--not-a-vulix-option" in output


def test_valid_yaml_config_example_passes_cleanly(tmp_path):
    root = tmp_path / "repo"
    root.mkdir()
    (root / "README.md").write_text("""# Guide
```yaml
scan:
  depth: 2
  checks:
    - sqli
    - xss
browser:
  headless: true
```
""", encoding="utf-8")
    findings = validate(root, [Path("README.md")])
    assert findings == []


def test_optional_allowlisted_config_keys_are_permitted(tmp_path):
    root = tmp_path / "repo"
    root.mkdir()
    (root / "README.md").write_text("""# Advanced Config
```yaml
# config/wscan.yaml
scan:
  allow_state_changing_probes: true
features:
  tls_scan: true
  token_lifecycle_manager: true
llm:
  models:
    planner: gpt-4o
    payload: claude-3-haiku
accounts:
  list:
    - username: admin
      password: secret
      role: admin
```
""", encoding="utf-8")
    findings = validate(root, [Path("README.md")])
    assert findings == []


def test_non_config_yaml_blocks_are_ignored(tmp_path):
    root = tmp_path / "repo"
    root.mkdir()
    (root / "README.md").write_text("""# Batch Guide
```yaml
global:
  depth: 2
  headless: true
targets:
  - url: https://app.example.invalid
```
""", encoding="utf-8")
    findings = validate(root, [Path("README.md")])
    assert findings == []


def test_unknown_and_typo_config_key_reports_line_path_and_nearest_key(tmp_path):
    root = tmp_path / "repo"
    root.mkdir()
    (root / "README.md").write_text("""# Documentation
Some text before.
```yaml
scan:
  depht: 3
  request_dlay: 1.0
  completely_unknown_setting: 42
browser:
  headles: true
```
""", encoding="utf-8")
    findings = validate(root, [Path("README.md")])
    rendered = "\n".join(map(str, findings))
    assert "README.md:5: scan.depht: unknown configuration key path (nearest valid key: 'scan.depth')" in rendered
    assert "README.md:6: scan.request_dlay: unknown configuration key path (nearest valid key: 'scan.request_delay')" in rendered
    assert "README.md:7: scan.completely_unknown_setting: unknown configuration key path" in rendered
    assert "README.md:9: browser.headles: unknown configuration key path (nearest valid key: 'browser.headless')" in rendered


def test_malformed_yaml_config_example_fails_explicitly(tmp_path):
    root = tmp_path / "repo"
    root.mkdir()
    (root / "README.md").write_text("""# Broken YAML
```yaml # config/wscan.yaml
scan:
  checks: [unclosed list
```
""", encoding="utf-8")
    findings = validate(root, [Path("README.md")])
    assert len(findings) == 1
    assert findings[0].line == 3
    assert "malformed YAML configuration example" in findings[0].reason


def test_pure_functions_config_drift_detection():
    from scripts.check_docs import (
        collect_config_key_paths,
        extract_yaml_blocks,
        find_nearest_key,
        is_vulix_config_example,
        compare_config_example_keys,
    )
    raw_config = {
        "scan": {"depth": 2, "checks": ["sqli"]},
        "browser": {"headless": False},
    }
    keys = collect_config_key_paths(raw_config)
    assert keys == {"scan", "scan.depth", "scan.checks", "browser", "browser.headless"}

    # extract_yaml_blocks
    blocks = extract_yaml_blocks("prose\n```yaml\nkey: val\n```\n")
    assert len(blocks) == 1
    assert blocks[0][0] == 3
    assert blocks[0][2] == "key: val\n"

    # is_vulix_config_example
    assert is_vulix_config_example("scan:\n  depth: 2\n")
    assert is_vulix_config_example("# config/wscan.yaml\ncustom: 1\n")
    assert not is_vulix_config_example("global:\n  depth: 2\n")

    # find_nearest_key
    assert find_nearest_key("scan.depht", keys) == "scan.depth"
    assert find_nearest_key("browser.headles", keys) == "browser.headless"

    # compare_config_example_keys
    sample = "scan:\n  depht: 2\n"
    diff = compare_config_example_keys(sample, 10, "doc.md", keys)
    assert len(diff) == 1
    assert diff[0].path == "doc.md"
    assert diff[0].line == 11
    assert diff[0].target == "scan.depht"
    assert "scan.depth" in diff[0].reason


def test_external_link_status_classifier():
    from scripts.check_docs import classify_http_status

    # 2xx / 3xx -> ok
    assert classify_http_status(200) == "ok"
    assert classify_http_status(204) == "ok"
    assert classify_http_status(301) == "ok"
    assert classify_http_status(302) == "ok"

    # Only 404 / 410 -> broken
    assert classify_http_status(404) == "broken"
    assert classify_http_status(410) == "broken"

    # 401, 403, 429, 5xx, or network errors -> inconclusive
    assert classify_http_status(401) == "inconclusive"
    assert classify_http_status(403) == "inconclusive"
    assert classify_http_status(429) == "inconclusive"
    assert classify_http_status(500) == "inconclusive"
    assert classify_http_status(502) == "inconclusive"
    assert classify_http_status(503) == "inconclusive"
    assert classify_http_status(None, exc=httpx.ConnectTimeout("timeout")) == "inconclusive"
    assert classify_http_status(None, exc=httpx.ConnectError("dns fail")) == "inconclusive"


def test_external_link_head_with_get_fallback():
    from scripts.check_docs import check_url

    # Case 1: HEAD returns 405 (method not allowed), GET returns 200
    def handler_405_then_200(request: httpx.Request):
        if request.method == "HEAD":
            return httpx.Response(405)
        return httpx.Response(200, text="OK")

    client = httpx.Client(transport=httpx.MockTransport(handler_405_then_200))
    status, classification = check_url("https://mock.test/page", client, max_retries=1, backoff_factor=0.0)
    assert status == 200
    assert classification == "ok"

    # Case 2: HEAD returns 404, but GET returns 200 (e.g. dynamic page)
    def handler_head_404_get_200(request: httpx.Request):
        if request.method == "HEAD":
            return httpx.Response(404)
        return httpx.Response(200, text="Found via GET")

    client = httpx.Client(transport=httpx.MockTransport(handler_head_404_get_200))
    status, classification = check_url("https://mock.test/page2", client, max_retries=1, backoff_factor=0.0)
    assert status == 200
    assert classification == "ok"

    # Case 3: HEAD returns 404 and GET returns 404 -> broken
    def handler_404_all(request: httpx.Request):
        return httpx.Response(404)

    client = httpx.Client(transport=httpx.MockTransport(handler_404_all))
    status, classification = check_url("https://mock.test/absent", client, max_retries=2, backoff_factor=0.0)
    assert status == 404
    assert classification == "broken"

    # Case 4: HEAD returns 410 and GET returns 410 -> broken
    def handler_410_all(request: httpx.Request):
        return httpx.Response(410)

    client = httpx.Client(transport=httpx.MockTransport(handler_410_all))
    status, classification = check_url("https://mock.test/gone", client, max_retries=2, backoff_factor=0.0)
    assert status == 410
    assert classification == "broken"

    # Case 5: 403 / 429 / 500 are inconclusive, never broken
    for code in (401, 403, 429, 500, 503):
        client = httpx.Client(transport=httpx.MockTransport(lambda req, c=code: httpx.Response(c)))
        status, classification = check_url("https://mock.test/gate", client, max_retries=1, backoff_factor=0.0)
        assert status == code
        assert classification == "inconclusive"


def test_external_link_retry_with_transient_recovery():
    from scripts.check_docs import check_url

    attempts = {"count": 0}

    def transient_handler(request: httpx.Request):
        attempts["count"] += 1
        if attempts["count"] < 3:
            raise httpx.ConnectError("Transient network drop")
        return httpx.Response(200)

    client = httpx.Client(transport=httpx.MockTransport(transient_handler))
    status, classification = check_url("https://mock.test/flaky", client, max_retries=2, backoff_factor=0.0)
    assert status == 200
    assert classification == "ok"
    assert attempts["count"] == 3


def test_external_link_skip_list_and_subdomains(tmp_path):
    from scripts.check_docs import is_host_skipped, load_skip_hosts, check_external_links

    skip_file = tmp_path / "skip.txt"
    skip_file.write_text("# Comment\nexample.com\nlocalhost\n\n", encoding="utf-8")
    skip_hosts = load_skip_hosts(skip_file)
    assert "example.com" in skip_hosts
    assert "localhost" in skip_hosts

    assert is_host_skipped("example.com", skip_hosts)
    assert is_host_skipped("app.example.com", skip_hosts)
    assert is_host_skipped("sub.app.example.com", skip_hosts)
    assert is_host_skipped("localhost", skip_hosts)
    assert is_host_skipped("localhost:8080", skip_hosts)
    assert not is_host_skipped("other.org", skip_hosts)

    # Check that skipped hosts never invoke the client
    call_log = []
    def fail_transport(request: httpx.Request):
        call_log.append(request.url)
        return httpx.Response(200)

    client = httpx.Client(transport=httpx.MockTransport(fail_transport))
    links = [("README.md:10", "https://example.com/test"), ("README.md:20", "https://app.example.com/path")]
    results = check_external_links(links, client=client, skip_hosts=skip_hosts, host_delay=0.0)
    assert len(results) == 2
    assert all(r["classification"] == "inconclusive" for r in results)
    assert call_log == []  # No requests made


def test_autolinks_and_fenced_blocks_in_external_collection(tmp_path):
    from scripts.check_docs import collect_external_links

    root = tmp_path / "repo"
    root.mkdir()
    (root / "docs").mkdir()
    (root / "docs" / "guide.md").write_text(
        "Prose autolink <https://docs.test/autolink> is collected.\n"
        "[markdown link](https://docs.test/inline) stays collected.\n"
        "`<https://docs.test/in-inline-code>` is masked.\n"
        "    <https://docs.test/indented-code> is masked.\n"
        "```\n"
        "<https://docs.test/in-fence> must be ignored.\n"
        "```\n"
        "[label](<https://docs.test/angle-dest>) counts once.\n",
        encoding="utf-8")

    pairs = collect_external_links([root / "docs" / "guide.md"], root)
    collected = {(source, url) for source, url in pairs}
    assert ("docs/guide.md:1", "https://docs.test/autolink") in collected
    assert ("docs/guide.md:2", "https://docs.test/inline") in collected
    assert ("docs/guide.md:8", "https://docs.test/angle-dest") in collected
    for masked in ("in-inline-code", "indented-code", "in-fence"):
        assert not any(url.endswith(masked) for _, url in pairs)


def test_catalog_reference_urls_are_collected(tmp_path):
    from scripts.check_docs import collect_catalog_reference_urls, collect_external_links

    root = tmp_path / "repo"
    (root / "wscan").mkdir(parents=True)
    (root / "README.md").write_text("[cwe](https://cwe.mitre.org/data/definitions/89.html)\n", encoding="utf-8")
    (root / "wscan" / "check_catalog.json").write_text(json.dumps({
        "schema_version": "1.0.0",
        "checks": {
            "sqli": {"references": [
                {"kind": "CWE", "id": "89.html",
                 "url": "https://cwe.mitre.org/data/definitions/89.html"},
                {"kind": "OWASP", "id": "wstg", "url": "https://example.com/ref"}]},
        },
    }), encoding="utf-8")

    refs = collect_catalog_reference_urls(root)
    assert refs == [
        ("wscan/check_catalog.json#sqli", "https://cwe.mitre.org/data/definitions/89.html"),
        ("wscan/check_catalog.json#sqli", "https://example.com/ref"),
    ]

    # The catalog URL also linked from README.md has both source locations and
    # is requested only once; same-source duplicates collapse.
    pairs = collect_external_links([root / "README.md"], root)
    assert len(pairs) == 3
    cwe_sources = [source for source, url in pairs if "89.html" in url]
    assert sorted(cwe_sources) == [
        "README.md:1",
        "wscan/check_catalog.json#sqli",
    ]
    assert len({url for _, url in pairs if "89.html" in url}) == 1


def test_check_external_links_checks_each_url_once_per_source(tmp_path):
    from scripts.check_docs import check_external_links

    call_log = []

    def handler(request: httpx.Request):
        call_log.append(str(request.url))
        return httpx.Response(200)

    client = httpx.Client(transport=httpx.MockTransport(handler))
    links = [
        ("README.md:1", "https://multi.test/page"),
        ("README.md:5", "https://multi.test/page"),
        ("docs/guide.md:2", "https://multi.test/page"),
        ("wscan/check_catalog.json#sqli", "https://multi.test/page"),
    ]
    results = check_external_links(links, client=client, host_delay=0.0)
    assert len(results) == 4
    assert {r["source"] for r in results} == {s for s, _ in links}
    assert all(r["classification"] == "ok" for r in results)
    # One URL, one network visit even with several source locations.
    assert call_log == ["https://multi.test/page"]


def test_skip_list_supports_wildcard_prefix_entries(tmp_path):
    from scripts.check_docs import check_external_links, is_host_skipped, load_skip_hosts

    skip_file = tmp_path / "skip.txt"
    skip_file.write_text("*.example.org\n", encoding="utf-8")
    skip_hosts = load_skip_hosts(skip_file)
    assert is_host_skipped("example.org", skip_hosts)
    assert is_host_skipped("app.example.org", skip_hosts)
    assert not is_host_skipped("example.com", skip_hosts)

    call_log = []

    def handler(request: httpx.Request):
        call_log.append(str(request.url))
        return httpx.Response(200)

    client = httpx.Client(transport=httpx.MockTransport(handler))
    results = check_external_links(
        [("README.md:1", "https://sub.example.org/page")],
        client=client, skip_hosts=skip_hosts, host_delay=0.0)
    assert len(results) == 1
    assert results[0]["classification"] == "inconclusive"
    assert call_log == []


def test_external_link_validation_artifact_and_failure_reporting(tmp_path):
    from scripts.check_docs import validate_external_links

    root = tmp_path / "repo"
    root.mkdir()
    (root / "README.md").write_text("""# Docs
[good link](https://api.test/good)
[broken link](https://api.test/bad)
[inconclusive link](https://api.test/protected)
[skipped link](https://example.com/skip)
""", encoding="utf-8")

    def mock_server(request: httpx.Request):
        url = str(request.url)
        if "/good" in url:
            return httpx.Response(200)
        if "/bad" in url:
            return httpx.Response(404)
        if "/protected" in url:
            return httpx.Response(403)
        return httpx.Response(500)

    report_file = tmp_path / "out" / "links-report.json"
    client = httpx.Client(transport=httpx.MockTransport(mock_server))

    results, findings = validate_external_links(
        root=root,
        report_path=report_file,
        client=client,
        host_delay=0.0,
        max_retries=1,
        backoff_factor=0.0,
    )

    # Check report file was written
    assert report_file.is_file()
    saved = json.loads(report_file.read_text(encoding="utf-8"))
    assert len(saved) == 4
    by_url = {item["url"]: item for item in saved}
    assert by_url["https://api.test/good"]["classification"] == "ok"
    assert by_url["https://api.test/good"]["status"] == 200
    assert by_url["https://api.test/bad"]["classification"] == "broken"
    assert by_url["https://api.test/bad"]["status"] == 404
    assert by_url["https://api.test/protected"]["classification"] == "inconclusive"
    assert by_url["https://api.test/protected"]["status"] == 403
    assert by_url["https://example.com/skip"]["classification"] == "inconclusive"

    # Only "broken" fails the job
    assert len(findings) == 1
    assert findings[0].target == "https://api.test/bad"
    assert "broken external link (HTTP 404)" in findings[0].reason


def test_external_link_cli_main(tmp_path, monkeypatch, capsys):
    root = tmp_path / "repo"
    root.mkdir()
    (root / "README.md").write_text("[good](https://api.test/ok)\n[missing](https://api.test/not-found)\n", encoding="utf-8")

    def mock_server(request: httpx.Request):
        if "not-found" in str(request.url):
            return httpx.Response(404)
        return httpx.Response(200)

    # Monkeypatch httpx.Client so no network is accessed
    real_client_init = httpx.Client
    monkeypatch.setattr(check_docs.httpx, "Client",
                        lambda *args, **kwargs: real_client_init(*args, transport=httpx.MockTransport(mock_server), **kwargs))

    report = tmp_path / "report.json"
    exit_code = check_docs.main(["--root", str(root), "--external", "--external-report", str(report)])
    assert exit_code == 1
    err = capsys.readouterr().err
    assert "broken external link (HTTP 404)" in err
    assert report.is_file()



