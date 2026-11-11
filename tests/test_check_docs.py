from pathlib import Path
import shutil
import subprocess

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

