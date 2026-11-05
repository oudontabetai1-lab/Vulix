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
