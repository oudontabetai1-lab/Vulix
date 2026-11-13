from pathlib import Path

import pytest
import yaml

from scripts.readme_install import END, START, extract_install, main


def marked(body: str) -> str:
    return f"intro\n{START}\n{body}\n{END}\n"


def test_extract_preserves_commands_without_executing_them():
    commands = 'python3 -m pip install -r requirements.txt\n# comment\nprintf "$HOME"'
    assert extract_install(marked(f"```bash\n{commands}\n```")) == commands + "\n"


@pytest.mark.parametrize("text", [
    "", START, END, f"{END}\n{START}",
    marked("```bash\necho ok\n```") + START,
    marked("```bash\necho ok\n```") + END,
    marked("```sh\necho ok\n```"),
    marked("```bash\n# only a comment\n```"),
    marked("```bash\necho ok\n```\n```bash\necho extra\n```"),
    marked("```bash\necho ok"),
])
def test_malformed_block_has_source_location(text):
    with pytest.raises(ValueError, match=r"README\.md:\d+:"):
        extract_install(text)


def test_unreadable_readme_has_source_location(monkeypatch, capsys):
    def unreadable(*args, **kwargs):
        raise UnicodeDecodeError("utf-8", b"\xff", 0, 1, "invalid byte")

    monkeypatch.setattr(Path, "read_text", unreadable)
    assert main() == 1
    captured = capsys.readouterr()
    assert captured.out == ""
    assert captured.err.startswith("README.md:1:")


def test_ci_runs_canonical_readme_install_before_test_dependencies():
    root = Path(__file__).resolve().parents[1]
    commands = extract_install((root / "README.md").read_text())
    assert "python3 -m pip install -r requirements.txt\n" in commands
    assert "python3 -m playwright install --with-deps chromium\n" in commands
    steps = yaml.safe_load((root / ".github/workflows/ci.yml").read_text())["jobs"]["test"]["steps"]
    install = next(i for i, step in enumerate(steps) if step.get("name") == "Install Vulix from README")
    assert steps[install]["run"].splitlines() == [
        'python scripts/readme_install.py > "$RUNNER_TEMP/vulix-install.sh"',
        'bash -e "$RUNNER_TEMP/vulix-install.sh"',
    ]
    assert "python main.py --help" in steps[install + 1]["run"]
    assert "chromium.launch(headless=True)" in steps[install + 1]["run"]
    assert steps[install + 2]["name"] == "Install test dependencies"
