import os
from pathlib import Path
import subprocess

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
    assert "python3 -m playwright install chromium\n" in commands
    assert "--with-deps" not in commands
    steps = yaml.safe_load((root / ".github/workflows/ci.yml").read_text())["jobs"]["test"]["steps"]
    install = next(i for i, step in enumerate(steps) if step.get("name") == "Install Vulix from README")
    assert steps[install]["run"].splitlines()[0] == (
        'python scripts/readme_install.py > "$RUNNER_TEMP/vulix-install.sh"'
    )
    assert steps[install + 1]["run"] == "python3 -m playwright install-deps chromium"
    assert "python main.py --help" in steps[install + 2]["run"]
    assert "chromium.launch(headless=True)" in steps[install + 2]["run"]
    assert steps[install + 3]["name"] == "Install test dependencies"


@pytest.mark.parametrize("succeed_on", [1, 2, 3, 4])
def test_ci_install_retries_three_times_with_five_second_intervals(tmp_path, succeed_on):
    root = Path(__file__).resolve().parents[1]
    steps = yaml.safe_load((root / ".github/workflows/ci.yml").read_text())["jobs"]["test"]["steps"]
    run = next(step["run"] for step in steps if step.get("name") == "Install Vulix from README")
    mock_bash = tmp_path / "bash"
    mock_bash.write_text('''#!/bin/sh
count=0
if [ -f "$RUNNER_TEMP/count" ]; then count=$(cat "$RUNNER_TEMP/count"); fi
count=$((count + 1))
echo "$count" > "$RUNNER_TEMP/count"
[ "$count" -ge "$SUCCEED_ON" ]
''')
    mock_sleep = tmp_path / "sleep"
    mock_sleep.write_text('#!/bin/sh\necho "$1" >> "$RUNNER_TEMP/sleeps"\n')
    mock_bash.chmod(0o755)
    mock_sleep.chmod(0o755)
    env = dict(os.environ, PATH=f"{tmp_path}:{os.environ['PATH']}",
               RUNNER_TEMP=str(tmp_path), SUCCEED_ON=str(succeed_on))
    result = subprocess.run(["/bin/bash", "-e", "-c", run], cwd=root, env=env,
                            capture_output=True, text=True)
    assert (result.returncode == 0) == (succeed_on <= 3)
    attempts = min(succeed_on, 3)
    assert (tmp_path / "count").read_text().strip() == str(attempts)
    sleeps = (tmp_path / "sleeps").read_text().splitlines() if attempts > 1 else []
    assert sleeps == ["5"] * (attempts - 1)
