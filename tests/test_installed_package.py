"""Exercise packaged resources and output paths outside the source checkout."""
import os
from pathlib import Path
import subprocess
import sys


def test_noneditable_install_resources_and_output(tmp_path):
    root = Path(__file__).resolve().parents[1]
    installed = tmp_path / "site"
    subprocess.run(
        [sys.executable, "-m", "pip", "install", "--no-deps",
         "--no-build-isolation", "--target", str(installed), str(root)],
        check=True, capture_output=True, text=True,
    )
    env = dict(os.environ, PYTHONPATH=str(installed))
    subprocess.run([sys.executable, "-c", '''
from pathlib import Path
import main
import wscan.engine as engine
import wscan.agent_engine as agent
import wscan.monitor as monitor
import wscan.report as report
from fastapi.testclient import TestClient
assert Path(main.__file__).parent.name == "site"
assert main._CONFIG_PATH.is_file()
assert report.TEMPLATES_DIR.joinpath("dashboard.html").is_file()
assert engine.OUTPUT_BASE == agent.OUTPUT_BASE == monitor.OUTPUT_BASE == Path.cwd() / "output"
scan = engine.ScanEngine("http://127.0.0.1:1", llm_provider="none", checks=["xss"], open_report=False)
assert scan.default_payloads["xss"]
assert scan.output_dir.parent == Path.cwd() / "output"
assert scan.output_dir.is_dir()
explicit = engine.ScanEngine("http://127.0.0.1:1", llm_provider="none", checks=["xss"], output_dir="custom", open_report=False)
assert explicit.output_dir == Path("custom")
assert explicit.output_dir.is_dir()
with TestClient(monitor.MonitorServer().app) as client:
    response = client.get("/")
    assert response.status_code == 200
    assert "Dashboard not found" not in response.text
'''], cwd=tmp_path, env=env, check=True, capture_output=True, text=True)
