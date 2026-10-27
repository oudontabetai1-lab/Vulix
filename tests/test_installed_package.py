"""Exercise packaged resources and output paths outside the source checkout."""
import os
from importlib.metadata import distributions
from pathlib import Path
import subprocess
import sys

from packaging.requirements import Requirement


def test_noneditable_install_resources_and_output(tmp_path):
    root = Path(__file__).resolve().parents[1]
    installed = tmp_path / "site"
    archives = tmp_path / "dist"
    subprocess.run(
        [sys.executable, "-c",
         "from setuptools.build_meta import build_sdist; import sys; build_sdist(sys.argv[1])",
         str(archives)],
        cwd=root, check=True, capture_output=True, text=True,
    )
    archive = next(archives.glob('*.tar.gz'))
    subprocess.run(
        [sys.executable, "-m", "pip", "install", "--no-deps",
         "--no-build-isolation", "--target", str(installed), str(archive)],
        check=True, capture_output=True, text=True,
    )
    metadata = next(dist.metadata for dist in distributions(path=[str(installed)])
                    if dist.metadata['Name'] == 'vulix')
    optional_files = list(root.glob('requirements-*.txt'))
    extras = {path.stem.removeprefix('requirements-'): path for path in optional_files}
    assert set(metadata.get_all('Provides-Extra', [])) == set(extras)
    requirements = [Requirement(value) for value in metadata.get_all('Requires-Dist', [])]
    for extra, path in {'': root / 'requirements.txt', **extras}.items():
        expected = {Requirement(line.strip()) for line in path.read_text().splitlines()
                    if line.strip() and not line.lstrip().startswith('#')}
        selected = []
        for requirement in requirements:
            if requirement.marker is None:
                if not extra:
                    selected.append(requirement)
            elif extra and requirement.marker.evaluate({'extra': extra}):
                selected.append(Requirement(str(requirement).split(';')[0].strip()))
        assert set(selected) == expected, extra or 'base'
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
assert monitor.TEMPLATES_DIR.joinpath("ui", "tokens.css").is_file()
assert monitor.TEMPLATES_DIR.joinpath("ui", "vulix-logo.png").is_file()
assert monitor.TEMPLATES_DIR.joinpath("ui", "vulix-logo-mark.png").is_file()
assert monitor.TEMPLATES_DIR.joinpath("ui", "favicon.png").is_file()
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
    css = client.get("/ui/tokens.css")
    assert css.status_code == 200 and "text/css" in css.headers["content-type"]
    logo = client.get("/ui/vulix-logo.png")
    assert logo.status_code == 200 and "image/png" in logo.headers["content-type"]
    mark = client.get("/ui/vulix-logo-mark.png")
    assert mark.status_code == 200 and "image/png" in mark.headers["content-type"]
'''], cwd=tmp_path, env=env, check=True, capture_output=True, text=True)
