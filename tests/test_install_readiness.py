import json
from pathlib import Path
import shutil
import subprocess
import sys

import pytest

from wscan.install_readiness import (
    CORE_RUNTIME_MODULES,
    MIN_PYTHON_VERSION,
    OPTIONAL_FEATURE_PACKS,
    evaluate_install_readiness,
    verify_packaging_contract,
)


def test_evaluate_install_readiness_all_present():
    """All core and optional modules present yields pass verdict."""
    res = evaluate_install_readiness(
        platform_name="darwin",
        python_version=(3, 12),
        module_probe=lambda mod: True,
        chromium_ready=True,
    )
    assert res["python_ok"] is True
    assert res["core_ready"] is True
    assert res["all_features_ready"] is True
    assert res["verdict"] == "pass"
    assert res["missing_core_modules"] == []
    for pack in res["feature_packs"].values():
        assert pack["status"] == "ready"
        assert pack["available"] is True
        assert pack["missing_modules"] == []


def test_evaluate_install_readiness_optional_missing():
    """Core ready but optional module missing yields degraded verdict."""
    missing = {"laya", "sslyze"}
    res = evaluate_install_readiness(
        platform_name="linux",
        python_version=(3, 11),
        module_probe=lambda mod: mod not in missing,
        chromium_ready=True,
    )
    assert res["python_ok"] is True
    assert res["core_ready"] is True
    assert res["all_features_ready"] is False
    assert res["verdict"] == "degraded"
    assert res["feature_packs"]["laya"]["status"] == "missing_dependencies"
    assert res["feature_packs"]["laya"]["available"] is False
    assert res["feature_packs"]["laya"]["missing_modules"] == ["laya"]
    assert res["feature_packs"]["tls"]["status"] == "missing_dependencies"
    assert res["feature_packs"]["tls"]["available"] is False
    assert res["feature_packs"]["tls"]["missing_modules"] == ["sslyze"]
    assert res["feature_packs"]["agent"]["status"] == "ready"
    assert res["feature_packs"]["mcp"]["status"] == "ready"
    assert res["feature_packs"]["qr"]["status"] == "ready"


@pytest.mark.parametrize("missing_mod", ["cryptography", "httpx", "playwright"])
def test_evaluate_install_readiness_missing_core_module(missing_mod):
    """Missing any core module yields fail verdict."""
    res = evaluate_install_readiness(
        platform_name="darwin",
        python_version=(3, 11),
        module_probe=lambda mod: mod != missing_mod,
        chromium_ready=True,
    )
    assert res["core_ready"] is False
    assert res["all_features_ready"] is False
    assert res["verdict"] == "fail"
    assert missing_mod in res["missing_core_modules"]


def test_evaluate_install_readiness_old_python():
    """Python version below 3.11 yields fail verdict."""
    res = evaluate_install_readiness(
        platform_name="darwin",
        python_version=(3, 10),
        module_probe=lambda mod: True,
        chromium_ready=True,
    )
    assert res["python_ok"] is False
    assert res["core_ready"] is False
    assert res["all_features_ready"] is False
    assert res["verdict"] == "fail"


def test_evaluate_install_readiness_chromium_not_ready():
    """Chromium unavailable yields core_ready=False and fail verdict."""
    res = evaluate_install_readiness(
        platform_name="darwin",
        python_version=(3, 11),
        module_probe=lambda mod: True,
        chromium_ready=False,
    )
    assert res["python_ok"] is True
    assert res["chromium_ready"] is False
    assert res["core_ready"] is False
    assert res["verdict"] == "fail"


def test_evaluate_install_readiness_unsupported_platform():
    """Unsupported platform never claims all_features_ready=True."""
    res = evaluate_install_readiness(
        platform_name="solaris",
        python_version=(3, 11),
        module_probe=lambda mod: True,
        chromium_ready=True,
    )
    assert res["core_ready"] is True
    assert res["all_features_ready"] is False
    assert res["verdict"] == "degraded"
    for pack in res["feature_packs"].values():
        assert pack["supported_on_platform"] is False
        assert pack["status"] == "unsupported_platform"
        assert pack["available"] is False


def test_cli_subprocess_require_core_json():
    """Executing CLI with --require-core --json returns 0 and valid JSON with core_ready: true."""
    root = Path(__file__).resolve().parents[1]
    cmd = [sys.executable, "-m", "wscan.install_readiness", "--require-core", "--json"]
    proc = subprocess.run(
        cmd,
        cwd=root,
        capture_output=True,
        text=True,
        check=False,
    )
    assert proc.returncode == 0, f"CLI stderr: {proc.stderr}"
    data = json.loads(proc.stdout)
    assert data["python_ok"] is True
    assert data["core_ready"] is True
    assert data["chromium_ready"] is True
    assert isinstance(data["core_modules"], dict)
    assert isinstance(data["feature_packs"], dict)


def test_verify_packaging_contract_current_repo():
    """Current repository passes packaging contract verification cleanly."""
    root = Path(__file__).resolve().parents[1]
    result = verify_packaging_contract(root)
    assert result["ok"] is True, f"Packaging contract errors: {result['errors']}"
    assert result["errors"] == []
    for check_name, check_ok in result["checks"].items():
        assert check_ok is True, f"Check failed: {check_name}"


def test_verify_packaging_contract_negative_bare_docker_port(tmp_path):
    """docker-compose.yml exposing bare 8765:8765 fails contract verification."""
    root = Path(__file__).resolve().parents[1]
    _copy_repo_minimal(root, tmp_path)
    compose_path = tmp_path / "docker-compose.yml"
    text = compose_path.read_text(encoding="utf-8")
    modified = text.replace(
        '${WSCAN_BIND_HOST:-127.0.0.1}:${WSCAN_PORT:-8765}:8765',
        '8765:8765',
    )
    compose_path.write_text(modified, encoding="utf-8")

    result = verify_packaging_contract(tmp_path)
    assert result["ok"] is False
    assert result["checks"]["docker_compose_loopback"] is False
    assert any("docker-compose.yml" in err for err in result["errors"])


def test_verify_packaging_contract_negative_install_bat_omits_pip_check(tmp_path):
    """install.bat omitting pip check fails contract verification."""
    root = Path(__file__).resolve().parents[1]
    _copy_repo_minimal(root, tmp_path)
    bat_path = tmp_path / "install.bat"
    text = bat_path.read_text(encoding="utf-8")
    modified = text.replace("python -m pip check\nif errorlevel 1 (\n    echo [ERROR] Dependency consistency check (pip check) failed.\n    pause\n    exit /b 1\n)", "")
    modified = modified.replace("python -m pip check\r\nif errorlevel 1 (\r\n    echo [ERROR] Dependency consistency check (pip check) failed.\r\n    pause\r\n    exit /b 1\r\n)", "")
    bat_path.write_text(modified, encoding="utf-8")

    result = verify_packaging_contract(tmp_path)
    assert result["ok"] is False
    assert result["checks"]["install_bat_verification"] is False
    assert any("install.bat must run 'python -m pip check'" in err for err in result["errors"])


def test_verify_packaging_contract_negative_install_bat_omits_readiness(tmp_path):
    """install.bat omitting install_readiness check fails contract verification."""
    root = Path(__file__).resolve().parents[1]
    _copy_repo_minimal(root, tmp_path)
    bat_path = tmp_path / "install.bat"
    text = bat_path.read_text(encoding="utf-8")
    modified = text.replace("python -m wscan.install_readiness --require-core", "echo skipping")
    bat_path.write_text(modified, encoding="utf-8")

    result = verify_packaging_contract(tmp_path)
    assert result["ok"] is False
    assert result["checks"]["install_bat_verification"] is False
    assert any("wscan.install_readiness" in err for err in result["errors"])


def test_verify_packaging_contract_negative_dockerfile_omits_pip_check(tmp_path):
    """Dockerfile omitting pip check fails contract verification."""
    root = Path(__file__).resolve().parents[1]
    _copy_repo_minimal(root, tmp_path)
    dockerfile_path = tmp_path / "Dockerfile"
    text = dockerfile_path.read_text(encoding="utf-8")
    modified = text.replace("python -m pip check && \\", "")
    dockerfile_path.write_text(modified, encoding="utf-8")

    result = verify_packaging_contract(tmp_path)
    assert result["ok"] is False
    assert result["checks"]["dockerfile_pip_check"] is False
    assert any("Dockerfile must run 'pip check'" in err for err in result["errors"])


def test_verify_packaging_contract_negative_conflicting_pins(tmp_path):
    """Conflicting pins across requirements files fails contract verification."""
    root = Path(__file__).resolve().parents[1]
    _copy_repo_minimal(root, tmp_path)
    agent_req = tmp_path / "requirements-agent.txt"
    agent_req.write_text("browser-use==0.12.6\nplaywright==1.10.0\n", encoding="utf-8")

    result = verify_packaging_contract(tmp_path)
    assert result["ok"] is False
    assert result["checks"]["no_conflicting_pins"] is False
    assert any("Conflicting" in err or "conflicts with" in err for err in result["errors"])


def _copy_repo_minimal(src_root: Path, dst_root: Path) -> None:
    """Helper to copy packaging contract files to an isolated test directory."""
    files_to_copy = [
        "pyproject.toml",
        "requirements.txt",
        "docker-compose.yml",
        "Dockerfile",
        "install.bat",
    ]
    files_to_copy.extend(f.name for f in src_root.glob("requirements-*.txt"))
    for filename in files_to_copy:
        src = src_root / filename
        if src.is_file():
            shutil.copy2(src, dst_root / filename)
