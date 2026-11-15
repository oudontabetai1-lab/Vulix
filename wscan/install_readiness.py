"""Runtime & packaging readiness assessment for fresh installs.

This module provides deterministic verification of:
1. Core runtime prerequisites (Python version, required core modules, Playwright).
2. Optional feature pack availability (agent, mcp, tls, qr, laya).
3. Packaging and dependency contract integrity across requirements files,
   pyproject.toml, docker-compose.yml, Dockerfile, and install.bat.
"""

from __future__ import annotations

import argparse
import importlib
import importlib.util
import json
from pathlib import Path
import sys
from typing import Any, Callable

MIN_PYTHON_VERSION: tuple[int, int] = (3, 11)

CORE_RUNTIME_MODULES: dict[str, str] = {
    "playwright": "playwright",
    "fastapi": "fastapi",
    "uvicorn": "uvicorn",
    "websockets": "websockets",
    "pyyaml": "yaml",
    "jinja2": "jinja2",
    "httpx": "httpx",
    "rich": "rich",
    "aiofiles": "aiofiles",
    "python-multipart": "multipart",
    "anthropic": "anthropic",
    "cryptography": "cryptography",
}

OPTIONAL_FEATURE_PACKS: dict[str, dict[str, Any]] = {
    "agent": {
        "requirements_file": "requirements-agent.txt",
        "modules": ("browser_use", "playwright"),
        "description": "Agent browser mode with browser-use integration",
        "supported_platforms": ("linux", "darwin", "win32"),
    },
    "mcp": {
        "requirements_file": "requirements-mcp.txt",
        "modules": ("mcp",),
        "description": "OOB email sink and MFA MCP integrations",
        "supported_platforms": ("linux", "darwin", "win32"),
    },
    "tls": {
        "requirements_file": "requirements-tls.txt",
        "modules": ("sslyze", "cryptography"),
        "description": "TLS configuration assessment via sslyze",
        "supported_platforms": ("linux", "darwin", "win32"),
    },
    "qr": {
        "requirements_file": "requirements-qr.txt",
        "modules": ("cv2", "numpy", "PIL"),
        "description": "Native TOTP QR image decoding via OpenCV",
        "supported_platforms": ("linux", "darwin", "win32"),
    },
    "laya": {
        "requirements_file": "requirements-laya.txt",
        "modules": ("laya",),
        "description": "Laya non-autoregressive decision model",
        "supported_platforms": ("linux", "darwin", "win32"),
    },
}


def _default_module_probe(mod_name: str) -> bool:
    try:
        return importlib.util.find_spec(mod_name) is not None
    except Exception:
        return False


def evaluate_install_readiness(
    *,
    platform_name: str | None = None,
    python_version: tuple[int, int] | None = None,
    module_probe: Callable[[str], bool] | None = None,
    chromium_ready: bool | None = None,
) -> dict[str, Any]:
    """Evaluate core and feature pack readiness.

    Pure and deterministic when arguments are provided; defaults to
    sys.platform, sys.version_info[:2], importlib.util.find_spec(mod), and
    checking Playwright Chromium availability when omitted.
    """
    effective_platform = platform_name if platform_name is not None else sys.platform
    effective_python_version = (
        python_version if python_version is not None else sys.version_info[:2]
    )

    probe_func: Callable[[str], bool]
    if module_probe is not None:
        probe_func = module_probe
    else:
        probe_func = _default_module_probe

    if chromium_ready is None:
        if module_probe is not None:
            chromium_ready = bool(module_probe("playwright"))
        else:
            chromium_ready = _default_module_probe("playwright")

    python_ok = bool(effective_python_version >= MIN_PYTHON_VERSION)

    core_modules: dict[str, bool] = {}
    missing_core_modules: list[str] = []
    for req_name, mod_name in CORE_RUNTIME_MODULES.items():
        is_ok = False
        try:
            is_ok = bool(probe_func(mod_name))
        except Exception:
            is_ok = False

        if not is_ok and req_name != mod_name and module_probe is not None:
            try:
                is_ok = bool(probe_func(req_name))
            except Exception:
                pass

        core_modules[req_name] = is_ok
        if not is_ok:
            missing_core_modules.append(req_name)

    core_ready = bool(python_ok and not missing_core_modules and chromium_ready)

    plat_lower = effective_platform.lower()
    feature_packs: dict[str, dict[str, Any]] = {}

    for pack_id, pack_info in OPTIONAL_FEATURE_PACKS.items():
        supported_platforms = pack_info.get("supported_platforms")
        if supported_platforms is None:
            supported_on_platform = True
        else:
            supported_on_platform = any(
                plat_lower == p or plat_lower.startswith(p) for p in supported_platforms
            )

        missing_modules: list[str] = []
        for mod in pack_info["modules"]:
            mod_ok = False
            try:
                mod_ok = bool(probe_func(mod))
            except Exception:
                mod_ok = False
            if not mod_ok:
                missing_modules.append(mod)

        if not supported_on_platform:
            status = "unsupported_platform"
            available = False
        elif missing_modules:
            status = "missing_dependencies"
            available = False
        else:
            status = "ready"
            available = True

        feature_packs[pack_id] = {
            "available": available,
            "supported_on_platform": supported_on_platform,
            "missing_modules": missing_modules,
            "requirements_file": pack_info["requirements_file"],
            "status": status,
        }

    all_features_ready = bool(
        core_ready and all(pack["status"] == "ready" for pack in feature_packs.values())
    )

    if not core_ready:
        verdict = "fail"
    elif all_features_ready:
        verdict = "pass"
    else:
        verdict = "degraded"

    return {
        "python_ok": python_ok,
        "core_modules": core_modules,
        "missing_core_modules": missing_core_modules,
        "chromium_ready": bool(chromium_ready),
        "core_ready": core_ready,
        "feature_packs": feature_packs,
        "all_features_ready": all_features_ready,
        "verdict": verdict,
    }


def _load_packaging():
    req_mod = importlib.import_module("packaging.requirements")
    spec_mod = importlib.import_module("packaging.specifiers")
    ver_mod = importlib.import_module("packaging.version")
    return req_mod.Requirement, spec_mod.SpecifierSet, ver_mod.Version


def _load_toml():
    if sys.version_info >= (3, 11):
        return importlib.import_module("tomllib")
    return importlib.import_module("tomli")


def verify_packaging_contract(repo_root: Path | str) -> dict[str, Any]:
    """Verify packaging, dependency, container, and setup script integrity."""
    root = Path(repo_root).resolve()
    checks: dict[str, bool] = {
        "pyproject_dependencies": False,
        "no_conflicting_pins": False,
        "docker_compose_loopback": False,
        "dockerfile_pip_check": False,
        "install_bat_verification": False,
    }
    errors: list[str] = []

    # 1. pyproject.toml dynamic dependencies & optional-dependencies
    pyproject_file = root / "pyproject.toml"
    if not pyproject_file.is_file():
        errors.append("pyproject.toml not found")
    else:
        try:
            toml_module = _load_toml()
            pyproject_data = toml_module.loads(pyproject_file.read_text(encoding="utf-8"))

            project = pyproject_data.get("project", {})
            dynamic = project.get("dynamic", [])
            dynamic_section = (
                pyproject_data.get("tool", {})
                .get("setuptools", {})
                .get("dynamic", {})
            )

            if "dependencies" not in dynamic or "optional-dependencies" not in dynamic:
                errors.append(
                    "pyproject.toml [project] dynamic must declare 'dependencies' and 'optional-dependencies'"
                )

            deps_file = dynamic_section.get("dependencies", {}).get("file", [])
            if deps_file != ["requirements.txt"]:
                errors.append(
                    f"pyproject.toml dependencies file must be ['requirements.txt'], got {deps_file}"
                )

            declared_extras = dynamic_section.get("optional-dependencies", {})
            optional_files = sorted(root.glob("requirements-*.txt"))
            expected_extras = {
                f.stem.removeprefix("requirements-"): f.name for f in optional_files
            }

            for extra, req_filename in expected_extras.items():
                extra_conf = declared_extras.get(extra, {})
                if extra_conf.get("file") != [req_filename]:
                    errors.append(
                        f"pyproject.toml optional-dependencies[{extra}] expected ['{req_filename}'], got {extra_conf.get('file')}"
                    )

            for extra in declared_extras:
                if extra not in expected_extras:
                    errors.append(
                        f"pyproject.toml has extra '{extra}' with no corresponding requirements-{extra}.txt"
                    )

            if not any("pyproject.toml" in err for err in errors):
                checks["pyproject_dependencies"] = True
        except Exception as exc:
            errors.append(f"Failed to parse pyproject.toml: {exc}")

    # 2. No conflicting package pins across requirements*.txt
    try:
        Requirement, SpecifierSet, Version = _load_packaging()
        all_req_files = [root / "requirements.txt"] + sorted(root.glob("requirements-*.txt"))
        packages: dict[str, list[tuple[str, Any]]] = {}

        for req_file in all_req_files:
            if not req_file.is_file():
                continue
            for line in req_file.read_text(encoding="utf-8").splitlines():
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                req = Requirement(line)
                norm_name = req.name.lower().replace("_", "-")
                packages.setdefault(norm_name, []).append((req_file.name, req))

        conflicts_found = False
        for pkg_name, req_list in packages.items():
            if len(req_list) < 2:
                continue

            exact_pins: list[tuple[str, str]] = []
            specifiers: list[tuple[str, Any]] = []

            for source, req in req_list:
                for spec in req.specifier:
                    if spec.operator == "==":
                        exact_pins.append((source, spec.version))
                specifiers.append((source, req.specifier))

            if len(exact_pins) >= 2:
                versions = {ver for _, ver in exact_pins}
                if len(versions) > 1:
                    conflicts_found = True
                    details = ", ".join(f"{src}: {ver}" for src, ver in exact_pins)
                    errors.append(
                        f"Conflicting exact pins for package '{pkg_name}': {details}"
                    )

            for src_pin, pin_ver in exact_pins:
                try:
                    v = Version(pin_ver)
                except Exception:
                    continue
                for src_spec, spec_set in specifiers:
                    if src_pin != src_spec and len(spec_set) > 0:
                        if v not in spec_set:
                            conflicts_found = True
                            errors.append(
                                f"Package '{pkg_name}' pinned to =={pin_ver} in {src_pin} "
                                f"conflicts with specifier '{spec_set}' in {src_spec}"
                            )

            lower_bounds: list[Any] = []
            upper_bounds: list[Any] = []
            for _, spec_set in specifiers:
                for spec in spec_set:
                    if spec.operator in (">=", ">"):
                        try:
                            lower_bounds.append(Version(spec.version))
                        except Exception:
                            pass
                    elif spec.operator in ("<=", "<"):
                        try:
                            upper_bounds.append(Version(spec.version))
                        except Exception:
                            pass

            if lower_bounds and upper_bounds:
                max_lower = max(lower_bounds)
                min_upper = min(upper_bounds)
                if max_lower > min_upper:
                    conflicts_found = True
                    errors.append(
                        f"Mutually exclusive range bounds for package '{pkg_name}': "
                        f"lower bound {max_lower} > upper bound {min_upper}"
                    )

        if not conflicts_found:
            checks["no_conflicting_pins"] = True
    except Exception as exc:
        errors.append(f"Failed to check requirement pins: {exc}")

    # 3. docker-compose.yml loopback binding default
    compose_file = root / "docker-compose.yml"
    if not compose_file.is_file():
        errors.append("docker-compose.yml not found")
    else:
        try:
            compose_text = compose_file.read_text(encoding="utf-8")
            has_loopback_default = "${WSCAN_BIND_HOST:-127.0.0.1}" in compose_text
            has_bare_lan_port = False
            for line in compose_text.splitlines():
                stripped = line.strip()
                if stripped.startswith("-") and "8765" in stripped:
                    clean_entry = stripped.lstrip("-").strip().strip('"').strip("'")
                    if clean_entry == "8765:8765" or clean_entry.startswith("0.0.0.0:"):
                        has_bare_lan_port = True

            if not has_loopback_default:
                errors.append(
                    "docker-compose.yml must default host port bind to loopback using ${WSCAN_BIND_HOST:-127.0.0.1}"
                )
            elif has_bare_lan_port:
                errors.append(
                    "docker-compose.yml exposes unauthenticated bare LAN port without loopback default"
                )
            else:
                checks["docker_compose_loopback"] = True
        except Exception as exc:
            errors.append(f"Failed to read docker-compose.yml: {exc}")

    # 4. Dockerfile pip check and file copies
    dockerfile = root / "Dockerfile"
    if not dockerfile.is_file():
        errors.append("Dockerfile not found")
    else:
        try:
            docker_text = dockerfile.read_text(encoding="utf-8")
            copies_pyproject = (
                "pyproject.toml" in docker_text and "requirements*.txt" in docker_text
            )
            has_pip_check = "pip check" in docker_text
            if not copies_pyproject:
                errors.append("Dockerfile must copy pyproject.toml and requirements*.txt")
            if not has_pip_check:
                errors.append("Dockerfile must run 'pip check' after pip install")
            if copies_pyproject and has_pip_check:
                checks["dockerfile_pip_check"] = True
        except Exception as exc:
            errors.append(f"Failed to read Dockerfile: {exc}")

    # 5. install.bat pip check and install_readiness verification
    bat_file = root / "install.bat"
    if not bat_file.is_file():
        errors.append("install.bat not found")
    else:
        try:
            bat_text = bat_file.read_text(encoding="utf-8")
            has_bat_pip_check = "pip check" in bat_text
            has_readiness_check = "wscan.install_readiness" in bat_text
            if not has_bat_pip_check:
                errors.append("install.bat must run 'python -m pip check'")
            if not has_readiness_check:
                errors.append("install.bat must verify runtime readiness via 'wscan.install_readiness'")
            if has_bat_pip_check and has_readiness_check:
                checks["install_bat_verification"] = True
        except Exception as exc:
            errors.append(f"Failed to read install.bat: {exc}")

    ok = bool(all(checks.values()) and not errors)
    return {
        "ok": ok,
        "checks": checks,
        "errors": errors,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Vulix install readiness & dependency validator"
    )
    parser.add_argument(
        "--require-core",
        action="store_true",
        help="Exit with non-zero status if core runtime dependencies are not satisfied",
    )
    parser.add_argument(
        "--require-all",
        action="store_true",
        help="Exit with non-zero status if any optional feature pack is not ready",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Output evaluation result as JSON",
    )
    parser.add_argument(
        "--verify-packaging",
        metavar="PATH",
        type=Path,
        nargs="?",
        const=Path.cwd(),
        default=None,
        help="Verify packaging and dependency contract for the repository",
    )
    args = parser.parse_args(argv)

    if args.verify_packaging is not None:
        contract = verify_packaging_contract(args.verify_packaging)
        if args.json:
            print(json.dumps(contract, indent=2))
        else:
            if contract["ok"]:
                print("Packaging contract verification: PASSED")
            else:
                print("Packaging contract verification: FAILED", file=sys.stderr)
                for err in contract["errors"]:
                    print(f"  - {err}", file=sys.stderr)
        return 0 if contract["ok"] else 1

    result = evaluate_install_readiness()

    if args.json:
        print(json.dumps(result, indent=2))
    else:
        status_line = f"Vulix Install Readiness: {result['verdict'].upper()}"
        print(status_line)
        print(f"  Python: {'OK' if result['python_ok'] else 'FAIL'}")
        print(
            f"  Core modules: {'OK' if not result['missing_core_modules'] else 'MISSING (' + ', '.join(result['missing_core_modules']) + ')'}"
        )
        print(f"  Chromium: {'OK' if result['chromium_ready'] else 'FAIL'}")
        print(f"  Core ready: {'YES' if result['core_ready'] else 'NO'}")
        print("  Feature packs:")
        for pack_id, pack in result["feature_packs"].items():
            print(f"    - {pack_id}: {pack['status']} (available: {pack['available']})")

    if args.require_all:
        return 0 if result["all_features_ready"] else 1
    if args.require_core:
        return 0 if result["core_ready"] else 1

    return 0 if result["core_ready"] else 1


if __name__ == "__main__":
    sys.exit(main())
