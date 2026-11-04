"""Report-only inventory of settings exposed by the CLI, YAML, runtime, and UI."""
from __future__ import annotations

import ast
from collections import Counter
from pathlib import Path
import re
import sys
from pathlib import Path

import yaml

ALIASES = {
    "include_registration": "toggles.skip_registration",
    "browser.header_scope_enforce": "header_scope_enforce",
    "browser.popup_header_intercept": "popup_header_intercept",
    "llm.provider": "llm",
    "auth.auth_pass": "auth_pass",
    "scan.depth": "depth",
    "scan.allow_state_changing_probes": "allow_state_changing_probes",
    "toggles.allow_state_changing_probes": "allow_state_changing_probes",
}
EXCLUDED = {"help": "argparse help is not a setting", "command": "internal subcommand selector"}


def resolve(name: str, schema_keys: set[str]) -> str | None:
    canonical = ALIASES.get(name, name)
    return canonical if canonical in schema_keys else None


def flatten_yaml(value, prefix=""):
    out = []
    if isinstance(value, dict):
        for key, child in value.items():
            path = f"{prefix}.{key}" if prefix else str(key)
            if isinstance(child, dict):
                out.extend(flatten_yaml(child, path))
            else:
                out.append(path)
    return out


def argparse_destinations(source: str) -> list[str]:
    tree = ast.parse(source)
    found = []
    for call in (n for n in ast.walk(tree) if isinstance(n, ast.Call)
        and isinstance(n.func, ast.Attribute) and n.func.attr == "add_argument"
                 and isinstance(n.func.value, ast.Name) and n.func.value.id == "scan"):
        options = [a.value for a in call.args if isinstance(a, ast.Constant) and isinstance(a.value, str)]
        if not options:
            continue
        dest = next((kw.value.value for kw in call.keywords if kw.arg == "dest"
                     and isinstance(kw.value, ast.Constant)), None)
        if not dest:
            long_opt = next((o for o in options if o.startswith("--")), options[0])
            dest = long_opt.lstrip("-").replace("-", "_")
        found.append(dest)
    return found


def inventory(root: Path) -> dict[str, list[str]]:
    yaml_data = yaml.safe_load((root / "config/wscan.yaml").read_text()) or {}
    source = (root / "main.py").read_text()
    dashboard = (root / "templates/dashboard.html").read_text()
    engine = ast.parse((root / "wscan/engine.py").read_text())
    runtime = []
    for node in ast.walk(engine):
        if isinstance(node, ast.FunctionDef) and node.name == "__init__":
            runtime.extend(a.arg for a in node.args.args if a.arg not in {"self", "args", "kwargs"})
    toggle_block = re.search(r"const cfgToggles\s*=\s*\{(.*?)\n\};", dashboard, re.S)
    toggle_keys = re.findall(r"^\s*([a-z_]+)\s*:", toggle_block.group(1), re.M) if toggle_block else []
    payload_block = re.search(r"const (?:config|cfg|scanConfig)\s*=\s*\{(.*?)\n\s*\};", dashboard, re.S)
    payload_keys = re.findall(r"^\s*([a-z_]+)\s*:", payload_block.group(1), re.M) if payload_block else []
    features = flatten_yaml(yaml_data.get("features", {}), "features")
    return {"cli": argparse_destinations(source), "yaml": flatten_yaml(yaml_data),
            "runtime": sorted(set(runtime)), "features": features,
            "cfgToggles": toggle_keys, "scan_payload": payload_keys}


def parity_warnings(surfaces: dict[str, list[str]], schema_keys: set[str]) -> list[str]:
    warnings = []
    seen_aliases = Counter(ALIASES.values())
    warnings.extend(f"duplicate alias target: {key}" for key, n in seen_aliases.items() if n > 1)
    resolved = set()
    for surface, names in surfaces.items():
        for name in names:
            if name in EXCLUDED:
                continue
            key = resolve(name, schema_keys)
            if key:
                resolved.add(key)
            else:
                warnings.append(f"{surface}: unresolved setting {name}")
    warnings.extend(f"stale schema key: {key}" for key in sorted(schema_keys - resolved))
    return warnings


def main(root: Path = Path(__file__).resolve().parents[1]) -> int:
    sys.path.insert(0, str(root))
    from wscan.settings_schema import FIELDS
    keys = {field["metadata"]["key"] for field in FIELDS}
    for warning in parity_warnings(inventory(root), keys):
        print(f"WARNING: {warning}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
