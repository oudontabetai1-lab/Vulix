"""Report-only inventory of settings exposed by the CLI, YAML, runtime, and UI."""
from __future__ import annotations

import ast
from collections import Counter
from pathlib import Path
import re
import sys

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
SCAN_SUBMITTERS = ("submitScanConfig", "submitAgentScan", "submitHybridScan")


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


def _literal(node, env):
    if isinstance(node, ast.Constant):
        return node.value
    if isinstance(node, ast.Name):
        return env.get(node.id)
    if isinstance(node, (ast.Tuple, ast.List)):
        values = [_literal(item, env) for item in node.elts]
        return values if all(value is not None for value in values) else None
    if isinstance(node, ast.JoinedStr):
        parts = []
        for value in node.values:
            if isinstance(value, ast.Constant) and isinstance(value.value, str):
                parts.append(value.value)
            elif isinstance(value, ast.FormattedValue):
                item = _literal(value.value, env)
                if item is None:
                    return None
                parts.append(str(item))
            else:
                return None
        return "".join(parts)
    return None


def argparse_destinations(source: str) -> list[str]:
    """Inventory scan parser action destinations, including literal generation loops."""
    found = []

    def visit(node, env):
        if isinstance(node, ast.For):
            contains_scan_action = any(
                isinstance(call, ast.Call) and isinstance(call.func, ast.Attribute)
                and call.func.attr == "add_argument" and isinstance(call.func.value, ast.Name)
                and call.func.value.id == "scan"
                for call in ast.walk(node)
            )
            if not contains_scan_action:
                for child in ast.iter_child_nodes(node):
                    visit(child, env)
                return
            values = _literal(node.iter, env)
            if isinstance(node.target, ast.Name) and values is not None:
                for value in values:
                    visit_block(node.body, {**env, node.target.id: value})
            else:
                found.append("<dynamic-add_argument-loop>")
            visit_block(node.orelse, env)
            return
        if (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
                and node.func.attr == "add_argument" and isinstance(node.func.value, ast.Name)
                and node.func.value.id == "scan"):
            options = [_literal(arg, env) for arg in node.args]
            options = [value for value in options if isinstance(value, str)]
            if not options:
                found.append("<dynamic-add_argument>")
                return
            explicit_dest = next((_literal(kw.value, env) for kw in node.keywords if kw.arg == "dest"), None)
            if explicit_dest is not None:
                dest = explicit_dest
            else:
                option = next((value for value in options if value.startswith("--")), options[0])
                dest = option.lstrip("-").replace("-", "_")
            found.append(dest)
            return
        for child in ast.iter_child_nodes(node):
            visit(child, env)

    def visit_block(nodes, env):
        for node in nodes:
            visit(node, env)

    visit(ast.parse(source), {})
    return found


def _balanced_end(source: str, opening: int) -> int:
    """Return the matching brace, ignoring JS strings and comments."""
    depth = 0
    quote = None
    escaped = False
    line_comment = block_comment = False
    i = opening
    while i < len(source):
        char, following = source[i], source[i + 1] if i + 1 < len(source) else ""
        if line_comment:
            if char == "\n":
                line_comment = False
        elif block_comment:
            if char == "*" and following == "/":
                block_comment = False
                i += 1
        elif quote:
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == quote:
                quote = None
        elif char in "'\"`":
            quote = char
        elif char == "/" and following == "/":
            line_comment = True
            i += 1
        elif char == "/" and following == "*":
            block_comment = True
            i += 1
        elif char == "{":
            depth += 1
        elif char == "}":
            depth -= 1
            if depth == 0:
                return i
        i += 1
    raise ValueError("unclosed JavaScript object")


def _object_keys(object_source: str) -> list[str]:
    keys = []
    depth = 1
    for line in object_source.splitlines():
        match = re.match(r"^(\s*)([A-Za-z_$][\w$]*)\s*:", line)
        if depth == 1 and match:
            keys.append(match.group(2))
        # Payload properties are one per line; counting braces on the line
        # keeps nested objects from becoming top-level settings.
        code = re.sub(r"(['\"`]).*?\1", "", line)
        code = code.split("//", 1)[0]
        depth += code.count("{") - code.count("}")
    return keys


def scan_payloads(source: str) -> dict[str, list[str]]:
    payloads = {}
    for name in SCAN_SUBMITTERS:
        function = re.search(r"\bfunction\s+" + re.escape(name) + r"\s*\([^)]*\)\s*\{", source)
        if not function:
            payloads[name] = ["<missing-submit-function>"]
            continue
        function_open = source.find("{", function.start())
        function_end = _balanced_end(source, function_open)
        body = source[function_open + 1:function_end]
        declaration = re.search(r"\bconst\s+config\s*=\s*\{", body)
        if not declaration:
            payloads[name] = ["<missing-config-object>"]
            continue
        object_open = function_open + 1 + body.find("{", declaration.start())
        object_end = _balanced_end(source, object_open)
        payloads[name] = _object_keys(source[object_open + 1:object_end])
    return payloads


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
    payloads = scan_payloads(dashboard)
    features = flatten_yaml(yaml_data.get("features", {}), "features")
    return {"cli": argparse_destinations(source), "yaml": flatten_yaml(yaml_data),
            "runtime": sorted(set(runtime)), "features": features,
            "cfgToggles": toggle_keys, **{f"scan_payload:{name}": keys for name, keys in payloads.items()}}


def parity_warnings(surfaces: dict[str, list[str]], schema_keys: set[str]) -> list[str]:
    warnings = []
    resolved = set()
    for surface, names in surfaces.items():
        warnings.extend(f"{surface}: duplicate inventory name {name}"
                        for name, count in Counter(names).items() if count > 1)
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
