"""Validate local Markdown references, documented CLI options, and configuration examples offline."""
from __future__ import annotations

import argparse
from contextlib import redirect_stderr, redirect_stdout
from dataclasses import dataclass
import difflib
import html
import io
from pathlib import Path
import re
import shlex
import subprocess
import sys
from urllib.parse import unquote, urlsplit

import yaml

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
_FENCE = re.compile(r"^ {0,3}(`{3,}|~{3,})")
_REFERENCE = re.compile(r"^ {0,3}\[([^]]+)\]:\s*(?:<([^>]+)>|(\S+))", re.M)
_INLINE = re.compile(r"(!?)\[([^]\n]+)\]\(\s*(<[^>\n]*>|(?:\\.|[^()\s]|\([^()\n]*\))*)(?:\s+['\"][^\n]*?['\"])?\s*\)")
_REF_USE = re.compile(r"(!?)\[([^]\n]+)\](?:\[([^]\n]*)\])?")
_ANCHOR = re.compile(r"<a\s+[^>]*(?:id|name)\s*=\s*(['\"])(.*?)\1", re.I)
_OPTION_TOKEN = re.compile(r"^--?[A-Za-z][A-Za-z0-9-]*(?:=.*)?$")
_CLI_COMMAND = re.compile(r"^(?:python(?:3(?:\.\d+)?)?\s+(?:main\.py|-m\s+vulix)|vulix)\b")

KNOWN_CONFIG_SECTIONS = {
    "accounts",
    "auth",
    "browser",
    "component_intel",
    "ctf",
    "features",
    "learning",
    "llm",
    "monitor",
    "notifications",
    "output",
    "planner",
    "scan",
}

OPTIONAL_CONFIG_KEYS: dict[str, str] = {
    "scan.allow_state_changing_probes": "commented safety toggle in config/wscan.yaml",
    "features.tls_scan": "engine-supported optional TLS scan feature flag",
    "features.token_lifecycle_manager": "engine-supported optional token lifecycle manager flag",
    "llm.models.planner": "documented planner role model override subkey under llm.models",
    "llm.models.payload": "documented payload role model override subkey under llm.models",
    "llm.models.adaptive": "documented adaptive role model override subkey under llm.models",
    "llm.models.triage": "documented triage role model override subkey under llm.models",
    "llm.models.report": "documented report role model override subkey under llm.models",
    "accounts.list.username": "documented account item field in config/wscan.yaml",
    "accounts.list.password": "documented account item field in config/wscan.yaml",
    "accounts.list.role": "documented account item field in config/wscan.yaml",
}


@dataclass(frozen=True)
class Finding:
    path: str
    line: int
    target: str
    reason: str

    def __str__(self) -> str:
        return f"{self.path}:{self.line}: {self.target}: {self.reason}"


def _mask_code(text: str, path: str, findings: list[Finding], *, inline: bool = True) -> str:
    """Blank fenced/indented blocks and inline code while preserving line numbers."""
    lines = text.splitlines(keepends=True)
    out = []
    fence = None
    for number, line in enumerate(lines, 1):
        marker = _FENCE.match(line)
        if fence:
            if marker and marker.group(1)[0] == fence[0] and len(marker.group(1)) >= len(fence):
                fence = None
            out.append("\n" if line.endswith("\n") else "")
            continue
        if marker:
            fence = marker.group(1)
            out.append("\n" if line.endswith("\n") else "")
            continue
        if line.startswith(("    ", "\t")):
            out.append("\n" if line.endswith("\n") else "")
            continue
        # A backtick span must close on the same line; otherwise Markdown's
        # syntax is ambiguous and we fail explicitly rather than guess.
        clean = re.sub(r"(`+)(.*?)\1", lambda m: " " * len(m.group(0)), line) if inline else line
        if inline and "`" in clean:
            findings.append(Finding(path, number, "inline code", "unclosed code span; cannot validate line"))
            clean = re.sub(r"`+.*$", lambda m: " " * len(m.group(0)), clean)
        out.append(clean)
    if fence:
        findings.append(Finding(path, max(1, len(lines)), "fenced code block", "unclosed fence"))
    return "".join(out)


def _heading_slug(text: str) -> str:
    text = re.sub(r"<[^>]*>", "", text)
    text = re.sub(r"!?(\[([^]]*)\])\([^)]*\)", r"\2", text)
    text = re.sub(r"[`*_~]", "", text)
    text = html.unescape(text).strip().lower()
    text = re.sub(r"[^\w\-\s]", "", text, flags=re.UNICODE)
    return re.sub(r"\s", "-", text)


def _anchors(text: str) -> set[str]:
    anchors = {html.unescape(value) for _, value in _ANCHOR.findall(text)}
    counts: dict[str, int] = {}
    for line in text.splitlines():
        match = re.match(r"^ {0,3}#{1,6}\s+(.+?)\s*#*\s*$", line)
        if not match:
            continue
        slug = _heading_slug(match.group(1))
        count = counts.get(slug, 0)
        anchors.add(slug if count == 0 else f"{slug}-{count}")
        counts[slug] = count + 1
    return anchors


def _definitions(text: str) -> tuple[dict[str, str], str]:
    definitions = {}

    def replace(match):
        target = match.group(2) or match.group(3)
        definitions[" ".join(match.group(1).lower().split())] = target
        return "\n" * match.group(0).count("\n")

    return definitions, _REFERENCE.sub(replace, text)


def _markdown_targets(text: str, path: str, findings: list[Finding]):
    masked = _mask_code(text, path, findings)
    refs, body = _definitions(masked)
    targets = []
    consumed = [False] * len(body)
    for match in _INLINE.finditer(body):
        raw = match.group(3).strip()
        target = raw[1:-1] if raw.startswith("<") and raw.endswith(">") else raw
        targets.append((match.start(), target))
        for pos in range(match.start(), match.end()):
            consumed[pos] = True
    for match in _REF_USE.finditer(body):
        if any(consumed[match.start():match.end()]):
            continue
        label = match.group(3) if match.group(3) else match.group(2)
        key = " ".join(label.lower().split())
        if key in refs:
            targets.append((match.start(), refs[key]))
            continue
        # Ordinary bracketed prose is not a link; explicit reference syntax is.
        if match.group(3) is not None:
            findings.append(Finding(path, body.count("\n", 0, match.start()) + 1,
                                    f"[{match.group(2)}][{label}]", "undefined Markdown reference"))
    malformed = re.finditer(r"!?\[[^]\n]+\]\s*\(", body)
    for match in malformed:
        if not any(consumed[match.start():match.end()]):
            findings.append(Finding(path, body.count("\n", 0, match.start()) + 1,
                                    "Markdown link", "malformed or unsupported link syntax"))
    for match in re.finditer(r"!\[[^]\n]+\](?![ \t]*[([])", body):
        findings.append(Finding(path, body.count("\n", 0, match.start()) + 1,
                                match.group(0), "image is missing a Markdown destination"))
    return [(body.count("\n", 0, pos) + 1, target) for pos, target in targets]


def _check_target(root: Path, source: Path, target: str, line: int,
                  anchors_by_path: dict[Path, set[str]]) -> Finding | None:
    try:
        parsed = urlsplit(target)
    except ValueError as exc:
        return Finding(source.relative_to(root).as_posix(), line, target,
                       f"malformed link target: {exc}")
    if parsed.scheme.lower() in {"http", "https", "mailto", "tel"} or target.startswith("//"):
        return None
    if parsed.scheme or parsed.netloc:
        return Finding(source.relative_to(root).as_posix(), line, target, "unsupported link scheme")
    decoded = unquote(parsed.path)
    dest = source if not decoded else source.parent / decoded
    root_real = root.resolve()
    try:
        resolved = dest.resolve(strict=False)
    except (OSError, RuntimeError, ValueError) as exc:
        return Finding(source.relative_to(root).as_posix(), line, target,
                       f"cannot safely resolve local target: {exc}")
    if not resolved.is_relative_to(root_real):
        return Finding(source.relative_to(root).as_posix(), line, target, "target escapes repository root (including symlinks)")
    if not dest.is_file():
        return Finding(source.relative_to(root).as_posix(), line, target, "local target does not exist")
    if parsed.fragment and resolved.suffix.lower() in {".md", ".markdown"}:
        anchors = anchors_by_path.get(resolved)
        if anchors is None:
            try:
                linked = resolved.read_text(encoding="utf-8")
            except (OSError, UnicodeError):
                return Finding(source.relative_to(root).as_posix(), line, target, "linked Markdown cannot be read as UTF-8")
            anchors = _anchors(_mask_code(linked, resolved.relative_to(root_real).as_posix(), [], inline=False))
            anchors_by_path[resolved] = anchors
        fragment = unquote(parsed.fragment)
        if fragment not in anchors:
            return Finding(source.relative_to(root).as_posix(), line, target, f"anchor #{fragment} does not exist")
    return None


def _markdown_files(root: Path) -> list[Path]:
    result = subprocess.run(["git", "ls-files", "-z", "--", "README.md", "docs"],
                            cwd=root, capture_output=True, check=True)
    return [root / name for name in result.stdout.decode("utf-8").split("\0")
            if name and Path(name).suffix.lower() in {".md", ".markdown"}]


def _parser_options(parser) -> set[str]:
    options = set()
    for action in parser._actions:
        options.update(action.option_strings)
        if isinstance(action, argparse._SubParsersAction):
            for child in action.choices.values():
                options.update(_parser_options(child))
    return options


def _cli_examples(text: str):
    lines = text.splitlines()
    i = 0
    fence = None
    while i < len(lines):
        marker = _FENCE.match(lines[i])
        if marker and fence is None:
            fence = marker.group(1)
            i += 1
            continue
        if fence and marker and marker.group(1)[0] == fence[0] and len(marker.group(1)) >= len(fence):
            fence = None
            i += 1
            continue
        if not fence:
            for span in re.finditer(r"(`+)(.*?)\1", lines[i]):
                command = span.group(2).strip()
                if _CLI_COMMAND.match(command):
                    yield i + 1, command
            i += 1
            continue
        start = i + 1
        command = lines[i].strip()
        while command.endswith("\\") and i + 1 < len(lines):
            command = command[:-1] + " " + lines[i + 1].strip()
            i += 1
        if _CLI_COMMAND.match(command):
            yield start, command
        i += 1


def _check_cli(root: Path, path: Path, text: str, parser, findings: list[Finding]) -> None:
    options = _parser_options(parser)
    for line, command in _cli_examples(text):
        try:
            tokens = shlex.split(command, comments=True)
        except ValueError as exc:
            findings.append(Finding(path.relative_to(root).as_posix(), line, command,
                                    f"malformed CLI example: {exc}"))
            continue
        if tokens[0].startswith("python"):
            option_tokens = tokens[3:] if len(tokens) > 1 and tokens[1] == "-m" else tokens[2:]
        else:
            option_tokens = tokens[1:]
        for token in option_tokens:
            candidate = token.strip("[](),")
            if _OPTION_TOKEN.fullmatch(candidate):
                name = candidate.split("=", 1)[0]
                if name not in options:
                    findings.append(Finding(path.relative_to(root).as_posix(), line, name,
                                            "option is not defined by the Vulix CLI parser"))
        # CLI examples are parsed only: no shell interpolation or command execution.
        args = shlex.split(re.sub(r"\[[^]]*\]", "", command), comments=True)
        module_entry = args[0] == "vulix" or (len(args) > 2 and args[0].startswith("python")
                                               and args[1:3] == ["-m", "vulix"])
        if args and args[0].startswith("python"):
            args = args[3:] if len(args) > 1 and args[1] == "-m" else args[2:]
        else:
            args = args[1:]
        if not args or args[0].startswith("<") or "…" in args or "..." in args:
            continue
        if module_entry and args and args[0] == "explore":
            args[0] = "scan"  # vulix.__main__ maps this product alias before main.parse_args.
        try:
            with redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
                parser.parse_args(args)
        except SystemExit as exc:
            if exc.code:
                findings.append(Finding(path.relative_to(root).as_posix(), line, command,
                                        "arguments are rejected by the Vulix CLI parser"))


def collect_config_key_paths(config_data: dict | None = None, config_path: Path | None = None) -> set[str]:
    """Recursively collect all valid dot-delimited key paths from config data or file."""
    if config_data is None:
        if config_path and config_path.is_file():
            try:
                config_data = yaml.safe_load(config_path.read_text(encoding="utf-8")) or {}
            except (OSError, yaml.YAMLError):
                config_data = {}
        else:
            config_data = {}

    paths: set[str] = set()

    def _walk(node, prefix: str = "") -> None:
        if isinstance(node, dict):
            for k, v in node.items():
                path = f"{prefix}.{k}" if prefix else str(k)
                paths.add(path)
                _walk(v, path)
        elif isinstance(node, list):
            for item in node:
                if isinstance(item, dict):
                    _walk(item, prefix)

    _walk(config_data)
    return paths


def extract_yaml_blocks(text: str) -> list[tuple[int, str, str]]:
    """Extract fenced ```yaml or ```yml code blocks as (start_line, info, content)."""
    lines = text.splitlines(keepends=True)
    i = 0
    fence = None
    fence_info = ""
    start_line = 0
    block_lines: list[str] = []
    blocks: list[tuple[int, str, str]] = []
    while i < len(lines):
        line = lines[i]
        marker = _FENCE.match(line)
        if fence is None and marker:
            info = line[marker.end():].strip()
            first_word = info.split()[0].lower() if info.split() else ""
            if first_word in ("yaml", "yml") or "wscan.yaml" in info.lower() or "vulix-config" in info.lower():
                fence = marker.group(1)
                fence_info = info
                start_line = i + 2  # 1-indexed first line inside block
                block_lines = []
            i += 1
            continue
        if fence is not None and marker and marker.group(1)[0] == fence[0] and len(marker.group(1)) >= len(fence):
            blocks.append((start_line, fence_info, "".join(block_lines)))
            fence = None
            fence_info = ""
            block_lines = []
            i += 1
            continue
        if fence is not None:
            block_lines.append(line)
        i += 1
    return blocks


def is_vulix_config_example(content: str, info: str = "", known_sections: set[str] | None = None) -> bool:
    """Decide if a YAML block represents a Vulix configuration example."""
    marker_patterns = ("config/wscan.yaml", "wscan.yaml", "vulix-config")
    combined_header = f"{info}\n{content[:200]}".lower()
    if any(marker in combined_header for marker in marker_patterns):
        return True

    sections = known_sections if known_sections is not None else KNOWN_CONFIG_SECTIONS
    try:
        data = yaml.safe_load(content)
    except yaml.YAMLError:
        return any(marker in content.lower() for marker in marker_patterns)

    if isinstance(data, dict):
        return bool(set(data.keys()) & sections)
    return False


def find_nearest_key(unknown_path: str, valid_paths: set[str]) -> str:
    """Find the closest valid key path using prefix locality and string similarity."""
    if not valid_paths:
        return ""
    if "." in unknown_path:
        prefix = unknown_path.rsplit(".", 1)[0]
        same_prefix = [p for p in valid_paths if p.startswith(prefix + ".") or p == prefix]
        matches = difflib.get_close_matches(unknown_path, same_prefix, n=1, cutoff=0.1)
        if matches:
            return matches[0]
    matches = difflib.get_close_matches(unknown_path, list(valid_paths), n=1, cutoff=0.1)
    if matches:
        return matches[0]
    return min(valid_paths, key=lambda p: difflib.SequenceMatcher(None, unknown_path, p).ratio())


def compare_config_example_keys(block_text: str, start_line: int, file_path: str,
                                valid_paths: set[str]) -> list[Finding]:
    """Verify that every key path in a configuration block exists in valid_paths."""
    findings: list[Finding] = []
    try:
        nodes = list(yaml.compose_all(block_text))
    except yaml.YAMLError as exc:
        return [Finding(file_path, start_line, "YAML syntax",
                        f"malformed YAML configuration example: {exc}")]

    def _check_node(node, prefix: str = "") -> None:
        if isinstance(node, yaml.MappingNode):
            for k_node, v_node in node.value:
                key = str(k_node.value)
                path = f"{prefix}.{key}" if prefix else key
                line = start_line + k_node.start_mark.line
                if path not in valid_paths:
                    nearest = find_nearest_key(path, valid_paths)
                    findings.append(Finding(
                        file_path, line, path,
                        f"unknown configuration key path (nearest valid key: '{nearest}')"
                    ))
                _check_node(v_node, path)
        elif isinstance(node, yaml.SequenceNode):
            for item in node.value:
                if isinstance(item, yaml.MappingNode):
                    _check_node(item, prefix)

    for doc in nodes:
        if doc is not None:
            _check_node(doc)

    return findings


def check_config_examples(root: Path, path: Path, text: str, valid_paths: set[str],
                          findings: list[Finding]) -> None:
    """Find and validate all Vulix configuration examples within a Markdown document."""
    rel_path = path.relative_to(root).as_posix() if path.is_relative_to(root) else str(path)
    for start_line, info, content in extract_yaml_blocks(text):
        if is_vulix_config_example(content, info):
            findings.extend(compare_config_example_keys(content, start_line, rel_path, valid_paths))


def validate(root: Path = ROOT, documents: list[Path] | None = None) -> list[Finding]:
    root = root.resolve()
    documents = _markdown_files(root) if documents is None else documents
    findings: list[Finding] = []
    contents = {}
    anchors = {}
    parser = None
    config_file = root / "config" / "wscan.yaml"
    if not config_file.is_file() and (ROOT / "config" / "wscan.yaml").is_file():
        config_file = ROOT / "config" / "wscan.yaml"
    valid_config_keys = collect_config_key_paths(config_path=config_file) | set(OPTIONAL_CONFIG_KEYS.keys())
    for path in documents:
        path = path if path.is_absolute() else root / path
        try:
            resolved = path.resolve(strict=True)
        except (OSError, RuntimeError) as exc:
            findings.append(Finding(str(path), 1, str(path), f"cannot safely resolve Markdown document: {exc}"))
            continue
        if not resolved.is_relative_to(root):
            findings.append(Finding(str(path), 1, str(path), "Markdown document escapes repository root"))
            continue
        try:
            text = resolved.read_text(encoding="utf-8")
        except (OSError, UnicodeError) as exc:
            findings.append(Finding(path.relative_to(root).as_posix(), 1, str(path), f"cannot read Markdown: {exc}"))
            continue
        contents[resolved] = text
        anchors[resolved] = _anchors(_mask_code(text, resolved.relative_to(root).as_posix(), findings, inline=False))
    for source, text in contents.items():
        for line, target in _markdown_targets(text, source.relative_to(root).as_posix(), findings):
            problem = _check_target(root, source, target, line, anchors)
            if problem:
                findings.append(problem)
        check_config_examples(root, source, text, valid_config_keys, findings)
        if source.name == "README.md" or "docs" in source.relative_to(root).parts:
            if parser is None:
                import main
                parser = main._build_parser()
            _check_cli(root, source, text, parser, findings)
    return findings


def main(argv: list[str] | None = None) -> int:
    arg_parser = argparse.ArgumentParser(description=__doc__)
    arg_parser.add_argument("--root", type=Path, default=ROOT)
    args = arg_parser.parse_args(argv)
    findings = validate(args.root)
    for finding in findings:
        print(finding, file=sys.stderr)
    if findings:
        print(f"documentation validation: {len(findings)} finding(s)", file=sys.stderr)
        return 1
    print("documentation validation: local Markdown references, CLI examples, and configuration examples are valid")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
