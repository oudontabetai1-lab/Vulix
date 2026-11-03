"""View modules must use design tokens/classes, never hard-coded hex colours."""
import re
from pathlib import Path

UI_DIR = Path(__file__).resolve().parent.parent / "templates" / "ui"
HEX_RE = re.compile(r"#[0-9a-fA-F]{3,8}\b")
# Allowlist: (file name, exact literal) pairs. Empty: nothing needs an exception.
ALLOWLIST: set[tuple[str, str]] = set()


def _strip_comments(text: str) -> str:
    text = re.sub(r"/\*.*?\*/", "", text, flags=re.S)
    return re.sub(r"(?m)^\s*//.*$", "", text)


def test_view_modules_have_no_hardcoded_hex_colors():
    files = sorted(UI_DIR.glob("*-module.js"))
    assert files
    offenders = []
    for f in files:
        for n, line in enumerate(_strip_comments(f.read_text(encoding="utf-8")).splitlines(), 1):
            for m in HEX_RE.findall(line):
                if (f.name, m) not in ALLOWLIST:
                    offenders.append(f"{f.name}: {m} ({line.strip()[:60]})")
    assert not offenders, "Hard-coded hex colours; use tokens.css/components.css:\n" + "\n".join(offenders)


def test_legacy_aliases_reference_status_tokens():
    css = (UI_DIR / "tokens.css").read_text(encoding="utf-8")
    for alias, target in (("success", "pass"), ("warning", "warning"), ("running", "running")):
        assert re.search(rf"--{alias}:\s*var\(--status-{target}\)\s*;", css), alias
