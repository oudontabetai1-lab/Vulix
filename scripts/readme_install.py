"""README の本体導入ブロックを抽出する（実行は CI の明示的な bash ステップのみ）。"""
from pathlib import Path
import sys


START = "<!-- vulix-install:start -->"
END = "<!-- vulix-install:end -->"


def extract_install(text: str) -> str:
    """一意なマーカーで囲まれた bash ブロックを返し、不正時は行番号付きで拒否する。"""
    lines = text.splitlines()
    starts = [i for i, line in enumerate(lines) if line == START]
    ends = [i for i, line in enumerate(lines) if line == END]
    line = starts[0] + 1 if starts else 1
    if len(starts) != 1 or len(ends) != 1:
        raise ValueError(f"README.md:{line}: install markers must occur exactly once each")
    start, end = starts[0], ends[0]
    block = lines[start + 1:end]
    if len(block) < 3 or block[0] != "```bash" or block[-1] != "```":
        raise ValueError(f"README.md:{line}: install markers must enclose one bash fence")
    if any("```" in item for item in block[1:-1]) or not any(
        item.strip() and not item.lstrip().startswith("#") for item in block[1:-1]
    ):
        raise ValueError(f"README.md:{start + 3}: install block must contain commands and no nested fences")
    return "\n".join(block[1:-1]) + "\n"


def main() -> int:
    readme = Path(__file__).resolve().parents[1] / "README.md"
    try:
        text = readme.read_text(encoding="utf-8")
    except (OSError, UnicodeError) as exc:
        print(f"README.md:1: {exc}", file=sys.stderr)
        return 1
    try:
        commands = extract_install(text)
    except ValueError as exc:
        print(str(exc), file=sys.stderr)
        return 1
    print(commands, end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
