"""追跡対象ファイルに内部管理用の強い識別子が混入していないかを検査する（stdlib のみ）。

公開リポジトリへ内部の課題番号・設計ノート・ナレッジ vault へのリンクが漏れるのを防ぐ。
誤検知を避けるため、一般語や機能値（capability の task 値、benchmark gap の owner_task、
製品用語 Phase 1/2、CSS の linear-gradient 等）には一致しない「強い識別子」だけを対象にする。

使い方: ``python scripts/check_internal_refs.py``（検出時は該当行を出力して exit 1）。
"""
from __future__ import annotations

import re
import subprocess
import sys
from pathlib import Path
from typing import Iterable, Iterator

# 本スクリプト自身が検出されないよう、語は分割して組み立てる。
# 直前は ASCII 英数字だけを除外する（\b だと日本語に直結した課題番号を見逃す）。
_NOT_AFTER_ASCII = r"(?<![A-Za-z0-9])"
_PATTERNS = [
    _NOT_AFTER_ASCII + "OUD" + r"-\d+",
    _NOT_AFTER_ASCII + "ADR" + r"-\d+",
    # 後続は問わない（「-日本語」・記号・行末も検出）。MODEL_NAME 等の _ 連結は対象外。
    _NOT_AFTER_ASCII + "(?:" + "|".join(["PRIN" + "CIPLE", "PL" + "AN", "MOD" + "EL", "DECI" + "SION"]) + ")-",
    "連携" + "プレイブック",
    r"\[\[" + "Designs" + "/",
    "obsi" + r"dian://",
]
STRONG_ID = re.compile("|".join(f"(?:{p})" for p in _PATTERNS))


def find_violations(lines: Iterable[str]) -> Iterator[tuple[int, str]]:
    """(行番号, 一致文字列) を返す純粋関数。"""
    for no, line in enumerate(lines, 1):
        m = STRONG_ID.search(line)
        if m:
            yield no, m.group(0)


def tracked_files(root: Path) -> list[str]:
    out = subprocess.run(["git", "ls-files", "-z"], cwd=root, capture_output=True, check=True)
    return [p for p in out.stdout.decode("utf-8").split("\0") if p]


def main(root: Path = Path(__file__).resolve().parents[1]) -> int:
    hits = []
    for rel in tracked_files(root):
        path = root / rel
        try:
            text = path.read_text(encoding="utf-8")
        except (UnicodeDecodeError, FileNotFoundError, IsADirectoryError):
            continue  # バイナリ・submodule 等は対象外
        for no, match in find_violations(text.splitlines()):
            hits.append(f"{rel}:{no}: {match}")
    for h in hits:
        print(h)
    if hits:
        print(f"internal reference gate: {len(hits)} violation(s)", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
