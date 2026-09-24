"""``python -m vulix <subcommand> ...`` の入口。

0069 Phase 1（加算的リブランド）: 現行 CLI（``main.py`` の argparse）へ**そのまま委譲**する
薄いラッパ。既存の ``python main.py <subcommand>`` 挙動を一切変えない。

サブコマンド別名（Vulix ブランド語彙）:
- ``explore`` → ``scan`` の別名（``python -m vulix explore <url>`` が ``scan`` として動く）。

``agent`` / ``triage`` / ``serve`` 等はそのまま委譲する。``replay`` は現行 CLI に対応する
独立サブコマンドが無い（flow/HAR 再生は ``scan --flows`` / ``--har`` のフラグ）ため、
別名は追加しない（Phase 2 で扱う）。
"""
import sys

import main as _main

# 別名 → 現行サブコマンド名。argparse の前に argv 上で置換する。
_ALIASES = {"explore": "scan"}


def _rewrite_argv(argv: list[str]) -> list[str]:
    """先頭のサブコマンド語だけを別名変換する（引数値には触れない）。"""
    if len(argv) >= 2 and argv[1] in _ALIASES:
        return [argv[0], _ALIASES[argv[1]], *argv[2:]]
    return argv


def main() -> None:
    sys.argv = _rewrite_argv(sys.argv)
    _main.main()


if __name__ == "__main__":
    main()
