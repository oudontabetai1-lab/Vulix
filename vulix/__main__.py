"""``python -m vulix <subcommand> ...`` の入口。

0069 Phase 1（加算的リブランド）: 現行 CLI（``main.py`` の argparse）へ**そのまま委譲**する
薄いラッパ。既存の ``python main.py <subcommand>`` 挙動を一切変えない。

サブコマンド別名（Vulix ブランド語彙）:
- ``explore`` → ``scan`` の別名（``python -m vulix explore <url>`` が ``scan`` として動く）。
  先頭サブコマンド語のみ argv 上で置換する。
- ``replay`` → ``main.py`` 側で ``scan`` の argparse 別名として登録済み（flow/HAR 再生は
  ``--flows`` / ``--har`` で行う）。ここでは置換せずそのまま委譲する。

``agent`` / ``triage`` / ``serve`` 等もそのまま委譲する。
"""
import sys

import main as _main

# 別名 → 現行サブコマンド名。argparse の前に argv 上で置換する。
_ALIASES = {"explore": "scan"}


def _show_alias_hint(argv: list[str]) -> None:
    """Vulix の top-level help に wrapper 固有の別名を表示する。"""
    if len(argv) >= 2 and argv[1] in {"-h", "--help"}:
        print(
            "Vulix command aliases: explore (alias for scan), "
            "replay (alias for scan; flow/HAR 再生)\n"
        )


def _rewrite_argv(argv: list[str]) -> list[str]:
    """先頭のサブコマンド語だけを別名変換する（引数値には触れない）。"""
    if len(argv) >= 2 and argv[1] in _ALIASES:
        return [argv[0], _ALIASES[argv[1]], *argv[2:]]
    return argv


def main() -> None:
    _show_alias_hint(sys.argv)
    sys.argv = _rewrite_argv(sys.argv)
    _main.main()


if __name__ == "__main__":
    main()
