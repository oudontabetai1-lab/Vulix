"""sys.modules 全体を差し替えるテスト用パッチの再発防止ガード。"""

from __future__ import annotations

import re
from pathlib import Path

_TESTS_DIR = Path(__file__).resolve().parent

# sys.modules の辞書全体を退避・復元する dict パッチ（文字列指定・キーワード指定の
# どちらも、複数行に跨る書き方も）を検出する。
_WHOLE_DICT_PATCH = re.compile(r"patch\s*\.\s*dict\s*\(\s*[\"']?sys\s*\.\s*modules")


def _scan() -> list[str]:
    offenders: list[str] = []
    for path in sorted(_TESTS_DIR.rglob("*.py")):
        if "__pycache__" in path.parts:
            continue
        text = path.read_text(encoding="utf-8")
        for match in _WHOLE_DICT_PATCH.finditer(text):
            line = text.count("\n", 0, match.start()) + 1
            offenders.append(f"{path.relative_to(_TESTS_DIR)}:{line}")
    return offenders


def test_no_whole_dict_patch_on_sys_modules():
    offenders = _scan()
    assert not offenders, (
        "sys.modules の辞書全体を退避・復元するパッチが残っています: "
        + ", ".join(offenders)
        + "。ブロック終了時に、そのブロック内で初めて import された無関係なモジュール"
        "（例: 遅延 import される HTTP クライアントの下位モジュール）まで sys.modules から"
        "消え、後続の import が別オブジェクトを作って一見無関係なテストが環境依存で落ちます。"
        "pytest 形式では monkeypatch.setitem(sys.modules, 名前, モジュール)、"
        "unittest.TestCase では tests._module_stubs.install_modules(testcase, {...}) を"
        "使ってください。"
    )
