"""sys.modules へ一時的にモジュールを差し込むテスト用ヘルパー。

unittest.mock の dict パッチを sys.modules に対して使うと、ブロック終了時に dict 全体が
退避時点の内容へ戻る。そのためブロック内で初めて import された無関係なモジュール
（例: 遅延 import される HTTP クライアントの下位モジュール）まで sys.modules から消え、
後続の import が別オブジェクトを作る。クラス同一性や ContextVar が二重化して、
一見無関係なテストが環境依存で落ちる。

ここでは「自分が設定したキー」だけを保存し、テスト終了時にそのキーだけ戻す。
"""

from __future__ import annotations

import sys
from typing import Mapping

_MISSING = object()


def install_modules(testcase, modules: Mapping[str, object]) -> None:
    """sys.modules に modules を差し込み、testcase の後処理でそのキーだけ元へ戻す。

    unittest.TestCase のテストから呼ぶ。pytest 形式のテストでは
    ``monkeypatch.setitem(sys.modules, 名前, モジュール)`` を使う。
    """
    previous = {name: sys.modules.get(name, _MISSING) for name in modules}
    sys.modules.update(modules)

    def _restore() -> None:
        for name, module in previous.items():
            if module is _MISSING:
                sys.modules.pop(name, None)
            else:
                sys.modules[name] = module

    testcase.addCleanup(_restore)
