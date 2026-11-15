"""sys.modules 差し替えヘルパーが自分のキーだけを戻すことの検証。"""

from __future__ import annotations

import sys
import unittest

from tests._module_stubs import install_modules

_STUB = "_wscan_test_module_stub"
_ADDED = "_wscan_test_module_added"


def test_install_modules_restores_previous_value():
    original = object()
    sys.modules[_STUB] = original
    try:
        class _Probe(unittest.TestCase):
            def runTest(self):
                install_modules(self, {_STUB: object()})
                assert sys.modules[_STUB] is not original

        _Probe().run()
        assert sys.modules[_STUB] is original
    finally:
        sys.modules.pop(_STUB, None)


def test_install_modules_keeps_modules_added_during_the_block():
    # 設定したキーだけを戻すので、差し替え中に増えた別のキーは残る
    # （後続テストの import が別モジュールオブジェクトにならない）。
    class _Probe(unittest.TestCase):
        def runTest(self):
            install_modules(self, {_STUB: object()})
            sys.modules[_ADDED] = object()

    try:
        _Probe().run()
        assert _STUB not in sys.modules
        assert _ADDED in sys.modules
    finally:
        sys.modules.pop(_STUB, None)
        sys.modules.pop(_ADDED, None)
