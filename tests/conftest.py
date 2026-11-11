"""テスト共通の設定。

ソース checkout では学習データ等の state 書込先が ``config/`` になる（wscan/state_paths.py）。
テストがそこへ書くと作業ツリーが汚れるため、全テストの state dir を一時ディレクトリへ向ける。
state_paths の既定解決を検証するテストは自前で env を指定するので影響しない。
"""

import pytest


@pytest.fixture(autouse=True)
def _isolate_wscan_state_dir(tmp_path, monkeypatch):
    monkeypatch.setenv("WSCAN_STATE_DIR", str(tmp_path / "wscan_state"))
