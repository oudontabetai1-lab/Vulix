"""テスト共通の設定。

ソース checkout では学習データ等の state 書込先が ``config/`` になる（wscan/state_paths.py）。
テストがそこへ書くと作業ツリーが汚れるため、全テストの state dir を一時ディレクトリへ向ける。
state_paths の既定解決を検証するテストは自前で env を指定するので影響しない。
"""

import pytest
import webbrowser


@pytest.fixture(autouse=True)
def _isolate_wscan_state_dir(tmp_path, monkeypatch):
    monkeypatch.setenv("WSCAN_STATE_DIR", str(tmp_path / "wscan_state"))


@pytest.fixture(autouse=True)
def _prevent_browser_open_during_tests(monkeypatch, request):
    """Propagate no-open policy and fail if code bypasses the shared guard."""
    monkeypatch.setenv("WSCAN_NO_AUTO_OPEN", "1")
    attempted = []

    def blocked_open(target, *args, **kwargs):
        attempted.append(str(target))
        raise AssertionError(f"Test attempted to open a browser: {target}")

    monkeypatch.setattr(webbrowser, "open", blocked_open)
    monkeypatch.setattr(webbrowser, "open_new", blocked_open)
    monkeypatch.setattr(webbrowser, "open_new_tab", blocked_open)
    request.addfinalizer(
        lambda: pytest.fail(f"Browser open attempted during test: {attempted}") if attempted else None
    )
