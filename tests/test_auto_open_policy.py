from types import SimpleNamespace

import webbrowser

import main
from wscan.open_policy import open_in_browser


def test_no_auto_open_environment_suppresses_browser_calls(monkeypatch):
    opened = []
    monkeypatch.setenv("WSCAN_NO_AUTO_OPEN", "1")
    monkeypatch.delenv("CI", raising=False)
    monkeypatch.setattr(webbrowser, "open", lambda url: opened.append(url) or True)

    assert open_in_browser("file:///tmp/report.html") is False
    assert main._effective_open_report(SimpleNamespace(open_report=True)) is False
    assert opened == []


def test_normal_environment_keeps_explicit_browser_open_behavior(monkeypatch):
    opened = []
    monkeypatch.delenv("WSCAN_NO_AUTO_OPEN", raising=False)
    monkeypatch.delenv("CI", raising=False)
    monkeypatch.setattr(webbrowser, "open", lambda url: opened.append(url) or True)

    assert open_in_browser("http://localhost:8765/app") is True
    assert opened == ["http://localhost:8765/app"]


def test_ci_environment_suppresses_browser_calls(monkeypatch):
    opened = []
    monkeypatch.delenv("WSCAN_NO_AUTO_OPEN", raising=False)
    monkeypatch.setenv("CI", "true")
    monkeypatch.setattr(webbrowser, "open", lambda url: opened.append(url) or True)

    assert open_in_browser("http://localhost:8765/app") is False
    assert opened == []
