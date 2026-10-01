"""wscan.laya_client の fail-safe（laya 未導入でも通る）。"""

import sys
import types

from wscan import laya_client

Q = {"q": {"type": "noul", "instructions": "?"}}


def _fake(monkeypatch, predict):
    laya_client._agents.clear()
    agent = types.SimpleNamespace(predict=predict)
    mod = types.SimpleNamespace(load=lambda *a, **k: agent)
    monkeypatch.setitem(sys.modules, "laya", mod)
    monkeypatch.setenv("WSCAN_LAYA", "1")


def test_default_off(monkeypatch):
    monkeypatch.delenv("WSCAN_LAYA", raising=False)
    assert not laya_client.enabled()
    assert not laya_client.available()
    assert laya_client.decide("s", Q) is None


def test_enabled_but_package_missing(monkeypatch):
    laya_client._agents.clear()
    monkeypatch.setenv("WSCAN_LAYA", "1")
    monkeypatch.setitem(sys.modules, "laya", None)
    assert not laya_client.available()
    assert laya_client.decide("s", Q) is None


def test_decide_returns_result(monkeypatch):
    _fake(monkeypatch, lambda s, q: {"answers": {"q": {"noul": 0.9}}})
    res = laya_client.decide("s", Q)
    assert res["answers"]["q"]["noul"] == 0.9


def test_predict_raises_is_none(monkeypatch):
    def boom(s, q):
        raise RuntimeError("x")

    _fake(monkeypatch, boom)
    assert laya_client.decide("s", Q) is None


def test_empty_questions_is_none(monkeypatch):
    _fake(monkeypatch, lambda s, q: {"answers": {"q": {"noul": 0.9}}})
    assert laya_client.decide("s", {}) is None
