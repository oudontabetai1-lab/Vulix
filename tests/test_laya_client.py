"""wscan.laya_client の fail-safe（laya 未導入でも通る）。"""

import sys
import threading
import time
import types

from wscan import laya_client

Q = {"q": {"type": "noul", "instructions": "?"}}


def _fake(monkeypatch, predict):
    laya_client._agents.clear()
    laya_client._failed.clear()
    agent = types.SimpleNamespace(predict=predict)
    calls = []

    def load(*a, **k):
        calls.append(1)
        if isinstance(predict, Exception):
            raise predict
        return agent

    monkeypatch.setitem(sys.modules, "laya", types.SimpleNamespace(load=load))
    monkeypatch.setenv("WSCAN_LAYA", "1")
    return calls


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


def test_incomplete_answers_is_none(monkeypatch):
    _fake(monkeypatch, lambda s, q: {"answers": {}})
    assert laya_client.decide("s", Q) is None


def test_unknown_variant_not_loaded(monkeypatch):
    calls = _fake(monkeypatch, lambda s, q: {"answers": {"q": {"noul": 0.9}}})
    assert laya_client.decide("s", Q, variant="bogus") is None
    assert calls == []


def test_load_failure_memoized(monkeypatch):
    calls = _fake(monkeypatch, RuntimeError("dl"))
    assert laya_client.decide("s", Q) is None
    assert laya_client.decide("s", Q) is None
    assert len(calls) == 1


def test_empty_answer_dict_is_none(monkeypatch):
    _fake(monkeypatch, lambda s, q: {"answers": {"q": {}}})
    assert laya_client.decide("s", Q) is None


def test_typed_answer_ok(monkeypatch):
    _fake(monkeypatch, lambda s, q: {"answers": {"q": {"noul": 0.5}}})
    assert laya_client.decide("s", Q)["answers"]["q"]["noul"] == 0.5


def test_choice_missing_key_is_none(monkeypatch):
    _fake(monkeypatch, lambda s, q: {"answers": {"q": {"noul": 0.5}}})
    assert laya_client.decide("s", {"q": {"type": "choice"}}) is None


def test_concurrent_first_load_once(monkeypatch):
    calls = _fake(monkeypatch, lambda s, q: {"answers": {"q": {"noul": 0.9}}})
    inner = sys.modules["laya"].load

    def slow(*a, **k):
        time.sleep(0.05)
        return inner(*a, **k)

    sys.modules["laya"].load = slow
    out = []
    ts = [threading.Thread(target=lambda: out.append(laya_client.decide("s", Q))) for _ in range(2)]
    [t.start() for t in ts]
    [t.join() for t in ts]
    assert len(calls) == 1
    assert len(out) == 2 and all(r["answers"]["q"]["noul"] == 0.9 for r in out)
