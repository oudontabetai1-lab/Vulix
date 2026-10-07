"""wscan.laya_calibration（純粋関数・Laya/ブラウザ非依存）。"""

import hashlib

from tests.fixtures import realistic_api, realistic_healthcare, realistic_intranet, realistic_site
from wscan import laya_calibration as lc

FIXTURES = {"site": realistic_site, "api": realistic_api,
            "intranet": realistic_intranet, "healthcare": realistic_healthcare}


def _u(s, salt):
    """id から決定論的な [0,1) 値（合成スコアのノイズ）。"""
    return int(hashlib.sha256(f"{salt}:{s['id']}".encode()).hexdigest()[:8], 16) / 2**32


def _overconfident(samples):
    """過信スコア: 正答 75% だが常に 0.95/0.05 を出す（confidence ≠ accuracy の典型）。"""
    out = {}
    for s in samples:
        right = _u(s, "a") < 0.75
        out[s["id"]] = 0.95 if (s["label"] == 1) == right else 0.05
    return out


def test_dataset_has_safe_twins_and_unique_ids():
    ds = lc.build_dataset(FIXTURES)
    pos = [s for s in ds if s["label"] == 1]
    neg = [s for s in ds if s["label"] == 0]
    assert len(pos) >= 40 and len(neg) >= 40  # 安全ツインが誤検知ガードとして揃う
    assert len({s["id"] for s in ds}) == len(ds)
    assert "note" not in lc.default_state(ds[0])  # 正解説明を state に漏らさない


def test_split_is_deterministic_stratified_and_disjoint():
    ds = lc.build_dataset(FIXTURES)
    c1, h1 = lc.split_holdout(ds)
    c2, h2 = lc.split_holdout(list(reversed(ds)))
    assert [s["id"] for s in h1] == [s["id"] for s in h2]
    assert not {s["id"] for s in c1} & {s["id"] for s in h1}
    assert len(c1) + len(h1) == len(ds)
    assert {s["label"] for s in h1} == {0, 1} and {s["label"] for s in c1} == {0, 1}


def test_ece_and_bins():
    assert lc.ece([1.0, 0.0], [1, 0]) == 0.0
    assert abs(lc.ece([0.9] * 10, [1] * 5 + [0] * 5) - 0.4) < 1e-9
    bins = lc.reliability_bins([0.05, 0.95, 1.0], [0, 1, 1], 10)
    assert [b["count"] for b in bins] == [1, 2]
    assert lc.ece([], []) == 0.0 and lc.brier([], []) == 0.0


def test_platt_reduces_ece_on_overconfident_scores():
    ds = lc.build_dataset(FIXTURES)
    p = [_overconfident(ds)[s["id"]] for s in ds]
    y = [s["label"] for s in ds]
    q = lc.apply_platt(p, lc.fit_platt(p, y))
    assert lc.ece(q, y) < lc.ece(p, y) / 2
    assert lc.fit_platt([0.9, 0.8], [1, 1]) == (1.0, 0.0)  # 片クラスは恒等


def test_threshold_cost_tradeoff_and_confusion():
    p, y = [0.1, 0.4, 0.6, 0.9], [0, 1, 0, 1]
    c = lc.confusion(p, y, 0.5)
    assert (c["tp"], c["fp"], c["fn"], c["tn"]) == (1, 1, 1, 1)
    # FN を重くすると閾値は下がり見逃しが消える
    t = lc.choose_threshold(p, y, fp_cost=1, fn_cost=10)
    assert t == 0.4 and lc.confusion(p, y, t)["fn"] == 0
    # FP を重くすると安全ツインへの誤検知が消える
    t = lc.choose_threshold(p, y, fp_cost=10, fn_cost=1)
    assert lc.confusion(p, y, t)["fp"] == 0


def test_evaluate_measures_fp_fn_before_after_on_holdout():
    ds = lc.build_dataset(FIXTURES)
    r = lc.evaluate(ds, _overconfident(ds))
    for side in ("raw", "calibrated"):
        h = r[side]["holdout"]
        assert {"fp", "fn", "fpr", "fnr"} <= h.keys()
        assert h["tp"] + h["fp"] + h["fn"] + h["tn"] == r["n_holdout"]
    assert r["calibrated"]["holdout_ece"] < r["raw"]["holdout_ece"]
    assert not r["overfit"]  # 汎化するスコアなら held-out でも同等のコスト率


def test_evaluate_flags_memorizing_scorer_as_overfit():
    """校正 split だけ正解を覚えた scorer（reward hacking）は held-out で崩れ overfit になる。"""
    ds = lc.build_dataset(FIXTURES)
    calib, _ = lc.split_holdout(ds)
    seen = {s["id"] for s in calib}
    scores = {s["id"]: (float(s["label"]) if s["id"] in seen else _u(s, "r")) for s in ds}
    r = lc.evaluate(ds, scores)
    assert r["calibrated"]["calib"]["fp"] == 0 and r["calibrated"]["calib"]["fn"] == 0
    assert r["overfit"]


def test_abstain_counted_not_dropped():
    ds = lc.build_dataset(FIXTURES)
    scores = _overconfident(ds)
    scores[ds[0]["id"]] = None
    assert lc.evaluate(ds, scores)["abstained"] == 1


def test_laya_scores_fail_open_and_reads_noul():
    ds = lc.build_dataset({"intranet": realistic_intranet})
    assert set(lc.laya_scores(ds, decide=lambda s, q: None).values()) == {None}
    got = lc.laya_scores(ds, decide=lambda s, q: {"answers": {"vulnerable": {"noul": 0.7}}})
    assert set(got.values()) == {0.7}
    bad = lc.laya_scores(ds, decide=lambda s, q: {"answers": {"vulnerable": {"noul": 3}}})
    assert set(bad.values()) == {None}


def test_laya_scores_default_off_without_env(monkeypatch):
    monkeypatch.delenv("WSCAN_LAYA", raising=False)
    ds = lc.build_dataset({"intranet": realistic_intranet})
    assert set(lc.laya_scores(ds).values()) == {None}
