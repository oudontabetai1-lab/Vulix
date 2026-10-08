"""Laya 確率の校正ハーネス（OUD-82）。

Laya の公式制約「確率は閾値で使う前に自タスクで校正する」「confidence ≠ accuracy」に対応する。
fixture の正解データ（`EXPECTED_FINDINGS`＝脆弱 / `SAFE_ENDPOINTS`＝安全ツイン）を校正データセットに
し、校正指標（信頼性図ビン・ECE・Brier）、Platt scaling、FP/FN コストに基づく閾値決定、
held-out での妥当性検証を行う。

全て**純粋関数**（HTTP/ブラウザ/Laya 非依存）。スコアは呼び出し側が `scores` として渡す
（Laya なら `laya_scores`、テストなら合成スコア）。検出ロジック・severity・dedup には触れない
（通常層で Laya を判定 oracle にしない方針は `laya_client` と同じ）。

reward hacking 検知: 閾値と校正パラメータは**校正 split だけ**で決め、held-out split は評価にのみ使う。
校正 split と held-out のコスト率の差が `max_gap` を超えたら `overfit=True`（過適合の疑い）を返す。
"""

from __future__ import annotations

import hashlib
import math
from typing import Any, Callable, Iterable, Optional

_EPS = 1e-6


# ---------------------------------------------------------------------------
# データセット
# ---------------------------------------------------------------------------
def build_dataset(fixtures: dict[str, Any]) -> list[dict]:
    """`{名前: fixture モジュール}` から校正サンプルを作る（label: 脆弱=1 / 安全ツイン=0）。

    `note` は正解の説明文なので Laya の state に入れないこと（ラベル漏洩）。保持は人間向け。
    """
    out = []
    for name, mod in fixtures.items():
        for label, rows in ((1, mod.EXPECTED_FINDINGS), (0, mod.SAFE_ENDPOINTS)):
            for r in rows:
                out.append({
                    "id": f"{name}:{r.get('check') or '-'}:{r['path']}:{r.get('field') or '-'}",
                    "fixture": name,
                    "check": r.get("check"),
                    "path": r["path"],
                    "field": r.get("field"),
                    "difficulty": r.get("difficulty"),
                    "note": r.get("note", ""),
                    "label": label,
                })
    return out


def split_holdout(samples: list[dict], holdout_frac: float = 0.3, salt: str = "laya") -> tuple[list, list]:
    """id のハッシュで決定論的に (calib, holdout) へ分ける。ラベル別に層化して両 split に両クラスを残す。

    乱数を使わない＝run 跨ぎで同じ分割（後から held-out を覗いて調整する余地を作らない）。
    """
    calib, hold = [], []
    for label in (0, 1):
        group = sorted((s for s in samples if s["label"] == label),
                       key=lambda s: hashlib.sha256(f"{salt}:{s['id']}".encode()).hexdigest())
        k = round(len(group) * holdout_frac)
        if len(group) >= 2:
            k = min(max(k, 1), len(group) - 1)
        hold += group[:k]
        calib += group[k:]
    return calib, hold


# ---------------------------------------------------------------------------
# 校正指標
# ---------------------------------------------------------------------------
def reliability_bins(probs: list[float], labels: list[int], n_bins: int = 10) -> list[dict]:
    """信頼性図の等幅ビン（空ビンは省く）。各ビン: 範囲・件数・平均確率・実際の陽性率。"""
    bins: list[list[int]] = [[] for _ in range(n_bins)]
    for i, p in enumerate(probs):
        bins[min(int(p * n_bins), n_bins - 1)].append(i)
    out = []
    for b, idx in enumerate(bins):
        if idx:
            out.append({
                "lo": b / n_bins, "hi": (b + 1) / n_bins, "count": len(idx),
                "confidence": sum(probs[i] for i in idx) / len(idx),
                "accuracy": sum(labels[i] for i in idx) / len(idx),
            })
    return out


def ece(probs: list[float], labels: list[int], n_bins: int = 10) -> Optional[float]:
    """Expected Calibration Error（件数重み付きの |平均確率 − 陽性率|）。"""
    if not probs:
        return None
    return sum(b["count"] * abs(b["confidence"] - b["accuracy"])
               for b in reliability_bins(probs, labels, n_bins)) / len(probs)


def brier(probs: list[float], labels: list[int]) -> Optional[float]:
    return sum((p - y) ** 2 for p, y in zip(probs, labels)) / len(probs) if probs else None


# ---------------------------------------------------------------------------
# Platt scaling（logit(p) への 1 次元ロジスティック回帰）
# ---------------------------------------------------------------------------
def _logit(p: float) -> float:
    p = min(max(p, _EPS), 1 - _EPS)
    return math.log(p / (1 - p))


def _sigmoid(z: float) -> float:
    return 1 / (1 + math.exp(-z)) if z >= 0 else math.exp(z) / (1 + math.exp(z))


def fit_platt(probs: list[float], labels: list[int], iters: int = 100) -> tuple[float, float]:
    """`q = sigmoid(a·logit(p) + b)` の (a, b) を Newton 法で推定する。

    Platt のターゲット平滑化（t+=(N+ +1)/(N+ +2), t-=1/(N- +2)）で完全分離でも発散しない。
    ponytail: 2 パラメータのみ。fixture 規模（数十件）では isotonic より過適合しにくい。
    """
    n_pos = sum(labels)
    n_neg = len(labels) - n_pos
    if not n_pos or not n_neg:
        return 1.0, 0.0  # 片クラスでは推定不能 → 恒等
    t_pos, t_neg = (n_pos + 1) / (n_pos + 2), 1 / (n_neg + 2)
    xs = [_logit(p) for p in probs]
    ts = [t_pos if y else t_neg for y in labels]
    def loss(a, b):
        return -sum(t * math.log(max(_sigmoid(a * x + b), 1e-300)) +
                    (1 - t) * math.log(max(1 - _sigmoid(a * x + b), 1e-300)) for x, t in zip(xs, ts))

    a, b = 1.0, 0.0
    cur = loss(a, b)
    for _ in range(iters):
        g_a = g_b = h_aa = h_ab = h_bb = 0.0
        for x, t in zip(xs, ts):
            q = _sigmoid(a * x + b)
            d, w = q - t, q * (1 - q)
            g_a += d * x
            g_b += d
            h_aa += w * x * x
            h_ab += w * x
            h_bb += w
        h_aa += 1e-9
        h_bb += 1e-9
        det = h_aa * h_bb - h_ab * h_ab
        if det <= 0:
            break
        da = (h_bb * g_a - h_ab * g_b) / det
        db = (h_aa * g_b - h_ab * g_a) / det
        # 飽和域での過大ステップによる発散を防ぐ backtracking（損失が下がるまで半減）
        step = 1.0
        while step > 1e-10:
            na, nb = a - step * da, b - step * db
            new = loss(na, nb)
            if new < cur:
                break
            step /= 2
        else:
            break
        if cur - new < 1e-12:
            a, b = na, nb
            break
        a, b, cur = na, nb, new
    return a, b


def apply_platt(probs: list[float], params: tuple[float, float]) -> list[float]:
    a, b = params
    return [_sigmoid(a * _logit(p) + b) for p in probs]


# ---------------------------------------------------------------------------
# 閾値（FP/FN）
# ---------------------------------------------------------------------------
def confusion(probs: list[float], labels: list[int], threshold: float) -> dict:
    """`p >= threshold` を陽性とした混同行列と FP/FN 率。"""
    tp = sum(1 for p, y in zip(probs, labels) if p >= threshold and y)
    fp = sum(1 for p, y in zip(probs, labels) if p >= threshold and not y)
    fn = sum(1 for p, y in zip(probs, labels) if p < threshold and y)
    tn = len(probs) - tp - fp - fn
    return {"tp": tp, "fp": fp, "fn": fn, "tn": tn,
            "fpr": fp / (fp + tn) if fp + tn else 0.0,
            "fnr": fn / (fn + tp) if fn + tp else 0.0}


def _cost_rate(c: dict, fp_cost: float, fn_cost: float) -> float:
    n = c["tp"] + c["fp"] + c["fn"] + c["tn"]
    return (fp_cost * c["fp"] + fn_cost * c["fn"]) / n if n else 0.0


def choose_threshold(probs: list[float], labels: list[int], fp_cost: float = 1.0, fn_cost: float = 1.0) -> float:
    """コスト `fp_cost·FP + fn_cost·FN` 最小の閾値。同点は低い閾値（＝見逃し側を減らす・fail-open）。

    PoC ごとの運用コスト（例: 攻撃入力の優先順位付けなら FN を重く）を引数で渡す。
    """
    cands = sorted(set(probs)) + [1.0 + _EPS]
    return min(cands, key=lambda t: (_cost_rate(confusion(probs, labels, t), fp_cost, fn_cost), t))


# ---------------------------------------------------------------------------
# 校正 → held-out 検証
# ---------------------------------------------------------------------------
def _valid_prob(v: Any) -> Optional[float]:
    """有限な [0,1] の実数ならその値、それ以外（None/bool/非数値/範囲外/NaN/inf）は None。"""
    if isinstance(v, bool) or not isinstance(v, (int, float)):
        return None
    v = float(v)
    return v if 0.0 <= v <= 1.0 else None  # NaN は比較が偽、inf は範囲外で弾かれる


def evaluate(samples: list[dict], scores: dict[str, Optional[float]], *, holdout_frac: float = 0.3,
             fp_cost: float = 1.0, fn_cost: float = 1.0, max_gap: float = 0.15, n_bins: int = 10) -> dict:
    """校正 split で Platt と閾値を決め、held-out で校正前/後の ECE・Brier・FP/FN を比較する。

    `scores[id]` が None（Laya 判断なし）のサンプルは黙って捨てず `abstained` に数える。
    有限な [0,1] の実数でない score（範囲外/NaN/inf/bool/非数値）は clamp せず abstain 扱いにし、
    `invalid` にも数える（不正 scorer に偽の有効値・完璧な ECE を与えない）。
    held-out は scorer に依らないよう**全サンプルを先に固定分割**し、各 split 内で abstain を除く。
    両 split にスコア付きの両クラスが無ければ status=insufficient-data とし、評価値は None。
    `overfit` は校正 split と held-out のコスト率差が `max_gap` 超（reward hacking/過適合の疑い）。
    """
    probs = {s["id"]: _valid_prob(scores.get(s["id"])) for s in samples}
    calib_all, hold_all = split_holdout(samples, holdout_frac)
    calib = [s for s in calib_all if probs[s["id"]] is not None]
    hold = [s for s in hold_all if probs[s["id"]] is not None]
    counts = {"n_calib": len(calib), "n_holdout": len(hold),
              "abstained": len(samples) - len(calib) - len(hold),
              "invalid": sum(scores.get(s["id"]) is not None and probs[s["id"]] is None for s in samples)}
    if any({s["label"] for s in rows} != {0, 1} for rows in (calib, hold)):
        return {**counts, "status": "insufficient-data",
                "reason": "Both calibration and holdout require scored samples of both classes.",
                "platt": None, "raw": None, "calibrated": None, "overfit": None}

    def _xy(rows):
        return [probs[s["id"]] for s in rows], [s["label"] for s in rows]

    pc, yc = _xy(calib)
    ph, yh = _xy(hold)
    params = fit_platt(pc, yc)

    def _side(p_cal, p_hold):
        t = choose_threshold(p_cal, yc, fp_cost, fn_cost)
        c_cal, c_hold = confusion(p_cal, yc, t), confusion(p_hold, yh, t)
        gap = _cost_rate(c_hold, fp_cost, fn_cost) - _cost_rate(c_cal, fp_cost, fn_cost)
        return {"threshold": t, "calib": c_cal, "holdout": c_hold, "gap": gap,
                "holdout_ece": ece(p_hold, yh, n_bins), "holdout_brier": brier(p_hold, yh),
                "reliability": reliability_bins(p_hold, yh, n_bins)}

    raw = _side(pc, ph)
    cal = _side(apply_platt(pc, params), apply_platt(ph, params))
    return {**counts, "status": "ok",
            "platt": params, "raw": raw, "calibrated": cal, "overfit": cal["gap"] > max_gap}


# ---------------------------------------------------------------------------
# Laya スコア取得（境界は laya_client のみ）
# ---------------------------------------------------------------------------
_QUESTION = {"vulnerable": {"type": "noul", "instructions":
                            "Probability that this input point is exploitable for the given check."}}


def default_state(sample: dict) -> Optional[dict]:
    """caller が収集・匿名化した実観測 `observations` のみを返す。無ければ abstain。

    observations は check とその実 HTTP/probe 観測を含む dict とする。
    fixture 名、安全/脆弱を暗示する path/field、label/note を混ぜない責任は caller にある。
    build_dataset は正解表であり実観測ではないため、既定でスコア取得できない。
    """
    observations = sample.get("observations")
    if not isinstance(observations, dict) or not observations.get("check") or len(observations) < 2:
        return None
    return observations


def laya_scores(samples: Iterable[dict], state_fn: Callable[[dict], Any] = default_state,
                questions: dict = _QUESTION, decide: Optional[Callable] = None) -> dict[str, Optional[float]]:
    """各サンプルの Laya 確率（`answers[q]["noul"]`）。未導入/障害/範囲外は None（＝abstain）。

    独自 state_fn も実観測からラベル中立な state を作ること。None は観測不足として扱う。
    fixture の ground truth から state やスコアを作った評価は実モデルの校正証拠にならない。
    ponytail: noul の値を確率とみなす。実出力の形（probabilities 等）を PoC で確認したら読み替える。
    """
    if decide is None:
        from wscan.laya_client import decide
    q = next(iter(questions), None)
    out: dict[str, Optional[float]] = {}
    for s in samples:
        out[s["id"]] = None
        if q is None:
            continue
        state = state_fn(s)
        if state is None:
            continue
        res = decide(state, questions)
        v = res["answers"][q].get("noul") if res else None
        out[s["id"]] = _valid_prob(v)
    return out
