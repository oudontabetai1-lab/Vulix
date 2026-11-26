"""期待情報利得（Expected Information Gain）による probe 候補の決定論ランキング（純粋関数）。

位置づけ（重要）:
- **shadow 専用**。Agent の実際の work 順序は変えず、「IG で並べたらこうなる」を観測用に出すだけ。
- ここで使う確率は **校正された確率ではない**。仮説の既存状態（未検証/部分的証拠/確証）と
  probe の種別を **粗いクラス**に写像した順序づけ用の値で、表は下の定数に明示する。
  score の小数点以下の精密さに意味はなく、意味があるのは順位だけ。
- confidence（仮説が真らしさ）は policy の allow ではない。ランクが高い＝実行してよい、ではない。
  scope/承認の判定は別層。必須 baseline work は `mandatory` で印を付け、順位に関係なく実行される。

式（2 値仮説 H、観測 o の離散分布）:
    EIG = H(prior) - Σ_o P(o) · H(P(H|o))
        P(o)   = prior·P(o|H) + (1-prior)·P(o|¬H)
        P(H|o) = prior·P(o|H) / P(o)
        H(p)   = -p·log2 p - (1-p)·log2(1-p)    （ビット）
    score = EIG · (1 - risk) / ((1 + cost) · (1 + repeats))
"""
from __future__ import annotations

import math
from dataclasses import dataclass, field
from typing import Mapping, Sequence

# ---------------------------------------------------------------------------
# 粗い確率クラス（由来を明示。経験的に校正した値ではない）
# ---------------------------------------------------------------------------

# 仮説の状態 → P(仮説が真) の粗いクラス。
#   unverified : 未検証（agent の自己申告のみ。"五分五分より低め"の弱い事前）
#   partial    : 部分的な証拠（dynamic replay で再現、決定論では未確証。五分五分）
#   confirmed  : 決定論スキャナで確証（ほぼ真）
#   rejected   : 否定済み（ほぼ偽）
HYPOTHESIS_STATE_PRIOR: dict[str, float] = {
    "unverified": 0.25,
    "partial": 0.5,
    "confirmed": 0.95,
    "rejected": 0.05,
}
DEFAULT_STATE = "unverified"

# probe 種別 → (P(陽性|真), P(陽性|偽))。粗いクラス。
#   deterministic : 決定論 oracle（応答差分で判定するスキャナ・再現検証）
#   heuristic     : 反射/ステータスなど弱い判定
#   weak          : ほぼ情報を持たない（探索・認証など仮説を直接検証しない work）
PROBE_CLASS_MODEL: dict[str, tuple[float, float]] = {
    "deterministic": (0.9, 0.05),
    "heuristic": (0.7, 0.2),
    "weak": (0.55, 0.45),
}
DEFAULT_PROBE_CLASS = "weak"

_SCORE_DIGITS = 12  # 浮動小数の揺れで tie-break が不安定にならないよう丸める


def binary_entropy(p: float) -> float:
    """2 値エントロピー（ビット）。p が 0/1（または範囲外）なら 0。"""
    if not isinstance(p, (int, float)) or math.isnan(p) or p <= 0.0 or p >= 1.0:
        return 0.0
    return -(p * math.log2(p) + (1.0 - p) * math.log2(1.0 - p))


def expected_information_gain(
    prior: float, outcome_model: Sequence[tuple[float, float]]
) -> float:
    """事前確率 `prior` と観測モデルから期待情報利得（ビット）を返す。

    outcome_model: 結果ごとの (P(o|H), P(o|¬H))。各列（H 側・¬H 側）の合計は 1。
    prior が 0/1（エントロピー 0）なら 0。モデルが不正なら ValueError。
    """
    prior = _clamp01(prior)
    if not outcome_model:
        raise ValueError("outcome_model must not be empty")
    sum_h = sum(h for h, _ in outcome_model)
    sum_nh = sum(n for _, n in outcome_model)
    if any(h < 0 or n < 0 for h, n in outcome_model) or abs(sum_h - 1) > 1e-6 or abs(sum_nh - 1) > 1e-6:
        raise ValueError("outcome probabilities must be non-negative and sum to 1 per hypothesis side")
    prior_entropy = binary_entropy(prior)
    if prior_entropy <= 0.0:
        return 0.0
    expected_posterior = 0.0
    for p_h, p_nh in outcome_model:
        p_o = prior * p_h + (1.0 - prior) * p_nh
        if p_o <= 0.0:
            continue
        expected_posterior += p_o * binary_entropy(prior * p_h / p_o)
    # 数値誤差で微小な負値になるのを 0 に丸める（IG は非負）
    return max(0.0, prior_entropy - expected_posterior)


def binary_outcome_model(probe_class: str) -> tuple[tuple[float, float], tuple[float, float]]:
    """probe クラスから (陽性, 陰性) の観測モデルを作る。未知クラスは weak。"""
    tpr, fpr = PROBE_CLASS_MODEL.get(probe_class, PROBE_CLASS_MODEL[DEFAULT_PROBE_CLASS])
    return ((tpr, fpr), (1.0 - tpr, 1.0 - fpr))


@dataclass(frozen=True)
class ProbeCandidate:
    candidate_id: str
    state: str = DEFAULT_STATE
    probe_class: str = DEFAULT_PROBE_CLASS
    cost: float = 0.0       # 0 以上。単位は呼び出し側（例: 想定 step 数）
    risk: float = 0.0       # 0..1。1 なら score 0（候補は消さず末尾側へ）
    repeats: int = 0        # 同種 probe の既試行回数（繰り返しペナルティ）
    mandatory: bool = False  # 決定論スケジューラが投入した必須 baseline


@dataclass(frozen=True)
class RankedCandidate:
    candidate_id: str
    rank: int  # 1 始まり
    score: float
    eig_bits: float
    prior: float
    state: str
    probe_class: str
    mandatory: bool
    reasons: tuple[str, ...] = field(default_factory=tuple)

    def to_dict(self) -> dict:
        return {
            "id": self.candidate_id, "rank": self.rank, "score": round(self.score, 6),
            "eig_bits": round(self.eig_bits, 6), "prior": self.prior, "state": self.state,
            "probe_class": self.probe_class, "mandatory": self.mandatory, "reasons": list(self.reasons),
        }


def _clamp01(value) -> float:
    try:
        v = float(value)
    except (TypeError, ValueError):
        return 0.0
    if math.isnan(v):
        return 0.0
    return min(1.0, max(0.0, v))


def _nonneg(value) -> float:
    try:
        v = float(value)
    except (TypeError, ValueError):
        return 0.0
    if math.isnan(v) or v < 0:
        return 0.0
    return v if not math.isinf(v) else 1e12


def score_candidate(candidate: ProbeCandidate) -> tuple[float, float, float, tuple[str, ...]]:
    """(score, eig_bits, prior, reasons)。入力の不正値は安全側（情報利得を作らない側）へ丸める。"""
    reasons: list[str] = []
    state = candidate.state if candidate.state in HYPOTHESIS_STATE_PRIOR else DEFAULT_STATE
    if state != candidate.state:
        reasons.append(f"unknown_state_as_{DEFAULT_STATE}")
    probe_class = candidate.probe_class if candidate.probe_class in PROBE_CLASS_MODEL else DEFAULT_PROBE_CLASS
    if probe_class != candidate.probe_class:
        reasons.append(f"unknown_probe_class_as_{DEFAULT_PROBE_CLASS}")
    prior = HYPOTHESIS_STATE_PRIOR[state]
    eig = expected_information_gain(prior, binary_outcome_model(probe_class))
    risk = _clamp01(candidate.risk)
    cost = _nonneg(candidate.cost)
    repeats = int(_nonneg(candidate.repeats))
    score = eig * (1.0 - risk) / ((1.0 + cost) * (1.0 + repeats))
    reasons.append(f"state={state}(prior={prior}) probe={probe_class} eig={eig:.4f}bit")
    if risk:
        reasons.append(f"risk_discount={1.0 - risk:.2f}")
    if cost:
        reasons.append(f"cost_divisor={1.0 + cost:.2f}")
    if repeats:
        reasons.append(f"repeat_divisor={1 + repeats}")
    if eig <= 0.0:
        reasons.append("no_information_gain")
    return score, eig, prior, tuple(reasons)


def rank_candidates(
    candidates: Sequence[ProbeCandidate], *, mandatory_first: bool = True
) -> list[RankedCandidate]:
    """候補を IG 順に並べる。入力の順序を baseline とし、同点は baseline 順 → id 順（決定論）。

    mandatory_first=True（既定）: 必須 baseline を先頭ブロックに置き（ブロック内は IG 順）、
    任意候補で必須 work が後回しにならないことを構造的に保証する。出力は入力の置換（候補は消さない）。
    空入力は空リスト。
    """
    scored = []
    for index, cand in enumerate(candidates):
        score, eig, prior, reasons = score_candidate(cand)
        scored.append((cand, index, score, eig, prior, reasons))

    def key(entry):
        cand, index, score, *_ = entry
        tier = 0 if (mandatory_first and cand.mandatory) else (1 if mandatory_first else 0)
        return (tier, -round(score, _SCORE_DIGITS), index, cand.candidate_id)

    ordered = sorted(scored, key=key)
    return [
        RankedCandidate(
            candidate_id=cand.candidate_id, rank=position, score=score, eig_bits=eig, prior=prior,
            state=cand.state if cand.state in HYPOTHESIS_STATE_PRIOR else DEFAULT_STATE,
            probe_class=cand.probe_class if cand.probe_class in PROBE_CLASS_MODEL else DEFAULT_PROBE_CLASS,
            mandatory=cand.mandatory, reasons=reasons,
        )
        for position, (cand, _i, score, eig, prior, reasons) in enumerate(ordered, start=1)
    ]


def hypothesis_state(hypothesis: Mapping | None) -> str:
    """既存の仮説 dict（Agent harness の形）を粗い状態クラスへ写像する。仮説なしは unverified。"""
    if not hypothesis:
        return DEFAULT_STATE
    status = str(hypothesis.get("status", "") or "").lower()
    if hypothesis.get("deterministic_confirmed"):
        return "confirmed"
    if status == "rejected":
        return "rejected"
    if hypothesis.get("dynamic_verified") or status == "accepted" or hypothesis.get("evidence_ids"):
        return "partial"
    return "unverified"
