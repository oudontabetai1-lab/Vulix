"""Laya 決定モデルの薄いクライアント（OUD-78 / 77a）。

Laya（`convaiinnovations/laya`、Convai Innovations、Apache-2.0）は非自己回帰の決定モデル。
`state` ＋ `questions` スキーマから choice/score/noul を確率つきで 1 forward 返す
（文章生成なし・ローカル実行）。本モジュールは Vulix が Laya を呼ぶ**唯一の境界**で、
**未導入・無効・障害・空入力のいずれでも `None` を返す**。呼び出し側は `None` を
「Laya 判断なし＝従来経路へ」として扱い、完全フォールバックする（加算的・フラグ＋例外保護）。

判定ロジックとは混ぜない**純粋境界**に保つ（HTTP/ブラウザ非依存、`equivalence_probe` と同型に
テスト可能）。通常層では Laya を脆弱性判定（oracle）に使わない — 攻撃入力の選択・優先順位・
ルーティング・triage・探索判断・確信度ラベル側でのみ利用する（設計: OUD-77 調査ノート）。

有効化は環境変数 `WSCAN_LAYA`（既定 OFF）。秘匿情報は扱わない（モデルはローカル実行）。
依存は `requirements-laya.txt` に分離（本体スキャンは Laya 非依存）。
"""

from __future__ import annotations

import os
import threading
from typing import Any, Optional

# GitHub README（https://github.com/NandhaKishorM/laya）で確認した checkpoint と load API。
# 未検証の variant（typed-decisions 等）は confabulation を避けて足さない（必要時に検証して追加）。
_MODEL_ID = "convaiinnovations/laya"
_SUBFOLDERS = {"default": None, "multilingual": "multilingual"}

# variant -> ロード済み agent（プロセス内キャッシュ。重い load を 1 回に）。
_agents: dict[str, Any] = {}
# load 失敗済み variant（以降の decide は重い再 load/再 DL を避けて即 None）。
# ponytail: プロセス内の恒久メモ。復旧を拾うなら一定時間後に再試行するクールダウン化。
_failed: set[str] = set()
# 初回 load の直列化（マルチスレッドで重い laya.load を二重実行しない）。
# ponytail: モジュール単一ロック。load 競合が問題になれば variant 単位のロックへ。
_load_lock = threading.Lock()


def enabled() -> bool:
    """既定 OFF。明示的に有効化したときだけ Laya を使う（env `WSCAN_LAYA`）。"""
    return os.getenv("WSCAN_LAYA", "").strip().lower() in ("1", "true", "yes", "on")


def available() -> bool:
    """有効 かつ `laya` パッケージが import 可能なときだけ True。"""
    if not enabled():
        return False
    try:
        import laya  # noqa: F401
    except Exception:
        return False
    return True


def _load(variant: str) -> Any:
    agent = _agents.get(variant)
    if agent is not None:
        return agent
    with _load_lock:
        # ロック内で再確認（待っている間に他スレッドが load/失敗記録した可能性）。
        agent = _agents.get(variant)
        if agent is not None:
            return agent
        if variant in _failed:
            raise RuntimeError("laya load failed earlier")
        import laya

        subfolder = _SUBFOLDERS[variant]
        try:
            agent = laya.load(_MODEL_ID, subfolder=subfolder) if subfolder else laya.load(_MODEL_ID)
        except Exception:
            _failed.add(variant)
            raise
        _agents[variant] = agent
        return agent


def _answer_ok(spec: Any, ans: Any) -> bool:
    """question の type に対応する回答キー（choice/score/noul）が揃っているか。"""
    if not isinstance(ans, dict):
        return False
    t = spec.get("type") if isinstance(spec, dict) else None
    if t in ("choice", "score", "noul"):
        return t in ans
    return bool(ans)  # type 不明は保守的に「空でない dict」のみ許容


def decide(state: Any, questions: dict, *, variant: str = "default") -> Optional[dict]:
    """Laya で決定を返す。未導入/無効/`questions` 空/障害/応答不正なら `None`（＝フォールバック）。

    戻り値は Laya の `result` dict（`result["answers"][q]` に choice/score/noul と probabilities）。
    呼び出し側は `None` を fail-open に扱う（攻撃・候補・探索を黙って減らさない）。
    """
    if not questions or variant not in _SUBFOLDERS or variant in _failed or not available():
        return None
    try:
        agent = _load(variant)
        result = agent.predict(state, questions)
    except Exception:
        # Laya の障害は確実性の敵（偽陰性）にしない。例外は握って None（従来経路へ）。
        return None
    # 要求した全 question が dict で揃っている完全な応答だけ採る（呼び出し側の KeyError 防止）。
    answers = result.get("answers") if isinstance(result, dict) else None
    if isinstance(answers, dict) and all(_answer_ok(spec, answers.get(q)) for q, spec in questions.items()):
        return result
    return None
