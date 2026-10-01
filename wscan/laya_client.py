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
from typing import Any, Optional

# GitHub README（https://github.com/NandhaKishorM/laya）で確認した checkpoint と load API。
# 未検証の variant（typed-decisions 等）は confabulation を避けて足さない（必要時に検証して追加）。
_MODEL_ID = "convaiinnovations/laya"
_SUBFOLDERS = {"default": None, "multilingual": "multilingual"}

# variant -> ロード済み agent（プロセス内キャッシュ。重い load を 1 回に）。
_agents: dict[str, Any] = {}


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
    import laya

    subfolder = _SUBFOLDERS.get(variant, None)
    agent = laya.load(_MODEL_ID, subfolder=subfolder) if subfolder else laya.load(_MODEL_ID)
    _agents[variant] = agent
    return agent


def decide(state: Any, questions: dict, *, variant: str = "default") -> Optional[dict]:
    """Laya で決定を返す。未導入/無効/`questions` 空/障害/応答不正なら `None`（＝フォールバック）。

    戻り値は Laya の `result` dict（`result["answers"][q]` に choice/score/noul と probabilities）。
    呼び出し側は `None` を fail-open に扱う（攻撃・候補・探索を黙って減らさない）。
    """
    if not questions or not available():
        return None
    try:
        agent = _load(variant)
        result = agent.predict(state, questions)
    except Exception:
        # Laya の障害は確実性の敵（偽陰性）にしない。例外は握って None（従来経路へ）。
        return None
    if isinstance(result, dict) and isinstance(result.get("answers"), dict):
        return result
    return None
