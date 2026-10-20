"""タイムアウト値の検証ロジック（純粋関数）。

CLI・config(wscan.yaml)・ダッシュボード(WS/API)から渡されるタイムアウト値の
正当性を開始前に検証し、無効値（0・負数・NaN・Inf・非数値）を拒否する。
HTTP/ページ読み込み上限と LLM 応答上限を取り違えないよう、エラーメッセージで
対象を明示する。ブラウザやネットワークに依存せず単体テスト可能。
"""
from __future__ import annotations

import math
from typing import Any


def validate_positive_timeout(
    value: Any,
    name: str = "タイムアウト",
    *,
    allow_none: bool = False,
    default: float | None = None,
) -> float | None:
    """正の有限 float 値を検証して返す（純粋関数）。

    Parameters
    ----------
    value : Any
        検証対象の値（文字列・数値など）。
    name : str
        エラーメッセージに含める設定項目名（例: "LLM タイムアウト"）。
    allow_none : bool
        None または空文字を許容するか。True の場合 default を返す。
    default : float | None
        allow_none=True 時の既定値。

    Returns
    -------
    float | None
        検証済みの正の有限秒数。

    Raises
    ------
    ValueError
        0、負数、NaN、無限大(Inf)、数値に変換できない値の場合。
    """
    if value is None or (isinstance(value, str) and not value.strip()):
        if allow_none:
            return default
        raise ValueError(f"{name} が指定されていません（正の有限秒を指定してください）")

    try:
        val = float(value)
    except (TypeError, ValueError) as exc:
        raise ValueError(f"{name} は数値である必要があります: {value!r}") from exc

    if math.isnan(val):
        raise ValueError(f"{name} に NaN は指定できません: {value!r}")

    if math.isinf(val):
        raise ValueError(f"{name} に無限大(Inf)は指定できません: {value!r}")

    if val <= 0:
        raise ValueError(f"{name} は正の数値である必要があります（0または負数は不可）: {value!r}")

    return val


def validate_scan_timeouts(
    *,
    timeout: Any = None,
    llm_timeout: Any = None,
    llm_stream_timeout: Any = None,
    allow_none: bool = True,
    default_timeout: float = 30.0,
    default_llm_timeout: float = 30.0,
    default_llm_stream_timeout: float = 90.0,
) -> dict[str, float]:
    """スキャンで使用されるタイムアウト群をまとめて検証する（純粋関数）。

    HTTP/ページ読み込み上限と LLM 応答上限（one-shot / streaming）を取り違えないよう、
    それぞれの項目名を明示したエラーを発生させる。

    Returns
    -------
    dict[str, float]
        正規化されたタイムアウト秒数の辞書:
        {"timeout": ..., "llm_timeout": ..., "llm_stream_timeout": ...}
    """
    v_timeout = validate_positive_timeout(
        timeout,
        "HTTP/ページ読み込みタイムアウト (timeout)",
        allow_none=allow_none,
        default=default_timeout,
    )
    v_llm = validate_positive_timeout(
        llm_timeout,
        "LLM タイムアウト (llm_timeout_seconds)",
        allow_none=allow_none,
        default=default_llm_timeout,
    )
    v_stream = validate_positive_timeout(
        llm_stream_timeout,
        "LLM streaming タイムアウト (llm_stream_timeout_seconds)",
        allow_none=allow_none,
        default=default_llm_stream_timeout,
    )

    return {
        "timeout": v_timeout if v_timeout is not None else default_timeout,
        "llm_timeout": v_llm if v_llm is not None else default_llm_timeout,
        "llm_stream_timeout": v_stream if v_stream is not None else default_llm_stream_timeout,
    }
