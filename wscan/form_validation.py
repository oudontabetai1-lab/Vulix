"""ブラウザ側フォーム制約検証（HTML5 Constraint Validation）の分類ヘルパー。

HTML5 の type（url, email, number 等）、required、pattern、maxlength などによる
クライアント側バリデーションはセキュリティ境界ではないため、プローブ送達が
これらによって阻害された場合は bypass 再試行の対象とする。
一方、file 入力（アップロードスキャナ管轄）や JavaScript イベントによる送信阻止は
制約検証ブロックとはみなさない。
"""

from __future__ import annotations

from typing import Any, Mapping


def is_blocked_by_constraint_validation(meta: Mapping[str, Any] | None) -> bool:
    """フォームプローブの送達失敗がブラウザのクライアント側制約検証に起因するか判定する純粋関数。

    ファイル入力（file）はアップロードスキャナ管轄のため対象外。
    HTML5 constraint validation（typeMismatch, patternMismatch, valueMissing, badInput 等）、
    form.checkValidity() の不合格、または type 制限/maxlength による値設定阻害を検出する。
    """
    if not meta or not isinstance(meta, (dict, Mapping)):
        return False
    if meta.get("isFileInput") or (meta.get("targetType") or "").lower() == "file":
        return False

    # 1. target 要素の validity が invalid、または各バリデーション制約フラグの違反
    if meta.get("targetValid") is False:
        return True
    validity = meta.get("targetValidity")
    if isinstance(validity, (dict, Mapping)):
        if any(validity.get(k) for k in (
            "typeMismatch", "patternMismatch", "valueMissing",
            "tooLong", "tooShort", "rangeUnderflow", "rangeOverflow",
            "stepMismatch", "badInput", "customError",
        )):
            return True

    # 2. フォーム全体の checkValidity() が invalid
    if meta.get("formValid") is False:
        return True

    # 3. 型強制や maxlength による値設定・FormData 反映の失敗
    target_type = (meta.get("targetType") or "").lower()
    value_matches = meta.get("valueMatches", True)
    if not value_matches:
        if target_type in (
            "number", "range", "date", "datetime-local",
            "time", "month", "week", "color", "email", "url",
        ):
            return True
        if meta.get("hasMaxLength"):
            return True

    # 4. 制約属性（pattern, required, type制限等）が存在し、値設定や送信に失敗した場合
    if meta.get("hasPattern") or meta.get("isRequired"):
        if not meta.get("success") or meta.get("formValid") is False or meta.get("targetValid") is False:
            return True

    return False


def classify_constraint_block_reason(meta: Mapping[str, Any] | None) -> str | None:
    """制約検証によるブロック要因の識別子を返す純粋関数（観測・ログ用）。"""
    if not is_blocked_by_constraint_validation(meta):
        return None
    validity = meta.get("targetValidity") if isinstance(meta, (dict, Mapping)) else None
    if isinstance(validity, (dict, Mapping)):
        for k in (
            "typeMismatch", "patternMismatch", "valueMissing",
            "tooLong", "tooShort", "badInput", "rangeUnderflow",
            "rangeOverflow", "stepMismatch", "customError",
        ):
            if validity.get(k):
                return k
    target_type = ((meta or {}).get("targetType") or "").lower()
    if target_type in ("number", "range", "date", "datetime-local", "time", "month", "week", "color"):
        return f"type_coercion:{target_type}"
    if (meta or {}).get("hasMaxLength"):
        return "maxlength_restricted"
    if (meta or {}).get("hasPattern"):
        return "patternMismatch"
    if (meta or {}).get("isRequired"):
        return "valueMissing"
    if (meta or {}).get("formValid") is False:
        return "form_invalid"
    return "constraint_validation_blocked"


def should_retry_with_validation_bypass(
    requests_sent_after_submit: int,
    meta: Mapping[str, Any] | None,
    reason: str | None,
) -> bool:
    """Determine whether to retry form submission with validation bypass.

    A retry is executed ONLY when:
    1. Zero requests were dispatched after submit (requests_sent_after_submit == 0).
    2. The failure reason is an undispatched constraint blockage ("submit_not_dispatched"
       or "target_value_not_successful").
    3. The in-page meta shows a constraint-validation failure (form or target invalid).
    4. No requests were dispatched, no navigation/other exceptions occurred, the form
       and target were found, and the target is not a file input.
    """
    if type(requests_sent_after_submit) is not int or requests_sent_after_submit != 0:
        return False

    if not reason:
        return False

    if reason in (
        "delivered",
        "request_value_unverified",
        "form_not_found",
        "target_not_found",
        "target_is_file",
        "timeout",
        "submit_exception",
        "navigation_error",
        "exception",
    ):
        return False

    if reason not in ("submit_not_dispatched", "target_value_not_successful"):
        return False

    if not meta or not isinstance(meta, (dict, Mapping)):
        return False

    if meta.get("isFileInput") or (meta.get("targetType") or "").lower() == "file":
        return False

    if meta.get("exception"):
        return False

    if meta.get("error") in ("form not found", "target not found", "target is file"):
        return False

    return is_blocked_by_constraint_validation(meta)

