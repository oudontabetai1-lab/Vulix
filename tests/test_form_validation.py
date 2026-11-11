"""Tests for pure helper functions in wscan.form_validation."""

import pytest
from wscan.form_validation import (
    is_blocked_by_constraint_validation,
    classify_constraint_block_reason,
    should_retry_with_validation_bypass,
)


def test_empty_or_none_metadata():
    assert not is_blocked_by_constraint_validation(None)
    assert not is_blocked_by_constraint_validation({})
    assert classify_constraint_block_reason(None) is None
    assert classify_constraint_block_reason({}) is None


def test_file_inputs_are_never_bypassed():
    # ファイル入力はアップロードスキャナ管轄のため bypass 対象外
    meta_file1 = {"isFileInput": True, "targetValid": False}
    meta_file2 = {"targetType": "file", "targetValid": False}
    assert not is_blocked_by_constraint_validation(meta_file1)
    assert not is_blocked_by_constraint_validation(meta_file2)
    assert classify_constraint_block_reason(meta_file1) is None


def test_target_invalid_states():
    # HTML5 constraint validation フラグに応じたブロック検出
    assert is_blocked_by_constraint_validation({"targetValid": False})
    assert is_blocked_by_constraint_validation({
        "targetValidity": {"typeMismatch": True, "valid": False}
    })
    assert is_blocked_by_constraint_validation({
        "targetValidity": {"patternMismatch": True, "valid": False}
    })
    assert is_blocked_by_constraint_validation({
        "targetValidity": {"valueMissing": True, "valid": False}
    })
    assert is_blocked_by_constraint_validation({
        "targetValidity": {"badInput": True, "valid": False}
    })
    assert is_blocked_by_constraint_validation({
        "targetValidity": {"tooLong": True, "valid": False}
    })

    assert classify_constraint_block_reason({
        "targetValidity": {"typeMismatch": True, "valid": False}
    }) == "typeMismatch"
    assert classify_constraint_block_reason({
        "targetValidity": {"patternMismatch": True, "valid": False}
    }) == "patternMismatch"


def test_form_check_validity_failure():
    # フォーム全体の checkValidity() が false
    meta = {"formValid": False, "targetValid": True, "valueMatches": True}
    assert is_blocked_by_constraint_validation(meta)
    assert classify_constraint_block_reason(meta) == "form_invalid"


def test_type_coercion_and_maxlength():
    # input type=number などの型強制で値が空文字列等になり不一致になった場合
    meta_num = {
        "success": False,
        "valueMatches": False,
        "targetType": "number",
        "formValid": True,
    }
    assert is_blocked_by_constraint_validation(meta_num)
    assert classify_constraint_block_reason(meta_num) == "type_coercion:number"

    # maxlength による切り詰め
    meta_len = {
        "success": False,
        "valueMatches": False,
        "targetType": "text",
        "hasMaxLength": True,
        "formValid": True,
    }
    assert is_blocked_by_constraint_validation(meta_len)
    assert classify_constraint_block_reason(meta_len) == "maxlength_restricted"


def test_normal_successful_field():
    # 通常の正常フィールド
    meta_normal = {
        "success": True,
        "targetValid": True,
        "formValid": True,
        "valueMatches": True,
        "targetType": "text",
        "targetValidity": {"valid": True},
    }
    assert not is_blocked_by_constraint_validation(meta_normal)
    assert classify_constraint_block_reason(meta_normal) is None


def test_js_onsubmit_prevent_default_not_constraint_blocked():
    # JS の onsubmit ハンドラ（return false / event.preventDefault()）によるブロックは
    # HTML5 constraint validation の不合格ではないため、pure helper は False を返す。
    meta_js = {
        "success": True,
        "targetValid": True,
        "formValid": True,
        "valueMatches": True,
        "targetType": "text",
        "targetValidity": {"valid": True},
        "hasPattern": False,
        "isRequired": False,
    }
    assert not is_blocked_by_constraint_validation(meta_js)


def test_should_retry_requests_sent_branches():
    # If requests were dispatched (> 0), never retry under any circumstances (prevent duplicate submissions)
    meta_invalid = {"targetValid": False, "targetType": "text"}
    assert not should_retry_with_validation_bypass(1, meta_invalid, "submit_not_dispatched")
    assert not should_retry_with_validation_bypass(2, meta_invalid, "submit_not_dispatched")
    assert not should_retry_with_validation_bypass(-1, meta_invalid, "submit_not_dispatched")
    assert not should_retry_with_validation_bypass(None, meta_invalid, "submit_not_dispatched")  # type: ignore
    assert not should_retry_with_validation_bypass("0", meta_invalid, "submit_not_dispatched")  # type: ignore
    assert not should_retry_with_validation_bypass(True, meta_invalid, "submit_not_dispatched")  # type: ignore
    assert not should_retry_with_validation_bypass(False, meta_invalid, "submit_not_dispatched")  # type: ignore


def test_should_retry_reason_branches():
    # Disallowed reasons: delivered, request_value_unverified, errors, exceptions
    meta_invalid = {"targetValid": False, "targetType": "text"}
    assert not should_retry_with_validation_bypass(0, meta_invalid, "delivered")
    assert not should_retry_with_validation_bypass(0, meta_invalid, "request_value_unverified")
    assert not should_retry_with_validation_bypass(0, meta_invalid, "form_not_found")
    assert not should_retry_with_validation_bypass(0, meta_invalid, "target_not_found")
    assert not should_retry_with_validation_bypass(0, meta_invalid, "target_is_file")
    assert not should_retry_with_validation_bypass(0, meta_invalid, "timeout")
    assert not should_retry_with_validation_bypass(0, meta_invalid, "submit_exception")
    assert not should_retry_with_validation_bypass(0, meta_invalid, "navigation_error")
    assert not should_retry_with_validation_bypass(0, meta_invalid, "exception")
    assert not should_retry_with_validation_bypass(0, meta_invalid, None)
    assert not should_retry_with_validation_bypass(0, meta_invalid, "")
    assert not should_retry_with_validation_bypass(0, meta_invalid, "arbitrary_reason")


def test_should_retry_meta_validation_and_exclusion_branches():
    # Meta must be a valid mapping without file inputs, exceptions, or error markers
    assert not should_retry_with_validation_bypass(0, None, "submit_not_dispatched")
    assert not should_retry_with_validation_bypass(0, {}, "submit_not_dispatched")
    assert not should_retry_with_validation_bypass(0, "not_a_dict", "submit_not_dispatched")  # type: ignore

    # File inputs are handled by upload scanner, never bypassed
    assert not should_retry_with_validation_bypass(0, {"isFileInput": True, "targetValid": False}, "submit_not_dispatched")
    assert not should_retry_with_validation_bypass(0, {"targetType": "file", "targetValid": False}, "submit_not_dispatched")
    assert not should_retry_with_validation_bypass(0, {"targetType": "FILE", "targetValid": False}, "submit_not_dispatched")

    # Exceptions during submission must not trigger retry
    assert not should_retry_with_validation_bypass(0, {"exception": "TimeoutError", "targetValid": False}, "submit_not_dispatched")
    assert not should_retry_with_validation_bypass(0, {"exception": "NavigationError", "targetValid": False}, "submit_not_dispatched")

    # Error fields in meta
    assert not should_retry_with_validation_bypass(0, {"error": "form not found", "targetValid": False}, "submit_not_dispatched")
    assert not should_retry_with_validation_bypass(0, {"error": "target not found", "targetValid": False}, "submit_not_dispatched")
    assert not should_retry_with_validation_bypass(0, {"error": "target is file", "targetValid": False}, "submit_not_dispatched")

    # Clean form with no constraint validation failure
    clean_meta = {
        "success": True,
        "targetValid": True,
        "formValid": True,
        "valueMatches": True,
        "targetType": "text",
        "targetValidity": {"valid": True},
    }
    assert not should_retry_with_validation_bypass(0, clean_meta, "submit_not_dispatched")


def test_should_retry_valid_branches():
    # 1. targetValid is False
    assert should_retry_with_validation_bypass(
        0, {"targetValid": False, "targetType": "text"}, "submit_not_dispatched"
    )

    # 2. formValid is False
    assert should_retry_with_validation_bypass(
        0, {"formValid": False, "targetValid": True, "valueMatches": True}, "submit_not_dispatched"
    )

    # 3. targetValidity flags
    for flag in ("typeMismatch", "patternMismatch", "valueMissing", "tooLong", "badInput"):
        assert should_retry_with_validation_bypass(
            0, {"targetValidity": {flag: True, "valid": False}, "targetType": "text"}, "submit_not_dispatched"
        )

    # 4. type coercion on numeric/date/url
    meta_num = {
        "success": False,
        "valueMatches": False,
        "targetType": "number",
        "formValid": True,
    }
    assert should_retry_with_validation_bypass(0, meta_num, "target_value_not_successful")

    # 5. maxlength truncation
    meta_len = {
        "success": False,
        "valueMatches": False,
        "targetType": "text",
        "hasMaxLength": True,
        "formValid": True,
    }
    assert should_retry_with_validation_bypass(0, meta_len, "target_value_not_successful")

