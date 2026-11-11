"""Tests for pure helper functions in wscan.form_validation."""

import pytest
from wscan.form_validation import (
    is_blocked_by_constraint_validation,
    classify_constraint_block_reason,
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
