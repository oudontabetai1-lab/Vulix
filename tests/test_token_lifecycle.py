"""Anti-CSRF / Nonce トークン・ライフサイクル契約の単体テスト（ブラウザ非依存・純粋テスト）。

本テストスイートは、TokenSource, TokenBinding, RefreshStrategy, TokenSnapshot,
TokenOutcome, RetryDecision, TokenCapabilityMatrix の契約仕様および純粋関数群を検証する。
"""
from __future__ import annotations

import dataclasses
import json
import pickle
import pytest

from wscan.token_lifecycle import (
    ALL_TOKEN_CARRIERS,
    ALL_TOKEN_TRANSPORTS,
    CarrierCapabilityEntry,
    ConsumptionCondition,
    DeclaredStatus,
    RefreshKind,
    RefreshStrategy,
    RetryDecision,
    TOKEN_LIFECYCLE_DISCLAIMER,
    TokenBinding,
    TokenCapabilityMatrix,
    TokenCarrier,
    TokenOutcome,
    TokenOutcomeKind,
    TokenSnapshot,
    TokenSource,
    TokenSourceType,
    TokenTransport,
    build_token_capability_matrix,
    classify_token_response,
    create_token_snapshot,
    decide_token_retry,
    derive_token_ref_id,
    is_probe_conclusive,
    normalize_carrier,
    normalize_status,
    normalize_transport,
    redact_token_value,
)


# ── 1. 型付き契約の構築テスト ──────────────────────────────────────────────

def test_contract_construction_all_types():
    """各契約データクラス・Enumの構築と不変条件を検証する。"""
    # 1. TokenSourceType 全値での TokenSource 構築
    for st in TokenSourceType:
        src = TokenSource(
            source_type=st,
            identifier=f"test_{st.value}",
            extraction_path="$.token",
            discovery_url="https://example.com/form",
            discovery_method="POST",
            metadata={"source_kind": st.value},
        )
        assert src.source_type == st
        assert src.identifier == f"test_{st.value}"
        assert src.is_discovered is True

    # 2. ConsumptionCondition 全値での TokenBinding 構築
    for cc in ConsumptionCondition:
        binding = TokenBinding(
            consumption=cc,
            actor_id="admin_user",
            session_id_ref="sess_ref_abc123",
            scope="/admin/settings",
            max_age_seconds=3600.0,
            metadata={"role": "admin"},
        )
        assert binding.consumption == cc
        assert binding.actor_id == "admin_user"
        assert binding.session_id_ref == "sess_ref_abc123"

    # 3. RefreshKind 全値での RefreshStrategy 構築
    for rk in RefreshKind:
        strat = RefreshStrategy(
            strategy=rk,
            endpoint_url="https://example.com/api/csrf",
            method="GET",
            selector_or_key="csrf_token",
            headers={"Accept": "application/json"},
            max_retries=2,
            timeout_seconds=5.0,
        )
        assert strat.strategy == rk
        assert strat.max_retries == 2

    # 4. TokenOutcomeKind 全値での TokenOutcome 構築
    for ok in TokenOutcomeKind:
        outcome = TokenOutcome(
            outcome=ok,
            reason_code=f"reason_{ok.value}",
            detail=f"Detail for {ok.value}",
            http_status_hint=200 if ok == TokenOutcomeKind.OK else 403,
            is_retryable=(ok == TokenOutcomeKind.RETRYABLE),
        )
        assert outcome.outcome == ok
        assert outcome.reason_code == f"reason_{ok.value}"

    # 5. RetryDecision 構築
    decision = RetryDecision(
        should_retry=True,
        reason="Test retry",
        attempt_count=1,
        max_retries=2,
        requires_refresh=True,
    )
    assert decision.should_retry is True
    assert decision.requires_refresh is True


# ── 2. マスキングと秘匿センチネルテスト（Redaction Sentinel） ─────────────

def test_redaction_sentinel_never_leaks_raw_secret():
    """生シークレット値が repr / asdict / to_dict / to_evidence / json に現れないことを検証。"""
    dummy_secret = "SUPER_SECRET_NONCE_VALUE_DO_NOT_LEAK_998877_XYZ"
    provenance = "form:csrfmiddlewaretoken @ https://example.com/checkout"
    scope = "https://example.com/checkout"

    binding = TokenBinding(consumption=ConsumptionCondition.ONE_TIME, actor_id="user42")
    source = TokenSource(source_type=TokenSourceType.FORM_FIELD, identifier="csrfmiddlewaretoken")

    snapshot = create_token_snapshot(
        raw_value=dummy_secret,
        provenance=provenance,
        scope=scope,
        binding=binding,
        source=source,
        issued_at=1700000000.0,
        metadata={"note": "checkout form token"},
        retain_secret_for_transport=True,
    )

    # 1. 文字列化・repr で生シークレットが漏洩しないこと
    assert dummy_secret not in repr(snapshot)
    assert dummy_secret not in str(snapshot)

    # 2. dataclasses.asdict で生シークレットが漏洩しないこと
    as_dict = dataclasses.asdict(snapshot)
    assert dummy_secret not in str(as_dict)
    assert "_secret_holder" not in as_dict

    # 3. to_dict() で生シークレットが漏洩しないこと
    snap_dict = snapshot.to_dict()
    assert dummy_secret not in str(snap_dict)
    assert dummy_secret not in json.dumps(snap_dict)

    # 4. to_evidence() で生シークレットが漏洩しないこと
    evidence = snapshot.to_evidence()
    assert dummy_secret not in str(evidence)
    assert dummy_secret not in json.dumps(evidence)

    # 5. マスクされた値と安定した参照IDが生成されていること
    assert snapshot.redacted_value == redact_token_value(dummy_secret)
    assert snapshot.token_ref_id.startswith("tok_ref_")
    assert snapshot.token_ref_id != dummy_secret
    assert snapshot.value_length == len(dummy_secret)
    assert len(snapshot.token_hash_hint) == 8

    # 6. vars(snapshot) および snapshot.__dict__ で生シークレットが漏洩しないこと
    assert dummy_secret not in str(vars(snapshot))
    assert dummy_secret not in vars(snapshot)
    assert dummy_secret not in vars(snapshot).values()

    if hasattr(snapshot, "__dict__"):
        assert dummy_secret not in str(snapshot.__dict__)
        assert dummy_secret not in snapshot.__dict__
        assert dummy_secret not in snapshot.__dict__.values()
        assert "_secret_holder" not in snapshot.__dict__

    # 7. json.dumps(..., default=vars) 試行で生シークレットが漏洩しないこと
    json_via_vars = json.dumps(snapshot, default=vars)
    assert dummy_secret not in json_via_vars

    # 8. pickle.dumps(snapshot) で生シークレットが漏洩しないこと
    pickled = pickle.dumps(snapshot)
    assert dummy_secret.encode("utf-8") not in pickled
    assert dummy_secret not in str(pickled)

    # 9. インスタンス属性に秘密属性が存在しないこと
    assert not hasattr(snapshot, "_secret_holder")
    assert not hasattr(snapshot, "_raw_secret")
    assert not hasattr(snapshot, "_retains_secret")

    # 10. 生シークレットは保持されず、アクセサは明示的に None を返すこと（送信時は RefreshStrategy で都度取得）
    assert snapshot.reveal_secret_for_transport() is None

    # 11. pickle 復元後も安全性が維持され、生値は一切復元・保持されないこと
    restored = pickle.loads(pickled)
    assert restored.token_ref_id == snapshot.token_ref_id
    assert dummy_secret not in repr(restored)
    assert dummy_secret not in str(vars(restored))
    assert restored.reveal_secret_for_transport() is None

    # 12. モジュールレベルの全グローバルに変数が漏洩・保持されていないこと
    import wscan.token_lifecycle as tl_mod
    assert not hasattr(tl_mod, "_RAW_SECRET_VAULT")
    assert not hasattr(tl_mod, "clear_token_secrets")
    assert not hasattr(tl_mod, "release_token_secret")
    for name, val in vars(tl_mod).items():
        if not name.startswith("__"):
            assert dummy_secret not in str(val), f"Global {name} contains secret material!"


def test_token_snapshot_never_retains_secret_and_release_is_noop():
    """TokenSnapshot が生シークレットを一切保持せず、release_secret が安全な no-op であることを検証。"""
    dummy_no_retain = "SECRET_VALUE_FOR_NO_RETAIN_12345"
    snap_no_retain = create_token_snapshot(
        raw_value=dummy_no_retain,
        provenance="header:X-CSRF-Token",
        retain_secret_for_transport=False,
    )
    assert snap_no_retain.reveal_secret_for_transport() is None
    assert dummy_no_retain not in str(vars(snap_no_retain))

    dummy_retain = "SECRET_TO_BE_RELEASED_ABC"
    snap_retain = create_token_snapshot(
        raw_value=dummy_retain,
        provenance="form:csrf",
        retain_secret_for_transport=True,
    )
    # retain_secret_for_transport=True を指定しても生シークレットは保持されない
    assert snap_retain.reveal_secret_for_transport() is None
    assert dummy_retain not in str(vars(snap_retain))
    assert snap_retain.release_secret() is None
    assert snap_retain.reveal_secret_for_transport() is None


def test_create_token_snapshot_is_pure_and_does_not_mutate_globals():
    """create_token_snapshot が純粋関数であり、連続呼び出しでもグローバル状態の肥大化・変異を起こさないことを検証。"""
    import copy
    import wscan.token_lifecycle as tl

    # 呼び出し前のモジュール内グローバル変数の状態を記録
    global_keys_before = set(vars(tl).keys())
    global_state_before = {
        k: copy.copy(v) if isinstance(v, (dict, list, set)) else v
        for k, v in vars(tl).items()
        if not k.startswith("__")
    }

    # 150 回以上の連続呼び出し（毎回異なる生シークレットを渡す）
    snapshots = [
        create_token_snapshot(
            raw_value=f"DYNAMIC_PROBE_SECRET_{i}_{'x' * 32}",
            provenance=f"header:X-CSRF-Token-{i}",
        )
        for i in range(150)
    ]
    assert len(snapshots) == 150

    # 呼び出し後、モジュール内グローバル変数のキー集合に一切の変化がないこと
    global_keys_after = set(vars(tl).keys())
    assert global_keys_before == global_keys_after

    # すべてのグローバル変数が肥大化（unbounded growth）していないこと
    for k, original_val in global_state_before.items():
        current_val = getattr(tl, k)
        if isinstance(original_val, (dict, list, set)):
            assert len(current_val) == len(original_val), f"Global {k} grew in length: {len(original_val)} -> {len(current_val)}"
            assert current_val == original_val, f"Global {k} was mutated"
        else:
            assert current_val == original_val, f"Global {k} was modified"

    # _RAW_SECRET_VAULT などの秘密保管グローバルが存在しないこと
    assert not hasattr(tl, "_RAW_SECRET_VAULT")


def test_no_module_global_holds_secret_material():
    """モジュールレベルのいかなる変数・辞書・オブジェクトも生シークレットを保持しないことを検証。"""
    import wscan.token_lifecycle as tl

    secret = "TOP_SECRET_AUTH_TOKEN_NEVER_PERSIST_MODULE_GLOBAL_999"
    snap = create_token_snapshot(raw_value=secret, provenance="cookie:csrftoken")
    assert snap.token_ref_id.startswith("tok_ref_")

    assert not hasattr(tl, "_RAW_SECRET_VAULT")
    assert not hasattr(tl, "clear_token_secrets")
    assert not hasattr(tl, "release_token_secret")

    # 全モジュール属性の走査: 生シークレットが文字列として一切現れないこと
    for name, val in vars(tl).items():
        if name.startswith("__"):
            continue
        assert secret not in str(val), f"Module global '{name}' exposed secret material!"
        if isinstance(val, dict):
            assert secret not in val, f"Secret found as key in '{name}'"
            assert secret not in val.values(), f"Secret found as value in '{name}'"


def test_redact_token_value_edge_cases():
    """redact_token_value ヘルパーの境界値テスト。"""
    # 空文字列
    assert redact_token_value("") == "[EMPTY]"
    # 8文字以下の短いシークレット（部分残しせず全体を長さでマスク）
    assert redact_token_value("abc") == "[REDACTED:len=3]"
    assert redact_token_value("12345678") == "[REDACTED:len=8]"
    # 9文字以上の通常シークレット
    res = redact_token_value("123456789", keep_prefix=2, keep_suffix=2)
    assert res == "12***89 (len=9)"
    # デフォルト (keep_prefix=4, keep_suffix=2)
    res_def = redact_token_value("abcdefghijklmnop")
    assert res_def == "abcd***op (len=16)"


def test_derive_token_ref_id_consistency():
    """derive_token_ref_id の決定性と一貫性を検証。"""
    assert derive_token_ref_id("").endswith("empty")
    ref1 = derive_token_ref_id("secret_token_alpha")
    ref2 = derive_token_ref_id("secret_token_alpha")
    ref3 = derive_token_ref_id("secret_token_beta")
    assert ref1 == ref2
    assert ref1 != ref3
    assert ref1.startswith("tok_ref_")


# ── 3. 結果分類（Outcome Classification）のテスト ─────────────────────────

def test_classify_refresh_failed_probe_is_not_confirmed_or_negative():
    """不変条件: トークン更新に失敗したプローブは確定（confirmed）や安全（negative）に倒さず BLOCKED に倒す。"""
    # 脆弱性検査時にトークン再取得を試みたが失敗した場合
    for code in (200, 400, 403, 419, 500):
        outcome = classify_token_response(
            status_code=code,
            refresh_attempted=True,
            refresh_succeeded=False,
        )
        assert outcome.outcome == TokenOutcomeKind.BLOCKED
        assert outcome.reason_code == "refresh_failed"
        assert is_probe_conclusive(outcome) is False
        assert outcome.is_retryable is False


def test_classify_token_absent_signals():
    """トークン非送信プローブの分類テスト（CSRF検証有無の判定シグナル）。"""
    # トークンなしでサーバがリクエストを受理した（CSRF脆弱の可能性）
    outcome_accepted = classify_token_response(
        status_code=200,
        token_present=False,
    )
    assert outcome_accepted.outcome == TokenOutcomeKind.MISSING
    assert outcome_accepted.reason_code == "token_absent_accepted"
    assert outcome_accepted.http_status_hint == 200

    # トークンなしでサーバが拒否した（CSRF対策が有効）
    outcome_rejected = classify_token_response(
        status_code=403,
        token_present=False,
    )
    assert outcome_rejected.outcome == TokenOutcomeKind.MISSING
    assert outcome_rejected.reason_code == "token_absent_rejected"
    assert outcome_rejected.http_status_hint == 403


def test_classify_http_status_hint_only_does_not_assume_stale():
    """不変条件: HTTP ステータス（403/419/422）単体では STALE と断定せず INCONCLUSIVE とする。"""
    # 403: 本文・ヘッダに CSRF シグナルがない場合（WAF か認可か不明）
    outcome_403 = classify_token_response(status_code=403, body="Forbidden")
    assert outcome_403.outcome == TokenOutcomeKind.INCONCLUSIVE
    assert outcome_403.reason_code == "status_hint_only"
    assert outcome_403.http_status_hint == 403
    assert is_probe_conclusive(outcome_403) is False

    # 419: 本文がない場合
    outcome_419 = classify_token_response(status_code=419, body="")
    assert outcome_419.outcome == TokenOutcomeKind.INCONCLUSIVE
    assert outcome_419.reason_code == "status_hint_only"

    # 422: 一般的なバリデーションエラー本文
    outcome_422 = classify_token_response(
        status_code=422,
        body='{"errors": {"email": ["Email format is invalid"]}}'
    )
    assert outcome_422.outcome == TokenOutcomeKind.INCONCLUSIVE
    assert outcome_422.reason_code == "status_hint_only"


def test_classify_stale_token_signals():
    """明示的な CSRF エラーシグナルが存在する場合の STALE 分類テスト。"""
    # 1. Laravel 419 + "page expired"
    outcome_laravel = classify_token_response(status_code=419, body="<h1>419 Page Expired</h1>")
    assert outcome_laravel.outcome == TokenOutcomeKind.STALE
    assert outcome_laravel.reason_code == "stale_token_mismatch"
    assert outcome_laravel.is_retryable is True

    # 2. Django 403 + "CSRF verification failed"
    outcome_django = classify_token_response(
        status_code=403,
        body=b"Forbidden (403) CSRF verification failed. Request aborted."
    )
    assert outcome_django.outcome == TokenOutcomeKind.STALE
    assert outcome_django.reason_code == "stale_token_mismatch"

    # 3. Express / csurf + ebadcsrcftoken
    outcome_csurf = classify_token_response(
        status_code=403,
        body='{"code": "EBADCSRFTOKEN", "message": "invalid csrf token"}'
    )
    assert outcome_csurf.outcome == TokenOutcomeKind.STALE

    # 4. レスポンスヘッダに CSRF エラー
    outcome_hdr = classify_token_response(
        status_code=403,
        headers={"X-CSRF-Error": "TokenMismatchException"}
    )
    assert outcome_hdr.outcome == TokenOutcomeKind.STALE


def test_classify_consumption_condition_lifecycle_signals():
    """ワンタイム / ローテーション / 静的 / セッション紐付けのライフサイクルシグナル分類テスト。"""
    # 1. ONE_TIME トークンが再利用された
    binding_one_time = TokenBinding(consumption=ConsumptionCondition.ONE_TIME)
    outcome_ot = classify_token_response(
        status_code=403,
        binding=binding_one_time,
        lifecycle_signal="one_time_reused",
    )
    assert outcome_ot.outcome == TokenOutcomeKind.STALE
    assert outcome_ot.reason_code == "stale_one_time_consumed"

    # 2. ROTATING トークンがリプレイされた
    binding_rotating = TokenBinding(consumption=ConsumptionCondition.ROTATING)
    outcome_rot = classify_token_response(
        status_code=403,
        binding=binding_rotating,
        lifecycle_signal="rotating_replayed",
    )
    assert outcome_rot.outcome == TokenOutcomeKind.STALE
    assert outcome_rot.reason_code == "stale_rotating_token"

    # 3. STATIC トークンが拒否された（リフレッシュ不能なため BLOCKED）
    binding_static = TokenBinding(consumption=ConsumptionCondition.STATIC)
    outcome_static = classify_token_response(
        status_code=403,
        body="invalid csrf token",
        binding=binding_static,
    )
    assert outcome_static.outcome == TokenOutcomeKind.BLOCKED
    assert outcome_static.reason_code == "static_token_rejected"

    # 4. SESSION_BOUND トークンでセッションが失効した
    binding_sess = TokenBinding(consumption=ConsumptionCondition.SESSION_BOUND)
    outcome_sess = classify_token_response(
        status_code=401,
        binding=binding_sess,
        lifecycle_signal="session_expired",
    )
    assert outcome_sess.outcome == TokenOutcomeKind.STALE
    assert outcome_sess.reason_code == "stale_session_bound"


def test_classify_blocked_waf_and_transient_upstream():
    """WAF遮断および一時的ネットワーク障害の分類テスト。"""
    # WAF ブロック本文
    outcome_waf = classify_token_response(
        status_code=403,
        body="Blocked by Cloudflare Security Policy"
    )
    assert outcome_waf.outcome == TokenOutcomeKind.BLOCKED
    assert outcome_waf.reason_code == "blocked_waf_or_policy"
    assert outcome_waf.is_retryable is False

    # 503 Service Unavailable (一時障害)
    outcome_503 = classify_token_response(status_code=503)
    assert outcome_503.outcome == TokenOutcomeKind.RETRYABLE
    assert outcome_503.reason_code == "transient_upstream_error"
    assert outcome_503.is_retryable is True


# ── 4. 有界リトライ判定（Bounded Retry Decision）のテスト ─────────────────

def test_bounded_retry_decisions():
    """有界リトライの判定ルールを検証する。"""
    strat_reload = RefreshStrategy(strategy=RefreshKind.PAGE_RELOAD, max_retries=2)
    strat_none = RefreshStrategy(strategy=RefreshKind.NONE)

    stale_outcome = TokenOutcome(
        outcome=TokenOutcomeKind.STALE,
        reason_code="stale_token_mismatch",
        is_retryable=True,
    )

    # 1. STALE かつ有効なリフレッシュ戦略がある場合: リトライ許可 (requires_refresh=True)
    d1 = decide_token_retry(
        outcome=stale_outcome,
        attempt_count=1,
        max_retries=2,
        refresh_strategy=strat_reload,
    )
    assert d1.should_retry is True
    assert d1.requires_refresh is True

    # 2. 上限到達（attempt_count >= max_retries）: リトライ不可（有界性）
    d_limit = decide_token_retry(
        outcome=stale_outcome,
        attempt_count=2,
        max_retries=2,
        refresh_strategy=strat_reload,
    )
    assert d_limit.should_retry is False
    assert "limit reached" in d_limit.reason

    # 3. STALE だがリフレッシュ戦略が NONE の場合: リトライ不可
    d_no_strat = decide_token_retry(
        outcome=stale_outcome,
        attempt_count=1,
        max_retries=2,
        refresh_strategy=strat_none,
    )
    assert d_no_strat.should_retry is False

    # 4. STATIC トークンバインディング: リフレッシュ不可のためリトライ不可
    binding_static = TokenBinding(consumption=ConsumptionCondition.STATIC)
    d_static = decide_token_retry(
        outcome=stale_outcome,
        attempt_count=1,
        max_retries=2,
        binding=binding_static,
        refresh_strategy=strat_reload,
    )
    assert d_static.should_retry is False

    # 5. BLOCKED 結果: リトライ不可
    blocked_outcome = TokenOutcome(outcome=TokenOutcomeKind.BLOCKED, reason_code="blocked_waf")
    d_blocked = decide_token_retry(outcome=blocked_outcome, attempt_count=1, max_retries=2)
    assert d_blocked.should_retry is False

    # 6. INCONCLUSIVE 結果: 盲目的なリトライは不可
    inconclusive_outcome = TokenOutcome(outcome=TokenOutcomeKind.INCONCLUSIVE, reason_code="status_hint_only")
    d_inconclusive = decide_token_retry(outcome=inconclusive_outcome, attempt_count=1, max_retries=2)
    assert d_inconclusive.should_retry is False

    # 7. OK 結果: 再試行不要
    ok_outcome = TokenOutcome(outcome=TokenOutcomeKind.OK, reason_code="ok")
    d_ok = decide_token_retry(outcome=ok_outcome, attempt_count=1, max_retries=2)
    assert d_ok.should_retry is False

    # 8. RETRYABLE（一時エラー）: リフレッシュ不要で再送可能
    transient_outcome = TokenOutcome(outcome=TokenOutcomeKind.RETRYABLE, reason_code="transient")
    d_transient = decide_token_retry(outcome=transient_outcome, attempt_count=1, max_retries=2)
    assert d_transient.should_retry is True
    assert d_transient.requires_refresh is False


# ── 5. 機能マトリクス（Capability Matrix）のテスト ─────────────────────────

def test_capability_matrix_construction_and_invariants():
    """機能マトリクスの構築と各トランスポート・キャリアの宣言ステータスを検証。"""
    matrix = build_token_capability_matrix()

    # 1. 宣言総数 = 6 キャリア × 7 トランスポート = 42
    assert len(matrix.entries) == 42
    assert len(ALL_TOKEN_CARRIERS) == 6
    assert len(ALL_TOKEN_TRANSPORTS) == 7

    # 2. 不変条件チェック: 宣言 != 実行保証
    assert matrix.declaration_only is True
    assert matrix.execution_coverage_claimed is False
    assert TOKEN_LIFECYCLE_DISCLAIMER in matrix.disclaimer

    # 3. 各トランスポートの代表的宣言ステータスチェック（現スライスでは未統合のため SUPPORTED は一切宣言せず PLANNED とする）
    # Playwright: form, multipart, json, header が PLANNED
    assert matrix.get_status(TokenCarrier.FORM_URLENCODED, TokenTransport.PLAYWRIGHT) == DeclaredStatus.PLANNED
    assert matrix.get_status(TokenCarrier.MULTIPART, TokenTransport.PLAYWRIGHT) == DeclaredStatus.PLANNED
    assert matrix.get_status(TokenCarrier.JSON, TokenTransport.PLAYWRIGHT) == DeclaredStatus.PLANNED
    assert matrix.is_supported("form", "playwright") is False
    assert matrix.is_planned("form", "playwright") is True

    # HTTPX: form, json, header が PLANNED
    assert matrix.get_status(TokenCarrier.FORM_URLENCODED, TokenTransport.HTTPX) == DeclaredStatus.PLANNED
    assert matrix.get_status(TokenCarrier.JSON, TokenTransport.HTTPX) == DeclaredStatus.PLANNED
    assert matrix.is_supported("json", "httpx") is False
    assert matrix.is_planned("json", "httpx") is True

    # SPA API: form-urlencoded は UNSUPPORTED、JSON は PLANNED
    assert matrix.get_status(TokenCarrier.FORM_URLENCODED, TokenTransport.SPA_API) == DeclaredStatus.UNSUPPORTED
    assert matrix.get_status(TokenCarrier.JSON, TokenTransport.SPA_API) == DeclaredStatus.PLANNED
    assert matrix.is_supported(TokenCarrier.JSON, TokenTransport.SPA_API) is False
    assert matrix.is_planned(TokenCarrier.JSON, TokenTransport.SPA_API) is True

    # HAR Replay: 静的記録再生のため動的 nonce は BLOCKED
    assert matrix.get_status(TokenCarrier.FORM_URLENCODED, TokenTransport.HAR_REPLAY) == DeclaredStatus.BLOCKED
    assert matrix.get_status(TokenCarrier.HTTP_HEADER, TokenTransport.HAR_REPLAY) == DeclaredStatus.BLOCKED
    assert matrix.get_status(TokenCarrier.COOKIE, TokenTransport.HAR_REPLAY) == DeclaredStatus.BLOCKED

    # Agent: form-urlencoded は PLANNED、multipart は現時点で UNSUPPORTED
    assert matrix.get_status(TokenCarrier.FORM_URLENCODED, TokenTransport.AGENT) == DeclaredStatus.PLANNED
    assert matrix.get_status(TokenCarrier.MULTIPART, TokenTransport.AGENT) == DeclaredStatus.UNSUPPORTED
    assert matrix.is_supported(TokenCarrier.FORM_URLENCODED, TokenTransport.AGENT) is False
    assert matrix.is_planned(TokenCarrier.FORM_URLENCODED, TokenTransport.AGENT) is True

    # Hybrid: form-urlencoded, multipart, json が PLANNED
    assert matrix.get_status(TokenCarrier.FORM_URLENCODED, TokenTransport.HYBRID) == DeclaredStatus.PLANNED
    assert matrix.get_status(TokenCarrier.MULTIPART, TokenTransport.HYBRID) == DeclaredStatus.PLANNED
    assert matrix.is_supported(TokenCarrier.FORM_URLENCODED, TokenTransport.HYBRID) is False
    assert matrix.is_planned(TokenCarrier.FORM_URLENCODED, TokenTransport.HYBRID) is True

    # Flow: form, multipart, json, header が PLANNED
    assert matrix.get_status(TokenCarrier.FORM_URLENCODED, TokenTransport.FLOW) == DeclaredStatus.PLANNED
    assert matrix.is_supported(TokenCarrier.FORM_URLENCODED, TokenTransport.FLOW) is False
    assert matrix.is_planned(TokenCarrier.FORM_URLENCODED, TokenTransport.FLOW) is True

    # 不誠実なステータス宣言の防止: 現スライスでは未統合のため SUPPORTED は 0 件であること
    supported_entries = [e for e in matrix.entries if e.status == DeclaredStatus.SUPPORTED]
    assert len(supported_entries) == 0
    assert all(e.status in (DeclaredStatus.PLANNED, DeclaredStatus.UNSUPPORTED, DeclaredStatus.BLOCKED) for e in matrix.entries)


def test_capability_matrix_distinguishes_supported_vs_planned():
    """将来のスライスで統合が完了した際に SUPPORTED と PLANNED を明確に区別できることを検証。"""
    default_matrix = build_token_capability_matrix()

    # 現スライスでは未統合のため PLANNED であり、is_supported は False
    assert default_matrix.get_status(TokenCarrier.FORM_URLENCODED, TokenTransport.PLAYWRIGHT) == DeclaredStatus.PLANNED
    assert default_matrix.is_supported(TokenCarrier.FORM_URLENCODED, TokenTransport.PLAYWRIGHT) is False
    assert default_matrix.is_planned(TokenCarrier.FORM_URLENCODED, TokenTransport.PLAYWRIGHT) is True

    # 後続スライスでの統合完了を模したオーバーライド
    integrated_matrix = build_token_capability_matrix(
        overrides={
            (TokenCarrier.FORM_URLENCODED, TokenTransport.PLAYWRIGHT): DeclaredStatus.SUPPORTED,
        }
    )

    # 統合後は SUPPORTED に遷移し、is_supported が True、is_planned が False となること
    assert integrated_matrix.get_status(TokenCarrier.FORM_URLENCODED, TokenTransport.PLAYWRIGHT) == DeclaredStatus.SUPPORTED
    assert integrated_matrix.is_supported(TokenCarrier.FORM_URLENCODED, TokenTransport.PLAYWRIGHT) is True
    assert integrated_matrix.is_planned(TokenCarrier.FORM_URLENCODED, TokenTransport.PLAYWRIGHT) is False

    # 他の未統合トランスポートは依然として PLANNED のまま区別されること
    assert integrated_matrix.get_status(TokenCarrier.JSON, TokenTransport.PLAYWRIGHT) == DeclaredStatus.PLANNED
    assert integrated_matrix.is_supported(TokenCarrier.JSON, TokenTransport.PLAYWRIGHT) is False
    assert integrated_matrix.is_planned(TokenCarrier.JSON, TokenTransport.PLAYWRIGHT) is True

    # DeclaredStatus の Enum レベルで相違すること
    assert DeclaredStatus.SUPPORTED != DeclaredStatus.PLANNED


def test_capability_matrix_overrides_and_serialization():
    """カスタムオーバーライドの反映と辞書シリアライズの検証。"""
    # HAR Replay の form-urlencoded を特定テスト環境で SUPPORTED にオーバーライド
    overrides = {
        (TokenCarrier.FORM_URLENCODED, TokenTransport.HAR_REPLAY): DeclaredStatus.SUPPORTED,
    }
    custom_matrix = build_token_capability_matrix(overrides=overrides)
    assert custom_matrix.get_status(TokenCarrier.FORM_URLENCODED, TokenTransport.HAR_REPLAY) == DeclaredStatus.SUPPORTED
    # 他のペアはデフォルトのまま
    assert custom_matrix.get_status(TokenCarrier.JSON, TokenTransport.HAR_REPLAY) == DeclaredStatus.BLOCKED

    # to_dict() の構造とフィールド検証
    d = custom_matrix.to_dict()
    assert d["schema_version"] == "1.0.0"
    assert d["declaration_only"] is True
    assert d["execution_coverage_claimed"] is False
    assert len(d["matrix"]) == 42
    # JSON シリアライズ可能であること
    serialized = json.dumps(d)
    assert "har_replay::form-urlencoded" in serialized


def test_normalization_helpers():
    """キャリア・トランスポート・ステータス文字列の正規化ヘルパーを検証。"""
    assert normalize_carrier("form") == TokenCarrier.FORM_URLENCODED
    assert normalize_carrier("form-urlencoded") == TokenCarrier.FORM_URLENCODED
    assert normalize_carrier("multipart") == TokenCarrier.MULTIPART
    assert normalize_carrier("json") == TokenCarrier.JSON
    assert normalize_carrier("header") == TokenCarrier.HTTP_HEADER
    assert normalize_carrier("cookie") == TokenCarrier.COOKIE

    assert normalize_transport("playwright") == TokenTransport.PLAYWRIGHT
    assert normalize_transport("httpx") == TokenTransport.HTTPX
    assert normalize_transport("spa-api") == TokenTransport.SPA_API
    assert normalize_transport("har-replay") == TokenTransport.HAR_REPLAY
    assert normalize_transport("agent") == TokenTransport.AGENT
    assert normalize_transport("hybrid") == TokenTransport.HYBRID

    assert normalize_status("supported") == DeclaredStatus.SUPPORTED
    assert normalize_status("planned") == DeclaredStatus.PLANNED
    assert normalize_status("unsupported") == DeclaredStatus.UNSUPPORTED
    assert normalize_status("blocked") == DeclaredStatus.BLOCKED
