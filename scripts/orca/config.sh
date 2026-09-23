#!/usr/bin/env bash
# Orca 並列オーケストレーション自動化の調整値。すべて環境変数で上書き可能。
# 既定は本リポジトリの既存運用（claude/<slug> ブランチ / test CI / @codex review）に合わせてある。

: "${ORCA_BASE_BRANCH:=main}"                 # PR のベースブランチ
: "${ORCA_BRANCH_PREFIX:=claude/}"            # セッションのブランチ接頭辞（Orca 既定）
: "${ORCA_PR_LABEL:=orca-auto}"               # パイプライン管理下の PR を識別するラベル
: "${ORCA_MERGE_METHOD:=squash}"              # squash | merge | rebase
: "${ORCA_DELETE_REMOTE_BRANCH:=true}"        # マージ後にリモートブランチを削除

# --- マージゲート（完全自動マージの発火条件） ---------------------------------
# 「レビュー通過で完全自動」を安全側に定義する。既定は fail-closed：
#   (1) 必須 CI チェックが SUCCESS  かつ  (2) レビューゲート通過 のときだけマージ。
: "${ORCA_REQUIRED_CHECK:=test}"              # .github/workflows/ci.yml のジョブ名（必須チェック）
: "${ORCA_TEST_CMD:=python -m pytest -q --ignore=tests/test_end_to_end_scan.py}"

# レビューゲート:
#   approve         … GitHub の承認レビュー(APPROVED)が付き、CHANGES_REQUESTED が無いとき通過（既定・最も安全）
#   no-open-threads … 未解決レビュースレッドが 0 かつレビューが1件以上あるとき通過
#   off             … レビュー無視（CI だけで自動マージ。非推奨）
: "${ORCA_REVIEW_GATE:=approve}"

# 承認を特定アカウントに限定したいとき（例: Codex bot の login）。空なら誰の承認でも可。
# 例: ORCA_CODEX_LOGINS="chatgpt-codex-connector codex[bot]"
: "${ORCA_CODEX_LOGINS:=}"

# --- Codex 連携（CLAUDE.md 運用に準拠） ---------------------------------------
: "${ORCA_CODEX_TRIGGER:=@codex review}"      # 接続済みアカウント名義で投稿してレビュー起動
: "${ORCA_POST_CODEX_ON_FINISH:=true}"        # finish 時に @codex review を投稿

# --- Orca worktree / セッションのクローズ -------------------------------------
: "${ORCA_WORKTREES_DIR:=.claude/worktrees}"          # Orca が worktree を置くディレクトリ
: "${ORCA_TRASH_DIR:=.claude/worktrees/.orca-worktree-trash}"  # Orca の回収先（既存慣習）
: "${ORCA_USE_ORCA_CLI:=auto}"                # auto|yes|no : orca CLI があれば worktree 削除に使う

# --- watcher --------------------------------------------------------------------
: "${ORCA_POLL_INTERVAL:=60}"                 # --watch 時のポーリング間隔(秒)
