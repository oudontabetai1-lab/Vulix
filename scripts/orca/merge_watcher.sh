#!/usr/bin/env bash
# コーディネータ: パイプライン管理下($ORCA_PR_LABEL)のオープン PR を走査し、
#   (1) 必須 CI が SUCCESS  かつ  (2) レビューゲート通過  のとき
# 自動で squash マージ → 対応する Orca セッション(worktree)を自動クローズする。
#
# 使い方:
#   scripts/orca/merge_watcher.sh --once     # 1回だけ走査（cron / 手動向き）
#   scripts/orca/merge_watcher.sh --watch    # $ORCA_POLL_INTERVAL 秒ごとに常駐
#   scripts/orca/merge_watcher.sh --dry-run  # 判定だけ表示しマージしない
#
# 「完全自動」でも fail-closed（条件を確認できなければマージしない）。
set -euo pipefail
_here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$_here/lib.sh"
need git; need gh; need jq

MODE="once"; DRY=false
while [ $# -gt 0 ]; do
  case "$1" in
    --once) MODE="once"; shift;;
    --watch) MODE="watch"; shift;;
    --dry-run) DRY=true; shift;;
    *) die "未知の引数: $1";;
  esac
done

process_pr() {
  local pr="$1" branch
  branch="$(gh pr view "$pr" --json headRefName -q .headRefName)"
  local isdraft; isdraft="$(gh pr view "$pr" --json isDraft -q .isDraft)"
  if [ "$isdraft" = "true" ]; then log "PR#$pr ($branch): draft — スキップ"; return; fi

  # ゲート判定
  if ! ci_ok "$pr"; then return; fi
  if ! review_ok "$pr"; then
    # レビュー未実施なら Codex 起動を促す（no-open-threads/approve 共通で有用）
    if ! codex_requested "$pr"; then post_codex_review "$pr"; fi
    return
  fi

  if [ "$DRY" = "true" ]; then ok "PR#$pr ($branch): ゲート通過 — DRY-RUN のためマージせず"; return; fi

  # 自動マージ
  local args=(--"$ORCA_MERGE_METHOD")
  [ "$ORCA_DELETE_REMOTE_BRANCH" = "true" ] && args+=(--delete-branch)
  log "PR#$pr ($branch): ゲート通過 → $ORCA_MERGE_METHOD マージ"
  if gh pr merge "$pr" "${args[@]}" >/dev/null 2>&1; then
    ok "PR#$pr マージ完了"
  else
    warn "PR#$pr マージ失敗（ブランチ保護/権限/コンフリクトの可能性）— スキップ"
    return
  fi

  # セッション（worktree）自動クローズ
  close_session "$branch"
  ok "PR#$pr: セッション '$branch' をクローズ"
}

scan_once() {
  local prs
  prs="$(gh pr list --state open --label "$ORCA_PR_LABEL" --json number -q '.[].number' 2>/dev/null || true)"
  if [ -z "$prs" ]; then log "対象 PR なし（label: $ORCA_PR_LABEL）"; return; fi
  local n; n="$(wc -w <<<"$prs")"
  log "対象オープン PR: $n 件"
  local pr
  for pr in $prs; do
    process_pr "$pr" || warn "PR#$pr の処理でエラー（続行）"
  done
}

cd "$(repo_root)"
gh auth status >/dev/null 2>&1 || die "gh 未認証です（gh auth login）"

if [ "$MODE" = "watch" ]; then
  ok "watcher 常駐開始（間隔 ${ORCA_POLL_INTERVAL}s / label $ORCA_PR_LABEL / gate: CI+$ORCA_REVIEW_GATE）"
  while true; do scan_once; sleep "$ORCA_POLL_INTERVAL"; done
else
  scan_once
fi
