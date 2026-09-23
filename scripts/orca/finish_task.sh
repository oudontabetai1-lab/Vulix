#!/usr/bin/env bash
# セッション側ライフサイクル: テスト → コミット → push → PR 作成 → @codex review。
# 各 Orca セッション（worktree）が、担当タスク完了時にこのスクリプトを1回実行する想定。
#
# 使い方:
#   scripts/orca/finish_task.sh --title "PRタイトル" [--body "本文"] [--commit "コミットメッセージ"]
#   (title 省略時はブランチ名から生成。body 省略時はテンプレを使用)
set -euo pipefail
_here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$_here/lib.sh"

need git; need gh; need jq

TITLE=""; BODY=""; COMMIT_MSG=""; SKIP_TESTS="${ORCA_SKIP_TESTS:-false}"
while [ $# -gt 0 ]; do
  case "$1" in
    --title) TITLE="$2"; shift 2;;
    --body) BODY="$2"; shift 2;;
    --commit) COMMIT_MSG="$2"; shift 2;;
    --skip-tests) SKIP_TESTS=true; shift;;
    *) die "未知の引数: $1";;
  esac
done

root="$(repo_root)"; cd "$root"
branch="$(current_branch)"
[ "$branch" != "$ORCA_BASE_BRANCH" ] || die "$ORCA_BASE_BRANCH 上では実行しません（$ORCA_BRANCH_PREFIX* ブランチで実行してください）"
case "$branch" in "$ORCA_BRANCH_PREFIX"*) : ;; *) warn "ブランチ '$branch' は接頭辞 '$ORCA_BRANCH_PREFIX' を持ちません（続行）";; esac

# 1) テスト（CLAUDE.md の push 前必須ライン）
if [ "$SKIP_TESTS" != "true" ]; then
  log "テスト実行: $ORCA_TEST_CMD"
  if ! eval "$ORCA_TEST_CMD"; then die "テスト失敗のため中断（壊れた PR は作らない）"; fi
  ok "テスト通過"
else
  warn "テストをスキップ（--skip-tests）"
fi

# 2) コミット（差分があるときだけ）
if ! git diff --quiet || ! git diff --cached --quiet; then
  git add -A
  git commit -m "${COMMIT_MSG:-wip: ${branch#$ORCA_BRANCH_PREFIX}}" >/dev/null
  ok "コミット作成"
else
  log "未コミットの差分なし"
fi

# 3) push
git push -u origin "$branch"
ok "push 完了: origin/$branch"

# 4) PR 作成（無ければ）
TITLE="${TITLE:-${branch#$ORCA_BRANCH_PREFIX}}"
if [ -z "$BODY" ]; then
  BODY=$(cat <<BODYEOF
## 概要
Orca セッション \`$branch\` の成果。

## チェック
- [ ] \`$ORCA_TEST_CMD\` 通過
- [ ] Codex レビュー対応済み

*(orca 自動化パイプライン: $ORCA_PR_LABEL)*
BODYEOF
)
fi
pr="$(pr_for_branch "$branch")"
if [ -z "$pr" ]; then
  gh pr create --base "$ORCA_BASE_BRANCH" --head "$branch" --title "$TITLE" --body "$BODY" >/dev/null
  pr="$(pr_for_branch "$branch")"
  ok "PR 作成: #$pr"
  gh pr edit "$pr" --add-label "$ORCA_PR_LABEL" >/dev/null 2>&1 \
    || warn "ラベル '$ORCA_PR_LABEL' 付与に失敗（ラベル未作成なら: gh label create $ORCA_PR_LABEL）"
else
  log "既存 PR を再利用: #$pr"
fi

# 5) Codex レビュー起動（接続済みアカウント名義。CLAUDE.md 運用）
if [ "$ORCA_POST_CODEX_ON_FINISH" = "true" ]; then
  if codex_requested "$pr"; then
    log "PR#$pr: 既に Codex 起動コメントあり（push 後の再レビュー依頼を投稿）"
  fi
  post_codex_review "$pr"
fi

ok "finish 完了: $(gh pr view "$pr" --json url -q .url 2>/dev/null || echo PR#$pr)"
