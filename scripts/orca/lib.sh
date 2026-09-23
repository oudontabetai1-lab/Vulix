#!/usr/bin/env bash
# Orca 自動化パイプラインの共有関数。finish_task.sh / merge_watcher.sh から source される。
# 判定ロジック（CI/レビュー）は純粋に gh の JSON を解釈するだけに保ち、副作用（マージ/削除）と分離する。
set -euo pipefail

_here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=/dev/null
source "$_here/config.sh"

log()  { printf '\033[36m[orca]\033[0m %s\n' "$*" >&2; }
ok()   { printf '\033[32m[orca]\033[0m %s\n' "$*" >&2; }
warn() { printf '\033[33m[orca]\033[0m %s\n' "$*" >&2; }
die()  { printf '\033[31m[orca] エラー:\033[0m %s\n' "$*" >&2; exit 1; }

need() { command -v "$1" >/dev/null 2>&1 || die "'$1' が必要です（PATH に見つかりません）"; }

repo_root() { git rev-parse --show-toplevel 2>/dev/null || die "git リポジトリ内で実行してください"; }
current_branch() { git rev-parse --abbrev-ref HEAD; }

# PR 番号を head ブランチから取得（無ければ空）
pr_for_branch() {
  local br="$1"
  gh pr list --head "$br" --state open --json number --jq '.[0].number // empty' 2>/dev/null || true
}

# --- CI ゲート ------------------------------------------------------------------
# 必須チェック($ORCA_REQUIRED_CHECK)が SUCCESS で、他の必須チェックに失敗/未完が無ければ 0。
ci_ok() {
  local pr="$1" roll
  roll="$(gh pr view "$pr" --json statusCheckRollup --jq '.statusCheckRollup' 2>/dev/null || echo '[]')"
  [ -n "$roll" ] && [ "$roll" != "null" ] || { warn "PR#$pr: チェック情報なし"; return 1; }

  # 必須チェックの結論（CheckRun は .conclusion、StatusContext は .state）
  local state
  state="$(jq -r --arg c "$ORCA_REQUIRED_CHECK" \
    '[.[] | select((.name // .context)==$c)] | (.[0].conclusion // .[0].state // "MISSING")' <<<"$roll")"
  if [ "$state" != "SUCCESS" ]; then
    warn "PR#$pr: 必須チェック '$ORCA_REQUIRED_CHECK' = $state（SUCCESS 待ち）"
    return 1
  fi
  # 他チェックに明確な失敗があればブロック（未完は無視＝必須のみ厳格）
  local failed
  failed="$(jq -r '[.[] | (.conclusion // .state)] | map(select(.=="FAILURE" or .=="ERROR" or .=="CANCELLED" or .=="TIMED_OUT"))|length' <<<"$roll")"
  if [ "${failed:-0}" -gt 0 ]; then
    warn "PR#$pr: 失敗したチェックが $failed 件あります"
    return 1
  fi
  return 0
}

# --- レビューゲート --------------------------------------------------------------
review_ok() {
  local pr="$1"
  case "$ORCA_REVIEW_GATE" in
    off) return 0 ;;
    approve) _review_ok_approve "$pr" ;;
    no-open-threads) _review_ok_no_threads "$pr" ;;
    *) die "未知の ORCA_REVIEW_GATE: $ORCA_REVIEW_GATE" ;;
  esac
}

_review_ok_approve() {
  local pr="$1" reviews decision
  reviews="$(gh pr view "$pr" --json latestReviews,reviewDecision 2>/dev/null || echo '{}')"
  decision="$(jq -r '.reviewDecision // empty' <<<"$reviews")"
  # ブランチ保護で承認必須なら reviewDecision を信頼
  if [ "$decision" = "CHANGES_REQUESTED" ]; then warn "PR#$pr: 変更要求あり"; return 1; fi

  local approved changes
  if [ -n "$ORCA_CODEX_LOGINS" ]; then
    # 承認を指定 login に限定
    approved="$(jq -r --arg L "$ORCA_CODEX_LOGINS" \
      '[.latestReviews[]? | select(.state=="APPROVED") | select((.author.login) as $a | ($L|split(" ")|index($a)))] | length' <<<"$reviews")"
  else
    approved="$(jq -r '[.latestReviews[]? | select(.state=="APPROVED")] | length' <<<"$reviews")"
  fi
  changes="$(jq -r '[.latestReviews[]? | select(.state=="CHANGES_REQUESTED")] | length' <<<"$reviews")"
  if [ "${changes:-0}" -gt 0 ]; then warn "PR#$pr: CHANGES_REQUESTED あり"; return 1; fi
  if [ "${approved:-0}" -ge 1 ]; then return 0; fi
  warn "PR#$pr: 承認レビュー待ち（approve ゲート）"
  return 1
}

# 未解決レビュースレッド 0 かつレビュー1件以上で通過
_review_ok_no_threads() {
  local pr="$1" repo owner name res unresolved total
  repo="$(gh repo view --json nameWithOwner --jq .nameWithOwner)"
  owner="${repo%/*}"; name="${repo#*/}"
  res="$(gh api graphql -f query='
    query($o:String!,$n:String!,$pr:Int!){ repository(owner:$o,name:$n){ pullRequest(number:$pr){
      reviewThreads(first:100){ nodes{ isResolved } } reviews(first:1){ totalCount } } } }' \
    -F o="$owner" -F n="$name" -F pr="$pr" 2>/dev/null || echo '{}')"
  unresolved="$(jq -r '[.data.repository.pullRequest.reviewThreads.nodes[]? | select(.isResolved==false)] | length' <<<"$res" 2>/dev/null || echo 1)"
  total="$(jq -r '.data.repository.pullRequest.reviews.totalCount // 0' <<<"$res" 2>/dev/null || echo 0)"
  if [ "${total:-0}" -lt 1 ]; then warn "PR#$pr: レビュー未実施（no-open-threads ゲート）"; return 1; fi
  if [ "${unresolved:-1}" -gt 0 ]; then warn "PR#$pr: 未解決スレッド $unresolved 件"; return 1; fi
  return 0
}

# head に対して Codex 起動コメントが既にあるか
codex_requested() {
  local pr="$1"
  # gh の --jq は --arg 非対応のため、本文を取り出して grep で判定する
  gh pr view "$pr" --json comments -q '.comments[]?.body' 2>/dev/null \
    | grep -qF -- "$ORCA_CODEX_TRIGGER"
}

post_codex_review() {
  local pr="$1"
  gh pr comment "$pr" --body "$ORCA_CODEX_TRIGGER" >/dev/null \
    && ok "PR#$pr: '$ORCA_CODEX_TRIGGER' を投稿（Codex レビュー起動）" \
    || warn "PR#$pr: Codex 起動コメントの投稿に失敗"
}

# --- セッション（worktree）クローズ ----------------------------------------------
# branch 'claude/<slug>' → worktree ディレクトリ '<worktrees>/<slug>' を回収する。
# Orca 既存慣習（.orca-worktree-trash へ退避）に合わせ、削除ではなく trash へ mv する。
close_session() {
  local branch="$1" root slug wt trash
  root="$(repo_root)"
  slug="${branch#"$ORCA_BRANCH_PREFIX"}"

  # 安全確認: slug は単一セグメント。'/' や '..' を含むものはパストラバーサルとして拒否
  case "$slug" in
    ""|*/*|*..*) warn "close_session: 不正な slug '$slug'（branch=$branch）— スキップ"; return 0 ;;
  esac
  wt="$root/$ORCA_WORKTREES_DIR/$slug"
  trash="$root/$ORCA_TRASH_DIR"

  # 二重確認: wt は必ず worktrees ディレクトリ直下であること
  case "$wt" in
    "$root/$ORCA_WORKTREES_DIR/"*) : ;;
    *) warn "close_session: 想定外のパス '$wt' — スキップ"; return 0 ;;
  esac

  # orca CLI が使えるなら優先（あれば）
  if [ "$ORCA_USE_ORCA_CLI" != "no" ] && command -v orca >/dev/null 2>&1; then
    if orca worktree remove "$wt" >/dev/null 2>&1; then ok "orca CLI で worktree を回収: $slug"; fi
  fi

  # git 登録済み worktree なら外す（未登録でもエラーにしない）
  git -C "$root" worktree remove --force "$wt" >/dev/null 2>&1 || true

  # ディレクトリが残っていれば trash へ退避（削除ではなく Orca 慣習の回収）
  if [ -d "$wt" ]; then
    mkdir -p "$trash"
    mv "$wt" "$trash/$slug-$(date +%Y%m%d-%H%M%S)" && ok "worktree を trash へ回収: $slug"
  fi

  # ローカルブランチを削除（リモートは gh pr merge --delete-branch 側で処理）
  git -C "$root" branch -D "$branch" >/dev/null 2>&1 && ok "ローカルブランチ削除: $branch" || true
}
