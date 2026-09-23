# Orca 並列オーケストレーション運用ガイド（開発者向け）

Orca で複数のコーディングエージェントを並列に走らせ、各タスクを **1 タスク = 1 セッション =
1 ブランチ = 1 PR** で回すための運用と、その **PR→レビュー→マージ→セッションクローズ** を
自動化する仕組み。実装は `scripts/orca/` と `orchestration/`。

> 位置づけ: タスクの DAG 分解・各セッションへの配布・セッション間メッセージングは
> **Orca 本体（orchestration スキル）**が担う。本仕組みはそれが手薄な
> **PR ライフサイクルの定型化と自動マージ／自動クローズ**を埋める薄いグルー。

## 全体像

```
Orca orchestrator ──┬─ session(worktree) claude/<slug-a> ─┐
（タスクをDAGで配布）  ├─ session(worktree) claude/<slug-b> ─┤ 各セッションが完了時に
                     └─ session(worktree) claude/<slug-c> ─┘ finish_task.sh を実行
                                                              │ test→commit→push→PR→@codex review
                                                              ▼
                              merge_watcher.sh（常駐 or cron）
                                  label=orca-auto の open PR を走査
                                  ゲート:(1) CI 'test' SUCCESS (2) レビュー通過
                                  → squash マージ → close_session（worktree を回収）
```

## 前提
- `gh` 認証済み（`gh auth status`）。Codex は接続済みアカウント名義の `@codex review` で起動
  （`github-actions[bot]` 等では起動しない — CLAUDE.md 参照）。
- 必須 CI は `.github/workflows/ci.yml` の `test` ジョブ。これが緑であることがマージ条件。
- ラベル `orca-auto` を作成しておく: `gh label create orca-auto -c '#5319e7' -d 'Orca 自動化パイプライン管理下'`

## 使い方

### 1. タスクを定義する
`orchestration/TEMPLATE_tasks.yaml` をコピーして編集。1 タスク 1 件・DAG は `depends_on`。
各セッションのプロンプトは `orchestration/TEMPLATE_task_prompt.md` を使い、**末尾で必ず
`finish_task.sh` を実行**させる。

### 2. 並列で走らせる
Orca 上で各タスクをセッション（worktree `claude/<slug>`）に割り当てて fan out する。
各セッションは実装が終わったら:

```bash
scripts/orca/finish_task.sh --title "feat: ..." --commit "..."
```

これで **push 前テスト → commit → push → PR 作成（ラベル付与）→ @codex review 投稿** まで自動。

### 3. 自動マージ＆自動クローズを常駐させる
リポジトリ直下（または任意の1セッション）で:

```bash
scripts/orca/merge_watcher.sh --watch      # 常駐（既定 60s 間隔）
# scripts/orca/merge_watcher.sh --once     # 1回だけ（cron 向き）
# scripts/orca/merge_watcher.sh --dry-run  # 判定のみ・マージしない
```

`orca-auto` の open PR を走査し、**CI 緑 かつ レビュー通過**なら squash マージし、
対応する worktree を Orca 慣習の `.orca-worktree-trash` へ回収してセッションを閉じる。

## マージゲート（「レビュー通過で完全自動」の定義）

完全自動でも **fail-closed**（条件を確認できなければマージしない）。`scripts/orca/config.sh`
または環境変数で調整:

| 変数 | 既定 | 意味 |
|---|---|---|
| `ORCA_REQUIRED_CHECK` | `test` | 必須 CI チェック名。SUCCESS 必須 |
| `ORCA_REVIEW_GATE` | `approve` | `approve` / `no-open-threads` / `off` |
| `ORCA_CODEX_LOGINS` | (空) | 承認を特定 login に限定（空=誰の承認でも可） |
| `ORCA_MERGE_METHOD` | `squash` | squash / merge / rebase |
| `ORCA_PR_LABEL` | `orca-auto` | 管理対象 PR のラベル |

- **`approve`（既定・推奨）**: GitHub の承認レビュー(APPROVED)が付き CHANGES_REQUESTED が無いときマージ。
  Codex のレビューを **Approve** として返す運用、または人が Approve する運用に対応。最も安全で曖昧さがない。
- **`no-open-threads`**: 未解決レビュースレッドが 0 かつレビュー 1 件以上でマージ。
  Codex が「Approve」を出さずコメントのみの運用向け（指摘を全て解決すれば通る）。
- Codex bot だけの承認を要求したい場合は `ORCA_CODEX_LOGINS` にその login を設定。

> 注意: `off` は CI だけで自動マージするため非推奨。`main` にブランチ保護（必須チェック＋承認必須）を
> かけておくと、この仕組みが誤爆しても GitHub 側でも二重にブロックできる。

## セッションのクローズ挙動
`close_session()`（`lib.sh`）は削除ではなく **Orca 慣習の trash 回収**を行う:
1. `orca` CLI があれば `orca worktree remove`（あれば優先）
2. `git worktree remove --force`（登録済みなら）
3. 残ったディレクトリを `.claude/worktrees/.orca-worktree-trash/<slug>-<日時>` へ `mv`
4. ローカルブランチ削除（リモートは `gh pr merge --delete-branch`）

パスが `.claude/worktrees/` 配下でなければ何もしない安全確認付き。

## トラブルシュート
- **マージされない**: `merge_watcher.sh --dry-run` で理由（CI 未緑 / 承認待ち / 変更要求）を確認。
- **ラベルが付かない**: `gh label create orca-auto` を先に実行。
- **Codex が起動しない**: 接続済みアカウント名義でコメントされているか（bot 名義は不可）。
