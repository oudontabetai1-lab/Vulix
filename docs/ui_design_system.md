# UI デザインシステム (`/app` シェル)

Vulix `/app` ダッシュボードおよび管理画面群で使用する共通デザインシステム、トークン、状態表現規約の技術ドキュメントです。

---

## 1. 設計方針と基本理念

1. **色のみに依存しない状態表現 (Accessible Statuses)**:
   すべてのステータス表示（合否、警告、進行状況など）は、色だけでなくテキストラベルまたは明示的なアイコンを併用します。色覚特性や高コントラスト環境でも状態の誤認を防ぎます。
2. **検証不確実性の明確化**:
   未確証（unverified）、利用不可（unavailable）、不明（unknown）、部分取得（partial）の状態を「合格（pass）」や「完了（complete）」として表示することは厳禁です。
3. **ブランドカラーとステータスカラーの分離**:
   Vulix ブランドアクセントカラー（`--accent: #9184d9`）は操作誘導やハイライト用とし、合否や警告などのセマンティックなステータスカラーとは明確に分離します。
4. **アクセシビリティと可視フォーカス**:
   すべてのインタラクティブ要素（ボタン、リンク、フォーム入力、タブ）はキーボード操作時に視認可能なフォーカスリング（`--focus-outline`）を表示します。
5. **レスポンシブ対応**:
   1440px（デスクトップ）、1280px（ラップトップ）、768px（タブレット・狭小幅）の3つの標準幅で横スクロール（水平オーバーフロー）が発生せず、快適に閲覧・操作できるレイアウトを維持します。

---

## 2. デザイントークン (`templates/ui/tokens.css`)

### サーフェス・ベーストークン
| トークン名 | 値 | 用途 |
|---|---|---|
| `--bg` | `#161826` | 画面全体の背景色 |
| `--surface` | `#1c1e2c` | メインコンテンツエリア、ヘッダー、カード背景 |
| `--surface2` | `#232532` | 入力フィールド、ネストされたカード、テーブルヘッダー |
| `--rail` | `#12141f` | 左サイドバー（ナビゲーションレール）背景 |
| `--border` | `#3f424d` | 標準ボーダー・区切り線 |
| `--text` | `#e9e9ed` | プライマリテキスト |
| `--text-muted` | `#9397ab` | セカンダリ・補足・ラベルテキスト |

### ブランドトークン
| トークン名 | 値 | 用途 |
|---|---|---|
| `--accent` | `#9184d9` | ブランドアクセント、プライマリボタン、選択枠 |
| `--accent-glow` | `rgba(145,132,217,0.18)` | フォーカスグロー、ハイライト背景 |

### セマンティックステータストークン
| 状態 | テキスト色トークン | 背景色トークン | 枠線トークン |
|---|---|---|---|
| `pass` (合格/正常) | `--status-pass: #22c55e` | `--status-pass-bg: rgba(34,197,94,0.12)` | `--status-pass-border: rgba(34,197,94,0.3)` |
| `fail` (失敗/重大) | `--status-fail: #e2708f` | `--status-fail-bg: rgba(226,112,143,0.12)` | `--status-fail-border: rgba(226,112,143,0.3)` |
| `warning` (警告/注意) | `--status-warning: #c7b96a` | `--status-warning-bg: rgba(199,185,106,0.12)` | `--status-warning-border: rgba(199,185,106,0.3)` |
| `not-checked` (未確認) | `--status-not-checked: #9397ab` | `--status-not-checked-bg: #232532` | `--status-not-checked-border: #3f424d` |
| `unknown` (不明) | `--status-unknown: #9397ab` | `--status-unknown-bg: #232532` | `--status-unknown-border: #3f424d` |
| `unavailable` (利用不可) | `--status-unavailable: #e2708f` | `--status-unavailable-bg: rgba(226,112,143,0.12)` | `--status-unavailable-border: rgba(226,112,143,0.3)` |
| `stale` (期限切れ/要確認) | `--status-stale: #d99a63` | `--status-stale-bg: rgba(217,154,99,0.12)` | `--status-stale-border: rgba(217,154,99,0.3)` |
| `running` (実行中) | `--status-running: #d99a63` | `--status-running-bg: rgba(217,154,99,0.12)` | `--status-running-border: rgba(217,154,99,0.3)` |

### スペーシングスケール
- `--space-xs`: `4px`
- `--space-sm`: `8px`
- `--space-md`: `12px`
- `--space-lg`: `16px`
- `--space-xl`: `20px`
- `--space-2xl`: `24px`
- `--space-3xl`: `32px`

### 密度スケール (Density Scale)
- Compact: `--density-compact-padding: 4px 8px;`, `--density-compact-gap: 4px;`
- Comfortable: `--density-comfortable-padding: 8px 14px;`, `--density-comfortable-gap: 8px;`
- Spacious: `--density-spacious-padding: 16px 20px;`, `--density-spacious-gap: 16px;`

### フォーカスリング
- `--focus-ring`: `0 0 0 2px var(--accent)`
- `--focus-ring-offset`: `2px`
- `--focus-outline`: `2px solid var(--accent)`

### 状態パターントークン
- `--state-error-text`: `#e2708f`
- `--state-error-bg`: `rgba(226, 112, 143, 0.12)`
- `--state-error-border`: `rgba(226, 112, 143, 0.3)`
- `--state-loading-text`: `#9397ab`
- `--state-empty-text`: `#9397ab`

---

## 3. 共通コンポーネントプリミティブ (`templates/ui/components.css`)

### ステータスバッジ (`.ui-status-badge`)
汎用的なステータス表示クラスです。
```html
<span class="ui-status-badge ui-status-pass">✓ OK</span>
<span class="ui-status-badge ui-status-warning">⚠ 警告</span>
<span class="ui-status-badge ui-status-fail">✗ 失敗</span>
<span class="ui-status-badge ui-status-not-checked">— 未確認</span>
<span class="ui-status-badge ui-status-unavailable">利用不可</span>
<span class="ui-status-badge ui-status-stale">要確認</span>
<span class="ui-status-badge ui-status-running">⟳ 実行中</span>
```

### 状態パターン
1. **Empty State (`.ui-state-empty`)**:
   データ未登録や結果なしのプレースホルダー表示。
2. **Loading State (`.ui-state-loading`)**:
   データ取得中のスピナーまたは案内テキスト。
3. **Error State (`.ui-state-error`)**:
   API 取得失敗や設定バリデーションエラーの明示表示。

### テーブル (`.ui-table-wrap`, `.ui-table`)
横スクロール対応コンテナとスタイル付きテーブル。
```html
<div class="ui-table-wrap" tabindex="0">
  <table class="ui-table">
    <thead>
      <tr><th>スキャン ID</th><th>ステータス</th></tr>
    </thead>
    <tbody>
      <tr><td>scan_01</td><td><span class="ui-status-badge ui-status-pass">完了</span></td></tr>
    </tbody>
  </table>
</div>
```

---

## 4. 画面別実装規約

| 画面 | 主なコンポーネント | 状態表現と留意点 |
|---|---|---|
| **Portal** | `#summarySurface`, `.ui-table` | スキャン履歴テーブル、エラー時は '未取得' と明記 |
| **Scan Setup** | `#setupSurface`, `.setup-grid`, `.setup-tab` | Preflight 事前診断バッジ、5タブ roving tabindex |
| **Monitor** | `#monitorFrame` / `#monitorModule` | 3ペイン分割レイアウト、レイアウト永続化 |
| **Crawl** | `#crawlSurface`, `.crawl-badge` | 完全性表示（完全 / 一部のみ / 未確定） |
| **Findings** | `#findingsSurface`, `.sev-badge`, `.verify-badge` | 深刻度・再現確証（reproduced / assumed / unreproduced） |
| **Agent Skills** | `#agentSkillsSurface`, `.agent-skills-table` | 機能利用可否（利用可能 / 利用不可 / 未確定） |
| **Settings** | `#settingsSurface`, `.ui-card`, `.ui-input` | 秘匿情報マスク、明示的保存 |
| **History & Audit** | `#summarySurface`, `.history-search-input` | 監査ログ操作種別と IP フォーマット |
