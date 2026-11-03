# Setup 設定宣言・実効フォーム設定 API

既存の通知設定 `GET/POST /api/v1/settings`、フォーム初期値
`GET /api/config/defaults`、capability manifest を変更せず、読取専用 API を併設する。
UI Setup 向けに設定キー・適用モード・scan preset 適用後の値と差分を公開する。
scan 起動経路・設定ファイル・永続化形式・既存 UI の動作は変更しない。

## 宣言と適用範囲

`wscan/settings_schema.py` の `FIELDS` / `PROFILES` から応答を生成する。
serve が `main._load_config` から作る `default_scan_cfg` の設定キーに、
通常/Agent/Hybrid の実フォーム送信キーを加えた宣言である。
`capability_matrix_html` は設定ではないため対象外。
サーバー管理用 retention や engine 内部設定など、YAML 全キーの一覧ではない。
完全性テストは初期値構築式と、DOM stub 上で実行した3モードの送信関数を照合する。

`toggles` 内は `toggles.headless` のようなドット区切りキー。
送信時は `headless` 等へ展開する。特に `toggles.community_payloads` /
`toggles.component_intel` / `toggles.tls_scan` の送信名は
`enable_community_payloads` / `enable_component_intel` / `enable_tls_scan`。
これはフォーム設定契約であり、scan リクエストそのものではない。

モードは `normal | agent | hybrid`（画面表示は Agent/Hybrid）。
Hybrid は偵察と通常検査の両フェーズを含む。適用モードは設定を受け取る経路の宣言で、
実行や成功の保証ではない。

profile は既存 `applyScanProfile` の `triage | standard | auth | precision | ctf`。
既存 JS 宣言と backend 宣言のキー・ラベル・上書き値の完全一致を実行テストで固定する。
既存 UI を動かすための配信経路は変えない。preset は normal/Hybrid 向けで、
Agent 単独への指定は拒否する。設定値のみを適用し、タブ移動等の UI 副作用は含めない。

`state_profile` はこれとは独立した設定で、既存 `VALID_PROFILES` の
`unrestricted | controlled-write | read-only` を使う。scan preset はこの値を変えない。
`read-only` の実リクエスト制御の限界は既存 `wscan/state_profile.py` のまま。

## HTTP 契約（JSON object）

| メソッド | パス | 成功レスポンス |
|---|---|---|
| GET | `/api/v1/settings/schema` | `SettingsSchema` |
| GET | `/api/v1/settings/effective` | `EffectiveConfig` |

両方とも任意の `schema_version=1.0.0` を受ける。未指定は現在版を返し、
一致しなければ HTTP 409 `{error: "schema_version_mismatch", schema_version: "1.0.0"}`。
既存 monitor の認証ミドルウェアを共有し、必要な認証なしでは HTTP 401。
POST 等での更新は提供しない（HTTP 405）。

共通フィールドは `schema_version: string = "1.0.0"`,
`manifest_kind: "settings_schema" | "effective_config"`,
`declaration_only: true`, `execution_coverage_claimed: false`。

`SettingsSchema`:

- `modes: string[]`
- `profiles: object` — profile 名から `{label: string, applicable_modes: string[], overrides: object}` への対応
- `fields: SettingField[]` — `key: string`, `type: string`, `label: string`,
  `applicable_modes: string[]`, `profiles: string[]`, `default: JSON value | null`,
  `redacted: boolean`, `constraints: object`
- 型は `boolean | integer | number | string | array | object`。
  制約は `enum`, `minimum`, `exclusiveMinimum`, `items: "scanner_id"`。
  scanner ID は既存 SCANNERS registry の宣言を参照する。
- `validate_settings_schema` は版欠落・版不一致・フィールド欠落・型違い・宣言改変を拒否する。
  同じ版ではこのサーバーの宣言との完全一致を要求する。

`EffectiveConfig` の query:

- `mode: string`（既定 `normal`）
- `profile: string`（省略時は preset を適用しない）
- 不明 mode/profile、Agent に対する profile は HTTP 400
  `{error: "invalid_mode_or_profile"}`。不正入力値は応答に反射しない。

`EffectiveConfig` の追加フィールド:

- `mode: string`, `profile: string | null`（省略時 null）
- `values: object` — 適用モードの設定キーから実効フォーム値への対応
- `diff: object` — preset 適用前後で変わったキーのみ `{before: JSON value, after: JSON value}`
- `redacted_keys: string[]` — 値を伏せたキー
- `invalid_keys: string[]` — 型・制約不正で宣言既定値へ戻したキー（不正値は返さない）
- `resolution_scope: "serve_form_defaults_then_scan_profile"`

例: 初期値が `depth=2` のとき
`GET /api/v1/settings/effective?mode=hybrid&profile=triage` は
`values.depth=1`、`diff.depth={"before":2,"after":1}` と、他の preset 上書き値を返す。
省略・全項目同値の場合の diff は `{}`。preset が触らない設定は保持する。

## 秘密値・互換性・限界

認証情報・Bearer・Cookie・ヘッダ・TOTP・TLS 証明書/鍵・IMAP・アカウントを
平文で出さない。URL や自由入力にも秘密が入り得るため、自由入力欄（モデル名、パス、
URL リストを含む）は schema の default と effective の value を常に `null` とし、
diff に含めない。`null` は未設定や空値を意味しない。値の有無・長さも公開しない。
公開する値は有限数値、真偽値、許可した列挙値、登録済み scanner ID のみ。
未知キーは公開しない。元設定や宣言を変更しないコピーを返す。

設定の欠落は `dict.get` と宣言既定値で補う。空・最小・未知キー入り config も既存 loader
と serve 初期値を経由して動く。新 API はファイルを読まず、scan を起動せず、保存しない。

実効値は **現在のサーバーのフォーム初期値へ scan preset を適用した宣言結果**。
未送信のブラウザ編集値、実行時 env/CLI 上書き、engine の動的推論・正規化、実行済み scan
の設定・検査カバレッジではない。UI は実行成功・安全性・coverage を推定してはならない。
UI 5タブ自体の実装は本契約の対象外。
