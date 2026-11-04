# Vulix ダッシュボード UI アーキテクチャ

本ドキュメントは、Vulix（旧称 WScan）の Web ダッシュボード（`/app` シェル）の内部アーキテクチャ、UI とサーバー間の通信契約、責務境界、拡張レジストリ、および設定の優先順位について、現行のソースコードに基づいて解説する開発者・運用者向けドキュメントです。

---

## 1. `/app` ダッシュボードのモジュール構造

Vulix の操作インターフェースは、`templates/app.html` を起点とするモジュール化されたシングルページアプリケーション（SPA）シェルとして構成されています。旧来の単一 HTML（`templates/dashboard.html`）から構造を分離し、各画面が疎結合な独立モジュールとして動作します。

```
templates/
├── app.html                      # /app シェル HTML（レイアウト、サイドバー、サーフェス定義）
├── portal.html                   # / ルートのサーバーポータル画面
├── dashboard.html                # /monitor ルートのレガシーライブモニター（兼トランスポートオーナー）
└── ui/
    ├── tokens.css                # デザイントークン（色・余白・フォント定義）
    ├── components.css            # 共通 UI コンポーネントスタイル
    ├── api-client.js             # 型付き HTTP クライアント (ApiClient / ScopedApiClient)
    ├── event-stream.js           # WebSocket イベントストリーム・カーソル投影
    ├── app-shell.js              # モジュールレジストリ & ナビゲーションディスパッチャ
    ├── app-entry.js              # /app ルーター & エントリポイント
    ├── capability-reader.js      # 機能マニフェスト読み取りクライアント
    ├── evidence-viewer-registry.js # 脆弱性証拠ビューアレジストリ
    ├── monitor-module.js         # 3ペイン Monitor 画面モジュール
    ├── setup-module.js           # Scan Setup 画面モジュール（5タブ + Preflight）
    ├── findings-module.js        # Findings 画面モジュール（2ペイン一覧/詳細）
    ├── crawl-module.js           # Crawl 画面モジュール（Graph / Tree Explorer / List）
    ├── traffic-module.js         # HTTP トラフィック閲覧画面モジュール
    ├── settings-module.js        # Settings（通知・外部連携）画面モジュール
    ├── agent-skills-module.js    # Agent Skills 画面モジュール
    ├── summary-modules.js        # Portal, History, Audit 画面モジュール群
    └── summary-reader.js         # サマリーデータ取得ヘルパー
```

### 1.1 アプリケーションシェル (`templates/app.html`)

`templates/app.html` は左サイドバー（ナビゲーションレール）と右メイン領域の 2 カラムレイアウトを提供します。
- **サイドバー (`aside`)**: ブランドロゴとナビゲーションボタン群（ポータル、スキャン履歴、監査ログ、Scan Setup、Monitor、Findings、Crawl、Traffic、Agent Skills、Settings）を配置。各ボタンは `data-route="<route-id>"` 属性を持ちます。
- **ヘッダー (`header`)**: 現在のアクティブ画面名（`#viewTitle`）およびスキャンコンテキスト（`#scanContext`、スキャン ID とステータス）を表示。
- **サーフェスコンテナ (`#surface`)**: 画面ごとに独立したコンテナ要素（`#summarySurface`, `#findingsSurface`, `#crawlSurface`, `#trafficSurface`, `#agentSkillsSurface`, `#setupSurface`, `#settingsSurface`, `#message`）および Monitor 投影用要素（`#monitorModule`, `#monitorFrame`）を持ち、アクティブな画面のみ `hidden` 属性を解除して表示します。

### 1.2 モジュールレジストリとルーター (`templates/ui/app-shell.js`, `templates/ui/app-entry.js`)

モジュール管理と画面遷移は `VulixAppShell.ModuleRegistry` および `VulixAppShell.NavigationDispatcher` が担います。

- **`ModuleRegistry` (`templates/ui/app-shell.js:17`)**:
  画面モジュールの定義（`id`, `title`, `route`, `mount(ctx)`, `unmount(ctx)`）を登録・保持し、画面遷移時の `transition(targetId, ctx)` によって前画面の `unmount` と新画面の `mount` を順序通り実行します。
- **`NavigationDispatcher` (`templates/ui/app-shell.js:162`)**:
  URL ハッシュ（例: `#/findings`, `#/setup`）の変更（`hashchange` イベント）を監視し、登録済みモジュールへ遷移させます。未登録または不正なハッシュが指定された場合は、安全に既定画面（`portal` / `live`）へフォールバックします。
- **ルーターパーサー (`templates/ui/app-entry.js:434` `parseRoute`)**:
  ハッシュ文字列からルート名と許可されたクエリパラメータ（ホワイトリスト方式）を検証・抽出します。
  - `/monitor`: `scan`
  - `/findings`: `scan`, `finding`, `url`, `search`, `severity`, `checkType`, `verification`, `provenance`
  - `/crawl`: `scan`, `node`, `url`, `mode`, `kind`, `search`
  - `/traffic`: `scan`, `entry`, `url`, `method`, `status`, `source`, `type`, `search`
  不正なクエリキーや長すぎる文字列、複数の同一キー指定は拒否され、`unavailable` 画面へ遷移します。

### 1.3 共通コンポーネントとデザイントークン (`templates/ui/tokens.css`, `templates/ui/components.css`)

- **デザイントークン (`templates/ui/tokens.css`)**:
  背景色（`--bg: #161826`）、サーフェス色（`--surface: #1c1e2c`, `--surface2: #232532`）、ブランド色（`--accent: #9184d9`）、境界線（`--border: #3f424d`）、セマンティックステータス色（`--status-pass`, `--status-fail`, `--status-warning`, `--status-not-checked`, `--status-unknown`, `--status-unavailable`, `--status-stale`）を一元定義します。ハードコードされたカラーコードの直接使用を禁止し、ダークテーマに統一された視覚階層を形成します。
- **共通スタイル (`templates/ui/components.css`)**:
  ボタン、バッジ、フォーム入力、テーブル、カード、モーダルなどの共通スタイルと、視認可能なキーボードフォーカスリング（`:focus-visible`）を定義します。

### 1.4 API クライアント (`templates/ui/api-client.js`)

サーバーとの HTTP 通信を一元管理するクライアントです。
- **型付き結果オブジェクト (`ApiResult`, `api-client.js:22`)**:
  通信結果を単一のブール値ではなく、明確なステート種別（`success`, `unauthorized`, `http_error`, `network_error`, `decode_error`, `aborted`）としてカプセル化します。HTTP 401 応答時には `isUnauthorized()` が true となり、認証切れを明確にハンドリングできます。
- **スコープ付きキャンセル (`ScopedApiClient`, `api-client.js:153`)**:
  各画面モジュールのマウント時に `api.createScope()` でスコープを生成します。画面がアンマウントされた際、`scope.cancelAll()` を呼び出すことで、進行中の全リクエストを `AbortController` 経由で一括中断します。これにより、画面遷移後に遅延着信した過去のレスポンスが新しい画面の DOM を誤って書き換える競合（stale read）を完全に防止します。

### 1.5 イベントストリームクライアント (`templates/ui/event-stream.js`)

WebSocket（`/ws`）経由のリアルタイム通知を受信・処理するクライアントです。
- 単一 WebSocket コネクションの維持と、3000ms 固定の再接続タイマー。
- HTTP/WS コード 4401（未認証・セッション失効）の検知と再接続ループの即時停止。
- 受信イベントのシーケンス番号管理（`CursorProjection`）による順序保証・重複排除・欠落時再同期。
- `requestAnimationFrame` によるバッチ描画（1フレームあたり最大50件）。
詳細な通信契約は「2. UI とサーバー間の契約」に後述します。

### 1.6 各画面モジュールの責務

`templates/ui/` 配下の各画面モジュールは、特定のドメイン責務を受け持ちます。

| 画面名 | ソースファイル | 主な責務・機能 |
|---|---|---|
| **Portal** | `templates/ui/summary-modules.js` | サーバー全体の稼働概要、実行中スキャンの状態確認・中止、ストレージ使用状況、過去スキャンの保持ポリシー整理（Prune）、定期スジュール設定の一覧・追加・切り替え。 |
| **Setup** | `templates/ui/setup-module.js` | 5 つのカテゴリタブ（クロール設定、検査項目、認証/セッション、AI/ヒューリスティック、高度な設定）によるスキャン構成作成。事前診断（Preflight）の実行。構成プロファイルの選択と実効差分表示。スキャン開始要求の発行。 |
| **Monitor** | `templates/ui/monitor-module.js` | 3 ペイン（巡回マップ、ブラウザ画面、ログ/イベント/通信）によるリアルタイムスキャン進捗監視。ペインのリサイズ、折りたたみ、最大化、プリセット保存。 |
| **Crawl** | `templates/ui/crawl-module.js` | サイト巡回構造の可視化。3 つの表示モード（SVG インタラクティブグラフ、ツリーエクスプローラー、テーブルリスト）。ノード詳細ドロワー（フォーム、入力パラメータ、検出脆弱性）。 |
| **Findings** | `templates/ui/findings-module.js` | 検出脆弱性の一覧・詳細分割表示（2 ペイン）。重要度、検証状態（reproduced / assumed 等）、出自（通常スキャナ / Agent 発見）によるフィルタリングと検索。証拠ビューアの描画。 |
| **Traffic** | `templates/ui/traffic-module.js` | スキャン中に記録された HTTP リクエスト/レスポンスログ（`http_requests.jsonl`）の読み取り専用閲覧。メソッド・ステータス・URL フィルタリング。機密パラメータのマスキング。 |
| **Settings** | `templates/ui/settings-module.js` | サーバーレベルの設定管理（Webhook 通知設定、最小通知重要度、スキャン完了通知）。設定の保存とテスト通知送信。 |
| **Agent Skills** | `templates/ui/agent-skills-module.js` | 静的機能マニフェスト（Capability Manifest）に基づく Agent / Hybrid / 通常スキャナの機能一覧・契約メタデータの閲覧。 |
| **History** | `templates/ui/summary-modules.js` | 過去スキャンの一覧表示、フィルタ検索、スキャン結果 ZIP のダウンロード、差分（Diff）比較モーダル表示、スキャン個別削除。 |
| **Audit** | `templates/ui/summary-modules.js` | 管理操作監査ログ（スキャン起動、停止、設定変更、ログイン等）のタイムライン表示。クライアント IP や操作パラメータの確認。 |

### 1.7 新規画面モジュールの追加手順

既存の他画面モジュールに一切変更を加えずに、新しい画面モジュールを追加できます。

1. **画面モジュールスクリプトの作成**:
   `templates/ui/my-feature-module.js` を作成し、ファクトリ関数を定義します。
   ```javascript
   (function (global) {
     'use strict';
     function createMyFeatureModule(options) {
       const { api, surfaceEl, titleEl, contextEl, unavailable, clearMessage, hideOthers } = options;
       return {
         id: 'my-feature',
         title: 'My Feature',
         route: '#/my-feature',
         capabilities: ['optional-cap'],
         mount(route) {
           hideOthers();
           clearMessage();
           titleEl.textContent = 'My Feature';
           surfaceEl.hidden = false;
           // ScopedApiClient を使用してデータ取得
           const scope = api.createScope();
           this._scope = scope;
           scope.get('/api/v1/my-data').then(res => {
             if (res.isSuccess()) {
               surfaceEl.textContent = JSON.stringify(res.data);
             }
           });
         },
         unmount() {
           if (this._scope) {
             this._scope.cancelAll('MyFeature unmounted');
             this._scope = null;
           }
           surfaceEl.hidden = true;
           surfaceEl.replaceChildren();
         }
       };
     }
     global.VulixMyFeatureModule = { createMyFeatureModule };
   })(window);
   ```
2. **`templates/app.html` への要素と script の追加**:
   - サイドバー内にナビゲーションボタンを追加:
     `<button class="history-btn" type="button" data-route="my-feature">My Feature</button>`
   - `#surface` 内に専用コンテナを追加:
     `<div id="myFeatureSurface" hidden></div>`
   - `<script src="/ui/my-feature-module.js"></script>` を読み込みに追加。
3. **`templates/ui/app-entry.js` への登録**:
   - `hideOthers()` 内で `myFeatureSurface.hidden = true;` を追加。
   - `parseRoute` の許可ルート一覧およびパラメータ定義に `'/my-feature'` を追加。
   - レジストリへ登録:
     ```javascript
     if (global.VulixMyFeatureModule) {
       registry.register(global.VulixMyFeatureModule.createMyFeatureModule({
         api,
         surfaceEl: document.getElementById('myFeatureSurface'),
         titleEl: title,
         contextEl: context,
         unavailable,
         clearMessage,
         hideOthers,
       }));
     }
     ```
既存の `findings-module.js` (`templates/ui/app-entry.js:343`) や `crawl-module.js` (`templates/ui/app-entry.js:387`) が同様の登録パターンを採用しています。

---

## 2. UI とサーバー間の契約

### 2.1 HTTP API エンドポイント一覧

UI スクリプト（`templates/ui/*.js`）から実際に呼び出されるサーバー側（`wscan/monitor.py`）の HTTP API エンドポイントは以下の通りです。

| HTTPメソッド | パス | 主な呼び出し元 | 処理概要・レスポンス形式 |
|---|---|---|---|
| `GET` | `/api/v1/scans` | `summary-reader.js`, `app-entry.js`, `findings-module.js`, `crawl-module.js`, `traffic-module.js` | 過去および実行中スキャンの一覧とストレージ容量情報を返却。`{scans: [...], storage: {...}}` |
| `GET` | `/api/v1/scans/{id}/download` | `summary-modules.js` | 指定スキャンの成果物一式（レポート、ログ、JSON）を ZIP 形式でダウンロード。 |
| `GET` | `/api/v1/scans/{id}/diff` | `summary-modules.js` | 指定スキャンと直前スキャンとの脆弱性・巡回 URL 差分情報を返却。 |
| `POST` | `/api/v1/scans/prune` | `summary-modules.js` | 保持ポリシーに基づき古いスキャンディレクトリを削除。`{status: "ok", deleted: [...]}` |
| `DELETE` | `/api/v1/scans/{id}` | `summary-modules.js` | 指定スキャンディレクトリを完全削除。 |
| `GET` | `/api/v1/audit` | `summary-reader.js` | サーバー管理操作ログ（`output/management_audit.jsonl`）を返却。`{audit: [...]}` |
| `GET` | `/api/v1/scan/status` | `summary-reader.js` | 実行中スキャンのステータス概要を返却。 |
| `POST` | `/api/v1/scan/abort` | `summary-modules.js` | 実行中スキャンの中止を要求。 |
| `GET` | `/api/v1/schedules` | `summary-reader.js` | 定期実行スケジュール一覧を返却。`{schedules: [...]}` |
| `POST` | `/api/v1/schedules` | `summary-modules.js` | 新規定期実行スケジュールを登録。 |
| `POST` | `/api/v1/schedules/{id}/toggle` | `summary-modules.js` | スケジュールの有効/停止を切り替え。 |
| `DELETE` | `/api/v1/schedules/{id}` | `summary-modules.js` | 定期実行スケジュールを削除。 |
| `GET` | `/api/capability-manifest`<br>`/api/v1/capability-manifest` | `capability-reader.js`, `agent-skills-module.js` | スキャナおよび Agent の静的機能宣言マニフェストを返却（後述）。 |
| `GET` | `/api/v1/settings/schema` | `setup-module.js`, `settings-module.js` | 設定フォーム構築のための宣言的スキーマ（フィールド定義、型、制約、プロファイル）。 |
| `GET` | `/api/v1/settings/effective` | `setup-module.js`, `settings-module.js` | 選択されたプロファイルやモードに応じた実効設定値と差分（秘密値は除外）。 |
| `POST` | `/api/v1/preflight` | `setup-module.js` | スキャン開始前の事前診断（DNS、疎通、TLS、認証スコープ等）を実行。プローブ送信は行わない。 |
| `GET` | `/api/v1/settings` | `settings-module.js` | Webhook 通知設定を取得（URL は伏字マスク化）。 |
| `POST` | `/api/v1/settings` | `settings-module.js` | Webhook 通知設定を更新保存。 |
| `POST` | `/api/v1/settings/test` | `settings-module.js` | 設定中の Webhook URL へテスト通知を送信。 |
| `GET` | `/api/v1/scans/{id}/findings`<br>`/api/v1/scan/findings` | `findings-module.js`, `traffic-module.js` | 指定スキャンまたは現行スキャンの脆弱性一覧（`findings.json`）を返却。 |
| `GET` | `/api/v1/scans/{id}/crawl-graph`<br>`/api/v1/scan/crawl-graph` | `crawl-module.js` | 指定スキャンまたは現行スキャンの巡回ノード・エッジ・完了状態を返却。 |
| `GET` | `/api/v1/scans/{id}/traffic?limit=500`<br>`/api/v1/scan/traffic?limit=500` | `traffic-module.js` | 記録された HTTP リクエスト/レスポンス履歴（`http_requests.jsonl`）を返却。 |

### 2.2 WebSocket イベントストリーム (`/ws`)

リアルタイム通知は `wscan/monitor.py:600` の `@app.websocket("/ws")` エンドポイントで提供され、クライアント側は `templates/ui/event-stream.js` が接続と投影を管理します。

#### 接続確立と認証ハンドシェイク
- WebSocket ハンドシェイク時、サーバーは Cookie またはトークンによる認証検証（`_ws_authorized`）を行います。
- 認証に失敗した場合、サーバーは **カスタム切断コード `4401`**（`wscan/monitor.py:603`）で即座に WebSocket を切断します。
- クライアント側（`event-stream.js:372`）は `code === 4401` を検知すると、**自動再接続タイマーを直ちに停止**し、リトライストームを抑止した上でログイン案内メッセージを発行します。

#### 初期スナップショット (`scan_snapshot`)
接続が受理されると、サーバーは現在のスキャン状態を完全にまとめた初期スナップショットイベント（`_scan_snapshot_event()`, `wscan/monitor.py:608`）を先頭で送信します。
スナップショット送信中にバックエンドで発生した新規イベントは `_ws_sync_buffers` に一時バッファリングされ、スナップショット完了後に順序を保ってクライアントへ配信されます。これにより、スナップショットとライブイベントの競合（レースコンディション）を完全に排除しています。

#### イベントエンベロープとシーケンス管理 (`CursorProjection`)
WebSocket で流れるイベントは以下のエンベロープを持ちます。
```json
{
  "server_id": "srv_xxxx",
  "run_id": "run_yyyy",
  "scan_id": "20261104_120000_target",
  "sequence": 42,
  "type": "finding",
  "timestamp": 1730718000.123,
  "data": { ... },
  "backend_version": "1.0.0"
}
```
- **シーケンス番号 (`sequence`)**: 各スキャン実行（`run_id`）内で 1 から連続して採番されます（スナップショットは 0）。
- **重複排除**: クライアントが保持する `lastEventSequence` 以下のシーケンス番号を持つイベントが届いた場合、重複として安全に破棄（`drop`）されます。
- **シーケンス欠落の検知と再同期**: 受信したシーケンス番号が `lastEventSequence + 1` より大きい場合、通信途絶等によるイベント欠落が発生したと判断し、クライアントはアクション `reconnect_on_gap` をトリガーして即座に WebSocket を再接続し、最新の `scan_snapshot` を再取得します。
- **新規スキャンリセット**: 異なる `run_id` でかつ `sequence === 1` の `scan_started` イベントを受信した場合、クライアントのカーソルと内部状態を初期化して新規スキャンへ移行します。

#### 既知イベント種別 (27 種)
`templates/ui/event-stream.js:77` の `KNOWN_EVENTS` で定義されるイベント種別:
`status`, `page_start`, `scan_config`, `payload_test`, `phase`, `page_graph_update`, `page_graph_vuln`, `subphase`, `phase_timing`, `url_start`, `url_complete`, `screenshot`, `finding`, `finding_update`, `scan_gap`, `request`, `response`, `progress`, `scan_complete`, `plan_review`, `crawl_review`, `intervention_state`, `manual_crawl_status`, `manual_crawl_frame`, `ai_analysis`, `waf_detected`, `awaiting_config`, `scan_rejected`, `scan_started`, `scan_snapshot`, `ping`。

#### 未知・不正形式イベントの安全な処理
- **エンベロープ検証 (`validateWireEvent`, `event-stream.js:123`)**:
  受信した JSON がオブジェクト構造を満たさない場合や、必須の型（`type` が文字列、`data` がオブジェクト等）に反する場合は不正イベントとして処理されます。
- **未知イベントの扱い**:
  カーソル情報（`server_id`, `run_id`, `sequence`）を持たない未知のイベントは安全に破棄されます。
  カーソル情報を持つ不正形式イベントや JSON 解析エラーが発生した場合、回線を汚染された状態（`_wireStale = true`）としてマークし、再接続によって正常なスナップショットからの回復を図ります。
- **バージョン不一致 (`backend_version_mismatch`)**:
  バックエンドとフロントエンドのバージョン不一致は回線の物理切断ではなく互換性の状態であるため、無限再接続ストームを起こさずに stale 状態を通知します。

### 2.3 スキーマ検証コードと検証テスト

通信契約は以下のコードおよび自動テスト群によって厳格に保護されています。
- **スキーマ検証実装**:
  - `templates/ui/event-stream.js`: `validateWireEvent()`, `CursorProjection`
  - `wscan/settings_schema.py`: `validate_settings_schema()`, `build_effective_config()`
  - `wscan/capability_manifest.py`: `validate_capability_manifest()`
- **テストスイート**:
  - `tests/test_ui_event_stream.py`: WebSocket 切断コード 4401 のハンドリング、シーケンス欠落検知と再接続、重複排除、RAF バッチング、フィクスチャに基づくカーソル投影テスト。
  - `tests/test_ui_api_client.py`: `ApiClient` の型付き結果判定、アンマウント時の `AbortController` キャンセル動作、HTTP 401 境界テスト。
  - `tests/test_settings_schema.py`: 設定スキーマの版検証、制約違反の検出、プロファイル上書きの整合性検証。
  - `tests/test_capability_manifest.py`: 機能マニフェストの必須フィールド検証、カバレッジ禁止キーワードの非含有テスト。
  - `tests/test_ui_app_screens_e2e.py`: `/app` シェル上の各画面遷移、フォーム送信、セッション失効時の画面動作をブラウザ実機で網羅検証。

---

## 3. 移行ノート (Migration Notes)

### 3.1 単一 `dashboard.html` からモジュール構成への分割

Vulix の UI は、当初 `templates/dashboard.html` という単一の大規模 HTML ファイル（約 40 万バイト）内に HTML、CSS、JavaScript、WebSocket 制御、各種ビュー描画ロジックが混在していました。
これを現代的なモジュール構造へ移行するにあたり、以下の原則で段階的な分離が行われました。

1. **トランスポートと描画の分離**:
   WebSocket の接続維持、スキャンのインメモリ状態管理、生イベントの購読といった低レイヤーの責務を、新 UI 画面の描画ライフサイクルから切り離しました。
2. **画面ごとの独立ファイル化**:
   各画面（Setup, Monitor, Findings, Crawl, Traffic, Settings, Agent Skills）を `templates/ui/*.js` として独立させ、共通の `ModuleRegistry` インターフェース（`mount` / `unmount`）に従う形へ再構築しました。
3. **安全な DOM 破棄と通信キャンセル**:
   旧来のインライン切り替えでは、非表示になった画面の通信やタイマーが背後で動き続ける問題がありました。新設計では `ScopedApiClient` により、画面アンマウント時に保留中の通信を確実にキャンセルします。

### 3.2 保持されている後方互換性と稼働中のレガシールート

新 UI（`/app`）の導入後も、既存の運用スクリプトやブックマークを破壊しないよう、サーバー（`wscan/monitor.py`）は従来の全エンドポイントを現在もそのまま提供しています。

- **`/` (Server Portal)**:
  `templates/portal.html` を返却（`wscan/monitor.py:577`）。スキャン履歴の確認、レポート表示、新規スキャン起動を行う従来のポータル画面です。テンプレートが存在しない場合は `/monitor` へ 307 リダイレクトします。
- **`/monitor` (Legacy Live Monitor)**:
  `templates/dashboard.html` を返却（`wscan/monitor.py:586`）。3ペイン構成のライブモニターと従来のインライン設定オーバーレイを備えた単一画面です。
- **`/app` (Modern Application Shell)**:
  `templates/app.html` を返却（`wscan/monitor.py:593`）。サイドバーナビゲーションを備えた新しいモジュール型統合ダッシュボードです。

### 3.3 iframe トランスポートオーナーと `VulixAppBridge`

`/app` シェル上で Monitor 画面やスキャン起動を行う際、システムは `templates/dashboard.html` を破棄して再実装するのではなく、**iframe トランスポートオーナー** として安全に再利用しています。

- `templates/app.html` 内の `<iframe id="monitorFrame" hidden></iframe>` は `/monitor` を読み込みます。
- この iframe 内の `dashboard.html` が単一の WebSocket（`/ws`）を保持し、**Transport Owner** としてリアルタイム通信を一元管理します。
- iframe の `window.VulixAppBridge`（`templates/dashboard.html:2959`）を通じて、親シェル（`/app`）と以下の API で連携します:
  - `getContext()`: 現在のスキャン ID、ステータス、サーバー識別子を取得。
  - `mountMonitor(host, scanId)`: iframe 内の 3 ペイン DOM を親シェルの `#monitorModule`（または ShadowRoot）へ投影。
  - `unmountMonitor()`: 投影を解除。
  - `setSurface(surface)`: `'setup'` または `'monitor'` のサーフェス表示を切り替え。
  - `startScan(config)`: WebSocket 経由でスキャン開始コマンド（`{action: "start_scan", config}`）を送信。
- 状態変更時は `window.parent.postMessage({ type: 'vulix:scan-context', context }, origin)`（`dashboard.html:2956`）により親シェルへ通知され、ヘッダーの表示が同期されます。

### 3.4 レガシー DOM アダプタ (`createLegacyViewAdapter`)

`templates/ui/app-shell.js:325` の `createLegacyViewAdapter` は、`dashboard.html` 内部に残る従来の DOM 要素（`viewLiveMonitor`, `viewScanHistory`, `viewAuditLog` 等のコンテナや `navLiveMonitor`, `hdrBtnLive` 等のボタン）を操作するためのアダプタです。
グローバル関数 `switchMainView(viewName)`（`app-shell.js:476`）のシグネチャを完全に維持しているため、レガシーなインライン `onclick="switchMainView('history')"` もそのまま正常に動作します。

---

## 4. 責務境界と正本 (Sources of Truth)

新機能の実装や UI の改修時に、バックエンドの正本をフロントエンドで二重管理・再実装することを防ぐため、関心事ごとの正本（Source of Truth）と境界ルールを以下のように定めています。

| 関心事 | 正本 (Source of Truth) の所在 | 配信エンドポイント | UI の責務と境界ルール |
|---|---|---|---|
| **設定スキーマ & プロファイル** | `wscan/settings_schema.py`<br>（`FIELDS`, `PROFILES`） | `GET /api/v1/settings/schema` | **UI はスキーマの単なる投影**。<br>フィールド定義、型、バリデーション制約、プロファイルの上書き値を UI 側で独自定義・ハードコードしてはならない。 |
| **実効設定 & 秘密値保護** | `wscan/settings_schema.py`<br>（`build_effective_config`）<br>`main.py`（`apply_config_secret_fallback`） | `GET /api/v1/settings/effective` | **UI は秘密値を保持・平文表示しない**。<br>パスワードやトークンはサーバー側で伏字化される。未入力時はサーバー側で既存設定へフォールバックされるため、UI からダミー値を送信しない。 |
| **事前診断 (Preflight)** | `wscan/preflight.py`<br>（`run_preflight`, `classify_exception`） | `POST /api/v1/preflight`<br>`GET /api/v1/scans/{id}/preflight` | **UI は診断ロジックを持たない**。<br>DNS 解決、TLS 検証、ポート疎通、認証スコープ等の判定はすべてサーバーで実行される。UI は受信した合否判定（`pass`, `warning`, `fail`, `not_checked`, `not_applicable`）をそのまま描画するのみ。未検査や失敗を「合格」と偽装してはならない。 |
| **静的機能マニフェスト** | `wscan/capability_manifest.py`<br>（`SCANNERS` と `ScannerContract`） | `GET /api/capability-manifest`<br>`GET /api/v1/capability-manifest` | **静的宣言 ≠ 実行カバレッジ**。<br>マニフェストは「スキャナが検査可能として設計された静的機能」の宣言に過ぎない。UI は免責事項を明示して表示し、動的スキャンの実行カバレッジや合格保証として扱ってはならない。 |
| **証拠ビューア** | `templates/ui/evidence-viewer-registry.js` | フロントエンド内部レジストリ | **エビデンスの安全なサニタイズと描画**。<br>受信した Finding データをサニタイズし、機密キーを自動マスキングした上で適切なビューア（DOM / JSON / HTTP / Fallback）にディスパッチする。 |
| **カバレッジ & 脆弱性データ** | `wscan/engine.py`<br>`wscan/scanners/base.py` (`Finding`)<br>`output/<scan_id>/findings.json` | `GET /api/v1/scans/{id}/findings`<br>WebSocket `finding` イベント | **実測データの正確な可視化**。<br>検出された脆弱性の確証状態（`verified: reproduced / assumed / unreproduced / skipped`）および出自（`provenance: scanner / agent / agent_verified`）を改変せずそのままバッジ表示する。 |

---

## 5. 拡張レジストリ

### 5.1 機能マニフェスト (`wscan/capability_manifest.py`)

機能マニフェストは、Vulix に組み込まれている全スキャナおよび Agent 機能の静的宣言メタデータを JSON 形式でクライアントへ提供します。

- **バージョニングとスキーマ検証**:
  マニフェストは `SCHEMA_VERSION = "1.0.0"`（`capability_manifest.py:32`）を持ちます。トップレベル必須フィールド（`schema_version`, `manifest_kind`, `declaration_only: true`, `execution_coverage_claimed: false`, `declaration_disclaimer`, `scanner_count`, `scanner_ids`, `scanners`）の存在と型が `validate_capability_manifest()` によって厳格に検証されます。
- **スキャナ契約との連動**:
  各スキャナ（`wscan/scanners/` 配下）は `ScannerContract`（`wscan/scanner_contract.py`）を宣言しており、マニフェスト生成関数（`build_capability_manifest()`）が SCANNERS レジストリから自動的にメタデータ（重症度、CVSS スコア、副作用分類、コスト、前提条件、対応キャリア）を抽出します。
- **カバレッジ偽装の防止 (`FORBIDDEN_COVERAGE_KEYWORDS`)**:
  静的マニフェストが実行結果のカバレッジと誤認されるのを防ぐため、`capability_manifest.py:168` では禁止キーワード（`coverage`, `tested`, `passed`, `verified`, `runtime_coverage`, `execution_count`, `test_passed`）を定義し、宣言内にこれらの語が混入していないことをテストで保証しています。
- **未実装機能の明示**:
  トラフィックの改ざん再送（mutation）、リプレイ（replay）、プロキシ（proxy）機能は現行コードに存在しないため、マニフェストにも一切宣言されていません。UI 側（`traffic-module.js` 等）でもこれらのアクションボタンは「not available in this version」として明示的に非活性（disabled）化されます。

### 5.2 エビデンスビューアレジストリ (`templates/ui/evidence-viewer-registry.js`)

脆弱性の証拠（Evidence）を安全かつ柔軟に表示するための拡張レジストリです。

- **ビューアの登録 API (`EvidenceViewerRegistry.register`)**:
  ```javascript
  EvidenceViewerRegistry.register('custom_check', function ({ finding, safe, escape }) {
    return `<div class="custom-evidence">${escape(finding.evidence)}</div>`;
  });
  ```
  `kind`（文字列）と描画関数（`render`）を渡して登録します。
- **種別判定とフォールバック階層 (`evidenceKind`)**:
  `finding.evidence_type` または `finding.check_type` に基づき、適切なビューアを選択します。
  1. カスタム登録されたビューア（`viewers.has(type)`）
  2. 組み込み `dom`: 正規表現 `/(?:dom|html|xss|reflection|dialog|sink)/` に合致
  3. 組み込み `json`: 正規表現 `/(?:json|graphql|mass_assignment|nosql|api)/` または `injection_location === 'json_body'` に合致
  4. 組み込み `http`: 正規表現 `/(?:http|request|response|trace|websocket)/` またはリクエスト/レスポンスオブジェクトが存在
  5. 組み込み `fallback`: 上記のいずれにも該当しない場合の安全な既定ビューア
- **機密フィールドの自動マスキング (`clean`)**:
  証拠オブジェクトのキー名が `sensitiveKey`（`evidence-viewer-registry.js:6`）に一致する場合、値は自動的に `'[redacted]'` に置換されます。
  - 対象キー正規表現: パスワード（`password`, `passwd`, `pwd`）、トークン・シークレット（`secret`, `token`, `bearer`, `jwt`）、セッション・Cookie（`cookie`, `session_id`, `sid`, `phpsessid`, `jsessionid`）、API キー（`api_key`, `auth_key`）、認証ヘッダ・署名（`auth`, `signature`, `credentials`）。
  - URL 中の認証情報（`http://user:pass@host/`）も `helpers.redactUrl` により `http://[redacted]@host/` へ自動置換されます。
- **スクリーンショットの安全性検証 (`screenshot`)**:
  JPEG マジックバイト（`FF D8 FF`）および Base64 文字列の正当性を検証した画像のみをレンダリングし、XSS や不正データの埋め込みを防ぎます。

---

## 6. 設定の優先順位 (Configuration Precedence)

Vulix における設定値の解決ルールは、CLI 実行時とダッシュボード（`serve`）実行時で明確に定義されています。

### 6.1 CLI 実行時 (`main.py`) の優先順位

CLI モード（`python3 main.py scan URL ...`）では、以下の順序で値が解決されます。

```
[最優先]  CLI 引数フラグ (例: --depth, --checks)
    ↑
[第2位]   環境変数 (特定の優先項目のみ。例: WSCAN_POPUP_HEADER_INTERCEPT, WSCAN_RETENTION_*)
    ↑
[第3位]   設定ファイル (config/wscan.yaml)
    ↑
[最下位]  コード内の組み込みデフォルト値
```

- `main._CFG`（`main.py:219`）が `config/wscan.yaml` を読み込みます。
- `argparse` の各引数の `default` 値として `_CFG` の値が割り当てられます。
- ユーザーが CLI で明示的にフラグを指定した場合、それが最優先されます。

### 6.2 ダッシュボード / サーバー実行時 (`main.py serve`) の優先順位

ダッシュボードからスキャンを開始する際、クライアントから送信された JSON（`cfg`）とサーバー側設定（`_CFG`）が `main.py:3621` の `apply_config_secret_fallback` を通じてマージされます。

```
[最優先]  ダッシュボード画面から入力された送信値 (空でない値)
    ↑
[フォールバック]  サーバー側設定ファイル (config/wscan.yaml) の値
```

- **通常フィールド**:
  ダッシュボードで設定された値（URL, Depth, Concurrency, Checks 等）が `config/wscan.yaml` の値を上書きします。
- **シークレット項目のフォールバック (`_SERVE_SECRET_FALLBACK_KEYS`, `main.py:291`)**:
  ブラウザ側へパスワードや Cookie などの機密値を平文配信しないため、画面側で空欄のままスキャンが開始された場合、サーバー側の `config/wscan.yaml` に定義された値（`auth_pass`, `cookies`, `low_priv_cookies`, `bearer`, `headers`, `tls_client_cert_password` 等）へ自動的にフォールバックします。画面上で新しい値を入力した場合は、入力値が優先されます。

### 6.3 設定項目ごとの個別優先ルール（リアルケース）

設定の種別によって、コード上で特殊な優先順位ロジックが存在します。

1. **MFA TOTP ソースの排他解決 (`resolve_submitted_totp_sources`, `main.py:350`)**:
   TOTP の設定ソースには `mfa_totp_uri`, `mfa_totp_secret`, `mfa_totp_qr` の 3 つが存在します。
   - ダッシュボードから **1 つでも非空の値が送信された場合**: 送信された項目のみを採用し、画面で空だった項目を `config/wscan.yaml` で補完しません（排他制御）。
   - **3 項目すべてが空の場合に限り**: `config/wscan.yaml` の値へフォールバックします。
2. **MFA 有効/無効トグル (`mfa_type`, `main.py:3427`)**:
   ダッシュボードで MFA を「無効」に設定した場合、空文字列 `mfa_type: ""` がサーバーへ送信されます。
   - `""`（空文字列）が届いた場合: 環境変数や config を上書きして **明示的に無効化** します。
   - キー自体が欠落（`None`）している場合のみ: 環境変数や config の値に委ねます。
3. **特定機能トグル (`enable_tls_scan`, `enable_component_intel`, `main.py:3466`)**:
   - `enable_tls_scan`: ダッシュボードから明示指定がない（`None`）場合、既定値 `False` で上書きせず、`checks` リスト内に `'tls_scan'` が含まれているかに基づいて推論されます。
   - `enable_component_intel`: 未指定（`None`）時は `config/wscan.yaml` の `features.component_intel` の設定に従います。
4. **環境変数が最優先される項目**:
   - `WSCAN_POPUP_HEADER_INTERCEPT` (`main.py:270` `_popup_header_intercept_default`):
     環境変数の値が存在する場合、`config/wscan.yaml` の `browser.popup_header_intercept` より優先されます。
   - 出力保持ポリシー (`main.py:3040`):
     環境変数 `WSCAN_RETENTION_DAYS` / `WSCAN_RETENTION_MAX_SCANS` が設定されている場合、`config/wscan.yaml` の `monitor.retention_*` より優先されます。
   - LLM API キー (`ANTHROPIC_API_KEY`, `OPENAI_API_KEY`, `GEMINI_API_KEY`):
     セキュリティ上 `wscan.yaml` やダッシュボードには永続化されず、プロセスの環境変数から直接取得されます。
   - OOB メール検査設定 (`WSCAN_OOB_*`):
     環境変数から直接読み込まれます（`OOBEmailConfig.from_env()`）。
5. **高速モード (`fast_mode`, `main.py:222` `_fast_mode_deterministic_note`)**:
   `--fast`（またはダッシュボードで高速モード有効時）は、高速化のために以下の設定を強制的に上書きします:
   - `planner`, `AI分析`, `WAF検出`, `sitemapクロール`: 強制的に `OFF`。個別フラグで有効化することはできません。
   - `LLM`: 既定のプロバイダー（`ollama`）のときのみ `none` へ落とされます。CLI で `--llm` を明示指定した場合は、その LLM 設定が維持されます。
6. **サーバー設定・通知設定 (`output/wscan_settings.json`)**:
   ダッシュボードの Settings 画面で設定する Webhook 通知設定（`/api/v1/settings`）は、`config/wscan.yaml` ではなく `output/wscan_settings.json` にアトミックに永続化されます（`wscan/monitor.py:1951` `_save_settings`）。スキャン完了時の通知送信には、この永続化された設定が使用されます。
