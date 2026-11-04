# Vulix ダッシュボード UI アーキテクチャ

本ドキュメントは、Vulix（旧称 WScan）の Web ダッシュボード（`/app` シェル）の内部アーキテクチャ、UI とサーバー間の通信契約、責務境界、拡張レジストリ、および設定値の解決について、現行のソースコードに基づいて解説する開発者・運用者向けドキュメントです。

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
    ├── app-shell.js              # モジュールレジストリ（＋レガシーシェル用ディスパッチャ）
    ├── app-entry.js              # /app ルーター & エントリポイント
    ├── capability-reader.js      # 機能マニフェスト読み取りクライアント
    ├── evidence-viewer-registry.js # 脆弱性証拠ビューアレジストリ
    ├── monitor-module.js         # 3ペイン Monitor 画面モジュール
    ├── setup-module.js           # Scan Setup 画面モジュール（5タブ + Preflight）
    ├── findings-module.js        # Findings 画面モジュール（2ペイン一覧/詳細）
    ├── crawl-module.js           # Crawl 画面モジュール（Graph / Tree Explorer / List）
    ├── traffic-module.js         # HTTP トラフィック閲覧画面モジュール
    ├── settings-module.js        # Settings（設定・通知）画面モジュール
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

`/app` の画面遷移は `templates/ui/app-entry.js` のルーターが担い、`templates/ui/app-shell.js` からは汎用の `ModuleRegistry` を利用します。

- **`ModuleRegistry` (`templates/ui/app-shell.js:17`)**:
  画面モジュールの定義（`id`, `title`, `route`, `mount(ctx)`, `unmount(ctx)`）を登録・保持し、画面遷移時の `transition(targetId, ctx)` によって前画面の `unmount` と新画面の `mount` を順序通り実行します。既定 ID は `live` ですが、`app-entry.js:432` で `portal` に変更されます。
- **`/app` のルーター (`templates/ui/app-entry.js:434` `parseRoute`, `:540` `renderRoute`)**:
  `window` の `hashchange` を購読し（`app-entry.js:569`）、ハッシュからルートを解析して `registry.transition()` を呼び出します。解析またはモジュールの取得に失敗した場合はアクティブなモジュールを破棄し、`#message` 領域にエラーメッセージを表示します。
- **`NavigationDispatcher` (`templates/ui/app-shell.js:162`)**:
  `templates/dashboard.html` が呼ぶ `setupAppShell`（`dashboard.html:7410`）向けの、許可ハッシュ→view id 対応表と既定 view `live` へのフォールバックを持つディスパッチャです。`/app` 側では生成されません。
- **ルート解析 (`parseRoute`)**:
  許可ルートは `/portal`, `/history`, `/audit`, `/setup`, `/monitor`, `/findings`, `/crawl`, `/traffic`, `/agent-skills`, `/settings` で、クエリパラメータはホワイトリスト方式で検証します。
  - `/monitor`: `scan`
  - `/findings`: `scan`, `finding`, `url`, `search`, `severity`, `checkType`, `verification`, `provenance`
  - `/crawl`: `scan`, `node`, `url`, `mode`, `kind`, `search`
  - `/traffic`: `scan`, `entry`, `url`, `method`, `status`, `source`, `type`, `search`
  不正なクエリキー、長すぎる文字列、複数の同一キー指定は拒否され（`null` を返す）、`renderRoute` がエラーメッセージを表示します。

### 1.3 共通コンポーネントとデザイントークン (`templates/ui/tokens.css`, `templates/ui/components.css`)

- **デザイントークン (`templates/ui/tokens.css`)**:
  背景色（`--bg: #161826`）、サーフェス色（`--surface: #1c1e2c`, `--surface2: #232532`）、ブランド色（`--accent: #9184d9`）、境界線（`--border: #3f424d`）、セマンティックステータス色（`--status-pass`, `--status-fail`, `--status-warning`, `--status-not-checked`, `--status-unknown`, `--status-unavailable`, `--status-stale`）を一元定義します。`tests/test_ui_module_no_hardcoded_colors.py` は `templates/ui/*-module.js` を対象に、コメントを除去した上で 16 進カラーリテラル（`#rgb`〜`#rrggbbaa`）が許可リスト（現在は空）以外に現れないことを検証します。CSS ファイルや `rgb()` / `rgba()` 表記は対象外です。同テストは `tokens.css` のレガシー別名（`--success`, `--warning`, `--running`）が `--status-*` トークンを参照していることも検証します。
- **共通スタイル (`templates/ui/components.css`)**:
  ボタン、バッジ、フォーム入力、テーブル、カード、モーダルなどの共通スタイルと、視認可能なキーボードフォーカスリング（`:focus-visible`）を定義します。

### 1.4 API クライアント (`templates/ui/api-client.js`)

サーバーとの HTTP 通信を一元管理するクライアントです。
- **型付き結果オブジェクト (`ApiResult`, `api-client.js:22`)**:
  通信結果を単一のブール値ではなく、明確なステート種別（`success`, `unauthorized`, `http_error`, `network_error`, `decode_error`, `aborted`）としてカプセル化します。HTTP 401 応答時には `isUnauthorized()` が true となり、認証切れを明確にハンドリングできます。
- **スコープ付きキャンセル (`ScopedApiClient`, `api-client.js:153`)**:
  スコープごとに `AbortController` を保持し、`cancelAll()`（`api-client.js:219`）でそのスコープを通じて発行した進行中リクエストを一括中断します。`/app` では Setup（`app-entry.js:166`）、スキャン指定付き Monitor（`app-entry.js:285`）、Findings（`findings-module.js:694`）、Crawl（`crawl-module.js:1739`）、Traffic（`traffic-module.js:268`）、Settings（`settings-module.js:460`）がスコープを生成し、アンマウント時に `cancelAll()` を呼びます。一方、Portal / History / Audit（`summary-modules.js`）は共有 `ApiClient` を直接呼び、スコープを持ちません（アンマウント時は世代カウンタを進めて古い応答を無視し、DOM を空にします）。Agent Skills も共有 `ApiClient` 経由でマニフェストを取得します。したがって中断が保証されるのはスコープ内の通信だけで、スコープ外の遅延応答は各画面側の判定に委ねられます。

### 1.5 イベントストリームクライアント (`templates/ui/event-stream.js`)

WebSocket（`/ws`）経由のリアルタイム通知を受信・処理するクライアントです。
- 単一 WebSocket コネクションの維持と、既定 3000ms の再接続タイマー（`reconnectDelay`）。
- HTTP/WS コード 4401（未認証・セッション失効）の検知と再接続ループの即時停止。
- 受信イベントのシーケンス番号管理（`CursorProjection`）による順序保証・重複排除・欠落時再同期。
- `requestAnimationFrame` によるバッチ描画（1フレームあたり最大50件）。
詳細な通信契約は「2. UI とサーバー間の契約」に後述します。

### 1.6 各画面モジュールの責務

`templates/ui/` 配下の各画面モジュールは、特定のドメイン責務を受け持ちます。

| 画面名 | ソースファイル | 主な責務・機能 |
|---|---|---|
| **Portal** | `templates/ui/summary-modules.js` | サーバー全体の稼働概要、実行中スキャンの状態確認・中止、ストレージ使用状況、過去スキャンの保持ポリシー整理（Prune）、定期スケジュール設定の一覧・追加・切り替え・削除。 |
| **Setup** | `templates/ui/setup-module.js` | 5 つのカテゴリタブ（クロール・スコープ、検査項目・ペイロード、認証・ネットワーク、AI・自律探索、高度な設定・フロー）によるスキャン構成作成。事前診断（Preflight）の実行。構成プロファイルの選択と実効差分表示。スキャン開始要求の発行。 |
| **Monitor** | `templates/ui/monitor-module.js` | 3 ペイン（左: Event Log・Findings・Network、中央: 巡回マップ / ブラウザ / 進捗タブ、右: Scan Workspace）によるリアルタイムスキャン進捗監視。ペインのリサイズ、折りたたみ、最大化、レイアウトプリセットの保存。 |
| **Crawl** | `templates/ui/crawl-module.js` | サイト巡回構造の可視化。3 つの表示モード（SVG インタラクティブグラフ、ツリーエクスプローラー、テーブルリスト）。ノード詳細ドロワー（フォーム、入力パラメータ、検出脆弱性）。 |
| **Findings** | `templates/ui/findings-module.js` | 検出脆弱性の一覧・詳細分割表示（2 ペイン）。重要度、検証状態（reproduced / assumed 等）、出自（通常スキャナ / Agent 発見）によるフィルタリングと検索。証拠ビューアの描画。 |
| **Traffic** | `templates/ui/traffic-module.js` | スキャン中に記録された HTTP リクエスト/レスポンスログ（`http_requests.jsonl`）の読み取り専用閲覧。メソッド・ステータス・URL フィルタリング。機密パラメータのマスキング。 |
| **Settings** | `templates/ui/settings-module.js` | 設定スキーマと実効値の表示（プリセット選択を含む）、Webhook 通知設定（URL はマスク表示）、最小通知重要度、スキャン完了通知の有効/無効、設定の保存とテスト通知送信。 |
| **Agent Skills** | `templates/ui/agent-skills-module.js` | 静的機能マニフェスト（Capability Manifest）に基づく Agent / Hybrid / 通常スキャナの機能一覧・契約メタデータの閲覧。 |
| **History** | `templates/ui/summary-modules.js` | 過去スキャンの一覧表示、フィルタ検索、スキャン結果 ZIP のダウンロード、差分（Diff）比較モーダル表示。 |
| **Audit** | `templates/ui/summary-modules.js` | 管理操作監査ログ（スキャン開始・中止・削除、履歴整理、定期実行の追加/切替/削除、ファイル配置、設定変更など）の一覧表示。時刻・操作名・クライアント IP・詳細の有無を表示し、`detail` の本文は描画しません（文字列なら「（詳細非表示）」、それ以外は「（詳細なし）」、`summary-modules.js:96`）。 |

### 1.7 新規画面モジュールの追加手順

既存の画面モジュールを変更せずに、新しい画面モジュールを追加できます（シェル側の `app.html` と `app-entry.js` には登録を追加します）。

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
| `GET` | `/api/v1/scans/{id}/diff` | `summary-modules.js` | 同一対象の直前スキャンとの脆弱性差分（新規/修正済み/継続）を返却。比較対象がなければ 404。 |
| `POST` | `/api/v1/scans/prune` | `summary-modules.js` | 保持ポリシーに基づき古いスキャンディレクトリを削除。`{status: "ok", deleted: [...]}` |
| `GET` | `/api/v1/audit` | `summary-reader.js` | サーバー管理操作ログ（`output/management_audit.jsonl`）を返却。`{audit: [...]}` |
| `GET` | `/api/v1/scan/status` | `summary-reader.js` | 実行中スキャンのステータス概要を返却。 |
| `POST` | `/api/v1/scan/abort` | `summary-modules.js` | 実行中スキャンの中止を要求。 |
| `GET` | `/api/v1/schedules` | `summary-reader.js` | 定期実行スケジュール一覧を返却。`{schedules: [...]}` |
| `POST` | `/api/v1/schedules` | `summary-modules.js` | 新規定期実行スケジュールを登録。 |
| `POST` | `/api/v1/schedules/{id}/toggle` | `summary-modules.js` | スケジュールの有効/停止を切り替え。 |
| `DELETE` | `/api/v1/schedules/{id}` | `summary-modules.js` | 定期実行スケジュールを削除。 |
| `GET` | `/api/capability-manifest`<br>`/api/v1/capability-manifest` | `capability-reader.js`, `agent-skills-module.js` | スキャナおよび Agent の静的機能宣言マニフェストを返却（後述）。 |
| `GET` | `/api/v1/settings/schema` | `setup-module.js`, `settings-module.js` | 設定フォーム構築のための宣言的スキーマ（フィールド定義、型、制約、プロファイル）。 |
| `GET` | `/api/v1/settings/effective` | `setup-module.js`, `settings-module.js` | フォーム初期値（serve の `default_scan_cfg`）に選択プロファイルを適用した値と差分（秘密値は除外、宣言上の解決）。 |
| `POST` | `/api/v1/preflight` | `setup-module.js` | DNS 解決、HTTP GET 到達性（直接およびプロキシ経由）、TLS 証明書検証の可否、Playwright Chromium の起動可否、出力ディレクトリの書き込み可否、ログインページへの非破壊 GET（認証情報は送信せず、スコープ内のみ）、認証準備状態、指定した checks の前提条件、Agent 用バックエンドの import 可否、ライブチャネル、OOB 設定の有無を診断（`wscan/preflight.py:351` `run_preflight`）。検査用ペイロードは送信しませんが、到達性確認とログインページ確認のために HTTP GET を送ります。 |
| `GET` | `/api/v1/settings` | `settings-module.js` | Webhook 通知設定を取得（URL は伏字マスク化）。 |
| `POST` | `/api/v1/settings` | `settings-module.js` | Webhook 通知設定を更新保存。 |
| `POST` | `/api/v1/settings/test` | `settings-module.js` | 設定中の Webhook URL へテスト通知を送信。 |
| `GET` | `/api/v1/scans/{id}/findings`<br>`/api/v1/scan/findings` | `findings-module.js`, `traffic-module.js` | 指定スキャン（`/api/v1/scans/{id}/findings`）は完了後に `output/<scan_id>/evidence.json` を読み取り、現行スキャン（`/api/v1/scan/findings`）はメモリ上の `self.api_findings` を返却。 |
| `GET` | `/api/v1/scans/{id}/crawl-graph`<br>`/api/v1/scan/crawl-graph` | `crawl-module.js` | 指定スキャンまたは現行スキャンの巡回ノード・エッジ・完了状態を返却。 |
| `GET` | `/api/v1/scans/{id}/traffic?limit=500`<br>`/api/v1/scan/traffic?limit=500` | `traffic-module.js` | 記録された HTTP リクエスト/レスポンス履歴（`http_requests.jsonl`）を返却。 |

### 2.2 WebSocket イベントストリーム (`/ws`)

リアルタイム通知は `wscan/monitor.py:600` の `@app.websocket("/ws")` エンドポイントで提供され、クライアント側は `templates/ui/event-stream.js` が接続と投影を管理します。

#### 接続確立と認証ハンドシェイク
- WebSocket ハンドシェイク時、サーバーは Cookie またはトークンによる認証検証（`_ws_authorized`）を行います。
- 認証に失敗した場合、サーバーは **カスタム切断コード `4401`**（`wscan/monitor.py:603`）で即座に WebSocket を切断します。
- クライアント側（`event-stream.js:373`）は `code === 4401` を検知すると、**自動再接続タイマーを直ちに停止**し、リトライストームを抑止した上でログイン案内メッセージを発行します。

#### 初期スナップショット (`scan_snapshot`)
接続が受理されると、サーバーは現在のスキャン状態をまとめたスナップショットイベントを先頭で送信します（`_scan_snapshot_event()` の定義は `wscan/monitor.py:2356`、送信は `:608`）。
スナップショット送信中にバックエンドで発生した新規イベントは `_ws_sync_buffers` に一時バッファリングされ、スナップショット完了後に順序を保ってクライアントへ配信されます。スナップショットのカーソルを基準に後続イベントを適用することで、両者の競合を避けています。

#### イベントエンベロープとシーケンス管理 (`CursorProjection`)
WebSocket で流れるイベントは、カーソル付きのものとカーソルなしのものがあります。

**カーソル付きイベント**（`emit()` が配信する通常イベントと `scan_snapshot`、`wscan/monitor.py:2470-2496` / `:2356`）:
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

**カーソルなしイベント**:
- keep-alive の ping は `{"type": "ping"}` のみ（`wscan/monitor.py:632`）。
- `manual_crawl_frame`（`broadcast_ephemeral()`、`wscan/monitor.py:2511`）は `type` / `timestamp` / `data` のみで、`server_id` / `run_id` / `sequence` を持ちません。
`validateWireEvent()` は耐久イベントを要求する場合、これら以外にカーソルを要求します。ただし同関数はカーソル判定より先に `data` オブジェクトを検証するため、サーバーが送る `data` を持たない ping を `fromWire` で渡すと `invalid_data` になります（`event-stream.js:123-145`, `:450-457`）。

- **シーケンス番号 (`sequence`)**: スキャン実行ごとに `_scan_sequence` が 0 から始まり、`emit()` のたびに 1 ずつ増えてイベントに載ります（`wscan/monitor.py:2482-2489`）。`scan_snapshot` は現在の `_scan_sequence` をそのまま載せるため、イベント未発生なら 0、発生済みなら最新値です。クライアントはスナップショット適用時にカーソルをその値へ合わせます（`applyScanSnapshot`, `templates/dashboard.html`）。
- **重複排除**: クライアントが保持する `lastEventSequence` 以下のシーケンス番号を持つイベントが届いた場合、重複として破棄（`drop`）されます。
- **シーケンス欠落の検知と再同期**: 受信したシーケンス番号が `lastEventSequence + 1` より大きい場合、通信途絶等によるイベント欠落と判断し、クライアントは `reconnect_on_gap` で WebSocket を再接続して最新の `scan_snapshot` を再取得します（`event-stream.js:231-243`, `:482`）。
- **新規スキャンリセット**: `run_id` が現在と異なるイベントは `scan_started` かつ `sequence === 1` の場合のみ受理して状態を初期化します。新規 `run_id` の他の種別は破棄され、`sequence` が 1 でない `scan_started` は欠落とみなして再接続します（`event-stream.js:212-228`）。

#### 既知イベント種別 (31 種)
`templates/ui/event-stream.js:77` の `KNOWN_EVENTS` で定義されるイベント種別:
`status`, `page_start`, `scan_config`, `payload_test`, `phase`, `page_graph_update`, `page_graph_vuln`, `subphase`, `phase_timing`, `url_start`, `url_complete`, `screenshot`, `finding`, `finding_update`, `scan_gap`, `request`, `response`, `progress`, `scan_complete`, `plan_review`, `crawl_review`, `intervention_state`, `manual_crawl_status`, `manual_crawl_frame`, `ai_analysis`, `waf_detected`, `awaiting_config`, `scan_rejected`, `scan_started`, `scan_snapshot`, `ping`。

#### 未知・不正形式イベントの安全な処理
- **エンベロープ検証 (`validateWireEvent`, `event-stream.js:123`)**:
  受信した JSON がオブジェクトでない場合や、`type` が空でない文字列でない、`data` がオブジェクトでない場合は不正イベントとして扱われます。`backend_version` が必須で、クライアントが保持するマニフェストの `schema_version` と一致しない場合も不正です。
- **カーソルの必須扱い**:
  `ping` と `manual_crawl_frame` 以外のイベントに `server_id` / `run_id` / `sequence` が無い場合は `missing_cursor` として不正になり、回線を stale（`_wireStale = true`）にして再接続します（`event-stream.js:142-144`）。カーソル付きの未知種別イベントは受理され、既存ハンドラへ渡ります。
- **不正形式・解析エラー**:
  カーソル付きの不正形式イベントや JSON 解析エラーが発生した場合、回線を stale としてマークし、再接続によって正常なスナップショットからの回復を図ります（stale 中は `scan_snapshot` 以外を処理しません）。
- **バージョン不一致 (`backend_version_mismatch`)**:
  バックエンドとフロントエンドのバージョン不一致は回線の物理切断ではなく互換性の状態であるため、再接続せずに stale 状態を通知します（`event-stream.js:457-462`）。

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
  - `tests/test_ui_app_screens_e2e.py`: Playwright で `/app` シェル上の各画面遷移、フォーム操作、セッション失効時の画面動作を検証。

---

## 3. 移行ノート (Migration Notes)

### 3.1 単一 `dashboard.html` からモジュール構成への分割

Vulix の UI は、当初 `templates/dashboard.html` という単一の大規模 HTML ファイル（約 40 万バイト）内に HTML、CSS、JavaScript、WebSocket 制御、各種ビュー描画ロジックが混在していました。
これを現代的なモジュール構造へ移行するにあたり、以下の原則で段階的な分離が行われました。

1. **トランスポートと描画の分離**:
   WebSocket の接続維持、スキャンのインメモリ状態管理、生イベントの購読といった低レイヤーの責務を、新 UI 画面の描画ライフサイクルから切り離しました。
2. **画面ごとの独立ファイル化**:
   各画面（Setup, Monitor, Findings, Crawl, Traffic, Settings, Agent Skills）を `templates/ui/*.js` として独立させ、共通の `ModuleRegistry` インターフェース（`mount` / `unmount`）に従う形へ再構築しました。
3. **画面破棄時の状態整理**:
   旧来のインライン切り替えでは、非表示になった画面の通信やタイマーが背後で動き続ける問題がありました。新設計では Setup / Monitor / Findings / Crawl / Traffic / Settings が `api.createScope()` で生成したスコープを保持し、画面破棄時に `cancelAll()` で保留中のリクエストを中断します。Portal / History / Audit などのサマリ系モジュールはスコープを持たず、世代カウンタで古い応答を破棄する方式です。

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

## 4. 責務境界とデータの所在

バックエンドが定義・検証するデータをフロントエンドで二重管理しない、という方針で各画面を構成しています。以下は現行コードでの定義場所・配信経路・UI 側の扱いです。

| 関心事 | 定義・検証するコード | 配信エンドポイント | UI 側の実装 |
|---|---|---|---|
| **設定スキーマ & プロファイル** | `wscan/settings_schema.py`<br>（`FIELDS`, `PROFILES`, `validate_settings_schema`） | `GET /api/v1/settings/schema` | Setup は `schema.fields` からフォームを、`schema.profiles` からプリセットを生成します（`setup-module.js:965`, `:1126`）。Settings も `schema.fields` を使いますが、プリセット一覧は画面内の固定リストです（`settings-module.js:226-233`）。 |
| **実効設定 & 秘密値** | `wscan/settings_schema.py`<br>（`build_effective_config`）<br>`main.py`（`apply_config_secret_fallback`） | `GET /api/v1/settings/effective` | サーバーが「serve のフォーム初期値（`monitor.default_scan_cfg`、`config/wscan.yaml` 由来で秘匿値は空）→ 選択プロファイルの `overrides`」の順で解決した値と差分を返します（`settings_schema.py:320-365`, `resolution_scope: "serve_form_defaults_then_scan_profile"`）。起動引数や環境変数を含む最終的な実行時優先順位ではありません。`redacted_keys` の項目は値が `null` で返り、UI は秘匿値を保持しません。スキャン開始時に空で届いた秘匿値だけが `apply_config_secret_fallback` で config から補われます（6 章参照）。 |
| **事前診断 (Preflight)** | `wscan/preflight.py`<br>（`run_preflight`, `classify_exception`） | `POST /api/v1/preflight`<br>`GET /api/v1/scans/{id}/preflight` | 判定はサーバーで実行し、UI は `pass`, `warning`, `fail`, `not_checked`, `not_applicable` をそのまま表示します（`setup-module.js:47-90`）。 |
| **静的機能マニフェスト** | `wscan/capability_manifest.py`<br>（`SCANNERS` と任意の `ScannerContract`） | `GET /api/capability-manifest`<br>`GET /api/v1/capability-manifest` | Agent Skills 画面は「宣言情報（表示専用）」として一覧表示します（`agent-skills-module.js:106`）。マニフェストは `declaration_only: true` / `execution_coverage_claimed: false` を持ち、実行カバレッジの主張は含みません。 |
| **証拠ビューア** | `templates/ui/evidence-viewer-registry.js` | フロントエンド内部レジストリ | 受信した Finding をサニタイズし、機密キーをマスキングした上で種別ごとのビューア（DOM / JSON / HTTP / Fallback）に振り分けます（5.2 参照）。 |
| **検出結果** | `wscan/engine.py`<br>`wscan/scanners/base.py` (`Finding`)<br>`output/<scan_id>/findings.json` | `GET /api/v1/scans/{id}/findings`<br>WebSocket `finding` イベント | `verification_state` を `reproduced` / `assumed` / `unreproduced` / `untested` / `unknown` のバッジとして表示します。出自は `source`（`agent` か否か）と `agent_verified` から `scanner` / `agent` / `agent_verified` の 3 状態として判定し、フィルタにも同じ判定を使います（`findings-module.js:132-224`, `:229-274`）。 |

---

## 5. 拡張レジストリ

### 5.1 機能マニフェスト (`wscan/capability_manifest.py`)

機能マニフェストは、Vulix に組み込まれている全スキャナおよび Agent 機能の静的宣言メタデータを JSON 形式でクライアントへ提供します。

- **バージョニングとスキーマ検証**:
  マニフェストは `SCHEMA_VERSION = "1.0.0"`（`capability_manifest.py:32`）を持ちます。`REQUIRED_TOP_LEVEL_FIELDS`（`capability_manifest.py:42-52`）は `schema_version`, `manifest_kind`, `declaration_only`, `execution_coverage_claimed`, `declaration_disclaimer`, `default_checks`, `scanner_count`, `scanner_ids`, `scanners` で、`validate_capability_manifest()`（`capability_manifest.py:337`）が存在・型に加えて `declaration_only === true`、`execution_coverage_claimed === false`、`scanner_count` と `scanner_ids` の整合、許可外のトップレベルフィールドの不在を検証します。
- **スキャナ契約との連動**:
  `build_capability_manifest()`（`capability_manifest.py:284`）は `SCANNERS` レジストリの各スキャナから、重症度、CVSS スコア、副作用分類、コスト、前提条件、対応キャリアなどのメタデータを組み立てます。`CONTRACT`（`ScannerContract`）が設定されているスキャナはその宣言値を使い、設定されていないスキャナは `StateChangeClass.CONDITIONAL` などの既定値とモジュール属性で補います（`capability_manifest.py:219-221`, `:244-251`）。`ScannerContract` の宣言は任意です。
- **カバレッジ偽装の防止 (`FORBIDDEN_COVERAGE_KEYWORDS`)**:
  静的マニフェストが実行結果のカバレッジと誤認されるのを防ぐため、`capability_manifest.py:168` では禁止キーワード（`coverage`, `tested`, `passed`, `verified`, `runtime_coverage`, `execution_count`, `test_passed`）を定義し、宣言内にこれらの語が混入していないことをテストで保証しています。
- **未実装機能の明示**:
  トラフィックの改ざん再送（mutation）、リプレイ（replay）、プロキシ（proxy）機能はサーバー側に実装されておらず、マニフェストでも宣言されていません（`capability_manifest.py:141` のコメント参照）。UI 側（`traffic-module.js`）はマニフェストの `capabilities` に該当する宣言がある場合のみボタンを有効化し、宣言が無ければ「not available in this version」として非活性にします（`resolveTrafficActions`, `traffic-module.js:151-196`）。

### 5.2 エビデンスビューアレジストリ (`templates/ui/evidence-viewer-registry.js`)

脆弱性の証拠（Evidence）を安全かつ柔軟に表示するための拡張レジストリです。

- **ビューアの登録 API (`EvidenceViewerRegistry.register`)**:
  ```javascript
  EvidenceViewerRegistry.register('custom_check', function ({ finding, safe, escape }) {
    return `<div class="custom-evidence">${escape(finding.evidence)}</div>`;
  });
  ```
  `kind`（文字列）と描画関数（`render`）を渡して登録します。
- **種別判定とフォールバック階層 (`render` / `evidenceKind`, `evidence-viewer-registry.js:62`, `:46`)**:
  `finding.evidence_type`（無ければ `finding.check_type`）を小文字化した `type` を使います。まず `render` が `viewers.has(type)` を確認し、登録済みビューア名と完全一致すればそのカスタムビューアを使います。一致しない場合は `evidenceKind()` が次の順で組み込み種別を決めます。
  1. 組み込み `dom`: 正規表現 `/(?:dom|html|xss|reflection|dialog|sink)/` に合致
  2. 組み込み `json`: 正規表現 `/(?:json|graphql|mass_assignment|nosql|api)/` に合致
  3. 組み込み `http`: 正規表現 `/(?:http|request|response|trace|websocket)/` に合致
  4. `finding.injection_location === 'json_body'` なら `json`
  5. `finding.request` または `finding.response` が非空なら `http`
  6. 組み込み `fallback`: 上記のいずれにも該当しない場合
  正規表現の判定が `injection_location` より先なので、`check_type` に `http` を含む Finding に `injection_location: "json_body"` が付いていても HTTP ビューアが選ばれます。
- **機密フィールドの自動マスキング (`clean`)**:
  証拠オブジェクトのキー名が `sensitiveKey`（`evidence-viewer-registry.js:6`）に一致する場合、値は自動的に `'[redacted]'` に置換されます。入れ子のオブジェクトと配列も再帰的に処理します。
  - 対象キーの例: パスワード（`password`, `passwd`, `pwd`）、トークン・シークレット（`secret`, `token`, `bearer`, `jwt`）、セッション・Cookie（`cookie`, `session_id`, `sid`, `phpsessid`, `jsessionid`）、API キー（`api_key`, `access_key`, `auth_key`）、認証ヘッダ・署名（`auth`, `authorization`, `signature`, `credentials`）、CSRF・SAML・ワンタイム（`csrf`, `xsrf`, `samlresponse`, `otp`, `ticket`）。完全な一覧は正規表現を参照してください。
  - `url` / `uri` / `request_url` / `response_url` キーの値は `helpers.redactUrl` で表示用にマスクされます（`http://user:pass@host/` → `http://<redacted>@host/` など。実装は `findings-module.js:31` の `redactDisplayUrl`、`helpers` への公開は `:71`）。それ以外の文字列は `helpers.redactText`（`findings-module.js:56` の `redactDisplayText`、公開は `:72`）で `Bearer` / `Basic` 認証値や `key=value` 形式の機密パラメータがマスクされます。
- **スクリーンショットの安全性検証 (`screenshot`)**:
  JPEG マジックバイト（`FF D8 FF`）および Base64 文字列の正当性を検証した画像のみをレンダリングし、XSS や不正データの埋め込みを防ぎます。

---

## 6. 設定値の解決

設定値の解決は単一の優先順位ではなく、CLI 実行時と `serve` 実行時で経路ごとに実装が異なります。以下は現行コードで確認できる挙動のみを記載します。

### 6.1 CLI 実行時 (`main.py`)

- `main._CFG = _load_config()`（`main.py:219`, `:67`）が `config/wscan.yaml` を読み、フラットな dict にします。ファイルが無い、または解析できない場合は空 dict になります。
- `parse_args()`（`main.py:778`）の多くの `default` は `_CFG.get(...)` で決まります（例: `--depth` `main.py:857`、`--timeout` `:919`、`--headless` `:861`、`--tls-verify` `:1139`）。CLI で明示した値はそのまま argparse の値になります。
- `action="store_true"` かつ `default=_CFG.get(...)` のフラグ（`--headless`, `--tls-verify`, `--ctf`, `--dom-xss` など）には打ち消し用のオプションがありません。そのため config が `true` のとき、CLI から `false` に戻すことはできません。`--community-payloads`（`main.py:1290`）と `--auto-config`（`:1482`）は `argparse.BooleanOptionalAction` なので `--no-...` で無効化できます。
- `--fast` は後段で `headless=True`、`no_planner` / `no_ai_analysis` / `no_waf_detection` / `no_sitemap_crawl` を `True`、`max_payloads` が 0 なら 12、`delay=0` を設定します（`main.py:2478-2485`）。LLM は `--llm` を明示していれば維持し、未指定かつ既定プロバイダー（`ollama`）のときだけ `none` に落とします（`_fast_mode_llm`, `main.py:247`）。

環境変数はすべての項目に共通する階層ではなく、以下の項目でのみ config より優先されます。

- `WSCAN_POPUP_HEADER_INTERCEPT`（`main.py:270` `_popup_header_intercept_default`）は `config/wscan.yaml` の `browser.popup_header_intercept` より優先されます。
- `WSCAN_RETENTION_DAYS` / `WSCAN_RETENTION_MAX_SCANS`（`main.py:3042-3046`）は `monitor.retention_*` より優先されます。
- LLM の API キー（`ANTHROPIC_API_KEY`, `OPENAI_API_KEY`, `GEMINI_API_KEY`, `WSCAN_LLM_API_KEY`）は環境変数から読みます（`wscan/llm_client.py`, `wscan/llm_endpoint.py`, `wscan/llm_agent_browser.py`）。
- OOB メール検査設定は `WSCAN_OOB_*` から `OOBEmailConfig.from_env()` が読みます（`wscan/oob_email.py:77`）。

### 6.2 ダッシュボード / `serve` 実行時 (`main.py`)

`serve` のスキャンループでは、クライアントから受け取った `cfg`（`monitor.scan_request_data`）に `apply_config_secret_fallback(cfg, _CFG)` を適用してから `run_one_scan(cfg)` を呼びます（`main.py:3621`）。この関数が config で補うのは秘匿フィールドだけです。

- 対象は `_SERVE_SECRET_FALLBACK_KEYS`（`main.py:291`）: `auth_pass`, `cookies`, `low_priv_cookies`, `bearer`, `mfa_totp_secret`, `mfa_totp_uri`, `mfa_totp_qr`, `mfa_email_imap_password`, `tls_client_cert_password`, `headers`。空文字・`None`（`headers` は空 dict も）のときだけ `config/wscan.yaml` の値で補い、非空なら送信値をそのまま使います（`main.py:369-396`）。
- TOTP の 3 ソースは例外で、1 つでも非空なら送信値のみを採用し、他を config で補いません（`resolve_submitted_totp_sources`, `main.py:350`）。
- 秘匿以外の値はこの関数ではマージされません。各値は `ScanEngine` 構築時に `cfg.get(key, 既定値)` で読まれ（例: `main.py:3457-3497`）、整数項目は `_coerce_serve_ints`（`main.py:446`）で正規化されます。
- `GET /api/v1/settings/effective` は上記とは別に、`monitor.default_scan_cfg` をフォーム初期値としてプロファイルを適用した「宣言上の値」を返します（4 章参照）。

### 6.3 設定項目ごとの個別ルール

1. **MFA TOTP ソースの排他解決 (`resolve_submitted_totp_sources`, `main.py:350`)**:
   TOTP の設定ソースには `mfa_totp_uri`, `mfa_totp_secret`, `mfa_totp_qr` の 3 つが存在します。
   - ダッシュボードから **1 つでも非空の値が送信された場合**: 送信された項目のみを採用し、画面で空だった項目を `config/wscan.yaml` で補完しません（排他制御）。
   - **3 項目すべてが空の場合に限り**: `config/wscan.yaml` の値へフォールバックします。
2. **MFA 有効/無効トグル (`mfa_type`, `main.py:3429`)**:
   ダッシュボードは常に `mfa_type` を送信し、`""` は「無効」を意味します。
   - `""` が届いた場合: `ScanEngine` 側で環境変数 `WSCAN_MFA_TYPE` より優先して **明示的に無効化** します（`wscan/engine.py:1240-1245`）。
   - キー自体が欠落（`None`）している場合のみ: 環境変数・config の値に委ねます。
3. **特定機能トグル (`enable_tls_scan`, `enable_component_intel`, `main.py:3466-3472`)**:
   - `enable_tls_scan`: 明示指定がない（`None`）場合、既定値 `False` で上書きせず、`checks` に `'tls_scan'` が含まれるかに基づいて `ScanEngine` が推論します。
   - `enable_component_intel`: 未指定（`None`）時は `checks` に `'outdated_components'` が含まれるか、`config/wscan.yaml` の `features.component_intel` に従います（`wscan/engine.py:1141-1145`）。
4. **サーバー設定・通知設定 (`output/wscan_settings.json`)**:
   ダッシュボードの Settings 画面で設定する Webhook 通知設定（`/api/v1/settings`）は、`config/wscan.yaml` ではなく `output/wscan_settings.json` にアトミックに永続化されます（`wscan/monitor.py:1951` `_save_settings`）。スキャン完了時の通知送信には、この永続化された設定が使用されます（`_notify_settings`, `wscan/monitor.py:1969`）。
