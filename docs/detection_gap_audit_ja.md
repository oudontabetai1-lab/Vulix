# 検知経路の第一パス監査

通常ツール層の現行実装を対象とした、宣言能力と実検知の切り分け。Agent/Hybrid の独自仮説は対象外。

## カテゴリ × 入力面 × 判定方式

`s`: contract 上 supported（検知成功の証明ではない）、`P`: 未接続/予定、`U`: パラメータ注入非対応。page/protocol 検査の `U` は検査全体の非対応を意味しない。Path は任意 path segment 注入と固定資源探索を区別する。

|カテゴリ|Query|Path|Form|JSON|Header|Cookie|判定方式|
|---|---|---|---|---|---|---|---|
|cache_poisoning|U|s|U|U|s|U|ヘッダ変種とcache反射/再取得|
|clickjacking|U|U|U|U|U|U|XFO/CSP frame-ancestors|
|cms|U|s|U|U|U|U|既知CMS資源/バージョン|
|cors|U|U|U|U|s|U|Origin変種とACAO/credentials|
|csrf|U|U|U|U|U|U|POSTフォームとtoken欠落|
|deserialization|s|P|s|s|P|P|直列化形式、エラー/marker/遅延|
|dom_xss|s|P|s|P|P|P|DOM sink hook、marker/JS実行|
|file_upload|U|U|U|U|U|U|multipartの拡張子/MIME/内容と公開応答|
|graphql|U|U|U|U|U|U|introspection、batch、注入、cost応答|
|header_injection|s|P|s|s|P|P|CRLF投入後の応答ヘッダ|
|host_header|U|U|U|U|s|U|Host変種と応答反射|
|http_methods|U|U|U|U|U|U|OPTIONS/TRACE/PROPFIND応答|
|info_disclosure|U|s|U|U|U|U|機密資源署名、詳細エラー、技術ヘッダ、一覧|
|js_static|U|U|U|U|U|U|JS source→sink解析|
|jwt|U|U|U|U|s|s|署名/alg/kid/claim検査|
|ldap|s|P|s|s|P|P|LDAPエラー/認証応答差|
|mail_header|s|P|s|P|P|P|メールOOB、反射/エラー|
|mass_assignment|U|U|U|s|U|U|追加JSONキーと状態/応答差|
|nosql|s|P|s|s|P|P|DBエラー、真偽応答差、構造化演算子|
|open_redirect|s|U|s|P|U|U|Location、遷移先|
|os|s|P|s|s|P|P|コマンド出力、echo実行、遅延|
|outdated_components|U|U|U|U|U|U|資産/ヘッダのバージョン署名|
|path_traversal|s|P|s|s|P|P|ファイル内容署名|
|privesc|s|s|s|U|s|U|未認証/権限差、IDOR応答差|
|prototype_pollution|s|U|U|s|U|U|prototype変異/DOM/JSON応答|
|race_condition|U|U|s|U|U|U|並行要求と結果不整合|
|request_smuggling|U|P|U|U|s|U|raw HTTP framing、応答差/時間|
|secret_leak|U|U|U|U|U|U|本文/JS内の鍵署名・entropy|
|security_headers|U|U|U|U|U|U|応答のセキュリティヘッダ|
|session|U|U|U|U|U|U|Cookie属性、セッション操作|
|sqli|s|P|s|s|P|P|DBエラー、真偽応答差、遅延、等価性|
|sri|U|U|U|U|U|U|外部scriptとintegrity欠落|
|ssrf|s|P|s|s|P|P|内部資源/metadata署名、反射除去|
|ssti|s|P|s|s|P|P|算術式の評価結果|
|stored_xss|s|P|s|P|P|P|書込後の別ページmarker/実行|
|tls_scan|U|U|U|U|U|U|TLS handshake/certificate設定|
|websocket|U|U|U|U|U|U|WS handshake/message反射|
|xss|s|P|s|P|P|P|反射文脈、イベント/JS実行、等価性|
|xxe|U|U|U|U|U|U|XML entityとファイル/OOB署名|

宣言の正本: `wscan/scanners/__init__.py` の SCANNERS と各 scanner の CONTRACT。表は `build_capability_matrix` から生成し、判定方式は各 scanner の scan/verify 経路を参照。XML（xxe）、multipart（file_upload）、GraphQL、WebSocket は専用 carrier。任意 Header/Cookie/Path 注入は多くの注入 scanner で未接続であり、Query/Form 成功から外挿しない。

共通経路: Crawl → input/template列挙 → scanner dispatch → payload投入 → HTTP/DOM観測 → Finding → verify。Query/Form はブラウザ送信、対応 JSON は harvest/template 経由の直接 HTTP。`InjectionPoint` canonical location は url_param/form/json_body の3種。

## 確認方法

- `WSCAN_E2E=1 python -m pytest tests/test_end_to_end_scan_extra.py -q`
- `WSCAN_E2E=1 python -m pytest tests/benchmarks/test_scanner_executor_e2e.py -q -k "not sqli and not intranet_injection and not stored_xss"`
- `WSCAN_E2E=1 python -m pytest tests/test_info_disclosure_page_context.py -q`
- `python -m pytest tests/test_document_capture_provenance.py tests/test_transport_error_observable.py -q`
- `python -m pytest -q --ignore=tests/test_end_to_end_scan.py`

## 再現条件と原因

|対象|再現条件|観測|切り分け|
|---|---|---|---|
|CSRF|realistic_api /console/billing/payment-method、無token POSTフォーム、匿名実エンジン|既知Positive欠落、page-level tested、wave_errors空|対象navigate前の別ページDOMをevaluate。入力到達後の観測準備問題|
|詳細エラー|realistic_api /console/debug-error、Python Traceback、現在DOMは別ページ|既知Positive欠落、page-level tested、wave_errors空|_check_error_pageが対象URLを使わずpage.contentを読む。安全ページも古いエラーDOMで誤検知可能|

最小回帰は同じ realistic_api の詳細エラー/安全ツインを使い、現在DOMと対象応答を逆にした2ケース、およびtransport失敗を含む。詳細エラーの観測を共有 `_document_body(url)` へ変更し、非2xx本文を保持する。直接GETが失敗した際のcapture fallbackも、fragmentのみ除外したURL/query、GET、document種別、request/response identityを要求する。最新document要求がpending/POST/証拠不明なら古いGETへ戻らず、取得不能として未完了checkpointに残す。XHRや他queryは対象documentの証拠にしない。redirectはブラウザnativeのredirect元request identityで連鎖を証明でき、各hopが直接GETと同じ追従規則（same-host、承認済みupgrade、明示scope）を満たし、最終hopもGET documentの場合だけ辿る。連鎖を証明できないredirect、別ホストhop、POST hop、URL不一致の応答は取得不能とする。通常の直接GETの保護付きredirect処理は維持する。

共有raw取得は info_disclosure、SRI、secret_leak、clickjacking、security_headers、outdated_components が利用する。詳細エラーと技術ヘッダの再検証はキャッシュを使わず、BaseScannerのGETでブラウザnative Cookie jarとSet-Cookie同期、redirect保護を使う。機密資源/ディレクトリ検証のno-followは維持する。実ChromiumでHttpOnly Cookieをscan→詳細エラーverify→技術ヘッダverifyと更新し、後続の保護ページnavigationが認証済みで成功する回帰を含む。

純粋 `_classify_error_body` の署名、severity、重複排除ロジックは変更しない。一方、詳細エラーFindingのrequest/response証拠は対象GETのURL、status、headers、本文先頭2KBへ変わるため、「検出データ非改変」とは扱わない。document観測と再検証はGETを送信する。GETにも状態変更やone-time token消費はあり得るため、read-only検査という分類だけで副作用なしとは保証しない。

## 残存確認項目

- CSRFの対象DOM準備と動的フォームは確認済みFN・未修正であり、個別follow-upの起票/紐付けもpending。SessionのCookie観測時点/URL帰属は別の検証候補。単に全page scannerの前へnavigateを追加すると状態変更GET/flow状態を変えるため個別設計と回帰が必要。
- JSONのXSS/DOM-XSS/redirect/stored-XSS/mail-header、および汎用Header/Cookie/Path注入はcontract上の未接続領域。対応済みPositiveのFNと混同しない。
- healthcareの既知高難度gap（boolean SQLi、二重decode traversal、backslash redirect）と長時間full scan、large_vuln_appの全経路は第一パスで完了したと扱わない。
- passive scannerのtested/no-op行やfield互換no-opは実probeの証拠にならない。到達台帳・requestログ・ground truthを併せて確認する。

## 第一パスの実行結果（詳細エラー観測の変更時点）

- intranet 実エンジン: 3 tests / 9 subtests 成功。OS・SSRF・NoSQL・DOM-XSS の既知 Positive と安全ツインを確認。
- 既存 benchmark 実 E2E: SQLi・intranet injection・stored-XSS を除く9 tests成功。XSS、SSTI、traversal、redirect、header injection、LDAP、security headers、SRI、secret leak、clickjacking、JS static、CORS、host header、upload、JWT の manifest 採点を確認。
- API の既知 Positive: 修正前 7/9 → 修正後 8/9。詳細エラーを回復し、安全エラーツインには finding 無し。残る CSRF は未修正。
- API の到達キー (check,path,field,location): 161 → 161、捕捉要求 39 → 39。large fixture（page_count=4、全検査ルート保持）の到達キー 58 → 58、捕捉要求 202 → 202、.env Positive を維持。選択scannerはpage-onlyでpayloads.jsonlは両runとも無いが、largeにはengineのchain marker POSTが各1件ある。nonce値だけが変わり、同じsupport入力へ送達している。捕捉要求はブラウザ由来であり、追加のdocument GETと再検証を含む直接HTTP検査の全probe台帳ではない。これは指定fixtureの到達キー/ブラウザ捕捉件数の比較であり、実行probe総数や任意入力面の注入非回帰を保証しない。
- 最小回帰: 修正前は別DOMのPositive/安全ツイン/取得不能の3ケース失敗、追加の実エンジン回帰も失敗。修正後は対象URL本文を判定し、既存 artifact 回帰と実E2Eを含め45 tests / 2 subtests成功。取得不能前に得た資源findingも保持する回帰を追加。

## 共通ページ文脈の追加切り分け

|経路|状態|理由・次の確認|
|---|---|---|
|info_disclosure 詳細エラー|対象URL観測を修正・実再現済み|URL別document取得と純粋判定。fallback証拠の同一性とverify Cookie同期も回帰対象|
|csrf scan_page|修正済み（scan_page_context 化し crawl 済み page.html を解析。E2E 未確認）|動的フォームは crawl 時 DOM スナップショットに依存|
|session scan_page|観測時点/帰属の候補|全context cookieをURLfilter無しで取得し、cookie名で一度だけ報告。今回API Positiveは検出済みでありFN確定とはしない|
|js_static scan_page|API template fallback候補|通常attackはscan_page_contextでcrawl HTMLを使い保護済み。API passはscan_page直呼びで現在DOM fallbackが残る|
|info_disclosure 技術ヘッダ / CORS wildcard|capture依存の候補|current_page_pairが対象のcapture無しで空。CORS任意Origin反射は直接HTTPで検出済み。wildcard固有経路は別検証が必要|
|stored_xss scan_page|対象navigateあり|現在URL不一致時にnavigateしてからcontentを読む。単なる同型FNとは扱わない|
|sri / secret_leak|URL別document取得あり|既存共有取得経路を使用。今回の修正の参照パターン|
|race_condition scan_page|capture provenance候補|最後の要求bodyを取得しburstを組む。field経路のフォーム取得と区別した再現が必要|
|file_upload / mail_header / DOM-XSS|field経路|form/probeのnavigation後にDOMを読むため、page-levelの順序だけで同型バグと断定しない|
|WebSocket|専用message経路|evaluateはsocketを開くためのブラウザtransport。HTML判定ではない|

追跡した候補をすべて修正済みとは扱わない。「渡されたURLと実際の観測元が同一である保証の欠落」を詳細エラーと共有raw fallbackで修正したが、全page scannerの文脈保証を解決したものではない。実証済みFNと静的候補を分けて後続検証する。39カテゴリの宣言表は各カテゴリ/全carrierの実到達証明ではなく、全体の検知率受入やnightly成功もこの選択実行結果からは保証しない。

第一パス時点の非E2E: 3322 passed、34 skipped、455 subtests passed。比較基準は3319 passed、33 skipped、453 subtests passed。これは当時の実行結果であり、変更後の全suiteは上記コマンドで再検証する。
