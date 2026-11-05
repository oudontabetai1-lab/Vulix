# チェックリファレンス

この資料はカタログ情報と静的な capability 宣言を示します。宣言はチェックの実行、実行カバレッジ、検出の保証を示しません。

カタログ版: 1\.0\.0

## cache\_poisoning

**チェック:** CachePoisoningScanner

**分類:** file

**名前:**
キャッシュ応答の入力依存性

**概要:**
キャッシュ応答の入力依存性

**検査対象:**
応答を基準/変異リクエスト間で比較します。

**脆弱な場合のリスク:**
キャッシュ応答の入力依存性が悪用されると、機密情報の漏えい、データ改変、または利用者/サービスへの影響につながるおそれがあります。

**確認方法:**
専用プローブの応答をルール条件で評価し、条件に合う場合に所見を記録します。

**修正概要:**
該当する入力を検証し、安全なAPIや制限的な設定を適用します。

**制約:**
検査対象の入力・ページと観測できた応答の範囲に限られ、未検査や観測不能な経路の安全性は示しません。

**前提条件:**

- 宣言なし

**宣言された carrier と状態:**

- `cookie`: state=unsupported; reason=cache header/path probe 以外は注入しない
- `form`: state=unsupported; reason=cache header/path probe 以外は注入しない
- `graphql`: state=unsupported; reason=cache header/path probe 以外は注入しない
- `header`: state=supported; value_kinds=string; transports=httpx; payload_shapes=scalar
- `json`: state=unsupported; reason=cache header/path probe 以外は注入しない
- `multipart`: state=unsupported; reason=cache header/path probe 以外は注入しない
- `path`: state=supported; value_kinds=string; transports=httpx; payload_shapes=scalar
- `query`: state=unsupported; reason=cache header/path probe 以外は注入しない
- `websocket`: state=unsupported; reason=cache header/path probe 以外は注入しない
- `xml`: state=unsupported; reason=cache header/path probe 以外は注入しない

**参考資料:**

- OWASP Web Cache Security Cheat Sheet — `https://cheatsheetseries.owasp.org/cheatsheets/Web_Cache_Security_Cheat_Sheet.html`

## clickjacking

**チェック:** ClickjackingScanner

**分類:** file

**名前:**
ページのフレーム埋め込み制限

**概要:**
クリックジャッキング — X\-Frame\-Options が未設定

**検査対象:**
ページ応答のフレーミング関連ヘッダーを確認します。

**脆弱な場合のリスク:**
ページのフレーム埋め込み制限が悪用されると、機密情報の漏えい、データ改変、または利用者/サービスへの影響につながるおそれがあります。

**確認方法:**
取得したページ、応答、または照合結果を実装済みの判定条件と比較します。

**修正概要:**
該当する入力を検証し、安全なAPIや制限的な設定を適用します。

**制約:**
検査対象の入力・ページと観測できた応答の範囲に限られ、未検査や観測不能な経路の安全性は示しません。

**前提条件:**

- 宣言なし

**宣言された carrier と状態:**

- `cookie`: state=unsupported; reason=page/response 解析でありパラメータ注入をしない
- `form`: state=unsupported; reason=page/response 解析でありパラメータ注入をしない
- `graphql`: state=unsupported; reason=page/response 解析でありパラメータ注入をしない
- `header`: state=unsupported; reason=page/response 解析でありパラメータ注入をしない
- `json`: state=unsupported; reason=page/response 解析でありパラメータ注入をしない
- `multipart`: state=unsupported; reason=page/response 解析でありパラメータ注入をしない
- `path`: state=unsupported; reason=page/response 解析でありパラメータ注入をしない
- `query`: state=unsupported; reason=page/response 解析でありパラメータ注入をしない
- `websocket`: state=unsupported; reason=page/response 解析でありパラメータ注入をしない
- `xml`: state=unsupported; reason=page/response 解析でありパラメータ注入をしない

**参考資料:**

- CWE 1021\.html — `https://cwe.mitre.org/data/definitions/1021.html`

## cms

**チェック:** CmsScanner

**分類:** file

**名前:**
CMS識別情報と既知の公開パス

**概要:**
CMS 固有の脆弱性

**検査対象:**
CMS識別用のパスと応答を調べます。

**脆弱な場合のリスク:**
CMS識別情報と既知の公開パスが悪用されると、機密情報の漏えい、データ改変、または利用者/サービスへの影響につながるおそれがあります。

**確認方法:**
取得したページ、応答、または照合結果を実装済みの判定条件と比較します。

**修正概要:**
該当する入力を検証し、安全なAPIや制限的な設定を適用します。

**制約:**
検査対象の入力・ページと観測できた応答の範囲に限られ、未検査や観測不能な経路の安全性は示しません。

**前提条件:**

- 宣言なし

**宣言された carrier と状態:**

- `cookie`: state=unsupported; reason=page/response 解析でありパラメータ注入をしない
- `form`: state=unsupported; reason=page/response 解析でありパラメータ注入をしない
- `graphql`: state=unsupported; reason=page/response 解析でありパラメータ注入をしない
- `header`: state=unsupported; reason=page/response 解析でありパラメータ注入をしない
- `json`: state=unsupported; reason=page/response 解析でありパラメータ注入をしない
- `multipart`: state=unsupported; reason=page/response 解析でありパラメータ注入をしない
- `path`: state=supported; value_kinds=string; transports=httpx; payload_shapes=scalar
- `query`: state=unsupported; reason=page/response 解析でありパラメータ注入をしない
- `websocket`: state=unsupported; reason=page/response 解析でありパラメータ注入をしない
- `xml`: state=unsupported; reason=page/response 解析でありパラメータ注入をしない

**参考資料:**

- CWE 200\.html — `https://cwe.mitre.org/data/definitions/200.html`

## cors

**チェック:** CORSScanner

**分類:** proto

**名前:**
CORS応答ヘッダーとオリジン許可

**概要:**
CORSの誤設定 — 任意オリジンからのクロスオリジンリクエストが可能

**検査対象:**
異なるOriginを用いた応答ヘッダーを確認します。

**脆弱な場合のリスク:**
CORS応答ヘッダーとオリジン許可が悪用されると、機密情報の漏えい、データ改変、または利用者/サービスへの影響につながるおそれがあります。

**確認方法:**
専用プローブの応答をルール条件で評価し、条件に合う場合に所見を記録します。

**修正概要:**
該当する入力を検証し、安全なAPIや制限的な設定を適用します。

**制約:**
検査対象の入力・ページと観測できた応答の範囲に限られ、未検査や観測不能な経路の安全性は示しません。

**前提条件:**

- 宣言なし

**宣言された carrier と状態:**

- `cookie`: state=unsupported; reason=page/response 解析でありパラメータ注入をしない
- `form`: state=unsupported; reason=page/response 解析でありパラメータ注入をしない
- `graphql`: state=unsupported; reason=page/response 解析でありパラメータ注入をしない
- `header`: state=supported; value_kinds=string; transports=httpx; payload_shapes=scalar
- `json`: state=unsupported; reason=page/response 解析でありパラメータ注入をしない
- `multipart`: state=unsupported; reason=page/response 解析でありパラメータ注入をしない
- `path`: state=unsupported; reason=page/response 解析でありパラメータ注入をしない
- `query`: state=unsupported; reason=page/response 解析でありパラメータ注入をしない
- `websocket`: state=unsupported; reason=page/response 解析でありパラメータ注入をしない
- `xml`: state=unsupported; reason=page/response 解析でありパラメータ注入をしない

**参考資料:**

- OWASP WSTG\-CLNT\-07 — `https://wstg.owasp.org/latest/4-Web_Application_Security_Testing/11-Client-side/07-Cross_Origin_Resource_Sharing/`

## csrf

**チェック:** CSRFScanner

**分類:** access

**名前:**
状態変更リクエストに対するCSRF対策

**概要:**
CSRF — 正規ユーザーに意図しないリクエストを送信させられる

**検査対象:**
ページ上のフォームと応答を解析します。

**脆弱な場合のリスク:**
状態変更リクエストに対するCSRF対策が悪用されると、機密情報の漏えい、データ改変、または利用者/サービスへの影響につながるおそれがあります。

**確認方法:**
取得したページ、応答、または照合結果を実装済みの判定条件と比較します。

**修正概要:**
状態変更要求に予測困難なCSRFトークンを要求し、Origin等を検証します。

**制約:**
検査対象の入力・ページと観測できた応答の範囲に限られ、未検査や観測不能な経路の安全性は示しません。

**前提条件:**

- `browser`

**宣言された carrier と状態:**

- `cookie`: state=unsupported; reason=page/response 解析でありパラメータ注入をしない
- `form`: state=unsupported; reason=page/response 解析でありパラメータ注入をしない
- `graphql`: state=unsupported; reason=page/response 解析でありパラメータ注入をしない
- `header`: state=unsupported; reason=page/response 解析でありパラメータ注入をしない
- `json`: state=unsupported; reason=page/response 解析でありパラメータ注入をしない
- `multipart`: state=unsupported; reason=page/response 解析でありパラメータ注入をしない
- `path`: state=unsupported; reason=page/response 解析でありパラメータ注入をしない
- `query`: state=unsupported; reason=page/response 解析でありパラメータ注入をしない
- `websocket`: state=unsupported; reason=page/response 解析でありパラメータ注入をしない
- `xml`: state=unsupported; reason=page/response 解析でありパラメータ注入をしない

**参考資料:**

- CWE 352\.html — `https://cwe.mitre.org/data/definitions/352.html`

## deserialization

**チェック:** DeserializationScanner

**分類:** injection

**名前:**
シリアライズ形式を含む入力の処理

**概要:**
安全でないデシリアライゼーション

**検査対象:**
シリアライズ形式を含む入力の処理を確認する専用入力を送信し、応答の内容や挙動を調べます。

**脆弱な場合のリスク:**
シリアライズ形式を含む入力の処理が悪用されると、機密情報の漏えい、データ改変、または利用者/サービスへの影響につながるおそれがあります。

**確認方法:**
専用プローブの応答をルール条件で評価し、条件に合う場合に所見を記録します。

**修正概要:**
該当する入力を検証し、安全なAPIや制限的な設定を適用します。

**制約:**
検査対象の入力・ページと観測できた応答の範囲に限られ、未検査や観測不能な経路の安全性は示しません。

**前提条件:**

- 宣言なし

**宣言された carrier と状態:**

- `cookie`: state=planned; reason=carrier 別 dispatcher は未接続
- `form`: state=supported; value_kinds=string; transports=playwright; payload_shapes=scalar; browser_required=true
- `graphql`: state=planned; reason=carrier 別 dispatcher は未接続
- `header`: state=planned; reason=carrier 別 dispatcher は未接続
- `json`: state=supported; value_kinds=string; transports=httpx; payload_shapes=scalar
- `multipart`: state=planned; reason=carrier 別 dispatcher は未接続
- `path`: state=planned; reason=carrier 別 dispatcher は未接続
- `query`: state=supported; value_kinds=string; transports=playwright; payload_shapes=scalar; browser_required=true
- `websocket`: state=planned; reason=carrier 別 dispatcher は未接続
- `xml`: state=planned; reason=carrier 別 dispatcher は未接続

**参考資料:**

- CWE 502\.html — `https://cwe.mitre.org/data/definitions/502.html`

## directory\_artifacts

**チェック:** DirectoryArtifactsScanner

**分類:** proto

**名前:**
公開ディレクトリ内の既知アーティファクト

**概要:**
公開ディレクトリ内の既知アーティファクト

**検査対象:**
ページ資源から候補を集め、公開パスへ読み取り要求を行います。

**脆弱な場合のリスク:**
公開ディレクトリ内の既知アーティファクトが悪用されると、機密情報の漏えい、データ改変、または利用者/サービスへの影響につながるおそれがあります。

**確認方法:**
専用プローブの応答をルール条件で評価し、条件に合う場合に所見を記録します。

**修正概要:**
該当する入力を検証し、安全なAPIや制限的な設定を適用します。

**制約:**
候補パスの上限と対象スコープにより全ファイルを網羅しません。

**前提条件:**

- 宣言なし

**宣言された carrier と状態:**

- `cookie`: state=unsupported; reason=観測リソース由来の read\-only GET 検査でパラメータ注入をしない
- `form`: state=unsupported; reason=観測リソース由来の read\-only GET 検査でパラメータ注入をしない
- `graphql`: state=unsupported; reason=観測リソース由来の read\-only GET 検査でパラメータ注入をしない
- `header`: state=unsupported; reason=観測リソース由来の read\-only GET 検査でパラメータ注入をしない
- `json`: state=unsupported; reason=観測リソース由来の read\-only GET 検査でパラメータ注入をしない
- `multipart`: state=unsupported; reason=観測リソース由来の read\-only GET 検査でパラメータ注入をしない
- `path`: state=supported; value_kinds=string; transports=httpx; payload_shapes=scalar
- `query`: state=unsupported; reason=観測リソース由来の read\-only GET 検査でパラメータ注入をしない
- `websocket`: state=unsupported; reason=観測リソース由来の read\-only GET 検査でパラメータ注入をしない
- `xml`: state=unsupported; reason=観測リソース由来の read\-only GET 検査でパラメータ注入をしない

**参考資料:**

- OWASP WSTG\-CONF\-04 — `https://wstg.owasp.org/latest/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management/04-Review_Old_Backup_and_Unreferenced_Files_for_Sensitive_Information/`

## dom\_xss

**チェック:** DOMXSSScanner

**分類:** xss

**名前:**
DOM操作を介したクロスサイトスクリプティング

**概要:**
DOM\-based XSS — クライアントサイドの DOM 操作による XSS

**検査対象:**
DOM操作を介したクロスサイトスクリプティングを確認する専用入力を送信し、応答の内容や挙動を調べます。

**脆弱な場合のリスク:**
DOM操作を介したクロスサイトスクリプティングが悪用されると、機密情報の漏えい、データ改変、または利用者/サービスへの影響につながるおそれがあります。

**確認方法:**
専用プローブの応答をルール条件で評価し、条件に合う場合に所見を記録します。

**修正概要:**
該当する入力を検証し、安全なAPIや制限的な設定を適用します。

**制約:**
検査対象の入力・ページと観測できた応答の範囲に限られ、未検査や観測不能な経路の安全性は示しません。

**前提条件:**

- 宣言なし

**宣言された carrier と状態:**

- `cookie`: state=planned; reason=DOM XSS の carrier 別 dispatcher は未接続
- `form`: state=supported; value_kinds=string; transports=dom,playwright; payload_shapes=scalar; browser_required=true
- `graphql`: state=planned; reason=DOM XSS の carrier 別 dispatcher は未接続
- `header`: state=planned; reason=DOM XSS の carrier 別 dispatcher は未接続
- `json`: state=planned; reason=DOM 実行を伴う JSON body 経路は未接続
- `multipart`: state=planned; reason=DOM XSS の carrier 別 dispatcher は未接続
- `path`: state=planned; reason=DOM XSS の carrier 別 dispatcher は未接続
- `query`: state=supported; value_kinds=string; transports=dom,playwright; payload_shapes=scalar; browser_required=true
- `websocket`: state=planned; reason=DOM XSS の carrier 別 dispatcher は未接続
- `xml`: state=planned; reason=DOM XSS の carrier 別 dispatcher は未接続

**参考資料:**

- CWE 79\.html — `https://cwe.mitre.org/data/definitions/79.html`

## file\_upload

**チェック:** FileUploadScanner

**分類:** file

**名前:**
アップロードファイルの受理と応答

**概要:**
安全でないファイルアップロード

**検査対象:**
アップロードファイルの受理と応答を確認する専用入力を送信し、応答の内容や挙動を調べます。

**脆弱な場合のリスク:**
アップロードファイルの受理と応答が悪用されると、機密情報の漏えい、データ改変、または利用者/サービスへの影響につながるおそれがあります。

**確認方法:**
専用プローブの応答をルール条件で評価し、条件に合う場合に所見を記録します。

**修正概要:**
該当する入力を検証し、安全なAPIや制限的な設定を適用します。

**制約:**
検査対象の入力・ページと観測できた応答の範囲に限られ、未検査や観測不能な経路の安全性は示しません。

**前提条件:**

- 宣言なし

**宣言された carrier と状態:**

- `cookie`: state=unsupported; reason=file upload は multipart 特化
- `form`: state=unsupported; reason=file upload は multipart 特化
- `graphql`: state=unsupported; reason=file upload は multipart 特化
- `header`: state=unsupported; reason=file upload は multipart 特化
- `json`: state=unsupported; reason=file upload は multipart 特化
- `multipart`: state=supported; value_kinds=binary,string; transports=httpx,playwright; payload_shapes=binary; browser_required=true
- `path`: state=unsupported; reason=file upload は multipart 特化
- `query`: state=unsupported; reason=file upload は multipart 特化
- `websocket`: state=unsupported; reason=file upload は multipart 特化
- `xml`: state=unsupported; reason=file upload は multipart 特化

**参考資料:**

- CWE 434\.html — `https://cwe.mitre.org/data/definitions/434.html`

## graphql

**チェック:** GraphQLScanner

**分類:** injection

**名前:**
GraphQLエンドポイントの設定と応答

**概要:**
GraphQL の脆弱性 \(イントロスペクション有効・インジェクションなど\)

**検査対象:**
GraphQLのエンドポイント、クエリ応答、設定を調べます。

**脆弱な場合のリスク:**
GraphQLエンドポイントの設定と応答が悪用されると、機密情報の漏えい、データ改変、または利用者/サービスへの影響につながるおそれがあります。

**確認方法:**
専用プローブの応答をルール条件で評価し、条件に合う場合に所見を記録します。

**修正概要:**
該当する入力を検証し、安全なAPIや制限的な設定を適用します。

**制約:**
検出可能なGraphQL経路と応答の範囲に限られます。

**前提条件:**

- 宣言なし

**宣言された carrier と状態:**

- `cookie`: state=unsupported; reason=GraphQL endpoint 特化
- `form`: state=unsupported; reason=GraphQL endpoint 特化
- `graphql`: state=supported; value_kinds=array,object,string; transports=httpx; payload_shapes=structured; structured_payload=true
- `header`: state=unsupported; reason=GraphQL endpoint 特化
- `json`: state=unsupported; reason=query/variables は graphql carrier で表現。transport は JSON だが汎用 JSON body 値注入ではない
- `multipart`: state=unsupported; reason=GraphQL endpoint 特化
- `path`: state=unsupported; reason=既知の候補パス探索は endpoint 検出のみで findings を生まない。path carrier への注入検査ではない
- `query`: state=unsupported; reason=注入対象は GraphQL operation/variables＝graphql carrier で表現。URL query へは注入しない
- `websocket`: state=unsupported; reason=GraphQL endpoint 特化
- `xml`: state=unsupported; reason=GraphQL endpoint 特化

**参考資料:**

- 宣言なし

## header\_injection

**チェック:** HeaderInjectionScanner

**分類:** header

**名前:**
入力値によるHTTPレスポンスヘッダーの改変

**概要:**
HTTPヘッダ・インジェクション / レスポンス分割

**検査対象:**
入力値によるHTTPレスポンスヘッダーの改変を確認する専用入力を送信し、応答の内容や挙動を調べます。

**脆弱な場合のリスク:**
入力値によるHTTPレスポンスヘッダーの改変が悪用されると、機密情報の漏えい、データ改変、または利用者/サービスへの影響につながるおそれがあります。

**確認方法:**
専用プローブの応答をルール条件で評価し、条件に合う場合に所見を記録します。

**修正概要:**
該当する入力を検証し、安全なAPIや制限的な設定を適用します。

**制約:**
検査対象の入力・ページと観測できた応答の範囲に限られ、未検査や観測不能な経路の安全性は示しません。

**前提条件:**

- 宣言なし

**宣言された carrier と状態:**

- `cookie`: state=planned; reason=carrier 別 dispatcher は未接続
- `form`: state=supported; value_kinds=string; transports=playwright; payload_shapes=scalar; browser_required=true
- `graphql`: state=planned; reason=carrier 別 dispatcher は未接続
- `header`: state=planned; reason=carrier 別 dispatcher は未接続
- `json`: state=supported; value_kinds=string; transports=httpx; payload_shapes=scalar
- `multipart`: state=planned; reason=carrier 別 dispatcher は未接続
- `path`: state=planned; reason=carrier 別 dispatcher は未接続
- `query`: state=supported; value_kinds=string; transports=playwright; payload_shapes=scalar; browser_required=true
- `websocket`: state=planned; reason=carrier 別 dispatcher は未接続
- `xml`: state=planned; reason=carrier 別 dispatcher は未接続

**参考資料:**

- CWE 113\.html — `https://cwe.mitre.org/data/definitions/113.html`

## host\_header

**チェック:** HostHeaderScanner

**分類:** header

**名前:**
Host関連ヘッダーの処理

**概要:**
Hostヘッダ・インジェクション

**検査対象:**
Host関連ヘッダーを変えた応答を比較します。

**脆弱な場合のリスク:**
Host関連ヘッダーの処理が悪用されると、機密情報の漏えい、データ改変、または利用者/サービスへの影響につながるおそれがあります。

**確認方法:**
専用プローブの応答をルール条件で評価し、条件に合う場合に所見を記録します。

**修正概要:**
該当する入力を検証し、安全なAPIや制限的な設定を適用します。

**制約:**
検査対象の入力・ページと観測できた応答の範囲に限られ、未検査や観測不能な経路の安全性は示しません。

**前提条件:**

- 宣言なし

**宣言された carrier と状態:**

- `cookie`: state=unsupported; reason=Host header 注入特化
- `form`: state=unsupported; reason=Host header 注入特化
- `graphql`: state=unsupported; reason=Host header 注入特化
- `header`: state=supported; value_kinds=string; transports=httpx; payload_shapes=scalar
- `json`: state=unsupported; reason=Host header 注入特化
- `multipart`: state=unsupported; reason=Host header 注入特化
- `path`: state=unsupported; reason=Host header 注入特化
- `query`: state=unsupported; reason=Host header 注入特化
- `websocket`: state=unsupported; reason=Host header 注入特化
- `xml`: state=unsupported; reason=Host header 注入特化

**参考資料:**

- OWASP WSTG\-INJT\-17 — `https://wstg.owasp.org/latest/4-Web_Application_Security_Testing/07-Injection/17-Host_Header_Injection/`

## http\_methods

**チェック:** HttpMethodsScanner

**分類:** proto

**名前:**
対象オリジンが応答するHTTPメソッド

**概要:**
対象オリジンが応答するHTTPメソッド

**検査対象:**
OPTIONS等のメソッド要求を対象オリジンへ送信します。

**脆弱な場合のリスク:**
対象オリジンが応答するHTTPメソッドが悪用されると、機密情報の漏えい、データ改変、または利用者/サービスへの影響につながるおそれがあります。

**確認方法:**
取得したページ、応答、または照合結果を実装済みの判定条件と比較します。

**修正概要:**
該当する入力を検証し、安全なAPIや制限的な設定を適用します。

**制約:**
検査対象の入力・ページと観測できた応答の範囲に限られ、未検査や観測不能な経路の安全性は示しません。

**前提条件:**

- 宣言なし

**宣言された carrier と状態:**

- `cookie`: state=unsupported; reason=オリジンの HTTP メソッド設定を観測しパラメータ注入をしない
- `form`: state=unsupported; reason=オリジンの HTTP メソッド設定を観測しパラメータ注入をしない
- `graphql`: state=unsupported; reason=オリジンの HTTP メソッド設定を観測しパラメータ注入をしない
- `header`: state=unsupported; reason=オリジンの HTTP メソッド設定を観測しパラメータ注入をしない
- `json`: state=unsupported; reason=オリジンの HTTP メソッド設定を観測しパラメータ注入をしない
- `multipart`: state=unsupported; reason=オリジンの HTTP メソッド設定を観測しパラメータ注入をしない
- `path`: state=unsupported; reason=オリジンの HTTP メソッド設定を観測しパラメータ注入をしない
- `query`: state=unsupported; reason=オリジンの HTTP メソッド設定を観測しパラメータ注入をしない
- `websocket`: state=unsupported; reason=オリジンの HTTP メソッド設定を観測しパラメータ注入をしない
- `xml`: state=unsupported; reason=オリジンの HTTP メソッド設定を観測しパラメータ注入をしない

**参考資料:**

- 宣言なし

## info\_disclosure

**チェック:** InfoDisclosureScanner

**分類:** proto

**名前:**
応答や公開パスから得られる情報

**概要:**
情報漏洩 — エラーメッセージ・バージョン情報など

**検査対象:**
応答内容と候補パスの応答を調べます。

**脆弱な場合のリスク:**
応答や公開パスから得られる情報が悪用されると、機密情報の漏えい、データ改変、または利用者/サービスへの影響につながるおそれがあります。

**確認方法:**
専用プローブの応答をルール条件で評価し、条件に合う場合に所見を記録します。

**修正概要:**
該当する入力を検証し、安全なAPIや制限的な設定を適用します。

**制約:**
検査対象の入力・ページと観測できた応答の範囲に限られ、未検査や観測不能な経路の安全性は示しません。

**前提条件:**

- 宣言なし

**宣言された carrier と状態:**

- `cookie`: state=unsupported; reason=page/response 解析でありパラメータ注入をしない
- `form`: state=unsupported; reason=page/response 解析でありパラメータ注入をしない
- `graphql`: state=unsupported; reason=page/response 解析でありパラメータ注入をしない
- `header`: state=unsupported; reason=page/response 解析でありパラメータ注入をしない
- `json`: state=unsupported; reason=page/response 解析でありパラメータ注入をしない
- `multipart`: state=unsupported; reason=page/response 解析でありパラメータ注入をしない
- `path`: state=supported; value_kinds=string; transports=httpx; payload_shapes=scalar
- `query`: state=unsupported; reason=page/response 解析でありパラメータ注入をしない
- `websocket`: state=unsupported; reason=page/response 解析でありパラメータ注入をしない
- `xml`: state=unsupported; reason=page/response 解析でありパラメータ注入をしない

**参考資料:**

- CWE 200\.html — `https://cwe.mitre.org/data/definitions/200.html`

## js\_static

**チェック:** JsStaticScanner

**分類:** xss

**名前:**
取得可能なJavaScript内の静的所見

**概要:**
取得可能なJavaScript内の静的所見

**検査対象:**
取得したJavaScript資源を静的ルールで解析します。

**脆弱な場合のリスク:**
取得可能なJavaScript内の静的所見が悪用されると、機密情報の漏えい、データ改変、または利用者/サービスへの影響につながるおそれがあります。

**確認方法:**
取得したページ、応答、または照合結果を実装済みの判定条件と比較します。

**修正概要:**
該当する入力を検証し、安全なAPIや制限的な設定を適用します。

**制約:**
検査対象の入力・ページと観測できた応答の範囲に限られ、未検査や観測不能な経路の安全性は示しません。

**前提条件:**

- 宣言なし

**宣言された carrier と状態:**

- `cookie`: state=unsupported; reason=page/response 解析でありパラメータ注入をしない
- `form`: state=unsupported; reason=page/response 解析でありパラメータ注入をしない
- `graphql`: state=unsupported; reason=page/response 解析でありパラメータ注入をしない
- `header`: state=unsupported; reason=page/response 解析でありパラメータ注入をしない
- `json`: state=unsupported; reason=page/response 解析でありパラメータ注入をしない
- `multipart`: state=unsupported; reason=page/response 解析でありパラメータ注入をしない
- `path`: state=unsupported; reason=page/response 解析でありパラメータ注入をしない
- `query`: state=unsupported; reason=page/response 解析でありパラメータ注入をしない
- `websocket`: state=unsupported; reason=page/response 解析でありパラメータ注入をしない
- `xml`: state=unsupported; reason=page/response 解析でありパラメータ注入をしない

**参考資料:**

- CWE 79\.html — `https://cwe.mitre.org/data/definitions/79.html`

## jwt

**チェック:** JWTScanner

**分類:** proto

**名前:**
ページ内のJWTとトークン検証上の問題

**概要:**
JWT の脆弱性 \(alg=none・弱い秘密鍵など\)

**検査対象:**
取得ページに含まれるJWTを解析します。

**脆弱な場合のリスク:**
ページ内のJWTとトークン検証上の問題が悪用されると、機密情報の漏えい、データ改変、または利用者/サービスへの影響につながるおそれがあります。

**確認方法:**
取得したページ、応答、または照合結果を実装済みの判定条件と比較します。

**修正概要:**
該当する入力を検証し、安全なAPIや制限的な設定を適用します。

**制約:**
検査対象の入力・ページと観測できた応答の範囲に限られ、未検査や観測不能な経路の安全性は示しません。

**前提条件:**

- 宣言なし

**宣言された carrier と状態:**

- `cookie`: state=supported; value_kinds=string; transports=httpx; payload_shapes=scalar
- `form`: state=unsupported; reason=page/response 解析でありパラメータ注入をしない
- `graphql`: state=unsupported; reason=page/response 解析でありパラメータ注入をしない
- `header`: state=supported; value_kinds=string; transports=httpx; payload_shapes=scalar
- `json`: state=unsupported; reason=page/response 解析でありパラメータ注入をしない
- `multipart`: state=unsupported; reason=page/response 解析でありパラメータ注入をしない
- `path`: state=unsupported; reason=page/response 解析でありパラメータ注入をしない
- `query`: state=unsupported; reason=page/response 解析でありパラメータ注入をしない
- `websocket`: state=unsupported; reason=page/response 解析でありパラメータ注入をしない
- `xml`: state=unsupported; reason=page/response 解析でありパラメータ注入をしない

**参考資料:**

- 宣言なし

## ldap

**チェック:** LDAPScanner

**分類:** injection

**名前:**
LDAP検索入力の解釈

**概要:**
LDAPインジェクション

**検査対象:**
LDAP検索入力の解釈を確認する専用入力を送信し、応答の内容や挙動を調べます。

**脆弱な場合のリスク:**
LDAP検索入力の解釈が悪用されると、機密情報の漏えい、データ改変、または利用者/サービスへの影響につながるおそれがあります。

**確認方法:**
専用プローブの応答をルール条件で評価し、条件に合う場合に所見を記録します。

**修正概要:**
該当する入力を検証し、安全なAPIや制限的な設定を適用します。

**制約:**
検査対象の入力・ページと観測できた応答の範囲に限られ、未検査や観測不能な経路の安全性は示しません。

**前提条件:**

- 宣言なし

**宣言された carrier と状態:**

- `cookie`: state=planned; reason=carrier 別 dispatcher は未接続
- `form`: state=supported; value_kinds=string; transports=playwright; payload_shapes=scalar; browser_required=true
- `graphql`: state=planned; reason=carrier 別 dispatcher は未接続
- `header`: state=planned; reason=carrier 別 dispatcher は未接続
- `json`: state=supported; value_kinds=string; transports=httpx; payload_shapes=scalar
- `multipart`: state=planned; reason=carrier 別 dispatcher は未接続
- `path`: state=planned; reason=carrier 別 dispatcher は未接続
- `query`: state=supported; value_kinds=string; transports=playwright; payload_shapes=scalar; browser_required=true
- `websocket`: state=planned; reason=carrier 別 dispatcher は未接続
- `xml`: state=planned; reason=carrier 別 dispatcher は未接続

**参考資料:**

- CWE 90\.html — `https://cwe.mitre.org/data/definitions/90.html`

## mail\_header

**チェック:** MailHeaderInjectionScanner

**分類:** header

**名前:**
メール関連入力のヘッダー注入

**概要:**
メールヘッダ・インジェクション

**検査対象:**
メール関連入力のヘッダー注入を確認する専用入力を送信し、応答の内容や挙動を調べます。

**脆弱な場合のリスク:**
メール関連入力のヘッダー注入が悪用されると、機密情報の漏えい、データ改変、または利用者/サービスへの影響につながるおそれがあります。

**確認方法:**
専用プローブの応答をルール条件で評価し、条件に合う場合に所見を記録します。

**修正概要:**
該当する入力を検証し、安全なAPIや制限的な設定を適用します。

**制約:**
OOB確認には対応する外部受信先が必要です。

**前提条件:**

- 宣言なし

**宣言された carrier と状態:**

- `cookie`: state=planned; reason=mail header injection の carrier 別 dispatcher は未接続
- `form`: state=supported; value_kinds=string; transports=httpx,oob,playwright; payload_shapes=scalar; browser_required=true
- `graphql`: state=planned; reason=mail header injection の carrier 別 dispatcher は未接続
- `header`: state=planned; reason=mail header injection の carrier 別 dispatcher は未接続
- `json`: state=planned; reason=JSON body の検出は未対応
- `multipart`: state=supported; value_kinds=string; transports=httpx,oob,playwright; payload_shapes=scalar; browser_required=true
- `path`: state=planned; reason=mail header injection の carrier 別 dispatcher は未接続
- `query`: state=supported; value_kinds=string; transports=httpx,oob; payload_shapes=scalar
- `websocket`: state=planned; reason=mail header injection の carrier 別 dispatcher は未接続
- `xml`: state=planned; reason=mail header injection の carrier 別 dispatcher は未接続

**参考資料:**

- CWE 93\.html — `https://cwe.mitre.org/data/definitions/93.html`

## mass\_assignment

**チェック:** MassAssignmentScanner

**分類:** injection

**名前:**
API JSON入力の許可外プロパティ受理

**概要:**
API JSON入力の許可外プロパティ受理

**検査対象:**
API仕様由来のJSON要求で追加プロパティの扱いを調べます。

**脆弱な場合のリスク:**
API JSON入力の許可外プロパティ受理が悪用されると、機密情報の漏えい、データ改変、または利用者/サービスへの影響につながるおそれがあります。

**確認方法:**
専用プローブの応答をルール条件で評価し、条件に合う場合に所見を記録します。

**修正概要:**
該当する入力を検証し、安全なAPIや制限的な設定を適用します。

**制約:**
検査対象の入力・ページと観測できた応答の範囲に限られ、未検査や観測不能な経路の安全性は示しません。

**前提条件:**

- `api_spec`

**宣言された carrier と状態:**

- `cookie`: state=unsupported; reason=API spec 由来 JSON body 特化
- `form`: state=unsupported; reason=API spec 由来 JSON body 特化
- `graphql`: state=unsupported; reason=API spec 由来 JSON body 特化
- `header`: state=unsupported; reason=API spec 由来 JSON body 特化
- `json`: state=supported; value_kinds=object; transports=httpx; payload_shapes=structured; structured_payload=true
- `multipart`: state=unsupported; reason=API spec 由来 JSON body 特化
- `path`: state=unsupported; reason=API spec 由来 JSON body 特化
- `query`: state=unsupported; reason=API spec 由来 JSON body 特化
- `websocket`: state=unsupported; reason=API spec 由来 JSON body 特化
- `xml`: state=unsupported; reason=API spec 由来 JSON body 特化

**参考資料:**

- 宣言なし

## nosql

**チェック:** NoSQLInjectionScanner

**分類:** injection

**名前:**
NoSQLクエリへの入力解釈

**概要:**
NoSQLインジェクション

**検査対象:**
NoSQLクエリへの入力解釈を確認する専用入力を送信し、応答の内容や挙動を調べます。

**脆弱な場合のリスク:**
NoSQLクエリへの入力解釈が悪用されると、機密情報の漏えい、データ改変、または利用者/サービスへの影響につながるおそれがあります。

**確認方法:**
専用プローブの応答をルール条件で評価し、条件に合う場合に所見を記録します。

**修正概要:**
該当する入力を検証し、安全なAPIや制限的な設定を適用します。

**制約:**
検査対象の入力・ページと観測できた応答の範囲に限られ、未検査や観測不能な経路の安全性は示しません。

**前提条件:**

- 宣言なし

**宣言された carrier と状態:**

- `cookie`: state=planned; reason=carrier 別 dispatcher は未接続
- `form`: state=supported; value_kinds=string; transports=playwright; payload_shapes=scalar; browser_required=true
- `graphql`: state=planned; reason=carrier 別 dispatcher は未接続
- `header`: state=planned; reason=carrier 別 dispatcher は未接続
- `json`: state=supported; value_kinds=object; transports=httpx; payload_shapes=structured; structured_payload=true
- `multipart`: state=planned; reason=carrier 別 dispatcher は未接続
- `path`: state=planned; reason=carrier 別 dispatcher は未接続
- `query`: state=supported; value_kinds=string; transports=playwright; payload_shapes=scalar; browser_required=true
- `websocket`: state=planned; reason=carrier 別 dispatcher は未接続
- `xml`: state=planned; reason=carrier 別 dispatcher は未接続

**参考資料:**

- CWE 943\.html — `https://cwe.mitre.org/data/definitions/943.html`

## open\_redirect

**チェック:** OpenRedirectScanner

**分類:** header

**名前:**
入力値を利用した外部リダイレクト

**概要:**
オープンリダイレクト — 任意URLへのリダイレクトが可能

**検査対象:**
入力値を利用した外部リダイレクトを確認する専用入力を送信し、応答の内容や挙動を調べます。

**脆弱な場合のリスク:**
入力値を利用した外部リダイレクトが悪用されると、機密情報の漏えい、データ改変、または利用者/サービスへの影響につながるおそれがあります。

**確認方法:**
専用プローブの応答をルール条件で評価し、条件に合う場合に所見を記録します。

**修正概要:**
遷移先をサーバー側で管理するか、許可リストで検証します。

**制約:**
検査対象の入力・ページと観測できた応答の範囲に限られ、未検査や観測不能な経路の安全性は示しません。

**前提条件:**

- 宣言なし

**宣言された carrier と状態:**

- `cookie`: state=unsupported; reason=redirect param 特化
- `form`: state=supported; value_kinds=string; transports=playwright; payload_shapes=scalar; browser_required=true
- `graphql`: state=unsupported; reason=redirect param 特化
- `header`: state=unsupported; reason=redirect param 特化
- `json`: state=planned; reason=JSON body の検出は未対応
- `multipart`: state=unsupported; reason=redirect param 特化
- `path`: state=unsupported; reason=redirect param 特化
- `query`: state=supported; value_kinds=string; transports=playwright; payload_shapes=scalar; browser_required=true
- `websocket`: state=unsupported; reason=redirect param 特化
- `xml`: state=unsupported; reason=redirect param 特化

**参考資料:**

- CWE 601\.html — `https://cwe.mitre.org/data/definitions/601.html`

## os

**チェック:** OSInjectionScanner

**分類:** injection

**名前:**
OSコマンドインジェクション

**概要:**
OSコマンド・インジェクション — サーバー上のOSコマンドが実行される

**検査対象:**
OSコマンドインジェクションを確認する専用入力を送信し、応答の内容や挙動を調べます。

**脆弱な場合のリスク:**
OSコマンドインジェクションが悪用されると、機密情報の漏えい、データ改変、または利用者/サービスへの影響につながるおそれがあります。

**確認方法:**
専用プローブの応答をルール条件で評価し、条件に合う場合に所見を記録します。

**修正概要:**
該当する入力を検証し、安全なAPIや制限的な設定を適用します。

**制約:**
検査対象の入力・ページと観測できた応答の範囲に限られ、未検査や観測不能な経路の安全性は示しません。

**前提条件:**

- 宣言なし

**宣言された carrier と状態:**

- `cookie`: state=planned; reason=carrier 別 dispatcher は未接続
- `form`: state=supported; value_kinds=string; transports=playwright; payload_shapes=scalar; browser_required=true
- `graphql`: state=planned; reason=carrier 別 dispatcher は未接続
- `header`: state=planned; reason=carrier 別 dispatcher は未接続
- `json`: state=supported; value_kinds=string; transports=httpx; payload_shapes=scalar
- `multipart`: state=planned; reason=carrier 別 dispatcher は未接続
- `path`: state=planned; reason=carrier 別 dispatcher は未接続
- `query`: state=supported; value_kinds=string; transports=playwright; payload_shapes=scalar; browser_required=true
- `websocket`: state=planned; reason=carrier 別 dispatcher は未接続
- `xml`: state=planned; reason=carrier 別 dispatcher は未接続

**参考資料:**

- CWE 78\.html — `https://cwe.mitre.org/data/definitions/78.html`

## outdated\_components

**チェック:** OutdatedComponentScanner

**分類:** file

**名前:**
検出したコンポーネントの既知情報

**概要:**
検出したコンポーネントの既知情報

**検査対象:**
ページのバナー/資源から識別した版を脆弱性情報源と照合します。

**脆弱な場合のリスク:**
検出したコンポーネントの既知情報が悪用されると、機密情報の漏えい、データ改変、または利用者/サービスへの影響につながるおそれがあります。

**確認方法:**
取得したページ、応答、または照合結果を実装済みの判定条件と比較します。

**修正概要:**
該当する入力を検証し、安全なAPIや制限的な設定を適用します。

**制約:**
版を識別できない資源や外部照会の失敗は判定できません。

**前提条件:**

- 宣言なし

**宣言された carrier と状態:**

- `cookie`: state=unsupported; reason=レスポンスバナー解析でありパラメータ注入をしない
- `form`: state=unsupported; reason=レスポンスバナー解析でありパラメータ注入をしない
- `graphql`: state=unsupported; reason=レスポンスバナー解析でありパラメータ注入をしない
- `header`: state=unsupported; reason=レスポンスバナー解析でありパラメータ注入をしない
- `json`: state=unsupported; reason=レスポンスバナー解析でありパラメータ注入をしない
- `multipart`: state=unsupported; reason=レスポンスバナー解析でありパラメータ注入をしない
- `path`: state=unsupported; reason=レスポンスバナー解析でありパラメータ注入をしない
- `query`: state=unsupported; reason=レスポンスバナー解析でありパラメータ注入をしない
- `websocket`: state=unsupported; reason=レスポンスバナー解析でありパラメータ注入をしない
- `xml`: state=unsupported; reason=レスポンスバナー解析でありパラメータ注入をしない

**参考資料:**

- CWE 1104\.html — `https://cwe.mitre.org/data/definitions/1104.html`

## path\_traversal

**チェック:** PathTraversalScanner

**分類:** header

**名前:**
パストラバーサルによるファイルアクセス

**概要:**
パス・トラバーサル — ディレクトリを越えた任意ファイルの読み取り

**検査対象:**
パストラバーサルによるファイルアクセスを確認する専用入力を送信し、応答の内容や挙動を調べます。

**脆弱な場合のリスク:**
パストラバーサルによるファイルアクセスが悪用されると、機密情報の漏えい、データ改変、または利用者/サービスへの影響につながるおそれがあります。

**確認方法:**
専用プローブの応答をルール条件で評価し、条件に合う場合に所見を記録します。

**修正概要:**
該当する入力を検証し、安全なAPIや制限的な設定を適用します。

**制約:**
検査対象の入力・ページと観測できた応答の範囲に限られ、未検査や観測不能な経路の安全性は示しません。

**前提条件:**

- 宣言なし

**宣言された carrier と状態:**

- `cookie`: state=planned; reason=carrier 別 dispatcher は未接続
- `form`: state=supported; value_kinds=string; transports=playwright; payload_shapes=scalar; browser_required=true
- `graphql`: state=planned; reason=carrier 別 dispatcher は未接続
- `header`: state=planned; reason=carrier 別 dispatcher は未接続
- `json`: state=supported; value_kinds=string; transports=httpx; payload_shapes=scalar
- `multipart`: state=planned; reason=carrier 別 dispatcher は未接続
- `path`: state=planned; reason=carrier 別 dispatcher は未接続
- `query`: state=supported; value_kinds=string; transports=playwright; payload_shapes=scalar; browser_required=true
- `websocket`: state=planned; reason=carrier 別 dispatcher は未接続
- `xml`: state=planned; reason=carrier 別 dispatcher は未接続

**参考資料:**

- CWE 22\.html — `https://cwe.mitre.org/data/definitions/22.html`

## privesc

**チェック:** PrivEscScanner

**分類:** access

**名前:**
認証済み経路の権限境界

**概要:**
権限昇格 — 低権限ユーザーが高権限リソースにアクセス可能

**検査対象:**
認証状態とページ/経路の応答を比較します。

**脆弱な場合のリスク:**
認証済み経路の権限境界が悪用されると、機密情報の漏えい、データ改変、または利用者/サービスへの影響につながるおそれがあります。

**確認方法:**
専用プローブの応答をルール条件で評価し、条件に合う場合に所見を記録します。

**修正概要:**
該当する入力を検証し、安全なAPIや制限的な設定を適用します。

**制約:**
到達可能な認証状態と対象経路の範囲に限られます。

**前提条件:**

- 宣言なし

**宣言された carrier と状態:**

- `cookie`: state=unsupported; reason=identity 切替の認証 cookie を持ち回るが cookie 値へ payload 注入はしない
- `form`: state=supported; value_kinds=string; transports=httpx; payload_shapes=scalar
- `graphql`: state=unsupported; reason=page/response 解析でありパラメータ注入をしない
- `header`: state=supported; value_kinds=string; transports=httpx; payload_shapes=scalar
- `json`: state=unsupported; reason=page/response 解析でありパラメータ注入をしない
- `multipart`: state=unsupported; reason=page/response 解析でありパラメータ注入をしない
- `path`: state=supported; value_kinds=string; transports=httpx; payload_shapes=scalar
- `query`: state=supported; value_kinds=string; transports=httpx; payload_shapes=scalar
- `websocket`: state=unsupported; reason=page/response 解析でありパラメータ注入をしない
- `xml`: state=unsupported; reason=page/response 解析でありパラメータ注入をしない

**参考資料:**

- OWASP WSTG\-ATHZ\-03 — `https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/05-Authorization_Testing/03-Testing_for_Privilege_Escalation/`

## prototype\_pollution

**チェック:** PrototypePollutionScanner

**分類:** injection

**名前:**
クライアント/サーバー側のプロトタイプ汚染兆候

**概要:**
クライアント/サーバー側のプロトタイプ汚染兆候

**検査対象:**
クライアント側とサーバー側の候補入力に対する応答を調べます。

**脆弱な場合のリスク:**
クライアント/サーバー側のプロトタイプ汚染兆候が悪用されると、機密情報の漏えい、データ改変、または利用者/サービスへの影響につながるおそれがあります。

**確認方法:**
専用プローブの応答をルール条件で評価し、条件に合う場合に所見を記録します。

**修正概要:**
該当する入力を検証し、安全なAPIや制限的な設定を適用します。

**制約:**
検査対象の入力・ページと観測できた応答の範囲に限られ、未検査や観測不能な経路の安全性は示しません。

**前提条件:**

- 宣言なし

**宣言された carrier と状態:**

- `cookie`: state=unsupported; reason=prototype pollution の現行 probe 対象外
- `form`: state=unsupported; reason=prototype pollution の現行 probe 対象外
- `graphql`: state=unsupported; reason=prototype pollution の現行 probe 対象外
- `header`: state=unsupported; reason=prototype pollution の現行 probe 対象外
- `json`: state=supported; value_kinds=object; transports=httpx; payload_shapes=structured; structured_payload=true
- `multipart`: state=unsupported; reason=prototype pollution の現行 probe 対象外
- `path`: state=unsupported; reason=prototype pollution の現行 probe 対象外
- `query`: state=supported; value_kinds=string; transports=dom,playwright; payload_shapes=scalar; browser_required=true
- `websocket`: state=unsupported; reason=prototype pollution の現行 probe 対象外
- `xml`: state=unsupported; reason=prototype pollution の現行 probe 対象外

**参考資料:**

- CWE 1321\.html — `https://cwe.mitre.org/data/definitions/1321.html`

## race\_condition

**チェック:** RaceConditionScanner

**分類:** access

**名前:**
並行リクエスト時の状態競合

**概要:**
競合状態 \(TOCTOU\) の脆弱性

**検査対象:**
対応するリクエストを並行実行して応答/状態差を調べます。

**脆弱な場合のリスク:**
並行リクエスト時の状態競合が悪用されると、機密情報の漏えい、データ改変、または利用者/サービスへの影響につながるおそれがあります。

**確認方法:**
専用プローブの応答をルール条件で評価し、条件に合う場合に所見を記録します。

**修正概要:**
該当する入力を検証し、安全なAPIや制限的な設定を適用します。

**制約:**
実行可能な要求と観測可能な状態差の範囲に限られます。

**前提条件:**

- `second_request`

**宣言された carrier と状態:**

- `cookie`: state=unsupported; reason=page/response 解析でありパラメータ注入をしない
- `form`: state=supported; value_kinds=string; transports=httpx,playwright; payload_shapes=scalar; browser_required=true
- `graphql`: state=unsupported; reason=page/response 解析でありパラメータ注入をしない
- `header`: state=unsupported; reason=page/response 解析でありパラメータ注入をしない
- `json`: state=unsupported; reason=page/response 解析でありパラメータ注入をしない
- `multipart`: state=unsupported; reason=page/response 解析でありパラメータ注入をしない
- `path`: state=unsupported; reason=page/response 解析でありパラメータ注入をしない
- `query`: state=unsupported; reason=page/response 解析でありパラメータ注入をしない
- `websocket`: state=unsupported; reason=page/response 解析でありパラメータ注入をしない
- `xml`: state=unsupported; reason=page/response 解析でありパラメータ注入をしない

**参考資料:**

- CWE 362\.html — `https://cwe.mitre.org/data/definitions/362.html`

## request\_smuggling

**チェック:** RequestSmugglingScanner

**分類:** proto

**名前:**
HTTPリクエスト境界の解釈差

**概要:**
HTTPリクエスト・スマグリング

**検査対象:**
HTTPフレーミング関連ヘッダーへの応答を調べます。

**脆弱な場合のリスク:**
HTTPリクエスト境界の解釈差が悪用されると、機密情報の漏えい、データ改変、または利用者/サービスへの影響につながるおそれがあります。

**確認方法:**
専用プローブの応答をルール条件で評価し、条件に合う場合に所見を記録します。

**修正概要:**
該当する入力を検証し、安全なAPIや制限的な設定を適用します。

**制約:**
検査対象の入力・ページと観測できた応答の範囲に限られ、未検査や観測不能な経路の安全性は示しません。

**前提条件:**

- `second_request`

**宣言された carrier と状態:**

- `cookie`: state=unsupported; reason=HTTP request framing header 特化
- `form`: state=unsupported; reason=HTTP request framing header 特化
- `graphql`: state=unsupported; reason=HTTP request framing header 特化
- `header`: state=supported; value_kinds=string; transports=httpx; payload_shapes=scalar
- `json`: state=unsupported; reason=HTTP request framing header 特化
- `multipart`: state=unsupported; reason=HTTP request framing header 特化
- `path`: state=planned; reason=raw path probe は未接続
- `query`: state=unsupported; reason=HTTP request framing header 特化
- `websocket`: state=unsupported; reason=HTTP request framing header 特化
- `xml`: state=unsupported; reason=HTTP request framing header 特化

**参考資料:**

- CWE 444\.html — `https://cwe.mitre.org/data/definitions/444.html`

## secret\_leak

**チェック:** SecretLeakScanner

**分類:** proto

**名前:**
ページ資源内の秘密情報らしい文字列

**概要:**
ページ資源内の秘密情報らしい文字列

**検査対象:**
取得したページ資源のテキストをパターン照合します。

**脆弱な場合のリスク:**
ページ資源内の秘密情報らしい文字列が悪用されると、機密情報の漏えい、データ改変、または利用者/サービスへの影響につながるおそれがあります。

**確認方法:**
取得したページ、応答、または照合結果を実装済みの判定条件と比較します。

**修正概要:**
該当する入力を検証し、安全なAPIや制限的な設定を適用します。

**制約:**
検査対象の入力・ページと観測できた応答の範囲に限られ、未検査や観測不能な経路の安全性は示しません。

**前提条件:**

- 宣言なし

**宣言された carrier と状態:**

- `cookie`: state=unsupported; reason=page/response 解析でありパラメータ注入をしない
- `form`: state=unsupported; reason=page/response 解析でありパラメータ注入をしない
- `graphql`: state=unsupported; reason=page/response 解析でありパラメータ注入をしない
- `header`: state=unsupported; reason=page/response 解析でありパラメータ注入をしない
- `json`: state=unsupported; reason=page/response 解析でありパラメータ注入をしない
- `multipart`: state=unsupported; reason=page/response 解析でありパラメータ注入をしない
- `path`: state=unsupported; reason=page/response 解析でありパラメータ注入をしない
- `query`: state=unsupported; reason=page/response 解析でありパラメータ注入をしない
- `websocket`: state=unsupported; reason=page/response 解析でありパラメータ注入をしない
- `xml`: state=unsupported; reason=page/response 解析でありパラメータ注入をしない

**参考資料:**

- OWASP WSTG\-INFO\-05 — `https://wstg.owasp.org/latest/4-Web_Application_Security_Testing/01-Information_Gathering/05-Review_Web_Page_Content_for_Information_Leakage/`

## security\_headers

**チェック:** SecurityHeadersScanner

**分類:** proto

**名前:**
HTTPセキュリティヘッダーの設定

**概要:**
セキュリティヘッダーの欠如

**検査対象:**
ページ応答に所定のセキュリティヘッダーがあるか調べます。

**脆弱な場合のリスク:**
HTTPセキュリティヘッダーの設定が悪用されると、機密情報の漏えい、データ改変、または利用者/サービスへの影響につながるおそれがあります。

**確認方法:**
取得したページ、応答、または照合結果を実装済みの判定条件と比較します。

**修正概要:**
該当する入力を検証し、安全なAPIや制限的な設定を適用します。

**制約:**
検査対象の入力・ページと観測できた応答の範囲に限られ、未検査や観測不能な経路の安全性は示しません。

**前提条件:**

- 宣言なし

**宣言された carrier と状態:**

- `cookie`: state=unsupported; reason=page/response 解析でありパラメータ注入をしない
- `form`: state=unsupported; reason=page/response 解析でありパラメータ注入をしない
- `graphql`: state=unsupported; reason=page/response 解析でありパラメータ注入をしない
- `header`: state=unsupported; reason=page/response 解析でありパラメータ注入をしない
- `json`: state=unsupported; reason=page/response 解析でありパラメータ注入をしない
- `multipart`: state=unsupported; reason=page/response 解析でありパラメータ注入をしない
- `path`: state=unsupported; reason=page/response 解析でありパラメータ注入をしない
- `query`: state=unsupported; reason=page/response 解析でありパラメータ注入をしない
- `websocket`: state=unsupported; reason=page/response 解析でありパラメータ注入をしない
- `xml`: state=unsupported; reason=page/response 解析でありパラメータ注入をしない

**参考資料:**

- 宣言なし

## session

**チェック:** SessionScanner

**分類:** access

**名前:**
セッションCookieの保護属性

**概要:**
セッション管理の問題 — Cookie 属性の不備など

**検査対象:**
ページ応答のCookie属性を確認します。

**脆弱な場合のリスク:**
セッションCookieの保護属性が悪用されると、機密情報の漏えい、データ改変、または利用者/サービスへの影響につながるおそれがあります。

**確認方法:**
取得したページ、応答、または照合結果を実装済みの判定条件と比較します。

**修正概要:**
該当する入力を検証し、安全なAPIや制限的な設定を適用します。

**制約:**
検査対象の入力・ページと観測できた応答の範囲に限られ、未検査や観測不能な経路の安全性は示しません。

**前提条件:**

- `browser`

**宣言された carrier と状態:**

- `cookie`: state=unsupported; reason=cookie を解析するが注入しない
- `form`: state=unsupported; reason=page/response 解析でありパラメータ注入をしない
- `graphql`: state=unsupported; reason=page/response 解析でありパラメータ注入をしない
- `header`: state=unsupported; reason=page/response 解析でありパラメータ注入をしない
- `json`: state=unsupported; reason=page/response 解析でありパラメータ注入をしない
- `multipart`: state=unsupported; reason=page/response 解析でありパラメータ注入をしない
- `path`: state=unsupported; reason=page/response 解析でありパラメータ注入をしない
- `query`: state=unsupported; reason=page/response 解析でありパラメータ注入をしない
- `websocket`: state=unsupported; reason=page/response 解析でありパラメータ注入をしない
- `xml`: state=unsupported; reason=page/response 解析でありパラメータ注入をしない

**参考資料:**

- CWE 1004\.html — `https://cwe.mitre.org/data/definitions/1004.html`
- CWE 1275\.html — `https://cwe.mitre.org/data/definitions/1275.html`
- CWE 614\.html — `https://cwe.mitre.org/data/definitions/614.html`

## sqli

**チェック:** SQLiScanner

**分類:** injection

**名前:**
SQLインジェクション

**概要:**
SQLインジェクション — ユーザー入力がSQLクエリに注入される

**検査対象:**
SQLインジェクションを確認する専用入力を送信し、応答の内容や挙動を調べます。

**脆弱な場合のリスク:**
SQLインジェクションが悪用されると、機密情報の漏えい、データ改変、または利用者/サービスへの影響につながるおそれがあります。

**確認方法:**
専用プローブの応答をルール条件で評価し、条件に合う場合に所見を記録します。

**修正概要:**
SQLパラメーター化クエリを使い、DB権限を必要最小限にします。

**制約:**
検査対象の入力・ページと観測できた応答の範囲に限られ、未検査や観測不能な経路の安全性は示しません。

**前提条件:**

- 宣言なし

**宣言された carrier と状態:**

- `cookie`: state=planned; reason=carrier 別 dispatcher は未接続
- `form`: state=supported; value_kinds=string; transports=playwright; payload_shapes=scalar; browser_required=true
- `graphql`: state=planned; reason=carrier 別 dispatcher は未接続
- `header`: state=planned; reason=carrier 別 dispatcher は未接続
- `json`: state=supported; value_kinds=string; transports=httpx; payload_shapes=scalar
- `multipart`: state=planned; reason=carrier 別 dispatcher は未接続
- `path`: state=planned; reason=carrier 別 dispatcher は未接続
- `query`: state=supported; value_kinds=string; transports=playwright; payload_shapes=scalar; browser_required=true
- `websocket`: state=planned; reason=carrier 別 dispatcher は未接続
- `xml`: state=supported; value_kinds=string; transports=httpx; payload_shapes=scalar

**参考資料:**

- CWE 89\.html — `https://cwe.mitre.org/data/definitions/89.html`

## sri

**チェック:** SRIScanner

**分類:** proto

**名前:**
外部スクリプト参照のSubresource Integrity

**概要:**
外部スクリプト参照のSubresource Integrity

**検査対象:**
HTML内の外部スクリプト参照とintegrity属性を調べます。

**脆弱な場合のリスク:**
外部スクリプト参照のSubresource Integrityが悪用されると、機密情報の漏えい、データ改変、または利用者/サービスへの影響につながるおそれがあります。

**確認方法:**
取得したページ、応答、または照合結果を実装済みの判定条件と比較します。

**修正概要:**
該当する入力を検証し、安全なAPIや制限的な設定を適用します。

**制約:**
検査対象の入力・ページと観測できた応答の範囲に限られ、未検査や観測不能な経路の安全性は示しません。

**前提条件:**

- 宣言なし

**宣言された carrier と状態:**

- `cookie`: state=unsupported; reason=page/response 解析でありパラメータ注入をしない
- `form`: state=unsupported; reason=page/response 解析でありパラメータ注入をしない
- `graphql`: state=unsupported; reason=page/response 解析でありパラメータ注入をしない
- `header`: state=unsupported; reason=page/response 解析でありパラメータ注入をしない
- `json`: state=unsupported; reason=page/response 解析でありパラメータ注入をしない
- `multipart`: state=unsupported; reason=page/response 解析でありパラメータ注入をしない
- `path`: state=unsupported; reason=page/response 解析でありパラメータ注入をしない
- `query`: state=unsupported; reason=page/response 解析でありパラメータ注入をしない
- `websocket`: state=unsupported; reason=page/response 解析でありパラメータ注入をしない
- `xml`: state=unsupported; reason=page/response 解析でありパラメータ注入をしない

**参考資料:**

- CWE 345\.html — `https://cwe.mitre.org/data/definitions/345.html`

## ssrf

**チェック:** SSRFScanner

**分類:** proto

**名前:**
サーバーから指定先へのリクエスト挙動

**概要:**
SSRF — サーバーを経由した内部リソースへのリクエスト送信

**検査対象:**
サーバーから指定先へのリクエスト挙動を確認する専用入力を送信し、応答の内容や挙動を調べます。

**脆弱な場合のリスク:**
サーバーから指定先へのリクエスト挙動が悪用されると、機密情報の漏えい、データ改変、または利用者/サービスへの影響につながるおそれがあります。

**確認方法:**
専用プローブの応答をルール条件で評価し、条件に合う場合に所見を記録します。

**修正概要:**
送信先とプロトコルを許可リスト化し、内部アドレスへの接続を遮断します。

**制約:**
応答本文に内部リソース由来のマーカーが含まれる場合に検出します。応答時間による判定は行いません。

**前提条件:**

- 宣言なし

**宣言された carrier と状態:**

- `cookie`: state=planned; reason=carrier 別 dispatcher は未接続
- `form`: state=supported; value_kinds=string; transports=playwright; payload_shapes=scalar; browser_required=true
- `graphql`: state=planned; reason=carrier 別 dispatcher は未接続
- `header`: state=planned; reason=carrier 別 dispatcher は未接続
- `json`: state=supported; value_kinds=string; transports=httpx; payload_shapes=scalar
- `multipart`: state=planned; reason=carrier 別 dispatcher は未接続
- `path`: state=planned; reason=carrier 別 dispatcher は未接続
- `query`: state=supported; value_kinds=string; transports=playwright; payload_shapes=scalar; browser_required=true
- `websocket`: state=planned; reason=carrier 別 dispatcher は未接続
- `xml`: state=planned; reason=carrier 別 dispatcher は未接続

**参考資料:**

- CWE 918\.html — `https://cwe.mitre.org/data/definitions/918.html`

## ssti

**チェック:** SSTIScanner

**分類:** injection

**名前:**
サーバーサイドテンプレートインジェクション

**概要:**
サーバーサイド・テンプレート・インジェクション

**検査対象:**
サーバーサイドテンプレートインジェクションを確認する専用入力を送信し、応答の内容や挙動を調べます。

**脆弱な場合のリスク:**
サーバーサイドテンプレートインジェクションが悪用されると、機密情報の漏えい、データ改変、または利用者/サービスへの影響につながるおそれがあります。

**確認方法:**
専用プローブの応答をルール条件で評価し、条件に合う場合に所見を記録します。

**修正概要:**
該当する入力を検証し、安全なAPIや制限的な設定を適用します。

**制約:**
検査対象の入力・ページと観測できた応答の範囲に限られ、未検査や観測不能な経路の安全性は示しません。

**前提条件:**

- 宣言なし

**宣言された carrier と状態:**

- `cookie`: state=planned; reason=carrier 別 dispatcher は未接続
- `form`: state=supported; value_kinds=string; transports=playwright; payload_shapes=scalar; browser_required=true
- `graphql`: state=planned; reason=carrier 別 dispatcher は未接続
- `header`: state=planned; reason=carrier 別 dispatcher は未接続
- `json`: state=supported; value_kinds=string; transports=httpx; payload_shapes=scalar
- `multipart`: state=planned; reason=carrier 別 dispatcher は未接続
- `path`: state=planned; reason=carrier 別 dispatcher は未接続
- `query`: state=supported; value_kinds=string; transports=playwright; payload_shapes=scalar; browser_required=true
- `websocket`: state=planned; reason=carrier 別 dispatcher は未接続
- `xml`: state=planned; reason=carrier 別 dispatcher は未接続

**参考資料:**

- CWE 1336\.html — `https://cwe.mitre.org/data/definitions/1336.html`

## stored\_xss

**チェック:** StoredXSSScanner

**分類:** xss

**名前:**
保存後に表示されるスクリプトの実行

**概要:**
蓄積型 XSS — 悪意あるスクリプトが保存され他ユーザーに影響する

**検査対象:**
保存後に表示されるスクリプトの実行を確認する専用入力を送信し、応答の内容や挙動を調べます。

**脆弱な場合のリスク:**
保存後に表示されるスクリプトの実行が悪用されると、機密情報の漏えい、データ改変、または利用者/サービスへの影響につながるおそれがあります。

**確認方法:**
専用プローブの応答をルール条件で評価し、条件に合う場合に所見を記録します。

**修正概要:**
該当する入力を検証し、安全なAPIや制限的な設定を適用します。

**制約:**
保存と再表示が実際に行われる経路に限られます。

**前提条件:**

- 宣言なし

**宣言された carrier と状態:**

- `cookie`: state=planned; reason=stored XSS の carrier 別 dispatcher は未接続
- `form`: state=supported; value_kinds=string; transports=playwright; payload_shapes=scalar; browser_required=true
- `graphql`: state=planned; reason=stored XSS の carrier 別 dispatcher は未接続
- `header`: state=planned; reason=stored XSS の carrier 別 dispatcher は未接続
- `json`: state=planned; reason=JSON body の検出は未対応
- `multipart`: state=planned; reason=stored XSS の carrier 別 dispatcher は未接続
- `path`: state=planned; reason=stored XSS の carrier 別 dispatcher は未接続
- `query`: state=supported; value_kinds=string; transports=playwright; payload_shapes=scalar; browser_required=true
- `websocket`: state=planned; reason=stored XSS の carrier 別 dispatcher は未接続
- `xml`: state=planned; reason=stored XSS の carrier 別 dispatcher は未接続

**参考資料:**

- CWE 79\.html — `https://cwe.mitre.org/data/definitions/79.html`

## tls\_scan

**チェック:** TlsConfigScanner

**分類:** proto

**名前:**
TLS接続で観測できるプロトコルと設定

**概要:**
TLS接続で観測できるプロトコルと設定

**検査対象:**
TLS接続設定をスキャナーで検査します。

**脆弱な場合のリスク:**
TLS接続で観測できるプロトコルと設定が悪用されると、機密情報の漏えい、データ改変、または利用者/サービスへの影響につながるおそれがあります。

**確認方法:**
取得したページ、応答、または照合結果を実装済みの判定条件と比較します。

**修正概要:**
該当する入力を検証し、安全なAPIや制限的な設定を適用します。

**制約:**
プロキシまたはクライアント証明書が必要な接続は検査できない場合があります。

**前提条件:**

- 宣言なし

**宣言された carrier と状態:**

- `cookie`: state=unsupported; reason=TLS 通信路の設定を観測しパラメータ注入をしない
- `form`: state=unsupported; reason=TLS 通信路の設定を観測しパラメータ注入をしない
- `graphql`: state=unsupported; reason=TLS 通信路の設定を観測しパラメータ注入をしない
- `header`: state=unsupported; reason=TLS 通信路の設定を観測しパラメータ注入をしない
- `json`: state=unsupported; reason=TLS 通信路の設定を観測しパラメータ注入をしない
- `multipart`: state=unsupported; reason=TLS 通信路の設定を観測しパラメータ注入をしない
- `path`: state=unsupported; reason=TLS 通信路の設定を観測しパラメータ注入をしない
- `query`: state=unsupported; reason=TLS 通信路の設定を観測しパラメータ注入をしない
- `websocket`: state=unsupported; reason=TLS 通信路の設定を観測しパラメータ注入をしない
- `xml`: state=unsupported; reason=TLS 通信路の設定を観測しパラメータ注入をしない

**参考資料:**

- CWE 326\.html — `https://cwe.mitre.org/data/definitions/326.html`

## transport\_security

**チェック:** TransportSecurityScanner

**分類:** proto

**名前:**
HTTPメソッド応答とHTTPS転送挙動

**概要:**
HTTPメソッド応答とHTTPS転送挙動

**検査対象:**
読み取り用HTTPメソッドとHTTPS転送応答を観測します。

**脆弱な場合のリスク:**
HTTPメソッド応答とHTTPS転送挙動が悪用されると、機密情報の漏えい、データ改変、または利用者/サービスへの影響につながるおそれがあります。

**確認方法:**
取得したページ、応答、または照合結果を実装済みの判定条件と比較します。

**修正概要:**
該当する入力を検証し、安全なAPIや制限的な設定を適用します。

**制約:**
検査対象の入力・ページと観測できた応答の範囲に限られ、未検査や観測不能な経路の安全性は示しません。

**前提条件:**

- 宣言なし

**宣言された carrier と状態:**

- `cookie`: state=unsupported; reason=Read\-only method probes and transport observations, no parameter injection
- `form`: state=unsupported; reason=Read\-only method probes and transport observations, no parameter injection
- `graphql`: state=unsupported; reason=Read\-only method probes and transport observations, no parameter injection
- `header`: state=unsupported; reason=Read\-only method probes and transport observations, no parameter injection
- `json`: state=unsupported; reason=Read\-only method probes and transport observations, no parameter injection
- `multipart`: state=unsupported; reason=Read\-only method probes and transport observations, no parameter injection
- `path`: state=unsupported; reason=Read\-only method probes and transport observations, no parameter injection
- `query`: state=unsupported; reason=Read\-only method probes and transport observations, no parameter injection
- `websocket`: state=unsupported; reason=Read\-only method probes and transport observations, no parameter injection
- `xml`: state=unsupported; reason=Read\-only method probes and transport observations, no parameter injection

**参考資料:**

- CWE 319\.html — `https://cwe.mitre.org/data/definitions/319.html`

## websocket

**チェック:** WebSocketScanner

**分類:** proto

**名前:**
WebSocket接続とメッセージ処理

**概要:**
WebSocket インジェクション

**検査対象:**
検出したWebSocket経路でメッセージ応答を調べます。

**脆弱な場合のリスク:**
WebSocket接続とメッセージ処理が悪用されると、機密情報の漏えい、データ改変、または利用者/サービスへの影響につながるおそれがあります。

**確認方法:**
専用プローブの応答をルール条件で評価し、条件に合う場合に所見を記録します。

**修正概要:**
該当する入力を検証し、安全なAPIや制限的な設定を適用します。

**制約:**
検査対象の入力・ページと観測できた応答の範囲に限られ、未検査や観測不能な経路の安全性は示しません。

**前提条件:**

- 宣言なし

**宣言された carrier と状態:**

- `cookie`: state=unsupported; reason=WS message 特化
- `form`: state=unsupported; reason=WS message 特化
- `graphql`: state=unsupported; reason=WS message 特化
- `header`: state=unsupported; reason=WS message 特化
- `json`: state=unsupported; reason=WS message 特化
- `multipart`: state=unsupported; reason=WS message 特化
- `path`: state=unsupported; reason=WS message 特化
- `query`: state=unsupported; reason=WS message 特化
- `websocket`: state=supported; value_kinds=object,string; transports=playwright,websocket; payload_shapes=scalar,structured; browser_required=true; structured_payload=true
- `xml`: state=unsupported; reason=WS message 特化

**参考資料:**

- 宣言なし

## xss

**チェック:** XSSScanner

**分類:** xss

**名前:**
反射型クロスサイトスクリプティング

**概要:**
クロスサイト・スクリプティング \(反射型\) — スクリプトが反射実行される

**検査対象:**
反射型クロスサイトスクリプティングを確認する専用入力を送信し、応答の内容や挙動を調べます。

**脆弱な場合のリスク:**
反射型クロスサイトスクリプティングが悪用されると、機密情報の漏えい、データ改変、または利用者/サービスへの影響につながるおそれがあります。

**確認方法:**
専用プローブの応答をルール条件で評価し、条件に合う場合に所見を記録します。

**修正概要:**
出力箇所に応じたエンコードとフレームワークの自動エスケープを使います。

**制約:**
検査対象の入力・ページと観測できた応答の範囲に限られ、未検査や観測不能な経路の安全性は示しません。

**前提条件:**

- 宣言なし

**宣言された carrier と状態:**

- `cookie`: state=planned; reason=carrier 別 dispatcher は未接続
- `form`: state=supported; value_kinds=string; transports=playwright; payload_shapes=scalar; browser_required=true
- `graphql`: state=planned; reason=carrier 別 dispatcher は未接続
- `header`: state=planned; reason=carrier 別 dispatcher は未接続
- `json`: state=supported; value_kinds=string; transports=httpx; payload_shapes=scalar
- `multipart`: state=planned; reason=carrier 別 dispatcher は未接続
- `path`: state=planned; reason=carrier 別 dispatcher は未接続
- `query`: state=supported; value_kinds=string; transports=playwright; payload_shapes=scalar; browser_required=true
- `websocket`: state=planned; reason=carrier 別 dispatcher は未接続
- `xml`: state=supported; value_kinds=string; transports=httpx; payload_shapes=scalar

**参考資料:**

- CWE 79\.html — `https://cwe.mitre.org/data/definitions/79.html`

## xxe

**チェック:** XXEScanner

**分類:** header

**名前:**
XML入力の外部エンティティ処理

**概要:**
XXE — XML外部エンティティ参照による情報漏洩

**検査対象:**
XML入力の外部エンティティ処理を確認する専用入力を送信し、応答の内容や挙動を調べます。

**脆弱な場合のリスク:**
XML入力の外部エンティティ処理が悪用されると、機密情報の漏えい、データ改変、または利用者/サービスへの影響につながるおそれがあります。

**確認方法:**
専用プローブの応答をルール条件で評価し、条件に合う場合に所見を記録します。

**修正概要:**
XMLパーサーで外部エンティティとDOCTYPEを無効化します。

**制約:**
XMLを受理する到達可能な入力が必要で、応答に現れない外部アクセスは確定できません。

**前提条件:**

- 宣言なし

**宣言された carrier と状態:**

- `cookie`: state=unsupported; reason=XXE は XML document 特化
- `form`: state=unsupported; reason=XXE は XML document 特化
- `graphql`: state=unsupported; reason=XXE は XML document 特化
- `header`: state=unsupported; reason=XXE は XML document 特化
- `json`: state=unsupported; reason=XXE は XML document 特化
- `multipart`: state=unsupported; reason=XXE は XML document 特化
- `path`: state=unsupported; reason=XXE は XML document 特化
- `query`: state=unsupported; reason=XXE は XML document 特化
- `websocket`: state=unsupported; reason=XXE は XML document 特化
- `xml`: state=supported; value_kinds=object,string; transports=httpx; payload_shapes=structured; structured_payload=true

**参考資料:**

- CWE 611\.html — `https://cwe.mitre.org/data/definitions/611.html`
