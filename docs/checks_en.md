# Check reference (English)

This reference describes catalog metadata and declared static capabilities. A declaration does not prove that a check ran, provide runtime coverage, or guarantee detection.

Catalog version: 1\.0\.0

## cache\_poisoning

**Check:** CachePoisoningScanner

**Category:** file

**Name:**
Input dependence of cached responses

**Summary:**
Input dependence of cached responses

**What is tested:**
It compares responses across baseline and varied requests\.

**Risk if vulnerable:**
Exploitation of input dependence of cached responses may expose sensitive data, alter data, or affect users or services\.

**Verification:**
It evaluates probe responses against scanner rules and records findings when conditions match\.

**Remediation:**
Validate the relevant input and use safe APIs or restrictive configuration\.

**Limitations:**
Coverage is limited to inspected inputs/pages and observable responses; untested or unobservable paths are not shown to be safe\.

**Prerequisites:**

- None declared.

**Declared carriers and status:**

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

**References:**

- OWASP Web Cache Security Cheat Sheet — `https://cheatsheetseries.owasp.org/cheatsheets/Web_Cache_Security_Cheat_Sheet.html`

## clickjacking

**Check:** ClickjackingScanner

**Category:** file

**Name:**
Restrictions on framing the page

**Summary:**
Restrictions on framing the page

**What is tested:**
It inspects framing\-related headers in the page response\.

**Risk if vulnerable:**
Exploitation of restrictions on framing the page may expose sensitive data, alter data, or affect users or services\.

**Verification:**
It compares retrieved pages, responses, or lookup results with implemented decision rules\.

**Remediation:**
Validate the relevant input and use safe APIs or restrictive configuration\.

**Limitations:**
Coverage is limited to inspected inputs/pages and observable responses; untested or unobservable paths are not shown to be safe\.

**Prerequisites:**

- None declared.

**Declared carriers and status:**

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

**References:**

- CWE 1021\.html — `https://cwe.mitre.org/data/definitions/1021.html`

## cms

**Check:** CmsScanner

**Category:** file

**Name:**
Cms identification and known public paths

**Summary:**
CMS identification and known public paths

**What is tested:**
It checks CMS identification paths and responses\.

**Risk if vulnerable:**
Exploitation of cms identification and known public paths may expose sensitive data, alter data, or affect users or services\.

**Verification:**
It compares retrieved pages, responses, or lookup results with implemented decision rules\.

**Remediation:**
Validate the relevant input and use safe APIs or restrictive configuration\.

**Limitations:**
Coverage is limited to inspected inputs/pages and observable responses; untested or unobservable paths are not shown to be safe\.

**Prerequisites:**

- None declared.

**Declared carriers and status:**

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

**References:**

- CWE 200\.html — `https://cwe.mitre.org/data/definitions/200.html`

## cors

**Check:** CORSScanner

**Category:** proto

**Name:**
Cors response headers and origin permissions

**Summary:**
CORS response headers and origin permissions

**What is tested:**
It checks response headers using a different Origin\.

**Risk if vulnerable:**
Exploitation of cors response headers and origin permissions may expose sensitive data, alter data, or affect users or services\.

**Verification:**
It evaluates probe responses against scanner rules and records findings when conditions match\.

**Remediation:**
Validate the relevant input and use safe APIs or restrictive configuration\.

**Limitations:**
Coverage is limited to inspected inputs/pages and observable responses; untested or unobservable paths are not shown to be safe\.

**Prerequisites:**

- None declared.

**Declared carriers and status:**

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

**References:**

- OWASP WSTG\-CLNT\-07 — `https://wstg.owasp.org/latest/4-Web_Application_Security_Testing/11-Client-side/07-Cross_Origin_Resource_Sharing/`

## csrf

**Check:** CSRFScanner

**Category:** access

**Name:**
Csrf protections on state\-changing requests

**Summary:**
CSRF protections on state\-changing requests

**What is tested:**
It analyzes page forms and responses\.

**Risk if vulnerable:**
Exploitation of csrf protections on state\-changing requests may expose sensitive data, alter data, or affect users or services\.

**Verification:**
It compares retrieved pages, responses, or lookup results with implemented decision rules\.

**Remediation:**
Require unpredictable CSRF tokens for state\-changing requests and validate origins\.

**Limitations:**
Coverage is limited to inspected inputs/pages and observable responses; untested or unobservable paths are not shown to be safe\.

**Prerequisites:**

- `browser`

**Declared carriers and status:**

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

**References:**

- CWE 352\.html — `https://cwe.mitre.org/data/definitions/352.html`

## deserialization

**Check:** DeserializationScanner

**Category:** injection

**Name:**
Handling of inputs in serialized formats

**Summary:**
Handling of inputs in serialized formats

**What is tested:**
The scanner submits dedicated inputs for handling of inputs in serialized formats and examines response content or behavior\.

**Risk if vulnerable:**
Exploitation of handling of inputs in serialized formats may expose sensitive data, alter data, or affect users or services\.

**Verification:**
It evaluates probe responses against scanner rules and records findings when conditions match\.

**Remediation:**
Validate the relevant input and use safe APIs or restrictive configuration\.

**Limitations:**
Coverage is limited to inspected inputs/pages and observable responses; untested or unobservable paths are not shown to be safe\.

**Prerequisites:**

- None declared.

**Declared carriers and status:**

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

**References:**

- CWE 502\.html — `https://cwe.mitre.org/data/definitions/502.html`

## directory\_artifacts

**Check:** DirectoryArtifactsScanner

**Category:** proto

**Name:**
Known artifacts in publicly reachable directories

**Summary:**
Known artifacts in publicly reachable directories

**What is tested:**
It gathers candidates from page resources and sends read requests to public paths\.

**Risk if vulnerable:**
Exploitation of known artifacts in publicly reachable directories may expose sensitive data, alter data, or affect users or services\.

**Verification:**
It evaluates probe responses against scanner rules and records findings when conditions match\.

**Remediation:**
Validate the relevant input and use safe APIs or restrictive configuration\.

**Limitations:**
候補パスの上限と対象スコープにより全ファイルを網羅しません。

**Prerequisites:**

- None declared.

**Declared carriers and status:**

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

**References:**

- OWASP WSTG\-CONF\-04 — `https://wstg.owasp.org/latest/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management/04-Review_Old_Backup_and_Unreferenced_Files_for_Sensitive_Information/`

## dom\_xss

**Check:** DOMXSSScanner

**Category:** xss

**Name:**
Cross\-site scripting

**Summary:**
Cross\-site scripting through client\-side DOM operations

**What is tested:**
The scanner submits dedicated inputs for cross\-site scripting through client\-side dom operations and examines response content or behavior\.

**Risk if vulnerable:**
Exploitation of cross\-site scripting through client\-side dom operations may expose sensitive data, alter data, or affect users or services\.

**Verification:**
It evaluates probe responses against scanner rules and records findings when conditions match\.

**Remediation:**
Validate the relevant input and use safe APIs or restrictive configuration\.

**Limitations:**
Coverage is limited to inspected inputs/pages and observable responses; untested or unobservable paths are not shown to be safe\.

**Prerequisites:**

- None declared.

**Declared carriers and status:**

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

**References:**

- CWE 79\.html — `https://cwe.mitre.org/data/definitions/79.html`

## file\_upload

**Check:** FileUploadScanner

**Category:** file

**Name:**
File upload acceptance and response

**Summary:**
File upload acceptance and response

**What is tested:**
The scanner submits dedicated inputs for file upload acceptance and response and examines response content or behavior\.

**Risk if vulnerable:**
Exploitation of file upload acceptance and response may expose sensitive data, alter data, or affect users or services\.

**Verification:**
It evaluates probe responses against scanner rules and records findings when conditions match\.

**Remediation:**
Validate the relevant input and use safe APIs or restrictive configuration\.

**Limitations:**
Coverage is limited to inspected inputs/pages and observable responses; untested or unobservable paths are not shown to be safe\.

**Prerequisites:**

- None declared.

**Declared carriers and status:**

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

**References:**

- CWE 434\.html — `https://cwe.mitre.org/data/definitions/434.html`

## graphql

**Check:** GraphQLScanner

**Category:** injection

**Name:**
Graphql endpoint configuration and responses

**Summary:**
GraphQL endpoint configuration and responses

**What is tested:**
It examines GraphQL endpoints, query responses, and configuration\.

**Risk if vulnerable:**
Exploitation of graphql endpoint configuration and responses may expose sensitive data, alter data, or affect users or services\.

**Verification:**
It evaluates probe responses against scanner rules and records findings when conditions match\.

**Remediation:**
Validate the relevant input and use safe APIs or restrictive configuration\.

**Limitations:**
検出可能なGraphQL経路と応答の範囲に限られます。

**Prerequisites:**

- None declared.

**Declared carriers and status:**

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

**References:**

- None declared.

## header\_injection

**Check:** HeaderInjectionScanner

**Category:** header

**Name:**
Http response header manipulation

**Summary:**
HTTP response header manipulation through input

**What is tested:**
The scanner submits dedicated inputs for http response header manipulation through input and examines response content or behavior\.

**Risk if vulnerable:**
Exploitation of http response header manipulation through input may expose sensitive data, alter data, or affect users or services\.

**Verification:**
It evaluates probe responses against scanner rules and records findings when conditions match\.

**Remediation:**
Validate the relevant input and use safe APIs or restrictive configuration\.

**Limitations:**
Coverage is limited to inspected inputs/pages and observable responses; untested or unobservable paths are not shown to be safe\.

**Prerequisites:**

- None declared.

**Declared carriers and status:**

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

**References:**

- CWE 113\.html — `https://cwe.mitre.org/data/definitions/113.html`

## host\_header

**Check:** HostHeaderScanner

**Category:** header

**Name:**
Handling of host\-related headers

**Summary:**
Handling of Host\-related headers

**What is tested:**
It compares responses after varying Host\-related headers\.

**Risk if vulnerable:**
Exploitation of handling of host\-related headers may expose sensitive data, alter data, or affect users or services\.

**Verification:**
It evaluates probe responses against scanner rules and records findings when conditions match\.

**Remediation:**
Validate the relevant input and use safe APIs or restrictive configuration\.

**Limitations:**
Coverage is limited to inspected inputs/pages and observable responses; untested or unobservable paths are not shown to be safe\.

**Prerequisites:**

- None declared.

**Declared carriers and status:**

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

**References:**

- OWASP WSTG\-INJT\-17 — `https://wstg.owasp.org/latest/4-Web_Application_Security_Testing/07-Injection/17-Host_Header_Injection/`

## http\_methods

**Check:** HttpMethodsScanner

**Category:** proto

**Name:**
Http methods that the target origin responds to

**Summary:**
HTTP methods that the target origin responds to

**What is tested:**
It sends methods such as OPTIONS to the target origin\.

**Risk if vulnerable:**
Exploitation of http methods that the target origin responds to may expose sensitive data, alter data, or affect users or services\.

**Verification:**
It compares retrieved pages, responses, or lookup results with implemented decision rules\.

**Remediation:**
Validate the relevant input and use safe APIs or restrictive configuration\.

**Limitations:**
Coverage is limited to inspected inputs/pages and observable responses; untested or unobservable paths are not shown to be safe\.

**Prerequisites:**

- None declared.

**Declared carriers and status:**

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

**References:**

- None declared.

## info\_disclosure

**Check:** InfoDisclosureScanner

**Category:** proto

**Name:**
Information exposed by responses and public paths

**Summary:**
Information exposed by responses and public paths

**What is tested:**
It inspects response content and candidate path responses\.

**Risk if vulnerable:**
Exploitation of information exposed by responses and public paths may expose sensitive data, alter data, or affect users or services\.

**Verification:**
It evaluates probe responses against scanner rules and records findings when conditions match\.

**Remediation:**
Validate the relevant input and use safe APIs or restrictive configuration\.

**Limitations:**
Coverage is limited to inspected inputs/pages and observable responses; untested or unobservable paths are not shown to be safe\.

**Prerequisites:**

- None declared.

**Declared carriers and status:**

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

**References:**

- CWE 200\.html — `https://cwe.mitre.org/data/definitions/200.html`

## js\_static

**Check:** JsStaticScanner

**Category:** xss

**Name:**
Static findings in retrieved javascript

**Summary:**
Static findings in retrieved JavaScript

**What is tested:**
It statically analyzes retrieved JavaScript resources\.

**Risk if vulnerable:**
Exploitation of static findings in retrieved javascript may expose sensitive data, alter data, or affect users or services\.

**Verification:**
It compares retrieved pages, responses, or lookup results with implemented decision rules\.

**Remediation:**
Validate the relevant input and use safe APIs or restrictive configuration\.

**Limitations:**
Coverage is limited to inspected inputs/pages and observable responses; untested or unobservable paths are not shown to be safe\.

**Prerequisites:**

- None declared.

**Declared carriers and status:**

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

**References:**

- CWE 79\.html — `https://cwe.mitre.org/data/definitions/79.html`

## jwt

**Check:** JWTScanner

**Category:** proto

**Name:**
Jwts exposed in pages and token validation issues

**Summary:**
JWTs exposed in pages and token validation issues

**What is tested:**
It parses JWTs found in retrieved pages\.

**Risk if vulnerable:**
Exploitation of jwts exposed in pages and token validation issues may expose sensitive data, alter data, or affect users or services\.

**Verification:**
It compares retrieved pages, responses, or lookup results with implemented decision rules\.

**Remediation:**
Validate the relevant input and use safe APIs or restrictive configuration\.

**Limitations:**
Coverage is limited to inspected inputs/pages and observable responses; untested or unobservable paths are not shown to be safe\.

**Prerequisites:**

- None declared.

**Declared carriers and status:**

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

**References:**

- None declared.

## ldap

**Check:** LDAPScanner

**Category:** injection

**Name:**
Interpretation of ldap search input

**Summary:**
Interpretation of LDAP search input

**What is tested:**
The scanner submits dedicated inputs for interpretation of ldap search input and examines response content or behavior\.

**Risk if vulnerable:**
Exploitation of interpretation of ldap search input may expose sensitive data, alter data, or affect users or services\.

**Verification:**
It evaluates probe responses against scanner rules and records findings when conditions match\.

**Remediation:**
Validate the relevant input and use safe APIs or restrictive configuration\.

**Limitations:**
Coverage is limited to inspected inputs/pages and observable responses; untested or unobservable paths are not shown to be safe\.

**Prerequisites:**

- None declared.

**Declared carriers and status:**

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

**References:**

- CWE 90\.html — `https://cwe.mitre.org/data/definitions/90.html`

## mail\_header

**Check:** MailHeaderInjectionScanner

**Category:** header

**Name:**
Header injection in mail\-related input

**Summary:**
Header injection in mail\-related input

**What is tested:**
The scanner submits dedicated inputs for header injection in mail\-related input and examines response content or behavior\.

**Risk if vulnerable:**
Exploitation of header injection in mail\-related input may expose sensitive data, alter data, or affect users or services\.

**Verification:**
It evaluates probe responses against scanner rules and records findings when conditions match\.

**Remediation:**
Validate the relevant input and use safe APIs or restrictive configuration\.

**Limitations:**
Out\-of\-band confirmation requires a configured external mail receiver\.

**Prerequisites:**

- None declared.

**Declared carriers and status:**

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

**References:**

- CWE 93\.html — `https://cwe.mitre.org/data/definitions/93.html`

## mass\_assignment

**Check:** MassAssignmentScanner

**Category:** injection

**Name:**
Acceptance of unapproved properties in api json input

**Summary:**
Acceptance of unapproved properties in API JSON input

**What is tested:**
It checks handling of added properties in API\-spec\-derived JSON requests\.

**Risk if vulnerable:**
Exploitation of acceptance of unapproved properties in api json input may expose sensitive data, alter data, or affect users or services\.

**Verification:**
It evaluates probe responses against scanner rules and records findings when conditions match\.

**Remediation:**
Validate the relevant input and use safe APIs or restrictive configuration\.

**Limitations:**
Coverage is limited to inspected inputs/pages and observable responses; untested or unobservable paths are not shown to be safe\.

**Prerequisites:**

- `api_spec`

**Declared carriers and status:**

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

**References:**

- None declared.

## nosql

**Check:** NoSQLInjectionScanner

**Category:** injection

**Name:**
Input interpretation in nosql queries

**Summary:**
Input interpretation in NoSQL queries

**What is tested:**
The scanner submits dedicated inputs for input interpretation in nosql queries and examines response content or behavior\.

**Risk if vulnerable:**
Exploitation of input interpretation in nosql queries may expose sensitive data, alter data, or affect users or services\.

**Verification:**
It evaluates probe responses against scanner rules and records findings when conditions match\.

**Remediation:**
Validate the relevant input and use safe APIs or restrictive configuration\.

**Limitations:**
Coverage is limited to inspected inputs/pages and observable responses; untested or unobservable paths are not shown to be safe\.

**Prerequisites:**

- None declared.

**Declared carriers and status:**

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

**References:**

- CWE 943\.html — `https://cwe.mitre.org/data/definitions/943.html`

## open\_redirect

**Check:** OpenRedirectScanner

**Category:** header

**Name:**
External redirects controlled by input

**Summary:**
External redirects controlled by input

**What is tested:**
The scanner submits dedicated inputs for external redirects controlled by input and examines response content or behavior\.

**Risk if vulnerable:**
Exploitation of external redirects controlled by input may expose sensitive data, alter data, or affect users or services\.

**Verification:**
It evaluates probe responses against scanner rules and records findings when conditions match\.

**Remediation:**
Control redirect destinations server\-side or validate them against an allowlist\.

**Limitations:**
Coverage is limited to inspected inputs/pages and observable responses; untested or unobservable paths are not shown to be safe\.

**Prerequisites:**

- None declared.

**Declared carriers and status:**

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

**References:**

- CWE 601\.html — `https://cwe.mitre.org/data/definitions/601.html`

## os

**Check:** OSInjectionScanner

**Category:** injection

**Name:**
Os command injection

**Summary:**
OS command injection

**What is tested:**
The scanner submits dedicated inputs for os command injection and examines response content or behavior\.

**Risk if vulnerable:**
Exploitation of os command injection may expose sensitive data, alter data, or affect users or services\.

**Verification:**
It evaluates probe responses against scanner rules and records findings when conditions match\.

**Remediation:**
Validate the relevant input and use safe APIs or restrictive configuration\.

**Limitations:**
Coverage is limited to inspected inputs/pages and observable responses; untested or unobservable paths are not shown to be safe\.

**Prerequisites:**

- None declared.

**Declared carriers and status:**

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

**References:**

- CWE 78\.html — `https://cwe.mitre.org/data/definitions/78.html`

## outdated\_components

**Check:** OutdatedComponentScanner

**Category:** file

**Name:**
Known information about detected components

**Summary:**
Known information about detected components

**What is tested:**
It matches identified versions from page banners/resources against vulnerability sources\.

**Risk if vulnerable:**
Exploitation of known information about detected components may expose sensitive data, alter data, or affect users or services\.

**Verification:**
It compares retrieved pages, responses, or lookup results with implemented decision rules\.

**Remediation:**
Validate the relevant input and use safe APIs or restrictive configuration\.

**Limitations:**
版を識別できない資源や外部照会の失敗は判定できません。

**Prerequisites:**

- None declared.

**Declared carriers and status:**

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

**References:**

- CWE 1104\.html — `https://cwe.mitre.org/data/definitions/1104.html`

## path\_traversal

**Check:** PathTraversalScanner

**Category:** header

**Name:**
File access

**Summary:**
File access through path traversal

**What is tested:**
The scanner submits dedicated inputs for file access through path traversal and examines response content or behavior\.

**Risk if vulnerable:**
Exploitation of file access through path traversal may expose sensitive data, alter data, or affect users or services\.

**Verification:**
It evaluates probe responses against scanner rules and records findings when conditions match\.

**Remediation:**
Validate the relevant input and use safe APIs or restrictive configuration\.

**Limitations:**
Coverage is limited to inspected inputs/pages and observable responses; untested or unobservable paths are not shown to be safe\.

**Prerequisites:**

- None declared.

**Declared carriers and status:**

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

**References:**

- CWE 22\.html — `https://cwe.mitre.org/data/definitions/22.html`

## privesc

**Check:** PrivEscScanner

**Category:** access

**Name:**
Authorization boundaries on authenticated routes

**Summary:**
Authorization boundaries on authenticated routes

**What is tested:**
It compares responses across authenticated states and routes\.

**Risk if vulnerable:**
Exploitation of authorization boundaries on authenticated routes may expose sensitive data, alter data, or affect users or services\.

**Verification:**
It evaluates probe responses against scanner rules and records findings when conditions match\.

**Remediation:**
Validate the relevant input and use safe APIs or restrictive configuration\.

**Limitations:**
到達可能な認証状態と対象経路の範囲に限られます。

**Prerequisites:**

- None declared.

**Declared carriers and status:**

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

**References:**

- OWASP WSTG\-ATHZ\-03 — `https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/05-Authorization_Testing/03-Testing_for_Privilege_Escalation/`

## prototype\_pollution

**Check:** PrototypePollutionScanner

**Category:** injection

**Name:**
Client\- and server\-side prototype pollution indicators

**Summary:**
Client\- and server\-side prototype pollution indicators

**What is tested:**
It examines responses to client\- and server\-side candidate inputs\.

**Risk if vulnerable:**
Exploitation of client\- and server\-side prototype pollution indicators may expose sensitive data, alter data, or affect users or services\.

**Verification:**
It evaluates probe responses against scanner rules and records findings when conditions match\.

**Remediation:**
Validate the relevant input and use safe APIs or restrictive configuration\.

**Limitations:**
Coverage is limited to inspected inputs/pages and observable responses; untested or unobservable paths are not shown to be safe\.

**Prerequisites:**

- None declared.

**Declared carriers and status:**

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

**References:**

- CWE 1321\.html — `https://cwe.mitre.org/data/definitions/1321.html`

## race\_condition

**Check:** RaceConditionScanner

**Category:** access

**Name:**
State races under concurrent requests

**Summary:**
State races under concurrent requests

**What is tested:**
It sends supported requests concurrently and examines response or state differences\.

**Risk if vulnerable:**
Exploitation of state races under concurrent requests may expose sensitive data, alter data, or affect users or services\.

**Verification:**
It evaluates probe responses against scanner rules and records findings when conditions match\.

**Remediation:**
Validate the relevant input and use safe APIs or restrictive configuration\.

**Limitations:**
実行可能な要求と観測可能な状態差の範囲に限られます。

**Prerequisites:**

- `second_request`

**Declared carriers and status:**

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

**References:**

- CWE 362\.html — `https://cwe.mitre.org/data/definitions/362.html`

## request\_smuggling

**Check:** RequestSmugglingScanner

**Category:** proto

**Name:**
Http request boundary interpretation differences

**Summary:**
HTTP request boundary interpretation differences

**What is tested:**
It examines responses to HTTP framing header probes\.

**Risk if vulnerable:**
Exploitation of http request boundary interpretation differences may expose sensitive data, alter data, or affect users or services\.

**Verification:**
It evaluates probe responses against scanner rules and records findings when conditions match\.

**Remediation:**
Validate the relevant input and use safe APIs or restrictive configuration\.

**Limitations:**
Coverage is limited to inspected inputs/pages and observable responses; untested or unobservable paths are not shown to be safe\.

**Prerequisites:**

- `second_request`

**Declared carriers and status:**

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

**References:**

- CWE 444\.html — `https://cwe.mitre.org/data/definitions/444.html`

## secret\_leak

**Check:** SecretLeakScanner

**Category:** proto

**Name:**
Secret\-like strings in page resources

**Summary:**
Secret\-like strings in page resources

**What is tested:**
It pattern\-matches text from retrieved page resources\.

**Risk if vulnerable:**
Exploitation of secret\-like strings in page resources may expose sensitive data, alter data, or affect users or services\.

**Verification:**
It compares retrieved pages, responses, or lookup results with implemented decision rules\.

**Remediation:**
Validate the relevant input and use safe APIs or restrictive configuration\.

**Limitations:**
Coverage is limited to inspected inputs/pages and observable responses; untested or unobservable paths are not shown to be safe\.

**Prerequisites:**

- None declared.

**Declared carriers and status:**

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

**References:**

- OWASP WSTG\-INFO\-05 — `https://wstg.owasp.org/latest/4-Web_Application_Security_Testing/01-Information_Gathering/05-Review_Web_Page_Content_for_Information_Leakage/`

## security\_headers

**Check:** SecurityHeadersScanner

**Category:** proto

**Name:**
Http security header configuration

**Summary:**
HTTP security header configuration

**What is tested:**
It checks whether page responses include selected security headers\.

**Risk if vulnerable:**
Exploitation of http security header configuration may expose sensitive data, alter data, or affect users or services\.

**Verification:**
It compares retrieved pages, responses, or lookup results with implemented decision rules\.

**Remediation:**
Validate the relevant input and use safe APIs or restrictive configuration\.

**Limitations:**
Coverage is limited to inspected inputs/pages and observable responses; untested or unobservable paths are not shown to be safe\.

**Prerequisites:**

- None declared.

**Declared carriers and status:**

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

**References:**

- None declared.

## session

**Check:** SessionScanner

**Category:** access

**Name:**
Protection attributes on session cookies

**Summary:**
Protection attributes on session cookies

**What is tested:**
It inspects cookie attributes in the page response\.

**Risk if vulnerable:**
Exploitation of protection attributes on session cookies may expose sensitive data, alter data, or affect users or services\.

**Verification:**
It compares retrieved pages, responses, or lookup results with implemented decision rules\.

**Remediation:**
Validate the relevant input and use safe APIs or restrictive configuration\.

**Limitations:**
Coverage is limited to inspected inputs/pages and observable responses; untested or unobservable paths are not shown to be safe\.

**Prerequisites:**

- `browser`

**Declared carriers and status:**

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

**References:**

- CWE 1004\.html — `https://cwe.mitre.org/data/definitions/1004.html`
- CWE 1275\.html — `https://cwe.mitre.org/data/definitions/1275.html`
- CWE 614\.html — `https://cwe.mitre.org/data/definitions/614.html`

## sqli

**Check:** SQLiScanner

**Category:** injection

**Name:**
Sql injection

**Summary:**
SQL injection

**What is tested:**
The scanner submits dedicated inputs for sql injection and examines response content or behavior\.

**Risk if vulnerable:**
Exploitation of sql injection may expose sensitive data, alter data, or affect users or services\.

**Verification:**
It evaluates probe responses against scanner rules and records findings when conditions match\.

**Remediation:**
Use parameterized SQL queries and least\-privilege database accounts\.

**Limitations:**
Coverage is limited to inspected inputs/pages and observable responses; untested or unobservable paths are not shown to be safe\.

**Prerequisites:**

- None declared.

**Declared carriers and status:**

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

**References:**

- CWE 89\.html — `https://cwe.mitre.org/data/definitions/89.html`

## sri

**Check:** SRIScanner

**Category:** proto

**Name:**
Subresource integrity on external script references

**Summary:**
Subresource Integrity on external script references

**What is tested:**
It checks external script references and integrity attributes in HTML\.

**Risk if vulnerable:**
Exploitation of subresource integrity on external script references may expose sensitive data, alter data, or affect users or services\.

**Verification:**
It compares retrieved pages, responses, or lookup results with implemented decision rules\.

**Remediation:**
Validate the relevant input and use safe APIs or restrictive configuration\.

**Limitations:**
Coverage is limited to inspected inputs/pages and observable responses; untested or unobservable paths are not shown to be safe\.

**Prerequisites:**

- None declared.

**Declared carriers and status:**

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

**References:**

- CWE 345\.html — `https://cwe.mitre.org/data/definitions/345.html`

## ssrf

**Check:** SSRFScanner

**Category:** proto

**Name:**
Server requests to supplied destinations

**Summary:**
Server requests to supplied destinations

**What is tested:**
The scanner submits dedicated inputs for server requests to supplied destinations and examines response content or behavior\.

**Risk if vulnerable:**
Exploitation of server requests to supplied destinations may expose sensitive data, alter data, or affect users or services\.

**Verification:**
It evaluates probe responses against scanner rules and records findings when conditions match\.

**Remediation:**
Allowlist destinations and protocols, and block requests to internal addresses\.

**Limitations:**
Detection relies on internal\-resource markers in the response body; response timing is not used as an oracle\.

**Prerequisites:**

- None declared.

**Declared carriers and status:**

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

**References:**

- CWE 918\.html — `https://cwe.mitre.org/data/definitions/918.html`

## ssti

**Check:** SSTIScanner

**Category:** injection

**Name:**
Server\-side template injection

**Summary:**
Server\-side template injection

**What is tested:**
The scanner submits dedicated inputs for server\-side template injection and examines response content or behavior\.

**Risk if vulnerable:**
Exploitation of server\-side template injection may expose sensitive data, alter data, or affect users or services\.

**Verification:**
It evaluates probe responses against scanner rules and records findings when conditions match\.

**Remediation:**
Validate the relevant input and use safe APIs or restrictive configuration\.

**Limitations:**
Coverage is limited to inspected inputs/pages and observable responses; untested or unobservable paths are not shown to be safe\.

**Prerequisites:**

- None declared.

**Declared carriers and status:**

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

**References:**

- CWE 1336\.html — `https://cwe.mitre.org/data/definitions/1336.html`

## stored\_xss

**Check:** StoredXSSScanner

**Category:** xss

**Name:**
Script execution after stored content is displayed

**Summary:**
Script execution after stored content is displayed

**What is tested:**
The scanner submits dedicated inputs for script execution after stored content is displayed and examines response content or behavior\.

**Risk if vulnerable:**
Exploitation of script execution after stored content is displayed may expose sensitive data, alter data, or affect users or services\.

**Verification:**
It evaluates probe responses against scanner rules and records findings when conditions match\.

**Remediation:**
Validate the relevant input and use safe APIs or restrictive configuration\.

**Limitations:**
保存と再表示が実際に行われる経路に限られます。

**Prerequisites:**

- None declared.

**Declared carriers and status:**

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

**References:**

- CWE 79\.html — `https://cwe.mitre.org/data/definitions/79.html`

## tls\_scan

**Check:** TlsConfigScanner

**Category:** proto

**Name:**
Protocols and settings observable over tls

**Summary:**
Protocols and settings observable over TLS

**What is tested:**
It inspects TLS connection settings\.

**Risk if vulnerable:**
Exploitation of protocols and settings observable over tls may expose sensitive data, alter data, or affect users or services\.

**Verification:**
It compares retrieved pages, responses, or lookup results with implemented decision rules\.

**Remediation:**
Validate the relevant input and use safe APIs or restrictive configuration\.

**Limitations:**
プロキシまたはクライアント証明書が必要な接続は検査できない場合があります。

**Prerequisites:**

- None declared.

**Declared carriers and status:**

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

**References:**

- CWE 326\.html — `https://cwe.mitre.org/data/definitions/326.html`

## transport\_security

**Check:** TransportSecurityScanner

**Category:** proto

**Name:**
Http method responses and https transport behavior

**Summary:**
HTTP method responses and HTTPS transport behavior

**What is tested:**
It observes read\-only HTTP method and HTTPS redirect responses\.

**Risk if vulnerable:**
Exploitation of http method responses and https transport behavior may expose sensitive data, alter data, or affect users or services\.

**Verification:**
It compares retrieved pages, responses, or lookup results with implemented decision rules\.

**Remediation:**
Validate the relevant input and use safe APIs or restrictive configuration\.

**Limitations:**
Coverage is limited to inspected inputs/pages and observable responses; untested or unobservable paths are not shown to be safe\.

**Prerequisites:**

- None declared.

**Declared carriers and status:**

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

**References:**

- CWE 319\.html — `https://cwe.mitre.org/data/definitions/319.html`

## websocket

**Check:** WebSocketScanner

**Category:** proto

**Name:**
Websocket connections and message handling

**Summary:**
WebSocket connections and message handling

**What is tested:**
It examines message responses on detected WebSocket routes\.

**Risk if vulnerable:**
Exploitation of websocket connections and message handling may expose sensitive data, alter data, or affect users or services\.

**Verification:**
It evaluates probe responses against scanner rules and records findings when conditions match\.

**Remediation:**
Validate the relevant input and use safe APIs or restrictive configuration\.

**Limitations:**
Coverage is limited to inspected inputs/pages and observable responses; untested or unobservable paths are not shown to be safe\.

**Prerequisites:**

- None declared.

**Declared carriers and status:**

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

**References:**

- None declared.

## xss

**Check:** XSSScanner

**Category:** xss

**Name:**
Reflected cross\-site scripting

**Summary:**
Reflected cross\-site scripting

**What is tested:**
The scanner submits dedicated inputs for reflected cross\-site scripting and examines response content or behavior\.

**Risk if vulnerable:**
Exploitation of reflected cross\-site scripting may expose sensitive data, alter data, or affect users or services\.

**Verification:**
It evaluates probe responses against scanner rules and records findings when conditions match\.

**Remediation:**
Use context\-aware output encoding and framework auto\-escaping\.

**Limitations:**
Coverage is limited to inspected inputs/pages and observable responses; untested or unobservable paths are not shown to be safe\.

**Prerequisites:**

- None declared.

**Declared carriers and status:**

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

**References:**

- CWE 79\.html — `https://cwe.mitre.org/data/definitions/79.html`

## xxe

**Check:** XXEScanner

**Category:** header

**Name:**
External entity processing in xml input

**Summary:**
External entity processing in XML input

**What is tested:**
The scanner submits dedicated inputs for external entity processing in xml input and examines response content or behavior\.

**Risk if vulnerable:**
Exploitation of external entity processing in xml input may expose sensitive data, alter data, or affect users or services\.

**Verification:**
It evaluates probe responses against scanner rules and records findings when conditions match\.

**Remediation:**
Disable external entities and DOCTYPE processing in the XML parser\.

**Limitations:**
XMLを受理する到達可能な入力が必要で、応答に現れない外部アクセスは確定できません。

**Prerequisites:**

- None declared.

**Declared carriers and status:**

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

**References:**

- CWE 611\.html — `https://cwe.mitre.org/data/definitions/611.html`
