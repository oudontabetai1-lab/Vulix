"""レポート出力の多言語化（ja/en）。

利用者向け出力文言だけを外部化する。検出判定・Finding・severity・dedup は一切
扱わない。LLM 非依存の純粋関数 lookup で、ブラウザ/ネットワークにも
依存しないためテストしやすい。

設計の不変条件:
- 既定は ``ja``。``ja`` の出力は現行とバイト不変（既存スナップショット回帰を避ける）。
- 未訳キーは ja へフォールバックし、出力を欠落させない（空文字にしない）。
- 未知の言語コードは ja へ正規化する（壊れた設定でも安全側）。

使い方:
    from wscan.i18n import translator
    t = translator("en")
    t("report.summary.confirmed")           # => "Confirmed"
    t("report.observability.dropped", total=3)  # => "Dropped probes/waves: 3"
"""
from __future__ import annotations

from typing import Callable

# 対応言語。既定（かつ全フォールバック先）は ja。
DEFAULT_LANG = "ja"
SUPPORTED_LANGS: tuple[str, ...] = ("ja", "en")


def normalize_lang(lang: "str | None") -> str:
    """言語コードを対応言語へ正規化する（純粋）。

    未知/空/None は既定（ja）へ倒す。``en-US`` のような地域付きタグは主サブタグで
    判定する。設定ミスでレポートが壊れるより、現行挙動（ja）へ落ちる方が安全。
    """
    if not lang:
        return DEFAULT_LANG
    code = str(lang).strip().lower().replace("_", "-")
    if not code:
        return DEFAULT_LANG
    if code in SUPPORTED_LANGS:
        return code
    primary = code.split("-", 1)[0]
    if primary in SUPPORTED_LANGS:
        return primary
    return DEFAULT_LANG


# ── 文言カタログ ──────────────────────────────────────────────────────────
# ja は現行コードの文言をそのまま保持する（バイト不変の単一の真実）。
# en は英訳。未訳キーは _MESSAGES["en"] に無いだけで ja が使われる。
_MESSAGES: dict[str, dict[str, str]] = {
    "ja": {
        # ── 共通ラベル ──
        "report.lang.html": "ja",
        "report.summary.confirmed": "確証 (Confirmed)",
        "report.summary.hypothesis": "未確証 (Hypothesis)",
        # ── URL パネル ──
        "report.url.status.vuln": "発見あり",
        "report.url.status.done": "完了",
        "report.url.filter.placeholder": "URL でフィルタ…",
        "report.url.tab.all": "すべて",
        "report.url.tab.vuln": "発見あり",
        "report.url.tab.done": "完了",
        # ── Finding バッジ ──
        "report.badge.confidence.confirmed": "✔ 確認済",
        "report.badge.confidence.likely": "〜 可能性高",
        "report.badge.confidence.tentative": "? 暫定",
        "report.badge.diff.new": "🆕 新規",
        "report.badge.diff.persistent": "🔄 継続",
        "report.badge.agent": "🤖 Agent発見（LLM独自解釈）",
        "report.badge.agent.unconfirmed": "🤖 Agent発見（LLM独自解釈・未確証）",
        "report.badge.agent.verified": "✅ 決定論的にも再現確認済み",
        "report.badge.confirmed": "✅ 確証",
        "report.badge.assumed": "〜 推定（再検証未実行）",
        "report.badge.unconfirmed": "⚠ 要確認",
        "report.badge.unconfirmed.title": "未確証: {note}",
        "report.badge.needs_manual": "⚠ 要手動確認",
        "report.badge.needs_manual.title": "group 内に未再検証(assumed)の経路あり。修正前に再現を確認",
        # ── 修正ガイダンス見出し ──
        "report.fix.heading.ai": "🤖 AI 推奨修正 (AI Fix Suggestion)",
        "report.fix.heading.static": "🛠️ 推奨修正 (静的ガイダンス)",
        # ── Attack Plan ──
        "report.plan.payloads.show": "▼ LLMペイロードを表示",
        "report.plan.payloads.show_count": "▼ LLMペイロードを表示 ({count}件)",
        "report.plan.payloads.hide": "▲ ペイロードを隠す",
        "report.plan.note": (
            "巡回完了後に LLM / ヒューリスティックが生成した攻撃プランです。\n"
            "            リスクスコアが高いフィールドを優先的に攻撃しました。\n"
            '            <strong style="color:#553c9a">⚠ Cross-page</strong> '
            "は格納型 XSS や別ページへの影響が疑われるフィールドを示します。"
        ),
        # ── サイトマップ（画面遷移図） ──
        "report.sitemap.pill": "画面遷移図",
        "report.sitemap.search": "検索…",
        "report.sitemap.mode.compact": "コンパクト",
        "report.sitemap.mode.shots": "スクショ",
        "report.sitemap.mode.explorer": "一覧",
        "report.sitemap.expand_all": "全展開",
        "report.sitemap.collapse_all": "全折りたたみ",
        "report.sitemap.legend.done": "完了",
        "report.sitemap.legend.vuln": "検出",
        "report.sitemap.hint": (
            "コンパクト=ツリー / スクショ=画面サムネにクリック箇所を表示 / 一覧=ツリー+詳細\n"
            "            · 矢印のラベル=クリックした要素 · ホイールでズーム / ドラッグでパン"
        ),
        # サイトマップ JS 内で使うラベル（JSON で JS へ渡す）
        "report.sitemap.js.pages": " ページ",
        "report.sitemap.js.click_path": "クリック箇所： ",
        "report.sitemap.js.origin": "（起点）",
        "report.sitemap.js.click_spot": "クリック箇所",
        "report.sitemap.js.click_offscreen": "クリック箇所はスクショ範囲外（端に表示）",
        "report.sitemap.js.clicked_element": "押した要素：",
        "report.sitemap.js.no_text": "(テキスト無し)",
        "report.sitemap.js.selector": "セレクタ：",
        "report.sitemap.js.url": "URL：",
        "report.sitemap.js.status": "状態：",
        "report.sitemap.js.open_this_page": "このページを開く ↗",
        "report.sitemap.js.open_page": "ページを開く ↗",
        "report.sitemap.js.close": "閉じる",
        # ── Observability ──
        "report.observability.heading": "Observability（観測性メトリクス）",
        "report.observability.dropped": "劣化・脱落した probe/wave: <strong>{total}</strong> 件",
        "report.observability.llm_calls": "LLM 呼び出し: <strong>{count}</strong> 件（詳細は llm_calls.jsonl）",
        "report.observability.warning": "0 findings は「安全」を意味しない可能性があります。",
        "report.observability.samples": "代表サンプル",
        "report.common.none": "なし",
        # ── Coverage ──
        "report.coverage.heading": "Coverage（到達性カバレッジ）",
        "report.coverage.summary": (
            "到達 URL: <strong>{reached}</strong> 件 / 試行: <strong>{attempts}</strong> 件 /\n"
            "            Findings: <strong>{findings}</strong> 件"
        ),
        "report.coverage.by_status": "試行結果（by_status）",
        "report.coverage.reached": "到達済み URL",
        "report.coverage.unreached": "未到達 URL",
        "report.coverage.blocked_warning": (
            "{blocked} 件が 403/429 でブロック＝WAF/レート制限により攻撃面を"
            "十分に検査できていない可能性があります"
        ),
        "report.coverage.check.heading": "検査カバレッジ（in-scope の scanner）",
        "report.coverage.check.summary": (
            "検査対象: <strong>{selected}</strong> / <strong>{total}</strong> 種類 "
            "(<strong>{status}</strong>)"
        ),
        "report.coverage.check.warning": (
            "登録 scanner の一部のみが検査対象です。未実行の検査があるため、"
            "Findings が 0 でも「安全」とは限りません。"
        ),
        "report.coverage.check.unknown": "設定に未知の検査名（誤記の可能性）があり無視されました: {names}",
        "report.coverage.check.not_selected": "未実行（未選択）の検査: {names}",
        "report.coverage.prereq.heading": "実行条件が満たされない検査",
        "report.coverage.prereq.note": (
            "以下の検査は選択されていますが、前提（認証・OOB・API 仕様・"
            "複数アカウント等）の未設定、または state profile による状態変更検査の skip のため、"
            "実質的に検査できていない可能性があります。Findings が 0 でも「安全」とは限りません。"
        ),
        "report.coverage.prereq.kind.missing": "前提不足",
        "report.coverage.prereq.kind.state_profile": "state profile",
        "report.coverage.table.check": "検査",
        "report.coverage.table.kind": "種別",
        "report.coverage.table.reason": "理由",
        # ── Executive レポート ──
        "report.exec.checks_count": "検査項目: {count} 種",
        "report.exec.agent_label": "🤖 Agent発見（LLM独自解釈）",
        "report.exec.agent_breakdown": "確証: {confirmed} / 未確証: {unconfirmed}",
        "report.exec.owasp_heading": "OWASP Top 10 違反 (上位5件)",
        "report.exec.pci_heading": "PCI DSS 違反 (上位5件)",
        "report.exec.no_violation": "違反なし",
        "report.exec.count_suffix": "{count}件",
        "report.exec.recommendations": "推奨事項",
        "report.exec.rec.critical": "【緊急】クリティカルな脆弱性が検出されました。即時修正が必要です。",
        "report.exec.rec.high": "【高】高リスクの脆弱性が検出されました。速やかな対応を推奨します。",
        "report.exec.rec.headers": "セキュリティヘッダ (CSP, HSTS, X-Frame-Options) の設定を確認してください。",
        "report.exec.rec.pentest": "定期的なペネトレーションテストの実施を推奨します。",
        "report.exec.scope_heading": "スキャン範囲",
        "report.exec.scope_body": "{pages} ページを検査 / 検査項目: {checks}",
        "report.exec.diff_heading": "差分スキャン結果",
        "report.exec.diff_body": (
            "🆕 新規: <b>{new}</b> 件 /\n"
            "                    ✅ 修正済: <b>{fixed}</b> 件 /\n"
            "                    🔄 継続: <b>{persistent}</b> 件"
        ),
        # ── Developer レポート ──
        "report.dev.subtitle": "確証 {confirmed} 件 / 未確証 {hypothesis} 件",
        "report.dev.confidence": "信頼度: {confidence}",
        "report.dev.fix_label": "修正ガイダンス:",
        "report.dev.diff_bar": "🆕 新規 {new} / ✅ 修正済 {fixed} / 🔄 継続 {persistent}",
        "report.dev.intro": "各項目をクリックして詳細を展開してください。チェックボックスで修正完了を記録できます。",
        "report.dev.no_findings": "✓ 検出された脆弱性はありません。",
        # ── SARIF ──
        "sarif.fallback.remediation": "{check} の適切な入力検証と出力エスケープを実施してください。",
        "report.matrix.supported": "supported（宣言のみ・E2E 未接続）",
        "report.matrix.heading": "Scanner capability matrix（in-scope の scanner × carrier）",
        "report.matrix.legend": "凡例: ",
        "report.matrix.hint": "セル記号の詳細（value_kinds/transports/理由）は各セルにマウスを重ねると表示されます。",
        # ── remediation（静的ガイダンスの汎用フォールバック ──
        "remediation.generic": (
            "**{check} 対策**\n"
            "脆弱性の詳細を確認し、入力値の検証・出力のエスケープ・最小権限原則を適用してください。"
        ),
    },
    "en": {
        # ── Common labels ──
        "report.lang.html": "en",
        "report.summary.confirmed": "Confirmed",
        "report.summary.hypothesis": "Hypothesis",
        # ── URL panel ──
        "report.url.status.vuln": "Findings",
        "report.url.status.done": "Done",
        "report.url.filter.placeholder": "Filter by URL…",
        "report.url.tab.all": "All",
        "report.url.tab.vuln": "Findings",
        "report.url.tab.done": "Done",
        # ── Finding badges ──
        "report.badge.confidence.confirmed": "✔ Confirmed",
        "report.badge.confidence.likely": "〜 Likely",
        "report.badge.confidence.tentative": "? Tentative",
        "report.badge.diff.new": "🆕 New",
        "report.badge.diff.persistent": "🔄 Persistent",
        "report.badge.agent": "🤖 Agent finding (LLM interpretation)",
        "report.badge.agent.unconfirmed": "🤖 Agent finding (LLM interpretation, unconfirmed)",
        "report.badge.agent.verified": "✅ Also reproduced deterministically",
        "report.badge.confirmed": "✅ Confirmed",
        "report.badge.assumed": "〜 Assumed (not re-verified)",
        "report.badge.unconfirmed": "⚠ Needs review",
        "report.badge.unconfirmed.title": "Unconfirmed: {note}",
        "report.badge.needs_manual": "⚠ Needs manual review",
        "report.badge.needs_manual.title": (
            "This group contains an assumed (not re-verified) path. "
            "Reproduce it before applying a fix."
        ),
        # ── Remediation headings ──
        "report.fix.heading.ai": "🤖 AI Fix Suggestion",
        "report.fix.heading.static": "🛠️ Recommended Fix (static guidance)",
        # ── Attack plan ──
        "report.plan.payloads.show": "▼ Show LLM payloads",
        "report.plan.payloads.show_count": "▼ Show LLM payloads ({count})",
        "report.plan.payloads.hide": "▲ Hide payloads",
        "report.plan.note": (
            "Attack plan generated by the LLM / heuristics after crawling.\n"
            "            Fields with a higher risk score were attacked first.\n"
            '            <strong style="color:#553c9a">⚠ Cross-page</strong> '
            "marks fields suspected of stored XSS or impact on other pages."
        ),
        # ── Site map ──
        "report.sitemap.pill": "Screen flow",
        "report.sitemap.search": "Search…",
        "report.sitemap.mode.compact": "Compact",
        "report.sitemap.mode.shots": "Screenshots",
        "report.sitemap.mode.explorer": "Explorer",
        "report.sitemap.expand_all": "Expand all",
        "report.sitemap.collapse_all": "Collapse all",
        "report.sitemap.legend.done": "Done",
        "report.sitemap.legend.vuln": "Findings",
        "report.sitemap.hint": (
            "Compact = tree / Screenshots = thumbnails with the clicked spot / "
            "Explorer = tree + detail\n"
            "            · Arrow labels = clicked element · Wheel to zoom / drag to pan"
        ),
        "report.sitemap.js.pages": " pages",
        "report.sitemap.js.click_path": "Clicked: ",
        "report.sitemap.js.origin": " (entry point)",
        "report.sitemap.js.click_spot": "Clicked spot",
        "report.sitemap.js.click_offscreen": "Clicked spot is outside the screenshot (shown at the edge)",
        "report.sitemap.js.clicked_element": "Clicked element: ",
        "report.sitemap.js.no_text": "(no text)",
        "report.sitemap.js.selector": "Selector: ",
        "report.sitemap.js.url": "URL: ",
        "report.sitemap.js.status": "Status: ",
        "report.sitemap.js.open_this_page": "Open this page ↗",
        "report.sitemap.js.open_page": "Open page ↗",
        "report.sitemap.js.close": "Close",
        # ── Observability ──
        "report.observability.heading": "Observability",
        "report.observability.dropped": "Degraded / dropped probes and waves: <strong>{total}</strong>",
        "report.observability.llm_calls": "LLM calls: <strong>{count}</strong> (details in llm_calls.jsonl)",
        "report.observability.warning": "0 findings does not necessarily mean the target is safe.",
        "report.observability.samples": "Representative samples",
        "report.common.none": "none",
        # ── Coverage ──
        "report.coverage.heading": "Coverage (reachability)",
        "report.coverage.summary": (
            "Reached URLs: <strong>{reached}</strong> / Attempts: <strong>{attempts}</strong> /\n"
            "            Findings: <strong>{findings}</strong>"
        ),
        "report.coverage.by_status": "Attempt results (by_status)",
        "report.coverage.reached": "Reached URLs",
        "report.coverage.unreached": "Unreached URLs",
        "report.coverage.blocked_warning": (
            "{blocked} request(s) were blocked with 403/429 — a WAF or rate limit may have "
            "prevented sufficient coverage of the attack surface."
        ),
        "report.coverage.check.heading": "Check coverage (in-scope scanners)",
        "report.coverage.check.summary": (
            "In scope: <strong>{selected}</strong> / <strong>{total}</strong> check types "
            "(<strong>{status}</strong>)"
        ),
        "report.coverage.check.warning": (
            "Only a subset of the registered scanners is in scope. Some checks were not run, "
            "so 0 findings does not mean the target is safe."
        ),
        "report.coverage.check.unknown": (
            "Unknown check name(s) in the configuration (possible typo) were ignored: {names}"
        ),
        "report.coverage.check.not_selected": "Checks not run (not selected): {names}",
        "report.coverage.prereq.heading": "Checks whose prerequisites are unmet",
        "report.coverage.prereq.note": (
            "The checks below are selected, but their prerequisites (authentication, OOB, API "
            "specification, multiple accounts, etc.) are not configured, or state-changing checks "
            "were skipped by the state profile. They may not have been effectively exercised, "
            "so 0 findings does not mean the target is safe."
        ),
        "report.coverage.prereq.kind.missing": "prerequisite missing",
        "report.coverage.prereq.kind.state_profile": "state profile",
        "report.coverage.table.check": "Check",
        "report.coverage.table.kind": "Kind",
        "report.coverage.table.reason": "Reason",
        # ── Executive report ──
        "report.exec.checks_count": "Checks: {count}",
        "report.exec.agent_label": "🤖 Agent findings (LLM interpretation)",
        "report.exec.agent_breakdown": "Confirmed: {confirmed} / Unconfirmed: {unconfirmed}",
        "report.exec.owasp_heading": "OWASP Top 10 violations (top 5)",
        "report.exec.pci_heading": "PCI DSS violations (top 5)",
        "report.exec.no_violation": "No violations",
        "report.exec.count_suffix": "{count}",
        "report.exec.recommendations": "Recommendations",
        "report.exec.rec.critical": (
            "[URGENT] Critical vulnerabilities were detected. Immediate remediation is required."
        ),
        "report.exec.rec.high": (
            "[HIGH] High-risk vulnerabilities were detected. Prompt remediation is recommended."
        ),
        "report.exec.rec.headers": (
            "Review the security header configuration (CSP, HSTS, X-Frame-Options)."
        ),
        "report.exec.rec.pentest": "Regular penetration testing is recommended.",
        "report.exec.scope_heading": "Scan scope",
        "report.exec.scope_body": "{pages} page(s) scanned / Checks: {checks}",
        "report.exec.diff_heading": "Diff scan result",
        "report.exec.diff_body": (
            "🆕 New: <b>{new}</b> /\n"
            "                    ✅ Fixed: <b>{fixed}</b> /\n"
            "                    🔄 Persistent: <b>{persistent}</b>"
        ),
        # ── Developer report ──
        "report.dev.subtitle": "Confirmed {confirmed} / Hypothesis {hypothesis}",
        "report.dev.confidence": "Confidence: {confidence}",
        "report.dev.fix_label": "Remediation guidance:",
        "report.dev.diff_bar": "🆕 New {new} / ✅ Fixed {fixed} / 🔄 Persistent {persistent}",
        "report.dev.intro": (
            "Click an item to expand the details. Use the checkbox to record that a fix is done."
        ),
        "report.dev.no_findings": "✓ No vulnerabilities were detected.",
        # ── SARIF ──
        "sarif.fallback.remediation": (
            "Apply proper input validation and output escaping for {check}."
        ),
        # ── remediation generic fallback ──
        "remediation.generic": (
            "**{check} countermeasures**\n"
            "Review the vulnerability details and apply input validation, output escaping, "
            "and the principle of least privilege."
        ),
    },
}


# SARIF の説明と静的修正案。証拠や機械可読の識別子は翻訳しない。
_MESSAGES["en"].update({
    "report.matrix.supported": "supported (declared only; not connected to E2E)",
    "report.matrix.heading": "Scanner capability matrix (in-scope scanners × carriers)",
    "report.matrix.legend": "Legend: ",
    "report.matrix.hint": "Hover over each cell for value kinds, transports and reasons.",
    "sarif.rule.sqli": "SQL injection — user input is injected into SQL queries",
    "sarif.rule.sqli_auth_bypass": "SQL injection — authentication bypass",
    "sarif.rule.xss": "Reflected cross-site scripting — injected scripts execute in the response",
    "sarif.rule.dom_xss": "DOM-based XSS — unsafe client-side DOM operations",
    "sarif.rule.stored_xss": "Stored XSS — persisted scripts affect other users",
    "sarif.rule.os": "OS command injection — server-side commands can be executed",
    "sarif.rule.ssti": "Server-side template injection",
    "sarif.rule.path_traversal": "Path traversal — files outside the allowed directory can be read",
    "sarif.rule.open_redirect": "Open redirect — redirection to arbitrary URLs",
    "sarif.rule.csrf": "CSRF — unintended requests can be sent on behalf of an authenticated user",
    "sarif.rule.cors": "CORS misconfiguration — cross-origin requests from untrusted origins",
    "sarif.rule.header_injection": "HTTP header injection / response splitting",
    "sarif.rule.mail_header": "Mail header injection",
    "sarif.rule.clickjacking": "Clickjacking — missing frame protection",
    "sarif.rule.session": "Session management issues — insecure cookie attributes",
    "sarif.rule.privesc": "Privilege escalation — unauthorized access to privileged resources",
    "sarif.rule.ssrf": "SSRF — server-side requests to internal resources",
    "sarif.rule.xxe": "XXE — information disclosure through XML external entities",
    "sarif.rule.deserialization": "Insecure deserialization",
    "sarif.rule.request_smuggling": "HTTP request smuggling",
    "sarif.rule.host_header": "Host header injection",
    "sarif.rule.security_headers": "Missing security headers",
    "sarif.rule.info_disclosure": "Information disclosure — error messages or version information",
    "sarif.rule.nosql": "NoSQL injection",
    "sarif.rule.graphql": "GraphQL vulnerabilities — introspection or injection",
    "sarif.rule.jwt": "JWT vulnerabilities — insecure algorithms or weak signing keys",
    "sarif.rule.ldap": "LDAP injection",
    "sarif.rule.file_upload": "Insecure file upload",
    "sarif.rule.race_condition": "Race condition (TOCTOU)",
    "sarif.rule.cms": "CMS-specific vulnerabilities",
    "sarif.rule.websocket": "WebSocket injection",
    "remediation.sqli": "Use parameterized queries; never concatenate user input into SQL. Grant the database account only the permissions it needs.",
    "remediation.xss": "Apply context-aware output encoding and framework auto-escaping. Sanitize allowed HTML and use a restrictive Content-Security-Policy.",
    "remediation.dom_xss": "Use textContent instead of innerHTML for untrusted data. Avoid eval and sanitize any HTML that must be rendered.",
    "remediation.stored_xss": "Validate stored input and encode it for the output context on every rendering path. Sanitize allowed HTML.",
    "remediation.os": "Avoid shell execution. Pass arguments as a list with shell=False, validate inputs with an allowlist, and use least privilege.",
    "remediation.ssti": "Keep user input out of template source. Pass it as template data, use auto-escaping, and restrict template capabilities.",
    "remediation.path_traversal": "Resolve and decode paths before verifying they stay inside the allowed base directory. Allowlist file names rather than stripping ../ alone.",
    "remediation.open_redirect": "Use server-controlled redirect destinations or validate them against an allowlist. Reject untrusted external destinations.",
    "remediation.csrf": "Require unpredictable CSRF tokens for state-changing requests. Set SameSite cookies and validate Origin/Referer.",
    "remediation.cors": "Allowlist trusted origins. Do not enable credentialed cross-origin access for untrusted origins.",
    "remediation.header_injection": "Reject CR and LF in header values. Use framework header APIs and validate inputs.",
    "remediation.clickjacking": "Configure CSP frame-ancestors and X-Frame-Options to restrict framing to trusted sites.",
    "remediation.session": "Set Secure, HttpOnly and SameSite cookie attributes. Rotate session IDs at login and invalidate sessions at logout.",
    "remediation.privesc": "Enforce authorization on every server-side action and object access. Verify ownership and role permissions; do not trust client-supplied IDs or roles.",
    "remediation.info_disclosure": "Hide detailed errors and version information from clients. Keep diagnostic details in protected server logs.",
    "remediation.security_headers": "Configure CSP, HSTS, X-Content-Type-Options, frame protection and Referrer-Policy as appropriate for the application.",
    "remediation.nosql": "Validate input types and reject user-supplied query operators. Build queries through safe driver APIs.",
    "remediation.deserialization": "Avoid deserializing untrusted objects. Use safe data formats, validate schemas and authenticate serialized data.",
    "remediation.request_smuggling": "Ensure proxies and backends agree on HTTP message framing. Reject ambiguous Content-Length/Transfer-Encoding combinations and update servers.",
    "remediation.ssrf": "Allowlist outbound destinations and protocols. Block private, loopback and link-local addresses after DNS resolution and on redirects.",
    "remediation.graphql": "Restrict introspection where appropriate, authorize each resolver, use safe query APIs and enforce query complexity limits.",
    "remediation.jwt": "Allowlist secure signing algorithms, verify signatures and claims, use strong keys and reject unsigned tokens.",
    "remediation.cms": "Update the CMS, plugins and themes. Remove unused components, restrict administration and review access controls.",
})


def translate(key: str, lang: str = DEFAULT_LANG, /, **params) -> str:
    """キーに対応する文言を返す（純粋）。

    未訳キーは ja へ、ja にも無ければキー自体を返す（出力を欠落させない）。
    ``params`` を渡すと ``str.format`` で差し込む。format が失敗しても落とさず
    素のテンプレートを返す（レポート生成を壊さないため）。
    """
    code = normalize_lang(lang)
    template = _MESSAGES.get(code, {}).get(key)
    if template is None and code != DEFAULT_LANG:
        # 未訳キーは既定言語へフォールバック（欠落させない）。
        template = _MESSAGES[DEFAULT_LANG].get(key)
    if template is None:
        # カタログに無いキーはキー文字列をそのまま返す（デバッグ可能・空にしない）。
        return key
    if not params:
        return template
    try:
        return template.format(**params)
    except (KeyError, IndexError, ValueError):
        return template


def translator(lang: str = DEFAULT_LANG) -> Callable[..., str]:
    """言語を束縛した lookup を返す（レポート生成側は ``t("key", **params)`` で使う）。"""
    code = normalize_lang(lang)

    def _t(key: str, **params) -> str:
        return translate(key, code, **params)

    return _t


def available_keys(lang: str = DEFAULT_LANG) -> list[str]:
    """指定言語のカタログに存在するキー一覧（テスト/検証用・純粋）。"""
    return sorted(_MESSAGES.get(normalize_lang(lang), {}))


def untranslated_keys(lang: str) -> list[str]:
    """ja にあって指定言語に無いキー（＝ja へフォールバックするキー）を返す。"""
    code = normalize_lang(lang)
    if code == DEFAULT_LANG:
        return []
    return sorted(set(_MESSAGES[DEFAULT_LANG]) - set(_MESSAGES.get(code, {})))
