"""
Flow Recorder / Replayer
========================
Playwright のナビゲーション・フォーム送信を JSON ステップとして記録し、
記録した手順を再生してペイロードを注入する。

シナリオ記録/再生により、ログイン後や複数画面にまたがる操作を再利用する。

記録コマンド:
    python main.py record --output flows/login_flow.json http://example.com/login

再生 (エンジン内部から呼び出し):
    from wscan.flow_recorder import FlowRecorder
    recorder = FlowRecorder()
    html, pair = await recorder.replay_with_payloads(steps, "bio", "<script>alert(1)</script>", browser)

ステップ形式 (JSON):
    [
      {"action": "navigate", "url": "http://example.com/login"},
      {"action": "fill",     "selector": "#username", "value": "admin"},
      {"action": "fill",     "selector": "#password", "value": "password"},
      {"action": "click",    "selector": "button[type=submit]"},
      {"action": "fill_inject", "selector": "#bio", "field_name": "bio"}
    ]

"fill_inject" ステップが payload 注入ポイント。
"""
from __future__ import annotations

import asyncio
import json
import secrets
import time
from pathlib import Path
from typing import Optional


class FlowRecorder:
    """Playwright 操作を JSON ステップとして記録・再生する。"""

    def __init__(self):
        self._steps: list[dict] = []

    # ──────────────────────────────────────────────────────────────────────────
    # Recording
    # ──────────────────────────────────────────────────────────────────────────

    async def record_interactive(
        self,
        start_url: str,
        output_path: str,
        headless: bool = False,
    ) -> list[dict]:
        """
        非ヘッドレスで Playwright を起動し、ユーザー操作を記録する。
        Ctrl+C で記録終了 → JSON 保存。

        Returns
        -------
        記録されたステップのリスト
        """
        from playwright.async_api import async_playwright

        print(f"[FlowRecorder] 記録開始: {start_url}")
        print("[FlowRecorder] 操作を行い、終了したら Ctrl+C を押してください。")
        steps: list[dict] = [{"action": "navigate", "url": start_url}]

        async with async_playwright() as pw:
            browser = await pw.chromium.launch(headless=headless)
            page = await browser.new_page()

            # ナビゲーション追跡。初期 goto（steps[0] と重複）だけを除き、いったん離れて
            # start_url へ**戻ってきた**遷移は記録する。全 start_url 遷移を潰すと、最後の
            # navigate が中間ページのままになり _match_pre_attack_flows が誤ったページへ flow を
            # 適用してしまう（Codex #170 P2）。
            _initial_load = {"seen": False}

            def on_navigate(frame):
                if frame != page.main_frame:
                    return
                url = frame.url
                if not url or url == "about:blank":
                    return
                # 最初の main-frame ナビゲーション（初期 goto）は steps[0] と重複するので新規
                # append しない。ただし初期 goto が別 scheme/host/path へ **redirect** した場合は、
                # 実着地 URL を steps[0] に反映する。さもないと最後の navigate が pre-redirect の
                # start_url のままになり _match_pre_attack_flows が crawl 済み着地ページと結び付けられ
                # ない／最終 target チェックで弾かれる（Codex #170 P2）。
                if not _initial_load["seen"]:
                    _initial_load["seen"] = True
                    if url != start_url and steps and steps[0].get("action") == "navigate":
                        steps[0]["url"] = url  # 初期 redirect の実着地を初期 step に反映
                    return
                steps.append({"action": "navigate", "url": url})

            page.on("framenavigated", on_navigate)

            # フォーム送信の追跡 (input change)
            # Use random token in function names so malicious page JS cannot
            # inject fake steps by calling the predictable global names.
            _tok = secrets.token_hex(12)
            _fn_fill = f"__wscan_fill_{_tok}__"
            _fn_click = f"__wscan_click_{_tok}__"
            _fn_notify = f"__wscan_notify_{_tok}__"

            await page.expose_function(_fn_fill, lambda selector, value: steps.append(
                {"action": "fill", "selector": selector, "value": value}
            ))
            await page.expose_function(_fn_click, lambda selector: steps.append(
                {"action": "click", "selector": selector}
            ))
            # ページ側の警告（file input skip 等）を **記録プロセスの stdout** へ出す。ページの
            # console.warn だけだと DevTools 非表示の headed recorder では操作者に届かない（Codex #170 P2）。
            await page.expose_function(
                _fn_notify, lambda message: print(f"[FlowRecorder][warn] {message}")
            )

            # ページに監視スクリプト注入
            await page.add_init_script(f"""
                // id 無し要素の一意な CSS パスを組み立てる。`button[type=submit]`（type 無しの
                // 既定 submit ボタンに一致しない）や `a`（先頭リンクを掴む）では replay が別要素を
                // click し得るため、祖先 id か nth-of-type チェーンで一意化する（Codex #170 P2）。
                const __wscanEsc = (v) => (window.CSS && CSS.escape) ? CSS.escape(v) : v;
                function __wscanPath(el) {{
                    if (el.id) return '#' + __wscanEsc(el.id);
                    const parts = [];
                    let node = el;
                    while (node && node.nodeType === 1
                           && node.tagName !== 'HTML' && node.tagName !== 'BODY') {{
                        if (node.id) {{ parts.unshift('#' + __wscanEsc(node.id)); break; }}
                        let i = 1, sib = node;
                        while ((sib = sib.previousElementSibling)) {{
                            if (sib.tagName === node.tagName) i++;
                        }}
                        parts.unshift(node.tagName.toLowerCase() + ':nth-of-type(' + i + ')');
                        node = node.parentElement;
                    }}
                    return parts.join(' > ');
                }}
                document.addEventListener('change', function(e) {{
                    const el = e.target;
                    if (el.tagName === 'INPUT' || el.tagName === 'TEXTAREA' || el.tagName === 'SELECT') {{
                        // CSS.escape で id を安全化（`user:name` 等の CSS 特殊文字が
                        // querySelector で pseudo-class 等と誤解釈され throw するのを防ぐ・#170 P2）。
                        const esc = (window.CSS && CSS.escape) ? CSS.escape(el.id) : el.id;
                        const escv = (v) => (window.CSS && CSS.escape) ? CSS.escape(v) : v;
                        // name/value は CSS.escape した**引用符なし**属性セレクタで組む。生の
                        // `[name="..."]` だと name に引用符/バックスラッシュを含むと無効セレクタになり、
                        // 通常入力は replay 不能、radio/checkbox は querySelectorAll が throw して step
                        // ごと欠落する（Codex #170 P2）。CSS.escape 出力は選択子として妥当。
                        let sel = el.id
                            ? '#' + esc
                            : (el.name ? '[name=' + escv(el.name) + ']' : __wscanPath(el));
                        // radio/checkbox は name を共有するのが普通で、[name="plan"] だけだと
                        // グループ内のどの選択肢か判別できず replay が誤って先頭を click する。
                        // id が無い場合、**明示 value 属性がグループ内で一意なとき**だけ
                        // [name][value] で弁別する。value 属性が無い（DOM の el.value は既定 "on" で
                        // 属性は不在＝そのセレクタは何にも一致しない）／同名グループで value が重複する
                        // 場合は一意な要素パスへフォールバックする（Codex #170 P2）。
                        if (!el.id && (el.type === 'radio' || el.type === 'checkbox')) {{
                            const attrVal = el.getAttribute('value');
                            let uniqueByValue = false;
                            let valueSel = '';
                            if (el.name && attrVal !== null) {{
                                valueSel = '[name=' + escv(el.name) + '][value=' + escv(attrVal) + ']';
                                let group = [];
                                try {{ group = document.querySelectorAll(valueSel); }} catch (e) {{ group = []; }}
                                uniqueByValue = (group.length === 1);
                            }}
                            sel = uniqueByValue ? valueSel : __wscanPath(el);
                        }}
                        // checkbox/radio は value ではなく checked 状態が本質。fill は value を
                        // 代入するだけで checked を変えず、規約同意等の前提を再現できない。click で
                        // 相互作用そのものを記録・再現する（#170 P2）。
                        if (el.type === 'checkbox' || el.type === 'radio') {{
                            if (typeof window['{_fn_click}'] === 'function') {{
                                window['{_fn_click}'](sel);
                            }}
                        }} else if (el.type === 'file') {{
                            // file input は録画しない。ブラウザは value を "C:\\fakepath\\..." で返し、
                            // replay で type=file の value 代入は InvalidStateError で拒否され flow 全体が
                            // 失敗＝ページの全検査を skip してしまう（Codex #170 P2）。skip を記録
                            // プロセスへ通知して操作者に見えるようにする（console.warn だけでは埋もれる）。
                            if (typeof window['{_fn_notify}'] === 'function') {{
                                window['{_fn_notify}']('file input はリプレイ不可のため記録しません: ' + sel);
                            }}
                        }} else if (typeof window['{_fn_fill}'] === 'function') {{
                            window['{_fn_fill}'](sel, el.value);
                        }}
                    }}
                }}, true);
                document.addEventListener('click', function(e) {{
                    // クリック対象がボタン/リンク内の子要素（アイコン span 等）でも、
                    // closest で実際の操作要素へ解決してから一意セレクタを記録する。
                    const el = e.target && e.target.closest
                        ? e.target.closest('button, a, input[type=submit], [type=submit]')
                        : null;
                    if (el) {{
                        const sel = __wscanPath(el);
                        if (typeof window['{_fn_click}'] === 'function') {{
                            window['{_fn_click}'](sel);
                        }}
                    }}
                }}, true);
            """)

            await page.goto(start_url)

            try:
                # ユーザーが Ctrl+C するまで待機
                while True:
                    await asyncio.sleep(1)
            except (KeyboardInterrupt, asyncio.CancelledError):
                pass
            finally:
                await browser.close()

        # 保存
        output = Path(output_path)
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(json.dumps(steps, ensure_ascii=False, indent=2), encoding="utf-8")
        print(f"[FlowRecorder] {len(steps)} ステップを保存: {output_path}")
        self._steps = steps
        return steps

    # ──────────────────────────────────────────────────────────────────────────
    # Loading / saving
    # ──────────────────────────────────────────────────────────────────────────

    def load(self, path: str) -> list[dict]:
        """JSON ファイルからステップを読み込む。"""
        from .textio import read_text_resilient
        p = Path(path)
        if not p.exists():
            raise FileNotFoundError(f"Flow file not found: {path}")
        steps = json.loads(read_text_resilient(p))
        self._steps = steps
        return steps

    # ──────────────────────────────────────────────────────────────────────────
    # Replay
    # ──────────────────────────────────────────────────────────────────────────

    async def replay_with_payloads(
        self,
        steps: list[dict],
        inject_field: str,
        payload: str,
        browser,
    ) -> tuple[str, dict]:
        """
        記録されたステップを再生し、inject_field の fill/fill_inject を payload に差し替える。

        Parameters
        ----------
        steps        : load() で得たステップリスト
        inject_field : ペイロードを注入するフィールド名 (field_name) または CSS セレクタ
        payload      : 注入するペイロード文字列
        browser      : BrowserManager インスタンス

        Returns
        -------
        (html_after_replay, request_response_pair)
        """
        html = ""
        pair: dict = {"request": {}, "response": {}}

        for step in steps:
            action = step.get("action", "")

            if action == "navigate":
                url = step.get("url", "")
                if url:
                    await browser.navigate(url)
                    await asyncio.sleep(0.3)

            elif action == "fill":
                selector = step.get("selector", "")
                value = step.get("value", "")
                if selector:
                    try:
                        await browser.page.fill(selector, value, timeout=5000)
                    except Exception:
                        pass

            elif action == "fill_inject":
                # ペイロード注入ポイント — field_name または selector でマッチ
                selector = step.get("selector", "")
                field_name = step.get("field_name", "")
                if field_name == inject_field or selector == inject_field:
                    if selector:
                        try:
                            await browser.page.fill(selector, payload, timeout=5000)
                        except Exception:
                            pass
                else:
                    # 他のフィールドはデフォルト値をそのまま入力
                    default_val = step.get("value", "")
                    if selector and default_val:
                        try:
                            await browser.page.fill(selector, default_val, timeout=5000)
                        except Exception:
                            pass

            elif action == "click":
                selector = step.get("selector", "")
                if selector:
                    try:
                        req_ts = time.time()
                        await browser.page.click(selector, timeout=5000)
                        await asyncio.sleep(0.5)
                        resp_ts = time.time()
                        html = await browser.page.content()
                        pair = {
                            "request": {"timestamp": req_ts, "url": browser.page.url},
                            "response": {"timestamp": resp_ts, "body": html, "status": 200},
                        }
                    except Exception:
                        pass

            elif action == "wait":
                ms = step.get("ms", 500)
                await asyncio.sleep(ms / 1000)

        # 最終状態の HTML
        try:
            html = await browser.page.content()
        except Exception:
            pass

        return html, pair

    # ──────────────────────────────────────────────────────────────────────────
    # Helper: inject_fields discovery
    # ──────────────────────────────────────────────────────────────────────────

    @staticmethod
    def get_inject_fields(steps: list[dict]) -> list[str]:
        """
        ステップリストから fill_inject ステップの field_name を収集する。
        スキャンエンジンがどのフィールドにペイロードを注入すべきか確認する際に使用。
        """
        return [
            s.get("field_name") or s.get("selector", "")
            for s in steps
            if s.get("action") == "fill_inject"
        ]
