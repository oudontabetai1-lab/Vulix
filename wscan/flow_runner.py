"""
Attack Flow Runner
Executes multi-step attack flows defined by the operator.

A ScanFlow is a named sequence of FlowSteps that the browser executes before
the scanner attacks a target page.  This enables scenarios such as:
  - Login → navigate to protected page → attack
  - Add item to cart → go to checkout → attack checkout form
  - Fill search box → submit → attack result page

Supported step actions
----------------------
navigate  : navigate to ``url``
fill      : fill a form field (``field`` = name/id, ``value`` = content)
submit    : click the submit button (or call form.submit() as fallback)
click     : click an arbitrary CSS selector (``selector``)
wait      : pause for ``timeout`` seconds (useful after AJAX transitions)
"""
from __future__ import annotations

import asyncio
import math
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

from rich.console import Console
from rich.markup import escape

if TYPE_CHECKING:
    from wscan.browser import BrowserManager

console = Console()

# wait/click timeout の上限（秒）。無限大（1e309/"Infinity"）や巨大値で asyncio.sleep が返らず
# スキャン全体が停止するのを防ぐ（Codex #170 P2）。
MAX_STEP_TIMEOUT_S = 600.0


def _parse_timeout(value) -> float:
    """有限・非負・上限以内の timeout だけを受理する（純粋）。不正値は ValueError（flow を skip させる）。"""
    t = float(value)
    if not math.isfinite(t) or t < 0 or t > MAX_STEP_TIMEOUT_S:
        raise ValueError(f"flow step timeout must be finite and within 0..{MAX_STEP_TIMEOUT_S:g}s: {value!r}")
    return t


class FlowStepError(Exception):
    """前提 step の失敗（対象欄・送信先の欠落等）。run() が失敗として扱う（F10）。"""


# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------

@dataclass
class FlowStep:
    """A single step inside a ScanFlow."""
    action: str          # navigate | fill | submit | click | wait
    url: str = ""        # navigate
    field: str = ""      # fill (name or id attribute)
    value: str = ""      # fill
    selector: str = ""   # click
    timeout: float = 5.0 # wait duration (s) or click timeout (s)
    # record 時の初期 redirect の実着地 URL（照合用メタデータ・実行はしない）。
    landed_url: str = ""

    def to_dict(self) -> dict:
        d: dict = {"action": self.action}
        if self.url:      d["url"]      = self.url
        if self.field:    d["field"]    = self.field
        if self.value:    d["value"]    = self.value
        if self.selector: d["selector"] = self.selector
        if self.landed_url: d["landed_url"] = self.landed_url
        if self.action == "wait" or self.action == "click":
            d["timeout"] = self.timeout
        return d

    @classmethod
    def from_dict(cls, d: dict) -> "FlowStep":
        action = d.get("action", "navigate")
        timeout = _parse_timeout(d.get("timeout", 5.0))
        # Playwright は click の timeout=0 を「無制限」と解釈し、欠落/非 actionable な selector で
        # スキャン全体が停止する。click の 0 は既定の有界値に置き換える（wait の 0 秒は許可・Codex #170 P2）。
        if action == "click" and timeout == 0:
            timeout = 5.0
        return cls(
            action=action,
            landed_url=str(d.get("landed_url", "") or ""),
            url=d.get("url", ""),
            field=d.get("field", ""),
            value=d.get("value", ""),
            selector=d.get("selector", ""),
            timeout=timeout,
        )


@dataclass
class ScanFlow:
    """
    A named, ordered sequence of steps executed before attacking a page.

    ``name``  — human-readable label shown in the dashboard and console
    ``steps`` — list of FlowStep objects executed in order
    """
    name: str
    steps: list[FlowStep] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {"name": self.name, "steps": [s.to_dict() for s in self.steps]}

    @classmethod
    def from_dict(cls, d: dict) -> "ScanFlow":
        return cls(
            name=d.get("name", "Flow"),
            steps=[FlowStep.from_dict(s) for s in d.get("steps", [])],
        )

    @classmethod
    def list_from_dicts(cls, lst: list[dict]) -> list["ScanFlow"]:
        return [cls.from_dict(d) for d in (lst or [])]


# ---------------------------------------------------------------------------
# Runner
# ---------------------------------------------------------------------------

class FlowRunner:
    """
    Executes ScanFlow instances sequentially using a BrowserManager.

    Usage::

        runner = FlowRunner(browser)
        ok = await runner.run(flow)
        # browser is now on the last page of the flow
    """

    def __init__(self, browser: "BrowserManager", *, scope_check=None):
        self.browser = browser
        # navigate 後の実着地 URL を検証するコールバック（url->bool、in-scope なら True）。
        # browser.navigate は redirect を追従し最終応答で成功を返すため、静的な step-URL 検査だけ
        # では scope 外へ redirect した先で fill/click が走るのを防げない（Codex #170 P2）。
        self._scope_check = scope_check

    def _assert_landing_in_scope(self) -> None:
        """直近の action 後の実着地 URL を scope 検証する（navigate/submit/click 共通・#170 P2）。

        submit/click も redirect や JS 遷移で scope 外/除外へ着地し得るため、静的 step 検査では
        検知できない runtime landing をここで弾き、その先で後続の fill/click を走らせない。
        """
        if self._scope_check is None:
            return
        landed = ""
        try:
            landed = self.browser.page.url or ""
        except Exception:
            landed = ""
        if landed and not self._scope_check(landed):
            raise FlowStepError(f"flow step landed on out-of-scope/excluded URL: {landed}")

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    async def run(self, flow: ScanFlow) -> bool:
        """
        Execute every step of *flow*.
        Returns True on success, False if any step raises an exception.
        """
        console.print(f"  [cyan][Flow][/cyan] {escape(flow.name)} ({len(flow.steps)} steps)")
        for i, step in enumerate(flow.steps, 1):
            try:
                await self._execute(step, i, len(flow.steps))
            except Exception as exc:
                console.print(
                    f"  [yellow][Flow] Step {i}/{len(flow.steps)} "
                    f"({escape(str(step.action))}) failed: {escape(str(exc))}[/yellow]"
                )
                return False
        console.print(f"  [green][Flow] Completed:[/green] {escape(flow.name)}")
        return True

    # ------------------------------------------------------------------
    # Internal step dispatch
    # ------------------------------------------------------------------

    async def _execute(self, step: FlowStep, num: int, total: int) -> None:
        label = f"[Flow {num}/{total}]"

        # 直前の action が非同期遷移を起こし、その後の wait 中に scope 外/除外へ着地した状態で
        # fill/click/submit を実行しないよう、対話 step の**着手前**に現在 URL を再検証する
        # （click 直後だけの検査では遅延遷移＋wait を取りこぼす・Codex #170 P2）。
        if step.action in ("fill", "click", "submit"):
            self._assert_landing_in_scope()

        if step.action == "navigate":
            console.print(f"  [dim]{label} navigate → {escape(step.url)}[/dim]")
            # navigate は 4xx/timeout で False を返す（例外は投げない）。破棄すると失敗した
            # 遷移を成功扱いし、前提未達のまま後続/攻撃へ進む（F10・Codex #167 P1）。
            if not await self.browser.navigate(step.url):
                raise FlowStepError(f"navigate failed (non-OK response/timeout): {step.url}")
            self._assert_landing_in_scope()

        elif step.action == "fill":
            # record が保存する fill step は CSS selector（`#id` / `[name="x"]`）を持つ。
            # selector があればそれを優先し、無ければ field(name/id)から組み立てる。これで
            # record→scan --flows の再生が実際に効く（click と対称・F09）。
            ident = step.selector or step.field
            filled = await self.browser.page.evaluate(
                """([sel, f, v]) => {
                    const find = (s) => { try { return document.querySelector(s); } catch (e) { return null; } };
                    const setNative = (el, prop, val) => {
                        let proto = Object.getPrototypeOf(el), desc = null;
                        while (proto && !(desc = Object.getOwnPropertyDescriptor(proto, prop))) {
                            proto = Object.getPrototypeOf(proto);
                        }
                        if (desc && desc.set) desc.set.call(el, val); else el[prop] = val;
                    };
                    let el = null;
                    if (sel) {
                        el = find(sel);
                        // 未エスケープの id セレクタ（`#user:name` 等）は querySelector が
                        // pseudo-class と誤解釈して throw/null になる。`#id` を属性セレクタで
                        // 再試行して既存の記録でも解決する（#170 P2）。
                        if (!el && sel[0] === '#')
                            el = find('[id="' + sel.slice(1).replace(/"/g, '\\\\"') + '"]');
                    } else {
                        el = find(`[name="${f}"],[id="${f}"]`);
                    }
                    if (!el) return {ok: false, ambiguous: false, sensitive: false};
                    const sensitive = (el.type === 'password');
                    // 旧記録は checkbox/radio も fill(value) で保存する。value は checked を符号化
                    // しない（未チェックでも value は "on"/value属性のまま）ため、明示的な真偽トークン
                    // だけを信頼し、それ以外は checked と仮定しつつ ambiguous を返して呼び出し側で
                    // 警告する（黙ってチェック状態を反転させない・Codex #170 P2）。現行 record は
                    // checkbox/radio を click で記録するのでこの曖昧さは生じない。
                    let ambiguous = false;
                    if (el.type === 'checkbox' || el.type === 'radio') {
                        const low = String(v).toLowerCase();
                        const falsy = (v === '' || low === 'false' || low === 'off'
                                       || low === '0' || low === 'no' || low === 'unchecked');
                        const truthyExplicit = (low === 'true' || low === '1'
                                                || low === 'checked' || low === 'yes');
                        // React 等の controlled input は value tracker を持ち、el.checked/el.value の
                        // 直接代入だと onChange が「変化なし」と判断して state を更新しない。prototype の
                        // native setter 経由で設定してから event を送る（Codex #170 P2）。
                        setNative(el, 'checked', !falsy);
                        ambiguous = !falsy && !truthyExplicit;
                    } else {
                        setNative(el, 'value', v);
                    }
                    ['input', 'change', 'blur'].forEach(e =>
                        el.dispatchEvent(new Event(e, {bubbles: true}))
                    );
                    return {ok: true, ambiguous: ambiguous, sensitive: sensitive};
                }""",
                [step.selector, step.field, step.value],
            )
            # JS は {ok, ambiguous, sensitive} を返す。安全に取り出す（旧 bool 返しにも耐性）。
            ok = filled.get("ok") if isinstance(filled, dict) else bool(filled)
            ambiguous = filled.get("ambiguous") if isinstance(filled, dict) else False
            sensitive = filled.get("sensitive") if isinstance(filled, dict) else False
            if not ok:
                # 存在しない欄への fill を成功扱いにすると前提の欠落を見逃す（F10）。
                raise FlowStepError(f"fill target not found: {ident!r}")
            # 平文パスワードを console/CI ログへ出さない。recorder は input type を保存しないため、
            # replay 時に実要素の type=password（sensitive）で判定し、加えて secret 系識別子も伏せる
            # （selector 文字列だけの判定では type=password で id が中立な欄を漏らす・Codex #170 P2）。
            masked = sensitive or any(
                p in ident.lower()
                for p in ("password", "passwd", "pass", "pwd", "secret")
            )
            display_val = "***" if masked else step.value
            # 記録値/selector に Rich markup（`[/admin]` 等）が含まれても MarkupError で fill 成功後に
            # 前提失敗扱いにならないよう escape する（Codex #170 P2）。
            console.print(f"  [dim]{label} fill \\[{escape(ident)}] = {escape(display_val[:40])}[/dim]")
            if ambiguous:
                # 旧記録の checkbox/radio は真の checked を値から復元できない。checked と仮定した
                # ことを明示し、現行 record（click 記録）での再取得を促す（黙って反転させない）。
                console.print(
                    f"  [yellow]{label} fill \\[{escape(ident)}]: 旧記録の checkbox/radio は値から "
                    f"checked 状態を復元できません（checked と仮定）。現行の record は click で "
                    f"記録するため再記録を推奨[/yellow]"
                )

        elif step.action == "submit":
            console.print(f"  [dim]{label} submit[/dim]")
            clicked = await self.browser.page.evaluate(
                """(sel) => {
                    // record が Enter 送信等で保存した form selector があればその form を送信する。
                    // requestSubmit は submit event を発火するので SPA の submit handler も動く（Codex #170 P2）。
                    if (sel) {
                        let form = null;
                        try { form = document.querySelector(sel); } catch (e) { form = null; }
                        if (form && form.tagName !== 'FORM') form = form.closest('form');
                        if (!form) return false;
                        if (form.requestSubmit) form.requestSubmit(); else form.submit();
                        return true;
                    }
                    // Prefer clicking the submit button (handles JS frameworks)
                    const btn = document.querySelector(
                        'button[type="submit"],input[type="submit"]'
                    ) || document.querySelector('[type="submit"]');
                    if (btn) { btn.click(); return true; }
                    const form = document.querySelector('form');
                    if (form) { form.submit(); return true; }
                    return false;
                }""",
                step.selector,
            )
            if not clicked:
                # 送信ボタン/フォームが無いのに成功扱いすると後続を誤って進める（F10 同型）。
                raise FlowStepError("submit target not found (no submit button or form)")
            try:
                await self.browser.page.wait_for_load_state(
                    "domcontentloaded", timeout=15_000
                )
            except Exception:
                pass
            self._assert_landing_in_scope()

        elif step.action == "click":
            sel = step.selector or step.field
            console.print(f"  [dim]{label} click \\[{escape(sel)}][/dim]")
            await self.browser.page.click(sel, timeout=int(step.timeout * 1000))
            try:
                await self.browser.page.wait_for_load_state(
                    "domcontentloaded", timeout=10_000
                )
            except Exception:
                pass
            self._assert_landing_in_scope()

        elif step.action == "wait":
            console.print(f"  [dim]{label} wait {step.timeout}s[/dim]")
            await asyncio.sleep(step.timeout)
            # wait 中に遅延遷移で scope 外へ着地していないか検証する（Codex #170 P2）。
            self._assert_landing_in_scope()

        else:
            # 不明アクション（タイプミス等）を skip して flow を成功扱いにすると、前提未達のまま
            # 誤った状態で検査してしまう。失敗として扱い run() を False にする（F10 と同型・#170 P2）。
            raise FlowStepError(f"unknown flow action: {step.action!r}")
