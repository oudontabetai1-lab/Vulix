"""Login surface・認証フィールド・認証状態の判定（純粋関数）。

``auth_fields``（入力欄の検出）・``auth_detect``（ログイン成否）・``mfa``（MFA 文脈）を
土台に、観測データ（HTML スナップショット・URL・応答状態）から次を**根拠付き**で返す:

- ``classify_surface``      … フォーム単位で login/registration/reset/search/other を判定。
  ログイン画面にある「Forgot password?」「Sign up」**リンク**は判定に使わず、見出し・
  legend・送信ボタン・action だけを文脈とする（紛らわしい surface の誤分類防止）。
- ``locate_auth_fields``    … 単一画面 / username→password 多段 / password 単独 / OTP /
  modal・SPA（form 外）での対象欄と submit 経路。明示 selector を最優先し、自動検出は
  一意に決まるときだけ使う（曖昧なら selector を返さず理由を残す）。
- ``locate_api_login``      … 捕捉した JSON リクエストのキー名から API ログインを特定。
- ``assess_login_state``    … success/failure/challenge/incomplete。自動判定の成功は
  **独立した肯定的証拠 2 つ以上**を要する（URL 遷移だけ・単一文字列だけでは成功にしない）。
  曖昧・非対応・transport error は INCOMPLETE と理由コードで返し、未ログインを成功に丸めない。

戻り値は selector・キー名・理由コードのみで、本文・資格情報・Cookie 値・OTP は保持しない
（ログ/レポートへ平文で流れない構造）。
"""
from __future__ import annotations

from dataclasses import dataclass, field
from html.parser import HTMLParser
import re
from typing import Optional
from urllib.parse import parse_qsl, urlparse

from . import auth_detect
from .auth_fields import _OTP_HINTS, _SAFE_VALUE, _USER_HINTS, _hinted
from .mfa import looks_like_mfa_page, mfa_field_present

LOGIN = "login"
REGISTRATION = "registration"
RESET = "reset"
SEARCH = "search"
OTHER = "other"
AMBIGUOUS = "ambiguous"

SUCCESS = "success"
FAILURE = "failure"
CHALLENGE = "challenge"
INCOMPLETE = "incomplete"

_LOGIN_WORDS = ("log in", "login", "sign in", "signin", "log on", "ログイン", "サインイン")
_REG_WORDS = ("sign up", "signup", "register", "registration", "create account",
              "create an account", "join", "新規登録", "会員登録", "アカウント作成")
_RESET_WORDS = ("reset password", "forgot password", "forgot your password", "recover",
                "password reset", "パスワード再設定", "パスワードをお忘れ", "パスワードのリセット")
_SEARCH_WORDS = ("search", "検索")
_LOGOUT_WORDS = ("log out", "logout", "sign out", "signout", "ログアウト", "サインアウト")
_SEARCH_NAMES = {"q", "query", "s", "search", "keyword", "keywords"}
_TEXTUAL = {"", "text", "email", "tel", "search", "number"}
_HEADINGS = {"h1", "h2", "h3", "h4", "title", "legend", "label"}
_VOID = {"area", "base", "br", "col", "embed", "hr", "img", "input",
         "link", "meta", "param", "source", "track", "wbr"}


# 操作を切り替える query キー（next/redirect/returnUrl 等の遷移先は語源にしない）
_ROUTE_KEYS = {"action", "route", "op", "operation", "cmd", "command", "do", "mode", "task", "r"}
# 汎用語（クーポン code・API token・PIN 等）だけでは OTP 欄とみなさない
_STRONG_OTP = tuple(h for h in _OTP_HINTS if h not in {"code", "token", "pin"})


def _path_words(path: str) -> str:
    return path.replace("/", " ").replace("-", " ").replace("_", " ")


def _route_words(url: str) -> str:
    """URL の path と routing 用 query 値を語に分解する（``?action=login`` 等）。"""
    p = urlparse(url or "")
    return _path_words(" ".join([p.path] + [v for k, v in parse_qsl(p.query)
                                            if k.lower() in _ROUTE_KEYS]))


def _has_word(text: str, words) -> bool:
    low = " ".join((text or "").lower().split())
    return any((re.search(r"(?<![a-z0-9])" + re.escape(w) + r"(?![a-z0-9])", low)
                if w.isascii() else w in low) for w in words)


@dataclass
class _Form:
    index: int                 # 文書内の form 順（form 外の入力群は -1）
    form_id: str = ""
    action: str = ""
    role: str = ""
    context: str = ""          # 直前の見出し＋ legend/label/送信ボタン文言
    inputs: list = field(default_factory=list)   # (attrs, blocked)
    submits: list = field(default_factory=list)  # (attrs, text)
    in_modal: bool = False
    visible: bool = True       # form 自体が可視か（logout form の操作可能性判定用）
    can_submit: bool = False   # 有効かつ可視の submit 手段を持つか


class _Doc(HTMLParser):
    """form ごとに入力・送信ボタン・文脈語を集める（<a> の文言は文脈に含めない）。"""

    def __init__(self, html: str):
        super().__init__(convert_charrefs=True)
        self.forms: list[_Form] = []
        self.loose = _Form(index=-1)
        self.current: Optional[_Form] = None
        self.stack: list[tuple[str, bool, bool, bool]] = []  # (tag, blocked, modal, disabled)
        self.text_target: Optional[str] = None        # 収集中の見出し/ボタン種別
        self.buf: list[str] = []
        self.button: Optional[dict] = None
        self.last_heading = ""
        self.all_inputs: list[dict] = []              # selector 一意性の母集団（hidden 含む全 input）
        self.external_submits: list[tuple[str, dict, str, bool]] = []
        self.external_inputs: list[tuple[str, dict, bool]] = []
        self.captcha_widget = False
        self.visible_text: list[str] = []
        # 操作可能（可視・有効・遷移/送信しうる）な a/button/submit/logout form の可視文言・パス
        self.controls: list[str] = []
        self.ctl_buf: Optional[list[str]] = None      # 収集中の a/button の可視文言
        self.ctl_op = False
        self.ctl_path = ""                            # 収集中 anchor の href パス
        self.feed(html or "")
        self.close()
        forms_by_id = {f.form_id: f for f in self.forms if f.form_id}
        for form_id, attrs, blocked in self.external_inputs:
            if form_id in forms_by_id:
                forms_by_id[form_id].inputs.append((attrs, blocked))
        for form_id, attrs, label, operable in self.external_submits:
            if form_id in forms_by_id:
                self._record_submit(forms_by_id[form_id], attrs, label, operable)

    @property
    def _blocked(self) -> bool:
        return any(s[1] for s in self.stack)

    @property
    def _modal(self) -> bool:
        return any(s[2] for s in self.stack)

    @property
    def _disabled(self) -> bool:
        # disabled な fieldset の子孫の入力/ボタンは操作不能
        return any(s[3] for s in self.stack)

    def _form(self) -> _Form:
        return self.current or self.loose

    def _record_submit(self, form: _Form, attrs: dict, label: str, operable: bool):
        form.can_submit |= operable
        form.submits.append((attrs, label or "submit"))
        form.context += " " + label

    def _submit(self, attrs: dict, label: str, operable: bool):
        if attrs.get("form"):
            self.external_submits.append((attrs["form"], attrs, label, operable))
        else:
            self._record_submit(self._form(), attrs, label, operable)

    def handle_starttag(self, tag, attrs):
        a: dict[str, str] = {}
        for k, v in attrs:
            a.setdefault(k, v or "")
        style = re.sub(r"\s+", "", a.get("style", "").lower())
        hidden = ("hidden" in a or "inert" in a or a.get("aria-hidden", "").lower() == "true"
                  or "display:none" in style or "visibility:hidden" in style
                  or tag in {"template", "noscript", "script", "style", "head"}
                  or (tag == "dialog" and "open" not in a))
        cls = (a.get("class", "") + " " + a.get("role", "") + " " + a.get("id", "")).lower()
        modal = tag == "dialog" or "modal" in cls or "dialog" in cls
        blocked = self._blocked or hidden
        disabled = self._disabled or (tag == "fieldset" and "disabled" in a)
        operable = not blocked and not disabled and "disabled" not in a
        name_id = (a.get("name", "") + " " + a.get("id", "") + " " + a.get("class", "")).lower()
        if ((tag == "iframe" and any(x in a.get("src", "").lower() for x in ("recaptcha", "hcaptcha"))
             and not blocked)
                or (tag == "input" and any(x in name_id for x in ("g-recaptcha-response", "h-captcha-response"))
                    and not blocked)
                or (tag in {"div", "iframe"} and a.get("data-sitekey") and not blocked)
                or (tag == "div" and any(x in name_id.split() for x in ("g-recaptcha", "h-captcha"))
                    and not blocked)):
            self.captcha_widget = True
        if tag == "form":
            self.current = _Form(index=len(self.forms), form_id=a.get("id", ""), action=a.get("action", ""),
                                 role=a.get("role", "").lower(),
                                 context=" ".join([self.last_heading, a.get("aria-label", "")]),
                                 in_modal=self._modal or modal, visible=not blocked)
            self.forms.append(self.current)
            self.last_heading = ""   # 見出しは直後の form 1 つにだけ結び付ける
        elif tag == "input":
            self.all_inputs.append(a)
            t = a.get("type", "").lower()
            if t in {"submit", "image", "button"} and operable:
                self.controls.append(a.get("value", ""))
            if t in {"submit", "image"}:
                label = a.get("value", "") or a.get("alt", "")
                self._submit({**a, "_tag": "input"}, label, operable)
            elif t != "hidden":
                a = {**a, "_uneditable": disabled or "disabled" in a or "readonly" in a}
                if a.get("form"):
                    self.external_inputs.append((a["form"], a, not operable or a["_uneditable"]))
                else:
                    self._form().inputs.append((a, not operable or a["_uneditable"]))
        elif tag == "button":
            # type=button も logout control の文言源として集める（submit 扱いは submit 型のみ）
            is_submit = a.get("type", "").lower() in {"", "submit"}
            self.button = {**a, "_tag": "button"} if is_submit else None
            self.button_operable = operable
            self.text_target, self.buf = "button", []
            self.ctl_buf, self.ctl_op, self.ctl_path = [], operable, ""
        elif tag == "a" and not blocked:
            # href の無い anchor は遷移しないので control にしない
            href = a.get("href", "").strip()
            self.ctl_buf, self.ctl_op, self.ctl_path = [], bool(href), _path_words(urlparse(href).path)
        elif tag in _HEADINGS:
            self.text_target, self.buf = tag, []
        if tag == "div" and a.get("role", "").lower() == "search" and self.current is None:
            self.loose.role = "search"
        if tag not in _VOID:
            self.stack.append((tag, blocked, modal, disabled))

    def handle_endtag(self, tag):
        if tag == "button" and self.text_target == "button":
            text = " ".join("".join(self.buf).split())
            self._end_control()
            if self.button is not None:
                self._submit(self.button, text, self.button_operable)
            self.text_target, self.button = None, None
        elif tag == "a" and self.ctl_buf is not None:
            self._end_control()
        elif self.text_target == tag and tag in _HEADINGS:
            text = " ".join("".join(self.buf).split())
            if tag in {"legend", "label"}:
                self._form().context += " " + text
            elif self.current is not None:
                self.current.context += " " + text
            else:
                self.last_heading = text
            self.text_target = None
        if tag == "form" and self.current is not None:
            # 空 form・disabled/非表示の送信手段しか無い form は送信できない
            if self.current.visible and self.current.can_submit and self.current.action:
                self.controls.append(_path_words(urlparse(self.current.action).path))
            self.current = None
        for i in range(len(self.stack) - 1, -1, -1):
            if self.stack[i][0] == tag:
                del self.stack[i:]
                break

    def _end_control(self):
        # 可視文言の無い a/button（hidden な子孫にだけ文言がある等）は操作要素として数えない
        text = " ".join("".join(self.ctl_buf or ()).split())
        if self.ctl_op and text:
            self.controls.append(f"{self.ctl_path} {text}")
        self.ctl_buf, self.ctl_op = None, False

    def handle_data(self, data):
        if self.text_target:
            self.buf.append(data)
        if not self._blocked:
            if self.ctl_buf is not None:
                self.ctl_buf.append(data)
            self.visible_text.append(data)


def _type(a: dict) -> str:
    return a.get("type", "").lower()


def _ac(a: dict) -> str:
    """autocomplete の詳細トークン（``section-x username webauthn`` → ``username``）。"""
    toks = [t for t in a.get("autocomplete", "").lower().split() if t != "webauthn"]
    return toks[-1] if toks else ""


def _name_words(a: dict) -> set:
    v = re.sub(r"([a-z0-9])([A-Z])", r"\1_\2", a.get("name", "") + " " + a.get("id", ""))
    return set(re.split(r"[^a-z0-9]+", v.lower()))


def _is_text(a: dict) -> bool:
    # 伏字の OTP（type=password + one-time-code）も OTP 候補の入力欄として扱う
    return _type(a) in _TEXTUAL or _ac(a) == "one-time-code"


def _is_pw(a: dict) -> bool:
    return _type(a) == "password" and _ac(a) != "one-time-code"


def _is_user(a: dict) -> bool:
    return _type(a) in _TEXTUAL and (_ac(a) in {"username", "email"} or _type(a) == "email"
                                     or _hinted(a, _USER_HINTS))


def _is_otp(a: dict) -> bool:
    return _is_text(a) and (_ac(a) == "one-time-code" or _hinted(a, _OTP_HINTS))


def _strong_otp(a: dict) -> bool:
    return _ac(a) == "one-time-code" or bool(_name_words(a) & set(_STRONG_OTP))


def _usable(f: _Form, visible_only: bool = False) -> list:
    """操作可能な欄。送信前は reveal 可能な modal 内の非表示欄も含める（template 等は除く）。"""
    return [a for a, b in f.inputs if not a.get("_uneditable")
            and (not b or (f.in_modal and not visible_only))]


@dataclass
class FormSurface:
    index: int
    kind: str
    step: str = ""             # login のとき: single / username_first / password_only / otp
    reasons: list = field(default_factory=list)
    in_modal: bool = False


@dataclass
class SurfaceResult:
    """ページ全体の判定。``kind`` はログイン対象として扱うべき種別。"""
    kind: str
    login_form: Optional[int] = None     # ログイン対象 form の index（form 外は -1）
    forms: list = field(default_factory=list)
    reasons: list = field(default_factory=list)


def _classify_form(f: _Form, inputs: list) -> FormSurface:
    pw = [a for a in inputs if _is_pw(a)]
    new_pw = [a for a in pw if _ac(a) == "new-password"]
    cur_pw = [a for a in pw if _ac(a) == "current-password"]
    texts = [a for a in inputs if _is_text(a)]
    user = [a for a in texts if _is_user(a)]
    otp = [a for a in texts if _is_otp(a)]
    ctx = f.context + " " + _route_words(f.action)
    login_w, reg_w, reset_w = (_has_word(ctx, w) for w in (_LOGIN_WORDS, _REG_WORDS, _RESET_WORDS))
    r = FormSurface(index=f.index, kind=OTHER, in_modal=f.in_modal)
    words = [n for n, hit in (("login_words", login_w), ("registration_words", reg_w),
                              ("reset_words", reset_w)) if hit]
    r.reasons = [f"password_fields:{len(pw)}"] + words
    if f.in_modal:
        r.reasons.append("in_modal")

    if not pw and (f.role == "search" or any(_type(a) == "search" for a in texts)
                   or (len(texts) == 1 and (texts[0].get("name", "").lower() in _SEARCH_NAMES
                                            or _has_word(ctx, _SEARCH_WORDS)) and not user)):
        r.kind = SEARCH
        return r
    if len(pw) >= 2 or (new_pw and not cur_pw):
        # 新パスワード欄（確認欄つき含む）はログインでない。reset 語があれば reset。
        if reset_w:
            r.kind = RESET
        elif reg_w or len(pw) >= 2:
            r.kind = REGISTRATION
        else:
            r.kind, r.reasons = AMBIGUOUS, r.reasons + ["new_password_without_context"]
        return r
    if pw:
        if reg_w and not login_w:
            r.kind = REGISTRATION
        elif reset_w and not login_w:
            r.kind = RESET
        elif reg_w and login_w and not cur_pw:
            r.kind, r.reasons = AMBIGUOUS, r.reasons + ["login_and_registration_words"]
        elif user or texts:
            r.kind, r.step = LOGIN, "single"
        elif login_w:
            r.kind, r.step = LOGIN, "password_only"
        else:
            # 単独 password 欄（退会・設定変更の再確認等）はログイン文脈が無ければ自動実行しない
            r.kind, r.reasons = AMBIGUOUS, r.reasons + ["password_only_without_login_context"]
        return r
    if otp and (login_w or any(_strong_otp(a) for a in otp)):
        r.kind, r.step = LOGIN, "otp"
        return r
    if otp:
        r.reasons.append("weak_otp_hint")
    if reset_w:
        r.kind = RESET
    elif reg_w and not login_w:
        r.kind = REGISTRATION
    elif login_w and len(user) == 1:
        r.kind, r.step = LOGIN, "username_first"
    return r


def classify_surface(html: str, *, visible_only: bool = False) -> SurfaceResult:
    """ページの login surface 種別を判定する（純粋関数）。

    ログイン対象 form がちょうど 1 つならそれを ``login_form`` に返す。複数の login 候補や
    曖昧 form しかない場合は ``AMBIGUOUS``（呼び出し側は INCOMPLETE として扱う）。
    ``visible_only`` は操作可能な入力を持つ form だけを見る（送信後の残存判定用。送信前は
    非表示 modal も reveal 対象なので既定は全 form）。
    """
    doc = _Doc(html)
    groups = [(f, _usable(f, visible_only)) for f in doc.forms + [doc.loose]]
    groups = [(f, inputs) for f, inputs in groups if inputs]
    forms = [_classify_form(f, inputs) for f, inputs in groups]
    # MFA 画面は見出しに OTP 語が無い素っ気ない欄でも、ページ文脈で OTP 段とみなす。
    if (looks_like_mfa_page(html or "")
            and _has_word(" ".join(doc.visible_text), ("enter", "provide", "verify", "入力"))):
        for s, (_, inputs) in zip(forms, groups):
            if s.kind == OTHER and sum(map(_is_text, inputs)) == 1 and not any(map(_is_pw, inputs)):
                s.kind, s.step = LOGIN, "otp"
                s.reasons.append("mfa_page_context")
    logins = [s for s in forms if s.kind == LOGIN]
    if len(logins) == 1:
        return SurfaceResult(LOGIN, logins[0].index, forms, [f"login_step:{logins[0].step}"])
    if len(logins) > 1:
        return SurfaceResult(AMBIGUOUS, None, forms, ["multiple_login_forms"])
    if any(s.kind == AMBIGUOUS for s in forms):
        return SurfaceResult(AMBIGUOUS, None, forms, ["ambiguous_form"])
    kinds = {s.kind for s in forms} - {OTHER}
    if len(kinds) == 1:
        return SurfaceResult(kinds.pop(), None, forms, [])
    if not forms:
        return SurfaceResult(OTHER, None, forms, ["no_inputs"])
    return SurfaceResult(OTHER if not kinds else AMBIGUOUS, None, forms,
                         ["no_login_form"] if not kinds else ["mixed_surfaces"])


@dataclass
class AuthFieldPlan:
    """ログイン対象欄と submit 経路。selector が空の欄は「この段に無い/特定不能」。"""
    step: str                               # single/username_first/password_only/otp/none
    user_selector: str = ""
    pass_selector: str = ""
    otp_selector: str = ""
    submit: str = ""                        # submit ボタン selector（空なら submit_strategy）
    submit_strategy: str = ""               # button / form_submit / enter
    sources: dict = field(default_factory=dict)   # 欄ごとの explicit/auto
    requires_reveal: bool = False           # modal 等で可視化操作が要る
    incomplete_reason: str = ""             # 特定できない理由（空なら実行可能）


def _unique_selector(all_attrs: list[dict], a: dict, tag: str = "input",
                     keys: tuple = ("id", "name")) -> str:
    for key in keys:
        v = a.get(key, "")
        if key == "type":   # HTML の type は大小文字を区別しない
            v, n = v.lower(), sum(_type(x) == v.lower() for x in all_attrs)
        else:
            n = sum(x.get(key) == v for x in all_attrs)
        if _SAFE_VALUE.fullmatch(v) and n == 1:
            return f'{tag}[{key}="{v}"]'
    return ""


def _submit_rank(attrs: dict, text: str) -> int:
    """login 文言の submit を優先し、登録/再設定（文言・formaction）の submit は使わない。"""
    if _has_word(text + " " + _route_words(attrs.get("formaction", "")), _REG_WORDS + _RESET_WORDS):
        return 2
    return 0 if _has_word(text, _LOGIN_WORDS) else 1


def locate_auth_fields(
    html: str,
    *,
    user_selector: str = "",
    pass_selector: str = "",
    otp_selector: str = "",
    submit_selector: str = "",
) -> AuthFieldPlan:
    """対象欄と submit 経路を返す（純粋関数）。

    明示 selector（設定の name/id は ``name_or_id_selector`` で selector 化して渡す）を欄ごとに
    最優先し、自動検出は ``classify_surface`` が login form を一意に特定した場合だけ補う。
    明示指定は DOM 実在の確認を呼び出し側（``browser._editable_auth_selector``）に委ねる。
    """
    explicit = {"user": user_selector, "pass": pass_selector, "otp": otp_selector}
    surface = classify_surface(html)
    doc = _Doc(html)
    groups = {f.index: f for f in doc.forms + [doc.loose]}
    plan = AuthFieldPlan(step="none")
    form = groups.get(surface.login_form) if surface.login_form is not None else None
    if form is not None:
        s = next(x for x in surface.forms if x.index == form.index)
        plan.step, plan.requires_reveal = s.step, s.in_modal
        inputs = _usable(form)
        texts = [a for a in inputs if _is_text(a)]
        pw = [a for a in inputs if _is_pw(a)]
        users = [a for a in texts if _is_user(a)] or (
            texts if len(texts) == 1 and s.step in {"single", "username_first"} else [])
        # 一意性は hidden を含む文書内の全 input で数える。name/id で決まらなければ
        # autocomplete・type が文書内で唯一のときだけ使う（先行する登録 form 等の欄を誤って
        # 埋めない。曖昧なら field_not_unique）。
        uniq = lambda a: _unique_selector(doc.all_inputs, a, keys=("id", "name", "autocomplete", "type"))  # noqa: E731
        if s.step in {"single", "username_first"} and len(users) == 1:
            plan.user_selector = uniq(users[0])
        if len(pw) == 1:
            plan.pass_selector = uniq(pw[0])
        if s.step == "otp" and len(texts) == 1:
            plan.otp_selector = uniq(texts[0])
        ranked = sorted(form.submits, key=lambda b: _submit_rank(*b))
        all_buttons = [a for g in groups.values() for a, _ in g.submits]
        if ranked and _submit_rank(*ranked[0]) < 2:
            button = ranked[0][0]
            plan.submit = _unique_selector(all_buttons, button, button.get("_tag", "button"))
            plan.submit_strategy = "button" if plan.submit else ("form_submit" if form.index >= 0 else "enter")
        else:
            plan.submit_strategy = "form_submit" if form.index >= 0 else "enter"
    for key, attr in (("user", "user_selector"), ("pass", "pass_selector"), ("otp", "otp_selector")):
        if explicit[key]:
            setattr(plan, attr, explicit[key])
            plan.sources[key] = "explicit"
        elif getattr(plan, attr):
            plan.sources[key] = "auto"
    if submit_selector:
        plan.submit, plan.submit_strategy = submit_selector, "button"
        plan.sources["submit"] = "explicit"
    if not plan.submit_strategy:
        # login form を特定できず明示欄だけで組んだ plan も送信経路を必ず持たせる
        plan.submit_strategy = "enter"
    if plan.step == "none" and (user_selector and pass_selector):
        plan.step = "single"
    elif plan.step == "none" and otp_selector:
        plan.step = "otp"
    needed = {"single": ("user_selector", "pass_selector"), "username_first": ("user_selector",),
              "password_only": ("pass_selector",), "otp": ("otp_selector",)}.get(plan.step)
    if needed is None:
        plan.incomplete_reason = "login_surface_" + (surface.reasons[0] if surface.reasons else surface.kind)
    elif not all(getattr(plan, n) for n in needed):
        plan.incomplete_reason = "field_not_unique:" + ",".join(n for n in needed if not getattr(plan, n))
    return plan


@dataclass
class ApiLoginTarget:
    url: str
    user_key: str
    pass_key: str


_API_USER_KEYS = ("username", "user", "email", "login", "userid", "user_id", "account", "mail")
_API_PASS_KEYS = ("password", "passwd", "pass", "pwd")
# path/query では単独の reset/forgot も明示的な再設定経路（/api/reset・/api/forgot）とみなす。
# パスワード変更/設定も認証の再生ではない（/api/change-password・changePassword 等）。
_API_EXCLUDE_WORDS = _REG_WORDS + _RESET_WORDS + (
    "reset", "forgot", "forgotten", "recovery", "change password", "password change",
    "update password", "set password", "changepassword", "updatepassword", "setpassword",
    "resetpassword", "forgotpassword")


def locate_api_login(url: str, method: str, body_keys) -> Optional[ApiLoginTarget]:
    """捕捉した JSON リクエスト（キー名のみ）が API ログインかを判定する（純粋関数）。

    値は受け取らない。登録/リセット/パスワード変更 API（path か routing query 値の ``register``
    ``reset-password`` ``change-password`` 等、確認用/新旧パスワードのキー）は除外。
    """
    if (method or "").upper() != "POST":
        return None
    keys = [str(k) for k in body_keys or ()]
    low = {k.lower(): k for k in keys}
    if _has_word(_route_words(url), _API_EXCLUDE_WORDS):
        return None
    pw = [low[k] for k in low if k in _API_PASS_KEYS]
    # 確認用/新旧パスワードのキー（current_password・newPassword 等）だけを変更操作とみなす
    if len(pw) != 1 or any(("pass" in k or "pwd" in k)
                           and ("confirm" in k or k.startswith(("new", "old", "current"))) for k in low):
        return None
    users = [low[k] for k in low if k in _API_USER_KEYS]
    if len(users) != 1:
        return None
    return ApiLoginTarget(url=url, user_key=users[0], pass_key=pw[0])


@dataclass
class LoginObservation:
    """ログイン送信後の観測（本文は判定にだけ使い、結果へは残さない）。"""
    post_url: str = ""
    login_url: str = ""
    body: str = ""
    status: Optional[int] = None
    transport_error: str = ""            # 例外型名など。値・本文は入れない
    success_indicator: str = ""          # 既存設定 login_success_indicator
    logged_in_marker: str = ""
    auth_cookie_set: Optional[bool] = None   # 送信後に新しい認証 Cookie が付いたか（値は渡さない）
    api_token_issued: Optional[bool] = None  # API 応答に token/session が含まれたか
    mfa_field: str = ""


@dataclass
class LoginAssessment:
    state: str
    evidence: list = field(default_factory=list)   # 肯定的証拠コード
    reasons: list = field(default_factory=list)    # 否定・不足の理由コード

    @property
    def authenticated(self) -> bool:
        return self.state == SUCCESS


def assess_login_state(obs: LoginObservation) -> LoginAssessment:
    """送信後の観測から認証状態を判定する（純粋関数）。

    - transport error / 5xx / 429 → INCOMPLETE（未ログインを失敗とも成功とも断定しない）。
    - 401・可視の失敗文言 → FAILURE。その他の 4xx → INCOMPLETE。MFA・CAPTCHA・パスワード段 → CHALLENGE。
    - SUCCESS は否定シグナルが無く、(a) 明示設定（success_indicator / logged_in_marker）が一致、
      または (b) 独立した肯定的証拠が 2 つ以上のとき。証拠 1 つ以下は INCOMPLETE。
    """
    if obs.transport_error:
        # 例外メッセージ（URL の userinfo/token を含みうる）は残さず、型名だけを理由にする
        err = obs.transport_error if obs.transport_error in {
            "ConnectError", "ConnectTimeout", "ReadError", "ReadTimeout", "WriteError",
            "WriteTimeout", "PoolTimeout", "RemoteProtocolError", "TimeoutError", "ConnectionError",
        } else "unknown"
        return LoginAssessment(INCOMPLETE, reasons=[f"transport_error:{err}"])
    if obs.status == 429 or (obs.status or 0) >= 500:
        return LoginAssessment(INCOMPLETE, reasons=[f"http_{obs.status}"])
    body = obs.body or ""
    if obs.status == 401:
        return LoginAssessment(FAILURE, reasons=["http_401"])
    doc = _Doc(body)
    # script/template 内の i18n 文字列等は失敗の根拠にしない（可視テキストのみ）
    if auth_detect.has_failure_text(" ".join(doc.visible_text)):
        return LoginAssessment(FAILURE, reasons=["failure_text"])
    if obs.status is not None and 400 <= obs.status < 500:
        # 403/422 等は資格情報の失敗とは断定できないが、成功の根拠も評価しない
        return LoginAssessment(INCOMPLETE, reasons=[f"http_{obs.status}"])
    if doc.captcha_widget:
        return LoginAssessment(CHALLENGE, reasons=["captcha_unsupported"])
    # 非表示/操作不能な form（閉じた login modal の残骸等）は残存の根拠にしない。
    surface = classify_surface(body, visible_only=True)
    login_step = next((s.step for s in surface.forms if s.kind == LOGIN), "")
    if login_step == "otp" or mfa_field_present(body, obs.mfa_field):
        return LoginAssessment(CHALLENGE, reasons=["mfa"])
    if login_step == "password_only":
        return LoginAssessment(CHALLENGE, reasons=["password_step"])
    visible_pw = any(_is_pw(a) and not b
                     for f in doc.forms + [doc.loose] for a, b in f.inputs)
    login_form_present = (visible_pw and auth_detect.has_login_form(body)) or login_step

    evidence, reasons = [], []
    if obs.auth_cookie_set is False and not obs.api_token_issued:
        # token 認証の API では Cookie 不在は否定シグナルにならない
        reasons.append("auth_cookie_absent")
    explicit = False
    if obs.success_indicator:
        if obs.success_indicator in (obs.post_url or "") or obs.success_indicator in body:
            evidence.append("success_indicator")
            explicit = True
        else:
            reasons.append("success_indicator_missing")
    if obs.logged_in_marker:
        if obs.logged_in_marker in body:
            evidence.append("logged_in_marker")
            explicit = True
        else:
            reasons.append("logged_in_marker_missing")
    if login_form_present and not explicit:
        return LoginAssessment(INCOMPLETE, reasons=["login_form_still_present"])
    if obs.post_url and not auth_detect.on_login_page(obs.post_url, obs.login_url) \
            and auth_detect._norm(obs.post_url) != auth_detect._norm(obs.login_url):
        evidence.append("left_login_page")
    if obs.auth_cookie_set:
        evidence.append("auth_cookie_set")
    if obs.api_token_issued:
        evidence.append("api_token_issued")
    # 本文の説明文ではなく、可視の操作要素（リンク/ボタン/ログアウト form）に限る。
    if _has_word(" ".join(doc.controls), _LOGOUT_WORDS):
        evidence.append("logout_control")
    if reasons:
        return LoginAssessment(INCOMPLETE, evidence, reasons)
    if explicit or len(evidence) >= 2:
        return LoginAssessment(SUCCESS, evidence)
    return LoginAssessment(INCOMPLETE, evidence, ["insufficient_success_evidence"])
