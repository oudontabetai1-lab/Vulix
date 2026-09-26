"""実 ScanEngine を suite 単位で実行する adapter（0034-R2）。"""
from __future__ import annotations

import asyncio
import math
import tempfile
from urllib.parse import urlparse

from wscan.benchmark_runner import ScanOutcome, ScanRunner


# scan_matrix の location は人間可読（"URL param"/"form field"）で、MatchSpec.location や
# Finding.injection_location（"url_param"/"form"）とは別語彙。exercised を case と比較できるよう
# 後者へ正規化する（Codex #134 P2）。未知値はそのまま通す（_location_compatible が空/不一致を扱う）。
_LOCATION_NORMALIZE = {"url param": "url_param", "form field": "form"}

# 「成功して突いた」＝実際に採点可能な行だけ exercised に入れる。error（scanner が payload 完了前に
# 例外）や skipped（未実行）は未計測なので除く（Codex #134 P1）。
_EXERCISED_STATUSES = frozenset({"tested", "finding"})


def _normalize_location(raw: str) -> str:
    return _LOCATION_NORMALIZE.get(str(raw or "").strip().lower(), str(raw or ""))


# probe が transport 層で握りつぶされた/template が実行不能だった check を示す観測ノート
# （engine.wave_errors、0007 D1）。status="tested" でも実際には probe が送達していない場合がある
# ため、劣化した check の行は exercised から除く（Codex #134 P1）。これらは check 全体を疑う
# （どの field で握りつぶしたか note に持たない）ため check 単位で degradation する。
_DEGRADATION_PREFIXES = (
    "transport_error:",
    "unexecutable_template:",
)

# field_budget_exceeded: はフィールド時間ボックス超過で注入を打ち切った injection point（_field_budget_gate、
# F06/0059）。gate は ('',{}) を返すため _scan_field が status="tested" を記録するが未送信 probe が残る＝
# 送達していない。新形式 note（field_budget_exceeded:<check>:<path>|<field>）は当該 IP を特定できるので
# per-IP に degradation を絞り、同 check の別 field の完全実行行を巻き込まない（R4#2）。IP 情報の無い旧形式
# のみ check 全体を劣化扱い（後方互換フォールバック）。
_FIELD_BUDGET_PREFIX = "field_budget_exceeded:"


def _degraded_checks(wave_errors) -> frozenset:
    """wave_errors から check 全体が劣化した note の check 名集合を作る（純粋）。

    transport_error/unexecutable_template（どの field か不明）と、IP 情報を持たない旧形式の
    field_budget_exceeded だけを check 単位で拾う。IP 情報付きの field_budget は
    ``_field_budget_degraded_ips`` で per-IP に扱う。"""
    degraded = set()
    for note in (wave_errors or []):
        if not isinstance(note, str):
            continue
        for prefix in _DEGRADATION_PREFIXES:
            if note.startswith(prefix):
                check = note[len(prefix):].split(":", 1)[0].strip()
                if check:
                    degraded.add(check)
        if note.startswith(_FIELD_BUDGET_PREFIX):
            check, sep, ipinfo = note[len(_FIELD_BUDGET_PREFIX):].partition(":")
            check = check.strip()
            # IP 情報（<path>|<field>）が無い旧形式のみ、どの field か特定できないので安全側で
            # check 全体を劣化扱い。新形式は per-IP で絞るためここでは拾わない。
            if check and not (sep and "|" in ipinfo):
                degraded.add(check)
    return frozenset(degraded)


def _field_budget_degraded_ips(wave_errors) -> frozenset:
    """IP 情報付き field_budget note から (check, path, field) 集合を作る（純粋・R4#2）。

    時間ボックスで打ち切った当該 injection point の tested 行だけを NOT_REACHED にし、同 check の
    別 field の完全実行行を巻き込まないためのキー。"""
    ips = set()
    for note in (wave_errors or []):
        if not isinstance(note, str) or not note.startswith(_FIELD_BUDGET_PREFIX):
            continue
        check, sep, ipinfo = note[len(_FIELD_BUDGET_PREFIX):].partition(":")
        if not (sep and "|" in ipinfo):
            continue
        path, _, field = ipinfo.partition("|")
        ips.add((check.strip(), path, field))
    return frozenset(ips)


def _row_exercised(row, degraded_checks, field_budget_ips=frozenset()) -> bool:
    """1 行が exercised か。finding は送達の陽性証拠なので常に採る。tested は劣化なら除く。

    - finding: 実際に finding を出した＝probe が送達され check が走った陽性証拠。劣化があっても採る
      （別 field の transport error で成功検出まで消さない・Codex #134 P2）。
    - tested: 空振り。probe が送達したか曖昧なので、劣化 check（transport 握りつぶし等）または
      当該 injection point が時間ボックスで打ち切られた（field_budget_ips）場合は除く。
    - error/skip 等: 未計測なので採らない。
    """
    status = row.get("status")
    if status == "finding":
        return True
    if status == "tested":
        check = str(row.get("check", ""))
        if check in degraded_checks:
            return False
        ip = (
            check,
            urlparse(str(row.get("url", "") or "")).path,
            str(row.get("field_name", "")),
        )
        return ip not in field_budget_ips
    return False


def _exercised_from_scan_matrix(
    scan_matrix, degraded_checks=frozenset(), field_budget_ips=frozenset()
) -> frozenset:
    """scan_matrix から (check, path, field, location) の exercised 集合を作る（純粋）。

    finding/tested（成功して突いた）行を採り、error/skip は未計測なので除く。degraded_checks
    （transport 握りつぶし等が観測された check）の曖昧な tested 行と、field_budget_ips（時間ボックスで
    打ち切った injection point）の tested 行は除くが、finding 行は残す（送達の陽性証拠・#134 P1/P2）。
    location は正規化する。"""
    return frozenset(
        (
            str(row.get("check", "")),
            urlparse(str(row.get("url", "") or "")).path,
            str(row.get("field_name", "")),
            _normalize_location(row.get("location", "")),
        )
        for row in (scan_matrix or [])
        if _row_exercised(row, degraded_checks, field_budget_ips)
    )


class ScanEngineScanRunner(ScanRunner):
    def __init__(self, timeout: float = 840.0) -> None:
        if not math.isfinite(timeout) or timeout <= 0:
            raise ValueError("timeout must be finite and positive")
        self.timeout = timeout

    def __call__(self, base_url: str, checks: list[str]) -> ScanOutcome:
        # 単体テスト/manifest 読み込み時には engine/browser を引き込まない。
        from wscan.engine import ScanEngine

        async def scan(output_dir: str) -> ScanOutcome:
            engine = ScanEngine(
                base_url.rstrip("/") + "/", checks=list(checks), llm_provider="none",
                headless=True, output_dir=output_dir, open_report=False,
                enable_waf_detection=False, enable_ai_analysis=False,
                enable_payload_learning=False, enable_adaptive_payloads=False,
                enable_sitemap_crawl=False, depth=2, fast_mode=True, max_payloads=8,
                request_delay=0, use_planner=False, sarif=False, timeout=8,
                navigation_retries=0,
            )
            await asyncio.wait_for(engine.run(), timeout=self.timeout)
            # 実際に「成功して」攻撃した注入点の実行台帳（scan_matrix）から exercised を作る。
            # crawler 未到達/errored/別 carrier だけ/transport 劣化した case を NOT_REACHED にし
            # TN/FN に混ぜない（#134）。ScanEngineScanRunner は前提を用意しない匿名スキャンなので
            # fulfilled_prerequisites は空（前提付き case は score 側で UNSUPPORTED）。
            wave = getattr(engine, "wave_errors", None)
            degraded = _degraded_checks(wave)
            fb_ips = _field_budget_degraded_ips(wave)
            exercised = _exercised_from_scan_matrix(
                getattr(engine, "scan_matrix", None),
                degraded_checks=degraded,
                field_budget_ips=fb_ips,
            )
            return ScanOutcome(findings=list(engine.all_findings), exercised=exercised)

        # worker が終了するまで出力先を保持し、例外/キャンセル時も後始末する。
        with tempfile.TemporaryDirectory(prefix="wscan-benchmark-") as output_dir:
            return asyncio.run(scan(output_dir))
