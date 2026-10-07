"""レポート多言語化の「ja 既定出力＝旧 main とバイト不変」回帰用の固定入力。

`tests/fixtures/report_i18n_baseline/` の期待バイト列は、多言語化前の main の
`ReportGenerator`/`SarifExporter` にこの入力を与えて生成したもの。i18n 非依存の
API だけを使う（旧 main でも同じ入力を再生成できるようにする）。
"""
import datetime
from unittest import mock

FIXED_NOW = datetime.datetime(2026, 1, 2, 3, 4, 5)
TEMPLATES = ("audit", "executive", "developer")
CHECKS = ["sqli", "xss", "privesc_unauth", "graphql_introspection"]


def _findings():
    from wscan.remediation import _get_static
    from wscan.scanners.base import Finding

    out = []
    for i, (ct, sev, state) in enumerate([
        ("sqli", "high", "reproduced"),
        ("xss", "medium", "assumed"),
        ("privesc_unauth", "critical", "assumed"),
    ]):
        f = Finding(check_type=ct, severity=sev, url=f"http://fixture.test/p{i}", field_name="q",
                    payload="'\"<script>", evidence="証拠 <b>&</b>", timestamp=0.0,
                    verification_state=state, confidence="likely")
        f.ai_fix = _get_static(ct)
        out.append(f)
    out[1]._diff_status = "new"
    out[2]._diff_status = "persistent"
    return out


def _attack_plans():
    from wscan.attack_planner import FieldAttackPlan, PageAttackPlan

    field = FieldAttackPlan(name="q", form_index=0, is_url_param=True, risk_score=8,
                            priority_checks=["sqli", "xss"], rationale="検索パラメータ",
                            custom_payloads={"sqli": ["' OR 1=1--"], "xss": ["<svg onload=1>"]})
    return [PageAttackPlan(url="http://fixture.test/p0", page_purpose="検索",
                           planned_by="llm", fields=[field])]


def _page_graph():
    return {
        "http://fixture.test/": {"parent": "", "depth": 0, "forms": 1, "inputs": 2, "params": 0},
        "http://fixture.test/p0": {
            "parent": "http://fixture.test/", "depth": 1, "forms": 1, "inputs": 1, "params": 1,
            "via": {"text": "検索 </script>", "selector": "a#s",
                    "rect": {"x": 1, "y": 2, "width": 3, "height": 4},
                    "viewport": {"width": 100, "height": 100}},
        },
    }


def render_all(output_dir):
    """全テンプレートの HTML と SARIF を固定時刻で生成し {name: bytes} を返す。"""
    from wscan.report import ReportGenerator
    from wscan.sarif import SarifExporter

    findings = _findings()
    kwargs = dict(
        target="http://fixture.test/", findings=findings,
        visited_urls=["http://fixture.test/", "http://fixture.test/p0"], checks=CHECKS,
        attack_plans=_attack_plans(), page_graph=_page_graph(),
        observability={"total": 2, "by_category": {"transport_error": 2},
                       "samples": ["transport_error:sqli:TimeoutError"], "llm_calls": 1},
        llm_summary={"provider": "none"},
    )
    out = {}
    with mock.patch("wscan.report.datetime") as dt:
        dt.datetime.now.return_value = FIXED_NOW
        for template in TEMPLATES:
            path = ReportGenerator(output_dir).generate(template=template, **kwargs)
            out[f"{template}.html"] = path.read_bytes()
    sarif = SarifExporter().export([f.to_dict() for f in findings], target_url="http://fixture.test/")
    import json
    out["report.sarif.json"] = json.dumps(sarif, ensure_ascii=False, indent=2, sort_keys=True).encode()
    return out
