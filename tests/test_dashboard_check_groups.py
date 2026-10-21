import re
from pathlib import Path

from wscan.scanners import SCANNERS


def test_dashboard_check_groups_match_scanner_registry():
    html = (Path(__file__).parents[1] / "templates" / "dashboard.html").read_text(encoding="utf-8")
    groups = html.split("const CHECK_GROUPS = {", 1)[1].split("\n};", 1)[0]
    visible = re.findall(r"\{id:'([^']+)'", groups)

    assert len(visible) == len(set(visible))
    defaults = re.findall(r"\{id:'([^']+)'[^\n]*def:(true|false)\}", groups)
    assert {check for check, enabled in defaults if enabled == "true"} == {"sqli", "os", "xss"}
    assert set(visible) == set(SCANNERS)
