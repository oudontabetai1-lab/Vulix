"""Evidence schemas preserve the existing wire format and origin labels."""
import json
from types import SimpleNamespace

import pytest

from wscan.agent_engine import _convert_agent_findings
from wscan.finding_provenance import AgentEvidenceDetails, JsStaticEvidenceDetails
from wscan.report import ReportGenerator
from wscan.scanners.base import Finding


@pytest.mark.parametrize("dynamic_verified", [False, True])
@pytest.mark.parametrize("agent_verified", [False, True])
def test_agent_origin_and_replay_survive_round_trip(
    dynamic_verified, agent_verified, tmp_path,
):
    candidate = SimpleNamespace(
        check_type="xss", severity="high", url="https://fixture.test/search",
        field_name="q", payload="probe", evidence="agent observation",
        dynamic_verified=dynamic_verified, agent_verified=agent_verified,
    )
    finding, = _convert_agent_findings([candidate])
    assert finding.evidence_details == AgentEvidenceDetails(
        agent_dynamic_reproduced=dynamic_verified,
    )
    restored = Finding.from_dict(json.loads(json.dumps(finding.to_dict())))
    assert restored.source == "agent"
    assert restored.agent_verified is agent_verified
    assert restored.evidence_details == finding.evidence_details
    assert restored.verification_state == "assumed"
    assert restored.verified is False
    report = ReportGenerator(tmp_path)
    badges = report._agent_badges_html(restored)
    if agent_verified:
        assert "✅ 決定論的にも再現確認済み" in badges
    else:
        assert "🤖 Agent発見（LLM独自解釈・未確証）" in badges
    assert 'class="badge-unconfirmed"' in report._verification_badges_html(restored)


def test_static_evidence_and_unknown_keys_survive_round_trip(tmp_path):
    details = JsStaticEvidenceDetails(
        sink="innerHTML", source="location.hash", tainted=True, line=7,
        script="https://fixture.test/app.js", snippet="node.innerHTML = input",
    )
    finding = Finding(
        check_type="js_static", severity="medium", url="https://fixture.test/",
        field_name="script", payload="", evidence="static observation",
        evidence_type="js_dangerous_sink", evidence_details=details,
    )
    # Open storage still accepts scanner extensions and older checkpoint keys.
    finding.evidence_details["custom_origin"] = {"route": ["legacy", "extension"]}
    restored = Finding.from_dict(json.loads(json.dumps(finding.to_dict())))
    assert restored.evidence_details == {
        "sink": "innerHTML", "source": "location.hash", "tainted": True,
        "line": 7, "script": "https://fixture.test/app.js",
        "snippet": "node.innerHTML = input",
        "custom_origin": {"route": ["legacy", "extension"]},
    }
    assert restored.source == "scanner"
    assert restored.evidence_type == "js_dangerous_sink"
    assert restored.verification_state == "assumed"
    assert ReportGenerator(tmp_path)._agent_badges_html(restored) == ""
