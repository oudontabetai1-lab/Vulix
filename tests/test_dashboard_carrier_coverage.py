import asyncio
from argparse import Namespace

import pytest
from fastapi.testclient import TestClient

import main
from wscan.scanner_contract import build_capability_matrix, render_capability_matrix_html
from wscan.scanners import SCANNERS


@pytest.mark.parametrize("lang", ["ja", "en"])
def test_serve_defaults_expose_the_existing_report_matrix(monkeypatch, lang):
    captured = {}

    class ServerConfigured(Exception):
        pass

    def capture_config(*, app, **kwargs):
        captured["app"] = app
        raise ServerConfigured

    monkeypatch.setattr("uvicorn.Config", capture_config)
    monkeypatch.setattr(main, "_CFG", {"report_lang": lang, "auth_pass": "secret"})
    with pytest.raises(ServerConfigured):
        asyncio.run(main.run_serve(Namespace(port=0, host="127.0.0.1")))

    client = TestClient(captured["app"])
    response = client.get("/api/config/defaults")
    assert response.status_code == 200
    defaults = response.json()
    expected = render_capability_matrix_html(
        build_capability_matrix({name: cls.CONTRACT for name, cls in SCANNERS.items()}),
        lang=lang,
    )
    assert defaults["capability_matrix_html"] == expected
    assert defaults["auth_pass"] == ""
    assert "value_kinds=" in expected
    assert "reason=" in expected
    assert ">P</td>" in expected
    assert ">U</td>" in expected
    assert ">s</td>" in expected
    dashboard = client.get("/monitor").text
    assert 'id="carrierCoverageMatrix"' in dashboard
    assert "cfg.capability_matrix_html" in dashboard


def test_report_matrix_renderer_does_not_change_its_input():
    import copy

    matrix = build_capability_matrix({name: cls.CONTRACT for name, cls in SCANNERS.items()})
    original = copy.deepcopy(matrix)
    render_capability_matrix_html(matrix)
    assert matrix == original
    assert render_capability_matrix_html({}) == ""
