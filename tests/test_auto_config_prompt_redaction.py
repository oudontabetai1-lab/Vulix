"""Regression coverage for free-form auto-config data sent to LLM providers."""
from __future__ import annotations

import json
import types

import pytest


SECRET_TEXT = (
    "Inspect https://alice:userinfo-secret@shop.example/login?token=query-secret; "
    "Django and React with a login page. password=field-secret; "
    "Authorization: Bearer bearer-secret; Cookie: sessionid=cookie-secret; "
    "configured-credential-secret; prioritize XSS."
)


def _valid_response() -> str:
    return json.dumps({"checks": ["xss"], "depth": 3, "notes": "Django login"})


def _assert_prompt_redacted(prompt: str) -> None:
    for secret in (
        "userinfo-secret", "query-secret", "field-secret", "bearer-secret",
        "cookie-secret", "configured-credential-secret", "alice:",
    ):
        assert secret not in prompt
    for useful_context in (
        "shop.example/login", "Django", "React", "login page", "XSS",
    ):
        assert useful_context in prompt
    assert "<untrusted_target_data" in prompt


@pytest.mark.asyncio
async def test_description_api_redacts_secrets_and_returns_privacy_notice(monkeypatch):
    from wscan import auto_config, url_scope

    captured = {}

    class FakePayloadGenerator:
        async def _check_llm_available(self):
            return True

    async def fake_provider_call(_pg, prompt, **_kwargs):
        captured["prompt"] = prompt
        return _valid_response()

    monkeypatch.setitem(
        url_scope._SECRET_VALUES,
        "configured-credential-secret",
        "configured_provider_credential",
    )
    monkeypatch.setattr(auto_config, "_call_llm", fake_provider_call)

    result = await auto_config.generate_from_description(
        FakePayloadGenerator(), SECRET_TEXT
    )

    _assert_prompt_redacted(captured["prompt"])
    assert result["checks"] == ["xss"]
    assert result["depth"] == 3
    assert result["privacy_notice"] == auto_config._PRIVACY_NOTICE


@pytest.mark.asyncio
async def test_cli_wizard_redacts_each_free_form_section_and_notifies_user(
    monkeypatch, capsys,
):
    from wscan import auto_config, url_scope

    captured = {}

    class FakePayloadGenerator:
        provider = "ollama"

        async def _check_llm_available(self):
            return True

    async def fake_provider_call(_pg, prompt, **_kwargs):
        captured["prompt"] = prompt
        return _valid_response()

    monkeypatch.setitem(
        url_scope._SECRET_VALUES,
        "configured-credential-secret",
        "configured_provider_credential",
    )
    monkeypatch.setattr(auto_config, "_call_llm", fake_provider_call)
    monkeypatch.setattr(
        auto_config,
        "_ask_multiline",
        lambda _prompt: next(iter(sections.pop(0))),
    )
    sections = [
        [SECRET_TEXT],
        ["Do not use password=prohibited-secret; Cookie: sessionid=prohibited-cookie."],
        ["Run XSS and do not send Bearer required-bearer-secret."],
    ]
    monkeypatch.setattr(auto_config, "_ask", lambda *_args, **_kwargs: "y")

    await auto_config.run_wizard(FakePayloadGenerator())

    prompt = captured["prompt"]
    _assert_prompt_redacted(prompt)
    for secret in (
        "prohibited-secret", "prohibited-cookie", "required-bearer-secret",
    ):
        assert secret not in prompt
    assert "Do not use" in prompt and "Run XSS" in prompt
    assert auto_config._PRIVACY_NOTICE in capsys.readouterr().out


@pytest.mark.asyncio
async def test_api_does_not_claim_redaction_when_input_has_no_detected_secrets(monkeypatch):
    from wscan import auto_config

    class FakePayloadGenerator:
        async def _check_llm_available(self):
            return True

    async def fake_provider_call(_pg, _prompt, **_kwargs):
        return _valid_response()

    monkeypatch.setattr(auto_config, "_call_llm", fake_provider_call)
    result = await auto_config.generate_from_description(
        FakePayloadGenerator(), "Django storefront with a login page; prioritize XSS."
    )

    assert result["privacy_notice"] == ""


@pytest.mark.asyncio
async def test_setup_cli_redacts_target_description_before_direct_provider_call(
    monkeypatch, capsys,
):
    import main
    from wscan import auto_config, payload_gen, url_scope

    captured = {}

    class FakePayloadGenerator:
        def __init__(self, **_kwargs):
            pass

        async def _check_llm_available(self):
            return True

    async def fake_provider_call(_pg, prompt, **_kwargs):
        captured["prompt"] = prompt
        return json.dumps({
            "checks": ["xss"], "depth": 2, "reason": "Django login", "flags": [],
        })

    monkeypatch.setitem(
        url_scope._SECRET_VALUES,
        "configured-credential-secret",
        "configured_provider_credential",
    )
    monkeypatch.setattr(payload_gen, "PayloadGenerator", FakePayloadGenerator)
    monkeypatch.setattr(auto_config, "_call_llm", fake_provider_call)
    args = main.parse_args(["setup", SECRET_TEXT, "--llm", "ollama"])

    await main.run_setup(args)

    _assert_prompt_redacted(captured["prompt"])
    assert auto_config._PRIVACY_NOTICE in capsys.readouterr().out
