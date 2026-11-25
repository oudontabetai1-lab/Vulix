"""Unit tests for wscan.runtime_scope_guard."""
from __future__ import annotations

import asyncio
from types import SimpleNamespace
import pytest
import httpx

from wscan.runtime_scope_guard import (
    OutOfScopeUrlError,
    ScopeDecision,
    ScopePolicy,
    RuntimeScopeGuardHook,
    evaluate_scope,
    _is_url_excluded_by_patterns,
)
from wscan.engine import is_url_excluded


def test_scope_policy_from_engine():
    engine = SimpleNamespace(
        target_urls=["http://example.com/app"],
        access_urls=["http://example.com/docs"],
        exclude_urls=["/logout"],
        login_url="http://auth.example.com/login",
    )
    policy = ScopePolicy.from_engine(engine)
    assert policy.target_urls == ("http://example.com/app",)
    assert policy.access_urls == ("http://example.com/docs",)
    assert policy.exclude_urls == ("/logout",)
    assert policy.login_url == "http://auth.example.com/login"
    assert policy.is_configured is True
    assert policy.allow_external is False


def test_scope_policy_unconfigured():
    engine = SimpleNamespace()
    policy = ScopePolicy.from_engine(engine)
    assert policy.is_configured is False
    # Unconfigured policy allows requests
    decision = evaluate_scope("http://anywhere.com", policy)
    assert decision.allowed is True
    assert decision.reason == "unconfigured_policy"


def test_evaluate_scope_target_and_access():
    policy = ScopePolicy(
        target_urls=("http://target.local:8080/app",),
        access_urls=("http://target.local:8080/docs", "http://cdn.local:8080"),
        login_url="http://target.local:8080/auth/login",
        exclude_urls=("/logout", "*/secret/*"),
    )

    # Valid target paths
    assert evaluate_scope("http://target.local:8080/app", policy).allowed is True
    assert evaluate_scope("http://target.local:8080/app/users", policy).allowed is True
    assert evaluate_scope("http://target.local:8080/app?page=1", policy).allowed is True
    assert evaluate_scope("http://target.local:8080/app#section", policy).allowed is True

    # Access paths
    assert evaluate_scope("http://target.local:8080/docs/readme", policy).allowed is True
    assert evaluate_scope("http://cdn.local:8080/asset.js", policy).allowed is True

    # Login URL
    assert evaluate_scope("http://target.local:8080/auth/login", policy).allowed is True

    # Excluded URLs
    dec_logout = evaluate_scope("http://target.local:8080/logout", policy)
    assert dec_logout.allowed is False
    assert dec_logout.reason == "excluded_url"

    dec_wild = evaluate_scope("http://target.local:8080/app/secret/token", policy)
    assert dec_wild.allowed is False
    assert dec_wild.reason == "excluded_url"

    # Out of scope URLs
    dec_cross_port = evaluate_scope("http://target.local:9999/app", policy)
    assert dec_cross_port.allowed is False
    assert dec_cross_port.reason == "out_of_scope_destination"

    dec_cross_host = evaluate_scope("http://evil.com/leak", policy)
    assert dec_cross_host.allowed is False
    assert dec_cross_host.reason == "out_of_scope_destination"

    dec_cross_scheme = evaluate_scope("https://target.local:8080/app", policy)
    assert dec_cross_scheme.allowed is False
    assert dec_cross_scheme.reason == "out_of_scope_destination"


def test_evaluate_scope_default_port_normalization():
    policy = ScopePolicy(target_urls=("http://example.com/app",))
    # Explicit port 80 for http should match
    dec = evaluate_scope("http://example.com:80/app/users", policy)
    assert dec.allowed is True
    assert dec.reason == "target_url"


def test_evaluate_scope_malformed_and_empty():
    policy = ScopePolicy(target_urls=("http://example.com",))
    assert evaluate_scope("", policy).allowed is False
    assert evaluate_scope("   ", policy).allowed is False
    assert evaluate_scope("javascript:alert(1)", policy).allowed is False
    assert evaluate_scope("file:///etc/passwd", policy).allowed is False


def test_evaluate_scope_normalizes_backslashes():
    policy = ScopePolicy(target_urls=("http://target.local:8080/app",))
    # WHATWG URL standard treats backslashes in http/https schemes as slashes
    dec_evil = evaluate_scope("http://evil.test\\@target.local:8080/app", policy)
    assert dec_evil.allowed is False
    assert dec_evil.reason == "out_of_scope_destination"

    dec_schemeless = evaluate_scope("\\\\evil.com/leak", policy)
    assert dec_schemeless.allowed is False
    assert dec_schemeless.reason == "unsupported_scheme"

    dec_in_scope = evaluate_scope("http://target.local:8080/app\\subpath", policy)
    assert dec_in_scope.allowed is True


def test_evaluate_scope_allow_external():
    policy = ScopePolicy(target_urls=("http://example.com",), allow_external=True)
    dec = evaluate_scope("https://external-api.com/v1", policy)
    assert dec.allowed is True
    assert dec.reason == "allow_external"


def test_evaluate_scope_exclusions_precede_allow_external():
    policy = ScopePolicy(
        target_urls=("http://example.com",),
        allow_external=True,
        exclude_urls=("https://external-api.com/blocked", "/admin*"),
    )
    # Excluded destinations must be blocked even when allow_external is True
    dec_blocked = evaluate_scope("https://external-api.com/blocked", policy)
    assert dec_blocked.allowed is False
    assert dec_blocked.reason == "excluded_url"

    dec_blocked_pattern = evaluate_scope("https://external-api.com/admin/delete", policy)
    assert dec_blocked_pattern.allowed is False
    assert dec_blocked_pattern.reason == "excluded_url"

    # Non-excluded external destinations remain allowed
    dec_allowed = evaluate_scope("https://external-api.com/allowed", policy)
    assert dec_allowed.allowed is True
    assert dec_allowed.reason == "allow_external"


def test_evaluate_scope_unconfigured_with_exclusions_only():
    policy = ScopePolicy(exclude_urls=("/logout", "http://evil.com/*"))
    # Excluded matches are blocked even when policy has no positive target scope
    dec_block = evaluate_scope("http://evil.com/leak", policy)
    assert dec_block.allowed is False
    assert dec_block.reason == "excluded_url"

    # Non-excluded URLs pass through unconfigured policy
    dec_pass = evaluate_scope("http://other.com/page", policy)
    assert dec_pass.allowed is True
    assert dec_pass.reason == "unconfigured_policy"


def test_evaluate_scope_allowed_external_origins():
    policy = ScopePolicy(
        target_urls=("http://example.com",),
        allowed_external_origins=("https://oob-sink.net:8443",),
    )
    dec = evaluate_scope("https://oob-sink.net:8443/poll", policy)
    assert dec.allowed is True
    assert dec.reason == "allowed_external_origin"

    dec2 = evaluate_scope("https://other-sink.net/poll", policy)
    assert dec2.allowed is False
    assert dec2.reason == "out_of_scope_destination"


def test_scope_guard_hook_blocks_redirect_mock():
    policy = ScopePolicy(target_urls=("http://target.com",))
    blocked_events = []

    def on_block(req, dec):
        blocked_events.append((str(req.url), dec.reason))

    hook = RuntimeScopeGuardHook(policy, on_block=on_block)

    class MockRedirectTransport(httpx.HTTPTransport):
        def handle_request(self, request):
            if "start" in str(request.url):
                return httpx.Response(302, headers={"Location": "http://evil.com/steal"}, request=request)
            return httpx.Response(200, text="ok", request=request)

    client = httpx.Client(
        transport=MockRedirectTransport(),
        event_hooks={"request": [hook]},
        follow_redirects=True,
    )

    with pytest.raises(OutOfScopeUrlError) as exc_info:
        client.get("http://target.com/start")

    assert exc_info.value.reason == "out_of_scope_destination"
    assert "http://evil.com/steal" in str(exc_info.value)
    assert len(blocked_events) == 1
    assert blocked_events[0] == ("http://evil.com/steal", "out_of_scope_destination")


@pytest.mark.asyncio
async def test_scope_guard_hook_async_mock():
    policy = ScopePolicy(target_urls=("http://target.com",))
    hook = RuntimeScopeGuardHook(policy)

    class MockAsyncRedirectTransport(httpx.AsyncHTTPTransport):
        def __init__(self):
            self.evil_called = False

        async def handle_async_request(self, request):
            if "start" in str(request.url):
                return httpx.Response(302, headers={"Location": "http://evil.com/leak"}, request=request)
            if "evil.com" in str(request.url):
                self.evil_called = True
                return httpx.Response(200, text="evil reached", request=request)
            return httpx.Response(200, text="ok", request=request)

    transport = MockAsyncRedirectTransport()
    client = httpx.AsyncClient(
        transport=transport,
        event_hooks={"request": [hook]},
        follow_redirects=True,
    )

    with pytest.raises(OutOfScopeUrlError):
        await client.get("http://target.com/start")

    # Assert the mock transport NEVER received the request to evil.com
    assert transport.evil_called is False


@pytest.mark.parametrize("url,pattern", [
    ("http://h/foo/admin-action", "admin"),
    ("http://h/administrator", "/admin"),
    ("http://h/admin", "/admin/*"),
    ("http://h/ADMIN?x=1", "/admin"),
    ("http://h/admin?x=1", "http://h/admin"),
])
def test_guard_exclusions_match_legacy_engine_contract(url, pattern):
    expected = is_url_excluded(url, (pattern,))
    assert expected is True
    assert _is_url_excluded_by_patterns(url, (pattern,)) is expected
