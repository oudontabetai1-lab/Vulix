"""Runtime Scope Guard for HTTP transport.

Provides deterministic destination scope evaluation and HTTPX pre-send redirect-hop
enforcement, ensuring no unauthorized network egress occurs during scanning.
"""
from __future__ import annotations

import dataclasses
import fnmatch
from typing import Any, Callable, Optional
from urllib.parse import urlparse, urlsplit

import httpx

from . import url_scope


class OutOfScopeUrlError(httpx.TransportError):
    """Raised when an HTTP request or redirect target is outside the configured runtime scope."""

    def __init__(
        self,
        message: str,
        *,
        request: Optional[httpx.Request] = None,
        url: str = "",
        reason: str = "",
    ) -> None:
        super().__init__(message)
        self.request = request
        self.url = url
        self.reason = reason


@dataclasses.dataclass(frozen=True)
class ScopeDecision:
    """Outcome of evaluating destination URL against scope policy."""

    allowed: bool
    reason: str
    url: str
    target: str = ""


@dataclasses.dataclass(frozen=True)
class ScopePolicy:
    """Normalized policy container for runtime scope evaluation."""

    target_urls: tuple[str, ...] = ()
    access_urls: tuple[str, ...] = ()
    exclude_urls: tuple[str, ...] = ()
    login_url: str = ""
    allow_external: bool = False
    allowed_external_origins: tuple[str, ...] = ()

    @property
    def is_configured(self) -> bool:
        """True if any target scope or explicit external restriction is set."""
        return bool(
            self.target_urls
            or self.access_urls
            or self.login_url
            or self.allowed_external_origins
        )

    @classmethod
    def from_engine(cls, engine: Any, **overrides) -> ScopePolicy:
        """Extract and normalize scope policy from a ScanEngine or similar context."""
        if "scope_policy" in overrides and isinstance(
            overrides["scope_policy"], ScopePolicy
        ):
            return overrides["scope_policy"]

        allow_external = bool(overrides.get("allow_external", False))

        raw_targets = overrides.get("target_urls")
        if raw_targets is None:
            raw_targets = getattr(engine, "target_urls", None)
        if raw_targets is None:
            single = overrides.get("target_url") or getattr(engine, "target_url", None)
            raw_targets = [single] if single else []

        targets = tuple(
            u.strip().rstrip("/")
            for u in raw_targets
            if u and isinstance(u, str) and u.strip()
        )

        raw_access = overrides.get("access_urls")
        if raw_access is None:
            raw_access = getattr(engine, "access_urls", None)
        access = tuple(
            u.strip().rstrip("/")
            for u in (raw_access or ())
            if u and isinstance(u, str) and u.strip()
        )

        raw_excludes = overrides.get("exclude_urls")
        if raw_excludes is None:
            raw_excludes = getattr(engine, "exclude_urls", None)
        excludes = tuple(
            u.strip()
            for u in (raw_excludes or ())
            if u and isinstance(u, str) and u.strip()
        )

        login_url = str(
            overrides.get("login_url") or getattr(engine, "login_url", "") or ""
        ).strip()

        raw_ext = overrides.get("allowed_external_origins")
        if raw_ext is None:
            raw_ext = getattr(engine, "allowed_external_origins", None)
        allowed_ext = tuple(
            u.strip().rstrip("/")
            for u in (raw_ext or ())
            if u and isinstance(u, str) and u.strip()
        )

        return cls(
            target_urls=targets,
            access_urls=access,
            exclude_urls=excludes,
            login_url=login_url,
            allow_external=allow_external,
            allowed_external_origins=allowed_ext,
        )


def _is_url_excluded_by_patterns(url: str, exclude_urls: tuple[str, ...]) -> bool:
    """Compatibility wrapper around the engine's historical exclusion contract."""
    from .engine import is_url_excluded

    return is_url_excluded(url, exclude_urls)


def _matches_scope_list(url: str, scopes: tuple[str, ...]) -> bool:
    """Check if URL matches any entry in scopes using url_scope with origin/port normalization."""
    if not scopes:
        return False
    if url_scope.url_matches_any_scope(url, scopes):
        return True
    for scope in scopes:
        if scope.startswith(("http://", "https://")):
            if url_scope.same_origin(url, scope):
                req_p = url_scope.request_path(url)
                scope_p = url_scope.request_path(scope)
                if url_scope.path_within(req_p, scope_p):
                    return True
    return False


def evaluate_scope(url: str, policy: ScopePolicy) -> ScopeDecision:
    """Pure, deterministic evaluation of destination URL against ScopePolicy.

    Fail-closed: Unparseable URLs or non-HTTP schemes are rejected when policy is configured.
    """
    clean_url = str(url or "").strip()
    if not clean_url:
        return ScopeDecision(False, "empty_url", clean_url)

    try:
        parsed = urlsplit(clean_url)
    except Exception:
        return ScopeDecision(False, "malformed_url", clean_url)

    scheme = (parsed.scheme or "").lower()
    if scheme not in ("http", "https"):
        return ScopeDecision(False, "unsupported_scheme", clean_url)

    # 1. Exclusion check (explicit exclusions always take precedence over allow_external and positive scope)
    if policy.exclude_urls and _is_url_excluded_by_patterns(clean_url, policy.exclude_urls):
        return ScopeDecision(False, "excluded_url", clean_url)

    if not policy.is_configured:
        return ScopeDecision(True, "unconfigured_policy", clean_url)

    if policy.allow_external:
        return ScopeDecision(True, "allow_external", clean_url)

    # 2. Explicit external origins (e.g. preconfigured OOB sink)
    if policy.allowed_external_origins:
        for ext in policy.allowed_external_origins:
            if url_scope.same_origin(clean_url, ext):
                return ScopeDecision(True, "allowed_external_origin", clean_url, target=ext)

    # 3. Direct target scope match
    if _matches_scope_list(clean_url, policy.target_urls):
        return ScopeDecision(True, "target_url", clean_url)

    # 4. Direct access scope match
    if _matches_scope_list(clean_url, policy.access_urls):
        return ScopeDecision(True, "access_url", clean_url)

    # 5. Login URL match (if configured)
    if policy.login_url:
        if url_scope.url_in_scope(clean_url, policy.login_url) or url_scope.same_origin(
            clean_url, policy.login_url
        ):
            return ScopeDecision(True, "login_url", clean_url, target=policy.login_url)

    # 6. Fragment-stripped match (fragments are client-side only)
    no_frag = url_scope.without_fragment(clean_url)
    if no_frag != clean_url:
        if _matches_scope_list(no_frag, policy.target_urls):
            return ScopeDecision(True, "target_url_no_frag", clean_url)
        if _matches_scope_list(no_frag, policy.access_urls):
            return ScopeDecision(True, "access_url_no_frag", clean_url)

    # 7. Query-stripped match (for path-scoped targets without query)
    clean_no_query = url_scope.without_query(clean_url)
    if clean_no_query != clean_url:
        if _matches_scope_list(clean_no_query, policy.target_urls):
            return ScopeDecision(True, "target_url_no_query", clean_url)
        if _matches_scope_list(clean_no_query, policy.access_urls):
            return ScopeDecision(True, "access_url_no_query", clean_url)

    return ScopeDecision(False, "out_of_scope_destination", clean_url)


class RuntimeScopeGuardHook:
    """HTTPX pre-send request event hook enforcing ScopePolicy before any network transmission."""

    def __init__(
        self,
        policy: ScopePolicy,
        *,
        on_block: Optional[Callable[[httpx.Request, ScopeDecision], None]] = None,
    ) -> None:
        self.policy = policy
        self.on_block = on_block

    def __call__(self, request: httpx.Request) -> RuntimeScopeGuardHook:
        url_str = str(request.url)
        decision = evaluate_scope(url_str, self.policy)
        if not decision.allowed:
            if self.on_block is not None:
                try:
                    self.on_block(request, decision)
                except Exception:
                    pass
            raise OutOfScopeUrlError(
                f"Out-of-scope egress blocked by Runtime Scope Guard: {url_str} (reason: {decision.reason})",
                request=request,
                url=url_str,
                reason=decision.reason,
            )
        return self

    def __await__(self):
        async def _noop():
            pass

        return _noop().__await__()
