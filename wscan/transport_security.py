"""Network-independent transport observations and bounded TLS handshakes."""
from __future__ import annotations

import asyncio
from datetime import datetime
from html.parser import HTMLParser
import ipaddress
import ssl
from urllib.parse import parse_qsl, urljoin, urlsplit
import xml.etree.ElementTree as ET

from wscan.url_scope import idna_host, redact_url


def method_difference(existing_status: int, missing_status: int,
                      probe_status: int, control_status: int) -> bool:
    """Require a reached resource and a real nonexistent sibling, not Allow alone."""
    return (200 <= existing_status < 300 and missing_status in (404, 410)
            and 200 <= probe_status < 300 and control_status in (404, 405, 410, 501))


def webdav_capabilities(status: int, body: str) -> list[str]:
    """A 207 alone is insufficient: require a DAV multistatus and resource response."""
    if status != 207:
        return []
    try:
        root = ET.fromstring(body)
    except ET.ParseError:
        return []
    if root.tag != "{DAV:}multistatus" or root.find("{DAV:}response/{DAV:}href") is None:
        return []
    capabilities = ["PROPFIND"]
    for item in root.findall(".//{DAV:}supported-method/{DAV:}method"):
        name = item.get("name", "").upper()
        if name and name not in capabilities:
            capabilities.append(name)
    return sorted(capabilities)


def override_matches(canonical: tuple, overridden: tuple, baseline: tuple,
                     control: tuple) -> bool:
    """Compare status, Allow and body against both normal and invalid-override GET."""
    return (200 <= canonical[0] < 300 and canonical == overridden
            and overridden != baseline and control == baseline)


def https_redirect_status(url: str, status: int, location: str) -> str:
    """Observe the first hop only; HTTP redirect chains are not secure upgrades."""
    if urlsplit(url).scheme != "http":
        return "not_applicable"
    if status in (301, 302, 303, 307, 308) and location:
        return "upgraded" if urlsplit(urljoin(url, location)).scheme == "https" else "insecure_redirect"
    return "plaintext" if 200 <= status < 300 else "unknown"


def plaintext_sensitive_fields(request: dict) -> list[str]:
    """Return only names of secrets in observed HTTP requests; never their values."""
    from wscan.scanners.base import _is_credential_header
    target = request.get("url", "")
    parts = urlsplit(target)
    if parts.scheme != "http":
        return []
    fields = {f"header:{k.lower()}" for k, v in (request.get("headers") or {}).items()
              if v and _is_credential_header(k)}
    if parts.username or parts.password:
        fields.add("url:userinfo")
    clean = urlsplit(redact_url(target, drop_userinfo=True))
    for (name, value), (_, redacted) in zip(parse_qsl(parts.query), parse_qsl(clean.query)):
        if value != redacted:
            fields.add(f"query:{name}")
    body = request.get("post_data") or ""
    # Captured form/JSON names are enough evidence; do not store submitted data.
    if isinstance(body, str):
        import json
        try:
            data = json.loads(body)
        except ValueError:
            data = dict(parse_qsl(body))
        if isinstance(data, dict):
            for name, value in data.items():
                if value and str(name).lower() in {"password", "passwd", "token", "access_token", "api_key"}:
                    fields.add(f"body:{name}")
    return sorted(fields)


class _ActiveContentParser(HTMLParser):
    # Raw-text/RCDATA elements: their contents are text, never parsed as elements by browsers.
    CDATA_CONTENT_ELEMENTS = ("script", "style", "textarea", "title", "xmp", "iframe", "noembed", "noframes")

    def __init__(self, url):
        super().__init__()
        self.base = url
        self.base_seen = False
        self.resources = set()
        self.inert_depth = 0
        self.plaintext = False

    def handle_startendtag(self, tag, attrs):
        # HTML に自己閉じ記法は無い: <textarea/> 等も RCDATA/raw text 領域を開く。
        self.handle_starttag(tag, attrs)
        if tag in self.CDATA_CONTENT_ELEMENTS:
            self.set_cdata_mode(tag)

    def handle_starttag(self, tag, attrs):
        if tag == "plaintext":  # PLAINTEXT 状態: 終了タグ無しで以降すべて literal text
            self.plaintext = True
        if self.plaintext:
            return
        if tag in {"template", "noscript"}:
            self.inert_depth += 1
        if self.inert_depth:
            return
        attrs = dict(attrs)
        if tag == "base" and attrs.get("href") and not self.base_seen:
            self.base = urljoin(self.base, attrs["href"])
            self.base_seen = True
        key = {"script": "src", "iframe": "src", "object": "data", "embed": "src"}.get(tag)
        if tag == "script" and attrs.get("type", "").lower().strip() not in {
                "", "module", "text/javascript", "application/javascript", "text/ecmascript", "application/ecmascript"}:
            return
        if tag == "link" and "stylesheet" in attrs.get("rel", "").lower().split():
            key = "href"
        if key and attrs.get(key):
            target = urljoin(self.base, attrs[key])
            if urlsplit(target).scheme == "http":
                self.resources.add(redact_url(target, drop_userinfo=True))

    def handle_endtag(self, tag):
        if tag in {"template", "noscript"} and self.inert_depth:
            self.inert_depth -= 1


_HTML_DOCUMENT_MEDIA_TYPES = frozenset({"text/html", "application/xhtml+xml"})


def document_kind(content_type: str) -> str:
    """Classify the real response: ``html`` / ``non_html`` / ``unknown`` (no Content-Type)."""
    media = (content_type or "").split(";", 1)[0].strip().lower()
    if not media:
        return "unknown"
    return "html" if media in _HTML_DOCUMENT_MEDIA_TYPES else "non_html"


def active_mixed_content(url: str, html: str) -> list[str]:
    """Declared executable/embed/style resources, excluding passive images and links."""
    if urlsplit(url).scheme != "https":
        return []
    parser = _ActiveContentParser(url)
    parser.feed(html or "")
    return sorted(parser.resources)


def hostname_matches(host: str, dns_names: list[str], ip_names: list[str]) -> bool:
    """SAN matching: wildcard covers exactly one complete DNS label, IP uses IP SAN."""
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        host = idna_host(host)
        for name in dns_names:
            name = idna_host(name)
            if name == host:
                return True
            if name.startswith("*.") and name.count("*") == 1:
                suffix = name[2:]
                if host.endswith("." + suffix) and len(host.split(".")) == len(suffix.split(".")) + 1:
                    return True
        return False
    return any(address == ipaddress.ip_address(name) for name in ip_names)


def certificate_facts(der: bytes, host: str) -> dict:
    """Decode the peer leaf; cryptography is optional, failures become coverage gaps."""
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import ec, rsa, dsa
    cert = x509.load_der_x509_certificate(der)
    try:
        san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
        dns = san.get_values_for_type(x509.DNSName)
        ips = [str(ip) for ip in san.get_values_for_type(x509.IPAddress)]
    except x509.ExtensionNotFound:
        dns, ips = [], []
    key = cert.public_key()
    kind = "RSA" if isinstance(key, rsa.RSAPublicKey) else "EC" if isinstance(key, ec.EllipticCurvePublicKey) else "DSA" if isinstance(key, dsa.DSAPublicKey) else type(key).__name__
    algorithm = cert.signature_hash_algorithm
    return {
        "fingerprint_sha256": cert.fingerprint(hashes.SHA256()).hex(),
        "not_before": cert.not_valid_before_utc.isoformat(),
        "not_after": cert.not_valid_after_utc.isoformat(),
        "hostname_match": hostname_matches(host, dns, ips),
        "signature_hash": algorithm.name if algorithm else "intrinsic",
        "signature_algorithm": cert.signature_algorithm_oid.dotted_string,
        "key_type": kind, "key_bits": getattr(key, "key_size", None),
    }


def tls_weaknesses(facts: dict, now: datetime) -> list[str]:
    """Classify facts only; unknown attributes must be accounted for by the caller."""
    issues = []
    for field, kind, compare in (("not_after", "certificate_expired", lambda a, b: a < b),
                                 ("not_before", "certificate_not_yet_valid", lambda a, b: a > b)):
        if facts.get(field) and compare(datetime.fromisoformat(facts[field]), now):
            issues.append(kind)
    if facts.get("hostname_match") is False:
        issues.append("certificate_hostname")
    if facts.get("trust_chain") is False:
        issues.append("certificate_trust")
    if facts.get("signature_hash", "").lower() in {"md5", "sha1"}:
        issues.append("certificate_signature")
    bits = facts.get("key_bits")
    if bits and ((facts.get("key_type") in {"RSA", "DSA"} and bits < 2048)
                 or (facts.get("key_type") == "EC" and bits < 224)):
        issues.append("certificate_key")
    if facts.get("protocol") in {"SSLv2", "SSLv3", "TLSv1", "TLSv1.1"}:
        issues.append("negotiated_protocol")
    if weak_cipher(facts.get("cipher", ""), facts.get("cipher_bits")):
        issues.append("negotiated_cipher")
    return issues


def weak_cipher(name: str, bits: int | None = None) -> bool:
    name = name.upper()
    return bool(name and (any(part in name for part in ("RC4", "DES", "NULL", "EXPORT", "ANON", "ADH-", "AECDH-"))
                         or (bits is not None and bits < 128)))


async def observe_tls(host: str, port: int, timeout: float, ca_cert: str = "") -> tuple[dict, list[str]]:
    """Separate chain validation from leaf collection; never send HTTP credentials."""
    facts, gaps = {}, []

    async def handshake(context):
        _, writer = await asyncio.wait_for(asyncio.open_connection(
            host, port, ssl=context, server_hostname=host,
            ssl_handshake_timeout=timeout), timeout=timeout)
        try:
            peer = writer.get_extra_info("ssl_object")
            cipher = peer.cipher()
            return {"protocol": peer.version(), "cipher": cipher[0], "cipher_bits": cipher[2]}, peer.getpeercert(binary_form=True)
        finally:
            writer.close()
            try:
                await asyncio.wait_for(writer.wait_closed(), timeout=timeout)
            except (OSError, asyncio.TimeoutError):
                pass

    try:
        context = ssl.create_default_context(cafile=ca_cert or None)
        context.check_hostname = False  # chain validation is independent of SAN matching
        connection, der = await handshake(context)
        facts.update(connection, trust_chain=True)
    except ssl.SSLCertVerificationError as exc:
        facts.update(trust_chain=False, verify_code=exc.verify_code)
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        try:
            connection, der = await handshake(context)
            facts.update(connection)
        except (OSError, asyncio.TimeoutError):
            return facts, ["peer_certificate_unavailable", "negotiation_unavailable"]
    except (OSError, asyncio.TimeoutError):
        return facts, ["tls_handshake_unavailable"]
    try:
        facts.update(certificate_facts(der, host))
    except Exception:
        gaps.append("certificate_parser_unavailable")
    # shortcut: inspect leaf strength only, use a chain-aware analyzer for intermediate strength.
    gaps.append("intermediate_certificate_strength_not_inspected")
    return facts, gaps
