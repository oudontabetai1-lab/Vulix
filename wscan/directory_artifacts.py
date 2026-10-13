from __future__ import annotations

import base64
import json
import posixpath
import re
from dataclasses import dataclass
from difflib import SequenceMatcher
from html.parser import HTMLParser
from urllib.parse import unquote, urljoin, urlsplit, urlunsplit

from wscan.url_scope import same_origin


MAX_BODY = 1_000_000


class _Markup(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.stack = []
        self.headings = []
        self.links = []
        self.text = []
        self._heading = None
        self._anchor = None

    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        self.stack.append(tag)
        if tag in ("title", "h1"):
            self._heading = [tag, ""]
        if tag == "a":
            self._anchor = [attrs.get("href", ""), "", any(t in self.stack for t in ("pre", "table", "ul"))]
        if tag in ("a", "link", "script", "img"):
            href = attrs.get("src") if tag in ("script", "img") else attrs.get("href")
            if href:
                self.links.append((href, "", False))

    def handle_endtag(self, tag):
        if self._heading and tag == self._heading[0]:
            self.headings.append(self._heading[1].strip())
            self._heading = None
        if tag == "a" and self._anchor:
            self.links.append(tuple(self._anchor))
            self._anchor = None
        if tag in self.stack:
            self.stack = self.stack[:len(self.stack) - self.stack[::-1].index(tag) - 1]

    def handle_data(self, data):
        self.text.append(data)
        if self._heading:
            self._heading[1] += data
        if self._anchor:
            self._anchor[1] += data


def _markup(body: str) -> _Markup:
    parsed = _Markup()
    parsed.feed((body or "")[:MAX_BODY])
    parsed.close()
    return parsed


@dataclass(frozen=True)
class ListingObservation:
    signals: tuple[str, ...] = ()
    entries: tuple[str, ...] = ()
    family: str = ""
    error_page: bool = False

    @property
    def composite(self) -> bool:
        structural = {"parent_link", "columns", "multiple_entries", "dated_entries"}
        present = set(self.signals)
        return not self.error_page and (
            "heading" in present and bool(present & structural)
            or len(present & structural) >= 2 and "dated_entries" in present
            or "parent_link" in present and bool(present & (structural - {"parent_link"}))
        )


def classify_directory_listing(body: str, url: str = "") -> ListingObservation:
    parsed = _markup(body)
    signals = []
    heading = any(re.match(r"(?i)^(?:index of\s+/|directory listing for\s+/)", h) for h in parsed.headings)
    if heading:
        signals.append("heading")
    error = any(re.search(r"(?i)^(?:404\b|403\b|not found\b|access denied\b|error\b)", h) for h in parsed.headings)
    parent = False
    entries = []
    directory = urlsplit(url).path or "/"
    if not directory.endswith("/"):
        directory = posixpath.dirname(directory) + "/"
    for href, text, structured in parsed.links:
        label = text.strip()
        if href in ("../", "..") and label in ("../", "..", "Parent Directory", "[To Parent Directory]"):
            parent = True
            continue
        if label == "[To Parent Directory]" and href:
            parent = True
            continue
        if not structured or not label or href.startswith(("?", "#")):
            continue
        absolute = urljoin(url, href) if url else href
        parts = urlsplit(absolute)
        if url and not same_origin(url, absolute):
            continue
        path = unquote(parts.path)
        name = posixpath.basename(path.rstrip("/"))
        if label.rstrip("/") != name or not name or name in (".", ".."):
            continue
        if url and posixpath.dirname(parts.path.rstrip("/")) + "/" != directory:
            continue
        if href not in entries:
            entries.append(href)
    if parent:
        signals.append("parent_link")
    elif "[To Parent Directory]" in " ".join(parsed.text):
        signals.append("parent_marker")
    visible = " ".join(parsed.text)
    if re.search(r"(?i)\bName\b", visible) and re.search(r"(?i)\b(?:Last modified|Last write time)\b", visible) and re.search(r"(?i)\bSize\b", visible):
        signals.append("columns")
    elif re.search(r"(?i)href\s*=\s*['\"]\?C=[NMSD];O=[AD]", body or ""):
        signals.append("columns")
    if len(entries) >= 2:
        signals.append("multiple_entries")
    if entries and re.search(r"\b(?:\d{1,2}-[A-Za-z]{3}-\d{4}|\d{4}-\d{2}-\d{2}|\d{1,2}/\d{1,2}/\d{4})\s+\d{1,2}:\d{2}", visible):
        signals.append("dated_entries")
    family = ""
    if any(h.lower().startswith("directory listing for") for h in parsed.headings):
        family = "python"
    elif "[To Parent Directory]" in visible:
        family = "iis"
    elif "columns" in signals:
        family = "apache"
    elif heading and "<pre" in (body or "").lower():
        family = "nginx"
    return ListingObservation(tuple(signals), tuple(entries[:100]), family, error)


def extract_resource_urls(body: str, base_url: str) -> tuple[str, ...]:
    result = []
    for href, _, _ in _markup(body).links:
        url = normalize_candidate_url(urljoin(base_url, href))
        if url and url not in result:
            result.append(url)
    return tuple(result)


def normalize_candidate_url(url: str) -> str:
    try:
        parts = urlsplit(str(url or ""))
        if parts.scheme not in ("http", "https") or not parts.hostname or parts.username or parts.password:
            return ""
        parts.port
        decoded = unquote(unquote(parts.path))
        if "\\" in decoded or any(p in (".", "..") for p in decoded.split("/")) or any(ord(c) < 32 for c in url):
            return ""
        return urlunsplit((parts.scheme, parts.netloc, parts.path or "/", parts.query, ""))
    except (ValueError, TypeError):
        return ""


@dataclass(frozen=True)
class ArtifactCandidate:
    url: str
    kind: str
    observed_url: str


def derive_artifact_candidates(observed_url: str) -> tuple[ArtifactCandidate, ...]:
    clean = normalize_candidate_url(observed_url)
    if not clean:
        return ()
    parts = urlsplit(clean)
    result = []
    path = parts.path
    directory = path if path.endswith("/") else posixpath.dirname(path) + "/"
    while directory:
        target = urlunsplit((parts.scheme, parts.netloc, directory, "", ""))
        result.append(ArtifactCandidate(target, "directory", clean))
        if directory == "/":
            break
        directory = posixpath.dirname(directory.rstrip("/")) + "/"
    name = posixpath.basename(path)
    suffix = posixpath.splitext(name)[1].lower()
    if name and not suffix and not name.startswith("."):
        result.insert(0, ArtifactCandidate(clean, "directory", clean))
    if not name or path.endswith("/") or (not suffix and not name.startswith(".")) or suffix in (".bak", ".old", ".orig", ".swp", ".zip", ".gz", ".tgz", ".map") or name.endswith("~"):
        if suffix == ".map":
            result.insert(0, ArtifactCandidate(clean, "source_map", clean))
        return tuple(result)
    if suffix in (".js", ".mjs", ".cjs", ".css"):
        result.insert(0, ArtifactCandidate(clean, "resource", clean))
        result.insert(1, ArtifactCandidate(urlunsplit(parts._replace(path=path + ".map", fragment="")), "source_map", clean))
    stem = posixpath.splitext(path)[0]
    backups = [path + s for s in (".bak", ".old", ".orig", "~", ".swp")]
    backups.append(posixpath.dirname(path) + "/." + name + ".swp")
    backups.extend((stem + ".zip", stem + ".tar.gz", path + ".zip", path + ".tar.gz"))
    for backup in dict.fromkeys(backups):
        result.append(ArtifactCandidate(urlunsplit(parts._replace(path=backup, fragment="")), "backup", clean))
    return tuple(result)


def control_matches(body: str, url: str, control_body: str, control_url: str) -> bool:
    if not body or not control_body:
        return False
    def normalized(text, target):
        parts = urlsplit(target)
        text = text[:50000].replace(target, "").replace(parts.path, "")
        for token in parts.path.split("/"):
            if len(token) > 2:
                text = text.replace(token, "")
        text = re.sub(r"[0-9a-f]{16,}|\d{4}-\d{2}-\d{2}[T ][\d:.Z+-]+|\b\d{10,}\b", "", text, flags=re.I)
        text = re.sub(r"(?i)(?:nonce|csrf|request[_-]?id|trace[_-]?id|timestamp)\s*[=:" + "\"'" + r"]+\s*[\w.\-+/=]+", "", text)
        return text.strip()
    a, b = normalized(body, url), normalized(control_body, control_url)
    return bool(a and b) and (a == b or SequenceMatcher(None, a, b, autojunk=False).ratio() >= .9)


def classify_backup(body: bytes, content_type: str, url: str) -> tuple[str, ...]:
    if not body:
        return ()
    if body.startswith((b"PK\x03\x04", b"\x1f\x8b")) or body[257:262] == b"ustar":
        return ("archive_signature",)
    text = body[:MAX_BODY].decode("utf-8", errors="replace")
    if re.search(r"(?i)<(?:!doctype|html|title|body)\b", text[:2000]) or "html" in content_type.lower():
        return ()
    signals = []
    if re.search(r"<\?php|^\s*(?:import\s+\w+|from\s+\w+\s+import|def\s+\w+\(|class\s+\w+)|\b(?:const|function)\s+\w+", text, re.M):
        signals.append("source_code")
    if re.search(r"(?i)\b(?:CREATE TABLE|INSERT INTO|DB_PASSWORD\s*=|SECRET_KEY\s*=)|-----BEGIN [A-Z ]*PRIVATE KEY-----", text):
        signals.append("sensitive_content")
    if len(text.strip()) > 20 and content_type and any(ct in content_type.lower() for ct in ("text/plain", "octet-stream", "javascript", "json", "xml")):
        signals.append("served_file")
    return tuple(signals)


def source_mapping_references(body: str) -> tuple[str, ...]:
    refs = re.findall(r"(?m)(?://[#@]|/\*[#@])\s*sourceMappingURL\s*=\s*([^\s*]+)", (body or "")[:MAX_BODY])
    return tuple(dict.fromkeys(refs))


@dataclass(frozen=True)
class SourceMapData:
    sources: tuple[str, ...]
    sources_content: tuple[str, ...]
    internal_paths: tuple[str, ...]

    @property
    def exposed(self) -> bool:
        return bool(self.internal_paths or any(self.sources_content))


def parse_source_map(body: str, _depth: int = 0) -> SourceMapData | None:
    if not isinstance(body, str) or len(body) > MAX_BODY or _depth > 4:
        return None
    if body.startswith("data:"):
        try:
            meta, encoded = body.split(",", 1)
            if not meta.lower().startswith("data:application/json"):
                return None
            if ";base64" in meta.lower():
                body = base64.b64decode(encoded, validate=True).decode("utf-8")
            else:
                body = unquote(encoded)
        except (ValueError, UnicodeError):
            return None
        if len(body) > MAX_BODY:
            return None
    try:
        data = json.loads(body)
    except (ValueError, TypeError, RecursionError):
        return None
    if not isinstance(data, dict) or type(data.get("version")) is not int or data["version"] != 3:
        return None
    if isinstance(data.get("sections"), list):
        sources, content, internal = [], [], []
        for section in data["sections"][:100]:
            if not isinstance(section, dict) or not isinstance(section.get("map"), dict):
                continue
            child = parse_source_map(json.dumps(section["map"]), _depth + 1)
            if child:
                sources.extend(child.sources)
                content.extend(child.sources_content)
                internal.extend(child.internal_paths)
        return SourceMapData(tuple(sources), tuple(content), tuple(dict.fromkeys(internal)))
    sources = data.get("sources")
    content = data.get("sourcesContent", [])
    root = data.get("sourceRoot", "")
    if not isinstance(sources, list) or not all(isinstance(s, str) for s in sources) or not isinstance(content, list) or not all(s is None or isinstance(s, str) for s in content) or not isinstance(root, str):
        return None
    paths = tuple(root.rstrip("/") + "/" + s if root else s for s in sources[:1000])
    internal = tuple(p for p in paths if re.search(r"(?i)^(?:/|[A-Z]:[\\/]|file:|webpack:|\.\./)|(?:^|/)(?:src|server|private|internal|node_modules)/", p))
    return SourceMapData(paths, tuple(s or "" for s in content[:1000]), internal)
