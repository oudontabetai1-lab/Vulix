"""Read-only access to the optional, static check description catalog."""
from __future__ import annotations

from dataclasses import dataclass
import json
import logging
from pathlib import Path
from typing import Any

from wscan.i18n import normalize_lang

logger = logging.getLogger(__name__)
_CATALOG_PATH = Path(__file__).with_name("check_catalog.json")
_REQUIRED_FIELDS = (
    "title", "short_description", "what_is_tested", "risk_if_vulnerable",
    "verification_overview", "remediation_overview", "limitations",
)


@dataclass(frozen=True)
class LocalizedDescription:
    title: str
    short_description: str
    what_is_tested: str
    risk_if_vulnerable: str
    verification_overview: str
    remediation_overview: str
    limitations: str


@dataclass(frozen=True)
class CatalogReference:
    kind: str
    id: str
    url: str | None = None


@dataclass(frozen=True)
class CatalogEntry:
    check_id: str
    ja: LocalizedDescription
    en: LocalizedDescription | None
    references: tuple[CatalogReference, ...]
    category: str = "unclassified"

    def localized(self, lang: str = "ja") -> LocalizedDescription:
        return self.en if normalize_lang(lang) == "en" and self.en else self.ja


_loaded = False
_version: str | None = None
_entries: tuple[CatalogEntry, ...] = ()


def _parse_description(value: Any) -> LocalizedDescription:
    if not isinstance(value, dict) or any(
        not isinstance(value.get(key), str) or not value[key].strip()
        for key in _REQUIRED_FIELDS
    ):
        raise ValueError("invalid localized description")
    return LocalizedDescription(**{key: value[key] for key in _REQUIRED_FIELDS})


def _load() -> None:
    global _loaded, _version, _entries
    if _loaded:
        return
    _loaded = True
    _version = None
    _entries = ()
    try:
        data = json.loads(_CATALOG_PATH.read_text(encoding="utf-8"))
        if not isinstance(data, dict) or data.get("schema_version") != "1.0.0":
            raise ValueError("invalid catalog schema")
        checks = data.get("checks")
        if not isinstance(checks, dict):
            raise ValueError("invalid catalog structure")
        entries = []
        for check_id, localized in checks.items():
            if not isinstance(check_id, str) or not check_id or not isinstance(localized, dict):
                raise ValueError("invalid catalog check")
            ja = _parse_description(localized.get("ja"))
            en = _parse_description(localized["en"]) if "en" in localized else None
            raw_refs = localized.get("references", [])
            if not isinstance(raw_refs, list):
                raise ValueError("invalid catalog references")
            references = []
            for ref in raw_refs:
                if (not isinstance(ref, dict) or ref.get("kind") not in {"CWE", "OWASP"}
                        or not isinstance(ref.get("id"), str) or not ref["id"].strip()
                        or ("url" in ref and (not isinstance(ref["url"], str)
                                               or not ref["url"].startswith("https://")))):
                    raise ValueError("invalid catalog reference")
                references.append(CatalogReference(ref["kind"], ref["id"], ref.get("url")))
            category = localized.get("category", "unclassified")
            if not isinstance(category, str) or category not in {"injection", "xss", "access", "header", "proto", "file"}:
                category = "unclassified"
            entries.append(CatalogEntry(check_id, ja, en, tuple(references), category))
        _version = data["schema_version"]
        _entries = tuple(entries)
    except (OSError, UnicodeError, json.JSONDecodeError, KeyError, TypeError, ValueError) as exc:
        logger.warning("Check description catalog unavailable; continuing without it: %s", exc)


def catalog_version() -> str | None:
    _load()
    return _version


def list_checks(lang: str = "ja") -> tuple[tuple[str, LocalizedDescription], ...]:
    _load()
    return tuple((entry.check_id, entry.localized(lang)) for entry in _entries)


def get_check_description(check_id: str, lang: str = "ja") -> LocalizedDescription | None:
    _load()
    return next((entry.localized(lang) for entry in _entries if entry.check_id == check_id), None)


def get_check_references(check_id: str) -> tuple[CatalogReference, ...]:
    _load()
    return next((entry.references for entry in _entries if entry.check_id == check_id), ())


def get_check_category(check_id: str) -> str:
    """Return the shared product group or ``unclassified`` for older/unknown entries."""
    _load()
    return next((entry.category for entry in _entries if entry.check_id == check_id), "unclassified")
