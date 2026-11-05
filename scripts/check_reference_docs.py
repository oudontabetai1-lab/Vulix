"""Generate or verify the checked-in reference pages for declared checks."""
from __future__ import annotations

import argparse
import html
import json
from pathlib import Path
import re
import sys
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
OUTPUTS = {
    "ja": ROOT / "docs" / "checks_ja.md",
    "en": ROOT / "docs" / "checks_en.md",
}
_TASK_REF = re.compile(r"\b\d{4,}-[A-Z]\b")


def _text(value: Any) -> str:
    """Escape data as Markdown text while preserving ordinary punctuation."""
    value = html.escape(str(value), quote=False)
    return re.sub(r"([\\`*_{}\[\]()#+.!>|~-])", r"\\\1", value).replace("\n", "<br>")


def _code(value: Any) -> str:
    return "`" + str(value).replace("`", "&#96;").replace("\n", " ") + "`"


def _description_lines(description: Any, locale: str) -> list[str]:
    fields = (
        ("title", "名前", "Name"),
        ("short_description", "概要", "Summary"),
        ("what_is_tested", "検査対象", "What is tested"),
        ("risk_if_vulnerable", "脆弱な場合のリスク", "Risk if vulnerable"),
        ("verification_overview", "確認方法", "Verification"),
        ("remediation_overview", "修正概要", "Remediation"),
        ("limitations", "制約", "Limitations"),
    )
    lines = []
    for field, ja, en in fields:
        label = ja if locale == "ja" else en
        lines.extend((f"**{label}:**", _text(getattr(description, field)), ""))
    return lines


def render_documents() -> dict[str, str]:
    from wscan.capability_manifest import SCHEMA_VERSION, build_capability_manifest
    from wscan.check_catalog import (
        catalog_version, get_check_category, get_check_description,
        get_check_references,
    )
    from wscan.scanners import SCANNERS

    manifest = build_capability_manifest()
    catalog = json.loads((ROOT / "wscan" / "check_catalog.json").read_text(encoding="utf-8"))
    entries = manifest.get("scanners", {})
    locales = {"ja": "日本語", "en": "English"}
    version = catalog_version() or "不明"  # Unknown stays explicit; no version is inferred.
    manifest_version = SCHEMA_VERSION
    rendered = {}
    for locale, language_name in locales.items():
        label = locale
        lines = [
            f"# Check reference ({language_name})" if locale == "en" else "# チェックリファレンス",
            "",
            ("The capability manifest and check catalog are separate formats with independent schema versions; they join by stable check ID, and no cross-version negotiation is implemented. "
             "The manifest schema version is {manifest_version}; the catalog version is {version}. The catalog reader currently accepts only version 1.0.0 and falls back to unavailable/empty metadata for an unsupported or unreadable catalog. "
             "The manifest validator accepts its current schema version {manifest_version}. A manifest declaration is static metadata, not evidence that a check ran, runtime coverage, or a detection guarantee.".format(manifest_version=_text(manifest_version), version=_text(version)) if locale == "en"
             else "Capability manifest と check catalog は別形式で、それぞれ独立した schema version を持ち、安定した check ID で対応します。version 間の negotiation は実装されていません。"
             "Manifest schema version は {manifest_version}、catalog version は {version} です。catalog reader が現在受け付けるのは 1.0.0 のみで、未対応または読込不能な catalog は利用不可・空のメタデータへフォールバックします。"
             "Manifest validator が受け付けるのは現在の schema version {manifest_version} です。manifest の宣言は静的メタデータであり、検査実行、runtime coverage、検出保証の証拠ではありません。".format(manifest_version=_text(manifest_version), version=_text(version))),
            "",
            f"Manifest schema version: {_text(manifest_version)}" if locale == "en" else f"Manifest schema version: {_text(manifest_version)}",
            f"Catalog version: {_text(version)}" if locale == "en" else f"カタログ版: {_text(version)}",
            "",
        ]
        for check_id in sorted(SCANNERS):
            scanner = entries.get(check_id)
            check_data = catalog.get("checks", {}).get(check_id, {})
            description = get_check_description(check_id, locale)
            title = "Check" if locale == "en" else "チェック"
            lines.extend((f"## {_text(check_id)}", ""))
            lines.extend((f"**{title}:** {_text(scanner.get('name', check_id) if scanner else check_id)}", ""))
            category = get_check_category(check_id)
            cat_label = "Category" if locale == "en" else "分類"
            lines.extend((f"**{cat_label}:** {_text(category)}", ""))
            locale_declared = isinstance(check_data, dict) and isinstance(check_data.get(label), dict)
            if description and locale_declared:
                lines.extend(_description_lines(description, locale))
            else:
                lines.extend(("Catalog description is not available." if locale == "en" else "カタログ説明はありません。", ""))

            prereq_label = "Prerequisites" if locale == "en" else "前提条件"
            lines.extend((f"**{prereq_label}:**", ""))
            prerequisites = sorted(scanner.get("prerequisites", [])) if scanner else []
            lines.extend([f"- {_code(item)}" for item in prerequisites] or ["- " + ("None declared." if locale == "en" else "宣言なし")])
            lines.append("")

            carriers_label = "Declared carriers and status" if locale == "en" else "宣言された carrier と状態"
            lines.extend((f"**{carriers_label}:**", ""))
            carriers = scanner.get("declared_carriers", {}) if scanner else {}
            if carriers:
                for carrier, declaration in sorted(carriers.items()):
                    state = _text(declaration.get("state", "unknown"))
                    fields = [f"state={state}"]
                    for field in ("value_kinds", "transports", "payload_shapes"):
                        values = sorted(declaration.get(field) or [])
                        if values:
                            fields.append(f"{field}={','.join(_text(v) for v in values)}")
                    for field in ("browser_required", "structured_payload"):
                        if declaration.get(field):
                            fields.append(f"{field}=true")
                    reason = _TASK_REF.sub("", str(declaration.get("reason") or "")).strip()
                    if reason:
                        fields.append("reason=" + _text(reason))
                    lines.append(f"- {_code(carrier)}: " + "; ".join(fields))
            else:
                lines.append("- " + ("No carrier metadata." if locale == "en" else "carrier 情報なし"))
            lines.append("")

            references_label = "References" if locale == "en" else "参考資料"
            lines.extend((f"**{references_label}:**", ""))
            references = sorted(get_check_references(check_id), key=lambda ref: (ref.kind, ref.id, ref.url or ""))
            if references:
                for ref in references:
                    item = f"{_text(ref.kind)} {_text(ref.id)}"
                    if ref.url:
                        item += " — " + _code(ref.url)
                    lines.append(f"- {item}")
            else:
                lines.append("- " + ("None declared." if locale == "en" else "宣言なし"))
            lines.append("")
        rendered[locale] = "\n".join(lines).rstrip() + "\n"
    return rendered


def check_or_write(*, check: bool, outputs: dict[str, Path] | None = None) -> bool:
    generated = render_documents()
    outputs = OUTPUTS if outputs is None else outputs
    stale = []
    for locale, path in outputs.items():
        content = generated[locale]
        if check:
            if not path.is_file() or path.read_text(encoding="utf-8") != content:
                stale.append(path.relative_to(ROOT).as_posix() if path.is_relative_to(ROOT) else str(path))
        else:
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(content, encoding="utf-8", newline="\n")
    if stale:
        print("Stale or missing check reference docs: " + ", ".join(stale), file=sys.stderr)
        return False
    return True


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    group = parser.add_mutually_exclusive_group()
    group.add_argument("--check", action="store_true", help="fail if generated docs are missing or stale")
    group.add_argument("--write", action="store_true", help="write generated docs (default)")
    args = parser.parse_args(argv)
    return 0 if check_or_write(check=args.check) else 1


if __name__ == "__main__":
    raise SystemExit(main())
