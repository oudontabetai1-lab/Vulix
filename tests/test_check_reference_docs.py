import subprocess
import sys
from pathlib import Path

from scripts.check_reference_docs import OUTPUTS, _text, render_documents
from wscan.capability_manifest import SCHEMA_VERSION, build_capability_manifest
from wscan.check_catalog import catalog_version, get_check_category, get_check_description, get_check_references
from wscan.scanners import SCANNERS


ROOT = Path(__file__).resolve().parents[1]


def test_checked_in_pages_match_generator_and_all_registry_metadata():
    generated = render_documents()
    manifest = build_capability_manifest()
    assert set(generated) == {"ja", "en"}
    for locale, path in OUTPUTS.items():
        content = path.read_text(encoding="utf-8")
        assert content == generated[locale]
        assert len([line for line in content.splitlines() if line.startswith("## ")]) == len(SCANNERS)
        assert f"Manifest schema version: {_text(SCHEMA_VERSION)}" in content
        assert ("Catalog version: " if locale == "en" else "カタログ版: ") + _text(catalog_version()) in content
        version_contract = "no cross-version negotiation is implemented" if locale == "en" else "version 間の negotiation は実装されていません"
        assert version_contract in content
        catalog_gate = ("catalog reader currently accepts only version 1.0.0" if locale == "en"
                        else "catalog reader が現在受け付けるのは 1.0.0 のみ")
        assert catalog_gate in content
        for check_id in sorted(SCANNERS):
            assert f"## {_text(check_id)}\n" in content
            assert _text(manifest["scanners"][check_id]["name"]) in content
            assert _text(get_check_category(check_id)) in content
            description = get_check_description(check_id, locale)
            for field in ("title", "short_description", "what_is_tested", "risk_if_vulnerable",
                          "verification_overview", "remediation_overview", "limitations"):
                assert _text(getattr(description, field)) in content
            for reference in get_check_references(check_id):
                assert _text(reference.kind) in content
                assert _text(reference.id) in content
                if reference.url:
                    assert reference.url.replace("`", "&#96;") in content

    # Guard against a loader regression that quietly removes the shared taxonomy.
    assert get_check_category("sqli") == "injection"
    assert get_check_category("xss") == "xss"
    assert get_check_category("cors") == "proto"


def test_generation_is_deterministic_and_check_mode_detects_drift(tmp_path, monkeypatch):
    import scripts.check_reference_docs as generator

    assert render_documents() == render_documents()
    outputs = {locale: tmp_path / path.name for locale, path in OUTPUTS.items()}
    for locale, path in outputs.items():
        path.write_text(render_documents()[locale], encoding="utf-8")
    monkeypatch.setattr(generator, "OUTPUTS", outputs)
    assert generator.main(["--check"]) == 0

    outputs["en"].write_text("stale\n", encoding="utf-8")
    assert generator.main(["--check"]) == 1
    outputs["ja"].unlink()
    assert generator.main(["--check"]) == 1
    assert generator.main(["--write"]) == 0
    assert subprocess.run([sys.executable, "scripts/check_reference_docs.py", "--check"], cwd=ROOT, check=False).returncode == 0


def test_rendered_carrier_metadata_does_not_expose_internal_task_refs():
    content = "\n".join(render_documents().values())
    manifest = build_capability_manifest()
    refs = {
        carrier["task"]
        for scanner in manifest["scanners"].values()
        for carrier in scanner["declared_carriers"].values()
        if carrier.get("task")
    }
    assert refs
    assert not any(task_ref in content for task_ref in refs)


def test_catalog_text_is_escaped_before_markdown_rendering():
    hostile = '<script>alert("x")</script> [link](javascript:alert(1)) | next'
    escaped = _text(hostile)
    assert "<script>" not in escaped
    assert "[link](javascript:" not in escaped
    assert "\\|" in escaped
    assert "&lt;script&gt;" in escaped


def test_missing_descriptions_and_manifest_rows_are_stated_without_invented_support(monkeypatch):
    import wscan.capability_manifest as capability
    import wscan.check_catalog as catalog

    monkeypatch.setattr(capability, "build_capability_manifest", lambda: {"scanners": {}})
    monkeypatch.setattr(catalog, "get_check_description", lambda *_args: None)
    docs = render_documents()
    assert "Catalog description is not available." in docs["en"]
    assert "カタログ説明はありません。" in docs["ja"]
    assert "No carrier metadata." in docs["en"]
    assert "carrier 情報なし" in docs["ja"]
    assert "state=supported" not in docs["en"]


def test_missing_or_malformed_category_metadata_degrades_to_unclassified(tmp_path, monkeypatch):
    import json
    import wscan.check_catalog as catalog

    source = json.loads((ROOT / "wscan" / "check_catalog.json").read_text(encoding="utf-8"))
    source["checks"]["sqli"].pop("category")
    source["checks"]["xss"]["category"] = ["invalid"]
    path = tmp_path / "catalog.json"
    path.write_text(json.dumps(source), encoding="utf-8")
    monkeypatch.setattr(catalog, "_CATALOG_PATH", path)
    monkeypatch.setattr(catalog, "_loaded", False)
    monkeypatch.setattr(catalog, "_entries", ())
    monkeypatch.setattr(catalog, "_version", None)

    assert catalog.catalog_version() == "1.0.0"
    assert catalog.get_check_category("sqli") == "unclassified"
    assert catalog.get_check_category("xss") == "unclassified"
    assert catalog.get_check_description("sqli", "en") is not None
