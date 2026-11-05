import subprocess
import sys
from pathlib import Path

import main
from wscan.capability_manifest import build_capability_manifest
from wscan.check_catalog import list_checks
from wscan.scanners import SCANNERS


ROOT = Path(__file__).resolve().parents[1]


def _cli(*args):
    return subprocess.run(
        [sys.executable, "main.py", *args], cwd=ROOT, capture_output=True, text=True,
    )


def test_entrypoint_lists_catalog_in_japanese_and_english_and_matches_registry():
    ja = _cli("checks")
    en = _cli("checks", "--lang", "en")
    assert ja.returncode == en.returncode == 0
    assert "検査ID | 名前 | 説明 | 分類 | 宣言された入力経路" in ja.stdout
    assert "カタログ版" not in ja.stdout
    assert "SQLインジェクション" in ja.stdout
    assert "Sql injection" in en.stdout
    listed_ids = {line.split(" | ", 1)[0] for line in ja.stdout.splitlines()[1:]}
    assert listed_ids == set(SCANNERS)
    manifest = build_capability_manifest()
    for check_id, scanner in manifest["scanners"].items():
        assert f"{check_id} | " in ja.stdout
        assert scanner["declaration_only"] is True
        assert all(state in {"supported", "unsupported", "planned", "unclassified"}
                   for state in (cap["state"] for cap in scanner["declared_carriers"].values()))


def test_entrypoint_details_use_catalog_and_contract_and_unknown_id_fails():
    result = _cli("check", "sqli", "--lang", "en")
    assert result.returncode == 0
    assert "Catalog version: 1.0.0" in result.stdout
    assert "What is tested:" in result.stdout
    assert "Limitations:" in result.stdout
    assert "Declared carriers:" in result.stdout
    assert "Prerequisites:" in result.stdout
    assert "References:" in result.stdout
    assert "query: state=supported" in result.stdout
    assert "carrier 別 dispatcher は未接続" in result.stdout
    task_refs = {
        carrier["task"]
        for scanner in build_capability_manifest()["scanners"].values()
        for carrier in scanner["declared_carriers"].values()
        if carrier["task"]
    }
    assert not any(task_ref in result.stdout for task_ref in task_refs)
    unknown = _cli("check", "no_such_check")
    assert unknown.returncode != 0
    assert "Unknown check ID" in unknown.stderr
    assert "checks" in unknown.stderr


def test_existing_scan_parser_flags_keep_their_contract():
    args = main.parse_args(["scan", "https://example.test", "--checks", "sqli", "xss", "--depth", "3"])
    assert args.command == "scan"
    assert args.url == ["https://example.test"]
    assert args.checks == ["sqli", "xss"]
    assert args.depth == 3


def test_catalog_entries_and_manifest_have_same_scanner_ids():
    import wscan.check_catalog as catalog
    catalog._loaded = False
    assert catalog.catalog_version() == "1.0.0"
    assert {check_id for check_id, _ in list_checks("ja")} == set(SCANNERS)
    assert set(build_capability_manifest()["scanners"]) == set(SCANNERS)
