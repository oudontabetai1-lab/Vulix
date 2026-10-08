"""0069 Phase1 残差分: `vulix` console_scripts エントリ と `replay` サブコマンドの後方互換。

中核（vulix/ re-export・docs 改称）は #174/#180 済。ここでは本 PR で足した2点だけを守る:
  1. pyproject.toml の console_scripts `vulix` が vulix/__main__:main を指し、呼び出し可能。
  2. `replay` が `scan` の別名として動作し、flow/HAR 再生フラグ(--flows/--har)を受け、
     dispatch で run_scan へ委譲される（独立実装を足さない）。
既存サブコマンド（scan）の後方互換も併せて確認する。
"""
import pathlib
import sys
import tomllib

import main
import vulix.__main__ as vulix_main

_ROOT = pathlib.Path(__file__).resolve().parent.parent


def _parse(argv, monkeypatch):
    """main.parse_args は sys.argv を直接読むため、argv を差し替えて呼ぶ。"""
    monkeypatch.setattr(sys, "argv", ["main", *argv])
    return main.parse_args()


def test_pyproject_declares_vulix_console_script():
    data = tomllib.loads((_ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    # `vulix` 実行エントリが現行 CLI 委譲（python -m vulix 相当）を指すこと。
    assert data["project"]["scripts"]["vulix"] == "vulix.__main__:main"
    # エントリ先が実在・呼び出し可能であること（entry 相当の検証）。
    assert callable(vulix_main.main)


def test_replay_is_scan_alias_and_accepts_flow_har(monkeypatch):
    a = _parse(["replay", "http://x", "--flows", "a.json", "b.json"], monkeypatch)
    assert a.command == "replay"          # alias 名が残る
    assert a.url == ["http://x"]           # scan と同じ位置引数
    assert a.flows == ["a.json", "b.json"]
    b = _parse(["replay", "http://x", "--har", "capture.har"], monkeypatch)
    assert b.har == "capture.har"


def test_replay_routes_to_run_scan(monkeypatch):
    # dispatch の catch-all で run_scan に入ること（独立ハンドラを作っていない）。
    captured = {}

    async def fake_run_scan(args):
        captured["command"] = args.command
        captured["flows"] = args.flows

    monkeypatch.setattr(main, "run_scan", fake_run_scan)
    monkeypatch.setattr(
        sys, "argv",
        ["vulix", "replay", "http://x", "--flows", "a.json", "--no-monitor"],
    )
    main.main()
    assert captured == {"command": "replay", "flows": ["a.json"]}


def test_legacy_scan_subcommand_still_works(monkeypatch):
    # 旧サブコマンドの後方互換（scan はそのまま）。
    a = _parse(["scan", "http://x"], monkeypatch)
    assert a.command == "scan"
    assert a.url == ["http://x"]
