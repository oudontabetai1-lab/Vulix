"""0069 Phase1: vulix が wscan の主要 API を同一オブジェクトで re-export する。"""
import vulix
import vulix.__main__ as vulix_main
import wscan.engine
import wscan.intervention
import wscan.payload_gen
import wscan.scanners.base


def test_vulix_reexports_same_objects():
    # 別クラスに二重実行されず、wscan と同一のクラスオブジェクトであること。
    assert vulix.ScanEngine is wscan.engine.ScanEngine
    assert vulix.PayloadGenerator is wscan.payload_gen.PayloadGenerator
    assert vulix.Finding is wscan.scanners.base.Finding
    assert vulix.BaseScanner is wscan.scanners.base.BaseScanner
    assert vulix.ScanController is wscan.intervention.ScanController
    assert vulix.__version__ == wscan.__version__


def test_explore_alias_rewrites_to_scan():
    # 先頭サブコマンドだけを変換し、以降の引数値には触れないこと。
    assert vulix_main._rewrite_argv(
        ["vulix", "explore", "https://ex", "--checks", "xss"]
    ) == ["vulix", "scan", "https://ex", "--checks", "xss"]
    # 別名でないサブコマンドはそのまま委譲。
    assert vulix_main._rewrite_argv(["vulix", "agent", "https://ex"]) == [
        "vulix", "agent", "https://ex",
    ]
    # 引数値に "explore" が現れても変換しない（先頭のみ対象）。
    assert vulix_main._rewrite_argv(["vulix", "scan", "explore"]) == [
        "vulix", "scan", "explore",
    ]
