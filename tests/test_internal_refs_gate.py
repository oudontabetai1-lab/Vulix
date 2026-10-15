"""内部識別子混入ゲート（scripts/check_internal_refs.py）の回帰テスト。"""
import importlib.util
from pathlib import Path

_ROOT = Path(__file__).resolve().parents[1]
_spec = importlib.util.spec_from_file_location("check_internal_refs", _ROOT / "scripts" / "check_internal_refs.py")
gate = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(gate)


def _hits(text):
    return [m for _, m in gate.find_violations(text.splitlines())]


def test_detects_strong_identifiers():
    # 語はテストファイル自身がゲートに掛からないよう分割して組み立てる。
    samples = ["see " + "OUD" + "-73", "ADR" + "-12", "PLAN" + "-x", "DECISION" + "-3",
               "連携" + "プレイブック", "[[" + "Designs/foo]]", "obsidian" + "://open?vault=x"]
    for s in samples:
        assert _hits(s), s


def test_detects_japanese_adjacent_and_non_ascii_suffix():
    # \b 依存だと見逃していたグルー形（日本語直結・非 ASCII 後続・末尾記号/行末）。
    samples = ["対応課題" + "OUD" + "-73", "設計" + "ADR" + "-4 参照", "MODEL" + "-日本語",
               "（" + "PLAN" + "-）", "PLAN" + "-", "原則" + "PRINCIPLE" + "-#1", "DECISION" + "-「a」"]
    for s in samples:
        assert _hits(s), s


def test_allows_functional_values_and_product_terms():
    allowed = [
        'task="0035-D"',
        'owner_task: "0034"',
        "ハイブリッド Phase 1 → Phase 2",
        "background:linear-gradient(135deg,#059669,#0891b2)",
        "matrix = [[1, 2], [3, 4]]",
        "MODEL_NAME = 'x'",
        "DECISION: 単一 source-of-truth",
        'task="00NN"',
        "XOUD" + "-1 と MYPLAN" + "-x は別語",
        "MODEL" + "_NAME と PLAN" + "S-x",
    ]
    for s in allowed:
        assert not _hits(s), s


def test_repository_is_clean():
    assert gate.main(_ROOT) == 0
