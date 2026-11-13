"""スキャン履歴の状態ラベル（ポータル / ダッシュボード / 統合画面）の共有と表示。"""
import json
import shutil
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def test_history_label_helper_maps_status_and_counts():
    node = shutil.which("node")
    if not node:
        return
    script = r"""
    const fs = require('fs'), vm = require('vm');
    vm.runInThisContext(fs.readFileSync('templates/ui/history-labels.js', 'utf8'));
    const L = VulixHistoryLabels;
    console.log(JSON.stringify({
      labels: ['done', 'scanning', 'aborted', 'error', 'incomplete', 'interrupted', 'SCANNING', ''].map(L.statusLabel),
      notes: [L.countsNote(true, true), L.countsNote(true, false), L.countsNote(false, true)],
    }));
    """
    result = subprocess.run(
        [node, "-"], input=script, text=True, capture_output=True, cwd=ROOT, timeout=20
    )
    assert result.returncode == 0, result.stderr
    data = json.loads(result.stdout)
    assert data["labels"] == ["完了", "実行中", "中断", "エラー", "未完了", "中断（途中）", "実行中", "不明"]
    assert data["notes"] == ["件（実行中・途中）", "件（途中）", ""]


def test_portal_history_status_cell_uses_shared_labels():
    """ポータル（/）の状態セルも生の status ではなく日本語ラベルを出す。"""
    portal = (ROOT / "templates/portal.html").read_text(encoding="utf-8")
    assert '<script src="/ui/history-labels.js"></script>' in portal
    assert "VulixHistoryLabels.statusLabel(s.status)" in portal
    # 状態セルに生の status をそのまま出さない（class 属性の status は維持）。
    assert '<td><span class="st ${esc(s.status)}">${esc(s.status)}</span></td>' not in portal
    # 途中件数の注記は従来どおり日本語。
    assert "件（実行中・途中）" in portal


def test_app_history_uses_shared_labels_without_duplicate_map():
    app = (ROOT / "templates/app.html").read_text(encoding="utf-8")
    assert app.index("/ui/history-labels.js") < app.index("/ui/summary-modules.js")
    modules = (ROOT / "templates/ui/summary-modules.js").read_text(encoding="utf-8")
    assert "VulixHistoryLabels" in modules
    # ラベル表を複製しない（ポータルと単一の正典を共有する）。
    assert "STATUS_LABELS =" not in modules


def test_dashboard_history_labels_stay_japanese():
    """レガシー履歴（/monitor）の日本語ラベルと途中件数の表記を固定する。"""
    dashboard = (ROOT / "templates/dashboard.html").read_text(encoding="utf-8")
    assert "statusLabel = '実行中';" in dashboard
    assert "statusLabel = '中断（途中）';" in dashboard
    assert "件（実行中・途中）" in dashboard
    assert "件（途中）" in dashboard