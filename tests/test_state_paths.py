"""state path resolution: overrides, legacy reads, fallback, and unwritable behavior."""
import os
from pathlib import Path

from wscan.payload_learning import PayloadLearner
from wscan.payload_importer import write_yaml
from wscan.state_paths import default_state_dir, readable_state_file


def test_env_override_wins(tmp_path):
    d = default_state_dir(env={"WSCAN_STATE_DIR": str(tmp_path / "s"), "XDG_STATE_HOME": "/x"}, install_root=tmp_path)
    assert d == tmp_path / "s"


def test_installed_uses_xdg_then_home(tmp_path):
    assert default_state_dir(env={"XDG_STATE_HOME": str(tmp_path)}, install_root=tmp_path) == tmp_path / "vulix"
    assert default_state_dir(env={}, home=tmp_path, install_root=tmp_path) == tmp_path / ".local/state/vulix"


def test_source_checkout_keeps_config_dir(tmp_path):
    (tmp_path / ".git").mkdir()
    assert default_state_dir(env={"XDG_STATE_HOME": "/x"}, install_root=tmp_path) == tmp_path / "config"


def test_read_falls_back_to_install_then_prefers_state(tmp_path, monkeypatch):
    monkeypatch.setenv("WSCAN_STATE_DIR", str(tmp_path / "state"))
    inst = tmp_path / "inst"; inst.mkdir()
    (inst / "a.yaml").write_text("x")
    assert readable_state_file("a.yaml", install_config_dir=inst) == inst / "a.yaml"
    (tmp_path / "state").mkdir(); (tmp_path / "state" / "a.yaml").write_text("y")
    assert readable_state_file("a.yaml", install_config_dir=inst) == tmp_path / "state" / "a.yaml"
    # どちらも無ければ state（書込先と一致）
    assert readable_state_file("b.yaml", install_config_dir=inst) == tmp_path / "state" / "b.yaml"


def test_learning_and_community_round_trip_via_state(tmp_path, monkeypatch):
    monkeypatch.setenv("WSCAN_STATE_DIR", str(tmp_path / "state"))
    pl = PayloadLearner()
    pl.record("xss", "<p>", True)
    pl.save()
    assert (tmp_path / "state" / "payload_learning.json").exists()
    assert PayloadLearner()._data["global"]["xss"]["<p>"]["hits"] == 1
    write_yaml(tmp_path / "state" / "community_payloads.yaml", {"xss": ["a"]}, sources={})
    assert readable_state_file("community_payloads.yaml").read_text().count("xss") == 1


def test_learning_unwritable_raises_for_caller_to_degrade(tmp_path, monkeypatch):
    # 書込不可なら save() は OSError（engine 側が捕捉し警告＋scan 継続）。load は無害。
    ro = tmp_path / "ro"; ro.mkdir(); ro.chmod(0o500)
    try:
        monkeypatch.setenv("WSCAN_STATE_DIR", str(ro / "sub"))
        pl = PayloadLearner()
        pl.record("xss", "<p>", True)
        if os.access(ro, os.W_OK):  # root 等では検証不能
            return
        try:
            pl.save()
            raise AssertionError("expected OSError")
        except OSError:
            pass
    finally:
        ro.chmod(0o700)
