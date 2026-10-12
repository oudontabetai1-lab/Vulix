"""ユーザ書込可能な state ディレクトリのパス解決（純粋関数）。

非 editable な ``pip install .`` や読取専用配置では、インストール先隣の ``config/`` へ書けない。
学習データ（payload_learning.json）と生成物（community_payloads.yaml）は書込可能な state へ置く。

解決順（書込先）: ``WSCAN_STATE_DIR`` > ソース checkout なら ``config/``（従来どおり）>
``$XDG_STATE_HOME/vulix`` > ``~/.local/state/vulix``。
読取は後方互換で、state に無ければインストール内 ``config/`` の既存ファイルへフォールバックする。
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Mapping, Optional

INSTALL_ROOT = Path(__file__).parent.parent
INSTALL_CONFIG_DIR = INSTALL_ROOT / "config"


def default_state_dir(
    env: Optional[Mapping[str, str]] = None,
    home: Optional[Path] = None,
    install_root: Path = INSTALL_ROOT,
) -> Path:
    env = os.environ if env is None else env
    if env.get("WSCAN_STATE_DIR"):
        return Path(env["WSCAN_STATE_DIR"]).expanduser()
    if (install_root / ".git").exists():  # editable / ソース checkout は従来どおり config/
        return install_root / "config"
    if env.get("XDG_STATE_HOME"):
        return Path(env["XDG_STATE_HOME"]).expanduser() / "vulix"
    return (home or Path.home()) / ".local" / "state" / "vulix"


def state_file(name: str, **kw) -> Path:
    """書込先（保存・生成）のパス。"""
    return default_state_dir(**kw) / name


def readable_state_file(name: str, install_config_dir: Path = INSTALL_CONFIG_DIR, **kw) -> Path:
    """読取元。state にあればそれ、無ければインストール内の既存ファイル、どちらも無ければ state。"""
    primary = state_file(name, **kw)
    legacy = install_config_dir / name
    if not primary.exists() and legacy.exists():
        return legacy
    return primary
