from __future__ import annotations

import os
from pathlib import Path
from typing import Any

from tests.ui_harness import UIHarness


class FakePage:
    def __init__(self) -> None:
        self.screenshots: list[dict[str, Any]] = []

    def screenshot(self, path: str, full_page: bool = False) -> bytes:
        p = Path(path)
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_bytes(b"fake_png_data")
        self.screenshots.append({"path": path, "full_page": full_page})
        return b"fake_png_data"


def test_save_doc_image_noop_when_env_unset(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.delenv("WSCAN_REFRESH_DOCS_IMAGES", raising=False)
    harness = UIHarness(repo_root=tmp_path)
    page = FakePage()

    harness.save_doc_image(page, "test-name")

    assert len(page.screenshots) == 0
    expected_file = tmp_path / "docs" / "images" / "test-name.png"
    assert not expected_file.exists()


def test_save_doc_image_noop_when_env_falsy(tmp_path: Path, monkeypatch) -> None:
    harness = UIHarness(repo_root=tmp_path)
    for falsy_val in ("", "0", "false", "no", "off", "random"):
        monkeypatch.setenv("WSCAN_REFRESH_DOCS_IMAGES", falsy_val)
        page = FakePage()
        harness.save_doc_image(page, "test-name")
        assert len(page.screenshots) == 0
        expected_file = tmp_path / "docs" / "images" / "test-name.png"
        assert not expected_file.exists()


def test_save_doc_image_writes_when_env_truthy(tmp_path: Path, monkeypatch) -> None:
    for truthy_val in ("1", "true", "True", "TRUE"):
        monkeypatch.setenv("WSCAN_REFRESH_DOCS_IMAGES", truthy_val)
        harness = UIHarness(repo_root=tmp_path)
        page = FakePage()

        name = f"doc-screen-{truthy_val.lower()}"
        harness.save_doc_image(page, name)

        expected_file = tmp_path / "docs" / "images" / f"{name}.png"
        assert len(page.screenshots) == 1
        assert page.screenshots[0] == {
            "path": str(expected_file),
            "full_page": False,
        }
        assert expected_file.is_file()
