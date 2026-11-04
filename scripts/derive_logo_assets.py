"""公式 Vulix ロゴ（オリジナル）から各派生アセットを決定論的に生成・検証するスクリプト。

オリジナルロゴ: templates/ui/vulix-logo.png (PNG 1254x1254, RGBA, sha256 d6aa10fbd221d54ffb050cf08a96fb1512b8437b08e80944690b50674aa70219)
派生アセット:
  - templates/ui/vulix-logo-mark.png (96x96, ヘッダー・カード表示用マーク)
  - templates/ui/apple-touch-icon.png (180x180, iOS/Safari WebClip 用アイコン)
  - templates/ui/favicon.png (32x32, モダンブラウザ用ファビコン)
  - templates/ui/favicon.ico (16x16, 32x32, 48x48, マルチ解像度 ICO)

すべての派生アセットは公式オリジナルから LANCZOS リサイズのみにより生成され、
近似的な再描画や色変更は行いません。
"""
from __future__ import annotations

import hashlib
import sys
from pathlib import Path
from PIL import Image

ORIGINAL_LOGO_SHA256 = "d6aa10fbd221d54ffb050cf08a96fb1512b8437b08e80944690b50674aa70219"
ORIGINAL_DIMENSIONS = (1254, 1254)


def verify_original_logo(orig_path: Path) -> Image.Image:
    """オリジナルロゴの存在・SHA256・解像度・RGBAモードを検証して Image オブジェクトを返す。"""
    if not orig_path.is_file():
        raise FileNotFoundError(f"Original logo file not found: {orig_path}")

    data = orig_path.read_bytes()
    actual_sha = hashlib.sha256(data).hexdigest()
    if actual_sha != ORIGINAL_LOGO_SHA256:
        raise ValueError(
            f"Original logo SHA256 mismatch: expected {ORIGINAL_LOGO_SHA256}, got {actual_sha}"
        )

    im = Image.open(orig_path)
    if im.size != ORIGINAL_DIMENSIONS:
        raise ValueError(
            f"Original logo dimensions mismatch: expected {ORIGINAL_DIMENSIONS}, got {im.size}"
        )
    if im.mode != "RGBA":
        raise ValueError(f"Original logo mode must be RGBA, got {im.mode}")

    return im


def derive_assets(ui_dir: Path) -> dict[str, Path]:
    """公式オリジナルからすべての派生アセットをリサイズして生成・保存する。"""
    orig_path = ui_dir / "vulix-logo.png"
    orig_img = verify_original_logo(orig_path)

    generated: dict[str, Path] = {}

    # 1. vulix-logo-mark.png (96x96)
    mark_path = ui_dir / "vulix-logo-mark.png"
    mark_img = orig_img.resize((96, 96), resample=Image.Resampling.LANCZOS)
    mark_img.save(mark_path, format="PNG", optimize=False)
    generated["mark"] = mark_path

    # 2. apple-touch-icon.png (180x180)
    apple_path = ui_dir / "apple-touch-icon.png"
    apple_img = orig_img.resize((180, 180), resample=Image.Resampling.LANCZOS)
    apple_img.save(apple_path, format="PNG", optimize=False)
    generated["apple_touch_icon"] = apple_path

    # 3. favicon.png (32x32)
    fav_png_path = ui_dir / "favicon.png"
    fav_png_img = orig_img.resize((32, 32), resample=Image.Resampling.LANCZOS)
    fav_png_img.save(fav_png_path, format="PNG", optimize=False)
    generated["favicon_png"] = fav_png_path

    # 4. favicon.ico (16x16, 32x32, 48x48)
    fav_ico_path = ui_dir / "favicon.ico"
    orig_img.save(fav_ico_path, format="ICO", sizes=[(16, 16), (32, 32), (48, 48)])
    generated["favicon_ico"] = fav_ico_path

    return generated


def main() -> int:
    root = Path(__file__).resolve().parents[1]
    ui_dir = root / "templates" / "ui"
    print(f"Generating official Vulix logo assets in {ui_dir}...")
    try:
        outputs = derive_assets(ui_dir)
        for key, p in outputs.items():
            print(f"  ✓ {key}: {p.name} ({p.stat().st_size} bytes)")
        print("All derived logo assets generated successfully.")
        return 0
    except Exception as exc:
        print(f"Error deriving logo assets: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
