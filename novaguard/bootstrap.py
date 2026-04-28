from __future__ import annotations

from datetime import datetime
from pathlib import Path

from PIL import Image, ImageDraw

from novaguard.config import CANARY_DIR, STATE_DIR, ensure_runtime_dirs, load_settings


ICON_PNG_NAME = "novasentinel_icon.png"
ICON_ICO_NAME = "novasentinel_icon.ico"


def ensure_bootstrap() -> None:
    ensure_runtime_dirs()
    load_settings()
    ensure_canary_files()
    ensure_icon_assets(force=True)


def ensure_canary_files() -> list[str]:
    ensure_runtime_dirs()
    stamp = datetime.now().strftime("%Y%m%d")
    filenames = [
        f"financial_report_{stamp}.docx.canary",
        f"family_photos_{stamp}.zip.canary",
        f"vault_backup_{stamp}.xlsx.canary",
    ]
    for name in filenames:
        path = CANARY_DIR / name
        if not path.exists():
            path.write_text(
                "NovaSentinel anti-ransomware canary. If this file changes unexpectedly, raise an alert.",
                encoding="utf-8",
            )
    return [str(path) for path in CANARY_DIR.iterdir() if path.is_file()]


def create_shield_icon(size: int = 64) -> Image.Image:
    image = Image.new("RGBA", (size, size), (0, 0, 0, 0))
    draw = ImageDraw.Draw(image)
    outline_width = max(2, round(size * 0.055))
    check_width = max(3, round(size * 0.085))
    draw.polygon(
        [
            (size * 0.50, size * 0.03),
            (size * 0.91, size * 0.19),
            (size * 0.84, size * 0.71),
            (size * 0.50, size * 0.97),
            (size * 0.16, size * 0.71),
            (size * 0.09, size * 0.19),
        ],
        fill=(40, 189, 147, 255),
    )
    draw.line(
        [
            (size * 0.50, size * 0.03),
            (size * 0.91, size * 0.19),
            (size * 0.84, size * 0.71),
            (size * 0.50, size * 0.97),
            (size * 0.16, size * 0.71),
            (size * 0.09, size * 0.19),
            (size * 0.50, size * 0.03),
        ],
        fill=(10, 104, 79, 255),
        width=outline_width,
        joint="curve",
    )
    draw.line(
        [
            (size * 0.30, size * 0.50),
            (size * 0.44, size * 0.65),
            (size * 0.71, size * 0.34),
        ],
        fill=(255, 255, 255, 255),
        width=check_width,
        joint="curve",
    )
    return image


def ensure_icon_assets(target_dir: Path | None = None, force: bool = False) -> tuple[Path, Path]:
    ensure_runtime_dirs()
    icon_dir = target_dir or STATE_DIR
    icon_dir.mkdir(parents=True, exist_ok=True)
    png_path = icon_dir / ICON_PNG_NAME
    ico_path = icon_dir / ICON_ICO_NAME
    if force or not png_path.exists():
        create_shield_icon(256).save(png_path, format="PNG")
    if force or not ico_path.exists():
        create_shield_icon(256).save(
            ico_path,
            format="ICO",
            sizes=[(16, 16), (32, 32), (48, 48), (64, 64), (128, 128), (256, 256)],
        )
    return png_path, ico_path
