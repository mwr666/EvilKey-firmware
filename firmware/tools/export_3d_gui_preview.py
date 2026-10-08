#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Export static preview sheets from the native Jet and LVGL host test outputs."""
from pathlib import Path
from shutil import copyfile

from PIL import Image, ImageDraw, ImageFont

ROOT = Path(__file__).resolve().parents[2]
BUILD = ROOT / "firmware/build"
OUT = ROOT / "docs/design/3d-gui"


def main():
    OUT.mkdir(parents=True, exist_ok=True)
    font = ImageFont.truetype("C:/Windows/Fonts/arial.ttf", 15)
    panels = [
        ("3d-ready", "READY"), ("settings-intro", "SETTINGS"),
        ("3d-saver", "SCREENSAVER"), ("3d-glitch", "GLITCH"),
        ("3d-pin", "PIN"), ("airmouse-ble-settings", "AIR MOUSE"),
        ("launcher-five", "APPS"), ("3d-diagnostics", "DIAGNOSTICS"),
    ]
    sheet = Image.new("RGB", (1200, 1030), "#080e10")
    draw = ImageDraw.Draw(sheet)
    for index, (name, caption) in enumerate(panels):
        # The host runner exports PNGs before its final classic-fallback run,
        # which intentionally overwrites PPMs. Use those native Jet PNGs here.
        source = BUILD / f"{name}.png"
        with Image.open(source) as image:
            if image.size != (280, 456):
                raise ValueError(f"Unexpected LVGL frame size: {source}")
            x, y = 20 + (index % 4) * 296, 35 + (index // 4) * 490
            sheet.paste(image.convert("RGB"), (x, y))
        draw.text((x, y + 466), caption, font=font, fill="#a7bec4")
        copyfile(source, OUT / source.name)
    sheet.save(OUT / "gui-overview.png")
    copyfile(BUILD / "launcher-intro.png", OUT / "launcher-intro.png")

    sheet = Image.new("RGB", (920, 610), "#080e10")
    draw = ImageDraw.Draw(sheet)
    for index, phase in enumerate([0, 32, 63, 96, 128, 160, 192, 224]):
        with Image.open(BUILD / f"jet-0-{phase:03}.ppm") as image:
            x, y = 20 + (index % 4) * 225, 25 + (index // 4) * 290
            sheet.paste(image.convert("RGB"), (x, y))
        caption = f"PHASE {phase}" + (" / GLITCH" if phase in (63, 192) else "")
        draw.text((x, y + 218), caption, font=font, fill="#a7bec4")
    sheet.save(OUT / "jet-logo-phases.png")
    print(f"Exported native static previews: {OUT}")


if __name__ == "__main__":
    main()
