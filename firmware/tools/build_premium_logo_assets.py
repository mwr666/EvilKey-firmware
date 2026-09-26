#!/usr/bin/env python3
"""Build the two-layer EvilKey LVGL logo from its transparent master asset.

The accent layer follows the device's configurable accent. The detached diamond
is a separate white layer, so changing the accent never recolours it.
"""
from pathlib import Path
from PIL import Image, ImageFilter

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "assets" / "evilkey_mark_source.png"
OUT = ROOT / "templates" / "port" / "ws_logo_assets.h"
SCREENSAVER_SIZE = 200
GLOW_SIZE = 216
GLITCH_STRIPS = (("upper", 50, 17), ("lower", 129, 14))
SIZES = {
    "ws_logo_header": (34, 34),
    "ws_logo_hero": (68, 68),
    "ws_logo_screensaver": (SCREENSAVER_SIZE, SCREENSAVER_SIZE),
}


def split_layers(source: Image.Image) -> tuple[Image.Image, Image.Image]:
    rgba = source.convert("RGBA")
    box = rgba.getchannel("A").getbbox()
    if box is None:
        raise ValueError("EvilKey logo source is transparent")
    rgba = rgba.crop(box)
    accent = Image.new("L", rgba.size)
    white = Image.new("L", rgba.size)
    accent_pixels = []
    white_pixels = []
    pixels = rgba.get_flattened_data() if hasattr(rgba, "get_flattened_data") else rgba.getdata()
    for red, green, blue, alpha in pixels:
        is_white = red > 170 and green > 170 and blue > 170
        accent_pixels.append(0 if is_white else alpha)
        white_pixels.append(alpha if is_white else 0)
    accent.putdata(accent_pixels)
    white.putdata(white_pixels)
    if not accent.getbbox() or not white.getbbox():
        raise ValueError("EvilKey logo needs both accent and white regions")
    return accent, white


def render_layer(layer: Image.Image, width: int, height: int) -> bytes:
    scale = min(width / layer.width, height / layer.height)
    size = (max(1, round(layer.width * scale)), max(1, round(layer.height * scale)))
    resized = layer.resize(size, Image.Resampling.LANCZOS)
    canvas = Image.new("L", (width, height), 0)
    canvas.paste(resized, ((width - size[0]) // 2, (height - size[1]) // 2))
    # Sub-5 alpha is below the first useful RGB565 level on the dark screen;
    # drop resize noise while retaining the full 8-bit antialiased edge.
    return canvas.point([0 if a < 5 else 255 if a > 250 else a
                         for a in range(256)]).tobytes()


def render_glow(accent: Image.Image) -> bytes:
    """A soft A8 halo behind the crisp, separately tinted logo."""
    sharp = Image.frombytes("L", (SCREENSAVER_SIZE, SCREENSAVER_SIZE),
                            render_layer(accent, SCREENSAVER_SIZE, SCREENSAVER_SIZE))
    padded = Image.new("L", (GLOW_SIZE, GLOW_SIZE), 0)
    padded.paste(sharp, (8, 8))
    blurred = padded.filter(ImageFilter.GaussianBlur(4.5))
    return blurred.point([0 if a < 4 else a for a in range(256)]).tobytes()


def main() -> None:
    accent, white = split_layers(Image.open(SRC))
    lines = [
        "/* SPDX-License-Identifier: AGPL-3.0-or-later",
        " * Generated from firmware/assets/evilkey_mark_source.png.",
        " * RGB565-clean accent/white alpha masks plus a soft 216 px halo. */",
        "#pragma once", "",
    ]
    for base, (width, height) in SIZES.items():
        for suffix, layer in (("accent", accent), ("white", white)):
            name = f"{base}_{suffix}"
            data = render_layer(layer, width, height)
            lines.append(f"static const uint8_t {name}_map[{len(data)}] = {{")
            for start in range(0, len(data), 20):
                lines.append("    " + ",".join(map(str, data[start:start + 20])) + ",")
            lines.extend([
                "};", f"static const lv_img_dsc_t {name} = {{",
                "    .header.cf = LV_IMG_CF_ALPHA_8BIT,",
                "    .header.always_zero = 0,",
                "    .header.reserved = 0,",
                f"    .header.w = {width},",
                f"    .header.h = {height},",
                f"    .data_size = {len(data)},",
                f"    .data = {name}_map,",
                "};", "",
            ])
    glow = render_glow(accent)
    lines.append(f"static const uint8_t ws_logo_screensaver_glow_map[{len(glow)}] = {{")
    for start in range(0, len(glow), 20):
        lines.append("    " + ",".join(map(str, glow[start:start + 20])) + ",")
    lines.extend([
        "};", "static const lv_img_dsc_t ws_logo_screensaver_glow = {",
        "    .header.cf = LV_IMG_CF_ALPHA_8BIT,",
        "    .header.always_zero = 0,",
        "    .header.reserved = 0,",
        f"    .header.w = {GLOW_SIZE},",
        f"    .header.h = {GLOW_SIZE},",
        "    .data_size = sizeof(ws_logo_screensaver_glow_map),",
        "    .data = ws_logo_screensaver_glow_map,",
        "};", "",
    ])
    # The screensaver disturbs only two narrow mint slices. Their A8 pixels live in
    # flash; the original white diamond remains a separate untouched image.
    sharp = render_layer(accent, SCREENSAVER_SIZE, SCREENSAVER_SIZE)
    for suffix, top, height in GLITCH_STRIPS:
        name = f"ws_logo_screensaver_glitch_{suffix}"
        data = sharp[top * SCREENSAVER_SIZE:(top + height) * SCREENSAVER_SIZE]
        lines.append(f"static const uint8_t {name}_map[{len(data)}] = {{")
        for start in range(0, len(data), 20):
            lines.append("    " + ",".join(map(str, data[start:start + 20])) + ",")
        lines.extend([
            "};", f"static const lv_img_dsc_t {name} = {{",
            "    .header.cf = LV_IMG_CF_ALPHA_8BIT,",
            "    .header.always_zero = 0,",
            "    .header.reserved = 0,",
            f"    .header.w = {SCREENSAVER_SIZE},",
            f"    .header.h = {height},",
            f"    .data_size = sizeof({name}_map),",
            f"    .data = {name}_map,",
            "};", "",
        ])
    OUT.write_text("\n".join(lines), encoding="utf-8")
    print(f"Wrote {OUT}")


if __name__ == "__main__":
    main()
