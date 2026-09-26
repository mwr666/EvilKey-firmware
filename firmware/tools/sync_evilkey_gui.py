#!/usr/bin/env python3
"""Sync the committed Arduino engine GUI from the EvilKey port templates."""
from pathlib import Path
import shutil

ROOT = Path(__file__).resolve().parents[1]
PORT = ROOT / "templates" / "port"
ENGINE = ROOT / "EvilKeyV1" / "src" / "engine" / "board"


def main() -> None:
    board = (PORT / "ws_board.c").read_text(encoding="utf-8")
    for old, new in (
        ('#include "pf_engine_api.h"', '#include "../../pf_engine_api.h"'),
        ('#include "led/led.h"', '#include "../sdk/src/led/led.h"'),
    ):
        if board.count(old) != 1:
            raise ValueError(f"Unexpected board include: {old}")
        board = board.replace(old, new, 1)
    (ENGINE / "ws_board.c").write_text(
        '#include "../../pf_build_config.h"\n' + board, encoding="utf-8"
    )
    shutil.copyfile(PORT / "ws_ui.h", ENGINE / "ws_ui.h")

    template = (PORT / "ws_lvgl.c").read_text(encoding="utf-8")
    old = '#include "pf_firmware_version.h"'
    if template.count(old) != 1:
        raise ValueError("Unexpected firmware version include in ws_lvgl.c")
    generated = '#include "../../pf_build_config.h"\n' + template.replace(
        old, '#include "../../pf_firmware_version.h"', 1)
    (ENGINE / "ws_lvgl.c").write_text(generated, encoding="utf-8")
    shutil.copyfile(PORT / "ws_logo_assets.h", ENGINE / "ws_logo_assets.h")
    shutil.copyfile(PORT / "ws_crystal_assets.h", ENGINE / "ws_crystal_assets.h")
    shutil.copyfile(PORT / "ws_settings_icon_asset.h", ENGINE / "ws_settings_icon_asset.h")
    print("Synced EvilKey board phase, LVGL, logo and crystal assets to committed Arduino engine")


if __name__ == "__main__":
    main()
