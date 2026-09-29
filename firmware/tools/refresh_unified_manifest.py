#!/usr/bin/env python3
"""Sync the unified GUI template into the generated engine and refresh hashes."""
from pathlib import Path
import hashlib
import json
import shutil

fw = Path(__file__).resolve().parents[1]
manifest_path = fw / "EvilKeyV1/GENERATED_MANIFEST.json"
engine = fw / "EvilKeyV1/src/engine"
template = fw / "templates/port/ws_lvgl.c"
target = engine / "board/ws_lvgl.c"
source = template.read_text(encoding="utf-8")
old = '#include "pf_firmware_version.h"'
assert source.count(old) == 1
target.write_text(source.replace(old, '#include "../../pf_firmware_version.h"'),
                  encoding="utf-8")
board_source = (fw / "templates/port/ws_board.c").read_text(encoding="utf-8")
for previous, generated in (
    ('#include "pf_engine_api.h"', '#include "../../pf_engine_api.h"'),
    ('#include "led/led.h"', '#include "../sdk/src/led/led.h"'),
):
    assert board_source.count(previous) == 1
    board_source = board_source.replace(previous, generated)
(engine / "board/ws_board.c").write_text(
    '#include "../../pf_build_config.h"\n' + board_source, encoding="utf-8")
ui_source = (fw / "templates/port/ws_ui.c").read_text(encoding="utf-8")
(engine / "board/ws_ui.c").write_text(
    '#include "../../pf_build_config.h"\n' + ui_source, encoding="utf-8")
shutil.copy2(fw / "templates/port/ws_ui.h", engine / "board/ws_ui.h")
shutil.copy2(fw / "templates/port/ws_ui_layout.h", engine / "board/ws_ui_layout.h")
shutil.copy2(fw / "templates/port/ws_unified_logo_assets.h",
             engine / "board/ws_unified_logo_assets.h")
shutil.copy2(fw / "templates/port/ws_panel.c", engine / "board/ws_panel.c")
hid_path = engine / "sdk/src/usb/hid/hid.c"
hid = hid_path.read_text(encoding="utf-8")
if "if (pf_air_mouse_role()) return;" not in hid:
    old = "extern void init_fido(void);"
    assert hid.count(old) == 1
    hid = hid.replace(old, "extern bool pf_air_mouse_role(void);\n" + old)
    old = "    /* USB Tool owns non-CTAP output reports (for example keyboard LEDs). */"
    assert hid.count(old) == 1
    hid = hid.replace(old,
        "    /* The mouse-only role cannot accept CTAP packets. */\n"
        "    if (pf_air_mouse_role()) return;\n" + old)
    hid_path.write_text(hid, encoding="utf-8")
manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
for rel in ("board/ws_lvgl.c", "board/ws_unified_logo_assets.h", "board/ws_board.c",
            "board/ws_panel.c", "board/ws_ui.c", "board/ws_ui.h", "board/ws_ui_layout.h",
            "sdk/src/usb/hid/hid.c"):
    manifest["generated_sha256"][rel] = hashlib.sha256((engine / rel).read_bytes()).hexdigest()
manifest["port_version"] = "0.4.0"
manifest_path.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
print("Updated generated manifest for EvilKey 0.4.0")
