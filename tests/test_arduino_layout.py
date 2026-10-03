"""R3 regression tests: generated include layout and native C harness.

This models Arduino's documented extension filter; it does NOT invoke the
Arduino builder or compile the full ESP32-S3 firmware. No USB is opened.
"""
from __future__ import annotations
import hashlib
import importlib.util
import os
import re
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
FW = ROOT / "firmware"
PORT = FW / "templates/port"
spec = importlib.util.spec_from_file_location("r1_prepare", FW / "prepare_arduino.py")
assert spec and spec.loader
PREPARE = importlib.util.module_from_spec(spec)
spec.loader.exec_module(PREPARE)
patch_spec = importlib.util.spec_from_file_location("r13_touch_patch", FW / "tools/touch_patch.py")
assert patch_spec and patch_spec.loader
TOUCH_PATCH = importlib.util.module_from_spec(patch_spec)
patch_spec.loader.exec_module(TOUCH_PATCH)


class ArduinoLayoutTests(unittest.TestCase):
    def test_evilkey_settings_uses_saver_cadence_and_crisp_static_gear(self):
        ui = (PORT / "ws_lvgl.c").read_text(encoding="utf-8")
        board = (PORT / "ws_board.c").read_text(encoding="utf-8")
        icon = (PORT / "ws_settings_icon_asset.h").read_text(encoding="utf-8")
        self.assertIn("(settings_elapsed/24U)%256U", board)
        self.assertIn("(saver_elapsed/24U)%1024U", board)
        self.assertIn("LV_IMG_CF_ALPHA_8BIT", icon)
        self.assertIn("ws_settings_gear_map[14400]", icon)
        self.assertIn("lv_img_set_src(p,&ws_settings_gear);", ui)
        self.assertNotIn("static const int8_t xy[8][2]", ui)
        motion = ui.split("static void update_settings_motion(", 1)[1].split(
            "static void main_state(", 1)[0]
        self.assertNotIn("lv_obj_set_style_opa(ui.settings_gear.root", motion)

    def test_evilkey_screensaver_orbits_close_without_a_phase_jump(self):
        ui = (PORT / "ws_lvgl.c").read_text(encoding="utf-8")
        board = (PORT / "ws_board.c").read_text(encoding="utf-8")
        header = (PORT / "ws_ui.h").read_text(encoding="utf-8")
        assets = (PORT / "ws_logo_assets.h").read_text(encoding="utf-8")
        self.assertIn("uint16_t screensaver_phase", header)
        self.assertIn("(saver_elapsed/24U)%1024U", board)
        rates = {}
        for name in ("rot", "rot2", "rot_fast"):
            match = re.search(
                rf"const int {name}=\(\(int\)phase\*(\d+)\)/(\d+);", ui
            )
            self.assertIsNotNone(match, name)
            rates[name] = tuple(map(int, match.groups()))
            self.assertEqual(rates[name][1], 1024)
        self.assertIn("rot_fast/2+211", ui)
        for turns in (rates["rot"][0], rates["rot2"][0],
                      rates["rot_fast"][0], rates["rot_fast"][0] // 2):
            self.assertEqual(turns % 360, 0)
            last_angle = ((1023 * turns) // 1024) % 360
            seam = min(last_angle, 360 - last_angle)
            self.assertLessEqual(seam, 5)
        self.assertIn("ws_logo_screensaver_accent_map[40000]", assets)
        self.assertIn("ws_logo_screensaver_white_map[40000]", assets)
        self.assertIn("const int logo_x=SAVER_LOGO_BASE+", ui)
        self.assertIn("const int logo_y=SAVER_LOGO_BASE+", ui)

    def test_r14_supports_arduino_esp32_3_3_12_and_keeps_3_3_11(self):
        cfg = (FW / "EvilKeyV1/src/pf_build_config.h").read_text(encoding="utf-8")
        stack = (FW / "tools/check_usb_stack.py").read_text(encoding="utf-8")
        port = (FW / "ARDUINO_PORT.json").read_text(encoding="utf-8")
        self.assertIn("ESP_ARDUINO_VERSION_VAL(3, 3, 11)", cfg)
        self.assertIn("ESP_ARDUINO_VERSION_VAL(3, 3, 12)", cfg)
        self.assertIn("3.3.11 or 3.3.12 only", cfg)
        self.assertIn('(3, 3, 11): "5b6bfb437b851b78578574ca44d157e115bf7930"', stack)
        self.assertIn('(3, 3, 12): "d8fcd0b428848010d3b3773b5b0e02515693f0e0"', stack)
        self.assertIn("PREFERRED = (3, 3, 12)", stack)
        self.assertIn("3.3.12 recommended", port)

    def test_r19_device_settings_keeps_evilkey_brand_palette_and_pin_geometry(self):
        ui = (PORT / "ws_lvgl.c").read_text(encoding="utf-8")
        conf = (FW / "templates/lvgl_conf.h").read_text(encoding="utf-8")
        layout = (PORT / "ws_ui_layout.h").read_text(encoding="utf-8")
        logo = (PORT / "ws_logo_assets.h").read_text(encoding="utf-8")
        board = (PORT / "ws_board.c").read_text(encoding="utf-8")
        self.assertIn("R22 keeps the validated Pico FIDO interaction/security geometry", ui)
        self.assertIn("EVILKEY", ui)
        self.assertNotIn("NOXID", ui.upper())
        self.assertIn("&ws_logo_header_accent", ui)
        self.assertIn("&ws_logo_header_white", ui)
        self.assertIn("&ws_logo_hero_accent", ui)
        self.assertIn("&ws_logo_hero_white", ui)
        self.assertIn("LV_IMG_CF_ALPHA_8BIT", logo)
        self.assertIn("lv_obj_set_style_img_recolor_opa", ui)
        self.assertIn("premium_wave(", ui)
        self.assertIn("update_premium_motion(", ui)
        self.assertIn("lv_obj_set_style_bg_grad_color", ui)
        self.assertIn("hero_orbit", ui)
        self.assertIn("spinner_arc_a", ui)
        self.assertNotIn("lv_obj_invalidate(ui.screen)", ui)
        for token in ("HERO_KEY", "HERO_SPINNER", "HERO_TOUCH", "HERO_CHECK",
                      "HERO_CROSS", "HERO_CLOCK", "HERO_LOCK", "HERO_MOON",
                      "HERO_WARNING", "HERO_USB", "build_backspace("):
            self.assertIn(token, ui)
        self.assertIn("#define LV_USE_LINE 1", conf)
        self.assertIn("#define LV_USE_IMG 1", conf)
        self.assertIn("#define LV_USE_ARC 1", conf)
        for token in ("#define WS_KEY_X 8", "#define WS_KEY_Y 132",
                      "#define WS_KEY_W 84", "#define WS_KEY_H 60",
                      "#define WS_KEY_DX 90", "#define WS_KEY_DY 66",
                      "#define WS_PIN_CANCEL_Y 400"):
            self.assertIn(token, layout)
        self.assertIn("settings.animation && v.state!=WS_UI_PIN", board)
        self.assertIn("(now/16U)%64U", board)
        self.assertIn("WS_SETTINGS_PAGE_TRANSITION_MS 165U", board)
        self.assertIn("WS_SETTINGS_TRANSITION_MS 230U", board)
        self.assertIn("WS_SETTINGS_PAGE_SLIDE_PX 56", board)
        self.assertIn("#define SETTINGS_ROWS 2U", ui)
        self.assertIn("#define SETTINGS_DOTS 10U", ui)
        self.assertIn("SWIPE UP / DOWN", ui)
        self.assertIn("build_settings_hint(", ui)
        self.assertIn("build_settings(", ui)
        self.assertIn("update_settings(", ui)
        self.assertIn("WS_SETTINGS_ACTION_MANAGER_DRIVE_TOGGLE", board)
        self.assertIn("settings_force_closed();", board)
        self.assertIn("#define LV_MEM_SIZE (128U * 1024U)", conf)
        self.assertNotIn("build_manager(", ui)
        self.assertNotIn("lv_obj_add_event_cb", ui)

    def test_usb_tool_leds_use_a_bounded_premium_capsule(self):
        ui = (PORT / "ws_lvgl.c").read_text(encoding="utf-8")
        for token in ("COL_LED_RED", "COL_LED_GREEN", "tool_led_group",
                      "build_tool_leds(", "update_tool_leds(",
                      "apply_tool_led(", "set_tool_led_opa(", "visual_valid"):
            self.assertIn(token, ui)
        self.assertIn("card(ui.main_group,202,54,68,30,15)", ui)
        self.assertIn("const bool tool=v->usb_tool_enabled && ws_ui_settings_allowed(v->state);", ui)
        self.assertIn("if(v->usb_tool_enabled && ws_ui_settings_allowed(v->state)) update_tool_leds(v);", ui)
        self.assertNotIn("approach_u8(", ui)
        self.assertNotIn("tool_led_red.label", ui)
        self.assertNotIn("tool_led_green.label", ui)
        self.assertNotIn('"  •  LED R"', ui)
        self.assertNotIn('"  •  LED G"', ui)
        self.assertNotIn("lv_obj_invalidate(ui.tool_led_group)", ui)

    def test_r15_read_write_enable_has_directional_pin_gate_and_legacy_pin_migration(self):
        board = (PORT / "ws_board.c").read_text(encoding="utf-8")
        ui = (PORT / "ws_ui.h").read_text(encoding="utf-8")
        lvgl = (PORT / "ws_lvgl.c").read_text(encoding="utf-8")
        local_uv = (FW / "templates/local_uv_engine.inc").read_text(encoding="utf-8")
        patch = (FW / "tools/touch_patch.py").read_text(encoding="utf-8")
        manager = (PORT / "ws_manager_config.h").read_text(encoding="utf-8")
        self.assertIn("R13_RW_PIN_GATE", board)
        self.assertIn("if(ws_manager_drive_read_only())", board)
        self.assertIn("settings_begin_rw_pin(settings,now)", board)
        self.assertIn("ws_manager_drive_set_read_only(true)", board)
        self.assertIn("pf_local_uv_verify_supplied_pin", board)
        self.assertIn("WS_PIN_OWNER_SETTINGS_RW", board)
        self.assertIn("WS_PIN_PURPOSE_ENABLE_RW", ui)
        self.assertIn('\"Enable write access\"', lvgl)
        self.assertIn('\"Wrong PIN - still READ ONLY\"', lvgl)
        self.assertIn("ALWAYS tear down", local_uv)
        self.assertIn("R16_RW_PIN_INIT_FIX", local_uv)
        self.assertIn("PIN_LEGACY_DATA_LEN", local_uv)
        self.assertIn("double_hash_pin(CONST_BYTE_ARRAY(h,16),verifier)", local_uv)
        self.assertIn("pf_uv_unlock_and_migrate_pin", local_uv)
        self.assertIn('#include "local_uv_binding.h"', local_uv)
        binding = (PORT / "local_uv_binding.h").read_text(encoding="utf-8")
        self.assertIn("file_search_by_fid(EF_PIN,NULL,SPECIFY_EF)", binding)
        self.assertIn("file_search_by_fid(EF_KEY_DEV,NULL,SPECIFY_EF)", binding)
        self.assertIn("encrypt_keydev_f1(key)", local_uv)
        self.assertIn("pf_uv_forget_working_secrets();\n    return result;", local_uv)
        self.assertIn("R13_RW_PIN_USB_GATE", patch)
        self.assertIn("ws_board_settings_pin_busy()", patch)
        self.assertIn("CTAP1_ERR_CHANNEL_BUSY", patch)
        self.assertIn("CTAP_PERMISSION_ACFG", manager)

        fixture = ("void f(void) {\n"
                   "    resp->init.data[0] = is_req_button_pending() ? 2 : 1;\n"
                   "        driver_init_hid();\n\n"
                   "        hid_rx[ITF_HID_CTAP].r_ptr += HID_RPT_SIZE;\n"
                   "}\n")
        transformed = TOUCH_PATCH.hid(fixture)
        self.assertIn('#include \"ws_board.h\"', transformed)
        self.assertIn("R13_RW_PIN_USB_GATE", transformed)
        self.assertIn("return ctap_error(CTAP1_ERR_CHANNEL_BUSY);", transformed)

    def test_lvgl_vendor_does_not_require_nonexistent_root_version_header(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            lvgl = base / "lvgl"
            (lvgl / "src").mkdir(parents=True)
            (lvgl / "src/lvgl.h").write_text(
                '#pragma once\n#include "../lvgl.h"\n', encoding="utf-8")
            (lvgl / "src/minimal.c").write_text(
                '/* LVGL fixture */\n', encoding="utf-8")
            (lvgl / "lvgl.h").write_text(
                '#pragma once\n#define LVGL_VERSION_MAJOR 8\n'
                '#define LVGL_VERSION_MINOR 4\n#define LVGL_VERSION_PATCH 0\n',
                encoding="utf-8")
            # Intentionally no repository-root lv_version.h: v8.4.0 does not
            # have one. This reproduces the R5 Windows WinError 2 regression.
            stage = base / "stage"
            stage.mkdir()
            generated = {}
            PREPARE.vendor_lvgl(lvgl, stage, generated, apply_rgb565_overlay=False)
            self.assertTrue((stage / "lvgl/lvgl.h").is_file())
            self.assertTrue((stage / "lvgl/src/minimal.c").is_file())
            self.assertFalse((stage / "lvgl/lv_version.h").exists())
            self.assertIn("lvgl/lvgl.h", generated)

    def test_handler_is_header_and_uses_canonical_version(self):
        header = PORT / "ws_manager_config.h"
        self.assertTrue(header.is_file())
        self.assertFalse((PORT / "ws_manager_config.inc").exists())
        text = header.read_text()
        self.assertIn("PF_FIRMWARE_VERSION_STRING", text)
        self.assertIn("CTAP_PERMISSION_ACFG", text)
        self.assertIn("fido_object_authorization_session_invalidate", text)

    def test_source_plan_maps_manager_header(self):
        # Only the file-list planner is exercised here, not upstream transforms.
        with tempfile.TemporaryDirectory() as tmp:
            roots = {name: (Path(tmp) / name).resolve() for name in PREPARE.REPOS}
            for name, root in roots.items():
                root.mkdir()
            for name, subdir, names in [
                ("sdk", "src", PREPARE.SDK_SOURCES),
                ("fido", "src/fido", PREPARE.FIDO_SOURCES),
                ("cbor", "src", PREPARE.CBOR_SOURCES),
                ("ducky", "components/ducky", ("ducky.c", "ducky_keymap.c")),
            ]:
                for filename in names:
                    p = roots[name] / subdir / filename
                    p.parent.mkdir(parents=True, exist_ok=True)
                    p.write_text("/* source-plan fixture; not an upstream implementation */\n")
            (roots["sdk"] / "picokeys_sdk_import.cmake").write_text("")
            (roots["crypto"] / "library").mkdir()
            _, mapping = PREPARE.source_plan(roots)
            self.assertEqual(mapping[PORT / "ws_manager_config.h"], "board/ws_manager_config.h")
            self.assertEqual(mapping[PORT / "ws_logo_assets.h"], "board/ws_logo_assets.h")
            self.assertEqual(mapping[PORT / "local_uv_binding.h"], "board/local_uv_binding.h")
            self.assertEqual(mapping[roots["ducky"] / "components/ducky/ducky.c"], "ducky/components/ducky/ducky.c")
            self.assertEqual(mapping[roots["ducky"] / "components/ducky/ducky_keymap.c"], "ducky/components/ducky/ducky_keymap.c")
            self.assertNotIn("board/local_uv_binding.inc", mapping.values())
            self.assertNotIn("board/ws_manager_config.inc", mapping.values())

    def test_rewrite_uses_correct_three_parent_path(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            origin = base / "upstream/fido/src/fido/cbor_config.c"
            output = base / "sketch/src/engine/fido/src/fido/cbor_config.c"
            target = base / "sketch/src/engine/board/ws_manager_config.h"
            result = PREPARE.rewrite_includes(
                '#include "ws_manager_config.h"\n', origin, output,
                {(PORT / "ws_manager_config.h").resolve(): target},
                [PORT], base / "config.h", base / "pf_engine_api.h")
            self.assertEqual(result, '#include "../../../board/ws_manager_config.h"\n')

    def test_r21_rewrites_canonical_firmware_version_for_lvgl(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            origin = PORT / "ws_lvgl.c"
            output = base / "sketch/src/engine/board/ws_lvgl.c"
            version = base / "sketch/src/pf_firmware_version.h"
            result = PREPARE.rewrite_includes(
                '#include "pf_firmware_version.h"\n', origin, output, {}, [PORT],
                base / "config.h", base / "sketch/src/pf_engine_api.h", version)
            self.assertEqual(result, '#include "../../pf_firmware_version.h"\n')

    def test_local_supported_header_passes(self):
        with tempfile.TemporaryDirectory() as tmp:
            engine = Path(tmp)
            (engine / "file.c").write_text('#include "./fragment.h"\n')
            (engine / "fragment.h").write_text("/* test */\n")
            PREPARE.validate_local_includes(engine)

    def test_r17_local_uv_binding_header_rewrites_and_validates(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            origin = base / "upstream/fido/src/fido/cbor_client_pin.c"
            output = base / "sketch/src/engine/fido/src/fido/cbor_client_pin.c"
            target = base / "sketch/src/engine/board/local_uv_binding.h"
            origin.parent.mkdir(parents=True)
            output.parent.mkdir(parents=True)
            target.parent.mkdir(parents=True)
            origin.write_text("/* fixture */\n")
            target.write_text("#pragma once\n")
            result = PREPARE.rewrite_includes(
                '#include "local_uv_binding.h"\n', origin, output,
                {(PORT / "local_uv_binding.h").resolve(): target.resolve()},
                [PORT], base / "config.h", base / "pf_engine_api.h")
            self.assertEqual(result, '#include "../../../board/local_uv_binding.h"\n')
            output.write_text(result)
            PREPARE.validate_local_includes(base / "sketch/src/engine")

    def test_existing_inc_is_rejected_before_build(self):
        with tempfile.TemporaryDirectory() as tmp:
            engine = Path(tmp)
            (engine / "file.c").write_text('#include "./fragment.inc"\n')
            (engine / "fragment.inc").write_text("/* physically present but not staged */\n")
            with self.assertRaisesRegex(RuntimeError, "ARDUINO_UNSUPPORTED_INCLUDE_EXTENSION"):
                PREPARE.validate_local_includes(engine)

    def test_missing_relative_header_still_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            engine = Path(tmp)
            (engine / "file.c").write_text('#include "./missing.h"\n')
            with self.assertRaisesRegex(RuntimeError, "Broken generated include"):
                PREPARE.validate_local_includes(engine)

    def test_psram_enabled_and_erase_flags_stay_unchanged(self):
        script = (FW / "build_arduino.py").read_text()
        self.assertIn("PSRAM=enabled", script)
        self.assertIn("build.psram_type=opi", script)
        self.assertIn("EraseFlash=none", script)
        self.assertIn("USBMode=default", script)
        self.assertIn("validate_output(ROOT/", script)

    @unittest.skipUnless((ROOT/'manager/evilkey_manager/project.py').is_file(),'Manager is distributed separately')
    def test_full_manager_export_carries_fixed_generator_and_header(self):
        sys.path.insert(0, str(ROOT / "manager"))
        from evilkey_manager.project import DEFAULTS, export_project
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "export"
            export_project(FW, out, DEFAULTS)
            self.assertTrue((out / "templates/port/ws_manager_config.h").is_file())
            self.assertTrue((out / "templates/port/ws_usb_tool_state.c").is_file())
            self.assertTrue((out / "EvilKeyV1/src/UsbTool.cpp").is_file())
            self.assertIn("FIDO_V1_USB_TOOL", (out / "EvilKeyV1/FidoConfig.h").read_text())
            self.assertFalse((out / "templates/port/ws_manager_config.inc").exists())
            self.assertIn('#include "ws_manager_config.h"',
                          (out / "tools/manager_source.py").read_text())
            self.assertIn("ARDUINO_UNSUPPORTED_INCLUDE_EXTENSION",
                          (out / "prepare_arduino.py").read_text())

    @unittest.skipUnless(os.name != "nt" and shutil.which("cc"), "Requires native C compiler")
    def test_filtered_staging_old_inc_fails_new_header_builds_and_runs(self):
        # A host-only reproduction of the missing-include mechanism. The M1
        # C harness uses mocked CBOR/HMAC results, not actual CTAP cryptography.
        with tempfile.TemporaryDirectory() as tmp:
            stage = Path(tmp) / "stage"
            board = stage / "src/engine/board"
            board.mkdir(parents=True)
            for source in PORT.iterdir():
                if source.is_file() and source.suffix in PREPARE.ARDUINO_CODE_SUFFIXES:
                    shutil.copy2(source, board / source.name)
            # R5 board/ws_lvgl.c has a real relative include into the vendored
            # LVGL tree. This host-only manager-auth fixture does not compile
            # the GUI, but validate_local_includes still correctly requires the
            # referenced header to exist.
            lvgl_header = stage / "src/engine/lvgl/lvgl.h"
            lvgl_header.parent.mkdir(parents=True, exist_ok=True)
            lvgl_header.write_text("#pragma once\n", encoding="utf-8")
            original = FW / "tests/release_026/test_manager_auth.c"
            translation_unit = stage / "src/engine/fido/src/fido/cbor_config.c"
            translation_unit.parent.mkdir(parents=True)
            # The host harness also consumes the canonical firmware-version header.
            version_dst = stage / "src/engine/fido/EvilKeyV1/src/pf_firmware_version.h"
            version_dst.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(FW / "EvilKeyV1/src/pf_firmware_version.h", version_dst)
            # Use the real include rewriter at the same relative depth as firmware.
            mapping = {p.resolve(): board / p.name for p in PORT.iterdir() if p.is_file()}
            rewritten = PREPARE.rewrite_includes(
                original.read_text(), original, translation_unit, mapping,
                [PORT], stage / "config.h", stage / "pf_engine_api.h")
            expected = '#include "../../../board/ws_manager_config.h"'
            self.assertIn(expected, rewritten)
            command = ["cc", "-std=c11", "-O1", "-Wall", "-Wextra", "-Werror",
                       str(translation_unit), str(board / "ws_settings_codec.c"),
                       "-o", str(stage / "manager_auth")]
            translation_unit.write_text(rewritten.replace(
                expected, '#include "../../../board/ws_manager_config.inc"'))
            bad = subprocess.run(command, capture_output=True, text=True, timeout=30)
            self.assertNotEqual(bad.returncode, 0)
            self.assertIn("ws_manager_config.inc", bad.stderr)
            translation_unit.write_text(rewritten)
            PREPARE.validate_local_includes(stage / "src/engine")
            good = subprocess.run(command, capture_output=True, text=True, timeout=30)
            self.assertEqual(good.returncode, 0, good.stdout + good.stderr)
            run = subprocess.run([str(stage / "manager_auth")], capture_output=True,
                                 text=True, timeout=10)
            self.assertEqual(run.returncode, 0, run.stdout + run.stderr)
            self.assertIn("PASS PFM1/PFM2", run.stdout)


if __name__ == "__main__":
    unittest.main(verbosity=2)
