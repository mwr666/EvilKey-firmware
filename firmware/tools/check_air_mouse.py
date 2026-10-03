#!/usr/bin/env python3
"""Check Air Mouse isolation, USB identity, and touch geometry contracts."""
from pathlib import Path
import re

root = Path(__file__).resolve().parents[2]
fw = root / "firmware"
port = fw / "templates/port"


def read(path):
    return path.read_text(encoding="utf-8")


def require(text, *parts):
    for part in parts:
        if part not in text:
            raise SystemExit(f"FAIL: missing Air Mouse contract: {part}")


config = read(fw / "EvilKeyV1/FidoConfig.h")
pid_names = (
    "FIDO_V1_CUSTOM_PID", "FIDO_V1_MANAGER_DRIVE_PID",
    "FIDO_V1_USB_TOOL_PID", "FIDO_V1_AIR_MOUSE_PID",
)
pids = []
for name in pid_names:
    match = re.search(r"^#define\s+" + name + r"\s+(0x[0-9A-Fa-f]+)\s*$", config, re.M)
    if not match:
        raise SystemExit(f"FAIL: missing numeric PID {name}")
    pids.append(int(match.group(1), 16))
if len(set(pids)) != len(pids):
    raise SystemExit("FAIL: Air Mouse USB PID collides with an existing role")

usb = read(fw / "EvilKeyV1/src/PicoFidoArduino.cpp")
require(usb, "TUD_HID_REPORT_DESC_MOUSE()", "s_config_air_mouse_hid",
        "s_descriptor_air_mouse_role", "if(s_descriptor_air_mouse_role)return s_config_air_mouse_hid;",
        "manager_drive = !tool && !mouse", "RTC_NOINIT_ATTR",
        "esp_reset_reason()==ESP_RST_SW", "s_air_mouse_boot_token=0;",
        "tud_hid_mouse_report(0,buttons,x,y,wheel,0)")
descriptor = usb.split("static const uint8_t air_mouse_report_descriptor[] = {", 1)[1].split("};", 1)[0]
if "KEYBOARD" in descriptor or "CONSUMER" in descriptor or "ABSMOUSE" in descriptor:
    raise SystemExit("FAIL: Air Mouse advertises a non-mouse HID report")

hid = read(fw / "EvilKeyV1/src/engine/sdk/src/usb/hid/hid.c")
handler = hid.split("void tud_hid_set_report_cb(", 2)[-1]
if handler.find("if (pf_air_mouse_role()) return;") < 0 or handler.find("if (pf_air_mouse_role()) return;") > handler.find("driver_process_usb_packet_hid(bufsize)"):
    raise SystemExit("FAIL: CTAP input is not gated in the mouse-only role")

ui = read(port / "ws_ui.h")
require(ui, "WS_SETTINGS_PAGE_DIAGNOSTICS = 5", "WS_SETTINGS_PAGE_AIR_MOUSE = 7",
        "WS_SETTINGS_PAGE_USB = 8", "WS_SETTINGS_PAGE_USB_TOOL = 9",
        "WS_SETTINGS_PAGE_COUNT = 10")
layout = read(port / "ws_ui_layout.h")
rects = []
rect_by_name = {}
for prefix in ("EXIT", "CAL", "LEFT", "RIGHT", "SCROLL", "MOVE"):
    values = []
    for suffix in ("X", "Y", "W", "H"):
        match = re.search(r"^#define\s+WS_MOUSE_" + prefix + "_" + suffix + r"\s+(\d+)\s*$", layout, re.M)
        if not match:
            raise SystemExit(f"FAIL: missing WS_MOUSE_{prefix}_{suffix}")
        values.append(int(match.group(1)))
    x, y, width, height = values
    if not (0 <= x < 280 and 0 <= y < 456 and width > 0 and height > 0 and x + width <= 280 and y + height <= 456):
        raise SystemExit(f"FAIL: {prefix} touch zone is outside the AMOLED")
    rects.append((prefix, x, y, x + width, y + height))
    rect_by_name[prefix] = (x, y, width, height)
for i, (name1, x1, y1, endx1, endy1) in enumerate(rects):
    for name2, x2, y2, endx2, endy2 in rects[i + 1:]:
        if x1 < endx2 and x2 < endx1 and y1 < endy2 and y2 < endy1:
            raise SystemExit(f"FAIL: {name1} and {name2} touch zones overlap")
left = rect_by_name["LEFT"]
right = rect_by_name["RIGHT"]
scroll = rect_by_name["SCROLL"]
move = rect_by_name["MOVE"]
cal = rect_by_name["CAL"]
exit_button = rect_by_name["EXIT"]
if not (left[3] >= 200 and right[3] >= 200 and
        left[1] == scroll[1] == right[1] and
        left[0] + left[2] < scroll[0] and
        scroll[0] + scroll[2] < right[0] and
        max(left[1] + left[3], scroll[1] + scroll[3], right[1] + right[3]) <
        min(cal[1], exit_button[1]) and
        max(left[1] + left[3], scroll[1] + scroll[3], right[1] + right[3]) < move[1] and
        move[1] + move[3] < min(cal[1], exit_button[1])):
    raise SystemExit("FAIL: tall click zones and centered scroll must precede SETTINGS/EXIT")

config_rects = []
for prefix in ("MINUS", "PLUS", "INVERT", "CAL", "BACK"):
    values = []
    for suffix in ("X", "Y", "W", "H"):
        match = re.search(r"^#define\s+WS_MOUSE_CFG_" + prefix + "_" + suffix + r"\s+(\d+)\s*$", layout, re.M)
        if not match:
            raise SystemExit(f"FAIL: missing WS_MOUSE_CFG_{prefix}_{suffix}")
        values.append(int(match.group(1)))
    x, y, width, height = values
    if not (0 <= x < 280 and 0 <= y < 456 and width > 0 and height > 0 and x + width <= 280 and y + height <= 456):
        raise SystemExit(f"FAIL: CFG_{prefix} touch zone is outside the AMOLED")
    config_rects.append((prefix, x, y, x + width, y + height))
for i, (name1, x1, y1, endx1, endy1) in enumerate(config_rects):
    for name2, x2, y2, endx2, endy2 in config_rects[i + 1:]:
        if x1 < endx2 and x2 < endx1 and y1 < endy2 and y2 < endy1:
            raise SystemExit(f"FAIL: CFG_{name1} and CFG_{name2} touch zones overlap")

board = read(port / "ws_board.c")
require(board, "qmi_read(0x35U,data,sizeof(data))", "air_mouse_calibrate();",
        "qmi_write(0x03U,0x06U)", "qmi_write(0x08U,0x01U)",
        "size_t length=(s_air_mouse_role || s_apps_touch_mode || s_gamepad_role)?sizeof(bytes):5U;",
        "s_mouse_point_count=(uint8_t)points;",
        "ws_mouse_latch_touch(&s_mouse_latch",
        "view->air_mouse_drag_latched=s_mouse_latch.drag;",
        "else if(motion_held && s_air_mouse_neutral_valid",
        "view->air_mouse_move_held=motion_held;",
        "pf_air_mouse_exit();", "pf_control_restart(s_control_requested);",
        "if(s_air_mouse_role) {", "return;",
        "if(held>=3000U && !s_air_mouse_action_hold_fired)",
        "s_air_mouse_action_hold_zone=action_zone;",
        "view->air_mouse_hold_step=hold_step;",
        "float tilt_x=tx*s_air_mouse_right_x+ty*s_air_mouse_right_y+",
        "float tilt_y=tx*s_air_mouse_down_x+ty*s_air_mouse_down_y+",
        "float radius=sqrtf(tilt_x*tilt_x+tilt_y*tilt_y);",
        "float gain=850.0f+1300.0f*active;",
        "air_mouse_vector_delta(tilt_y,s_air_mouse_invert_y?tilt_x:-tilt_x,",
        "pixels_per_g*=sensitivity_scale[s_air_mouse_sensitivity-1U];",
        "nvs_open_from_partition(\"wsdev\",\"ws_airmouse\",NVS_READWRITE,&h)",
        "view->air_mouse_settings_open=s_air_mouse_settings_open;",
        "if(*fraction>100.0f)",

        "view->air_mouse_touch_fault=!s_touch_available || s_touch_errors>=10U;")
lvgl = read(port / "ws_lvgl.c")
require(lvgl, "HOLD 3 SEC", "HOLD TO MOVE", "DRAG ON", "DRAG OFF",
        "Hold MOVE to steer.\\nTap DRAG to hold left.\\nTap again to release.",
        "air_mouse_exit_progress", "air_mouse_calibrate_progress",
        "s_last_view.air_mouse_hold_step!=v->air_mouse_hold_step",
        "Touch unavailable", "Touch outside controls", "INVERT VERTICAL",
        "BACK TO MOUSE", "3 = original speed")
print("PASS: Air Mouse has an isolated mouse-only USB role and gated CTAP input")
print("PASS: one-shot mode selection, Settings order, tall touch zones and 3-second guarded actions")
