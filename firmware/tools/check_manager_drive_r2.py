from __future__ import annotations
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[2]
FW = ROOT / "firmware"


def require(path: Path, *needles: str) -> str:
    if not path.is_file():
        raise SystemExit(f"FAIL: missing {path.relative_to(ROOT)}")
    text = path.read_text(encoding="utf-8", errors="strict")
    for needle in needles:
        if needle not in text:
            raise SystemExit(f"FAIL: {path.relative_to(ROOT)} missing {needle!r}")
    return text


def main() -> int:
    cfg = require(FW / "EvilKeyV1/FidoConfig.h",
                  "#define FIDO_V1_MANAGER_DRIVE            1",
                  "#define FIDO_V1_MANAGER_DRIVE_DEFAULT    0",
                  "#define FIDO_V1_MANAGER_DRIVE_VID        0xFEFF",
                  "#define FIDO_V1_MANAGER_DRIVE_PID        0xFCFC")
    usb = require(FW / "EvilKeyV1/src/PicoFidoArduino.cpp",
                  '#include "PfUsbMsc.h"', "manager_drive_register()",
                  "s_msc->isWritable(false)", "s_msc->mediaPresent(media)",
                  "const uint8_t hid_itf = *itf",
                  "TUD_HID_INOUT_DESCRIPTOR(hid_itf")
    if "*itf != 0" in usb:
        raise SystemExit("FAIL: HID descriptor still assumes USB interface 0")
    require(FW / "templates/port/ws_manager_drive_state.c",
            '"pf_manager"', '"mdrive_v1"', "nvs_commit", "nvs_get_u8", "nvs_set_u8")
    require(FW / "templates/port/ws_board.c",
            "ws_ui_idle_hit_test", "ws_manager_drive_set_enabled", "esp_restart()")
    require(FW / "templates/port/ws_ui.c",
            '"MANAGER DRIVE ON"', '"MANAGER DRIVE OFF"', '"READ ONLY - TAP TO DISABLE"')
    require(FW / "prepare_arduino.py", '"ws_manager_drive_state.c"')
    require(ROOT / "manager/evilkey_manager/project.py",
            '"FIDO_V1_MANAGER_DRIVE":1', '"FIDO_V1_MANAGER_DRIVE_DEFAULT":0',
            '"FIDO_V1_MANAGER_DRIVE_PID":0xFCFC')
    require(FW / "tests/release_026/test_manager_drive_state.c", "PASS Manager Drive NVS")
    require(FW / "tests/release_026/test_gui_ui1.c", "Manager Drive has a separate READY-only")
    print("PASS: Manager Drive R2 source integration")
    print("PASS: Manager Drive defaults OFF and exports microSD read-only")
    print("PASS: FIDO HID descriptor no longer assumes interface 0")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
