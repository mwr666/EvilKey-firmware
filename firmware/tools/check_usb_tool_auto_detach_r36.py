#!/usr/bin/env python3
"""R36 source/contract guard for conservative USB Tool auto-detach."""
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SRC = ROOT / "firmware" / "EvilKeyV1" / "src"


def require(path: Path, *tokens: str) -> str:
    text = path.read_text(encoding="utf-8")
    missing = [token for token in tokens if token not in text]
    if missing:
        raise SystemExit(f"FAIL: {path}: missing {missing}")
    return text


adapter = require(
    SRC / "PfUsbMsc.cpp",
    "PF_SCSI_SYNCHRONIZE_CACHE_10 = 0x35U",
    "PF_SCSI_SYNCHRONIZE_CACHE_16 = 0x91U",
    "tud_msc_scsi_complete_cb",
    "SD.writeRAW is synchronous",
)
arduino = require(
    SRC / "PicoFidoArduino.cpp",
    '#include "PfUsbMsc.h"',
    "s_tool_storage_host_write_seen=true;",
    "s_tool_storage_sync_after_last_write=false;",
    "tool_storage_scsi_complete",
    "pf_usb_tool_storage_auto_detach_state",
    "s_tool_storage_io_in_flight!=0U",
    "pf_usb_tool_storage_claim_auto_detach",
    "portENTER_CRITICAL(&s_tool_storage_guard)",
)
tool = require(
    SRC / "UsbTool.cpp",
    "PF_STORAGE_AUTO_DETACH_IDLE_MS 10000U",
    "pf_usb_tool_storage_arm_auto_detach();",
    "PF_USB_TOOL_AUTO_DETACH_WAIT_SYNC",
    "pf_usb_tool_storage_claim_auto_detach(PF_STORAGE_AUTO_DETACH_IDLE_MS)",
    "handle_storage_auto_detach();",
    "Completed - storage detached",
)
require(
    SRC / "pf_engine_api.h",
    "PF_USB_TOOL_AUTO_DETACH_WAIT_IDLE",
    "PF_USB_TOOL_AUTO_DETACH_WAIT_SYNC",
    "PF_USB_TOOL_AUTO_DETACH_READY",
)
safe_eject = require(
    ROOT / "microSD_EVILKEY_EXAMPLES" / "duckyscripts" / "helpers" /
        "SafeEject.ps1",
    "Write-VolumeCache -DriveLetter $driveLetter",
    "FSCTL_LOCK_VOLUME",
    "FSCTL_DISMOUNT_VOLUME",
    "IOCTL_STORAGE_EJECT_MEDIA",
    "[switch]$SignalScrollLock",
    "Start-Sleep -Milliseconds 750",
    "[PicoFidoSafeRemovalR36]::SignalScrollLock()",
)
require(
    ROOT / "microSD_EVILKEY_EXAMPLES" / "duckyscripts" / "library" /
        "credentials" / "Save_WiFi_Passwords.txt",
    "ATTACKMODE HID STORAGE",
    "SafeEject.ps1",
    "loot.txt",
)
complete_test = require(
    ROOT / "microSD_EVILKEY_EXAMPLES" / "duckyscripts" / "test" /
        "Complete-Loot-Test" / "payload.txt",
    "SafeEject.ps1",
    "-SignalScrollLock",
    "WAIT_FOR_SCROLL_CHANGE",
)
harvest_path = (ROOT / "microSD_EVILKEY_EXAMPLES" / "duckyscripts" /
                "library" / "credentials" / "Harvest" / "sy_cred.ps1")
if harvest_path.is_file():
    # The locally retained third-party example is excluded from this repository.
    harvest_script = require(
        harvest_path,
        "duckyscripts\\helpers\\SafeEject.ps1",
        "-SignalScrollLock",
        "PicoFIDO-eject-error.txt",
    )
    if "class PicoFidoStorage" in harvest_script or "IOCTL_STORAGE_EJECT_MEDIA" in harvest_script:
        raise SystemExit("FAIL: Harvest still embeds a duplicated safe-eject implementation")
else:
    print("SKIP: third-party Harvest example is not included")
if "eject_test.ps1" in complete_test:
    raise SystemExit("FAIL: Complete-Loot-Test still references the duplicated eject helper")
if (ROOT / "microSD_EVILKEY_EXAMPLES" / "duckyscripts" / "test" /
        "Complete-Loot-Test" / "eject_test.ps1").exists():
    raise SystemExit("FAIL: duplicated Complete-Loot-Test eject helper still exists")
if safe_eject.index("if ($result -ne 0)") > safe_eject.index("if ($SignalScrollLock)"):
    raise SystemExit("FAIL: Scroll Lock can be signalled before eject success is checked")

if "#include <USBMSC.h>" in arduino:
    raise SystemExit("FAIL: installed Arduino USBMSC would shadow the local SCSI adapter")
if adapter.index("PF_SCSI_SYNCHRONIZE_CACHE_10") > adapter.index("return 0;", adapter.index("switch (scsi_cmd[0])")):
    raise SystemExit("FAIL: SYNCHRONIZE CACHE is not acknowledged by the local adapter")
if tool.index("stage8_cleanup();") > tool.index("pf_usb_tool_storage_arm_auto_detach();"):
    raise SystemExit("FAIL: auto-detach was armed before local loot writers were closed")


UNARMED, WAIT_IDLE, WAIT_SYNC, READY = range(4)


def policy(*, armed=True, present=True, wrote=False, synced=False,
           in_flight=0, arm_age=0, io_age=0, idle=10_000):
    if not armed or not present:
        return UNARMED
    if wrote and not synced:
        return WAIT_SYNC
    if in_flight or arm_age < idle or io_age < idle:
        return WAIT_IDLE
    return READY


assert policy(arm_age=9_999, io_age=12_000) == WAIT_IDLE
assert policy(arm_age=10_000, io_age=10_000) == READY
assert policy(wrote=True, arm_age=60_000, io_age=60_000) == WAIT_SYNC
assert policy(wrote=True, synced=True, arm_age=60_000, io_age=9_999) == WAIT_IDLE
assert policy(wrote=True, synced=True, arm_age=60_000, io_age=10_000) == READY
# A write after a prior flush resets synced=false in the firmware and must block.
assert policy(wrote=True, synced=False, arm_age=60_000, io_age=60_000) == WAIT_SYNC
assert policy(in_flight=1, arm_age=60_000, io_age=60_000) == WAIT_IDLE
assert policy(present=False, arm_age=60_000, io_age=60_000) == UNARMED

map_path = ROOT / "firmware" / "build-arduino" / "EvilKeyV1.ino.map"
if map_path.is_file():
    link_map = map_path.read_text(encoding="utf-8", errors="replace")
    owner = "tud_msc_scsi_cb"
    lines = [line for line in link_map.splitlines() if line.startswith(owner)]
    if len(lines) != 1 or "PfUsbMsc.cpp.o" not in lines[0]:
        raise SystemExit("FAIL: linked SCSI callback is not uniquely owned by PfUsbMsc.cpp")
    if "core.a(USBMSC.cpp.o)" in link_map:
        raise SystemExit("FAIL: Arduino core USBMSC object was linked beside PfUsbMsc")

print("PASS: R36 conservative auto-detach contract and linked MSC ownership")
