#!/usr/bin/env python3
"""R34 source guard: Hak5-compatible passive OS fingerprint architecture."""
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
FW = ROOT / "firmware"


def need(path: Path, *tokens: str) -> str:
    text = path.read_text(encoding="utf-8")
    for token in tokens:
        if token not in text:
            raise SystemExit(f"FAIL {path}: missing {token!r}")
    return text


patch = need(
    FW / "tools" / "ducky3_hid_patch.py",
    "preprocess_defined_blocks",
    'equal_case(command, "IF_DEFINED_TRUE")',
    'equal_case(command, "IF_NOT_DEFINED_TRUE")',
    'equal_case(command, "ELSE_DEFINED")',
    'equal_case(command, "END_IF_DEFINED")',
    "reset_host_configuration_request_count",
    "host_os_guess",
    "valid_internal",
)
adapter = need(
    FW / "EvilKeyV1" / "src" / "UsbTool.cpp",
    "pf_usb_configuration_descriptor_requested",
    "s_host_configuration_request_count",
    "io_reset_host_config_count",
    "io_host_os_guess",
    "if(s_host_configuration_request_count>2U)return 1U",
)
if "s_received_led_report?3U:0U" in adapter.replace(" ", ""):
    raise SystemExit("FAIL: R34 must not synthesize configuration-request count from an LED reply")

need(
    FW / "tools" / "check_usb_stack.py",
    "PICO_FIDO_DUCKY_OS_HOOK_S2",
    "pf_usb_configuration_descriptor_requested",
    "tud_descriptor_configuration_cb",
    "legacy_patch_bytes",
    'recorded_test not in ("S1", "S2")',
)
need(
    FW / "tests" / "release_026" / "test_ducky_os_r34.c",
    "IF_DEFINED_TRUE #DISABLED",
    "IF_NOT_DEFINED_TRUE #MISSING",
    "$_HOST_CONFIGURATION_REQUEST_COUNT = 0",
    "PASSIVE_WINDOWS_DETECT",
    "host_os_guess",
)
need(
    FW / "tools" / "run_ducky_runtime_tests.py",
    '("r33", "test_ducky_os_r33.c")',
    '("r34", "test_ducky_os_r34.c")',
)

print("PASS: R34 uses exact TinyUSB configuration-descriptor observations, not LED-derived counts")
print("PASS: R34 adds compile-time DEFINE gates, long internal assignment, counter reset and OS snapshot")
