#!/usr/bin/env python3
"""Internal V1 source transformations inherited from the development port.
Imported by prepare_arduino.py; not a standalone builder.
"""
from __future__ import annotations
import argparse
import hashlib
import json
from pathlib import Path
import re
import shutil
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1] / "templates"
LOCK = json.loads((ROOT.parent / "UPSTREAM_LOCK.json").read_text(encoding="utf-8"))


def run(args: list[str], cwd: Path | None = None) -> str:
    print("+", " ".join(args), flush=True)
    return subprocess.check_output(args, cwd=cwd, text=True).strip()


def git_blob_hash(data: bytes) -> str:
    return hashlib.sha1(f"blob {len(data)}\0".encode() + data).hexdigest()


def replace_once(text: str, old: str, new: str, label: str) -> str:
    if text.count(old) != 1:
        raise RuntimeError(f"{label}: expected exactly one matching anchor; refusing to patch")
    return text.replace(old, new, 1)


def replace_function(text: str, name: str, replacement: str) -> str:
    # Anchors are deliberately specific to the verified upstream revision.
    pattern = rf"(?ms)^void {re.escape(name)}\(void\) \{{.*?^\}}"
    text, count = re.subn(pattern, lambda _: replacement.rstrip(), text)
    if count != 1:
        raise RuntimeError(f"Cannot replace {name}: found {count} function blocks")
    return text


BUTTON_START = r'''void button_wait_start(void) {
    /* Waveshare V1: physical presence is never automatically commissioned away. */
    const uint32_t button_timeout = 30000;
    cancel_button = false;
    async_button_wait = true;
    ws_pending_result = BUTTON_EV_NONE;
    async_button_led_mode = led_get_mode();
    req_button_pending = true;
    led_set_mode(MODE_BUTTON);
    ws_board_presence_begin(button_timeout);
    signal_user_presence_request_data_t data = {
        .timeout = button_timeout / 1000,
    };
    signal_emit_param(SIGNAL_USER_PRESENCE_REQUEST, &data);
}'''

BUTTON_POLL = r'''void button_wait_poll(void) {
    if (!async_button_wait) {
        return;
    }
    if (ws_pending_result == BUTTON_EV_NONE) {
        ws_pending_result = ws_board_presence_poll();
    }
    if (cancel_button) {
        ws_pending_result = BUTTON_EV_CANCELLED;
    }
    if (ws_pending_result == BUTTON_EV_NONE) {
        return;
    }
    button_event_t result = ws_pending_result;
    uint32_t flag = result == BUTTON_EV_PRESSED ? EV_BUTTON_PRESSED :
                    result == BUTTON_EV_TIMEOUT ? EV_BUTTON_TIMEOUT : EV_BUTTON_CANCELLED;
    /* Retry on a full queue instead of silently losing a one-shot decision. */
    if (!queue_try_add(&usb_to_card_q, &flag)) {
        return;
    }
    async_button_wait = false;
    req_button_pending = false;
    ws_pending_result = BUTTON_EV_NONE;
    ws_board_presence_end(result);
    led_set_mode(async_button_led_mode);
    if (result == BUTTON_EV_PRESSED) {
        signal_emit(SIGNAL_USER_PRESENCE_COMPLETED);
    } else if (result == BUTTON_EV_TIMEOUT) {
        signal_emit(SIGNAL_USER_PRESENCE_TIMEOUT);
    } else {
        signal_emit(SIGNAL_USER_PRESENCE_CANCELLED);
    }
}'''


def patch_files(original: dict[str, str]) -> dict[str, str]:
    """Pure transformation. prepare() verifies complete upstream blobs first."""
    output = dict(original)
    p = "CMakeLists.txt"
    s = output[p]
    # Local-development IDs only. They are NOT a registered commercial VID/PID.
    s = replace_once(s, "set(USB_VID 0x2E8A)", "set(USB_VID 0xFEFF)", p)
    s = replace_once(s, "set(USB_PID 0x10FE)", "set(USB_PID 0xFCFD)", p)
    s = replace_once(s, "set(DEBUG_APDU 1)", "set(DEBUG_APDU 0)", p)
    s = replace_once(s, "set(ENABLE_DIAGNOSTICS 1)", "set(ENABLE_DIAGNOSTICS 0)", p)
    s = replace_once(s, "set(PICOKEYS_COMPONENTS fido)", '''set(PICOKEYS_COMPONENTS fido)
    set(SDKCONFIG_DEFAULTS "${CMAKE_CURRENT_LIST_DIR}/board/ws_v1/sdkconfig.defaults")
    set(ENABLE_OATH_APP OFF CACHE BOOL "FIDO-only development build" FORCE)
    set(ENABLE_OTP_APP OFF CACHE BOOL "No emulated OTP keyboard" FORCE)
    set(ENABLE_POWER_ON_RESET OFF CACHE BOOL "USB development build" FORCE)
    set(ENABLE_PQC OFF CACHE BOOL "FIDO baseline" FORCE)
    set(FORCE_BUTTON_WAIT ON CACHE BOOL "Require user presence" FORCE)''', p)
    s = replace_once(s, "    project(pico_fido)\n", '''    project(pico_fido)
    if(CONFIG_SECURE_BOOT OR CONFIG_SECURE_FLASH_ENC_ENABLED OR
       CONFIG_SECURE_SIGNED_APPS_NO_SECURE_BOOT OR CONFIG_NVS_ENCRYPTION)
        message(FATAL_ERROR "WS V1 DEV: provisioning options are forbidden")
    endif()
    if(NOT CONFIG_IDF_TARGET_ESP32S3)
        message(FATAL_ERROR "WS V1 requires ESP32-S3")
    endif()
''', p)
    output[p] = s

    p = "pico-keys-sdk/src/main.c"
    s = replace_once(output[p], '#include "picokeys.h"',
                     '#include "picokeys.h"\n#include "ws_board.h"', p)
    s = replace_once(s, "    led_blinking_task();", "    led_blinking_task();\n    ws_board_poll();", p)
    s = replace_once(s, "    gpio_pulldown_dis(BOOT_PIN);", '''    gpio_pulldown_dis(BOOT_PIN);
    gpio_pullup_en(BOOT_PIN);
    ws_board_init();''', p)
    output[p] = s

    p = "pico-keys-sdk/src/button.c"
    s = replace_once(output[p], '#include "button.h"', '#include "button.h"\n#include "ws_board.h"', p)
    s = replace_once(s, "static bool async_button_pressed = false;",
                     "static button_event_t ws_pending_result = BUTTON_EV_NONE;", p)
    s = replace_once(s, "static uint32_t async_button_started = 0;\n", "", p)
    s = replace_once(s, "static uint32_t async_button_timeout = 0;\n", "", p)
    s = replace_function(s, "button_wait_start", BUTTON_START)
    s = replace_function(s, "button_wait_poll", BUTTON_POLL)
    output[p] = s

    p = "pico-keys-sdk/src/usb/usb.c"
    s = output[p]
    old_interfaces = """    uint8_t enabled_usb_itf = PHY_USB_ITF_ALL;
#ifndef ENABLE_EMULATION
    if (phy_data.enabled_usb_itf_present) {
        enabled_usb_itf = phy_data.enabled_usb_itf;
    }
#endif"""
    s = replace_once(s, old_interfaces,
        "    /* Development profile: FIDO HID only, no keyboard or CCID. */\n"
        "    uint8_t enabled_usb_itf = PHY_USB_ITF_HID;", p)
    output[p] = s

    p = "pico-keys-sdk/src/usb/usb_descriptors.c"
    output[p] = replace_once(output[p], "#define MAX_USB_POWER       2",
        "/* Declared bus-power budget, mA. Hardware consumption still needs measurement. */\n"
        "#define MAX_USB_POWER       500", p)

    p = "pico-keys-sdk/src/led/led.c"
    output[p] = replace_function(output[p], "led_init", '''void led_init(void) {
    /* GPIO48 is I2C SCL on V1, not a NeoPixel output. Ignore host LED config. */
    led_driver = &led_driver_dummy;
    led_driver->init();
    led_set_mode(MODE_NOT_MOUNTED);
}''')

    p = "pico-keys-sdk/config/esp32/components/pico-keys-sdk/CMakeLists.txt"
    s = replace_once(output[p], "idf_component_register(", '''get_filename_component(WS_BOARD_DIR "${PICOKEYS_SDK_DIR}/../board/ws_v1" ABSOLUTE)
list(APPEND PICOKEYS_SOURCES
    ${WS_BOARD_DIR}/ws_board.c
    ${WS_BOARD_DIR}/ws_panel.c
    ${WS_BOARD_DIR}/ws_presence.c
    ${WS_BOARD_DIR}/ws_ui.c
)
list(APPEND PICOKEYS_INCLUDE_DIRS ${WS_BOARD_DIR})
list(APPEND PICOKEYS_REQUIRES driver esp_lcd esp_timer nvs_flash)

idf_component_register(''', p)
    output[p] = s

    p = "pico-keys-sdk/config/esp32/components/pico-keys-sdk/idf_component.yml"
    output[p] = replace_once(output[p], '"^1.7.6"', '"1.7.6"', p)
    output["pico-keys-sdk/src/otp/otp_esp32.c"] = (ROOT / "port/otp_esp32_dev.c").read_text(encoding="utf-8")
    return output

