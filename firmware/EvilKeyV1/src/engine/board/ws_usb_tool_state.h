/* SPDX-License-Identifier: AGPL-3.0-or-later */
#pragma once
#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
    WS_USB_LAYOUT_US = 0,
    WS_USB_LAYOUT_PL_PROGRAMMER = 1,
    WS_USB_LAYOUT_DE = 2,
    WS_USB_LAYOUT_FR = 3,
    WS_USB_LAYOUT_ES = 4,
    WS_USB_LAYOUT_COUNT = 5
} ws_usb_layout_t;

#define WS_USB_LANGUAGE_CODE_MAX 20

/* Non-secret USB Tool preferences. They share the wsdev/pf_manager namespace
 * with display/Manager preferences, never the FIDO credential/key storage. */
void ws_usb_tool_state_init(void);
bool ws_usb_tool_enabled(void);
bool ws_usb_tool_storage_ok(void);
ws_usb_layout_t ws_usb_tool_layout(void);
bool ws_usb_tool_set_enabled(bool enabled);
bool ws_usb_tool_set_layout(ws_usb_layout_t layout);
const char *ws_usb_tool_layout_name(ws_usb_layout_t layout);
void ws_usb_tool_language_code(char *out,size_t out_len);
bool ws_usb_tool_set_language_code(const char *code);

#ifdef __cplusplus
}
#endif
