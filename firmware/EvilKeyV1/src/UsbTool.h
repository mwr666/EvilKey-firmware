/* SPDX-License-Identifier: AGPL-3.0-or-later */
#pragma once
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
    PF_USB_TOOL_DISABLED = 0,
    PF_USB_TOOL_NO_SD = 1,
    PF_USB_TOOL_IDLE = 2,
    PF_USB_TOOL_RUNNING = 3,
    PF_USB_TOOL_OK = 4,
    PF_USB_TOOL_ERROR = 5,
    PF_USB_TOOL_CANCELLED = 6,
    PF_USB_TOOL_CONFIRM_STAGE8 = 7
} pf_usb_tool_status_t;

typedef enum {
    PF_USB_TOOL_LED_OFF = 0,
    PF_USB_TOOL_LED_RED = 1,
    PF_USB_TOOL_LED_GREEN = 2
} pf_usb_tool_led_t;

/* Called only when the persistent USB role is USB Tool. No payload is ever
 * auto-executed; a local GUI action must call pf_usb_tool_run_selected(). */
bool pf_usb_tool_begin(void);
void pf_usb_tool_end(void);
bool pf_usb_tool_media_ready(void);
uint8_t pf_usb_tool_status(void);
bool pf_usb_tool_running(void);
uint16_t pf_usb_tool_script_count(void);
uint16_t pf_usb_tool_selected_index(void);
void pf_usb_tool_selected_name(char *out,size_t out_len);
bool pf_usb_tool_select_delta(int delta);
uint16_t pf_usb_tool_language_count(void);
uint16_t pf_usb_tool_language_index(void);
void pf_usb_tool_language_name(char *out,size_t out_len);
bool pf_usb_tool_select_language_delta(int delta);
bool pf_usb_tool_run_selected(void);
bool pf_usb_tool_confirmation_pending(void);
bool pf_usb_tool_confirm_stage8(void);
bool pf_usb_tool_stage8_active(void);
void pf_usb_tool_stop(void);
uint32_t pf_usb_tool_error_line(void);
void pf_usb_tool_status_text(char *out,size_t out_len);
uint8_t pf_usb_tool_ducky_led(void);
uint32_t pf_usb_tool_storage_activity_timeout_ms(void);
/* Runtime ATTACKMODE bridge. A mode is OFF=0, HID=1, STORAGE=2 or both=3.
 * Descriptor identity changes are applied only while physically disconnected. */
bool pf_usb_tool_apply_attackmode_profile(uint8_t mode,bool custom_identity,
    uint16_t vid,uint16_t pid,const char *manufacturer,const char *product,
    const char *serial);
uint16_t pf_usb_tool_current_vid(void);
uint16_t pf_usb_tool_current_pid(void);

#ifdef __cplusplus
}
#endif
