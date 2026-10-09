/* SPDX-License-Identifier: AGPL-3.0-or-later */
#pragma once
#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>
#ifdef __cplusplus
extern "C" {
#endif
int pf_engine_start(void);
void pf_engine_usb_state(int state); /* 0 disconnected, 1 mounted, 2 suspended */
bool pf_arduino_usb_start(void);
bool pf_air_mouse_role(void);
bool pf_air_mouse_report(uint8_t buttons,int8_t x,int8_t y,int8_t wheel);
void pf_air_mouse_restart_into(void);
void pf_air_mouse_exit(void);
bool pf_manager_drive_take_eject(void); /* completed host eject; consume once */
bool pf_manager_drive_media_ready(void); /* microSD MSC media state */
void pf_manager_drive_apply_read_only(bool read_only); /* authenticated runtime write protection */
/* USB Tool runtime. These calls are inert unless the persistent boot role is USB Tool. */
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
uint8_t pf_usb_tool_ducky_led(void); /* 0 off, 1 red, 2 green */
bool pf_usb_tool_storage_present(void);
uint32_t pf_usb_tool_storage_activity_age_ms(void);
uint32_t pf_usb_tool_storage_activity_timeout_ms(void);
#define PF_USB_TOOL_AUTO_DETACH_UNARMED 0U
#define PF_USB_TOOL_AUTO_DETACH_WAIT_IDLE 1U
#define PF_USB_TOOL_AUTO_DETACH_WAIT_SYNC 2U
#define PF_USB_TOOL_AUTO_DETACH_READY 3U
void pf_usb_tool_storage_arm_auto_detach(void);
void pf_usb_tool_storage_cancel_auto_detach(void);
uint8_t pf_usb_tool_storage_auto_detach_state(uint32_t idle_ms);
uint32_t pf_usb_tool_storage_auto_detach_remaining_ms(uint32_t idle_ms);
bool pf_usb_tool_storage_host_write_seen(void);
bool pf_usb_tool_storage_claim_auto_detach(uint32_t idle_ms);
#ifdef __cplusplus
}
#endif
