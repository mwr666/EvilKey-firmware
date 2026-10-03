#pragma once
#include "../../../EvilKeyV1/src/pf_engine_api.h"
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
bool pf_manager_drive_media_ready(void);
void pf_manager_drive_apply_read_only(bool read_only);

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
void pf_usb_tool_stop(void);
uint32_t pf_usb_tool_error_line(void);
void pf_usb_tool_status_text(char *out,size_t out_len);
