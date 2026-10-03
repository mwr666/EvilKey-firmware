/* SPDX-License-Identifier: AGPL-3.0-or-later */
#pragma once
#include <stdbool.h>
#include <stdint.h>
#include "ws_presence.h"
#include "ws_controls.h"
#include "ws_ft3168_probe.h"

typedef enum {
    WS_UI_DISCONNECTED = 0, WS_UI_READY, WS_UI_PROCESSING,
    WS_UI_WAITING, WS_UI_CONFIRMED, WS_UI_CANCELLED,
    WS_UI_TIMEOUT, WS_UI_SUSPENDED, WS_UI_PIN, WS_UI_PIN_BAD, WS_UI_PIN_BLOCKED, WS_UI_INPUT_ERROR
} ws_ui_state_t;

/* Idle-state settings navigation is gesture-only in R15.  Keep the
 * idle action type for ABI/source compatibility, but there is no tappable
 * settings target on the idle screens. */
typedef enum {
    WS_IDLE_ACTION_NONE = 0,
    WS_IDLE_ACTION_SETTINGS = 1
} ws_idle_action_t;

typedef enum {
    WS_SETTINGS_PAGE_HOME = 0,
    WS_SETTINGS_PAGE_DISPLAY = 1,
    WS_SETTINGS_PAGE_APPEARANCE = 2,
    WS_SETTINGS_PAGE_POWER = 3,
    WS_SETTINGS_PAGE_AUTH = 4,
    WS_SETTINGS_PAGE_DIAGNOSTICS = 5,
    WS_SETTINGS_PAGE_GAMEPAD = 6,
    WS_SETTINGS_PAGE_AIR_MOUSE = 7,
    WS_SETTINGS_PAGE_USB = 8,
    WS_SETTINGS_PAGE_USB_TOOL = 9,
    WS_SETTINGS_PAGE_COUNT = 10
} ws_settings_page_t;

/* Presentation/control actions for the non-authentication Settings screen.
 * These actions never map to FIDO UP/UV decisions. */
typedef enum {
    WS_SETTINGS_ACTION_NONE = 0,
    WS_SETTINGS_ACTION_BACK,
    WS_SETTINGS_ACTION_TAB_DISPLAY,
    WS_SETTINGS_ACTION_TAB_TIMING,
    WS_SETTINGS_ACTION_BRIGHTNESS_MINUS,
    WS_SETTINGS_ACTION_BRIGHTNESS_PLUS,
    WS_SETTINGS_ACTION_DIM_BRIGHTNESS_MINUS,
    WS_SETTINGS_ACTION_DIM_BRIGHTNESS_PLUS,
    WS_SETTINGS_ACTION_ACCENT_PREV,
    WS_SETTINGS_ACTION_ACCENT_NEXT,
    WS_SETTINGS_ACTION_ANIMATION_TOGGLE,
    WS_SETTINGS_ACTION_DIM_SECONDS_MINUS,
    WS_SETTINGS_ACTION_DIM_SECONDS_PLUS,
    WS_SETTINGS_ACTION_OFF_SECONDS_MINUS,
    WS_SETTINGS_ACTION_OFF_SECONDS_PLUS,
    WS_SETTINGS_ACTION_PRESENCE_SECONDS_MINUS,
    WS_SETTINGS_ACTION_PRESENCE_SECONDS_PLUS,
    WS_SETTINGS_ACTION_UV_SECONDS_MINUS,
    WS_SETTINGS_ACTION_UV_SECONDS_PLUS,
    WS_SETTINGS_ACTION_MANAGER_DRIVE_TOGGLE,
    WS_SETTINGS_ACTION_MANAGER_RO_TOGGLE,
    WS_SETTINGS_ACTION_USB_TOOL_TOGGLE,
    WS_SETTINGS_ACTION_USB_LAYOUT_PREV,
    WS_SETTINGS_ACTION_USB_LAYOUT_NEXT,
    WS_SETTINGS_ACTION_DIAGNOSTICS_TOGGLE,
    WS_SETTINGS_ACTION_AIR_MOUSE_START,
    WS_SETTINGS_ACTION_AIR_MOUSE_TRANSPORT,
    WS_SETTINGS_ACTION_GAMEPAD_PROFILE,
    WS_SETTINGS_ACTION_GAMEPAD_START
} ws_settings_action_t;

typedef enum {
    WS_USB_TOOL_ACTION_NONE = 0,
    WS_USB_TOOL_ACTION_PREV = 1,
    WS_USB_TOOL_ACTION_RUN_STOP = 2,
    WS_USB_TOOL_ACTION_NEXT = 3
} ws_usb_tool_action_t;

typedef enum {
    WS_SETTINGS_FEEDBACK_NONE = 0,
    WS_SETTINGS_FEEDBACK_SAVED = 1,
    WS_SETTINGS_FEEDBACK_ERROR = 2,
    WS_SETTINGS_FEEDBACK_PIN_REQUIRED = 3,
    WS_SETTINGS_FEEDBACK_PIN_BAD = 4,
    WS_SETTINGS_FEEDBACK_PIN_BLOCKED = 5,
    WS_SETTINGS_FEEDBACK_PIN_CANCELLED = 6,
    WS_SETTINGS_FEEDBACK_PIN_TIMEOUT = 7
} ws_settings_feedback_t;

typedef enum {
    WS_PIN_PURPOSE_FIDO = 0,
    WS_PIN_PURPOSE_ENABLE_RW = 1
} ws_pin_purpose_t;

typedef struct {
    ws_ui_state_t state;
    uint32_t epoch;
    unsigned seconds_left;
    bool touch_enabled;
    bool touch_available;
    bool dim;
    bool screen_off; /* Display only: touch and FIDO stay running. */
    bool boot_allowed;
    unsigned pin_length;
    unsigned uv_retries;
    uint8_t pin_permissions;
    uint8_t pin_purpose;
    /* Visual feedback only; never used to grant UP/UV. No PIN plaintext. */
    uint8_t pressed_action;
    uint8_t animation_phase;
    uint8_t brightness, dim_brightness;
    uint32_t accent_rgb, settings_revision;

    /* R15 on-device Settings presentation state. A transition value of 0 means
     * idle screen, 255 means Settings fully visible.  settings_page_offset is
     * a presentation-only vertical slide of the newly selected settings page. */
    /* Full-screen logo screensaver is presentation-only and reachable from
     * idle states, including USB disconnected. Transition is 0..255; motion
     * uses a separate 1024-step loop so every ring closes without a jump. */
    uint8_t screensaver_transition;
    uint16_t screensaver_phase;
    /* R25: text fade starts when the saver is opened instead of following the
     * absolute orbit clock.  360 steps at 25 ms form one exact 9.000 s cycle:
     * 1 s fade-in, 5 s bright hold, 1 s fade-out, 2 s dark hold. */
    uint16_t screensaver_text_phase;
    bool screensaver_open;

    uint8_t settings_transition;
    /* R25: independent slow landing-page motion; do not reuse the ~62.5 Hz
     * main animation phase. All Settings sub-effects close on this same 256-step
     * cycle so the wrap from phase 255 to 0 cannot produce a visible jump. */
    uint8_t settings_motion_phase;
    uint8_t settings_page;
    int16_t settings_page_offset;
    uint8_t settings_pressed_action;
    uint8_t settings_feedback;
    /* Display-only diagnostics. Enabled in RAM, never saved to NVS. */
    bool diagnostics_enabled;
    uint32_t diagnostics_tick;
    uint32_t apps_mount_ms,apps_scan_ms,apps_icon_ms,apps_headers_read;
    uint32_t ui_poll_gap_ms,ui_render_ms;
    bool air_mouse_available;
    bool air_mouse_active;
    bool air_mouse_sensor_ok;
    bool air_mouse_calibrating;
    bool air_mouse_restarting;
    uint8_t air_mouse_buttons;
    uint8_t air_mouse_touch_zone;
    bool air_mouse_move_held;
    bool air_mouse_drag_latched;
    uint8_t air_mouse_hold_step;
    bool air_mouse_touch_fault;
    bool air_mouse_touch_outside;
    bool air_mouse_settings_open;
    uint8_t air_mouse_sensitivity; /* 1..5; 3 keeps the original cursor speed. */
    bool air_mouse_invert_y;
    WsControlPrefs controls;
    WsGamepad gamepad;
    bool gamepad_active,ble_connected,ble_ready,ble_failed;
    uint8_t air_mouse_ble_modal;
    /* Read-only touch diagnostics for physical BLE controls acceptance. */
    uint8_t controls_touch_count,controls_touch_raw,controls_touch_max;
    bool controls_touch_valid;
    WsFT3168Probe controls_touch_probe;
    WsFT3168FrameEvidence controls_touch_frame;
    bool settings_open;
    bool settings_storage_ok;
    bool settings_animation;
    uint16_t settings_dim_seconds;
    uint16_t settings_off_seconds;
    uint16_t settings_presence_seconds;
    uint16_t settings_uv_seconds;

    /* Manager Drive remains separate from FIDO credentials/PIN state. */
    bool manager_drive_available;
    bool manager_drive_enabled;
    bool manager_drive_media_ready;
    bool manager_drive_storage_ok;
    bool manager_drive_read_only;
    bool manager_drive_pressed;
    bool manager_drive_restarting;

    /* USB Tool is a mutually-exclusive boot role with explicit local launch. */
    bool usb_tool_available;
    bool usb_tool_enabled;
    bool usb_tool_storage_ok;
    bool usb_tool_media_ready;
    bool usb_tool_running;
    bool usb_tool_restarting;
    bool usb_tool_storage_active;
    uint8_t usb_tool_layout;
    uint8_t usb_tool_status;
    uint8_t usb_tool_ducky_led;
    uint8_t usb_tool_pressed_action;
    uint16_t usb_tool_script_count;
    uint16_t usb_tool_selected_index;
    uint32_t usb_tool_error_line;
    char usb_tool_script_name[80];
    char usb_tool_language_name[28];
    char usb_tool_status_text[64];
    /* Apps are presentation-only. They cannot authorize FIDO operations. */
    bool apps_ready,apps_mounted,apps_running,apps_exit_confirm,apps_exit_dragging;
    bool apps_scanning,apps_catalog_ready,apps_overflow;
    uint8_t launcher_transition,launcher_page,launcher_pressed; /* page 0: introduction; 1..8: grids */
    int16_t launcher_page_offset;
    uint16_t apps_icon_valid;
    uint32_t apps_catalog_generation;
    char apps_names[9][64];
    uint8_t apps_exit_pressed,apps_exit_progress;
    uint8_t apps_count,apps_selected;
    uint32_t apps_frame;
    char apps_id[32];
    char apps_status[80];
} ws_ui_snapshot_t;

typedef enum { WS_ROOT_SETTINGS=0, WS_ROOT_APPS, WS_ROOT_HOME, WS_ROOT_SAVER } ws_root_page_t;
/* Finger direction: +1 = swipe right, -1 = swipe left. Ends clamp. */
ws_root_page_t ws_ui_root_next(ws_root_page_t page,int direction,bool has_apps);
/* Slot 1..9; zero means outside. Shared with the drawing layout. */
uint8_t ws_ui_launcher_hit_test(uint16_t x,uint16_t y);

ws_action_t ws_ui_hit_test(uint16_t x, uint16_t y);
ws_idle_action_t ws_ui_idle_hit_test(uint16_t x, uint16_t y);
ws_settings_action_t ws_ui_settings_hit_test(uint8_t page,uint16_t x,uint16_t y);
ws_usb_tool_action_t ws_ui_usb_tool_hit_test(uint16_t x,uint16_t y);
uint8_t ws_ui_air_mouse_hit_test(bool settings_open,uint16_t x,uint16_t y);
bool ws_ui_settings_allowed(ws_ui_state_t state);
/* Compatibility alias retained for older internal checks. */
bool ws_ui_manager_drive_allowed(ws_ui_state_t state);
