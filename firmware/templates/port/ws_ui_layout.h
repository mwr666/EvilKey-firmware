/* SPDX-License-Identifier: AGPL-3.0-or-later */
#pragma once
/* UI1: native 280 x 456; all hit rectangles are half-open. */
#define WS_UP_X 16
#define WS_UP_W 248
#define WS_APPROVE_Y 282
#define WS_APPROVE_H 70
#define WS_CANCEL_Y 364
#define WS_CANCEL_H 70
#define WS_KEY_X 8
#define WS_KEY_Y 132
#define WS_KEY_W 84
#define WS_KEY_H 60
#define WS_KEY_DX 90
#define WS_KEY_DY 66
#define WS_PIN_CANCEL_X 8
#define WS_PIN_CANCEL_Y 400
#define WS_PIN_CANCEL_W 264
#define WS_PIN_CANCEL_H 48

/* R15 Settings is entered only by swipe-left from READY/STANDBY.  The bottom
 * hint remains visual only; there is deliberately no idle-screen tap target. */

/* Each functional Settings page contains at most two generous controls. */
#define WS_SETTINGS_ROW_X 10
#define WS_SETTINGS_ROW_W 260
#define WS_SETTINGS_ROW_Y 128
#define WS_SETTINGS_ROW_H 112
#define WS_SETTINGS_ROW_DY 126

/* Large controls inside a settings row.  Absolute X coordinates are shared by
 * hit testing and the LVGL presentation layer. */
#define WS_SETTINGS_CONTROL_Y_IN_ROW 50
#define WS_SETTINGS_CONTROL_H 52
#define WS_SETTINGS_MINUS_X 20
#define WS_SETTINGS_MINUS_W 58
#define WS_SETTINGS_VALUE_X 88
#define WS_SETTINGS_VALUE_W 104
#define WS_SETTINGS_PLUS_X 202
#define WS_SETTINGS_PLUS_W 58
#define WS_SETTINGS_WIDE_X 20
#define WS_SETTINGS_WIDE_W 240

/* Gesture thresholds are deliberately larger than tap jitter. */
#define WS_SETTINGS_SWIPE_X 62
#define WS_SETTINGS_SWIPE_Y 48
#define WS_SETTINGS_TAP_SLOP 16

/* USB Tool local-execution controls. These exist only in the USB Tool boot
 * role and never overlap FIDO confirmation targets. */
#define WS_USB_TOOL_BUTTON_Y 326
#define WS_USB_TOOL_BUTTON_H 58
#define WS_USB_TOOL_PREV_X 12
#define WS_USB_TOOL_PREV_W 72
#define WS_USB_TOOL_RUN_X 94
#define WS_USB_TOOL_RUN_W 92
#define WS_USB_TOOL_NEXT_X 196
#define WS_USB_TOOL_NEXT_W 72

/* Air Mouse active surface; these zones do not overlap FIDO approval UI. */
#define WS_MOUSE_EXIT_X 144
#define WS_MOUSE_EXIT_Y 366
#define WS_MOUSE_EXIT_W 124
#define WS_MOUSE_EXIT_H 70
#define WS_MOUSE_CAL_X 12
#define WS_MOUSE_CAL_Y 366
#define WS_MOUSE_CAL_W 124
#define WS_MOUSE_CAL_H 70
#define WS_MOUSE_LEFT_X 12
#define WS_MOUSE_LEFT_Y 20
#define WS_MOUSE_LEFT_W 96
#define WS_MOUSE_LEFT_H 222
#define WS_MOUSE_RIGHT_X 172
#define WS_MOUSE_RIGHT_Y 20
#define WS_MOUSE_RIGHT_W 96
#define WS_MOUSE_RIGHT_H 222
#define WS_MOUSE_SCROLL_X 114
#define WS_MOUSE_SCROLL_Y 20
#define WS_MOUSE_SCROLL_W 52
#define WS_MOUSE_SCROLL_H 222
#define WS_MOUSE_MOVE_X 12
#define WS_MOUSE_MOVE_Y 252
#define WS_MOUSE_MOVE_W 256
#define WS_MOUSE_MOVE_H 102

/* Air Mouse settings surface (independent of the normal Settings carousel). */
#define WS_MOUSE_CFG_MINUS_X 28
#define WS_MOUSE_CFG_MINUS_Y 133
#define WS_MOUSE_CFG_MINUS_W 60
#define WS_MOUSE_CFG_MINUS_H 58
#define WS_MOUSE_CFG_PLUS_X 192
#define WS_MOUSE_CFG_PLUS_Y 133
#define WS_MOUSE_CFG_PLUS_W 60
#define WS_MOUSE_CFG_PLUS_H 58
#define WS_MOUSE_CFG_INVERT_X 20
#define WS_MOUSE_CFG_INVERT_Y 221
#define WS_MOUSE_CFG_INVERT_W 240
#define WS_MOUSE_CFG_INVERT_H 70
#define WS_MOUSE_CFG_CAL_X 20
#define WS_MOUSE_CFG_CAL_Y 310
#define WS_MOUSE_CFG_CAL_W 240
#define WS_MOUSE_CFG_CAL_H 70
#define WS_MOUSE_CFG_BACK_X 20
#define WS_MOUSE_CFG_BACK_Y 392
#define WS_MOUSE_CFG_BACK_W 240
#define WS_MOUSE_CFG_BACK_H 48
