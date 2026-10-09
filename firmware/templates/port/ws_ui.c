/* SPDX-License-Identifier: AGPL-3.0-or-later
 * UI policy and touch geometry shared by the security state machines and LVGL.
 * Rendering is implemented in ws_lvgl.c. Authentication decisions stay here/
 * in ws_presence.c and ws_pinpad.c; LVGL is presentation-only.
 */
#include "ws_ui.h"

ws_root_page_t ws_ui_root_next(ws_root_page_t page,int direction,bool has_apps)
{
    if(!direction)return page;
    int next=(int)page+(direction>0?1:direction<0?-1:0);
    if(next==WS_ROOT_APPS && !has_apps) next+=direction>0?1:-1;
    if(next<WS_ROOT_SETTINGS) next=WS_ROOT_SETTINGS;
    if(next>WS_ROOT_SAVER) next=WS_ROOT_SAVER;
    return (ws_root_page_t)next;
}

uint8_t ws_ui_launcher_hit_test(uint16_t x,uint16_t y)
{
    if(x<8 || x>=272 || y<64 || y>=386) return 0;
    unsigned col=(x-8)/90,row=(y-64)/110;
    if(col>=3 || row>=3 || (x-8)%90>=84 || (y-64)%110>=102) return 0;
    return (uint8_t)(row*3+col+1);
}
#include "ws_ui_layout.h"

ws_action_t ws_ui_hit_test(uint16_t x,uint16_t y)
{
    if(x<WS_UP_X || x>=WS_UP_X+WS_UP_W) return WS_ACTION_NONE;
    if(y>=WS_APPROVE_Y && y<WS_APPROVE_Y+WS_APPROVE_H) return WS_ACTION_APPROVE;
    if(y>=WS_CANCEL_Y && y<WS_CANCEL_Y+WS_CANCEL_H) return WS_ACTION_CANCEL;
    return WS_ACTION_NONE;
}

ws_idle_action_t ws_ui_idle_hit_test(uint16_t x,uint16_t y)
{
    (void)x;(void)y;
    /* R15: the READY/STANDBY icon was removed.  Swipe-left is the only entry
     * gesture, matching the visual hint and avoiding an invisible tap target. */
    return WS_IDLE_ACTION_NONE;
}

static int row_index(uint16_t x,uint16_t y)
{
    if(x<WS_SETTINGS_ROW_X || x>=WS_SETTINGS_ROW_X+WS_SETTINGS_ROW_W) return -1;
    for(int row=0;row<2;++row) {
        unsigned ry=WS_SETTINGS_ROW_Y+(unsigned)row*WS_SETTINGS_ROW_DY;
        if(y>=ry && y<ry+WS_SETTINGS_ROW_H) return row;
    }
    return -1;
}

static bool in_control_band(uint16_t y,int row)
{
    unsigned ry=WS_SETTINGS_ROW_Y+(unsigned)row*WS_SETTINGS_ROW_DY;
    unsigned cy=ry+WS_SETTINGS_CONTROL_Y_IN_ROW;
    return y>=cy && y<cy+WS_SETTINGS_CONTROL_H;
}
static bool in_minus(uint16_t x)
{return x>=WS_SETTINGS_MINUS_X && x<WS_SETTINGS_MINUS_X+WS_SETTINGS_MINUS_W;}
static bool in_plus(uint16_t x)
{return x>=WS_SETTINGS_PLUS_X && x<WS_SETTINGS_PLUS_X+WS_SETTINGS_PLUS_W;}
static bool in_wide(uint16_t x)
{return x>=WS_SETTINGS_WIDE_X && x<WS_SETTINGS_WIDE_X+WS_SETTINGS_WIDE_W;}

ws_settings_action_t ws_ui_settings_hit_test(uint8_t page,uint16_t x,uint16_t y)
{
    if(page>=WS_SETTINGS_PAGE_COUNT || page==WS_SETTINGS_PAGE_HOME)
        return WS_SETTINGS_ACTION_NONE;
    if(page==WS_SETTINGS_PAGE_DIAGNOSTICS && x>=WS_DIAGNOSTICS_SAVE_X &&
       x<WS_DIAGNOSTICS_SAVE_X+WS_DIAGNOSTICS_SAVE_W && y>=WS_DIAGNOSTICS_SAVE_Y &&
       y<WS_DIAGNOSTICS_SAVE_Y+WS_DIAGNOSTICS_SAVE_H)return WS_SETTINGS_ACTION_DIAGNOSTICS_SAVE;
    int row=row_index(x,y);
    if(row<0 || !in_control_band(y,row)) return WS_SETTINGS_ACTION_NONE;

    switch((ws_settings_page_t)page) {
    case WS_SETTINGS_PAGE_DISPLAY:
        if(row==0) return in_minus(x)?WS_SETTINGS_ACTION_BRIGHTNESS_MINUS:
                         in_plus(x)?WS_SETTINGS_ACTION_BRIGHTNESS_PLUS:WS_SETTINGS_ACTION_NONE;
        return in_minus(x)?WS_SETTINGS_ACTION_DIM_BRIGHTNESS_MINUS:
               in_plus(x)?WS_SETTINGS_ACTION_DIM_BRIGHTNESS_PLUS:WS_SETTINGS_ACTION_NONE;
    case WS_SETTINGS_PAGE_APPEARANCE:
        if(row==0) return in_minus(x)?WS_SETTINGS_ACTION_ACCENT_PREV:
                         in_plus(x)?WS_SETTINGS_ACTION_ACCENT_NEXT:WS_SETTINGS_ACTION_NONE;
        return in_wide(x)?WS_SETTINGS_ACTION_ANIMATION_TOGGLE:WS_SETTINGS_ACTION_NONE;
    case WS_SETTINGS_PAGE_POWER:
        if(row==0) return in_minus(x)?WS_SETTINGS_ACTION_DIM_SECONDS_MINUS:
                         in_plus(x)?WS_SETTINGS_ACTION_DIM_SECONDS_PLUS:WS_SETTINGS_ACTION_NONE;
        return in_minus(x)?WS_SETTINGS_ACTION_OFF_SECONDS_MINUS:
               in_plus(x)?WS_SETTINGS_ACTION_OFF_SECONDS_PLUS:WS_SETTINGS_ACTION_NONE;
    case WS_SETTINGS_PAGE_AUTH:
        if(row==0) return in_minus(x)?WS_SETTINGS_ACTION_PRESENCE_SECONDS_MINUS:
                         in_plus(x)?WS_SETTINGS_ACTION_PRESENCE_SECONDS_PLUS:WS_SETTINGS_ACTION_NONE;
        return in_minus(x)?WS_SETTINGS_ACTION_UV_SECONDS_MINUS:
               in_plus(x)?WS_SETTINGS_ACTION_UV_SECONDS_PLUS:WS_SETTINGS_ACTION_NONE;
    case WS_SETTINGS_PAGE_USB:
        if(row==0) return in_wide(x)?WS_SETTINGS_ACTION_MANAGER_DRIVE_TOGGLE:WS_SETTINGS_ACTION_NONE;
        return in_wide(x)?WS_SETTINGS_ACTION_MANAGER_RO_TOGGLE:WS_SETTINGS_ACTION_NONE;
    case WS_SETTINGS_PAGE_USB_TOOL:
        if(row==0) return in_wide(x)?WS_SETTINGS_ACTION_USB_TOOL_TOGGLE:WS_SETTINGS_ACTION_NONE;
        return in_minus(x)?WS_SETTINGS_ACTION_USB_LAYOUT_PREV:
               in_plus(x)?WS_SETTINGS_ACTION_USB_LAYOUT_NEXT:WS_SETTINGS_ACTION_NONE;
    case WS_SETTINGS_PAGE_DIAGNOSTICS:
        return row==0 && in_wide(x)?WS_SETTINGS_ACTION_DIAGNOSTICS_TOGGLE:WS_SETTINGS_ACTION_NONE;
    case WS_SETTINGS_PAGE_AIR_MOUSE:
        return in_wide(x)?(row==0?WS_SETTINGS_ACTION_AIR_MOUSE_TRANSPORT:WS_SETTINGS_ACTION_AIR_MOUSE_START):WS_SETTINGS_ACTION_NONE;
    case WS_SETTINGS_PAGE_GAMEPAD:
        return in_wide(x)?(row==0?WS_SETTINGS_ACTION_GAMEPAD_PROFILE:WS_SETTINGS_ACTION_GAMEPAD_START):WS_SETTINGS_ACTION_NONE;
    case WS_SETTINGS_PAGE_HOME:
    case WS_SETTINGS_PAGE_COUNT:
    default:
        return WS_SETTINGS_ACTION_NONE;
    }
}

uint8_t ws_ui_air_mouse_hit_test(bool settings_open,uint16_t x,uint16_t y)
{
    if(settings_open) {
        if(x>=WS_MOUSE_CFG_BACK_X && x<WS_MOUSE_CFG_BACK_X+WS_MOUSE_CFG_BACK_W &&
           y>=WS_MOUSE_CFG_BACK_Y && y<WS_MOUSE_CFG_BACK_Y+WS_MOUSE_CFG_BACK_H)return 7U;
        if(x>=WS_MOUSE_CFG_CAL_X && x<WS_MOUSE_CFG_CAL_X+WS_MOUSE_CFG_CAL_W &&
           y>=WS_MOUSE_CFG_CAL_Y && y<WS_MOUSE_CFG_CAL_Y+WS_MOUSE_CFG_CAL_H)return 8U;
        if(x>=WS_MOUSE_CFG_MINUS_X && x<WS_MOUSE_CFG_MINUS_X+WS_MOUSE_CFG_MINUS_W &&
           y>=WS_MOUSE_CFG_MINUS_Y && y<WS_MOUSE_CFG_MINUS_Y+WS_MOUSE_CFG_MINUS_H)return 9U;
        if(x>=WS_MOUSE_CFG_PLUS_X && x<WS_MOUSE_CFG_PLUS_X+WS_MOUSE_CFG_PLUS_W &&
           y>=WS_MOUSE_CFG_PLUS_Y && y<WS_MOUSE_CFG_PLUS_Y+WS_MOUSE_CFG_PLUS_H)return 10U;
        if(x>=WS_MOUSE_CFG_INVERT_X && x<WS_MOUSE_CFG_INVERT_X+WS_MOUSE_CFG_INVERT_W &&
           y>=WS_MOUSE_CFG_INVERT_Y && y<WS_MOUSE_CFG_INVERT_Y+WS_MOUSE_CFG_INVERT_H)return 11U;
        return 0U;
    }
    if(x>=WS_MOUSE_EXIT_X && x<WS_MOUSE_EXIT_X+WS_MOUSE_EXIT_W &&
       y>=WS_MOUSE_EXIT_Y && y<WS_MOUSE_EXIT_Y+WS_MOUSE_EXIT_H)return 1U;
    if(x>=WS_MOUSE_CAL_X && x<WS_MOUSE_CAL_X+WS_MOUSE_CAL_W &&
       y>=WS_MOUSE_CAL_Y && y<WS_MOUSE_CAL_Y+WS_MOUSE_CAL_H)return 2U;
    if(x>=WS_MOUSE_LEFT_X && x<WS_MOUSE_LEFT_X+WS_MOUSE_LEFT_W &&
       y>=WS_MOUSE_LEFT_Y && y<WS_MOUSE_LEFT_Y+WS_MOUSE_LEFT_H)return y>=180U?16U:3U;
    if(x>=WS_MOUSE_RIGHT_X && x<WS_MOUSE_RIGHT_X+WS_MOUSE_RIGHT_W &&
       y>=WS_MOUSE_RIGHT_Y && y<WS_MOUSE_RIGHT_Y+WS_MOUSE_RIGHT_H)return 4U;
    if(x>=WS_MOUSE_SCROLL_X && x<WS_MOUSE_SCROLL_X+WS_MOUSE_SCROLL_W &&
       y>=WS_MOUSE_SCROLL_Y && y<WS_MOUSE_SCROLL_Y+WS_MOUSE_SCROLL_H)return 5U;
    if(x>=WS_MOUSE_MOVE_X && x<WS_MOUSE_MOVE_X+WS_MOUSE_MOVE_W &&
       y>=WS_MOUSE_MOVE_Y && y<WS_MOUSE_MOVE_Y+WS_MOUSE_MOVE_H)return 6U;
    return 0U;
}

ws_usb_tool_action_t ws_ui_usb_tool_hit_test(uint16_t x,uint16_t y)
{
    if(y<WS_USB_TOOL_BUTTON_Y || y>=WS_USB_TOOL_BUTTON_Y+WS_USB_TOOL_BUTTON_H)
        return WS_USB_TOOL_ACTION_NONE;
    if(x>=WS_USB_TOOL_PREV_X && x<WS_USB_TOOL_PREV_X+WS_USB_TOOL_PREV_W)
        return WS_USB_TOOL_ACTION_PREV;
    if(x>=WS_USB_TOOL_RUN_X && x<WS_USB_TOOL_RUN_X+WS_USB_TOOL_RUN_W)
        return WS_USB_TOOL_ACTION_RUN_STOP;
    if(x>=WS_USB_TOOL_NEXT_X && x<WS_USB_TOOL_NEXT_X+WS_USB_TOOL_NEXT_W)
        return WS_USB_TOOL_ACTION_NEXT;
    return WS_USB_TOOL_ACTION_NONE;
}

bool ws_ui_settings_allowed(ws_ui_state_t state)
{
    return state==WS_UI_DISCONNECTED || state==WS_UI_READY || state==WS_UI_SUSPENDED;
}

bool ws_ui_manager_drive_allowed(ws_ui_state_t state)
{
    return ws_ui_settings_allowed(state);
}
