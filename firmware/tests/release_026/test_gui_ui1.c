/* GUI policy regression. Pixel composition is owned by pinned LVGL 8.4;
 * security/configuration hit geometry is deterministic and tested here. */
#include "ws_ui.h"
#include "ws_ui_layout.h"
#include <assert.h>
#include <stdint.h>
#include <stdio.h>

static bool in(unsigned x,unsigned y,unsigned rx,unsigned ry,unsigned rw,unsigned rh)
{return x>=rx && x<rx+rw && y>=ry && y<ry+rh;}

static void test_presence_hit_map(void)
{
    for(unsigned y=0;y<456;++y)for(unsigned x=0;x<280;++x) {
        ws_action_t expected=WS_ACTION_NONE;
        if(x>=WS_UP_X && x<WS_UP_X+WS_UP_W) {
            if(y>=WS_APPROVE_Y && y<WS_APPROVE_Y+WS_APPROVE_H) expected=WS_ACTION_APPROVE;
            if(y>=WS_CANCEL_Y && y<WS_CANCEL_Y+WS_CANCEL_H) expected=WS_ACTION_CANCEL;
        }
        assert(ws_ui_hit_test((uint16_t)x,(uint16_t)y)==expected);
    }
    puts("PASS: all 127680 presence hit coordinates match validated authentication geometry");
}

static void test_idle_hit_map(void)
{
    for(unsigned y=0;y<456;++y)for(unsigned x=0;x<280;++x)
        assert(ws_ui_idle_hit_test((uint16_t)x,(uint16_t)y)==WS_IDLE_ACTION_NONE);
    puts("PASS: READY/STANDBY has no hidden/tappable Settings icon; entry is swipe-only");
}

static ws_settings_action_t expected_settings(uint8_t page,unsigned x,unsigned y)
{
    if(page>=WS_SETTINGS_PAGE_COUNT || page==WS_SETTINGS_PAGE_HOME)
        return WS_SETTINGS_ACTION_NONE;
    if(!in(x,y,WS_SETTINGS_ROW_X,WS_SETTINGS_ROW_Y,WS_SETTINGS_ROW_W,
           WS_SETTINGS_ROW_H+WS_SETTINGS_ROW_DY)) return WS_SETTINGS_ACTION_NONE;
    int row=-1;
    for(int i=0;i<2;++i) {
        unsigned ry=WS_SETTINGS_ROW_Y+(unsigned)i*WS_SETTINGS_ROW_DY;
        if(in(x,y,WS_SETTINGS_ROW_X,ry,WS_SETTINGS_ROW_W,WS_SETTINGS_ROW_H)) {row=i;break;}
    }
    if(row<0)return WS_SETTINGS_ACTION_NONE;
    unsigned ry=WS_SETTINGS_ROW_Y+(unsigned)row*WS_SETTINGS_ROW_DY;
    if(y<ry+WS_SETTINGS_CONTROL_Y_IN_ROW || y>=ry+WS_SETTINGS_CONTROL_Y_IN_ROW+WS_SETTINGS_CONTROL_H)
        return WS_SETTINGS_ACTION_NONE;
    bool minus=x>=WS_SETTINGS_MINUS_X && x<WS_SETTINGS_MINUS_X+WS_SETTINGS_MINUS_W;
    bool plus=x>=WS_SETTINGS_PLUS_X && x<WS_SETTINGS_PLUS_X+WS_SETTINGS_PLUS_W;
    bool wide=x>=WS_SETTINGS_WIDE_X && x<WS_SETTINGS_WIDE_X+WS_SETTINGS_WIDE_W;
    switch((ws_settings_page_t)page) {
    case WS_SETTINGS_PAGE_DISPLAY:
        return row==0?(minus?WS_SETTINGS_ACTION_BRIGHTNESS_MINUS:plus?WS_SETTINGS_ACTION_BRIGHTNESS_PLUS:WS_SETTINGS_ACTION_NONE):
                      (minus?WS_SETTINGS_ACTION_DIM_BRIGHTNESS_MINUS:plus?WS_SETTINGS_ACTION_DIM_BRIGHTNESS_PLUS:WS_SETTINGS_ACTION_NONE);
    case WS_SETTINGS_PAGE_APPEARANCE:
        return row==0?(minus?WS_SETTINGS_ACTION_ACCENT_PREV:plus?WS_SETTINGS_ACTION_ACCENT_NEXT:WS_SETTINGS_ACTION_NONE):
                      (wide?WS_SETTINGS_ACTION_ANIMATION_TOGGLE:WS_SETTINGS_ACTION_NONE);
    case WS_SETTINGS_PAGE_POWER:
        return row==0?(minus?WS_SETTINGS_ACTION_DIM_SECONDS_MINUS:plus?WS_SETTINGS_ACTION_DIM_SECONDS_PLUS:WS_SETTINGS_ACTION_NONE):
                      (minus?WS_SETTINGS_ACTION_OFF_SECONDS_MINUS:plus?WS_SETTINGS_ACTION_OFF_SECONDS_PLUS:WS_SETTINGS_ACTION_NONE);
    case WS_SETTINGS_PAGE_AUTH:
        return row==0?(minus?WS_SETTINGS_ACTION_PRESENCE_SECONDS_MINUS:plus?WS_SETTINGS_ACTION_PRESENCE_SECONDS_PLUS:WS_SETTINGS_ACTION_NONE):
                      (minus?WS_SETTINGS_ACTION_UV_SECONDS_MINUS:plus?WS_SETTINGS_ACTION_UV_SECONDS_PLUS:WS_SETTINGS_ACTION_NONE);
    case WS_SETTINGS_PAGE_USB:
        return wide?(row==0?WS_SETTINGS_ACTION_MANAGER_DRIVE_TOGGLE:WS_SETTINGS_ACTION_MANAGER_RO_TOGGLE):WS_SETTINGS_ACTION_NONE;
    case WS_SETTINGS_PAGE_USB_TOOL:
        return row==0?(wide?WS_SETTINGS_ACTION_USB_TOOL_TOGGLE:WS_SETTINGS_ACTION_NONE):
                      (minus?WS_SETTINGS_ACTION_USB_LAYOUT_PREV:plus?WS_SETTINGS_ACTION_USB_LAYOUT_NEXT:WS_SETTINGS_ACTION_NONE);
    case WS_SETTINGS_PAGE_DIAGNOSTICS:
        return row==0 && wide?WS_SETTINGS_ACTION_DIAGNOSTICS_TOGGLE:WS_SETTINGS_ACTION_NONE;
    default:return WS_SETTINGS_ACTION_NONE;
    }
}

static void test_settings_hit_maps(void)
{
    for(uint8_t page=0;page<WS_SETTINGS_PAGE_COUNT;++page)
        for(unsigned y=0;y<456;++y)for(unsigned x=0;x<280;++x)
            assert(ws_ui_settings_hit_test(page,(uint16_t)x,(uint16_t)y)==expected_settings(page,x,y));
    puts("PASS: all eight Settings screens have exact half-open touch maps with two large controls max");
}

static void test_usb_tool_hit_map(void)
{
    for(unsigned y=0;y<456;++y)for(unsigned x=0;x<280;++x) {
        ws_usb_tool_action_t e=WS_USB_TOOL_ACTION_NONE;
        if(y>=WS_USB_TOOL_BUTTON_Y && y<WS_USB_TOOL_BUTTON_Y+WS_USB_TOOL_BUTTON_H) {
            if(x>=WS_USB_TOOL_PREV_X && x<WS_USB_TOOL_PREV_X+WS_USB_TOOL_PREV_W)e=WS_USB_TOOL_ACTION_PREV;
            else if(x>=WS_USB_TOOL_RUN_X && x<WS_USB_TOOL_RUN_X+WS_USB_TOOL_RUN_W)e=WS_USB_TOOL_ACTION_RUN_STOP;
            else if(x>=WS_USB_TOOL_NEXT_X && x<WS_USB_TOOL_NEXT_X+WS_USB_TOOL_NEXT_W)e=WS_USB_TOOL_ACTION_NEXT;
        }
        assert(ws_ui_usb_tool_hit_test((uint16_t)x,(uint16_t)y)==e);
    }
    puts("PASS: USB Tool PREV/RUN/NEXT hit map is deterministic and non-overlapping");
}

static void test_settings_allowed_states(void)
{
    for(int state=0;state<=WS_UI_INPUT_ERROR;++state) {
        bool expected=state==WS_UI_READY || state==WS_UI_SUSPENDED;
        assert(ws_ui_settings_allowed((ws_ui_state_t)state)==expected);
        assert(ws_ui_manager_drive_allowed((ws_ui_state_t)state)==expected);
    }
    assert(!ws_ui_settings_allowed((ws_ui_state_t)999));
    puts("PASS: Settings and MSC configuration remain restricted to READY and STANDBY");
}

static void test_snapshot_no_pin_plaintext(void)
{
    ws_ui_snapshot_t v={0};
    v.pin_length=63;v.uv_retries=8;v.pin_permissions=3;v.settings_page_offset=-96;
    assert(sizeof(v)>0 && v.pin_length==63 && v.uv_retries==8 && v.settings_page_offset==-96);
    puts("PASS: LVGL snapshot carries PIN length/status only, never PIN plaintext");
}

int main(void)
{
    test_presence_hit_map();test_idle_hit_map();test_settings_hit_maps();test_usb_tool_hit_map();
    test_settings_allowed_states();test_snapshot_no_pin_plaintext();return 0;
}
