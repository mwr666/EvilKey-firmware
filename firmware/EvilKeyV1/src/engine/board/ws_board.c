#include "../../pf_build_config.h"
/* SPDX-License-Identifier: AGPL-3.0-or-later */
#include "sdkconfig.h"
#include "ws_board.h"
#include "ws_gui_theme.h"
#include "ws_screen_power.h"
#include "ws_settings.h"
#include "../../pf_engine_api.h"
#include "esp_system.h"
#include "esp_heap_caps.h"
#include "../../apps/ek_render_parallel.h"
#ifndef FIDO_V1_MANAGER_DRIVE
#define FIDO_V1_MANAGER_DRIVE 0
#endif
#ifndef FIDO_V1_USB_TOOL
#define FIDO_V1_USB_TOOL 0
#endif
#if FIDO_V1_MANAGER_DRIVE
#include "ws_manager_drive_state.h"
#endif
#if FIDO_V1_USB_TOOL
#include "ws_usb_tool_state.h"
#endif
#pragma message ("PICO_FIDO_R27_HAK5_COMPAT: recursive payload library + Hak5 language JSON adapter")
#pragma message ("PICO_FIDO_R28_RAM_OPT: variable-length payload index; PSRAM preferred with heap fallback")
#pragma message ("PICO_FIDO_LVGL_R25_SETTINGS_LOOP_POLISH: seamless Settings loop + 5 s saver bright hold")
#pragma message ("PICO_FIDO_LVGL_R24_SAVER_FADE_SETTINGS_POLISH: static saver text fade + anchored slow Settings motion retained")
#pragma message ("PICO_FIDO_LVGL_R23_RENDER_POLISH: coherent saver + inset PIN ring retained")
#pragma message ("PICO_FIDO_LVGL_R22_MAX_FPS: async DMA + double-buffered LVGL")
#pragma message ("PICO_FIDO_LVGL_R21_AMOLED_PREMIUM_SCREENSAVER: native large-logo saver retained")
/* PICO_FIDO_LVGL_R16_RW_PIN_INIT_FIX retained: host-independent PIN binding. */
#include "ws_presence.h"
#include "ws_panel.h"
#include "ws_lvgl.h"
#include "ws_pins.h"
#include "ws_ui.h"
#include "ws_ui_layout.h"
#include "../../apps/ek_service.h"
#include "../../apps/ek_exit_dialog.h"
#include "ws_pinpad.h"
#include "ws_local_uv.h"
#include "ws_uv_retries.h"
#include "../sdk/src/led/led.h"
#include "driver/gpio.h"
#include "driver/i2c.h"
#include "esp_log.h"
#include "esp_timer.h"
#include "nvs.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include <string.h>
#include <stdio.h>
#include <math.h>

#if defined(CONFIG_SECURE_BOOT) || defined(CONFIG_SECURE_FLASH_ENC_ENABLED) || \
    defined(CONFIG_SECURE_SIGNED_APPS_NO_SECURE_BOOT) || defined(CONFIG_NVS_ENCRYPTION)
#error "This development port must not be built with provisioning/security options enabled"
#endif

static const char *TAG="ws_v1";
static portMUX_TYPE s_lock=portMUX_INITIALIZER_UNLOCKED;
static ws_ui_snapshot_t s_view;
static bool s_panel_ok;
static uint32_t s_displayed_epoch;
static bool s_touch_available;
static ws_contact_t s_touch;
typedef struct { uint16_t x,y; } ws_mouse_point_t;
static ws_mouse_point_t s_mouse_points[2];
static uint8_t s_mouse_point_count;
static EvilKeyAppTouch s_app_points[2];
static uint8_t s_app_point_count;
static bool s_apps_touch_mode;
static bool s_apps_sensor_ok;
static bool s_apps_sample_valid;
static uint32_t s_apps_imu_retry_at;
static uint32_t s_apps_imu_sample_at;
static unsigned s_apps_imu_errors;
static int32_t s_apps_ax_mg,s_apps_ay_mg,s_apps_az_mg;
static uint32_t s_touch_polled;
static unsigned s_touch_errors;
static uint32_t s_air_mouse_touch_retry_at;
static ws_presence_t s_presence;
static uint32_t s_epoch;
static bool s_pending;
static ws_ui_state_t s_last_result=WS_UI_DISCONNECTED;
static bool s_show_result;
static uint32_t s_result_at;
static ws_screen_power_t s_screen;
static bool s_display_bright; /* Published only after successful panel I/O. */
static bool s_initialized;
/* PIN input state is protected by s_lock. Core0 owns I2C. The FIDO worker
 * requests/consumes input, and the display task sees only the masked length. */
static ws_pinpad_t s_pinpad;
static bool s_pin_active;
static uint32_t s_pin_epoch;
static unsigned s_pin_retries;
static uint8_t s_pin_permissions;
typedef enum {
    WS_PIN_OWNER_NONE = 0,
    WS_PIN_OWNER_FIDO = 1,
    WS_PIN_OWNER_SETTINGS_RW = 2
} ws_pin_owner_t;
static ws_pin_owner_t s_pin_owner;
static bool s_feedback_pending;
static int s_feedback_error;
static uint16_t s_touch_x,s_touch_y;
/* R21 idle navigation. Ordinary settings remain configuration-only.
 * READY/STANDBY uses swipe-left for Settings and swipe-right for the premium
 * logo screensaver. Both surfaces are presentation-only. The READ ONLY ->
 * READ/WRITE transition may temporarily borrow the existing PIN pad, but never
 * the FIDO presence state or a FIDO UV/token session. */
static bool s_settings_open;
static ws_root_page_t s_root_page=WS_ROOT_HOME;
static bool s_launcher_open;
static uint8_t s_launcher_transition,s_launcher_from,s_launcher_to,s_launcher_page;
static bool s_launcher_intro=true;
static int8_t s_launcher_page_direction;
static uint32_t s_launcher_at,s_launcher_page_at;
static int16_t s_launcher_page_offset,s_launcher_page_from;
static bool s_settings_touch_was_down;
static EkExitDialog s_app_exit_dialog;
static uint8_t s_settings_page;
static uint8_t s_settings_transition;
static uint8_t s_settings_transition_from;
static uint8_t s_settings_transition_to;
static uint8_t s_settings_touch_action;
static uint8_t s_settings_feedback;
static bool s_diagnostics_enabled;
static uint32_t s_poll_at,s_poll_gap_max,s_render_ms_max;
static bool s_air_mouse_role;
static bool s_gamepad_role;
static WsControlPrefs s_controls;
static WsGamepad s_gamepad;
static WsControlPoint s_pad_points[2];
static uint8_t s_pad_count;
static uint8_t s_controls_touch_raw,s_controls_touch_max;
static WsFT3168Probe s_controls_touch_probe;
static WsFT3168FrameEvidence s_controls_touch_frame;
static WsPadReport s_pad_sent;
static bool s_pad_connected;
static uint32_t s_pad_imu_at;
static WsMouseLatch s_mouse_latch;
static PfControlMode s_control_requested;
static bool s_air_mouse_sensor_ok;
static bool s_air_mouse_restart_pending;
static uint32_t s_air_mouse_restart_at;
static uint32_t s_air_mouse_sampled_at;
static uint32_t s_air_mouse_action_hold_at;
static uint8_t s_air_mouse_action_hold_zone;
static bool s_air_mouse_action_hold_fired;
static uint8_t s_air_mouse_touch_zone;
static uint8_t s_air_mouse_sent_buttons;
static int16_t s_air_mouse_scroll_last_y;
static int16_t s_air_mouse_scroll_accum;
static unsigned s_air_mouse_errors;
static unsigned s_air_mouse_cal_samples;
static float s_air_mouse_gravity_x,s_air_mouse_gravity_y,s_air_mouse_gravity_z;
static float s_air_mouse_neutral_sum_x,s_air_mouse_neutral_sum_y,s_air_mouse_neutral_sum_z;
static float s_air_mouse_neutral_x,s_air_mouse_neutral_y,s_air_mouse_neutral_z;
static float s_air_mouse_right_x,s_air_mouse_right_y,s_air_mouse_right_z;
static float s_air_mouse_down_x,s_air_mouse_down_y,s_air_mouse_down_z;
static bool s_air_mouse_gravity_valid,s_air_mouse_neutral_valid;
static float s_air_mouse_fraction_x,s_air_mouse_fraction_y;
static bool s_air_mouse_settings_open,s_air_mouse_ui_touch_armed;
static uint8_t s_mouse_ble_modal;
static bool s_mouse_ble_connected;
static uint32_t s_control_boot_hold;
static uint8_t s_air_mouse_sensitivity=3U;
static bool s_air_mouse_invert_y;
static int16_t s_settings_page_offset;
static int16_t s_settings_page_offset_from;
static uint16_t s_settings_start_x,s_settings_start_y;
static uint16_t s_settings_last_x,s_settings_last_y;
static uint32_t s_settings_transition_at,s_settings_page_transition_at,s_settings_feedback_at;
static uint32_t s_settings_opened_at;
static uint32_t s_usb_tool_hold_started_at;
static bool s_usb_tool_hold_fired;
/* R21 screensaver owns no authentication state. It only tracks a slide value
 * and is evicted immediately when the device leaves READY/STANDBY. */
static bool s_screensaver_open;
static uint8_t s_screensaver_transition;
static uint8_t s_screensaver_transition_from;
static uint8_t s_screensaver_transition_to;
static uint32_t s_screensaver_transition_at;
static uint32_t s_screensaver_opened_at;
static bool s_manager_restart_pending;
static bool s_usb_tool_restart_pending;
#if FIDO_V1_MANAGER_DRIVE || FIDO_V1_USB_TOOL
static uint32_t s_usb_role_restart_at;
#endif


static uint32_t now_ms(void)
{
    return (uint32_t)(esp_timer_get_time()/1000);
}

#define WS_SETTINGS_TRANSITION_MS 230U
#define WS_SCREENSAVER_TRANSITION_MS 260U
#define WS_SETTINGS_PAGE_TRANSITION_MS 165U
#define WS_SETTINGS_PAGE_SLIDE_PX 56
#define WS_SETTINGS_FEEDBACK_MS 1100U

static unsigned coord_delta(uint16_t a,uint16_t b)
{
    return a>b?(unsigned)(a-b):(unsigned)(b-a);
}

static uint8_t ease_out_u8(uint8_t p)
{
    /* Cubic ease-out in fixed point: 1-(1-p)^3. */
    uint32_t q=255U-p;
    uint32_t q3=q*q*q;
    uint32_t remain=(q3+32512U)/65025U;
    return (uint8_t)(255U-(remain>255U?255U:remain));
}

static void settings_transition_begin(bool open,uint32_t now,bool animate)
{
    uint8_t target=open?255U:0U;
    s_settings_open=open;
    if(open) s_root_page=WS_ROOT_SETTINGS;
    if(open) s_settings_opened_at=now;
    s_settings_touch_was_down=false;
    s_settings_touch_action=0;
    if(open && s_settings_transition==0U) { s_settings_page=WS_SETTINGS_PAGE_HOME; s_settings_page_offset=0; }
    if(!animate) {
        s_settings_transition=target;
        s_settings_transition_from=target;
        s_settings_transition_to=target;
        return;
    }
    s_settings_transition_from=s_settings_transition;
    s_settings_transition_to=target;
    s_settings_transition_at=now;
}

static void settings_transition_tick(uint32_t now)
{
    if(s_settings_transition==s_settings_transition_to)return;
    uint32_t elapsed=(uint32_t)(now-s_settings_transition_at);
    if(elapsed>=WS_SETTINGS_TRANSITION_MS) {
        s_settings_transition=s_settings_transition_to;
        return;
    }
    uint8_t p=(uint8_t)((elapsed*255U)/WS_SETTINGS_TRANSITION_MS);
    uint8_t e=ease_out_u8(p);
    int from=s_settings_transition_from,to=s_settings_transition_to;
    int value=from+((to-from)*(int)e)/255;
    if(value<0)value=0;if(value>255)value=255;
    s_settings_transition=(uint8_t)value;
}

static void screensaver_transition_begin(bool open,uint32_t now,bool animate)
{
    uint8_t target=open?255U:0U;
    s_screensaver_open=open;
    if(open) s_root_page=WS_ROOT_SAVER;
    if(open) s_screensaver_opened_at=now;
    s_settings_touch_was_down=false;
    s_settings_touch_action=0U;
    if(!animate) {
        s_screensaver_transition=target;
        s_screensaver_transition_from=target;
        s_screensaver_transition_to=target;
        return;
    }
    s_screensaver_transition_from=s_screensaver_transition;
    s_screensaver_transition_to=target;
    s_screensaver_transition_at=now;
}

static void screensaver_transition_tick(uint32_t now)
{
    if(s_screensaver_transition==s_screensaver_transition_to)return;
    uint32_t elapsed=(uint32_t)(now-s_screensaver_transition_at);
    if(elapsed>=WS_SCREENSAVER_TRANSITION_MS) {
        s_screensaver_transition=s_screensaver_transition_to;
        return;
    }
    uint8_t p=(uint8_t)((elapsed*255U)/WS_SCREENSAVER_TRANSITION_MS);
    uint8_t e=ease_out_u8(p);
    int from=s_screensaver_transition_from,to=s_screensaver_transition_to;
    int value=from+((to-from)*(int)e)/255;
    if(value<0)value=0;if(value>255)value=255;
    s_screensaver_transition=(uint8_t)value;
}

static void launcher_transition_begin(bool open,uint32_t now,bool animate)
{
    s_launcher_open=open;s_launcher_from=s_launcher_transition;
    s_launcher_to=open?255U:0U;s_launcher_at=now;
    if(!animate) s_launcher_transition=s_launcher_to;
    s_settings_touch_was_down=false;s_settings_touch_action=0;
}
static void launcher_transition_tick(uint32_t now)
{
    uint32_t elapsed=(uint32_t)(now-s_launcher_at);
    if(elapsed>=WS_SETTINGS_TRANSITION_MS) s_launcher_transition=s_launcher_to;
    else {
        unsigned p=elapsed*255U/WS_SETTINGS_TRANSITION_MS;
        int e=ease_out_u8((uint8_t)p);
        s_launcher_transition=(uint8_t)(s_launcher_from+
            ((int)s_launcher_to-(int)s_launcher_from)*e/255);
    }
    elapsed=(uint32_t)(now-s_launcher_page_at);
    if(elapsed>=WS_SETTINGS_PAGE_TRANSITION_MS) s_launcher_page_offset=0;
    else s_launcher_page_offset=(int16_t)(s_launcher_page_from*
        (255-(int)ease_out_u8((uint8_t)(elapsed*255U/WS_SETTINGS_PAGE_TRANSITION_MS)))/255);
}
static void root_navigate(int direction,bool has_apps,uint32_t now,bool animate)
{
    ws_root_page_t next=ws_ui_root_next(s_root_page,direction,has_apps);
    if(next==s_root_page) return;
    if(next==WS_ROOT_APPS) {
        s_launcher_intro=true;
        s_launcher_page_direction=0;
        ek_apps_select_page(0);
    }
    launcher_transition_begin(next==WS_ROOT_APPS,now,animate);
    settings_transition_begin(next==WS_ROOT_SETTINGS,now,animate);
    screensaver_transition_begin(next==WS_ROOT_SAVER,now,true);
    s_root_page=next;
}

static void settings_page_change(uint8_t next,int direction,uint32_t now,bool animate)
{
    if(next>=WS_SETTINGS_PAGE_COUNT) next=WS_SETTINGS_PAGE_HOME;
    s_settings_page=next;
    s_settings_touch_was_down=false;
    s_settings_touch_action=0;
    if(!animate) {
        s_settings_page_offset=0;
        s_settings_page_offset_from=0;
        return;
    }
    /* R19: keep page motion deliberately short.  The 56 px travel reads as
     * hierarchy rather than a carousel and reduces the dirty rectangle on
     * every intermediate frame. */
    s_settings_page_offset_from=(int16_t)(direction>0?WS_SETTINGS_PAGE_SLIDE_PX:-WS_SETTINGS_PAGE_SLIDE_PX);
    s_settings_page_offset=s_settings_page_offset_from;
    s_settings_page_transition_at=now;
}

static void settings_page_tick(uint32_t now)
{
    if(s_settings_page_offset==0)return;
    uint32_t elapsed=(uint32_t)(now-s_settings_page_transition_at);
    if(elapsed>=WS_SETTINGS_PAGE_TRANSITION_MS) {
        s_settings_page_offset=0;
        return;
    }
    uint8_t p=(uint8_t)((elapsed*255U)/WS_SETTINGS_PAGE_TRANSITION_MS);
    uint8_t e=ease_out_u8(p);
    int value=((int)s_settings_page_offset_from*(255-(int)e))/255;
    s_settings_page_offset=(int16_t)value;
}

static void settings_force_closed(void)
{
    s_settings_open=false;
    s_settings_transition=0;
    s_settings_transition_from=0;
    s_settings_transition_to=0;
    s_settings_page_offset=0;
    s_settings_page_offset_from=0;
    s_settings_touch_was_down=false;
    s_settings_touch_action=0;
}

static void screensaver_force_closed(void)
{
    s_screensaver_open=false;
    s_screensaver_transition=0U;
    s_screensaver_transition_from=0U;
    s_screensaver_transition_to=0U;
    s_settings_touch_was_down=false;
    s_settings_touch_action=0U;
}

static void settings_feedback(uint8_t value,uint32_t now)
{
    s_settings_feedback=value;
    s_settings_feedback_at=now;
}

static bool settings_commit(ws_settings_t *next,uint32_t now)
{
    uint8_t wire[WS_SETTINGS_WIRE_SIZE];
    ws_settings_encode(next,wire);
    ws_settings_result_t r=ws_settings_apply(wire,sizeof(wire));
    settings_feedback(r==WS_SETTINGS_OK?WS_SETTINGS_FEEDBACK_SAVED:
                      WS_SETTINGS_FEEDBACK_ERROR,now);
    return r==WS_SETTINGS_OK;
}

static uint16_t step_value(uint16_t current,const uint16_t *values,unsigned count,int direction)
{
    if(!values || !count)return current;
    if(direction>0) {
        for(unsigned i=0;i<count;++i)if(values[i]>current)return values[i];
        return values[count-1U];
    }
    for(unsigned i=count;i>0;--i)if(values[i-1U]<current)return values[i-1U];
    return values[0];
}

static uint32_t accent_step(uint32_t current,int direction)
{
    static const uint32_t palette[]={
        0x4DE3C1U,0x70B8FFU,0xB38CFFU,0xFF8ED4U,
        0xFFB86BU,0xF6E36BU,0x7DEB74U,0x8BE8FFU
    };
    unsigned best=0;uint32_t best_d=UINT32_MAX;
    unsigned cr=(current>>16)&255U,cg=(current>>8)&255U,cb=current&255U;
    for(unsigned i=0;i<sizeof(palette)/sizeof(palette[0]);++i) {
        unsigned pr=(palette[i]>>16)&255U,pg=(palette[i]>>8)&255U,pb=palette[i]&255U;
        int dr=(int)pr-(int)cr,dg=(int)pg-(int)cg,db=(int)pb-(int)cb;
        uint32_t d=(uint32_t)(dr*dr+dg*dg+db*db);
        if(d<best_d){best_d=d;best=i;}
    }
    unsigned n=(unsigned)(sizeof(palette)/sizeof(palette[0]));
    best=direction>0?(best+1U)%n:(best+n-1U)%n;
    return palette[best];
}

static bool settings_begin_rw_pin(const ws_settings_t *settings,uint32_t now)
{
#if !FIDO_V1_MANAGER_DRIVE
    (void)settings;(void)now;
    settings_feedback(WS_SETTINGS_FEEDBACK_ERROR,now);
    return false;
#else
    /* R13_RW_PIN_GATE: only READ ONLY -> READ/WRITE requires local FIDO PIN. */
    if(!pf_local_uv_ready()) {
        settings_feedback(WS_SETTINGS_FEEDBACK_PIN_REQUIRED,now);
        return false;
    }
    int retries=ws_uv_retries_get();
    if(retries<0) {
        settings_feedback(WS_SETTINGS_FEEDBACK_ERROR,now);
        return false;
    }
    if(retries==0) {
        settings_feedback(WS_SETTINGS_FEEDBACK_PIN_BLOCKED,now);
        return false;
    }
    bool started=false;
    portENTER_CRITICAL(&s_lock);
    if(s_initialized && s_panel_ok && s_touch_available && !s_pending && !s_pin_active) {
        /* R18_SETTINGS_PIN_CANCEL_FIX: cancel_button is a level flag owned by
         * the CTAP/transport path. It can legitimately remain true after an
         * earlier CTAPHID_CANCEL or USB suspend/disconnect even though no FIDO
         * transaction is active anymore. Standard CBOR clears it when a new
         * request starts. A Settings-owned PIN is also a new, independent
         * request, so discard only that stale level here. Any later physical
         * USB abort still calls ws_board_pin_abort(), and a fresh FIDO PIN
         * continues to observe cancel_button normally. */
        cancel_button=false;
        ws_pinpad_begin(&s_pinpad,now,(uint32_t)settings->uv_seconds*1000U);
        s_pin_epoch=(s_pin_epoch+1U)|0x80000000U;
        s_pin_retries=(unsigned)retries;
        s_pin_permissions=0;
        s_pin_owner=WS_PIN_OWNER_SETTINGS_RW;
        s_displayed_epoch=0;
        s_pin_active=true;
        started=true;
    }
    portEXIT_CRITICAL(&s_lock);
    if(started) {
        /* Settings itself is hidden while the modal PIN screen is active. */
        settings_force_closed();
        ws_screen_power_wake(&s_screen,now);
    } else {
        settings_feedback(WS_SETTINGS_FEEDBACK_ERROR,now);
    }
    return started;
#endif
}

static uint8_t settings_rw_pin_feedback(int result)
{
    if(result==0) return WS_SETTINGS_FEEDBACK_SAVED;
    if(result==0x3f) return WS_SETTINGS_FEEDBACK_PIN_BAD;       /* CTAP2_ERR_UV_INVALID */
    if(result==0x3c || result==0x32) return WS_SETTINGS_FEEDBACK_PIN_BLOCKED;
    if(result==0x2d || result==0x27) return WS_SETTINGS_FEEDBACK_PIN_CANCELLED;
    if(result==0x2f) return WS_SETTINGS_FEEDBACK_PIN_TIMEOUT;
    if(result==0x30) return WS_SETTINGS_FEEDBACK_PIN_REQUIRED;  /* CTAP2_ERR_NOT_ALLOWED */
    return WS_SETTINGS_FEEDBACK_ERROR;
}

static void settings_finish_rw_pin(ws_pin_status_t status,const char *pin,size_t pin_len,
                                   const ws_settings_t *settings,ws_ui_snapshot_t *v,uint32_t now)
{
#if FIDO_V1_MANAGER_DRIVE
    int result=0x7f;
    if(status==WS_PIN_SUBMITTED) {
        result=pf_local_uv_verify_supplied_pin(pin,pin_len);
        if(result==0) {
            /* The write-enable bit is committed only after a fresh correct PIN. */
            if(ws_manager_drive_read_only() && ws_manager_drive_set_read_only(false)) {
                pf_manager_drive_apply_read_only(false);
                v->manager_drive_read_only=false;
            } else if(ws_manager_drive_read_only()) {
                result=0x7f;
                v->manager_drive_storage_ok=false;
            }
        }
    } else if(status==WS_PIN_CANCELLED) {
        result=0x2d;
    } else if(status==WS_PIN_TIMEOUT) {
        result=0x2f;
    }
    settings_feedback(settings_rw_pin_feedback(result),now);
    /* Return specifically to TIMING + USB. A failed/cancelled PIN never changes
     * READ ONLY, and a successful check leaves no FIDO UV/token session alive. */
    settings_transition_begin(true,now,settings->animation);
    s_settings_page=WS_SETTINGS_PAGE_USB;
#else
    (void)status;(void)pin;(void)pin_len;(void)settings;(void)v;
    settings_feedback(WS_SETTINGS_FEEDBACK_ERROR,now);
#endif
}

static bool settings_apply_action(ws_settings_action_t action,ws_settings_t *settings,
                                  ws_ui_snapshot_t *v,uint32_t now)
{
    (void)v; /* Used by the Manager Drive branch when compiled in. */
    static const uint16_t idle_steps[]={0,5,10,15,30,45,60,90,120,180,300,600,900,1800,3600};
    static const uint16_t presence_steps[]={1,5,10,15,20,30,45,60,90,120};
    static const uint16_t uv_steps[]={15,30,45,60,90,120};
    ws_settings_t next=*settings;
    bool changed=false;
    switch(action) {
    case WS_SETTINGS_ACTION_BACK:
        settings_transition_begin(false,now,settings->animation);s_root_page=WS_ROOT_HOME;return false;
    case WS_SETTINGS_ACTION_TAB_DISPLAY:
    case WS_SETTINGS_ACTION_TAB_TIMING:
        return false;
    case WS_SETTINGS_ACTION_DIAGNOSTICS_TOGGLE:
        /* Presentation telemetry only. No NVS write, USB role change or
         * security-state transition is attached to this control. */
        s_diagnostics_enabled=!s_diagnostics_enabled;
        s_poll_gap_max=0;
        portENTER_CRITICAL(&s_lock);s_render_ms_max=0;portEXIT_CRITICAL(&s_lock);
        v->diagnostics_enabled=s_diagnostics_enabled;
        ws_screen_power_wake(&s_screen,now);
        return false;
    case WS_SETTINGS_ACTION_DIAGNOSTICS_SAVE:
        ek_apps_diagnostics_export_request();
        ws_screen_power_wake(&s_screen,now);
        return false;
    case WS_SETTINGS_ACTION_AIR_MOUSE_TRANSPORT:
    case WS_SETTINGS_ACTION_GAMEPAD_PROFILE: {
        WsControlPrefs next=s_controls;
        if(action==WS_SETTINGS_ACTION_AIR_MOUSE_TRANSPORT)next.transport^=1;
        else next.profile^=1;
        if(pf_controls_save(&next)){s_controls=next;settings_feedback(WS_SETTINGS_FEEDBACK_SAVED,now);}
        else settings_feedback(WS_SETTINGS_FEEDBACK_ERROR,now);
        return false;
    }
    case WS_SETTINGS_ACTION_GAMEPAD_START:
    case WS_SETTINGS_ACTION_AIR_MOUSE_START:
        if((action==WS_SETTINGS_ACTION_GAMEPAD_START || s_air_mouse_sensor_ok) && s_touch_available && !s_air_mouse_restart_pending &&
           !s_manager_restart_pending && !s_usb_tool_restart_pending &&
           !ws_usb_tool_enabled() && !ws_manager_drive_enabled()) {
            s_air_mouse_restart_pending=true;
            s_control_requested=action==WS_SETTINGS_ACTION_GAMEPAD_START?PF_CONTROL_BLE_PAD:
                s_controls.transport?PF_CONTROL_BLE_MOUSE:PF_CONTROL_USB_MOUSE;
            s_air_mouse_restart_at=now;
            settings_feedback(WS_SETTINGS_FEEDBACK_SAVED,now);
            ws_screen_power_wake(&s_screen,now);
            ESP_LOGI(TAG,"Control role requested: %u",(unsigned)s_control_requested);
        } else settings_feedback(WS_SETTINGS_FEEDBACK_ERROR,now);
        return false;
    case WS_SETTINGS_ACTION_BRIGHTNESS_MINUS:
        next.brightness=(uint8_t)(next.brightness<=20U?8U:next.brightness-13U);
        if(next.dim_brightness>next.brightness)next.dim_brightness=next.brightness;
        changed=true;break;
    case WS_SETTINGS_ACTION_BRIGHTNESS_PLUS:
        next.brightness=(uint8_t)(next.brightness>=242U?255U:next.brightness+13U);
        changed=true;break;
    case WS_SETTINGS_ACTION_DIM_BRIGHTNESS_MINUS:
        next.dim_brightness=(uint8_t)(next.dim_brightness<=2U?1U:next.dim_brightness-2U);
        changed=true;break;
    case WS_SETTINGS_ACTION_DIM_BRIGHTNESS_PLUS: {
        uint8_t hi=next.brightness<32U?next.brightness:32U;
        next.dim_brightness=(uint8_t)(next.dim_brightness+2U>hi?hi:next.dim_brightness+2U);
        changed=true;break;
    }
    case WS_SETTINGS_ACTION_ACCENT_PREV:next.accent_rgb=accent_step(next.accent_rgb,-1);changed=true;break;
    case WS_SETTINGS_ACTION_ACCENT_NEXT:next.accent_rgb=accent_step(next.accent_rgb,1);changed=true;break;
    case WS_SETTINGS_ACTION_ANIMATION_TOGGLE:next.animation=!next.animation;changed=true;break;
    case WS_SETTINGS_ACTION_DIM_SECONDS_MINUS:next.dim_seconds=step_value(next.dim_seconds,idle_steps,sizeof(idle_steps)/sizeof(idle_steps[0]),-1);changed=true;break;
    case WS_SETTINGS_ACTION_DIM_SECONDS_PLUS:next.dim_seconds=step_value(next.dim_seconds,idle_steps,sizeof(idle_steps)/sizeof(idle_steps[0]),1);changed=true;break;
    case WS_SETTINGS_ACTION_OFF_SECONDS_MINUS:next.off_seconds=step_value(next.off_seconds,idle_steps,sizeof(idle_steps)/sizeof(idle_steps[0]),-1);changed=true;break;
    case WS_SETTINGS_ACTION_OFF_SECONDS_PLUS:next.off_seconds=step_value(next.off_seconds,idle_steps,sizeof(idle_steps)/sizeof(idle_steps[0]),1);changed=true;break;
    case WS_SETTINGS_ACTION_PRESENCE_SECONDS_MINUS:next.presence_seconds=step_value(next.presence_seconds,presence_steps,sizeof(presence_steps)/sizeof(presence_steps[0]),-1);changed=true;break;
    case WS_SETTINGS_ACTION_PRESENCE_SECONDS_PLUS:next.presence_seconds=step_value(next.presence_seconds,presence_steps,sizeof(presence_steps)/sizeof(presence_steps[0]),1);changed=true;break;
    case WS_SETTINGS_ACTION_UV_SECONDS_MINUS:next.uv_seconds=step_value(next.uv_seconds,uv_steps,sizeof(uv_steps)/sizeof(uv_steps[0]),-1);changed=true;break;
    case WS_SETTINGS_ACTION_UV_SECONDS_PLUS:next.uv_seconds=step_value(next.uv_seconds,uv_steps,sizeof(uv_steps)/sizeof(uv_steps[0]),1);changed=true;break;
    case WS_SETTINGS_ACTION_MANAGER_DRIVE_TOGGLE:
#if FIDO_V1_MANAGER_DRIVE
        if(!s_manager_restart_pending && !s_usb_tool_restart_pending) {
            bool target=!ws_manager_drive_enabled();
            bool role_ok=true;
#if FIDO_V1_USB_TOOL
            if(target && ws_usb_tool_enabled()) role_ok=ws_usb_tool_set_enabled(false);
#endif
            if(role_ok && ws_manager_drive_set_enabled(target)) {
                v->manager_drive_enabled=target;
                v->manager_drive_media_ready=false;
                s_manager_restart_pending=true;
                s_usb_tool_restart_pending=false;
                s_usb_role_restart_at=now;
                settings_feedback(WS_SETTINGS_FEEDBACK_SAVED,now);
                ws_screen_power_wake(&s_screen,now);
                ESP_LOGI(TAG,"Manager Drive %s from Settings; restarting USB descriptors",
                         target?"enabled":"disabled");
            } else {
                v->manager_drive_storage_ok=false;
                settings_feedback(WS_SETTINGS_FEEDBACK_ERROR,now);
            }
        }
#else
        settings_feedback(WS_SETTINGS_FEEDBACK_ERROR,now);
#endif
        return false;
    case WS_SETTINGS_ACTION_MANAGER_RO_TOGGLE:
#if FIDO_V1_MANAGER_DRIVE
        if(ws_manager_drive_read_only()) {
            /* READ ONLY -> READ/WRITE is the sole on-device setting protected
             * by a PIN. Do not change persistent state until verification. */
            (void)settings_begin_rw_pin(settings,now);
        } else {
            /* READ/WRITE -> READ ONLY is a safety-tightening transition and is
             * intentionally immediate, like the remaining display settings. */
            if(ws_manager_drive_set_read_only(true)) {
                pf_manager_drive_apply_read_only(true);
                v->manager_drive_read_only=true;
                settings_feedback(WS_SETTINGS_FEEDBACK_SAVED,now);
            } else {
                v->manager_drive_storage_ok=false;
                settings_feedback(WS_SETTINGS_FEEDBACK_ERROR,now);
            }
        }
#else
        settings_feedback(WS_SETTINGS_FEEDBACK_ERROR,now);
#endif
        return false;
    case WS_SETTINGS_ACTION_USB_TOOL_TOGGLE:
#if FIDO_V1_USB_TOOL
        if(!s_manager_restart_pending && !s_usb_tool_restart_pending) {
            bool target=!ws_usb_tool_enabled();
            bool role_ok=true;
#if FIDO_V1_MANAGER_DRIVE
            if(target && ws_manager_drive_enabled()) role_ok=ws_manager_drive_set_enabled(false);
#endif
            if(role_ok && ws_usb_tool_set_enabled(target)) {
                if(pf_usb_tool_running())pf_usb_tool_stop();
                v->usb_tool_enabled=target;
                s_usb_tool_restart_pending=true;
                s_manager_restart_pending=false;
                s_usb_role_restart_at=now;
                settings_feedback(WS_SETTINGS_FEEDBACK_SAVED,now);
                ws_screen_power_wake(&s_screen,now);
                ESP_LOGI(TAG,"USB Tool %s from Settings; restarting USB descriptors",
                         target?"enabled":"disabled");
            } else {
                v->usb_tool_storage_ok=false;
                settings_feedback(WS_SETTINGS_FEEDBACK_ERROR,now);
            }
        }
#else
        settings_feedback(WS_SETTINGS_FEEDBACK_ERROR,now);
#endif
        return false;
    case WS_SETTINGS_ACTION_USB_LAYOUT_PREV:
    case WS_SETTINGS_ACTION_USB_LAYOUT_NEXT:
#if FIDO_V1_USB_TOOL
        if(!pf_usb_tool_running()) {
            int dir=action==WS_SETTINGS_ACTION_USB_LAYOUT_NEXT?1:-1;
            bool saved=false;
            if(ws_usb_tool_enabled() && pf_usb_tool_media_ready() && pf_usb_tool_language_count()>0U) {
                saved=pf_usb_tool_select_language_delta(dir);
                if(saved)pf_usb_tool_language_name(v->usb_tool_language_name,sizeof(v->usb_tool_language_name));
            } else {
                int layout=(int)ws_usb_tool_layout()+dir;
                while(layout<0)layout+=WS_USB_LAYOUT_COUNT;
                while(layout>=WS_USB_LAYOUT_COUNT)layout-=WS_USB_LAYOUT_COUNT;
                saved=ws_usb_tool_set_layout((ws_usb_layout_t)layout);
                if(saved){v->usb_tool_layout=(uint8_t)layout;snprintf(v->usb_tool_language_name,sizeof(v->usb_tool_language_name),"%s",ws_usb_tool_layout_name((ws_usb_layout_t)layout));}
            }
            if(saved)settings_feedback(WS_SETTINGS_FEEDBACK_SAVED,now);
            else {v->usb_tool_storage_ok=false;settings_feedback(WS_SETTINGS_FEEDBACK_ERROR,now);}
        } else settings_feedback(WS_SETTINGS_FEEDBACK_ERROR,now);
#else
        settings_feedback(WS_SETTINGS_FEEDBACK_ERROR,now);
#endif
        return false;
    case WS_SETTINGS_ACTION_NONE:
    default:return false;
    }
    if(changed && settings_commit(&next,now)) {
        ws_settings_get(settings,NULL);
        return true;
    }
    return false;
}

static bool touch_probe_register(uint8_t reg,uint8_t *value,void *context)
{
    (void)context;
    return i2c_master_write_read_device(I2C_NUM_0,WS_TOUCH_ADDR,&reg,1,
                       value,1,pdMS_TO_TICKS(10))==ESP_OK;
}
static bool touch_write_register(uint8_t reg,uint8_t value,void *context)
{
    (void)context;
    const uint8_t data[]={reg,value};
    return i2c_master_write_to_device(I2C_NUM_0,WS_TOUCH_ADDR,data,sizeof(data),
                                    pdMS_TO_TICKS(20))==ESP_OK;
}

static esp_err_t touch_init(void)
{
    const i2c_config_t cfg={
        .mode=I2C_MODE_MASTER,
        .sda_io_num=WS_I2C_SDA, .scl_io_num=WS_I2C_SCL,
        .sda_pullup_en=GPIO_PULLUP_ENABLE, .scl_pullup_en=GPIO_PULLUP_ENABLE,
        .master={.clk_speed=300000}, .clk_flags=0,
    };
    esp_err_t err=i2c_param_config(I2C_NUM_0,&cfg);
    if(err==ESP_OK) err=i2c_driver_install(I2C_NUM_0,I2C_MODE_MASTER,0,0,0);
    const uint8_t normal_mode[]={0x00,0x00};
    if(err==ESP_OK) err=i2c_master_write_to_device(I2C_NUM_0,WS_TOUCH_ADDR,
                            normal_mode,sizeof(normal_mode),pdMS_TO_TICKS(20));
    /* One owner and startup only. Normal boots restore the observed A:01
     * default, so a controller left powered through an MCU reset cannot
     * retain the controls experiment in the FIDO role. No NVS writes. */
    if(err==ESP_OK) {
        s_controls_touch_probe=ws_ft3168_probe(touch_probe_register,NULL);
        /* A:00 did not repair two contacts on the physical panel. Restore
         * its observed A:01 default in every role; subsequent probes read only. */
        WsFT3168MonitorResult mode=ws_ft3168_monitor_mode(&s_controls_touch_probe,
            false,touch_probe_register,touch_write_register,NULL);
        ESP_LOGI(TAG,"FT3168 monitor restoration result=%u A=%02x valid=%u",
            (unsigned)mode,s_controls_touch_probe.value[4],
            (unsigned)((s_controls_touch_probe.valid_mask>>4)&1U));
    }
    return err;
}

static ws_contact_t touch_read(void)
{
    ws_contact_t result={0};
    uint8_t reg=0x02;
    /* FIDO and PIN remain single-touch. Apps and Air Mouse read both points. */
    uint8_t bytes[11]={0};
    if(s_air_mouse_role || s_gamepad_role)s_controls_touch_raw=0;
    if(s_gamepad_role)s_pad_count=0;
    if(s_air_mouse_role)s_mouse_point_count=0U;
    if(s_apps_touch_mode)s_app_point_count=0U;
    size_t length=(s_air_mouse_role || s_apps_touch_mode || s_gamepad_role)?sizeof(bytes):5U;
    esp_err_t err;
    if(s_air_mouse_role || s_gamepad_role) {
        /* Read complete slots including event/ID/weight/area. Separately
         * read the count like the Waveshare example, to detect a difference
         * in the panel's burst response. Keep FIDO/PIN/Apps reads unchanged. */
        uint8_t frame[15]={0},start=0,single=0;
        err=i2c_master_write_read_device(I2C_NUM_0,WS_TOUCH_ADDR,
                      &start,1,frame,sizeof(frame),pdMS_TO_TICKS(10));
        if(err==ESP_OK) {
            bool single_valid=touch_probe_register(0x02,&single,NULL);
            bool capture=s_gamepad_role?(s_gamepad.modal==0):
                                         (!s_air_mouse_settings_open && s_mouse_ble_modal==0);
            ws_ft3168_frame_observe(&s_controls_touch_frame,frame,sizeof(frame),
                                   single_valid,single,capture);
            memcpy(bytes,frame+2,sizeof(bytes));
        }
    } else err=i2c_master_write_read_device(I2C_NUM_0,WS_TOUCH_ADDR,
                       &reg,1,bytes,length,pdMS_TO_TICKS(10));
    if(err!=ESP_OK) return result; /* Invalid, NOT a synthetic release. */
    unsigned points=bytes[0]&0x0F;
    if(s_air_mouse_role || s_gamepad_role) {
        s_controls_touch_raw=(uint8_t)points;
        if(points>s_controls_touch_max)s_controls_touch_max=(uint8_t)points;
    }
    if(points==0) {
        result.valid=true;
        return result;
    }
    if(points>((s_air_mouse_role || s_apps_touch_mode || s_gamepad_role)?2U:1U)) return result;
    for(unsigned i=0;i<points;++i) {
        unsigned offset=1U+6U*i;
        uint16_t x=(uint16_t)(((bytes[offset]&0x0F)<<8)|bytes[offset+1U]);
        uint16_t y=(uint16_t)(((bytes[offset+2U]&0x0F)<<8)|bytes[offset+3U]);
        if(x>=WS_LCD_WIDTH || y>=WS_LCD_HEIGHT) return result;
        if(s_air_mouse_role){s_mouse_points[i].x=x;s_mouse_points[i].y=y;}
        if(s_gamepad_role)s_pad_points[i]=(WsControlPoint){(int16_t)x,(int16_t)y,(uint16_t)(bytes[offset+2U]>>4)};
        if(s_apps_touch_mode) {
            s_app_points[i].x=(int16_t)x;
            s_app_points[i].y=(int16_t)y;
            s_app_points[i].id=(uint16_t)(bytes[offset+2U]>>4);
            s_app_points[i].reserved=0;
        }
        if(i==0U){s_touch_x=x;s_touch_y=y;}
    }
    if(s_air_mouse_role)s_mouse_point_count=(uint8_t)points;
    if(s_gamepad_role)s_pad_count=(uint8_t)points;
    if(s_apps_touch_mode)s_app_point_count=(uint8_t)points;
    result.valid=true;
    result.down=true;
    result.action=ws_ui_hit_test(s_touch_x,s_touch_y);
    return result;
}

/* QMI8658C shares I2C0 with FT3168. Only this core0 board task touches the
 * bus; the display task never starts an IMU transaction. Air Mouse uses the
 * accelerometer at +/-2 g and 125 Hz to produce a two-axis tilt vector. */
#define WS_QMI_ADDR 0x6BU
static bool qmi_read(uint8_t reg,uint8_t *out,size_t length)
{
    return i2c_master_write_read_device(I2C_NUM_0,WS_QMI_ADDR,&reg,1,out,length,
                                        pdMS_TO_TICKS(10))==ESP_OK;
}

static bool qmi_write(uint8_t reg,uint8_t value)
{
    const uint8_t data[2]={reg,value};
    return i2c_master_write_to_device(I2C_NUM_0,WS_QMI_ADDR,data,sizeof(data),
                                      pdMS_TO_TICKS(10))==ESP_OK;
}

static bool qmi_probe(void)
{
    uint8_t id=0;
    return qmi_read(0x00U,&id,1U) && id==0x05U;
}

static bool qmi_start_accel(void)
{
    return qmi_probe() && qmi_write(0x08U,0x00U) &&
           qmi_write(0x02U,0x40U) && qmi_write(0x03U,0x06U) &&
           qmi_write(0x08U,0x01U);
}

static void air_mouse_calibrate(void)
{
    s_air_mouse_cal_samples=0;
    s_air_mouse_neutral_sum_x=s_air_mouse_neutral_sum_y=s_air_mouse_neutral_sum_z=0.0f;
    s_air_mouse_neutral_valid=false;
    s_air_mouse_fraction_x=s_air_mouse_fraction_y=0.0f;
}

static void air_mouse_preferences_load(void)
{
    /* Air Mouse preferences are separate from FIDO keys and the Manager UI
     * record. Missing or malformed data retains the safe original mapping. */
    uint8_t saved[2]={0};
    size_t size=sizeof(saved);
    nvs_handle_t h=0;
    if(nvs_open_from_partition("wsdev","ws_airmouse",NVS_READONLY,&h)!=ESP_OK)return;
    esp_err_t result=nvs_get_blob(h,"pointer_v1",saved,&size);
    nvs_close(h);
    if(result==ESP_OK && size==sizeof(saved) && saved[0]>=1U &&
       saved[0]<=5U && saved[1]<=1U) {
        s_air_mouse_sensitivity=saved[0];
        s_air_mouse_invert_y=saved[1]!=0U;
    }
}

static bool air_mouse_preferences_save(uint8_t sensitivity,bool invert_y)
{
    const uint8_t saved[2]={sensitivity,invert_y?1U:0U};
    uint8_t check[2]={0};
    size_t size=sizeof(check);
    nvs_handle_t h=0;
    esp_err_t result=nvs_open_from_partition("wsdev","ws_airmouse",NVS_READWRITE,&h);
    if(result!=ESP_OK)return false;
    result=nvs_set_blob(h,"pointer_v1",saved,sizeof(saved));
    if(result==ESP_OK)result=nvs_commit(h);
    if(result==ESP_OK)result=nvs_get_blob(h,"pointer_v1",check,&size);
    nvs_close(h);
    if(result!=ESP_OK || size!=sizeof(saved) || memcmp(saved,check,size)!=0)return false;
    s_air_mouse_sensitivity=sensitivity;
    s_air_mouse_invert_y=invert_y;
    s_air_mouse_fraction_x=s_air_mouse_fraction_y=0.0f;
    return true;
}

static void air_mouse_neutral_finish(void)
{
    float x=s_air_mouse_neutral_sum_x,y=s_air_mouse_neutral_sum_y;
    float z=s_air_mouse_neutral_sum_z;
    float length=sqrtf(x*x+y*y+z*z);
    if(length<1.0f)return;
    s_air_mouse_neutral_x=x/length;
    s_air_mouse_neutral_y=y/length;
    s_air_mouse_neutral_z=z/length;
    /* Screen-right projected onto the plane perpendicular to gravity.
     * The second tangent axis is orthogonal, so diagonal tilt is symmetric. */
    float dot=s_air_mouse_neutral_x;
    float rx=1.0f-dot*s_air_mouse_neutral_x;
    float ry=-dot*s_air_mouse_neutral_y;
    float rz=-dot*s_air_mouse_neutral_z;
    length=sqrtf(rx*rx+ry*ry+rz*rz);
    if(length<0.25f) {
        dot=s_air_mouse_neutral_y;
        rx=-dot*s_air_mouse_neutral_x;
        ry=1.0f-dot*s_air_mouse_neutral_y;
        rz=-dot*s_air_mouse_neutral_z;
        length=sqrtf(rx*rx+ry*ry+rz*rz);
    }
    if(length<0.25f)return;
    s_air_mouse_right_x=rx/length;
    s_air_mouse_right_y=ry/length;
    s_air_mouse_right_z=rz/length;
    s_air_mouse_down_x=s_air_mouse_neutral_y*s_air_mouse_right_z-
                       s_air_mouse_neutral_z*s_air_mouse_right_y;
    s_air_mouse_down_y=s_air_mouse_neutral_z*s_air_mouse_right_x-
                       s_air_mouse_neutral_x*s_air_mouse_right_z;
    s_air_mouse_down_z=s_air_mouse_neutral_x*s_air_mouse_right_y-
                       s_air_mouse_neutral_y*s_air_mouse_right_x;
    s_air_mouse_neutral_valid=true;
}

static int8_t air_mouse_pixel_delta(float *fraction)
{
    if(*fraction>100.0f){*fraction=0.0f;return 100;}
    if(*fraction< -100.0f){*fraction=0.0f;return -100;}
    int whole=(int)*fraction;
    *fraction-=(float)whole;
    return (int8_t)whole;
}

static void air_mouse_vector_delta(float tilt_x,float tilt_y,uint32_t elapsed_ms,
                                   int8_t *dx,int8_t *dy)
{
    /* Joystick semantics: direction comes from the two-axis tilt vector;
     * deflection sets cursor velocity. One circular dead zone and shared gain
     * preserve diagonals instead of favoring the cardinal directions. */
    float radius=sqrtf(tilt_x*tilt_x+tilt_y*tilt_y);
    if(radius>0.04f) {
        float active=radius-0.04f;
        float gain=850.0f+1300.0f*active;
        if(gain>1800.0f)gain=1800.0f;
        if(elapsed_ms>30U)elapsed_ms=30U;
        static const float sensitivity_scale[5]={0.55f,0.75f,1.0f,1.35f,1.70f};
        float pixels_per_g=active*gain*(float)elapsed_ms/(radius*1000.0f);
        pixels_per_g*=sensitivity_scale[s_air_mouse_sensitivity-1U];
        s_air_mouse_fraction_x+=tilt_x*pixels_per_g;
        s_air_mouse_fraction_y+=tilt_y*pixels_per_g;
    }
    /* Keep both relative HID deltas within the same per-report limit. */
    *dx=air_mouse_pixel_delta(&s_air_mouse_fraction_x);
    *dy=air_mouse_pixel_delta(&s_air_mouse_fraction_y);
}

static void air_mouse_poll(uint32_t now,ws_ui_snapshot_t *view)
{
    bool ble=pf_control_mode()==PF_CONTROL_BLE_MOUSE;
    if(ble && view->ble_connected!=s_mouse_ble_connected) {
        s_mouse_ble_connected=view->ble_connected;
        s_air_mouse_ui_touch_armed=false;s_air_mouse_sent_buttons=0;
        ws_mouse_latch_reset(&s_mouse_latch);
        s_air_mouse_fraction_x=s_air_mouse_fraction_y=0.0f;
        pf_ble_release();
    }
    bool fresh=s_touch_available && s_touch.valid &&
        (uint32_t)(now-s_touch_polled)<=60U;
    uint8_t zone=0U;
    uint16_t zone_y=0U;
    bool motion_held=false,touch_outside=false;
    if(fresh && s_touch.down) {
        for(unsigned i=0;i<s_mouse_point_count;++i) {
            uint8_t hit=ws_ui_air_mouse_hit_test(s_air_mouse_settings_open,
                                                 s_mouse_points[i].x,s_mouse_points[i].y);
            if(ble && s_air_mouse_settings_open) {
                int x=s_mouse_points[i].x,y=s_mouse_points[i].y;
                if(s_mouse_ble_modal)hit=y>=250 && y<308?(x>=20 && x<136?14:x>=144 && x<260?15:0):0;
                else if(y>=286 && y<330 && x>=20 && x<260)hit=8;
                else if(y>=336 && y<380)hit=x>=20 && x<136?12:x>=144 && x<260?13:0;
                else if(y>=310 && y<392)hit=0;
            }
            if(hit!=0U && zone==0U) {
                zone=hit;
                zone_y=s_mouse_points[i].y;
            }
            else if(hit==0U)touch_outside=true;
        }
    }
    if(fresh && (!s_touch.down || s_mouse_point_count==0U))
        s_air_mouse_ui_touch_armed=true;
    if(!fresh)s_air_mouse_ui_touch_armed=false;
    if(!s_air_mouse_ui_touch_armed){zone=0;motion_held=false;}
    if(ble && s_air_mouse_settings_open && s_air_mouse_ui_touch_armed && s_mouse_point_count==1U && zone>=12U) {
        pf_ble_release();s_air_mouse_sent_buttons=0;
        s_air_mouse_ui_touch_armed=false;
        if(zone==12U)pf_ble_pair();
        else if(zone==13U)s_mouse_ble_modal=1;
        else if(zone==14U){pf_ble_forget();s_mouse_ble_modal=0;}
        else if(zone==15U)s_mouse_ble_modal=0;
        zone=0;
    }
    /* A brief tap must never restart USB or reset the neutral tilt. Leaving the
     * target, lifting the finger, or a missing touch sample resets the hold. */
    uint8_t action_zone=s_air_mouse_ui_touch_armed && !motion_held &&
        s_mouse_point_count==1U &&
        (zone==1U || zone==2U || zone==8U)?zone:0U;
    if(action_zone!=s_air_mouse_action_hold_zone) {
        s_air_mouse_action_hold_zone=action_zone;
        s_air_mouse_action_hold_at=now;
        s_air_mouse_action_hold_fired=false;
    }
    uint8_t hold_step=0U;
    if(action_zone) {
        uint32_t held=(uint32_t)(now-s_air_mouse_action_hold_at);
        hold_step=held>=3000U?30U:(uint8_t)(held/100U);
        if(held>=3000U && !s_air_mouse_action_hold_fired) {
            s_air_mouse_action_hold_fired=true;
            if(action_zone==1U) pf_air_mouse_exit();
            else if(action_zone==2U) {
                s_air_mouse_settings_open=true;
                s_air_mouse_ui_touch_armed=false;
                zone=0U;
            } else {
                if(!s_air_mouse_sensor_ok)s_air_mouse_sensor_ok=qmi_start_accel();
                if(s_air_mouse_sensor_ok)air_mouse_calibrate();
            }
        }
    }

    if(s_air_mouse_settings_open && s_air_mouse_ui_touch_armed &&
       s_mouse_point_count==1U && (zone==7U || zone==9U ||
       zone==10U || zone==11U)) {
        s_air_mouse_ui_touch_armed=false;
        if(zone==7U) {
            s_air_mouse_settings_open=false;
            zone=0U;
        } else {
            uint8_t sensitivity=s_air_mouse_sensitivity;
            bool invert_y=s_air_mouse_invert_y;
            if(zone==9U && sensitivity>1U)--sensitivity;
            if(zone==10U && sensitivity<5U)++sensitivity;
            if(zone==11U)invert_y=!invert_y;
            if((sensitivity!=s_air_mouse_sensitivity || invert_y!=s_air_mouse_invert_y) &&
               !air_mouse_preferences_save(sensitivity,invert_y))
                ESP_LOGW(TAG,"Air Mouse preferences could not be saved");
        }
    }

    int8_t wheel=0;
    if(zone==5U) {
        if(s_air_mouse_touch_zone==5U) {
            s_air_mouse_scroll_accum+=(int16_t)(s_air_mouse_scroll_last_y-(int16_t)zone_y);
            if(s_air_mouse_scroll_accum>=24) {wheel=1;s_air_mouse_scroll_accum-=24;}
            else if(s_air_mouse_scroll_accum<=-24) {wheel=-1;s_air_mouse_scroll_accum+=24;}
        } else s_air_mouse_scroll_accum=0;
        s_air_mouse_scroll_last_y=(int16_t)zone_y;
    } else s_air_mouse_scroll_accum=0;
    s_air_mouse_touch_zone=zone;
    bool transport_ready=ble?view->ble_connected:
        led_get_mode()!=MODE_NOT_MOUNTED && led_get_mode()!=MODE_SUSPENDED;
    bool latch_enabled=transport_ready && !s_air_mouse_settings_open && !s_mouse_ble_modal &&
        zone!=1U && zone!=2U && s_air_mouse_sensor_ok && s_air_mouse_neutral_valid;
    ws_mouse_latch_touch(&s_mouse_latch,fresh && s_mouse_point_count<=1U,
        s_touch.down && s_mouse_point_count!=0U,zone,latch_enabled);
    uint8_t buttons=s_mouse_latch.buttons;
    motion_held=s_mouse_latch.move;
    if(!latch_enabled){buttons=0;motion_held=false;wheel=0;}

    int8_t dx=0,dy=0;
    if(s_air_mouse_sensor_ok && (uint32_t)(now-s_air_mouse_sampled_at)>=10U) {
        uint32_t elapsed=s_air_mouse_sampled_at?(uint32_t)(now-s_air_mouse_sampled_at):10U;
        s_air_mouse_sampled_at=now;
        uint8_t data[6]={0};
        if(qmi_read(0x35U,data,sizeof(data))) {
            s_air_mouse_errors=0;
            int16_t ax=(int16_t)((uint16_t)data[0]|((uint16_t)data[1]<<8));
            int16_t ay=(int16_t)((uint16_t)data[2]|((uint16_t)data[3]<<8));
            int16_t az=(int16_t)((uint16_t)data[4]|((uint16_t)data[5]<<8));
            float length=sqrtf((float)ax*ax+(float)ay*ay+(float)az*az);
            bool accel_valid=isfinite(length) && length>1000.0f && length<32000.0f;
            if(!accel_valid){ws_mouse_latch_reset(&s_mouse_latch);buttons=0;motion_held=false;}
            if(accel_valid) {
                float gx=(float)ax/length,gy=(float)ay/length,gz=(float)az/length;
                if(!s_air_mouse_gravity_valid) {
                    s_air_mouse_gravity_x=gx;s_air_mouse_gravity_y=gy;
                    s_air_mouse_gravity_z=gz;s_air_mouse_gravity_valid=true;
                } else {
                    s_air_mouse_gravity_x=0.22f*gx+0.78f*s_air_mouse_gravity_x;
                    s_air_mouse_gravity_y=0.22f*gy+0.78f*s_air_mouse_gravity_y;
                    s_air_mouse_gravity_z=0.22f*gz+0.78f*s_air_mouse_gravity_z;
                }
            }
            if(s_air_mouse_cal_samples<60U) {
                if(s_air_mouse_gravity_valid && accel_valid) {
                    s_air_mouse_neutral_sum_x+=s_air_mouse_gravity_x;
                    s_air_mouse_neutral_sum_y+=s_air_mouse_gravity_y;
                    s_air_mouse_neutral_sum_z+=s_air_mouse_gravity_z;
                    ++s_air_mouse_cal_samples;
                    if(s_air_mouse_cal_samples==60U)air_mouse_neutral_finish();
                }
            } else if(motion_held && s_air_mouse_neutral_valid && accel_valid) {
                float tx=s_air_mouse_gravity_x-s_air_mouse_neutral_x;
                float ty=s_air_mouse_gravity_y-s_air_mouse_neutral_y;
                float tz=s_air_mouse_gravity_z-s_air_mouse_neutral_z;
                float tilt_x=tx*s_air_mouse_right_x+ty*s_air_mouse_right_y+
                             tz*s_air_mouse_right_z;
                float tilt_y=tx*s_air_mouse_down_x+ty*s_air_mouse_down_y+
                             tz*s_air_mouse_down_z;
                /* On the fitted board, the projected axes are rotated 90 deg
                 * relative to the USB cursor: physical right is +tilt_y,
                 * and physical down is -tilt_x. Rotate the whole vector so
                 * diagonal motion retains the same radial response. */
                air_mouse_vector_delta(tilt_y,s_air_mouse_invert_y?tilt_x:-tilt_x,
                                       elapsed,&dx,&dy);
            }
        } else {
            ws_mouse_latch_reset(&s_mouse_latch);buttons=0;motion_held=false;dx=dy=0;
            if(++s_air_mouse_errors>=10U) {
                s_air_mouse_sensor_ok=false;
                ESP_LOGW(TAG,"Air Mouse accelerometer unavailable; pointer movement stopped");
            }
        }
    }
    if(!motion_held) {
        dx=dy=0;
        s_air_mouse_fraction_x=s_air_mouse_fraction_y=0.0f;
    }
    if((dx||dy||wheel||buttons!=s_air_mouse_sent_buttons) &&
       pf_air_mouse_report(buttons,dx,dy,wheel))s_air_mouse_sent_buttons=buttons;
    view->air_mouse_active=true;
    view->air_mouse_sensor_ok=s_air_mouse_sensor_ok;
    view->air_mouse_calibrating=s_air_mouse_cal_samples<60U;
    view->air_mouse_buttons=buttons;
    view->air_mouse_touch_zone=zone;
    view->air_mouse_move_held=motion_held;
    view->air_mouse_drag_latched=s_mouse_latch.drag;
    view->air_mouse_hold_step=hold_step;
    view->air_mouse_touch_fault=!s_touch_available || s_touch_errors>=10U;
    view->air_mouse_touch_outside=touch_outside;
    view->air_mouse_settings_open=s_air_mouse_settings_open;
    view->air_mouse_sensitivity=s_air_mouse_sensitivity;
    view->air_mouse_invert_y=s_air_mouse_invert_y;
    view->air_mouse_ble_modal=s_mouse_ble_modal;
}

#ifdef CONFIG_WS_V1_DISPLAY
typedef struct {
    ws_ui_snapshot_t last;
    bool valid, off;
    uint8_t brightness;
} ws_display_cache_t;

static bool view_content_changed(const ws_ui_snapshot_t *a,const ws_ui_snapshot_t *b)
{
    return a->state!=b->state || a->epoch!=b->epoch ||
        memcmp(&a->controls,&b->controls,sizeof(a->controls))!=0 ||
        memcmp(&a->gamepad.report,&b->gamepad.report,sizeof(a->gamepad.report))!=0 ||
        a->gamepad.modal!=b->gamepad.modal || a->gamepad.hold_step!=b->gamepad.hold_step ||
        a->gamepad.ui_pressed!=b->gamepad.ui_pressed || a->gamepad.ui_modal!=b->gamepad.ui_modal ||
        a->gamepad.imu.ready!=b->gamepad.imu.ready || a->gamepad.imu.valid!=b->gamepad.imu.valid ||
        a->gamepad_active!=b->gamepad_active || a->ble_connected!=b->ble_connected ||
        a->ble_ready!=b->ble_ready || a->ble_failed!=b->ble_failed ||
        a->controls_touch_count!=b->controls_touch_count ||
        a->controls_touch_raw!=b->controls_touch_raw ||
        a->controls_touch_max!=b->controls_touch_max ||
        a->controls_touch_valid!=b->controls_touch_valid ||
        (b->gamepad_active && b->gamepad.modal==2 &&
         memcmp(&a->controls_touch_frame,&b->controls_touch_frame,sizeof(a->controls_touch_frame))!=0) ||
        a->air_mouse_ble_modal!=b->air_mouse_ble_modal ||
        a->seconds_left!=b->seconds_left || a->touch_available!=b->touch_available ||
        a->touch_enabled!=b->touch_enabled || a->boot_allowed!=b->boot_allowed ||
        a->pin_length!=b->pin_length || a->uv_retries!=b->uv_retries ||
        a->pin_permissions!=b->pin_permissions || a->pin_purpose!=b->pin_purpose ||
        a->pressed_action!=b->pressed_action ||
        a->animation_phase!=b->animation_phase || a->accent_rgb!=b->accent_rgb ||
        a->settings_revision!=b->settings_revision ||
        a->screensaver_transition!=b->screensaver_transition ||
        a->screensaver_phase!=b->screensaver_phase ||
        a->screensaver_text_phase!=b->screensaver_text_phase ||
        a->screensaver_open!=b->screensaver_open ||
        a->settings_transition!=b->settings_transition ||
        a->settings_motion_phase!=b->settings_motion_phase || a->settings_page!=b->settings_page ||
        a->settings_page_offset!=b->settings_page_offset ||
        a->settings_pressed_action!=b->settings_pressed_action ||
        a->settings_feedback!=b->settings_feedback || a->settings_open!=b->settings_open ||
        a->diagnostics_enabled!=b->diagnostics_enabled ||
        a->diagnostics_tick!=b->diagnostics_tick ||
        a->diagnostics_export_request!=b->diagnostics_export_request ||
        a->diagnostics_export_status!=b->diagnostics_export_status ||
        strcmp(a->diagnostics_export_message,b->diagnostics_export_message)!=0 ||
        a->air_mouse_available!=b->air_mouse_available ||
        a->air_mouse_active!=b->air_mouse_active ||
        a->air_mouse_sensor_ok!=b->air_mouse_sensor_ok ||
        a->air_mouse_calibrating!=b->air_mouse_calibrating ||
        a->air_mouse_restarting!=b->air_mouse_restarting ||
        a->air_mouse_drag_latched!=b->air_mouse_drag_latched ||
        a->air_mouse_buttons!=b->air_mouse_buttons ||
        a->air_mouse_touch_zone!=b->air_mouse_touch_zone ||
        a->air_mouse_move_held!=b->air_mouse_move_held ||
        a->air_mouse_hold_step!=b->air_mouse_hold_step ||
        a->air_mouse_touch_fault!=b->air_mouse_touch_fault ||
        a->air_mouse_touch_outside!=b->air_mouse_touch_outside ||
        a->air_mouse_settings_open!=b->air_mouse_settings_open ||
        a->air_mouse_sensitivity!=b->air_mouse_sensitivity ||
        a->air_mouse_invert_y!=b->air_mouse_invert_y ||
        a->settings_storage_ok!=b->settings_storage_ok ||
        a->settings_animation!=b->settings_animation ||
        a->settings_dim_seconds!=b->settings_dim_seconds ||
        a->settings_off_seconds!=b->settings_off_seconds ||
        a->settings_presence_seconds!=b->settings_presence_seconds ||
        a->settings_uv_seconds!=b->settings_uv_seconds ||
        a->manager_drive_available!=b->manager_drive_available ||
        a->manager_drive_enabled!=b->manager_drive_enabled ||
        a->manager_drive_media_ready!=b->manager_drive_media_ready ||
        a->manager_drive_storage_ok!=b->manager_drive_storage_ok ||
        a->manager_drive_read_only!=b->manager_drive_read_only ||
        a->manager_drive_pressed!=b->manager_drive_pressed ||
        a->manager_drive_restarting!=b->manager_drive_restarting ||
        a->apps_ready!=b->apps_ready || a->apps_mounted!=b->apps_mounted ||
        a->apps_running!=b->apps_running ||
        a->launcher_transition!=b->launcher_transition ||
        a->launcher_page_offset!=b->launcher_page_offset ||
        a->launcher_page!=b->launcher_page || a->launcher_pressed!=b->launcher_pressed ||
        a->apps_catalog_generation!=b->apps_catalog_generation ||
        a->apps_scanning!=b->apps_scanning || a->apps_catalog_ready!=b->apps_catalog_ready ||
        a->apps_exit_confirm!=b->apps_exit_confirm ||
        a->apps_exit_pressed!=b->apps_exit_pressed ||
        a->apps_exit_dragging!=b->apps_exit_dragging ||
        a->apps_exit_progress!=b->apps_exit_progress ||
        a->apps_count!=b->apps_count ||
        a->apps_selected!=b->apps_selected || a->apps_frame!=b->apps_frame ||
        strcmp(a->apps_id,b->apps_id)!=0 || strcmp(a->apps_status,b->apps_status)!=0;
}

/* Sole owner of panel I/O. The small step is also exercised by host tests.
 * Never hold the shared lock across SPI, DMA waits or display delays. */
static bool ws_display_step(ws_display_cache_t *cache)
{
    ws_ui_snapshot_t view;
    portENTER_CRITICAL(&s_lock);
    view=s_view;
    bool usable=s_panel_ok;
    portEXIT_CRITICAL(&s_lock);
    if(!usable)return false;
    esp_err_t err=ESP_OK;
    if(view.screen_off) {
        if(!cache->valid || !cache->off) {
            err=ws_panel_brightness(0);
            if(err==ESP_OK) err=ws_panel_set_enabled(false);
        }
        cache->off=true;cache->brightness=0;
    } else {
        bool redraw=!cache->valid || cache->off || view_content_changed(&cache->last,&view);
        /* DISPOFF preserves display RAM access. Render the new frame while dark
         * before enabling the display, so an old approval/PIN screen never flashes. */
        if(redraw) {
            uint32_t started=now_ms();
            
            bool admitted=ek_render_frame_begin(EK_RENDER_FRAME_DISPLAY);
            
            err=ws_lvgl_render(&view);
            
            ek_render_frame_end(admitted);
            uint32_t duration=now_ms()-started;
            portENTER_CRITICAL(&s_lock);
            if(duration>s_render_ms_max)s_render_ms_max=duration;
            portEXIT_CRITICAL(&s_lock);
        }
        if(err==ESP_OK && cache->off) err=ws_panel_set_enabled(true);
        uint8_t bright=view.brightness?view.brightness:CONFIG_WS_V1_BRIGHTNESS;
        uint8_t dim_brightness=view.dim_brightness?view.dim_brightness:8;
        if(dim_brightness>bright)dim_brightness=bright;
        uint8_t next=view.dim?dim_brightness:bright;
        if(err==ESP_OK && (!cache->valid || cache->off || cache->brightness!=next))
            err=ws_panel_brightness(next);
        if(err==ESP_OK){cache->off=false;cache->brightness=next;}
    }
    portENTER_CRITICAL(&s_lock);
    if(err==ESP_OK) {
        s_display_bright=!view.screen_off && !view.dim;
        s_displayed_epoch=s_display_bright &&
            (view.state==WS_UI_WAITING || view.state==WS_UI_PIN)?view.epoch:0;
    } else {
        s_panel_ok=false;s_display_bright=false;s_displayed_epoch=0;
    }
    portEXIT_CRITICAL(&s_lock);
    
    if(err!=ESP_OK) {
        ESP_LOGE(TAG,"AMOLED failed: %s; touch/PIN approval disabled",esp_err_to_name(err));
        return false;
    }
    cache->last=view;cache->valid=true;
    return true;
}
static void display_task(void *arg)
{
    (void)arg;
    ws_display_cache_t cache={0};
    uint32_t deadline=now_ms();
    while(ws_display_step(&cache)) {
        /* Absolute-time phases retain the same animation period. Rendering
         * consumes the frame budget instead of adding an 8ms delay afterward.
         * Input/authentication polling remains in its independent board task. */
        uint32_t frame_ms=50U;
        if(cache.valid) {
            const ws_ui_snapshot_t *v=&cache.last;
            if((v->settings_transition!=0U && v->settings_transition!=255U) ||
               (v->screensaver_transition!=0U && v->screensaver_transition!=255U) ||
               (v->launcher_transition!=0U && v->launcher_transition!=255U) ||
               v->settings_page_offset!=0 || v->launcher_page_offset!=0)
                frame_ms=8U;
            else if(v->screensaver_open)
                frame_ms=8U;
            else if(v->settings_animation && v->state!=WS_UI_PIN)
                frame_ms=8U;
        }
        /* JET images have their own 33ms gate in LVGL; cheap decoration and
         * navigation retain the 8ms cadence and their original durations. */
        deadline+=frame_ms;
        const uint32_t now=now_ms();
        if((int32_t)(deadline-now)<=0){deadline=now;vTaskDelay(pdMS_TO_TICKS(1U));}
        else vTaskDelay(pdMS_TO_TICKS(deadline-now));
    }
    vTaskDelete(NULL);
}
#endif

void ws_board_init(void)
{
    if(s_initialized) return;
    s_initialized=true;
    s_air_mouse_role=pf_air_mouse_role();
    s_gamepad_role=pf_control_mode()==PF_CONTROL_BLE_PAD;
    pf_controls_preferences(&s_controls);
    ws_gamepad_init(&s_gamepad);
    s_view.gamepad_active=s_gamepad_role;s_view.gamepad=s_gamepad;s_view.controls=s_controls;
    ws_settings_init();
    air_mouse_preferences_load();
#if FIDO_V1_MANAGER_DRIVE
    ws_manager_drive_state_init();
#endif
    /* R16: file_scan_flash() already ran in pf_engine_start. Bind EF_PIN now,
     * before USB/CTAPHID traffic can race the first Settings use. */
    if(pf_control_mode()<PF_CONTROL_BLE_MOUSE)(void)pf_local_uv_ready();
    ws_screen_power_init(&s_screen,now_ms());
    s_display_bright=false;
    memset(&s_view,0,sizeof(s_view));
    s_view.state=WS_UI_DISCONNECTED;
    if(pf_control_mode()<PF_CONTROL_BLE_MOUSE && !ek_apps_start()) ESP_LOGW(TAG,"Apps worker unavailable; FIDO remains available");
    ESP_LOGW(TAG,"DEVELOPMENT ONLY: keys in unencrypted NVS, no eFuse programming");
#ifdef CONFIG_WS_V1_DISPLAY
    esp_err_t err=touch_init();
    s_touch_available=err==ESP_OK;
    if(err!=ESP_OK) ESP_LOGW(TAG,"FT3168 unavailable: %s",esp_err_to_name(err));
    s_air_mouse_sensor_ok=s_touch_available && qmi_probe();
    if((s_air_mouse_role || s_gamepad_role) && s_air_mouse_sensor_ok) {
        s_air_mouse_sensor_ok=qmi_start_accel();
        air_mouse_calibrate();
        ESP_LOGI(TAG,"Controls IMU %s",s_air_mouse_sensor_ok?"ready":"configuration failed");
    }
    s_view.touch_available=s_touch_available;
#ifdef CONFIG_WS_V1_TOUCH_CONFIRM
    s_view.touch_enabled=true;
#endif
#else
    /* Reference the optional initializer to avoid unused-function diagnostics. */
    (void)touch_init;
#endif
}

void ws_board_start_display(void)
{
#ifdef CONFIG_WS_V1_DISPLAY
    static bool started;
    if(started || !s_initialized)return;
    started=true;
    ESP_LOGI(TAG,"Display startup after transport: internal free=%u, largest=%u",
        (unsigned)heap_caps_get_free_size(MALLOC_CAP_INTERNAL|MALLOC_CAP_8BIT),
        (unsigned)heap_caps_get_largest_free_block(MALLOC_CAP_INTERNAL|MALLOC_CAP_8BIT));
    esp_err_t err=ws_panel_init();
    if(err==ESP_OK)err=ws_lvgl_init();
    portENTER_CRITICAL(&s_lock);
    s_panel_ok=err==ESP_OK;
    portEXIT_CRITICAL(&s_lock);
    if(err!=ESP_OK)ESP_LOGE(TAG,"AMOLED/LVGL init: %s; touch/PIN unavailable",esp_err_to_name(err));
    if(err==ESP_OK && xTaskCreate(display_task,"ws_display",8192,NULL,1,NULL)!=pdPASS) {
        portENTER_CRITICAL(&s_lock);s_panel_ok=false;portEXIT_CRITICAL(&s_lock);
        ESP_LOGE(TAG,"Cannot start AMOLED task; touch/PIN unavailable");
    }
#endif
}

void ws_board_poll(void)
{
    if(!s_initialized) return;
    uint32_t now=now_ms();
#if FIDO_V1_MANAGER_DRIVE
    if(pf_manager_drive_take_eject() && !s_manager_restart_pending &&
       !s_usb_tool_restart_pending && !s_air_mouse_role && !s_gamepad_role) {
        if(ws_manager_drive_set_enabled(false)) {
            cancel_button=true;
            ws_board_pin_abort();
            s_manager_restart_pending=true;
            s_usb_role_restart_at=now;
            settings_feedback(WS_SETTINGS_FEEDBACK_SAVED,now);
            ws_screen_power_wake(&s_screen,now);
        } else settings_feedback(WS_SETTINGS_FEEDBACK_ERROR,now);
    }
#endif

    if(s_poll_at && s_diagnostics_enabled && now-s_poll_at>s_poll_gap_max)
        s_poll_gap_max=now-s_poll_at;
    s_poll_at=now;
    ws_settings_t settings;bool settings_storage_ok=false;ws_settings_get(&settings,&settings_storage_ok);
    /* Only core0 owns result-screen state. The FIDO worker uses a mailbox. */
    portENTER_CRITICAL(&s_lock);
    bool feedback=s_feedback_pending;
    int error=s_feedback_error;
    s_feedback_pending=false;
    portEXIT_CRITICAL(&s_lock);
    if(feedback) {
        s_last_result=error==0?WS_UI_CONFIRMED:error==0x3f?WS_UI_PIN_BAD:
            error==0x3c || error==0x32?WS_UI_PIN_BLOCKED:
            error==0x2d || error==0x27?WS_UI_CANCELLED:
            error==0x2f?WS_UI_TIMEOUT:WS_UI_INPUT_ERROR;
        s_result_at=now;s_show_result=true;
    }
    if((s_air_mouse_role || s_gamepad_role) && !s_touch_available &&
       (uint32_t)(now-s_air_mouse_touch_retry_at)>=1000U) {
        s_air_mouse_touch_retry_at=now;
        const uint8_t normal_mode[]={0x00,0x00};
        if(i2c_master_write_to_device(I2C_NUM_0,WS_TOUCH_ADDR,normal_mode,
                                      sizeof(normal_mode),pdMS_TO_TICKS(20))==ESP_OK) {
            s_touch_available=true;
            s_touch_errors=0;
            ESP_LOGI(TAG,"Air Mouse touch I2C recovered");
        }
    }
    if(s_touch_available && (uint32_t)(now-s_touch_polled)>=20U) {
        s_touch_polled=now;
        s_touch=touch_read();
        if(s_touch.valid) {
            s_touch_errors=0;
            portENTER_CRITICAL(&s_lock);
            bool display_bright=s_display_bright;
            portEXIT_CRITICAL(&s_lock);
            if(s_air_mouse_role || s_gamepad_role) {
                /* This screen stays awake. Do not let a stale wake-tap gate
                 * swallow mouse buttons, scroll or the guarded exit action. */
                ws_screen_power_wake(&s_screen,now);
            } else if(!ws_screen_power_touch(&s_screen,now,s_touch,display_bright))
                memset(&s_touch,0,sizeof(s_touch));
        } else {
            if(!s_air_mouse_role && !s_gamepad_role)
                (void)ws_screen_power_touch(&s_screen,now,s_touch,false);
            if(s_touch_errors<10U && ++s_touch_errors==10U) {
                if(s_air_mouse_role || s_gamepad_role) {
                    ESP_LOGW(TAG,"Air Mouse touch I2C read errors; retrying without disabling touch");
                } else {
                    portENTER_CRITICAL(&s_lock);
                    s_touch_available=false;
                    portEXIT_CRITICAL(&s_lock);
                    ESP_LOGW(TAG,"FT3168 read errors: touch disabled until reboot");
                }
            }
        }
    }
    if(gpio_get_level(WS_BOOT)==0) ws_screen_power_wake(&s_screen,now);
    if(s_air_mouse_role || s_gamepad_role) {
        if(gpio_get_level(WS_BOOT)==0) {
            if(!s_control_boot_hold)s_control_boot_hold=now;
            if(now-s_control_boot_hold>=1200U) {
                pf_ble_release();vTaskDelay(pdMS_TO_TICKS(30));pf_control_restart(PF_CONTROL_NORMAL);
            }
        } else s_control_boot_hold=0;
    }
    ws_ui_snapshot_t v={0};
    v.brightness=settings.brightness;v.dim_brightness=settings.dim_brightness;
    v.accent_rgb=settings.accent_rgb;v.settings_revision=settings.revision;
    v.settings_storage_ok=settings_storage_ok;v.settings_animation=settings.animation;
    v.settings_dim_seconds=settings.dim_seconds;v.settings_off_seconds=settings.off_seconds;
    v.settings_presence_seconds=settings.presence_seconds;v.settings_uv_seconds=settings.uv_seconds;
    v.epoch=s_epoch;
    v.boot_allowed=FIDO_V1_BOOT_CONFIRM_FALLBACK!=0;
    v.air_mouse_available=s_air_mouse_sensor_ok && s_touch_available &&
        !ws_usb_tool_enabled() && !ws_manager_drive_enabled();
    v.air_mouse_sensor_ok=s_air_mouse_sensor_ok;
    v.controls=s_controls;
    v.ble_connected=pf_ble_connected();v.ble_ready=pf_ble_ready();v.ble_failed=pf_ble_failed();
    if(s_gamepad_role || s_air_mouse_role) {
        v.controls_touch_valid=s_touch_available && s_touch.valid && now-s_touch_polled<=60U;
        v.controls_touch_raw=s_controls_touch_raw;
        v.controls_touch_max=s_controls_touch_max;
        v.controls_touch_probe=s_controls_touch_probe;
        v.controls_touch_frame=s_controls_touch_frame;
        v.controls_touch_count=v.controls_touch_valid?(s_gamepad_role?s_pad_count:s_mouse_point_count):0;
    }
    if(s_gamepad_role) {
        if(v.ble_connected!=s_pad_connected){
            s_gamepad.armed=false;s_gamepad.ui_capture=0;s_gamepad.ui_pressed=0;s_pad_connected=v.ble_connected;
            s_pad_sent=(WsPadReport){.hat=8};pf_ble_release();
        }
        WsPadAction action=ws_gamepad_touch(&s_gamepad,&s_controls,
            s_touch_available && s_touch.valid && now-s_touch_polled<=60U,s_pad_points,s_touch.down?s_pad_count:0,now);
        if(action==WS_PAD_CALIBRATE) {
            ws_gamepad_calibrate(&s_gamepad);
            if(!s_air_mouse_sensor_ok)s_air_mouse_sensor_ok=qmi_start_accel();
        }
        if((uint32_t)(now-s_pad_imu_at)>=20U) {
            s_pad_imu_at=now;
            uint8_t raw[6];
            if(s_air_mouse_sensor_ok && qmi_read(0x35U,raw,sizeof(raw))) {
                int16_t ax=(int16_t)((uint16_t)raw[0]|((uint16_t)raw[1]<<8));
                int16_t ay=(int16_t)((uint16_t)raw[2]|((uint16_t)raw[3]<<8));
                int16_t az=(int16_t)((uint16_t)raw[4]|((uint16_t)raw[5]<<8));
                ws_gamepad_imu_sample(&s_gamepad,ax,ay,az,now);
            } else s_gamepad.imu.valid=false;
        }
        ws_gamepad_apply_imu(&s_gamepad,&s_controls,v.ble_connected,now);
        v.controls=s_controls;
        if(action==WS_PAD_EXIT){
            pf_ble_release();(void)pf_controls_save(&s_controls);
            vTaskDelay(pdMS_TO_TICKS(30));pf_control_restart(PF_CONTROL_NORMAL);
        }
        if(action==WS_PAD_PAIR)pf_ble_pair();
        if(action==WS_PAD_FORGET)pf_ble_forget();
        if(action==WS_PAD_SAVE && !pf_controls_save(&s_controls))ESP_LOGW(TAG,"Controller preferences save failed");
        if(memcmp(&s_pad_sent,&s_gamepad.report,sizeof(s_pad_sent))!=0 && pf_ble_pad_report(&s_gamepad.report))s_pad_sent=s_gamepad.report;
        v.gamepad=s_gamepad;v.gamepad_active=true;
        v.state=v.ble_connected?WS_UI_READY:WS_UI_DISCONNECTED;
        v.dim=false;v.screen_off=false;
        ws_screen_power_wake(&s_screen,now);
        portENTER_CRITICAL(&s_lock);s_view=v;portEXIT_CRITICAL(&s_lock);
        return;
    }
    if(s_air_mouse_role) {
        air_mouse_poll(now,&v);
        v.state=pf_control_mode()==PF_CONTROL_BLE_MOUSE?(v.ble_connected?WS_UI_READY:WS_UI_DISCONNECTED):
            led_get_mode()==MODE_NOT_MOUNTED?WS_UI_DISCONNECTED:WS_UI_READY;
        ws_screen_power_tick_config(&s_screen,now,true,s_touch_available,
            (uint32_t)settings.dim_seconds*1000U,(uint32_t)settings.off_seconds*1000U);
        v.dim=false;v.screen_off=false;
        portENTER_CRITICAL(&s_lock);
        s_view=v;
        portEXIT_CRITICAL(&s_lock);
        return;
    }
#if FIDO_V1_MANAGER_DRIVE
    v.manager_drive_available=true;
    v.manager_drive_enabled=ws_manager_drive_enabled();
    v.manager_drive_media_ready=v.manager_drive_enabled && pf_manager_drive_media_ready();
    v.manager_drive_storage_ok=ws_manager_drive_storage_ok();
    v.manager_drive_read_only=ws_manager_drive_read_only();
#else
    v.manager_drive_storage_ok=true;
#endif
#if FIDO_V1_USB_TOOL
    v.usb_tool_available=true;
    v.usb_tool_enabled=ws_usb_tool_enabled();
    v.usb_tool_storage_ok=ws_usb_tool_storage_ok();
    v.usb_tool_layout=(uint8_t)ws_usb_tool_layout();
    v.usb_tool_media_ready=v.usb_tool_enabled && pf_usb_tool_media_ready();
    v.usb_tool_running=pf_usb_tool_running();
    (void)pf_usb_tool_confirmation_pending();
    v.usb_tool_status=pf_usb_tool_status();
    v.usb_tool_ducky_led=pf_usb_tool_ducky_led();
    v.usb_tool_storage_active=pf_usb_tool_storage_present() &&
        pf_usb_tool_storage_activity_age_ms()<=pf_usb_tool_storage_activity_timeout_ms();
    v.usb_tool_script_count=pf_usb_tool_script_count();
    v.usb_tool_selected_index=pf_usb_tool_selected_index();
    v.usb_tool_error_line=pf_usb_tool_error_line();
    pf_usb_tool_selected_name(v.usb_tool_script_name,sizeof(v.usb_tool_script_name));
    pf_usb_tool_language_name(v.usb_tool_language_name,sizeof(v.usb_tool_language_name));
    pf_usb_tool_status_text(v.usb_tool_status_text,sizeof(v.usb_tool_status_text));
#else
    v.usb_tool_storage_ok=true;
#endif
    char settings_pin[WS_PIN_MAX_BYTES+1U]={0};
    size_t settings_pin_len=0;
    ws_pin_status_t settings_pin_status=WS_PIN_IDLE;
    bool settings_pin_done=false;
    portENTER_CRITICAL(&s_lock);
    bool pin_active=s_pin_active;
    if(pin_active) {
        bool visible=s_panel_ok && s_display_bright && s_displayed_epoch==s_pin_epoch;
        ws_contact_t contact={0};
        if(visible && s_touch_available && (uint32_t)(now-s_touch_polled)<=60U) {
            contact=s_touch;
            if(contact.down) contact.action=(ws_action_t)ws_pinpad_hit_test(s_touch_x,s_touch_y);
        }
        /* R18: the Settings READ/WRITE PIN is not a CTAP transaction and must
         * not inherit a stale CTAP cancel level. Transport loss still aborts
         * it through ws_board_pin_abort(); on-screen Cancel remains handled by
         * ws_pinpad_step() itself. Normal FIDO PIN keeps the original cancel. */
        bool pin_cancel=s_pin_owner==WS_PIN_OWNER_FIDO && cancel_button;
        ws_pinpad_step(&s_pinpad,now,pin_cancel,s_panel_ok && s_touch_available,contact);
        v.epoch=s_pin_epoch;
        v.pin_length=s_pinpad.length;
        v.uv_retries=s_pin_retries;
        v.pin_permissions=s_pin_permissions;
        v.pin_purpose=s_pin_owner==WS_PIN_OWNER_SETTINGS_RW?
            WS_PIN_PURPOSE_ENABLE_RW:WS_PIN_PURPOSE_FIDO;
        if(contact.valid && contact.down && s_pinpad.status==WS_PIN_EDITING)
            v.pressed_action=(uint8_t)contact.action;
        uint32_t elapsed=(uint32_t)(now-s_pinpad.started_at);
        v.seconds_left=elapsed>=s_pinpad.timeout_ms?0:(s_pinpad.timeout_ms-elapsed+999U)/1000U;

        /* A Settings-owned PIN has no FIDO worker waiting for ws_board_get_pin().
         * Consume it here, then perform the narrow verifier outside s_lock. */
        if(s_pin_owner==WS_PIN_OWNER_SETTINGS_RW && s_pinpad.status!=WS_PIN_EDITING) {
            settings_pin_status=s_pinpad.status;
            if(settings_pin_status==WS_PIN_SUBMITTED &&
               !ws_pinpad_take(&s_pinpad,settings_pin,sizeof(settings_pin),&settings_pin_len))
                settings_pin_status=WS_PIN_IO_ERROR;
            else if(settings_pin_status!=WS_PIN_SUBMITTED)
                ws_pinpad_abort(&s_pinpad,WS_PIN_IDLE);
            s_pin_active=false;
            s_pin_owner=WS_PIN_OWNER_NONE;
            s_displayed_epoch=0;
            pin_active=false;
            settings_pin_done=true;
        }
    }
    portEXIT_CRITICAL(&s_lock);
    if(settings_pin_done) {
        settings_finish_rw_pin(settings_pin_status,settings_pin,settings_pin_len,&settings,&v,now);
        ws_pinpad_zero(settings_pin,sizeof(settings_pin));
    }
    v.touch_available=s_touch_available;
#ifdef CONFIG_WS_V1_TOUCH_CONFIRM
    v.touch_enabled=true;
#endif
    uint32_t mode=led_get_mode();
    if(pin_active) {
        v.state=WS_UI_PIN;
        ws_screen_power_wake(&s_screen,now);
    } else if(s_pending) {
        v.state=WS_UI_WAITING;
        /* Presentation only: existing gesture state machine still decides. */
        portENTER_CRITICAL(&s_lock);
        bool prompt_visible=s_panel_ok && s_display_bright && s_displayed_epoch==s_epoch;
        portEXIT_CRITICAL(&s_lock);
        if(prompt_visible && s_touch_available && s_touch.valid && s_touch.down &&
           (uint32_t)(now-s_touch_polled)<=60U)
            v.pressed_action=(uint8_t)s_touch.action;
        uint32_t elapsed=(uint32_t)(now-s_presence.started_at);
        v.seconds_left=elapsed>=s_presence.timeout_ms?0:
                      (s_presence.timeout_ms-elapsed+999U)/1000U;
        ws_screen_power_wake(&s_screen,now);
    } else if(s_show_result && (uint32_t)(now-s_result_at)<1800U) {
        v.state=s_last_result;
        ws_screen_power_wake(&s_screen,now);
    } else {
        s_show_result=false;
        if(mode==MODE_SUSPENDED) v.state=WS_UI_SUSPENDED;
        else if(mode==MODE_NOT_MOUNTED) v.state=WS_UI_DISCONNECTED;
        else if(mode==MODE_PROCESSING) {
            v.state=WS_UI_PROCESSING;
            ws_screen_power_wake(&s_screen,now);
        } else v.state=WS_UI_READY;
    }
    /* Settings and the logo screensaver are reachable from idle states,
     * including USB disconnected. Authentication, processing and result states
     * evict both immediately so presentation cannot obscure a security prompt. */
    bool settings_idle_state=ws_ui_settings_allowed(v.state);
    if(!settings_idle_state) {
        settings_force_closed();
        screensaver_force_closed();
        s_launcher_open=false;s_launcher_transition=s_launcher_from=s_launcher_to=0;
        s_launcher_page_offset=s_launcher_page_from=0;s_root_page=WS_ROOT_HOME;
    } else {
        settings_transition_tick(now);
        screensaver_transition_tick(now);
        settings_page_tick(now);
        launcher_transition_tick(now);
    }
    const bool apps_visible=settings_idle_state && s_launcher_transition==255U && s_launcher_open;
    ek_apps_set_visible(apps_visible);
    EkAppsState apps;
    ek_apps_snapshot(&apps);
    if(!apps.count) s_launcher_intro=true;
    unsigned launcher_page=s_launcher_intro?0U:(unsigned)apps.page+1U;
    if(s_launcher_page!=launcher_page) {
        int direction=s_launcher_page_direction?s_launcher_page_direction:
            (launcher_page>s_launcher_page?1:-1);
        s_launcher_page_direction=0;
        s_launcher_page=(uint8_t)launcher_page;
        s_launcher_page_from=settings.animation?(int16_t)(direction*WS_SETTINGS_PAGE_SLIDE_PX):0;
        s_launcher_page_offset=s_launcher_page_from;s_launcher_page_at=now;
    }
    bool apps_active=apps_visible && apps.running;
    if(s_apps_touch_mode!=apps_active) {
        s_app_point_count=0U;
        s_apps_sample_valid=false;
        if(apps_active) s_apps_imu_retry_at=now-1000U;
    }
    s_apps_touch_mode=apps_active;
    if(apps_active && !s_apps_sensor_ok &&
       (uint32_t)(now-s_apps_imu_retry_at)>=1000U) {
        s_apps_imu_retry_at=now;
        s_apps_sensor_ok=qmi_start_accel();
        s_apps_sample_valid=false;
    }
    if(!apps_active && s_apps_sensor_ok) {
        (void)qmi_write(0x08U,0x00U);
        s_apps_sensor_ok=false;s_apps_imu_errors=0;
        s_apps_sample_valid=false;
    }
    if(apps_active && s_apps_sensor_ok &&
       (uint32_t)(now-s_apps_imu_sample_at)>=20U) {
        s_apps_imu_sample_at=now;
        uint8_t sample[6]={0};
        if(qmi_read(0x35U,sample,sizeof(sample))) {
            int16_t ax=(int16_t)((uint16_t)sample[0]|((uint16_t)sample[1]<<8));
            int16_t ay=(int16_t)((uint16_t)sample[2]|((uint16_t)sample[3]<<8));
            int16_t az=(int16_t)((uint16_t)sample[4]|((uint16_t)sample[5]<<8));
            s_apps_ax_mg=(int32_t)ax*1000/16384;
            s_apps_ay_mg=(int32_t)ay*1000/16384;
            s_apps_az_mg=(int32_t)az*1000/16384;
            s_apps_imu_errors=0;
            s_apps_sample_valid=true;
        } else {
            s_apps_sample_valid=false;
            if(++s_apps_imu_errors>=3U) s_apps_sensor_ok=false;
        }
    }

    if(s_settings_feedback!=WS_SETTINGS_FEEDBACK_NONE &&
       (uint32_t)(now-s_settings_feedback_at)>=WS_SETTINGS_FEEDBACK_MS)
        s_settings_feedback=WS_SETTINGS_FEEDBACK_NONE;

    bool settings_fresh_touch=settings_idle_state && !s_air_mouse_restart_pending && !s_manager_restart_pending &&
        !s_usb_tool_restart_pending && s_touch_available && s_touch.valid && (uint32_t)(now-s_touch_polled)<=60U;
    const bool idle_nav_stable=
        (s_settings_transition==0U || s_settings_transition==255U) &&
        (s_screensaver_transition==0U || s_screensaver_transition==255U) &&
        (s_launcher_transition==0U || s_launcher_transition==255U) &&
        s_settings_page_offset==0 && s_launcher_page_offset==0;
    if(apps_visible && apps.running) {
        EkExitEvent exit_event=ek_exit_dialog_touch(&s_app_exit_dialog,
            settings_fresh_touch,s_touch.down?s_app_point_count:0U,
            s_touch_x,s_touch_y,s_app_point_count?s_app_points[0].id:0U);
        if(exit_event==EK_EXIT_EVENT_CONFIRM) ek_apps_request(EK_APPS_STOP);
        ek_apps_set_modal(ek_exit_dialog_paused(&s_app_exit_dialog));
        if(!ek_exit_dialog_blocks_input(&s_app_exit_dialog) && exit_event!=EK_EXIT_EVENT_CONFIRM &&
           settings_fresh_touch && s_touch.down)
            ek_apps_input(s_app_points,s_app_point_count,s_apps_sample_valid,
                          s_apps_ax_mg,s_apps_ay_mg,s_apps_az_mg);
        else ek_apps_input(NULL,0,s_apps_sample_valid,
                           s_apps_ax_mg,s_apps_ay_mg,s_apps_az_mg);
        if(settings_fresh_touch && s_touch.down) ws_screen_power_wake(&s_screen,now);
        s_settings_touch_was_down=false;
    } else if(settings_fresh_touch && idle_nav_stable) {
        if(s_touch.down) {
            if(!s_settings_touch_was_down) {
                s_settings_start_x=s_settings_last_x=s_touch_x;
                s_settings_start_y=s_settings_last_y=s_touch_y;
                if(s_launcher_transition==255U && !s_launcher_intro)
                    s_settings_touch_action=ws_ui_launcher_hit_test(s_touch_x,s_touch_y);
                else if(s_settings_transition==255U)
                    s_settings_touch_action=(uint8_t)ws_ui_settings_hit_test(s_settings_page,s_touch_x,s_touch_y);
#if FIDO_V1_USB_TOOL
                else if(ws_usb_tool_enabled() && s_screensaver_transition==0U)
                    s_settings_touch_action=(uint8_t)ws_ui_usb_tool_hit_test(s_touch_x,s_touch_y);
#endif
                else s_settings_touch_action=0U;
                s_usb_tool_hold_started_at=now;s_usb_tool_hold_fired=false;
            } else {
                s_settings_last_x=s_touch_x;s_settings_last_y=s_touch_y;
            }
            s_settings_touch_was_down=true;
            unsigned mx=coord_delta(s_settings_last_x,s_settings_start_x);
            unsigned my=coord_delta(s_settings_last_y,s_settings_start_y);
            if(mx<=WS_SETTINGS_TAP_SLOP && my<=WS_SETTINGS_TAP_SLOP &&
               s_launcher_transition==255U) {
                uint8_t here=ws_ui_launcher_hit_test(s_touch_x,s_touch_y);
                if(here==s_settings_touch_action) v.launcher_pressed=here;
            } else if(mx<=WS_SETTINGS_TAP_SLOP && my<=WS_SETTINGS_TAP_SLOP &&
               s_settings_transition==255U && s_screensaver_transition==0U) {
                ws_settings_action_t here=ws_ui_settings_hit_test(s_settings_page,s_touch_x,s_touch_y);
                if((uint8_t)here==s_settings_touch_action)
                    v.settings_pressed_action=(uint8_t)here;
            }
#if FIDO_V1_USB_TOOL
            else if(mx<=WS_SETTINGS_TAP_SLOP && my<=WS_SETTINGS_TAP_SLOP &&
                    ws_usb_tool_enabled() && s_settings_transition==0U && s_screensaver_transition==0U) {
                ws_usb_tool_action_t here=ws_ui_usb_tool_hit_test(s_touch_x,s_touch_y);
                if((uint8_t)here==s_settings_touch_action){
                    v.usb_tool_pressed_action=(uint8_t)here;
                    if(here==WS_USB_TOOL_ACTION_RUN_STOP && pf_usb_tool_confirmation_pending() &&
                       !s_usb_tool_hold_fired && (uint32_t)(now-s_usb_tool_hold_started_at)>=1500U){
                        s_usb_tool_hold_fired=pf_usb_tool_confirm_stage8();
                        if(s_usb_tool_hold_fired)ws_screen_power_wake(&s_screen,now);
                    }
                }
            }
#endif
        } else if(s_settings_touch_was_down) {
            int dx=(int)s_settings_last_x-(int)s_settings_start_x;
            int dy=(int)s_settings_last_y-(int)s_settings_start_y;
            unsigned ax=coord_delta(s_settings_last_x,s_settings_start_x);
            unsigned ay=coord_delta(s_settings_last_y,s_settings_start_y);
#if FIDO_V1_USB_TOOL
            if(ws_usb_tool_enabled() && s_settings_transition==0U && s_screensaver_transition==0U &&
               ax<=WS_SETTINGS_TAP_SLOP && ay<=WS_SETTINGS_TAP_SLOP) {
                ws_usb_tool_action_t action=(ws_usb_tool_action_t)s_settings_touch_action;
                ws_usb_tool_action_t release_action=ws_ui_usb_tool_hit_test(s_settings_last_x,s_settings_last_y);
                if(action==release_action) {
                    if(action==WS_USB_TOOL_ACTION_PREV)(void)pf_usb_tool_select_delta(-1);
                    else if(action==WS_USB_TOOL_ACTION_NEXT)(void)pf_usb_tool_select_delta(1);
                    else if(action==WS_USB_TOOL_ACTION_RUN_STOP) {
                        if(s_usb_tool_hold_fired){}
                        else if(pf_usb_tool_running())pf_usb_tool_stop();
                        else if(!pf_usb_tool_confirmation_pending())
                            (void)pf_usb_tool_run_selected();
                    }
                    if(action!=WS_USB_TOOL_ACTION_NONE)ws_screen_power_wake(&s_screen,now);
                }
            } else
#endif
            if(ax>=WS_SETTINGS_SWIPE_X && ax>ay) {
                root_navigate(dx>0?1:-1,apps.catalog_ready && apps.count>0,now,settings.animation);
                ws_screen_power_wake(&s_screen,now);
            } else if(s_launcher_transition==255U && ay>=WS_SETTINGS_SWIPE_Y && ay>ax) {
                if(apps.catalog_ready && !apps.scanning && apps.count) {
                    unsigned pages=(apps.count+EK_APPS_PAGE_SIZE-1)/EK_APPS_PAGE_SIZE;
                    unsigned current=s_launcher_intro?0U:(unsigned)apps.page+1U;
                    unsigned next=(current+(dy<0?1U:pages))%(pages+1U);
                    /* Like Settings, the introduction and grids form a cycle.
                     * Direction follows the finger even across index wrap. */
                    s_launcher_page_direction=dy<0?1:-1;
                    s_launcher_intro=next==0;
                    if(next) ek_apps_select_page(next-1);
                }
            } else if(s_launcher_transition==255U &&
                      !s_launcher_intro &&
                      ax<=WS_SETTINGS_TAP_SLOP && ay<=WS_SETTINGS_TAP_SLOP) {
                uint8_t here=ws_ui_launcher_hit_test(s_settings_last_x,s_settings_last_y);
                if(here && here==s_settings_touch_action)
                    ek_apps_launch((unsigned)apps.page*EK_APPS_PAGE_SIZE+here-1);
            } else if(s_settings_transition==255U && s_screensaver_transition==0U &&
                      ay>=WS_SETTINGS_SWIPE_Y && ay>ax) {
                uint8_t next=s_settings_page;
                if(dy<0) next=(uint8_t)((next+1U)%WS_SETTINGS_PAGE_COUNT);
                else next=(uint8_t)((next+WS_SETTINGS_PAGE_COUNT-1U)%WS_SETTINGS_PAGE_COUNT);
                settings_page_change(next,dy<0?1:-1,now,settings.animation);
            } else if(s_settings_transition==255U && s_screensaver_transition==0U &&
                      ax<=WS_SETTINGS_TAP_SLOP && ay<=WS_SETTINGS_TAP_SLOP) {
                ws_settings_action_t action=(ws_settings_action_t)s_settings_touch_action;
                ws_settings_action_t release_action=ws_ui_settings_hit_test(
                    s_settings_page,s_settings_last_x,s_settings_last_y);
                if(action==release_action)
                    (void)settings_apply_action(action,&settings,&v,now);
            }
            s_settings_touch_was_down=false;
            s_settings_touch_action=0U;
        }
    } else if(!settings_fresh_touch || !idle_nav_stable) {
        s_settings_touch_was_down=false;
        s_settings_touch_action=0U;
    }
    if(!apps_visible || !apps.running) {
        ek_apps_input(NULL,0,false,0,0,0);
        ek_apps_set_modal(false);
        ek_exit_dialog_reset(&s_app_exit_dialog);
    }

    /* Re-read after local commits so the same rendered frame reflects the
     * persisted revision/value rather than the pre-tap snapshot. */
    ws_settings_get(&settings,&settings_storage_ok);
    v.brightness=settings.brightness;v.dim_brightness=settings.dim_brightness;
    v.accent_rgb=settings.accent_rgb;v.settings_revision=settings.revision;
    v.settings_storage_ok=settings_storage_ok;v.settings_animation=settings.animation;
    v.settings_dim_seconds=settings.dim_seconds;v.settings_off_seconds=settings.off_seconds;
    v.settings_presence_seconds=settings.presence_seconds;v.settings_uv_seconds=settings.uv_seconds;
    v.screensaver_transition=s_screensaver_transition;
    v.screensaver_open=s_screensaver_open;
    v.settings_transition=s_settings_transition;v.settings_page=s_settings_page;
    v.settings_page_offset=s_settings_page_offset;
    v.settings_open=s_settings_open;v.settings_feedback=s_settings_feedback;
    ek_apps_snapshot(&apps);
    v.apps_ready=apps.ready;v.apps_mounted=apps.mounted;v.apps_running=apps.running;
    v.launcher_transition=s_launcher_transition;v.launcher_page=s_launcher_page;
    v.launcher_page_offset=s_launcher_page_offset;
    v.apps_scanning=apps.scanning;v.apps_catalog_ready=apps.catalog_ready;
    v.apps_overflow=apps.overflow;v.apps_icon_valid=apps.icon_valid;
    v.apps_catalog_generation=apps.catalog_generation;
    v.apps_mount_ms=apps.mount_ms;v.apps_scan_ms=apps.scan_ms;
    v.apps_icon_ms=apps.icon_ms;v.apps_headers_read=apps.headers_read;
    v.ui_poll_gap_ms=s_poll_gap_max;
    portENTER_CRITICAL(&s_lock);v.ui_render_ms=s_render_ms_max;portEXIT_CRITICAL(&s_lock);
    memcpy(v.apps_names,apps.names,sizeof(v.apps_names));
    v.apps_exit_confirm=s_app_exit_dialog.visible;
    v.apps_exit_pressed=(uint8_t)s_app_exit_dialog.pressed;
    v.apps_exit_dragging=s_app_exit_dialog.dragging;
    v.apps_exit_progress=s_app_exit_dialog.progress;
    v.apps_count=apps.count;v.apps_selected=apps.selected;v.apps_frame=apps.frame;
    memcpy(v.apps_id,apps.id,sizeof(v.apps_id));
    memcpy(v.apps_status,apps.status,sizeof(v.apps_status));
    v.air_mouse_available=s_air_mouse_sensor_ok && s_touch_available &&
        !ws_usb_tool_enabled() && !ws_manager_drive_enabled();
    v.air_mouse_restarting=s_air_mouse_restart_pending;
    v.diagnostics_enabled=s_diagnostics_enabled;
    EkDiagnosticsExport report;ek_apps_diagnostics_export_snapshot(&report);
    v.diagnostics_export_request=report.request;v.diagnostics_export_status=(uint8_t)report.status;
    snprintf(v.diagnostics_export_message,sizeof(v.diagnostics_export_message),"%s",
        report.status==EK_DIAGNOSTICS_EXPORT_SAVED?report.filename:report.error);
    v.diagnostics_tick=s_diagnostics_enabled && s_settings_page==WS_SETTINGS_PAGE_DIAGNOSTICS &&
        s_settings_transition==255U?now/1000U:0U;
#if FIDO_V1_MANAGER_DRIVE
    v.manager_drive_available=true;
    v.manager_drive_enabled=ws_manager_drive_enabled();
    v.manager_drive_media_ready=v.manager_drive_enabled && pf_manager_drive_media_ready();
    v.manager_drive_storage_ok=ws_manager_drive_storage_ok();
    v.manager_drive_read_only=ws_manager_drive_read_only();
    v.manager_drive_restarting=s_manager_restart_pending;
#else
    v.manager_drive_storage_ok=true;
#endif
#if FIDO_V1_USB_TOOL
    v.usb_tool_available=true;
    v.usb_tool_enabled=ws_usb_tool_enabled();
    v.usb_tool_storage_ok=ws_usb_tool_storage_ok();
    v.usb_tool_layout=(uint8_t)ws_usb_tool_layout();
    v.usb_tool_media_ready=v.usb_tool_enabled && pf_usb_tool_media_ready();
    v.usb_tool_running=pf_usb_tool_running();
    v.usb_tool_restarting=s_usb_tool_restart_pending;
    (void)pf_usb_tool_confirmation_pending();
    v.usb_tool_status=pf_usb_tool_status();
    v.usb_tool_ducky_led=pf_usb_tool_ducky_led();
    v.usb_tool_storage_active=pf_usb_tool_storage_present() &&
        pf_usb_tool_storage_activity_age_ms()<=pf_usb_tool_storage_activity_timeout_ms();
    v.usb_tool_script_count=pf_usb_tool_script_count();
    v.usb_tool_selected_index=pf_usb_tool_selected_index();
    v.usb_tool_error_line=pf_usb_tool_error_line();
    pf_usb_tool_selected_name(v.usb_tool_script_name,sizeof(v.usb_tool_script_name));
    pf_usb_tool_language_name(v.usb_tool_language_name,sizeof(v.usb_tool_language_name));
    pf_usb_tool_status_text(v.usb_tool_status_text,sizeof(v.usb_tool_status_text));
#else
    v.usb_tool_storage_ok=true;
#endif
    v.manager_drive_pressed=v.settings_pressed_action==WS_SETTINGS_ACTION_MANAGER_DRIVE_TOGGLE;
    /* Static status symbols use a quiet 6.144 s halo loop (64 x 96 ms).
     * Stop advancing it once another page fully owns the screen; Settings,
     * Apps and the saver retain their independent animation clocks. */
    if(settings.animation && v.state!=WS_UI_PIN &&
       s_settings_transition!=255U && s_screensaver_transition!=255U && s_launcher_transition!=255U)
        v.animation_phase=(uint8_t)((now/96U)%64U);

    if(settings.animation && (s_settings_open || s_settings_transition!=0U ||
        (s_launcher_transition!=0U && s_launcher_intro))) {
        /* Match the screensaver's 24 ms phase step: 256 steps = 6.144 s per
         * outer Settings orbit. The gear stays anchored and fully opaque. */
        uint32_t settings_elapsed=(uint32_t)(now-s_settings_opened_at);
        v.settings_motion_phase=(uint8_t)((settings_elapsed/24U)%256U);
    }

    if(s_screensaver_open || s_screensaver_transition!=0U) {
        /* 24 ms per step preserves the existing orbit speeds. Four former
         * 256-step spans make a seamless 1024-step loop for every ring. */
        uint32_t saver_elapsed=(uint32_t)(now-s_screensaver_opened_at);
        v.screensaver_phase=(uint16_t)((saver_elapsed/24U)%1024U);
        /* R25 text fade is entry-relative so every visit begins with a gentle
         * fade-in. 40/200/40/80 ticks at 25 ms = 1.000 s fade, 5.000 s bright hold,
         * 1.000 s fade-out, 2.000 s dark hold. */
        v.screensaver_text_phase=(uint16_t)((saver_elapsed/25U)%360U);
    }
#ifdef CONFIG_WS_V1_DISPLAY
    /* USB suspend is not screen inactivity. Touch wakes the panel even while
     * the host keeps this USB interface selectively suspended. */
    bool hold_awake=s_pending || pin_active || v.state==WS_UI_PROCESSING ||
        s_manager_restart_pending || s_usb_tool_restart_pending || s_air_mouse_restart_pending ||
        v.usb_tool_running || s_settings_open || s_settings_transition!=0U ||
        s_launcher_open || s_launcher_transition!=0U ||
        s_screensaver_open || s_screensaver_transition!=0U ||
        (s_show_result && (uint32_t)(now-s_result_at)<1800U);
    ws_screen_power_tick_config(&s_screen,now,hold_awake,s_touch_available,
                         (uint32_t)settings.dim_seconds*1000U,
                         (uint32_t)settings.off_seconds*1000U);
    v.dim=s_screen.level==WS_SCREEN_DIMMED;
    v.screen_off=s_screen.level==WS_SCREEN_OFF;
#endif
    portENTER_CRITICAL(&s_lock);
    s_view=v;
    portEXIT_CRITICAL(&s_lock);
#if FIDO_V1_MANAGER_DRIVE || FIDO_V1_USB_TOOL
    /* Give the display task enough time to present RESTARTING before reset. */
    if((s_manager_restart_pending || s_usb_tool_restart_pending) &&
       (uint32_t)(now-s_usb_role_restart_at)>=700U)
        esp_restart();
#endif
    if(s_air_mouse_restart_pending && (uint32_t)(now-s_air_mouse_restart_at)>=700U)
        pf_control_restart(s_control_requested);
}

void ws_board_presence_begin(uint32_t timeout_ms)
{
    /* PF_UV_STALE_STATE_R3: a new presence request owns the UI. If an earlier PIN request was
     * abandoned during USB cancel/re-sync, invalidate its waiter now. */
    portENTER_CRITICAL(&s_lock);
    if(s_pin_active) {
        ws_pinpad_abort(&s_pinpad,WS_PIN_CANCELLED);
        s_pin_active=false;
        s_pin_owner=WS_PIN_OWNER_NONE;
        s_pin_epoch=(s_pin_epoch+1U)|0x80000000U;
        s_displayed_epoch=0;
    }
    portEXIT_CRITICAL(&s_lock);
    ws_presence_start(&s_presence,now_ms(),timeout_ms);
    ++s_epoch;
    if(s_epoch==0) ++s_epoch;
    portENTER_CRITICAL(&s_lock);
    s_pending=true;
    portEXIT_CRITICAL(&s_lock);
    s_show_result=false;
    /* Clear any sample captured before the new request. */
    memset(&s_touch,0,sizeof(s_touch));
    portENTER_CRITICAL(&s_lock);
    s_displayed_epoch=0;
    portEXIT_CRITICAL(&s_lock);
    ws_board_poll();
}

button_event_t ws_board_presence_poll(void)
{
    uint32_t now=now_ms();
    ws_contact_t boot={.valid=FIDO_V1_BOOT_CONFIRM_FALLBACK!=0,.down=gpio_get_level(WS_BOOT)==0,
                       .action=WS_ACTION_APPROVE};
    ws_contact_t touch={0};
#ifdef CONFIG_WS_V1_TOUCH_CONFIRM
    portENTER_CRITICAL(&s_lock);
    bool visible=s_panel_ok && s_display_bright && s_displayed_epoch==s_epoch;
    portEXIT_CRITICAL(&s_lock);
    if(s_touch_available && visible && (uint32_t)(now-s_touch_polled)<=60U) touch=s_touch;
#endif
    switch(ws_presence_step(&s_presence,now,cancel_button,boot,touch)) {
    case WS_UP_APPROVED: return BUTTON_EV_PRESSED;
    case WS_UP_CANCELLED: return BUTTON_EV_CANCELLED;
    case WS_UP_TIMED_OUT: return BUTTON_EV_TIMEOUT;
    default: return BUTTON_EV_NONE;
    }
}

void ws_board_presence_end(button_event_t result)
{
    portENTER_CRITICAL(&s_lock);
    s_pending=false;
    portEXIT_CRITICAL(&s_lock);
    s_presence.active=false;
    memset(&s_touch,0,sizeof(s_touch));
    s_show_result=true;
    s_result_at=now_ms();
    s_last_result=result==BUTTON_EV_PRESSED?WS_UI_CONFIRMED:
                  result==BUTTON_EV_TIMEOUT?WS_UI_TIMEOUT:WS_UI_CANCELLED;
    portENTER_CRITICAL(&s_lock);
    s_displayed_epoch=0;
    portEXIT_CRITICAL(&s_lock);
    ws_board_poll();
}

/* Returns 0 only after a complete new tap on OK. PIN is then validated by the
 * FIDO worker; collecting input alone never sets a user-verification flag. */
int ws_board_get_pin(char *out,size_t capacity,size_t *length,unsigned retries,uint8_t permissions)
{
    if(!out || !length || capacity<WS_PIN_MAX_BYTES+1U) return 3;
    ws_pinpad_zero(out,capacity); *length=0;
    uint32_t pin_timeout=ws_settings_uv_timeout_ms();
    uint32_t my_epoch=0;
    portENTER_CRITICAL(&s_lock);
    /* PF_UV_STALE_STATE_R3: a completed/abandoned presence request may leave only the board-side
     * busy flag behind if its result could not be delivered. It is safe to
     * recover only when the presence state machine is no longer active. */
    if(s_pending && !s_presence.active) {
        s_pending=false;
        memset(&s_touch,0,sizeof(s_touch));
        s_displayed_epoch=0;
    }
    /* A previous PIN worker can disappear after USB cancel/re-sync. Supersede
     * its board state before starting a fresh UV request. The epoch makes a
     * still-running old waiter notice that it no longer owns the pinpad. */
    if(s_pin_active) {
        ws_pinpad_abort(&s_pinpad,WS_PIN_CANCELLED);
        s_pin_active=false;
        s_pin_owner=WS_PIN_OWNER_NONE;
        s_pin_epoch=(s_pin_epoch+1U)|0x80000000U;
        s_displayed_epoch=0;
    }
    if(!s_initialized || !s_panel_ok || !s_touch_available || s_pending) {
        portEXIT_CRITICAL(&s_lock);return 3;
    }
    ws_pinpad_begin(&s_pinpad,now_ms(),pin_timeout);
    /* A separate epoch domain prevents a stale UP frame from enabling PIN input. */
    s_pin_epoch=(s_pin_epoch+1U)|0x80000000U;
    my_epoch=s_pin_epoch;
    s_pin_retries=retries;
    s_pin_permissions=permissions;
    s_pin_owner=WS_PIN_OWNER_FIDO;
    s_displayed_epoch=0; s_pin_active=true;
    portEXIT_CRITICAL(&s_lock);
    for(;;) {
        int result=-1;
        bool owns_pinpad=false;
        portENTER_CRITICAL(&s_lock);
        owns_pinpad=s_pin_active && s_pin_owner==WS_PIN_OWNER_FIDO && s_pin_epoch==my_epoch;
        if(!owns_pinpad) {
            result=1;
        } else {
            if(cancel_button) ws_pinpad_abort(&s_pinpad,WS_PIN_CANCELLED);
            /* Enforce the deadline even if the input poll task stops progressing. */
            if(s_pinpad.status==WS_PIN_EDITING &&
               (uint32_t)(now_ms()-s_pinpad.started_at)>=s_pinpad.timeout_ms)
                ws_pinpad_abort(&s_pinpad,WS_PIN_TIMEOUT);
            switch(s_pinpad.status) {
            case WS_PIN_SUBMITTED:
                result=ws_pinpad_take(&s_pinpad,out,capacity,length)?0:3;break;
            case WS_PIN_CANCELLED:result=1;break;
            case WS_PIN_TIMEOUT:result=2;break;
            case WS_PIN_IO_ERROR:result=3;break;
            default:break;
            }
        }
        if(result>=0 && owns_pinpad) {
            s_pin_active=false;s_pin_owner=WS_PIN_OWNER_NONE;s_displayed_epoch=0;
            ws_pinpad_abort(&s_pinpad,WS_PIN_IDLE);
        }
        portEXIT_CRITICAL(&s_lock);
        if(result>=0) return result;
        vTaskDelay(pdMS_TO_TICKS(10));
    }
}
bool ws_board_pin_pending(void)
{
    portENTER_CRITICAL(&s_lock);bool active=s_pin_active;portEXIT_CRITICAL(&s_lock);
    return active;
}
bool ws_board_settings_pin_busy(void)
{
    portENTER_CRITICAL(&s_lock);
    bool active=s_pin_active && s_pin_owner==WS_PIN_OWNER_SETTINGS_RW;
    portEXIT_CRITICAL(&s_lock);
    return active;
}
void ws_board_pin_abort(void)
{
    /* PF_UV_STALE_STATE_R3: cancellation must invalidate ownership immediately. A worker that is
     * already blocked in ws_board_get_pin() observes the epoch change and
     * exits without being able to clear a newer request. */
    portENTER_CRITICAL(&s_lock);
    if(s_pin_active) {
        ws_pinpad_abort(&s_pinpad,WS_PIN_CANCELLED);
        s_pin_active=false;
        s_pin_owner=WS_PIN_OWNER_NONE;
        s_pin_epoch=(s_pin_epoch+1U)|0x80000000U;
    }
    s_displayed_epoch=0;
    portEXIT_CRITICAL(&s_lock);
}
void ws_board_pin_feedback(int error)
{
    portENTER_CRITICAL(&s_lock);
    s_feedback_error=error;s_feedback_pending=true;
    portEXIT_CRITICAL(&s_lock);
}
