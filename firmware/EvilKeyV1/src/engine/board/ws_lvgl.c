#include "../../pf_build_config.h"
/* SPDX-License-Identifier: AGPL-3.0-or-later
 * Experimental Jet 3D frontend: shared logo/crystal pose, live hero icons and
 * gear, spatial AA, shallow LVGL surfaces. Classic source fallback is retained.
 * LVGL 8.4 presentation layer for Waveshare ESP32-S3-Touch-AMOLED-1.64 V1.
 *
 * R22 keeps the validated Pico FIDO interaction/security geometry.
 * R25 keeps the R22 zero-copy RGB565 transport, the R23 fixed
 * 252x252 screensaver core and R24 spatially anchored saver typography. Hardware
 * video from R24 exposed a phase-wrap discontinuity in the half-speed Settings
 * inner orbit plus visually noisy independent spark/glow pulses. R25 puts every
 * Settings transform on one closed 256-step loop, keeps the gear body/teeth fixed,
 * and replaces background blinking with a restrained coherent luminance breath.
 * Saver typography now holds fully visible for 5 s and fully dark for 2 s.
 * There are no software shadows, full-screen invalidates or
 * per-frame image scaling/rotation.  PIN hit geometry remains exactly the same
 * as the validated R6 implementation.
 *
 * SECURITY BOUNDARY:
 * LVGL draws controls but does not grant FIDO UP/UV. ws_board.c,
 * ws_presence.c and ws_pinpad.c keep the authoritative fresh-touch state
 * machines and use fixed geometry from ws_ui_layout.h. This prevents an LVGL
 * event, animation, stale widget state or accidental callback from becoming an
 * authentication decision.
 */
#include "ws_lvgl.h"
#include "ws_panel.h"
#include "ws_gamepad_view.h"
#include "ws_control_style.h"
#include "ws_gui_3d.h"
#include "ws_pins.h"
#include "ws_ui_layout.h"
#include "ws_gui_theme.h"
#include "../../apps/ek_service.h"
#include "../../apps/ek_render_parallel.h"
#include "../../apps/ek_exit_dialog.h"
#include "esp_err.h"
#include "esp_heap_caps.h"
#include "esp_timer.h"
#include "esp_log.h"
#include "miniz.h"
#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include "../lvgl/lvgl.h"
#include "ws_logo_assets.h"
#include "ws_unified_logo_assets.h"
#include "ws_settings_icon_asset.h"
#include "../../pf_firmware_version.h"

#define DRAW_PIXELS(rows) ((uint32_t)WS_LCD_WIDTH*(uint32_t)(rows))
#if LV_COLOR_DEPTH != 16 || LV_COLOR_16_SWAP != 1
#error "R22 requires RGB565 with LV_COLOR_16_SWAP=1 for zero-copy panel DMA"
#endif
#define RGB24_DEFAULT WS_CONTROL_ACCENT_DEFAULT
static const char *TAG="ws_lvgl";

/* Match the production Pico FIDO palette used by the previous renderer. */
#define COL_BG      WS_CONTROL_BG
#define COL_TEXT    WS_CONTROL_TEXT
#define COL_MUTED   WS_CONTROL_MUTED
#define COL_FAINT   0x7F8B93UL
#define COL_PANEL   WS_CONTROL_PANEL
#define COL_PANEL2  WS_CONTROL_PANEL2
#define COL_BORDER  WS_CONTROL_BORDER
#define COL_INK     WS_CONTROL_INK
#define COL_GLASS   0x0B1114UL
#define COL_WARN    WS_CONTROL_WARN
#define COL_BAD     WS_CONTROL_BAD
#define COL_BAD_DIM 0x40212BUL
#define COL_LED_RED 0xFF435AUL
#define COL_LED_GREEN 0x36F5B8UL
#define SAVER_LOGO_SIZE 200
#define SAVER_LOGO_BASE 26

#define ICON_PARTS_MAX 16U
#define ICON_COUNT 10U
#define SETTINGS_ROWS 2U
#define SETTINGS_DOTS 10U

typedef enum {
    HERO_KEY=0,
    HERO_SPINNER,
    HERO_TOUCH,
    HERO_CHECK,
    HERO_CROSS,
    HERO_CLOCK,
    HERO_LOCK,
    HERO_MOON,
    HERO_WARNING,
    HERO_USB
} hero_icon_id_t;

typedef struct {
    lv_obj_t *root;
    lv_obj_t *part[ICON_PARTS_MAX];
    uint8_t count;
} ws_icon_t;

typedef struct {
    lv_obj_t *card;
    lv_obj_t *title;
    lv_obj_t *minus;
    lv_obj_t *minus_label;
    lv_obj_t *value;
    lv_obj_t *value_label;
    lv_obj_t *plus;
    lv_obj_t *plus_label;
} ws_setting_row_t;

typedef struct {
    lv_obj_t *pulse;
    lv_obj_t *lens;
    lv_obj_t *core;
    lv_obj_t *glint;
    lv_opa_t pulse_opa;
    lv_opa_t lens_opa;
    lv_opa_t core_opa;
    lv_opa_t glint_opa;
    bool visual_valid;
} ws_tool_led_t;

static lv_disp_draw_buf_t s_draw_buf;
static lv_disp_drv_t s_disp_drv;
static lv_color_t *s_pixels_a;
static lv_color_t *s_pixels_b;
/* External composition buffers can preserve 2 x 64 rows after USB has
 * reserved internal SRAM. Only these two 16-row staging strips reach DMA. */
static lv_color_t *s_staging[2];
#define STAGING_ROWS 16U
static lv_color_t *s_rotation_dma;
static size_t s_rotation_bytes;
static uint32_t s_draw_pixels;
static esp_err_t s_flush_error=ESP_OK;
static bool s_ready;
static bool s_3d_available;
static lv_img_dsc_t s_3d_sources[WS_3D_CHANNELS];
static lv_obj_t *s_3d_objects[WS_3D_CHANNELS];
static uint32_t s_3d_generations[WS_3D_CHANNELS];
static uint32_t s_3d_deadlines[WS_3D_CHANNELS],s_3d_accents[WS_3D_CHANNELS],s_3d_icons[WS_3D_CHANNELS];
static uint32_t s_render_tick,s_frame_id;
static bool s_3d_force_frame;
typedef struct { lv_disp_drv_t *drv; uint32_t frame; bool final; } frame_flush_t;
static frame_flush_t s_frame_flush[2];
static unsigned s_frame_flush_slot;
typedef struct { lv_obj_t *glow; uint32_t accent; int rotation[3]; uint8_t opacity[8]; bool valid; } halo_cache_t;
static halo_cache_t s_halo_cache[2];
static uint16_t *s_apps_pixels;
static uint32_t s_apps_frame;
static uint8_t *s_launcher_pixels;
static uint32_t s_launcher_generation;
static lv_img_dsc_t s_launcher_img[EK_APPS_PAGE_SIZE];
static lv_img_dsc_t s_apps_img={
    .header={.cf=LV_IMG_CF_TRUE_COLOR,.always_zero=0,.reserved=0,
             .w=EK_APPS_WIDTH,.h=EK_APPS_HEIGHT},
    .data_size=EK_APPS_PIXELS*sizeof(uint16_t),.data=NULL
};

/* One current indexed frame per layer. These are LVGL image sources, not DMA
 * buffers. Prefer PSRAM so the validated internal DMA draw buffers retain
 * their RAM margin; fall back to internal 8-bit RAM when PSRAM is unavailable. */
#define WS_UNIFIED_MINT_BUFFER_SIZE \
    (WS_UNIFIED_PALETTE_BYTES+WS_UNIFIED_MINT_W*WS_UNIFIED_MINT_H)
#define WS_UNIFIED_CRYSTAL_BUFFER_SIZE \
    (WS_UNIFIED_PALETTE_BYTES+WS_UNIFIED_CRYSTAL_W*WS_UNIFIED_CRYSTAL_H)
static uint8_t *s_unified_mint_pixels;
static uint8_t *s_unified_crystal_pixels;
static lv_img_dsc_t s_unified_mint_img={
    .header={.cf=LV_IMG_CF_INDEXED_8BIT,.always_zero=0,.reserved=0,
             .w=WS_UNIFIED_MINT_W,.h=WS_UNIFIED_MINT_H},
    .data_size=WS_UNIFIED_MINT_BUFFER_SIZE,.data=NULL
};
static lv_img_dsc_t s_unified_crystal_img={
    .header={.cf=LV_IMG_CF_INDEXED_8BIT,.always_zero=0,.reserved=0,
             .w=WS_UNIFIED_CRYSTAL_W,.h=WS_UNIFIED_CRYSTAL_H},
    .data_size=WS_UNIFIED_CRYSTAL_BUFFER_SIZE,.data=NULL
};
static uint16_t s_unified_phase=256U;
static uint32_t s_unified_accent=0xFFFFFFFFUL;
/* The decoder needs about 11 KB. Keep it off ws_display's stack and out of
 * internal RAM: TinyUSB starts after LVGL and needs that memory to enumerate. */
static tinfl_decompressor *s_unified_inflater;

static bool inflate_unified_frame(uint8_t *output,size_t output_size,
                                  const uint8_t *input,size_t input_size)
{
    if(!s_unified_inflater) return false;
    tinfl_init(s_unified_inflater);
    size_t read_size=input_size;
    size_t write_size=output_size;
    const tinfl_status status=tinfl_decompress(
        s_unified_inflater,input,&read_size,output,output,&write_size,
        TINFL_FLAG_PARSE_ZLIB_HEADER|TINFL_FLAG_USING_NON_WRAPPING_OUTPUT_BUF);
    return status==TINFL_STATUS_DONE && read_size==input_size &&
           write_size==output_size;
}

static uint8_t unified_tint(uint8_t value,uint8_t accent,uint8_t reference)
{
    const unsigned scaled=((unsigned)value*(unsigned)accent+(unsigned)reference/2U)/
                          (unsigned)reference;
    return (uint8_t)(scaled>255U?255U:scaled);
}

static bool decode_unified_logo(uint16_t phase,uint32_t accent)
{
    const uint16_t local=phase&255U;
    const bool image_changed=local!=s_unified_phase;
    if(!image_changed && accent==s_unified_accent) return true;
    const ws_unified_mint_frame_t *mint=&ws_unified_mint_frames[local];
    const ws_unified_crystal_frame_t *crystal=&ws_unified_crystal_frames[local];
    if(image_changed) {
        const bool mint_ok=inflate_unified_frame(
            s_unified_mint_pixels+WS_UNIFIED_PALETTE_BYTES,
            WS_UNIFIED_MINT_W*WS_UNIFIED_MINT_H,
            ws_unified_mint_data+mint->offset,mint->length);
        const bool crystal_ok=inflate_unified_frame(
            s_unified_crystal_pixels+WS_UNIFIED_PALETTE_BYTES,
            WS_UNIFIED_CRYSTAL_W*WS_UNIFIED_CRYSTAL_H,
            ws_unified_crystal_data+crystal->offset,crystal->length);
        if(!mint_ok || !crystal_ok) {
            memset(s_unified_mint_pixels,0,WS_UNIFIED_PALETTE_BYTES);
            memset(s_unified_crystal_pixels,0,WS_UNIFIED_PALETTE_BYTES);
            s_unified_phase=256U;
            ESP_LOGE(TAG,"unified logo frame decode failed at %u",(unsigned)local);
            return false;
        }
        s_unified_phase=local;
    }
    const uint8_t ar=(uint8_t)(accent>>16);
    const uint8_t ag=(uint8_t)(accent>>8);
    const uint8_t ab=(uint8_t)accent;
    for(unsigned i=0;i<32U;++i) {
        const uint8_t *p=mint->palette_rgba+4U*i;
        uint8_t r=p[0],g=p[1],b=p[2];
        if((mint->mint_tint_mask&(1UL<<i))!=0U) {
            r=unified_tint(r,ar,77U);
            g=unified_tint(g,ag,227U);
            b=unified_tint(b,ab,193U);
        }
        uint8_t *out=s_unified_mint_pixels+4U*i;
        out[0]=b;out[1]=g;out[2]=r;out[3]=p[3];
    }
    for(unsigned i=0;i<16U;++i) {
        const uint8_t *p=crystal->palette_rgba+4U*i;
        uint8_t *out=s_unified_crystal_pixels+4U*i;
        out[0]=p[2];out[1]=p[1];out[2]=p[0];out[3]=p[3];
    }
    s_unified_accent=accent;
    lv_img_cache_invalidate_src(&s_unified_mint_img);
    lv_img_cache_invalidate_src(&s_unified_crystal_img);
    return true;
}

/* Static line geometry. lv_line_set_points stores the pointer, therefore the
 * arrays intentionally have static lifetime. Coordinates are local to the
 * corresponding icon root. */
static const lv_point_t P_CHECK_A[]={{16,35},{29,49}};
static const lv_point_t P_CHECK_B[]={{29,49},{55,18}};
static const lv_point_t P_CROSS_A[]={{18,18},{52,52}};
static const lv_point_t P_CROSS_B[]={{52,18},{18,52}};
static const lv_point_t P_CLOCK_H[]={{35,35},{35,20}};
static const lv_point_t P_CLOCK_M[]={{35,35},{47,43}};
static const lv_point_t P_LOCK_KEY[]={{35,40},{35,51}};
static const lv_point_t P_WARN_STEM[]={{35,15},{35,43}};
static const lv_point_t P_USB_CABLE[]={{35,46},{35,61}};
static const lv_point_t P_TOUCH_RAY_A[]={{52,48},{61,55}};
static const lv_point_t P_TOUCH_RAY_B[]={{58,35},{68,35}};
static const lv_point_t P_TOUCH_RAY_C[]={{47,57},{49,67}};
static const lv_point_t P_BACKSPACE_OUTLINE[]={{18,30},{30,18},{61,18},{61,42},{30,42},{18,30}};
static const lv_point_t P_BACKSPACE_X1[]={{38,25},{50,37}};
static const lv_point_t P_BACKSPACE_X2[]={{50,25},{38,37}};

typedef struct {
    lv_obj_t *screen;
    lv_obj_t *main_group;

    lv_obj_t *brand_group;
    ws_icon_t brand_key;
    lv_obj_t *brand;

    lv_obj_t *hero;
    lv_obj_t *hero_outer;
    lv_obj_t *hero_mid;
    lv_obj_t *hero_inner;
    lv_obj_t *hero_orbit;
    lv_obj_t *hero_glint;
    ws_icon_t icons[ICON_COUNT];
    lv_obj_t *spinner_arc_a;
    lv_obj_t *spinner_arc_b;
    lv_obj_t *progress_dot[3];
    lv_obj_t *result_flare;

    lv_obj_t *title;
    lv_obj_t *line1;
    lv_obj_t *line2;
    lv_obj_t *usb;
    lv_obj_t *countdown;

    lv_obj_t *approve;
    lv_obj_t *approve_label;
    lv_obj_t *cancel;
    lv_obj_t *cancel_label;

    lv_obj_t *tool_prev;
    lv_obj_t *tool_prev_label;
    lv_obj_t *tool_run;
    lv_obj_t *tool_run_label;
    lv_obj_t *tool_next;
    lv_obj_t *tool_next_label;

    lv_obj_t *tool_led_group;
    ws_tool_led_t tool_led_red;
    ws_tool_led_t tool_led_green;

    lv_obj_t *settings_swipe;

    lv_obj_t *screensaver_group;
    lv_obj_t *screensaver_core;
    lv_obj_t *screensaver_outer;
    lv_obj_t *screensaver_mid;
    lv_obj_t *screensaver_inner;
    lv_obj_t *screensaver_orbit_a;
    lv_obj_t *screensaver_orbit_b;
    lv_obj_t *screensaver_orbit_c;
    lv_obj_t *screensaver_logo_glow;
    lv_obj_t *screensaver_logo_ghost;
    lv_obj_t *screensaver_logo;
    lv_obj_t *screensaver_glitch_cover[2];
    lv_obj_t *screensaver_glitch_slice[2];
    lv_obj_t *screensaver_glitch_scan;
    lv_obj_t *screensaver_logo_white;
    lv_obj_t *screensaver_text_group;
    lv_obj_t *screensaver_brand;
    lv_obj_t *screensaver_caption;
    lv_obj_t *screensaver_hint;
    lv_obj_t *screensaver_spark[4];

    lv_obj_t *settings_group;
    lv_obj_t *settings_content;
    lv_obj_t *settings_glow;
    lv_obj_t *settings_orbit;
    lv_obj_t *settings_orbit_inner;
    lv_obj_t *settings_glint;
    lv_obj_t *settings_spark[4];
    ws_icon_t settings_gear;
    lv_obj_t *settings_title;
    lv_obj_t *settings_subtitle;
    ws_setting_row_t settings_row[SETTINGS_ROWS];
    lv_obj_t *settings_swatch;
    lv_obj_t *diagnostics_card;
    lv_obj_t *diagnostics_title;
    lv_obj_t *diagnostics_value;
    lv_obj_t *diagnostics_memory;
    lv_obj_t *diagnostics_save;
    lv_obj_t *diagnostics_save_label;
    lv_obj_t *air_mouse_info_card;
    lv_obj_t *air_mouse_info_label;
    lv_obj_t *settings_footer;
    lv_obj_t *settings_return;
    lv_obj_t *settings_dot[SETTINGS_DOTS];
    lv_obj_t *apps_group;
    lv_obj_t *launcher_group,*launcher_content,*launcher_status,*launcher_counter;
    lv_obj_t *launcher_header,*launcher_intro,*launcher_glow,*launcher_orbit,*launcher_orbit_inner,*launcher_glint;
    lv_obj_t *launcher_spark[4];
    lv_obj_t *launcher_tiles[9],*launcher_count;
    lv_obj_t *launcher_cell[EK_APPS_PAGE_SIZE],*launcher_icon[EK_APPS_PAGE_SIZE];
    lv_obj_t *launcher_name[EK_APPS_PAGE_SIZE],*launcher_dot[9];
    lv_obj_t *apps_image;
    lv_obj_t *apps_exit_overlay;
    lv_obj_t *apps_exit_no;
    lv_obj_t *apps_exit_yes;
    lv_obj_t *apps_exit_grip,*apps_exit_arrow,*apps_exit_pull,*apps_exit_dim;
    lv_obj_t *apps_exit_caption,*apps_exit_fill,*apps_exit_percent;

    lv_obj_t *air_mouse_group;
    lv_obj_t *air_mouse_move;
    lv_obj_t *air_mouse_title;
    lv_obj_t *air_mouse_status;
    lv_obj_t *air_mouse_pair,*air_mouse_forget,*air_mouse_ble_dialog;
    lv_obj_t *air_mouse_hint;
    lv_obj_t *air_mouse_exit;
    lv_obj_t *air_mouse_exit_progress;
    lv_obj_t *air_mouse_calibrate;
    lv_obj_t *air_mouse_calibrate_progress;
    lv_obj_t *air_mouse_left;
    lv_obj_t *air_mouse_left_label;
    lv_obj_t *air_mouse_drag,*air_mouse_drag_label;
    lv_obj_t *air_mouse_right;
    lv_obj_t *air_mouse_right_label;
    lv_obj_t *air_mouse_scroll;
    lv_obj_t *air_mouse_settings_group;
    lv_obj_t *air_mouse_sensitivity_minus;
    lv_obj_t *air_mouse_sensitivity_plus;
    lv_obj_t *air_mouse_sensitivity_value;
    lv_obj_t *air_mouse_invert;
    lv_obj_t *air_mouse_invert_value;
    lv_obj_t *air_mouse_settings_calibrate;
    lv_obj_t *air_mouse_settings_calibrate_progress;
    lv_obj_t *air_mouse_settings_back;

    lv_obj_t *pin_group;
    lv_obj_t *pin_title;
    lv_obj_t *pin_scope;
    lv_obj_t *pin_field;
    lv_obj_t *pin_dot[10];
    lv_obj_t *pin_length;
    lv_obj_t *pin_tries;
    lv_obj_t *pin_seconds;
    lv_obj_t *keys[12];
    lv_obj_t *key_press_ring[12];
    lv_obj_t *key_labels[12];
    ws_icon_t backspace;
    lv_obj_t *pin_cancel;
    lv_obj_t *pin_cancel_label;
} ws_widgets_t;
static ws_widgets_t ui;
static uint8_t s_screensaver_text_opa=0xFFU;

static lv_color_t color(uint32_t rgb) { return lv_color_hex(rgb & 0xFFFFFFUL); }

static void hidden(lv_obj_t *o,bool yes)
{
    if(!o) return;
    const bool is_hidden=lv_obj_has_flag(o,LV_OBJ_FLAG_HIDDEN);
    if(yes && !is_hidden) lv_obj_add_flag(o,LV_OBJ_FLAG_HIDDEN);
    else if(!yes && is_hidden) lv_obj_clear_flag(o,LV_OBJ_FLAG_HIDDEN);
}

static void base_obj(lv_obj_t *o,int x,int y,int w,int h)
{
    lv_obj_set_pos(o,x,y);
    lv_obj_set_size(o,w,h);
    lv_obj_clear_flag(o,LV_OBJ_FLAG_SCROLLABLE);
    lv_obj_clear_flag(o,LV_OBJ_FLAG_CLICKABLE);
    lv_obj_set_style_pad_all(o,0,0);
    lv_obj_set_style_border_width(o,0,0);
    lv_obj_set_style_outline_width(o,0,0);
    lv_obj_set_style_shadow_width(o,0,0);
    lv_obj_set_style_bg_opa(o,LV_OPA_TRANSP,0);
}

static lv_obj_t *group_at(lv_obj_t *parent,int x,int y,int w,int h)
{
    lv_obj_t *o=lv_obj_create(parent);
    base_obj(o,x,y,w,h);
    return o;
}

static lv_obj_t *label(lv_obj_t *parent,const char *text,const lv_font_t *font,
                       int x,int y,int w,int h)
{
    lv_obj_t *o=lv_label_create(parent);
    lv_label_set_text(o,text);
    lv_label_set_long_mode(o,LV_LABEL_LONG_CLIP);
    lv_obj_set_pos(o,x,y);
    lv_obj_set_size(o,w,h);
    lv_obj_clear_flag(o,LV_OBJ_FLAG_CLICKABLE);
    lv_obj_set_style_text_font(o,font,0);
    lv_obj_set_style_text_color(o,color(COL_TEXT),0);
    lv_obj_set_style_text_align(o,LV_TEXT_ALIGN_CENTER,0);
    return o;
}

/* Jet owns only the decorative image sources. LVGL remains the sole display
 * owner and retains native-resolution typography and security hit geometry. */
static bool jet_image_due(unsigned channel)
{
    return s_3d_available && (!s_3d_sources[channel].data || (int32_t)(s_render_tick-s_3d_deadlines[channel])>=0);
}
static void update_3d_image(unsigned channel,uint16_t phase,uint32_t accent,unsigned icon)
{
    ws_gui_3d_frame_t frame;
    if(channel!=WS_3D_HERO && s_3d_sources[channel].data && !s_3d_force_frame &&
       s_3d_accents[channel]==accent && s_3d_icons[channel]==icon &&
       !jet_image_due(channel))return;
    if(!s_3d_available || !s_3d_objects[channel] ||
       !ws_gui_3d_render(channel,phase,accent,icon,&frame)) return;
    const bool fresh=!s_3d_sources[channel].data;
    if(fresh || s_3d_force_frame || s_3d_accents[channel]!=accent || s_3d_icons[channel]!=icon)
        s_3d_deadlines[channel]=s_render_tick+33000U;
    else {
        s_3d_deadlines[channel]+=33000U;
        if((int32_t)(s_render_tick-s_3d_deadlines[channel])>=0)s_3d_deadlines[channel]=s_render_tick+33000U;
    }
    s_3d_accents[channel]=accent;s_3d_icons[channel]=icon;
    if(!fresh && s_3d_generations[channel]==frame.generation)return;
    lv_img_dsc_t *d=&s_3d_sources[channel];
    const bool first=!d->data;
    d->header.cf=LV_IMG_CF_TRUE_COLOR_ALPHA;d->header.w=frame.width;d->header.h=frame.height;
    d->data_size=(uint32_t)frame.width*frame.height*3U;d->data=frame.pixels;
    s_3d_generations[channel]=frame.generation;
    if(first)lv_img_set_src(s_3d_objects[channel],d);
    lv_obj_invalidate(s_3d_objects[channel]);
}
static void create_3d_image(unsigned channel,lv_obj_t *parent,int x,int y)
{
    if(!s_3d_available)return;
    s_3d_objects[channel]=lv_img_create(parent);
    lv_obj_clear_flag(s_3d_objects[channel],LV_OBJ_FLAG_CLICKABLE);
    lv_obj_set_pos(s_3d_objects[channel],x,y);
    update_3d_image(channel,0,RGB24_DEFAULT,channel==WS_3D_HERO?HERO_KEY:0);
}
static void surface_depth(lv_obj_t *o,uint32_t bg)
{
    /* Two RGB565 gradient stops and an inset highlight convey shallow depth.
     * No blur/shadow buffers, perspective text or transformed touch targets. */
    uint32_t bottom=(((bg>>16)&255U)*3U/4U)<<16 | (((bg>>8)&255U)*3U/4U)<<8 | (bg&255U)*3U/4U;
    lv_obj_set_style_bg_color(o,color(bg),0);
    lv_obj_set_style_bg_grad_color(o,color(bottom),0);
    lv_obj_set_style_bg_grad_dir(o,LV_GRAD_DIR_VER,0);
    lv_obj_set_style_bg_main_stop(o,0,0);
    lv_obj_set_style_bg_grad_stop(o,255,0);
}

static lv_obj_t *card(lv_obj_t *parent,int x,int y,int w,int h,int radius)
{
    lv_obj_t *o=lv_obj_create(parent);
    base_obj(o,x,y,w,h);
    lv_obj_set_style_radius(o,radius,0);
    lv_obj_set_style_bg_opa(o,LV_OPA_COVER,0);
    lv_obj_set_style_bg_color(o,color(COL_PANEL),0);
    lv_obj_set_style_border_width(o,1,0);
    lv_obj_set_style_border_color(o,color(COL_BORDER),0);
    surface_depth(o,COL_PANEL);
    return o;
}

static lv_obj_t *circle(lv_obj_t *parent,int x,int y,int d,uint32_t fill,
                        lv_opa_t fill_opa,uint32_t border,int border_w,
                        lv_opa_t border_opa)
{
    lv_obj_t *o=lv_obj_create(parent);
    base_obj(o,x,y,d,d);
    lv_obj_set_style_radius(o,d/2,0);
    lv_obj_set_style_bg_color(o,color(fill),0);
    lv_obj_set_style_bg_opa(o,fill_opa,0);
    lv_obj_set_style_border_color(o,color(border),0);
    lv_obj_set_style_border_width(o,border_w,0);
    lv_obj_set_style_border_opa(o,border_opa,0);
    return o;
}

static lv_obj_t *arc_obj(lv_obj_t *parent,int x,int y,int d,uint32_t rgb,
                         int base_width,int indicator_width,lv_opa_t base_opa,
                         lv_opa_t indicator_opa,int start,int end)
{
    lv_obj_t *o=lv_arc_create(parent);
    lv_obj_set_pos(o,x,y);
    lv_obj_set_size(o,d,d);
    lv_obj_clear_flag(o,LV_OBJ_FLAG_SCROLLABLE);
    lv_obj_clear_flag(o,LV_OBJ_FLAG_CLICKABLE);
    lv_obj_remove_style(o,NULL,LV_PART_KNOB);
    lv_arc_set_bg_angles(o,0,360);
    lv_arc_set_angles(o,start,end);
    lv_obj_set_style_arc_color(o,color(rgb),LV_PART_MAIN);
    lv_obj_set_style_arc_width(o,base_width,LV_PART_MAIN);
    lv_obj_set_style_arc_opa(o,base_opa,LV_PART_MAIN);
    lv_obj_set_style_arc_rounded(o,true,LV_PART_MAIN);
    lv_obj_set_style_arc_color(o,color(rgb),LV_PART_INDICATOR);
    lv_obj_set_style_arc_width(o,indicator_width,LV_PART_INDICATOR);
    lv_obj_set_style_arc_opa(o,indicator_opa,LV_PART_INDICATOR);
    lv_obj_set_style_arc_rounded(o,true,LV_PART_INDICATOR);
    return o;
}

static lv_obj_t *line_obj(lv_obj_t *parent,const lv_point_t *points,uint16_t count,
                          int x,int y,int width,uint32_t rgb)
{
    lv_obj_t *o=lv_line_create(parent);
    lv_line_set_points(o,points,count);
    lv_obj_set_pos(o,x,y);
    lv_obj_clear_flag(o,LV_OBJ_FLAG_CLICKABLE);
    lv_obj_set_style_line_width(o,width,0);
    lv_obj_set_style_line_color(o,color(rgb),0);
    lv_obj_set_style_line_rounded(o,true,0);
    return o;
}

static void set_card(lv_obj_t *o,uint32_t bg,uint32_t border,int border_width)
{
    lv_obj_set_style_bg_color(o,color(bg),0);
    lv_obj_set_style_bg_opa(o,LV_OPA_COVER,0);
    lv_obj_set_style_border_color(o,color(border),0);
    lv_obj_set_style_border_width(o,border_width,0);
    if(bg==COL_PANEL || bg==COL_PANEL2) surface_depth(o,bg);
    else lv_obj_set_style_bg_grad_dir(o,LV_GRAD_DIR_NONE,0);
}

static void set_card_flat(lv_obj_t *o,uint32_t bg,uint32_t border,int border_width)
{
    /* Settings state badges reuse gradient-capable controls. Reset both stops
     * so a solid accent/warning/error fill cannot inherit a dark gradient. */
    set_card(o,bg,border,border_width);
    lv_obj_set_style_bg_grad_color(o,color(bg),0);
}

static void set_text(lv_obj_t *o,const char *text,uint32_t rgb)
{
    lv_label_set_text(o,text);
    lv_obj_set_style_text_color(o,color(rgb),0);
}

static void icon_init(ws_icon_t *icon,lv_obj_t *parent,int x,int y,int w,int h)
{
    memset(icon,0,sizeof(*icon));
    icon->root=group_at(parent,x,y,w,h);
}

static void icon_add(ws_icon_t *icon,lv_obj_t *part)
{
    if(icon->count<ICON_PARTS_MAX) icon->part[icon->count++]=part;
}

static void icon_tint(ws_icon_t *icon,uint32_t rgb)
{
    for(uint8_t i=0;i<icon->count;++i) {
        lv_obj_t *p=icon->part[i];
        lv_obj_set_style_bg_color(p,color(rgb),0);
        lv_obj_set_style_border_color(p,color(rgb),0);
        lv_obj_set_style_line_color(p,color(rgb),0);
        lv_obj_set_style_text_color(p,color(rgb),0);
        lv_obj_set_style_img_recolor(p,color(rgb),0);
        lv_obj_set_style_img_recolor_opa(p,LV_OPA_COVER,0);
    }
}

static void icon_show_only(hero_icon_id_t id)
{
    for(unsigned i=0;i<ICON_COUNT;++i) hidden(ui.icons[i].root,i!=(unsigned)id);
}

static void flush_wait(lv_disp_drv_t *drv)
{
    
    uint32_t start=(uint32_t)esp_timer_get_time();
    /* Same active wait as LVGL8.4's default; measure it once without changing
     * DMA ownership, scheduling or the existing completion/error policy. */
    while(drv->draw_buf->flushing) {}
    ws_gui_3d_record_lvgl_wait((uint32_t)esp_timer_get_time()-start);
    
}
static void flush_done(void *ctx)
{
    /* esp_lcd invokes this from the color-DMA completion callback. LVGL 8.4
     * waits for this signal before reusing the single DMA draw buffer. */
    frame_flush_t *stamp=(frame_flush_t *)ctx;
    if(stamp->final)ws_gui_3d_frame_complete(stamp->frame,(uint32_t)esp_timer_get_time());
    lv_disp_flush_ready(stamp->drv);
}
static void staging_done(void *ctx) { (void)ctx; }

static void controls_rounder_cb(lv_disp_drv_t *drv,lv_area_t *area)
{
    /* CO5300's address windows start even and end odd (Waveshare V1 demo).
     * Full logical rows also prevent LVGL's rotation scratch from splitting
     * narrow dirty rectangles into odd-height chunks. The BLE draw buffer
     * holds 9 landscape rows; LVGL rounds that down to 8, producing aligned
     * physical columns in either orientation without another RAM allocation. */
    /* AirMouse needs the same window alignment without rotation: narrow
     * label/card invalidations can otherwise produce odd stripe boundaries. */
    const bool landscape=drv->rotated==LV_DISP_ROT_90 || drv->rotated==LV_DISP_ROT_270;
    area->x1=0;
    area->x2=(landscape?WS_LCD_HEIGHT:WS_LCD_WIDTH)-1;
    area->y1&=~1;
    area->y2|=1;
}

static void flush_cb(lv_disp_drv_t *drv,const lv_area_t *area,lv_color_t *px)
{
    if(!area || !px) {
        s_flush_error=ESP_ERR_INVALID_ARG;
        lv_disp_flush_ready(drv);
        return;
    }
    esp_err_t pending=ws_panel_wait_idle(500U);
    if(pending!=ESP_OK){s_flush_error=pending;lv_disp_flush_ready(drv);return;}
    frame_flush_t *stamp=&s_frame_flush[s_frame_flush_slot++&1U];
    *stamp=(frame_flush_t){drv,s_frame_id,lv_disp_flush_is_last(drv)};
    const int32_t w=area->x2-area->x1+1;
    const int32_t h=area->y2-area->y1+1;
    if(w<=0 || h<=0 || area->x1<0 || area->y1<0 ||
       area->x2>=WS_LCD_WIDTH || area->y2>=WS_LCD_HEIGHT) {
        s_flush_error=ESP_ERR_INVALID_ARG;
        lv_disp_flush_ready(drv);
        return;
    }
    if(s_staging[0]) {
        esp_err_t idle=ws_panel_wait_idle(500U);
        if(idle!=ESP_OK){s_flush_error=idle;lv_disp_flush_ready(drv);return;}
        /* Full-width, even address windows are guaranteed by the rounder.
         * Alternate scratch ownership: submit N only after N-1 completed;
         * copy into the other strip while N-1 is still being transmitted. */
        for(int row=0,slot=0;row<h;slot^=1) {
            const int rows=h-row>(int)STAGING_ROWS?(int)STAGING_ROWS:h-row;
            memcpy(s_staging[slot],px+(size_t)row*w,(size_t)rows*w*sizeof(*px));
            const bool last=row+rows==h;
            esp_err_t err=ws_panel_flush_async((uint16_t)area->x1,(uint16_t)(area->y1+row),
                (uint16_t)area->x2,(uint16_t)(area->y1+row+rows-1),
                (const uint16_t *)s_staging[slot],(size_t)w*rows,
                last?flush_done:staging_done,last?stamp:NULL);
            if(err!=ESP_OK){s_flush_error=err;lv_disp_flush_ready(drv);return;}
            ws_gui_3d_frame_flush(s_frame_id,(uint32_t)((size_t)w*rows*2U));
            row+=rows;
        }
        return;
    }
    /* LVGL's 90-degree scratch buffer belongs to its PSRAM pool. Only
     * internal DMA SRAM may reach the panel transport. Keep the copy alive
     * until the asynchronous transfer completes, including square rotations. */
    if(drv->sw_rotate && drv->rotated!=LV_DISP_ROT_NONE) {
        const size_t bytes=(size_t)w*(size_t)h*sizeof(*px);
        if((area->x1&1) || (area->y1&1) || !(area->x2&1) || !(area->y2&1)) {
            s_flush_error=ESP_ERR_INVALID_ARG;
            lv_disp_flush_ready(drv);return;
        }
        esp_err_t idle=ws_panel_wait_idle(500U);
        if(idle!=ESP_OK || !s_rotation_dma || bytes>s_rotation_bytes) {
            s_flush_error=idle!=ESP_OK?idle:ESP_ERR_INVALID_SIZE;
            lv_disp_flush_ready(drv);return;
        }
        memcpy(s_rotation_dma,px,bytes);
        px=s_rotation_dma;
    }
    esp_err_t err=ws_panel_flush_async((uint16_t)area->x1,(uint16_t)area->y1,
                                       (uint16_t)area->x2,(uint16_t)area->y2,
                                       (const uint16_t *)px,(size_t)w*(size_t)h,
                                       flush_done,stamp);
    if(err==ESP_OK)ws_gui_3d_frame_flush(s_frame_id,(uint32_t)((size_t)w*h*2U));
    if(err!=ESP_OK) {
        if(s_flush_error==ESP_OK) s_flush_error=err;
        /* No DMA owns this buffer when queueing failed. */
        lv_disp_flush_ready(drv);
    }
}

static const char *scope_text(uint8_t p)
{
    switch(p) {
    case 1:return "Create credential";
    case 2:return "Sign in";
    case 3:return "Register / sign in";
    case 4:return "Manage credentials";
    case 16:return "Credential data";
    case 32:return "Device settings";
    case 64:return "Read credentials";
    case 0:return "Verify identity";
    default:return "Multiple permissions";
    }
}

static void build_brand(void)
{
    /* The larger EvilKey mark has an accent body and a fixed white diamond. */
    ui.brand_group=group_at(ui.main_group,0,14,WS_LCD_WIDTH,34);
    icon_init(&ui.brand_key,ui.brand_group,58,0,34,34);
    lv_obj_t *mark=lv_img_create(ui.brand_key.root);
    lv_img_set_src(mark,&ws_logo_header_accent);
    lv_obj_set_pos(mark,0,0);
    lv_obj_clear_flag(mark,LV_OBJ_FLAG_CLICKABLE);
    lv_obj_set_style_img_recolor(mark,color(RGB24_DEFAULT),0);
    lv_obj_set_style_img_recolor_opa(mark,LV_OPA_COVER,0);
    icon_add(&ui.brand_key,mark);
    lv_obj_t *diamond=lv_img_create(ui.brand_key.root);
    lv_img_set_src(diamond,&ws_logo_header_white);
    lv_obj_set_pos(diamond,0,0);
    lv_obj_clear_flag(diamond,LV_OBJ_FLAG_CLICKABLE);
    lv_obj_set_style_img_recolor(diamond,color(COL_TEXT),0);
    lv_obj_set_style_img_recolor_opa(diamond,LV_OPA_COVER,0);

    ui.brand=label(ui.brand_group,"EVILKEY",&lv_font_montserrat_20,101,2,120,28);
    lv_obj_set_style_text_align(ui.brand,LV_TEXT_ALIGN_LEFT,0);
    lv_obj_set_width(ui.brand,LV_SIZE_CONTENT);
}

static void build_key_icon(ws_icon_t *ic)
{
    /* Both logo layers remain inside the established 70 px hero icon surface. */
    lv_obj_t *mark=lv_img_create(ic->root);
    lv_img_set_src(mark,&ws_logo_hero_accent);
    lv_obj_set_pos(mark,1,1);
    lv_obj_clear_flag(mark,LV_OBJ_FLAG_CLICKABLE);
    lv_obj_set_style_img_recolor(mark,color(RGB24_DEFAULT),0);
    lv_obj_set_style_img_recolor_opa(mark,LV_OPA_COVER,0);
    icon_add(ic,mark);
    lv_obj_t *diamond=lv_img_create(ic->root);
    lv_img_set_src(diamond,&ws_logo_hero_white);
    lv_obj_set_pos(diamond,1,1);
    lv_obj_clear_flag(diamond,LV_OBJ_FLAG_CLICKABLE);
    lv_obj_set_style_img_recolor(diamond,color(COL_TEXT),0);
    lv_obj_set_style_img_recolor_opa(diamond,LV_OPA_COVER,0);
}

static void build_spinner_icon(ws_icon_t *ic)
{
    /* Two clean concentric loaders read as a single precision instrument while
     * touching far fewer pixels than the old twelve independently animated dots. */
    ui.spinner_arc_a=arc_obj(ic->root,8,8,54,RGB24_DEFAULT,1,4,LV_OPA_20,LV_OPA_COVER,0,92);
    ui.spinner_arc_b=arc_obj(ic->root,15,15,40,RGB24_DEFAULT,1,2,LV_OPA_20,LV_OPA_60,0,58);
    icon_add(ic,ui.spinner_arc_a);
    icon_add(ic,ui.spinner_arc_b);
}

static void build_touch_icon(ws_icon_t *ic)
{
    lv_obj_t *p=circle(ic->root,12,12,46,COL_BG,LV_OPA_TRANSP,RGB24_DEFAULT,2,LV_OPA_COVER);icon_add(ic,p);
    p=circle(ic->root,28,28,14,RGB24_DEFAULT,LV_OPA_COVER,RGB24_DEFAULT,0,LV_OPA_TRANSP);icon_add(ic,p);
    p=line_obj(ic->root,P_TOUCH_RAY_A,2,0,0,2,RGB24_DEFAULT);icon_add(ic,p);
    p=line_obj(ic->root,P_TOUCH_RAY_B,2,0,0,2,RGB24_DEFAULT);icon_add(ic,p);
    p=line_obj(ic->root,P_TOUCH_RAY_C,2,0,0,2,RGB24_DEFAULT);icon_add(ic,p);
}

static void build_check_icon(ws_icon_t *ic)
{
    lv_obj_t *p=line_obj(ic->root,P_CHECK_A,2,0,0,5,RGB24_DEFAULT);icon_add(ic,p);
    p=line_obj(ic->root,P_CHECK_B,2,0,0,5,RGB24_DEFAULT);icon_add(ic,p);
}

static void build_cross_icon(ws_icon_t *ic)
{
    lv_obj_t *p=line_obj(ic->root,P_CROSS_A,2,0,0,4,RGB24_DEFAULT);icon_add(ic,p);
    p=line_obj(ic->root,P_CROSS_B,2,0,0,4,RGB24_DEFAULT);icon_add(ic,p);
}

static void build_clock_icon(ws_icon_t *ic)
{
    lv_obj_t *p=circle(ic->root,13,13,44,COL_BG,LV_OPA_TRANSP,RGB24_DEFAULT,3,LV_OPA_COVER);icon_add(ic,p);
    p=line_obj(ic->root,P_CLOCK_H,2,0,0,3,RGB24_DEFAULT);icon_add(ic,p);
    p=line_obj(ic->root,P_CLOCK_M,2,0,0,3,RGB24_DEFAULT);icon_add(ic,p);
}

static void build_lock_icon(ws_icon_t *ic)
{
    lv_obj_t *p=circle(ic->root,23,7,24,COL_BG,LV_OPA_TRANSP,RGB24_DEFAULT,3,LV_OPA_COVER);icon_add(ic,p);
    p=card(ic->root,17,23,36,31,6);
    lv_obj_set_style_bg_opa(p,LV_OPA_20,0);
    lv_obj_set_style_border_width(p,2,0);
    icon_add(ic,p);
    /* Keyhole is cut from the coloured lock using the black screen colour. */
    circle(ic->root,32,34,6,COL_BG,LV_OPA_COVER,COL_BG,0,LV_OPA_TRANSP);
    line_obj(ic->root,P_LOCK_KEY,2,0,0,3,COL_BG);
}

static void build_moon_icon(ws_icon_t *ic)
{
    lv_obj_t *p=circle(ic->root,12,13,44,RGB24_DEFAULT,LV_OPA_COVER,RGB24_DEFAULT,0,LV_OPA_TRANSP);icon_add(ic,p);
    circle(ic->root,28,5,40,COL_BG,LV_OPA_COVER,COL_BG,0,LV_OPA_TRANSP);
}

static void build_warning_icon(ws_icon_t *ic)
{
    lv_obj_t *p=line_obj(ic->root,P_WARN_STEM,2,0,0,4,RGB24_DEFAULT);icon_add(ic,p);
    p=circle(ic->root,31,51,8,RGB24_DEFAULT,LV_OPA_COVER,RGB24_DEFAULT,0,LV_OPA_TRANSP);icon_add(ic,p);
}

static void build_usb_icon(ws_icon_t *ic)
{
    lv_obj_t *p=card(ic->root,21,10,28,36,5);
    lv_obj_set_style_bg_opa(p,LV_OPA_20,0);
    lv_obj_set_style_border_width(p,2,0);
    icon_add(ic,p);
    p=card(ic->root,27,18,5,10,1);set_card(p,RGB24_DEFAULT,RGB24_DEFAULT,0);icon_add(ic,p);
    p=card(ic->root,38,18,5,10,1);set_card(p,RGB24_DEFAULT,RGB24_DEFAULT,0);icon_add(ic,p);
    p=line_obj(ic->root,P_USB_CABLE,2,0,0,3,RGB24_DEFAULT);icon_add(ic,p);
}

static void build_hero(void)
{
    /* R19: neutral concentric glass + two small arc surfaces.  Unlike a blurred
     * shadow, the arc surfaces rasterize only the 108 px hero region. */
    ui.hero=group_at(ui.main_group,86,86,108,108);
    ui.hero_outer=circle(ui.hero,0,0,108,COL_BG,LV_OPA_TRANSP,RGB24_DEFAULT,1,34);
    ui.hero_mid=circle(ui.hero,7,7,94,COL_BG,LV_OPA_TRANSP,RGB24_DEFAULT,1,20);
    ui.hero_inner=circle(ui.hero,19,19,70,RGB24_DEFAULT,9,RGB24_DEFAULT,1,34);
    ui.hero_orbit=arc_obj(ui.hero,0,0,108,RGB24_DEFAULT,1,2,LV_OPA_10,LV_OPA_70,0,84);
    ui.hero_glint=arc_obj(ui.hero,7,7,94,RGB24_DEFAULT,1,2,LV_OPA_TRANSP,LV_OPA_40,0,42);

    for(unsigned i=0;i<ICON_COUNT;++i) icon_init(&ui.icons[i],ui.hero,19,19,70,70);
    build_key_icon(&ui.icons[HERO_KEY]);
    build_spinner_icon(&ui.icons[HERO_SPINNER]);
    build_touch_icon(&ui.icons[HERO_TOUCH]);
    build_check_icon(&ui.icons[HERO_CHECK]);
    build_cross_icon(&ui.icons[HERO_CROSS]);
    build_clock_icon(&ui.icons[HERO_CLOCK]);
    build_lock_icon(&ui.icons[HERO_LOCK]);
    build_moon_icon(&ui.icons[HERO_MOON]);
    build_warning_icon(&ui.icons[HERO_WARNING]);
    build_usb_icon(&ui.icons[HERO_USB]);
    icon_show_only(HERO_KEY);
    create_3d_image(WS_3D_HERO,ui.hero,14,14);
}

static void build_gear_icon(ws_icon_t *ic,int size)
{
    /* One antialiased alpha mask replaces the former ring and detached dots.
     * LVGL tints A8 pixels with the selected accent without a rotating image
     * transform, so the icon stays sharp and cheap to draw. */
    lv_obj_t *p=lv_img_create(ic->root);
    lv_img_set_src(p,&ws_settings_gear);
    lv_obj_set_pos(p,(size-120)/2,(size-120)/2);
    lv_obj_clear_flag(p,LV_OBJ_FLAG_CLICKABLE);
    icon_add(ic,p);
    if(s_3d_available){hidden(p,true);create_3d_image(WS_3D_GEAR,ic->root,0,0);}
}

static void build_settings_hint(void)
{
    /* R15: no top-right gear on READY/STANDBY.  The existing bottom hint is
     * enough and accurately describes the only entry gesture. */
    ui.settings_swipe=label(ui.main_group,"SWIPE LEFT / SETTINGS",&lv_font_montserrat_14,
                            8,418,264,20);
    lv_obj_set_style_text_color(ui.settings_swipe,color(COL_FAINT),0);
}

static void build_tool_led(ws_tool_led_t *led,lv_obj_t *parent,int x,uint32_t rgb)
{
    /* Four tiny fixed layers emulate a glass diode without blur or shadows.
     * Runtime motion changes opacity only, keeping the dirty area bounded to
     * the 68 x 30 status capsule. */
    led->pulse=circle(parent,x,4,22,COL_BG,LV_OPA_TRANSP,rgb,1,LV_OPA_COVER);
    led->lens=circle(parent,x+4,8,14,rgb,LV_OPA_COVER,rgb,1,LV_OPA_COVER);
    led->core=circle(parent,x+8,12,6,rgb,LV_OPA_COVER,rgb,0,LV_OPA_TRANSP);
    led->glint=circle(parent,x+7,10,3,COL_TEXT,LV_OPA_COVER,COL_TEXT,0,LV_OPA_TRANSP);
}

static void build_tool_leds(void)
{
    ui.tool_led_group=card(ui.main_group,202,54,68,30,15);
    set_card(ui.tool_led_group,COL_GLASS,COL_BORDER,1);
    lv_obj_set_style_bg_grad_color(ui.tool_led_group,color(COL_BG),0);
    lv_obj_set_style_bg_grad_dir(ui.tool_led_group,LV_GRAD_DIR_VER,0);
    build_tool_led(&ui.tool_led_red,ui.tool_led_group,7,COL_LED_RED);
    build_tool_led(&ui.tool_led_green,ui.tool_led_group,39,COL_LED_GREEN);
    hidden(ui.tool_led_group,true);
}

static void build_screensaver(void)
{
    /* R23: coherent AMOLED composition.  R21/R22 moved a transparent 252 px
     * parent plus its children every frame.  On the V1 panel there is no MCU
     * TE input, so that produced several independent dirty windows while the
     * panel was scanning and the camera/user could see torn intermediate
     * geometry.  Keep the large core fixed, animate only its contents and
     * coalesce the whole core into one LVGL invalidation per saver frame. */
    ui.screensaver_group=group_at(ui.screen,-WS_LCD_WIDTH,0,WS_LCD_WIDTH,WS_LCD_HEIGHT);
    ui.screensaver_core=group_at(ui.screensaver_group,14,48,252,252);

    /* Long orbital strokes replace the formerly static full-circle borders and
     * the translucent filled disc.  Every emissive ring now migrates. */
    ui.screensaver_outer=arc_obj(ui.screensaver_core,0,0,252,RGB24_DEFAULT,1,2,
                                 LV_OPA_TRANSP,LV_OPA_30,8,154);
    ui.screensaver_mid=arc_obj(ui.screensaver_core,18,18,216,RGB24_DEFAULT,1,2,
                               LV_OPA_TRANSP,LV_OPA_20,0,224);
    ui.screensaver_inner=arc_obj(ui.screensaver_core,37,37,178,RGB24_DEFAULT,1,2,
                                 LV_OPA_TRANSP,LV_OPA_30,24,122);
    ui.screensaver_orbit_a=arc_obj(ui.screensaver_core,0,0,252,RGB24_DEFAULT,1,4,
                                   LV_OPA_TRANSP,LV_OPA_80,0,44);
    ui.screensaver_orbit_b=arc_obj(ui.screensaver_core,18,18,216,RGB24_DEFAULT,1,3,
                                   LV_OPA_TRANSP,LV_OPA_60,0,30);
    ui.screensaver_orbit_c=arc_obj(ui.screensaver_core,37,37,178,RGB24_DEFAULT,1,3,
                                   LV_OPA_TRANSP,LV_OPA_40,0,72);

    ui.screensaver_logo_glow=lv_img_create(ui.screensaver_core);
    lv_img_set_src(ui.screensaver_logo_glow,&ws_logo_screensaver_glow);
    lv_obj_set_pos(ui.screensaver_logo_glow,SAVER_LOGO_BASE-8,SAVER_LOGO_BASE-8);
    lv_obj_clear_flag(ui.screensaver_logo_glow,LV_OBJ_FLAG_CLICKABLE);
    lv_obj_set_style_img_recolor(ui.screensaver_logo_glow,color(RGB24_DEFAULT),0);
    lv_obj_set_style_img_recolor_opa(ui.screensaver_logo_glow,LV_OPA_COVER,0);
    lv_obj_set_style_opa(ui.screensaver_logo_glow,36,0);

    ui.screensaver_logo_ghost=lv_img_create(ui.screensaver_core);
    lv_img_set_src(ui.screensaver_logo_ghost,&s_unified_mint_img);
    lv_obj_set_pos(ui.screensaver_logo_ghost,
                   SAVER_LOGO_BASE+WS_UNIFIED_MINT_X_OFFSET+2,
                   SAVER_LOGO_BASE+WS_UNIFIED_MINT_Y_OFFSET);
    lv_obj_clear_flag(ui.screensaver_logo_ghost,LV_OBJ_FLAG_CLICKABLE);
    lv_obj_set_style_img_recolor(ui.screensaver_logo_ghost,color(COL_LED_RED),0);
    lv_obj_set_style_img_recolor_opa(ui.screensaver_logo_ghost,LV_OPA_COVER,0);
    lv_obj_set_style_opa(ui.screensaver_logo_ghost,68,0);
    hidden(ui.screensaver_logo_ghost,true);

    ui.screensaver_logo=lv_img_create(ui.screensaver_core);
    lv_img_set_src(ui.screensaver_logo,&s_unified_mint_img);
    lv_obj_set_pos(ui.screensaver_logo,
                   SAVER_LOGO_BASE+WS_UNIFIED_MINT_X_OFFSET,
                   SAVER_LOGO_BASE+WS_UNIFIED_MINT_Y_OFFSET);
    lv_obj_clear_flag(ui.screensaver_logo,LV_OBJ_FLAG_CLICKABLE);
    lv_obj_set_style_img_recolor_opa(ui.screensaver_logo,LV_OPA_TRANSP,0);

    static const int16_t glitch_top[2]={50,129};
    static const int16_t glitch_height[2]={17,14};
    const lv_img_dsc_t *const glitch_asset[2]={
        &ws_logo_screensaver_glitch_upper,&ws_logo_screensaver_glitch_lower
    };
    for(unsigned i=0;i<2U;++i) {
        ui.screensaver_glitch_cover[i]=lv_obj_create(ui.screensaver_core);
        base_obj(ui.screensaver_glitch_cover[i],SAVER_LOGO_BASE,SAVER_LOGO_BASE+glitch_top[i],
                 SAVER_LOGO_SIZE,glitch_height[i]);
        lv_obj_set_style_bg_color(ui.screensaver_glitch_cover[i],color(COL_BG),0);
        lv_obj_set_style_bg_opa(ui.screensaver_glitch_cover[i],LV_OPA_COVER,0);
        hidden(ui.screensaver_glitch_cover[i],true);
        ui.screensaver_glitch_slice[i]=lv_img_create(ui.screensaver_core);
        lv_img_set_src(ui.screensaver_glitch_slice[i],glitch_asset[i]);
        lv_obj_set_pos(ui.screensaver_glitch_slice[i],SAVER_LOGO_BASE,
                       SAVER_LOGO_BASE+glitch_top[i]);
        lv_obj_clear_flag(ui.screensaver_glitch_slice[i],LV_OBJ_FLAG_CLICKABLE);
        lv_obj_set_style_img_recolor(ui.screensaver_glitch_slice[i],color(RGB24_DEFAULT),0);
        lv_obj_set_style_img_recolor_opa(ui.screensaver_glitch_slice[i],LV_OPA_COVER,0);
        hidden(ui.screensaver_glitch_slice[i],true);
    }
    ui.screensaver_glitch_scan=lv_obj_create(ui.screensaver_core);
    base_obj(ui.screensaver_glitch_scan,14,102,224,1);
    lv_obj_set_style_bg_color(ui.screensaver_glitch_scan,color(COL_LED_RED),0);
    lv_obj_set_style_bg_opa(ui.screensaver_glitch_scan,160,0);
    hidden(ui.screensaver_glitch_scan,true);

    ui.screensaver_logo_white=lv_img_create(ui.screensaver_core);
    lv_img_set_src(ui.screensaver_logo_white,&s_unified_crystal_img);
    lv_obj_set_pos(ui.screensaver_logo_white,
                   SAVER_LOGO_BASE+WS_UNIFIED_CRYSTAL_X_OFFSET,
                   SAVER_LOGO_BASE+WS_UNIFIED_CRYSTAL_Y_OFFSET);
    lv_obj_clear_flag(ui.screensaver_logo_white,LV_OBJ_FLAG_CLICKABLE);

    create_3d_image(WS_3D_SAVER,ui.screensaver_core,SAVER_LOGO_BASE,SAVER_LOGO_BASE);
    if(s_3d_available){hidden(ui.screensaver_logo,true);hidden(ui.screensaver_logo_white,true);
        hidden(ui.screensaver_logo_glow,true);}
    ui.screensaver_text_group=group_at(ui.screensaver_group,4,314,272,134);
    ui.screensaver_brand=label(ui.screensaver_text_group,"EVILKEY",&lv_font_montserrat_28,
                               6,0,260,38);
    lv_obj_set_style_text_letter_space(ui.screensaver_brand,3,0);
    ui.screensaver_caption=label(ui.screensaver_text_group,
                                 "FIRMWARE  " PF_FIRMWARE_VERSION_STRING,
                                 &lv_font_montserrat_14,6,48,260,20);
    lv_obj_set_style_text_color(ui.screensaver_caption,color(COL_MUTED),0);
    ui.screensaver_hint=label(ui.screensaver_text_group,"SWIPE LEFT / HOME",
                              &lv_font_montserrat_14,6,104,260,20);
    lv_obj_set_style_text_color(ui.screensaver_hint,color(COL_FAINT),0);
    /* R24: start dark so entering the saver never flashes static text before
     * the first fade sample is applied.  Position remains fixed for the entire
     * saver lifetime; only opacity changes. */
    lv_obj_set_style_opa(ui.screensaver_brand,LV_OPA_TRANSP,0);
    lv_obj_set_style_opa(ui.screensaver_caption,LV_OPA_TRANSP,0);
    lv_obj_set_style_opa(ui.screensaver_hint,LV_OPA_TRANSP,0);

    static const int16_t spark_xy[4][2]={{26,60},{248,104},{239,286},{35,296}};
    for(unsigned i=0;i<4;++i)
        ui.screensaver_spark[i]=circle(ui.screensaver_group,spark_xy[i][0],spark_xy[i][1],4,
                                       RGB24_DEFAULT,LV_OPA_20,RGB24_DEFAULT,0,LV_OPA_TRANSP);
}

static void build_setting_row(ws_setting_row_t *r,lv_obj_t *parent)
{
    r->card=card(parent,WS_SETTINGS_ROW_X,WS_SETTINGS_ROW_Y,
                 WS_SETTINGS_ROW_W,WS_SETTINGS_ROW_H,18);
    lv_obj_set_style_bg_grad_color(r->card,color(COL_PANEL2),0);
    lv_obj_set_style_bg_grad_dir(r->card,LV_GRAD_DIR_VER,0);
    r->title=label(r->card,"Setting",&lv_font_montserrat_20,12,10,236,28);
    lv_obj_set_style_text_align(r->title,LV_TEXT_ALIGN_LEFT,0);

    r->minus=card(r->card,WS_SETTINGS_MINUS_X-WS_SETTINGS_ROW_X,WS_SETTINGS_CONTROL_Y_IN_ROW,
                  WS_SETTINGS_MINUS_W,WS_SETTINGS_CONTROL_H,14);
    r->minus_label=label(r->minus,"-",&lv_font_montserrat_28,0,8,WS_SETTINGS_MINUS_W,34);
    r->value=card(r->card,WS_SETTINGS_VALUE_X-WS_SETTINGS_ROW_X,WS_SETTINGS_CONTROL_Y_IN_ROW,
                  WS_SETTINGS_VALUE_W,WS_SETTINGS_CONTROL_H,14);
    r->value_label=label(r->value,"",&lv_font_montserrat_20,2,12,WS_SETTINGS_VALUE_W-4,28);
    r->plus=card(r->card,WS_SETTINGS_PLUS_X-WS_SETTINGS_ROW_X,WS_SETTINGS_CONTROL_Y_IN_ROW,
                 WS_SETTINGS_PLUS_W,WS_SETTINGS_CONTROL_H,14);
    r->plus_label=label(r->plus,"+",&lv_font_montserrat_28,0,8,WS_SETTINGS_PLUS_W,34);
}

static void build_landing_halo(lv_obj_t *parent,lv_obj_t **glow,lv_obj_t **orbit,
                               lv_obj_t **inner,lv_obj_t **glint,lv_obj_t **spark)
{
    *glow=circle(parent,62,58,156,RGB24_DEFAULT,LV_OPA_TRANSP,RGB24_DEFAULT,1,LV_OPA_30);
    *orbit=arc_obj(parent,54,50,172,RGB24_DEFAULT,1,3,LV_OPA_TRANSP,LV_OPA_50,0,76);
    *inner=arc_obj(parent,70,66,140,RGB24_DEFAULT,1,2,LV_OPA_TRANSP,LV_OPA_40,0,132);
    *glint=arc_obj(parent,62,58,156,RGB24_DEFAULT,1,4,LV_OPA_TRANSP,LV_OPA_70,0,28);
    static const int16_t xy[4][2]={{72,93},{207,96},{211,181},{69,186}};
    for(unsigned i=0;i<4U;++i)
        spark[i]=circle(parent,xy[i][0],xy[i][1],4,RGB24_DEFAULT,LV_OPA_50,
                        RGB24_DEFAULT,0,LV_OPA_TRANSP);
}

static void build_settings(void)
{
    ui.settings_group=group_at(ui.screen,WS_LCD_WIDTH,0,WS_LCD_WIDTH,WS_LCD_HEIGHT);
    ui.settings_content=group_at(ui.settings_group,0,0,WS_LCD_WIDTH,WS_LCD_HEIGHT);

    /* Landing page: the gear is deliberately the dominant visual element. */
    build_landing_halo(ui.settings_content,&ui.settings_glow,&ui.settings_orbit,
        &ui.settings_orbit_inner,&ui.settings_glint,ui.settings_spark);
    icon_init(&ui.settings_gear,ui.settings_content,80,76,120,120);
    build_gear_icon(&ui.settings_gear,120);

    ui.settings_title=label(ui.settings_content,"SETTINGS",&lv_font_montserrat_28,10,222,260,38);
    ui.settings_subtitle=label(ui.settings_content,"",&lv_font_montserrat_20,10,276,260,30);

    for(unsigned i=0;i<SETTINGS_ROWS;++i) build_setting_row(&ui.settings_row[i],ui.settings_content);
    ui.settings_swatch=card(ui.settings_row[0].value,8,17,18,18,6);
    set_card(ui.settings_swatch,RGB24_DEFAULT,RGB24_DEFAULT,0);

    ui.diagnostics_card=card(ui.settings_content,WS_SETTINGS_ROW_X,
                             WS_SETTINGS_ROW_Y+WS_SETTINGS_ROW_DY,
                             WS_SETTINGS_ROW_W,WS_SETTINGS_ROW_H,18);
    lv_obj_set_style_bg_grad_color(ui.diagnostics_card,color(COL_PANEL2),0);
    lv_obj_set_style_bg_grad_dir(ui.diagnostics_card,LV_GRAD_DIR_VER,0);
    ui.diagnostics_title=label(ui.diagnostics_card,"DRAW BUFFER",&lv_font_montserrat_14,
                               12,8,236,20);
    ui.diagnostics_value=label(ui.diagnostics_card,"OFF",&lv_font_montserrat_20,
                               12,29,236,30);
    ui.diagnostics_memory=label(ui.diagnostics_card,"Enable to show memory status",
                                &lv_font_montserrat_14,12,61,236,48);
    lv_obj_set_style_text_align(ui.diagnostics_title,LV_TEXT_ALIGN_LEFT,0);
    lv_obj_set_style_text_align(ui.diagnostics_value,LV_TEXT_ALIGN_LEFT,0);
    lv_obj_set_style_text_align(ui.diagnostics_memory,LV_TEXT_ALIGN_LEFT,0);
    hidden(ui.diagnostics_card,true);
    ui.diagnostics_save=card(ui.settings_content,WS_DIAGNOSTICS_SAVE_X,WS_DIAGNOSTICS_SAVE_Y,
        WS_DIAGNOSTICS_SAVE_W,WS_DIAGNOSTICS_SAVE_H,12);
    ui.diagnostics_save_label=label(ui.diagnostics_save,"Save report",&lv_font_montserrat_14,4,9,232,28);
    hidden(ui.diagnostics_save,true);

    ui.air_mouse_info_card=card(ui.settings_content,WS_SETTINGS_ROW_X,
                                 WS_SETTINGS_ROW_Y+WS_SETTINGS_ROW_DY,
                                 WS_SETTINGS_ROW_W,WS_SETTINGS_ROW_H,18);
    ui.air_mouse_info_label=label(ui.air_mouse_info_card,
        "Hold MOVE to steer.\nTap DRAG to hold left.\nTap again to release.",
        &lv_font_montserrat_14,12,13,236,86);
    lv_obj_set_style_text_align(ui.air_mouse_info_label,LV_TEXT_ALIGN_LEFT,0);
    hidden(ui.air_mouse_info_card,true);

    ui.settings_return=label(ui.settings_content,"SWIPE RIGHT / BACK",&lv_font_montserrat_14,
                             10,386,260,20);
    ui.settings_footer=label(ui.settings_content,"SWIPE UP / DOWN",&lv_font_montserrat_14,
                             10,408,260,20);
    for(unsigned i=0;i<SETTINGS_DOTS;++i)
        ui.settings_dot[i]=circle(ui.settings_content,61+(int)i*17,436,6,COL_FAINT,
                                  LV_OPA_COVER,COL_FAINT,0,LV_OPA_TRANSP);

}

static void build_apps(void)
{
    ui.launcher_group=group_at(ui.screen,0,0,WS_LCD_WIDTH,WS_LCD_HEIGHT);
    ui.launcher_header=label(ui.launcher_group,"APPS",&lv_font_montserrat_28,12,15,170,38);
    ui.launcher_counter=label(ui.launcher_group,"",&lv_font_montserrat_14,180,25,88,24);
    ui.launcher_intro=group_at(ui.launcher_group,0,0,WS_LCD_WIDTH,386);
    build_landing_halo(ui.launcher_intro,&ui.launcher_glow,&ui.launcher_orbit,
        &ui.launcher_orbit_inner,&ui.launcher_glint,ui.launcher_spark);
    for(unsigned i=0;i<9;++i)
        ui.launcher_tiles[i]=card(ui.launcher_intro,98+(int)(i%3)*29,
            94+(int)(i/3)*29,26,26,5);
    if(s_3d_available) {
        for(unsigned i=0;i<9;++i)hidden(ui.launcher_tiles[i],true);
        create_3d_image(WS_3D_APPS,ui.launcher_intro,80,76);
    }
    label(ui.launcher_intro,"APPS",&lv_font_montserrat_28,10,222,260,38);
    ui.launcher_count=label(ui.launcher_intro,"0 apps on microSD",
        &lv_font_montserrat_20,10,276,260,30);
    lv_obj_set_style_text_color(ui.launcher_count,color(COL_MUTED),0);
    ui.launcher_content=group_at(ui.launcher_group,0,0,WS_LCD_WIDTH,396);
    for(unsigned i=0;i<EK_APPS_PAGE_SIZE;++i) {
        int x=8+(int)(i%3)*90,y=64+(int)(i/3)*110;
        ui.launcher_cell[i]=card(ui.launcher_content,x,y,84,102,12);
        set_card_flat(ui.launcher_cell[i],COL_GLASS,COL_BORDER,1);
        if(s_launcher_pixels) {
            s_launcher_img[i].header.cf=LV_IMG_CF_TRUE_COLOR;
            s_launcher_img[i].header.w=64;s_launcher_img[i].header.h=64;
            s_launcher_img[i].data_size=EK_APPS_ICON_BYTES;
            s_launcher_img[i].data=s_launcher_pixels+i*EK_APPS_ICON_BYTES;
            ui.launcher_icon[i]=lv_img_create(ui.launcher_cell[i]);
            lv_img_set_src(ui.launcher_icon[i],&s_launcher_img[i]);
            lv_obj_set_pos(ui.launcher_icon[i],10,4);
        }
        ui.launcher_name[i]=label(ui.launcher_cell[i],"",&lv_font_montserrat_14,2,68,80,32);
        lv_label_set_long_mode(ui.launcher_name[i],LV_LABEL_LONG_DOT);
    }
    ui.launcher_status=label(ui.launcher_group,"SWIPE RIGHT / HOME",&lv_font_montserrat_14,8,386,264,20);
    lv_obj_t *left_hint=label(ui.launcher_group,"SWIPE LEFT / SETTINGS",&lv_font_montserrat_14,8,406,264,20);
    lv_obj_t *vertical_hint=label(ui.launcher_group,"SWIPE UP / DOWN",&lv_font_montserrat_14,8,426,264,20);
    lv_obj_set_style_text_color(left_hint,color(COL_FAINT),0);
    lv_obj_set_style_text_color(vertical_hint,color(COL_FAINT),0);
    for(unsigned i=0;i<9;++i)
        ui.launcher_dot[i]=circle(ui.launcher_group,75+(int)i*18,448,6,COL_FAINT,
            LV_OPA_COVER,COL_FAINT,0,LV_OPA_TRANSP);
    hidden(ui.launcher_group,true);
    ui.apps_group=group_at(ui.screen,0,0,WS_LCD_WIDTH,WS_LCD_HEIGHT);
    if(s_apps_pixels) {
        ui.apps_image=lv_img_create(ui.apps_group);
        lv_img_set_src(ui.apps_image,&s_apps_img);
        lv_obj_set_pos(ui.apps_image,0,0);
    } else {
        label(ui.apps_group,"App display memory unavailable",&lv_font_montserrat_18,
              12,190,256,64);
    }
    ui.apps_exit_dim=group_at(ui.apps_group,0,0,WS_LCD_WIDTH,WS_LCD_HEIGHT);
    lv_obj_set_style_bg_color(ui.apps_exit_dim,color(0),0);
    lv_obj_set_style_bg_opa(ui.apps_exit_dim,(lv_opa_t)72,0);
    hidden(ui.apps_exit_dim,true);
    ui.apps_exit_pull=card(ui.apps_group,4,4,272,72,12);
    set_card_flat(ui.apps_exit_pull,0x122328UL,0x365a60UL,1);
    lv_obj_t *pull_title=label(ui.apps_exit_pull,"BACK TO APPS",&lv_font_montserrat_14,48,9,214,20);
    lv_obj_set_style_text_align(pull_title,LV_TEXT_ALIGN_LEFT,0);
    ui.apps_exit_caption=label(ui.apps_exit_pull,"DRAG RIGHT TO EXIT",&lv_font_montserrat_12,48,30,214,18);
    lv_obj_set_style_text_align(ui.apps_exit_caption,LV_TEXT_ALIGN_LEFT,0);
    lv_obj_set_style_text_color(ui.apps_exit_caption,color(COL_MUTED),0);
    lv_obj_t *track=card(ui.apps_exit_pull,48,54,172,4,2);
    set_card_flat(track,COL_BORDER,COL_BORDER,0);
    ui.apps_exit_fill=card(track,0,0,1,4,2);
    set_card_flat(ui.apps_exit_fill,RGB24_DEFAULT,RGB24_DEFAULT,0);
    ui.apps_exit_percent=label(ui.apps_exit_pull,"0%",&lv_font_montserrat_12,224,47,42,18);
    hidden(ui.apps_exit_pull,true);
    ui.apps_exit_grip=card(ui.apps_group,4,4,40,40,11);
    set_card_flat(ui.apps_exit_grip,0x142328UL,0x365a60UL,1);
    static const lv_point_t shaft[]={{0,6},{14,6}};
    static const lv_point_t head[]={{8,0},{14,6},{8,12}};
    ui.apps_exit_arrow=group_at(ui.apps_exit_grip,12,13,16,14);
    line_obj(ui.apps_exit_arrow,shaft,2,0,0,2,RGB24_DEFAULT);
    line_obj(ui.apps_exit_arrow,head,3,0,0,2,RGB24_DEFAULT);
    ui.apps_exit_overlay=group_at(ui.apps_group,0,0,WS_LCD_WIDTH,WS_LCD_HEIGHT);
    lv_obj_set_style_bg_color(ui.apps_exit_overlay,color(0x000000UL),0);
    lv_obj_set_style_bg_opa(ui.apps_exit_overlay,(lv_opa_t)184,0);
    lv_obj_t *dialog=card(ui.apps_exit_overlay,18,119,244,218,18);
    set_card_flat(dialog,0x122025UL,0x365a60UL,1);
    lv_obj_t *glint=card(dialog,100,0,42,2,0);
    set_card_flat(glint,RGB24_DEFAULT,RGB24_DEFAULT,0);
    lv_obj_t *symbol=card(dialog,98,20,46,46,14);
    set_card_flat(symbol,0x1b3638UL,0x1b3638UL,0);
    static const lv_point_t door[]={{7,0},{0,0},{0,14},{7,14}};
    line_obj(symbol,door,4,13,16,2,RGB24_DEFAULT);
    line_obj(symbol,shaft,2,19,18,2,RGB24_DEFAULT);
    line_obj(symbol,head,3,19,18,2,RGB24_DEFAULT);
    label(dialog,"LEAVE APP?",&lv_font_montserrat_20,10,81,222,30);
    lv_obj_t *subtitle=label(dialog,"Return to your apps?",&lv_font_montserrat_14,10,113,222,24);
    lv_obj_set_style_text_color(subtitle,color(COL_MUTED),0);
    /* LVGL child coordinates begin inside the dialog's one-pixel border. */
    ui.apps_exit_no=card(dialog,EK_EXIT_NO_X-19,EK_EXIT_Y-120,
                         EK_EXIT_BUTTON_W,EK_EXIT_BUTTON_H,11);
    ui.apps_exit_yes=card(dialog,EK_EXIT_YES_X-19,EK_EXIT_Y-120,
                          EK_EXIT_BUTTON_W,EK_EXIT_BUTTON_H,11);
    label(ui.apps_exit_no,"NO",&lv_font_montserrat_14,4,13,90,22);
    lv_obj_t *yes=label(ui.apps_exit_yes,"YES",&lv_font_montserrat_14,4,13,90,22);
    lv_obj_set_style_text_color(yes,color(0xffb3beUL),0);
    hidden(ui.apps_exit_overlay,true);
    hidden(ui.apps_group,true);
}

static void build_air_mouse(void)
{
    ui.air_mouse_group=group_at(ui.screen,0,0,WS_LCD_WIDTH,WS_LCD_HEIGHT);
    ui.air_mouse_left=card(ui.air_mouse_group,WS_MOUSE_LEFT_X,WS_MOUSE_LEFT_Y,
                           WS_MOUSE_LEFT_W,WS_MOUSE_LEFT_H,16);
    ui.air_mouse_left_label=label(ui.air_mouse_left,"LEFT",&lv_font_montserrat_20,4,60,88,32);
    ui.air_mouse_drag=card(ui.air_mouse_group,12,180,96,62,12);
    ui.air_mouse_drag_label=label(ui.air_mouse_drag,"DRAG OFF",&lv_font_montserrat_14,2,20,92,24);
    ui.air_mouse_scroll=card(ui.air_mouse_group,WS_MOUSE_SCROLL_X,WS_MOUSE_SCROLL_Y,
                             WS_MOUSE_SCROLL_W,WS_MOUSE_SCROLL_H,14);
    label(ui.air_mouse_scroll,"^\n\nS\nC\nR\nO\nL\nL\n\nv",&lv_font_montserrat_14,
          5,12,42,198);
    ui.air_mouse_right=card(ui.air_mouse_group,WS_MOUSE_RIGHT_X,WS_MOUSE_RIGHT_Y,
                           WS_MOUSE_RIGHT_W,WS_MOUSE_RIGHT_H,16);
    ui.air_mouse_right_label=label(ui.air_mouse_right,"RIGHT",&lv_font_montserrat_20,4,94,88,32);
    ui.air_mouse_move=card(ui.air_mouse_group,WS_MOUSE_MOVE_X,WS_MOUSE_MOVE_Y,
                           WS_MOUSE_MOVE_W,WS_MOUSE_MOVE_H,16);
    ui.air_mouse_title=label(ui.air_mouse_move,"HOLD TO MOVE",&lv_font_montserrat_20,
                             10,7,236,28);
    ui.air_mouse_status=label(ui.air_mouse_move,"Hold still to calibrate",
                               &lv_font_montserrat_18,10,39,236,24);
    ui.air_mouse_hint=label(ui.air_mouse_move,"DRAG: tap to hold / release",
                            &lv_font_montserrat_14,10,73,236,20);
    lv_obj_set_style_text_color(ui.air_mouse_hint,color(COL_MUTED),0);
    ui.air_mouse_calibrate=card(ui.air_mouse_group,WS_MOUSE_CAL_X,WS_MOUSE_CAL_Y,
                                WS_MOUSE_CAL_W,WS_MOUSE_CAL_H,14);
    label(ui.air_mouse_calibrate,"SETTINGS",&lv_font_montserrat_18,4,8,116,26);
    lv_obj_t *cal_hold=label(ui.air_mouse_calibrate,"HOLD 3 SEC",&lv_font_montserrat_14,
                             4,33,116,20);
    lv_obj_set_style_text_color(cal_hold,color(COL_MUTED),0);
    ui.air_mouse_calibrate_progress=card(ui.air_mouse_calibrate,8,60,1,4,2);
    hidden(ui.air_mouse_calibrate_progress,true);
    ui.air_mouse_exit=card(ui.air_mouse_group,WS_MOUSE_EXIT_X,WS_MOUSE_EXIT_Y,
                           WS_MOUSE_EXIT_W,WS_MOUSE_EXIT_H,14);
    label(ui.air_mouse_exit,"EXIT",&lv_font_montserrat_20,4,7,116,28);
    lv_obj_t *exit_hold=label(ui.air_mouse_exit,"HOLD 3 SEC",&lv_font_montserrat_14,
                              4,33,116,20);
    lv_obj_set_style_text_color(exit_hold,color(COL_MUTED),0);
    ui.air_mouse_exit_progress=card(ui.air_mouse_exit,8,60,1,4,2);
    hidden(ui.air_mouse_exit_progress,true);

    ui.air_mouse_settings_group=group_at(ui.screen,0,0,WS_LCD_WIDTH,WS_LCD_HEIGHT);
    label(ui.air_mouse_settings_group,"AIR MOUSE",&lv_font_montserrat_20,20,22,240,32);
    lv_obj_t *settings_sub=label(ui.air_mouse_settings_group,"POINTER SETTINGS",
                                 &lv_font_montserrat_14,20,61,240,24);
    lv_obj_set_style_text_color(settings_sub,color(COL_MUTED),0);
    label(ui.air_mouse_settings_group,"SENSITIVITY",&lv_font_montserrat_14,20,104,240,22);
    ui.air_mouse_sensitivity_minus=card(ui.air_mouse_settings_group,
        WS_MOUSE_CFG_MINUS_X,WS_MOUSE_CFG_MINUS_Y,WS_MOUSE_CFG_MINUS_W,WS_MOUSE_CFG_MINUS_H,14);
    label(ui.air_mouse_sensitivity_minus,"-",&lv_font_montserrat_20,0,15,60,28);
    lv_obj_t *sens_value=card(ui.air_mouse_settings_group,94,133,92,58,14);
    ui.air_mouse_sensitivity_value=label(sens_value,"3 / 5",
                                          &lv_font_montserrat_20,0,15,92,30);
    ui.air_mouse_sensitivity_plus=card(ui.air_mouse_settings_group,
        WS_MOUSE_CFG_PLUS_X,WS_MOUSE_CFG_PLUS_Y,WS_MOUSE_CFG_PLUS_W,WS_MOUSE_CFG_PLUS_H,14);
    label(ui.air_mouse_sensitivity_plus,"+",&lv_font_montserrat_20,0,15,60,28);
    lv_obj_t *sens_note=label(ui.air_mouse_settings_group,"3 = original speed",
                               &lv_font_montserrat_14,20,196,240,20);
    lv_obj_set_style_text_color(sens_note,color(COL_MUTED),0);
    ui.air_mouse_invert=card(ui.air_mouse_settings_group,WS_MOUSE_CFG_INVERT_X,
        WS_MOUSE_CFG_INVERT_Y,WS_MOUSE_CFG_INVERT_W,WS_MOUSE_CFG_INVERT_H,14);
    label(ui.air_mouse_invert,"INVERT VERTICAL",&lv_font_montserrat_14,10,8,160,22);
    lv_obj_t *invert_note=label(ui.air_mouse_invert,"Up / down cursor",
                                   &lv_font_montserrat_14,10,35,165,22);
    lv_obj_set_style_text_color(invert_note,color(COL_MUTED),0);
    ui.air_mouse_invert_value=label(ui.air_mouse_invert,"OFF",
                                       &lv_font_montserrat_18,178,20,54,30);
    ui.air_mouse_settings_calibrate=card(ui.air_mouse_settings_group,
        WS_MOUSE_CFG_CAL_X,WS_MOUSE_CFG_CAL_Y,WS_MOUSE_CFG_CAL_W,WS_MOUSE_CFG_CAL_H,14);
    label(ui.air_mouse_settings_calibrate,"CALIBRATE",&lv_font_montserrat_20,0,8,240,26);
    lv_obj_t *cal_note=label(ui.air_mouse_settings_calibrate,"HOLD 3 SEC - KEEP STILL",
                             &lv_font_montserrat_14,0,35,240,20);
    lv_obj_set_style_text_color(cal_note,color(COL_MUTED),0);
    ui.air_mouse_settings_calibrate_progress=card(ui.air_mouse_settings_calibrate,
                                                   8,60,1,4,2);
    hidden(ui.air_mouse_settings_calibrate_progress,true);
    ui.air_mouse_settings_back=card(ui.air_mouse_settings_group,
        WS_MOUSE_CFG_BACK_X,WS_MOUSE_CFG_BACK_Y,WS_MOUSE_CFG_BACK_W,WS_MOUSE_CFG_BACK_H,14);
    label(ui.air_mouse_settings_back,"BACK TO MOUSE",&lv_font_montserrat_18,0,10,240,28);
    hidden(ui.air_mouse_settings_group,true);
    hidden(ui.air_mouse_group,true);
    if(pf_control_mode()==PF_CONTROL_BLE_MOUSE) {
        lv_obj_set_y(ui.air_mouse_settings_calibrate,286);
        lv_obj_set_height(ui.air_mouse_settings_calibrate,44);
        lv_obj_set_y(lv_obj_get_child(ui.air_mouse_settings_calibrate,0),10);
        hidden(lv_obj_get_child(ui.air_mouse_settings_calibrate,1),true);
        lv_obj_set_y(ui.air_mouse_settings_calibrate_progress,39);
        ui.air_mouse_pair=card(ui.air_mouse_settings_group,20,336,116,44,12);
        label(ui.air_mouse_pair,"PAIR",&lv_font_montserrat_18,0,10,116,28);
        ui.air_mouse_forget=card(ui.air_mouse_settings_group,144,336,116,44,12);
        label(ui.air_mouse_forget,"FORGET",&lv_font_montserrat_18,0,10,116,28);
        ui.air_mouse_ble_dialog=card(ui.air_mouse_settings_group,10,100,260,260,18);
        label(ui.air_mouse_ble_dialog,"FORGET PAIRING?",&lv_font_montserrat_20,10,26,240,32);
        label(ui.air_mouse_ble_dialog,"Remove mouse BLE bonds?\nFIDO keys are preserved.",&lv_font_montserrat_18,10,80,240,56);
        lv_obj_t *yes=card(ui.air_mouse_ble_dialog,10,150,116,58,12);
        label(yes,"YES",&lv_font_montserrat_20,0,17,116,30);
        lv_obj_t *no=card(ui.air_mouse_ble_dialog,134,150,116,58,12);
        label(no,"NO",&lv_font_montserrat_20,0,17,116,30);
        hidden(ui.air_mouse_ble_dialog,true);
    }
}

static void build_main(void)
{
    ui.main_group=group_at(ui.screen,0,0,WS_LCD_WIDTH,WS_LCD_HEIGHT);
    build_brand();
    build_hero();

    ui.title=label(ui.main_group,"Connect USB",&lv_font_montserrat_34,8,202,264,44);
    ui.line1=label(ui.main_group,"Connect to your",&lv_font_montserrat_20,8,269,264,28);
    ui.line2=label(ui.main_group,"computer.",&lv_font_montserrat_20,8,300,264,28);
    ui.usb=label(ui.main_group,"USB disconnected",&lv_font_montserrat_18,8,336,264,24);
    ui.countdown=label(ui.main_group,"",&lv_font_montserrat_18,8,250,264,24);

    for(unsigned i=0;i<3;++i)
        ui.progress_dot[i]=circle(ui.main_group,130+(int)i*10,348,5,COL_FAINT,LV_OPA_COVER,COL_FAINT,0,LV_OPA_TRANSP);
    ui.result_flare=card(ui.main_group,102,351,76,2,1);
    set_card(ui.result_flare,RGB24_DEFAULT,RGB24_DEFAULT,0);
    lv_obj_set_style_bg_grad_color(ui.result_flare,color(COL_BG),0);
    lv_obj_set_style_bg_grad_dir(ui.result_flare,LV_GRAD_DIR_HOR,0);

    ui.approve=card(ui.main_group,WS_UP_X,WS_APPROVE_Y,WS_UP_W,WS_APPROVE_H,16);
    lv_obj_set_style_bg_grad_color(ui.approve,color(COL_PANEL2),0);
    lv_obj_set_style_bg_grad_dir(ui.approve,LV_GRAD_DIR_VER,0);
    ui.approve_label=label(ui.approve,"Approve",&lv_font_montserrat_28,0,18,WS_UP_W,36);
    ui.cancel=card(ui.main_group,WS_UP_X,WS_CANCEL_Y,WS_UP_W,WS_CANCEL_H,16);
    lv_obj_set_style_bg_grad_color(ui.cancel,color(COL_PANEL),0);
    lv_obj_set_style_bg_grad_dir(ui.cancel,LV_GRAD_DIR_VER,0);
    ui.cancel_label=label(ui.cancel,"Cancel",&lv_font_montserrat_20,0,23,WS_UP_W,28);

    ui.tool_prev=card(ui.main_group,WS_USB_TOOL_PREV_X,WS_USB_TOOL_BUTTON_Y,
                      WS_USB_TOOL_PREV_W,WS_USB_TOOL_BUTTON_H,14);
    ui.tool_prev_label=label(ui.tool_prev,"PREV",&lv_font_montserrat_18,0,17,WS_USB_TOOL_PREV_W,26);
    ui.tool_run=card(ui.main_group,WS_USB_TOOL_RUN_X,WS_USB_TOOL_BUTTON_Y,
                     WS_USB_TOOL_RUN_W,WS_USB_TOOL_BUTTON_H,14);
    ui.tool_run_label=label(ui.tool_run,"RUN",&lv_font_montserrat_18,0,17,WS_USB_TOOL_RUN_W,26);
    ui.tool_next=card(ui.main_group,WS_USB_TOOL_NEXT_X,WS_USB_TOOL_BUTTON_Y,
                      WS_USB_TOOL_NEXT_W,WS_USB_TOOL_BUTTON_H,14);
    ui.tool_next_label=label(ui.tool_next,"NEXT",&lv_font_montserrat_18,0,17,WS_USB_TOOL_NEXT_W,26);
    hidden(ui.tool_prev,true);hidden(ui.tool_run,true);hidden(ui.tool_next,true);

    build_tool_leds();
    build_settings_hint();
}

static void build_backspace(void)
{
    icon_init(&ui.backspace,ui.keys[9],0,0,WS_KEY_W,WS_KEY_H);
    lv_obj_t *p=line_obj(ui.backspace.root,P_BACKSPACE_OUTLINE,6,0,0,2,COL_TEXT);icon_add(&ui.backspace,p);
    p=line_obj(ui.backspace.root,P_BACKSPACE_X1,2,0,0,2,COL_TEXT);icon_add(&ui.backspace,p);
    p=line_obj(ui.backspace.root,P_BACKSPACE_X2,2,0,0,2,COL_TEXT);icon_add(&ui.backspace,p);
}

static void build_pin(void)
{
    ui.pin_group=group_at(ui.screen,0,0,WS_LCD_WIDTH,WS_LCD_HEIGHT);
    ui.pin_title=label(ui.pin_group,"Enter PIN",&lv_font_montserrat_28,8,4,264,38);
    ui.pin_scope=label(ui.pin_group,"Verify identity",&lv_font_montserrat_18,8,45,264,25);

    ui.pin_field=card(ui.pin_group,8,77,264,31,12);
    lv_obj_set_style_bg_grad_color(ui.pin_field,color(COL_PANEL2),0);
    lv_obj_set_style_bg_grad_dir(ui.pin_field,LV_GRAD_DIR_VER,0);
    for(unsigned i=0;i<10;++i) {
        ui.pin_dot[i]=circle(ui.pin_field,10+(int)i*16,11,8,COL_TEXT,LV_OPA_COVER,COL_FAINT,0,LV_OPA_TRANSP);
    }
    ui.pin_length=label(ui.pin_field,"0 digits",&lv_font_montserrat_14,175,4,78,22);
    lv_obj_set_style_text_align(ui.pin_length,LV_TEXT_ALIGN_RIGHT,0);
    ui.pin_tries=label(ui.pin_group,"8 tries",&lv_font_montserrat_18,12,106,112,24);
    lv_obj_set_style_text_align(ui.pin_tries,LV_TEXT_ALIGN_LEFT,0);
    ui.pin_seconds=label(ui.pin_group,"120 s",&lv_font_montserrat_18,156,106,112,24);
    lv_obj_set_style_text_align(ui.pin_seconds,LV_TEXT_ALIGN_RIGHT,0);

    static const char *names[12]={"1","2","3","4","5","6","7","8","9","","0","Verify"};
    for(unsigned row=0;row<4;++row) for(unsigned col=0;col<3;++col) {
        unsigned i=row*3U+col;
        int x=WS_KEY_X+WS_KEY_DX*(int)col;
        int y=WS_KEY_Y+WS_KEY_DY*(int)row;
        ui.keys[i]=card(ui.pin_group,x,y,WS_KEY_W,WS_KEY_H,14);
        lv_obj_set_style_bg_grad_color(ui.keys[i],color(COL_PANEL2),0);
        lv_obj_set_style_bg_grad_dir(ui.keys[i],LV_GRAD_DIR_VER,0);
        /* R23 pressed feedback is an inset ring.  The old accent border sat on
         * the key's outer raster edge and the bottom antialiased row could be
         * clipped by partial invalidation on hardware.  This ring stays fully
         * inside the key without changing the validated touch rectangle. */
        ui.key_press_ring[i]=lv_obj_create(ui.keys[i]);
        base_obj(ui.key_press_ring[i],3,3,WS_KEY_W-6,WS_KEY_H-6);
        lv_obj_set_style_radius(ui.key_press_ring[i],11,0);
        lv_obj_set_style_bg_opa(ui.key_press_ring[i],LV_OPA_TRANSP,0);
        lv_obj_set_style_border_width(ui.key_press_ring[i],2,0);
        lv_obj_set_style_border_color(ui.key_press_ring[i],color(RGB24_DEFAULT),0);
        lv_obj_set_style_border_opa(ui.key_press_ring[i],LV_OPA_TRANSP,0);
        const lv_font_t *font=i==11?&lv_font_montserrat_20:&lv_font_montserrat_34;
        ui.key_labels[i]=label(ui.keys[i],names[i],font,0,i==11?18:11,WS_KEY_W,i==11?28:42);
    }
    build_backspace();

    ui.pin_cancel=card(ui.pin_group,WS_PIN_CANCEL_X,WS_PIN_CANCEL_Y,
                       WS_PIN_CANCEL_W,WS_PIN_CANCEL_H,12);
    ui.pin_cancel_label=label(ui.pin_cancel,"Cancel",&lv_font_montserrat_20,0,10,WS_PIN_CANCEL_W,28);
}

esp_err_t ws_lvgl_init(void)
{
    if(s_ready) return ESP_OK;
    /* LVGL has no error return from lv_init(). Check the required external
     * pool before its TLSF initializer asks for the 128 KiB block. Launcher
     * widgets and transition drawing masks exceeded the old 64 KiB pool. */
    if(heap_caps_get_largest_free_block(MALLOC_CAP_SPIRAM|MALLOC_CAP_8BIT)<LV_MEM_SIZE)
        return ESP_ERR_NO_MEM;
    lv_init();

    /* The LVGL object pool now lives in PSRAM, freeing internal SRAM for the
     * 0.2.10 transport: two 64-row DMA strips. CPU can rasterize the next
     * strip while SPI transfers the previous one. If that allocation fails,
     * keep the device usable with the physically checked 0.2.14 single-strip
     * path rather than reverting to the 2 x 32-row mode that showed a line. */
    static const uint16_t row_candidates[]={64U,48U,32U,16U};
    uint16_t selected_rows=0U;
    const bool ble_role=ws_controls_is_ble(pf_control_mode());
    const uint16_t target_rows=ble_role?16U:64U;
    const uint32_t target_pixels=DRAW_PIXELS(target_rows);
    const size_t target_bytes=(size_t)target_pixels*sizeof(lv_color_t);
    s_pixels_a=(lv_color_t *)heap_caps_malloc(target_bytes,
                                               MALLOC_CAP_DMA|MALLOC_CAP_INTERNAL);
    if(!ble_role) s_pixels_b=(lv_color_t *)heap_caps_malloc(target_bytes,
                                               MALLOC_CAP_DMA|MALLOC_CAP_INTERNAL);
    if(s_pixels_a && (ble_role || s_pixels_b)) {
        s_draw_pixels=target_pixels;
        selected_rows=target_rows;
    } else {
        if(s_pixels_a) heap_caps_free(s_pixels_a);
        if(s_pixels_b) heap_caps_free(s_pixels_b);
        s_pixels_a=NULL;s_pixels_b=NULL;
    }
    if(!s_pixels_a && !ble_role && FIDO_V1_GUI_3D) {
        const uint32_t small_pixels=DRAW_PIXELS(STAGING_ROWS);
        s_pixels_a=(lv_color_t*)heap_caps_malloc(small_pixels*sizeof(lv_color_t),MALLOC_CAP_DMA|MALLOC_CAP_INTERNAL);
        s_pixels_b=(lv_color_t*)heap_caps_malloc(small_pixels*sizeof(lv_color_t),MALLOC_CAP_DMA|MALLOC_CAP_INTERNAL);
        if(s_pixels_a&&s_pixels_b){s_draw_pixels=small_pixels;selected_rows=STAGING_ROWS;}
        else {heap_caps_free(s_pixels_a);heap_caps_free(s_pixels_b);s_pixels_a=s_pixels_b=NULL;}
    }
    if(!s_pixels_a && !ble_role && FIDO_V1_GUI_3D) {
        s_pixels_a=(lv_color_t *)heap_caps_malloc(target_bytes,MALLOC_CAP_SPIRAM|MALLOC_CAP_8BIT);
        s_pixels_b=(lv_color_t *)heap_caps_malloc(target_bytes,MALLOC_CAP_SPIRAM|MALLOC_CAP_8BIT);
        for(unsigned i=0;i<2;i++)s_staging[i]=(lv_color_t *)heap_caps_malloc(
            DRAW_PIXELS(STAGING_ROWS)*sizeof(lv_color_t),MALLOC_CAP_DMA|MALLOC_CAP_INTERNAL);
        if(s_pixels_a && s_pixels_b && s_staging[0] && s_staging[1]) {
            s_draw_pixels=target_pixels;selected_rows=target_rows;
        } else {
            heap_caps_free(s_pixels_a);heap_caps_free(s_pixels_b);
            s_pixels_a=s_pixels_b=NULL;
            for(unsigned i=0;i<2;i++){heap_caps_free(s_staging[i]);s_staging[i]=NULL;}
        }
    }
    for(unsigned i=0;!s_pixels_a && i<sizeof(row_candidates)/sizeof(row_candidates[0]);++i) {
        const uint16_t rows=row_candidates[i];
        if(rows>WS_LCD_STRIP_ROWS || rows>target_rows) continue;
        const uint32_t pixels=DRAW_PIXELS(rows);
        s_pixels_a=(lv_color_t *)heap_caps_malloc((size_t)pixels*sizeof(lv_color_t),
                                                  MALLOC_CAP_DMA|MALLOC_CAP_INTERNAL);
        if(s_pixels_a) {
            s_draw_pixels=pixels;
            selected_rows=rows;
            break;
        }
    }
    if(!s_pixels_a || s_draw_pixels==0U) return ESP_ERR_NO_MEM;
    ESP_LOGI(TAG,"LVGL draw buffers: %u x %u rows (%u bytes each), %s; free DMA=%u, largest=%u",
             s_pixels_b?2U:1U,(unsigned)selected_rows,
             (unsigned)(s_draw_pixels*sizeof(lv_color_t)),
             s_staging[0]?"PSRAM + 2 x 16-row internal DMA":"internal DMA SRAM",
             (unsigned)heap_caps_get_free_size(MALLOC_CAP_DMA|MALLOC_CAP_INTERNAL),
             (unsigned)heap_caps_get_largest_free_block(MALLOC_CAP_DMA|MALLOC_CAP_INTERNAL));

    lv_disp_draw_buf_init(&s_draw_buf,s_pixels_a,s_pixels_b,s_draw_pixels);
    lv_disp_drv_init(&s_disp_drv);
    s_disp_drv.hor_res=WS_LCD_WIDTH;
    s_disp_drv.ver_res=WS_LCD_HEIGHT;
    s_disp_drv.flush_cb=flush_cb;
    s_disp_drv.wait_cb=flush_wait;
    s_disp_drv.draw_buf=&s_draw_buf;
    s_disp_drv.sw_rotate=pf_control_mode()==PF_CONTROL_BLE_PAD;
    /* Every V1 panel window must start even/end odd, including animated
     * decorative images and Settings. Mouse-only rounding left ordinary
     * moving images able to submit odd partial windows. */
    s_disp_drv.rounder_cb=controls_rounder_cb;
    if(s_disp_drv.sw_rotate) {
        s_rotation_bytes=LV_DISP_ROT_MAX_BUF>target_bytes?LV_DISP_ROT_MAX_BUF:target_bytes;
        s_rotation_dma=(lv_color_t *)heap_caps_malloc(s_rotation_bytes,
                                             MALLOC_CAP_DMA|MALLOC_CAP_INTERNAL);
        if(!s_rotation_dma)return ESP_ERR_NO_MEM;
    }
    lv_disp_t *disp=lv_disp_drv_register(&s_disp_drv);
    if(!disp) return ESP_FAIL;
    if(pf_control_mode()==PF_CONTROL_BLE_PAD) {
        WsControlPrefs prefs;pf_controls_preferences(&prefs);
        ws_gamepad_view_init(disp,&prefs);
        s_flush_error=ESP_OK;lv_refr_now(NULL);
        if(s_flush_error!=ESP_OK)return s_flush_error;
        esp_err_t idle=ws_panel_wait_idle(500U);if(idle!=ESP_OK)return idle;
        s_ready=true;return ESP_OK;
    }

    s_3d_available=FIDO_V1_GUI_3D && ws_gui_3d_init();
    if(s_3d_available)ws_gui_3d_configure_tiles();
    ESP_LOGI(TAG,"Jet 3D: %s, PSRAM sources/scratch %u bytes",
             s_3d_available?"ready":"classic fallback",(unsigned)ws_gui_3d_stats().psram_bytes);
    /* USB.begin() runs after ws_lvgl_init(). A static tinfl_decompressor used
     * to consume 11 KB of internal BSS before TinyUSB could allocate its
     * endpoint/task state, which can make Windows reject the first descriptor. */
    s_unified_inflater=(tinfl_decompressor *)heap_caps_calloc(
        1U,sizeof(*s_unified_inflater),MALLOC_CAP_SPIRAM|MALLOC_CAP_8BIT);
    if(!s_unified_inflater) return ESP_ERR_NO_MEM;

    if(!s_unified_mint_pixels || !s_unified_crystal_pixels) {
        bool external=true;
        s_unified_mint_pixels=(uint8_t *)heap_caps_malloc(
            WS_UNIFIED_MINT_BUFFER_SIZE,MALLOC_CAP_SPIRAM|MALLOC_CAP_8BIT);
        s_unified_crystal_pixels=(uint8_t *)heap_caps_malloc(
            WS_UNIFIED_CRYSTAL_BUFFER_SIZE,MALLOC_CAP_SPIRAM|MALLOC_CAP_8BIT);
        if(!s_unified_mint_pixels || !s_unified_crystal_pixels) {
            if(s_unified_mint_pixels) heap_caps_free(s_unified_mint_pixels);
            if(s_unified_crystal_pixels) heap_caps_free(s_unified_crystal_pixels);
            external=false;
            s_unified_mint_pixels=(uint8_t *)heap_caps_malloc(
                WS_UNIFIED_MINT_BUFFER_SIZE,MALLOC_CAP_INTERNAL|MALLOC_CAP_8BIT);
            s_unified_crystal_pixels=(uint8_t *)heap_caps_malloc(
                WS_UNIFIED_CRYSTAL_BUFFER_SIZE,MALLOC_CAP_INTERNAL|MALLOC_CAP_8BIT);
        }
        if(!s_unified_mint_pixels || !s_unified_crystal_pixels) {
            if(s_unified_mint_pixels) heap_caps_free(s_unified_mint_pixels);
            if(s_unified_crystal_pixels) heap_caps_free(s_unified_crystal_pixels);
            s_unified_mint_pixels=NULL;
            s_unified_crystal_pixels=NULL;
            return ESP_ERR_NO_MEM;
        }
        memset(s_unified_mint_pixels,0,WS_UNIFIED_MINT_BUFFER_SIZE);
        memset(s_unified_crystal_pixels,0,WS_UNIFIED_CRYSTAL_BUFFER_SIZE);
        s_unified_mint_img.data=s_unified_mint_pixels;
        s_unified_crystal_img.data=s_unified_crystal_pixels;
        ESP_LOGI(TAG,"unified logo source: %u + %u bytes in %s",
                 (unsigned)WS_UNIFIED_MINT_BUFFER_SIZE,
                 (unsigned)WS_UNIFIED_CRYSTAL_BUFFER_SIZE,
                 external?"PSRAM":"internal RAM fallback");
    }

    /* Reuse LVGL's automatically created active screen instead of allocating
     * a second root screen. This saves heap on the no-PSRAM target. */
    ui.screen=lv_disp_get_scr_act(disp);
    if(!ui.screen) return ESP_FAIL;
    base_obj(ui.screen,0,0,WS_LCD_WIDTH,WS_LCD_HEIGHT);
    lv_obj_set_style_bg_opa(ui.screen,LV_OPA_COVER,0);
    lv_obj_set_style_bg_color(ui.screen,color(COL_BG),0);
    build_main();
    build_screensaver();
    build_settings();
    build_air_mouse();
    build_pin();
    s_apps_pixels=(uint16_t *)heap_caps_malloc(EK_APPS_PIXELS*sizeof(uint16_t),
                                                MALLOC_CAP_SPIRAM|MALLOC_CAP_8BIT);
    if(s_apps_pixels) {
        memset(s_apps_pixels,0,EK_APPS_PIXELS*sizeof(uint16_t));
        s_apps_img.data=(const uint8_t *)s_apps_pixels;
    }
    s_launcher_pixels=(uint8_t *)heap_caps_calloc(EK_APPS_PAGE_SIZE,EK_APPS_ICON_BYTES,
        MALLOC_CAP_SPIRAM|MALLOC_CAP_8BIT);
    build_apps();
    for(unsigned i=0;i<3;++i) hidden(ui.progress_dot[i],true);
    hidden(ui.result_flare,true);
    hidden(ui.screensaver_group,true);
    hidden(ui.settings_group,true);
    hidden(ui.air_mouse_group,true);
    hidden(ui.air_mouse_settings_group,true);
    hidden(ui.pin_group,true);
    s_flush_error=ESP_OK;
    lv_refr_now(NULL);
    if(s_flush_error!=ESP_OK) return s_flush_error;
    esp_err_t idle=ws_panel_wait_idle(500U);
    if(idle!=ESP_OK) return idle;
    s_ready=true;
    return ESP_OK;
}

static void set_hero_colour(uint32_t rgb)
{
    lv_obj_set_style_border_color(ui.hero_outer,color(rgb),0);
    lv_obj_set_style_border_color(ui.hero_mid,color(rgb),0);
    lv_obj_set_style_border_color(ui.hero_inner,color(rgb),0);
    lv_obj_set_style_bg_color(ui.hero_inner,color(rgb),0);
    lv_obj_set_style_arc_color(ui.hero_orbit,color(rgb),LV_PART_MAIN);
    lv_obj_set_style_arc_color(ui.hero_orbit,color(rgb),LV_PART_INDICATOR);
    lv_obj_set_style_arc_color(ui.hero_glint,color(rgb),LV_PART_INDICATOR);
    lv_obj_set_style_arc_color(ui.spinner_arc_a,color(rgb),LV_PART_MAIN);
    lv_obj_set_style_arc_color(ui.spinner_arc_a,color(rgb),LV_PART_INDICATOR);
    lv_obj_set_style_arc_color(ui.spinner_arc_b,color(rgb),LV_PART_MAIN);
    lv_obj_set_style_arc_color(ui.spinner_arc_b,color(rgb),LV_PART_INDICATOR);
    for(unsigned i=0;i<ICON_COUNT;++i) icon_tint(&ui.icons[i],rgb);
}

static const uint8_t PREMIUM_WAVE_LUT[64]={
    0,1,3,6,11,18,25,33,41,52,62,73,84,96,109,121,
    133,145,158,170,181,192,202,213,221,229,237,243,248,252,254,255,
    255,254,252,248,243,237,229,221,213,202,192,181,170,158,145,133,
    121,109,96,84,73,62,52,41,33,25,18,11,6,3,1,0
};

static uint8_t premium_wave(uint8_t phase)
{
    /* R22 moves the R19 smoothstep curve into a 64-byte LUT. Screensaver and
     * hero motion call this many times per frame, so eliminating integer
     * multiply/divide work keeps more CPU time available for rasterization. */
    return PREMIUM_WAVE_LUT[phase&63U];
}

static void set_tool_led_opa(lv_obj_t *obj,lv_opa_t value,lv_opa_t *cached,bool force)
{
    if(force || *cached!=value) {
        lv_obj_set_style_opa(obj,value,0);
        *cached=value;
    }
}

static void apply_tool_led(ws_tool_led_t *led,bool active,uint8_t wave)
{
    /* The lens and core remain stable. Only the active outer ring breathes,
     * avoiding the muddy overlap seen when the 80 ms R/G storage signal was
     * passed through a crossfade. No object moves, scales or allocates. */
    const lv_opa_t pulse=active?(lv_opa_t)(38U+wave/4U):6U;
    const lv_opa_t lens=active?220U:34U;
    const lv_opa_t core=active?246U:16U;
    const lv_opa_t glint=active?172U:12U;
    const bool force=!led->visual_valid;
    set_tool_led_opa(led->pulse,pulse,&led->pulse_opa,force);
    set_tool_led_opa(led->lens,lens,&led->lens_opa,force);
    set_tool_led_opa(led->core,core,&led->core_opa,force);
    set_tool_led_opa(led->glint,glint,&led->glint_opa,force);
    led->visual_valid=true;
}

static void update_tool_leds(const ws_ui_snapshot_t *v)
{
    const uint8_t wave=v->settings_animation?premium_wave(v->animation_phase):128U;
    apply_tool_led(&ui.tool_led_red,v->usb_tool_ducky_led==1U,wave);
    apply_tool_led(&ui.tool_led_green,v->usb_tool_ducky_led==2U,wave);
}

static void set_screensaver_colour(uint32_t accent)
{
    lv_obj_t *const arcs[]={
        ui.screensaver_outer,ui.screensaver_mid,ui.screensaver_inner,
        ui.screensaver_orbit_a,ui.screensaver_orbit_b,ui.screensaver_orbit_c
    };
    for(unsigned i=0;i<sizeof(arcs)/sizeof(arcs[0]);++i) {
        lv_obj_set_style_arc_color(arcs[i],color(accent),LV_PART_MAIN);
        lv_obj_set_style_arc_color(arcs[i],color(i==4U?COL_LED_RED:accent),LV_PART_INDICATOR);
    }
    lv_obj_set_style_img_recolor(ui.screensaver_logo_glow,color(accent),0);
    for(unsigned i=0;i<2U;++i)
        lv_obj_set_style_img_recolor(ui.screensaver_glitch_slice[i],color(accent),0);
    lv_obj_set_style_text_color(ui.screensaver_brand,color(COL_TEXT),0);
    lv_obj_set_style_text_color(ui.screensaver_caption,color(accent),0);
    for(unsigned i=0;i<4;++i) lv_obj_set_style_bg_color(ui.screensaver_spark[i],color(accent),0);
}

static uint8_t screensaver_text_opacity(uint16_t phase)
{
    /* R25 exact 9.000 s cycle at 25 ms/tick:
     *   40 ticks = 1.000 s eased fade-in
     *  200 ticks = 5.000 s fully visible hold
     *   40 ticks = 1.000 s eased fade-out
     *   80 ticks = 2.000 s fully dark hold
     * The first half of PREMIUM_WAVE_LUT is a monotonic 0..255 ease curve. */
    if(phase<40U) {
        unsigned idx=((unsigned)phase*31U+19U)/39U;
        if(idx>31U) idx=31U;
        return PREMIUM_WAVE_LUT[idx];
    }
    if(phase<240U) return 255U;
    if(phase<280U) {
        unsigned down=(unsigned)(phase-240U);
        unsigned idx=((39U-down)*31U+19U)/39U;
        if(idx>31U) idx=31U;
        return PREMIUM_WAVE_LUT[idx];
    }
    return 0U;
}

static void update_screensaver_motion(const ws_ui_snapshot_t *v,uint32_t accent)
{
    const uint16_t phase=v->screensaver_phase;
    /* Both layers are projected from the same plane. The crystal's own
     * 72-frame vertical rotation is already composed into each 24 ms pair. */
    if(!s_3d_available)(void)decode_unified_logo(phase,accent);
    const uint8_t breathe=premium_wave((uint8_t)(phase>>1));
    const uint8_t drift_x=premium_wave((uint8_t)((phase>>2)+7U));
    const uint8_t drift_y=premium_wave((uint8_t)((phase>>2)+23U));
    const uint8_t logo_wave=premium_wave((uint8_t)((phase>>1)+11U));
    /* 1024 x 24 ms closes every orbit at the same speed as before:
     * outer 4 turns, mid 6 turns, fast 10 turns, half-fast 5 turns. */
    const int rot=((int)phase*1440)/1024;
    const int rot2=((int)phase*2160)/1024;
    const int rot_fast=((int)phase*3600)/1024;

    /* R23 fixed-core rendering is retained.  Only children move inside the
     * coherent 252x252 invalid area, so logo/orbits remain tear-resistant. */
    lv_arc_set_rotation(ui.screensaver_outer,(int16_t)(rot%360));
    lv_arc_set_rotation(ui.screensaver_mid,(int16_t)((540-(rot2%360))%360));
    lv_arc_set_rotation(ui.screensaver_inner,(int16_t)((rot2+137)%360));
    lv_arc_set_rotation(ui.screensaver_orbit_a,(int16_t)((rot_fast+17)%360));
    lv_arc_set_rotation(ui.screensaver_orbit_b,(int16_t)((720-(rot_fast%360))%360));
    lv_arc_set_rotation(ui.screensaver_orbit_c,(int16_t)((rot_fast/2+211)%360));

    lv_obj_set_style_arc_opa(ui.screensaver_outer,(lv_opa_t)(34U+breathe/6U),LV_PART_INDICATOR);
    lv_obj_set_style_arc_opa(ui.screensaver_mid,(lv_opa_t)(22U+breathe/8U),LV_PART_INDICATOR);
    lv_obj_set_style_arc_opa(ui.screensaver_inner,(lv_opa_t)(28U+breathe/7U),LV_PART_INDICATOR);
    lv_obj_set_style_arc_opa(ui.screensaver_orbit_a,(lv_opa_t)(118U+breathe/3U),LV_PART_INDICATOR);
    lv_obj_set_style_arc_opa(ui.screensaver_orbit_b,(lv_opa_t)(72U+breathe/4U),LV_PART_INDICATOR);
    lv_obj_set_style_arc_opa(ui.screensaver_orbit_c,(lv_opa_t)(48U+breathe/5U),LV_PART_INDICATOR);

    /* The same 28x20 px closed path runs in every mode. The 200 px mark and
     * 216 px halo stay within the fixed 252 px core at every phase. */
    {
        const int logo_x=SAVER_LOGO_BASE+((int)logo_wave*28)/255-14;
        const int logo_y=SAVER_LOGO_BASE+((int)drift_y*20)/255-10;
        if(lv_obj_get_x(ui.screensaver_logo)!=logo_x+WS_UNIFIED_MINT_X_OFFSET)
            lv_obj_set_x(ui.screensaver_logo,logo_x+WS_UNIFIED_MINT_X_OFFSET);
        if(lv_obj_get_y(ui.screensaver_logo)!=logo_y+WS_UNIFIED_MINT_Y_OFFSET)
            lv_obj_set_y(ui.screensaver_logo,logo_y+WS_UNIFIED_MINT_Y_OFFSET);
        if(lv_obj_get_x(ui.screensaver_logo_white)!=logo_x+WS_UNIFIED_CRYSTAL_X_OFFSET)
            lv_obj_set_x(ui.screensaver_logo_white,logo_x+WS_UNIFIED_CRYSTAL_X_OFFSET);
        if(lv_obj_get_y(ui.screensaver_logo_white)!=logo_y+WS_UNIFIED_CRYSTAL_Y_OFFSET)
            lv_obj_set_y(ui.screensaver_logo_white,logo_y+WS_UNIFIED_CRYSTAL_Y_OFFSET);

        const int glow_x=logo_x-8+((int)drift_x*3)/255;
        const int glow_y=logo_y-8+((int)drift_y*2)/255;
        if(lv_obj_get_x(ui.screensaver_logo_glow)!=glow_x) lv_obj_set_x(ui.screensaver_logo_glow,glow_x);
        if(lv_obj_get_y(ui.screensaver_logo_glow)!=glow_y) lv_obj_set_y(ui.screensaver_logo_glow,glow_y);
    }
    lv_obj_set_style_opa(ui.screensaver_logo,(lv_opa_t)(224U+breathe/9U),0);
    lv_obj_set_style_opa(ui.screensaver_logo_white,(lv_opa_t)(224U+breathe/9U),0);
    lv_obj_set_style_opa(ui.screensaver_logo_glow,(lv_opa_t)(36U+breathe/13U),0);

    /* Every mode shares the same logo/orbit animation. Two deterministic
     * eight-frame tears (192 ms each) close on the 256-step phase boundary.
     * The original EVILKEY/firmware/hint text and navigation stay untouched. */
    const uint16_t local=phase&255U;
    const bool glitch=(local>=62U && local<70U) || (local>=190U && local<198U);
    hidden(ui.screensaver_logo_ghost,!glitch);
    hidden(ui.screensaver_glitch_scan,!glitch);
    for(unsigned i=0;i<2U;++i) {
        hidden(ui.screensaver_glitch_cover[i],!glitch);
        hidden(ui.screensaver_glitch_slice[i],!glitch);
    }
    if(glitch) {
        const unsigned step=local<70U?(unsigned)(local-62U):(unsigned)(local-190U);
        const int logo_x=lv_obj_get_x(ui.screensaver_logo)-WS_UNIFIED_MINT_X_OFFSET;
        const int logo_y=lv_obj_get_y(ui.screensaver_logo)-WS_UNIFIED_MINT_Y_OFFSET;
        const int shifts[2]={step<4U?3:-2,step<4U?-2:3};
        static const int16_t strip_top[2]={50,129};
        lv_obj_set_pos(ui.screensaver_logo_ghost,
                       logo_x+WS_UNIFIED_MINT_X_OFFSET+2,
                       logo_y+WS_UNIFIED_MINT_Y_OFFSET);
        for(unsigned i=0;i<2U;++i) {
            lv_obj_set_pos(ui.screensaver_glitch_cover[i],logo_x,logo_y+strip_top[i]);
            lv_obj_set_pos(ui.screensaver_glitch_slice[i],logo_x+shifts[i],logo_y+strip_top[i]);
        }
        lv_obj_set_y(ui.screensaver_glitch_scan,98+(int)step*5);
    }

    if(s_3d_available) {
        update_3d_image(WS_3D_SAVER,phase,accent,0);
        lv_obj_set_pos(s_3d_objects[WS_3D_SAVER],
                       SAVER_LOGO_BASE+((int)logo_wave*28)/255-14,
                       SAVER_LOGO_BASE+((int)drift_y*20)/255-10);
        hidden(ui.screensaver_logo_ghost,true);hidden(ui.screensaver_glitch_scan,true);
        for(unsigned i=0;i<2U;i++){hidden(ui.screensaver_glitch_cover[i],true);hidden(ui.screensaver_glitch_slice[i],true);}
    }
    /* R25: typography never changes x/y. Fade all three lines in lockstep and
     * update only while opacity is changing. The exact 5.000 s bright and 2.000 s
     * dark plateaus therefore generate no text redraw traffic at all. */
    const uint8_t text_opa=screensaver_text_opacity(v->screensaver_text_phase);
    if(text_opa!=s_screensaver_text_opa) {
        const lv_opa_t brand_opa=(lv_opa_t)text_opa;
        const lv_opa_t caption_opa=(lv_opa_t)(((unsigned)text_opa*216U+127U)/255U);
        const lv_opa_t hint_opa=(lv_opa_t)(((unsigned)text_opa*154U+127U)/255U);
        lv_obj_set_style_opa(ui.screensaver_brand,brand_opa,0);
        lv_obj_set_style_opa(ui.screensaver_caption,caption_opa,0);
        lv_obj_set_style_opa(ui.screensaver_hint,hint_opa,0);
        s_screensaver_text_opa=text_opa;
    }

    static const int16_t spark_base[4][2]={{26,60},{248,104},{239,286},{35,296}};
    for(unsigned i=0;i<4;++i) {
        const uint8_t w=premium_wave((uint8_t)((phase>>1)+(uint8_t)(i*13U)));
        const uint8_t q=premium_wave((uint8_t)((phase>>2)+(uint8_t)(i*9U)));
        const int sx=spark_base[i][0]+((int)q*8)/255-4;
        const int sy=spark_base[i][1]+((int)w*10)/255-5;
        if(lv_obj_get_x(ui.screensaver_spark[i])!=sx) lv_obj_set_x(ui.screensaver_spark[i],sx);
        if(lv_obj_get_y(ui.screensaver_spark[i])!=sy) lv_obj_set_y(ui.screensaver_spark[i],sy);
        lv_obj_set_style_bg_opa(ui.screensaver_spark[i],(lv_opa_t)(12U+w/4U),0);
    }

    lv_obj_invalidate(ui.screensaver_core);
    (void)accent;
}

static void update_premium_motion(const ws_ui_snapshot_t *v,hero_icon_id_t hero,uint32_t rgb)
{
    // The status symbol is static; update_main refreshes it on state/theme
    // changes. Animate only the surrounding halo, without invalidating Jet.
    const uint8_t wave=premium_wave(v->animation_phase);
    const int rotation=((int)(v->animation_phase&63U)*360)/64;
    lv_arc_set_rotation(ui.hero_orbit,(int16_t)rotation);
    lv_arc_set_rotation(ui.hero_glint,(int16_t)((360-rotation)%360));
    lv_obj_set_style_arc_color(ui.hero_orbit,color(rgb),LV_PART_MAIN);
    lv_obj_set_style_arc_color(ui.hero_orbit,color(rgb),LV_PART_INDICATOR);
    lv_obj_set_style_arc_color(ui.hero_glint,color(rgb),LV_PART_INDICATOR);
    lv_obj_set_style_arc_opa(ui.hero_orbit,(lv_opa_t)(86U+wave/8U),LV_PART_INDICATOR);
    lv_obj_set_style_arc_opa(ui.hero_glint,(lv_opa_t)(34U+wave/12U),LV_PART_INDICATOR);
    lv_obj_set_style_border_opa(ui.hero_outer,(lv_opa_t)(25U+wave/24U),0);
    lv_obj_set_style_border_opa(ui.hero_mid,(lv_opa_t)(15U+wave/32U),0);
    lv_obj_set_style_bg_opa(ui.hero_inner,(lv_opa_t)(7U+wave/48U),0);
    lv_obj_set_style_opa(ui.icons[hero].root,LV_OPA_COVER,0);

    if(hero==HERO_SPINNER) {
        for(unsigned i=0;i<3;++i) {
            // Three complete dot cycles per halo loop, including its wrap.
            unsigned age=(i+3U-(((v->animation_phase*9U)/64U)%3U))%3U;
            lv_obj_set_style_bg_color(ui.progress_dot[i],color(rgb),0);
            lv_obj_set_style_bg_opa(ui.progress_dot[i],(lv_opa_t)(age==0U?235U:age==1U?105U:38U),0);
        }
    }
}

static void update_spinner(uint8_t phase,uint32_t rgb)
{
    const int rotation=((int)(phase&63U)*720)/64;
    lv_obj_set_style_arc_color(ui.spinner_arc_a,color(rgb),LV_PART_INDICATOR);
    lv_obj_set_style_arc_color(ui.spinner_arc_a,color(rgb),LV_PART_MAIN);
    lv_obj_set_style_arc_color(ui.spinner_arc_b,color(rgb),LV_PART_INDICATOR);
    lv_obj_set_style_arc_color(ui.spinner_arc_b,color(rgb),LV_PART_MAIN);
    lv_arc_set_rotation(ui.spinner_arc_a,(int16_t)(rotation%360));
    lv_arc_set_rotation(ui.spinner_arc_b,(int16_t)((720-rotation)%360));
}

static void set_title_font(const lv_font_t *font)
{
    lv_obj_set_style_text_font(ui.title,font,0);
}

static bool settings_pressed(const ws_ui_snapshot_t *v,ws_settings_action_t action)
{
    return v->settings_pressed_action==(uint8_t)action;
}

static void settings_control(lv_obj_t *box,lv_obj_t *text,bool pressed,uint32_t accent)
{
    set_card(box,pressed?COL_PANEL2:COL_PANEL,pressed?accent:COL_BORDER,1);
    lv_obj_set_style_bg_grad_color(box,color(pressed?COL_PANEL:COL_PANEL2),0);
    lv_obj_set_style_bg_grad_dir(box,LV_GRAD_DIR_VER,0);
    lv_obj_set_style_border_width(box,pressed?2:1,0);
    lv_obj_set_style_text_color(text,color(pressed?accent:COL_TEXT),0);
}

static void settings_row_layout(ws_setting_row_t *r,unsigned index)
{
    int y=WS_SETTINGS_ROW_Y+(int)index*WS_SETTINGS_ROW_DY;
    lv_obj_set_pos(r->card,WS_SETTINGS_ROW_X,y);
    lv_obj_set_size(r->card,WS_SETTINGS_ROW_W,WS_SETTINGS_ROW_H);
    lv_obj_set_pos(r->title,12,10);lv_obj_set_size(r->title,236,28);
    lv_obj_set_style_text_font(r->title,&lv_font_montserrat_20,0);
    lv_obj_set_pos(r->minus,WS_SETTINGS_MINUS_X-WS_SETTINGS_ROW_X,WS_SETTINGS_CONTROL_Y_IN_ROW);
    lv_obj_set_size(r->minus,WS_SETTINGS_MINUS_W,WS_SETTINGS_CONTROL_H);
    lv_obj_set_pos(r->value,WS_SETTINGS_VALUE_X-WS_SETTINGS_ROW_X,WS_SETTINGS_CONTROL_Y_IN_ROW);
    lv_obj_set_size(r->value,WS_SETTINGS_VALUE_W,WS_SETTINGS_CONTROL_H);
    lv_obj_set_pos(r->plus,WS_SETTINGS_PLUS_X-WS_SETTINGS_ROW_X,WS_SETTINGS_CONTROL_Y_IN_ROW);
    lv_obj_set_size(r->plus,WS_SETTINGS_PLUS_W,WS_SETTINGS_CONTROL_H);
    lv_obj_set_pos(r->minus_label,0,8);lv_obj_set_size(r->minus_label,WS_SETTINGS_MINUS_W,34);
    lv_obj_set_pos(r->plus_label,0,8);lv_obj_set_size(r->plus_label,WS_SETTINGS_PLUS_W,34);
    lv_obj_set_pos(r->value_label,2,12);lv_obj_set_size(r->value_label,WS_SETTINGS_VALUE_W-4,28);
    lv_obj_set_style_text_font(r->value_label,&lv_font_montserrat_20,0);
    lv_obj_set_style_text_align(r->value_label,LV_TEXT_ALIGN_CENTER,0);
}

static void settings_row_set(ws_setting_row_t *r,const char *title,const char *value,
                             bool wide,bool left_pressed,bool right_pressed,
                             bool value_pressed,uint32_t accent)
{
    hidden(r->card,false);
    set_text(r->title,title,COL_TEXT);
    set_text(r->value_label,value,COL_TEXT);
    settings_control(r->minus,r->minus_label,left_pressed,accent);
    settings_control(r->plus,r->plus_label,right_pressed,accent);
    settings_control(r->value,r->value_label,value_pressed,accent);
    hidden(r->minus,wide);
    hidden(r->plus,wide);
    if(wide) {
        lv_obj_set_pos(r->value,WS_SETTINGS_WIDE_X-WS_SETTINGS_ROW_X,WS_SETTINGS_CONTROL_Y_IN_ROW);
        lv_obj_set_width(r->value,WS_SETTINGS_WIDE_W);
        lv_obj_set_width(r->value_label,WS_SETTINGS_WIDE_W-4);
        lv_obj_set_style_text_font(r->value_label,&lv_font_montserrat_18,0);
    } else {
        lv_obj_set_pos(r->value,WS_SETTINGS_VALUE_X-WS_SETTINGS_ROW_X,WS_SETTINGS_CONTROL_Y_IN_ROW);
        lv_obj_set_width(r->value,WS_SETTINGS_VALUE_W);
        lv_obj_set_width(r->value_label,WS_SETTINGS_VALUE_W-4);
        lv_obj_set_style_text_font(r->value_label,&lv_font_montserrat_20,0);
    }
}

static unsigned brightness_percent(uint8_t raw)
{
    return ((unsigned)raw*100U+127U)/255U;
}

static const char *settings_default_subtitle(uint8_t page)
{
    if(page==WS_SETTINGS_PAGE_GAMEPAD || page==WS_SETTINGS_PAGE_AIR_MOUSE) {
        const char *last=pf_ble_last_status();if(last && *last)return last;
    }
    switch((ws_settings_page_t)page) {
    case WS_SETTINGS_PAGE_DISPLAY:return "Brightness";
    case WS_SETTINGS_PAGE_APPEARANCE:return "Colour and motion";
    case WS_SETTINGS_PAGE_POWER:return "Idle screen behaviour";
    case WS_SETTINGS_PAGE_AUTH:return "Interaction timeouts";
    case WS_SETTINGS_PAGE_AIR_MOUSE:return "Tilt pointer / touch controls";
    case WS_SETTINGS_PAGE_GAMEPAD:return "Landscape touchscreen / BLE";
    case WS_SETTINGS_PAGE_USB:return "USB Mass Storage / microSD";
    case WS_SETTINGS_PAGE_USB_TOOL:return "HID automation / DuckyScript";
    case WS_SETTINGS_PAGE_DIAGNOSTICS:return "Display and memory";
    case WS_SETTINGS_PAGE_HOME:
    default:return "";
    }
}

static void update_settings(const ws_ui_snapshot_t *v,uint32_t accent)
{
    uint8_t page=v->settings_page<WS_SETTINGS_PAGE_COUNT?v->settings_page:WS_SETTINGS_PAGE_HOME;
    const bool home=page==WS_SETTINGS_PAGE_HOME;

    icon_tint(&ui.settings_gear,accent);
    lv_obj_set_style_border_color(ui.settings_glow,color(accent),0);
    lv_obj_set_style_bg_color(ui.settings_glow,color(accent),0);
    lv_obj_set_style_border_opa(ui.settings_glow,34,0);
    lv_obj_set_style_bg_opa(ui.settings_glow,LV_OPA_TRANSP,0);
    lv_obj_t *const settings_arcs[]={ui.settings_orbit,ui.settings_orbit_inner,ui.settings_glint};
    for(unsigned i=0;i<sizeof(settings_arcs)/sizeof(settings_arcs[0]);++i)
        lv_obj_set_style_arc_color(settings_arcs[i],color(accent),LV_PART_INDICATOR);
    lv_obj_set_style_arc_opa(ui.settings_orbit,88,LV_PART_INDICATOR);
    lv_obj_set_style_arc_opa(ui.settings_orbit_inner,62,LV_PART_INDICATOR);
    lv_obj_set_style_arc_opa(ui.settings_glint,116,LV_PART_INDICATOR);
    lv_arc_set_rotation(ui.settings_orbit,0);
    lv_arc_set_rotation(ui.settings_orbit_inner,180);
    lv_arc_set_rotation(ui.settings_glint,32);
    hidden(ui.settings_glow,!home);
    hidden(ui.settings_orbit,!home);
    hidden(ui.settings_orbit_inner,!home);
    hidden(ui.settings_glint,!home);
    for(unsigned i=0;i<4U;++i) {
        lv_obj_set_style_bg_color(ui.settings_spark[i],color(accent),0);
        hidden(ui.settings_spark[i],!home);
    }
    hidden(ui.settings_gear.root,!home);

    for(unsigned i=0;i<SETTINGS_ROWS;++i) {
        hidden(ui.settings_row[i].card,true);
        settings_row_layout(&ui.settings_row[i],i);
    }
    hidden(ui.settings_swatch,true);
    hidden(ui.diagnostics_card,page!=WS_SETTINGS_PAGE_DIAGNOSTICS);
    hidden(ui.diagnostics_save,page!=WS_SETTINGS_PAGE_DIAGNOSTICS);
    hidden(ui.settings_return,page==WS_SETTINGS_PAGE_DIAGNOSTICS);
    hidden(ui.settings_footer,page==WS_SETTINGS_PAGE_DIAGNOSTICS);
    hidden(ui.air_mouse_info_card,true);

    const char *title="SETTINGS";
    switch((ws_settings_page_t)page) {
    case WS_SETTINGS_PAGE_DISPLAY:title="DISPLAY";break;
    case WS_SETTINGS_PAGE_APPEARANCE:title="APPEARANCE";break;
    case WS_SETTINGS_PAGE_POWER:title="SCREEN POWER";break;
    case WS_SETTINGS_PAGE_AUTH:title="FIDO TIMING";break;
    case WS_SETTINGS_PAGE_AIR_MOUSE:title="AIR MOUSE";break;
    case WS_SETTINGS_PAGE_GAMEPAD:title="BLE GAMEPAD";break;
    case WS_SETTINGS_PAGE_USB:title="USB & STORAGE";break;
    case WS_SETTINGS_PAGE_USB_TOOL:title="USB TOOL";break;
    case WS_SETTINGS_PAGE_DIAGNOSTICS:title="DIAGNOSTICS";break;
    case WS_SETTINGS_PAGE_HOME:
    default:break;
    }

    const char *sub=settings_default_subtitle(page);
    uint32_t sub_col=home?COL_MUTED:COL_FAINT;
    if(v->manager_drive_restarting || v->usb_tool_restarting || v->air_mouse_restarting) { sub="Restarting device...";sub_col=COL_WARN; }
    else if(!v->settings_storage_ok || !v->manager_drive_storage_ok || !v->usb_tool_storage_ok) { sub="Settings storage error";sub_col=COL_BAD; }
    else if(v->settings_feedback==WS_SETTINGS_FEEDBACK_SAVED) { sub="Saved";sub_col=accent; }
    else if(v->settings_feedback==WS_SETTINGS_FEEDBACK_PIN_REQUIRED) { sub="FIDO PIN unavailable";sub_col=COL_WARN; }
    else if(v->settings_feedback==WS_SETTINGS_FEEDBACK_PIN_BAD) { sub="Wrong PIN - still READ ONLY";sub_col=COL_BAD; }
    else if(v->settings_feedback==WS_SETTINGS_FEEDBACK_PIN_BLOCKED) { sub="PIN blocked - still READ ONLY";sub_col=COL_BAD; }
    else if(v->settings_feedback==WS_SETTINGS_FEEDBACK_PIN_CANCELLED) { sub="Write access cancelled";sub_col=COL_MUTED; }
    else if(v->settings_feedback==WS_SETTINGS_FEEDBACK_PIN_TIMEOUT) { sub="PIN timeout - still READ ONLY";sub_col=COL_WARN; }
    else if(v->settings_feedback==WS_SETTINGS_FEEDBACK_ERROR) { sub="Could not save";sub_col=COL_BAD; }
    if(page==WS_SETTINGS_PAGE_DIAGNOSTICS){
        sub=v->diagnostics_export_status==EK_DIAGNOSTICS_EXPORT_BUSY?"Saving report...":
            v->diagnostics_export_message[0]?v->diagnostics_export_message:"/evilkey/diagnostics";
        sub_col=v->diagnostics_export_status==EK_DIAGNOSTICS_EXPORT_ERROR?COL_BAD:
            v->diagnostics_export_status==EK_DIAGNOSTICS_EXPORT_SAVED?accent:COL_MUTED;
    }

    set_text(ui.settings_title,title,COL_TEXT);
    set_text(ui.settings_subtitle,sub,sub_col);
    hidden(ui.settings_subtitle,home && !sub[0]);
    if(home) {
        lv_obj_set_pos(ui.settings_title,10,222);lv_obj_set_size(ui.settings_title,260,38);
        lv_obj_set_style_text_font(ui.settings_title,&lv_font_montserrat_28,0);
        lv_obj_set_style_text_align(ui.settings_title,LV_TEXT_ALIGN_CENTER,0);
        lv_obj_set_pos(ui.settings_subtitle,10,276);lv_obj_set_size(ui.settings_subtitle,260,30);
        lv_obj_set_style_text_font(ui.settings_subtitle,&lv_font_montserrat_20,0);
        lv_obj_set_style_text_align(ui.settings_subtitle,LV_TEXT_ALIGN_CENTER,0);
    } else {
        lv_obj_set_pos(ui.settings_title,12,24);lv_obj_set_size(ui.settings_title,256,38);
        lv_obj_set_style_text_font(ui.settings_title,&lv_font_montserrat_28,0);
        lv_obj_set_style_text_align(ui.settings_title,LV_TEXT_ALIGN_LEFT,0);
        lv_obj_set_pos(ui.settings_subtitle,12,67);lv_obj_set_size(ui.settings_subtitle,256,22);
        lv_obj_set_style_text_font(ui.settings_subtitle,&lv_font_montserrat_14,0);
        lv_obj_set_style_text_align(ui.settings_subtitle,LV_TEXT_ALIGN_LEFT,0);
    }

    char value[28];
    switch((ws_settings_page_t)page) {
    case WS_SETTINGS_PAGE_DISPLAY:
        snprintf(value,sizeof(value),"%u%%",brightness_percent(v->brightness));
        settings_row_set(&ui.settings_row[0],"Screen brightness",value,false,
            settings_pressed(v,WS_SETTINGS_ACTION_BRIGHTNESS_MINUS),
            settings_pressed(v,WS_SETTINGS_ACTION_BRIGHTNESS_PLUS),false,accent);
        snprintf(value,sizeof(value),"%u%%",brightness_percent(v->dim_brightness));
        settings_row_set(&ui.settings_row[1],"Dimmed brightness",value,false,
            settings_pressed(v,WS_SETTINGS_ACTION_DIM_BRIGHTNESS_MINUS),
            settings_pressed(v,WS_SETTINGS_ACTION_DIM_BRIGHTNESS_PLUS),false,accent);
        break;
    case WS_SETTINGS_PAGE_APPEARANCE:
        snprintf(value,sizeof(value),"%06lX",(unsigned long)(accent&0xFFFFFFUL));
        settings_row_set(&ui.settings_row[0],"Accent colour",value,false,
            settings_pressed(v,WS_SETTINGS_ACTION_ACCENT_PREV),
            settings_pressed(v,WS_SETTINGS_ACTION_ACCENT_NEXT),false,accent);
        hidden(ui.settings_swatch,false);
        set_card(ui.settings_swatch,accent,accent,0);
        lv_obj_set_pos(ui.settings_swatch,8,17);
        lv_obj_set_pos(ui.settings_row[0].value_label,30,12);
        lv_obj_set_size(ui.settings_row[0].value_label,70,28);
        lv_obj_set_style_text_font(ui.settings_row[0].value_label,&lv_font_montserrat_14,0);
        settings_row_set(&ui.settings_row[1],"Processing animation",
            v->settings_animation?"ON":"OFF",true,false,false,
            settings_pressed(v,WS_SETTINGS_ACTION_ANIMATION_TOGGLE),accent);
        if(v->settings_animation)
            set_card_flat(ui.settings_row[1].value,accent,accent,1);
        else
            set_card(ui.settings_row[1].value,COL_PANEL,COL_BORDER,1);
        set_text(ui.settings_row[1].value_label,v->settings_animation?"ON":"OFF",
                 v->settings_animation?COL_INK:COL_MUTED);
        break;
    case WS_SETTINGS_PAGE_POWER:
        snprintf(value,sizeof(value),"%u s",v->settings_dim_seconds);
        settings_row_set(&ui.settings_row[0],"Dim after idle",value,false,
            settings_pressed(v,WS_SETTINGS_ACTION_DIM_SECONDS_MINUS),
            settings_pressed(v,WS_SETTINGS_ACTION_DIM_SECONDS_PLUS),false,accent);
        snprintf(value,sizeof(value),"%u s",v->settings_off_seconds);
        settings_row_set(&ui.settings_row[1],"Screen off after dim",value,false,
            settings_pressed(v,WS_SETTINGS_ACTION_OFF_SECONDS_MINUS),
            settings_pressed(v,WS_SETTINGS_ACTION_OFF_SECONDS_PLUS),false,accent);
        break;
    case WS_SETTINGS_PAGE_AUTH:
        snprintf(value,sizeof(value),"%u s",v->settings_presence_seconds);
        settings_row_set(&ui.settings_row[0],"Confirmation timeout",value,false,
            settings_pressed(v,WS_SETTINGS_ACTION_PRESENCE_SECONDS_MINUS),
            settings_pressed(v,WS_SETTINGS_ACTION_PRESENCE_SECONDS_PLUS),false,accent);
        snprintf(value,sizeof(value),"%u s",v->settings_uv_seconds);
        settings_row_set(&ui.settings_row[1],"PIN entry timeout",value,false,
            settings_pressed(v,WS_SETTINGS_ACTION_UV_SECONDS_MINUS),
            settings_pressed(v,WS_SETTINGS_ACTION_UV_SECONDS_PLUS),false,accent);
        break;
    case WS_SETTINGS_PAGE_AIR_MOUSE:
        settings_row_set(&ui.settings_row[0],"Transport",v->controls.transport?"BLE":"USB HID",
            true,false,false,settings_pressed(v,WS_SETTINGS_ACTION_AIR_MOUSE_TRANSPORT),accent);
        settings_row_set(&ui.settings_row[1],"Air Mouse",
            v->air_mouse_restarting?"STARTING":v->air_mouse_available?"START":"N/A",
            true,false,false,settings_pressed(v,WS_SETTINGS_ACTION_AIR_MOUSE_START),accent);
        break;
    case WS_SETTINGS_PAGE_GAMEPAD:
        settings_row_set(&ui.settings_row[0],"Host profile",v->controls.profile?"PC / XBOX":"ANDROID",
            true,false,false,settings_pressed(v,WS_SETTINGS_ACTION_GAMEPAD_PROFILE),accent);
        settings_row_set(&ui.settings_row[1],"Touchscreen Gamepad",
            v->air_mouse_restarting?"STARTING":v->touch_available?"START":"N/A",
            true,false,false,settings_pressed(v,WS_SETTINGS_ACTION_GAMEPAD_START),accent);
        break;
    case WS_SETTINGS_PAGE_USB: {
        const bool drive_ok=v->manager_drive_available && v->manager_drive_storage_ok;
        const char *drive_value=!v->manager_drive_available?"N/A":
            v->manager_drive_restarting?"RESTARTING":
            v->manager_drive_enabled?(v->manager_drive_media_ready?"ON":"NO SD"):"OFF";
        settings_row_set(&ui.settings_row[0],"USB Mass Storage",drive_value,true,false,false,
            settings_pressed(v,WS_SETTINGS_ACTION_MANAGER_DRIVE_TOGGLE),accent);
        if(drive_ok && v->manager_drive_enabled && v->manager_drive_media_ready) {
            set_card_flat(ui.settings_row[0].value,accent,accent,1);
            set_text(ui.settings_row[0].value_label,"ON",COL_INK);
        } else if(v->manager_drive_enabled && !v->manager_drive_media_ready) {
            set_card_flat(ui.settings_row[0].value,COL_WARN,COL_WARN,1);
            set_text(ui.settings_row[0].value_label,"NO SD",COL_BG);
        } else if(!drive_ok && v->manager_drive_available) {
            set_card_flat(ui.settings_row[0].value,COL_BAD,COL_BAD,1);
            set_text(ui.settings_row[0].value_label,"ERROR",COL_BG);
        }
        const char *ro_value=!v->manager_drive_available?"N/A":
            (v->manager_drive_read_only?"READ ONLY":"READ / WRITE");
        settings_row_set(&ui.settings_row[1],"microSD access",ro_value,true,false,false,
            settings_pressed(v,WS_SETTINGS_ACTION_MANAGER_RO_TOGGLE),accent);
        if(v->manager_drive_available) {
            if(v->manager_drive_read_only)
                set_card(ui.settings_row[1].value,COL_PANEL2,accent,1);
            else
                set_card_flat(ui.settings_row[1].value,accent,accent,1);
            set_text(ui.settings_row[1].value_label,ro_value,
                     v->manager_drive_read_only?accent:COL_INK);
        }
        break;
    }
    case WS_SETTINGS_PAGE_USB_TOOL: {
        const char *tool_value=!v->usb_tool_available?"N/A":
            v->usb_tool_restarting?"RESTARTING":v->usb_tool_enabled?"ON":"OFF";
        settings_row_set(&ui.settings_row[0],"USB Tool mode",tool_value,true,false,false,
            settings_pressed(v,WS_SETTINGS_ACTION_USB_TOOL_TOGGLE),accent);
        if(v->usb_tool_enabled) {
            set_card_flat(ui.settings_row[0].value,accent,accent,1);
            set_text(ui.settings_row[0].value_label,"ON",COL_INK);
        }
        const char *layout=v->usb_tool_language_name[0]?v->usb_tool_language_name:"US";
        settings_row_set(&ui.settings_row[1],"Keyboard layout",layout,false,
            settings_pressed(v,WS_SETTINGS_ACTION_USB_LAYOUT_PREV),
            settings_pressed(v,WS_SETTINGS_ACTION_USB_LAYOUT_NEXT),false,accent);
        break;
    }
    case WS_SETTINGS_PAGE_DIAGNOSTICS: {
        bool saving=v->diagnostics_export_status==EK_DIAGNOSTICS_EXPORT_BUSY;
        bool pressed=settings_pressed(v,WS_SETTINGS_ACTION_DIAGNOSTICS_SAVE);
        set_card_flat(ui.diagnostics_save,pressed&&!saving?accent:COL_PANEL2,
            saving?COL_FAINT:accent,1);
        set_text(ui.diagnostics_save_label,v->diagnostics_export_status==EK_DIAGNOSTICS_EXPORT_BUSY?"Saving...":"Save report",saving?COL_FAINT:pressed?COL_INK:accent);
        settings_row_set(&ui.settings_row[0],"Show live status",
            v->diagnostics_enabled?"ON":"OFF",true,false,false,
            settings_pressed(v,WS_SETTINGS_ACTION_DIAGNOSTICS_TOGGLE),accent);
        if(v->diagnostics_enabled) {
            set_card_flat(ui.settings_row[0].value,accent,accent,1);
            set_text(ui.settings_row[0].value_label,"ON",COL_INK);
            const unsigned rows=(unsigned)(s_draw_pixels/WS_LCD_WIDTH);
            snprintf(value,sizeof(value),"%u x %u  RGB565",s_pixels_b?2U:1U,rows);
            set_text(ui.diagnostics_value,value,accent);
            char memory[128];
            snprintf(memory,sizeof(memory),"DMA free %u KB  /  max %u KB\nPSRAM %u KB / %s",
                (unsigned)(heap_caps_get_free_size(MALLOC_CAP_DMA|MALLOC_CAP_INTERNAL)/1024U),
                (unsigned)(heap_caps_get_largest_free_block(MALLOC_CAP_DMA|MALLOC_CAP_INTERNAL)/1024U),
                (unsigned)(heap_caps_get_free_size(MALLOC_CAP_SPIRAM|MALLOC_CAP_8BIT)/1024U),
                s_staging[0]?"DMA 2x16":"direct DMA");
            const unsigned section=(v->diagnostics_tick/3U)%7U;
            if(section==1U) {
                snprintf(value,sizeof(value),"%u apps / %u headers",v->apps_count,
                         (unsigned)v->apps_headers_read);
                snprintf(memory,sizeof(memory),"Mount %u / scan %u ms\nIcons %u ms (page %u)",
                    (unsigned)v->apps_mount_ms,(unsigned)v->apps_scan_ms,
                    (unsigned)v->apps_icon_ms,(unsigned)v->launcher_page+1);
                set_text(ui.diagnostics_title,"APPS CATALOG",COL_MUTED);
            } else if(section==2U) {
                lv_mem_monitor_t pool;lv_mem_monitor(&pool);
                ws_gui_3d_presentation_stats_t ps=ws_gui_3d_presentation_stats();
                snprintf(value,sizeof(value),"Poll max %u ms",(unsigned)v->ui_poll_gap_ms);
                snprintf(memory,sizeof(memory),"CPU %u ms / pool %u KB\nFrame P95 %u / wait %u ms\n%u flush / %u KB",
                    (unsigned)v->ui_render_ms,(unsigned)(pool.free_size/1024U),
                    (unsigned)(ps.p95_us/1000U),(unsigned)(ps.panel_wait_us/1000U),
                    (unsigned)ps.flushes,(unsigned)(ps.bytes/1024U));
                set_text(ui.diagnostics_title,"UI LATENCY",COL_MUTED);
            } else if(section==3U) {
                ws_gui_3d_stats_t jet=ws_gui_3d_stats();
                const unsigned channel=(v->diagnostics_tick/12U)%WS_3D_CHANNELS;
                static const char *names[]={"Saver","Settings","Status","Apps"};
                ws_gui_3d_channel_stats_t cs=ws_gui_3d_channel_stats(channel);
                snprintf(value,sizeof(value),"%s: %s",names[channel],jet.ready?"Jet ON":"FALLBACK");
                snprintf(memory,sizeof(memory),"P50 %u / P95 %u ms\nG %u / R %u / C %u us\n%u tris / samples %u %s",
                         (unsigned)(cs.p50_us/1000U),(unsigned)(cs.p95_us/1000U),
                         (unsigned)cs.geometry_us,(unsigned)cs.raster_us,(unsigned)cs.convert_us,
                         (unsigned)cs.triangles,(unsigned)cs.detail_samples,v->diagnostics_enabled?"live":"1/8");
                set_text(ui.diagnostics_title,"3D RENDERER",COL_MUTED);
            } else if(section==6U) {
                EkRenderWorkerStats cores;ek_render_worker_stats(&cores);
                set_text(ui.diagnostics_title,"RENDER CORES",COL_MUTED);
                snprintf(value,sizeof(value),"%s",cores.ready&&cores.enabled?"Dual core":"Serial fallback");
                snprintf(memory,sizeof(memory),"C0 %u / C1 %u\nStack %u / %u B",
                    (unsigned)cores.jobs[0],(unsigned)cores.jobs[1],
                    (unsigned)cores.stack_free[0],(unsigned)cores.stack_free[1]);
            } else if(section>=4U) {
                EkSceneProfile native;ek_apps_scene_profile(&native);
                set_text(ui.diagnostics_title,section==4U?"NATIVE SCENE3D":"SCENE COPY / CLOCK",COL_MUTED);
                if(native.stats.status) {
                    if(section==4U) {
                        const char *status=native.stats.status==EVILKEY_3D_OK?"OK":
                            native.stats.status==EVILKEY_3D_TIMEOUT?"Timeout":"Error";
                        snprintf(value,sizeof(value),"%s / %u us",status,(unsigned)native.stats.elapsed_us);
                        snprintf(memory,sizeof(memory),"Clr %u / cam %u us\nGeom %u (raster %u)",
                                 (unsigned)native.clear_us,(unsigned)native.setup_us,
                                 (unsigned)native.geometry_us,(unsigned)native.raster_us);
                    } else {
                        snprintf(value,sizeof(value),"Copy %u us",(unsigned)native.reconstruct_us);
                        snprintf(memory,sizeof(memory),"Gap %u us / %u clocks\n%u tris / %u pixels",
                                 (unsigned)native.max_clock_gap_us,(unsigned)native.clock_calls,
                                 (unsigned)native.stats.triangles,(unsigned)native.stats.pixel_tests);
                    }
                } else {
                    snprintf(value,sizeof(value),"No scene sample");
                    snprintf(memory,sizeof(memory),"Run a 3D app, then exit\nWall us / geom includes raster");
                }
            } else set_text(ui.diagnostics_title,"DRAW BUFFER",COL_MUTED);
            set_text(ui.diagnostics_value,value,accent);
            set_text(ui.diagnostics_memory,memory,COL_MUTED);
        } else {
            set_text(ui.diagnostics_value,"OFF",COL_FAINT);
            set_text(ui.diagnostics_memory,"Enable to show memory status",COL_MUTED);
        }
        if(!v->diagnostics_enabled)set_text(ui.diagnostics_title,"DRAW BUFFER",COL_MUTED);
        break;
    }
    case WS_SETTINGS_PAGE_HOME:
    default:
        break;
    }

    set_text(ui.settings_footer,"SWIPE UP / DOWN",COL_FAINT);
    set_text(ui.settings_return,v->apps_catalog_ready && v->apps_count?
        "SWIPE RIGHT / APPS":"SWIPE RIGHT / HOME",COL_FAINT);
    lv_obj_set_style_text_align(ui.settings_footer,LV_TEXT_ALIGN_CENTER,0);
    lv_obj_set_style_text_align(ui.settings_return,LV_TEXT_ALIGN_CENTER,0);
    for(unsigned i=0;i<SETTINGS_DOTS;++i) {
        bool active=i==page;
        lv_obj_set_style_bg_color(ui.settings_dot[i],color(active?accent:COL_FAINT),0);
        lv_obj_set_style_bg_opa(ui.settings_dot[i],active?LV_OPA_COVER:LV_OPA_40,0);
    }
}

static void update_landing_halo(lv_obj_t *glow,lv_obj_t *orbit,lv_obj_t *orbit_inner,
                                lv_obj_t *glint,lv_obj_t **spark,uint8_t phase,
                                bool animated,uint32_t accent)
{
    if(!animated)phase=0;
    /* premium_wave() is a 64-step closed curve. Divide the 256-step Settings
     * phase by four so ambient luminance breathes exactly once per full loop. */
    const uint8_t wave=animated?premium_wave((uint8_t)(phase>>2)):0U;
    const uint8_t phase_quarter=(uint8_t)(phase+64U);
    const uint8_t wave2=animated?premium_wave((uint8_t)(phase_quarter>>2)):0U;
    const int rotation=((int)phase*360)/256;
    const int inner_rotation=(180+360-rotation)%360;
    const int glint_rotation=(32+rotation*2)%360;

    /* One deterministic closed composition. The gear is the visual anchor;
     * the outer and inner strokes each complete one whole turn in opposite
     * directions over the same 6.144 s period, while the glint completes two.
     * At phase 255 -> 0 every object advances only by its normal angular step. */
    halo_cache_t *cache=&s_halo_cache[glow==ui.settings_glow?0:1];
    const bool changed=!cache->valid || cache->glow!=glow || cache->accent!=accent;
    const uint8_t opacity[8]={animated?22U+wave/16U:34U,animated?82U+wave/16U:88U,
        animated?58U+wave2/18U:62U,animated?108U+wave/12U:116U,
        42U+wave/20U,48U+wave2/20U,46U+wave/20U,52U+wave2/20U};
    const int rotations[3]={rotation,inner_rotation,glint_rotation};
    if(changed){
        lv_obj_set_style_border_color(glow,color(accent),0);
        lv_obj_set_style_bg_color(glow,color(accent),0);
        lv_obj_set_style_bg_opa(glow,LV_OPA_TRANSP,0);
        lv_obj_set_style_arc_color(orbit,color(accent),LV_PART_INDICATOR);
        lv_obj_set_style_arc_color(orbit_inner,color(accent),LV_PART_INDICATOR);
        lv_obj_set_style_arc_color(glint,color(accent),LV_PART_INDICATOR);
        for(unsigned i=0;i<4U;++i)lv_obj_set_style_bg_color(spark[i],color(accent),0);
    }
    if(changed || cache->opacity[0]!=opacity[0])lv_obj_set_style_border_opa(glow,opacity[0],0);
    lv_obj_t *arcs[3]={orbit,orbit_inner,glint};
    for(unsigned i=0;i<3U;++i){
        if(changed || cache->opacity[i+1]!=opacity[i+1])lv_obj_set_style_arc_opa(arcs[i],opacity[i+1],LV_PART_INDICATOR);
        if(changed || cache->rotation[i]!=rotations[i])lv_arc_set_rotation(arcs[i],(int16_t)rotations[i]);
    }
    for(unsigned i=0;i<4U;++i)if(changed || cache->opacity[i+4]!=opacity[i+4])lv_obj_set_style_bg_opa(spark[i],opacity[i+4],0);
    cache->glow=glow;cache->accent=accent;cache->valid=true;
    memcpy(cache->opacity,opacity,sizeof opacity);memcpy(cache->rotation,rotations,sizeof rotations);

}

static void update_settings_motion(const ws_ui_snapshot_t *v,uint32_t accent)
{
    if(v->settings_page!=WS_SETTINGS_PAGE_HOME)return;
    update_3d_image(WS_3D_GEAR,v->settings_animation?v->settings_motion_phase:0,accent,0);
    update_landing_halo(ui.settings_glow,ui.settings_orbit,ui.settings_orbit_inner,
        ui.settings_glint,ui.settings_spark,v->settings_motion_phase,v->settings_animation,accent);
}

static void main_state(const ws_ui_snapshot_t *v,uint32_t accent)
{
    const char *title="Connect USB";
    const char *l1="Connect to your";
    const char *l2="computer.";
    uint32_t hero_col=COL_MUTED;
    hero_icon_id_t hero=HERO_USB;
    const lv_font_t *title_font=&lv_font_montserrat_34;
    const bool tool=v->usb_tool_enabled && ws_ui_settings_allowed(v->state);
    if(tool) {
        title="USB Tool";
        l1=v->usb_tool_script_count?(v->usb_tool_script_name[0]?v->usb_tool_script_name:"Payload selected"):
           (v->usb_tool_media_ready?"No payloads found":"Insert microSD");
        static char tool_meta[64];
        const char *layout=v->usb_tool_language_name[0]?v->usb_tool_language_name:"US";
        if(v->usb_tool_script_count)
            snprintf(tool_meta,sizeof(tool_meta),"%s  •  %u / %u",layout,(unsigned)v->usb_tool_selected_index+1U,(unsigned)v->usb_tool_script_count);
        else snprintf(tool_meta,sizeof(tool_meta),"%s  •  /duckyscripts",layout);
        l2=tool_meta;hero=HERO_KEY;hero_col=accent;title_font=&lv_font_montserrat_28;
    }

    if(!tool) switch(v->state) {
    case WS_UI_READY:
        title="Ready";l1="Start sign-in on";l2="your computer.";
        hero=HERO_KEY;hero_col=accent;break;
    case WS_UI_PROCESSING:
        title="Processing";l1="Please wait...";l2="Keep USB connected.";
        hero=HERO_SPINNER;hero_col=accent;break;
    case WS_UI_WAITING:
        title="Confirm request";l1="Only approve";l2="your own request.";
        hero=HERO_TOUCH;hero_col=accent;title_font=&lv_font_montserrat_28;break;
    case WS_UI_CONFIRMED:
        title="Success";l1="Request approved.";l2="Continue on computer.";
        hero=HERO_CHECK;hero_col=accent;break;
    case WS_UI_CANCELLED:
        title="Cancelled";l1="Request stopped.";l2="Start again to retry.";
        hero=HERO_CROSS;hero_col=COL_MUTED;break;
    case WS_UI_TIMEOUT:
        title="Time expired";l1="Request timed out.";l2="Start again to retry.";
        hero=HERO_CLOCK;hero_col=COL_WARN;title_font=&lv_font_montserrat_28;break;
    case WS_UI_PIN_BAD:
        title="Incorrect PIN";l1="Try again from";l2="your computer.";
        hero=HERO_LOCK;hero_col=COL_BAD;title_font=&lv_font_montserrat_28;break;
    case WS_UI_PIN_BLOCKED:
        title="PIN unavailable";l1="Check PIN retries";l2="on your computer.";
        hero=HERO_LOCK;hero_col=COL_BAD;title_font=&lv_font_montserrat_28;break;
    case WS_UI_INPUT_ERROR:
        title="Input unavailable";l1="Check the display";l2="and touch input.";
        hero=HERO_WARNING;hero_col=COL_BAD;title_font=&lv_font_montserrat_28;break;
    case WS_UI_SUSPENDED:
        title="Standby";l1="Waiting for a";l2="sign-in request.";
        hero=HERO_MOON;hero_col=COL_MUTED;break;
    case WS_UI_DISCONNECTED:
    default:
        hero=HERO_USB;hero_col=COL_MUTED;break;
    }

    icon_tint(&ui.brand_key,accent);
    set_hero_colour(hero_col);
    icon_show_only(hero);
    if(s_3d_available){update_3d_image(WS_3D_HERO,0,hero_col,hero);
        for(unsigned i=0;i<ICON_COUNT;i++)hidden(ui.icons[i].root,true);}
    if(!v->settings_animation) {
        lv_arc_set_rotation(ui.hero_orbit,0);
        lv_arc_set_rotation(ui.hero_glint,0);
        lv_obj_set_style_arc_opa(ui.hero_orbit,88,LV_PART_INDICATOR);
        lv_obj_set_style_arc_opa(ui.hero_glint,36,LV_PART_INDICATOR);
        lv_obj_set_style_border_opa(ui.hero_outer,34,0);
        lv_obj_set_style_border_opa(ui.hero_mid,20,0);
        lv_obj_set_style_bg_opa(ui.hero_inner,9,0);
        lv_obj_set_style_opa(ui.icons[hero].root,LV_OPA_COVER,0);
    }

    const bool processing=v->state==WS_UI_PROCESSING;
    for(unsigned i=0;i<3;++i) {
        hidden(ui.progress_dot[i],!processing);
        if(processing && !v->settings_animation) {
            static const lv_opa_t still_opa[3]={235,105,38};
            lv_obj_set_style_bg_color(ui.progress_dot[i],color(hero_col),0);
            lv_obj_set_style_bg_opa(ui.progress_dot[i],still_opa[i],0);
        }
    }
    const bool result=v->state==WS_UI_CONFIRMED || v->state==WS_UI_CANCELLED ||
                      v->state==WS_UI_TIMEOUT || v->state==WS_UI_PIN_BAD ||
                      v->state==WS_UI_PIN_BLOCKED || v->state==WS_UI_INPUT_ERROR;
    hidden(ui.result_flare,!result);
    if(result) {
        set_card(ui.result_flare,hero_col,hero_col,0);
        lv_obj_set_style_bg_opa(ui.result_flare,150,0);
    }

    set_title_font(title_font);
    set_text(ui.title,title,COL_TEXT);
    set_text(ui.line1,l1,COL_MUTED);
    set_text(ui.line2,l2,COL_MUTED);

    hidden(ui.tool_prev,true);hidden(ui.tool_run,true);hidden(ui.tool_next,true);
    hidden(ui.tool_led_group,!tool);
    if(tool) {
        update_tool_leds(v);
        lv_obj_set_pos(ui.title,8,196);lv_obj_set_size(ui.title,264,40);
        lv_obj_set_pos(ui.line1,14,246);lv_obj_set_size(ui.line1,252,28);
        lv_obj_set_pos(ui.line2,8,278);lv_obj_set_size(ui.line2,264,24);
        lv_obj_set_style_text_font(ui.line1,&lv_font_montserrat_18,0);
        lv_obj_set_style_text_font(ui.line2,&lv_font_montserrat_14,0);
        hidden(ui.countdown,true);hidden(ui.approve,true);hidden(ui.cancel,true);
        hidden(ui.tool_prev,false);hidden(ui.tool_run,false);hidden(ui.tool_next,false);
        const bool can_select=v->usb_tool_script_count>1U && !v->usb_tool_running;
        const bool can_run=v->usb_tool_media_ready && v->usb_tool_script_count>0U;
        const bool prev_pressed=can_select && v->usb_tool_pressed_action==WS_USB_TOOL_ACTION_PREV;
        const bool next_pressed=can_select && v->usb_tool_pressed_action==WS_USB_TOOL_ACTION_NEXT;
        const bool run_pressed=(can_run||v->usb_tool_running) && v->usb_tool_pressed_action==WS_USB_TOOL_ACTION_RUN_STOP;
        set_card(ui.tool_prev,prev_pressed?COL_PANEL2:COL_PANEL,can_select?accent:COL_BORDER,1);
        set_text(ui.tool_prev_label,"PREV",can_select?COL_TEXT:COL_FAINT);
        set_card(ui.tool_next,next_pressed?COL_PANEL2:COL_PANEL,can_select?accent:COL_BORDER,1);
        set_text(ui.tool_next_label,"NEXT",can_select?COL_TEXT:COL_FAINT);
        if(v->usb_tool_running) {
            set_card(ui.tool_run,run_pressed?COL_BAD_DIM:COL_BG,COL_BAD,1);
            set_text(ui.tool_run_label,"STOP",COL_TEXT);
        } else {
            set_card(ui.tool_run,run_pressed?COL_TEXT:(can_run?accent:COL_PANEL),can_run?accent:COL_BORDER,1);
            set_text(ui.tool_run_label,"RUN",can_run?(run_pressed?COL_INK:COL_INK):COL_FAINT);
        }
        const char *status=v->usb_tool_status_text[0]?v->usb_tool_status_text:
            (v->usb_tool_media_ready?"Ready":"Script storage unavailable");
        uint32_t status_col=COL_MUTED;
        if(v->usb_tool_status==3U)status_col=accent;
        else if(v->usb_tool_status==4U)status_col=accent;
        else if(v->usb_tool_status==5U)status_col=COL_BAD;
        else if(v->usb_tool_status==1U)status_col=COL_WARN;
        if(v->usb_tool_storage_active)status_col=COL_WARN;
        const char *storage_suffix=v->usb_tool_storage_active?"  •  SD":"";
        char status_line[128];
        if(v->usb_tool_status==5U && v->usb_tool_error_line)
            snprintf(status_line,sizeof(status_line),"%s  •  line %lu%s",status,
                (unsigned long)v->usb_tool_error_line,storage_suffix);
        else snprintf(status_line,sizeof(status_line),"%s%s",status,storage_suffix);
        set_text(ui.usb,status_line,status_col);
        lv_obj_set_pos(ui.usb,8,394);lv_obj_set_size(ui.usb,264,22);
        lv_obj_set_style_text_font(ui.usb,&lv_font_montserrat_14,0);
        hidden(ui.usb,false);hidden(ui.settings_swipe,false);
        set_text(ui.settings_swipe,v->apps_catalog_ready && v->apps_count?"SWIPE LEFT / APPS":"SWIPE LEFT / SETTINGS",COL_FAINT);
        lv_obj_set_style_text_align(ui.settings_swipe,LV_TEXT_ALIGN_CENTER,0);
        return;
    }

    const bool waiting=v->state==WS_UI_WAITING;
    if(waiting) {
        lv_obj_set_pos(ui.title,8,53);
        lv_obj_set_size(ui.title,264,40);
        lv_obj_set_pos(ui.line1,8,194);
        lv_obj_set_pos(ui.line2,8,224);

        char sec[24];
        snprintf(sec,sizeof(sec),"%u s",v->seconds_left>120U?120U:v->seconds_left);
        set_text(ui.countdown,sec,v->seconds_left<=10U?COL_WARN:COL_MUTED);
        hidden(ui.countdown,false);
        hidden(ui.approve,false);
        hidden(ui.cancel,false);
        hidden(ui.usb,true);
        hidden(ui.settings_swipe,true);

        const bool touch=v->touch_enabled && v->touch_available;
        uint32_t abg=touch?accent:COL_PANEL;
        uint32_t aedge=touch?accent:COL_BORDER;
        uint32_t afg=touch?COL_INK:COL_TEXT;
        if(touch && v->pressed_action==WS_ACTION_APPROVE) abg=COL_TEXT;
        set_card(ui.approve,abg,aedge,1);
        lv_obj_set_style_bg_grad_color(ui.approve,color(touch?abg:COL_PANEL2),0);
        lv_obj_set_style_border_width(ui.approve,touch?1:1,0);
        set_text(ui.approve_label,touch?"Approve":(v->boot_allowed?"Press BOOT":"Touch unavailable"),afg);

        const bool cancel_down=touch && v->pressed_action==WS_ACTION_CANCEL;
        set_card(ui.cancel,cancel_down?COL_BAD_DIM:COL_BG,cancel_down?COL_BAD:COL_BORDER,1);
        lv_obj_set_style_bg_grad_color(ui.cancel,color(cancel_down?COL_BAD_DIM:COL_PANEL),0);
        set_text(ui.cancel_label,touch?"Cancel":"Cancel on computer",COL_TEXT);
    } else {
        lv_obj_set_pos(ui.title,8,202);
        lv_obj_set_size(ui.title,264,44);
        lv_obj_set_pos(ui.line1,8,269);
        lv_obj_set_pos(ui.line2,8,300);
        hidden(ui.countdown,true);
        hidden(ui.approve,true);
        hidden(ui.cancel,true);

        /* Authentication/result screens stay visually isolated. Settings
         * navigation is available in idle states; write-enable PIN is modal. */
        const bool idle=ws_ui_settings_allowed(v->state);
        hidden(ui.usb,!idle);
        hidden(ui.settings_swipe,!idle);
        if(idle) {
            set_text(ui.usb,v->state==WS_UI_DISCONNECTED?"USB data unavailable":"USB connected",
                v->state==WS_UI_READY?accent:COL_MUTED);
            lv_obj_set_pos(ui.usb,8,382);
            set_text(ui.settings_swipe,v->apps_catalog_ready && v->apps_count?"SWIPE LEFT / APPS":"SWIPE LEFT / SETTINGS",COL_FAINT);
            lv_obj_set_style_text_align(ui.settings_swipe,LV_TEXT_ALIGN_CENTER,0);
        }
    }
}

static void update_pin_dots(unsigned len)
{
    unsigned visible=len<6U?6U:len>10U?10U:len;
    for(unsigned i=0;i<10;++i) {
        bool show=i<visible;
        hidden(ui.pin_dot[i],!show);
        if(!show) continue;
        if(i<len) {
            lv_obj_set_style_bg_color(ui.pin_dot[i],color(COL_TEXT),0);
            lv_obj_set_style_bg_opa(ui.pin_dot[i],LV_OPA_COVER,0);
            lv_obj_set_style_border_width(ui.pin_dot[i],0,0);
        } else {
            lv_obj_set_style_bg_opa(ui.pin_dot[i],LV_OPA_TRANSP,0);
            lv_obj_set_style_border_color(ui.pin_dot[i],color(COL_FAINT),0);
            lv_obj_set_style_border_width(ui.pin_dot[i],1,0);
            lv_obj_set_style_border_opa(ui.pin_dot[i],LV_OPA_COVER,0);
        }
    }
}

static void pin_state(const ws_ui_snapshot_t *v,uint32_t accent)
{
    icon_tint(&ui.brand_key,accent);
    const bool settings_rw=v->pin_purpose==WS_PIN_PURPOSE_ENABLE_RW;
    set_text(ui.pin_title,settings_rw?"Enable write access":"Enter PIN",COL_TEXT);
    set_text(ui.pin_scope,settings_rw?"FIDO PIN for READ/WRITE":scope_text(v->pin_permissions),COL_MUTED);
    unsigned len=v->pin_length>63U?63U:v->pin_length;
    unsigned tries=v->uv_retries>8U?8U:v->uv_retries;
    unsigned seconds=v->seconds_left>120U?120U:v->seconds_left;
    update_pin_dots(len);

    char buf[32];
    snprintf(buf,sizeof(buf),"%u digits",len);
    set_text(ui.pin_length,buf,COL_TEXT);
    snprintf(buf,sizeof(buf),"%u tries",tries);
    set_text(ui.pin_tries,buf,tries<=2U?COL_BAD:COL_MUTED);
    snprintf(buf,sizeof(buf),"%u s",seconds);
    set_text(ui.pin_seconds,buf,seconds<=10U?COL_WARN:COL_MUTED);

    const bool touch=v->touch_enabled && v->touch_available;
    static const char *const key_names[12]={"1","2","3","4","5","6","7","8","9","","0","Verify"};
    for(unsigned i=0;i<12;++i) {
        unsigned action=i<9?11U+i:i==9?20U:i==10?10U:21U;
        const bool enter=i==11;
        const bool enabled=touch && (!enter || len>=4U);
        const bool pressed=enabled && v->pressed_action==action;
        uint32_t bg=enter&&enabled?accent:COL_PANEL;
        uint32_t edge=enter&&enabled?accent:COL_BORDER;
        if(pressed) {
            bg=enter?COL_TEXT:COL_PANEL2;
            edge=enter?accent:COL_BORDER;
        }
        set_card(ui.keys[i],bg,edge,1);
        lv_obj_set_style_bg_grad_color(ui.keys[i],color(enter&&enabled?bg:COL_PANEL2),0);
        lv_obj_set_style_bg_grad_dir(ui.keys[i],LV_GRAD_DIR_VER,0);
        lv_obj_set_style_border_color(ui.key_press_ring[i],color(accent),0);
        lv_obj_set_style_border_opa(ui.key_press_ring[i],pressed?LV_OPA_COVER:LV_OPA_TRANSP,0);
        if(i!=9) set_text(ui.key_labels[i],enter && settings_rw?"Unlock":key_names[i],
                              enabled?(enter?COL_INK:COL_TEXT):COL_FAINT);
        if(i==9) icon_tint(&ui.backspace,enabled?COL_TEXT:COL_FAINT);
    }

    const bool cancel_pressed=touch && v->pressed_action==22U;
    set_card(ui.pin_cancel,cancel_pressed?COL_BAD_DIM:COL_BG,cancel_pressed?COL_BAD:COL_BORDER,1);
    set_text(ui.pin_cancel_label,"Cancel",touch?COL_TEXT:COL_FAINT);
}

static ws_ui_snapshot_t s_last_view;
static bool s_last_view_valid;
static hero_icon_id_t s_active_hero=HERO_KEY;
static uint32_t s_active_hero_colour=RGB24_DEFAULT;

static hero_icon_id_t hero_for_state(ws_ui_state_t state)
{
    switch(state) {
    case WS_UI_READY:return HERO_KEY;
    case WS_UI_PROCESSING:return HERO_SPINNER;
    case WS_UI_WAITING:return HERO_TOUCH;
    case WS_UI_CONFIRMED:return HERO_CHECK;
    case WS_UI_CANCELLED:return HERO_CROSS;
    case WS_UI_TIMEOUT:return HERO_CLOCK;
    case WS_UI_PIN_BAD:
    case WS_UI_PIN_BLOCKED:return HERO_LOCK;
    case WS_UI_INPUT_ERROR:return HERO_WARNING;
    case WS_UI_SUSPENDED:return HERO_MOON;
    case WS_UI_DISCONNECTED:
    default:return HERO_USB;
    }
}

static uint32_t hero_colour_for_state(ws_ui_state_t state,uint32_t accent)
{
    switch(state) {
    case WS_UI_READY:
    case WS_UI_PROCESSING:
    case WS_UI_WAITING:
    case WS_UI_CONFIRMED:return accent;
    case WS_UI_TIMEOUT:return COL_WARN;
    case WS_UI_PIN_BAD:
    case WS_UI_PIN_BLOCKED:
    case WS_UI_INPUT_ERROR:return COL_BAD;
    case WS_UI_CANCELLED:
    case WS_UI_SUSPENDED:
    case WS_UI_DISCONNECTED:
    default:return COL_MUTED;
    }
}

static bool main_content_changed(const ws_ui_snapshot_t *a,const ws_ui_snapshot_t *b)
{
    return a->state!=b->state || a->seconds_left!=b->seconds_left ||
        a->touch_available!=b->touch_available || a->touch_enabled!=b->touch_enabled ||
        a->boot_allowed!=b->boot_allowed || a->pressed_action!=b->pressed_action ||
        a->accent_rgb!=b->accent_rgb || a->settings_animation!=b->settings_animation ||
        a->apps_count!=b->apps_count || a->apps_catalog_ready!=b->apps_catalog_ready ||
        a->usb_tool_enabled!=b->usb_tool_enabled || a->usb_tool_media_ready!=b->usb_tool_media_ready ||
        a->usb_tool_running!=b->usb_tool_running || a->usb_tool_status!=b->usb_tool_status ||
        a->usb_tool_storage_active!=b->usb_tool_storage_active ||
        a->usb_tool_ducky_led!=b->usb_tool_ducky_led ||
        a->usb_tool_pressed_action!=b->usb_tool_pressed_action ||
        a->usb_tool_layout!=b->usb_tool_layout || a->usb_tool_script_count!=b->usb_tool_script_count ||
        a->usb_tool_selected_index!=b->usb_tool_selected_index || a->usb_tool_error_line!=b->usb_tool_error_line ||
        strcmp(a->usb_tool_script_name,b->usb_tool_script_name)!=0 ||
        strcmp(a->usb_tool_language_name,b->usb_tool_language_name)!=0 ||
        strcmp(a->usb_tool_status_text,b->usb_tool_status_text)!=0;
}

static bool settings_content_changed(const ws_ui_snapshot_t *a,const ws_ui_snapshot_t *b)
{
    return a->settings_page!=b->settings_page || a->settings_pressed_action!=b->settings_pressed_action ||
        memcmp(&a->controls,&b->controls,sizeof(a->controls))!=0 ||
        a->settings_feedback!=b->settings_feedback || a->settings_storage_ok!=b->settings_storage_ok ||
        a->settings_animation!=b->settings_animation || a->settings_dim_seconds!=b->settings_dim_seconds ||
        a->diagnostics_enabled!=b->diagnostics_enabled || a->diagnostics_tick!=b->diagnostics_tick ||
        a->diagnostics_export_request!=b->diagnostics_export_request ||
        a->diagnostics_export_status!=b->diagnostics_export_status ||
        strcmp(a->diagnostics_export_message,b->diagnostics_export_message)!=0 ||
        a->settings_off_seconds!=b->settings_off_seconds ||
        a->settings_presence_seconds!=b->settings_presence_seconds ||
        a->settings_uv_seconds!=b->settings_uv_seconds || a->brightness!=b->brightness ||
        a->dim_brightness!=b->dim_brightness || a->accent_rgb!=b->accent_rgb ||
        a->manager_drive_available!=b->manager_drive_available ||
        a->manager_drive_enabled!=b->manager_drive_enabled ||
        a->manager_drive_media_ready!=b->manager_drive_media_ready ||
        a->manager_drive_storage_ok!=b->manager_drive_storage_ok ||
        a->manager_drive_read_only!=b->manager_drive_read_only ||
        a->manager_drive_pressed!=b->manager_drive_pressed ||
        a->manager_drive_restarting!=b->manager_drive_restarting ||
        a->usb_tool_available!=b->usb_tool_available || a->usb_tool_enabled!=b->usb_tool_enabled ||
        a->usb_tool_storage_ok!=b->usb_tool_storage_ok || a->usb_tool_layout!=b->usb_tool_layout ||
        strcmp(a->usb_tool_language_name,b->usb_tool_language_name)!=0 ||
        a->usb_tool_restarting!=b->usb_tool_restarting ||
        a->air_mouse_available!=b->air_mouse_available ||
        a->air_mouse_restarting!=b->air_mouse_restarting ||
        a->apps_ready!=b->apps_ready || a->apps_mounted!=b->apps_mounted ||
        a->apps_running!=b->apps_running || a->apps_count!=b->apps_count ||
        a->apps_selected!=b->apps_selected ||
        strcmp(a->apps_id,b->apps_id)!=0 || strcmp(a->apps_status,b->apps_status)!=0;
}

static void update_air_mouse(const ws_ui_snapshot_t *v,uint32_t accent)
{
    if(ui.air_mouse_ble_dialog)hidden(ui.air_mouse_ble_dialog,!v->air_mouse_ble_modal);
    if(v->air_mouse_settings_open) {
        char sensitivity[12];
        snprintf(sensitivity,sizeof(sensitivity),"%u / 5",
                 (unsigned)v->air_mouse_sensitivity);
        set_text(ui.air_mouse_sensitivity_value,sensitivity,accent);
        set_text(ui.air_mouse_invert_value,v->air_mouse_invert_y?"ON":"OFF",
                 v->air_mouse_invert_y?accent:COL_TEXT);
        set_card(ui.air_mouse_sensitivity_minus,v->air_mouse_touch_zone==9U?COL_PANEL2:COL_PANEL,
                 v->air_mouse_touch_zone==9U?accent:COL_BORDER,1);
        set_card(ui.air_mouse_sensitivity_plus,v->air_mouse_touch_zone==10U?COL_PANEL2:COL_PANEL,
                 v->air_mouse_touch_zone==10U?accent:COL_BORDER,1);
        set_card(ui.air_mouse_invert,v->air_mouse_touch_zone==11U?COL_PANEL2:COL_PANEL,
                 v->air_mouse_touch_zone==11U?accent:COL_BORDER,1);
        set_card(ui.air_mouse_settings_calibrate,v->air_mouse_touch_zone==8U?COL_PANEL2:COL_PANEL,
                 v->air_mouse_touch_zone==8U?accent:COL_BORDER,1);
        set_card(ui.air_mouse_settings_back,v->air_mouse_touch_zone==7U?COL_PANEL2:COL_PANEL,
                 v->air_mouse_touch_zone==7U?accent:COL_BORDER,1);
        hidden(ui.air_mouse_settings_calibrate_progress,v->air_mouse_touch_zone!=8U);
        lv_obj_set_width(ui.air_mouse_settings_calibrate_progress,
                         1+(224*(int)v->air_mouse_hold_step)/30);
        set_card_flat(ui.air_mouse_settings_calibrate_progress,accent,accent,0);
        return;
    }
    set_card(ui.air_mouse_move,v->air_mouse_move_held?COL_PANEL2:COL_PANEL,
             v->air_mouse_move_held?accent:COL_BORDER,1);
    set_text(ui.air_mouse_title,v->air_mouse_drag_latched?"DRAG ACTIVE":
        v->air_mouse_move_held?"MOVING":"HOLD TO MOVE",accent);
    set_text(ui.air_mouse_hint,v->air_mouse_drag_latched?
        "Tap DRAG to release":"DRAG: tap to hold / release",COL_MUTED);
    set_card(ui.air_mouse_drag,v->air_mouse_drag_latched?accent:COL_PANEL,
        v->air_mouse_drag_latched?accent:COL_BORDER,1);
    set_text(ui.air_mouse_drag_label,v->air_mouse_drag_latched?"DRAG ON":"DRAG OFF",
        v->air_mouse_drag_latched?COL_INK:COL_TEXT);
    set_text(ui.air_mouse_status,v->air_mouse_touch_fault?"Touch unavailable":
        v->air_mouse_touch_outside?"Touch outside controls":
        !v->air_mouse_sensor_ok?"IMU unavailable":
        v->ble_failed?"BLE unavailable":
        v->state==WS_UI_DISCONNECTED?(v->controls.transport?"Pair BLE on host":"Connect USB"):
        v->air_mouse_calibrating?"Hold still to calibrate":"Pointer ready",
        v->air_mouse_touch_fault?COL_BAD:v->air_mouse_touch_outside?COL_WARN:
        !v->air_mouse_sensor_ok?COL_BAD:v->state==WS_UI_DISCONNECTED?COL_WARN:COL_TEXT);
    set_card(ui.air_mouse_exit,v->air_mouse_touch_zone==1U?COL_BAD_DIM:COL_PANEL,
             v->air_mouse_touch_zone==1U?COL_BAD:COL_BORDER,1);
    set_card(ui.air_mouse_calibrate,v->air_mouse_touch_zone==2U?COL_PANEL2:COL_PANEL,
             v->air_mouse_touch_zone==2U?accent:COL_BORDER,1);
    const int progress_width=1+(108*(int)v->air_mouse_hold_step)/30;
    hidden(ui.air_mouse_exit_progress,v->air_mouse_touch_zone!=1U);
    hidden(ui.air_mouse_calibrate_progress,v->air_mouse_touch_zone!=2U);
    lv_obj_set_width(ui.air_mouse_exit_progress,progress_width);
    lv_obj_set_width(ui.air_mouse_calibrate_progress,progress_width);
    set_card_flat(ui.air_mouse_exit_progress,COL_BAD,COL_BAD,0);
    set_card_flat(ui.air_mouse_calibrate_progress,accent,accent,0);
    set_card(ui.air_mouse_left,(v->air_mouse_buttons&1U)?accent:COL_PANEL,
             (v->air_mouse_buttons&1U)?accent:COL_BORDER,1);
    lv_obj_set_style_text_color(ui.air_mouse_left_label,
        color((v->air_mouse_buttons&1U)?COL_INK:COL_TEXT),0);
    set_card(ui.air_mouse_right,(v->air_mouse_buttons&2U)?accent:COL_PANEL,
             (v->air_mouse_buttons&2U)?accent:COL_BORDER,1);
    lv_obj_set_style_text_color(ui.air_mouse_right_label,
        color((v->air_mouse_buttons&2U)?COL_INK:COL_TEXT),0);
    set_card(ui.air_mouse_scroll,v->air_mouse_touch_zone==5U?COL_PANEL2:COL_PANEL,
             v->air_mouse_touch_zone==5U?accent:COL_BORDER,1);
}

static bool screensaver_content_changed(const ws_ui_snapshot_t *a,const ws_ui_snapshot_t *b)
{
    return a->accent_rgb!=b->accent_rgb;
}

static bool pin_content_changed(const ws_ui_snapshot_t *a,const ws_ui_snapshot_t *b)
{
    return a->pin_length!=b->pin_length || a->uv_retries!=b->uv_retries ||
        a->pin_permissions!=b->pin_permissions || a->pin_purpose!=b->pin_purpose ||
        a->seconds_left!=b->seconds_left || a->pressed_action!=b->pressed_action ||
        a->touch_available!=b->touch_available || a->touch_enabled!=b->touch_enabled ||
        a->accent_rgb!=b->accent_rgb;
}

static void update_launcher(const ws_ui_snapshot_t *v,uint32_t accent)
{
    bool copied=s_launcher_pixels && ek_apps_copy_icons(s_launcher_pixels,
        EK_APPS_PAGE_SIZE*EK_APPS_ICON_BYTES,&s_launcher_generation);
    if(copied) {
        for(unsigned i=0;i<EK_APPS_PAGE_SIZE*EK_APPS_ICON_BYTES;i+=2) {
            uint8_t c=s_launcher_pixels[i];s_launcher_pixels[i]=s_launcher_pixels[i+1];
            s_launcher_pixels[i+1]=c;
        }
    }
    unsigned pages=(v->apps_count+EK_APPS_PAGE_SIZE-1)/EK_APPS_PAGE_SIZE;
    bool intro=v->launcher_page==0;
    hidden(ui.launcher_intro,!intro);
    hidden(ui.launcher_header,intro);
    hidden(ui.launcher_counter,intro);
    hidden(ui.launcher_content,intro);
    lv_obj_set_y(ui.launcher_intro,v->launcher_page_offset);
    for(unsigned i=0;i<EK_APPS_PAGE_SIZE;++i) {
        bool occupied=!intro && ((unsigned)v->launcher_page-1)*EK_APPS_PAGE_SIZE+i<v->apps_count;
        bool valid=(v->apps_icon_valid&(1u<<i))!=0;
        hidden(ui.launcher_cell[i],!occupied);
        bool pressed=v->launcher_pressed==i+1 && valid;
        set_card_flat(ui.launcher_cell[i],pressed?COL_PANEL2:COL_GLASS,
            pressed?accent:COL_BORDER,pressed?2:1);
        if(ui.launcher_icon[i]) {
            hidden(ui.launcher_icon[i],!valid);
            if(copied) {
                lv_img_cache_invalidate_src(&s_launcher_img[i]);
                lv_obj_invalidate(ui.launcher_icon[i]);
            }
        }
        set_text(ui.launcher_name[i],v->apps_names[i],valid?COL_TEXT:COL_FAINT);
    }
    char counter[32];snprintf(counter,sizeof(counter),"%u / %u",
        intro?0:(unsigned)v->launcher_page,pages);
    set_text(ui.launcher_counter,counter,COL_MUTED);
    char count_status[40];snprintf(count_status,sizeof(count_status),"%u apps on microSD",v->apps_count);
    set_text(ui.launcher_count,count_status,COL_MUTED);
    const char *status=!v->apps_status[0] || strcmp(v->apps_status,"Tap an app to run")==0?
        "SWIPE RIGHT / HOME":v->apps_status;
    set_text(ui.launcher_status,!s_launcher_pixels?"Icon memory unavailable":
        v->apps_scanning?"Scanning microSD...":status,COL_FAINT);
    for(unsigned i=0;i<9;++i) {
        hidden(ui.launcher_dot[i],i>=pages+1);
        int x=(WS_LCD_WIDTH-(int)(pages*18+6))/2+(int)i*18;
        lv_obj_set_x(ui.launcher_dot[i],x);
        bool active=i==v->launcher_page;
        lv_obj_set_style_bg_color(ui.launcher_dot[i],color(active?accent:COL_FAINT),0);
        lv_obj_set_style_bg_opa(ui.launcher_dot[i],active?LV_OPA_COVER:LV_OPA_40,0);
    }
    lv_obj_set_y(ui.launcher_content,v->launcher_page_offset);
    /* A grid/intro switch changes visibility of nested transparent groups.
     * Repaint the launcher once after structural changes; child-only dirty
     * rectangles can leave static intro labels/tiles missing after paging.
     * Do not invalidate the full group on ordinary animation ticks. */
    if(!s_last_view_valid || s_last_view.launcher_page!=v->launcher_page ||
       s_last_view.apps_count!=v->apps_count)
        lv_obj_invalidate(ui.launcher_group);
}

static void update_launcher_motion(const ws_ui_snapshot_t *v,uint32_t accent)
{
    if(v->launcher_page!=0) return;
    unsigned phase=v->settings_animation?v->settings_motion_phase:0;
    update_3d_image(WS_3D_APPS,(uint16_t)phase,accent,0);
    uint8_t wave=premium_wave((uint8_t)(phase>>2));
    update_landing_halo(ui.launcher_glow,ui.launcher_orbit,ui.launcher_orbit_inner,
        ui.launcher_glint,ui.launcher_spark,(uint8_t)phase,v->settings_animation,accent);
    for(unsigned i=0;!s_3d_available && i<9;++i) {
        bool bright=i==0 || i==4 || i==8;
        set_card_flat(ui.launcher_tiles[i],bright?accent:COL_PANEL2,accent,1);
        lv_obj_set_style_border_opa(ui.launcher_tiles[i],(lv_opa_t)(100U+wave/3U),0);
    }
}

static bool diagnostics_append(char *text,size_t capacity,size_t *used,const char *format,...)
{
    if(*used>=capacity)return false;
    va_list args;va_start(args,format);
    int count=vsnprintf(text+*used,capacity-*used,format,args);va_end(args);
    if(count<0||(size_t)count>=capacity-*used){*used=capacity;return false;}
    *used+=(size_t)count;return true;
}
static void diagnostics_profile(char *text,size_t capacity,size_t *used,const EkSceneProfile *p)
{
    diagnostics_append(text,capacity,used,
        "status=%u\nelapsed_us=%u\ntriangles=%u\npixel_tests=%u\nclear_us=%u\n"
        "camera_us=%u\ngeometry_us=%u\nraster_us=%u\ncopy_us=%u\nclock_calls=%u\nmax_clock_gap_us=%u\n",
        (unsigned)p->stats.status,(unsigned)p->stats.elapsed_us,(unsigned)p->stats.triangles,
        (unsigned)p->stats.pixel_tests,(unsigned)p->clear_us,(unsigned)p->setup_us,
        (unsigned)p->geometry_us,(unsigned)p->raster_us,(unsigned)p->reconstruct_us,
        (unsigned)p->clock_calls,(unsigned)p->max_clock_gap_us);
}
/* Explicit-request capture on the display owner. Heap ownership transfers to
 * the Apps worker only on successful submission; no SD work occurs here. */
static __attribute__((noinline)) void diagnostics_report(const ws_ui_snapshot_t *v)
{
    char *text=heap_caps_malloc(EK_DIAGNOSTICS_REPORT_CAPACITY,MALLOC_CAP_SPIRAM|MALLOC_CAP_8BIT);
    if(!text){ek_apps_diagnostics_export_failed("Report memory unavailable");return;}
    size_t used=0;const size_t capacity=EK_DIAGNOSTICS_REPORT_CAPACITY;
#define REPORT(...) diagnostics_append(text,capacity,&used,__VA_ARGS__)
    REPORT("EvilKey Diagnostics\nformat_version=1\nfirmware=%s\nspec_revision=22\n"
        "captured_monotonic_us=%llu\nwidth=280\nheight=456\nlive_status=%u\n"
        "timing_unit=us unless key ends in _ms\n"
        "snapshot_note=component snapshots collected at request; no continuous history\n"
        "native_status=0 empty,1 OK,2 TIMEOUT,other native fault\n"
        "admission_note=queue wait precedes unchanged native compute budget; end-to-end latency is not bounded to20ms\n"
        "native_limits=20000us pre-copy,300000 pixel candidates\n",
        PF_FIRMWARE_VERSION_STRING,(unsigned long long)esp_timer_get_time(),v->diagnostics_enabled?1U:0U);
    lv_mem_monitor_t pool;lv_mem_monitor(&pool);
    REPORT("\n[draw_buffer]\nbuffers=%u\nrows=%u\nrgb565=1\nstaging=%s\n"
        "dma_free_bytes=%u\ndma_largest_bytes=%u\npsram_free_bytes=%u\nlvgl_pool_free_bytes=%u\n",
        s_pixels_b?2U:1U,(unsigned)(s_draw_pixels/WS_LCD_WIDTH),s_staging[0]?"2x16":"direct",
        (unsigned)heap_caps_get_free_size(MALLOC_CAP_DMA|MALLOC_CAP_INTERNAL),
        (unsigned)heap_caps_get_largest_free_block(MALLOC_CAP_DMA|MALLOC_CAP_INTERNAL),
        (unsigned)heap_caps_get_free_size(MALLOC_CAP_SPIRAM|MALLOC_CAP_8BIT),(unsigned)pool.free_size);
    REPORT("\n[apps_catalog]\napps=%u\nheaders=%u\nmount_ms=%u\nscan_ms=%u\nicons_ms=%u\npage=%u\n"
        "\n[ui_latency]\npoll_max_ms=%u\nrender_max_ms=%u\n",
        (unsigned)v->apps_count,(unsigned)v->apps_headers_read,(unsigned)v->apps_mount_ms,
        (unsigned)v->apps_scan_ms,(unsigned)v->apps_icon_ms,(unsigned)v->launcher_page+1,
        (unsigned)v->ui_poll_gap_ms,(unsigned)v->ui_render_ms);
    ws_gui_3d_presentation_stats_t ps=ws_gui_3d_presentation_stats();
    REPORT("compose_us=%u\npanel_wait_us=%u\npeak_compose_us=%u\npeak_panel_wait_us=%u\n"
        "frame_p50_us=%u\nframe_p95_us=%u\nframe_us=%u\npeak_frame_us=%u\nframes=%u\n"
        "flushes=%u\nbytes=%u\nfailed_frames=%u\ntile_rows=%u\nface_cache_bytes=%u\ninternal_tiles=%u\n",
        (unsigned)ps.compose_us,(unsigned)ps.panel_wait_us,(unsigned)ps.peak_compose_us,
        (unsigned)ps.peak_panel_wait_us,(unsigned)ps.p50_us,(unsigned)ps.p95_us,(unsigned)ps.frame_us,
        (unsigned)ps.peak_frame_us,(unsigned)ps.frames,(unsigned)ps.flushes,(unsigned)ps.bytes,
        (unsigned)ps.failed_frames,(unsigned)ps.tile_rows,(unsigned)ps.face_cache_bytes,ps.internal_tiles?1U:0U);
    ws_gui_3d_stats_t jet=ws_gui_3d_stats();
    REPORT("lvgl_wait_us=%u\npeak_lvgl_wait_us=%u\nwait_note=panel_wait includes LVGL active wait and panel semaphore; subsets of compose wall\n",
        (unsigned)ps.lvgl_wait_us,(unsigned)ps.peak_lvgl_wait_us);
    EkAppsCopyStats copy;ek_apps_copy_stats(&copy);
    REPORT("\n[app_frame_copy]\ncopies=%u\nlast_bytes=%u\nlast_us=%u\npeak_us=%u\nwidth=%u\nheight=%u\npanel_order=%u\n"
        "copy_note=copy/conversion inside Apps guard; excludes guard queue; bytes are destination bytes\n",
        (unsigned)copy.copies,(unsigned)copy.last_bytes,(unsigned)copy.last_us,(unsigned)copy.peak_us,
        (unsigned)copy.last_width,(unsigned)copy.last_height,(unsigned)copy.panel_order);
    REPORT("method=%u\nmethod_meaning=0 native memcpy,1 fused,2 full row memcpy+scalar swap\n",(unsigned)copy.method);
    REPORT("\n[gui_renderer]\nready=%u\npsram_bytes=%u\nframes=%u\nlast_us=%u\npeak_us=%u\ntriangles=%u\n",
        jet.ready?1U:0U,(unsigned)jet.psram_bytes,(unsigned)jet.frames,(unsigned)jet.last_us,
        (unsigned)jet.peak_us,(unsigned)jet.triangles);
    static const char *names[]={"Saver","Settings","Status","Apps"};
    for(unsigned i=0;i<WS_3D_CHANNELS;i++){
        ws_gui_3d_channel_stats_t c=ws_gui_3d_channel_stats(i);
        REPORT("\n[gui.%s]\nframes=%u\ncache_hits=%u\ngeometry_us=%u\nraster_us=%u\nconvert_us=%u\n"
            "last_us=%u\npeak_us=%u\np50_us=%u\np95_us=%u\ntriangles=%u\nconverted_samples=%u\n"
            "detail_samples=%u\ndetail_sample=%u\n",names[i],(unsigned)c.frames,(unsigned)c.cache_hits,
            (unsigned)c.geometry_us,(unsigned)c.raster_us,(unsigned)c.convert_us,(unsigned)c.last_us,
            (unsigned)c.peak_us,(unsigned)c.p50_us,(unsigned)c.p95_us,(unsigned)c.triangles,
            (unsigned)c.converted_samples,(unsigned)c.detail_samples,c.detail_sample?1U:0U);
    }
    EkSceneProfile native;ek_apps_scene_profile(&native);
    REPORT("\n[native.last]\n");diagnostics_profile(text,capacity,&used,&native);
    EkRenderWorkerStats cores;ek_render_worker_stats(&cores);
    REPORT("\n[render_cores]\nready=%u\nenabled=%u\ncore0_jobs=%u\ncore1_jobs=%u\ncore0_stack_free_bytes=%u\ncore1_stack_free_bytes=%u\n",
        (unsigned)cores.ready,(unsigned)cores.enabled,(unsigned)cores.jobs[0],(unsigned)cores.jobs[1],
        (unsigned)cores.stack_free[0],(unsigned)cores.stack_free[1]);
    EkRenderFrameStats admission;ek_render_frame_stats(&admission);
    REPORT("\n[graphics_admission]\nready=%u\nowner=%u\nowner_meaning=0 idle,1 native compute,2 display\n"
        "native_acquisitions=%u\nnative_contentions=%u\nnative_wait_last_us=%u\nnative_wait_peak_us=%u\n"
        "display_acquisitions=%u\ndisplay_contentions=%u\ndisplay_wait_last_us=%u\ndisplay_wait_peak_us=%u\n",
        (unsigned)admission.ready,(unsigned)admission.owner,(unsigned)admission.acquisitions[0],
        (unsigned)admission.contentions[0],(unsigned)admission.wait_last_us[0],(unsigned)admission.wait_peak_us[0],
        (unsigned)admission.acquisitions[1],(unsigned)admission.contentions[1],
        (unsigned)admission.wait_last_us[1],(unsigned)admission.wait_peak_us[1]);
    REPORT("\nreport_end=complete\n");
#undef REPORT
    if(used>=capacity){free(text);ek_apps_diagnostics_export_failed("Report too large");}
    else if(!ek_apps_diagnostics_export(text,used)){free(text);ek_apps_diagnostics_export_failed("Report worker unavailable");}
}
esp_err_t ws_lvgl_render(const ws_ui_snapshot_t *v)
{
    if(!s_ready || !v) return ESP_ERR_INVALID_STATE;
    static uint32_t captured_request;
    if(v->diagnostics_export_status==EK_DIAGNOSTICS_EXPORT_BUSY &&
       v->diagnostics_export_request && captured_request!=v->diagnostics_export_request){
        captured_request=v->diagnostics_export_request;diagnostics_report(v);
    }
    s_render_tick=(uint32_t)esp_timer_get_time();
    s_frame_id=ws_gui_3d_frame_begin(s_render_tick);
    ws_gui_3d_profile(v->diagnostics_enabled);
    if(pf_control_mode()==PF_CONTROL_BLE_PAD) {
        ws_gamepad_view_render(v);
    
    s_flush_error=ESP_OK;lv_refr_now(NULL);
        ws_gui_3d_frame_end(s_frame_id,(uint32_t)esp_timer_get_time(),ws_gui_3d_take_panel_wait(),s_flush_error==ESP_OK);
        return s_flush_error;
    }
    const uint32_t accent=v->accent_rgb?v->accent_rgb:RGB24_DEFAULT;
    const bool pin=v->state==WS_UI_PIN;
    const bool first=!s_last_view_valid;
    const bool was_pin=s_last_view_valid && s_last_view.state==WS_UI_PIN;
    s_3d_force_frame=first || was_pin || (s_last_view_valid && s_last_view.settings_animation!=v->settings_animation) ||
        (s_last_view_valid && ((s_last_view.settings_transition!=v->settings_transition && (v->settings_transition==0 || v->settings_transition==255)) ||
        (s_last_view.screensaver_transition!=v->screensaver_transition && (v->screensaver_transition==0 || v->screensaver_transition==255)) ||
        (s_last_view.launcher_transition!=v->launcher_transition && (v->launcher_transition==0 || v->launcher_transition==255))));

    const bool app_visible=v->apps_running && ws_ui_settings_allowed(v->state) &&
        v->launcher_transition==255U;
    hidden(ui.launcher_group,app_visible || pin || v->air_mouse_active ||
        !ws_ui_settings_allowed(v->state) || !v->launcher_transition);
    hidden(ui.apps_group,!app_visible);
    if(app_visible) {
        hidden(ui.apps_exit_grip,v->apps_exit_confirm);
        hidden(ui.apps_exit_pull,!v->apps_exit_dragging);
        hidden(ui.apps_exit_dim,!v->apps_exit_dragging);
        set_card_flat(ui.apps_exit_grip,v->apps_exit_dragging?accent:0x142328UL,
                      v->apps_exit_dragging?accent:0x365a60UL,1);
        for(unsigned i=0;i<2;++i)
            lv_obj_set_style_line_color(lv_obj_get_child(ui.apps_exit_arrow,(int32_t)i),
                color(v->apps_exit_dragging?0x081916UL:accent),0);
        if(v->apps_exit_dragging) {
            unsigned progress=v->apps_exit_progress>100?100:v->apps_exit_progress;
            hidden(ui.apps_exit_fill,!progress);
            lv_obj_set_width(ui.apps_exit_fill,(lv_coord_t)(progress*172/100+(!progress)));
            set_card_flat(ui.apps_exit_fill,accent,accent,0);
            char percent[8];snprintf(percent,sizeof(percent),"%u%%",progress);
            set_text(ui.apps_exit_percent,percent,accent);
            set_text(ui.apps_exit_caption,progress==100?"RELEASE TO CONFIRM":"DRAG RIGHT TO EXIT",COL_MUTED);
        }
        hidden(ui.apps_exit_overlay,!v->apps_exit_confirm);
        if(v->apps_exit_confirm) {
            set_card_flat(ui.apps_exit_no,
                v->apps_exit_pressed==EK_EXIT_BUTTON_NO?accent:0x1b2d34UL,
                v->apps_exit_pressed==EK_EXIT_BUTTON_NO?accent:0x36515bUL,1);
            set_card_flat(ui.apps_exit_yes,
                v->apps_exit_pressed==EK_EXIT_BUTTON_YES?COL_BAD:0x39232cUL,
                0x925060UL,1);
        }
        hidden(ui.air_mouse_group,true);
        hidden(ui.air_mouse_settings_group,true);
        hidden(ui.pin_group,true);
        hidden(ui.main_group,true);
        hidden(ui.settings_group,true);
        hidden(ui.screensaver_group,true);
        EkAppsDirty dirty={0};
        if(s_apps_pixels && ui.apps_image &&
           ek_apps_copy_frame_panel(s_apps_pixels,EK_APPS_PIXELS,&s_apps_frame,&dirty)) {
            lv_img_cache_invalidate_src(&s_apps_img);
            lv_area_t area;
            lv_obj_get_coords(ui.apps_image,&area);
            area.x1+=dirty.x;area.y1+=dirty.y;
            area.x2=area.x1+dirty.width-1;
            area.y2=area.y1+dirty.height-1;
            lv_obj_invalidate_area(ui.apps_image,&area);
        }
    } else if(v->air_mouse_active) {
        hidden(ui.air_mouse_group,v->air_mouse_settings_open);
        hidden(ui.air_mouse_settings_group,!v->air_mouse_settings_open);
        hidden(ui.pin_group,true);
        hidden(ui.main_group,true);
        hidden(ui.settings_group,true);
        hidden(ui.screensaver_group,true);
        /* Settings data changes independently of touch/IMU state. */
        if(first || !s_last_view.air_mouse_active ||
           s_last_view.ble_ready!=v->ble_ready || s_last_view.ble_failed!=v->ble_failed ||
           s_last_view.air_mouse_ble_modal!=v->air_mouse_ble_modal ||
           s_last_view.state!=v->state ||
           s_last_view.air_mouse_touch_zone!=v->air_mouse_touch_zone ||
           s_last_view.air_mouse_move_held!=v->air_mouse_move_held ||
           s_last_view.air_mouse_drag_latched!=v->air_mouse_drag_latched ||
           s_last_view.air_mouse_buttons!=v->air_mouse_buttons ||
           s_last_view.air_mouse_hold_step!=v->air_mouse_hold_step ||
           s_last_view.air_mouse_touch_fault!=v->air_mouse_touch_fault ||
           s_last_view.air_mouse_touch_outside!=v->air_mouse_touch_outside ||
           s_last_view.air_mouse_calibrating!=v->air_mouse_calibrating ||
           s_last_view.air_mouse_sensor_ok!=v->air_mouse_sensor_ok ||
           s_last_view.air_mouse_settings_open!=v->air_mouse_settings_open ||
           s_last_view.air_mouse_sensitivity!=v->air_mouse_sensitivity ||
           s_last_view.air_mouse_invert_y!=v->air_mouse_invert_y)
            update_air_mouse(v,accent);
    } else if(pin) {
        hidden(ui.air_mouse_group,true);
        hidden(ui.air_mouse_settings_group,true);
        hidden(ui.pin_group,false);
        hidden(ui.main_group,true);
        hidden(ui.settings_group,true);
        hidden(ui.screensaver_group,true);
        if(first || !was_pin || pin_content_changed(&s_last_view,v)) pin_state(v,accent);
    } else {
        hidden(ui.air_mouse_group,true);
        hidden(ui.air_mouse_settings_group,true);
        const uint8_t settings_t=v->settings_transition;
        const uint8_t saver_t=v->screensaver_transition;
        const uint8_t launcher_t=v->launcher_transition;
        unsigned transition=settings_t>0U&&settings_t<255U?settings_t:
            saver_t>0U&&saver_t<255U?saver_t:launcher_t;
        int depth=transition>0U&&transition<255U?(int)(transition*(255U-transition)*160U/16256U):0;
        ws_gui_3d_transition(saver_t>0U?-depth:depth);
        const bool apps_settings_slide=settings_t!=0U && launcher_t!=0U;
        const bool main_visible=!apps_settings_slide &&
            settings_t!=255U && saver_t!=255U && launcher_t!=255U;
        const bool settings_visible=settings_t!=0U;
        const bool saver_visible=saver_t!=0U;
        hidden(ui.pin_group,true);
        hidden(ui.main_group,!main_visible);
        hidden(ui.settings_group,!settings_visible);
        hidden(ui.screensaver_group,!saver_visible);
        if(launcher_t) {
            if(first || s_launcher_generation!=v->apps_catalog_generation ||
                !s_last_view.launcher_transition ||
                s_last_view.launcher_page!=v->launcher_page ||
                s_last_view.launcher_pressed!=v->launcher_pressed ||
                s_last_view.launcher_page_offset!=v->launcher_page_offset ||
                s_last_view.apps_count!=v->apps_count ||
                s_last_view.apps_icon_valid!=v->apps_icon_valid ||
                s_last_view.apps_catalog_ready!=v->apps_catalog_ready ||
                s_last_view.apps_running!=v->apps_running ||
                s_last_view.apps_scanning!=v->apps_scanning ||
                strcmp(s_last_view.apps_status,v->apps_status)!=0 ||
                s_last_view.accent_rgb!=v->accent_rgb)
                update_launcher(v,accent);
            if(first || !s_last_view.launcher_transition ||
                s_last_view.launcher_page!=v->launcher_page ||
                s_last_view.settings_motion_phase!=v->settings_motion_phase ||
                s_last_view.settings_animation!=v->settings_animation ||
                (v->settings_animation && jet_image_due(WS_3D_APPS)) ||
                (s_3d_available && (s_last_view.settings_transition!=settings_t ||
                    s_last_view.launcher_transition!=launcher_t ||
                    s_last_view.screensaver_transition!=saver_t)) ||
                s_last_view.accent_rgb!=v->accent_rgb)
                update_launcher_motion(v,accent);
        }

        if(first || was_pin || main_content_changed(&s_last_view,v)) {
            main_state(v,accent);
            s_active_hero=hero_for_state(v->state);
            s_active_hero_colour=hero_colour_for_state(v->state,accent);
        }
        if(first || was_pin || settings_content_changed(&s_last_view,v)) update_settings(v,accent);
        if(first || was_pin || screensaver_content_changed(&s_last_view,v))
            set_screensaver_colour(accent);

        if(first || was_pin || !s_last_view_valid ||
           s_last_view.settings_transition!=settings_t ||
           s_last_view.settings_open!=v->settings_open ||
           s_last_view.screensaver_transition!=saver_t ||
           s_last_view.launcher_transition!=launcher_t) {
            /* SETTINGS arrives from the right. The screensaver mirrors it from
             * the left, while the idle surface moves only 64 px for understated
             * parallax instead of a costly full-width translation. */
            int main_x=-((int)settings_t*64)/255+((int)saver_t*64)/255-((int)launcher_t*64)/255;
            lv_obj_set_x(ui.main_group,main_x);
            int settings_x=WS_LCD_WIDTH-((int)settings_t*WS_LCD_WIDTH)/255;
            int launcher_x=WS_LCD_WIDTH-((int)launcher_t*WS_LCD_WIDTH)/255;
            if(apps_settings_slide) {
                /* Adjacent pages move together. Use one shared edge so rounding
                 * cannot expose Home or leave a gap between the two pages. */
                if(v->settings_open) launcher_x=settings_x-WS_LCD_WIDTH;
                else {
                    launcher_x=-WS_LCD_WIDTH+((int)launcher_t*WS_LCD_WIDTH)/255;
                    settings_x=launcher_x+WS_LCD_WIDTH;
                }
            }
            lv_obj_set_x(ui.launcher_group,launcher_x);
            lv_obj_set_x(ui.settings_group,settings_x);
            lv_obj_set_x(ui.screensaver_group,-WS_LCD_WIDTH+((int)saver_t*WS_LCD_WIDTH)/255);
        }
        if(first || was_pin || !s_last_view_valid || s_last_view.settings_page_offset!=v->settings_page_offset)
            lv_obj_set_y(ui.settings_content,(int)v->settings_page_offset);

        if(v->settings_animation && main_visible &&
           (first || was_pin || s_last_view.animation_phase!=v->animation_phase ||
            s_last_view.settings_transition!=settings_t || s_last_view.screensaver_transition!=saver_t)) {
            update_premium_motion(v,s_active_hero,s_active_hero_colour);
            if(v->usb_tool_enabled && ws_ui_settings_allowed(v->state)) update_tool_leds(v);
            if(s_active_hero==HERO_SPINNER) update_spinner(v->animation_phase,s_active_hero_colour);
            if(v->state==WS_UI_CONFIRMED || v->state==WS_UI_CANCELLED || v->state==WS_UI_TIMEOUT ||
               v->state==WS_UI_PIN_BAD || v->state==WS_UI_PIN_BLOCKED || v->state==WS_UI_INPUT_ERROR)
                lv_obj_set_style_bg_opa(ui.result_flare,(lv_opa_t)(126U+premium_wave(v->animation_phase)/12U),0);
        }
        if(settings_visible &&
           (first || was_pin || s_last_view.settings_motion_phase!=v->settings_motion_phase ||
            (v->settings_page==WS_SETTINGS_PAGE_HOME && v->settings_animation && jet_image_due(WS_3D_GEAR)) ||
            s_last_view.settings_animation!=v->settings_animation ||
            s_last_view.settings_page!=v->settings_page || s_last_view.accent_rgb!=v->accent_rgb || s_last_view.settings_transition!=settings_t))
            update_settings_motion(v,accent);
        if(saver_visible && (first || was_pin || jet_image_due(WS_3D_SAVER) ||
           s_last_view.screensaver_phase!=v->screensaver_phase ||
           s_last_view.screensaver_transition!=saver_t))
            update_screensaver_motion(v,accent);
    }

    s_last_view=*v;
    s_last_view_valid=true;
    s_flush_error=ESP_OK;
    /* R22 retains R19/R21 dirty-rectangle rendering. No explicit full-screen
     * invalidation is used; the faster transport path only changes how those
     * dirty areas are buffered and transferred. */
    
    lv_refr_now(NULL);
    ws_gui_3d_frame_end(s_frame_id,(uint32_t)esp_timer_get_time(),ws_gui_3d_take_panel_wait(),s_flush_error==ESP_OK);
    return s_flush_error;
}
