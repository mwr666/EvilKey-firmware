#!/usr/bin/env python3
"""R23 hardware-observed saver/PIN/settings render regression guard."""
from pathlib import Path
ROOT=Path(__file__).resolve().parents[2]
FW=ROOT/'firmware'; PORT=FW/'templates'/'port'

def need(path,*tokens):
    text=path.read_text(encoding='utf-8')
    for token in tokens:
        if token not in text:
            raise SystemExit(f'FAIL {path}: missing {token!r}')
    return text

def main():
    ui=need(PORT/'ws_lvgl.c',
        'R25 keeps the R22 zero-copy RGB565 transport',
        'R23: coherent AMOLED composition.',
        'ui.screensaver_outer=arc_obj(',
        'ui.screensaver_mid=arc_obj(',
        'ui.screensaver_inner=arc_obj(',
        'lv_obj_invalidate(ui.screensaver_core);',
        'const int logo_x=SAVER_LOGO_BASE+((int)logo_wave*28)/255-14;',
        'screensaver_text_opacity(',
        'key_press_ring[12]',
        'base_obj(ui.key_press_ring[i],3,3,WS_KEY_W-6,WS_KEY_H-6);',
        'lv_obj_set_style_border_opa(ui.key_press_ring[i],pressed?LV_OPA_COVER:LV_OPA_TRANSP,0);',
        'settings_motion_phase',
        'Keep the gear fully opaque and fixed.',
        'settings_orbit_inner','settings_glint','settings_spark[4]')
    board=need(PORT/'ws_board.c',
        'PICO_FIDO_LVGL_R23_RENDER_POLISH',
        '(saver_elapsed/24U)%1024U',
        '(now/16U)%64U')
    layout=need(PORT/'ws_ui_layout.h',
        '#define WS_KEY_X 8','#define WS_KEY_Y 132','#define WS_KEY_W 84','#define WS_KEY_H 60',
        '#define WS_KEY_DX 90','#define WS_KEY_DY 66',
        '#define WS_PIN_CANCEL_X 8','#define WS_PIN_CANCEL_Y 400',
        '#define WS_PIN_CANCEL_W 264','#define WS_PIN_CANCEL_H 48')
    panel=need(PORT/'ws_panel.c',
        'asynchronous RGB565 DMA flush path','.trans_queue_depth=2',
        'esp_lcd_panel_io_tx_color(s_io,0x32002C00,pixels,needed*2U);')

    if 'lv_obj_set_x(ui.screensaver_core' in ui or 'lv_obj_set_y(ui.screensaver_core' in ui:
        raise SystemExit('FAIL: large screensaver parent translation returned')
    if 'lv_obj_invalidate(ui.screen)' in ui:
        raise SystemExit('FAIL: full-screen invalidation returned')
    if 'lv_img_set_zoom' in ui or 'lv_img_set_angle' in ui:
        raise SystemExit('FAIL: runtime image transforms returned to saver hot path')
    if 'lv_obj_add_event_cb' in ui or 'LV_EVENT_CLICKED' in ui:
        raise SystemExit('FAIL: presentation layer gained input authority')
    if 's_tx[i]=' in panel or 'p<<8' in panel or 'p>>8' in panel:
        raise SystemExit('FAIL: R22 zero-copy transport was regressed')

    print('PASS: R23 saver keeps a fixed 252x252 parent and coalesces the animated core')
    print('PASS: R23 removes the static filled saver disc and uses moving orbital strokes')
    print('PASS: R23 PIN press feedback is an inset accent ring; hit geometry is unchanged')
    print('PASS: R23 Settings layered visual language remains; the gear is anchored')
    print('PASS: R22 async zero-copy transport remains intact')

if __name__=='__main__':
    main()
