#!/usr/bin/env python3
"""R24 hardware-video regression guard: static saver text fade + anchored slow Settings."""
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
    ui_h=need(PORT/'ws_ui.h','screensaver_text_phase','settings_motion_phase')
    board=need(PORT/'ws_board.c',
        'PICO_FIDO_LVGL_R24_SAVER_FADE_SETTINGS_POLISH',
        's_settings_opened_at=now;',
        'v.settings_motion_phase=(uint8_t)((settings_elapsed/24U)%256U);',
        's_screensaver_opened_at=now;',
        'v.screensaver_text_phase=(uint16_t)((saver_elapsed/25U)%360U);',
        's_settings_transition!=255U && s_screensaver_transition!=255U',
        '(now/16U)%64U')
    ui=need(PORT/'ws_lvgl.c',
        'screensaver_text_opacity(uint16_t phase)',
        'if(phase<40U)', 'return 0U;',
        'text_opa!=s_screensaver_text_opa',
        'ui.screensaver_brand,brand_opa',
        'ui.screensaver_caption,caption_opa',
        'ui.screensaver_hint,hint_opa',
        'const uint8_t phase=v->settings_motion_phase;',
        'const int rotation=((int)phase*360)/256;',
        'Keep the gear fully opaque and fixed.',
        'Four fixed pinpricks remain visible throughout the loop.',
        'lv_obj_invalidate(ui.screensaver_core);',
        'R25 keeps the R22 zero-copy RGB565 transport')
    panel=need(PORT/'ws_panel.c',
        'asynchronous RGB565 DMA flush path','.trans_queue_depth=2',
        'esp_lcd_panel_io_tx_color(s_io,0x32002C00,pixels,needed*2U);')

    # Hardware-observed R23 regression: saver text must never move in x/y.
    forbidden=(
        'lv_obj_set_x(ui.screensaver_text_group',
        'lv_obj_set_y(ui.screensaver_text_group',
        'lv_obj_get_x(ui.screensaver_text_group',
        'lv_obj_get_y(ui.screensaver_text_group',
    )
    for token in forbidden:
        if token in ui:
            raise SystemExit(f'FAIL: R24 saver typography moved again: {token}')

    # The Settings gear body and its teeth must remain geometrically fixed.
    if 'gear_teeth_rotate' in ui:
        raise SystemExit('FAIL: R23 rotating Settings gear teeth returned')
    settings_fn=ui[ui.index('static void update_settings_motion('):ui.index('static void main_state(')]
    for token in ('lv_obj_set_x(ui.settings_gear','lv_obj_set_y(ui.settings_gear'):
        if token in settings_fn:
            raise SystemExit(f'FAIL: Settings gear is being translated: {token}')

    if 'lv_obj_invalidate(ui.screen)' in ui:
        raise SystemExit('FAIL: full-screen invalidation returned')
    if 's_tx[i]=' in panel or 'p<<8' in panel or 'p>>8' in panel:
        raise SystemExit('FAIL: R22 zero-copy display path regressed')

    print('PASS: R24 saver text is spatially fixed and uses eased fade only')
    print('PASS: R24 stationary-text baseline retained; R25 supersedes only plateau timing')
    print('PASS: R24 anchored Settings gear baseline retained; R25 closes all surrounding motion on one loop')
    print('PASS: R22 zero-copy async DMA + R23 coherent saver core remain intact')

if __name__=='__main__':
    main()
