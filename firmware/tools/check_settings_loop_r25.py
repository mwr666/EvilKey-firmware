#!/usr/bin/env python3
"""R25 hardware-video regression guard: seamless Settings loop + 5 s saver hold."""
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
    need(PORT/'ws_ui.h','uint16_t screensaver_text_phase;','settings_motion_phase')
    board=need(PORT/'ws_board.c',
        'PICO_FIDO_LVGL_R25_SETTINGS_LOOP_POLISH',
        'v.settings_motion_phase=(uint8_t)((settings_elapsed/24U)%256U);',
        'v.screensaver_text_phase=(uint16_t)((saver_elapsed/25U)%360U);',
        '40/200/40/80 ticks at 25 ms = 1.000 s fade, 5.000 s bright hold')
    if '(saver_elapsed/24U)%1024U' not in board:
        raise SystemExit('FAIL: Settings and screensaver phase clocks no longer match')
    ui=need(PORT/'ws_lvgl.c',
        'static uint8_t screensaver_text_opacity(uint16_t phase)',
        'if(phase<40U)', 'if(phase<240U) return 255U;', 'if(phase<280U)',
        'const uint8_t wave=premium_wave((uint8_t)(phase>>2));',
        'const int inner_rotation=(180+360-rotation)%360;',
        'const int glint_rotation=(32+rotation*2)%360;',
        'lv_obj_set_style_bg_opa(ui.settings_glow,LV_OPA_TRANSP,0);',
        'Four fixed pinpricks remain visible throughout the loop.',
        'spark_base[4]={42U,48U,46U,52U}',
        '#include "ws_settings_icon_asset.h"',
        'lv_img_set_src(p,&ws_settings_gear);',
        'Keep the gear fully opaque and fixed.',
        'R25 keeps the R22 zero-copy RGB565 transport')
    need(PORT/'ws_settings_icon_asset.h',
         'ws_settings_gear_map[14400]', 'LV_IMG_CF_ALPHA_8BIT',
         '.header.w = 120', '.header.h = 120')
    # Regression that caused the physical-video jump: a half-turn inner orbit on
    # a 256-step clock can never close after one cycle.
    settings_fn=ui[ui.index('static void update_settings_motion('):ui.index('static void main_state(')]
    forbidden=(
        '540-(rotation/2)',
        'rotation/2',
        'spark_off[4]',
        '28U+sw/2U',
    )
    for token in forbidden:
        if token in settings_fn:
            raise SystemExit(f'FAIL: discontinuous/noisy R24 Settings expression returned: {token}')
    # Verify the actual integer-angle wrap is only a normal one-frame increment.
    def rot(phase): return (phase*360)//256
    outer_before=rot(255); outer_after=rot(0)
    outer_step=(outer_after-outer_before)%360
    inner_before=(180+360-rot(255))%360; inner_after=180
    inner_step=(inner_before-inner_after)%360
    glint_before=(32+2*rot(255))%360; glint_after=32
    glint_step=(glint_after-glint_before)%360
    if not (outer_step<=2 and inner_step<=2 and glint_step<=4):
        raise SystemExit(f'FAIL: loop boundary jump outer={outer_step} inner={inner_step} glint={glint_step}')
    print('PASS: R25 Settings outer/inner/glint transforms are phase-closed at the 255 -> 0 boundary')
    print('PASS: Settings orbit matches the screensaver 24 ms cadence and uses a static A8 gear')
    print('PASS: R25 ambient glow has no filled blinking disc and pinpricks never disappear')
    print('PASS: R25 saver text cycle is 1 s fade-in / 5 s bright / 1 s fade-out / 2 s dark')

if __name__=='__main__':
    main()
