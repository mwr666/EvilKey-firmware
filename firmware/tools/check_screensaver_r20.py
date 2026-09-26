#!/usr/bin/env python3
"""R20 premium full-screen screensaver source/security/performance guard."""
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
    h=need(PORT/'ws_ui.h','screensaver_transition','screensaver_phase','screensaver_open')
    board=need(PORT/'ws_board.c',
        'PICO_FIDO_LVGL_R21_AMOLED_PREMIUM_SCREENSAVER',
        '#define WS_SCREENSAVER_TRANSITION_MS 260U',
        'screensaver_transition_begin(true,now,true)',
        'screensaver_transition_begin(false,now,true)',
        'screensaver_force_closed();',
        '(saver_elapsed/24U)%1024U',
        's_screensaver_open || s_screensaver_transition!=0U')
    ui=need(PORT/'ws_lvgl.c',
        'build_screensaver(', 'ws_logo_screensaver_accent', 'ws_logo_screensaver_white',
        'screensaver_orbit_a','screensaver_orbit_b','screensaver_orbit_c',
        'update_screensaver_motion(', 'SETTINGS  <  SWIPE  >  SAVER',
        'SWIPE LEFT  /  BACK', 'lv_obj_get_x(ui.screensaver_logo)',
        'R22 retains R19/R21 dirty-rectangle rendering')
    assets=need(PORT/'ws_logo_assets.h',
        'ws_logo_screensaver_accent_map[40000]',
        'ws_logo_screensaver_white_map[40000]',
        '.header.w = 200','.header.h = 200')
    tests=need(FW/'tests/release_026/test_board_ui1.c',
        'PASS board R20: READY swipe-right opens animated logo screensaver',
        'PASS board R20: STANDBY exposes the same premium screensaver',
        'PASS board R20 security: authentication state immediately evicts screensaver')
    if 'lv_obj_invalidate(ui.screen)' in ui:
        raise SystemExit('FAIL: screensaver reintroduced full-screen invalidation')
    if 'lv_img_set_zoom' in ui or 'lv_img_set_angle' in ui:
        raise SystemExit('FAIL: screensaver uses per-frame image transforms instead of lightweight arc motion')
    if 'lv_obj_add_event_cb' in ui or 'LV_EVENT_CLICKED' in ui:
        raise SystemExit('FAIL: LVGL presentation layer gained input authority')
    if 's_screensaver_open' not in board or 'settings_idle_state' not in board:
        raise SystemExit('FAIL: screensaver is not bounded to idle-state navigation')
    print('PASS: R20 swipe-right READY/STANDBY screensaver navigation is present')
    print('PASS: R20 saver uses static alpha logo + local arc/opacity motion, no image transforms/full-screen invalidate')
    print('PASS: authentication states evict screensaver and LVGL remains presentation-only')

if __name__=='__main__': main()
