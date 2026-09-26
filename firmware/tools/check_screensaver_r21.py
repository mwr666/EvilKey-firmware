#!/usr/bin/env python3
"""R21 AMOLED premium screensaver source/security/performance guard."""
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
    need(PORT/'ws_ui.h','screensaver_transition','screensaver_phase','screensaver_open')
    board=need(PORT/'ws_board.c',
        'PICO_FIDO_LVGL_R21_AMOLED_PREMIUM_SCREENSAVER',
        '#define WS_SCREENSAVER_TRANSITION_MS 260U',
        'screensaver_transition_begin(true,now,true)',
        'screensaver_transition_begin(false,now,true)',
        'screensaver_force_closed();',
        '(saver_elapsed/24U)%1024U',
        's_screensaver_open || s_screensaver_transition!=0U',
        'uint8_t next=view.dim?dim_brightness:bright;')
    ui=need(PORT/'ws_lvgl.c',
        '#include "pf_firmware_version.h"',
        'build_screensaver(', 'ws_logo_screensaver_glow', 'decode_unified_logo(', 'ws_unified_mint_frames',
        'screensaver_logo_glow','screensaver_text_group',
        'screensaver_orbit_a','screensaver_orbit_b','screensaver_orbit_c',
        'update_screensaver_motion(', 'SETTINGS  <  SWIPE  >  SAVER',
        '"FIRMWARE  " PF_FIRMWARE_VERSION_STRING',
        'SWIPE LEFT  /  BACK',
        'lv_obj_invalidate(ui.screensaver_core)',
        'screensaver_text_opacity(',
        'v->screensaver_text_phase',
        'R22 retains R19/R21 dirty-rectangle rendering')
    assets=need(PORT/'ws_logo_assets.h',
        'ws_logo_screensaver_glow_map[46656]',
        'ws_logo_screensaver_accent_map[40000]',
        'ws_logo_screensaver_white_map[40000]',
        '.header.w = 200','.header.h = 200')
    need(PORT/'ws_unified_logo_assets.h','ws_unified_mint_frames[256]',
         'ws_unified_crystal_frames[256]', '#define WS_UNIFIED_MINT_W 150U')
    builder=need(FW/'tools/build_premium_logo_assets.py','SCREENSAVER_SIZE = 200')
    prepare=need(FW/'prepare_arduino.py',
        'elif name == "pf_firmware_version.h" and external_version is not None:',
        'src / "pf_engine_api.h", src / "pf_firmware_version.h"')
    need(FW/'EvilKeyV1/src/pf_firmware_version.h','PF_FIRMWARE_VERSION_STRING')
    tests=need(FW/'tests/release_026/test_board_ui1.c',
        'PASS board R20: READY swipe-right opens animated logo screensaver',
        'PASS board R20: STANDBY exposes the same premium screensaver',
        'PASS board R20 security: authentication state immediately evicts screensaver')
    if 'lv_obj_invalidate(ui.screen)' in ui:
        raise SystemExit('FAIL: screensaver reintroduced full-screen invalidation')
    if 'lv_img_set_zoom' in ui or 'lv_img_set_angle' in ui:
        raise SystemExit('FAIL: screensaver uses per-frame image transforms')
    if 'lv_obj_add_event_cb' in ui or 'LV_EVENT_CLICKED' in ui:
        raise SystemExit('FAIL: LVGL presentation layer gained input authority')
    if 'screensaver_brightness' in board or 'screensaver_brightness' in ui:
        raise SystemExit('FAIL: screensaver introduced an independent brightness path')
    if 's_screensaver_open' not in board or 'settings_idle_state' not in board:
        raise SystemExit('FAIL: screensaver is not bounded to idle-state navigation')
    print('PASS: EvilKey uses unified 256-frame 3D logo, rotating crystal and canonical firmware version string')
    print('PASS: R21 large-logo saver contract is retained; R23 fixed-core rendering and R24 stationary text fade supersede text migration')
    print('PASS: R21 retains dirty rectangles, global brightness and authentication eviction')


if __name__=='__main__':
    main()
