#!/usr/bin/env python3
"""Compatibility-named static guard for the current EvilKey LVGL layer."""
from pathlib import Path
ROOT=Path(__file__).resolve().parents[2];FW=ROOT/'firmware';PORT=FW/'templates'/'port'

def require(path:Path,*needles:str)->str:
    text=path.read_text(encoding='utf-8')
    for needle in needles:
        if needle not in text: raise SystemExit(f'FAIL {path}: missing {needle!r}')
    return text

def main()->None:
    ui=require(PORT/'ws_lvgl.c',
        'R25 keeps the R22 zero-copy RGB565 transport',
        'EVILKEY','#include "ws_logo_assets.h"','lv_img_create(',
        '&ws_logo_header_accent','&ws_logo_header_white',
        '&ws_logo_hero_accent','&ws_logo_hero_white','lv_obj_set_style_img_recolor_opa(',
        'premium_wave(','update_premium_motion(','lv_obj_set_style_bg_grad_color(',
        'hero_orbit','hero_glint','spinner_arc_a','spinner_arc_b','progress_dot[3]','result_flare',
        'build_settings_hint(','build_settings(','update_settings(',
        'settings_transition','settings_page_offset',
        '#define SETTINGS_ROWS 2U','#define SETTINGS_DOTS 9U',
        '#define COL_BG      0x000000UL','#define COL_PANEL   0x101C20UL',
        '#define COL_PANEL2  0x18282CUL','#define COL_BORDER  0x2A3C42UL',
        '#define COL_BAD     0xFF7685UL')
    if 'NOXID' in ui.upper(): raise SystemExit('FAIL: NOXID belongs to a separate branch')
    if 'lv_obj_add_event_cb' in ui or 'LV_EVENT_CLICKED' in ui:
        raise SystemExit('FAIL: LVGL visual layer must remain presentation-only')
    require(PORT/'ws_logo_assets.h','LV_IMG_CF_ALPHA_8BIT',
            'ws_logo_header_accent_map[1156]','ws_logo_header_white_map[1156]',
            'ws_logo_hero_accent_map[4624]','ws_logo_hero_white_map[4624]',
            '.header.w = 34','.header.h = 34','.header.w = 68','.header.h = 68')
    if not (FW/'assets'/'evilkey_mark_source.png').is_file():
        raise SystemExit('FAIL: approved EvilKey logo source PNG is missing')
    require(FW/'templates'/'lvgl_conf.h','#define LV_MEM_SIZE (128U * 1024U)',
            '#define LV_FONT_MONTSERRAT_18 1','#define LV_FONT_MONTSERRAT_28 1',
            '#define LV_FONT_MONTSERRAT_34 1','#define LV_USE_LINE 1','#define LV_USE_IMG 1','#define LV_USE_ARC 1',
            '#define LV_USE_IMG_TRANSFORM 0')
    require(PORT/'ws_ui_layout.h','#define WS_KEY_X 8','#define WS_KEY_Y 132','#define WS_KEY_W 84',
            '#define WS_KEY_H 60','#define WS_KEY_DX 90','#define WS_KEY_DY 66',
            '#define WS_PIN_CANCEL_X 8','#define WS_PIN_CANCEL_Y 400',
            '#define WS_PIN_CANCEL_W 264','#define WS_PIN_CANCEL_H 48',
            '#define WS_SETTINGS_ROW_H 112','#define WS_SETTINGS_CONTROL_H 52')
    board=require(PORT/'ws_board.c',
        'R22 main-screen motion remains a 16 ms (~62.5 Hz) absolute-time phase.',
        'settings.animation && v.state!=WS_UI_PIN','(now/16U)%64U',
        'WS_SETTINGS_TRANSITION_MS 230U','WS_SETTINGS_PAGE_TRANSITION_MS 165U')
    if 'lv_obj_invalidate(ui.screen)' in ui:
        raise SystemExit('FAIL: full-screen LVGL invalidation returned')
    if '(now/125U)%32U' in board or '(now/32U)%32U' in board:
        raise SystemExit('FAIL: legacy low-resolution animation cadence remains')
    print('PASS: RGB565-polished dark/mint palette, two-colour EvilKey logo and presentation-only LVGL boundary retained')
    print('PASS: PIN keypad/cancel geometry remains unchanged')
    print('PASS: Settings uses a large landing gear plus nine spacious vertically-swiped pages')
    print('PASS: R22 uses a 64-step ~62.5 Hz absolute-time phase with LVGL dirty-rectangle rendering')

if __name__=='__main__': main()
