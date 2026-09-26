#!/usr/bin/env python3
"""R19 premium-motion/performance guard for firmware + Manager."""
from pathlib import Path
ROOT=Path(__file__).resolve().parents[2]
FW=ROOT/'firmware'; PORT=FW/'templates'/'port'; MAN=ROOT/'manager'/'evilkey_manager'

def need(path,*tokens):
    text=path.read_text(encoding='utf-8')
    for token in tokens:
        if token not in text: raise SystemExit(f'FAIL {path}: missing {token!r}')
    return text

def main():
    ui=need(PORT/'ws_lvgl.c',
        'R25 keeps the R22 zero-copy RGB565 transport',
        'hero_orbit','hero_glint','spinner_arc_a','spinner_arc_b',
        'premium_wave','update_settings_motion','main_content_changed',
        'LV_PART_INDICATOR','lv_refr_now(NULL)',
        'R22 retains R19/R21 dirty-rectangle rendering')
    if 'lv_obj_invalidate(ui.screen)' in ui:
        raise SystemExit('FAIL: full-screen invalidate would defeat dirty-rectangle rendering')
    if 'spinner_dot[12]' in ui:
        raise SystemExit('FAIL: old 12-object spinner remains')
    if 'lv_obj_add_event_cb' in ui or 'LV_EVENT_CLICKED' in ui:
        raise SystemExit('FAIL: LVGL presentation layer gained authentication callbacks')
    # Animated software shadows are prohibited; the base style may still explicitly zero them.
    for line in ui.splitlines():
        if 'lv_obj_set_style_shadow_width' in line and ',0,0)' not in line.replace(' ',''):
            raise SystemExit('FAIL: non-zero LVGL shadow width remains in premium motion path')
    need(FW/'templates'/'lvgl_conf.h','#define LV_USE_ARC 1')
    board=need(PORT/'ws_board.c',
        '#define WS_SETTINGS_TRANSITION_MS 230U',
        '#define WS_SETTINGS_PAGE_TRANSITION_MS 165U',
        '#define WS_SETTINGS_PAGE_SLIDE_PX 56',
        '(now/16U)%64U','frame_ms=8U')
    if '(now/32U)%32U' in board:
        raise SystemExit('FAIL: old 32-step phase remains')
    need(PORT/'ws_ui_layout.h',
        '#define WS_KEY_X 8','#define WS_KEY_Y 132','#define WS_KEY_W 84','#define WS_KEY_H 60',
        '#define WS_PIN_CANCEL_X 8','#define WS_PIN_CANCEL_Y 400',
        '#define WS_PIN_CANCEL_W 264','#define WS_PIN_CANCEL_H 48')
    widgets=need(MAN/'widgets.py',
        "BG = '#050607'","INK = '#F5F5F7'","TEAL = '#5EE6C5'",
        'def mix(a,b,t):','def ease(t):','def _animate_hover','def _animate_knob')
    gui=need(MAN/'gui.py','math.cos','delay=40','ScreenPreview','Segmented navigation')
    print('PASS: R19 eliminates full-screen animation invalidation and 12-dot spinner churn')
    print('PASS: R19 local arc motion is retained; R22 raises the phase/poll cadence without full-screen redraw')
    print('PASS: PIN/cancel geometry and presentation-only security boundary remain unchanged')
    print('PASS: Manager uses neutral premium surfaces and smooth status/toggle microinteractions')

if __name__=='__main__': main()
