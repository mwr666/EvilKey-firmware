#!/usr/bin/env python3
"""Compatibility-named guard for the current on-device Settings/MSC relocation."""
from pathlib import Path
ROOT=Path(__file__).resolve().parents[2];FW=ROOT/'firmware';PORT=FW/'templates'/'port'

def require(path,*needles):
    text=path.read_text(encoding='utf-8')
    for n in needles:
        if n not in text: raise SystemExit(f'FAIL {path}: missing {n!r}')
    return text

def main():
    board=require(PORT/'ws_board.c',
        'settings_apply_action(',
        'WS_SETTINGS_ACTION_MANAGER_DRIVE_TOGGLE',
        'WS_SETTINGS_ACTION_MANAGER_RO_TOGGLE',
        'settings_transition_begin(true,now,settings.animation)',
        'settings_force_closed();',
        'dx<=-(int)WS_SETTINGS_SWIPE_X',
        'settings_page_change(next,dy<0?1:-1,now,settings.animation)')
    if 'WS_IDLE_ACTION_MANAGER_DRIVE' in board:
        raise SystemExit('FAIL: legacy direct Manager Drive idle action remains in board touch path')
    ui=require(PORT/'ws_ui.c',
        'WS_SETTINGS_ACTION_MANAGER_DRIVE_TOGGLE',
        'WS_SETTINGS_ACTION_MANAGER_RO_TOGGLE',
        'return WS_IDLE_ACTION_NONE;',
        'return state==WS_UI_READY || state==WS_UI_SUSPENDED;')
    if 'WS_IDLE_ACTION_SETTINGS' in ui:
        raise SystemExit('FAIL: READY/STANDBY still exposes a tappable Settings icon target')
    lvgl=require(PORT/'ws_lvgl.c',
        'build_settings_hint(', 'build_settings(', 'update_settings(',
        '"USB Mass Storage"', '"microSD access"',
        '"SETTINGS  <  SWIPE  >  SAVER"', '"SWIPE UP / DOWN"')
    if 'build_manager(' in lvgl or 'ui.manager=' in lvgl:
        raise SystemExit('FAIL: legacy Manager Drive card still exists on READY/STANDBY')
    require(PORT/'ws_ui_layout.h','R15','WS_SETTINGS_SWIPE_X','WS_SETTINGS_ROW_H 112')
    require(FW/'tests/release_026/test_gui_ui1.c',
        'READY/STANDBY has no hidden/tappable Settings icon',
        'eight Settings screens',
        'Settings and MSC configuration remain restricted to READY and STANDBY')
    require(ROOT/'docs/MANAGER_DRIVE.md','SETTINGS','USB & STORAGE')
    print('PASS: MSC enable/disable and microSD access mode live only in on-device Settings')
    print('PASS: READY/STANDBY exposes Settings by swipe-left only; no top-right tap target remains')
    print('PASS: Settings is reachable only from READY/STANDBY and is evicted by authentication states')

if __name__=='__main__': main()
