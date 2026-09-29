#!/usr/bin/env python3
"""R15 Settings UX, cadence and legacy/current PIN source guard."""
from pathlib import Path
ROOT=Path(__file__).resolve().parents[2]
FW=ROOT/'firmware'; PORT=FW/'templates'/'port'

def need(path,*tokens):
    text=path.read_text(encoding='utf-8')
    for t in tokens:
        if t not in text: raise SystemExit(f'FAIL {path}: missing {t!r}')
    return text

def main():
    h=need(PORT/'ws_ui.h','WS_SETTINGS_PAGE_HOME','WS_SETTINGS_PAGE_DISPLAY',
           'WS_SETTINGS_PAGE_APPEARANCE','WS_SETTINGS_PAGE_POWER','WS_SETTINGS_PAGE_AUTH',
           'WS_SETTINGS_PAGE_DIAGNOSTICS = 5','WS_SETTINGS_PAGE_AIR_MOUSE = 6',
           'WS_SETTINGS_PAGE_USB = 7','WS_SETTINGS_PAGE_USB_TOOL = 8',
           'WS_SETTINGS_PAGE_COUNT = 10','settings_page_offset')
    ui=need(PORT/'ws_ui.c','return WS_IDLE_ACTION_NONE;','for(int row=0;row<2;++row)',
            'WS_SETTINGS_PAGE_DISPLAY','WS_SETTINGS_PAGE_USB')
    layout=need(PORT/'ws_ui_layout.h','#define WS_SETTINGS_ROW_H 112',
                '#define WS_SETTINGS_CONTROL_H 52','#define WS_SETTINGS_WIDE_W 240',
                '#define WS_SETTINGS_SWIPE_Y 48')
    lv=need(PORT/'ws_lvgl.c','#define SETTINGS_ROWS 2U','#define SETTINGS_DOTS 10U',
            'build_gear_icon(&ui.settings_gear,120)',
            '"SETTINGS  <  SWIPE  >  SAVER"','"SWIPE UP / DOWN"',
            '"DISPLAY"','"APPEARANCE"','"SCREEN POWER"','"FIDO TIMING"','"USB & STORAGE"','"USB TOOL"',
            '"DIAGNOSTICS"','s_pixels_b?2U:1U','heap_caps_get_free_size(MALLOC_CAP_DMA|MALLOC_CAP_INTERNAL)')
    if 'settings_hint_gear' in lv or 'WS_IDLE_ACTION_SETTINGS' in ui:
        raise SystemExit('FAIL: removed top-right Settings gear/tap path is still present')
    board=need(PORT/'ws_board.c','#define WS_SETTINGS_TRANSITION_MS 230U',
               '#define WS_SETTINGS_PAGE_TRANSITION_MS 165U','#define WS_SETTINGS_PAGE_SLIDE_PX 56',
               '(now/16U)%64U','frame_ms=8U',
               'settings_page_change(next,dy<0?1:-1,now,settings.animation)')
    local=need(FW/'templates/local_uv_engine.inc','R16_RW_PIN_INIT_FIX',
               'file_t *pin=pf_local_uv_pin_file();',
               'if(n==PIN_LEGACY_DATA_LEN) return true;',
               'stored_len==PIN_LEGACY_DATA_LEN?2U:3U',
               'double_hash_pin(CONST_BYTE_ARRAY(h,16),verifier)',
               'pf_uv_unlock_and_migrate_pin(', 'upgraded[2]=1')
    need(FW/'tests/release_026/test_gui_ui1.c','no hidden/tappable Settings icon','eight Settings screens')
    need(FW/'tests/release_026/test_board_ui1.c','PASS board R15','open_usb_settings()')
    print('PASS: swipe-only Settings landing screen + ten-page vertical navigation')
    print('PASS: R15 large controls and no READY/STANDBY tappable gear')
    print('PASS: R19 motion tuning keeps the R15 Settings model while shortening travel and increasing cadence')
    print('PASS: R16 local PIN readiness is host-independent; R15 legacy migration remains')

if __name__=='__main__': main()
