#!/usr/bin/env python3
"""Static integration guard for the R5 LVGL migration."""
from pathlib import Path
import json
ROOT=Path(__file__).resolve().parents[2];FW=ROOT/'firmware'

def require(path,*needles):
    text=path.read_text(encoding='utf-8')
    for n in needles:
        if n not in text: raise SystemExit(f'FAIL {path}: missing {n!r}')
    return text

def main():
    lock=json.loads((FW/'UPSTREAM_LOCK.json').read_text(encoding='utf-8'))
    if lock.get('lvgl_commit')!='4495f428630cc1741bd8bfd977f080e8460e8e8d':
        raise SystemExit('FAIL: LVGL revision is not pinned to reviewed v8.4.0 commit')
    prep=require(FW/'prepare_arduino.py','"lvgl": ("https://github.com/lvgl/lvgl.git", LOCK["lvgl_commit"])',
                 'def vendor_lvgl(','shutil.copytree(src_root, lvgl_dest / "src")','templates/lvgl_conf.h')
    if 'lvgl_root / "lv_version.h"' in prep or '("lvgl.h","lv_version.h")' in prep:
        raise SystemExit('FAIL: pinned LVGL 8.4.0 has no root lv_version.h; generator would fail on Windows')
    ui=require(FW/'templates/port/ws_lvgl.c','lv_init();','lv_disp_drv_register(&s_disp_drv)',
               'lv_refr_now(NULL);','lv_disp_get_scr_act(disp);','ws_panel_flush_async(','SECURITY BOUNDARY:')
    if 'lv_obj_add_event_cb' in ui or 'LV_EVENT_CLICKED' in ui:
        raise SystemExit('FAIL: authentication GUI must not use LVGL click callbacks as authority')
    board=require(FW/'templates/port/ws_board.c','#include "ws_lvgl.h"','ws_lvgl_init();','ws_lvgl_render(&view);',
                  'ws_presence_step(','ws_pinpad_step(')
    panel=require(FW/'templates/port/ws_panel.c','ws_panel_flush_async(','esp_lcd_panel_io_tx_color(','s_pending=true')
    if 's_tx[i]=' in panel: raise SystemExit('FAIL: R22 must not restore the per-pixel staging copy')
    conf=require(FW/'templates/lvgl_conf.h','#define LV_COLOR_DEPTH 16','#define LV_COLOR_16_SWAP 1','#define LV_USE_LABEL 1',
                 '#define LV_USE_DEMO_WIDGETS 0','#define LV_MEM_SIZE (64U * 1024U)',
                 '#define LV_TICK_CUSTOM 1','#define LV_TICK_CUSTOM_INCLUDE "esp_timer.h"')
    require(FW/'EvilKeyV1/FidoConfig.h','#define FIDO_V1_MANAGER_DRIVE_READ_ONLY_DEFAULT 0')
    print('PASS: R5 uses pinned LVGL 8.4.0 for GUI composition')
    print('PASS: LVGL vendoring matches the actual v8.4.0 root layout (no nonexistent lv_version.h)')
    print('PASS: LVGL has no authentication click callbacks; UP/UV/PIN authority remains outside the GUI framework')
    print('PASS: R22 keeps the LVGL 8.4 migration and uses byte-swapped RGB565 direct async QSPI DMA')

if __name__=='__main__': main()
