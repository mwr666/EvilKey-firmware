#!/usr/bin/env python3
"""R22 LVGL maximum-throughput source/performance regression guard."""
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
    conf=need(FW/'templates/lvgl_conf.h',
              '#define LV_COLOR_DEPTH 16','#define LV_COLOR_16_SWAP 1',
              '#define LV_MEM_POOL_INCLUDE "esp_heap_caps.h"',
              'MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT')
    pins=need(PORT/'ws_pins.h','#define WS_LCD_STRIP_ROWS 64')
    ui=need(PORT/'ws_lvgl.c',
        'R25 keeps the R22 zero-copy RGB565 transport',
        '#error "R22 requires RGB565 with LV_COLOR_16_SWAP=1 for zero-copy panel DMA"',
        'heap_caps_malloc((size_t)pixels*sizeof(lv_color_t)',
        'MALLOC_CAP_DMA|MALLOC_CAP_INTERNAL',
        'static const uint16_t row_candidates[]={64U,48U,32U,16U};',
        'lv_disp_draw_buf_init(&s_draw_buf,s_pixels_a,s_pixels_b,s_draw_pixels);',
        's_pixels_b=(lv_color_t *)heap_caps_malloc(target_bytes,',
        'ws_panel_flush_async(', 'flush_done,drv',
        'lv_disp_flush_ready((lv_disp_drv_t *)ctx);',
        'PREMIUM_WAVE_LUT[64]', 'return PREMIUM_WAVE_LUT[phase&63U];',
        'screensaver_text_opacity(',
        'R22 retains R19/R21 dirty-rectangle rendering')
    panel=need(PORT/'ws_panel.c',
        'asynchronous RGB565 DMA flush path',
        '.trans_queue_depth=2',
        'ws_panel_wait_idle(500U)',
        'esp_lcd_panel_io_tx_color(s_io,0x32002C00,pixels,needed*2U);',
        'if(done) done(done_ctx);')
    board=need(PORT/'ws_board.c',
        'PICO_FIDO_LVGL_R22_MAX_FPS',
        '(now/16U)%64U','(settings_elapsed/24U)%256U','frame_ms=8U')
    build=need(FW/'build_arduino.py','PSRAM=enabled','build.psram_type=opi')
    if 's_tx[i]=' in panel or 'p<<8' in panel or 'p>>8' in panel:
        raise SystemExit('FAIL: per-pixel RGB565 byte-swap/copy returned to the flush path')
    if 'if(s_pixels_a && s_pixels_b)' not in ui or 's_pixels_b=NULL' not in ui:
        raise SystemExit('FAIL: double-buffer target or single-buffer fallback is missing')
    if 'lv_obj_invalidate(ui.screen)' in ui:
        raise SystemExit('FAIL: full-screen invalidation defeats partial-buffer throughput')
    draw_allocation=ui.split('static const uint16_t row_candidates[]=',1)[1].split('lv_disp_draw_buf_init(',1)[0]
    if 'PSRAM=disabled' in build or 'MALLOC_CAP_SPIRAM' in draw_allocation:
        raise SystemExit('FAIL: PSRAM is disabled or hot LVGL draw buffers were moved out of internal DMA SRAM')
    print('PASS: two 64-row internal DMA buffers are targeted with the validated single-buffer fallback')
    print('PASS: R22 is zero-copy from LVGL draw buffer to esp_lcd color DMA; LVGL releases on DMA completion')
    print('PASS: R22 removes per-pixel flush byte swapping via LV_COLOR_16_SWAP=1')
    print('PASS: R22 main GUI keeps ~62.5 Hz phase when visible; R23 saver uses ~41.7 Hz coherent-core cadence')
    print('PASS: LVGL object pool uses OPI PSRAM; RGB565 draw buffers stay in internal DMA SRAM')

if __name__=='__main__': main()
