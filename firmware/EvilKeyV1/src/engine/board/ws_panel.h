/* SPDX-License-Identifier: AGPL-3.0-or-later */
#pragma once
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include "esp_err.h"

typedef void (*ws_panel_flush_done_cb_t)(void *ctx);

esp_err_t ws_panel_init(void);
/* Queues RGB565 data directly from a DMA-capable LVGL draw buffer. The caller
 * must keep pixels alive until done(ctx) runs from the panel completion ISR. */
esp_err_t ws_panel_flush_async(uint16_t x1,uint16_t y1,uint16_t x2,uint16_t y2,
                               const uint16_t *pixels,size_t pixel_count,
                               ws_panel_flush_done_cb_t done,void *done_ctx);
/* Waits only when a color DMA transaction is still in flight. */
esp_err_t ws_panel_wait_idle(uint32_t timeout_ms);
esp_err_t ws_panel_brightness(uint8_t brightness);
/* Display task only; keeps the touch controller and USB running. */
esp_err_t ws_panel_set_enabled(bool enabled);
