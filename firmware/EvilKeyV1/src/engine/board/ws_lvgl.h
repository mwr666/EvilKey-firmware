/* SPDX-License-Identifier: AGPL-3.0-or-later */
#pragma once
#include "esp_err.h"
#include "ws_ui.h"

/* LVGL is intentionally isolated behind this API so the authentication state
 * machines never depend on widget events. All calls are made by the display
 * owner/task; the snapshot contains no PIN plaintext. */
esp_err_t ws_lvgl_init(void);
esp_err_t ws_lvgl_render(const ws_ui_snapshot_t *view);
