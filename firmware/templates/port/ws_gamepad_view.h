/* SPDX-License-Identifier: AGPL-3.0-or-later */
#pragma once
#include "ws_ui.h"
#include "../lvgl/lvgl.h"
void ws_gamepad_view_init(lv_disp_t *display,const WsControlPrefs *prefs);
void ws_gamepad_view_render(const ws_ui_snapshot_t *view);
