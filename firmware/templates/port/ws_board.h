/* SPDX-License-Identifier: AGPL-3.0-or-later */
#pragma once
#include <stdbool.h>
#include <stdint.h>
#include "button.h"
void ws_board_init(void);
/* Call after USB/BLE startup so display allocations cannot starve the transport. */
void ws_board_start_display(void);
void ws_board_poll(void);
void ws_board_presence_begin(uint32_t timeout_ms);
button_event_t ws_board_presence_poll(void);
void ws_board_presence_end(button_event_t result);

void ws_board_pin_abort(void); /* Clear a pending PIN on disconnect/suspend. */
bool ws_board_settings_pin_busy(void); /* Gate host CTAP while local RW authorization owns PIN UI. */
