/* SPDX-License-Identifier: AGPL-3.0-or-later */
#pragma once
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include "ws_presence.h"
#define WS_PIN_MAX_BYTES 63U
#define WS_PIN_KEY_0 10
#define WS_PIN_KEY_DELETE 20
#define WS_PIN_KEY_ENTER 21
#define WS_PIN_KEY_CANCEL 22
#define WS_PIN_RETRY_MAX 8U
/* Pure input state. No plaintext PIN is ever part of a display snapshot. */
typedef enum { WS_PIN_IDLE, WS_PIN_EDITING, WS_PIN_SUBMITTED,
               WS_PIN_CANCELLED, WS_PIN_TIMEOUT, WS_PIN_IO_ERROR } ws_pin_status_t;
typedef struct {
    ws_pin_status_t status;
    uint32_t started_at, timeout_ms;
    ws_gesture_t gesture;
    char digits[WS_PIN_MAX_BYTES+1];
    uint8_t length;
} ws_pinpad_t;
void ws_pinpad_zero(void *p, size_t n);
void ws_pinpad_begin(ws_pinpad_t *p, uint32_t now, uint32_t timeout_ms);
void ws_pinpad_step(ws_pinpad_t *p, uint32_t now, bool cancel,
                    bool io_ok, ws_contact_t touch);
void ws_pinpad_abort(ws_pinpad_t *p, ws_pin_status_t reason);
bool ws_pinpad_take(ws_pinpad_t *p, char *out, size_t cap, size_t *len);
int ws_pinpad_hit_test(uint16_t x, uint16_t y);
