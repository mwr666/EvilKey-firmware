/* SPDX-License-Identifier: AGPL-3.0-or-later */
#pragma once
#include <stdbool.h>
#include <stdint.h>

typedef enum {
    WS_ACTION_NONE = 0,
    WS_ACTION_APPROVE,
    WS_ACTION_CANCEL
} ws_action_t;

typedef enum {
    WS_UP_WAITING = 0,
    WS_UP_APPROVED,
    WS_UP_CANCELLED,
    WS_UP_TIMED_OUT
} ws_up_result_t;

typedef struct {
    bool valid;
    bool down;
    ws_action_t action;
} ws_contact_t;

typedef struct {
    bool initialized;
    bool raw_down;
    bool armed;
    bool pressed;
    ws_action_t candidate_action;
    ws_action_t pressed_action;
    uint32_t changed_at;
} ws_gesture_t;

typedef struct {
    bool active;
    uint32_t started_at;
    uint32_t timeout_ms;
    ws_gesture_t boot;
    ws_gesture_t touch;
} ws_presence_t;

/* A fresh released -> pressed -> released gesture is required for each request.
 * Initial held contacts, bounce, invalid I2C reads and target changes do not count.
 * All deadlines use unsigned elapsed time and tolerate a uint32_t timer wrap. */
void ws_presence_start(ws_presence_t *p, uint32_t now, uint32_t timeout_ms);
ws_up_result_t ws_presence_step(ws_presence_t *p, uint32_t now,
                               bool cancel, ws_contact_t boot,
                               ws_contact_t touch);

ws_action_t ws_gesture_step(ws_gesture_t *g, uint32_t now, ws_contact_t c);
