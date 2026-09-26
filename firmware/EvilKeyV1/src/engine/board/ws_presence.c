#include "../../pf_build_config.h"
/* SPDX-License-Identifier: AGPL-3.0-or-later */
#include "ws_presence.h"
#include <string.h>

#define DEBOUNCE_MS 40U

ws_action_t ws_gesture_step(ws_gesture_t *g, uint32_t now, ws_contact_t c)
{
    if (!c.valid) {
        memset(g, 0, sizeof(*g));
        return WS_ACTION_NONE;
    }
    if (!g->initialized) {
        g->initialized = true;
        g->raw_down = c.down;
        g->candidate_action = c.action;
        g->changed_at = now;
        return WS_ACTION_NONE;
    }
    if (c.down != g->raw_down) {
        g->raw_down = c.down;
        g->changed_at = now;
        if (c.down) {
            g->candidate_action = c.action;
        }
    }
    if (c.down) {
        /* Sliding into or between controls is not a valid tap. */
        if (c.action == WS_ACTION_NONE || c.action != g->candidate_action ||
            (g->pressed && c.action != g->pressed_action)) {
            g->armed = false;
            g->pressed = false;
        }
        if (g->armed && !g->pressed && c.action != WS_ACTION_NONE &&
            (uint32_t)(now - g->changed_at) >= DEBOUNCE_MS) {
            g->pressed = true;
            g->pressed_action = c.action;
        }
        return WS_ACTION_NONE;
    }
    if ((uint32_t)(now - g->changed_at) < DEBOUNCE_MS) {
        return WS_ACTION_NONE;
    }
    if (g->pressed) {
        ws_action_t result = g->pressed_action;
        memset(g, 0, sizeof(*g));
        return result;
    }
    g->armed = true;
    return WS_ACTION_NONE;
}

void ws_presence_start(ws_presence_t *p, uint32_t now, uint32_t timeout_ms)
{
    memset(p, 0, sizeof(*p));
    p->active = true;
    p->started_at = now;
    /* Keep the interval comfortably below the unsigned wrap interval. */
    p->timeout_ms = timeout_ms > 0U && timeout_ms <= 120000U ? timeout_ms : 30000U;
}

ws_up_result_t ws_presence_step(ws_presence_t *p, uint32_t now,
                               bool cancel, ws_contact_t boot,
                               ws_contact_t touch)
{
    if (!p->active) {
        return WS_UP_WAITING;
    }
    ws_up_result_t result = WS_UP_WAITING;
    if (cancel) {
        result = WS_UP_CANCELLED;
    } else if ((uint32_t)(now - p->started_at) >= p->timeout_ms) {
        result = WS_UP_TIMED_OUT;
    } else {
        ws_action_t b = ws_gesture_step(&p->boot, now, boot);
        ws_action_t t = ws_gesture_step(&p->touch, now, touch);
        /* A simultaneous cancel always takes precedence over approval. */
        if (b == WS_ACTION_CANCEL || t == WS_ACTION_CANCEL) {
            result = WS_UP_CANCELLED;
        } else if (b == WS_ACTION_APPROVE || t == WS_ACTION_APPROVE) {
            result = WS_UP_APPROVED;
        }
    }
    if (result != WS_UP_WAITING) {
        p->active = false;
        memset(&p->boot, 0, sizeof(p->boot));
        memset(&p->touch, 0, sizeof(p->touch));
    }
    return result;
}
