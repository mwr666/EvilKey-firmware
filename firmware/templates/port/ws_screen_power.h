/* SPDX-License-Identifier: AGPL-3.0-or-later */
#pragma once
#include <stdbool.h>
#include <stdint.h>
#include "ws_presence.h"

/* Pure UI1 state machine. Owned by the board-poll task, never a USB callback.
 * Only the AMOLED is switched off; this module has no power/USB/auth APIs. */
#define WS_SCREEN_OFF_AFTER_DIM_MS 60000U
#define WS_SCREEN_WAKE_RELEASE_MS 60U

typedef enum { WS_SCREEN_BRIGHT=0, WS_SCREEN_DIMMED, WS_SCREEN_OFF } ws_screen_level_t;
typedef struct {
    ws_screen_level_t level;
    uint32_t activity_at, dimmed_at, release_at;
    bool block_touch, release_seen;
} ws_screen_power_t;

static inline void ws_screen_power_init(ws_screen_power_t *p,uint32_t now) {
    *p=(ws_screen_power_t){.level=WS_SCREEN_BRIGHT,.activity_at=now};
}
static inline void ws_screen_power_wake(ws_screen_power_t *p,uint32_t now) {
    p->level=WS_SCREEN_BRIGHT;
    p->activity_at=now;
    /* Waking because of a host prompt must NOT clear an unfinished wake tap. */
}
/* Called exactly once per new I2C sample. False = do NOT send this sample to
 * PIN/presence. Invalid readings cannot masquerade as a finger release. */
static inline bool ws_screen_power_touch(ws_screen_power_t *p,uint32_t now,
                                         ws_contact_t c,bool display_bright) {
    if(c.valid && c.down) {
        if(p->level!=WS_SCREEN_BRIGHT || !display_bright) p->block_touch=true;
        ws_screen_power_wake(p,now);
    }
    if(!p->block_touch) return true;
    if(!c.valid || c.down) {
        p->release_seen=false;
        return false;
    }
    if(!p->release_seen) {
        p->release_seen=true;p->release_at=now;
        return false;
    }
    if((uint32_t)(now-p->release_at)<WS_SCREEN_WAKE_RELEASE_MS) return false;
    p->block_touch=false;p->release_seen=false;
    /* This is a valid up sample only. Existing gesture debounce still applies. */
    return true;
}
static inline void ws_screen_power_tick_config(ws_screen_power_t *p,uint32_t now,
                                        bool hold_awake,bool touch_available,
                                        uint32_t dim_after_ms,uint32_t off_after_dim_ms) {
    if(hold_awake || !touch_available || dim_after_ms==0) {
        ws_screen_power_wake(p,now);return;
    }
    if(p->level==WS_SCREEN_BRIGHT && (uint32_t)(now-p->activity_at)>=dim_after_ms) {
        p->level=WS_SCREEN_DIMMED;p->dimmed_at=now;
    } else if(p->level==WS_SCREEN_DIMMED && off_after_dim_ms &&
              (uint32_t)(now-p->dimmed_at)>=off_after_dim_ms) {
        p->level=WS_SCREEN_OFF;
    }
}

static inline void ws_screen_power_tick(ws_screen_power_t *p,uint32_t now,
        bool hold_awake,bool touch_available,uint32_t dim_after_ms) {
    ws_screen_power_tick_config(p,now,hold_awake,touch_available,dim_after_ms,
                                WS_SCREEN_OFF_AFTER_DIM_MS);
}
