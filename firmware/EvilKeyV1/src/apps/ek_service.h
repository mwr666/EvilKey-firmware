/* SPDX-License-Identifier: AGPL-3.0-or-later */
#pragma once
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include "evilkey_app_abi.h"
#ifdef __cplusplus
extern "C" {
#endif

enum { EK_APPS_WIDTH=280, EK_APPS_HEIGHT=456, EK_APPS_PIXELS=EK_APPS_WIDTH*EK_APPS_HEIGHT };
typedef enum {
    EK_APPS_NONE=0, EK_APPS_PREV, EK_APPS_NEXT, EK_APPS_RUN, EK_APPS_STOP
} EkAppsCommand;
typedef struct {
    bool ready, mounted, running;
    uint8_t count, selected;
    uint32_t frame;
    char id[32];
    char status[80];
} EkAppsState;

int ek_apps_start(void);
void ek_apps_set_visible(bool visible);
void ek_apps_set_modal(bool visible);
void ek_apps_request(EkAppsCommand command);
/* Samples are copied into the worker mailbox. All I2C stays on the board task. */
void ek_apps_input(const EvilKeyAppTouch *touch, uint32_t count,
                   bool accel_valid, int32_t ax_mg, int32_t ay_mg,
                   int32_t az_mg);
void ek_apps_snapshot(EkAppsState *out);
typedef struct { uint16_t x,y,width,height; } EkAppsDirty;
int ek_apps_copy_frame(uint16_t *pixels,size_t count,uint32_t *generation,
                       EkAppsDirty *dirty);

#ifdef __cplusplus
}
#endif
