/* SPDX-License-Identifier: AGPL-3.0-or-later */
#pragma once
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
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
/* Raw display coordinates; release uses down=false and clears coordinates. */
void ek_apps_touch(int32_t x, int32_t y, bool down);
void ek_apps_snapshot(EkAppsState *out);
int ek_apps_copy_frame(uint16_t *pixels,size_t count,uint32_t *generation);

#ifdef __cplusplus
}
#endif
