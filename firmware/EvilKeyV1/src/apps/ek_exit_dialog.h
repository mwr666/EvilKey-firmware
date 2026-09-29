/* SPDX-License-Identifier: AGPL-3.0-or-later
 * Firmware-owned exit confirmation for every EvilKey app.
 */
#pragma once
#include <stdbool.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

enum {
    EK_EXIT_NO_X = 32, EK_EXIT_Y = 247,
    EK_EXIT_YES_X = 150, EK_EXIT_BUTTON_W = 98,
    EK_EXIT_BUTTON_H = 58, EK_EXIT_SWIPE_X = 62
};

typedef enum {
    EK_EXIT_BUTTON_NONE = 0,
    EK_EXIT_BUTTON_NO = 1,
    EK_EXIT_BUTTON_YES = 2
} EkExitButton;

typedef enum {
    EK_EXIT_EVENT_NONE = 0,
    EK_EXIT_EVENT_OPEN,
    EK_EXIT_EVENT_CANCEL,
    EK_EXIT_EVENT_CONFIRM
} EkExitEvent;

typedef struct {
    bool visible;
    bool was_down;
    uint16_t start_x;
    EkExitButton pressed;
} EkExitDialog;

void ek_exit_dialog_reset(EkExitDialog *dialog);
EkExitEvent ek_exit_dialog_touch(EkExitDialog *dialog, bool fresh,
                                  bool down, uint16_t x, uint16_t y);

#ifdef __cplusplus
}
#endif
