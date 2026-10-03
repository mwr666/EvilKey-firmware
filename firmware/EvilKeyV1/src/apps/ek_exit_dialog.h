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
    EK_EXIT_NO_X = 34, EK_EXIT_Y = 273,
    EK_EXIT_YES_X = 146, EK_EXIT_BUTTON_W = 98,
    EK_EXIT_BUTTON_H = 44, EK_EXIT_SWIPE_X = 90,
    EK_EXIT_ZONE_SIZE = 56, EK_EXIT_ACTIVE_HEIGHT = 160
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
    bool dragging;
    uint8_t owner; /* 0 idle, 1 app, 2 firmware, 3 cancelled until all up */
    uint8_t progress; /* 0..100; 100 stays armed until release or invalid contact */
    uint16_t start_x, start_y, contact_id;
    EkExitButton pressed;
} EkExitDialog;

void ek_exit_dialog_reset(EkExitDialog *dialog);
EkExitEvent ek_exit_dialog_touch(EkExitDialog *dialog, bool fresh,
                                  uint8_t contacts, uint16_t x, uint16_t y,
                                  uint16_t contact_id);
bool ek_exit_dialog_blocks_input(const EkExitDialog *dialog);
bool ek_exit_dialog_paused(const EkExitDialog *dialog);

#ifdef __cplusplus
}
#endif
