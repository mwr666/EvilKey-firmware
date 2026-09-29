/* SPDX-License-Identifier: AGPL-3.0-or-later */
#include "ek_exit_dialog.h"
#include <string.h>

static EkExitButton hit_button(uint16_t x, uint16_t y) {
    if (y < EK_EXIT_Y || y >= EK_EXIT_Y + EK_EXIT_BUTTON_H) return EK_EXIT_BUTTON_NONE;
    if (x >= EK_EXIT_NO_X && x < EK_EXIT_NO_X + EK_EXIT_BUTTON_W)
        return EK_EXIT_BUTTON_NO;
    if (x >= EK_EXIT_YES_X && x < EK_EXIT_YES_X + EK_EXIT_BUTTON_W)
        return EK_EXIT_BUTTON_YES;
    return EK_EXIT_BUTTON_NONE;
}

void ek_exit_dialog_reset(EkExitDialog *dialog) {
    if (dialog) memset(dialog, 0, sizeof(*dialog));
}

EkExitEvent ek_exit_dialog_touch(EkExitDialog *dialog, bool fresh,
                                  bool down, uint16_t x, uint16_t y) {
    if (!dialog) return EK_EXIT_EVENT_NONE;
    if (!fresh) {
        /* A stale sensor sample cannot accept a button or finish a swipe. */
        dialog->was_down = false;
        dialog->pressed = EK_EXIT_BUTTON_NONE;
        return EK_EXIT_EVENT_NONE;
    }
    if (dialog->visible) {
        if (down) {
            EkExitButton here = hit_button(x, y);
            if (!dialog->was_down) dialog->pressed = here;
            else if (here != dialog->pressed) dialog->pressed = EK_EXIT_BUTTON_NONE;
            dialog->was_down = true;
            return EK_EXIT_EVENT_NONE;
        }
        EkExitButton accepted = dialog->was_down && dialog->pressed == hit_button(x, y)
            ? dialog->pressed : EK_EXIT_BUTTON_NONE;
        dialog->was_down = false;
        dialog->pressed = EK_EXIT_BUTTON_NONE;
        if (accepted == EK_EXIT_BUTTON_NONE) return EK_EXIT_EVENT_NONE;
        dialog->visible = false;
        return accepted == EK_EXIT_BUTTON_YES ? EK_EXIT_EVENT_CONFIRM : EK_EXIT_EVENT_CANCEL;
    }
    if (down) {
        if (!dialog->was_down) dialog->start_x = x;
        dialog->was_down = true;
        return EK_EXIT_EVENT_NONE;
    }
    bool exit_swipe = dialog->was_down && x > dialog->start_x &&
        x - dialog->start_x >= EK_EXIT_SWIPE_X;
    dialog->was_down = false;
    if (!exit_swipe) return EK_EXIT_EVENT_NONE;
    dialog->visible = true;
    dialog->pressed = EK_EXIT_BUTTON_NONE;
    return EK_EXIT_EVENT_OPEN;
}
