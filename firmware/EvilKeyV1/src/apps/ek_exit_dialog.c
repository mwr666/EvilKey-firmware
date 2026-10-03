/* SPDX-License-Identifier: AGPL-3.0-or-later */
#include "ek_exit_dialog.h"
#include <string.h>

enum { OWNER_IDLE, OWNER_APP, OWNER_FIRMWARE, OWNER_CANCELLED };

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

bool ek_exit_dialog_blocks_input(const EkExitDialog *d) {
    return d && (d->visible || d->owner == OWNER_FIRMWARE || d->owner == OWNER_CANCELLED);
}

bool ek_exit_dialog_paused(const EkExitDialog *d) {
    return ek_exit_dialog_blocks_input(d);
}

static void cancel_contact(EkExitDialog *d) {
    d->owner = OWNER_CANCELLED;
    d->dragging = false;
    d->progress = 0;
    d->was_down = false;
    d->pressed = EK_EXIT_BUTTON_NONE;
}

EkExitEvent ek_exit_dialog_touch(EkExitDialog *dialog, bool fresh,
                                  uint8_t contacts, uint16_t x, uint16_t y,
                                  uint16_t contact_id) {
    if (!dialog) return EK_EXIT_EVENT_NONE;
    if (!fresh) {
        /* Never reinterpret a held finger after sensor recovery. */
        if (dialog->owner != OWNER_APP) cancel_contact(dialog);
        return EK_EXIT_EVENT_NONE;
    }
    if (dialog->owner == OWNER_CANCELLED) {
        if (!contacts) dialog->owner = OWNER_IDLE;
        return EK_EXIT_EVENT_NONE;
    }
    if (dialog->visible) {
        if (contacts > 1 || (contacts && dialog->was_down && contact_id != dialog->contact_id)) {
            cancel_contact(dialog);
            return EK_EXIT_EVENT_NONE;
        }
        if (contacts) {
            EkExitButton here = hit_button(x, y);
            if (!dialog->was_down) {dialog->pressed = here;dialog->contact_id = contact_id;}
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
        dialog->owner = OWNER_IDLE;
        return accepted == EK_EXIT_BUTTON_YES ? EK_EXIT_EVENT_CONFIRM : EK_EXIT_EVENT_CANCEL;
    }
    if (dialog->owner == OWNER_APP) {
        if (!contacts) dialog->owner = OWNER_IDLE;
        return EK_EXIT_EVENT_NONE; /* Ownership never changes mid-contact. */
    }
    if (dialog->owner == OWNER_IDLE) {
        if (!contacts) return EK_EXIT_EVENT_NONE;
        if (contacts != 1 || x >= EK_EXIT_ZONE_SIZE || y >= EK_EXIT_ZONE_SIZE) {
            dialog->owner = OWNER_APP;
            return EK_EXIT_EVENT_NONE;
        }
        dialog->owner = OWNER_FIRMWARE;
        dialog->dragging = dialog->was_down = true;
        dialog->start_x = x; dialog->start_y = y; dialog->contact_id = contact_id;
        dialog->progress = 0;
        return EK_EXIT_EVENT_NONE;
    }
    if (contacts > 1 || (contacts && contact_id != dialog->contact_id)) {
        cancel_contact(dialog);
        if (!contacts) dialog->owner = OWNER_IDLE;
        return EK_EXIT_EVENT_NONE;
    }
    /* Capture still starts only in the corner. Once owned, the whole upper
       band accepts diagonal travel; app-origin sliders remain app-owned.
       Completion is sticky, including zero coordinates reported on release. */
    if (dialog->progress < 100) {
        if (y >= EK_EXIT_ACTIVE_HEIGHT) {
            cancel_contact(dialog);
            if (!contacts) dialog->owner = OWNER_IDLE;
            return EK_EXIT_EVENT_NONE;
        }
        int dx = (int)x - dialog->start_x;
        dialog->progress = dx <= 0 ? 0 : dx >= EK_EXIT_SWIPE_X ? 100 :
            (uint8_t)(dx * 100 / EK_EXIT_SWIPE_X);
    }
    if (contacts) return EK_EXIT_EVENT_NONE;
    bool complete = dialog->progress == 100;
    dialog->owner = OWNER_IDLE;
    dialog->dragging = dialog->was_down = false;
    dialog->progress = 0;
    if (!complete) return EK_EXIT_EVENT_NONE;
    dialog->visible = true;
    dialog->pressed = EK_EXIT_BUTTON_NONE;
    return EK_EXIT_EVENT_OPEN;
}
