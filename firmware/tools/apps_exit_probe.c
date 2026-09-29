/* SPDX-License-Identifier: AGPL-3.0-or-later */
#include "../EvilKeyV1/src/apps/ek_exit_dialog.h"
#include <stdio.h>

#define CHECK(expr) do { if (!(expr)) { \
    fprintf(stderr,"Exit dialog check failed at line %d: %s\n",__LINE__,#expr); \
    return 1; \
} } while (0)

int main(void) {
    EkExitDialog dialog = {0};
    CHECK(ek_exit_dialog_touch(&dialog,true,true,120,420)==EK_EXIT_EVENT_NONE);
    CHECK(ek_exit_dialog_touch(&dialog,true,false,120,420)==EK_EXIT_EVENT_NONE);
    CHECK(!dialog.visible);
    CHECK(ek_exit_dialog_touch(&dialog,true,true,200,200)==EK_EXIT_EVENT_NONE);
    CHECK(ek_exit_dialog_touch(&dialog,true,false,100,200)==EK_EXIT_EVENT_NONE);
    CHECK(!dialog.visible);

    CHECK(ek_exit_dialog_touch(&dialog,true,true,40,190)==EK_EXIT_EVENT_NONE);
    CHECK(ek_exit_dialog_touch(&dialog,false,false,150,190)==EK_EXIT_EVENT_NONE);
    CHECK(!dialog.visible); /* A stale release cannot open the dialog. */
    CHECK(ek_exit_dialog_touch(&dialog,true,true,40,190)==EK_EXIT_EVENT_NONE);
    CHECK(ek_exit_dialog_touch(&dialog,true,false,150,190)==EK_EXIT_EVENT_OPEN);
    CHECK(dialog.visible && dialog.pressed==EK_EXIT_BUTTON_NONE);
    CHECK(ek_exit_dialog_touch(&dialog,true,false,150,190)==EK_EXIT_EVENT_NONE);
    CHECK(ek_exit_dialog_touch(&dialog,true,true,140,210)==EK_EXIT_EVENT_NONE);
    CHECK(ek_exit_dialog_touch(&dialog,true,false,140,210)==EK_EXIT_EVENT_NONE);
    CHECK(dialog.visible); /* A tap outside requires an explicit Yes or No. */

    CHECK(ek_exit_dialog_touch(&dialog,true,true,190,270)==EK_EXIT_EVENT_NONE);
    CHECK(dialog.pressed==EK_EXIT_BUTTON_YES);
    CHECK(ek_exit_dialog_touch(&dialog,true,true,70,270)==EK_EXIT_EVENT_NONE);
    CHECK(ek_exit_dialog_touch(&dialog,true,false,70,270)==EK_EXIT_EVENT_NONE);
    CHECK(dialog.visible); /* Dragging from Yes to No cannot confirm. */
    CHECK(ek_exit_dialog_touch(&dialog,true,true,190,270)==EK_EXIT_EVENT_NONE);
    CHECK(ek_exit_dialog_touch(&dialog,false,false,190,270)==EK_EXIT_EVENT_NONE);
    CHECK(ek_exit_dialog_touch(&dialog,true,false,190,270)==EK_EXIT_EVENT_NONE);
    CHECK(dialog.visible); /* A stale touch cannot confirm. */

    CHECK(ek_exit_dialog_touch(&dialog,true,true,70,270)==EK_EXIT_EVENT_NONE);
    CHECK(dialog.pressed==EK_EXIT_BUTTON_NO);
    CHECK(ek_exit_dialog_touch(&dialog,true,false,70,270)==EK_EXIT_EVENT_CANCEL);
    CHECK(!dialog.visible);
    CHECK(ek_exit_dialog_touch(&dialog,true,true,40,190)==EK_EXIT_EVENT_NONE);
    CHECK(ek_exit_dialog_touch(&dialog,true,false,150,190)==EK_EXIT_EVENT_OPEN);
    CHECK(ek_exit_dialog_touch(&dialog,true,true,190,270)==EK_EXIT_EVENT_NONE);
    CHECK(ek_exit_dialog_touch(&dialog,true,false,190,270)==EK_EXIT_EVENT_CONFIRM);
    CHECK(!dialog.visible);
    ek_exit_dialog_reset(&dialog);
    CHECK(!dialog.visible && !dialog.was_down && dialog.pressed==EK_EXIT_BUTTON_NONE);
    puts("Apps exit dialog: swipe opens, No resumes, Yes confirms, stale/drag rejected");
    return 0;
}
