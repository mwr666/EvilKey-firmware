/* SPDX-License-Identifier: AGPL-3.0-or-later */
#include "../EvilKeyV1/src/apps/ek_exit_dialog.h"
#include "../EvilKeyV1/src/apps/evilkey_app_abi.h"
#include <stdio.h>
#define CHECK(e) do {if(!(e)){fprintf(stderr,"Exit check line %d: %s\n",__LINE__,#e);return 1;}}while(0)
#define T(f,n,x,y) ek_exit_dialog_touch(&d,f,n,x,y,7)
int main(void) {
    EkExitDialog d={0};
    CHECK(EK_EXIT_ZONE_SIZE==EVILKEY_APP_SYSTEM_ZONE_WIDTH);
    CHECK(EK_EXIT_ZONE_SIZE==EVILKEY_APP_SYSTEM_ZONE_HEIGHT);
    /* Slider begun in the app keeps ownership, even through the corner. */
    CHECK(T(true,1,80,20)==EK_EXIT_EVENT_NONE);CHECK(!ek_exit_dialog_blocks_input(&d));
    CHECK(T(true,1,10,20)==EK_EXIT_EVENT_NONE);CHECK(!ek_exit_dialog_paused(&d));
    CHECK(T(true,1,200,20)==EK_EXIT_EVENT_NONE);CHECK(T(true,0,200,20)==EK_EXIT_EVENT_NONE);
    CHECK(!d.visible);
    /* Exclusive boundary; other first touches and initial multi-touch belong to app. */
    for(unsigned edge=0;edge<3;++edge){
        unsigned x=edge==0?EK_EXIT_ZONE_SIZE:10,y=edge==1?EK_EXIT_ZONE_SIZE:10,n=edge==2?2:1;
        CHECK(T(true,n,x,y)==EK_EXIT_EVENT_NONE);CHECK(!ek_exit_dialog_blocks_input(&d));
        CHECK(T(true,1,10,10)==EK_EXIT_EVENT_NONE);CHECK(!ek_exit_dialog_blocks_input(&d));
        CHECK(T(true,0,200,10)==EK_EXIT_EVENT_NONE);CHECK(!d.visible);
    }
    CHECK(T(true,1,20,20)==EK_EXIT_EVENT_NONE);CHECK(d.dragging&&ek_exit_dialog_paused(&d));
    CHECK(T(true,1,65,20)==EK_EXIT_EVENT_NONE);CHECK(d.progress==50);
    CHECK(T(true,0,65,20)==EK_EXIT_EVENT_NONE);CHECK(!d.visible&&!ek_exit_dialog_paused(&d));
    /* The active band expands after corner capture; incomplete progress is reversible. */
    CHECK(T(true,1,20,20)==EK_EXIT_EVENT_NONE);CHECK(T(true,1,65,100)==EK_EXIT_EVENT_NONE);
    CHECK(d.dragging&&d.progress==50);CHECK(T(true,1,40,159)==EK_EXIT_EVENT_NONE);
    CHECK(d.dragging&&d.progress==22);CHECK(T(true,0,40,159)==EK_EXIT_EVENT_NONE);CHECK(!d.visible);
    /* Completion latches through diagonal overtravel, screen edge and backtracking.
       Release coordinates can be zero: they must not erase an armed gesture. */
    CHECK(T(true,1,55,55)==EK_EXIT_EVENT_NONE);CHECK(T(true,1,145,159)==EK_EXIT_EVENT_NONE);
    CHECK(d.progress==100&&!d.visible);CHECK(T(true,1,279,220)==EK_EXIT_EVENT_NONE);
    CHECK(d.dragging&&d.progress==100);CHECK(T(true,1,0,455)==EK_EXIT_EVENT_NONE);
    CHECK(d.progress==100);CHECK(T(true,0,0,0)==EK_EXIT_EVENT_OPEN);CHECK(d.visible);
    CHECK(T(true,1,70,290)==EK_EXIT_EVENT_NONE);CHECK(T(true,0,70,290)==EK_EXIT_EVENT_CANCEL);
    /* Vertical cancel remains blocked until every finger is released. */
    CHECK(T(true,1,20,20)==EK_EXIT_EVENT_NONE);CHECK(T(true,1,65,160)==EK_EXIT_EVENT_NONE);
    CHECK(!d.dragging&&ek_exit_dialog_blocks_input(&d));
    CHECK(T(true,1,110,20)==EK_EXIT_EVENT_NONE);CHECK(!d.visible);
    CHECK(T(true,0,110,20)==EK_EXIT_EVENT_NONE);CHECK(!ek_exit_dialog_paused(&d));
    /* Second finger and contact-ID replacement cannot arm a new gesture. */
    CHECK(T(true,1,20,20)==EK_EXIT_EVENT_NONE);CHECK(T(true,2,100,20)==EK_EXIT_EVENT_NONE);
    CHECK(T(true,1,20,20)==EK_EXIT_EVENT_NONE);CHECK(T(true,1,200,20)==EK_EXIT_EVENT_NONE);
    CHECK(T(true,0,200,20)==EK_EXIT_EVENT_NONE);CHECK(!d.visible);
    /* Even after latching, multi-touch/stale input/contact replacement still cancel. */
    for(unsigned fault=0;fault<3;++fault){
        CHECK(T(true,1,20,20)==EK_EXIT_EVENT_NONE);CHECK(T(true,1,110,100)==EK_EXIT_EVENT_NONE);
        CHECK(d.progress==100);
        CHECK(ek_exit_dialog_touch(&d,fault!=0,fault==1?2:1,279,200,fault==2?8:7)==EK_EXIT_EVENT_NONE);
        CHECK(!d.dragging&&d.progress==0&&ek_exit_dialog_blocks_input(&d));
        CHECK(T(true,0,0,0)==EK_EXIT_EVENT_NONE);CHECK(!d.visible&&!ek_exit_dialog_paused(&d));
    }
    CHECK(T(true,1,20,20)==EK_EXIT_EVENT_NONE);
    CHECK(ek_exit_dialog_touch(&d,true,1,110,20,8)==EK_EXIT_EVENT_NONE);
    CHECK(T(true,0,110,20)==EK_EXIT_EVENT_NONE);CHECK(!d.visible);
    /* Stale sample cancels and requires all-up, also if no touch was seen before. */
    CHECK(T(true,1,20,20)==EK_EXIT_EVENT_NONE);CHECK(T(false,0,110,20)==EK_EXIT_EVENT_NONE);
    CHECK(T(true,1,110,20)==EK_EXIT_EVENT_NONE);CHECK(T(true,0,110,20)==EK_EXIT_EVENT_NONE);
    CHECK(!d.visible);CHECK(T(false,0,0,0)==EK_EXIT_EVENT_NONE);
    CHECK(T(true,1,20,20)==EK_EXIT_EVENT_NONE);CHECK(!d.dragging);
    CHECK(T(true,0,110,20)==EK_EXIT_EVENT_NONE);CHECK(!d.visible);
    CHECK(T(true,1,20,20)==EK_EXIT_EVENT_NONE);CHECK(T(true,1,110,20)==EK_EXIT_EVENT_NONE);
    CHECK(T(true,0,110,20)==EK_EXIT_EVENT_OPEN);CHECK(d.visible&&ek_exit_dialog_paused(&d));
    CHECK(T(true,1,200,180)==EK_EXIT_EVENT_NONE);CHECK(T(true,0,200,180)==EK_EXIT_EVENT_NONE);CHECK(d.visible);
    CHECK(T(true,1,190,290)==EK_EXIT_EVENT_NONE);CHECK(d.pressed==EK_EXIT_BUTTON_YES);
    CHECK(T(true,1,70,290)==EK_EXIT_EVENT_NONE);CHECK(T(true,0,70,290)==EK_EXIT_EVENT_NONE);CHECK(d.visible);
    CHECK(T(true,1,190,290)==EK_EXIT_EVENT_NONE);CHECK(T(false,0,190,290)==EK_EXIT_EVENT_NONE);
    CHECK(T(true,0,190,290)==EK_EXIT_EVENT_NONE);CHECK(d.visible);
    CHECK(T(true,1,70,290)==EK_EXIT_EVENT_NONE);CHECK(T(true,0,70,290)==EK_EXIT_EVENT_CANCEL);
    CHECK(!d.visible&&!ek_exit_dialog_paused(&d));
    CHECK(T(true,1,55,55)==EK_EXIT_EVENT_NONE);CHECK(T(true,0,145,55)==EK_EXIT_EVENT_OPEN);
    CHECK(T(true,2,190,290)==EK_EXIT_EVENT_NONE);CHECK(T(true,1,190,290)==EK_EXIT_EVENT_NONE);
    CHECK(T(true,0,190,290)==EK_EXIT_EVENT_NONE);CHECK(d.visible);
    CHECK(T(true,1,190,290)==EK_EXIT_EVENT_NONE);CHECK(T(true,0,190,290)==EK_EXIT_EVENT_CONFIRM);
    CHECK(!d.visible);ek_exit_dialog_reset(&d);CHECK(!ek_exit_dialog_blocks_input(&d));
    puts("PASS corner ownership, 160px active band, reversible partial progress, latched completion/edge/zero-coordinate release, multi/ID/stale cancellation, NO/YES");
    return 0;
}
