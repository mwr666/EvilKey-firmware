/* Host-only tests of the actual header used by ws_board.c. */
#include "ws_screen_power.h"
#include <assert.h>
#include <stdio.h>
static const ws_contact_t UP={true,false,WS_ACTION_NONE};
static const ws_contact_t DOWN={true,true,WS_ACTION_APPROVE};
static const ws_contact_t BAD={false,false,WS_ACTION_NONE};
int main(void) {
    ws_screen_power_t p;
    ws_screen_power_init(&p,100);
    ws_screen_power_tick(&p,30099,false,true,30000);assert(p.level==WS_SCREEN_BRIGHT);
    ws_screen_power_tick(&p,30100,false,true,30000);assert(p.level==WS_SCREEN_DIMMED);
    ws_screen_power_tick(&p,90099,false,true,30000);assert(p.level==WS_SCREEN_DIMMED);
    ws_screen_power_tick(&p,90100,false,true,30000);assert(p.level==WS_SCREEN_OFF);
    ws_screen_power_tick(&p,0,false,true,30000);assert(p.level==WS_SCREEN_OFF);
    puts("PASS power: 30 seconds + 60 seconds; off latched through clock wrap");
    assert(!ws_screen_power_touch(&p,90101,DOWN,false));assert(p.level==WS_SCREEN_BRIGHT && p.block_touch);
    assert(!ws_screen_power_touch(&p,90500,DOWN,true));
    assert(!ws_screen_power_touch(&p,90520,UP,true));
    assert(!ws_screen_power_touch(&p,90560,BAD,true));
    assert(!ws_screen_power_touch(&p,90580,UP,true));
    assert(!ws_screen_power_touch(&p,90639,UP,true));
    assert(ws_screen_power_touch(&p,90640,UP,true));
    assert(ws_screen_power_touch(&p,90660,DOWN,true));
    puts("PASS wake: held wake tap consumed; invalid I2C cannot complete release");
    p.level=WS_SCREEN_DIMMED;
    assert(!ws_screen_power_touch(&p,91000,DOWN,true));assert(p.level==WS_SCREEN_BRIGHT);
    ws_screen_power_tick(&p,91500,true,true,30000);assert(p.block_touch);
    assert(!ws_screen_power_touch(&p,91520,DOWN,true));
    puts("PASS dim touch: bright again; new host prompt cannot clear wake barrier");
    ws_screen_power_init(&p,0);
    assert(!ws_screen_power_touch(&p,1,DOWN,false));assert(p.block_touch);
    ws_screen_power_init(&p,0);
    assert(ws_screen_power_touch(&p,40000,BAD,true));
    ws_screen_power_tick(&p,40000,false,true,30000);assert(p.level==WS_SCREEN_DIMMED);
    ws_screen_power_tick(&p,50000,true,true,30000);assert(p.level==WS_SCREEN_BRIGHT);
    ws_screen_power_tick(&p,999999,false,false,30000);assert(p.level==WS_SCREEN_BRIGHT);
    ws_screen_power_tick(&p,1999999,false,true,0);assert(p.level==WS_SCREEN_BRIGHT);
    puts("PASS policies: pending I/O wake blocked; invalid contact is not activity; active prompt, failed touch and dim=0 stay bright");
    uint32_t t=UINT32_MAX-15000U;ws_screen_power_init(&p,t);
    ws_screen_power_tick(&p,t+30000U,false,true,30000);assert(p.level==WS_SCREEN_DIMMED);
    ws_screen_power_tick(&p,t+89999U,false,true,30000);assert(p.level==WS_SCREEN_DIMMED);
    ws_screen_power_tick(&p,t+90000U,false,true,30000);assert(p.level==WS_SCREEN_OFF);
    assert(!ws_screen_power_touch(&p,UINT32_MAX-30U,DOWN,false));
    assert(!ws_screen_power_touch(&p,UINT32_MAX-20U,UP,true));
    assert(!ws_screen_power_touch(&p,38U,UP,true));
    assert(ws_screen_power_touch(&p,39U,UP,true));
    puts("PASS wraparound: dim deadline, off deadline and wake-release debounce");
}
