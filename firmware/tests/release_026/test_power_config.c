#include "ws_screen_power.h"
#include <assert.h>
#include <stdio.h>
int main(void){ws_screen_power_t p;
 ws_screen_power_init(&p,100);ws_screen_power_tick_config(&p,5100,false,true,5000,0);assert(p.level==WS_SCREEN_DIMMED);
 ws_screen_power_tick_config(&p,100000,false,true,5000,0);assert(p.level==WS_SCREEN_DIMMED);
 ws_screen_power_tick_config(&p,100001,false,true,0,5000);assert(p.level==WS_SCREEN_BRIGHT);
 ws_screen_power_init(&p,UINT32_MAX-100);ws_screen_power_tick_config(&p,499,false,true,500,800);assert(p.level==WS_SCREEN_DIMMED);
 ws_screen_power_tick_config(&p,1299,false,true,500,800);assert(p.level==WS_SCREEN_OFF);
 ws_screen_power_tick_config(&p,1400,true,true,500,800);assert(p.level==WS_SCREEN_BRIGHT);
 puts("PASS: configurable power intervals, no-off, no-dim and uptime wraparound");return 0;}
