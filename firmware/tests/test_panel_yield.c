#define main panel_regression_main
#include "release_026/test_panel_ui1.c"
#undef main
int main(int argc,char **argv){
 if(argc==1)return panel_regression_main();
 (void)argv;static uint16_t data[560];assert(ws_panel_init()==ESP_OK);
 mock_awakened=true;unsigned before=yield_requests;
 assert(ws_panel_flush_async(0,0,279,1,data,560,done_cb,(void*)0x1234)==ESP_OK);
 complete_color();assert(done_calls==1&&!s_pending&&sem_token);
 assert(yield_requests==before+1); /* baseline MUST fail: callback return was discarded */
 assert(ws_panel_wait_idle(500)==ESP_OK);
 mock_awakened=false;before=yield_requests;
 assert(ws_panel_flush_async(0,0,279,1,data,560,done_cb,(void*)0x1234)==ESP_OK);
 complete_color();assert(done_calls==2&&!s_pending&&sem_token&&yield_requests==before);
 assert(ws_panel_wait_idle(500)==ESP_OK);
 puts("PANEL CONDITIONAL YIELD PASS:ignoredbool,DONE/context/idle/give beforeyield;false noyield;no metadata/timer");
}
