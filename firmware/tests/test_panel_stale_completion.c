/* SPDX-License-Identifier: AGPL-3.0-or-later */
#define main panel_regression_main
#include "release_026/test_panel_ui1.c"
#undef main
int main(void){
 static uint16_t pixels[560];assert(ws_panel_init()==ESP_OK);
 assert(ws_panel_flush_async(0,0,279,1,pixels,560,done_cb,(void*)0x1234)==ESP_OK);
 sem_token=true;auto_complete=false; /* Previous transfer token, current DMA still owns bytes. */
 assert(ws_panel_wait_idle(500)==ESP_ERR_TIMEOUT);
 assert(s_pending&&model_pending==pixels&&!done_calls&&s_flush_done==done_cb&&s_flush_ctx==(void*)0x1234);
 assert(!memcmp(pixels,dma_copy,sizeof pixels));
 complete_color();assert(!s_pending&&!model_pending&&done_calls==1);
 puts("PASS stale completion token cannot release current DMA; timeout retains bytes/context; late callback safe");
 return 0;
}
