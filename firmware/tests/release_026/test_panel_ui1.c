/* Physical panel regression: LVGL owns composition, panel owns async QSPI DMA. */
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "../../templates/port/ws_panel.c"

static bool bus_error;
static bool reset_error;
static unsigned reset_levels,reset_configs;
static bool sem_token;
static unsigned cmds,colors,delayed,last_cmd;
static size_t last_size;
static unsigned char last_byte;
static const void *last_color_ptr;
static esp_lcd_panel_io_spi_config_t config;
static unsigned done_calls;
/* Independent panel RAM/address-pointer oracle. Pixels land only at DMA
 * completion, from the original unchanged source, in physical coordinates. */
static uint16_t panel_ram[320*456],dma_copy[280*64];
static unsigned cx0,cx1,cy0,cy1,cursor,write_start,write_continue;
static const uint16_t *model_pending;
static size_t model_pixels;
static bool auto_complete;
static unsigned yield_requests;
static bool mock_awakened=true;
void test_port_yield_from_isr(void){assert(!s_pending&&sem_token&&!s_flush_done&&!s_flush_ctx);++yield_requests;}
static unsigned fail_cmd;
static void complete_color(void);
static uint64_t mock_time;
static bool mock_diagnostics_enabled;
bool ek_render_diagnostics_enabled(void){return mock_diagnostics_enabled;}
static uint32_t mock_resume_delay;
int64_t esp_timer_get_time(void){return ++mock_time;}
void ws_gui_3d_record_panel_wait(uint32_t us){(void)us;}

SemaphoreHandle_t xSemaphoreCreateBinary(void){sem_token=false;return (void*)1;}
BaseType_t xSemaphoreGiveFromISR(SemaphoreHandle_t s,BaseType_t*a){(void)s;sem_token=true;*a=mock_awakened?pdTRUE:pdFALSE;return pdTRUE;}
BaseType_t xSemaphoreTake(SemaphoreHandle_t s,unsigned timeout){(void)s;if(!sem_token&&timeout&&auto_complete&&model_pending){complete_color();mock_time+=mock_resume_delay;}if(!sem_token)return pdFALSE;sem_token=false;return pdTRUE;}
void vTaskDelay(unsigned ms){delayed+=ms;}
esp_err_t gpio_config(const gpio_config_t*p){assert(p->pin_bit_mask==(1ULL<<21));++reset_configs;return reset_error?ESP_ERR_TIMEOUT:ESP_OK;}
esp_err_t gpio_set_level(int p,int n){assert(p==21);assert(n==(int)(reset_levels%2));++reset_levels;return ESP_OK;}
esp_err_t spi_bus_initialize(int host,const spi_bus_config_t*b,int dma){
 assert(host==SPI2_HOST&&dma==SPI_DMA_CH_AUTO);
 assert(b->max_transfer_sz==280*64*2);return ESP_OK;
}
esp_err_t esp_lcd_new_panel_io_spi(esp_lcd_spi_bus_handle_t bus,const esp_lcd_panel_io_spi_config_t*c,esp_lcd_panel_io_handle_t*out){
 assert(bus==SPI2_HOST);assert(c->pclk_hz==40*1000*1000);assert(c->trans_queue_depth==2);
 config=*c;*out=(void*)2;return ESP_OK;
}
esp_err_t esp_lcd_panel_io_tx_param(esp_lcd_panel_io_handle_t io,int cmd,const void*data,size_t n){
 assert(io==(void*)2);assert(((unsigned)cmd&0xff0000ffU)==0x02000000U);
 last_cmd=((unsigned)cmd>>8)&255;last_size=n;if(n)last_byte=*(const unsigned char*)data;
 assert(!model_pending); /* No address or control command may overtake DMA. */
 if(last_cmd==0x28||last_cmd==0x29)assert(data==NULL&&n==0);
 ++cmds;if(bus_error||last_cmd==fail_cmd)return ESP_ERR_TIMEOUT;
 if(last_cmd==0x2A||last_cmd==0x2B){
  assert(n==4);const unsigned char *p=data;unsigned lo=p[0]*256+p[1],hi=p[2]*256+p[3];
  if(last_cmd==0x2A){assert(lo>=20&&hi<300);cx0=lo;cx1=hi;}
  else {assert(hi<456);cy0=lo;cy1=hi;}
 }
 return ESP_OK;
}
esp_err_t esp_lcd_panel_io_tx_color(esp_lcd_panel_io_handle_t io,int cmd,const void*data,size_t n){
 assert(io==(void*)2&&(cmd==0x32002C00||cmd==0x32003C00));assert(data!=NULL&&n>0&&n<=280U*64U*2U&&!(n&3));
 assert(!model_pending);last_color_ptr=data;++colors;if(bus_error)return ESP_ERR_TIMEOUT;
 if(cmd==0x32002C00){cursor=0;++write_start;}else ++write_continue;
 model_pending=data;model_pixels=n/2;memcpy(dma_copy,data,n);return ESP_OK;
}
static void complete_color(void){
 assert(s_pending);esp_lcd_panel_io_event_data_t event={0};
 assert(model_pending&&memcmp(model_pending,dma_copy,model_pixels*2)==0);
 unsigned width=cx1-cx0+1,height=cy1-cy0+1;
 for(size_t i=0;i<model_pixels;i++){
  panel_ram[(cy0+cursor/width)*320+cx0+cursor%width]=model_pending[i];
  cursor=(cursor+1)%(width*height);
 }
 model_pending=NULL;
 /* Pinned ESP-IDF's SPI post callback discards this bool. */
 (void)config.on_color_trans_done((void*)2,&event,config.user_ctx);
}
static void done_cb(void *ctx){assert(ctx==(void*)0x1234);++done_calls;}
static void stream_tests(void){
 static uint16_t source[280*456],a[280*64],b[280*64];
 for(unsigned i=0;i<280U*456;i++)source[i]=(uint16_t)i; /* All65536 RGB565. */
 auto_complete=true;
 unsigned cases=0;
 for(unsigned sr=16;sr<=64;sr+=48)for(unsigned start=44;start<456;start+=102){
  unsigned end=start+106;if(end>456)end=456;if(end&1)++end;
  memset(panel_ram,0xa5,sizeof panel_ram);
  unsigned before=cmds,before2c=write_start,before3c=write_continue;
  assert(ws_panel_stream_begin(0,start,279,end-1)==ESP_OK);
  assert(ws_panel_init()==ESP_ERR_INVALID_STATE);
  assert(ws_panel_brightness(99)==ESP_ERR_INVALID_STATE);
  assert(ws_panel_set_enabled(false)==ESP_ERR_INVALID_STATE);
  assert(ws_panel_flush_async(0,0,279,1,a,560,done_cb,(void*)0x1234)==ESP_ERR_INVALID_STATE);
  unsigned chunks=0;
  for(unsigned y=start;y<end;){
   unsigned rows=end-y;if(rows>sr)rows=sr;uint16_t *p=chunks&1?b:a;
   memcpy(p,source+y*280,rows*280*2);
   assert(ws_panel_stream_write(y,rows,p,rows*280,done_cb,(void*)0x1234)==ESP_OK);
   y+=rows;++chunks;
  }
  assert(ws_panel_stream_end()==ESP_OK&&!s_pending&&!s_stream.active&&!model_pending);
  assert(cmds==before+2&&write_start==before2c+1&&write_continue==before3c+chunks-1);
  for(unsigned y=0;y<456;y++)for(unsigned x=0;x<320;x++){
   uint16_t expected=(y>=start&&y<end&&x>=20&&x<300)?source[y*280+x-20]:0xa5a5;
   assert(panel_ram[y*320+x]==expected);
  }
  ++cases;
 }
 /* Complete shipping viewport:26 strips16rows,one start+25continuations. */
 unsigned cmd0=cmds,c0=write_continue;
 assert(ws_panel_stream_begin(0,44,279,455)==ESP_OK);
 for(unsigned y=44;y<456;y+=16){unsigned rows=456-y;if(rows>16)rows=16;assert(ws_panel_stream_write(y,rows,source+y*280,rows*280,done_cb,(void*)0x1234)==ESP_OK);}
 assert(ws_panel_stream_end()==ESP_OK&&cmds==cmd0+2&&write_continue==c0+25);
 for(unsigned y=44;y<456;y++)assert(memcmp(panel_ram+y*320+20,source+y*280,560)==0);
 /* Invalid requests must not touch the bus or consume pointer/next_y. */
 unsigned before=cmds;
 assert(ws_panel_stream_begin(1,44,279,455)==ESP_ERR_INVALID_ARG&&cmds==before);
 assert(ws_panel_stream_begin(0,44,280,455)==ESP_ERR_INVALID_ARG);
 assert(ws_panel_stream_begin(0,44,279,456)==ESP_ERR_INVALID_ARG);
 assert(ws_panel_stream_begin(0,45,279,455)==ESP_ERR_INVALID_ARG);
 assert(ws_panel_stream_begin(0,44,279,454)==ESP_ERR_INVALID_ARG);
 assert(ws_panel_stream_begin(0,44,279,455)==ESP_OK);before=cmds;unsigned cc=colors;
 assert(ws_panel_stream_begin(0,44,279,455)==ESP_ERR_INVALID_STATE);
 assert(ws_panel_stream_write(46,16,a,4480,done_cb,(void*)0x1234)==ESP_ERR_INVALID_ARG);
 assert(ws_panel_stream_write(44,0,a,0,done_cb,(void*)0x1234)==ESP_ERR_INVALID_ARG);
 assert(ws_panel_stream_write(44,3,a,840,done_cb,(void*)0x1234)==ESP_ERR_INVALID_ARG);
 assert(ws_panel_stream_write(44,414,a,280*414,done_cb,(void*)0x1234)==ESP_ERR_INVALID_ARG);
 assert(ws_panel_stream_write(44,66,a,280*66,done_cb,(void*)0x1234)==ESP_ERR_INVALID_SIZE);
 assert(ws_panel_stream_write(44,16,a,4479,done_cb,(void*)0x1234)==ESP_ERR_INVALID_SIZE);
 assert(ws_panel_stream_write(44,16,NULL,4480,done_cb,(void*)0x1234)==ESP_ERR_INVALID_ARG);
 assert(ws_panel_stream_write(44,16,a,4480,NULL,NULL)==ESP_ERR_INVALID_ARG);
 assert(s_stream.next_y==44&&cmds==before&&colors==cc);
 assert(ws_panel_stream_write(44,2,a,560,done_cb,(void*)0x1234)==ESP_OK);
 assert(ws_panel_stream_end()==ESP_ERR_INVALID_STATE&&!s_pending&&!s_stream.active);
 assert(ws_panel_stream_end()==ESP_ERR_INVALID_STATE);
 assert(ws_panel_stream_begin(4,100,15,103)==ESP_OK);
 assert(ws_panel_stream_write(100,2,a,24,done_cb,(void*)0x1234)==ESP_OK);
 assert(ws_panel_stream_abort()==ESP_OK&&!s_pending&&!s_stream.active);
 assert(ws_panel_flush_async(0,0,279,1,a,560,done_cb,(void*)0x1234)==ESP_OK);
 assert(ws_panel_wait_idle(500)==ESP_OK);
 /* Address failure independently at CASET and PASET; no open stream. */
 for(unsigned cmd=0x2A;cmd<=0x2B;cmd++){
  fail_cmd=cmd;assert(ws_panel_stream_begin(0,44,279,455)==ESP_ERR_TIMEOUT);
  assert(!s_usable&&!s_stream.active&&!s_pending);fail_cmd=0;s_usable=true;
 }
 /* Queue failure at every strip: no consumption, no bogus callback. */
 for(unsigned fail=0;fail<26;fail++){
  assert(ws_panel_stream_begin(0,44,279,455)==ESP_OK);
  for(unsigned i=0;i<fail;i++)assert(ws_panel_stream_write(44+i*16,16,source+(44+i*16)*280,4480,done_cb,(void*)0x1234)==ESP_OK);
  assert(ws_panel_wait_idle(500)==ESP_OK);bus_error=true;unsigned d=done_calls;
  unsigned y=44+fail*16,rows=456-y;if(rows>16)rows=16;
  assert(ws_panel_stream_write(y,rows,source+y*280,rows*280,done_cb,(void*)0x1234)==ESP_ERR_TIMEOUT);
  assert(s_stream.next_y==y&&!s_pending&&!s_flush_done&&!model_pending&&done_calls==d&&!s_usable);
  assert(ws_panel_stream_abort()==ESP_ERR_INVALID_STATE&&!s_stream.active);
  bus_error=false;s_usable=true;++cases;
 }
 /* Timeout at final wait: fail, latch, preserve SRAM until late real ISR. */
 assert(ws_panel_stream_begin(0,454,279,455)==ESP_OK);
 assert(ws_panel_stream_write(454,2,a,560,done_cb,(void*)0x1234)==ESP_OK);
 auto_complete=false;unsigned d=done_calls;
 assert(ws_panel_stream_end()==ESP_ERR_TIMEOUT&&!s_stream.active&&s_pending&&!s_usable);
 assert(done_calls==d&&ws_panel_brightness(99)==ESP_ERR_INVALID_STATE);
 assert(ws_panel_init()==ESP_ERR_INVALID_STATE);
 complete_color();assert(done_calls==d+1&&!s_pending);s_usable=true;
 assert(ws_panel_wait_idle(500)==ESP_OK);
 printf("PASS: independent controller RAM/QSPI2C/3C cursor, all RGB565, %u window/error cases;52 address commands become2;DMA immutable/error/final ACK ownership\n",cases);
}

int main(void){
 reset_error=true;
 assert(ws_panel_prepare_reset()==ESP_ERR_TIMEOUT&&!s_reset_ready&&!reset_levels&&!delayed);
 reset_error=false;
#if EVILKEY_BOARD_REVISION == 11
 /* V1.1 resets shared touch/LCD before I2C. Panel initialization must not
  * send a second pulse that discards the already configured touch state. */
 assert(ws_panel_prepare_reset()==ESP_OK&&reset_levels==2&&delayed==160);
 assert(ws_panel_prepare_reset()==ESP_OK&&reset_levels==2&&delayed==160);
#endif
 static uint16_t px[280*64];for(unsigned i=0;i<280U*64U;++i)px[i]=(uint16_t)(0x1234U+i);
 assert(ws_panel_set_enabled(false)==ESP_ERR_INVALID_STATE);
 assert(ws_panel_init()==ESP_OK);assert(s_usable&&!s_pending);assert(last_cmd==0x29);
 assert(reset_levels==2&&reset_configs==2&&delayed==260);
 assert(config.cs_gpio_num==(EVILKEY_BOARD_REVISION==11?46:9));
 assert(ws_panel_prepare_reset()==ESP_OK&&reset_levels==2&&delayed==260);
 assert(ws_panel_brightness(0)==ESP_OK);assert(last_cmd==0x51&&last_size==1&&last_byte==0);
 unsigned delay=delayed;assert(ws_panel_set_enabled(false)==ESP_OK);
 assert(last_cmd==0x28&&last_size==0&&delayed==delay+10);

 unsigned c=colors;
 assert(ws_panel_flush_async(0,0,279,63,px,280U*64U,done_cb,(void*)0x1234)==ESP_OK);
 assert(colors==c+1&&s_pending&&last_color_ptr==px&&done_calls==0);
 /* R22 zero-copy: the exact LVGL pointer is owned by DMA until completion. */
 assert(ws_panel_wait_idle(0)==ESP_ERR_TIMEOUT);assert(!s_usable);

 /* Re-arm for the completion-path and command regression tests. */
 s_usable=true;sem_token=false;s_pending=true;s_flush_done=done_cb;s_flush_ctx=(void*)0x1234;
 complete_color();assert(!s_pending&&done_calls==1&&sem_token);
 assert(ws_panel_wait_idle(0)==ESP_OK&&!sem_token);

 assert(ws_panel_flush_async(0,0,279,63,NULL,280U*64U,done_cb,(void*)0x1234)==ESP_ERR_INVALID_ARG);
 assert(ws_panel_flush_async(0,0,279,64,px,280U*65U,done_cb,(void*)0x1234)==ESP_ERR_INVALID_SIZE);
 assert(ws_panel_flush_async(1,1,0,1,px,1,done_cb,(void*)0x1234)==ESP_ERR_INVALID_ARG);
 assert(ws_panel_flush_async(0,0,279,63,px,280U*64U,NULL,(void*)0x1234)==ESP_ERR_INVALID_ARG);
 assert(ws_panel_set_enabled(true)==ESP_OK&&last_cmd==0x29);
 assert(ws_panel_brightness(200)==ESP_OK&&last_byte==200);
 stream_tests();
 bus_error=true;assert(ws_panel_set_enabled(false)==ESP_ERR_TIMEOUT);assert(!s_usable);
 unsigned calls=cmds;assert(ws_panel_set_enabled(true)==ESP_ERR_INVALID_STATE);assert(cmds==calls);
 puts("PASS: raw QSPI panel; 64-row zero-copy async DMA, callback ownership, on/off/brightness, error latching");
 return 0;
}
