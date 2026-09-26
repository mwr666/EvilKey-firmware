/* Physical panel regression: LVGL owns composition, panel owns async QSPI DMA. */
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "../../templates/port/ws_panel.c"

static bool bus_error;
static bool sem_token;
static unsigned cmds,colors,delayed,last_cmd;
static size_t last_size;
static unsigned char last_byte;
static const void *last_color_ptr;
static esp_lcd_panel_io_spi_config_t config;
static unsigned done_calls;

SemaphoreHandle_t xSemaphoreCreateBinary(void){sem_token=false;return (void*)1;}
BaseType_t xSemaphoreGiveFromISR(SemaphoreHandle_t s,BaseType_t*a){(void)s;sem_token=true;*a=pdTRUE;return pdTRUE;}
BaseType_t xSemaphoreTake(SemaphoreHandle_t s,unsigned timeout){(void)s;(void)timeout;if(!sem_token)return pdFALSE;sem_token=false;return pdTRUE;}
void vTaskDelay(unsigned ms){delayed+=ms;}
esp_err_t gpio_config(const gpio_config_t*p){assert(p->pin_bit_mask==(1ULL<<WS_LCD_RESET));return ESP_OK;}
esp_err_t gpio_set_level(int p,int n){assert(p==WS_LCD_RESET);(void)n;return ESP_OK;}
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
 if(last_cmd==0x28||last_cmd==0x29)assert(data==NULL&&n==0);
 ++cmds;return bus_error?ESP_ERR_TIMEOUT:ESP_OK;
}
esp_err_t esp_lcd_panel_io_tx_color(esp_lcd_panel_io_handle_t io,int cmd,const void*data,size_t n){
 assert(io==(void*)2&&cmd==0x32002C00);assert(data!=NULL&&n>0&&n<=280U*64U*2U);
 last_color_ptr=data;++colors;return bus_error?ESP_ERR_TIMEOUT:ESP_OK;
}
static void complete_color(void){
 assert(s_pending);esp_lcd_panel_io_event_data_t event={0};
 assert(config.on_color_trans_done((void*)2,&event,config.user_ctx));
}
static void done_cb(void *ctx){assert(ctx==(void*)0x1234);++done_calls;}

int main(void){
 static uint16_t px[280*64];for(unsigned i=0;i<280U*64U;++i)px[i]=(uint16_t)(0x1234U+i);
 assert(ws_panel_set_enabled(false)==ESP_ERR_INVALID_STATE);
 assert(ws_panel_init()==ESP_OK);assert(s_usable&&!s_pending);assert(last_cmd==0x29);
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
 bus_error=true;assert(ws_panel_set_enabled(false)==ESP_ERR_TIMEOUT);assert(!s_usable);
 unsigned calls=cmds;assert(ws_panel_set_enabled(true)==ESP_ERR_INVALID_STATE);assert(cmds==calls);
 puts("PASS: raw QSPI panel; 64-row zero-copy async DMA, callback ownership, on/off/brightness, error latching");
 return 0;
}
