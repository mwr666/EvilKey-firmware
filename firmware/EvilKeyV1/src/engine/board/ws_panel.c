#include "../../pf_build_config.h"
/* SPDX-License-Identifier: AGPL-3.0-or-later
 * QSPI framing and display initialization follow Waveshare's supplied
 * CO5300-compatible SH8601 example. LVGL owns composition; this module owns
 * only the physical panel and the asynchronous RGB565 DMA flush path.
 *
 * R22 performance contract:
 * - LVGL buffers are already byte-swapped (LV_COLOR_16_SWAP=1),
 * - DMA reads directly from LVGL's internal-SRAM draw buffer,
 * - no per-pixel staging/copy loop exists here,
 * - completion releases the LVGL buffer from the LCD ISR callback.
 */
#include "ws_panel.h"
#include "ws_pins.h"
#include "ws_gui_3d.h"
#include "esp_timer.h"
#include <stdint.h>
#include "driver/gpio.h"
#include "driver/spi_master.h"
#include "esp_lcd_panel_io.h"
#include "freertos/FreeRTOS.h"
#include "freertos/semphr.h"
#include "freertos/task.h"

static esp_lcd_panel_io_handle_t s_io;
static SemaphoreHandle_t s_done;
static volatile bool s_pending;
static ws_panel_flush_done_cb_t s_flush_done;
static void *s_flush_ctx;
static bool s_usable;

#define WS_PANEL_MAX_PIXELS ((size_t)WS_LCD_WIDTH*(size_t)WS_LCD_STRIP_ROWS)
#define TRY(expr) do { esp_err_t e_=(expr); if(e_!=ESP_OK) return e_; } while(0)

static bool color_done(esp_lcd_panel_io_handle_t io,
                       esp_lcd_panel_io_event_data_t *event, void *ctx)
{
    (void)io; (void)event; (void)ctx;
    ws_panel_flush_done_cb_t done=s_flush_done;
    void *done_ctx=s_flush_ctx;
    s_flush_done=NULL;
    s_flush_ctx=NULL;
    BaseType_t awakened=pdFALSE;
    /* Waveshare's LVGL reference also releases lv_disp_flush_ready() from this
     * color-transfer callback. Keep the callback tiny and ISR-safe. */
    if(done) done(done_ctx);
    /* Publish idle only after the callback consumed its frame context. The
     * display owner can otherwise recycle that context while ISR still reads it. */
    s_pending=false;
    xSemaphoreGiveFromISR(s_done,&awakened);
    return awakened==pdTRUE;
}

esp_err_t ws_panel_wait_idle(uint32_t timeout_ms)
{
    if(!s_usable) return ESP_ERR_INVALID_STATE;
    if(!s_pending) {
        /* Drain a completion token left by a transfer that finished before the
         * display task reached this point. */
        (void)xSemaphoreTake(s_done,0);
        return ESP_OK;
    }
    const uint64_t start=esp_timer_get_time();
    const BaseType_t completed=xSemaphoreTake(s_done,pdMS_TO_TICKS(timeout_ms));
    ws_gui_3d_record_panel_wait((uint32_t)(esp_timer_get_time()-start));
    if(completed!=pdTRUE) {
        s_usable=false;
        return ESP_ERR_TIMEOUT;
    }
    return ESP_OK;
}

static esp_err_t command(uint8_t cmd, const void *data, size_t bytes)
{
    return esp_lcd_panel_io_tx_param(s_io,(int)(0x02000000U|((uint32_t)cmd<<8)),data,bytes);
}
static esp_err_t one(uint8_t cmd,uint8_t data)
{
    return command(cmd,&data,1);
}

esp_err_t ws_panel_init(void)
{
    s_usable=false;
    s_pending=false;
    s_flush_done=NULL;
    s_flush_ctx=NULL;
    s_done=xSemaphoreCreateBinary();
    if(!s_done) return ESP_ERR_NO_MEM;
    const spi_bus_config_t bus={
        .sclk_io_num=WS_LCD_CLK, .data0_io_num=WS_LCD_D0,
        .data1_io_num=WS_LCD_D1, .data2_io_num=WS_LCD_D2,
        .data3_io_num=WS_LCD_D3,
        .max_transfer_sz=WS_LCD_WIDTH*WS_LCD_STRIP_ROWS*2,
    };
    TRY(spi_bus_initialize(SPI2_HOST,&bus,SPI_DMA_CH_AUTO));
    const esp_lcd_panel_io_spi_config_t io={
        .cs_gpio_num=WS_LCD_CS, .dc_gpio_num=-1,
        .spi_mode=0, .pclk_hz=40*1000*1000,
        /* Keep one color transfer in flight; LVGL may render into its second
         * draw buffer while DMA owns the first. The queue also carries panel
         * commands, which must not overtake an unfinished color transfer. */
        .trans_queue_depth=2, .on_color_trans_done=color_done,
        .user_ctx=NULL, .lcd_cmd_bits=32, .lcd_param_bits=8,
        .flags={.quad_mode=true},
    };
    TRY(esp_lcd_new_panel_io_spi((esp_lcd_spi_bus_handle_t)SPI2_HOST,&io,&s_io));
    const gpio_config_t reset={
        .pin_bit_mask=1ULL<<WS_LCD_RESET, .mode=GPIO_MODE_OUTPUT,
        .pull_up_en=GPIO_PULLUP_DISABLE, .pull_down_en=GPIO_PULLDOWN_DISABLE,
        .intr_type=GPIO_INTR_DISABLE,
    };
    TRY(gpio_config(&reset));
    TRY(gpio_set_level(WS_LCD_RESET,0));
    vTaskDelay(pdMS_TO_TICKS(10));
    TRY(gpio_set_level(WS_LCD_RESET,1));
    vTaskDelay(pdMS_TO_TICKS(150));
    TRY(one(0x36,0x00)); /* RGB, native portrait orientation */
    TRY(one(0x3A,0x55)); /* RGB565 */
    TRY(command(0x11,NULL,0));
    vTaskDelay(pdMS_TO_TICKS(80));
    TRY(one(0xC4,0x80));
    TRY(one(0x35,0x00));
    TRY(one(0x53,0x20));
    vTaskDelay(pdMS_TO_TICKS(10));
    TRY(one(0x63,0xFF));
    TRY(one(0x51,0x00)); /* Keep dark until the first complete LVGL frame. */
    TRY(command(0x29,NULL,0));
    vTaskDelay(pdMS_TO_TICKS(10));
    s_usable=true;
    return ESP_OK;
}

esp_err_t ws_panel_brightness(uint8_t brightness)
{
    if(!s_usable) return ESP_ERR_INVALID_STATE;
    esp_err_t err=ws_panel_wait_idle(500U);
    if(err==ESP_OK) err=one(0x51,brightness);
    if(err!=ESP_OK) s_usable=false;
    return err;
}

/* Display-off only (DCS 0x28/0x29), NOT sleep-in, power-rail removal or MCU
 * sleep. I2C touch stays active. Call only from the display task after DMA. */
esp_err_t ws_panel_set_enabled(bool enabled)
{
    if(!s_usable) return ESP_ERR_INVALID_STATE;
    esp_err_t err=ws_panel_wait_idle(500U);
    if(err==ESP_OK) err=command(enabled?0x29:0x28,NULL,0);
    if(err!=ESP_OK) s_usable=false;
    else vTaskDelay(pdMS_TO_TICKS(10));
    return err;
}

esp_err_t ws_panel_flush_async(uint16_t x1,uint16_t y1,uint16_t x2,uint16_t y2,
                               const uint16_t *pixels,size_t pixel_count,
                               ws_panel_flush_done_cb_t done,void *done_ctx)
{
    if(!s_usable) return ESP_ERR_INVALID_STATE;
    if(!pixels || !done || x2<x1 || y2<y1 || x2>=WS_LCD_WIDTH || y2>=WS_LCD_HEIGHT)
        return ESP_ERR_INVALID_ARG;
    const size_t width=(size_t)x2-(size_t)x1+1U;
    const size_t height=(size_t)y2-(size_t)y1+1U;
    const size_t needed=width*height;
    if(needed==0U || pixel_count!=needed || needed>WS_PANEL_MAX_PIXELS)
        return ESP_ERR_INVALID_SIZE;

    /* A second LVGL buffer can be rendered while the previous transfer is in
     * flight. Only when LVGL is ready to submit the next strip do we wait for
     * the previous strip, because the window-address commands are polling
     * transactions and must not overtake queued color data. */
    esp_err_t err=ws_panel_wait_idle(500U);
    if(err!=ESP_OK) return err;

    unsigned px0=(unsigned)x1+WS_LCD_X_OFFSET;
    unsigned px1=(unsigned)x2+WS_LCD_X_OFFSET;
    unsigned py0=(unsigned)y1+WS_LCD_Y_OFFSET;
    unsigned py1=(unsigned)y2+WS_LCD_Y_OFFSET;
    uint8_t xs[]={px0>>8,px0&255,px1>>8,px1&255};
    uint8_t ys[]={py0>>8,py0&255,py1>>8,py1&255};
    err=command(0x2A,xs,sizeof(xs));
    if(err==ESP_OK) err=command(0x2B,ys,sizeof(ys));
    if(err==ESP_OK) {
        (void)xSemaphoreTake(s_done,0);
        s_flush_done=done;
        s_flush_ctx=done_ctx;
        s_pending=true;
        /* pixels already have panel byte order because LV_COLOR_16_SWAP=1. */
        err=esp_lcd_panel_io_tx_color(s_io,0x32002C00,pixels,needed*2U);
        if(err!=ESP_OK) {
            s_pending=false;
            s_flush_done=NULL;
            s_flush_ctx=NULL;
        }
    }
    if(err!=ESP_OK) s_usable=false;
    return err;
}
