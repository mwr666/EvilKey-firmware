#pragma once
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include "esp_err.h"
typedef void *esp_lcd_panel_io_handle_t;
typedef intptr_t esp_lcd_spi_bus_handle_t;
typedef struct {int unused;} esp_lcd_panel_io_event_data_t;
typedef struct {int cs_gpio_num,dc_gpio_num,spi_mode,pclk_hz,trans_queue_depth;
 bool (*on_color_trans_done)(esp_lcd_panel_io_handle_t,esp_lcd_panel_io_event_data_t*,void*);
 void *user_ctx; int lcd_cmd_bits,lcd_param_bits;struct {bool quad_mode;}flags;} esp_lcd_panel_io_spi_config_t;
esp_err_t esp_lcd_new_panel_io_spi(esp_lcd_spi_bus_handle_t,const esp_lcd_panel_io_spi_config_t*,esp_lcd_panel_io_handle_t*);
esp_err_t esp_lcd_panel_io_tx_param(esp_lcd_panel_io_handle_t,int,const void*,size_t);
esp_err_t esp_lcd_panel_io_tx_color(esp_lcd_panel_io_handle_t,int,const void*,size_t);
