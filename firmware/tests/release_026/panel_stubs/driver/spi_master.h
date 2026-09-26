#pragma once
#include "esp_err.h"
#define SPI2_HOST 2
#define SPI_DMA_CH_AUTO 3
typedef struct {int sclk_io_num,data0_io_num,data1_io_num,data2_io_num,data3_io_num,max_transfer_sz;} spi_bus_config_t;
esp_err_t spi_bus_initialize(int,const spi_bus_config_t*,int);
