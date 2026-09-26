#pragma once
#include <stddef.h>
#include <stdint.h>
#include "esp_err.h"
#define I2C_MODE_MASTER 1
#define I2C_NUM_0 0
typedef struct {int mode,sda_io_num,scl_io_num,sda_pullup_en,scl_pullup_en;struct{int clk_speed;}master;int clk_flags;} i2c_config_t;
esp_err_t i2c_param_config(int,const i2c_config_t*);
esp_err_t i2c_driver_install(int,int,int,int,int);
esp_err_t i2c_master_write_to_device(int,uint8_t,const uint8_t*,size_t,unsigned);
esp_err_t i2c_master_write_read_device(int,uint8_t,const uint8_t*,size_t,uint8_t*,size_t,unsigned);
