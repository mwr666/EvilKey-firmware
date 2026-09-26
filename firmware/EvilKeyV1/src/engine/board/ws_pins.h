/* SPDX-License-Identifier: AGPL-3.0-or-later */
#pragma once
/* Waveshare ESP32-S3-Touch-AMOLED-1.64, PCB V1 ONLY. */
#define WS_USB_DM        19
#define WS_USB_DP        20
#define WS_BOOT           0
/* PCB V1 TF slot: SPI wiring from the Waveshare V1 schematic. */
#define WS_SD_CS          38
#define WS_SD_MOSI        39
#define WS_SD_MISO        40
#define WS_SD_SCLK        41
#define WS_LCD_CS         9
#define WS_LCD_CLK       10
#define WS_LCD_D0        11
#define WS_LCD_D1        12
#define WS_LCD_D2        13
#define WS_LCD_D3        14
#define WS_LCD_RESET     21
#define WS_I2C_SDA       47
#define WS_I2C_SCL       48
#define WS_TOUCH_ADDR  0x38
#define WS_LCD_WIDTH    280
#define WS_LCD_HEIGHT   456
#define WS_LCD_X_OFFSET  20
#define WS_LCD_Y_OFFSET   0
#define WS_LCD_STRIP_ROWS 64
/* V1 has no MCU-connected touch IRQ/reset. Poll the FT3168 over I2C.
 * Do not configure GPIO48 as NeoPixel, or GPIO19/20 as ordinary GPIO. */
