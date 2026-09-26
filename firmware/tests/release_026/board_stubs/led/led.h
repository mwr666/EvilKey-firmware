#pragma once
#include <stdint.h>
#define MODE_MOUNTED 1
#define MODE_NOT_MOUNTED 2
#define MODE_PROCESSING 3
#define MODE_SUSPENDED 4
uint32_t led_get_mode(void);
