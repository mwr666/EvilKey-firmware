#pragma once
#include <stdint.h>
typedef int portMUX_TYPE;
#define portMUX_INITIALIZER_UNLOCKED 0
#define pdMS_TO_TICKS(x) (x)
#define pdTRUE 1
void test_enter(void);void test_exit(void);
#define portENTER_CRITICAL(x) ((void)(x),test_enter())
#define portEXIT_CRITICAL(x) ((void)(x),test_exit())
