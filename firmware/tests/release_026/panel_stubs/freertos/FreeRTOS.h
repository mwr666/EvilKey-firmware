#pragma once
typedef int BaseType_t;
#define pdFALSE 0
#define pdTRUE 1
#define pdMS_TO_TICKS(x) (x)
void test_port_yield_from_isr(void);
#define portYIELD_FROM_ISR() test_port_yield_from_isr()
