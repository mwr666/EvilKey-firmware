/* SPDX-License-Identifier: AGPL-3.0-or-later */
#pragma once
#include <stdint.h>
extern uint64_t host_time_us;
#ifdef EK_LVGL_TEST_CLOCK
uint64_t host_test_time(void);
static inline uint64_t esp_timer_get_time(void){return host_test_time();}
#else
static inline uint64_t esp_timer_get_time(void){return host_time_us;}
#endif
