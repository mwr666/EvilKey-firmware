/* Host-only memory readings for the board diagnostic snapshot. */
#pragma once
#include <stddef.h>
#define MALLOC_CAP_INTERNAL 1U
#define MALLOC_CAP_8BIT 2U
static inline size_t heap_caps_get_free_size(unsigned caps) { (void)caps; return 32768U; }
static inline size_t heap_caps_get_largest_free_block(unsigned caps) { (void)caps; return 24576U; }
