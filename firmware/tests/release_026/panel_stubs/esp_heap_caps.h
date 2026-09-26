#pragma once
#include <stddef.h>
#define MALLOC_CAP_DMA 1
#define MALLOC_CAP_INTERNAL 2
void *heap_caps_malloc(size_t,unsigned);
