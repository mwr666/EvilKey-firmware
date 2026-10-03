#pragma once
#include <stdlib.h>
#define MALLOC_CAP_SPIRAM 1
#define MALLOC_CAP_8BIT 2
#define MALLOC_CAP_INTERNAL 4
static inline void *heap_caps_malloc(size_t size, int) { return malloc(size); }
static inline void *heap_caps_calloc(size_t n,size_t size,int){return calloc(n,size);}
static inline size_t heap_caps_get_free_size(int){return 65536;}
static inline size_t heap_caps_get_largest_free_block(int){return 65536;}
