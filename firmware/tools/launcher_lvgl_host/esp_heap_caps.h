/* SPDX-License-Identifier: AGPL-3.0-or-later */
#pragma once
#include <stdlib.h>
#define MALLOC_CAP_SPIRAM 1
#define MALLOC_CAP_8BIT 2
#define MALLOC_CAP_INTERNAL 4
#define MALLOC_CAP_DMA 8
static inline void *heap_caps_malloc(size_t n,int c){
    if(getenv("EVILKEY_TEST_3D_ALLOC_FAIL") && (c&MALLOC_CAP_INTERNAL) && !(c&MALLOC_CAP_SPIRAM))return NULL;
    if(getenv("EVILKEY_TEST_STAGING") && (c&MALLOC_CAP_DMA) && n>280*16*2)return NULL;
    return malloc(n);
}
static inline void *heap_caps_calloc(size_t n,size_t s,int c){(void)c;return calloc(n,s);}
static inline void heap_caps_free(void *p){free(p);}
static inline void *heap_caps_realloc(void *p,size_t n,int c){(void)c;return realloc(p,n);}
static inline size_t heap_caps_get_free_size(int c){return getenv("EVILKEY_TEST_3D_LOW_INTERNAL") && (c&MALLOC_CAP_INTERNAL)?25000:8000000;}
static inline size_t heap_caps_get_largest_free_block(int c){return getenv("EVILKEY_TEST_3D_LOW_INTERNAL") && (c&MALLOC_CAP_INTERNAL)?21000:8000000;}
