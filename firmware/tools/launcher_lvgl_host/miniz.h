/* SPDX-License-Identifier: AGPL-3.0-or-later */
#pragma once
#include <stddef.h>
typedef struct { char state[11000]; } tinfl_decompressor;
typedef int tinfl_status;
#define TINFL_STATUS_DONE 0
#define TINFL_FLAG_PARSE_ZLIB_HEADER 1
#define TINFL_FLAG_USING_NON_WRAPPING_OUTPUT_BUF 2
static inline void tinfl_init(tinfl_decompressor *d){(void)d;}
static inline int tinfl_decompress(tinfl_decompressor *d,const void *i,size_t *n,void *s,void *o,size_t *m,int f){(void)d;(void)i;(void)n;(void)s;(void)o;(void)m;(void)f;return -1;}
