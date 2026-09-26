/*
 *  Copyright The Mbed TLS Contributors
 *  SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
 */

/**
 * \file mps_trace.h
 *
 * \brief Tracing module for MPS
 */

#ifndef PF_MBEDTLS_MPS_MBEDTLS_MPS_TRACE_H
#define PF_MBEDTLS_MPS_MBEDTLS_MPS_TRACE_H

#include "common.h"
#include "mps_common.h"
#include "mps_trace.h"

#include "../include/mbedtls/platform.h"

#if defined(PF_MBEDTLS_MPS_ENABLE_TRACE)

/*
 * Adapt this to enable/disable tracing output
 * from the various layers of the MPS.
 */

#define PF_MBEDTLS_MPS_TRACE_ENABLE_LAYER_1
#define PF_MBEDTLS_MPS_TRACE_ENABLE_LAYER_2
#define PF_MBEDTLS_MPS_TRACE_ENABLE_LAYER_3
#define PF_MBEDTLS_MPS_TRACE_ENABLE_LAYER_4
#define PF_MBEDTLS_MPS_TRACE_ENABLE_READER
#define PF_MBEDTLS_MPS_TRACE_ENABLE_WRITER

/*
 * To use the existing trace module, only change
 * MBEDTLS_MPS_TRACE_ENABLE_XXX above, but don't modify the
 * rest of this file.
 */

typedef enum {
    PF_MBEDTLS_MPS_TRACE_TYPE_COMMENT,
    PF_MBEDTLS_MPS_TRACE_TYPE_CALL,
    PF_MBEDTLS_MPS_TRACE_TYPE_ERROR,
    PF_MBEDTLS_MPS_TRACE_TYPE_RETURN
} pf_mbedtls_mps_trace_type;

#define PF_MBEDTLS_MPS_TRACE_BIT_LAYER_1 1
#define PF_MBEDTLS_MPS_TRACE_BIT_LAYER_2 2
#define PF_MBEDTLS_MPS_TRACE_BIT_LAYER_3 3
#define PF_MBEDTLS_MPS_TRACE_BIT_LAYER_4 4
#define PF_MBEDTLS_MPS_TRACE_BIT_WRITER  5
#define PF_MBEDTLS_MPS_TRACE_BIT_READER  6

#if defined(PF_MBEDTLS_MPS_TRACE_ENABLE_LAYER_1)
#define PF_MBEDTLS_MPS_TRACE_MASK_LAYER_1 (1u << PF_MBEDTLS_MPS_TRACE_BIT_LAYER_1)
#else
#define PF_MBEDTLS_MPS_TRACE_MASK_LAYER_1 0
#endif

#if defined(PF_MBEDTLS_MPS_TRACE_ENABLE_LAYER_2)
#define PF_MBEDTLS_MPS_TRACE_MASK_LAYER_2 (1u << PF_MBEDTLS_MPS_TRACE_BIT_LAYER_2)
#else
#define PF_MBEDTLS_MPS_TRACE_MASK_LAYER_2 0
#endif

#if defined(PF_MBEDTLS_MPS_TRACE_ENABLE_LAYER_3)
#define PF_MBEDTLS_MPS_TRACE_MASK_LAYER_3 (1u << PF_MBEDTLS_MPS_TRACE_BIT_LAYER_3)
#else
#define PF_MBEDTLS_MPS_TRACE_MASK_LAYER_3 0
#endif

#if defined(PF_MBEDTLS_MPS_TRACE_ENABLE_LAYER_4)
#define PF_MBEDTLS_MPS_TRACE_MASK_LAYER_4 (1u << PF_MBEDTLS_MPS_TRACE_BIT_LAYER_4)
#else
#define PF_MBEDTLS_MPS_TRACE_MASK_LAYER_4 0
#endif

#if defined(PF_MBEDTLS_MPS_TRACE_ENABLE_READER)
#define PF_MBEDTLS_MPS_TRACE_MASK_READER (1u << PF_MBEDTLS_MPS_TRACE_BIT_READER)
#else
#define PF_MBEDTLS_MPS_TRACE_MASK_READER 0
#endif

#if defined(PF_MBEDTLS_MPS_TRACE_ENABLE_WRITER)
#define PF_MBEDTLS_MPS_TRACE_MASK_WRITER (1u << PF_MBEDTLS_MPS_TRACE_BIT_WRITER)
#else
#define PF_MBEDTLS_MPS_TRACE_MASK_WRITER 0
#endif

#define PF_MBEDTLS_MPS_TRACE_MASK (PF_MBEDTLS_MPS_TRACE_MASK_LAYER_1 |       \
                                PF_MBEDTLS_MPS_TRACE_MASK_LAYER_2 |       \
                                PF_MBEDTLS_MPS_TRACE_MASK_LAYER_3 |       \
                                PF_MBEDTLS_MPS_TRACE_MASK_LAYER_4 |       \
                                PF_MBEDTLS_MPS_TRACE_MASK_READER  |       \
                                PF_MBEDTLS_MPS_TRACE_MASK_WRITER)

/* We have to avoid globals because E-ACSL chokes on them...
 * Wrap everything in stub functions. */
int  pf_mbedtls_mps_trace_get_depth(void);
void pf_mbedtls_mps_trace_inc_depth(void);
void pf_mbedtls_mps_trace_dec_depth(void);

void pf_mbedtls_mps_trace_color(int id);
void pf_mbedtls_mps_trace_indent(int level, pf_mbedtls_mps_trace_type ty);

void pf_mbedtls_mps_trace_print_msg(int id, int line, const char *format, ...);

#define PF_MBEDTLS_MPS_TRACE(type, ...)                                              \
    do {                                                                            \
        if (!(PF_MBEDTLS_MPS_TRACE_MASK & (1u << pf_mbedtls_mps_trace_id)))         \
        break;                                                                  \
        pf_mbedtls_mps_trace_indent(pf_mbedtls_mps_trace_get_depth(), type);            \
        pf_mbedtls_mps_trace_color(pf_mbedtls_mps_trace_id);                            \
        pf_mbedtls_mps_trace_print_msg(pf_mbedtls_mps_trace_id, __LINE__, __VA_ARGS__); \
        pf_mbedtls_mps_trace_color(0);                                               \
    } while (0)

#define PF_MBEDTLS_MPS_TRACE_INIT(...)                                         \
    do {                                                                      \
        if (!(PF_MBEDTLS_MPS_TRACE_MASK & (1u << pf_mbedtls_mps_trace_id)))   \
        break;                                                            \
        PF_MBEDTLS_MPS_TRACE(PF_MBEDTLS_MPS_TRACE_TYPE_CALL, __VA_ARGS__);        \
        pf_mbedtls_mps_trace_inc_depth();                                        \
    } while (0)

#define PF_MBEDTLS_MPS_TRACE_END(val)                                        \
    do {                                                                    \
        if (!(PF_MBEDTLS_MPS_TRACE_MASK & (1u << pf_mbedtls_mps_trace_id))) \
        break;                                                          \
        PF_MBEDTLS_MPS_TRACE(PF_MBEDTLS_MPS_TRACE_TYPE_RETURN, "%d (-%#04x)",    \
                          (int) (val), -((unsigned) (val)));                           \
        pf_mbedtls_mps_trace_dec_depth();                                      \
    } while (0)

#define PF_MBEDTLS_MPS_TRACE_RETURN(val)         \
    do {                                        \
        /* Breaks tail recursion. */            \
        int ret__ = val;                        \
        PF_MBEDTLS_MPS_TRACE_END(ret__);         \
        return ret__;                        \
    } while (0)

#else /* MBEDTLS_MPS_TRACE */

#define PF_MBEDTLS_MPS_TRACE(type, ...) do { } while (0)
#define PF_MBEDTLS_MPS_TRACE_INIT(...)  do { } while (0)
#define PF_MBEDTLS_MPS_TRACE_END          do { } while (0)

#define PF_MBEDTLS_MPS_TRACE_RETURN(val) return val;

#endif /* MBEDTLS_MPS_TRACE */

#endif /* MBEDTLS_MPS_MBEDTLS_MPS_TRACE_H */
