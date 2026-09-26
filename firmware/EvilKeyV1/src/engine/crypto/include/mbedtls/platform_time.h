/**
 * \file platform_time.h
 *
 * \brief Mbed TLS Platform time abstraction
 */
/*
 *  Copyright The Mbed TLS Contributors
 *  SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
 */
#ifndef PF_MBEDTLS_PLATFORM_TIME_H
#define PF_MBEDTLS_PLATFORM_TIME_H

#include "build_info.h"

#ifdef __cplusplus
extern "C" {
#endif

/*
 * The time_t datatype
 */
#if defined(PF_MBEDTLS_PLATFORM_TIME_TYPE_MACRO)
typedef PF_MBEDTLS_PLATFORM_TIME_TYPE_MACRO pf_mbedtls_time_t;
#else
/* For time_t */
#include <time.h>
typedef time_t pf_mbedtls_time_t;
#endif /* MBEDTLS_PLATFORM_TIME_TYPE_MACRO */

#if defined(PF_MBEDTLS_PLATFORM_MS_TIME_TYPE_MACRO)
typedef PF_MBEDTLS_PLATFORM_MS_TIME_TYPE_MACRO pf_mbedtls_ms_time_t;
#else
#include <stdint.h>
#include <inttypes.h>
typedef int64_t pf_mbedtls_ms_time_t;
#endif /* MBEDTLS_PLATFORM_MS_TIME_TYPE_MACRO */

/**
 * \brief   Get time in milliseconds.
 *
 * \return Monotonically-increasing current time in milliseconds.
 *
 * \note Define MBEDTLS_PLATFORM_MS_TIME_ALT to be able to provide an
 *       alternative implementation
 *
 * \warning This function returns a monotonically-increasing time value from a
 *          start time that will differ from platform to platform, and possibly
 *          from run to run of the process.
 *
 */
pf_mbedtls_ms_time_t pf_mbedtls_ms_time(void);

/*
 * The function pointers for time
 */
#if defined(PF_MBEDTLS_PLATFORM_TIME_ALT)
extern pf_mbedtls_time_t (*pf_mbedtls_time)(pf_mbedtls_time_t *time);

/**
 * \brief   Set your own time function pointer
 *
 * \param   time_func   the time function implementation
 *
 * \return              0
 */
int pf_mbedtls_platform_set_time(pf_mbedtls_time_t (*time_func)(pf_mbedtls_time_t *time));
#else
#if defined(PF_MBEDTLS_PLATFORM_TIME_MACRO)
#define pf_mbedtls_time    PF_MBEDTLS_PLATFORM_TIME_MACRO
#else
#define pf_mbedtls_time   time
#endif /* MBEDTLS_PLATFORM_TIME_MACRO */
#endif /* MBEDTLS_PLATFORM_TIME_ALT */

#ifdef __cplusplus
}
#endif

#endif /* platform_time.h */
