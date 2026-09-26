/**
 * \file ssl_cookie.h
 *
 * \brief DTLS cookie callbacks implementation
 */
/*
 *  Copyright The Mbed TLS Contributors
 *  SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
 */
#ifndef PF_MBEDTLS_SSL_COOKIE_H
#define PF_MBEDTLS_SSL_COOKIE_H
#include "private_access.h"

#include "build_info.h"

#include "ssl.h"

#if !defined(PF_MBEDTLS_USE_PSA_CRYPTO)
#if defined(PF_MBEDTLS_THREADING_C)
#include "threading.h"
#endif
#endif /* !MBEDTLS_USE_PSA_CRYPTO */

/**
 * \name SECTION: Module settings
 *
 * The configuration options you can set for this module are in this section.
 * Either change them in mbedtls_config.h or define them on the compiler command line.
 * \{
 */
#ifndef PF_MBEDTLS_SSL_COOKIE_TIMEOUT
#define PF_MBEDTLS_SSL_COOKIE_TIMEOUT     60 /**< Default expiration delay of DTLS cookies, in seconds if HAVE_TIME, or in number of cookies issued */
#endif

/** \} name SECTION: Module settings */

#ifdef __cplusplus
extern "C" {
#endif

/**
 * \brief          Context for the default cookie functions.
 */
typedef struct pf_mbedtls_ssl_cookie_ctx {
#if defined(PF_MBEDTLS_USE_PSA_CRYPTO)
    pf_mbedtls_svc_key_id_t    PF_MBEDTLS_PRIVATE(pf_psa_hmac_key);  /*!< key id for the HMAC portion   */
    pf_psa_algorithm_t         PF_MBEDTLS_PRIVATE(pf_psa_hmac_alg);  /*!< key algorithm for the HMAC portion   */
#else
    pf_mbedtls_md_context_t    PF_MBEDTLS_PRIVATE(hmac_ctx);   /*!< context for the HMAC portion   */
#endif /* MBEDTLS_USE_PSA_CRYPTO */
#if !defined(PF_MBEDTLS_HAVE_TIME)
    unsigned long   PF_MBEDTLS_PRIVATE(serial);     /*!< serial number for expiration   */
#endif
    unsigned long   PF_MBEDTLS_PRIVATE(timeout);    /*!< timeout delay, in seconds if HAVE_TIME,
                                                    or in number of tickets issued */

#if !defined(PF_MBEDTLS_USE_PSA_CRYPTO)
#if defined(PF_MBEDTLS_THREADING_C)
    pf_mbedtls_threading_mutex_t PF_MBEDTLS_PRIVATE(mutex);
#endif
#endif /* !MBEDTLS_USE_PSA_CRYPTO */
} pf_mbedtls_ssl_cookie_ctx;

/**
 * \brief          Initialize cookie context
 */
void pf_mbedtls_ssl_cookie_init(pf_mbedtls_ssl_cookie_ctx *ctx);

/**
 * \brief          Setup cookie context (generate keys)
 */
int pf_mbedtls_ssl_cookie_setup(pf_mbedtls_ssl_cookie_ctx *ctx,
                             pf_mbedtls_f_rng_t *f_rng,
                             void *p_rng);

/**
 * \brief          Set expiration delay for cookies
 *                 (Default MBEDTLS_SSL_COOKIE_TIMEOUT)
 *
 * \param ctx      Cookie context
 * \param delay    Delay, in seconds if HAVE_TIME, or in number of cookies
 *                 issued in the meantime.
 *                 0 to disable expiration (NOT recommended)
 */
void pf_mbedtls_ssl_cookie_set_timeout(pf_mbedtls_ssl_cookie_ctx *ctx, unsigned long delay);

/**
 * \brief          Free cookie context
 */
void pf_mbedtls_ssl_cookie_free(pf_mbedtls_ssl_cookie_ctx *ctx);

/**
 * \brief          Generate cookie, see \c mbedtls_ssl_cookie_write_t
 */
pf_mbedtls_ssl_cookie_write_t pf_mbedtls_ssl_cookie_write;

/**
 * \brief          Verify cookie, see \c mbedtls_ssl_cookie_write_t
 */
pf_mbedtls_ssl_cookie_check_t pf_mbedtls_ssl_cookie_check;

#ifdef __cplusplus
}
#endif

#endif /* ssl_cookie.h */
