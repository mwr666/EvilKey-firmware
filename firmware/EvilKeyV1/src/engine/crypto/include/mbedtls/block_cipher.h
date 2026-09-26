/**
 * \file block_cipher.h
 *
 * \brief Internal abstraction layer.
 */
/*
 *  Copyright The Mbed TLS Contributors
 *  SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
 */
#ifndef PF_MBEDTLS_BLOCK_CIPHER_H
#define PF_MBEDTLS_BLOCK_CIPHER_H

#include "private_access.h"

#include "build_info.h"

#if defined(PF_MBEDTLS_AES_C)
#include "aes.h"
#endif
#if defined(PF_MBEDTLS_ARIA_C)
#include "aria.h"
#endif
#if defined(PF_MBEDTLS_CAMELLIA_C)
#include "camellia.h"
#endif

#if defined(PF_MBEDTLS_BLOCK_CIPHER_SOME_PSA)
#include "../psa/crypto_types.h"
#endif

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
    PF_MBEDTLS_BLOCK_CIPHER_ID_NONE = 0,  /**< Unset. */
    PF_MBEDTLS_BLOCK_CIPHER_ID_AES,       /**< The AES cipher. */
    PF_MBEDTLS_BLOCK_CIPHER_ID_CAMELLIA,  /**< The Camellia cipher. */
    PF_MBEDTLS_BLOCK_CIPHER_ID_ARIA,      /**< The Aria cipher. */
} pf_mbedtls_block_cipher_id_t;

/**
 * Used internally to indicate whether a context uses legacy or PSA.
 *
 * Internal use only.
 */
typedef enum {
    PF_MBEDTLS_BLOCK_CIPHER_ENGINE_LEGACY = 0,
    PF_MBEDTLS_BLOCK_CIPHER_ENGINE_PSA,
} pf_mbedtls_block_cipher_engine_t;

typedef struct {
    pf_mbedtls_block_cipher_id_t PF_MBEDTLS_PRIVATE(id);
#if defined(PF_MBEDTLS_BLOCK_CIPHER_SOME_PSA)
    pf_mbedtls_block_cipher_engine_t PF_MBEDTLS_PRIVATE(engine);
    pf_mbedtls_svc_key_id_t PF_MBEDTLS_PRIVATE(pf_psa_key_id);
#endif
    union {
        unsigned dummy; /* Make the union non-empty even with no supported algorithms. */
#if defined(PF_MBEDTLS_AES_C)
        pf_mbedtls_aes_context PF_MBEDTLS_PRIVATE(aes);
#endif
#if defined(PF_MBEDTLS_ARIA_C)
        pf_mbedtls_aria_context PF_MBEDTLS_PRIVATE(aria);
#endif
#if defined(PF_MBEDTLS_CAMELLIA_C)
        pf_mbedtls_camellia_context PF_MBEDTLS_PRIVATE(camellia);
#endif
    } PF_MBEDTLS_PRIVATE(ctx);
} pf_mbedtls_block_cipher_context_t;

#ifdef __cplusplus
}
#endif

#endif /* MBEDTLS_BLOCK_CIPHER_H */
