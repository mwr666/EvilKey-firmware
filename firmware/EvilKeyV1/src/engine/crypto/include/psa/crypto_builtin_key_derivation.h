/*
 *  Context structure declaration of the Mbed TLS software-based PSA drivers
 *  called through the PSA Crypto driver dispatch layer.
 *  This file contains the context structures of key derivation algorithms
 *  which need to rely on other algorithms.
 *
 * \note This file may not be included directly. Applications must
 * include psa/crypto.h.
 *
 * \note This header and its content are not part of the Mbed TLS API and
 * applications must not depend on it. Its main purpose is to define the
 * multi-part state objects of the Mbed TLS software-based PSA drivers. The
 * definitions of these objects are then used by crypto_struct.h to define the
 * implementation-defined types of PSA multi-part state objects.
 */
/*
 *  Copyright The Mbed TLS Contributors
 *  SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
 */

#ifndef PF_PSA_CRYPTO_BUILTIN_KEY_DERIVATION_H
#define PF_PSA_CRYPTO_BUILTIN_KEY_DERIVATION_H
#include "../mbedtls/private_access.h"

#include "crypto_driver_common.h"

#if defined(PF_MBEDTLS_PSA_BUILTIN_ALG_HKDF) || \
    defined(PF_MBEDTLS_PSA_BUILTIN_ALG_HKDF_EXTRACT) || \
    defined(PF_MBEDTLS_PSA_BUILTIN_ALG_HKDF_EXPAND)
typedef struct {
    uint8_t *PF_MBEDTLS_PRIVATE(info);
    size_t PF_MBEDTLS_PRIVATE(info_length);
#if PF_PSA_HASH_MAX_SIZE > 0xff
#error "PSA_HASH_MAX_SIZE does not fit in uint8_t"
#endif
    uint8_t PF_MBEDTLS_PRIVATE(offset_in_block);
    uint8_t PF_MBEDTLS_PRIVATE(block_number);
    unsigned int PF_MBEDTLS_PRIVATE(state) : 2;
    unsigned int PF_MBEDTLS_PRIVATE(info_set) : 1;
    uint8_t PF_MBEDTLS_PRIVATE(output_block)[PF_PSA_HASH_MAX_SIZE];
    uint8_t PF_MBEDTLS_PRIVATE(prk)[PF_PSA_HASH_MAX_SIZE];
    struct pf_psa_mac_operation_s PF_MBEDTLS_PRIVATE(hmac);
} pf_psa_hkdf_key_derivation_t;
#endif /* MBEDTLS_PSA_BUILTIN_ALG_HKDF ||
          MBEDTLS_PSA_BUILTIN_ALG_HKDF_EXTRACT ||
          MBEDTLS_PSA_BUILTIN_ALG_HKDF_EXPAND */
#if defined(PF_MBEDTLS_PSA_BUILTIN_ALG_TLS12_ECJPAKE_TO_PMS)
typedef struct {
    uint8_t PF_MBEDTLS_PRIVATE(data)[PF_PSA_TLS12_ECJPAKE_TO_PMS_DATA_SIZE];
} pf_psa_tls12_ecjpake_to_pms_t;
#endif /* MBEDTLS_PSA_BUILTIN_ALG_TLS12_ECJPAKE_TO_PMS */

#if defined(PF_MBEDTLS_PSA_BUILTIN_ALG_TLS12_PRF) || \
    defined(PF_MBEDTLS_PSA_BUILTIN_ALG_TLS12_PSK_TO_MS)
typedef enum {
    PF_PSA_TLS12_PRF_STATE_INIT,             /* no input provided */
    PF_PSA_TLS12_PRF_STATE_SEED_SET,         /* seed has been set */
    PF_PSA_TLS12_PRF_STATE_OTHER_KEY_SET,    /* other key has been set - optional */
    PF_PSA_TLS12_PRF_STATE_KEY_SET,          /* key has been set */
    PF_PSA_TLS12_PRF_STATE_LABEL_SET,        /* label has been set */
    PF_PSA_TLS12_PRF_STATE_OUTPUT            /* output has been started */
} pf_psa_tls12_prf_key_derivation_state_t;

typedef struct pf_psa_tls12_prf_key_derivation_s {
#if PF_PSA_HASH_MAX_SIZE > 0xff
#error "PSA_HASH_MAX_SIZE does not fit in uint8_t"
#endif

    /* Indicates how many bytes in the current HMAC block have
     * not yet been read by the user. */
    uint8_t PF_MBEDTLS_PRIVATE(left_in_block);

    /* The 1-based number of the block. */
    uint8_t PF_MBEDTLS_PRIVATE(block_number);

    pf_psa_tls12_prf_key_derivation_state_t PF_MBEDTLS_PRIVATE(state);

    uint8_t *PF_MBEDTLS_PRIVATE(secret);
    size_t PF_MBEDTLS_PRIVATE(secret_length);
    uint8_t *PF_MBEDTLS_PRIVATE(seed);
    size_t PF_MBEDTLS_PRIVATE(seed_length);
    uint8_t *PF_MBEDTLS_PRIVATE(label);
    size_t PF_MBEDTLS_PRIVATE(label_length);
#if defined(PF_MBEDTLS_PSA_BUILTIN_ALG_TLS12_PSK_TO_MS)
    uint8_t *PF_MBEDTLS_PRIVATE(other_secret);
    size_t PF_MBEDTLS_PRIVATE(other_secret_length);
#endif /* MBEDTLS_PSA_BUILTIN_ALG_TLS12_PSK_TO_MS */

    uint8_t PF_MBEDTLS_PRIVATE(Ai)[PF_PSA_HASH_MAX_SIZE];

    /* `HMAC_hash( prk, A( i ) + seed )` in the notation of RFC 5246, Sect. 5. */
    uint8_t PF_MBEDTLS_PRIVATE(output_block)[PF_PSA_HASH_MAX_SIZE];
} pf_psa_tls12_prf_key_derivation_t;
#endif /* MBEDTLS_PSA_BUILTIN_ALG_TLS12_PRF) ||
        * MBEDTLS_PSA_BUILTIN_ALG_TLS12_PSK_TO_MS */
#if defined(PF_PSA_HAVE_SOFT_PBKDF2)
typedef enum {
    PF_PSA_PBKDF2_STATE_INIT,             /* no input provided */
    PF_PSA_PBKDF2_STATE_INPUT_COST_SET,   /* input cost has been set */
    PF_PSA_PBKDF2_STATE_SALT_SET,         /* salt has been set */
    PF_PSA_PBKDF2_STATE_PASSWORD_SET,     /* password has been set */
    PF_PSA_PBKDF2_STATE_OUTPUT            /* output has been started */
} pf_psa_pbkdf2_key_derivation_state_t;

typedef struct {
    pf_psa_pbkdf2_key_derivation_state_t PF_MBEDTLS_PRIVATE(state);
    uint64_t PF_MBEDTLS_PRIVATE(input_cost);
    uint8_t *PF_MBEDTLS_PRIVATE(salt);
    size_t PF_MBEDTLS_PRIVATE(salt_length);
    uint8_t PF_MBEDTLS_PRIVATE(password)[PF_PSA_HMAC_MAX_HASH_BLOCK_SIZE];
    size_t PF_MBEDTLS_PRIVATE(password_length);
    uint8_t PF_MBEDTLS_PRIVATE(output_block)[PF_PSA_HASH_MAX_SIZE];
    uint8_t PF_MBEDTLS_PRIVATE(bytes_used);
    uint32_t PF_MBEDTLS_PRIVATE(block_number);
} pf_psa_pbkdf2_key_derivation_t;
#endif /* PSA_HAVE_SOFT_PBKDF2 */

#endif /* PSA_CRYPTO_BUILTIN_KEY_DERIVATION_H */
