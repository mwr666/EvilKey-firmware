/*
 *  Context structure declaration of the Mbed TLS software-based PSA drivers
 *  called through the PSA Crypto driver dispatch layer.
 *  This file contains the context structures of those algorithms which need to
 *  rely on other algorithms, i.e. are 'composite' algorithms.
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

#ifndef PF_PSA_CRYPTO_BUILTIN_COMPOSITES_H
#define PF_PSA_CRYPTO_BUILTIN_COMPOSITES_H
#include "../mbedtls/private_access.h"

#include "crypto_driver_common.h"

#include "../mbedtls/cmac.h"
#if defined(PF_MBEDTLS_PSA_BUILTIN_ALG_GCM)
#include "../mbedtls/gcm.h"
#endif
#if defined(PF_MBEDTLS_PSA_BUILTIN_ALG_CCM)
#include "../mbedtls/ccm.h"
#endif
#include "../mbedtls/chachapoly.h"

/*
 * MAC multi-part operation definitions.
 */
#if defined(PF_MBEDTLS_PSA_BUILTIN_ALG_CMAC) || \
    defined(PF_MBEDTLS_PSA_BUILTIN_ALG_HMAC)
#define PF_MBEDTLS_PSA_BUILTIN_MAC
#endif

#if defined(PF_MBEDTLS_PSA_BUILTIN_ALG_HMAC) || defined(PF_PSA_CRYPTO_DRIVER_TEST)
typedef struct {
    /** The HMAC algorithm in use */
    pf_psa_algorithm_t PF_MBEDTLS_PRIVATE(alg);
    /** The hash context. */
    struct pf_psa_hash_operation_s hash_ctx;
    /** The HMAC part of the context. */
    uint8_t PF_MBEDTLS_PRIVATE(opad)[PF_PSA_HMAC_MAX_HASH_BLOCK_SIZE];
} pf_mbedtls_psa_hmac_operation_t;

#define PF_MBEDTLS_PSA_HMAC_OPERATION_INIT { 0, PF_PSA_HASH_OPERATION_INIT, { 0 } }
#endif /* MBEDTLS_PSA_BUILTIN_ALG_HMAC */

typedef struct {
    pf_psa_algorithm_t PF_MBEDTLS_PRIVATE(alg);
    union {
        unsigned PF_MBEDTLS_PRIVATE(dummy); /* Make the union non-empty even with no supported algorithms. */
#if defined(PF_MBEDTLS_PSA_BUILTIN_ALG_HMAC) || defined(PF_PSA_CRYPTO_DRIVER_TEST)
        pf_mbedtls_psa_hmac_operation_t PF_MBEDTLS_PRIVATE(hmac);
#endif /* MBEDTLS_PSA_BUILTIN_ALG_HMAC */
#if defined(PF_MBEDTLS_PSA_BUILTIN_ALG_CMAC) || defined(PF_PSA_CRYPTO_DRIVER_TEST)
        pf_mbedtls_cipher_context_t PF_MBEDTLS_PRIVATE(cmac);
#endif /* MBEDTLS_PSA_BUILTIN_ALG_CMAC */
    } PF_MBEDTLS_PRIVATE(ctx);
} pf_mbedtls_psa_mac_operation_t;

#define PF_MBEDTLS_PSA_MAC_OPERATION_INIT { 0, { 0 } }

#if defined(PF_MBEDTLS_PSA_BUILTIN_ALG_GCM) || \
    defined(PF_MBEDTLS_PSA_BUILTIN_ALG_CCM) || \
    defined(PF_MBEDTLS_PSA_BUILTIN_ALG_CHACHA20_POLY1305)
#define PF_MBEDTLS_PSA_BUILTIN_AEAD  1
#endif

/* Context structure for the Mbed TLS AEAD implementation. */
typedef struct {
    pf_psa_algorithm_t PF_MBEDTLS_PRIVATE(alg);
    pf_psa_key_type_t PF_MBEDTLS_PRIVATE(key_type);

    unsigned int PF_MBEDTLS_PRIVATE(is_encrypt) : 1;

    uint8_t PF_MBEDTLS_PRIVATE(tag_length);

    union {
        unsigned dummy; /* Enable easier initializing of the union. */
#if defined(PF_MBEDTLS_PSA_BUILTIN_ALG_CCM)
        pf_mbedtls_ccm_context PF_MBEDTLS_PRIVATE(ccm);
#endif /* MBEDTLS_PSA_BUILTIN_ALG_CCM */
#if defined(PF_MBEDTLS_PSA_BUILTIN_ALG_GCM)
        pf_mbedtls_gcm_context PF_MBEDTLS_PRIVATE(gcm);
#endif /* MBEDTLS_PSA_BUILTIN_ALG_GCM */
#if defined(PF_MBEDTLS_PSA_BUILTIN_ALG_CHACHA20_POLY1305)
        pf_mbedtls_chachapoly_context PF_MBEDTLS_PRIVATE(chachapoly);
#endif /* MBEDTLS_PSA_BUILTIN_ALG_CHACHA20_POLY1305 */

    } ctx;

} pf_mbedtls_psa_aead_operation_t;

#define PF_MBEDTLS_PSA_AEAD_OPERATION_INIT { 0, 0, 0, 0, { 0 } }

#include "../mbedtls/ecdsa.h"

/* Context structure for the Mbed TLS interruptible sign hash implementation. */
typedef struct {
#if (defined(PF_MBEDTLS_PSA_BUILTIN_ALG_ECDSA) || \
    defined(PF_MBEDTLS_PSA_BUILTIN_ALG_DETERMINISTIC_ECDSA)) && \
    defined(PF_MBEDTLS_ECP_RESTARTABLE)
    pf_mbedtls_ecdsa_context *PF_MBEDTLS_PRIVATE(ctx);
    pf_mbedtls_ecdsa_restart_ctx PF_MBEDTLS_PRIVATE(restart_ctx);

    uint32_t PF_MBEDTLS_PRIVATE(num_ops);

    size_t PF_MBEDTLS_PRIVATE(coordinate_bytes);
    pf_psa_algorithm_t PF_MBEDTLS_PRIVATE(alg);
    pf_mbedtls_md_type_t PF_MBEDTLS_PRIVATE(md_alg);
    uint8_t PF_MBEDTLS_PRIVATE(hash)[PF_PSA_BITS_TO_BYTES(PF_PSA_VENDOR_ECC_MAX_CURVE_BITS)];
    size_t PF_MBEDTLS_PRIVATE(hash_length);

#else
    /* Make the struct non-empty if algs not supported. */
    unsigned PF_MBEDTLS_PRIVATE(dummy);

#endif /* defined(MBEDTLS_PSA_BUILTIN_ALG_ECDSA) ||
        * defined(MBEDTLS_PSA_BUILTIN_ALG_DETERMINISTIC_ECDSA) &&
        * defined( MBEDTLS_ECP_RESTARTABLE ) */
} pf_mbedtls_psa_sign_hash_interruptible_operation_t;

#if (defined(PF_MBEDTLS_PSA_BUILTIN_ALG_ECDSA) || \
    defined(PF_MBEDTLS_PSA_BUILTIN_ALG_DETERMINISTIC_ECDSA)) && \
    defined(PF_MBEDTLS_ECP_RESTARTABLE)
#define PF_MBEDTLS_PSA_SIGN_HASH_INTERRUPTIBLE_OPERATION_INIT { { 0 }, { 0 }, 0, 0, 0, 0, 0, 0 }
#else
#define PF_MBEDTLS_PSA_SIGN_HASH_INTERRUPTIBLE_OPERATION_INIT { 0 }
#endif

/* Context structure for the Mbed TLS interruptible verify hash
 * implementation.*/
typedef struct {
#if (defined(PF_MBEDTLS_PSA_BUILTIN_ALG_ECDSA) || \
    defined(PF_MBEDTLS_PSA_BUILTIN_ALG_DETERMINISTIC_ECDSA)) && \
    defined(PF_MBEDTLS_ECP_RESTARTABLE)

    pf_mbedtls_ecdsa_context *PF_MBEDTLS_PRIVATE(ctx);
    pf_mbedtls_ecdsa_restart_ctx PF_MBEDTLS_PRIVATE(restart_ctx);

    uint32_t PF_MBEDTLS_PRIVATE(num_ops);

    uint8_t PF_MBEDTLS_PRIVATE(hash)[PF_PSA_BITS_TO_BYTES(PF_PSA_VENDOR_ECC_MAX_CURVE_BITS)];
    size_t PF_MBEDTLS_PRIVATE(hash_length);

    pf_mbedtls_mpi PF_MBEDTLS_PRIVATE(r);
    pf_mbedtls_mpi PF_MBEDTLS_PRIVATE(s);

#else
    /* Make the struct non-empty if algs not supported. */
    unsigned PF_MBEDTLS_PRIVATE(dummy);

#endif /* defined(MBEDTLS_PSA_BUILTIN_ALG_ECDSA) ||
        * defined(MBEDTLS_PSA_BUILTIN_ALG_DETERMINISTIC_ECDSA) &&
        * defined( MBEDTLS_ECP_RESTARTABLE ) */

} pf_mbedtls_psa_verify_hash_interruptible_operation_t;

#if (defined(PF_MBEDTLS_PSA_BUILTIN_ALG_ECDSA) || \
    defined(PF_MBEDTLS_PSA_BUILTIN_ALG_DETERMINISTIC_ECDSA)) && \
    defined(PF_MBEDTLS_ECP_RESTARTABLE)
#define PF_MBEDTLS_VERIFY_SIGN_HASH_INTERRUPTIBLE_OPERATION_INIT { { 0 }, { 0 }, 0, 0, 0, 0, { 0 }, \
        { 0 } }
#else
#define PF_MBEDTLS_VERIFY_SIGN_HASH_INTERRUPTIBLE_OPERATION_INIT { 0 }
#endif


/* EC-JPAKE operation definitions */

#include "../mbedtls/ecjpake.h"

#if defined(PF_MBEDTLS_PSA_BUILTIN_ALG_JPAKE)
#define PF_MBEDTLS_PSA_BUILTIN_PAKE  1
#endif

/* Note: the format for mbedtls_ecjpake_read/write function has an extra
 * length byte for each step, plus an extra 3 bytes for ECParameters in the
 * server's 2nd round. */
#define PF_MBEDTLS_PSA_JPAKE_BUFFER_SIZE ((3 + 1 + 65 + 1 + 65 + 1 + 32) * 2)

typedef struct {
    pf_psa_algorithm_t PF_MBEDTLS_PRIVATE(alg);

    uint8_t *PF_MBEDTLS_PRIVATE(password);
    size_t PF_MBEDTLS_PRIVATE(password_len);
#if defined(PF_MBEDTLS_PSA_BUILTIN_ALG_JPAKE)
    pf_mbedtls_ecjpake_role PF_MBEDTLS_PRIVATE(role);
    uint8_t PF_MBEDTLS_PRIVATE(buffer[PF_MBEDTLS_PSA_JPAKE_BUFFER_SIZE]);
    size_t PF_MBEDTLS_PRIVATE(buffer_length);
    size_t PF_MBEDTLS_PRIVATE(buffer_offset);
#endif
    /* Context structure for the Mbed TLS EC-JPAKE implementation. */
    union {
        unsigned int PF_MBEDTLS_PRIVATE(dummy);
#if defined(PF_MBEDTLS_PSA_BUILTIN_ALG_JPAKE)
        pf_mbedtls_ecjpake_context PF_MBEDTLS_PRIVATE(jpake);
#endif
    } PF_MBEDTLS_PRIVATE(ctx);

} pf_mbedtls_psa_pake_operation_t;

#define PF_MBEDTLS_PSA_PAKE_OPERATION_INIT { { 0 } }

#endif /* PSA_CRYPTO_BUILTIN_COMPOSITES_H */
