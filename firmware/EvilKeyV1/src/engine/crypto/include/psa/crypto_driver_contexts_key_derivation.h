/*
 *  Declaration of context structures for use with the PSA driver wrapper
 *  interface. This file contains the context structures for key derivation
 *  operations.
 *
 *  Warning: This file will be auto-generated in the future.
 *
 * \note This file may not be included directly. Applications must
 * include psa/crypto.h.
 *
 * \note This header and its content are not part of the Mbed TLS API and
 * applications must not depend on it. Its main purpose is to define the
 * multi-part state objects of the PSA drivers included in the cryptographic
 * library. The definitions of these objects are then used by crypto_struct.h
 * to define the implementation-defined types of PSA multi-part state objects.
 */
/*  Copyright The Mbed TLS Contributors
 *  SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
 */

#ifndef PF_PSA_CRYPTO_DRIVER_CONTEXTS_KEY_DERIVATION_H
#define PF_PSA_CRYPTO_DRIVER_CONTEXTS_KEY_DERIVATION_H

#include "crypto_driver_common.h"

/* Include the context structure definitions for the Mbed TLS software drivers */
#include "crypto_builtin_key_derivation.h"

/* Include the context structure definitions for those drivers that were
 * declared during the autogeneration process. */

typedef union {
    unsigned dummy; /* Make sure this union is always non-empty */
#if defined(PF_MBEDTLS_PSA_BUILTIN_ALG_HKDF) || \
    defined(PF_MBEDTLS_PSA_BUILTIN_ALG_HKDF_EXTRACT) || \
    defined(PF_MBEDTLS_PSA_BUILTIN_ALG_HKDF_EXPAND)
    pf_psa_hkdf_key_derivation_t PF_MBEDTLS_PRIVATE(hkdf);
#endif
#if defined(PF_MBEDTLS_PSA_BUILTIN_ALG_TLS12_PRF) || \
    defined(PF_MBEDTLS_PSA_BUILTIN_ALG_TLS12_PSK_TO_MS)
    pf_psa_tls12_prf_key_derivation_t PF_MBEDTLS_PRIVATE(tls12_prf);
#endif
#if defined(PF_MBEDTLS_PSA_BUILTIN_ALG_TLS12_ECJPAKE_TO_PMS)
    pf_psa_tls12_ecjpake_to_pms_t PF_MBEDTLS_PRIVATE(tls12_ecjpake_to_pms);
#endif
#if defined(PF_PSA_HAVE_SOFT_PBKDF2)
    pf_psa_pbkdf2_key_derivation_t PF_MBEDTLS_PRIVATE(pbkdf2);
#endif
} pf_psa_driver_key_derivation_context_t;

#endif /* PSA_CRYPTO_DRIVER_CONTEXTS_KEY_DERIVATION_H */
/* End of automatically generated file. */
