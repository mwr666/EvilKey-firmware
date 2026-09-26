/**
 * \file psa/crypto_legacy.h
 *
 * \brief Add temporary suppport for deprecated symbols before they are
 *        removed from the library.
 *
 * PSA_WANT_KEY_TYPE_xxx_KEY_PAIR and MBEDTLS_PSA_ACCEL_KEY_TYPE_xxx_KEY_PAIR
 * symbols are deprecated.
 * New symols add a suffix to that base name in order to clearly state what is
 * the expected use for the key (use, import, export, generate, derive).
 * Here we define some backward compatibility support for uses stil using
 * the legacy symbols.
 */
/*
 *  Copyright The Mbed TLS Contributors
 *  SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
 */

#ifndef PF_MBEDTLS_PSA_CRYPTO_LEGACY_H
#define PF_MBEDTLS_PSA_CRYPTO_LEGACY_H

#if defined(PF_PSA_WANT_KEY_TYPE_ECC_KEY_PAIR) //no-check-names
#if !defined(PF_PSA_WANT_KEY_TYPE_ECC_KEY_PAIR_BASIC)
#define PF_PSA_WANT_KEY_TYPE_ECC_KEY_PAIR_BASIC      1
#endif
#if !defined(PF_PSA_WANT_KEY_TYPE_ECC_KEY_PAIR_IMPORT)
#define PF_PSA_WANT_KEY_TYPE_ECC_KEY_PAIR_IMPORT   1
#endif
#if !defined(PF_PSA_WANT_KEY_TYPE_ECC_KEY_PAIR_EXPORT)
#define PF_PSA_WANT_KEY_TYPE_ECC_KEY_PAIR_EXPORT   1
#endif
#if !defined(PF_PSA_WANT_KEY_TYPE_ECC_KEY_PAIR_GENERATE)
#define PF_PSA_WANT_KEY_TYPE_ECC_KEY_PAIR_GENERATE 1
#endif
#if !defined(PF_PSA_WANT_KEY_TYPE_ECC_KEY_PAIR_DERIVE)
#define PF_PSA_WANT_KEY_TYPE_ECC_KEY_PAIR_DERIVE   1
#endif
#endif

#if defined(PF_PSA_WANT_KEY_TYPE_RSA_KEY_PAIR) //no-check-names
#if !defined(PF_PSA_WANT_KEY_TYPE_RSA_KEY_PAIR_BASIC)
#define PF_PSA_WANT_KEY_TYPE_RSA_KEY_PAIR_BASIC      1
#endif
#if !defined(PF_PSA_WANT_KEY_TYPE_RSA_KEY_PAIR_IMPORT)
#define PF_PSA_WANT_KEY_TYPE_RSA_KEY_PAIR_IMPORT   1
#endif
#if !defined(PF_PSA_WANT_KEY_TYPE_RSA_KEY_PAIR_EXPORT)
#define PF_PSA_WANT_KEY_TYPE_RSA_KEY_PAIR_EXPORT   1
#endif
#if !defined(PF_PSA_WANT_KEY_TYPE_RSA_KEY_PAIR_GENERATE)
#define PF_PSA_WANT_KEY_TYPE_RSA_KEY_PAIR_GENERATE 1
#endif
#endif

#if defined(PF_MBEDTLS_PSA_ACCEL_KEY_TYPE_ECC_KEY_PAIR) //no-check-names
#if !defined(PF_MBEDTLS_PSA_ACCEL_KEY_TYPE_ECC_KEY_PAIR_BASIC)
#define PF_MBEDTLS_PSA_ACCEL_KEY_TYPE_ECC_KEY_PAIR_BASIC
#endif
#if !defined(PF_MBEDTLS_PSA_ACCEL_KEY_TYPE_ECC_KEY_PAIR_IMPORT)
#define PF_MBEDTLS_PSA_ACCEL_KEY_TYPE_ECC_KEY_PAIR_IMPORT
#endif
#if !defined(PF_MBEDTLS_PSA_ACCEL_KEY_TYPE_ECC_KEY_PAIR_EXPORT)
#define PF_MBEDTLS_PSA_ACCEL_KEY_TYPE_ECC_KEY_PAIR_EXPORT
#endif
#if !defined(PF_MBEDTLS_PSA_ACCEL_KEY_TYPE_ECC_KEY_PAIR_GENERATE)
#define PF_MBEDTLS_PSA_ACCEL_KEY_TYPE_ECC_KEY_PAIR_GENERATE
#endif
#if !defined(PF_MBEDTLS_PSA_ACCEL_KEY_TYPE_ECC_KEY_PAIR_DERIVE)
#define PF_MBEDTLS_PSA_ACCEL_KEY_TYPE_ECC_KEY_PAIR_DERIVE
#endif
#endif

#if defined(PF_MBEDTLS_PSA_ACCEL_KEY_TYPE_RSA_KEY_PAIR) //no-check-names
#if !defined(PF_MBEDTLS_PSA_ACCEL_KEY_TYPE_RSA_KEY_PAIR_BASIC)
#define PF_MBEDTLS_PSA_ACCEL_KEY_TYPE_RSA_KEY_PAIR_BASIC
#endif
#if !defined(PF_MBEDTLS_PSA_ACCEL_KEY_TYPE_RSA_KEY_PAIR_IMPORT)
#define PF_MBEDTLS_PSA_ACCEL_KEY_TYPE_RSA_KEY_PAIR_IMPORT
#endif
#if !defined(PF_MBEDTLS_PSA_ACCEL_KEY_TYPE_RSA_KEY_PAIR_EXPORT)
#define PF_MBEDTLS_PSA_ACCEL_KEY_TYPE_RSA_KEY_PAIR_EXPORT
#endif
#if !defined(PF_MBEDTLS_PSA_ACCEL_KEY_TYPE_RSA_KEY_PAIR_GENERATE)
#define PF_MBEDTLS_PSA_ACCEL_KEY_TYPE_RSA_KEY_PAIR_GENERATE
#endif
#endif

#endif /* MBEDTLS_PSA_CRYPTO_LEGACY_H */
