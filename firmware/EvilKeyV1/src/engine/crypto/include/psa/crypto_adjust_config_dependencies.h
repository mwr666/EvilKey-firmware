/**
 * \file psa/crypto_adjust_config_dependencies.h
 * \brief Adjust PSA configuration by resolving some dependencies.
 *
 * This is an internal header. Do not include it directly.
 *
 * See docs/proposed/psa-conditional-inclusion-c.md.
 * If the Mbed TLS implementation of a cryptographic mechanism A depends on a
 * cryptographic mechanism B then if the cryptographic mechanism A is enabled
 * and not accelerated enable B. Note that if A is enabled and accelerated, it
 * is not necessary to enable B for A support.
 */
/*
 *  Copyright The Mbed TLS Contributors
 *  SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
 */

#ifndef PF_PSA_CRYPTO_ADJUST_CONFIG_DEPENDENCIES_H
#define PF_PSA_CRYPTO_ADJUST_CONFIG_DEPENDENCIES_H

#if !defined(PF_MBEDTLS_CONFIG_FILES_READ)
#error "Do not include psa/crypto_adjust_*.h manually! This can lead to problems, " \
    "up to and including runtime errors such as buffer overflows. " \
    "If you're trying to fix a complaint from check_config.h, just remove " \
    "it from your configuration file: since Mbed TLS 3.0, it is included " \
    "automatically at the right point."
#endif /* */

#if (defined(PF_PSA_WANT_ALG_TLS12_PRF) && \
    !defined(PF_MBEDTLS_PSA_ACCEL_ALG_TLS12_PRF)) || \
    (defined(PF_PSA_WANT_ALG_TLS12_PSK_TO_MS) && \
    !defined(PF_MBEDTLS_PSA_ACCEL_ALG_TLS12_PSK_TO_MS)) || \
    (defined(PF_PSA_WANT_ALG_HKDF) && \
    !defined(PF_MBEDTLS_PSA_ACCEL_ALG_HKDF)) || \
    (defined(PF_PSA_WANT_ALG_HKDF_EXTRACT) && \
    !defined(PF_MBEDTLS_PSA_ACCEL_ALG_HKDF_EXTRACT)) || \
    (defined(PF_PSA_WANT_ALG_HKDF_EXPAND) && \
    !defined(PF_MBEDTLS_PSA_ACCEL_ALG_HKDF_EXPAND)) || \
    (defined(PF_PSA_WANT_ALG_PBKDF2_HMAC) && \
    !defined(PF_MBEDTLS_PSA_ACCEL_ALG_PBKDF2_HMAC))
#define PF_PSA_WANT_ALG_HMAC 1
#define PF_PSA_WANT_KEY_TYPE_HMAC 1
#endif

#if (defined(PF_PSA_WANT_ALG_PBKDF2_AES_CMAC_PRF_128) && \
    !defined(PF_MBEDTLS_PSA_ACCEL_ALG_PBKDF2_AES_CMAC_PRF_128))
#define PF_PSA_WANT_KEY_TYPE_AES 1
#define PF_PSA_WANT_ALG_CMAC 1
#endif

#endif /* PSA_CRYPTO_ADJUST_CONFIG_DEPENDENCIES_H */
