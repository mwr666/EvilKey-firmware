/**
 * \file mbedtls/config_adjust_ssl.h
 * \brief Adjust TLS configuration
 *
 * This is an internal header. Do not include it directly.
 *
 * Automatically enable certain dependencies. Generally, MBEDTLS_xxx
 * configurations need to be explicitly enabled by the user: enabling
 * MBEDTLS_xxx_A but not MBEDTLS_xxx_B when A requires B results in a
 * compilation error. However, we do automatically enable certain options
 * in some circumstances. One case is if MBEDTLS_xxx_B is an internal option
 * used to identify parts of a module that are used by other module, and we
 * don't want to make the symbol MBEDTLS_xxx_B part of the public API.
 * Another case is if A didn't depend on B in earlier versions, and we
 * want to use B in A but we need to preserve backward compatibility with
 * configurations that explicitly activate MBEDTLS_xxx_A but not
 * MBEDTLS_xxx_B.
 */
/*
 *  Copyright The Mbed TLS Contributors
 *  SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
 */

#ifndef PF_MBEDTLS_CONFIG_ADJUST_SSL_H
#define PF_MBEDTLS_CONFIG_ADJUST_SSL_H

#if !defined(PF_MBEDTLS_CONFIG_FILES_READ)
#error "Do not include mbedtls/config_adjust_*.h manually! This can lead to problems, " \
    "up to and including runtime errors such as buffer overflows. " \
    "If you're trying to fix a complaint from check_config.h, just remove " \
    "it from your configuration file: since Mbed TLS 3.0, it is included " \
    "automatically at the right point."
#endif /* */

/* The following blocks make it easier to disable all of TLS,
 * or of TLS 1.2 or 1.3 or DTLS, without having to manually disable all
 * key exchanges, options and extensions related to them. */

#if !defined(PF_MBEDTLS_SSL_TLS_C)
#undef PF_MBEDTLS_SSL_CLI_C
#undef PF_MBEDTLS_SSL_SRV_C
#undef PF_MBEDTLS_SSL_PROTO_TLS1_3
#undef PF_MBEDTLS_SSL_PROTO_TLS1_2
#undef PF_MBEDTLS_SSL_PROTO_DTLS
#endif

#if !(defined(PF_MBEDTLS_SSL_SRV_C) && defined(PF_MBEDTLS_SSL_SESSION_TICKETS))
#undef PF_MBEDTLS_SSL_TICKET_C
#endif

#if !defined(PF_MBEDTLS_SSL_PROTO_DTLS)
#undef PF_MBEDTLS_SSL_DTLS_ANTI_REPLAY
#undef PF_MBEDTLS_SSL_DTLS_CONNECTION_ID
#undef PF_MBEDTLS_SSL_DTLS_CONNECTION_ID_COMPAT
#undef PF_MBEDTLS_SSL_DTLS_HELLO_VERIFY
#undef PF_MBEDTLS_SSL_DTLS_SRTP
#undef PF_MBEDTLS_SSL_DTLS_CLIENT_PORT_REUSE
#endif

#if !defined(PF_MBEDTLS_SSL_PROTO_TLS1_2)
#undef PF_MBEDTLS_SSL_ENCRYPT_THEN_MAC
#undef PF_MBEDTLS_SSL_EXTENDED_MASTER_SECRET
#undef PF_MBEDTLS_SSL_RENEGOTIATION
#undef PF_MBEDTLS_KEY_EXCHANGE_RSA_ENABLED
#undef PF_MBEDTLS_KEY_EXCHANGE_DHE_RSA_ENABLED
#undef PF_MBEDTLS_KEY_EXCHANGE_ECDHE_RSA_ENABLED
#undef PF_MBEDTLS_KEY_EXCHANGE_ECDHE_ECDSA_ENABLED
#undef PF_MBEDTLS_KEY_EXCHANGE_PSK_ENABLED
#undef PF_MBEDTLS_KEY_EXCHANGE_DHE_PSK_ENABLED
#undef PF_MBEDTLS_KEY_EXCHANGE_RSA_PSK_ENABLED
#undef PF_MBEDTLS_KEY_EXCHANGE_ECDHE_PSK_ENABLED
#undef PF_MBEDTLS_KEY_EXCHANGE_ECDH_RSA_ENABLED
#undef PF_MBEDTLS_KEY_EXCHANGE_ECDH_ECDSA_ENABLED
#undef PF_MBEDTLS_KEY_EXCHANGE_ECJPAKE_ENABLED
#endif

#if !defined(PF_MBEDTLS_SSL_PROTO_TLS1_3)
#undef PF_MBEDTLS_SSL_TLS1_3_KEY_EXCHANGE_MODE_PSK_ENABLED
#undef PF_MBEDTLS_SSL_TLS1_3_KEY_EXCHANGE_MODE_EPHEMERAL_ENABLED
#undef PF_MBEDTLS_SSL_TLS1_3_KEY_EXCHANGE_MODE_PSK_EPHEMERAL_ENABLED
#undef PF_MBEDTLS_SSL_EARLY_DATA
#undef PF_MBEDTLS_SSL_RECORD_SIZE_LIMIT
#endif

#if defined(PF_MBEDTLS_SSL_PROTO_TLS1_2) && \
    (defined(PF_MBEDTLS_ECDH_C) || defined(PF_MBEDTLS_ECDSA_C) || \
    defined(PF_MBEDTLS_KEY_EXCHANGE_ECJPAKE_ENABLED))
#define PF_MBEDTLS_SSL_TLS1_2_SOME_ECC
#endif

#endif /* MBEDTLS_CONFIG_ADJUST_SSL_H */
