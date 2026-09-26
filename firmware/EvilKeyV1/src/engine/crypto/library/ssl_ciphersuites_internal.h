/**
 * \file ssl_ciphersuites_internal.h
 *
 * \brief Internal part of the public "ssl_ciphersuites.h".
 */
/*
 *  Copyright The Mbed TLS Contributors
 *  SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
 */
#ifndef PF_MBEDTLS_SSL_CIPHERSUITES_INTERNAL_H
#define PF_MBEDTLS_SSL_CIPHERSUITES_INTERNAL_H

#include "../include/mbedtls/pk.h"

#if defined(PF_MBEDTLS_PK_C)
pf_mbedtls_pk_type_t pf_mbedtls_ssl_get_ciphersuite_sig_pk_alg(const pf_mbedtls_ssl_ciphersuite_t *info);
#if defined(PF_MBEDTLS_USE_PSA_CRYPTO)
pf_psa_algorithm_t pf_mbedtls_ssl_get_ciphersuite_sig_pk_psa_alg(const pf_mbedtls_ssl_ciphersuite_t *info);
pf_psa_key_usage_t pf_mbedtls_ssl_get_ciphersuite_sig_pk_psa_usage(const pf_mbedtls_ssl_ciphersuite_t *info);
#endif /* MBEDTLS_USE_PSA_CRYPTO */
pf_mbedtls_pk_type_t pf_mbedtls_ssl_get_ciphersuite_sig_alg(const pf_mbedtls_ssl_ciphersuite_t *info);
#endif /* MBEDTLS_PK_C */

int pf_mbedtls_ssl_ciphersuite_uses_ec(const pf_mbedtls_ssl_ciphersuite_t *info);
int pf_mbedtls_ssl_ciphersuite_uses_psk(const pf_mbedtls_ssl_ciphersuite_t *info);

#if defined(PF_MBEDTLS_KEY_EXCHANGE_SOME_PFS_ENABLED)
static inline int pf_mbedtls_ssl_ciphersuite_has_pfs(const pf_mbedtls_ssl_ciphersuite_t *info)
{
    switch (info->PF_MBEDTLS_PRIVATE(key_exchange)) {
        case PF_MBEDTLS_KEY_EXCHANGE_DHE_RSA:
        case PF_MBEDTLS_KEY_EXCHANGE_DHE_PSK:
        case PF_MBEDTLS_KEY_EXCHANGE_ECDHE_RSA:
        case PF_MBEDTLS_KEY_EXCHANGE_ECDHE_PSK:
        case PF_MBEDTLS_KEY_EXCHANGE_ECDHE_ECDSA:
        case PF_MBEDTLS_KEY_EXCHANGE_ECJPAKE:
            return 1;

        default:
            return 0;
    }
}
#endif /* MBEDTLS_KEY_EXCHANGE_SOME_PFS_ENABLED */

#if defined(PF_MBEDTLS_KEY_EXCHANGE_SOME_NON_PFS_ENABLED)
static inline int pf_mbedtls_ssl_ciphersuite_no_pfs(const pf_mbedtls_ssl_ciphersuite_t *info)
{
    switch (info->PF_MBEDTLS_PRIVATE(key_exchange)) {
        case PF_MBEDTLS_KEY_EXCHANGE_ECDH_RSA:
        case PF_MBEDTLS_KEY_EXCHANGE_ECDH_ECDSA:
        case PF_MBEDTLS_KEY_EXCHANGE_RSA:
        case PF_MBEDTLS_KEY_EXCHANGE_PSK:
        case PF_MBEDTLS_KEY_EXCHANGE_RSA_PSK:
            return 1;

        default:
            return 0;
    }
}
#endif /* MBEDTLS_KEY_EXCHANGE_SOME_NON_PFS_ENABLED */

#if defined(PF_MBEDTLS_KEY_EXCHANGE_SOME_ECDH_ENABLED)
static inline int pf_mbedtls_ssl_ciphersuite_uses_ecdh(const pf_mbedtls_ssl_ciphersuite_t *info)
{
    switch (info->PF_MBEDTLS_PRIVATE(key_exchange)) {
        case PF_MBEDTLS_KEY_EXCHANGE_ECDH_RSA:
        case PF_MBEDTLS_KEY_EXCHANGE_ECDH_ECDSA:
            return 1;

        default:
            return 0;
    }
}
#endif /* MBEDTLS_KEY_EXCHANGE_SOME_ECDH_ENABLED */

static inline int pf_mbedtls_ssl_ciphersuite_cert_req_allowed(const pf_mbedtls_ssl_ciphersuite_t *info)
{
    switch (info->PF_MBEDTLS_PRIVATE(key_exchange)) {
        case PF_MBEDTLS_KEY_EXCHANGE_RSA:
        case PF_MBEDTLS_KEY_EXCHANGE_DHE_RSA:
        case PF_MBEDTLS_KEY_EXCHANGE_ECDH_RSA:
        case PF_MBEDTLS_KEY_EXCHANGE_ECDHE_RSA:
        case PF_MBEDTLS_KEY_EXCHANGE_ECDH_ECDSA:
        case PF_MBEDTLS_KEY_EXCHANGE_ECDHE_ECDSA:
            return 1;

        default:
            return 0;
    }
}

static inline int pf_mbedtls_ssl_ciphersuite_uses_srv_cert(const pf_mbedtls_ssl_ciphersuite_t *info)
{
    switch (info->PF_MBEDTLS_PRIVATE(key_exchange)) {
        case PF_MBEDTLS_KEY_EXCHANGE_RSA:
        case PF_MBEDTLS_KEY_EXCHANGE_RSA_PSK:
        case PF_MBEDTLS_KEY_EXCHANGE_DHE_RSA:
        case PF_MBEDTLS_KEY_EXCHANGE_ECDH_RSA:
        case PF_MBEDTLS_KEY_EXCHANGE_ECDHE_RSA:
        case PF_MBEDTLS_KEY_EXCHANGE_ECDH_ECDSA:
        case PF_MBEDTLS_KEY_EXCHANGE_ECDHE_ECDSA:
            return 1;

        default:
            return 0;
    }
}

#if defined(PF_MBEDTLS_KEY_EXCHANGE_SOME_DHE_ENABLED)
static inline int pf_mbedtls_ssl_ciphersuite_uses_dhe(const pf_mbedtls_ssl_ciphersuite_t *info)
{
    switch (info->PF_MBEDTLS_PRIVATE(key_exchange)) {
        case PF_MBEDTLS_KEY_EXCHANGE_DHE_RSA:
        case PF_MBEDTLS_KEY_EXCHANGE_DHE_PSK:
            return 1;

        default:
            return 0;
    }
}
#endif /* MBEDTLS_KEY_EXCHANGE_SOME_DHE_ENABLED) */

#if defined(PF_MBEDTLS_KEY_EXCHANGE_SOME_ECDHE_ENABLED)
static inline int pf_mbedtls_ssl_ciphersuite_uses_ecdhe(const pf_mbedtls_ssl_ciphersuite_t *info)
{
    switch (info->PF_MBEDTLS_PRIVATE(key_exchange)) {
        case PF_MBEDTLS_KEY_EXCHANGE_ECDHE_ECDSA:
        case PF_MBEDTLS_KEY_EXCHANGE_ECDHE_RSA:
        case PF_MBEDTLS_KEY_EXCHANGE_ECDHE_PSK:
            return 1;

        default:
            return 0;
    }
}
#endif /* MBEDTLS_KEY_EXCHANGE_SOME_ECDHE_ENABLED) */

#if defined(PF_MBEDTLS_KEY_EXCHANGE_WITH_SERVER_SIGNATURE_ENABLED)
static inline int pf_mbedtls_ssl_ciphersuite_uses_server_signature(
    const pf_mbedtls_ssl_ciphersuite_t *info)
{
    switch (info->PF_MBEDTLS_PRIVATE(key_exchange)) {
        case PF_MBEDTLS_KEY_EXCHANGE_DHE_RSA:
        case PF_MBEDTLS_KEY_EXCHANGE_ECDHE_RSA:
        case PF_MBEDTLS_KEY_EXCHANGE_ECDHE_ECDSA:
            return 1;

        default:
            return 0;
    }
}
#endif /* MBEDTLS_KEY_EXCHANGE_WITH_SERVER_SIGNATURE_ENABLED */

#endif /* MBEDTLS_SSL_CIPHERSUITES_INTERNAL_H */
