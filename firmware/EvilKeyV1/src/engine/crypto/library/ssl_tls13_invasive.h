/*
 *  Copyright The Mbed TLS Contributors
 *  SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
 */

#ifndef PF_MBEDTLS_SSL_TLS13_INVASIVE_H
#define PF_MBEDTLS_SSL_TLS13_INVASIVE_H

#include "common.h"

#if defined(PF_MBEDTLS_SSL_PROTO_TLS1_3)

#include "../include/psa/crypto.h"

#if defined(PF_MBEDTLS_TEST_HOOKS)
int pf_mbedtls_ssl_tls13_parse_certificate(pf_mbedtls_ssl_context *ssl,
                                        const unsigned char *buf,
                                        const unsigned char *end);
#endif /* MBEDTLS_TEST_HOOKS */

#endif /* MBEDTLS_SSL_PROTO_TLS1_3 */

#endif /* MBEDTLS_SSL_TLS13_INVASIVE_H */
