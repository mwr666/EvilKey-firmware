/**
 * \file ssl_debug_helpers.h
 *
 * \brief Automatically generated helper functions for debugging
 */
/*
 *  Copyright The Mbed TLS Contributors
 *  SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
 */

#ifndef PF_MBEDTLS_SSL_DEBUG_HELPERS_H
#define PF_MBEDTLS_SSL_DEBUG_HELPERS_H

#include "common.h"

#if defined(PF_MBEDTLS_DEBUG_C)

#include "../include/mbedtls/ssl.h"
#include "ssl_misc.h"


const char *pf_mbedtls_ssl_states_str(pf_mbedtls_ssl_states in);

#if defined(PF_MBEDTLS_SSL_EARLY_DATA) && defined(PF_MBEDTLS_SSL_CLI_C)
const char *pf_mbedtls_ssl_early_data_status_str(pf_mbedtls_ssl_early_data_status in);
const char *pf_mbedtls_ssl_early_data_state_str(pf_mbedtls_ssl_early_data_state in);
#endif

const char *pf_mbedtls_ssl_protocol_version_str(pf_mbedtls_ssl_protocol_version in);

const char *pf_mbedtls_tls_prf_types_str(pf_mbedtls_tls_prf_types in);

const char *pf_mbedtls_ssl_key_export_type_str(pf_mbedtls_ssl_key_export_type in);

const char *pf_mbedtls_ssl_sig_alg_to_str(uint16_t in);

const char *pf_mbedtls_ssl_named_group_to_str(uint16_t in);

const char *pf_mbedtls_ssl_get_extension_name(unsigned int extension_type);

const char *pf_mbedtls_ssl_get_hs_msg_name(int hs_msg_type);

void pf_mbedtls_ssl_print_extensions(const pf_mbedtls_ssl_context *ssl,
                                  int level, const char *file, int line,
                                  int hs_msg_type, uint32_t extensions_mask,
                                  const char *extra);

void pf_mbedtls_ssl_print_extension(const pf_mbedtls_ssl_context *ssl,
                                 int level, const char *file, int line,
                                 int hs_msg_type, unsigned int extension_type,
                                 const char *extra_msg0, const char *extra_msg1);

#if defined(PF_MBEDTLS_SSL_PROTO_TLS1_3) && defined(PF_MBEDTLS_SSL_SESSION_TICKETS)
void pf_mbedtls_ssl_print_ticket_flags(const pf_mbedtls_ssl_context *ssl,
                                    int level, const char *file, int line,
                                    unsigned int flags);
#endif /* MBEDTLS_SSL_PROTO_TLS1_3 && MBEDTLS_SSL_SESSION_TICKETS */

#define PF_MBEDTLS_SSL_PRINT_EXTS(level, hs_msg_type, extensions_mask)            \
    pf_mbedtls_ssl_print_extensions(ssl, level, __FILE__, __LINE__,       \
                                 hs_msg_type, extensions_mask, NULL)

#define PF_MBEDTLS_SSL_PRINT_EXT(level, hs_msg_type, extension_type, extra)      \
    pf_mbedtls_ssl_print_extension(ssl, level, __FILE__, __LINE__,        \
                                hs_msg_type, extension_type,           \
                                extra, NULL)

#if defined(PF_MBEDTLS_SSL_PROTO_TLS1_3) && defined(PF_MBEDTLS_SSL_SESSION_TICKETS)
#define PF_MBEDTLS_SSL_PRINT_TICKET_FLAGS(level, flags)             \
    pf_mbedtls_ssl_print_ticket_flags(ssl, level, __FILE__, __LINE__, flags)
#endif

#else

#define PF_MBEDTLS_SSL_PRINT_EXTS(level, hs_msg_type, extension_mask)

#define PF_MBEDTLS_SSL_PRINT_EXT(level, hs_msg_type, extension_type, extra)

#if defined(PF_MBEDTLS_SSL_PROTO_TLS1_3) && defined(PF_MBEDTLS_SSL_SESSION_TICKETS)
#define PF_MBEDTLS_SSL_PRINT_TICKET_FLAGS(level, flags)
#endif

#endif /* MBEDTLS_DEBUG_C */

#endif /* MBEDTLS_SSL_DEBUG_HELPERS_H */
