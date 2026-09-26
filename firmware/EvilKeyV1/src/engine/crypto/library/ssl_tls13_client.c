#include "../../../pf_build_config.h"
/*
 *  TLS 1.3 client-side functions
 *
 *  Copyright The Mbed TLS Contributors
 *  SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
 */

#include "common.h"

#if defined(PF_MBEDTLS_SSL_CLI_C) && defined(PF_MBEDTLS_SSL_PROTO_TLS1_3)

#include <string.h>

#include "debug_internal.h"
#include "../include/mbedtls/error.h"
#include "../include/mbedtls/platform.h"

#include "ssl_misc.h"
#include "ssl_client.h"
#include "ssl_tls13_keys.h"
#include "ssl_debug_helpers.h"
#include "../include/mbedtls/psa_util.h"

#if defined(PF_MBEDTLS_SSL_TLS1_3_KEY_EXCHANGE_MODE_SOME_EPHEMERAL_ENABLED)
/* Define a local translating function to save code size by not using too many
 * arguments in each translating place. */
static int local_err_translation(pf_psa_status_t status)
{
    return pf_psa_status_to_mbedtls(status, pf_psa_to_ssl_errors,
                                 ARRAY_LENGTH(pf_psa_to_ssl_errors),
                                 pf_psa_generic_status_to_mbedtls);
}
#define PF_PSA_TO_MBEDTLS_ERR(status) local_err_translation(status)
#endif

/* Write extensions */

/*
 * ssl_tls13_write_supported_versions_ext():
 *
 * struct {
 *      ProtocolVersion versions<2..254>;
 * } SupportedVersions;
 */
PF_MBEDTLS_CHECK_RETURN_CRITICAL
static int ssl_tls13_write_supported_versions_ext(pf_mbedtls_ssl_context *ssl,
                                                  unsigned char *buf,
                                                  unsigned char *end,
                                                  size_t *out_len)
{
    unsigned char *p = buf;
    unsigned char versions_len = (ssl->handshake->min_tls_version <=
                                  PF_MBEDTLS_SSL_VERSION_TLS1_2) ? 4 : 2;

    *out_len = 0;

    PF_MBEDTLS_SSL_DEBUG_MSG(3, ("client hello, adding supported versions extension"));

    /* Check if we have space to write the extension:
     * - extension_type         (2 bytes)
     * - extension_data_length  (2 bytes)
     * - versions_length        (1 byte )
     * - versions               (2 or 4 bytes)
     */
    PF_MBEDTLS_SSL_CHK_BUF_PTR(p, end, 5 + versions_len);

    PF_MBEDTLS_PUT_UINT16_BE(PF_MBEDTLS_TLS_EXT_SUPPORTED_VERSIONS, p, 0);
    PF_MBEDTLS_PUT_UINT16_BE(versions_len + 1, p, 2);
    p += 4;

    /* Length of versions */
    *p++ = versions_len;

    /* Write values of supported versions.
     * They are defined by the configuration.
     * Currently, we advertise only TLS 1.3 or both TLS 1.3 and TLS 1.2.
     */
    pf_mbedtls_ssl_write_version(p, PF_MBEDTLS_SSL_TRANSPORT_STREAM,
                              PF_MBEDTLS_SSL_VERSION_TLS1_3);
    PF_MBEDTLS_SSL_DEBUG_MSG(3, ("supported version: [3:4]"));


    if (ssl->handshake->min_tls_version <= PF_MBEDTLS_SSL_VERSION_TLS1_2) {
        pf_mbedtls_ssl_write_version(p + 2, PF_MBEDTLS_SSL_TRANSPORT_STREAM,
                                  PF_MBEDTLS_SSL_VERSION_TLS1_2);
        PF_MBEDTLS_SSL_DEBUG_MSG(3, ("supported version: [3:3]"));
    }

    *out_len = 5 + versions_len;

    pf_mbedtls_ssl_tls13_set_hs_sent_ext_mask(
        ssl, PF_MBEDTLS_TLS_EXT_SUPPORTED_VERSIONS);

    return 0;
}

PF_MBEDTLS_CHECK_RETURN_CRITICAL
static int ssl_tls13_parse_supported_versions_ext(pf_mbedtls_ssl_context *ssl,
                                                  const unsigned char *buf,
                                                  const unsigned char *end)
{
    ((void) ssl);

    PF_MBEDTLS_SSL_CHK_BUF_READ_PTR(buf, end, 2);
    if (pf_mbedtls_ssl_read_version(buf, ssl->conf->transport) !=
        PF_MBEDTLS_SSL_VERSION_TLS1_3) {
        PF_MBEDTLS_SSL_DEBUG_MSG(1, ("unexpected version"));

        PF_MBEDTLS_SSL_PEND_FATAL_ALERT(PF_MBEDTLS_SSL_ALERT_MSG_ILLEGAL_PARAMETER,
                                     PF_MBEDTLS_ERR_SSL_ILLEGAL_PARAMETER);
        return PF_MBEDTLS_ERR_SSL_ILLEGAL_PARAMETER;
    }

    if (&buf[2] != end) {
        PF_MBEDTLS_SSL_DEBUG_MSG(
            1, ("supported_versions ext data length incorrect"));
        PF_MBEDTLS_SSL_PEND_FATAL_ALERT(PF_MBEDTLS_SSL_ALERT_MSG_DECODE_ERROR,
                                     PF_MBEDTLS_ERR_SSL_DECODE_ERROR);
        return PF_MBEDTLS_ERR_SSL_DECODE_ERROR;
    }

    return 0;
}

#if defined(PF_MBEDTLS_SSL_ALPN)
PF_MBEDTLS_CHECK_RETURN_CRITICAL
static int ssl_tls13_parse_alpn_ext(pf_mbedtls_ssl_context *ssl,
                                    const unsigned char *buf, size_t len)
{
    const unsigned char *p = buf;
    const unsigned char *end = buf + len;
    size_t protocol_name_list_len, protocol_name_len;
    const unsigned char *protocol_name_list_end;

    /* If we didn't send it, the server shouldn't send it */
    if (ssl->conf->alpn_list == NULL) {
        return PF_MBEDTLS_ERR_SSL_BAD_INPUT_DATA;
    }

    /*
     * opaque ProtocolName<1..2^8-1>;
     *
     * struct {
     *     ProtocolName protocol_name_list<2..2^16-1>
     * } ProtocolNameList;
     *
     * the "ProtocolNameList" MUST contain exactly one "ProtocolName"
     */

    PF_MBEDTLS_SSL_CHK_BUF_READ_PTR(p, end, 2);
    protocol_name_list_len = PF_MBEDTLS_GET_UINT16_BE(p, 0);
    p += 2;

    PF_MBEDTLS_SSL_CHK_BUF_READ_PTR(p, end, protocol_name_list_len);
    protocol_name_list_end = p + protocol_name_list_len;

    PF_MBEDTLS_SSL_CHK_BUF_READ_PTR(p, protocol_name_list_end, 1);
    protocol_name_len = *p++;

    /* Check that the server chosen protocol was in our list and save it */
    PF_MBEDTLS_SSL_CHK_BUF_READ_PTR(p, protocol_name_list_end, protocol_name_len);
    for (const char **alpn = ssl->conf->alpn_list; *alpn != NULL; alpn++) {
        if (protocol_name_len == strlen(*alpn) &&
            memcmp(p, *alpn, protocol_name_len) == 0) {
            ssl->alpn_chosen = *alpn;
            return 0;
        }
    }

    return PF_MBEDTLS_ERR_SSL_BAD_INPUT_DATA;
}
#endif /* MBEDTLS_SSL_ALPN */

PF_MBEDTLS_CHECK_RETURN_CRITICAL
static int ssl_tls13_reset_key_share(pf_mbedtls_ssl_context *ssl)
{
    uint16_t group_id = ssl->handshake->offered_group_id;

    if (group_id == 0) {
        return PF_MBEDTLS_ERR_SSL_INTERNAL_ERROR;
    }

#if defined(PF_MBEDTLS_SSL_TLS1_3_KEY_EXCHANGE_MODE_SOME_EPHEMERAL_ENABLED)
    if (pf_mbedtls_ssl_tls13_named_group_is_ecdhe(group_id) ||
        pf_mbedtls_ssl_tls13_named_group_is_ffdh(group_id)) {
        int ret = PF_MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
        pf_psa_status_t status = PF_PSA_ERROR_CORRUPTION_DETECTED;

        /* Destroy generated private key. */
        status = pf_psa_destroy_key(ssl->handshake->xxdh_psa_privkey);
        if (status != PF_PSA_SUCCESS) {
            ret = PF_PSA_TO_MBEDTLS_ERR(status);
            PF_MBEDTLS_SSL_DEBUG_RET(1, "psa_destroy_key", ret);
            return ret;
        }

        ssl->handshake->xxdh_psa_privkey = PF_MBEDTLS_SVC_KEY_ID_INIT;
        return 0;
    } else
#endif /* MBEDTLS_SSL_TLS1_3_KEY_EXCHANGE_MODE_SOME_EPHEMERAL_ENABLED */
    if (0 /* other KEMs? */) {
        /* Do something */
    }

    return PF_MBEDTLS_ERR_SSL_INTERNAL_ERROR;
}

/*
 * Functions for writing key_share extension.
 */
#if defined(PF_MBEDTLS_SSL_TLS1_3_KEY_EXCHANGE_MODE_SOME_EPHEMERAL_ENABLED)
PF_MBEDTLS_CHECK_RETURN_CRITICAL
static int ssl_tls13_get_default_group_id(pf_mbedtls_ssl_context *ssl,
                                          uint16_t *group_id)
{
    int ret = PF_MBEDTLS_ERR_SSL_FEATURE_UNAVAILABLE;


#if defined(PF_PSA_WANT_ALG_ECDH) || defined(PF_PSA_WANT_ALG_FFDH)
    const uint16_t *group_list = pf_mbedtls_ssl_get_groups(ssl);
    /* Pick first available ECDHE group compatible with TLS 1.3 */
    if (group_list == NULL) {
        return PF_MBEDTLS_ERR_SSL_BAD_CONFIG;
    }

    for (; *group_list != 0; group_list++) {
#if defined(PF_PSA_WANT_ALG_ECDH)
        if ((pf_mbedtls_ssl_get_psa_curve_info_from_tls_id(
                 *group_list, NULL, NULL) == PF_PSA_SUCCESS) &&
            pf_mbedtls_ssl_tls13_named_group_is_ecdhe(*group_list)) {
            *group_id = *group_list;
            return 0;
        }
#endif
#if defined(PF_PSA_WANT_ALG_FFDH)
        if (pf_mbedtls_ssl_tls13_named_group_is_ffdh(*group_list)) {
            *group_id = *group_list;
            return 0;
        }
#endif
    }
#else
    ((void) ssl);
    ((void) group_id);
#endif /* PSA_WANT_ALG_ECDH || PSA_WANT_ALG_FFDH */

    return ret;
}

/*
 * ssl_tls13_write_key_share_ext
 *
 * Structure of key_share extension in ClientHello:
 *
 *  struct {
 *          NamedGroup group;
 *          opaque key_exchange<1..2^16-1>;
 *      } KeyShareEntry;
 *  struct {
 *          KeyShareEntry client_shares<0..2^16-1>;
 *      } KeyShareClientHello;
 */
PF_MBEDTLS_CHECK_RETURN_CRITICAL
static int ssl_tls13_write_key_share_ext(pf_mbedtls_ssl_context *ssl,
                                         unsigned char *buf,
                                         unsigned char *end,
                                         size_t *out_len)
{
    unsigned char *p = buf;
    unsigned char *client_shares; /* Start of client_shares */
    size_t client_shares_len;     /* Length of client_shares */
    uint16_t group_id;
    int ret = PF_MBEDTLS_ERR_SSL_FEATURE_UNAVAILABLE;

    *out_len = 0;

    /* Check if we have space for header and length fields:
     * - extension_type         (2 bytes)
     * - extension_data_length  (2 bytes)
     * - client_shares_length   (2 bytes)
     */
    PF_MBEDTLS_SSL_CHK_BUF_PTR(p, end, 6);
    p += 6;

    PF_MBEDTLS_SSL_DEBUG_MSG(3, ("client hello: adding key share extension"));

    /* HRR could already have requested something else. */
    group_id = ssl->handshake->offered_group_id;
    if (!pf_mbedtls_ssl_tls13_named_group_is_ecdhe(group_id) &&
        !pf_mbedtls_ssl_tls13_named_group_is_ffdh(group_id)) {
        PF_MBEDTLS_SSL_PROC_CHK(ssl_tls13_get_default_group_id(ssl,
                                                            &group_id));
    }

    /*
     * Dispatch to type-specific key generation function.
     *
     * So far, we're only supporting ECDHE. With the introduction
     * of PQC KEMs, we'll want to have multiple branches, one per
     * type of KEM, and dispatch to the corresponding crypto. And
     * only one key share entry is allowed.
     */
    client_shares = p;
#if defined(PF_PSA_WANT_ALG_ECDH) || defined(PF_PSA_WANT_ALG_FFDH)
    if (pf_mbedtls_ssl_tls13_named_group_is_ecdhe(group_id) ||
        pf_mbedtls_ssl_tls13_named_group_is_ffdh(group_id)) {
        /* Pointer to group */
        unsigned char *group = p;
        /* Length of key_exchange */
        size_t key_exchange_len = 0;

        /* Check there is space for header of KeyShareEntry
         * - group                  (2 bytes)
         * - key_exchange_length    (2 bytes)
         */
        PF_MBEDTLS_SSL_CHK_BUF_PTR(p, end, 4);
        p += 4;
        ret = pf_mbedtls_ssl_tls13_generate_and_write_xxdh_key_exchange(
            ssl, group_id, p, end, &key_exchange_len);
        p += key_exchange_len;
        if (ret != 0) {
            PF_MBEDTLS_SSL_DEBUG_MSG(1, ("client hello: failed generating xxdh key exchange"));
            return ret;
        }

        /* Write group */
        PF_MBEDTLS_PUT_UINT16_BE(group_id, group, 0);
        /* Write key_exchange_length */
        PF_MBEDTLS_PUT_UINT16_BE(key_exchange_len, group, 2);
    } else
#endif /* PSA_WANT_ALG_ECDH || PSA_WANT_ALG_FFDH */
    if (0 /* other KEMs? */) {
        /* Do something */
    } else {
        return PF_MBEDTLS_ERR_SSL_INTERNAL_ERROR;
    }

    /* Length of client_shares */
    client_shares_len = p - client_shares;
    if (client_shares_len == 0) {
        PF_MBEDTLS_SSL_DEBUG_MSG(1, ("No key share defined."));
        return PF_MBEDTLS_ERR_SSL_INTERNAL_ERROR;
    }
    /* Write extension_type */
    PF_MBEDTLS_PUT_UINT16_BE(PF_MBEDTLS_TLS_EXT_KEY_SHARE, buf, 0);
    /* Write extension_data_length */
    PF_MBEDTLS_PUT_UINT16_BE(client_shares_len + 2, buf, 2);
    /* Write client_shares_length */
    PF_MBEDTLS_PUT_UINT16_BE(client_shares_len, buf, 4);

    /* Update offered_group_id field */
    ssl->handshake->offered_group_id = group_id;

    /* Output the total length of key_share extension. */
    *out_len = p - buf;

    PF_MBEDTLS_SSL_DEBUG_BUF(
        3, "client hello, key_share extension", buf, *out_len);

    pf_mbedtls_ssl_tls13_set_hs_sent_ext_mask(ssl, PF_MBEDTLS_TLS_EXT_KEY_SHARE);

cleanup:

    return ret;
}
#endif /* MBEDTLS_SSL_TLS1_3_KEY_EXCHANGE_MODE_SOME_EPHEMERAL_ENABLED */

/*
 * ssl_tls13_parse_hrr_key_share_ext()
 *      Parse key_share extension in Hello Retry Request
 *
 * struct {
 *        NamedGroup selected_group;
 * } KeyShareHelloRetryRequest;
 */
PF_MBEDTLS_CHECK_RETURN_CRITICAL
static int ssl_tls13_parse_hrr_key_share_ext(pf_mbedtls_ssl_context *ssl,
                                             const unsigned char *buf,
                                             const unsigned char *end)
{
#if defined(PF_PSA_WANT_ALG_ECDH) || defined(PF_PSA_WANT_ALG_FFDH)
    const unsigned char *p = buf;
    int selected_group;
    int found = 0;

    const uint16_t *group_list = pf_mbedtls_ssl_get_groups(ssl);
    if (group_list == NULL) {
        return PF_MBEDTLS_ERR_SSL_BAD_CONFIG;
    }

    PF_MBEDTLS_SSL_DEBUG_BUF(3, "key_share extension", p, end - buf);

    /* Read selected_group */
    PF_MBEDTLS_SSL_CHK_BUF_READ_PTR(p, end, 2);
    selected_group = PF_MBEDTLS_GET_UINT16_BE(p, 0);
    PF_MBEDTLS_SSL_DEBUG_MSG(3, ("selected_group ( %d )", selected_group));

    /* Upon receipt of this extension in a HelloRetryRequest, the client
     * MUST first verify that the selected_group field corresponds to a
     * group which was provided in the "supported_groups" extension in the
     * original ClientHello.
     * The supported_group was based on the info in ssl->conf->group_list.
     *
     * If the server provided a key share that was not sent in the ClientHello
     * then the client MUST abort the handshake with an "illegal_parameter" alert.
     */
    for (; *group_list != 0; group_list++) {
        if (*group_list != selected_group) {
            continue;
        }
#if defined(PF_PSA_WANT_ALG_ECDH)
        if (pf_mbedtls_ssl_tls13_named_group_is_ecdhe(*group_list)) {
            if (pf_mbedtls_ssl_get_psa_curve_info_from_tls_id(
                    *group_list, NULL, NULL) == PF_PSA_ERROR_NOT_SUPPORTED) {
                continue;
            }
            /* Found only if psa_curve is supported and group_list == selected_group */
            found = 1;
            break;
        }
#endif /* PSA_WANT_ALG_ECDH */
#if defined(PF_PSA_WANT_ALG_FFDH)
        if (pf_mbedtls_ssl_tls13_named_group_is_ffdh(*group_list)) {
            found = 1;
            break;
        }
#endif /* PSA_WANT_ALG_FFDH */
    }

    /* Client MUST verify that the selected_group field does not
     * correspond to a group which was provided in the "key_share"
     * extension in the original ClientHello. If the server sent an
     * HRR message with a key share already provided in the
     * ClientHello then the client MUST abort the handshake with
     * an "illegal_parameter" alert.
     */
    if (found == 0 || selected_group == ssl->handshake->offered_group_id) {
        PF_MBEDTLS_SSL_DEBUG_MSG(1, ("Invalid key share in HRR"));
        PF_MBEDTLS_SSL_PEND_FATAL_ALERT(
            PF_MBEDTLS_SSL_ALERT_MSG_ILLEGAL_PARAMETER,
            PF_MBEDTLS_ERR_SSL_ILLEGAL_PARAMETER);
        return PF_MBEDTLS_ERR_SSL_ILLEGAL_PARAMETER;
    }

    /* Remember server's preference for next ClientHello */
    ssl->handshake->offered_group_id = selected_group;

    return 0;
#else /* PSA_WANT_ALG_ECDH || PSA_WANT_ALG_FFDH */
    (void) ssl;
    (void) buf;
    (void) end;
    return PF_MBEDTLS_ERR_SSL_BAD_CONFIG;
#endif /* PSA_WANT_ALG_ECDH || PSA_WANT_ALG_FFDH */
}

/*
 * ssl_tls13_parse_key_share_ext()
 *      Parse key_share extension in Server Hello
 *
 * struct {
 *        KeyShareEntry server_share;
 * } KeyShareServerHello;
 * struct {
 *        NamedGroup group;
 *        opaque key_exchange<1..2^16-1>;
 * } KeyShareEntry;
 */
PF_MBEDTLS_CHECK_RETURN_CRITICAL
static int ssl_tls13_parse_key_share_ext(pf_mbedtls_ssl_context *ssl,
                                         const unsigned char *buf,
                                         const unsigned char *end)
{
    int ret = PF_MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    const unsigned char *p = buf;
    uint16_t group, offered_group;

    /* ...
     * NamedGroup group; (2 bytes)
     * ...
     */
    PF_MBEDTLS_SSL_CHK_BUF_READ_PTR(p, end, 2);
    group = PF_MBEDTLS_GET_UINT16_BE(p, 0);
    p += 2;

    /* Check that the chosen group matches the one we offered. */
    offered_group = ssl->handshake->offered_group_id;
    if (offered_group != group) {
        PF_MBEDTLS_SSL_DEBUG_MSG(
            1, ("Invalid server key share, our group %u, their group %u",
                (unsigned) offered_group, (unsigned) group));
        PF_MBEDTLS_SSL_PEND_FATAL_ALERT(PF_MBEDTLS_SSL_ALERT_MSG_HANDSHAKE_FAILURE,
                                     PF_MBEDTLS_ERR_SSL_HANDSHAKE_FAILURE);
        return PF_MBEDTLS_ERR_SSL_HANDSHAKE_FAILURE;
    }

#if defined(PF_MBEDTLS_SSL_TLS1_3_KEY_EXCHANGE_MODE_SOME_EPHEMERAL_ENABLED)
    if (pf_mbedtls_ssl_tls13_named_group_is_ecdhe(group) ||
        pf_mbedtls_ssl_tls13_named_group_is_ffdh(group)) {
        PF_MBEDTLS_SSL_DEBUG_MSG(2,
                              ("DHE group name: %s", pf_mbedtls_ssl_named_group_to_str(group)));
        ret = pf_mbedtls_ssl_tls13_read_public_xxdhe_share(ssl, p, end - p);
        if (ret != 0) {
            return ret;
        }
    } else
#endif /* MBEDTLS_SSL_TLS1_3_KEY_EXCHANGE_MODE_SOME_EPHEMERAL_ENABLED */
    if (0 /* other KEMs? */) {
        /* Do something */
    } else {
        return PF_MBEDTLS_ERR_SSL_INTERNAL_ERROR;
    }

    return ret;
}

/*
 * ssl_tls13_parse_cookie_ext()
 *      Parse cookie extension in Hello Retry Request
 *
 * struct {
 *        opaque cookie<1..2^16-1>;
 * } Cookie;
 *
 * When sending a HelloRetryRequest, the server MAY provide a "cookie"
 * extension to the client (this is an exception to the usual rule that
 * the only extensions that may be sent are those that appear in the
 * ClientHello).  When sending the new ClientHello, the client MUST copy
 * the contents of the extension received in the HelloRetryRequest into
 * a "cookie" extension in the new ClientHello.  Clients MUST NOT use
 * cookies in their initial ClientHello in subsequent connections.
 */
PF_MBEDTLS_CHECK_RETURN_CRITICAL
static int ssl_tls13_parse_cookie_ext(pf_mbedtls_ssl_context *ssl,
                                      const unsigned char *buf,
                                      const unsigned char *end)
{
    uint16_t cookie_len;
    const unsigned char *p = buf;
    pf_mbedtls_ssl_handshake_params *handshake = ssl->handshake;

    /* Retrieve length field of cookie */
    PF_MBEDTLS_SSL_CHK_BUF_READ_PTR(p, end, 2);
    cookie_len = PF_MBEDTLS_GET_UINT16_BE(p, 0);
    p += 2;

    PF_MBEDTLS_SSL_CHK_BUF_READ_PTR(p, end, cookie_len);
    PF_MBEDTLS_SSL_DEBUG_BUF(3, "cookie extension", p, cookie_len);

    pf_mbedtls_free(handshake->cookie);
    handshake->cookie_len = 0;
    handshake->cookie = pf_mbedtls_calloc(1, cookie_len);
    if (handshake->cookie == NULL) {
        PF_MBEDTLS_SSL_DEBUG_MSG(1,
                              ("alloc failed ( %ud bytes )",
                               cookie_len));
        return PF_MBEDTLS_ERR_SSL_ALLOC_FAILED;
    }

    memcpy(handshake->cookie, p, cookie_len);
    handshake->cookie_len = cookie_len;

    return 0;
}

PF_MBEDTLS_CHECK_RETURN_CRITICAL
static int ssl_tls13_write_cookie_ext(pf_mbedtls_ssl_context *ssl,
                                      unsigned char *buf,
                                      unsigned char *end,
                                      size_t *out_len)
{
    unsigned char *p = buf;
    *out_len = 0;
    pf_mbedtls_ssl_handshake_params *handshake = ssl->handshake;

    if (handshake->cookie == NULL) {
        PF_MBEDTLS_SSL_DEBUG_MSG(3, ("no cookie to send; skip extension"));
        return 0;
    }

    PF_MBEDTLS_SSL_DEBUG_BUF(3, "client hello, cookie",
                          handshake->cookie,
                          handshake->cookie_len);

    PF_MBEDTLS_SSL_CHK_BUF_PTR(p, end, handshake->cookie_len + 6);

    PF_MBEDTLS_SSL_DEBUG_MSG(3, ("client hello, adding cookie extension"));

    PF_MBEDTLS_PUT_UINT16_BE(PF_MBEDTLS_TLS_EXT_COOKIE, p, 0);
    PF_MBEDTLS_PUT_UINT16_BE(handshake->cookie_len + 2, p, 2);
    PF_MBEDTLS_PUT_UINT16_BE(handshake->cookie_len, p, 4);
    p += 6;

    /* Cookie */
    memcpy(p, handshake->cookie, handshake->cookie_len);

    *out_len = handshake->cookie_len + 6;

    pf_mbedtls_ssl_tls13_set_hs_sent_ext_mask(ssl, PF_MBEDTLS_TLS_EXT_COOKIE);

    return 0;
}

#if defined(PF_MBEDTLS_SSL_TLS1_3_KEY_EXCHANGE_MODE_SOME_PSK_ENABLED)
/*
 * ssl_tls13_write_psk_key_exchange_modes_ext() structure:
 *
 * enum { psk_ke( 0 ), psk_dhe_ke( 1 ), ( 255 ) } PskKeyExchangeMode;
 *
 * struct {
 *     PskKeyExchangeMode ke_modes<1..255>;
 * } PskKeyExchangeModes;
 */
PF_MBEDTLS_CHECK_RETURN_CRITICAL
static int ssl_tls13_write_psk_key_exchange_modes_ext(pf_mbedtls_ssl_context *ssl,
                                                      unsigned char *buf,
                                                      unsigned char *end,
                                                      size_t *out_len)
{
    unsigned char *p = buf;
    int ke_modes_len = 0;

    ((void) ke_modes_len);
    *out_len = 0;

    /* Skip writing extension if no PSK key exchange mode
     * is enabled in the config.
     */
    if (!pf_mbedtls_ssl_conf_tls13_is_some_psk_enabled(ssl)) {
        PF_MBEDTLS_SSL_DEBUG_MSG(3, ("skip psk_key_exchange_modes extension"));
        return 0;
    }

    /* Require 7 bytes of data, otherwise fail,
     * even if extension might be shorter.
     */
    PF_MBEDTLS_SSL_CHK_BUF_PTR(p, end, 7);
    PF_MBEDTLS_SSL_DEBUG_MSG(
        3, ("client hello, adding psk_key_exchange_modes extension"));

    PF_MBEDTLS_PUT_UINT16_BE(PF_MBEDTLS_TLS_EXT_PSK_KEY_EXCHANGE_MODES, p, 0);

    /* Skip extension length (2 bytes) and
     * ke_modes length (1 byte) for now.
     */
    p += 5;

    if (pf_mbedtls_ssl_conf_tls13_is_psk_ephemeral_enabled(ssl)) {
        *p++ = PF_MBEDTLS_SSL_TLS1_3_PSK_MODE_ECDHE;
        ke_modes_len++;

        PF_MBEDTLS_SSL_DEBUG_MSG(4, ("Adding PSK-ECDHE key exchange mode"));
    }

    if (pf_mbedtls_ssl_conf_tls13_is_psk_enabled(ssl)) {
        *p++ = PF_MBEDTLS_SSL_TLS1_3_PSK_MODE_PURE;
        ke_modes_len++;

        PF_MBEDTLS_SSL_DEBUG_MSG(4, ("Adding pure PSK key exchange mode"));
    }

    /* Now write the extension and ke_modes length */
    PF_MBEDTLS_PUT_UINT16_BE(ke_modes_len + 1, buf, 2);
    buf[4] = ke_modes_len;

    *out_len = p - buf;

    pf_mbedtls_ssl_tls13_set_hs_sent_ext_mask(
        ssl, PF_MBEDTLS_TLS_EXT_PSK_KEY_EXCHANGE_MODES);

    return 0;
}

#if defined(PF_MBEDTLS_SSL_SESSION_TICKETS)
static pf_psa_algorithm_t ssl_tls13_get_ciphersuite_hash_alg(int ciphersuite)
{
    const pf_mbedtls_ssl_ciphersuite_t *ciphersuite_info = NULL;
    ciphersuite_info = pf_mbedtls_ssl_ciphersuite_from_id(ciphersuite);

    if (ciphersuite_info != NULL) {
        return pf_mbedtls_md_psa_alg_from_type((pf_mbedtls_md_type_t) ciphersuite_info->mac);
    }

    return PF_PSA_ALG_NONE;
}

static int ssl_tls13_has_configured_ticket(pf_mbedtls_ssl_context *ssl)
{
    pf_mbedtls_ssl_session *session = ssl->session_negotiate;
    return ssl->handshake->resume &&
           session != NULL && session->ticket != NULL &&
           pf_mbedtls_ssl_conf_tls13_is_kex_mode_enabled(
        ssl, pf_mbedtls_ssl_tls13_session_get_ticket_flags(
            session, PF_MBEDTLS_SSL_TLS1_3_KEY_EXCHANGE_MODE_PSK_ALL));
}

#if defined(PF_MBEDTLS_SSL_EARLY_DATA)
static int ssl_tls13_early_data_has_valid_ticket(pf_mbedtls_ssl_context *ssl)
{
    pf_mbedtls_ssl_session *session = ssl->session_negotiate;
    return ssl->handshake->resume &&
           session->tls_version == PF_MBEDTLS_SSL_VERSION_TLS1_3 &&
           pf_mbedtls_ssl_tls13_session_ticket_allow_early_data(session) &&
           pf_mbedtls_ssl_tls13_cipher_suite_is_offered(ssl, session->ciphersuite);
}
#endif

PF_MBEDTLS_CHECK_RETURN_CRITICAL
static int ssl_tls13_ticket_get_identity(pf_mbedtls_ssl_context *ssl,
                                         pf_psa_algorithm_t *hash_alg,
                                         const unsigned char **identity,
                                         size_t *identity_len)
{
    pf_mbedtls_ssl_session *session = ssl->session_negotiate;

    if (!ssl_tls13_has_configured_ticket(ssl)) {
        return -1;
    }

    *hash_alg = ssl_tls13_get_ciphersuite_hash_alg(session->ciphersuite);
    *identity = session->ticket;
    *identity_len = session->ticket_len;
    return 0;
}

PF_MBEDTLS_CHECK_RETURN_CRITICAL
static int ssl_tls13_ticket_get_psk(pf_mbedtls_ssl_context *ssl,
                                    pf_psa_algorithm_t *hash_alg,
                                    const unsigned char **psk,
                                    size_t *psk_len)
{

    pf_mbedtls_ssl_session *session = ssl->session_negotiate;

    if (!ssl_tls13_has_configured_ticket(ssl)) {
        return -1;
    }

    *hash_alg = ssl_tls13_get_ciphersuite_hash_alg(session->ciphersuite);
    *psk = session->resumption_key;
    *psk_len = session->resumption_key_len;

    return 0;
}
#endif /* MBEDTLS_SSL_SESSION_TICKETS */

PF_MBEDTLS_CHECK_RETURN_CRITICAL
static int ssl_tls13_psk_get_identity(pf_mbedtls_ssl_context *ssl,
                                      pf_psa_algorithm_t *hash_alg,
                                      const unsigned char **identity,
                                      size_t *identity_len)
{

    if (!pf_mbedtls_ssl_conf_has_static_psk(ssl->conf)) {
        return -1;
    }

    *hash_alg = PF_PSA_ALG_SHA_256;
    *identity = ssl->conf->psk_identity;
    *identity_len = ssl->conf->psk_identity_len;
    return 0;
}

PF_MBEDTLS_CHECK_RETURN_CRITICAL
static int ssl_tls13_psk_get_psk(pf_mbedtls_ssl_context *ssl,
                                 pf_psa_algorithm_t *hash_alg,
                                 const unsigned char **psk,
                                 size_t *psk_len)
{

    if (!pf_mbedtls_ssl_conf_has_static_psk(ssl->conf)) {
        return -1;
    }

    *hash_alg = PF_PSA_ALG_SHA_256;
    *psk = ssl->conf->psk;
    *psk_len = ssl->conf->psk_len;
    return 0;
}

static int ssl_tls13_get_configured_psk_count(pf_mbedtls_ssl_context *ssl)
{
    int configured_psk_count = 0;
#if defined(PF_MBEDTLS_SSL_SESSION_TICKETS)
    if (ssl_tls13_has_configured_ticket(ssl)) {
        PF_MBEDTLS_SSL_DEBUG_MSG(3, ("Ticket is configured"));
        configured_psk_count++;
    }
#endif
    if (pf_mbedtls_ssl_conf_has_static_psk(ssl->conf)) {
        PF_MBEDTLS_SSL_DEBUG_MSG(3, ("PSK is configured"));
        configured_psk_count++;
    }
    return configured_psk_count;
}

PF_MBEDTLS_CHECK_RETURN_CRITICAL
static int ssl_tls13_write_identity(pf_mbedtls_ssl_context *ssl,
                                    unsigned char *buf,
                                    unsigned char *end,
                                    const unsigned char *identity,
                                    size_t identity_len,
                                    uint32_t obfuscated_ticket_age,
                                    size_t *out_len)
{
    ((void) ssl);
    *out_len = 0;

    /*
     * - identity_len           (2 bytes)
     * - identity               (psk_identity_len bytes)
     * - obfuscated_ticket_age  (4 bytes)
     */
    PF_MBEDTLS_SSL_CHK_BUF_PTR(buf, end, 6 + identity_len);

    PF_MBEDTLS_PUT_UINT16_BE(identity_len, buf, 0);
    memcpy(buf + 2, identity, identity_len);
    PF_MBEDTLS_PUT_UINT32_BE(obfuscated_ticket_age, buf, 2 + identity_len);

    PF_MBEDTLS_SSL_DEBUG_BUF(4, "write identity", buf, 6 + identity_len);

    *out_len = 6 + identity_len;

    return 0;
}

PF_MBEDTLS_CHECK_RETURN_CRITICAL
static int ssl_tls13_write_binder(pf_mbedtls_ssl_context *ssl,
                                  unsigned char *buf,
                                  unsigned char *end,
                                  int psk_type,
                                  pf_psa_algorithm_t hash_alg,
                                  const unsigned char *psk,
                                  size_t psk_len,
                                  size_t *out_len)
{
    int ret = PF_MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    unsigned char binder_len;
    unsigned char transcript[PF_MBEDTLS_TLS1_3_MD_MAX_SIZE];
    size_t transcript_len = 0;

    *out_len = 0;

    binder_len = PF_PSA_HASH_LENGTH(hash_alg);

    /*
     * - binder_len           (1 bytes)
     * - binder               (binder_len bytes)
     */
    PF_MBEDTLS_SSL_CHK_BUF_PTR(buf, end, 1 + binder_len);

    buf[0] = binder_len;

    /* Get current state of handshake transcript. */
    ret = pf_mbedtls_ssl_get_handshake_transcript(
        ssl, pf_mbedtls_md_type_from_psa_alg(hash_alg),
        transcript, sizeof(transcript), &transcript_len);
    if (ret != 0) {
        return ret;
    }

    ret = pf_mbedtls_ssl_tls13_create_psk_binder(ssl, hash_alg,
                                              psk, psk_len, psk_type,
                                              transcript, buf + 1);
    if (ret != 0) {
        PF_MBEDTLS_SSL_DEBUG_RET(1, "mbedtls_ssl_tls13_create_psk_binder", ret);
        return ret;
    }
    PF_MBEDTLS_SSL_DEBUG_BUF(4, "write binder", buf, 1 + binder_len);

    *out_len = 1 + binder_len;

    return 0;
}

/*
 * mbedtls_ssl_tls13_write_identities_of_pre_shared_key_ext() structure:
 *
 * struct {
 *   opaque identity<1..2^16-1>;
 *   uint32 obfuscated_ticket_age;
 * } PskIdentity;
 *
 * opaque PskBinderEntry<32..255>;
 *
 * struct {
 *   PskIdentity identities<7..2^16-1>;
 *   PskBinderEntry binders<33..2^16-1>;
 * } OfferedPsks;
 *
 * struct {
 *   select (Handshake.msg_type) {
 *      case client_hello: OfferedPsks;
 *      ...
 *   };
 * } PreSharedKeyExtension;
 *
 */
int pf_mbedtls_ssl_tls13_write_identities_of_pre_shared_key_ext(
    pf_mbedtls_ssl_context *ssl, unsigned char *buf, unsigned char *end,
    size_t *out_len, size_t *binders_len)
{
    int ret = PF_MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    int configured_psk_count = 0;
    unsigned char *p = buf;
    pf_psa_algorithm_t hash_alg = PF_PSA_ALG_NONE;
    const unsigned char *identity;
    size_t identity_len;
    size_t l_binders_len = 0;
    size_t output_len;

    *out_len = 0;
    *binders_len = 0;

    /* Check if we have any PSKs to offer. If no, skip pre_shared_key */
    configured_psk_count = ssl_tls13_get_configured_psk_count(ssl);
    if (configured_psk_count == 0) {
        PF_MBEDTLS_SSL_DEBUG_MSG(3, ("skip pre_shared_key extensions"));
        return 0;
    }

    PF_MBEDTLS_SSL_DEBUG_MSG(4, ("Pre-configured PSK number = %d",
                              configured_psk_count));

    /* Check if we have space to write the extension, binders included.
     * - extension_type         (2 bytes)
     * - extension_data_len     (2 bytes)
     * - identities_len         (2 bytes)
     */
    PF_MBEDTLS_SSL_CHK_BUF_PTR(p, end, 6);
    p += 6;

#if defined(PF_MBEDTLS_SSL_SESSION_TICKETS)
    if (ssl_tls13_ticket_get_identity(
            ssl, &hash_alg, &identity, &identity_len) == 0) {
#if defined(PF_MBEDTLS_HAVE_TIME)
        pf_mbedtls_ms_time_t now = pf_mbedtls_ms_time();
        pf_mbedtls_ssl_session *session = ssl->session_negotiate;
        /* The ticket age has been checked to be smaller than the
         * `ticket_lifetime` in ssl_prepare_client_hello() which is smaller than
         * 7 days (enforced in ssl_tls13_parse_new_session_ticket()) . Thus the
         * cast to `uint32_t` of the ticket age is safe. */
        uint32_t obfuscated_ticket_age =
            (uint32_t) (now - session->ticket_reception_time);
        obfuscated_ticket_age += session->ticket_age_add;

        ret = ssl_tls13_write_identity(ssl, p, end,
                                       identity, identity_len,
                                       obfuscated_ticket_age,
                                       &output_len);
#else
        ret = ssl_tls13_write_identity(ssl, p, end, identity, identity_len,
                                       0, &output_len);
#endif /* MBEDTLS_HAVE_TIME */
        if (ret != 0) {
            return ret;
        }

        p += output_len;
        l_binders_len += 1 + PF_PSA_HASH_LENGTH(hash_alg);
    }
#endif /* MBEDTLS_SSL_SESSION_TICKETS */

    if (ssl_tls13_psk_get_identity(
            ssl, &hash_alg, &identity, &identity_len) == 0) {

        ret = ssl_tls13_write_identity(ssl, p, end, identity, identity_len, 0,
                                       &output_len);
        if (ret != 0) {
            return ret;
        }

        p += output_len;
        l_binders_len += 1 + PF_PSA_HASH_LENGTH(hash_alg);
    }

    PF_MBEDTLS_SSL_DEBUG_MSG(3,
                          ("client hello, adding pre_shared_key extension, "
                           "omitting PSK binder list"));

    /* Take into account the two bytes for the length of the binders. */
    l_binders_len += 2;
    /* Check if there is enough space for binders */
    PF_MBEDTLS_SSL_CHK_BUF_PTR(p, end, l_binders_len);

    /*
     * - extension_type         (2 bytes)
     * - extension_data_len     (2 bytes)
     * - identities_len         (2 bytes)
     */
    PF_MBEDTLS_PUT_UINT16_BE(PF_MBEDTLS_TLS_EXT_PRE_SHARED_KEY, buf, 0);
    PF_MBEDTLS_PUT_UINT16_BE(p - buf - 4 + l_binders_len, buf, 2);
    PF_MBEDTLS_PUT_UINT16_BE(p - buf - 6, buf, 4);

    *out_len = (p - buf) + l_binders_len;
    *binders_len = l_binders_len;

    PF_MBEDTLS_SSL_DEBUG_BUF(3, "pre_shared_key identities", buf, p - buf);

    return 0;
}

int pf_mbedtls_ssl_tls13_write_binders_of_pre_shared_key_ext(
    pf_mbedtls_ssl_context *ssl, unsigned char *buf, unsigned char *end)
{
    int ret = PF_MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    unsigned char *p = buf;
    pf_psa_algorithm_t hash_alg = PF_PSA_ALG_NONE;
    const unsigned char *psk;
    size_t psk_len;
    size_t output_len;

    /* Check if we have space to write binders_len.
     * - binders_len         (2 bytes)
     */
    PF_MBEDTLS_SSL_CHK_BUF_PTR(p, end, 2);
    p += 2;

#if defined(PF_MBEDTLS_SSL_SESSION_TICKETS)
    if (ssl_tls13_ticket_get_psk(ssl, &hash_alg, &psk, &psk_len) == 0) {

        ret = ssl_tls13_write_binder(ssl, p, end,
                                     PF_MBEDTLS_SSL_TLS1_3_PSK_RESUMPTION,
                                     hash_alg, psk, psk_len,
                                     &output_len);
        if (ret != 0) {
            return ret;
        }
        p += output_len;
    }
#endif /* MBEDTLS_SSL_SESSION_TICKETS */

    if (ssl_tls13_psk_get_psk(ssl, &hash_alg, &psk, &psk_len) == 0) {

        ret = ssl_tls13_write_binder(ssl, p, end,
                                     PF_MBEDTLS_SSL_TLS1_3_PSK_EXTERNAL,
                                     hash_alg, psk, psk_len,
                                     &output_len);
        if (ret != 0) {
            return ret;
        }
        p += output_len;
    }

    PF_MBEDTLS_SSL_DEBUG_MSG(3, ("client hello, adding PSK binder list."));

    /*
     * - binders_len         (2 bytes)
     */
    PF_MBEDTLS_PUT_UINT16_BE(p - buf - 2, buf, 0);

    PF_MBEDTLS_SSL_DEBUG_BUF(3, "pre_shared_key binders", buf, p - buf);

    pf_mbedtls_ssl_tls13_set_hs_sent_ext_mask(
        ssl, PF_MBEDTLS_TLS_EXT_PRE_SHARED_KEY);

    return 0;
}

/*
 * struct {
 *   opaque identity<1..2^16-1>;
 *   uint32 obfuscated_ticket_age;
 * } PskIdentity;
 *
 * opaque PskBinderEntry<32..255>;
 *
 * struct {
 *
 *   select (Handshake.msg_type) {
 *         ...
 *         case server_hello: uint16 selected_identity;
 *   };
 *
 * } PreSharedKeyExtension;
 *
 */
PF_MBEDTLS_CHECK_RETURN_CRITICAL
static int ssl_tls13_parse_server_pre_shared_key_ext(pf_mbedtls_ssl_context *ssl,
                                                     const unsigned char *buf,
                                                     const unsigned char *end)
{
    int ret = PF_MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    int selected_identity;
    const unsigned char *psk;
    size_t psk_len;
    pf_psa_algorithm_t hash_alg;

    PF_MBEDTLS_SSL_CHK_BUF_READ_PTR(buf, end, 2);
    selected_identity = PF_MBEDTLS_GET_UINT16_BE(buf, 0);
    ssl->handshake->selected_identity = (uint16_t) selected_identity;

    PF_MBEDTLS_SSL_DEBUG_MSG(3, ("selected_identity = %d", selected_identity));

    if (selected_identity >= ssl_tls13_get_configured_psk_count(ssl)) {
        PF_MBEDTLS_SSL_DEBUG_MSG(1, ("Invalid PSK identity."));

        PF_MBEDTLS_SSL_PEND_FATAL_ALERT(PF_MBEDTLS_SSL_ALERT_MSG_ILLEGAL_PARAMETER,
                                     PF_MBEDTLS_ERR_SSL_ILLEGAL_PARAMETER);
        return PF_MBEDTLS_ERR_SSL_ILLEGAL_PARAMETER;
    }

#if defined(PF_MBEDTLS_SSL_SESSION_TICKETS)
    if (selected_identity == 0 && ssl_tls13_has_configured_ticket(ssl)) {
        ret = ssl_tls13_ticket_get_psk(ssl, &hash_alg, &psk, &psk_len);
    } else
#endif
    if (pf_mbedtls_ssl_conf_has_static_psk(ssl->conf)) {
        ret = ssl_tls13_psk_get_psk(ssl, &hash_alg, &psk, &psk_len);
    } else {
        PF_MBEDTLS_SSL_DEBUG_MSG(1, ("should never happen"));
        return PF_MBEDTLS_ERR_SSL_INTERNAL_ERROR;
    }
    if (ret != 0) {
        return ret;
    }

    if (pf_mbedtls_md_psa_alg_from_type((pf_mbedtls_md_type_t) ssl->handshake->ciphersuite_info->mac)
        != hash_alg) {
        PF_MBEDTLS_SSL_DEBUG_MSG(
            1, ("Invalid ciphersuite for external psk."));

        PF_MBEDTLS_SSL_PEND_FATAL_ALERT(PF_MBEDTLS_SSL_ALERT_MSG_ILLEGAL_PARAMETER,
                                     PF_MBEDTLS_ERR_SSL_ILLEGAL_PARAMETER);
        return PF_MBEDTLS_ERR_SSL_ILLEGAL_PARAMETER;
    }

    ret = pf_mbedtls_ssl_set_hs_psk(ssl, psk, psk_len);
    if (ret != 0) {
        PF_MBEDTLS_SSL_DEBUG_RET(1, "mbedtls_ssl_set_hs_psk", ret);
        return ret;
    }

    return 0;
}
#endif /* MBEDTLS_SSL_TLS1_3_KEY_EXCHANGE_MODE_SOME_PSK_ENABLED */

int pf_mbedtls_ssl_tls13_write_client_hello_exts(pf_mbedtls_ssl_context *ssl,
                                              unsigned char *buf,
                                              unsigned char *end,
                                              size_t *out_len)
{
    int ret = PF_MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    unsigned char *p = buf;
    size_t ext_len;

    *out_len = 0;

    ret = pf_mbedtls_ssl_tls13_crypto_init(ssl);
    if (ret != 0) {
        return ret;
    }

    /* Write supported_versions extension
     *
     * Supported Versions Extension is mandatory with TLS 1.3.
     */
    ret = ssl_tls13_write_supported_versions_ext(ssl, p, end, &ext_len);
    if (ret != 0) {
        return ret;
    }
    p += ext_len;

    /* Echo the cookie if the server provided one in its preceding
     * HelloRetryRequest message.
     */
    ret = ssl_tls13_write_cookie_ext(ssl, p, end, &ext_len);
    if (ret != 0) {
        return ret;
    }
    p += ext_len;

#if defined(PF_MBEDTLS_SSL_RECORD_SIZE_LIMIT)
    ret = pf_mbedtls_ssl_tls13_write_record_size_limit_ext(
        ssl, p, end, &ext_len);
    if (ret != 0) {
        return ret;
    }
    p += ext_len;
#endif

#if defined(PF_MBEDTLS_SSL_TLS1_3_KEY_EXCHANGE_MODE_SOME_EPHEMERAL_ENABLED)
    if (pf_mbedtls_ssl_conf_tls13_is_some_ephemeral_enabled(ssl)) {
        ret = ssl_tls13_write_key_share_ext(ssl, p, end, &ext_len);
        if (ret != 0) {
            return ret;
        }
        p += ext_len;
    }
#endif

#if defined(PF_MBEDTLS_SSL_EARLY_DATA)
    /* In the first ClientHello, write the early data indication extension if
     * necessary and update the early data state.
     * If an HRR has been received and thus we are currently writing the
     * second ClientHello, the second ClientHello must not contain an early
     * data extension and the early data state must stay as it is:
     * MBEDTLS_SSL_EARLY_DATA_STATE_NO_IND_SENT or
     * MBEDTLS_SSL_EARLY_DATA_STATE_REJECTED.
     */
    if (!ssl->handshake->hello_retry_request_flag) {
        if (pf_mbedtls_ssl_conf_tls13_is_some_psk_enabled(ssl) &&
            ssl_tls13_early_data_has_valid_ticket(ssl) &&
            ssl->conf->early_data_enabled == PF_MBEDTLS_SSL_EARLY_DATA_ENABLED) {
            ret = pf_mbedtls_ssl_tls13_write_early_data_ext(
                ssl, 0, p, end, &ext_len);
            if (ret != 0) {
                return ret;
            }
            p += ext_len;

            ssl->early_data_state = PF_MBEDTLS_SSL_EARLY_DATA_STATE_IND_SENT;
        } else {
            ssl->early_data_state = PF_MBEDTLS_SSL_EARLY_DATA_STATE_NO_IND_SENT;
        }
    }
#endif /* MBEDTLS_SSL_EARLY_DATA */

#if defined(PF_MBEDTLS_SSL_TLS1_3_KEY_EXCHANGE_MODE_SOME_PSK_ENABLED)
    /* For PSK-based key exchange we need the pre_shared_key extension
     * and the psk_key_exchange_modes extension.
     *
     * The pre_shared_key extension MUST be the last extension in the
     * ClientHello. Servers MUST check that it is the last extension and
     * otherwise fail the handshake with an "illegal_parameter" alert.
     *
     * Add the psk_key_exchange_modes extension.
     */
    ret = ssl_tls13_write_psk_key_exchange_modes_ext(ssl, p, end, &ext_len);
    if (ret != 0) {
        return ret;
    }
    p += ext_len;
#endif

    *out_len = p - buf;

    return 0;
}

int pf_mbedtls_ssl_tls13_finalize_client_hello(pf_mbedtls_ssl_context *ssl)
{
    ((void) ssl);

#if defined(PF_MBEDTLS_SSL_EARLY_DATA)
    int ret = PF_MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    pf_psa_algorithm_t hash_alg = PF_PSA_ALG_NONE;
    const unsigned char *psk;
    size_t psk_len;
    const pf_mbedtls_ssl_ciphersuite_t *ciphersuite_info;

    if (ssl->early_data_state == PF_MBEDTLS_SSL_EARLY_DATA_STATE_IND_SENT) {
        PF_MBEDTLS_SSL_DEBUG_MSG(
            1, ("Set hs psk for early data when writing the first psk"));

        ret = ssl_tls13_ticket_get_psk(ssl, &hash_alg, &psk, &psk_len);
        if (ret != 0) {
            PF_MBEDTLS_SSL_DEBUG_RET(
                1, "ssl_tls13_ticket_get_psk", ret);
            return ret;
        }

        ret = pf_mbedtls_ssl_set_hs_psk(ssl, psk, psk_len);
        if (ret  != 0) {
            PF_MBEDTLS_SSL_DEBUG_RET(1, "mbedtls_ssl_set_hs_psk", ret);
            return ret;
        }

        /*
         * Early data are going to be encrypted using the ciphersuite
         * associated with the pre-shared key used for the handshake.
         * Note that if the server rejects early data, the handshake
         * based on the pre-shared key may complete successfully
         * with a selected ciphersuite different from the ciphersuite
         * associated with the pre-shared key. Only the hashes of the
         * two ciphersuites have to be the same. In that case, the
         * encrypted handshake data and application data are
         * encrypted using a different ciphersuite than the one used for
         * the rejected early data.
         */
        ciphersuite_info = pf_mbedtls_ssl_ciphersuite_from_id(
            ssl->session_negotiate->ciphersuite);
        ssl->handshake->ciphersuite_info = ciphersuite_info;

        /* Enable psk and psk_ephemeral to make stage early happy */
        ssl->handshake->key_exchange_mode =
            PF_MBEDTLS_SSL_TLS1_3_KEY_EXCHANGE_MODE_PSK_ALL;

        /* Start the TLS 1.3 key schedule:
         *     Set the PSK and derive early secret.
         */
        ret = pf_mbedtls_ssl_tls13_key_schedule_stage_early(ssl);
        if (ret != 0) {
            PF_MBEDTLS_SSL_DEBUG_RET(
                1, "mbedtls_ssl_tls13_key_schedule_stage_early", ret);
            return ret;
        }

        /* Derive early data key material */
        ret = pf_mbedtls_ssl_tls13_compute_early_transform(ssl);
        if (ret != 0) {
            PF_MBEDTLS_SSL_DEBUG_RET(
                1, "mbedtls_ssl_tls13_compute_early_transform", ret);
            return ret;
        }

#if defined(PF_MBEDTLS_SSL_TLS1_3_COMPATIBILITY_MODE)
        pf_mbedtls_ssl_handshake_set_state(
            ssl, PF_MBEDTLS_SSL_CLIENT_CCS_AFTER_CLIENT_HELLO);
#else
        PF_MBEDTLS_SSL_DEBUG_MSG(
            1, ("Switch to early data keys for outbound traffic"));
        pf_mbedtls_ssl_set_outbound_transform(
            ssl, ssl->handshake->transform_earlydata);
        ssl->early_data_state = PF_MBEDTLS_SSL_EARLY_DATA_STATE_CAN_WRITE;
#endif
    }
#endif /* MBEDTLS_SSL_EARLY_DATA */
    return 0;
}
/*
 * Functions for parsing and processing Server Hello
 */

/**
 * \brief Detect if the ServerHello contains a supported_versions extension
 *        or not.
 *
 * \param[in] ssl  SSL context
 * \param[in] buf  Buffer containing the ServerHello message
 * \param[in] end  End of the buffer containing the ServerHello message
 *
 * \return 0 if the ServerHello does not contain a supported_versions extension
 * \return 1 if the ServerHello contains a supported_versions extension
 * \return A negative value if an error occurred while parsing the ServerHello.
 */
PF_MBEDTLS_CHECK_RETURN_CRITICAL
static int ssl_tls13_is_supported_versions_ext_present(
    pf_mbedtls_ssl_context *ssl,
    const unsigned char *buf,
    const unsigned char *end)
{
    const unsigned char *p = buf;
    size_t legacy_session_id_echo_len;
    const unsigned char *supported_versions_data;
    const unsigned char *supported_versions_data_end;

    /*
     * Check there is enough data to access the legacy_session_id_echo vector
     * length:
     * - legacy_version                 2 bytes
     * - random                         MBEDTLS_SERVER_HELLO_RANDOM_LEN bytes
     * - legacy_session_id_echo length  1 byte
     */
    PF_MBEDTLS_SSL_CHK_BUF_READ_PTR(p, end, PF_MBEDTLS_SERVER_HELLO_RANDOM_LEN + 3);
    p += PF_MBEDTLS_SERVER_HELLO_RANDOM_LEN + 2;
    legacy_session_id_echo_len = *p;

    /*
     * Jump to the extensions, jumping over:
     * - legacy_session_id_echo     (legacy_session_id_echo_len + 1) bytes
     * - cipher_suite               2 bytes
     * - legacy_compression_method  1 byte
     */
    PF_MBEDTLS_SSL_CHK_BUF_READ_PTR(p, end, legacy_session_id_echo_len + 4);
    p += legacy_session_id_echo_len + 4;

    return pf_mbedtls_ssl_tls13_is_supported_versions_ext_present_in_exts(
        ssl, p, end,
        &supported_versions_data, &supported_versions_data_end);
}

/* Returns a negative value on failure, and otherwise
 * - 1 if the last eight bytes of the ServerHello random bytes indicate that
 *     the server is TLS 1.3 capable but negotiating TLS 1.2 or below.
 * - 0 otherwise
 */
PF_MBEDTLS_CHECK_RETURN_CRITICAL
static int ssl_tls13_is_downgrade_negotiation(pf_mbedtls_ssl_context *ssl,
                                              const unsigned char *buf,
                                              const unsigned char *end)
{
    /* First seven bytes of the magic downgrade strings, see RFC 8446 4.1.3 */
    static const unsigned char magic_downgrade_string[] =
    { 0x44, 0x4F, 0x57, 0x4E, 0x47, 0x52, 0x44 };
    const unsigned char *last_eight_bytes_of_random;
    unsigned char last_byte_of_random;

    PF_MBEDTLS_SSL_CHK_BUF_READ_PTR(buf, end, PF_MBEDTLS_SERVER_HELLO_RANDOM_LEN + 2);
    last_eight_bytes_of_random = buf + 2 + PF_MBEDTLS_SERVER_HELLO_RANDOM_LEN - 8;

    if (memcmp(last_eight_bytes_of_random,
               magic_downgrade_string,
               sizeof(magic_downgrade_string)) == 0) {
        last_byte_of_random = last_eight_bytes_of_random[7];
        return last_byte_of_random == 0 ||
               last_byte_of_random == 1;
    }

    return 0;
}

/* Returns a negative value on failure, and otherwise
 * - SSL_SERVER_HELLO or
 * - SSL_SERVER_HELLO_HRR
 * to indicate which message is expected and to be parsed next.
 */
#define SSL_SERVER_HELLO 0
#define SSL_SERVER_HELLO_HRR 1
PF_MBEDTLS_CHECK_RETURN_CRITICAL
static int ssl_server_hello_is_hrr(pf_mbedtls_ssl_context *ssl,
                                   const unsigned char *buf,
                                   const unsigned char *end)
{

    /* Check whether this message is a HelloRetryRequest ( HRR ) message.
     *
     * Server Hello and HRR are only distinguished by Random set to the
     * special value of the SHA-256 of "HelloRetryRequest".
     *
     * struct {
     *    ProtocolVersion legacy_version = 0x0303;
     *    Random random;
     *    opaque legacy_session_id_echo<0..32>;
     *    CipherSuite cipher_suite;
     *    uint8 legacy_compression_method = 0;
     *    Extension extensions<6..2^16-1>;
     * } ServerHello;
     *
     */
    PF_MBEDTLS_SSL_CHK_BUF_READ_PTR(
        buf, end, 2 + sizeof(pf_mbedtls_ssl_tls13_hello_retry_request_magic));

    if (memcmp(buf + 2, pf_mbedtls_ssl_tls13_hello_retry_request_magic,
               sizeof(pf_mbedtls_ssl_tls13_hello_retry_request_magic)) == 0) {
        return SSL_SERVER_HELLO_HRR;
    }

    return SSL_SERVER_HELLO;
}

/*
 * Returns a negative value on failure, and otherwise
 * - SSL_SERVER_HELLO or
 * - SSL_SERVER_HELLO_HRR or
 * - SSL_SERVER_HELLO_TLS1_2
 */
#define SSL_SERVER_HELLO_TLS1_2 2
PF_MBEDTLS_CHECK_RETURN_CRITICAL
static int ssl_tls13_preprocess_server_hello(pf_mbedtls_ssl_context *ssl,
                                             const unsigned char *buf,
                                             const unsigned char *end)
{
    int ret = PF_MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    pf_mbedtls_ssl_handshake_params *handshake = ssl->handshake;

    PF_MBEDTLS_SSL_PROC_CHK_NEG(ssl_tls13_is_supported_versions_ext_present(
                                 ssl, buf, end));

    if (ret == 0) {
        PF_MBEDTLS_SSL_PROC_CHK_NEG(
            ssl_tls13_is_downgrade_negotiation(ssl, buf, end));

        /* If the server is negotiating TLS 1.2 or below and:
         * . we did not propose TLS 1.2 or
         * . the server responded it is TLS 1.3 capable but negotiating a lower
         *   version of the protocol and thus we are under downgrade attack
         * abort the handshake with an "illegal parameter" alert.
         */
        if (handshake->min_tls_version > PF_MBEDTLS_SSL_VERSION_TLS1_2 || ret) {
            PF_MBEDTLS_SSL_PEND_FATAL_ALERT(PF_MBEDTLS_SSL_ALERT_MSG_ILLEGAL_PARAMETER,
                                         PF_MBEDTLS_ERR_SSL_ILLEGAL_PARAMETER);
            return PF_MBEDTLS_ERR_SSL_ILLEGAL_PARAMETER;
        }

        /*
         * Version 1.2 of the protocol has been negotiated, set the
         * ssl->keep_current_message flag for the ServerHello to be kept and
         * parsed as a TLS 1.2 ServerHello. We also change ssl->tls_version to
         * MBEDTLS_SSL_VERSION_TLS1_2 thus from now on mbedtls_ssl_handshake_step()
         * will dispatch to the TLS 1.2 state machine.
         */
        ssl->keep_current_message = 1;
        ssl->tls_version = PF_MBEDTLS_SSL_VERSION_TLS1_2;
        PF_MBEDTLS_SSL_PROC_CHK(pf_mbedtls_ssl_add_hs_msg_to_checksum(
                                 ssl, PF_MBEDTLS_SSL_HS_SERVER_HELLO,
                                 buf, (size_t) (end - buf)));

        if (pf_mbedtls_ssl_conf_tls13_is_some_ephemeral_enabled(ssl)) {
            ret = ssl_tls13_reset_key_share(ssl);
            if (ret != 0) {
                return ret;
            }
        }

        return SSL_SERVER_HELLO_TLS1_2;
    }

    ssl->session_negotiate->tls_version = ssl->tls_version;
    ssl->session_negotiate->endpoint = ssl->conf->endpoint;

    handshake->received_extensions = PF_MBEDTLS_SSL_EXT_MASK_NONE;

    ret = ssl_server_hello_is_hrr(ssl, buf, end);
    switch (ret) {
        case SSL_SERVER_HELLO:
            PF_MBEDTLS_SSL_DEBUG_MSG(2, ("received ServerHello message"));
            break;
        case SSL_SERVER_HELLO_HRR:
            PF_MBEDTLS_SSL_DEBUG_MSG(2, ("received HelloRetryRequest message"));
            /* If a client receives a second HelloRetryRequest in the same
             * connection (i.e., where the ClientHello was itself in response
             * to a HelloRetryRequest), it MUST abort the handshake with an
             * "unexpected_message" alert.
             */
            if (handshake->hello_retry_request_flag) {
                PF_MBEDTLS_SSL_DEBUG_MSG(1, ("Multiple HRRs received"));
                PF_MBEDTLS_SSL_PEND_FATAL_ALERT(
                    PF_MBEDTLS_SSL_ALERT_MSG_UNEXPECTED_MESSAGE,
                    PF_MBEDTLS_ERR_SSL_UNEXPECTED_MESSAGE);
                return PF_MBEDTLS_ERR_SSL_UNEXPECTED_MESSAGE;
            }
            /*
             * Clients must abort the handshake with an "illegal_parameter"
             * alert if the HelloRetryRequest would not result in any change
             * in the ClientHello.
             * In a PSK only key exchange that what we expect.
             */
            if (!pf_mbedtls_ssl_conf_tls13_is_some_ephemeral_enabled(ssl)) {
                PF_MBEDTLS_SSL_DEBUG_MSG(1,
                                      ("Unexpected HRR in pure PSK key exchange."));
                PF_MBEDTLS_SSL_PEND_FATAL_ALERT(
                    PF_MBEDTLS_SSL_ALERT_MSG_ILLEGAL_PARAMETER,
                    PF_MBEDTLS_ERR_SSL_ILLEGAL_PARAMETER);
                return PF_MBEDTLS_ERR_SSL_ILLEGAL_PARAMETER;
            }

            handshake->hello_retry_request_flag = 1;

            break;
    }

cleanup:

    return ret;
}

PF_MBEDTLS_CHECK_RETURN_CRITICAL
static int ssl_tls13_check_server_hello_session_id_echo(pf_mbedtls_ssl_context *ssl,
                                                        const unsigned char **buf,
                                                        const unsigned char *end)
{
    const unsigned char *p = *buf;
    size_t legacy_session_id_echo_len;

    PF_MBEDTLS_SSL_CHK_BUF_READ_PTR(p, end, 1);
    legacy_session_id_echo_len = *p++;

    PF_MBEDTLS_SSL_CHK_BUF_READ_PTR(p, end, legacy_session_id_echo_len);

    /* legacy_session_id_echo */
    if (ssl->session_negotiate->id_len != legacy_session_id_echo_len ||
        memcmp(ssl->session_negotiate->id, p, legacy_session_id_echo_len) != 0) {
        PF_MBEDTLS_SSL_DEBUG_BUF(3, "Expected Session ID",
                              ssl->session_negotiate->id,
                              ssl->session_negotiate->id_len);
        PF_MBEDTLS_SSL_DEBUG_BUF(3, "Received Session ID", p,
                              legacy_session_id_echo_len);

        PF_MBEDTLS_SSL_PEND_FATAL_ALERT(PF_MBEDTLS_SSL_ALERT_MSG_ILLEGAL_PARAMETER,
                                     PF_MBEDTLS_ERR_SSL_ILLEGAL_PARAMETER);

        return PF_MBEDTLS_ERR_SSL_ILLEGAL_PARAMETER;
    }

    p += legacy_session_id_echo_len;
    *buf = p;

    PF_MBEDTLS_SSL_DEBUG_BUF(3, "Session ID", ssl->session_negotiate->id,
                          ssl->session_negotiate->id_len);
    return 0;
}

/* Parse ServerHello message and configure context
 *
 * struct {
 *    ProtocolVersion legacy_version = 0x0303; // TLS 1.2
 *    Random random;
 *    opaque legacy_session_id_echo<0..32>;
 *    CipherSuite cipher_suite;
 *    uint8 legacy_compression_method = 0;
 *    Extension extensions<6..2^16-1>;
 * } ServerHello;
 */
PF_MBEDTLS_CHECK_RETURN_CRITICAL
static int ssl_tls13_parse_server_hello(pf_mbedtls_ssl_context *ssl,
                                        const unsigned char *buf,
                                        const unsigned char *end,
                                        int is_hrr)
{
    int ret = PF_MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    const unsigned char *p = buf;
    pf_mbedtls_ssl_handshake_params *handshake = ssl->handshake;
    size_t extensions_len;
    const unsigned char *extensions_end;
    uint16_t cipher_suite;
    const pf_mbedtls_ssl_ciphersuite_t *ciphersuite_info;
    int fatal_alert = 0;
    uint32_t allowed_extensions_mask;
    int hs_msg_type = is_hrr ? PF_MBEDTLS_SSL_TLS1_3_HS_HELLO_RETRY_REQUEST :
                      PF_MBEDTLS_SSL_HS_SERVER_HELLO;

    /*
     * Check there is space for minimal fields
     *
     * - legacy_version             ( 2 bytes)
     * - random                     (MBEDTLS_SERVER_HELLO_RANDOM_LEN bytes)
     * - legacy_session_id_echo     ( 1 byte ), minimum size
     * - cipher_suite               ( 2 bytes)
     * - legacy_compression_method  ( 1 byte )
     */
    PF_MBEDTLS_SSL_CHK_BUF_READ_PTR(p, end, PF_MBEDTLS_SERVER_HELLO_RANDOM_LEN + 6);

    PF_MBEDTLS_SSL_DEBUG_BUF(4, "server hello", p, end - p);
    PF_MBEDTLS_SSL_DEBUG_BUF(3, "server hello, version", p, 2);

    /* ...
     * ProtocolVersion legacy_version = 0x0303; // TLS 1.2
     * ...
     * with ProtocolVersion defined as:
     * uint16 ProtocolVersion;
     */
    if (pf_mbedtls_ssl_read_version(p, ssl->conf->transport) !=
        PF_MBEDTLS_SSL_VERSION_TLS1_2) {
        PF_MBEDTLS_SSL_DEBUG_MSG(1, ("Unsupported version of TLS."));
        PF_MBEDTLS_SSL_PEND_FATAL_ALERT(PF_MBEDTLS_SSL_ALERT_MSG_PROTOCOL_VERSION,
                                     PF_MBEDTLS_ERR_SSL_BAD_PROTOCOL_VERSION);
        ret = PF_MBEDTLS_ERR_SSL_BAD_PROTOCOL_VERSION;
        goto cleanup;
    }
    p += 2;

    /* ...
     * Random random;
     * ...
     * with Random defined as:
     * opaque Random[MBEDTLS_SERVER_HELLO_RANDOM_LEN];
     */
    if (!is_hrr) {
        memcpy(&handshake->randbytes[PF_MBEDTLS_CLIENT_HELLO_RANDOM_LEN], p,
               PF_MBEDTLS_SERVER_HELLO_RANDOM_LEN);
        PF_MBEDTLS_SSL_DEBUG_BUF(3, "server hello, random bytes",
                              p, PF_MBEDTLS_SERVER_HELLO_RANDOM_LEN);
    }
    p += PF_MBEDTLS_SERVER_HELLO_RANDOM_LEN;

    /* ...
     * opaque legacy_session_id_echo<0..32>;
     * ...
     */
    if (ssl_tls13_check_server_hello_session_id_echo(ssl, &p, end) != 0) {
        fatal_alert = PF_MBEDTLS_SSL_ALERT_MSG_ILLEGAL_PARAMETER;
        goto cleanup;
    }

    /* ...
     * CipherSuite cipher_suite;
     * ...
     * with CipherSuite defined as:
     * uint8 CipherSuite[2];
     */
    PF_MBEDTLS_SSL_CHK_BUF_READ_PTR(p, end, 2);
    cipher_suite = PF_MBEDTLS_GET_UINT16_BE(p, 0);
    p += 2;


    ciphersuite_info = pf_mbedtls_ssl_ciphersuite_from_id(cipher_suite);
    /*
     * Check whether this ciphersuite is valid and offered.
     */
    if ((pf_mbedtls_ssl_validate_ciphersuite(ssl, ciphersuite_info,
                                          ssl->tls_version,
                                          ssl->tls_version) != 0) ||
        !pf_mbedtls_ssl_tls13_cipher_suite_is_offered(ssl, cipher_suite)) {
        fatal_alert = PF_MBEDTLS_SSL_ALERT_MSG_ILLEGAL_PARAMETER;
    }
    /*
     * If we received an HRR before and that the proposed selected
     * ciphersuite in this server hello is not the same as the one
     * proposed in the HRR, we abort the handshake and send an
     * "illegal_parameter" alert.
     */
    else if ((!is_hrr) && handshake->hello_retry_request_flag &&
             (cipher_suite != ssl->session_negotiate->ciphersuite)) {
        fatal_alert = PF_MBEDTLS_SSL_ALERT_MSG_ILLEGAL_PARAMETER;
    }

    if (fatal_alert == PF_MBEDTLS_SSL_ALERT_MSG_ILLEGAL_PARAMETER) {
        PF_MBEDTLS_SSL_DEBUG_MSG(1, ("invalid ciphersuite(%04x) parameter",
                                  cipher_suite));
        goto cleanup;
    }

    /* Configure ciphersuites */
    pf_mbedtls_ssl_optimize_checksum(ssl, ciphersuite_info);

    handshake->ciphersuite_info = ciphersuite_info;
    PF_MBEDTLS_SSL_DEBUG_MSG(3, ("server hello, chosen ciphersuite: ( %04x ) - %s",
                              cipher_suite, ciphersuite_info->name));

#if defined(PF_MBEDTLS_HAVE_TIME)
    ssl->session_negotiate->start = pf_mbedtls_time(NULL);
#endif /* MBEDTLS_HAVE_TIME */

    /* ...
     * uint8 legacy_compression_method = 0;
     * ...
     */
    PF_MBEDTLS_SSL_CHK_BUF_READ_PTR(p, end, 1);
    if (p[0] != PF_MBEDTLS_SSL_COMPRESS_NULL) {
        PF_MBEDTLS_SSL_DEBUG_MSG(1, ("bad legacy compression method"));
        fatal_alert = PF_MBEDTLS_SSL_ALERT_MSG_ILLEGAL_PARAMETER;
        goto cleanup;
    }
    p++;

    /* ...
     * Extension extensions<6..2^16-1>;
     * ...
     * struct {
     *      ExtensionType extension_type; (2 bytes)
     *      opaque extension_data<0..2^16-1>;
     * } Extension;
     */
    PF_MBEDTLS_SSL_CHK_BUF_READ_PTR(p, end, 2);
    extensions_len = PF_MBEDTLS_GET_UINT16_BE(p, 0);
    p += 2;

    /* Check extensions do not go beyond the buffer of data. */
    PF_MBEDTLS_SSL_CHK_BUF_READ_PTR(p, end, extensions_len);
    extensions_end = p + extensions_len;

    PF_MBEDTLS_SSL_DEBUG_BUF(3, "server hello extensions", p, extensions_len);

    handshake->received_extensions = PF_MBEDTLS_SSL_EXT_MASK_NONE;
    allowed_extensions_mask = is_hrr ?
                              PF_MBEDTLS_SSL_TLS1_3_ALLOWED_EXTS_OF_HRR :
                              PF_MBEDTLS_SSL_TLS1_3_ALLOWED_EXTS_OF_SH;

    while (p < extensions_end) {
        unsigned int extension_type;
        size_t extension_data_len;
        const unsigned char *extension_data_end;

        PF_MBEDTLS_SSL_CHK_BUF_READ_PTR(p, extensions_end, 4);
        extension_type = PF_MBEDTLS_GET_UINT16_BE(p, 0);
        extension_data_len = PF_MBEDTLS_GET_UINT16_BE(p, 2);
        p += 4;

        PF_MBEDTLS_SSL_CHK_BUF_READ_PTR(p, extensions_end, extension_data_len);
        extension_data_end = p + extension_data_len;

        ret = pf_mbedtls_ssl_tls13_check_received_extension(
            ssl, hs_msg_type, extension_type, allowed_extensions_mask);
        if (ret != 0) {
            return ret;
        }

        switch (extension_type) {
            case PF_MBEDTLS_TLS_EXT_COOKIE:

                ret = ssl_tls13_parse_cookie_ext(ssl,
                                                 p, extension_data_end);
                if (ret != 0) {
                    PF_MBEDTLS_SSL_DEBUG_RET(1,
                                          "ssl_tls13_parse_cookie_ext",
                                          ret);
                    goto cleanup;
                }
                break;

            case PF_MBEDTLS_TLS_EXT_SUPPORTED_VERSIONS:
                ret = ssl_tls13_parse_supported_versions_ext(ssl,
                                                             p,
                                                             extension_data_end);
                if (ret != 0) {
                    goto cleanup;
                }
                break;

#if defined(PF_MBEDTLS_SSL_TLS1_3_KEY_EXCHANGE_MODE_SOME_PSK_ENABLED)
            case PF_MBEDTLS_TLS_EXT_PRE_SHARED_KEY:
                PF_MBEDTLS_SSL_DEBUG_MSG(3, ("found pre_shared_key extension"));

                if ((ret = ssl_tls13_parse_server_pre_shared_key_ext(
                         ssl, p, extension_data_end)) != 0) {
                    PF_MBEDTLS_SSL_DEBUG_RET(
                        1, ("ssl_tls13_parse_server_pre_shared_key_ext"), ret);
                    return ret;
                }
                break;
#endif

            case PF_MBEDTLS_TLS_EXT_KEY_SHARE:
                PF_MBEDTLS_SSL_DEBUG_MSG(3, ("found key_shares extension"));
                if (!pf_mbedtls_ssl_conf_tls13_is_some_ephemeral_enabled(ssl)) {
                    fatal_alert = PF_MBEDTLS_SSL_ALERT_MSG_UNSUPPORTED_EXT;
                    goto cleanup;
                }

                if (is_hrr) {
                    ret = ssl_tls13_parse_hrr_key_share_ext(ssl,
                                                            p, extension_data_end);
                } else {
                    ret = ssl_tls13_parse_key_share_ext(ssl,
                                                        p, extension_data_end);
                }
                if (ret != 0) {
                    PF_MBEDTLS_SSL_DEBUG_RET(1,
                                          "ssl_tls13_parse_key_share_ext",
                                          ret);
                    goto cleanup;
                }
                break;

            default:
                ret = PF_MBEDTLS_ERR_SSL_INTERNAL_ERROR;
                goto cleanup;
        }

        p += extension_data_len;
    }

    PF_MBEDTLS_SSL_PRINT_EXTS(3, hs_msg_type, handshake->received_extensions);

cleanup:

    if (fatal_alert == PF_MBEDTLS_SSL_ALERT_MSG_UNSUPPORTED_EXT) {
        PF_MBEDTLS_SSL_PEND_FATAL_ALERT(PF_MBEDTLS_SSL_ALERT_MSG_UNSUPPORTED_EXT,
                                     PF_MBEDTLS_ERR_SSL_UNSUPPORTED_EXTENSION);
        ret = PF_MBEDTLS_ERR_SSL_UNSUPPORTED_EXTENSION;
    } else if (fatal_alert == PF_MBEDTLS_SSL_ALERT_MSG_ILLEGAL_PARAMETER) {
        PF_MBEDTLS_SSL_PEND_FATAL_ALERT(PF_MBEDTLS_SSL_ALERT_MSG_ILLEGAL_PARAMETER,
                                     PF_MBEDTLS_ERR_SSL_ILLEGAL_PARAMETER);
        ret = PF_MBEDTLS_ERR_SSL_ILLEGAL_PARAMETER;
    }
    return ret;
}

#if defined(PF_MBEDTLS_DEBUG_C)
static const char *ssl_tls13_get_kex_mode_str(int mode)
{
    switch (mode) {
        case PF_MBEDTLS_SSL_TLS1_3_KEY_EXCHANGE_MODE_PSK:
            return "psk";
        case PF_MBEDTLS_SSL_TLS1_3_KEY_EXCHANGE_MODE_EPHEMERAL:
            return "ephemeral";
        case PF_MBEDTLS_SSL_TLS1_3_KEY_EXCHANGE_MODE_PSK_EPHEMERAL:
            return "psk_ephemeral";
        default:
            return "unknown mode";
    }
}
#endif /* MBEDTLS_DEBUG_C */

PF_MBEDTLS_CHECK_RETURN_CRITICAL
static int ssl_tls13_postprocess_server_hello(pf_mbedtls_ssl_context *ssl)
{
    int ret = PF_MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    pf_mbedtls_ssl_handshake_params *handshake = ssl->handshake;

    /* Determine the key exchange mode:
     * 1) If both the pre_shared_key and key_share extensions were received
     *    then the key exchange mode is PSK with EPHEMERAL.
     * 2) If only the pre_shared_key extension was received then the key
     *    exchange mode is PSK-only.
     * 3) If only the key_share extension was received then the key
     *    exchange mode is EPHEMERAL-only.
     */
    switch (handshake->received_extensions &
            (PF_MBEDTLS_SSL_EXT_MASK(PRE_SHARED_KEY) |
             PF_MBEDTLS_SSL_EXT_MASK(KEY_SHARE))) {
        /* Only the pre_shared_key extension was received */
        case PF_MBEDTLS_SSL_EXT_MASK(PRE_SHARED_KEY):
            handshake->key_exchange_mode =
                PF_MBEDTLS_SSL_TLS1_3_KEY_EXCHANGE_MODE_PSK;
            break;

        /* Only the key_share extension was received */
        case PF_MBEDTLS_SSL_EXT_MASK(KEY_SHARE):
            handshake->key_exchange_mode =
                PF_MBEDTLS_SSL_TLS1_3_KEY_EXCHANGE_MODE_EPHEMERAL;
            break;

        /* Both the pre_shared_key and key_share extensions were received */
        case (PF_MBEDTLS_SSL_EXT_MASK(PRE_SHARED_KEY) |
              PF_MBEDTLS_SSL_EXT_MASK(KEY_SHARE)):
            handshake->key_exchange_mode =
                PF_MBEDTLS_SSL_TLS1_3_KEY_EXCHANGE_MODE_PSK_EPHEMERAL;
            break;

        /* Neither pre_shared_key nor key_share extension was received */
        default:
            PF_MBEDTLS_SSL_DEBUG_MSG(1, ("Unknown key exchange."));
            ret = PF_MBEDTLS_ERR_SSL_HANDSHAKE_FAILURE;
            goto cleanup;
    }

    if (!pf_mbedtls_ssl_conf_tls13_is_kex_mode_enabled(
            ssl, handshake->key_exchange_mode)) {
        ret = PF_MBEDTLS_ERR_SSL_HANDSHAKE_FAILURE;
        PF_MBEDTLS_SSL_DEBUG_MSG(
            2, ("Key exchange mode(%s) is not supported.",
                ssl_tls13_get_kex_mode_str(handshake->key_exchange_mode)));
        goto cleanup;
    }

    PF_MBEDTLS_SSL_DEBUG_MSG(
        3, ("Selected key exchange mode: %s",
            ssl_tls13_get_kex_mode_str(handshake->key_exchange_mode)));

    /* Start the TLS 1.3 key scheduling if not already done.
     *
     * If we proposed early data then we have already derived an
     * early secret using the selected PSK and its associated hash.
     * It means that if the negotiated key exchange mode is psk or
     * psk_ephemeral, we have already correctly computed the
     * early secret and thus we do not do it again. In all other
     * cases we compute it here.
     */
#if defined(PF_MBEDTLS_SSL_EARLY_DATA)
    if (ssl->early_data_state == PF_MBEDTLS_SSL_EARLY_DATA_STATE_NO_IND_SENT ||
        handshake->key_exchange_mode ==
        PF_MBEDTLS_SSL_TLS1_3_KEY_EXCHANGE_MODE_EPHEMERAL)
#endif
    {
        ret = pf_mbedtls_ssl_tls13_key_schedule_stage_early(ssl);
        if (ret != 0) {
            PF_MBEDTLS_SSL_DEBUG_RET(
                1, "mbedtls_ssl_tls13_key_schedule_stage_early", ret);
            goto cleanup;
        }
    }

    ret = pf_mbedtls_ssl_tls13_compute_handshake_transform(ssl);
    if (ret != 0) {
        PF_MBEDTLS_SSL_DEBUG_RET(1,
                              "mbedtls_ssl_tls13_compute_handshake_transform",
                              ret);
        goto cleanup;
    }

    pf_mbedtls_ssl_set_inbound_transform(ssl, handshake->transform_handshake);
    PF_MBEDTLS_SSL_DEBUG_MSG(1, ("Switch to handshake keys for inbound traffic"));
    ssl->session_in = ssl->session_negotiate;

cleanup:
    if (ret != 0) {
        PF_MBEDTLS_SSL_PEND_FATAL_ALERT(
            PF_MBEDTLS_SSL_ALERT_MSG_HANDSHAKE_FAILURE,
            PF_MBEDTLS_ERR_SSL_HANDSHAKE_FAILURE);
    }

    return ret;
}

PF_MBEDTLS_CHECK_RETURN_CRITICAL
static int ssl_tls13_postprocess_hrr(pf_mbedtls_ssl_context *ssl)
{
    int ret = PF_MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;

    pf_mbedtls_ssl_session_reset_msg_layer(ssl, 0);

    /*
     * We are going to re-generate a shared secret corresponding to the group
     * selected by the server, which is different from the group for which we
     * generated a shared secret in the first client hello.
     * Thus, reset the shared secret.
     */
    ret = ssl_tls13_reset_key_share(ssl);
    if (ret != 0) {
        return ret;
    }

    ssl->session_negotiate->ciphersuite = ssl->handshake->ciphersuite_info->id;

#if defined(PF_MBEDTLS_SSL_EARLY_DATA)
    if (ssl->early_data_state != PF_MBEDTLS_SSL_EARLY_DATA_STATE_NO_IND_SENT) {
        ssl->early_data_state = PF_MBEDTLS_SSL_EARLY_DATA_STATE_REJECTED;
    }
#endif

    return 0;
}

/*
 * Wait and parse ServerHello handshake message.
 * Handler for MBEDTLS_SSL_SERVER_HELLO
 */
PF_MBEDTLS_CHECK_RETURN_CRITICAL
static int ssl_tls13_process_server_hello(pf_mbedtls_ssl_context *ssl)
{
    int ret = PF_MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    unsigned char *buf = NULL;
    size_t buf_len = 0;
    int is_hrr = 0;

    PF_MBEDTLS_SSL_DEBUG_MSG(2, ("=> %s", __func__));

    PF_MBEDTLS_SSL_PROC_CHK(pf_mbedtls_ssl_tls13_fetch_handshake_msg(
                             ssl, PF_MBEDTLS_SSL_HS_SERVER_HELLO, &buf, &buf_len));

    ret = ssl_tls13_preprocess_server_hello(ssl, buf, buf + buf_len);
    if (ret < 0) {
        goto cleanup;
    } else {
        is_hrr = (ret == SSL_SERVER_HELLO_HRR);
    }

    if (ret == SSL_SERVER_HELLO_TLS1_2) {
        ret = 0;
        goto cleanup;
    }

    /*
     * TLS 1.3 is negotiated. Check that ServerHello/HRR ends at a record
     * boundary. For HRR, which does not trigger a key update, this checks
     * that HRR terminates the server flight.
     */
    if (ssl->in_hslen != ssl->in_msglen) {
        PF_MBEDTLS_SSL_DEBUG_MSG(1, ("ServerHello end not aligned with a record boundary"));
        ret = PF_MBEDTLS_ERR_SSL_UNEXPECTED_MESSAGE;
        PF_MBEDTLS_SSL_PEND_FATAL_ALERT(PF_MBEDTLS_SSL_ALERT_MSG_UNEXPECTED_MESSAGE,
                                     PF_MBEDTLS_ERR_SSL_UNEXPECTED_MESSAGE);
        goto cleanup;
    }

    PF_MBEDTLS_SSL_PROC_CHK(ssl_tls13_parse_server_hello(ssl, buf,
                                                      buf + buf_len,
                                                      is_hrr));
    if (is_hrr) {
        PF_MBEDTLS_SSL_PROC_CHK(pf_mbedtls_ssl_reset_transcript_for_hrr(ssl));
    }

    PF_MBEDTLS_SSL_PROC_CHK(pf_mbedtls_ssl_add_hs_msg_to_checksum(
                             ssl, PF_MBEDTLS_SSL_HS_SERVER_HELLO, buf, buf_len));

    if (is_hrr) {
        PF_MBEDTLS_SSL_PROC_CHK(ssl_tls13_postprocess_hrr(ssl));
#if defined(PF_MBEDTLS_SSL_TLS1_3_COMPATIBILITY_MODE)
        /* If not offering early data, the client sends a dummy CCS record
         * immediately before its second flight. This may either be before
         * its second ClientHello or before its encrypted handshake flight.
         */
        pf_mbedtls_ssl_handshake_set_state(
            ssl, PF_MBEDTLS_SSL_CLIENT_CCS_BEFORE_2ND_CLIENT_HELLO);
#else
        pf_mbedtls_ssl_handshake_set_state(ssl, PF_MBEDTLS_SSL_CLIENT_HELLO);
#endif /* MBEDTLS_SSL_TLS1_3_COMPATIBILITY_MODE */
    } else {
        PF_MBEDTLS_SSL_PROC_CHK(ssl_tls13_postprocess_server_hello(ssl));
        pf_mbedtls_ssl_handshake_set_state(ssl, PF_MBEDTLS_SSL_ENCRYPTED_EXTENSIONS);
    }

cleanup:
    PF_MBEDTLS_SSL_DEBUG_MSG(2, ("<= %s ( %s )", __func__,
                              is_hrr ? "HelloRetryRequest" : "ServerHello"));
    return ret;
}

/*
 *
 * Handler for MBEDTLS_SSL_ENCRYPTED_EXTENSIONS
 *
 * The EncryptedExtensions message contains any extensions which
 * should be protected, i.e., any which are not needed to establish
 * the cryptographic context.
 */

/* Parse EncryptedExtensions message
 * struct {
 *     Extension extensions<0..2^16-1>;
 * } EncryptedExtensions;
 */
PF_MBEDTLS_CHECK_RETURN_CRITICAL
static int ssl_tls13_parse_encrypted_extensions(pf_mbedtls_ssl_context *ssl,
                                                const unsigned char *buf,
                                                const unsigned char *end)
{
    int ret = 0;
    size_t extensions_len;
    const unsigned char *p = buf;
    const unsigned char *extensions_end;
    pf_mbedtls_ssl_handshake_params *handshake = ssl->handshake;

    PF_MBEDTLS_SSL_CHK_BUF_READ_PTR(p, end, 2);
    extensions_len = PF_MBEDTLS_GET_UINT16_BE(p, 0);
    p += 2;

    PF_MBEDTLS_SSL_CHK_BUF_READ_PTR(p, end, extensions_len);
    extensions_end = p + extensions_len;

    PF_MBEDTLS_SSL_DEBUG_BUF(3, "encrypted extensions", p, extensions_len);

    handshake->received_extensions = PF_MBEDTLS_SSL_EXT_MASK_NONE;

    while (p < extensions_end) {
        unsigned int extension_type;
        size_t extension_data_len;

        /*
         * struct {
         *     ExtensionType extension_type; (2 bytes)
         *     opaque extension_data<0..2^16-1>;
         * } Extension;
         */
        PF_MBEDTLS_SSL_CHK_BUF_READ_PTR(p, extensions_end, 4);
        extension_type = PF_MBEDTLS_GET_UINT16_BE(p, 0);
        extension_data_len = PF_MBEDTLS_GET_UINT16_BE(p, 2);
        p += 4;

        PF_MBEDTLS_SSL_CHK_BUF_READ_PTR(p, extensions_end, extension_data_len);

        ret = pf_mbedtls_ssl_tls13_check_received_extension(
            ssl, PF_MBEDTLS_SSL_HS_ENCRYPTED_EXTENSIONS, extension_type,
            PF_MBEDTLS_SSL_TLS1_3_ALLOWED_EXTS_OF_EE);
        if (ret != 0) {
            return ret;
        }

        switch (extension_type) {
#if defined(PF_MBEDTLS_SSL_ALPN)
            case PF_MBEDTLS_TLS_EXT_ALPN:
                PF_MBEDTLS_SSL_DEBUG_MSG(3, ("found alpn extension"));

                if ((ret = ssl_tls13_parse_alpn_ext(
                         ssl, p, (size_t) extension_data_len)) != 0) {
                    return ret;
                }

                break;
#endif /* MBEDTLS_SSL_ALPN */

#if defined(PF_MBEDTLS_SSL_EARLY_DATA)
            case PF_MBEDTLS_TLS_EXT_EARLY_DATA:

                if (extension_data_len != 0) {
                    /* The message must be empty. */
                    PF_MBEDTLS_SSL_PEND_FATAL_ALERT(PF_MBEDTLS_SSL_ALERT_MSG_DECODE_ERROR,
                                                 PF_MBEDTLS_ERR_SSL_DECODE_ERROR);
                    return PF_MBEDTLS_ERR_SSL_DECODE_ERROR;
                }

                break;
#endif /* MBEDTLS_SSL_EARLY_DATA */

#if defined(PF_MBEDTLS_SSL_RECORD_SIZE_LIMIT)
            case PF_MBEDTLS_TLS_EXT_RECORD_SIZE_LIMIT:
                PF_MBEDTLS_SSL_DEBUG_MSG(3, ("found record_size_limit extension"));

                ret = pf_mbedtls_ssl_tls13_parse_record_size_limit_ext(
                    ssl, p, p + extension_data_len);
                if (ret != 0) {
                    PF_MBEDTLS_SSL_DEBUG_RET(
                        1, ("mbedtls_ssl_tls13_parse_record_size_limit_ext"), ret);
                    return ret;
                }
                break;
#endif /* MBEDTLS_SSL_RECORD_SIZE_LIMIT */

            default:
                PF_MBEDTLS_SSL_PRINT_EXT(
                    3, PF_MBEDTLS_SSL_HS_ENCRYPTED_EXTENSIONS,
                    extension_type, "( ignored )");
                break;
        }

        p += extension_data_len;
    }

    if ((handshake->received_extensions & PF_MBEDTLS_SSL_EXT_MASK(RECORD_SIZE_LIMIT)) &&
        (handshake->received_extensions & PF_MBEDTLS_SSL_EXT_MASK(MAX_FRAGMENT_LENGTH))) {
        PF_MBEDTLS_SSL_DEBUG_MSG(3,
                              (
                                  "Record size limit extension cannot be used with max fragment length extension"));
        PF_MBEDTLS_SSL_PEND_FATAL_ALERT(
            PF_MBEDTLS_SSL_ALERT_MSG_ILLEGAL_PARAMETER,
            PF_MBEDTLS_ERR_SSL_ILLEGAL_PARAMETER);
        return PF_MBEDTLS_ERR_SSL_ILLEGAL_PARAMETER;
    }

    PF_MBEDTLS_SSL_PRINT_EXTS(3, PF_MBEDTLS_SSL_HS_ENCRYPTED_EXTENSIONS,
                           handshake->received_extensions);

    /* Check that we consumed all the message. */
    if (p != end) {
        PF_MBEDTLS_SSL_DEBUG_MSG(1, ("EncryptedExtension lengths misaligned"));
        PF_MBEDTLS_SSL_PEND_FATAL_ALERT(PF_MBEDTLS_SSL_ALERT_MSG_DECODE_ERROR,
                                     PF_MBEDTLS_ERR_SSL_DECODE_ERROR);
        return PF_MBEDTLS_ERR_SSL_DECODE_ERROR;
    }

    return ret;
}

PF_MBEDTLS_CHECK_RETURN_CRITICAL
static int ssl_tls13_process_encrypted_extensions(pf_mbedtls_ssl_context *ssl)
{
    int ret;
    unsigned char *buf;
    size_t buf_len;
    pf_mbedtls_ssl_handshake_params *handshake = ssl->handshake;

    PF_MBEDTLS_SSL_DEBUG_MSG(2, ("=> parse encrypted extensions"));

    PF_MBEDTLS_SSL_PROC_CHK(pf_mbedtls_ssl_tls13_fetch_handshake_msg(
                             ssl, PF_MBEDTLS_SSL_HS_ENCRYPTED_EXTENSIONS,
                             &buf, &buf_len));

    /* Process the message contents */
    PF_MBEDTLS_SSL_PROC_CHK(
        ssl_tls13_parse_encrypted_extensions(ssl, buf, buf + buf_len));

#if defined(PF_MBEDTLS_SSL_EARLY_DATA)
    if (handshake->received_extensions & PF_MBEDTLS_SSL_EXT_MASK(EARLY_DATA)) {
        /* RFC8446 4.2.11
         * If the server supplies an "early_data" extension, the
         * client MUST verify that the server's selected_identity
         * is 0. If any other value is returned, the client MUST
         * abort the handshake with an "illegal_parameter" alert.
         *
         * RFC 8446 4.2.10
         * In order to accept early data, the server MUST have accepted a PSK
         * cipher suite and selected the first key offered in the client's
         * "pre_shared_key" extension. In addition, it MUST verify that the
         * following values are the same as those associated with the
         * selected PSK:
         * - The TLS version number
         * - The selected cipher suite
         * - The selected ALPN [RFC7301] protocol, if any
         *
         * The server has sent an early data extension in its Encrypted
         * Extension message thus accepted to receive early data. We
         * check here that the additional constraints on the handshake
         * parameters, when early data are exchanged, are met,
         * namely:
         * - a PSK has been selected for the handshake
         * - the selected PSK for the handshake was the first one proposed
         *   by the client.
         * - the selected ciphersuite for the handshake is the ciphersuite
         *   associated with the selected PSK.
         */
        if ((!pf_mbedtls_ssl_tls13_key_exchange_mode_with_psk(ssl)) ||
            handshake->selected_identity != 0 ||
            handshake->ciphersuite_info->id !=
            ssl->session_negotiate->ciphersuite) {

            PF_MBEDTLS_SSL_PEND_FATAL_ALERT(
                PF_MBEDTLS_SSL_ALERT_MSG_ILLEGAL_PARAMETER,
                PF_MBEDTLS_ERR_SSL_ILLEGAL_PARAMETER);
            return PF_MBEDTLS_ERR_SSL_ILLEGAL_PARAMETER;
        }

        ssl->early_data_state = PF_MBEDTLS_SSL_EARLY_DATA_STATE_ACCEPTED;
    } else if (ssl->early_data_state !=
               PF_MBEDTLS_SSL_EARLY_DATA_STATE_NO_IND_SENT) {
        ssl->early_data_state = PF_MBEDTLS_SSL_EARLY_DATA_STATE_REJECTED;
    }
#endif

    /*
     * In case the client has proposed a PSK associated with a ticket,
     * `ssl->session_negotiate->ciphersuite` still contains at this point the
     * identifier of the ciphersuite associated with the ticket. This is that
     * way because, if an exchange of early data is agreed upon, we need
     * it to check that the ciphersuite selected for the handshake is the
     * ticket ciphersuite (see above). This information is not needed
     * anymore thus we can now set it to the identifier of the ciphersuite
     * used in this session under negotiation.
     */
    ssl->session_negotiate->ciphersuite = handshake->ciphersuite_info->id;

    PF_MBEDTLS_SSL_PROC_CHK(pf_mbedtls_ssl_add_hs_msg_to_checksum(
                             ssl, PF_MBEDTLS_SSL_HS_ENCRYPTED_EXTENSIONS,
                             buf, buf_len));

#if defined(PF_MBEDTLS_SSL_TLS1_3_KEY_EXCHANGE_MODE_EPHEMERAL_ENABLED)
    if (pf_mbedtls_ssl_tls13_key_exchange_mode_with_psk(ssl)) {
        pf_mbedtls_ssl_handshake_set_state(ssl, PF_MBEDTLS_SSL_SERVER_FINISHED);

        /* Since we're not using a certificate, set verify_result to success */
        ssl->session_negotiate->verify_result = 0;
    } else {
        pf_mbedtls_ssl_handshake_set_state(ssl, PF_MBEDTLS_SSL_CERTIFICATE_REQUEST);
    }
#else
    ((void) ssl);
    pf_mbedtls_ssl_handshake_set_state(ssl, PF_MBEDTLS_SSL_SERVER_FINISHED);
#endif

cleanup:

    PF_MBEDTLS_SSL_DEBUG_MSG(2, ("<= parse encrypted extensions"));
    return ret;

}

#if defined(PF_MBEDTLS_SSL_EARLY_DATA)
/*
 * Handler for MBEDTLS_SSL_END_OF_EARLY_DATA
 *
 * RFC 8446 section 4.5
 *
 * struct {} EndOfEarlyData;
 *
 * If the server sent an "early_data" extension in EncryptedExtensions, the
 * client MUST send an EndOfEarlyData message after receiving the server
 * Finished. Otherwise, the client MUST NOT send an EndOfEarlyData message.
 */

PF_MBEDTLS_CHECK_RETURN_CRITICAL
static int ssl_tls13_write_end_of_early_data(pf_mbedtls_ssl_context *ssl)
{
    int ret = PF_MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    unsigned char *buf = NULL;
    size_t buf_len;
    PF_MBEDTLS_SSL_DEBUG_MSG(2, ("=> write EndOfEarlyData"));

    PF_MBEDTLS_SSL_PROC_CHK(pf_mbedtls_ssl_start_handshake_msg(
                             ssl, PF_MBEDTLS_SSL_HS_END_OF_EARLY_DATA,
                             &buf, &buf_len));

    PF_MBEDTLS_SSL_PROC_CHK(pf_mbedtls_ssl_add_hs_hdr_to_checksum(
                             ssl, PF_MBEDTLS_SSL_HS_END_OF_EARLY_DATA, 0));

    PF_MBEDTLS_SSL_PROC_CHK(
        pf_mbedtls_ssl_finish_handshake_msg(ssl, buf_len, 0));

    pf_mbedtls_ssl_handshake_set_state(ssl, PF_MBEDTLS_SSL_CLIENT_CERTIFICATE);

cleanup:

    PF_MBEDTLS_SSL_DEBUG_MSG(2, ("<= write EndOfEarlyData"));
    return ret;
}

int pf_mbedtls_ssl_get_early_data_status(pf_mbedtls_ssl_context *ssl)
{
    if ((ssl->conf->endpoint != PF_MBEDTLS_SSL_IS_CLIENT) ||
        (!pf_mbedtls_ssl_is_handshake_over(ssl))) {
        return PF_MBEDTLS_ERR_SSL_BAD_INPUT_DATA;
    }

    switch (ssl->early_data_state) {
        case PF_MBEDTLS_SSL_EARLY_DATA_STATE_NO_IND_SENT:
            return PF_MBEDTLS_SSL_EARLY_DATA_STATUS_NOT_INDICATED;
            break;

        case PF_MBEDTLS_SSL_EARLY_DATA_STATE_REJECTED:
            return PF_MBEDTLS_SSL_EARLY_DATA_STATUS_REJECTED;
            break;

        case PF_MBEDTLS_SSL_EARLY_DATA_STATE_SERVER_FINISHED_RECEIVED:
            return PF_MBEDTLS_SSL_EARLY_DATA_STATUS_ACCEPTED;
            break;

        default:
            return PF_MBEDTLS_ERR_SSL_INTERNAL_ERROR;
    }
}
#endif /* MBEDTLS_SSL_EARLY_DATA */

#if defined(PF_MBEDTLS_SSL_TLS1_3_KEY_EXCHANGE_MODE_EPHEMERAL_ENABLED)
/*
 * STATE HANDLING: CertificateRequest
 *
 */
#define SSL_CERTIFICATE_REQUEST_EXPECT_REQUEST 0
#define SSL_CERTIFICATE_REQUEST_SKIP           1
/* Coordination:
 * Deals with the ambiguity of not knowing if a CertificateRequest
 * will be sent. Returns a negative code on failure, or
 * - SSL_CERTIFICATE_REQUEST_EXPECT_REQUEST
 * - SSL_CERTIFICATE_REQUEST_SKIP
 * indicating if a Certificate Request is expected or not.
 */
PF_MBEDTLS_CHECK_RETURN_CRITICAL
static int ssl_tls13_certificate_request_coordinate(pf_mbedtls_ssl_context *ssl)
{
    int ret = PF_MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;

    if ((ret = pf_mbedtls_ssl_read_record(ssl, 0)) != 0) {
        PF_MBEDTLS_SSL_DEBUG_RET(1, "mbedtls_ssl_read_record", ret);
        return ret;
    }
    ssl->keep_current_message = 1;

    if ((ssl->in_msgtype == PF_MBEDTLS_SSL_MSG_HANDSHAKE) &&
        (ssl->in_msg[0] == PF_MBEDTLS_SSL_HS_CERTIFICATE_REQUEST)) {
        PF_MBEDTLS_SSL_DEBUG_MSG(3, ("got a certificate request"));
        return SSL_CERTIFICATE_REQUEST_EXPECT_REQUEST;
    }

    PF_MBEDTLS_SSL_DEBUG_MSG(3, ("got no certificate request"));

    return SSL_CERTIFICATE_REQUEST_SKIP;
}

/*
 * ssl_tls13_parse_certificate_request()
 *     Parse certificate request
 * struct {
 *   opaque certificate_request_context<0..2^8-1>;
 *   Extension extensions<2..2^16-1>;
 * } CertificateRequest;
 */
PF_MBEDTLS_CHECK_RETURN_CRITICAL
static int ssl_tls13_parse_certificate_request(pf_mbedtls_ssl_context *ssl,
                                               const unsigned char *buf,
                                               const unsigned char *end)
{
    int ret = PF_MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    const unsigned char *p = buf;
    size_t certificate_request_context_len = 0;
    size_t extensions_len = 0;
    const unsigned char *extensions_end;
    pf_mbedtls_ssl_handshake_params *handshake = ssl->handshake;

    /* ...
     * opaque certificate_request_context<0..2^8-1>
     * ...
     */
    PF_MBEDTLS_SSL_CHK_BUF_READ_PTR(p, end, 1);
    certificate_request_context_len = (size_t) p[0];
    p += 1;

    if (certificate_request_context_len > 0) {
        PF_MBEDTLS_SSL_CHK_BUF_READ_PTR(p, end, certificate_request_context_len);
        PF_MBEDTLS_SSL_DEBUG_BUF(3, "Certificate Request Context",
                              p, certificate_request_context_len);

        handshake->certificate_request_context =
            pf_mbedtls_calloc(1, certificate_request_context_len);
        if (handshake->certificate_request_context == NULL) {
            PF_MBEDTLS_SSL_DEBUG_MSG(1, ("buffer too small"));
            return PF_MBEDTLS_ERR_SSL_ALLOC_FAILED;
        }
        memcpy(handshake->certificate_request_context, p,
               certificate_request_context_len);
        p += certificate_request_context_len;
    }

    /* ...
     * Extension extensions<2..2^16-1>;
     * ...
     */
    PF_MBEDTLS_SSL_CHK_BUF_READ_PTR(p, end, 2);
    extensions_len = PF_MBEDTLS_GET_UINT16_BE(p, 0);
    p += 2;

    PF_MBEDTLS_SSL_CHK_BUF_READ_PTR(p, end, extensions_len);
    extensions_end = p + extensions_len;

    handshake->received_extensions = PF_MBEDTLS_SSL_EXT_MASK_NONE;

    while (p < extensions_end) {
        unsigned int extension_type;
        size_t extension_data_len;

        PF_MBEDTLS_SSL_CHK_BUF_READ_PTR(p, extensions_end, 4);
        extension_type = PF_MBEDTLS_GET_UINT16_BE(p, 0);
        extension_data_len = PF_MBEDTLS_GET_UINT16_BE(p, 2);
        p += 4;

        PF_MBEDTLS_SSL_CHK_BUF_READ_PTR(p, extensions_end, extension_data_len);

        ret = pf_mbedtls_ssl_tls13_check_received_extension(
            ssl, PF_MBEDTLS_SSL_HS_CERTIFICATE_REQUEST, extension_type,
            PF_MBEDTLS_SSL_TLS1_3_ALLOWED_EXTS_OF_CR);
        if (ret != 0) {
            return ret;
        }

        switch (extension_type) {
            case PF_MBEDTLS_TLS_EXT_SIG_ALG:
                PF_MBEDTLS_SSL_DEBUG_MSG(3,
                                      ("found signature algorithms extension"));
                ret = pf_mbedtls_ssl_parse_sig_alg_ext(ssl, p,
                                                    p + extension_data_len);
                if (ret != 0) {
                    return ret;
                }

                break;

            default:
                PF_MBEDTLS_SSL_PRINT_EXT(
                    3, PF_MBEDTLS_SSL_HS_CERTIFICATE_REQUEST,
                    extension_type, "( ignored )");
                break;
        }

        p += extension_data_len;
    }

    PF_MBEDTLS_SSL_PRINT_EXTS(3, PF_MBEDTLS_SSL_HS_CERTIFICATE_REQUEST,
                           handshake->received_extensions);

    /* Check that we consumed all the message. */
    if (p != end) {
        PF_MBEDTLS_SSL_DEBUG_MSG(1,
                              ("CertificateRequest misaligned"));
        goto decode_error;
    }

    /* RFC 8446 section 4.3.2
     *
     * The "signature_algorithms" extension MUST be specified
     */
    if ((handshake->received_extensions & PF_MBEDTLS_SSL_EXT_MASK(SIG_ALG)) == 0) {
        PF_MBEDTLS_SSL_DEBUG_MSG(3,
                              ("no signature algorithms extension found"));
        goto decode_error;
    }

    ssl->handshake->client_auth = 1;
    return 0;

decode_error:
    PF_MBEDTLS_SSL_PEND_FATAL_ALERT(PF_MBEDTLS_SSL_ALERT_MSG_DECODE_ERROR,
                                 PF_MBEDTLS_ERR_SSL_DECODE_ERROR);
    return PF_MBEDTLS_ERR_SSL_DECODE_ERROR;
}

/*
 * Handler for  MBEDTLS_SSL_CERTIFICATE_REQUEST
 */
PF_MBEDTLS_CHECK_RETURN_CRITICAL
static int ssl_tls13_process_certificate_request(pf_mbedtls_ssl_context *ssl)
{
    int ret = PF_MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;

    PF_MBEDTLS_SSL_DEBUG_MSG(2, ("=> parse certificate request"));

    PF_MBEDTLS_SSL_PROC_CHK_NEG(ssl_tls13_certificate_request_coordinate(ssl));

    if (ret == SSL_CERTIFICATE_REQUEST_EXPECT_REQUEST) {
        unsigned char *buf;
        size_t buf_len;

        PF_MBEDTLS_SSL_PROC_CHK(pf_mbedtls_ssl_tls13_fetch_handshake_msg(
                                 ssl, PF_MBEDTLS_SSL_HS_CERTIFICATE_REQUEST,
                                 &buf, &buf_len));

        PF_MBEDTLS_SSL_PROC_CHK(ssl_tls13_parse_certificate_request(
                                 ssl, buf, buf + buf_len));

        PF_MBEDTLS_SSL_PROC_CHK(pf_mbedtls_ssl_add_hs_msg_to_checksum(
                                 ssl, PF_MBEDTLS_SSL_HS_CERTIFICATE_REQUEST,
                                 buf, buf_len));
    } else if (ret == SSL_CERTIFICATE_REQUEST_SKIP) {
        ret = 0;
    } else {
        PF_MBEDTLS_SSL_DEBUG_MSG(1, ("should never happen"));
        ret = PF_MBEDTLS_ERR_SSL_INTERNAL_ERROR;
        goto cleanup;
    }

    pf_mbedtls_ssl_handshake_set_state(ssl, PF_MBEDTLS_SSL_SERVER_CERTIFICATE);

cleanup:

    PF_MBEDTLS_SSL_DEBUG_MSG(2, ("<= parse certificate request"));
    return ret;
}

/*
 * Handler for MBEDTLS_SSL_SERVER_CERTIFICATE
 */
PF_MBEDTLS_CHECK_RETURN_CRITICAL
static int ssl_tls13_process_server_certificate(pf_mbedtls_ssl_context *ssl)
{
    int ret;

    ret = pf_mbedtls_ssl_tls13_process_certificate(ssl);
    if (ret != 0) {
        return ret;
    }

    pf_mbedtls_ssl_handshake_set_state(ssl, PF_MBEDTLS_SSL_CERTIFICATE_VERIFY);
    return 0;
}

/*
 * Handler for MBEDTLS_SSL_CERTIFICATE_VERIFY
 */
PF_MBEDTLS_CHECK_RETURN_CRITICAL
static int ssl_tls13_process_certificate_verify(pf_mbedtls_ssl_context *ssl)
{
    int ret;

    ret = pf_mbedtls_ssl_tls13_process_certificate_verify(ssl);
    if (ret != 0) {
        return ret;
    }

    pf_mbedtls_ssl_handshake_set_state(ssl, PF_MBEDTLS_SSL_SERVER_FINISHED);
    return 0;
}
#endif /* MBEDTLS_SSL_TLS1_3_KEY_EXCHANGE_MODE_EPHEMERAL_ENABLED */

/*
 * Handler for MBEDTLS_SSL_SERVER_FINISHED
 */
PF_MBEDTLS_CHECK_RETURN_CRITICAL
static int ssl_tls13_process_server_finished(pf_mbedtls_ssl_context *ssl)
{
    int ret;

    ret = pf_mbedtls_ssl_tls13_process_finished_message(ssl);
    if (ret != 0) {
        return ret;
    }

    ret = pf_mbedtls_ssl_tls13_compute_application_transform(ssl);
    if (ret != 0) {
        PF_MBEDTLS_SSL_PEND_FATAL_ALERT(
            PF_MBEDTLS_SSL_ALERT_MSG_HANDSHAKE_FAILURE,
            PF_MBEDTLS_ERR_SSL_HANDSHAKE_FAILURE);
        return ret;
    }

#if defined(PF_MBEDTLS_SSL_EARLY_DATA)
    if (ssl->early_data_state == PF_MBEDTLS_SSL_EARLY_DATA_STATE_ACCEPTED) {
        ssl->early_data_state = PF_MBEDTLS_SSL_EARLY_DATA_STATE_SERVER_FINISHED_RECEIVED;
        pf_mbedtls_ssl_handshake_set_state(ssl, PF_MBEDTLS_SSL_END_OF_EARLY_DATA);
    } else
#endif /* MBEDTLS_SSL_EARLY_DATA */
    {
#if defined(PF_MBEDTLS_SSL_TLS1_3_COMPATIBILITY_MODE)
        pf_mbedtls_ssl_handshake_set_state(
            ssl, PF_MBEDTLS_SSL_CLIENT_CCS_AFTER_SERVER_FINISHED);
#else
        pf_mbedtls_ssl_handshake_set_state(ssl, PF_MBEDTLS_SSL_CLIENT_CERTIFICATE);
#endif /* MBEDTLS_SSL_TLS1_3_COMPATIBILITY_MODE */
    }

    return 0;
}

/*
 * Handler for MBEDTLS_SSL_CLIENT_CERTIFICATE
 */
PF_MBEDTLS_CHECK_RETURN_CRITICAL
static int ssl_tls13_write_client_certificate(pf_mbedtls_ssl_context *ssl)
{
    int non_empty_certificate_msg = 0;

    PF_MBEDTLS_SSL_DEBUG_MSG(1,
                          ("Switch to handshake traffic keys for outbound traffic"));
    pf_mbedtls_ssl_set_outbound_transform(ssl, ssl->handshake->transform_handshake);

#if defined(PF_MBEDTLS_SSL_TLS1_3_KEY_EXCHANGE_MODE_EPHEMERAL_ENABLED)
    if (ssl->handshake->client_auth) {
        int ret = pf_mbedtls_ssl_tls13_write_certificate(ssl);
        if (ret != 0) {
            return ret;
        }

        if (pf_mbedtls_ssl_own_cert(ssl) != NULL) {
            non_empty_certificate_msg = 1;
        }
    } else {
        PF_MBEDTLS_SSL_DEBUG_MSG(2, ("skip write certificate"));
    }
#endif

    if (non_empty_certificate_msg) {
        pf_mbedtls_ssl_handshake_set_state(ssl,
                                        PF_MBEDTLS_SSL_CLIENT_CERTIFICATE_VERIFY);
    } else {
        PF_MBEDTLS_SSL_DEBUG_MSG(2, ("skip write certificate verify"));
        pf_mbedtls_ssl_handshake_set_state(ssl, PF_MBEDTLS_SSL_CLIENT_FINISHED);
    }

    return 0;
}

#if defined(PF_MBEDTLS_SSL_TLS1_3_KEY_EXCHANGE_MODE_EPHEMERAL_ENABLED)
/*
 * Handler for MBEDTLS_SSL_CLIENT_CERTIFICATE_VERIFY
 */
PF_MBEDTLS_CHECK_RETURN_CRITICAL
static int ssl_tls13_write_client_certificate_verify(pf_mbedtls_ssl_context *ssl)
{
    int ret = pf_mbedtls_ssl_tls13_write_certificate_verify(ssl);

    if (ret == 0) {
        pf_mbedtls_ssl_handshake_set_state(ssl, PF_MBEDTLS_SSL_CLIENT_FINISHED);
    }

    return ret;
}
#endif /* MBEDTLS_SSL_TLS1_3_KEY_EXCHANGE_MODE_EPHEMERAL_ENABLED */

/*
 * Handler for MBEDTLS_SSL_CLIENT_FINISHED
 */
PF_MBEDTLS_CHECK_RETURN_CRITICAL
static int ssl_tls13_write_client_finished(pf_mbedtls_ssl_context *ssl)
{
    int ret;

    ret = pf_mbedtls_ssl_tls13_write_finished_message(ssl);
    if (ret != 0) {
        return ret;
    }

    ret = pf_mbedtls_ssl_tls13_compute_resumption_master_secret(ssl);
    if (ret != 0) {
        PF_MBEDTLS_SSL_DEBUG_RET(
            1, "mbedtls_ssl_tls13_compute_resumption_master_secret ", ret);
        return ret;
    }

    pf_mbedtls_ssl_handshake_set_state(ssl, PF_MBEDTLS_SSL_FLUSH_BUFFERS);
    return 0;
}

/*
 * Handler for MBEDTLS_SSL_FLUSH_BUFFERS
 */
PF_MBEDTLS_CHECK_RETURN_CRITICAL
static int ssl_tls13_flush_buffers(pf_mbedtls_ssl_context *ssl)
{
    PF_MBEDTLS_SSL_DEBUG_MSG(2, ("handshake: done"));
    pf_mbedtls_ssl_handshake_set_state(ssl, PF_MBEDTLS_SSL_HANDSHAKE_WRAPUP);
    return 0;
}

/*
 * Handler for MBEDTLS_SSL_HANDSHAKE_WRAPUP
 */
PF_MBEDTLS_CHECK_RETURN_CRITICAL
static int ssl_tls13_handshake_wrapup(pf_mbedtls_ssl_context *ssl)
{

    pf_mbedtls_ssl_tls13_handshake_wrapup(ssl);

    pf_mbedtls_ssl_handshake_set_state(ssl, PF_MBEDTLS_SSL_HANDSHAKE_OVER);
    return 0;
}

#if defined(PF_MBEDTLS_SSL_SESSION_TICKETS)

#if defined(PF_MBEDTLS_SSL_EARLY_DATA)
/* From RFC 8446 section 4.2.10
 *
 * struct {
 *     select (Handshake.msg_type) {
 *         case new_session_ticket:   uint32 max_early_data_size;
 *         ...
 *     };
 * } EarlyDataIndication;
 */
PF_MBEDTLS_CHECK_RETURN_CRITICAL
static int ssl_tls13_parse_new_session_ticket_early_data_ext(
    pf_mbedtls_ssl_context *ssl,
    const unsigned char *buf,
    const unsigned char *end)
{
    pf_mbedtls_ssl_session *session = ssl->session;

    PF_MBEDTLS_SSL_CHK_BUF_READ_PTR(buf, end, 4);

    session->max_early_data_size = PF_MBEDTLS_GET_UINT32_BE(buf, 0);
    pf_mbedtls_ssl_tls13_session_set_ticket_flags(
        session, PF_MBEDTLS_SSL_TLS1_3_TICKET_ALLOW_EARLY_DATA);
    PF_MBEDTLS_SSL_DEBUG_MSG(
        3, ("received max_early_data_size: %u",
            (unsigned int) session->max_early_data_size));

    return 0;
}
#endif /* MBEDTLS_SSL_EARLY_DATA */

PF_MBEDTLS_CHECK_RETURN_CRITICAL
static int ssl_tls13_parse_new_session_ticket_exts(pf_mbedtls_ssl_context *ssl,
                                                   const unsigned char *buf,
                                                   const unsigned char *end)
{
    pf_mbedtls_ssl_handshake_params *handshake = ssl->handshake;
    const unsigned char *p = buf;


    handshake->received_extensions = PF_MBEDTLS_SSL_EXT_MASK_NONE;

    while (p < end) {
        unsigned int extension_type;
        size_t extension_data_len;
        int ret;

        PF_MBEDTLS_SSL_CHK_BUF_READ_PTR(p, end, 4);
        extension_type = PF_MBEDTLS_GET_UINT16_BE(p, 0);
        extension_data_len = PF_MBEDTLS_GET_UINT16_BE(p, 2);
        p += 4;

        PF_MBEDTLS_SSL_CHK_BUF_READ_PTR(p, end, extension_data_len);

        ret = pf_mbedtls_ssl_tls13_check_received_extension(
            ssl, PF_MBEDTLS_SSL_HS_NEW_SESSION_TICKET, extension_type,
            PF_MBEDTLS_SSL_TLS1_3_ALLOWED_EXTS_OF_NST);
        if (ret != 0) {
            return ret;
        }

        switch (extension_type) {
#if defined(PF_MBEDTLS_SSL_EARLY_DATA)
            case PF_MBEDTLS_TLS_EXT_EARLY_DATA:
                ret = ssl_tls13_parse_new_session_ticket_early_data_ext(
                    ssl, p, p + extension_data_len);
                if (ret != 0) {
                    PF_MBEDTLS_SSL_DEBUG_RET(
                        1, "ssl_tls13_parse_new_session_ticket_early_data_ext",
                        ret);
                    return ret;
                }
                break;
#endif /* MBEDTLS_SSL_EARLY_DATA */

            default:
                PF_MBEDTLS_SSL_PRINT_EXT(
                    3, PF_MBEDTLS_SSL_HS_NEW_SESSION_TICKET,
                    extension_type, "( ignored )");
                break;
        }

        p +=  extension_data_len;
    }

    PF_MBEDTLS_SSL_PRINT_EXTS(3, PF_MBEDTLS_SSL_HS_NEW_SESSION_TICKET,
                           handshake->received_extensions);

    return 0;
}

/*
 * From RFC8446, page 74
 *
 * struct {
 *    uint32 ticket_lifetime;
 *    uint32 ticket_age_add;
 *    opaque ticket_nonce<0..255>;
 *    opaque ticket<1..2^16-1>;
 *    Extension extensions<0..2^16-2>;
 * } NewSessionTicket;
 *
 */
PF_MBEDTLS_CHECK_RETURN_CRITICAL
static int ssl_tls13_parse_new_session_ticket(pf_mbedtls_ssl_context *ssl,
                                              unsigned char *buf,
                                              unsigned char *end,
                                              unsigned char **ticket_nonce,
                                              size_t *ticket_nonce_len)
{
    int ret = PF_MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    unsigned char *p = buf;
    pf_mbedtls_ssl_session *session = ssl->session;
    size_t ticket_len;
    unsigned char *ticket;
    size_t extensions_len;

    *ticket_nonce = NULL;
    *ticket_nonce_len = 0;
    /*
     *    ticket_lifetime   4 bytes
     *    ticket_age_add    4 bytes
     *    ticket_nonce_len  1 byte
     */
    PF_MBEDTLS_SSL_CHK_BUF_READ_PTR(p, end, 9);

    session->ticket_lifetime = PF_MBEDTLS_GET_UINT32_BE(p, 0);
    PF_MBEDTLS_SSL_DEBUG_MSG(3,
                          ("ticket_lifetime: %u",
                           (unsigned int) session->ticket_lifetime));
    if (session->ticket_lifetime >
        PF_MBEDTLS_SSL_TLS1_3_MAX_ALLOWED_TICKET_LIFETIME) {
        PF_MBEDTLS_SSL_DEBUG_MSG(3, ("ticket_lifetime exceeds 7 days."));
        return PF_MBEDTLS_ERR_SSL_ILLEGAL_PARAMETER;
    }

    session->ticket_age_add = PF_MBEDTLS_GET_UINT32_BE(p, 4);
    PF_MBEDTLS_SSL_DEBUG_MSG(3,
                          ("ticket_age_add: %u",
                           (unsigned int) session->ticket_age_add));

    *ticket_nonce_len = p[8];
    p += 9;

    PF_MBEDTLS_SSL_CHK_BUF_READ_PTR(p, end, *ticket_nonce_len);
    *ticket_nonce = p;
    PF_MBEDTLS_SSL_DEBUG_BUF(3, "ticket_nonce:", *ticket_nonce, *ticket_nonce_len);
    p += *ticket_nonce_len;

    /* Ticket */
    PF_MBEDTLS_SSL_CHK_BUF_READ_PTR(p, end, 2);
    ticket_len = PF_MBEDTLS_GET_UINT16_BE(p, 0);
    p += 2;
    PF_MBEDTLS_SSL_CHK_BUF_READ_PTR(p, end, ticket_len);
    PF_MBEDTLS_SSL_DEBUG_BUF(3, "received ticket", p, ticket_len);

    /* Check if we previously received a ticket already. */
    if (session->ticket != NULL || session->ticket_len > 0) {
        pf_mbedtls_free(session->ticket);
        session->ticket = NULL;
        session->ticket_len = 0;
    }

    if ((ticket = pf_mbedtls_calloc(1, ticket_len)) == NULL) {
        PF_MBEDTLS_SSL_DEBUG_MSG(1, ("ticket alloc failed"));
        return PF_MBEDTLS_ERR_SSL_ALLOC_FAILED;
    }
    memcpy(ticket, p, ticket_len);
    p += ticket_len;
    session->ticket = ticket;
    session->ticket_len = ticket_len;

    /* Clear all flags in ticket_flags */
    pf_mbedtls_ssl_tls13_session_clear_ticket_flags(
        session, PF_MBEDTLS_SSL_TLS1_3_TICKET_FLAGS_MASK);

    PF_MBEDTLS_SSL_CHK_BUF_READ_PTR(p, end, 2);
    extensions_len = PF_MBEDTLS_GET_UINT16_BE(p, 0);
    p += 2;
    PF_MBEDTLS_SSL_CHK_BUF_READ_PTR(p, end, extensions_len);

    PF_MBEDTLS_SSL_DEBUG_BUF(3, "ticket extension", p, extensions_len);

    ret = ssl_tls13_parse_new_session_ticket_exts(ssl, p, p + extensions_len);
    if (ret != 0) {
        PF_MBEDTLS_SSL_DEBUG_RET(1,
                              "ssl_tls13_parse_new_session_ticket_exts",
                              ret);
        return ret;
    }

    return 0;
}

/* Non negative return values for ssl_tls13_postprocess_new_session_ticket().
 * - POSTPROCESS_NEW_SESSION_TICKET_SIGNAL, all good, we have to signal the
 *   application that a valid ticket has been received.
 * - POSTPROCESS_NEW_SESSION_TICKET_DISCARD, no fatal error, we keep the
 *   connection alive but we do not signal the ticket to the application.
 */
#define POSTPROCESS_NEW_SESSION_TICKET_SIGNAL 0
#define POSTPROCESS_NEW_SESSION_TICKET_DISCARD 1
PF_MBEDTLS_CHECK_RETURN_CRITICAL
static int ssl_tls13_postprocess_new_session_ticket(pf_mbedtls_ssl_context *ssl,
                                                    unsigned char *ticket_nonce,
                                                    size_t ticket_nonce_len)
{
    int ret = PF_MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    pf_mbedtls_ssl_session *session = ssl->session;
    const pf_mbedtls_ssl_ciphersuite_t *ciphersuite_info;
    pf_psa_algorithm_t pf_psa_hash_alg;
    int hash_length;

    if (session->ticket_lifetime == 0) {
        return POSTPROCESS_NEW_SESSION_TICKET_DISCARD;
    }

#if defined(PF_MBEDTLS_HAVE_TIME)
    /* Store ticket creation time */
    session->ticket_reception_time = pf_mbedtls_ms_time();
#endif

    ciphersuite_info = pf_mbedtls_ssl_ciphersuite_from_id(session->ciphersuite);
    if (ciphersuite_info == NULL) {
        PF_MBEDTLS_SSL_DEBUG_MSG(1, ("should never happen"));
        return PF_MBEDTLS_ERR_SSL_INTERNAL_ERROR;
    }

    pf_psa_hash_alg = pf_mbedtls_md_psa_alg_from_type((pf_mbedtls_md_type_t) ciphersuite_info->mac);
    hash_length = PF_PSA_HASH_LENGTH(pf_psa_hash_alg);
    if (hash_length == -1 ||
        (size_t) hash_length > sizeof(session->resumption_key)) {
        return PF_MBEDTLS_ERR_SSL_INTERNAL_ERROR;
    }


    PF_MBEDTLS_SSL_DEBUG_BUF(3, "resumption_master_secret",
                          session->app_secrets.resumption_master_secret,
                          hash_length);

    /* Compute resumption key
     *
     *  HKDF-Expand-Label( resumption_master_secret,
     *                    "resumption", ticket_nonce, Hash.length )
     */
    ret = pf_mbedtls_ssl_tls13_hkdf_expand_label(
        pf_psa_hash_alg,
        session->app_secrets.resumption_master_secret,
        hash_length,
        PF_MBEDTLS_SSL_TLS1_3_LBL_WITH_LEN(resumption),
        ticket_nonce,
        ticket_nonce_len,
        session->resumption_key,
        hash_length);

    if (ret != 0) {
        PF_MBEDTLS_SSL_DEBUG_RET(2,
                              "Creating the ticket-resumed PSK failed",
                              ret);
        return ret;
    }

    session->resumption_key_len = hash_length;

    PF_MBEDTLS_SSL_DEBUG_BUF(3, "Ticket-resumed PSK",
                          session->resumption_key,
                          session->resumption_key_len);

    /* Set ticket_flags depends on the selected key exchange modes */
    pf_mbedtls_ssl_tls13_session_set_ticket_flags(
        session, ssl->conf->tls13_kex_modes);
    PF_MBEDTLS_SSL_PRINT_TICKET_FLAGS(4, session->ticket_flags);

    return POSTPROCESS_NEW_SESSION_TICKET_SIGNAL;
}

/*
 * Handler for MBEDTLS_SSL_TLS1_3_NEW_SESSION_TICKET
 */
PF_MBEDTLS_CHECK_RETURN_CRITICAL
static int ssl_tls13_process_new_session_ticket(pf_mbedtls_ssl_context *ssl)
{
    int ret = PF_MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    unsigned char *buf;
    size_t buf_len;
    unsigned char *ticket_nonce;
    size_t ticket_nonce_len;

    PF_MBEDTLS_SSL_DEBUG_MSG(2, ("=> parse new session ticket"));

    PF_MBEDTLS_SSL_PROC_CHK(pf_mbedtls_ssl_tls13_fetch_handshake_msg(
                             ssl, PF_MBEDTLS_SSL_HS_NEW_SESSION_TICKET,
                             &buf, &buf_len));

    /*
     * We are about to update (maybe only partially) ticket data thus block
     * any session export for the time being.
     */
    ssl->session->exported = 1;

    PF_MBEDTLS_SSL_PROC_CHK(ssl_tls13_parse_new_session_ticket(
                             ssl, buf, buf + buf_len,
                             &ticket_nonce, &ticket_nonce_len));

    PF_MBEDTLS_SSL_PROC_CHK_NEG(ssl_tls13_postprocess_new_session_ticket(
                                 ssl, ticket_nonce, ticket_nonce_len));

    switch (ret) {
        case POSTPROCESS_NEW_SESSION_TICKET_SIGNAL:
            /*
             * All good, we have received a new valid ticket, session data can
             * be exported now and we signal the ticket to the application.
             */
            ssl->session->exported = 0;
            ret = PF_MBEDTLS_ERR_SSL_RECEIVED_NEW_SESSION_TICKET;
            break;

        case POSTPROCESS_NEW_SESSION_TICKET_DISCARD:
            ret = 0;
            PF_MBEDTLS_SSL_DEBUG_MSG(2, ("Discard new session ticket"));
            break;

        default:
            ret = PF_MBEDTLS_ERR_SSL_INTERNAL_ERROR;
    }

    pf_mbedtls_ssl_handshake_set_state(ssl, PF_MBEDTLS_SSL_HANDSHAKE_OVER);

cleanup:

    PF_MBEDTLS_SSL_DEBUG_MSG(2, ("<= parse new session ticket"));
    return ret;
}
#endif /* MBEDTLS_SSL_SESSION_TICKETS */

int pf_mbedtls_ssl_tls13_handshake_client_step(pf_mbedtls_ssl_context *ssl)
{
    int ret = 0;

    switch (ssl->state) {
        case PF_MBEDTLS_SSL_HELLO_REQUEST:
            pf_mbedtls_ssl_handshake_set_state(ssl, PF_MBEDTLS_SSL_CLIENT_HELLO);
            break;

        case PF_MBEDTLS_SSL_CLIENT_HELLO:
            ret = pf_mbedtls_ssl_write_client_hello(ssl);
            break;

        case PF_MBEDTLS_SSL_SERVER_HELLO:
            ret = ssl_tls13_process_server_hello(ssl);
            break;

        case PF_MBEDTLS_SSL_ENCRYPTED_EXTENSIONS:
            ret = ssl_tls13_process_encrypted_extensions(ssl);
            break;

#if defined(PF_MBEDTLS_SSL_TLS1_3_KEY_EXCHANGE_MODE_EPHEMERAL_ENABLED)
        case PF_MBEDTLS_SSL_CERTIFICATE_REQUEST:
            ret = ssl_tls13_process_certificate_request(ssl);
            break;

        case PF_MBEDTLS_SSL_SERVER_CERTIFICATE:
            ret = ssl_tls13_process_server_certificate(ssl);
            break;

        case PF_MBEDTLS_SSL_CERTIFICATE_VERIFY:
            ret = ssl_tls13_process_certificate_verify(ssl);
            break;
#endif /* MBEDTLS_SSL_TLS1_3_KEY_EXCHANGE_MODE_EPHEMERAL_ENABLED */

        case PF_MBEDTLS_SSL_SERVER_FINISHED:
            ret = ssl_tls13_process_server_finished(ssl);
            break;

#if defined(PF_MBEDTLS_SSL_EARLY_DATA)
        case PF_MBEDTLS_SSL_END_OF_EARLY_DATA:
            ret = ssl_tls13_write_end_of_early_data(ssl);
            break;
#endif

        case PF_MBEDTLS_SSL_CLIENT_CERTIFICATE:
            ret = ssl_tls13_write_client_certificate(ssl);
            break;

#if defined(PF_MBEDTLS_SSL_TLS1_3_KEY_EXCHANGE_MODE_EPHEMERAL_ENABLED)
        case PF_MBEDTLS_SSL_CLIENT_CERTIFICATE_VERIFY:
            ret = ssl_tls13_write_client_certificate_verify(ssl);
            break;
#endif /* MBEDTLS_SSL_TLS1_3_KEY_EXCHANGE_MODE_EPHEMERAL_ENABLED */

        case PF_MBEDTLS_SSL_CLIENT_FINISHED:
            ret = ssl_tls13_write_client_finished(ssl);
            break;

        case PF_MBEDTLS_SSL_FLUSH_BUFFERS:
            ret = ssl_tls13_flush_buffers(ssl);
            break;

        case PF_MBEDTLS_SSL_HANDSHAKE_WRAPUP:
            ret = ssl_tls13_handshake_wrapup(ssl);
            break;

            /*
             * Injection of dummy-CCS's for middlebox compatibility
             */
#if defined(PF_MBEDTLS_SSL_TLS1_3_COMPATIBILITY_MODE)
        case PF_MBEDTLS_SSL_CLIENT_CCS_BEFORE_2ND_CLIENT_HELLO:
            ret = pf_mbedtls_ssl_tls13_write_change_cipher_spec(ssl);
            if (ret != 0) {
                break;
            }
            pf_mbedtls_ssl_handshake_set_state(ssl, PF_MBEDTLS_SSL_CLIENT_HELLO);
            break;

        case PF_MBEDTLS_SSL_CLIENT_CCS_AFTER_SERVER_FINISHED:
            ret = pf_mbedtls_ssl_tls13_write_change_cipher_spec(ssl);
            if (ret != 0) {
                break;
            }
            pf_mbedtls_ssl_handshake_set_state(ssl, PF_MBEDTLS_SSL_CLIENT_CERTIFICATE);
            break;

#if defined(PF_MBEDTLS_SSL_EARLY_DATA)
        case PF_MBEDTLS_SSL_CLIENT_CCS_AFTER_CLIENT_HELLO:
            ret = pf_mbedtls_ssl_tls13_write_change_cipher_spec(ssl);
            if (ret == 0) {
                pf_mbedtls_ssl_handshake_set_state(ssl, PF_MBEDTLS_SSL_SERVER_HELLO);

                PF_MBEDTLS_SSL_DEBUG_MSG(
                    1, ("Switch to early data keys for outbound traffic"));
                pf_mbedtls_ssl_set_outbound_transform(
                    ssl, ssl->handshake->transform_earlydata);
                ssl->early_data_state = PF_MBEDTLS_SSL_EARLY_DATA_STATE_CAN_WRITE;
            }
            break;
#endif /* MBEDTLS_SSL_EARLY_DATA */
#endif /* MBEDTLS_SSL_TLS1_3_COMPATIBILITY_MODE */

#if defined(PF_MBEDTLS_SSL_SESSION_TICKETS)
        case PF_MBEDTLS_SSL_TLS1_3_NEW_SESSION_TICKET:
            ret = ssl_tls13_process_new_session_ticket(ssl);
            break;
#endif /* MBEDTLS_SSL_SESSION_TICKETS */

        default:
            PF_MBEDTLS_SSL_DEBUG_MSG(1, ("invalid state %d", ssl->state));
            return PF_MBEDTLS_ERR_SSL_BAD_INPUT_DATA;
    }

    return ret;
}

#endif /* MBEDTLS_SSL_CLI_C && MBEDTLS_SSL_PROTO_TLS1_3 */
