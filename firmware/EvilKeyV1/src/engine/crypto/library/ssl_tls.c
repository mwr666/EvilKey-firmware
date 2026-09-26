#include "../../../pf_build_config.h"
/*
 *  TLS shared functions
 *
 *  Copyright The Mbed TLS Contributors
 *  SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
 */
/*
 *  http://www.ietf.org/rfc/rfc2246.txt
 *  http://www.ietf.org/rfc/rfc4346.txt
 */

#include "common.h"

#if defined(PF_MBEDTLS_SSL_TLS_C)

#include "../include/mbedtls/platform.h"

#include "../include/mbedtls/ssl.h"
#include "ssl_client.h"
#include "ssl_debug_helpers.h"
#include "ssl_misc.h"
#include "ssl_tls13_keys.h"

#include "debug_internal.h"
#include "../include/mbedtls/error.h"
#include "../include/mbedtls/platform_util.h"
#include "../include/mbedtls/version.h"
#include "../include/mbedtls/constant_time.h"

#include <string.h>

#if defined(PF_MBEDTLS_USE_PSA_CRYPTO)
#include "../include/mbedtls/psa_util.h"
#include "../include/psa/crypto.h"
#endif

#if defined(PF_MBEDTLS_X509_CRT_PARSE_C)
#include "../include/mbedtls/oid.h"
#endif

#if defined(PF_MBEDTLS_USE_PSA_CRYPTO)
/* Define local translating functions to save code size by not using too many
 * arguments in each translating place. */
static int local_err_translation(pf_psa_status_t status)
{
    return pf_psa_status_to_mbedtls(status, pf_psa_to_ssl_errors,
                                 ARRAY_LENGTH(pf_psa_to_ssl_errors),
                                 pf_psa_generic_status_to_mbedtls);
}
#define PF_PSA_TO_MBEDTLS_ERR(status) local_err_translation(status)
#endif

#if defined(PF_MBEDTLS_TEST_HOOKS)
static pf_mbedtls_ssl_chk_buf_ptr_args chk_buf_ptr_fail_args;

void pf_mbedtls_ssl_set_chk_buf_ptr_fail_args(
    const uint8_t *cur, const uint8_t *end, size_t need)
{
    chk_buf_ptr_fail_args.cur = cur;
    chk_buf_ptr_fail_args.end = end;
    chk_buf_ptr_fail_args.need = need;
}

void pf_mbedtls_ssl_reset_chk_buf_ptr_fail_args(void)
{
    memset(&chk_buf_ptr_fail_args, 0, sizeof(chk_buf_ptr_fail_args));
}

int pf_mbedtls_ssl_cmp_chk_buf_ptr_fail_args(pf_mbedtls_ssl_chk_buf_ptr_args *args)
{
    return (chk_buf_ptr_fail_args.cur  != args->cur) ||
           (chk_buf_ptr_fail_args.end  != args->end) ||
           (chk_buf_ptr_fail_args.need != args->need);
}
#endif /* MBEDTLS_TEST_HOOKS */

#if defined(PF_MBEDTLS_SSL_PROTO_DTLS)

#if defined(PF_MBEDTLS_SSL_DTLS_CONNECTION_ID)
/* Top-level Connection ID API */

int pf_mbedtls_ssl_conf_cid(pf_mbedtls_ssl_config *conf,
                         size_t len,
                         int ignore_other_cid)
{
    if (len > PF_MBEDTLS_SSL_CID_IN_LEN_MAX) {
        return PF_MBEDTLS_ERR_SSL_BAD_INPUT_DATA;
    }

    if (ignore_other_cid != PF_MBEDTLS_SSL_UNEXPECTED_CID_FAIL &&
        ignore_other_cid != PF_MBEDTLS_SSL_UNEXPECTED_CID_IGNORE) {
        return PF_MBEDTLS_ERR_SSL_BAD_INPUT_DATA;
    }

    conf->ignore_unexpected_cid = ignore_other_cid;
    conf->cid_len = len;
    return 0;
}

int pf_mbedtls_ssl_set_cid(pf_mbedtls_ssl_context *ssl,
                        int enable,
                        unsigned char const *own_cid,
                        size_t own_cid_len)
{
    if (ssl->conf->transport != PF_MBEDTLS_SSL_TRANSPORT_DATAGRAM) {
        return PF_MBEDTLS_ERR_SSL_BAD_INPUT_DATA;
    }

    ssl->negotiate_cid = enable;
    if (enable == PF_MBEDTLS_SSL_CID_DISABLED) {
        PF_MBEDTLS_SSL_DEBUG_MSG(3, ("Disable use of CID extension."));
        return 0;
    }
    PF_MBEDTLS_SSL_DEBUG_MSG(3, ("Enable use of CID extension."));
    PF_MBEDTLS_SSL_DEBUG_BUF(3, "Own CID", own_cid, own_cid_len);

    if (own_cid_len != ssl->conf->cid_len) {
        PF_MBEDTLS_SSL_DEBUG_MSG(3, ("CID length %u does not match CID length %u in config",
                                  (unsigned) own_cid_len,
                                  (unsigned) ssl->conf->cid_len));
        return PF_MBEDTLS_ERR_SSL_BAD_INPUT_DATA;
    }

    memcpy(ssl->own_cid, own_cid, own_cid_len);
    /* Truncation is not an issue here because
     * MBEDTLS_SSL_CID_IN_LEN_MAX at most 255. */
    ssl->own_cid_len = (uint8_t) own_cid_len;

    return 0;
}

int pf_mbedtls_ssl_get_own_cid(pf_mbedtls_ssl_context *ssl,
                            int *enabled,
                            unsigned char own_cid[PF_MBEDTLS_SSL_CID_IN_LEN_MAX],
                            size_t *own_cid_len)
{
    *enabled = PF_MBEDTLS_SSL_CID_DISABLED;

    if (ssl->conf->transport != PF_MBEDTLS_SSL_TRANSPORT_DATAGRAM) {
        return PF_MBEDTLS_ERR_SSL_BAD_INPUT_DATA;
    }

    /* We report MBEDTLS_SSL_CID_DISABLED in case the CID length is
     * zero as this is indistinguishable from not requesting to use
     * the CID extension. */
    if (ssl->own_cid_len == 0 || ssl->negotiate_cid == PF_MBEDTLS_SSL_CID_DISABLED) {
        return 0;
    }

    if (own_cid_len != NULL) {
        *own_cid_len = ssl->own_cid_len;
        if (own_cid != NULL) {
            memcpy(own_cid, ssl->own_cid, ssl->own_cid_len);
        }
    }

    *enabled = PF_MBEDTLS_SSL_CID_ENABLED;

    return 0;
}

int pf_mbedtls_ssl_get_peer_cid(pf_mbedtls_ssl_context *ssl,
                             int *enabled,
                             unsigned char peer_cid[PF_MBEDTLS_SSL_CID_OUT_LEN_MAX],
                             size_t *peer_cid_len)
{
    *enabled = PF_MBEDTLS_SSL_CID_DISABLED;

    if (ssl->conf->transport != PF_MBEDTLS_SSL_TRANSPORT_DATAGRAM ||
        pf_mbedtls_ssl_is_handshake_over(ssl) == 0) {
        return PF_MBEDTLS_ERR_SSL_BAD_INPUT_DATA;
    }

    /* We report MBEDTLS_SSL_CID_DISABLED in case the CID extensions
     * were used, but client and server requested the empty CID.
     * This is indistinguishable from not using the CID extension
     * in the first place. */
    if (ssl->transform_in->in_cid_len  == 0 &&
        ssl->transform_in->out_cid_len == 0) {
        return 0;
    }

    if (peer_cid_len != NULL) {
        *peer_cid_len = ssl->transform_in->out_cid_len;
        if (peer_cid != NULL) {
            memcpy(peer_cid, ssl->transform_in->out_cid,
                   ssl->transform_in->out_cid_len);
        }
    }

    *enabled = PF_MBEDTLS_SSL_CID_ENABLED;

    return 0;
}
#endif /* MBEDTLS_SSL_DTLS_CONNECTION_ID */

#endif /* MBEDTLS_SSL_PROTO_DTLS */

#if defined(PF_MBEDTLS_SSL_MAX_FRAGMENT_LENGTH)
/*
 * Convert max_fragment_length codes to length.
 * RFC 6066 says:
 *    enum{
 *        2^9(1), 2^10(2), 2^11(3), 2^12(4), (255)
 *    } MaxFragmentLength;
 * and we add 0 -> extension unused
 */
static unsigned int ssl_mfl_code_to_length(int mfl)
{
    switch (mfl) {
        case PF_MBEDTLS_SSL_MAX_FRAG_LEN_NONE:
            return PF_MBEDTLS_TLS_EXT_ADV_CONTENT_LEN;
        case PF_MBEDTLS_SSL_MAX_FRAG_LEN_512:
            return 512;
        case PF_MBEDTLS_SSL_MAX_FRAG_LEN_1024:
            return 1024;
        case PF_MBEDTLS_SSL_MAX_FRAG_LEN_2048:
            return 2048;
        case PF_MBEDTLS_SSL_MAX_FRAG_LEN_4096:
            return 4096;
        default:
            return PF_MBEDTLS_TLS_EXT_ADV_CONTENT_LEN;
    }
}
#endif /* MBEDTLS_SSL_MAX_FRAGMENT_LENGTH */

int pf_mbedtls_ssl_session_copy(pf_mbedtls_ssl_session *dst,
                             const pf_mbedtls_ssl_session *src)
{
    pf_mbedtls_ssl_session_free(dst);
    memcpy(dst, src, sizeof(pf_mbedtls_ssl_session));
#if defined(PF_MBEDTLS_SSL_SESSION_TICKETS) && defined(PF_MBEDTLS_SSL_CLI_C)
    dst->ticket = NULL;
#if defined(PF_MBEDTLS_SSL_PROTO_TLS1_3) && \
    defined(PF_MBEDTLS_SSL_SERVER_NAME_INDICATION)
    dst->hostname = NULL;
#endif
#endif /* MBEDTLS_SSL_SESSION_TICKETS && MBEDTLS_SSL_CLI_C */

#if defined(PF_MBEDTLS_SSL_SRV_C) && defined(PF_MBEDTLS_SSL_ALPN) && \
    defined(PF_MBEDTLS_SSL_EARLY_DATA)
    dst->ticket_alpn = NULL;
#endif

#if defined(PF_MBEDTLS_X509_CRT_PARSE_C)

#if defined(PF_MBEDTLS_SSL_KEEP_PEER_CERTIFICATE)
    if (src->peer_cert != NULL) {
        int ret = PF_MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;

        dst->peer_cert = pf_mbedtls_calloc(1, sizeof(pf_mbedtls_x509_crt));
        if (dst->peer_cert == NULL) {
            return PF_MBEDTLS_ERR_SSL_ALLOC_FAILED;
        }

        pf_mbedtls_x509_crt_init(dst->peer_cert);

        if ((ret = pf_mbedtls_x509_crt_parse_der(dst->peer_cert, src->peer_cert->raw.p,
                                              src->peer_cert->raw.len)) != 0) {
            pf_mbedtls_free(dst->peer_cert);
            dst->peer_cert = NULL;
            return ret;
        }
    }
#else /* MBEDTLS_SSL_KEEP_PEER_CERTIFICATE */
    if (src->peer_cert_digest != NULL) {
        dst->peer_cert_digest =
            pf_mbedtls_calloc(1, src->peer_cert_digest_len);
        if (dst->peer_cert_digest == NULL) {
            return PF_MBEDTLS_ERR_SSL_ALLOC_FAILED;
        }

        memcpy(dst->peer_cert_digest, src->peer_cert_digest,
               src->peer_cert_digest_len);
        dst->peer_cert_digest_type = src->peer_cert_digest_type;
        dst->peer_cert_digest_len = src->peer_cert_digest_len;
    }
#endif /* MBEDTLS_SSL_KEEP_PEER_CERTIFICATE */

#endif /* MBEDTLS_X509_CRT_PARSE_C */

#if defined(PF_MBEDTLS_SSL_SRV_C) && defined(PF_MBEDTLS_SSL_ALPN) && \
    defined(PF_MBEDTLS_SSL_EARLY_DATA)
    {
        int ret = pf_mbedtls_ssl_session_set_ticket_alpn(dst, src->ticket_alpn);
        if (ret != 0) {
            return ret;
        }
    }
#endif /* MBEDTLS_SSL_SRV_C && MBEDTLS_SSL_ALPN && MBEDTLS_SSL_EARLY_DATA */

#if defined(PF_MBEDTLS_SSL_SESSION_TICKETS) && defined(PF_MBEDTLS_SSL_CLI_C)
    if (src->ticket != NULL) {
        dst->ticket = pf_mbedtls_calloc(1, src->ticket_len);
        if (dst->ticket == NULL) {
            return PF_MBEDTLS_ERR_SSL_ALLOC_FAILED;
        }

        memcpy(dst->ticket, src->ticket, src->ticket_len);
    }

#if defined(PF_MBEDTLS_SSL_PROTO_TLS1_3) && \
    defined(PF_MBEDTLS_SSL_SERVER_NAME_INDICATION)
    if (src->endpoint == PF_MBEDTLS_SSL_IS_CLIENT) {
        int ret = PF_MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
        ret = pf_mbedtls_ssl_session_set_hostname(dst, src->hostname);
        if (ret != 0) {
            return ret;
        }
    }
#endif /* MBEDTLS_SSL_PROTO_TLS1_3 &&
          MBEDTLS_SSL_SERVER_NAME_INDICATION */
#endif /* MBEDTLS_SSL_SESSION_TICKETS && MBEDTLS_SSL_CLI_C */

    return 0;
}

#if defined(PF_MBEDTLS_SSL_VARIABLE_BUFFER_LENGTH)
PF_MBEDTLS_CHECK_RETURN_CRITICAL
static int resize_buffer(unsigned char **buffer, size_t len_new, size_t *len_old)
{
    unsigned char *resized_buffer = pf_mbedtls_calloc(1, len_new);
    if (resized_buffer == NULL) {
        return PF_MBEDTLS_ERR_SSL_ALLOC_FAILED;
    }

    /* We want to copy len_new bytes when downsizing the buffer, and
     * len_old bytes when upsizing, so we choose the smaller of two sizes,
     * to fit one buffer into another. Size checks, ensuring that no data is
     * lost, are done outside of this function. */
    memcpy(resized_buffer, *buffer,
           (len_new < *len_old) ? len_new : *len_old);
    pf_mbedtls_zeroize_and_free(*buffer, *len_old);

    *buffer = resized_buffer;
    *len_old = len_new;

    return 0;
}

static void handle_buffer_resizing(pf_mbedtls_ssl_context *ssl, int downsizing,
                                   size_t in_buf_new_len,
                                   size_t out_buf_new_len)
{
    int modified = 0;
    size_t written_in = 0, iv_offset_in = 0, len_offset_in = 0, hdr_in = 0;
    size_t written_out = 0, iv_offset_out = 0, len_offset_out = 0;
    if (ssl->in_buf != NULL) {
        written_in = ssl->in_msg - ssl->in_buf;
        iv_offset_in = ssl->in_iv - ssl->in_buf;
        len_offset_in = ssl->in_len - ssl->in_buf;
        hdr_in = ssl->in_hdr - ssl->in_buf;
        if (downsizing ?
            ssl->in_buf_len > in_buf_new_len && ssl->in_left < in_buf_new_len :
            ssl->in_buf_len < in_buf_new_len) {
            if (resize_buffer(&ssl->in_buf, in_buf_new_len, &ssl->in_buf_len) != 0) {
                PF_MBEDTLS_SSL_DEBUG_MSG(1, ("input buffer resizing failed - out of memory"));
            } else {
                PF_MBEDTLS_SSL_DEBUG_MSG(2, ("Reallocating in_buf to %" PF_MBEDTLS_PRINTF_SIZET,
                                          in_buf_new_len));
                modified = 1;
            }
        }
    }

    if (ssl->out_buf != NULL) {
        written_out = ssl->out_msg - ssl->out_buf;
        iv_offset_out = ssl->out_iv - ssl->out_buf;
        len_offset_out = ssl->out_len - ssl->out_buf;
        if (downsizing ?
            ssl->out_buf_len > out_buf_new_len && ssl->out_left < out_buf_new_len :
            ssl->out_buf_len < out_buf_new_len) {
            if (resize_buffer(&ssl->out_buf, out_buf_new_len, &ssl->out_buf_len) != 0) {
                PF_MBEDTLS_SSL_DEBUG_MSG(1, ("output buffer resizing failed - out of memory"));
            } else {
                PF_MBEDTLS_SSL_DEBUG_MSG(2, ("Reallocating out_buf to %" PF_MBEDTLS_PRINTF_SIZET,
                                          out_buf_new_len));
                modified = 1;
            }
        }
    }
    if (modified) {
        /* Update pointers here to avoid doing it twice. */
        ssl->in_hdr = ssl->in_buf + hdr_in;
        pf_mbedtls_ssl_update_in_pointers(ssl);
        pf_mbedtls_ssl_reset_out_pointers(ssl);

        /* Fields below might not be properly updated with record
         * splitting or with CID, so they are manually updated here. */
        ssl->out_msg = ssl->out_buf + written_out;
        ssl->out_len = ssl->out_buf + len_offset_out;
        ssl->out_iv = ssl->out_buf + iv_offset_out;

        ssl->in_msg = ssl->in_buf + written_in;
        ssl->in_len = ssl->in_buf + len_offset_in;
        ssl->in_iv = ssl->in_buf + iv_offset_in;
    }
}
#endif /* MBEDTLS_SSL_VARIABLE_BUFFER_LENGTH */

#if defined(PF_MBEDTLS_SSL_PROTO_TLS1_2)

#if defined(PF_MBEDTLS_SSL_CONTEXT_SERIALIZATION)
typedef int (*tls_prf_fn)(const unsigned char *secret, size_t slen,
                          const char *label,
                          const unsigned char *random, size_t rlen,
                          unsigned char *dstbuf, size_t dlen);

static tls_prf_fn ssl_tls12prf_from_cs(int ciphersuite_id);

#endif /* MBEDTLS_SSL_CONTEXT_SERIALIZATION */

/* Type for the TLS PRF */
typedef int ssl_tls_prf_t(const unsigned char *, size_t, const char *,
                          const unsigned char *, size_t,
                          unsigned char *, size_t);

PF_MBEDTLS_CHECK_RETURN_CRITICAL
static int ssl_tls12_populate_transform(pf_mbedtls_ssl_transform *transform,
                                        int ciphersuite,
                                        const unsigned char master[48],
#if defined(PF_MBEDTLS_SSL_SOME_SUITES_USE_CBC_ETM)
                                        int encrypt_then_mac,
#endif /* MBEDTLS_SSL_SOME_SUITES_USE_CBC_ETM */
                                        ssl_tls_prf_t tls_prf,
                                        const unsigned char randbytes[64],
                                        pf_mbedtls_ssl_protocol_version tls_version,
                                        unsigned endpoint,
                                        const pf_mbedtls_ssl_context *ssl);

#if defined(PF_MBEDTLS_MD_CAN_SHA256)
PF_MBEDTLS_CHECK_RETURN_CRITICAL
static int tls_prf_sha256(const unsigned char *secret, size_t slen,
                          const char *label,
                          const unsigned char *random, size_t rlen,
                          unsigned char *dstbuf, size_t dlen);
static int ssl_calc_verify_tls_sha256(const pf_mbedtls_ssl_context *, unsigned char *, size_t *);
static int ssl_calc_finished_tls_sha256(pf_mbedtls_ssl_context *, unsigned char *, int);

#endif /* MBEDTLS_MD_CAN_SHA256*/

#if defined(PF_MBEDTLS_MD_CAN_SHA384)
PF_MBEDTLS_CHECK_RETURN_CRITICAL
static int tls_prf_sha384(const unsigned char *secret, size_t slen,
                          const char *label,
                          const unsigned char *random, size_t rlen,
                          unsigned char *dstbuf, size_t dlen);

static int ssl_calc_verify_tls_sha384(const pf_mbedtls_ssl_context *, unsigned char *, size_t *);
static int ssl_calc_finished_tls_sha384(pf_mbedtls_ssl_context *, unsigned char *, int);
#endif /* MBEDTLS_MD_CAN_SHA384*/

PF_MBEDTLS_CHECK_RETURN_CRITICAL
static int ssl_tls12_session_load(pf_mbedtls_ssl_session *session,
                                  const unsigned char *buf,
                                  size_t len);
#endif /* MBEDTLS_SSL_PROTO_TLS1_2 */

static int ssl_update_checksum_start(pf_mbedtls_ssl_context *, const unsigned char *, size_t);

#if defined(PF_MBEDTLS_MD_CAN_SHA256)
static int ssl_update_checksum_sha256(pf_mbedtls_ssl_context *, const unsigned char *, size_t);
#endif /* MBEDTLS_MD_CAN_SHA256*/

#if defined(PF_MBEDTLS_MD_CAN_SHA384)
static int ssl_update_checksum_sha384(pf_mbedtls_ssl_context *, const unsigned char *, size_t);
#endif /* MBEDTLS_MD_CAN_SHA384*/

int  pf_mbedtls_ssl_tls_prf(const pf_mbedtls_tls_prf_types prf,
                         const unsigned char *secret, size_t slen,
                         const char *label,
                         const unsigned char *random, size_t rlen,
                         unsigned char *dstbuf, size_t dlen)
{
    pf_mbedtls_ssl_tls_prf_cb *tls_prf = NULL;

    switch (prf) {
#if defined(PF_MBEDTLS_SSL_PROTO_TLS1_2)
#if defined(PF_MBEDTLS_MD_CAN_SHA384)
        case PF_MBEDTLS_SSL_TLS_PRF_SHA384:
            tls_prf = tls_prf_sha384;
            break;
#endif /* MBEDTLS_MD_CAN_SHA384*/
#if defined(PF_MBEDTLS_MD_CAN_SHA256)
        case PF_MBEDTLS_SSL_TLS_PRF_SHA256:
            tls_prf = tls_prf_sha256;
            break;
#endif /* MBEDTLS_MD_CAN_SHA256*/
#endif /* MBEDTLS_SSL_PROTO_TLS1_2 */
        default:
            return PF_MBEDTLS_ERR_SSL_FEATURE_UNAVAILABLE;
    }

    return tls_prf(secret, slen, label, random, rlen, dstbuf, dlen);
}

#if defined(PF_MBEDTLS_X509_CRT_PARSE_C)
static void ssl_clear_peer_cert(pf_mbedtls_ssl_session *session)
{
#if defined(PF_MBEDTLS_SSL_KEEP_PEER_CERTIFICATE)
    if (session->peer_cert != NULL) {
        pf_mbedtls_x509_crt_free(session->peer_cert);
        pf_mbedtls_free(session->peer_cert);
        session->peer_cert = NULL;
    }
#else /* MBEDTLS_SSL_KEEP_PEER_CERTIFICATE */
    if (session->peer_cert_digest != NULL) {
        /* Zeroization is not necessary. */
        pf_mbedtls_free(session->peer_cert_digest);
        session->peer_cert_digest      = NULL;
        session->peer_cert_digest_type = PF_MBEDTLS_MD_NONE;
        session->peer_cert_digest_len  = 0;
    }
#endif /* !MBEDTLS_SSL_KEEP_PEER_CERTIFICATE */
}
#endif /* MBEDTLS_X509_CRT_PARSE_C */

uint32_t pf_mbedtls_ssl_get_extension_id(unsigned int extension_type)
{
    switch (extension_type) {
        case PF_MBEDTLS_TLS_EXT_SERVERNAME:
            return PF_MBEDTLS_SSL_EXT_ID_SERVERNAME;

        case PF_MBEDTLS_TLS_EXT_MAX_FRAGMENT_LENGTH:
            return PF_MBEDTLS_SSL_EXT_ID_MAX_FRAGMENT_LENGTH;

        case PF_MBEDTLS_TLS_EXT_STATUS_REQUEST:
            return PF_MBEDTLS_SSL_EXT_ID_STATUS_REQUEST;

        case PF_MBEDTLS_TLS_EXT_SUPPORTED_GROUPS:
            return PF_MBEDTLS_SSL_EXT_ID_SUPPORTED_GROUPS;

        case PF_MBEDTLS_TLS_EXT_SIG_ALG:
            return PF_MBEDTLS_SSL_EXT_ID_SIG_ALG;

        case PF_MBEDTLS_TLS_EXT_USE_SRTP:
            return PF_MBEDTLS_SSL_EXT_ID_USE_SRTP;

        case PF_MBEDTLS_TLS_EXT_HEARTBEAT:
            return PF_MBEDTLS_SSL_EXT_ID_HEARTBEAT;

        case PF_MBEDTLS_TLS_EXT_ALPN:
            return PF_MBEDTLS_SSL_EXT_ID_ALPN;

        case PF_MBEDTLS_TLS_EXT_SCT:
            return PF_MBEDTLS_SSL_EXT_ID_SCT;

        case PF_MBEDTLS_TLS_EXT_CLI_CERT_TYPE:
            return PF_MBEDTLS_SSL_EXT_ID_CLI_CERT_TYPE;

        case PF_MBEDTLS_TLS_EXT_SERV_CERT_TYPE:
            return PF_MBEDTLS_SSL_EXT_ID_SERV_CERT_TYPE;

        case PF_MBEDTLS_TLS_EXT_PADDING:
            return PF_MBEDTLS_SSL_EXT_ID_PADDING;

        case PF_MBEDTLS_TLS_EXT_PRE_SHARED_KEY:
            return PF_MBEDTLS_SSL_EXT_ID_PRE_SHARED_KEY;

        case PF_MBEDTLS_TLS_EXT_EARLY_DATA:
            return PF_MBEDTLS_SSL_EXT_ID_EARLY_DATA;

        case PF_MBEDTLS_TLS_EXT_SUPPORTED_VERSIONS:
            return PF_MBEDTLS_SSL_EXT_ID_SUPPORTED_VERSIONS;

        case PF_MBEDTLS_TLS_EXT_COOKIE:
            return PF_MBEDTLS_SSL_EXT_ID_COOKIE;

        case PF_MBEDTLS_TLS_EXT_PSK_KEY_EXCHANGE_MODES:
            return PF_MBEDTLS_SSL_EXT_ID_PSK_KEY_EXCHANGE_MODES;

        case PF_MBEDTLS_TLS_EXT_CERT_AUTH:
            return PF_MBEDTLS_SSL_EXT_ID_CERT_AUTH;

        case PF_MBEDTLS_TLS_EXT_OID_FILTERS:
            return PF_MBEDTLS_SSL_EXT_ID_OID_FILTERS;

        case PF_MBEDTLS_TLS_EXT_POST_HANDSHAKE_AUTH:
            return PF_MBEDTLS_SSL_EXT_ID_POST_HANDSHAKE_AUTH;

        case PF_MBEDTLS_TLS_EXT_SIG_ALG_CERT:
            return PF_MBEDTLS_SSL_EXT_ID_SIG_ALG_CERT;

        case PF_MBEDTLS_TLS_EXT_KEY_SHARE:
            return PF_MBEDTLS_SSL_EXT_ID_KEY_SHARE;

        case PF_MBEDTLS_TLS_EXT_TRUNCATED_HMAC:
            return PF_MBEDTLS_SSL_EXT_ID_TRUNCATED_HMAC;

        case PF_MBEDTLS_TLS_EXT_SUPPORTED_POINT_FORMATS:
            return PF_MBEDTLS_SSL_EXT_ID_SUPPORTED_POINT_FORMATS;

        case PF_MBEDTLS_TLS_EXT_ENCRYPT_THEN_MAC:
            return PF_MBEDTLS_SSL_EXT_ID_ENCRYPT_THEN_MAC;

        case PF_MBEDTLS_TLS_EXT_EXTENDED_MASTER_SECRET:
            return PF_MBEDTLS_SSL_EXT_ID_EXTENDED_MASTER_SECRET;

        case PF_MBEDTLS_TLS_EXT_RECORD_SIZE_LIMIT:
            return PF_MBEDTLS_SSL_EXT_ID_RECORD_SIZE_LIMIT;

        case PF_MBEDTLS_TLS_EXT_SESSION_TICKET:
            return PF_MBEDTLS_SSL_EXT_ID_SESSION_TICKET;

    }

    return PF_MBEDTLS_SSL_EXT_ID_UNRECOGNIZED;
}

uint32_t pf_mbedtls_ssl_get_extension_mask(unsigned int extension_type)
{
    return 1 << pf_mbedtls_ssl_get_extension_id(extension_type);
}

#if defined(PF_MBEDTLS_DEBUG_C)
static const char *extension_name_table[] = {
    [PF_MBEDTLS_SSL_EXT_ID_UNRECOGNIZED] = "unrecognized",
    [PF_MBEDTLS_SSL_EXT_ID_SERVERNAME] = "server_name",
    [PF_MBEDTLS_SSL_EXT_ID_MAX_FRAGMENT_LENGTH] = "max_fragment_length",
    [PF_MBEDTLS_SSL_EXT_ID_STATUS_REQUEST] = "status_request",
    [PF_MBEDTLS_SSL_EXT_ID_SUPPORTED_GROUPS] = "supported_groups",
    [PF_MBEDTLS_SSL_EXT_ID_SIG_ALG] = "signature_algorithms",
    [PF_MBEDTLS_SSL_EXT_ID_USE_SRTP] = "use_srtp",
    [PF_MBEDTLS_SSL_EXT_ID_HEARTBEAT] = "heartbeat",
    [PF_MBEDTLS_SSL_EXT_ID_ALPN] = "application_layer_protocol_negotiation",
    [PF_MBEDTLS_SSL_EXT_ID_SCT] = "signed_certificate_timestamp",
    [PF_MBEDTLS_SSL_EXT_ID_CLI_CERT_TYPE] = "client_certificate_type",
    [PF_MBEDTLS_SSL_EXT_ID_SERV_CERT_TYPE] = "server_certificate_type",
    [PF_MBEDTLS_SSL_EXT_ID_PADDING] = "padding",
    [PF_MBEDTLS_SSL_EXT_ID_PRE_SHARED_KEY] = "pre_shared_key",
    [PF_MBEDTLS_SSL_EXT_ID_EARLY_DATA] = "early_data",
    [PF_MBEDTLS_SSL_EXT_ID_SUPPORTED_VERSIONS] = "supported_versions",
    [PF_MBEDTLS_SSL_EXT_ID_COOKIE] = "cookie",
    [PF_MBEDTLS_SSL_EXT_ID_PSK_KEY_EXCHANGE_MODES] = "psk_key_exchange_modes",
    [PF_MBEDTLS_SSL_EXT_ID_CERT_AUTH] = "certificate_authorities",
    [PF_MBEDTLS_SSL_EXT_ID_OID_FILTERS] = "oid_filters",
    [PF_MBEDTLS_SSL_EXT_ID_POST_HANDSHAKE_AUTH] = "post_handshake_auth",
    [PF_MBEDTLS_SSL_EXT_ID_SIG_ALG_CERT] = "signature_algorithms_cert",
    [PF_MBEDTLS_SSL_EXT_ID_KEY_SHARE] = "key_share",
    [PF_MBEDTLS_SSL_EXT_ID_TRUNCATED_HMAC] = "truncated_hmac",
    [PF_MBEDTLS_SSL_EXT_ID_SUPPORTED_POINT_FORMATS] = "supported_point_formats",
    [PF_MBEDTLS_SSL_EXT_ID_ENCRYPT_THEN_MAC] = "encrypt_then_mac",
    [PF_MBEDTLS_SSL_EXT_ID_EXTENDED_MASTER_SECRET] = "extended_master_secret",
    [PF_MBEDTLS_SSL_EXT_ID_SESSION_TICKET] = "session_ticket",
    [PF_MBEDTLS_SSL_EXT_ID_RECORD_SIZE_LIMIT] = "record_size_limit"
};

static const unsigned int extension_type_table[] = {
    [PF_MBEDTLS_SSL_EXT_ID_UNRECOGNIZED] = 0xff,
    [PF_MBEDTLS_SSL_EXT_ID_SERVERNAME] = PF_MBEDTLS_TLS_EXT_SERVERNAME,
    [PF_MBEDTLS_SSL_EXT_ID_MAX_FRAGMENT_LENGTH] = PF_MBEDTLS_TLS_EXT_MAX_FRAGMENT_LENGTH,
    [PF_MBEDTLS_SSL_EXT_ID_STATUS_REQUEST] = PF_MBEDTLS_TLS_EXT_STATUS_REQUEST,
    [PF_MBEDTLS_SSL_EXT_ID_SUPPORTED_GROUPS] = PF_MBEDTLS_TLS_EXT_SUPPORTED_GROUPS,
    [PF_MBEDTLS_SSL_EXT_ID_SIG_ALG] = PF_MBEDTLS_TLS_EXT_SIG_ALG,
    [PF_MBEDTLS_SSL_EXT_ID_USE_SRTP] = PF_MBEDTLS_TLS_EXT_USE_SRTP,
    [PF_MBEDTLS_SSL_EXT_ID_HEARTBEAT] = PF_MBEDTLS_TLS_EXT_HEARTBEAT,
    [PF_MBEDTLS_SSL_EXT_ID_ALPN] = PF_MBEDTLS_TLS_EXT_ALPN,
    [PF_MBEDTLS_SSL_EXT_ID_SCT] = PF_MBEDTLS_TLS_EXT_SCT,
    [PF_MBEDTLS_SSL_EXT_ID_CLI_CERT_TYPE] = PF_MBEDTLS_TLS_EXT_CLI_CERT_TYPE,
    [PF_MBEDTLS_SSL_EXT_ID_SERV_CERT_TYPE] = PF_MBEDTLS_TLS_EXT_SERV_CERT_TYPE,
    [PF_MBEDTLS_SSL_EXT_ID_PADDING] = PF_MBEDTLS_TLS_EXT_PADDING,
    [PF_MBEDTLS_SSL_EXT_ID_PRE_SHARED_KEY] = PF_MBEDTLS_TLS_EXT_PRE_SHARED_KEY,
    [PF_MBEDTLS_SSL_EXT_ID_EARLY_DATA] = PF_MBEDTLS_TLS_EXT_EARLY_DATA,
    [PF_MBEDTLS_SSL_EXT_ID_SUPPORTED_VERSIONS] = PF_MBEDTLS_TLS_EXT_SUPPORTED_VERSIONS,
    [PF_MBEDTLS_SSL_EXT_ID_COOKIE] = PF_MBEDTLS_TLS_EXT_COOKIE,
    [PF_MBEDTLS_SSL_EXT_ID_PSK_KEY_EXCHANGE_MODES] = PF_MBEDTLS_TLS_EXT_PSK_KEY_EXCHANGE_MODES,
    [PF_MBEDTLS_SSL_EXT_ID_CERT_AUTH] = PF_MBEDTLS_TLS_EXT_CERT_AUTH,
    [PF_MBEDTLS_SSL_EXT_ID_OID_FILTERS] = PF_MBEDTLS_TLS_EXT_OID_FILTERS,
    [PF_MBEDTLS_SSL_EXT_ID_POST_HANDSHAKE_AUTH] = PF_MBEDTLS_TLS_EXT_POST_HANDSHAKE_AUTH,
    [PF_MBEDTLS_SSL_EXT_ID_SIG_ALG_CERT] = PF_MBEDTLS_TLS_EXT_SIG_ALG_CERT,
    [PF_MBEDTLS_SSL_EXT_ID_KEY_SHARE] = PF_MBEDTLS_TLS_EXT_KEY_SHARE,
    [PF_MBEDTLS_SSL_EXT_ID_TRUNCATED_HMAC] = PF_MBEDTLS_TLS_EXT_TRUNCATED_HMAC,
    [PF_MBEDTLS_SSL_EXT_ID_SUPPORTED_POINT_FORMATS] = PF_MBEDTLS_TLS_EXT_SUPPORTED_POINT_FORMATS,
    [PF_MBEDTLS_SSL_EXT_ID_ENCRYPT_THEN_MAC] = PF_MBEDTLS_TLS_EXT_ENCRYPT_THEN_MAC,
    [PF_MBEDTLS_SSL_EXT_ID_EXTENDED_MASTER_SECRET] = PF_MBEDTLS_TLS_EXT_EXTENDED_MASTER_SECRET,
    [PF_MBEDTLS_SSL_EXT_ID_SESSION_TICKET] = PF_MBEDTLS_TLS_EXT_SESSION_TICKET,
    [PF_MBEDTLS_SSL_EXT_ID_RECORD_SIZE_LIMIT] = PF_MBEDTLS_TLS_EXT_RECORD_SIZE_LIMIT
};

const char *pf_mbedtls_ssl_get_extension_name(unsigned int extension_type)
{
    return extension_name_table[
        pf_mbedtls_ssl_get_extension_id(extension_type)];
}

const char *pf_mbedtls_ssl_get_hs_msg_name(int hs_msg_type)
{
    switch (hs_msg_type) {
        case PF_MBEDTLS_SSL_HS_CLIENT_HELLO:
            return "ClientHello";
        case PF_MBEDTLS_SSL_HS_SERVER_HELLO:
            return "ServerHello";
        case PF_MBEDTLS_SSL_TLS1_3_HS_HELLO_RETRY_REQUEST:
            return "HelloRetryRequest";
        case PF_MBEDTLS_SSL_HS_NEW_SESSION_TICKET:
            return "NewSessionTicket";
        case PF_MBEDTLS_SSL_HS_ENCRYPTED_EXTENSIONS:
            return "EncryptedExtensions";
        case PF_MBEDTLS_SSL_HS_CERTIFICATE:
            return "Certificate";
        case PF_MBEDTLS_SSL_HS_SERVER_KEY_EXCHANGE:
            return "ServerKeyExchange";
        case PF_MBEDTLS_SSL_HS_CERTIFICATE_REQUEST:
            return "CertificateRequest";
        case PF_MBEDTLS_SSL_HS_CERTIFICATE_VERIFY:
            return "CertificateVerify";
        case PF_MBEDTLS_SSL_HS_CLIENT_KEY_EXCHANGE:
            return "ClientKeyExchange";
        case PF_MBEDTLS_SSL_HS_FINISHED:
            return "Finished";
    }
    return "Unknown";
}

void pf_mbedtls_ssl_print_extension(const pf_mbedtls_ssl_context *ssl,
                                 int level, const char *file, int line,
                                 int hs_msg_type, unsigned int extension_type,
                                 const char *extra_msg0, const char *extra_msg1)
{
    const char *extra_msg;
    if (extra_msg0 && extra_msg1) {
        pf_mbedtls_debug_print_msg(
            ssl, level, file, line,
            "%s: %s(%u) extension %s %s.",
            pf_mbedtls_ssl_get_hs_msg_name(hs_msg_type),
            pf_mbedtls_ssl_get_extension_name(extension_type),
            extension_type,
            extra_msg0, extra_msg1);
        return;
    }

    extra_msg = extra_msg0 ? extra_msg0 : extra_msg1;
    if (extra_msg) {
        pf_mbedtls_debug_print_msg(
            ssl, level, file, line,
            "%s: %s(%u) extension %s.", pf_mbedtls_ssl_get_hs_msg_name(hs_msg_type),
            pf_mbedtls_ssl_get_extension_name(extension_type), extension_type,
            extra_msg);
        return;
    }

    pf_mbedtls_debug_print_msg(
        ssl, level, file, line,
        "%s: %s(%u) extension.", pf_mbedtls_ssl_get_hs_msg_name(hs_msg_type),
        pf_mbedtls_ssl_get_extension_name(extension_type), extension_type);
}

void pf_mbedtls_ssl_print_extensions(const pf_mbedtls_ssl_context *ssl,
                                  int level, const char *file, int line,
                                  int hs_msg_type, uint32_t extensions_mask,
                                  const char *extra)
{

    for (unsigned i = 0;
         i < sizeof(extension_name_table) / sizeof(extension_name_table[0]);
         i++) {
        pf_mbedtls_ssl_print_extension(
            ssl, level, file, line, hs_msg_type, extension_type_table[i],
            extensions_mask & (1 << i) ? "exists" : "does not exist", extra);
    }
}

#if defined(PF_MBEDTLS_SSL_PROTO_TLS1_3) && defined(PF_MBEDTLS_SSL_SESSION_TICKETS)
static const char *ticket_flag_name_table[] =
{
    [0] = "ALLOW_PSK_RESUMPTION",
    [2] = "ALLOW_PSK_EPHEMERAL_RESUMPTION",
    [3] = "ALLOW_EARLY_DATA",
};

void pf_mbedtls_ssl_print_ticket_flags(const pf_mbedtls_ssl_context *ssl,
                                    int level, const char *file, int line,
                                    unsigned int flags)
{
    size_t i;

    pf_mbedtls_debug_print_msg(ssl, level, file, line,
                            "print ticket_flags (0x%02x)", flags);

    flags = flags & PF_MBEDTLS_SSL_TLS1_3_TICKET_FLAGS_MASK;

    for (i = 0; i < ARRAY_LENGTH(ticket_flag_name_table); i++) {
        if ((flags & (1 << i))) {
            pf_mbedtls_debug_print_msg(ssl, level, file, line, "- %s is set.",
                                    ticket_flag_name_table[i]);
        }
    }
}
#endif /* MBEDTLS_SSL_PROTO_TLS1_3 && MBEDTLS_SSL_SESSION_TICKETS */

#endif /* MBEDTLS_DEBUG_C */

void pf_mbedtls_ssl_optimize_checksum(pf_mbedtls_ssl_context *ssl,
                                   const pf_mbedtls_ssl_ciphersuite_t *ciphersuite_info)
{
    ((void) ciphersuite_info);

#if defined(PF_MBEDTLS_MD_CAN_SHA384)
    if (ciphersuite_info->mac == PF_MBEDTLS_MD_SHA384) {
        ssl->handshake->update_checksum = ssl_update_checksum_sha384;
    } else
#endif
#if defined(PF_MBEDTLS_MD_CAN_SHA256)
    if (ciphersuite_info->mac != PF_MBEDTLS_MD_SHA384) {
        ssl->handshake->update_checksum = ssl_update_checksum_sha256;
    } else
#endif
    {
        PF_MBEDTLS_SSL_DEBUG_MSG(1, ("should never happen"));
        return;
    }
}

int pf_mbedtls_ssl_add_hs_hdr_to_checksum(pf_mbedtls_ssl_context *ssl,
                                       unsigned hs_type,
                                       size_t total_hs_len)
{
    unsigned char hs_hdr[4];

    /* Build HS header for checksum update. */
    hs_hdr[0] = PF_MBEDTLS_BYTE_0(hs_type);
    hs_hdr[1] = PF_MBEDTLS_BYTE_2(total_hs_len);
    hs_hdr[2] = PF_MBEDTLS_BYTE_1(total_hs_len);
    hs_hdr[3] = PF_MBEDTLS_BYTE_0(total_hs_len);

    return ssl->handshake->update_checksum(ssl, hs_hdr, sizeof(hs_hdr));
}

int pf_mbedtls_ssl_add_hs_msg_to_checksum(pf_mbedtls_ssl_context *ssl,
                                       unsigned hs_type,
                                       unsigned char const *msg,
                                       size_t msg_len)
{
    int ret;
    ret = pf_mbedtls_ssl_add_hs_hdr_to_checksum(ssl, hs_type, msg_len);
    if (ret != 0) {
        return ret;
    }
    return ssl->handshake->update_checksum(ssl, msg, msg_len);
}

int pf_mbedtls_ssl_reset_checksum(pf_mbedtls_ssl_context *ssl)
{
#if defined(PF_MBEDTLS_MD_CAN_SHA256) || \
    defined(PF_MBEDTLS_MD_CAN_SHA384)
#if defined(PF_MBEDTLS_USE_PSA_CRYPTO)
    pf_psa_status_t status;
#else
    int ret = PF_MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
#endif
#else /* SHA-256 or SHA-384 */
    ((void) ssl);
#endif /* SHA-256 or SHA-384 */
#if defined(PF_MBEDTLS_MD_CAN_SHA256)
#if defined(PF_MBEDTLS_USE_PSA_CRYPTO)
    status = pf_psa_hash_abort(&ssl->handshake->fin_sha256_psa);
    if (status != PF_PSA_SUCCESS) {
        return PF_PSA_TO_MBEDTLS_ERR(status);
    }
    status = pf_psa_hash_setup(&ssl->handshake->fin_sha256_psa, PF_PSA_ALG_SHA_256);
    if (status != PF_PSA_SUCCESS) {
        return PF_PSA_TO_MBEDTLS_ERR(status);
    }
#else
    pf_mbedtls_md_free(&ssl->handshake->fin_sha256);
    pf_mbedtls_md_init(&ssl->handshake->fin_sha256);
    ret = pf_mbedtls_md_setup(&ssl->handshake->fin_sha256,
                           pf_mbedtls_md_info_from_type(PF_MBEDTLS_MD_SHA256),
                           0);
    if (ret != 0) {
        return ret;
    }
    ret = pf_mbedtls_md_starts(&ssl->handshake->fin_sha256);
    if (ret != 0) {
        return ret;
    }
#endif
#endif
#if defined(PF_MBEDTLS_MD_CAN_SHA384)
#if defined(PF_MBEDTLS_USE_PSA_CRYPTO)
    status = pf_psa_hash_abort(&ssl->handshake->fin_sha384_psa);
    if (status != PF_PSA_SUCCESS) {
        return PF_PSA_TO_MBEDTLS_ERR(status);
    }
    status = pf_psa_hash_setup(&ssl->handshake->fin_sha384_psa, PF_PSA_ALG_SHA_384);
    if (status != PF_PSA_SUCCESS) {
        return PF_PSA_TO_MBEDTLS_ERR(status);
    }
#else
    pf_mbedtls_md_free(&ssl->handshake->fin_sha384);
    pf_mbedtls_md_init(&ssl->handshake->fin_sha384);
    ret = pf_mbedtls_md_setup(&ssl->handshake->fin_sha384,
                           pf_mbedtls_md_info_from_type(PF_MBEDTLS_MD_SHA384), 0);
    if (ret != 0) {
        return ret;
    }
    ret = pf_mbedtls_md_starts(&ssl->handshake->fin_sha384);
    if (ret != 0) {
        return ret;
    }
#endif
#endif
    return 0;
}

static int ssl_update_checksum_start(pf_mbedtls_ssl_context *ssl,
                                     const unsigned char *buf, size_t len)
{
#if defined(PF_MBEDTLS_MD_CAN_SHA256) || \
    defined(PF_MBEDTLS_MD_CAN_SHA384)
#if defined(PF_MBEDTLS_USE_PSA_CRYPTO)
    pf_psa_status_t status;
#else
    int ret = PF_MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
#endif
#else /* SHA-256 or SHA-384 */
    ((void) ssl);
    (void) buf;
    (void) len;
#endif /* SHA-256 or SHA-384 */
#if defined(PF_MBEDTLS_MD_CAN_SHA256)
#if defined(PF_MBEDTLS_USE_PSA_CRYPTO)
    status = pf_psa_hash_update(&ssl->handshake->fin_sha256_psa, buf, len);
    if (status != PF_PSA_SUCCESS) {
        return PF_PSA_TO_MBEDTLS_ERR(status);
    }
#else
    ret = pf_mbedtls_md_update(&ssl->handshake->fin_sha256, buf, len);
    if (ret != 0) {
        return ret;
    }
#endif
#endif
#if defined(PF_MBEDTLS_MD_CAN_SHA384)
#if defined(PF_MBEDTLS_USE_PSA_CRYPTO)
    status = pf_psa_hash_update(&ssl->handshake->fin_sha384_psa, buf, len);
    if (status != PF_PSA_SUCCESS) {
        return PF_PSA_TO_MBEDTLS_ERR(status);
    }
#else
    ret = pf_mbedtls_md_update(&ssl->handshake->fin_sha384, buf, len);
    if (ret != 0) {
        return ret;
    }
#endif
#endif
    return 0;
}

#if defined(PF_MBEDTLS_MD_CAN_SHA256)
static int ssl_update_checksum_sha256(pf_mbedtls_ssl_context *ssl,
                                      const unsigned char *buf, size_t len)
{
#if defined(PF_MBEDTLS_USE_PSA_CRYPTO)
    return PF_PSA_TO_MBEDTLS_ERR(pf_psa_hash_update(
                                  &ssl->handshake->fin_sha256_psa, buf, len));
#else
    return pf_mbedtls_md_update(&ssl->handshake->fin_sha256, buf, len);
#endif
}
#endif

#if defined(PF_MBEDTLS_MD_CAN_SHA384)
static int ssl_update_checksum_sha384(pf_mbedtls_ssl_context *ssl,
                                      const unsigned char *buf, size_t len)
{
#if defined(PF_MBEDTLS_USE_PSA_CRYPTO)
    return PF_PSA_TO_MBEDTLS_ERR(pf_psa_hash_update(
                                  &ssl->handshake->fin_sha384_psa, buf, len));
#else
    return pf_mbedtls_md_update(&ssl->handshake->fin_sha384, buf, len);
#endif
}
#endif

static void ssl_handshake_params_init(pf_mbedtls_ssl_handshake_params *handshake)
{
    memset(handshake, 0, sizeof(pf_mbedtls_ssl_handshake_params));

#if defined(PF_MBEDTLS_MD_CAN_SHA256)
#if defined(PF_MBEDTLS_USE_PSA_CRYPTO)
    handshake->fin_sha256_psa = pf_psa_hash_operation_init();
#else
    pf_mbedtls_md_init(&handshake->fin_sha256);
#endif
#endif
#if defined(PF_MBEDTLS_MD_CAN_SHA384)
#if defined(PF_MBEDTLS_USE_PSA_CRYPTO)
    handshake->fin_sha384_psa = pf_psa_hash_operation_init();
#else
    pf_mbedtls_md_init(&handshake->fin_sha384);
#endif
#endif

    handshake->update_checksum = ssl_update_checksum_start;

#if defined(PF_MBEDTLS_DHM_C)
    pf_mbedtls_dhm_init(&handshake->dhm_ctx);
#endif
#if !defined(PF_MBEDTLS_USE_PSA_CRYPTO) && \
    defined(PF_MBEDTLS_KEY_EXCHANGE_SOME_ECDH_OR_ECDHE_1_2_ENABLED)
    pf_mbedtls_ecdh_init(&handshake->ecdh_ctx);
#endif
#if defined(PF_MBEDTLS_KEY_EXCHANGE_ECJPAKE_ENABLED)
#if defined(PF_MBEDTLS_USE_PSA_CRYPTO)
    handshake->pf_psa_pake_ctx = pf_psa_pake_operation_init();
    handshake->pf_psa_pake_password = PF_MBEDTLS_SVC_KEY_ID_INIT;
#else
    pf_mbedtls_ecjpake_init(&handshake->ecjpake_ctx);
#endif /* MBEDTLS_USE_PSA_CRYPTO */
#if defined(PF_MBEDTLS_SSL_CLI_C)
    handshake->ecjpake_cache = NULL;
    handshake->ecjpake_cache_len = 0;
#endif
#endif

#if defined(PF_MBEDTLS_SSL_ECP_RESTARTABLE_ENABLED)
    pf_mbedtls_x509_crt_restart_init(&handshake->ecrs_ctx);
#endif

#if defined(PF_MBEDTLS_SSL_SERVER_NAME_INDICATION)
    handshake->sni_authmode = PF_MBEDTLS_SSL_VERIFY_UNSET;
#endif

#if defined(PF_MBEDTLS_X509_CRT_PARSE_C) && \
    !defined(PF_MBEDTLS_SSL_KEEP_PEER_CERTIFICATE)
    pf_mbedtls_pk_init(&handshake->peer_pubkey);
#endif
}

void pf_mbedtls_ssl_transform_init(pf_mbedtls_ssl_transform *transform)
{
    memset(transform, 0, sizeof(pf_mbedtls_ssl_transform));

#if defined(PF_MBEDTLS_USE_PSA_CRYPTO)
    transform->pf_psa_key_enc = PF_MBEDTLS_SVC_KEY_ID_INIT;
    transform->pf_psa_key_dec = PF_MBEDTLS_SVC_KEY_ID_INIT;
#else
    pf_mbedtls_cipher_init(&transform->cipher_ctx_enc);
    pf_mbedtls_cipher_init(&transform->cipher_ctx_dec);
#endif

#if defined(PF_MBEDTLS_SSL_SOME_SUITES_USE_MAC)
#if defined(PF_MBEDTLS_USE_PSA_CRYPTO)
    transform->pf_psa_mac_enc = PF_MBEDTLS_SVC_KEY_ID_INIT;
    transform->pf_psa_mac_dec = PF_MBEDTLS_SVC_KEY_ID_INIT;
#else
    pf_mbedtls_md_init(&transform->md_ctx_enc);
    pf_mbedtls_md_init(&transform->md_ctx_dec);
#endif
#endif
}

void pf_mbedtls_ssl_session_init(pf_mbedtls_ssl_session *session)
{
    memset(session, 0, sizeof(pf_mbedtls_ssl_session));
    /* Set verify_result to -1u to indicate 'result not available'. */
    session->verify_result = 0xFFFFFFFF;
}

PF_MBEDTLS_CHECK_RETURN_CRITICAL
static int ssl_handshake_init(pf_mbedtls_ssl_context *ssl)
{
    int ret = PF_MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;

    /* Clear old handshake information if present */
#if defined(PF_MBEDTLS_SSL_PROTO_TLS1_2)
    if (ssl->transform_negotiate) {
        pf_mbedtls_ssl_transform_free(ssl->transform_negotiate);
    }
#endif /* MBEDTLS_SSL_PROTO_TLS1_2 */
    if (ssl->session_negotiate) {
        pf_mbedtls_ssl_session_free(ssl->session_negotiate);
    }
    if (ssl->handshake) {
        pf_mbedtls_ssl_handshake_free(ssl);
    }

#if defined(PF_MBEDTLS_SSL_PROTO_TLS1_2)
    /*
     * Either the pointers are now NULL or cleared properly and can be freed.
     * Now allocate missing structures.
     */
    if (ssl->transform_negotiate == NULL) {
        ssl->transform_negotiate = pf_mbedtls_calloc(1, sizeof(pf_mbedtls_ssl_transform));
    }
#endif /* MBEDTLS_SSL_PROTO_TLS1_2 */

    if (ssl->session_negotiate == NULL) {
        ssl->session_negotiate = pf_mbedtls_calloc(1, sizeof(pf_mbedtls_ssl_session));
    }

    if (ssl->handshake == NULL) {
        ssl->handshake = pf_mbedtls_calloc(1, sizeof(pf_mbedtls_ssl_handshake_params));
    }
#if defined(PF_MBEDTLS_SSL_VARIABLE_BUFFER_LENGTH)
    /* If the buffers are too small - reallocate */

    handle_buffer_resizing(ssl, 0, PF_MBEDTLS_SSL_IN_BUFFER_LEN,
                           PF_MBEDTLS_SSL_OUT_BUFFER_LEN);
#endif

    /* All pointers should exist and can be directly freed without issue */
    if (ssl->handshake           == NULL ||
#if defined(PF_MBEDTLS_SSL_PROTO_TLS1_2)
        ssl->transform_negotiate == NULL ||
#endif
        ssl->session_negotiate   == NULL) {
        PF_MBEDTLS_SSL_DEBUG_MSG(1, ("alloc() of ssl sub-contexts failed"));

        pf_mbedtls_free(ssl->handshake);
        ssl->handshake = NULL;

#if defined(PF_MBEDTLS_SSL_PROTO_TLS1_2)
        pf_mbedtls_free(ssl->transform_negotiate);
        ssl->transform_negotiate = NULL;
#endif

        pf_mbedtls_free(ssl->session_negotiate);
        ssl->session_negotiate = NULL;

        return PF_MBEDTLS_ERR_SSL_ALLOC_FAILED;
    }

#if defined(PF_MBEDTLS_SSL_EARLY_DATA)
#if defined(PF_MBEDTLS_SSL_CLI_C)
    ssl->early_data_state = PF_MBEDTLS_SSL_EARLY_DATA_STATE_IDLE;
#endif
#if defined(PF_MBEDTLS_SSL_SRV_C)
    ssl->discard_early_data_record = PF_MBEDTLS_SSL_EARLY_DATA_NO_DISCARD;
#endif
    ssl->total_early_data_size = 0;
#endif /* MBEDTLS_SSL_EARLY_DATA */

    /* Initialize structures */
    pf_mbedtls_ssl_session_init(ssl->session_negotiate);
    ssl_handshake_params_init(ssl->handshake);

#if defined(PF_MBEDTLS_SSL_PROTO_TLS1_2)
    pf_mbedtls_ssl_transform_init(ssl->transform_negotiate);
#endif

    /* Setup handshake checksums */
    ret = pf_mbedtls_ssl_reset_checksum(ssl);
    if (ret != 0) {
        PF_MBEDTLS_SSL_DEBUG_RET(1, "mbedtls_ssl_reset_checksum", ret);
        return ret;
    }

#if defined(PF_MBEDTLS_SSL_PROTO_TLS1_3) && \
    defined(PF_MBEDTLS_SSL_SRV_C) && \
    defined(PF_MBEDTLS_SSL_SESSION_TICKETS)
    ssl->handshake->new_session_tickets_count =
        ssl->conf->new_session_tickets_count;
#endif

#if defined(PF_MBEDTLS_SSL_PROTO_DTLS)
    if (ssl->conf->transport == PF_MBEDTLS_SSL_TRANSPORT_DATAGRAM) {
        ssl->handshake->alt_transform_out = ssl->transform_out;

        if (ssl->conf->endpoint == PF_MBEDTLS_SSL_IS_CLIENT) {
            ssl->handshake->retransmit_state = PF_MBEDTLS_SSL_RETRANS_PREPARING;
        } else {
            ssl->handshake->retransmit_state = PF_MBEDTLS_SSL_RETRANS_WAITING;
        }

        pf_mbedtls_ssl_set_timer(ssl, 0);
    }
#endif

/*
 * curve_list is translated to IANA TLS group identifiers here because
 * mbedtls_ssl_conf_curves returns void and so can't return
 * any error codes.
 */
#if defined(PF_MBEDTLS_ECP_C)
#if !defined(PF_MBEDTLS_DEPRECATED_REMOVED)
    /* Heap allocate and translate curve_list from internal to IANA group ids */
    if (ssl->conf->curve_list != NULL) {
        size_t length;
        const pf_mbedtls_ecp_group_id *curve_list = ssl->conf->curve_list;

        for (length = 0;  (curve_list[length] != PF_MBEDTLS_ECP_DP_NONE); length++) {
        }

        /* Leave room for zero termination */
        uint16_t *group_list = pf_mbedtls_calloc(length + 1, sizeof(uint16_t));
        if (group_list == NULL) {
            return PF_MBEDTLS_ERR_SSL_ALLOC_FAILED;
        }

        for (size_t i = 0; i < length; i++) {
            uint16_t tls_id = pf_mbedtls_ssl_get_tls_id_from_ecp_group_id(
                curve_list[i]);
            if (tls_id == 0) {
                pf_mbedtls_free(group_list);
                return PF_MBEDTLS_ERR_SSL_BAD_CONFIG;
            }
            group_list[i] = tls_id;
        }

        group_list[length] = 0;

        ssl->handshake->group_list = group_list;
        ssl->handshake->group_list_heap_allocated = 1;
    } else {
        ssl->handshake->group_list = ssl->conf->group_list;
        ssl->handshake->group_list_heap_allocated = 0;
    }
#endif /* MBEDTLS_DEPRECATED_REMOVED */
#endif /* MBEDTLS_ECP_C */

#if defined(PF_MBEDTLS_SSL_HANDSHAKE_WITH_CERT_ENABLED)
#if !defined(PF_MBEDTLS_DEPRECATED_REMOVED)
#if defined(PF_MBEDTLS_SSL_PROTO_TLS1_2)
    /* Heap allocate and translate sig_hashes from internal hash identifiers to
       signature algorithms IANA identifiers.  */
    if (pf_mbedtls_ssl_conf_is_tls12_only(ssl->conf) &&
        ssl->conf->sig_hashes != NULL) {
        const int *md;
        const int *sig_hashes = ssl->conf->sig_hashes;
        size_t sig_algs_len = 0;
        uint16_t *p;

        PF_MBEDTLS_STATIC_ASSERT(PF_MBEDTLS_SSL_MAX_SIG_ALG_LIST_LEN
                              <= (SIZE_MAX - (2 * sizeof(uint16_t))),
                              "MBEDTLS_SSL_MAX_SIG_ALG_LIST_LEN too big");

        for (md = sig_hashes; *md != PF_MBEDTLS_MD_NONE; md++) {
            if (pf_mbedtls_ssl_hash_from_md_alg(*md) == PF_MBEDTLS_SSL_HASH_NONE) {
                continue;
            }
#if defined(PF_MBEDTLS_KEY_EXCHANGE_ECDSA_CERT_REQ_ALLOWED_ENABLED)
            sig_algs_len += sizeof(uint16_t);
#endif

#if defined(PF_MBEDTLS_RSA_C)
            sig_algs_len += sizeof(uint16_t);
#endif
            if (sig_algs_len > PF_MBEDTLS_SSL_MAX_SIG_ALG_LIST_LEN) {
                return PF_MBEDTLS_ERR_SSL_BAD_CONFIG;
            }
        }

        if (sig_algs_len < PF_MBEDTLS_SSL_MIN_SIG_ALG_LIST_LEN) {
            return PF_MBEDTLS_ERR_SSL_BAD_CONFIG;
        }

        ssl->handshake->sig_algs = pf_mbedtls_calloc(1, sig_algs_len +
                                                  sizeof(uint16_t));
        if (ssl->handshake->sig_algs == NULL) {
            return PF_MBEDTLS_ERR_SSL_ALLOC_FAILED;
        }

        p = (uint16_t *) ssl->handshake->sig_algs;
        for (md = sig_hashes; *md != PF_MBEDTLS_MD_NONE; md++) {
            unsigned char hash = pf_mbedtls_ssl_hash_from_md_alg(*md);
            if (hash == PF_MBEDTLS_SSL_HASH_NONE) {
                continue;
            }
#if defined(PF_MBEDTLS_KEY_EXCHANGE_ECDSA_CERT_REQ_ALLOWED_ENABLED)
            *p = ((hash << 8) | PF_MBEDTLS_SSL_SIG_ECDSA);
            p++;
#endif
#if defined(PF_MBEDTLS_RSA_C)
            *p = ((hash << 8) | PF_MBEDTLS_SSL_SIG_RSA);
            p++;
#endif
        }
        *p = PF_MBEDTLS_TLS_SIG_NONE;
        ssl->handshake->sig_algs_heap_allocated = 1;
    } else
#endif /* MBEDTLS_SSL_PROTO_TLS1_2 */
    {
        ssl->handshake->sig_algs_heap_allocated = 0;
    }
#endif /* !MBEDTLS_DEPRECATED_REMOVED */
#endif /* MBEDTLS_SSL_HANDSHAKE_WITH_CERT_ENABLED */
    return 0;
}

#if defined(PF_MBEDTLS_SSL_DTLS_HELLO_VERIFY) && defined(PF_MBEDTLS_SSL_SRV_C)
/* Dummy cookie callbacks for defaults */
PF_MBEDTLS_CHECK_RETURN_CRITICAL
static int ssl_cookie_write_dummy(void *ctx,
                                  unsigned char **p, unsigned char *end,
                                  const unsigned char *cli_id, size_t cli_id_len)
{
    ((void) ctx);
    ((void) p);
    ((void) end);
    ((void) cli_id);
    ((void) cli_id_len);

    return PF_MBEDTLS_ERR_SSL_FEATURE_UNAVAILABLE;
}

PF_MBEDTLS_CHECK_RETURN_CRITICAL
static int ssl_cookie_check_dummy(void *ctx,
                                  const unsigned char *cookie, size_t cookie_len,
                                  const unsigned char *cli_id, size_t cli_id_len)
{
    ((void) ctx);
    ((void) cookie);
    ((void) cookie_len);
    ((void) cli_id);
    ((void) cli_id_len);

    return PF_MBEDTLS_ERR_SSL_FEATURE_UNAVAILABLE;
}
#endif /* MBEDTLS_SSL_DTLS_HELLO_VERIFY && MBEDTLS_SSL_SRV_C */

/*
 * Initialize an SSL context
 */
void pf_mbedtls_ssl_init(pf_mbedtls_ssl_context *ssl)
{
    memset(ssl, 0, sizeof(pf_mbedtls_ssl_context));
}

PF_MBEDTLS_CHECK_RETURN_CRITICAL
static int ssl_conf_version_check(const pf_mbedtls_ssl_context *ssl)
{
    const pf_mbedtls_ssl_config *conf = ssl->conf;

#if defined(PF_MBEDTLS_SSL_PROTO_TLS1_3)
    if (pf_mbedtls_ssl_conf_is_tls13_only(conf)) {
        if (conf->transport == PF_MBEDTLS_SSL_TRANSPORT_DATAGRAM) {
            PF_MBEDTLS_SSL_DEBUG_MSG(1, ("DTLS 1.3 is not yet supported."));
            return PF_MBEDTLS_ERR_SSL_FEATURE_UNAVAILABLE;
        }

        PF_MBEDTLS_SSL_DEBUG_MSG(4, ("The SSL configuration is tls13 only."));
        return 0;
    }
#endif

#if defined(PF_MBEDTLS_SSL_PROTO_TLS1_2)
    if (pf_mbedtls_ssl_conf_is_tls12_only(conf)) {
        PF_MBEDTLS_SSL_DEBUG_MSG(4, ("The SSL configuration is tls12 only."));
        return 0;
    }
#endif

#if defined(PF_MBEDTLS_SSL_PROTO_TLS1_2) && defined(PF_MBEDTLS_SSL_PROTO_TLS1_3)
    if (pf_mbedtls_ssl_conf_is_hybrid_tls12_tls13(conf)) {
        if (ssl->conf->transport == PF_MBEDTLS_SSL_TRANSPORT_DATAGRAM) {
            PF_MBEDTLS_SSL_DEBUG_MSG(1, ("DTLS not yet supported in Hybrid TLS 1.3 + TLS 1.2"));
            return PF_MBEDTLS_ERR_SSL_FEATURE_UNAVAILABLE;
        }

        PF_MBEDTLS_SSL_DEBUG_MSG(4, ("The SSL configuration is TLS 1.3 or TLS 1.2."));
        return 0;
    }
#endif

    PF_MBEDTLS_SSL_DEBUG_MSG(1, ("The SSL configuration is invalid."));
    return PF_MBEDTLS_ERR_SSL_BAD_CONFIG;
}

PF_MBEDTLS_CHECK_RETURN_CRITICAL
static int ssl_conf_check(const pf_mbedtls_ssl_context *ssl)
{
    int ret;
    ret = ssl_conf_version_check(ssl);
    if (ret != 0) {
        return ret;
    }

    if (ssl->conf->f_rng == NULL) {
        PF_MBEDTLS_SSL_DEBUG_MSG(1, ("no RNG provided"));
        return PF_MBEDTLS_ERR_SSL_NO_RNG;
    }

    /* Space for further checks */

    return 0;
}

/*
 * Setup an SSL context
 */

int pf_mbedtls_ssl_setup(pf_mbedtls_ssl_context *ssl,
                      const pf_mbedtls_ssl_config *conf)
{
    int ret = PF_MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    size_t in_buf_len = PF_MBEDTLS_SSL_IN_BUFFER_LEN;
    size_t out_buf_len = PF_MBEDTLS_SSL_OUT_BUFFER_LEN;

    ssl->conf = conf;

    if ((ret = ssl_conf_check(ssl)) != 0) {
        return ret;
    }
    ssl->tls_version = ssl->conf->max_tls_version;

    /*
     * Prepare base structures
     */

    /* Set to NULL in case of an error condition */
    ssl->out_buf = NULL;

#if defined(PF_MBEDTLS_SSL_VARIABLE_BUFFER_LENGTH)
    ssl->in_buf_len = in_buf_len;
#endif
    ssl->in_buf = pf_mbedtls_calloc(1, in_buf_len);
    if (ssl->in_buf == NULL) {
        PF_MBEDTLS_SSL_DEBUG_MSG(1, ("alloc(%" PF_MBEDTLS_PRINTF_SIZET " bytes) failed", in_buf_len));
        ret = PF_MBEDTLS_ERR_SSL_ALLOC_FAILED;
        goto error;
    }

#if defined(PF_MBEDTLS_SSL_VARIABLE_BUFFER_LENGTH)
    ssl->out_buf_len = out_buf_len;
#endif
    ssl->out_buf = pf_mbedtls_calloc(1, out_buf_len);
    if (ssl->out_buf == NULL) {
        PF_MBEDTLS_SSL_DEBUG_MSG(1, ("alloc(%" PF_MBEDTLS_PRINTF_SIZET " bytes) failed", out_buf_len));
        ret = PF_MBEDTLS_ERR_SSL_ALLOC_FAILED;
        goto error;
    }

    pf_mbedtls_ssl_reset_in_pointers(ssl);
    pf_mbedtls_ssl_reset_out_pointers(ssl);

#if defined(PF_MBEDTLS_SSL_DTLS_SRTP)
    memset(&ssl->dtls_srtp_info, 0, sizeof(ssl->dtls_srtp_info));
#endif

    if ((ret = ssl_handshake_init(ssl)) != 0) {
        goto error;
    }

    return 0;

error:
    pf_mbedtls_free(ssl->in_buf);
    pf_mbedtls_free(ssl->out_buf);

    ssl->conf = NULL;

#if defined(PF_MBEDTLS_SSL_VARIABLE_BUFFER_LENGTH)
    ssl->in_buf_len = 0;
    ssl->out_buf_len = 0;
#endif
    ssl->in_buf = NULL;
    ssl->out_buf = NULL;

    ssl->in_hdr = NULL;
    ssl->in_ctr = NULL;
    ssl->in_len = NULL;
    ssl->in_iv = NULL;
    ssl->in_msg = NULL;

    ssl->out_hdr = NULL;
    ssl->out_ctr = NULL;
    ssl->out_len = NULL;
    ssl->out_iv = NULL;
    ssl->out_msg = NULL;

    return ret;
}

/*
 * Reset an initialized and used SSL context for re-use while retaining
 * all application-set variables, function pointers and data.
 *
 * If partial is non-zero, keep data in the input buffer and client ID.
 * (Use when a DTLS client reconnects from the same port.)
 */
void pf_mbedtls_ssl_session_reset_msg_layer(pf_mbedtls_ssl_context *ssl,
                                         int partial)
{
#if defined(PF_MBEDTLS_SSL_VARIABLE_BUFFER_LENGTH)
    size_t in_buf_len = ssl->in_buf_len;
    size_t out_buf_len = ssl->out_buf_len;
#else
    size_t in_buf_len = PF_MBEDTLS_SSL_IN_BUFFER_LEN;
    size_t out_buf_len = PF_MBEDTLS_SSL_OUT_BUFFER_LEN;
#endif

#if !defined(PF_MBEDTLS_SSL_DTLS_CLIENT_PORT_REUSE) || !defined(PF_MBEDTLS_SSL_SRV_C)
    partial = 0;
#endif

    /* Cancel any possibly running timer */
    pf_mbedtls_ssl_set_timer(ssl, 0);

    pf_mbedtls_ssl_reset_in_pointers(ssl);
    pf_mbedtls_ssl_reset_out_pointers(ssl);

    /* Reset incoming message parsing */
    ssl->in_offt    = NULL;
    ssl->nb_zero    = 0;
    ssl->in_msgtype = 0;
    ssl->in_msglen  = 0;
    ssl->in_hslen   = 0;
    ssl->keep_current_message = 0;
    ssl->transform_in  = NULL;

    /* TLS: reset in_hsfraglen, which is part of message parsing.
     * DTLS: on a client reconnect, don't reset badmac_seen. */
    if (!partial) {
        ssl->badmac_seen_or_in_hsfraglen = 0;
    }

#if defined(PF_MBEDTLS_SSL_PROTO_DTLS)
    ssl->next_record_offset = 0;
    ssl->in_epoch = 0;
#endif

    /* Keep current datagram if partial == 1 */
    if (partial == 0) {
        ssl->in_left = 0;
        memset(ssl->in_buf, 0, in_buf_len);
    }

    ssl->send_alert = 0;
    ssl->alert_reason = 0;
    ssl->alert_type = 0;

    /* Reset outgoing message writing */
    ssl->out_msgtype = 0;
    ssl->out_msglen  = 0;
    ssl->out_left    = 0;
    memset(ssl->out_buf, 0, out_buf_len);
    memset(ssl->cur_out_ctr, 0, sizeof(ssl->cur_out_ctr));
    ssl->transform_out = NULL;

#if defined(PF_MBEDTLS_SSL_DTLS_ANTI_REPLAY)
    pf_mbedtls_ssl_dtls_replay_reset(ssl);
#endif

#if defined(PF_MBEDTLS_SSL_PROTO_TLS1_2)
    if (ssl->transform) {
        pf_mbedtls_ssl_transform_free(ssl->transform);
        pf_mbedtls_free(ssl->transform);
        ssl->transform = NULL;
    }
#endif /* MBEDTLS_SSL_PROTO_TLS1_2 */

#if defined(PF_MBEDTLS_SSL_PROTO_TLS1_3)
    pf_mbedtls_ssl_transform_free(ssl->transform_application);
    pf_mbedtls_free(ssl->transform_application);
    ssl->transform_application = NULL;

    if (ssl->handshake != NULL) {
#if defined(PF_MBEDTLS_SSL_EARLY_DATA)
        pf_mbedtls_ssl_transform_free(ssl->handshake->transform_earlydata);
        pf_mbedtls_free(ssl->handshake->transform_earlydata);
        ssl->handshake->transform_earlydata = NULL;
#endif

        pf_mbedtls_ssl_transform_free(ssl->handshake->transform_handshake);
        pf_mbedtls_free(ssl->handshake->transform_handshake);
        ssl->handshake->transform_handshake = NULL;
    }

#endif /* MBEDTLS_SSL_PROTO_TLS1_3 */
}

int pf_mbedtls_ssl_session_reset_int(pf_mbedtls_ssl_context *ssl, int partial)
{
    int ret = PF_MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;

    pf_mbedtls_ssl_handshake_set_state(ssl, PF_MBEDTLS_SSL_HELLO_REQUEST);
    ssl->tls_version = ssl->conf->max_tls_version;

    pf_mbedtls_ssl_session_reset_msg_layer(ssl, partial);

    /* Reset renegotiation state */
#if defined(PF_MBEDTLS_SSL_RENEGOTIATION)
    ssl->renego_status = PF_MBEDTLS_SSL_INITIAL_HANDSHAKE;
    ssl->renego_records_seen = 0;

    ssl->verify_data_len = 0;
    memset(ssl->own_verify_data, 0, PF_MBEDTLS_SSL_VERIFY_DATA_MAX_LEN);
    memset(ssl->peer_verify_data, 0, PF_MBEDTLS_SSL_VERIFY_DATA_MAX_LEN);
#endif
    ssl->secure_renegotiation = PF_MBEDTLS_SSL_LEGACY_RENEGOTIATION;

    ssl->session_in  = NULL;
    ssl->session_out = NULL;
    if (ssl->session) {
        pf_mbedtls_ssl_session_free(ssl->session);
        pf_mbedtls_free(ssl->session);
        ssl->session = NULL;
    }

#if defined(PF_MBEDTLS_SSL_ALPN)
    ssl->alpn_chosen = NULL;
#endif

#if defined(PF_MBEDTLS_SSL_DTLS_SRTP)
    memset(&ssl->dtls_srtp_info, 0, sizeof(ssl->dtls_srtp_info));
#endif /* MBEDTLS_SSL_DTLS_SRTP */

#if defined(PF_MBEDTLS_SSL_DTLS_HELLO_VERIFY) && defined(PF_MBEDTLS_SSL_SRV_C)
    int free_cli_id = 1;
#if defined(PF_MBEDTLS_SSL_DTLS_CLIENT_PORT_REUSE)
    free_cli_id = (partial == 0);
#endif
    if (free_cli_id) {
        pf_mbedtls_free(ssl->cli_id);
        ssl->cli_id = NULL;
        ssl->cli_id_len = 0;
    }
#endif

    if ((ret = ssl_handshake_init(ssl)) != 0) {
        return ret;
    }

    return 0;
}

/*
 * Reset an initialized and used SSL context for re-use while retaining
 * all application-set variables, function pointers and data.
 */
int pf_mbedtls_ssl_session_reset(pf_mbedtls_ssl_context *ssl)
{
    return pf_mbedtls_ssl_session_reset_int(ssl, 0);
}

/*
 * SSL set accessors
 */
void pf_mbedtls_ssl_conf_endpoint(pf_mbedtls_ssl_config *conf, int endpoint)
{
    conf->endpoint   = endpoint;
}

void pf_mbedtls_ssl_conf_transport(pf_mbedtls_ssl_config *conf, int transport)
{
    conf->transport = transport;
}

#if defined(PF_MBEDTLS_SSL_DTLS_ANTI_REPLAY)
void pf_mbedtls_ssl_conf_dtls_anti_replay(pf_mbedtls_ssl_config *conf, char mode)
{
    conf->anti_replay = mode;
}
#endif

void pf_mbedtls_ssl_conf_dtls_badmac_limit(pf_mbedtls_ssl_config *conf, unsigned limit)
{
    conf->badmac_limit = limit;
}

#if defined(PF_MBEDTLS_SSL_PROTO_DTLS)

void pf_mbedtls_ssl_set_datagram_packing(pf_mbedtls_ssl_context *ssl,
                                      unsigned allow_packing)
{
    ssl->disable_datagram_packing = !allow_packing;
}

void pf_mbedtls_ssl_conf_handshake_timeout(pf_mbedtls_ssl_config *conf,
                                        uint32_t min, uint32_t max)
{
    conf->hs_timeout_min = min;
    conf->hs_timeout_max = max;
}
#endif

void pf_mbedtls_ssl_conf_authmode(pf_mbedtls_ssl_config *conf, int authmode)
{
    conf->authmode   = authmode;
}

#if defined(PF_MBEDTLS_X509_CRT_PARSE_C)
void pf_mbedtls_ssl_conf_verify(pf_mbedtls_ssl_config *conf,
                             int (*f_vrfy)(void *, pf_mbedtls_x509_crt *, int, uint32_t *),
                             void *p_vrfy)
{
    conf->f_vrfy      = f_vrfy;
    conf->p_vrfy      = p_vrfy;
}
#endif /* MBEDTLS_X509_CRT_PARSE_C */

void pf_mbedtls_ssl_conf_rng(pf_mbedtls_ssl_config *conf,
                          int (*f_rng)(void *, unsigned char *, size_t),
                          void *p_rng)
{
    conf->f_rng      = f_rng;
    conf->p_rng      = p_rng;
}

void pf_mbedtls_ssl_conf_dbg(pf_mbedtls_ssl_config *conf,
                          void (*f_dbg)(void *, int, const char *, int, const char *),
                          void  *p_dbg)
{
    conf->f_dbg      = f_dbg;
    conf->p_dbg      = p_dbg;
}

void pf_mbedtls_ssl_set_bio(pf_mbedtls_ssl_context *ssl,
                         void *p_bio,
                         pf_mbedtls_ssl_send_t *f_send,
                         pf_mbedtls_ssl_recv_t *f_recv,
                         pf_mbedtls_ssl_recv_timeout_t *f_recv_timeout)
{
    ssl->p_bio          = p_bio;
    ssl->f_send         = f_send;
    ssl->f_recv         = f_recv;
    ssl->f_recv_timeout = f_recv_timeout;
}

#if defined(PF_MBEDTLS_SSL_PROTO_DTLS)
void pf_mbedtls_ssl_set_mtu(pf_mbedtls_ssl_context *ssl, uint16_t mtu)
{
    ssl->mtu = mtu;
}
#endif

void pf_mbedtls_ssl_conf_read_timeout(pf_mbedtls_ssl_config *conf, uint32_t timeout)
{
    conf->read_timeout   = timeout;
}

void pf_mbedtls_ssl_set_timer_cb(pf_mbedtls_ssl_context *ssl,
                              void *p_timer,
                              pf_mbedtls_ssl_set_timer_t *f_set_timer,
                              pf_mbedtls_ssl_get_timer_t *f_get_timer)
{
    ssl->p_timer        = p_timer;
    ssl->f_set_timer    = f_set_timer;
    ssl->f_get_timer    = f_get_timer;

    /* Make sure we start with no timer running */
    pf_mbedtls_ssl_set_timer(ssl, 0);
}

#if defined(PF_MBEDTLS_SSL_SRV_C)
void pf_mbedtls_ssl_conf_session_cache(pf_mbedtls_ssl_config *conf,
                                    void *p_cache,
                                    pf_mbedtls_ssl_cache_get_t *f_get_cache,
                                    pf_mbedtls_ssl_cache_set_t *f_set_cache)
{
    conf->p_cache = p_cache;
    conf->f_get_cache = f_get_cache;
    conf->f_set_cache = f_set_cache;
}
#endif /* MBEDTLS_SSL_SRV_C */

#if defined(PF_MBEDTLS_SSL_CLI_C)
int pf_mbedtls_ssl_set_session(pf_mbedtls_ssl_context *ssl, const pf_mbedtls_ssl_session *session)
{
    int ret = PF_MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;

    if (ssl == NULL ||
        session == NULL ||
        ssl->session_negotiate == NULL ||
        ssl->conf->endpoint != PF_MBEDTLS_SSL_IS_CLIENT) {
        return PF_MBEDTLS_ERR_SSL_BAD_INPUT_DATA;
    }

    if (ssl->handshake->resume == 1) {
        return PF_MBEDTLS_ERR_SSL_FEATURE_UNAVAILABLE;
    }

#if defined(PF_MBEDTLS_SSL_PROTO_TLS1_3)
    if (session->tls_version == PF_MBEDTLS_SSL_VERSION_TLS1_3) {
#if defined(PF_MBEDTLS_SSL_SESSION_TICKETS)
        const pf_mbedtls_ssl_ciphersuite_t *ciphersuite_info =
            pf_mbedtls_ssl_ciphersuite_from_id(session->ciphersuite);

        if (pf_mbedtls_ssl_validate_ciphersuite(
                ssl, ciphersuite_info, PF_MBEDTLS_SSL_VERSION_TLS1_3,
                PF_MBEDTLS_SSL_VERSION_TLS1_3) != 0) {
            PF_MBEDTLS_SSL_DEBUG_MSG(4, ("%d is not a valid TLS 1.3 ciphersuite.",
                                      session->ciphersuite));
            return PF_MBEDTLS_ERR_SSL_BAD_INPUT_DATA;
        }
#else
        /*
         * If session tickets are not enabled, it is not possible to resume a
         * TLS 1.3 session, thus do not make any change to the SSL context in
         * the first place.
         */
        return 0;
#endif
    }
#endif /* MBEDTLS_SSL_PROTO_TLS1_3 */

    if ((ret = pf_mbedtls_ssl_session_copy(ssl->session_negotiate,
                                        session)) != 0) {
        return ret;
    }

    ssl->handshake->resume = 1;

    return 0;
}
#endif /* MBEDTLS_SSL_CLI_C */

void pf_mbedtls_ssl_conf_ciphersuites(pf_mbedtls_ssl_config *conf,
                                   const int *ciphersuites)
{
    conf->ciphersuite_list = ciphersuites;
}

#if defined(PF_MBEDTLS_SSL_PROTO_TLS1_3)
void pf_mbedtls_ssl_conf_tls13_key_exchange_modes(pf_mbedtls_ssl_config *conf,
                                               const int kex_modes)
{
    conf->tls13_kex_modes = kex_modes & PF_MBEDTLS_SSL_TLS1_3_KEY_EXCHANGE_MODE_ALL;
}

#if defined(PF_MBEDTLS_SSL_EARLY_DATA)
void pf_mbedtls_ssl_conf_early_data(pf_mbedtls_ssl_config *conf,
                                 int early_data_enabled)
{
    conf->early_data_enabled = early_data_enabled;
}

#if defined(PF_MBEDTLS_SSL_SRV_C)
void pf_mbedtls_ssl_conf_max_early_data_size(
    pf_mbedtls_ssl_config *conf, uint32_t max_early_data_size)
{
    conf->max_early_data_size = max_early_data_size;
}
#endif /* MBEDTLS_SSL_SRV_C */

#endif /* MBEDTLS_SSL_EARLY_DATA */
#endif /* MBEDTLS_SSL_PROTO_TLS1_3 */

#if defined(PF_MBEDTLS_X509_CRT_PARSE_C)
void pf_mbedtls_ssl_conf_cert_profile(pf_mbedtls_ssl_config *conf,
                                   const pf_mbedtls_x509_crt_profile *profile)
{
    conf->cert_profile = profile;
}

static void ssl_key_cert_free(pf_mbedtls_ssl_key_cert *key_cert)
{
    pf_mbedtls_ssl_key_cert *cur = key_cert, *next;

    while (cur != NULL) {
        next = cur->next;
        pf_mbedtls_free(cur);
        cur = next;
    }
}

/* Append a new keycert entry to a (possibly empty) list */
PF_MBEDTLS_CHECK_RETURN_CRITICAL
static int ssl_append_key_cert(pf_mbedtls_ssl_key_cert **head,
                               pf_mbedtls_x509_crt *cert,
                               pf_mbedtls_pk_context *key)
{
    pf_mbedtls_ssl_key_cert *new_cert;

    if (cert == NULL) {
        /* Free list if cert is null */
        ssl_key_cert_free(*head);
        *head = NULL;
        return 0;
    }

    new_cert = pf_mbedtls_calloc(1, sizeof(pf_mbedtls_ssl_key_cert));
    if (new_cert == NULL) {
        return PF_MBEDTLS_ERR_SSL_ALLOC_FAILED;
    }

    new_cert->cert = cert;
    new_cert->key  = key;
    new_cert->next = NULL;

    /* Update head if the list was null, else add to the end */
    if (*head == NULL) {
        *head = new_cert;
    } else {
        pf_mbedtls_ssl_key_cert *cur = *head;
        while (cur->next != NULL) {
            cur = cur->next;
        }
        cur->next = new_cert;
    }

    return 0;
}

int pf_mbedtls_ssl_conf_own_cert(pf_mbedtls_ssl_config *conf,
                              pf_mbedtls_x509_crt *own_cert,
                              pf_mbedtls_pk_context *pk_key)
{
    return ssl_append_key_cert(&conf->key_cert, own_cert, pk_key);
}

void pf_mbedtls_ssl_conf_ca_chain(pf_mbedtls_ssl_config *conf,
                               pf_mbedtls_x509_crt *ca_chain,
                               pf_mbedtls_x509_crl *ca_crl)
{
    conf->ca_chain   = ca_chain;
    conf->ca_crl     = ca_crl;

#if defined(PF_MBEDTLS_X509_TRUSTED_CERTIFICATE_CALLBACK)
    /* mbedtls_ssl_conf_ca_chain() and mbedtls_ssl_conf_ca_cb()
     * cannot be used together. */
    conf->f_ca_cb = NULL;
    conf->p_ca_cb = NULL;
#endif /* MBEDTLS_X509_TRUSTED_CERTIFICATE_CALLBACK */
}

#if defined(PF_MBEDTLS_X509_TRUSTED_CERTIFICATE_CALLBACK)
void pf_mbedtls_ssl_conf_ca_cb(pf_mbedtls_ssl_config *conf,
                            pf_mbedtls_x509_crt_ca_cb_t f_ca_cb,
                            void *p_ca_cb)
{
    conf->f_ca_cb = f_ca_cb;
    conf->p_ca_cb = p_ca_cb;

    /* mbedtls_ssl_conf_ca_chain() and mbedtls_ssl_conf_ca_cb()
     * cannot be used together. */
    conf->ca_chain   = NULL;
    conf->ca_crl     = NULL;
}
#endif /* MBEDTLS_X509_TRUSTED_CERTIFICATE_CALLBACK */
#endif /* MBEDTLS_X509_CRT_PARSE_C */

#if defined(PF_MBEDTLS_SSL_SERVER_NAME_INDICATION)
const unsigned char *pf_mbedtls_ssl_get_hs_sni(pf_mbedtls_ssl_context *ssl,
                                            size_t *name_len)
{
    *name_len = ssl->handshake->sni_name_len;
    return ssl->handshake->sni_name;
}

int pf_mbedtls_ssl_set_hs_own_cert(pf_mbedtls_ssl_context *ssl,
                                pf_mbedtls_x509_crt *own_cert,
                                pf_mbedtls_pk_context *pk_key)
{
    return ssl_append_key_cert(&ssl->handshake->sni_key_cert,
                               own_cert, pk_key);
}

void pf_mbedtls_ssl_set_hs_ca_chain(pf_mbedtls_ssl_context *ssl,
                                 pf_mbedtls_x509_crt *ca_chain,
                                 pf_mbedtls_x509_crl *ca_crl)
{
    ssl->handshake->sni_ca_chain   = ca_chain;
    ssl->handshake->sni_ca_crl     = ca_crl;
}

#if defined(PF_MBEDTLS_KEY_EXCHANGE_CERT_REQ_ALLOWED_ENABLED)
void pf_mbedtls_ssl_set_hs_dn_hints(pf_mbedtls_ssl_context *ssl,
                                 const pf_mbedtls_x509_crt *crt)
{
    ssl->handshake->dn_hints = crt;
}
#endif /* MBEDTLS_KEY_EXCHANGE_CERT_REQ_ALLOWED_ENABLED */

void pf_mbedtls_ssl_set_hs_authmode(pf_mbedtls_ssl_context *ssl,
                                 int authmode)
{
    ssl->handshake->sni_authmode = authmode;
}
#endif /* MBEDTLS_SSL_SERVER_NAME_INDICATION */

#if defined(PF_MBEDTLS_X509_CRT_PARSE_C)
void pf_mbedtls_ssl_set_verify(pf_mbedtls_ssl_context *ssl,
                            int (*f_vrfy)(void *, pf_mbedtls_x509_crt *, int, uint32_t *),
                            void *p_vrfy)
{
    ssl->f_vrfy = f_vrfy;
    ssl->p_vrfy = p_vrfy;
}
#endif

#if defined(PF_MBEDTLS_KEY_EXCHANGE_ECJPAKE_ENABLED)

#if defined(PF_MBEDTLS_USE_PSA_CRYPTO)
static const uint8_t jpake_server_id[] = { 's', 'e', 'r', 'v', 'e', 'r' };
static const uint8_t jpake_client_id[] = { 'c', 'l', 'i', 'e', 'n', 't' };

static pf_psa_status_t pf_mbedtls_ssl_set_hs_ecjpake_password_common(
    pf_mbedtls_ssl_context *ssl,
    pf_mbedtls_svc_key_id_t pwd)
{
    pf_psa_status_t status;
    pf_psa_pake_cipher_suite_t cipher_suite = pf_psa_pake_cipher_suite_init();
    const uint8_t *user = NULL;
    size_t user_len = 0;
    const uint8_t *peer = NULL;
    size_t peer_len = 0;
    pf_psa_pake_cs_set_algorithm(&cipher_suite, PF_PSA_ALG_JPAKE);
    pf_psa_pake_cs_set_primitive(&cipher_suite,
                              PF_PSA_PAKE_PRIMITIVE(PF_PSA_PAKE_PRIMITIVE_TYPE_ECC,
                                                 PF_PSA_ECC_FAMILY_SECP_R1,
                                                 256));
    pf_psa_pake_cs_set_hash(&cipher_suite, PF_PSA_ALG_SHA_256);

    status = pf_psa_pake_setup(&ssl->handshake->pf_psa_pake_ctx, &cipher_suite);
    if (status != PF_PSA_SUCCESS) {
        return status;
    }

    if (ssl->conf->endpoint == PF_MBEDTLS_SSL_IS_SERVER) {
        user = jpake_server_id;
        user_len = sizeof(jpake_server_id);
        peer = jpake_client_id;
        peer_len = sizeof(jpake_client_id);
    } else {
        user = jpake_client_id;
        user_len = sizeof(jpake_client_id);
        peer = jpake_server_id;
        peer_len = sizeof(jpake_server_id);
    }

    status = pf_psa_pake_set_user(&ssl->handshake->pf_psa_pake_ctx, user, user_len);
    if (status != PF_PSA_SUCCESS) {
        return status;
    }

    status = pf_psa_pake_set_peer(&ssl->handshake->pf_psa_pake_ctx, peer, peer_len);
    if (status != PF_PSA_SUCCESS) {
        return status;
    }

    status = pf_psa_pake_set_password_key(&ssl->handshake->pf_psa_pake_ctx, pwd);
    if (status != PF_PSA_SUCCESS) {
        return status;
    }

    ssl->handshake->pf_psa_pake_ctx_is_ok = 1;

    return PF_PSA_SUCCESS;
}

int pf_mbedtls_ssl_set_hs_ecjpake_password(pf_mbedtls_ssl_context *ssl,
                                        const unsigned char *pw,
                                        size_t pw_len)
{
    pf_psa_key_attributes_t attributes = PF_PSA_KEY_ATTRIBUTES_INIT;
    pf_psa_status_t status;

    if (ssl->handshake == NULL || ssl->conf == NULL) {
        return PF_MBEDTLS_ERR_SSL_BAD_INPUT_DATA;
    }

    /* Empty password is not valid  */
    if ((pw == NULL) || (pw_len == 0)) {
        return PF_MBEDTLS_ERR_SSL_BAD_INPUT_DATA;
    }

    pf_psa_set_key_usage_flags(&attributes, PF_PSA_KEY_USAGE_DERIVE);
    pf_psa_set_key_algorithm(&attributes, PF_PSA_ALG_JPAKE);
    pf_psa_set_key_type(&attributes, PF_PSA_KEY_TYPE_PASSWORD);

    status = pf_psa_import_key(&attributes, pw, pw_len,
                            &ssl->handshake->pf_psa_pake_password);
    if (status != PF_PSA_SUCCESS) {
        return PF_MBEDTLS_ERR_SSL_HW_ACCEL_FAILED;
    }

    status = pf_mbedtls_ssl_set_hs_ecjpake_password_common(ssl,
                                                        ssl->handshake->pf_psa_pake_password);
    if (status != PF_PSA_SUCCESS) {
        pf_psa_destroy_key(ssl->handshake->pf_psa_pake_password);
        pf_psa_pake_abort(&ssl->handshake->pf_psa_pake_ctx);
        return PF_MBEDTLS_ERR_SSL_HW_ACCEL_FAILED;
    }

    return 0;
}

int pf_mbedtls_ssl_set_hs_ecjpake_password_opaque(pf_mbedtls_ssl_context *ssl,
                                               pf_mbedtls_svc_key_id_t pwd)
{
    pf_psa_status_t status;

    if (ssl->handshake == NULL || ssl->conf == NULL) {
        return PF_MBEDTLS_ERR_SSL_BAD_INPUT_DATA;
    }

    if (pf_mbedtls_svc_key_id_is_null(pwd)) {
        return PF_MBEDTLS_ERR_SSL_BAD_INPUT_DATA;
    }

    status = pf_mbedtls_ssl_set_hs_ecjpake_password_common(ssl, pwd);
    if (status != PF_PSA_SUCCESS) {
        pf_psa_pake_abort(&ssl->handshake->pf_psa_pake_ctx);
        return PF_MBEDTLS_ERR_SSL_HW_ACCEL_FAILED;
    }

    return 0;
}
#else /* MBEDTLS_USE_PSA_CRYPTO */
int pf_mbedtls_ssl_set_hs_ecjpake_password(pf_mbedtls_ssl_context *ssl,
                                        const unsigned char *pw,
                                        size_t pw_len)
{
    pf_mbedtls_ecjpake_role role;

    if (ssl->handshake == NULL || ssl->conf == NULL) {
        return PF_MBEDTLS_ERR_SSL_BAD_INPUT_DATA;
    }

    /* Empty password is not valid  */
    if ((pw == NULL) || (pw_len == 0)) {
        return PF_MBEDTLS_ERR_SSL_BAD_INPUT_DATA;
    }

    if (ssl->conf->endpoint == PF_MBEDTLS_SSL_IS_SERVER) {
        role = PF_MBEDTLS_ECJPAKE_SERVER;
    } else {
        role = PF_MBEDTLS_ECJPAKE_CLIENT;
    }

    return pf_mbedtls_ecjpake_setup(&ssl->handshake->ecjpake_ctx,
                                 role,
                                 PF_MBEDTLS_MD_SHA256,
                                 PF_MBEDTLS_ECP_DP_SECP256R1,
                                 pw, pw_len);
}
#endif /* MBEDTLS_USE_PSA_CRYPTO */
#endif /* MBEDTLS_KEY_EXCHANGE_ECJPAKE_ENABLED */

#if defined(PF_MBEDTLS_SSL_HANDSHAKE_WITH_PSK_ENABLED)
int pf_mbedtls_ssl_conf_has_static_psk(pf_mbedtls_ssl_config const *conf)
{
    if (conf->psk_identity     == NULL ||
        conf->psk_identity_len == 0) {
        return 0;
    }

#if defined(PF_MBEDTLS_USE_PSA_CRYPTO)
    if (!pf_mbedtls_svc_key_id_is_null(conf->psk_opaque)) {
        return 1;
    }
#endif /* MBEDTLS_USE_PSA_CRYPTO */

    if (conf->psk != NULL && conf->psk_len != 0) {
        return 1;
    }

    return 0;
}

static void ssl_conf_remove_psk(pf_mbedtls_ssl_config *conf)
{
    /* Remove reference to existing PSK, if any. */
#if defined(PF_MBEDTLS_USE_PSA_CRYPTO)
    if (!pf_mbedtls_svc_key_id_is_null(conf->psk_opaque)) {
        /* The maintenance of the PSK key slot is the
         * user's responsibility. */
        conf->psk_opaque = PF_MBEDTLS_SVC_KEY_ID_INIT;
    }
#endif /* MBEDTLS_USE_PSA_CRYPTO */
    if (conf->psk != NULL) {
        pf_mbedtls_zeroize_and_free(conf->psk, conf->psk_len);
        conf->psk = NULL;
        conf->psk_len = 0;
    }

    /* Remove reference to PSK identity, if any. */
    if (conf->psk_identity != NULL) {
        pf_mbedtls_free(conf->psk_identity);
        conf->psk_identity = NULL;
        conf->psk_identity_len = 0;
    }
}

/* This function assumes that PSK identity in the SSL config is unset.
 * It checks that the provided identity is well-formed and attempts
 * to make a copy of it in the SSL config.
 * On failure, the PSK identity in the config remains unset. */
PF_MBEDTLS_CHECK_RETURN_CRITICAL
static int ssl_conf_set_psk_identity(pf_mbedtls_ssl_config *conf,
                                     unsigned char const *psk_identity,
                                     size_t psk_identity_len)
{
    /* Identity len will be encoded on two bytes */
    if (psk_identity               == NULL ||
        psk_identity_len           == 0    ||
        (psk_identity_len >> 16) != 0    ||
        psk_identity_len > PF_MBEDTLS_SSL_OUT_CONTENT_LEN) {
        return PF_MBEDTLS_ERR_SSL_BAD_INPUT_DATA;
    }

    conf->psk_identity = pf_mbedtls_calloc(1, psk_identity_len);
    if (conf->psk_identity == NULL) {
        return PF_MBEDTLS_ERR_SSL_ALLOC_FAILED;
    }

    conf->psk_identity_len = psk_identity_len;
    memcpy(conf->psk_identity, psk_identity, conf->psk_identity_len);

    return 0;
}

int pf_mbedtls_ssl_conf_psk(pf_mbedtls_ssl_config *conf,
                         const unsigned char *psk, size_t psk_len,
                         const unsigned char *psk_identity, size_t psk_identity_len)
{
    int ret = PF_MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;

    /* We currently only support one PSK, raw or opaque. */
    if (pf_mbedtls_ssl_conf_has_static_psk(conf)) {
        return PF_MBEDTLS_ERR_SSL_FEATURE_UNAVAILABLE;
    }

    /* Check and set raw PSK */
    if (psk == NULL) {
        return PF_MBEDTLS_ERR_SSL_BAD_INPUT_DATA;
    }
    if (psk_len == 0) {
        return PF_MBEDTLS_ERR_SSL_BAD_INPUT_DATA;
    }
    if (psk_len > PF_MBEDTLS_PSK_MAX_LEN) {
        return PF_MBEDTLS_ERR_SSL_BAD_INPUT_DATA;
    }

    if ((conf->psk = pf_mbedtls_calloc(1, psk_len)) == NULL) {
        return PF_MBEDTLS_ERR_SSL_ALLOC_FAILED;
    }
    conf->psk_len = psk_len;
    memcpy(conf->psk, psk, conf->psk_len);

    /* Check and set PSK Identity */
    ret = ssl_conf_set_psk_identity(conf, psk_identity, psk_identity_len);
    if (ret != 0) {
        ssl_conf_remove_psk(conf);
    }

    return ret;
}

static void ssl_remove_psk(pf_mbedtls_ssl_context *ssl)
{
#if defined(PF_MBEDTLS_USE_PSA_CRYPTO)
    if (!pf_mbedtls_svc_key_id_is_null(ssl->handshake->psk_opaque)) {
        /* The maintenance of the external PSK key slot is the
         * user's responsibility. */
        if (ssl->handshake->psk_opaque_is_internal) {
            pf_psa_destroy_key(ssl->handshake->psk_opaque);
            ssl->handshake->psk_opaque_is_internal = 0;
        }
        ssl->handshake->psk_opaque = PF_MBEDTLS_SVC_KEY_ID_INIT;
    }
#else
    if (ssl->handshake->psk != NULL) {
        pf_mbedtls_zeroize_and_free(ssl->handshake->psk,
                                 ssl->handshake->psk_len);
        ssl->handshake->psk_len = 0;
        ssl->handshake->psk = NULL;
    }
#endif /* MBEDTLS_USE_PSA_CRYPTO */
}

int pf_mbedtls_ssl_set_hs_psk(pf_mbedtls_ssl_context *ssl,
                           const unsigned char *psk, size_t psk_len)
{
#if defined(PF_MBEDTLS_USE_PSA_CRYPTO)
    pf_psa_key_attributes_t key_attributes = pf_psa_key_attributes_init();
    pf_psa_status_t status = PF_PSA_ERROR_CORRUPTION_DETECTED;
    pf_psa_algorithm_t alg = PF_PSA_ALG_NONE;
    pf_mbedtls_svc_key_id_t key = PF_MBEDTLS_SVC_KEY_ID_INIT;
#endif /* MBEDTLS_USE_PSA_CRYPTO */

    if (psk == NULL || ssl->handshake == NULL) {
        return PF_MBEDTLS_ERR_SSL_BAD_INPUT_DATA;
    }

    if (psk_len > PF_MBEDTLS_PSK_MAX_LEN) {
        return PF_MBEDTLS_ERR_SSL_BAD_INPUT_DATA;
    }

    ssl_remove_psk(ssl);

#if defined(PF_MBEDTLS_USE_PSA_CRYPTO)
#if defined(PF_MBEDTLS_SSL_PROTO_TLS1_2)
    if (ssl->tls_version == PF_MBEDTLS_SSL_VERSION_TLS1_2) {
        if (ssl->handshake->ciphersuite_info->mac == PF_MBEDTLS_MD_SHA384) {
            alg = PF_PSA_ALG_TLS12_PSK_TO_MS(PF_PSA_ALG_SHA_384);
        } else {
            alg = PF_PSA_ALG_TLS12_PSK_TO_MS(PF_PSA_ALG_SHA_256);
        }
        pf_psa_set_key_usage_flags(&key_attributes, PF_PSA_KEY_USAGE_DERIVE);
    }
#endif /* MBEDTLS_SSL_PROTO_TLS1_2 */

#if defined(PF_MBEDTLS_SSL_PROTO_TLS1_3)
    if (ssl->tls_version == PF_MBEDTLS_SSL_VERSION_TLS1_3) {
        alg = PF_PSA_ALG_HKDF_EXTRACT(PF_PSA_ALG_ANY_HASH);
        pf_psa_set_key_usage_flags(&key_attributes,
                                PF_PSA_KEY_USAGE_DERIVE | PF_PSA_KEY_USAGE_EXPORT);
    }
#endif /* MBEDTLS_SSL_PROTO_TLS1_3 */

    pf_psa_set_key_algorithm(&key_attributes, alg);
    pf_psa_set_key_type(&key_attributes, PF_PSA_KEY_TYPE_DERIVE);

    status = pf_psa_import_key(&key_attributes, psk, psk_len, &key);
    if (status != PF_PSA_SUCCESS) {
        return PF_MBEDTLS_ERR_SSL_HW_ACCEL_FAILED;
    }

    /* Allow calling psa_destroy_key() on psk remove */
    ssl->handshake->psk_opaque_is_internal = 1;
    return pf_mbedtls_ssl_set_hs_psk_opaque(ssl, key);
#else
    if ((ssl->handshake->psk = pf_mbedtls_calloc(1, psk_len)) == NULL) {
        return PF_MBEDTLS_ERR_SSL_ALLOC_FAILED;
    }

    ssl->handshake->psk_len = psk_len;
    memcpy(ssl->handshake->psk, psk, ssl->handshake->psk_len);

    return 0;
#endif /* MBEDTLS_USE_PSA_CRYPTO */
}

#if defined(PF_MBEDTLS_USE_PSA_CRYPTO)
int pf_mbedtls_ssl_conf_psk_opaque(pf_mbedtls_ssl_config *conf,
                                pf_mbedtls_svc_key_id_t psk,
                                const unsigned char *psk_identity,
                                size_t psk_identity_len)
{
    int ret = PF_MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;

    /* We currently only support one PSK, raw or opaque. */
    if (pf_mbedtls_ssl_conf_has_static_psk(conf)) {
        return PF_MBEDTLS_ERR_SSL_FEATURE_UNAVAILABLE;
    }

    /* Check and set opaque PSK */
    if (pf_mbedtls_svc_key_id_is_null(psk)) {
        return PF_MBEDTLS_ERR_SSL_BAD_INPUT_DATA;
    }
    conf->psk_opaque = psk;

    /* Check and set PSK Identity */
    ret = ssl_conf_set_psk_identity(conf, psk_identity,
                                    psk_identity_len);
    if (ret != 0) {
        ssl_conf_remove_psk(conf);
    }

    return ret;
}

int pf_mbedtls_ssl_set_hs_psk_opaque(pf_mbedtls_ssl_context *ssl,
                                  pf_mbedtls_svc_key_id_t psk)
{
    if ((pf_mbedtls_svc_key_id_is_null(psk)) ||
        (ssl->handshake == NULL)) {
        return PF_MBEDTLS_ERR_SSL_BAD_INPUT_DATA;
    }

    ssl_remove_psk(ssl);
    ssl->handshake->psk_opaque = psk;
    return 0;
}
#endif /* MBEDTLS_USE_PSA_CRYPTO */

#if defined(PF_MBEDTLS_SSL_SRV_C)
void pf_mbedtls_ssl_conf_psk_cb(pf_mbedtls_ssl_config *conf,
                             int (*f_psk)(void *, pf_mbedtls_ssl_context *, const unsigned char *,
                                          size_t),
                             void *p_psk)
{
    conf->f_psk = f_psk;
    conf->p_psk = p_psk;
}
#endif /* MBEDTLS_SSL_SRV_C */

#endif /* MBEDTLS_SSL_HANDSHAKE_WITH_PSK_ENABLED */

#if defined(PF_MBEDTLS_USE_PSA_CRYPTO)
static pf_mbedtls_ssl_mode_t pf_mbedtls_ssl_get_base_mode(
    pf_psa_algorithm_t alg)
{
#if defined(PF_MBEDTLS_SSL_SOME_SUITES_USE_MAC)
    if (alg == PF_PSA_ALG_CBC_NO_PADDING) {
        return PF_MBEDTLS_SSL_MODE_CBC;
    }
#endif /* MBEDTLS_SSL_SOME_SUITES_USE_MAC */
    if (PF_PSA_ALG_IS_AEAD(alg)) {
        return PF_MBEDTLS_SSL_MODE_AEAD;
    }
    return PF_MBEDTLS_SSL_MODE_STREAM;
}

#else /* MBEDTLS_USE_PSA_CRYPTO */

static pf_mbedtls_ssl_mode_t pf_mbedtls_ssl_get_base_mode(
    pf_mbedtls_cipher_mode_t mode)
{
#if defined(PF_MBEDTLS_SSL_SOME_SUITES_USE_MAC)
    if (mode == PF_MBEDTLS_MODE_CBC) {
        return PF_MBEDTLS_SSL_MODE_CBC;
    }
#endif /* MBEDTLS_SSL_SOME_SUITES_USE_MAC */

#if defined(PF_MBEDTLS_GCM_C) || \
    defined(PF_MBEDTLS_CCM_C) || \
    defined(PF_MBEDTLS_CHACHAPOLY_C)
    if (mode == PF_MBEDTLS_MODE_GCM ||
        mode == PF_MBEDTLS_MODE_CCM ||
        mode == PF_MBEDTLS_MODE_CHACHAPOLY) {
        return PF_MBEDTLS_SSL_MODE_AEAD;
    }
#endif /* MBEDTLS_GCM_C || MBEDTLS_CCM_C || MBEDTLS_CHACHAPOLY_C */

    return PF_MBEDTLS_SSL_MODE_STREAM;
}
#endif /* MBEDTLS_USE_PSA_CRYPTO */

static pf_mbedtls_ssl_mode_t pf_mbedtls_ssl_get_actual_mode(
    pf_mbedtls_ssl_mode_t base_mode,
    int encrypt_then_mac)
{
#if defined(PF_MBEDTLS_SSL_SOME_SUITES_USE_CBC_ETM)
    if (encrypt_then_mac == PF_MBEDTLS_SSL_ETM_ENABLED &&
        base_mode == PF_MBEDTLS_SSL_MODE_CBC) {
        return PF_MBEDTLS_SSL_MODE_CBC_ETM;
    }
#else
    (void) encrypt_then_mac;
#endif
    return base_mode;
}

pf_mbedtls_ssl_mode_t pf_mbedtls_ssl_get_mode_from_transform(
    const pf_mbedtls_ssl_transform *transform)
{
    pf_mbedtls_ssl_mode_t base_mode = pf_mbedtls_ssl_get_base_mode(
#if defined(PF_MBEDTLS_USE_PSA_CRYPTO)
        transform->pf_psa_alg
#else
        pf_mbedtls_cipher_get_cipher_mode(&transform->cipher_ctx_enc)
#endif
        );

    int encrypt_then_mac = 0;
#if defined(PF_MBEDTLS_SSL_SOME_SUITES_USE_CBC_ETM)
    encrypt_then_mac = transform->encrypt_then_mac;
#endif
    return pf_mbedtls_ssl_get_actual_mode(base_mode, encrypt_then_mac);
}

pf_mbedtls_ssl_mode_t pf_mbedtls_ssl_get_mode_from_ciphersuite(
#if defined(PF_MBEDTLS_SSL_SOME_SUITES_USE_CBC_ETM)
    int encrypt_then_mac,
#endif /* MBEDTLS_SSL_SOME_SUITES_USE_CBC_ETM */
    const pf_mbedtls_ssl_ciphersuite_t *suite)
{
    pf_mbedtls_ssl_mode_t base_mode = PF_MBEDTLS_SSL_MODE_STREAM;

#if defined(PF_MBEDTLS_USE_PSA_CRYPTO)
    pf_psa_status_t status;
    pf_psa_algorithm_t alg;
    pf_psa_key_type_t type;
    size_t size;
    status = pf_mbedtls_ssl_cipher_to_psa((pf_mbedtls_cipher_type_t) suite->cipher,
                                       0, &alg, &type, &size);
    if (status == PF_PSA_SUCCESS) {
        base_mode = pf_mbedtls_ssl_get_base_mode(alg);
    }
#else
    const pf_mbedtls_cipher_info_t *cipher =
        pf_mbedtls_cipher_info_from_type((pf_mbedtls_cipher_type_t) suite->cipher);
    if (cipher != NULL) {
        base_mode =
            pf_mbedtls_ssl_get_base_mode(
                pf_mbedtls_cipher_info_get_mode(cipher));
    }
#endif /* MBEDTLS_USE_PSA_CRYPTO */

#if !defined(PF_MBEDTLS_SSL_SOME_SUITES_USE_CBC_ETM)
    int encrypt_then_mac = 0;
#endif
    return pf_mbedtls_ssl_get_actual_mode(base_mode, encrypt_then_mac);
}

#if defined(PF_MBEDTLS_USE_PSA_CRYPTO) || defined(PF_MBEDTLS_SSL_PROTO_TLS1_3)

pf_psa_status_t pf_mbedtls_ssl_cipher_to_psa(pf_mbedtls_cipher_type_t pf_mbedtls_cipher_type,
                                       size_t taglen,
                                       pf_psa_algorithm_t *alg,
                                       pf_psa_key_type_t *key_type,
                                       size_t *key_size)
{
#if !defined(PF_MBEDTLS_SSL_HAVE_CCM)
    (void) taglen;
#endif
    switch (pf_mbedtls_cipher_type) {
#if defined(PF_MBEDTLS_SSL_HAVE_AES) && defined(PF_MBEDTLS_SSL_HAVE_CBC)
        case PF_MBEDTLS_CIPHER_AES_128_CBC:
            *alg = PF_PSA_ALG_CBC_NO_PADDING;
            *key_type = PF_PSA_KEY_TYPE_AES;
            *key_size = 128;
            break;
#endif
#if defined(PF_MBEDTLS_SSL_HAVE_AES) && defined(PF_MBEDTLS_SSL_HAVE_CCM)
        case PF_MBEDTLS_CIPHER_AES_128_CCM:
            *alg = taglen ? PF_PSA_ALG_AEAD_WITH_SHORTENED_TAG(PF_PSA_ALG_CCM, taglen) : PF_PSA_ALG_CCM;
            *key_type = PF_PSA_KEY_TYPE_AES;
            *key_size = 128;
            break;
#endif
#if defined(PF_MBEDTLS_SSL_HAVE_AES) && defined(PF_MBEDTLS_SSL_HAVE_GCM)
        case PF_MBEDTLS_CIPHER_AES_128_GCM:
            *alg = PF_PSA_ALG_GCM;
            *key_type = PF_PSA_KEY_TYPE_AES;
            *key_size = 128;
            break;
#endif
#if defined(PF_MBEDTLS_SSL_HAVE_AES) && defined(PF_MBEDTLS_SSL_HAVE_CCM)
        case PF_MBEDTLS_CIPHER_AES_192_CCM:
            *alg = taglen ? PF_PSA_ALG_AEAD_WITH_SHORTENED_TAG(PF_PSA_ALG_CCM, taglen) : PF_PSA_ALG_CCM;
            *key_type = PF_PSA_KEY_TYPE_AES;
            *key_size = 192;
            break;
#endif
#if defined(PF_MBEDTLS_SSL_HAVE_AES) && defined(PF_MBEDTLS_SSL_HAVE_GCM)
        case PF_MBEDTLS_CIPHER_AES_192_GCM:
            *alg = PF_PSA_ALG_GCM;
            *key_type = PF_PSA_KEY_TYPE_AES;
            *key_size = 192;
            break;
#endif
#if defined(PF_MBEDTLS_SSL_HAVE_AES) && defined(PF_MBEDTLS_SSL_HAVE_CBC)
        case PF_MBEDTLS_CIPHER_AES_256_CBC:
            *alg = PF_PSA_ALG_CBC_NO_PADDING;
            *key_type = PF_PSA_KEY_TYPE_AES;
            *key_size = 256;
            break;
#endif
#if defined(PF_MBEDTLS_SSL_HAVE_AES) && defined(PF_MBEDTLS_SSL_HAVE_CCM)
        case PF_MBEDTLS_CIPHER_AES_256_CCM:
            *alg = taglen ? PF_PSA_ALG_AEAD_WITH_SHORTENED_TAG(PF_PSA_ALG_CCM, taglen) : PF_PSA_ALG_CCM;
            *key_type = PF_PSA_KEY_TYPE_AES;
            *key_size = 256;
            break;
#endif
#if defined(PF_MBEDTLS_SSL_HAVE_AES) && defined(PF_MBEDTLS_SSL_HAVE_GCM)
        case PF_MBEDTLS_CIPHER_AES_256_GCM:
            *alg = PF_PSA_ALG_GCM;
            *key_type = PF_PSA_KEY_TYPE_AES;
            *key_size = 256;
            break;
#endif
#if defined(PF_MBEDTLS_SSL_HAVE_ARIA) && defined(PF_MBEDTLS_SSL_HAVE_CBC)
        case PF_MBEDTLS_CIPHER_ARIA_128_CBC:
            *alg = PF_PSA_ALG_CBC_NO_PADDING;
            *key_type = PF_PSA_KEY_TYPE_ARIA;
            *key_size = 128;
            break;
#endif
#if defined(PF_MBEDTLS_SSL_HAVE_ARIA) && defined(PF_MBEDTLS_SSL_HAVE_CCM)
        case PF_MBEDTLS_CIPHER_ARIA_128_CCM:
            *alg = taglen ? PF_PSA_ALG_AEAD_WITH_SHORTENED_TAG(PF_PSA_ALG_CCM, taglen) : PF_PSA_ALG_CCM;
            *key_type = PF_PSA_KEY_TYPE_ARIA;
            *key_size = 128;
            break;
#endif
#if defined(PF_MBEDTLS_SSL_HAVE_ARIA) && defined(PF_MBEDTLS_SSL_HAVE_GCM)
        case PF_MBEDTLS_CIPHER_ARIA_128_GCM:
            *alg = PF_PSA_ALG_GCM;
            *key_type = PF_PSA_KEY_TYPE_ARIA;
            *key_size = 128;
            break;
#endif
#if defined(PF_MBEDTLS_SSL_HAVE_ARIA) && defined(PF_MBEDTLS_SSL_HAVE_CCM)
        case PF_MBEDTLS_CIPHER_ARIA_192_CCM:
            *alg = taglen ? PF_PSA_ALG_AEAD_WITH_SHORTENED_TAG(PF_PSA_ALG_CCM, taglen) : PF_PSA_ALG_CCM;
            *key_type = PF_PSA_KEY_TYPE_ARIA;
            *key_size = 192;
            break;
#endif
#if defined(PF_MBEDTLS_SSL_HAVE_ARIA) && defined(PF_MBEDTLS_SSL_HAVE_GCM)
        case PF_MBEDTLS_CIPHER_ARIA_192_GCM:
            *alg = PF_PSA_ALG_GCM;
            *key_type = PF_PSA_KEY_TYPE_ARIA;
            *key_size = 192;
            break;
#endif
#if defined(PF_MBEDTLS_SSL_HAVE_ARIA) && defined(PF_MBEDTLS_SSL_HAVE_CBC)
        case PF_MBEDTLS_CIPHER_ARIA_256_CBC:
            *alg = PF_PSA_ALG_CBC_NO_PADDING;
            *key_type = PF_PSA_KEY_TYPE_ARIA;
            *key_size = 256;
            break;
#endif
#if defined(PF_MBEDTLS_SSL_HAVE_ARIA) && defined(PF_MBEDTLS_SSL_HAVE_CCM)
        case PF_MBEDTLS_CIPHER_ARIA_256_CCM:
            *alg = taglen ? PF_PSA_ALG_AEAD_WITH_SHORTENED_TAG(PF_PSA_ALG_CCM, taglen) : PF_PSA_ALG_CCM;
            *key_type = PF_PSA_KEY_TYPE_ARIA;
            *key_size = 256;
            break;
#endif
#if defined(PF_MBEDTLS_SSL_HAVE_ARIA) && defined(PF_MBEDTLS_SSL_HAVE_GCM)
        case PF_MBEDTLS_CIPHER_ARIA_256_GCM:
            *alg = PF_PSA_ALG_GCM;
            *key_type = PF_PSA_KEY_TYPE_ARIA;
            *key_size = 256;
            break;
#endif
#if defined(PF_MBEDTLS_SSL_HAVE_CAMELLIA) && defined(PF_MBEDTLS_SSL_HAVE_CBC)
        case PF_MBEDTLS_CIPHER_CAMELLIA_128_CBC:
            *alg = PF_PSA_ALG_CBC_NO_PADDING;
            *key_type = PF_PSA_KEY_TYPE_CAMELLIA;
            *key_size = 128;
            break;
#endif
#if defined(PF_MBEDTLS_SSL_HAVE_CAMELLIA) && defined(PF_MBEDTLS_SSL_HAVE_CCM)
        case PF_MBEDTLS_CIPHER_CAMELLIA_128_CCM:
            *alg = taglen ? PF_PSA_ALG_AEAD_WITH_SHORTENED_TAG(PF_PSA_ALG_CCM, taglen) : PF_PSA_ALG_CCM;
            *key_type = PF_PSA_KEY_TYPE_CAMELLIA;
            *key_size = 128;
            break;
#endif
#if defined(PF_MBEDTLS_SSL_HAVE_CAMELLIA) && defined(PF_MBEDTLS_SSL_HAVE_GCM)
        case PF_MBEDTLS_CIPHER_CAMELLIA_128_GCM:
            *alg = PF_PSA_ALG_GCM;
            *key_type = PF_PSA_KEY_TYPE_CAMELLIA;
            *key_size = 128;
            break;
#endif
#if defined(PF_MBEDTLS_SSL_HAVE_CAMELLIA) && defined(PF_MBEDTLS_SSL_HAVE_CCM)
        case PF_MBEDTLS_CIPHER_CAMELLIA_192_CCM:
            *alg = taglen ? PF_PSA_ALG_AEAD_WITH_SHORTENED_TAG(PF_PSA_ALG_CCM, taglen) : PF_PSA_ALG_CCM;
            *key_type = PF_PSA_KEY_TYPE_CAMELLIA;
            *key_size = 192;
            break;
#endif
#if defined(PF_MBEDTLS_SSL_HAVE_CAMELLIA) && defined(PF_MBEDTLS_SSL_HAVE_GCM)
        case PF_MBEDTLS_CIPHER_CAMELLIA_192_GCM:
            *alg = PF_PSA_ALG_GCM;
            *key_type = PF_PSA_KEY_TYPE_CAMELLIA;
            *key_size = 192;
            break;
#endif
#if defined(PF_MBEDTLS_SSL_HAVE_CAMELLIA) && defined(PF_MBEDTLS_SSL_HAVE_CBC)
        case PF_MBEDTLS_CIPHER_CAMELLIA_256_CBC:
            *alg = PF_PSA_ALG_CBC_NO_PADDING;
            *key_type = PF_PSA_KEY_TYPE_CAMELLIA;
            *key_size = 256;
            break;
#endif
#if defined(PF_MBEDTLS_SSL_HAVE_CAMELLIA) && defined(PF_MBEDTLS_SSL_HAVE_CCM)
        case PF_MBEDTLS_CIPHER_CAMELLIA_256_CCM:
            *alg = taglen ? PF_PSA_ALG_AEAD_WITH_SHORTENED_TAG(PF_PSA_ALG_CCM, taglen) : PF_PSA_ALG_CCM;
            *key_type = PF_PSA_KEY_TYPE_CAMELLIA;
            *key_size = 256;
            break;
#endif
#if defined(PF_MBEDTLS_SSL_HAVE_CAMELLIA) && defined(PF_MBEDTLS_SSL_HAVE_GCM)
        case PF_MBEDTLS_CIPHER_CAMELLIA_256_GCM:
            *alg = PF_PSA_ALG_GCM;
            *key_type = PF_PSA_KEY_TYPE_CAMELLIA;
            *key_size = 256;
            break;
#endif
#if defined(PF_MBEDTLS_SSL_HAVE_CHACHAPOLY)
        case PF_MBEDTLS_CIPHER_CHACHA20_POLY1305:
            *alg = PF_PSA_ALG_CHACHA20_POLY1305;
            *key_type = PF_PSA_KEY_TYPE_CHACHA20;
            *key_size = 256;
            break;
#endif
        case PF_MBEDTLS_CIPHER_NULL:
            *alg = PF_MBEDTLS_SSL_NULL_CIPHER;
            *key_type = 0;
            *key_size = 0;
            break;
        default:
            return PF_PSA_ERROR_NOT_SUPPORTED;
    }

    return PF_PSA_SUCCESS;
}
#endif /* MBEDTLS_USE_PSA_CRYPTO || MBEDTLS_SSL_PROTO_TLS1_3 */

#if defined(PF_MBEDTLS_DHM_C) && defined(PF_MBEDTLS_SSL_SRV_C)
int pf_mbedtls_ssl_conf_dh_param_bin(pf_mbedtls_ssl_config *conf,
                                  const unsigned char *dhm_P, size_t P_len,
                                  const unsigned char *dhm_G, size_t G_len)
{
    int ret = PF_MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;

    pf_mbedtls_mpi_free(&conf->dhm_P);
    pf_mbedtls_mpi_free(&conf->dhm_G);

    if ((ret = pf_mbedtls_mpi_read_binary(&conf->dhm_P, dhm_P, P_len)) != 0 ||
        (ret = pf_mbedtls_mpi_read_binary(&conf->dhm_G, dhm_G, G_len)) != 0) {
        pf_mbedtls_mpi_free(&conf->dhm_P);
        pf_mbedtls_mpi_free(&conf->dhm_G);
        return ret;
    }

    return 0;
}

int pf_mbedtls_ssl_conf_dh_param_ctx(pf_mbedtls_ssl_config *conf, pf_mbedtls_dhm_context *dhm_ctx)
{
    int ret = PF_MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;

    pf_mbedtls_mpi_free(&conf->dhm_P);
    pf_mbedtls_mpi_free(&conf->dhm_G);

    if ((ret = pf_mbedtls_dhm_get_value(dhm_ctx, PF_MBEDTLS_DHM_PARAM_P,
                                     &conf->dhm_P)) != 0 ||
        (ret = pf_mbedtls_dhm_get_value(dhm_ctx, PF_MBEDTLS_DHM_PARAM_G,
                                     &conf->dhm_G)) != 0) {
        pf_mbedtls_mpi_free(&conf->dhm_P);
        pf_mbedtls_mpi_free(&conf->dhm_G);
        return ret;
    }

    return 0;
}
#endif /* MBEDTLS_DHM_C && MBEDTLS_SSL_SRV_C */

#if defined(PF_MBEDTLS_DHM_C) && defined(PF_MBEDTLS_SSL_CLI_C)
/*
 * Set the minimum length for Diffie-Hellman parameters
 */
void pf_mbedtls_ssl_conf_dhm_min_bitlen(pf_mbedtls_ssl_config *conf,
                                     unsigned int bitlen)
{
    conf->dhm_min_bitlen = bitlen;
}
#endif /* MBEDTLS_DHM_C && MBEDTLS_SSL_CLI_C */

#if defined(PF_MBEDTLS_SSL_HANDSHAKE_WITH_CERT_ENABLED)
#if !defined(PF_MBEDTLS_DEPRECATED_REMOVED) && defined(PF_MBEDTLS_SSL_PROTO_TLS1_2)
/*
 * Set allowed/preferred hashes for handshake signatures
 */
void pf_mbedtls_ssl_conf_sig_hashes(pf_mbedtls_ssl_config *conf,
                                 const int *hashes)
{
    conf->sig_hashes = hashes;
}
#endif /* !MBEDTLS_DEPRECATED_REMOVED && MBEDTLS_SSL_PROTO_TLS1_2 */

/* Configure allowed signature algorithms for handshake */
void pf_mbedtls_ssl_conf_sig_algs(pf_mbedtls_ssl_config *conf,
                               const uint16_t *sig_algs)
{
#if !defined(PF_MBEDTLS_DEPRECATED_REMOVED)
    conf->sig_hashes = NULL;
#endif /* !MBEDTLS_DEPRECATED_REMOVED */
    conf->sig_algs = sig_algs;
}
#endif /* MBEDTLS_SSL_HANDSHAKE_WITH_CERT_ENABLED */

#if defined(PF_MBEDTLS_ECP_C)
#if !defined(PF_MBEDTLS_DEPRECATED_REMOVED)
/*
 * Set the allowed elliptic curves
 *
 * mbedtls_ssl_setup() takes the provided list
 * and translates it to a list of IANA TLS group identifiers,
 * stored in ssl->handshake->group_list.
 *
 */
void pf_mbedtls_ssl_conf_curves(pf_mbedtls_ssl_config *conf,
                             const pf_mbedtls_ecp_group_id *curve_list)
{
    conf->curve_list = curve_list;
    conf->group_list = NULL;
}
#endif /* MBEDTLS_DEPRECATED_REMOVED */
#endif /* MBEDTLS_ECP_C */

/*
 * Set the allowed groups
 */
void pf_mbedtls_ssl_conf_groups(pf_mbedtls_ssl_config *conf,
                             const uint16_t *group_list)
{
#if defined(PF_MBEDTLS_ECP_C) && !defined(PF_MBEDTLS_DEPRECATED_REMOVED)
    conf->curve_list = NULL;
#endif
    conf->group_list = group_list;
}

#if defined(PF_MBEDTLS_X509_CRT_PARSE_C)

/* A magic value for `ssl->hostname` indicating that
 * mbedtls_ssl_set_hostname() has been called with `NULL`.
 * If mbedtls_ssl_set_hostname() has never been called on `ssl`, then
 * `ssl->hostname == NULL`. */
static const char *const ssl_hostname_skip_cn_verification = "";

#if defined(PF_MBEDTLS_SSL_HANDSHAKE_WITH_CERT_ENABLED)
/** Whether mbedtls_ssl_set_hostname() has been called.
 *
 * \param[in]   ssl     SSL context
 *
 * \return \c 1 if mbedtls_ssl_set_hostname() has been called on \p ssl
 *         (including `mbedtls_ssl_set_hostname(ssl, NULL)`),
 *         otherwise \c 0.
 */
static int pf_mbedtls_ssl_has_set_hostname_been_called(
    const pf_mbedtls_ssl_context *ssl)
{
    return ssl->hostname != NULL;
}
#endif

/*
 * Exported for ssl_client.c when SNI is enabled.  When SNI is off the only
 * in-file caller is get_hostname_for_verification() which is guarded by
 * MBEDTLS_SSL_HANDSHAKE_WITH_CERT_ENABLED, so compile the function out
 * entirely when neither macro is defined.
 */
#if defined(PF_MBEDTLS_SSL_SERVER_NAME_INDICATION) || \
    defined(PF_MBEDTLS_SSL_HANDSHAKE_WITH_CERT_ENABLED)
#if !defined(PF_MBEDTLS_SSL_SERVER_NAME_INDICATION)
static
#endif
const char *pf_mbedtls_ssl_get_hostname_pointer(const pf_mbedtls_ssl_context *ssl)
{
    if (ssl->hostname == ssl_hostname_skip_cn_verification) {
        return NULL;
    }
    return ssl->hostname;
}
#endif /* MBEDTLS_SSL_SERVER_NAME_INDICATION || MBEDTLS_SSL_HANDSHAKE_WITH_CERT_ENABLED */

static void pf_mbedtls_ssl_free_hostname(pf_mbedtls_ssl_context *ssl)
{
    if (ssl->hostname != NULL &&
        ssl->hostname != ssl_hostname_skip_cn_verification) {
        pf_mbedtls_zeroize_and_free(ssl->hostname, strlen(ssl->hostname));
    }
    ssl->hostname = NULL;
}

int pf_mbedtls_ssl_set_hostname(pf_mbedtls_ssl_context *ssl, const char *hostname)
{
    /* Initialize to suppress unnecessary compiler warning */
    size_t hostname_len = 0;

    /* Check if new hostname is valid before
     * making any change to current one */
    if (hostname != NULL) {
        hostname_len = strlen(hostname);

        if (hostname_len > PF_MBEDTLS_SSL_MAX_HOST_NAME_LEN) {
            return PF_MBEDTLS_ERR_SSL_BAD_INPUT_DATA;
        }
    }

    /* Now it's clear that we will overwrite the old hostname,
     * so we can free it safely */
    pf_mbedtls_ssl_free_hostname(ssl);

    if (hostname == NULL) {
        /* Passing NULL as hostname clears the old one, but leaves a
         * special marker to indicate that mbedtls_ssl_set_hostname()
         * has been called. */
        /* ssl->hostname should be const, but isn't. We won't actually
         * write to the buffer, so it's ok to cast away the const. */
        ssl->hostname = (char *) ssl_hostname_skip_cn_verification;
    } else {
        ssl->hostname = pf_mbedtls_calloc(1, hostname_len + 1);
        if (ssl->hostname == NULL) {
            /* mbedtls_ssl_set_hostname() has been called, but unsuccessfully.
             * Leave ssl->hostname in the same state as if the function had
             * not been called, i.e. a null pointer. */
            return PF_MBEDTLS_ERR_SSL_ALLOC_FAILED;
        }

        memcpy(ssl->hostname, hostname, hostname_len);

        ssl->hostname[hostname_len] = '\0';
    }

    return 0;
}
#endif /* MBEDTLS_X509_CRT_PARSE_C */

#if defined(PF_MBEDTLS_SSL_SERVER_NAME_INDICATION)
void pf_mbedtls_ssl_conf_sni(pf_mbedtls_ssl_config *conf,
                          int (*f_sni)(void *, pf_mbedtls_ssl_context *,
                                       const unsigned char *, size_t),
                          void *p_sni)
{
    conf->f_sni = f_sni;
    conf->p_sni = p_sni;
}
#endif /* MBEDTLS_SSL_SERVER_NAME_INDICATION */

#if defined(PF_MBEDTLS_SSL_ALPN)
int pf_mbedtls_ssl_conf_alpn_protocols(pf_mbedtls_ssl_config *conf, const char **protos)
{
    size_t cur_len, tot_len;
    const char **p;

    /*
     * RFC 7301 3.1: "Empty strings MUST NOT be included and byte strings
     * MUST NOT be truncated."
     * We check lengths now rather than later.
     */
    tot_len = 0;
    for (p = protos; *p != NULL; p++) {
        cur_len = strlen(*p);
        tot_len += cur_len;

        if ((cur_len == 0) ||
            (cur_len > PF_MBEDTLS_SSL_MAX_ALPN_NAME_LEN) ||
            (tot_len > PF_MBEDTLS_SSL_MAX_ALPN_LIST_LEN)) {
            return PF_MBEDTLS_ERR_SSL_BAD_INPUT_DATA;
        }
    }

    conf->alpn_list = protos;

    return 0;
}

const char *pf_mbedtls_ssl_get_alpn_protocol(const pf_mbedtls_ssl_context *ssl)
{
    return ssl->alpn_chosen;
}
#endif /* MBEDTLS_SSL_ALPN */

#if defined(PF_MBEDTLS_SSL_DTLS_SRTP)
void pf_mbedtls_ssl_conf_srtp_mki_value_supported(pf_mbedtls_ssl_config *conf,
                                               int support_mki_value)
{
    conf->dtls_srtp_mki_support = support_mki_value;
}

int pf_mbedtls_ssl_dtls_srtp_set_mki_value(pf_mbedtls_ssl_context *ssl,
                                        unsigned char *mki_value,
                                        uint16_t mki_len)
{
    if (mki_len > PF_MBEDTLS_TLS_SRTP_MAX_MKI_LENGTH) {
        return PF_MBEDTLS_ERR_SSL_BAD_INPUT_DATA;
    }

    if (ssl->conf->dtls_srtp_mki_support == PF_MBEDTLS_SSL_DTLS_SRTP_MKI_UNSUPPORTED) {
        return PF_MBEDTLS_ERR_SSL_FEATURE_UNAVAILABLE;
    }

    memcpy(ssl->dtls_srtp_info.mki_value, mki_value, mki_len);
    ssl->dtls_srtp_info.mki_len = mki_len;
    return 0;
}

int pf_mbedtls_ssl_conf_dtls_srtp_protection_profiles(pf_mbedtls_ssl_config *conf,
                                                   const pf_mbedtls_ssl_srtp_profile *profiles)
{
    const pf_mbedtls_ssl_srtp_profile *p;
    size_t list_size = 0;

    /* check the profiles list: all entry must be valid,
     * its size cannot be more than the total number of supported profiles, currently 4 */
    for (p = profiles; *p != PF_MBEDTLS_TLS_SRTP_UNSET &&
         list_size <= PF_MBEDTLS_TLS_SRTP_MAX_PROFILE_LIST_LENGTH;
         p++) {
        if (pf_mbedtls_ssl_check_srtp_profile_value(*p) != PF_MBEDTLS_TLS_SRTP_UNSET) {
            list_size++;
        } else {
            /* unsupported value, stop parsing and set the size to an error value */
            list_size = PF_MBEDTLS_TLS_SRTP_MAX_PROFILE_LIST_LENGTH + 1;
        }
    }

    if (list_size > PF_MBEDTLS_TLS_SRTP_MAX_PROFILE_LIST_LENGTH) {
        conf->dtls_srtp_profile_list = NULL;
        conf->dtls_srtp_profile_list_len = 0;
        return PF_MBEDTLS_ERR_SSL_BAD_INPUT_DATA;
    }

    conf->dtls_srtp_profile_list = profiles;
    conf->dtls_srtp_profile_list_len = list_size;

    return 0;
}

void pf_mbedtls_ssl_get_dtls_srtp_negotiation_result(const pf_mbedtls_ssl_context *ssl,
                                                  pf_mbedtls_dtls_srtp_info *dtls_srtp_info)
{
    dtls_srtp_info->chosen_dtls_srtp_profile = ssl->dtls_srtp_info.chosen_dtls_srtp_profile;
    /* do not copy the mki value if there is no chosen profile */
    if (dtls_srtp_info->chosen_dtls_srtp_profile == PF_MBEDTLS_TLS_SRTP_UNSET) {
        dtls_srtp_info->mki_len = 0;
    } else {
        dtls_srtp_info->mki_len = ssl->dtls_srtp_info.mki_len;
        memcpy(dtls_srtp_info->mki_value, ssl->dtls_srtp_info.mki_value,
               ssl->dtls_srtp_info.mki_len);
    }
}
#endif /* MBEDTLS_SSL_DTLS_SRTP */

#if !defined(PF_MBEDTLS_DEPRECATED_REMOVED)
void pf_mbedtls_ssl_conf_max_version(pf_mbedtls_ssl_config *conf, int major, int minor)
{
    conf->max_tls_version = (pf_mbedtls_ssl_protocol_version) ((major << 8) | minor);
}

void pf_mbedtls_ssl_conf_min_version(pf_mbedtls_ssl_config *conf, int major, int minor)
{
    conf->min_tls_version = (pf_mbedtls_ssl_protocol_version) ((major << 8) | minor);
}
#endif /* MBEDTLS_DEPRECATED_REMOVED */

#if defined(PF_MBEDTLS_SSL_SRV_C)
void pf_mbedtls_ssl_conf_cert_req_ca_list(pf_mbedtls_ssl_config *conf,
                                       char cert_req_ca_list)
{
    conf->cert_req_ca_list = cert_req_ca_list;
}
#endif

#if defined(PF_MBEDTLS_SSL_ENCRYPT_THEN_MAC)
void pf_mbedtls_ssl_conf_encrypt_then_mac(pf_mbedtls_ssl_config *conf, char etm)
{
    conf->encrypt_then_mac = etm;
}
#endif

#if defined(PF_MBEDTLS_SSL_EXTENDED_MASTER_SECRET)
void pf_mbedtls_ssl_conf_extended_master_secret(pf_mbedtls_ssl_config *conf, char ems)
{
    conf->extended_ms = ems;
}
#endif

#if defined(PF_MBEDTLS_SSL_MAX_FRAGMENT_LENGTH)
int pf_mbedtls_ssl_conf_max_frag_len(pf_mbedtls_ssl_config *conf, unsigned char mfl_code)
{
    if (mfl_code >= PF_MBEDTLS_SSL_MAX_FRAG_LEN_INVALID ||
        ssl_mfl_code_to_length(mfl_code) > PF_MBEDTLS_TLS_EXT_ADV_CONTENT_LEN) {
        return PF_MBEDTLS_ERR_SSL_BAD_INPUT_DATA;
    }

    conf->mfl_code = mfl_code;

    return 0;
}
#endif /* MBEDTLS_SSL_MAX_FRAGMENT_LENGTH */

void pf_mbedtls_ssl_conf_legacy_renegotiation(pf_mbedtls_ssl_config *conf, int allow_legacy)
{
    conf->allow_legacy_renegotiation = allow_legacy;
}

#if defined(PF_MBEDTLS_SSL_RENEGOTIATION)
void pf_mbedtls_ssl_conf_renegotiation(pf_mbedtls_ssl_config *conf, int renegotiation)
{
    conf->disable_renegotiation = renegotiation;
}

void pf_mbedtls_ssl_conf_renegotiation_enforced(pf_mbedtls_ssl_config *conf, int max_records)
{
    conf->renego_max_records = max_records;
}

void pf_mbedtls_ssl_conf_renegotiation_period(pf_mbedtls_ssl_config *conf,
                                           const unsigned char period[8])
{
    memcpy(conf->renego_period, period, 8);
}
#endif /* MBEDTLS_SSL_RENEGOTIATION */

#if defined(PF_MBEDTLS_SSL_SESSION_TICKETS)
#if defined(PF_MBEDTLS_SSL_CLI_C)

void pf_mbedtls_ssl_conf_session_tickets(pf_mbedtls_ssl_config *conf, int use_tickets)
{
    conf->session_tickets &= ~PF_MBEDTLS_SSL_SESSION_TICKETS_TLS1_2_MASK;
    conf->session_tickets |= (use_tickets != 0) <<
                             PF_MBEDTLS_SSL_SESSION_TICKETS_TLS1_2_BIT;
}

#if defined(PF_MBEDTLS_SSL_PROTO_TLS1_3)
void pf_mbedtls_ssl_conf_tls13_enable_signal_new_session_tickets(
    pf_mbedtls_ssl_config *conf, int signal_new_session_tickets)
{
    conf->session_tickets &= ~PF_MBEDTLS_SSL_SESSION_TICKETS_TLS1_3_MASK;
    conf->session_tickets |= (signal_new_session_tickets != 0) <<
                             PF_MBEDTLS_SSL_SESSION_TICKETS_TLS1_3_BIT;
}
#endif /* MBEDTLS_SSL_PROTO_TLS1_3 */
#endif /* MBEDTLS_SSL_CLI_C */

#if defined(PF_MBEDTLS_SSL_SRV_C)

#if defined(PF_MBEDTLS_SSL_PROTO_TLS1_3) && defined(PF_MBEDTLS_SSL_SESSION_TICKETS)
void pf_mbedtls_ssl_conf_new_session_tickets(pf_mbedtls_ssl_config *conf,
                                          uint16_t num_tickets)
{
    conf->new_session_tickets_count = num_tickets;
}
#endif

void pf_mbedtls_ssl_conf_session_tickets_cb(pf_mbedtls_ssl_config *conf,
                                         pf_mbedtls_ssl_ticket_write_t *f_ticket_write,
                                         pf_mbedtls_ssl_ticket_parse_t *f_ticket_parse,
                                         void *p_ticket)
{
    conf->f_ticket_write = f_ticket_write;
    conf->f_ticket_parse = f_ticket_parse;
    conf->p_ticket       = p_ticket;
}
#endif
#endif /* MBEDTLS_SSL_SESSION_TICKETS */

void pf_mbedtls_ssl_set_export_keys_cb(pf_mbedtls_ssl_context *ssl,
                                    pf_mbedtls_ssl_export_keys_t *f_export_keys,
                                    void *p_export_keys)
{
    ssl->f_export_keys = f_export_keys;
    ssl->p_export_keys = p_export_keys;
}

#if defined(PF_MBEDTLS_SSL_ASYNC_PRIVATE)
void pf_mbedtls_ssl_conf_async_private_cb(
    pf_mbedtls_ssl_config *conf,
    pf_mbedtls_ssl_async_sign_t *f_async_sign,
    pf_mbedtls_ssl_async_decrypt_t *f_async_decrypt,
    pf_mbedtls_ssl_async_resume_t *f_async_resume,
    pf_mbedtls_ssl_async_cancel_t *f_async_cancel,
    void *async_config_data)
{
    conf->f_async_sign_start = f_async_sign;
    conf->f_async_decrypt_start = f_async_decrypt;
    conf->f_async_resume = f_async_resume;
    conf->f_async_cancel = f_async_cancel;
    conf->p_async_config_data = async_config_data;
}

void *pf_mbedtls_ssl_conf_get_async_config_data(const pf_mbedtls_ssl_config *conf)
{
    return conf->p_async_config_data;
}

void *pf_mbedtls_ssl_get_async_operation_data(const pf_mbedtls_ssl_context *ssl)
{
    if (ssl->handshake == NULL) {
        return NULL;
    } else {
        return ssl->handshake->user_async_ctx;
    }
}

void pf_mbedtls_ssl_set_async_operation_data(pf_mbedtls_ssl_context *ssl,
                                          void *ctx)
{
    if (ssl->handshake != NULL) {
        ssl->handshake->user_async_ctx = ctx;
    }
}
#endif /* MBEDTLS_SSL_ASYNC_PRIVATE */

/*
 * SSL get accessors
 */
uint32_t pf_mbedtls_ssl_get_verify_result(const pf_mbedtls_ssl_context *ssl)
{
    if (ssl->session != NULL) {
        return ssl->session->verify_result;
    }

    if (ssl->session_negotiate != NULL) {
        return ssl->session_negotiate->verify_result;
    }

    return 0xFFFFFFFF;
}

int pf_mbedtls_ssl_get_ciphersuite_id_from_ssl(const pf_mbedtls_ssl_context *ssl)
{
    if (ssl == NULL || ssl->session == NULL) {
        return 0;
    }

    return ssl->session->ciphersuite;
}

const char *pf_mbedtls_ssl_get_ciphersuite(const pf_mbedtls_ssl_context *ssl)
{
    if (ssl == NULL || ssl->session == NULL) {
        return NULL;
    }

    return pf_mbedtls_ssl_get_ciphersuite_name(ssl->session->ciphersuite);
}

const char *pf_mbedtls_ssl_get_version(const pf_mbedtls_ssl_context *ssl)
{
#if defined(PF_MBEDTLS_SSL_PROTO_DTLS)
    if (ssl->conf->transport == PF_MBEDTLS_SSL_TRANSPORT_DATAGRAM) {
        switch (ssl->tls_version) {
            case PF_MBEDTLS_SSL_VERSION_TLS1_2:
                return "DTLSv1.2";
            default:
                return "unknown (DTLS)";
        }
    }
#endif

    switch (ssl->tls_version) {
        case PF_MBEDTLS_SSL_VERSION_TLS1_2:
            return "TLSv1.2";
        case PF_MBEDTLS_SSL_VERSION_TLS1_3:
            return "TLSv1.3";
        default:
            return "unknown";
    }
}

#if defined(PF_MBEDTLS_SSL_RECORD_SIZE_LIMIT)

size_t pf_mbedtls_ssl_get_output_record_size_limit(const pf_mbedtls_ssl_context *ssl)
{
    const size_t max_len = PF_MBEDTLS_SSL_OUT_CONTENT_LEN;
    size_t record_size_limit = max_len;

    if (ssl->session != NULL &&
        ssl->session->record_size_limit >= PF_MBEDTLS_SSL_RECORD_SIZE_LIMIT_MIN &&
        ssl->session->record_size_limit < max_len) {
        record_size_limit = ssl->session->record_size_limit;
    }

    // TODO: this is currently untested
    /* During a handshake, use the value being negotiated */
    if (ssl->session_negotiate != NULL &&
        ssl->session_negotiate->record_size_limit >= PF_MBEDTLS_SSL_RECORD_SIZE_LIMIT_MIN &&
        ssl->session_negotiate->record_size_limit < max_len) {
        record_size_limit = ssl->session_negotiate->record_size_limit;
    }

    return record_size_limit;
}
#endif /* MBEDTLS_SSL_RECORD_SIZE_LIMIT */

#if defined(PF_MBEDTLS_SSL_MAX_FRAGMENT_LENGTH)
size_t pf_mbedtls_ssl_get_input_max_frag_len(const pf_mbedtls_ssl_context *ssl)
{
    size_t max_len = PF_MBEDTLS_SSL_IN_CONTENT_LEN;
    size_t read_mfl;

#if defined(PF_MBEDTLS_SSL_PROTO_TLS1_2)
    /* Use the configured MFL for the client if we're past SERVER_HELLO_DONE */
    if (ssl->conf->endpoint == PF_MBEDTLS_SSL_IS_CLIENT &&
        ssl->state >= PF_MBEDTLS_SSL_SERVER_HELLO_DONE) {
        return ssl_mfl_code_to_length(ssl->conf->mfl_code);
    }
#endif

    /* Check if a smaller max length was negotiated */
    if (ssl->session_out != NULL) {
        read_mfl = ssl_mfl_code_to_length(ssl->session_out->mfl_code);
        if (read_mfl < max_len) {
            max_len = read_mfl;
        }
    }

    /* During a handshake, use the value being negotiated */
    if (ssl->session_negotiate != NULL) {
        read_mfl = ssl_mfl_code_to_length(ssl->session_negotiate->mfl_code);
        if (read_mfl < max_len) {
            max_len = read_mfl;
        }
    }

    return max_len;
}

size_t pf_mbedtls_ssl_get_output_max_frag_len(const pf_mbedtls_ssl_context *ssl)
{
    size_t max_len;

    /*
     * Assume mfl_code is correct since it was checked when set
     */
    max_len = ssl_mfl_code_to_length(ssl->conf->mfl_code);

    /* Check if a smaller max length was negotiated */
    if (ssl->session_out != NULL &&
        ssl_mfl_code_to_length(ssl->session_out->mfl_code) < max_len) {
        max_len = ssl_mfl_code_to_length(ssl->session_out->mfl_code);
    }

    /* During a handshake, use the value being negotiated */
    if (ssl->session_negotiate != NULL &&
        ssl_mfl_code_to_length(ssl->session_negotiate->mfl_code) < max_len) {
        max_len = ssl_mfl_code_to_length(ssl->session_negotiate->mfl_code);
    }

    return max_len;
}
#endif /* MBEDTLS_SSL_MAX_FRAGMENT_LENGTH */

#if defined(PF_MBEDTLS_SSL_PROTO_DTLS)
size_t pf_mbedtls_ssl_get_current_mtu(const pf_mbedtls_ssl_context *ssl)
{
    if (ssl->handshake == NULL || ssl->handshake->mtu == 0) {
        return ssl->mtu;
    }

    if (ssl->mtu == 0) {
        return ssl->handshake->mtu;
    }

    return ssl->mtu < ssl->handshake->mtu ?
           ssl->mtu : ssl->handshake->mtu;
}
#endif /* MBEDTLS_SSL_PROTO_DTLS */

int pf_mbedtls_ssl_get_max_out_record_payload(const pf_mbedtls_ssl_context *ssl)
{
    size_t max_len = PF_MBEDTLS_SSL_OUT_CONTENT_LEN;

#if !defined(PF_MBEDTLS_SSL_MAX_FRAGMENT_LENGTH) && \
    !defined(PF_MBEDTLS_SSL_RECORD_SIZE_LIMIT) && \
    !defined(PF_MBEDTLS_SSL_PROTO_DTLS)
    (void) ssl;
#endif

#if defined(PF_MBEDTLS_SSL_MAX_FRAGMENT_LENGTH)
    const size_t mfl = pf_mbedtls_ssl_get_output_max_frag_len(ssl);

    if (max_len > mfl) {
        max_len = mfl;
    }
#endif

#if defined(PF_MBEDTLS_SSL_RECORD_SIZE_LIMIT)
    const size_t record_size_limit = pf_mbedtls_ssl_get_output_record_size_limit(ssl);

    if (max_len > record_size_limit) {
        max_len = record_size_limit;
    }
#endif

    if (ssl->transform_out != NULL &&
        ssl->transform_out->tls_version == PF_MBEDTLS_SSL_VERSION_TLS1_3) {
        /*
         * In TLS 1.3 case, when records are protected, `max_len` as computed
         * above is the maximum length of the TLSInnerPlaintext structure that
         * along the plaintext payload contains the inner content type (one byte)
         * and some zero padding. Given the algorithm used for padding
         * in mbedtls_ssl_encrypt_buf(), compute the maximum length for
         * the plaintext payload. Round down to a multiple of
         * MBEDTLS_SSL_CID_TLS1_3_PADDING_GRANULARITY and
         * subtract 1.
         */
        max_len = ((max_len / PF_MBEDTLS_SSL_CID_TLS1_3_PADDING_GRANULARITY) *
                   PF_MBEDTLS_SSL_CID_TLS1_3_PADDING_GRANULARITY) - 1;
    }

#if defined(PF_MBEDTLS_SSL_PROTO_DTLS)
    if (pf_mbedtls_ssl_get_current_mtu(ssl) != 0) {
        const size_t mtu = pf_mbedtls_ssl_get_current_mtu(ssl);
        const int ret = pf_mbedtls_ssl_get_record_expansion(ssl);
        const size_t overhead = (size_t) ret;

        if (ret < 0) {
            return ret;
        }

        if (mtu <= overhead) {
            PF_MBEDTLS_SSL_DEBUG_MSG(1, ("MTU too low for record expansion"));
            return PF_MBEDTLS_ERR_SSL_FEATURE_UNAVAILABLE;
        }

        if (max_len > mtu - overhead) {
            max_len = mtu - overhead;
        }
    }
#endif /* MBEDTLS_SSL_PROTO_DTLS */

#if !defined(PF_MBEDTLS_SSL_MAX_FRAGMENT_LENGTH) &&        \
    !defined(PF_MBEDTLS_SSL_PROTO_DTLS) &&                 \
    !defined(PF_MBEDTLS_SSL_RECORD_SIZE_LIMIT)
    ((void) ssl);
#endif

    return (int) max_len;
}

int pf_mbedtls_ssl_get_max_in_record_payload(const pf_mbedtls_ssl_context *ssl)
{
    size_t max_len = PF_MBEDTLS_SSL_IN_CONTENT_LEN;

#if !defined(PF_MBEDTLS_SSL_MAX_FRAGMENT_LENGTH)
    (void) ssl;
#endif

#if defined(PF_MBEDTLS_SSL_MAX_FRAGMENT_LENGTH)
    const size_t mfl = pf_mbedtls_ssl_get_input_max_frag_len(ssl);

    if (max_len > mfl) {
        max_len = mfl;
    }
#endif

    return (int) max_len;
}

#if defined(PF_MBEDTLS_X509_CRT_PARSE_C)
const pf_mbedtls_x509_crt *pf_mbedtls_ssl_get_peer_cert(const pf_mbedtls_ssl_context *ssl)
{
    if (ssl == NULL || ssl->session == NULL) {
        return NULL;
    }

#if defined(PF_MBEDTLS_SSL_KEEP_PEER_CERTIFICATE)
    return ssl->session->peer_cert;
#else
    return NULL;
#endif /* MBEDTLS_SSL_KEEP_PEER_CERTIFICATE */
}
#endif /* MBEDTLS_X509_CRT_PARSE_C */

#if defined(PF_MBEDTLS_SSL_CLI_C)
int pf_mbedtls_ssl_get_session(const pf_mbedtls_ssl_context *ssl,
                            pf_mbedtls_ssl_session *dst)
{
    int ret;

    if (ssl == NULL ||
        dst == NULL ||
        ssl->session == NULL ||
        ssl->conf->endpoint != PF_MBEDTLS_SSL_IS_CLIENT) {
        return PF_MBEDTLS_ERR_SSL_BAD_INPUT_DATA;
    }

    /* Since Mbed TLS 3.0, mbedtls_ssl_get_session() is no longer
     * idempotent: Each session can only be exported once.
     *
     * (This is in preparation for TLS 1.3 support where we will
     * need the ability to export multiple sessions (aka tickets),
     * which will be achieved by calling mbedtls_ssl_get_session()
     * multiple times until it fails.)
     *
     * Check whether we have already exported the current session,
     * and fail if so.
     */
    if (ssl->session->exported == 1) {
        return PF_MBEDTLS_ERR_SSL_FEATURE_UNAVAILABLE;
    }

    ret = pf_mbedtls_ssl_session_copy(dst, ssl->session);
    if (ret != 0) {
        return ret;
    }

    /* Remember that we've exported the session. */
    ssl->session->exported = 1;
    return 0;
}
#endif /* MBEDTLS_SSL_CLI_C */

#if defined(PF_MBEDTLS_SSL_PROTO_TLS1_2)

/* Serialization of TLS 1.2 sessions
 *
 * For more detail, see the description of ssl_session_save().
 */
static size_t ssl_tls12_session_save(const pf_mbedtls_ssl_session *session,
                                     unsigned char *buf,
                                     size_t buf_len)
{
    unsigned char *p = buf;
    size_t used = 0;

#if defined(PF_MBEDTLS_HAVE_TIME)
    uint64_t start;
#endif
#if defined(PF_MBEDTLS_X509_CRT_PARSE_C)
#if defined(PF_MBEDTLS_SSL_KEEP_PEER_CERTIFICATE)
    size_t cert_len;
#endif /* MBEDTLS_SSL_KEEP_PEER_CERTIFICATE */
#endif /* MBEDTLS_X509_CRT_PARSE_C */

    /*
     * Time
     */
#if defined(PF_MBEDTLS_HAVE_TIME)
    used += 8;

    if (used <= buf_len) {
        start = (uint64_t) session->start;

        PF_MBEDTLS_PUT_UINT64_BE(start, p, 0);
        p += 8;
    }
#endif /* MBEDTLS_HAVE_TIME */

    /*
     * Basic mandatory fields
     */
    used += 1 /* id_len */
            + sizeof(session->id)
            + sizeof(session->master)
            + 4; /* verify_result */

    if (used <= buf_len) {
        *p++ = PF_MBEDTLS_BYTE_0(session->id_len);
        memcpy(p, session->id, 32);
        p += 32;

        memcpy(p, session->master, 48);
        p += 48;

        PF_MBEDTLS_PUT_UINT32_BE(session->verify_result, p, 0);
        p += 4;
    }

    /*
     * Peer's end-entity certificate
     */
#if defined(PF_MBEDTLS_X509_CRT_PARSE_C)
#if defined(PF_MBEDTLS_SSL_KEEP_PEER_CERTIFICATE)
    if (session->peer_cert == NULL) {
        cert_len = 0;
    } else {
        cert_len = session->peer_cert->raw.len;
    }

    used += 3 + cert_len;

    if (used <= buf_len) {
        *p++ = PF_MBEDTLS_BYTE_2(cert_len);
        *p++ = PF_MBEDTLS_BYTE_1(cert_len);
        *p++ = PF_MBEDTLS_BYTE_0(cert_len);

        if (session->peer_cert != NULL) {
            memcpy(p, session->peer_cert->raw.p, cert_len);
            p += cert_len;
        }
    }
#else /* MBEDTLS_SSL_KEEP_PEER_CERTIFICATE */
    if (session->peer_cert_digest != NULL) {
        used += 1 /* type */ + 1 /* length */ + session->peer_cert_digest_len;
        if (used <= buf_len) {
            *p++ = (unsigned char) session->peer_cert_digest_type;
            *p++ = (unsigned char) session->peer_cert_digest_len;
            memcpy(p, session->peer_cert_digest,
                   session->peer_cert_digest_len);
            p += session->peer_cert_digest_len;
        }
    } else {
        used += 2;
        if (used <= buf_len) {
            *p++ = (unsigned char) PF_MBEDTLS_MD_NONE;
            *p++ = 0;
        }
    }
#endif /* !MBEDTLS_SSL_KEEP_PEER_CERTIFICATE */
#endif /* MBEDTLS_X509_CRT_PARSE_C */

    /*
     * Session ticket if any, plus associated data
     */
#if defined(PF_MBEDTLS_SSL_SESSION_TICKETS)
#if defined(PF_MBEDTLS_SSL_CLI_C)
    if (session->endpoint == PF_MBEDTLS_SSL_IS_CLIENT) {
        used += 3 + session->ticket_len + 4; /* len + ticket + lifetime */

        if (used <= buf_len) {
            *p++ = PF_MBEDTLS_BYTE_2(session->ticket_len);
            *p++ = PF_MBEDTLS_BYTE_1(session->ticket_len);
            *p++ = PF_MBEDTLS_BYTE_0(session->ticket_len);

            if (session->ticket != NULL) {
                memcpy(p, session->ticket, session->ticket_len);
                p += session->ticket_len;
            }

            PF_MBEDTLS_PUT_UINT32_BE(session->ticket_lifetime, p, 0);
            p += 4;
        }
    }
#endif /* MBEDTLS_SSL_CLI_C */
#if defined(PF_MBEDTLS_HAVE_TIME) && defined(PF_MBEDTLS_SSL_SRV_C)
    if (session->endpoint == PF_MBEDTLS_SSL_IS_SERVER) {
        used += 8;

        if (used <= buf_len) {
            PF_MBEDTLS_PUT_UINT64_BE((uint64_t) session->ticket_creation_time, p, 0);
            p += 8;
        }
    }
#endif /* MBEDTLS_HAVE_TIME && MBEDTLS_SSL_SRV_C */
#endif /* MBEDTLS_SSL_SESSION_TICKETS */

    /*
     * Misc extension-related info
     */
#if defined(PF_MBEDTLS_SSL_MAX_FRAGMENT_LENGTH)
    used += 1;

    if (used <= buf_len) {
        *p++ = session->mfl_code;
    }
#endif

#if defined(PF_MBEDTLS_SSL_ENCRYPT_THEN_MAC)
    used += 1;

    if (used <= buf_len) {
        *p++ = PF_MBEDTLS_BYTE_0(session->encrypt_then_mac);
    }
#endif

    return used;
}

PF_MBEDTLS_CHECK_RETURN_CRITICAL
static int ssl_tls12_session_load(pf_mbedtls_ssl_session *session,
                                  const unsigned char *buf,
                                  size_t len)
{
#if defined(PF_MBEDTLS_HAVE_TIME)
    uint64_t start;
#endif
#if defined(PF_MBEDTLS_X509_CRT_PARSE_C)
#if defined(PF_MBEDTLS_SSL_KEEP_PEER_CERTIFICATE)
    size_t cert_len;
#endif /* MBEDTLS_SSL_KEEP_PEER_CERTIFICATE */
#endif /* MBEDTLS_X509_CRT_PARSE_C */

    const unsigned char *p = buf;
    const unsigned char * const end = buf + len;

    /*
     * Time
     */
#if defined(PF_MBEDTLS_HAVE_TIME)
    if (8 > (size_t) (end - p)) {
        return PF_MBEDTLS_ERR_SSL_BAD_INPUT_DATA;
    }

    start = PF_MBEDTLS_GET_UINT64_BE(p, 0);
    p += 8;

    session->start = (pf_mbedtls_time_t) start;
#endif /* MBEDTLS_HAVE_TIME */

    /*
     * Basic mandatory fields
     */
    if (1 + 32 + 48 + 4 > (size_t) (end - p)) {
        return PF_MBEDTLS_ERR_SSL_BAD_INPUT_DATA;
    }

    session->id_len = *p++;
    memcpy(session->id, p, 32);
    p += 32;

    memcpy(session->master, p, 48);
    p += 48;

    session->verify_result = PF_MBEDTLS_GET_UINT32_BE(p, 0);
    p += 4;

    /* Immediately clear invalid pointer values that have been read, in case
     * we exit early before we replaced them with valid ones. */
#if defined(PF_MBEDTLS_X509_CRT_PARSE_C)
#if defined(PF_MBEDTLS_SSL_KEEP_PEER_CERTIFICATE)
    session->peer_cert = NULL;
#else
    session->peer_cert_digest = NULL;
#endif /* !MBEDTLS_SSL_KEEP_PEER_CERTIFICATE */
#endif /* MBEDTLS_X509_CRT_PARSE_C */
#if defined(PF_MBEDTLS_SSL_SESSION_TICKETS) && defined(PF_MBEDTLS_SSL_CLI_C)
    session->ticket = NULL;
#endif /* MBEDTLS_SSL_SESSION_TICKETS && MBEDTLS_SSL_CLI_C */

    /*
     * Peer certificate
     */
#if defined(PF_MBEDTLS_X509_CRT_PARSE_C)
#if defined(PF_MBEDTLS_SSL_KEEP_PEER_CERTIFICATE)
    /* Deserialize CRT from the end of the ticket. */
    if (3 > (size_t) (end - p)) {
        return PF_MBEDTLS_ERR_SSL_BAD_INPUT_DATA;
    }

    cert_len = PF_MBEDTLS_GET_UINT24_BE(p, 0);
    p += 3;

    if (cert_len != 0) {
        int ret = PF_MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;

        if (cert_len > (size_t) (end - p)) {
            return PF_MBEDTLS_ERR_SSL_BAD_INPUT_DATA;
        }

        session->peer_cert = pf_mbedtls_calloc(1, sizeof(pf_mbedtls_x509_crt));

        if (session->peer_cert == NULL) {
            return PF_MBEDTLS_ERR_SSL_ALLOC_FAILED;
        }

        pf_mbedtls_x509_crt_init(session->peer_cert);

        if ((ret = pf_mbedtls_x509_crt_parse_der(session->peer_cert,
                                              p, cert_len)) != 0) {
            pf_mbedtls_x509_crt_free(session->peer_cert);
            pf_mbedtls_free(session->peer_cert);
            session->peer_cert = NULL;
            return ret;
        }

        p += cert_len;
    }
#else /* MBEDTLS_SSL_KEEP_PEER_CERTIFICATE */
    /* Deserialize CRT digest from the end of the ticket. */
    if (2 > (size_t) (end - p)) {
        return PF_MBEDTLS_ERR_SSL_BAD_INPUT_DATA;
    }

    session->peer_cert_digest_type = (pf_mbedtls_md_type_t) *p++;
    session->peer_cert_digest_len  = (size_t) *p++;

    if (session->peer_cert_digest_len != 0) {
        const pf_mbedtls_md_info_t *md_info =
            pf_mbedtls_md_info_from_type(session->peer_cert_digest_type);
        if (md_info == NULL) {
            return PF_MBEDTLS_ERR_SSL_BAD_INPUT_DATA;
        }
        if (session->peer_cert_digest_len != pf_mbedtls_md_get_size(md_info)) {
            return PF_MBEDTLS_ERR_SSL_BAD_INPUT_DATA;
        }

        if (session->peer_cert_digest_len > (size_t) (end - p)) {
            return PF_MBEDTLS_ERR_SSL_BAD_INPUT_DATA;
        }

        session->peer_cert_digest =
            pf_mbedtls_calloc(1, session->peer_cert_digest_len);
        if (session->peer_cert_digest == NULL) {
            return PF_MBEDTLS_ERR_SSL_ALLOC_FAILED;
        }

        memcpy(session->peer_cert_digest, p,
               session->peer_cert_digest_len);
        p += session->peer_cert_digest_len;
    }
#endif /* MBEDTLS_SSL_KEEP_PEER_CERTIFICATE */
#endif /* MBEDTLS_X509_CRT_PARSE_C */

    /*
     * Session ticket and associated data
     */
#if defined(PF_MBEDTLS_SSL_SESSION_TICKETS)
#if defined(PF_MBEDTLS_SSL_CLI_C)
    if (session->endpoint == PF_MBEDTLS_SSL_IS_CLIENT) {
        if (3 > (size_t) (end - p)) {
            return PF_MBEDTLS_ERR_SSL_BAD_INPUT_DATA;
        }

        session->ticket_len = PF_MBEDTLS_GET_UINT24_BE(p, 0);
        p += 3;

        if (session->ticket_len != 0) {
            if (session->ticket_len > (size_t) (end - p)) {
                return PF_MBEDTLS_ERR_SSL_BAD_INPUT_DATA;
            }

            session->ticket = pf_mbedtls_calloc(1, session->ticket_len);
            if (session->ticket == NULL) {
                return PF_MBEDTLS_ERR_SSL_ALLOC_FAILED;
            }

            memcpy(session->ticket, p, session->ticket_len);
            p += session->ticket_len;
        }

        if (4 > (size_t) (end - p)) {
            return PF_MBEDTLS_ERR_SSL_BAD_INPUT_DATA;
        }

        session->ticket_lifetime = PF_MBEDTLS_GET_UINT32_BE(p, 0);
        p += 4;
    }
#endif /* MBEDTLS_SSL_CLI_C */
#if defined(PF_MBEDTLS_HAVE_TIME) && defined(PF_MBEDTLS_SSL_SRV_C)
    if (session->endpoint == PF_MBEDTLS_SSL_IS_SERVER) {
        if (8 > (size_t) (end - p)) {
            return PF_MBEDTLS_ERR_SSL_BAD_INPUT_DATA;
        }
        session->ticket_creation_time = PF_MBEDTLS_GET_UINT64_BE(p, 0);
        p += 8;
    }
#endif /* MBEDTLS_HAVE_TIME && MBEDTLS_SSL_SRV_C */
#endif /* MBEDTLS_SSL_SESSION_TICKETS */

    /*
     * Misc extension-related info
     */
#if defined(PF_MBEDTLS_SSL_MAX_FRAGMENT_LENGTH)
    if (1 > (size_t) (end - p)) {
        return PF_MBEDTLS_ERR_SSL_BAD_INPUT_DATA;
    }

    session->mfl_code = *p++;
#endif

#if defined(PF_MBEDTLS_SSL_ENCRYPT_THEN_MAC)
    if (1 > (size_t) (end - p)) {
        return PF_MBEDTLS_ERR_SSL_BAD_INPUT_DATA;
    }

    session->encrypt_then_mac = *p++;
#endif

    /* Done, should have consumed entire buffer */
    if (p != end) {
        return PF_MBEDTLS_ERR_SSL_BAD_INPUT_DATA;
    }

    return 0;
}

#endif /* MBEDTLS_SSL_PROTO_TLS1_2 */

#if defined(PF_MBEDTLS_SSL_PROTO_TLS1_3)
/* Serialization of TLS 1.3 sessions:
 *
 * For more detail, see the description of ssl_session_save().
 */
#if defined(PF_MBEDTLS_SSL_SESSION_TICKETS)
PF_MBEDTLS_CHECK_RETURN_CRITICAL
static int ssl_tls13_session_save(const pf_mbedtls_ssl_session *session,
                                  unsigned char *buf,
                                  size_t buf_len,
                                  size_t *olen)
{
    unsigned char *p = buf;
#if defined(PF_MBEDTLS_SSL_CLI_C) && \
    defined(PF_MBEDTLS_SSL_SERVER_NAME_INDICATION)
    size_t hostname_len = (session->hostname == NULL) ?
                          0 : strlen(session->hostname) + 1;
#endif

#if defined(PF_MBEDTLS_SSL_SRV_C) && \
    defined(PF_MBEDTLS_SSL_EARLY_DATA) && defined(PF_MBEDTLS_SSL_ALPN)
    const size_t alpn_len = (session->ticket_alpn == NULL) ?
                            0 : strlen(session->ticket_alpn) + 1;
#endif
    size_t needed =   4  /* ticket_age_add */
                    + 1  /* ticket_flags */
                    + 1; /* resumption_key length */

    *olen = 0;

    if (session->resumption_key_len > PF_MBEDTLS_SSL_TLS1_3_TICKET_RESUMPTION_KEY_LEN) {
        return PF_MBEDTLS_ERR_SSL_BAD_INPUT_DATA;
    }
    needed += session->resumption_key_len;  /* resumption_key */

#if defined(PF_MBEDTLS_SSL_EARLY_DATA)
    needed += 4;                            /* max_early_data_size */
#endif
#if defined(PF_MBEDTLS_SSL_RECORD_SIZE_LIMIT)
    needed += 2;                            /* record_size_limit */
#endif /* MBEDTLS_SSL_RECORD_SIZE_LIMIT */

#if defined(PF_MBEDTLS_HAVE_TIME)
    needed += 8; /* ticket_creation_time or ticket_reception_time */
#endif

#if defined(PF_MBEDTLS_SSL_SRV_C)
    if (session->endpoint == PF_MBEDTLS_SSL_IS_SERVER) {
#if defined(PF_MBEDTLS_SSL_EARLY_DATA) && defined(PF_MBEDTLS_SSL_ALPN)
        needed +=   2                         /* alpn_len */
                  + alpn_len;                 /* alpn */
#endif
    }
#endif /* MBEDTLS_SSL_SRV_C */

#if defined(PF_MBEDTLS_SSL_CLI_C)
    if (session->endpoint == PF_MBEDTLS_SSL_IS_CLIENT) {
#if defined(PF_MBEDTLS_SSL_SERVER_NAME_INDICATION)
        needed +=  2                        /* hostname_len */
                  + hostname_len;           /* hostname */
#endif

        needed +=   4                       /* ticket_lifetime */
                  + 2;                      /* ticket_len */

        /* Check size_t overflow */
        if (session->ticket_len > SIZE_MAX - needed) {
            return PF_MBEDTLS_ERR_SSL_BAD_INPUT_DATA;
        }

        needed += session->ticket_len;      /* ticket */
    }
#endif /* MBEDTLS_SSL_CLI_C */

    *olen = needed;
    if (needed > buf_len) {
        return PF_MBEDTLS_ERR_SSL_BUFFER_TOO_SMALL;
    }

    PF_MBEDTLS_PUT_UINT32_BE(session->ticket_age_add, p, 0);
    p[4] = session->ticket_flags;

    /* save resumption_key */
    p[5] = session->resumption_key_len;
    p += 6;
    memcpy(p, session->resumption_key, session->resumption_key_len);
    p += session->resumption_key_len;

#if defined(PF_MBEDTLS_SSL_EARLY_DATA)
    PF_MBEDTLS_PUT_UINT32_BE(session->max_early_data_size, p, 0);
    p += 4;
#endif
#if defined(PF_MBEDTLS_SSL_RECORD_SIZE_LIMIT)
    PF_MBEDTLS_PUT_UINT16_BE(session->record_size_limit, p, 0);
    p += 2;
#endif /* MBEDTLS_SSL_RECORD_SIZE_LIMIT */

#if defined(PF_MBEDTLS_SSL_SRV_C)
    if (session->endpoint == PF_MBEDTLS_SSL_IS_SERVER) {
#if defined(PF_MBEDTLS_HAVE_TIME)
        PF_MBEDTLS_PUT_UINT64_BE((uint64_t) session->ticket_creation_time, p, 0);
        p += 8;
#endif /* MBEDTLS_HAVE_TIME */

#if defined(PF_MBEDTLS_SSL_EARLY_DATA) && defined(PF_MBEDTLS_SSL_ALPN)
        PF_MBEDTLS_PUT_UINT16_BE(alpn_len, p, 0);
        p += 2;

        if (alpn_len > 0) {
            /* save chosen alpn */
            memcpy(p, session->ticket_alpn, alpn_len);
            p += alpn_len;
        }
#endif /* MBEDTLS_SSL_EARLY_DATA && MBEDTLS_SSL_ALPN */
    }
#endif /* MBEDTLS_SSL_SRV_C */

#if defined(PF_MBEDTLS_SSL_CLI_C)
    if (session->endpoint == PF_MBEDTLS_SSL_IS_CLIENT) {
#if defined(PF_MBEDTLS_SSL_SERVER_NAME_INDICATION)
        PF_MBEDTLS_PUT_UINT16_BE(hostname_len, p, 0);
        p += 2;
        if (hostname_len > 0) {
            /* save host name */
            memcpy(p, session->hostname, hostname_len);
            p += hostname_len;
        }
#endif /* MBEDTLS_SSL_SERVER_NAME_INDICATION */

#if defined(PF_MBEDTLS_HAVE_TIME)
        PF_MBEDTLS_PUT_UINT64_BE((uint64_t) session->ticket_reception_time, p, 0);
        p += 8;
#endif
        PF_MBEDTLS_PUT_UINT32_BE(session->ticket_lifetime, p, 0);
        p += 4;

        PF_MBEDTLS_PUT_UINT16_BE(session->ticket_len, p, 0);
        p += 2;

        if (session->ticket != NULL && session->ticket_len > 0) {
            memcpy(p, session->ticket, session->ticket_len);
            p += session->ticket_len;
        }
    }
#endif /* MBEDTLS_SSL_CLI_C */
    return 0;
}

PF_MBEDTLS_CHECK_RETURN_CRITICAL
static int ssl_tls13_session_load(pf_mbedtls_ssl_session *session,
                                  const unsigned char *buf,
                                  size_t len)
{
    const unsigned char *p = buf;
    const unsigned char *end = buf + len;

    if (end - p < 6) {
        return PF_MBEDTLS_ERR_SSL_BAD_INPUT_DATA;
    }
    session->ticket_age_add = PF_MBEDTLS_GET_UINT32_BE(p, 0);
    session->ticket_flags = p[4];

    /* load resumption_key */
    session->resumption_key_len = p[5];
    p += 6;

    if (end - p < session->resumption_key_len) {
        return PF_MBEDTLS_ERR_SSL_BAD_INPUT_DATA;
    }

    if (sizeof(session->resumption_key) < session->resumption_key_len) {
        return PF_MBEDTLS_ERR_SSL_BAD_INPUT_DATA;
    }
    memcpy(session->resumption_key, p, session->resumption_key_len);
    p += session->resumption_key_len;

#if defined(PF_MBEDTLS_SSL_EARLY_DATA)
    if (end - p < 4) {
        return PF_MBEDTLS_ERR_SSL_BAD_INPUT_DATA;
    }
    session->max_early_data_size = PF_MBEDTLS_GET_UINT32_BE(p, 0);
    p += 4;
#endif
#if defined(PF_MBEDTLS_SSL_RECORD_SIZE_LIMIT)
    if (end - p < 2) {
        return PF_MBEDTLS_ERR_SSL_BAD_INPUT_DATA;
    }
    session->record_size_limit = PF_MBEDTLS_GET_UINT16_BE(p, 0);
    p += 2;
#endif /* MBEDTLS_SSL_RECORD_SIZE_LIMIT */

#if  defined(PF_MBEDTLS_SSL_SRV_C)
    if (session->endpoint == PF_MBEDTLS_SSL_IS_SERVER) {
#if defined(PF_MBEDTLS_HAVE_TIME)
        if (end - p < 8) {
            return PF_MBEDTLS_ERR_SSL_BAD_INPUT_DATA;
        }
        session->ticket_creation_time = PF_MBEDTLS_GET_UINT64_BE(p, 0);
        p += 8;
#endif /* MBEDTLS_HAVE_TIME */

#if defined(PF_MBEDTLS_SSL_EARLY_DATA) && defined(PF_MBEDTLS_SSL_ALPN)
        size_t alpn_len;

        if (end - p < 2) {
            return PF_MBEDTLS_ERR_SSL_BAD_INPUT_DATA;
        }

        alpn_len = PF_MBEDTLS_GET_UINT16_BE(p, 0);
        p += 2;

        if (end - p < (long int) alpn_len) {
            return PF_MBEDTLS_ERR_SSL_BAD_INPUT_DATA;
        }

        if (alpn_len > 0) {
            /* The data is about to be used as a null-terminated string, so
             * check that it actually is one. */
            if (p[alpn_len - 1] != '\0') {
                return PF_MBEDTLS_ERR_SSL_BAD_INPUT_DATA;
            }

            int ret = pf_mbedtls_ssl_session_set_ticket_alpn(session, (char *) p);
            if (ret != 0) {
                return ret;
            }
            p += alpn_len;
        }
#endif /* MBEDTLS_SSL_EARLY_DATA && MBEDTLS_SSL_ALPN */
    }
#endif /* MBEDTLS_SSL_SRV_C */

#if defined(PF_MBEDTLS_SSL_CLI_C)
    if (session->endpoint == PF_MBEDTLS_SSL_IS_CLIENT) {
#if defined(PF_MBEDTLS_SSL_SERVER_NAME_INDICATION)
        size_t hostname_len;
        /* load host name */
        if (end - p < 2) {
            return PF_MBEDTLS_ERR_SSL_BAD_INPUT_DATA;
        }
        hostname_len = PF_MBEDTLS_GET_UINT16_BE(p, 0);
        p += 2;

        if (end - p < (long int) hostname_len) {
            return PF_MBEDTLS_ERR_SSL_BAD_INPUT_DATA;
        }
        if (hostname_len > 0) {
            /* The data is about to be used as a null-terminated string, so
             * check that it actually is one. */
            if (p[hostname_len - 1] != '\0') {
                return PF_MBEDTLS_ERR_SSL_BAD_INPUT_DATA;
            }

            int ret = pf_mbedtls_ssl_session_set_hostname(session, (const char *) p);
            if (ret != 0) {
                return ret;
            }
            p += hostname_len;
        }
#endif /* MBEDTLS_SSL_SERVER_NAME_INDICATION */

#if defined(PF_MBEDTLS_HAVE_TIME)
        if (end - p < 8) {
            return PF_MBEDTLS_ERR_SSL_BAD_INPUT_DATA;
        }
        session->ticket_reception_time = PF_MBEDTLS_GET_UINT64_BE(p, 0);
        p += 8;
#endif
        if (end - p < 4) {
            return PF_MBEDTLS_ERR_SSL_BAD_INPUT_DATA;
        }
        session->ticket_lifetime = PF_MBEDTLS_GET_UINT32_BE(p, 0);
        p += 4;

        if (end - p <  2) {
            return PF_MBEDTLS_ERR_SSL_BAD_INPUT_DATA;
        }
        session->ticket_len = PF_MBEDTLS_GET_UINT16_BE(p, 0);
        p += 2;

        if (end - p < (long int) session->ticket_len) {
            return PF_MBEDTLS_ERR_SSL_BAD_INPUT_DATA;
        }
        if (session->ticket_len > 0) {
            session->ticket = pf_mbedtls_calloc(1, session->ticket_len);
            if (session->ticket == NULL) {
                return PF_MBEDTLS_ERR_SSL_ALLOC_FAILED;
            }
            memcpy(session->ticket, p, session->ticket_len);
            p += session->ticket_len;
        }
    }
#endif /* MBEDTLS_SSL_CLI_C */

    if (p != end) {
        return PF_MBEDTLS_ERR_SSL_BAD_INPUT_DATA;
    }

    return 0;

}
#else /* MBEDTLS_SSL_SESSION_TICKETS */
PF_MBEDTLS_CHECK_RETURN_CRITICAL
static int ssl_tls13_session_save(const pf_mbedtls_ssl_session *session,
                                  unsigned char *buf,
                                  size_t buf_len,
                                  size_t *olen)
{
    ((void) session);
    ((void) buf);
    ((void) buf_len);
    *olen = 0;
    return PF_MBEDTLS_ERR_SSL_FEATURE_UNAVAILABLE;
}

static int ssl_tls13_session_load(const pf_mbedtls_ssl_session *session,
                                  const unsigned char *buf,
                                  size_t buf_len)
{
    ((void) session);
    ((void) buf);
    ((void) buf_len);
    return PF_MBEDTLS_ERR_SSL_FEATURE_UNAVAILABLE;
}
#endif /* !MBEDTLS_SSL_SESSION_TICKETS */
#endif /* MBEDTLS_SSL_PROTO_TLS1_3 */

/*
 * Define ticket header determining Mbed TLS version
 * and structure of the ticket.
 */

/*
 * Define bitflag determining compile-time settings influencing
 * structure of serialized SSL sessions.
 */

#if defined(PF_MBEDTLS_HAVE_TIME)
#define SSL_SERIALIZED_SESSION_CONFIG_TIME 1
#else
#define SSL_SERIALIZED_SESSION_CONFIG_TIME 0
#endif /* MBEDTLS_HAVE_TIME */

#if defined(PF_MBEDTLS_X509_CRT_PARSE_C)
#define SSL_SERIALIZED_SESSION_CONFIG_CRT 1
#else
#define SSL_SERIALIZED_SESSION_CONFIG_CRT 0
#endif /* MBEDTLS_X509_CRT_PARSE_C */

#if defined(PF_MBEDTLS_SSL_KEEP_PEER_CERTIFICATE)
#define SSL_SERIALIZED_SESSION_CONFIG_KEEP_PEER_CRT 1
#else
#define SSL_SERIALIZED_SESSION_CONFIG_KEEP_PEER_CRT 0
#endif /* MBEDTLS_SSL_SESSION_TICKETS */

#if defined(PF_MBEDTLS_SSL_CLI_C) && defined(PF_MBEDTLS_SSL_SESSION_TICKETS)
#define SSL_SERIALIZED_SESSION_CONFIG_CLIENT_TICKET 1
#else
#define SSL_SERIALIZED_SESSION_CONFIG_CLIENT_TICKET 0
#endif /* MBEDTLS_SSL_CLI_C && MBEDTLS_SSL_SESSION_TICKETS */

#if defined(PF_MBEDTLS_SSL_MAX_FRAGMENT_LENGTH)
#define SSL_SERIALIZED_SESSION_CONFIG_MFL 1
#else
#define SSL_SERIALIZED_SESSION_CONFIG_MFL 0
#endif /* MBEDTLS_SSL_MAX_FRAGMENT_LENGTH */

#if defined(PF_MBEDTLS_SSL_ENCRYPT_THEN_MAC)
#define SSL_SERIALIZED_SESSION_CONFIG_ETM 1
#else
#define SSL_SERIALIZED_SESSION_CONFIG_ETM 0
#endif /* MBEDTLS_SSL_ENCRYPT_THEN_MAC */

#if defined(PF_MBEDTLS_SSL_SESSION_TICKETS)
#define SSL_SERIALIZED_SESSION_CONFIG_TICKET 1
#else
#define SSL_SERIALIZED_SESSION_CONFIG_TICKET 0
#endif /* MBEDTLS_SSL_SESSION_TICKETS */

#if defined(PF_MBEDTLS_SSL_SERVER_NAME_INDICATION)
#define SSL_SERIALIZED_SESSION_CONFIG_SNI 1
#else
#define SSL_SERIALIZED_SESSION_CONFIG_SNI 0
#endif /* MBEDTLS_SSL_SERVER_NAME_INDICATION */

#if defined(PF_MBEDTLS_SSL_EARLY_DATA)
#define SSL_SERIALIZED_SESSION_CONFIG_EARLY_DATA 1
#else
#define SSL_SERIALIZED_SESSION_CONFIG_EARLY_DATA 0
#endif /* MBEDTLS_SSL_EARLY_DATA */

#if defined(PF_MBEDTLS_SSL_RECORD_SIZE_LIMIT)
#define SSL_SERIALIZED_SESSION_CONFIG_RECORD_SIZE 1
#else
#define SSL_SERIALIZED_SESSION_CONFIG_RECORD_SIZE 0
#endif /* MBEDTLS_SSL_RECORD_SIZE_LIMIT */

#if defined(PF_MBEDTLS_SSL_ALPN) && defined(PF_MBEDTLS_SSL_SRV_C) && \
    defined(PF_MBEDTLS_SSL_EARLY_DATA)
#define SSL_SERIALIZED_SESSION_CONFIG_ALPN 1
#else
#define SSL_SERIALIZED_SESSION_CONFIG_ALPN 0
#endif /* MBEDTLS_SSL_ALPN */

#define SSL_SERIALIZED_SESSION_CONFIG_TIME_BIT          0
#define SSL_SERIALIZED_SESSION_CONFIG_CRT_BIT           1
#define SSL_SERIALIZED_SESSION_CONFIG_CLIENT_TICKET_BIT 2
#define SSL_SERIALIZED_SESSION_CONFIG_MFL_BIT           3
#define SSL_SERIALIZED_SESSION_CONFIG_ETM_BIT           4
#define SSL_SERIALIZED_SESSION_CONFIG_TICKET_BIT        5
#define SSL_SERIALIZED_SESSION_CONFIG_KEEP_PEER_CRT_BIT 6
#define SSL_SERIALIZED_SESSION_CONFIG_SNI_BIT           7
#define SSL_SERIALIZED_SESSION_CONFIG_EARLY_DATA_BIT    8
#define SSL_SERIALIZED_SESSION_CONFIG_RECORD_SIZE_BIT   9
#define SSL_SERIALIZED_SESSION_CONFIG_ALPN_BIT          10

#define SSL_SERIALIZED_SESSION_CONFIG_BITFLAG                           \
    ((uint16_t) (                                                      \
         (SSL_SERIALIZED_SESSION_CONFIG_TIME << SSL_SERIALIZED_SESSION_CONFIG_TIME_BIT) | \
         (SSL_SERIALIZED_SESSION_CONFIG_CRT << SSL_SERIALIZED_SESSION_CONFIG_CRT_BIT) | \
         (SSL_SERIALIZED_SESSION_CONFIG_CLIENT_TICKET << \
             SSL_SERIALIZED_SESSION_CONFIG_CLIENT_TICKET_BIT) | \
         (SSL_SERIALIZED_SESSION_CONFIG_MFL << SSL_SERIALIZED_SESSION_CONFIG_MFL_BIT) | \
         (SSL_SERIALIZED_SESSION_CONFIG_ETM << SSL_SERIALIZED_SESSION_CONFIG_ETM_BIT) | \
         (SSL_SERIALIZED_SESSION_CONFIG_TICKET << SSL_SERIALIZED_SESSION_CONFIG_TICKET_BIT) | \
         (SSL_SERIALIZED_SESSION_CONFIG_KEEP_PEER_CRT << \
             SSL_SERIALIZED_SESSION_CONFIG_KEEP_PEER_CRT_BIT) | \
         (SSL_SERIALIZED_SESSION_CONFIG_SNI << SSL_SERIALIZED_SESSION_CONFIG_SNI_BIT) | \
         (SSL_SERIALIZED_SESSION_CONFIG_EARLY_DATA << \
             SSL_SERIALIZED_SESSION_CONFIG_EARLY_DATA_BIT) | \
         (SSL_SERIALIZED_SESSION_CONFIG_RECORD_SIZE << \
             SSL_SERIALIZED_SESSION_CONFIG_RECORD_SIZE_BIT) | \
         (SSL_SERIALIZED_SESSION_CONFIG_ALPN << \
             SSL_SERIALIZED_SESSION_CONFIG_ALPN_BIT)))

static const unsigned char ssl_serialized_session_header[] = {
    PF_MBEDTLS_VERSION_MAJOR,
    PF_MBEDTLS_VERSION_MINOR,
    PF_MBEDTLS_VERSION_PATCH,
    PF_MBEDTLS_BYTE_1(SSL_SERIALIZED_SESSION_CONFIG_BITFLAG),
    PF_MBEDTLS_BYTE_0(SSL_SERIALIZED_SESSION_CONFIG_BITFLAG),
};

/*
 * Serialize a session in the following format:
 * (in the presentation language of TLS, RFC 8446 section 3)
 *
 * TLS 1.2 session:
 *
 * struct {
 * #if defined(MBEDTLS_SSL_SESSION_TICKETS)
 *    opaque ticket<0..2^24-1>;       // length 0 means no ticket
 *    uint32 ticket_lifetime;
 * #endif
 * } ClientOnlyData;
 *
 * struct {
 * #if defined(MBEDTLS_HAVE_TIME)
 *    uint64 start_time;
 * #endif
 *     uint8 session_id_len;           // at most 32
 *     opaque session_id[32];
 *     opaque master[48];              // fixed length in the standard
 *     uint32 verify_result;
 * #if defined(MBEDTLS_SSL_KEEP_PEER_CERTIFICATE
 *    opaque peer_cert<0..2^24-1>;    // length 0 means no peer cert
 * #else
 *    uint8 peer_cert_digest_type;
 *    opaque peer_cert_digest<0..2^8-1>
 * #endif
 *     select (endpoint) {
 *         case client: ClientOnlyData;
 *         case server: uint64 ticket_creation_time;
 *     };
 * #if defined(MBEDTLS_SSL_MAX_FRAGMENT_LENGTH)
 *    uint8 mfl_code;                 // up to 255 according to standard
 * #endif
 * #if defined(MBEDTLS_SSL_ENCRYPT_THEN_MAC)
 *    uint8 encrypt_then_mac;         // 0 or 1
 * #endif
 * } serialized_session_tls12;
 *
 *
 * TLS 1.3 Session:
 *
 * struct {
 * #if defined(MBEDTLS_SSL_SERVER_NAME_INDICATION)
 *    opaque hostname<0..2^16-1>;
 * #endif
 * #if defined(MBEDTLS_HAVE_TIME)
 *    uint64 ticket_reception_time;
 * #endif
 *    uint32 ticket_lifetime;
 *    opaque ticket<1..2^16-1>;
 * } ClientOnlyData;
 *
 * struct {
 *    uint32 ticket_age_add;
 *    uint8 ticket_flags;
 *    opaque resumption_key<0..255>;
 * #if defined(MBEDTLS_SSL_EARLY_DATA)
 *    uint32 max_early_data_size;
 * #endif
 * #if defined(MBEDTLS_SSL_RECORD_SIZE_LIMIT)
 *    uint16 record_size_limit;
 * #endif
 *    select ( endpoint ) {
 *         case client: ClientOnlyData;
 *         case server:
 * #if defined(MBEDTLS_HAVE_TIME)
 *                      uint64 ticket_creation_time;
 * #endif
 * #if defined(MBEDTLS_SSL_EARLY_DATA) && defined(MBEDTLS_SSL_ALPN)
 *                      opaque ticket_alpn<0..256>;
 * #endif
 *     };
 * } serialized_session_tls13;
 *
 *
 * SSL session:
 *
 * struct {
 *
 *    opaque mbedtls_version[3];   // library version: major, minor, patch
 *    opaque session_format[2];    // library-version specific 16-bit field
 *                                 // determining the format of the remaining
 *                                 // serialized data.
 *
 *          Note: When updating the format, remember to keep
 *          these version+format bytes.
 *
 *                                 // In this version, `session_format` determines
 *                                 // the setting of those compile-time
 *                                 // configuration options which influence
 *                                 // the structure of mbedtls_ssl_session.
 *
 *    uint8_t minor_ver;           // Protocol minor version. Possible values:
 *                                 // - TLS 1.2 (0x0303)
 *                                 // - TLS 1.3 (0x0304)
 *    uint8_t endpoint;
 *    uint16_t ciphersuite;
 *
 *    select (serialized_session.tls_version) {
 *
 *      case MBEDTLS_SSL_VERSION_TLS1_2:
 *        serialized_session_tls12 data;
 *      case MBEDTLS_SSL_VERSION_TLS1_3:
 *        serialized_session_tls13 data;
 *
 *   };
 *
 * } serialized_session;
 *
 */

PF_MBEDTLS_CHECK_RETURN_CRITICAL
static int ssl_session_save(const pf_mbedtls_ssl_session *session,
                            unsigned char omit_header,
                            unsigned char *buf,
                            size_t buf_len,
                            size_t *olen)
{
    unsigned char *p = buf;
    size_t used = 0;
    size_t remaining_len;
#if defined(PF_MBEDTLS_SSL_PROTO_TLS1_3)
    size_t out_len;
    int ret = PF_MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
#endif
    if (session == NULL) {
        return PF_MBEDTLS_ERR_SSL_INTERNAL_ERROR;
    }

    if (!omit_header) {
        /*
         * Add Mbed TLS version identifier
         */
        used += sizeof(ssl_serialized_session_header);

        if (used <= buf_len) {
            memcpy(p, ssl_serialized_session_header,
                   sizeof(ssl_serialized_session_header));
            p += sizeof(ssl_serialized_session_header);
        }
    }

    /*
     * TLS version identifier, endpoint, ciphersuite
     */
    used += 1    /* TLS version */
            + 1  /* endpoint */
            + 2; /* ciphersuite */
    if (used <= buf_len) {
        *p++ = PF_MBEDTLS_BYTE_0(session->tls_version);
        *p++ = session->endpoint;
        PF_MBEDTLS_PUT_UINT16_BE(session->ciphersuite, p, 0);
        p += 2;
    }

    /* Forward to version-specific serialization routine. */
    remaining_len = (buf_len >= used) ? buf_len - used : 0;
    switch (session->tls_version) {
#if defined(PF_MBEDTLS_SSL_PROTO_TLS1_2)
        case PF_MBEDTLS_SSL_VERSION_TLS1_2:
            used += ssl_tls12_session_save(session, p, remaining_len);
            break;
#endif /* MBEDTLS_SSL_PROTO_TLS1_2 */

#if defined(PF_MBEDTLS_SSL_PROTO_TLS1_3)
        case PF_MBEDTLS_SSL_VERSION_TLS1_3:
            ret = ssl_tls13_session_save(session, p, remaining_len, &out_len);
            if (ret != 0 && ret != PF_MBEDTLS_ERR_SSL_BUFFER_TOO_SMALL) {
                return ret;
            }
            used += out_len;
            break;
#endif /* MBEDTLS_SSL_PROTO_TLS1_3 */

        default:
            return PF_MBEDTLS_ERR_SSL_FEATURE_UNAVAILABLE;
    }

    *olen = used;
    if (used > buf_len) {
        return PF_MBEDTLS_ERR_SSL_BUFFER_TOO_SMALL;
    }

    return 0;
}

/*
 * Public wrapper for ssl_session_save()
 */
int pf_mbedtls_ssl_session_save(const pf_mbedtls_ssl_session *session,
                             unsigned char *buf,
                             size_t buf_len,
                             size_t *olen)
{
    return ssl_session_save(session, 0, buf, buf_len, olen);
}

/*
 * Deserialize session, see mbedtls_ssl_session_save() for format.
 *
 * This internal version is wrapped by a public function that cleans up in
 * case of error, and has an extra option omit_header.
 */
PF_MBEDTLS_CHECK_RETURN_CRITICAL
static int ssl_session_load(pf_mbedtls_ssl_session *session,
                            unsigned char omit_header,
                            const unsigned char *buf,
                            size_t len)
{
    const unsigned char *p = buf;
    const unsigned char * const end = buf + len;
    size_t remaining_len;


    if (session == NULL) {
        return PF_MBEDTLS_ERR_SSL_INTERNAL_ERROR;
    }

    if (!omit_header) {
        /*
         * Check Mbed TLS version identifier
         */

        if ((size_t) (end - p) < sizeof(ssl_serialized_session_header)) {
            return PF_MBEDTLS_ERR_SSL_BAD_INPUT_DATA;
        }

        if (memcmp(p, ssl_serialized_session_header,
                   sizeof(ssl_serialized_session_header)) != 0) {
            return PF_MBEDTLS_ERR_SSL_VERSION_MISMATCH;
        }
        p += sizeof(ssl_serialized_session_header);
    }

    /*
     * TLS version identifier, endpoint, ciphersuite
     */
    if (4 > (size_t) (end - p)) {
        return PF_MBEDTLS_ERR_SSL_BAD_INPUT_DATA;
    }
    session->tls_version = (pf_mbedtls_ssl_protocol_version) (0x0300 | *p++);
    session->endpoint = *p++;
    session->ciphersuite = PF_MBEDTLS_GET_UINT16_BE(p, 0);
    p += 2;

    /* Dispatch according to TLS version. */
    remaining_len = (size_t) (end - p);
    switch (session->tls_version) {
#if defined(PF_MBEDTLS_SSL_PROTO_TLS1_2)
        case PF_MBEDTLS_SSL_VERSION_TLS1_2:
            return ssl_tls12_session_load(session, p, remaining_len);
#endif /* MBEDTLS_SSL_PROTO_TLS1_2 */

#if defined(PF_MBEDTLS_SSL_PROTO_TLS1_3)
        case PF_MBEDTLS_SSL_VERSION_TLS1_3:
            return ssl_tls13_session_load(session, p, remaining_len);
#endif /* MBEDTLS_SSL_PROTO_TLS1_3 */

        default:
            return PF_MBEDTLS_ERR_SSL_BAD_INPUT_DATA;
    }
}

/*
 * Deserialize session: public wrapper for error cleaning
 */
int pf_mbedtls_ssl_session_load(pf_mbedtls_ssl_session *session,
                             const unsigned char *buf,
                             size_t len)
{
    int ret = ssl_session_load(session, 0, buf, len);

    if (ret != 0) {
        pf_mbedtls_ssl_session_free(session);
    }

    return ret;
}

/*
 * Perform a single step of the SSL handshake
 */
PF_MBEDTLS_CHECK_RETURN_CRITICAL
static int ssl_prepare_handshake_step(pf_mbedtls_ssl_context *ssl)
{
    int ret = PF_MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;

    /*
     * We may have not been able to send to the peer all the handshake data
     * that were written into the output buffer by the previous handshake step,
     * if the write to the network callback returned with the
     * #MBEDTLS_ERR_SSL_WANT_WRITE error code.
     * We proceed to the next handshake step only when all data from the
     * previous one have been sent to the peer, thus we make sure that this is
     * the case here by calling `mbedtls_ssl_flush_output()`. The function may
     * return with the #MBEDTLS_ERR_SSL_WANT_WRITE error code in which case
     * we have to wait before to go ahead.
     * In the case of TLS 1.3, handshake step handlers do not send data to the
     * peer. Data are only sent here and through
     * `mbedtls_ssl_handle_pending_alert` in case an error that triggered an
     * alert occurred.
     */
    if ((ret = pf_mbedtls_ssl_flush_output(ssl)) != 0) {
        return ret;
    }

#if defined(PF_MBEDTLS_SSL_PROTO_DTLS)
    if (ssl->conf->transport == PF_MBEDTLS_SSL_TRANSPORT_DATAGRAM &&
        ssl->handshake->retransmit_state == PF_MBEDTLS_SSL_RETRANS_SENDING) {
        if ((ret = pf_mbedtls_ssl_flight_transmit(ssl)) != 0) {
            return ret;
        }
    }
#endif /* MBEDTLS_SSL_PROTO_DTLS */

    return ret;
}

int pf_mbedtls_ssl_handshake_step(pf_mbedtls_ssl_context *ssl)
{
    int ret = PF_MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;

    if (ssl            == NULL                       ||
        ssl->conf      == NULL                       ||
        ssl->handshake == NULL                       ||
        ssl->state == PF_MBEDTLS_SSL_HANDSHAKE_OVER) {
        return PF_MBEDTLS_ERR_SSL_BAD_INPUT_DATA;
    }

    ret = ssl_prepare_handshake_step(ssl);
    if (ret != 0) {
        return ret;
    }

    ret = pf_mbedtls_ssl_handle_pending_alert(ssl);
    if (ret != 0) {
        goto cleanup;
    }

    /* If ssl->conf->endpoint is not one of MBEDTLS_SSL_IS_CLIENT or
     * MBEDTLS_SSL_IS_SERVER, this is the return code we give */
    ret = PF_MBEDTLS_ERR_SSL_BAD_INPUT_DATA;

#if defined(PF_MBEDTLS_SSL_CLI_C)
    if (ssl->conf->endpoint == PF_MBEDTLS_SSL_IS_CLIENT) {
        PF_MBEDTLS_SSL_DEBUG_MSG(2, ("client state: %s",
                                  pf_mbedtls_ssl_states_str((pf_mbedtls_ssl_states) ssl->state)));

        switch (ssl->state) {
            case PF_MBEDTLS_SSL_HELLO_REQUEST:
                pf_mbedtls_ssl_handshake_set_state(ssl, PF_MBEDTLS_SSL_CLIENT_HELLO);
                ret = 0;
                break;

            case PF_MBEDTLS_SSL_CLIENT_HELLO:
                ret = pf_mbedtls_ssl_write_client_hello(ssl);
                break;

            default:
#if defined(PF_MBEDTLS_SSL_PROTO_TLS1_2) && defined(PF_MBEDTLS_SSL_PROTO_TLS1_3)
                if (ssl->tls_version == PF_MBEDTLS_SSL_VERSION_TLS1_3) {
                    ret = pf_mbedtls_ssl_tls13_handshake_client_step(ssl);
                } else {
                    ret = pf_mbedtls_ssl_handshake_client_step(ssl);
                }
#elif defined(PF_MBEDTLS_SSL_PROTO_TLS1_2)
                ret = pf_mbedtls_ssl_handshake_client_step(ssl);
#else
                ret = pf_mbedtls_ssl_tls13_handshake_client_step(ssl);
#endif
        }
    }
#endif /* MBEDTLS_SSL_CLI_C */

#if defined(PF_MBEDTLS_SSL_SRV_C)
    if (ssl->conf->endpoint == PF_MBEDTLS_SSL_IS_SERVER) {
#if defined(PF_MBEDTLS_SSL_PROTO_TLS1_2) && defined(PF_MBEDTLS_SSL_PROTO_TLS1_3)
        if (ssl->tls_version == PF_MBEDTLS_SSL_VERSION_TLS1_3) {
            ret = pf_mbedtls_ssl_tls13_handshake_server_step(ssl);
        } else {
            ret = pf_mbedtls_ssl_handshake_server_step(ssl);
        }
#elif defined(PF_MBEDTLS_SSL_PROTO_TLS1_2)
        ret = pf_mbedtls_ssl_handshake_server_step(ssl);
#else
        ret = pf_mbedtls_ssl_tls13_handshake_server_step(ssl);
#endif
    }
#endif /* MBEDTLS_SSL_SRV_C */

    if (ret != 0) {
        /* handshake_step return error. And it is same
         * with alert_reason.
         */
        if (ssl->send_alert) {
            ret = pf_mbedtls_ssl_handle_pending_alert(ssl);
            goto cleanup;
        }
    }

cleanup:
    return ret;
}

/*
 * Perform the SSL handshake
 */
int pf_mbedtls_ssl_handshake(pf_mbedtls_ssl_context *ssl)
{
    int ret = 0;

    /* Sanity checks */

    if (ssl == NULL || ssl->conf == NULL) {
        return PF_MBEDTLS_ERR_SSL_BAD_INPUT_DATA;
    }

#if defined(PF_MBEDTLS_SSL_PROTO_DTLS)
    if (ssl->conf->transport == PF_MBEDTLS_SSL_TRANSPORT_DATAGRAM &&
        (ssl->f_set_timer == NULL || ssl->f_get_timer == NULL)) {
        PF_MBEDTLS_SSL_DEBUG_MSG(1, ("You must use "
                                  "mbedtls_ssl_set_timer_cb() for DTLS"));
        return PF_MBEDTLS_ERR_SSL_BAD_INPUT_DATA;
    }
#endif /* MBEDTLS_SSL_PROTO_DTLS */

    PF_MBEDTLS_SSL_DEBUG_MSG(2, ("=> handshake"));

    /* Main handshake loop */
    while (ssl->state != PF_MBEDTLS_SSL_HANDSHAKE_OVER) {
        ret = pf_mbedtls_ssl_handshake_step(ssl);

        if (ret != 0) {
            break;
        }
    }

    PF_MBEDTLS_SSL_DEBUG_MSG(2, ("<= handshake"));

    return ret;
}

#if defined(PF_MBEDTLS_SSL_RENEGOTIATION)
#if defined(PF_MBEDTLS_SSL_SRV_C)
/*
 * Write HelloRequest to request renegotiation on server
 */
PF_MBEDTLS_CHECK_RETURN_CRITICAL
static int ssl_write_hello_request(pf_mbedtls_ssl_context *ssl)
{
    int ret = PF_MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;

    PF_MBEDTLS_SSL_DEBUG_MSG(2, ("=> write hello request"));

    ssl->out_msglen  = 4;
    ssl->out_msgtype = PF_MBEDTLS_SSL_MSG_HANDSHAKE;
    ssl->out_msg[0]  = PF_MBEDTLS_SSL_HS_HELLO_REQUEST;

    if ((ret = pf_mbedtls_ssl_write_handshake_msg(ssl)) != 0) {
        PF_MBEDTLS_SSL_DEBUG_RET(1, "mbedtls_ssl_write_handshake_msg", ret);
        return ret;
    }

    PF_MBEDTLS_SSL_DEBUG_MSG(2, ("<= write hello request"));

    return 0;
}
#endif /* MBEDTLS_SSL_SRV_C */

/*
 * Actually renegotiate current connection, triggered by either:
 * - any side: calling mbedtls_ssl_renegotiate(),
 * - client: receiving a HelloRequest during mbedtls_ssl_read(),
 * - server: receiving any handshake message on server during mbedtls_ssl_read() after
 *   the initial handshake is completed.
 * If the handshake doesn't complete due to waiting for I/O, it will continue
 * during the next calls to mbedtls_ssl_renegotiate() or mbedtls_ssl_read() respectively.
 */
int pf_mbedtls_ssl_start_renegotiation(pf_mbedtls_ssl_context *ssl)
{
    int ret = PF_MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;

    PF_MBEDTLS_SSL_DEBUG_MSG(2, ("=> renegotiate"));

    if ((ret = ssl_handshake_init(ssl)) != 0) {
        return ret;
    }

    /* RFC 6347 4.2.2: "[...] the HelloRequest will have message_seq = 0 and
     * the ServerHello will have message_seq = 1" */
#if defined(PF_MBEDTLS_SSL_PROTO_DTLS)
    if (ssl->conf->transport == PF_MBEDTLS_SSL_TRANSPORT_DATAGRAM &&
        ssl->renego_status == PF_MBEDTLS_SSL_RENEGOTIATION_PENDING) {
        if (ssl->conf->endpoint == PF_MBEDTLS_SSL_IS_SERVER) {
            ssl->handshake->out_msg_seq = 1;
        } else {
            ssl->handshake->in_msg_seq = 1;
        }
    }
#endif

    pf_mbedtls_ssl_handshake_set_state(ssl, PF_MBEDTLS_SSL_HELLO_REQUEST);
    ssl->renego_status = PF_MBEDTLS_SSL_RENEGOTIATION_IN_PROGRESS;

    if ((ret = pf_mbedtls_ssl_handshake(ssl)) != 0) {
        PF_MBEDTLS_SSL_DEBUG_RET(1, "mbedtls_ssl_handshake", ret);
        return ret;
    }

    PF_MBEDTLS_SSL_DEBUG_MSG(2, ("<= renegotiate"));

    return 0;
}

/*
 * Renegotiate current connection on client,
 * or request renegotiation on server
 */
int pf_mbedtls_ssl_renegotiate(pf_mbedtls_ssl_context *ssl)
{
    int ret = PF_MBEDTLS_ERR_SSL_FEATURE_UNAVAILABLE;

    if (ssl == NULL || ssl->conf == NULL) {
        return PF_MBEDTLS_ERR_SSL_BAD_INPUT_DATA;
    }

#if defined(PF_MBEDTLS_SSL_SRV_C)
    /* On server, just send the request */
    if (ssl->conf->endpoint == PF_MBEDTLS_SSL_IS_SERVER) {
        if (pf_mbedtls_ssl_is_handshake_over(ssl) == 0) {
            return PF_MBEDTLS_ERR_SSL_BAD_INPUT_DATA;
        }

        ssl->renego_status = PF_MBEDTLS_SSL_RENEGOTIATION_PENDING;

        /* Did we already try/start sending HelloRequest? */
        if (ssl->out_left != 0) {
            return pf_mbedtls_ssl_flush_output(ssl);
        }

        return ssl_write_hello_request(ssl);
    }
#endif /* MBEDTLS_SSL_SRV_C */

#if defined(PF_MBEDTLS_SSL_CLI_C)
    /*
     * On client, either start the renegotiation process or,
     * if already in progress, continue the handshake
     */
    if (ssl->renego_status != PF_MBEDTLS_SSL_RENEGOTIATION_IN_PROGRESS) {
        if (pf_mbedtls_ssl_is_handshake_over(ssl) == 0) {
            return PF_MBEDTLS_ERR_SSL_BAD_INPUT_DATA;
        }

        if ((ret = pf_mbedtls_ssl_start_renegotiation(ssl)) != 0) {
            PF_MBEDTLS_SSL_DEBUG_RET(1, "mbedtls_ssl_start_renegotiation", ret);
            return ret;
        }
    } else {
        if ((ret = pf_mbedtls_ssl_handshake(ssl)) != 0) {
            PF_MBEDTLS_SSL_DEBUG_RET(1, "mbedtls_ssl_handshake", ret);
            return ret;
        }
    }
#endif /* MBEDTLS_SSL_CLI_C */

    return ret;
}
#endif /* MBEDTLS_SSL_RENEGOTIATION */

void pf_mbedtls_ssl_handshake_free(pf_mbedtls_ssl_context *ssl)
{
    pf_mbedtls_ssl_handshake_params *handshake = ssl->handshake;

    if (handshake == NULL) {
        return;
    }

#if defined(PF_MBEDTLS_PK_HAVE_ECC_KEYS)
#if !defined(PF_MBEDTLS_DEPRECATED_REMOVED)
    if (ssl->handshake->group_list_heap_allocated) {
        pf_mbedtls_free((void *) handshake->group_list);
    }
    handshake->group_list = NULL;
#endif /* MBEDTLS_DEPRECATED_REMOVED */
#endif /* MBEDTLS_PK_HAVE_ECC_KEYS */

#if defined(PF_MBEDTLS_SSL_HANDSHAKE_WITH_CERT_ENABLED)
#if !defined(PF_MBEDTLS_DEPRECATED_REMOVED)
    if (ssl->handshake->sig_algs_heap_allocated) {
        pf_mbedtls_free((void *) handshake->sig_algs);
    }
    handshake->sig_algs = NULL;
#endif /* MBEDTLS_DEPRECATED_REMOVED */
#if defined(PF_MBEDTLS_SSL_PROTO_TLS1_3)
    if (ssl->handshake->certificate_request_context) {
        pf_mbedtls_free((void *) handshake->certificate_request_context);
    }
#endif /* MBEDTLS_SSL_PROTO_TLS1_3 */
#endif /* MBEDTLS_SSL_HANDSHAKE_WITH_CERT_ENABLED */

#if defined(PF_MBEDTLS_SSL_ASYNC_PRIVATE)
    if (ssl->conf->f_async_cancel != NULL && handshake->async_in_progress != 0) {
        ssl->conf->f_async_cancel(ssl);
        handshake->async_in_progress = 0;
    }
#endif /* MBEDTLS_SSL_ASYNC_PRIVATE */

#if defined(PF_MBEDTLS_MD_CAN_SHA256)
#if defined(PF_MBEDTLS_USE_PSA_CRYPTO)
    pf_psa_hash_abort(&handshake->fin_sha256_psa);
#else
    pf_mbedtls_md_free(&handshake->fin_sha256);
#endif
#endif
#if defined(PF_MBEDTLS_MD_CAN_SHA384)
#if defined(PF_MBEDTLS_USE_PSA_CRYPTO)
    pf_psa_hash_abort(&handshake->fin_sha384_psa);
#else
    pf_mbedtls_md_free(&handshake->fin_sha384);
#endif
#endif

#if defined(PF_MBEDTLS_DHM_C)
    pf_mbedtls_dhm_free(&handshake->dhm_ctx);
#endif
#if !defined(PF_MBEDTLS_USE_PSA_CRYPTO) && \
    defined(PF_MBEDTLS_KEY_EXCHANGE_SOME_ECDH_OR_ECDHE_1_2_ENABLED)
    pf_mbedtls_ecdh_free(&handshake->ecdh_ctx);
#endif

#if defined(PF_MBEDTLS_KEY_EXCHANGE_ECJPAKE_ENABLED)
#if defined(PF_MBEDTLS_USE_PSA_CRYPTO)
    pf_psa_pake_abort(&handshake->pf_psa_pake_ctx);
    /*
     * Opaque keys are not stored in the handshake's data and it's the user
     * responsibility to destroy them. Clear ones, instead, are created by
     * the TLS library and should be destroyed at the same level
     */
    if (!pf_mbedtls_svc_key_id_is_null(handshake->pf_psa_pake_password)) {
        pf_psa_destroy_key(handshake->pf_psa_pake_password);
    }
    handshake->pf_psa_pake_password = PF_MBEDTLS_SVC_KEY_ID_INIT;
#else
    pf_mbedtls_ecjpake_free(&handshake->ecjpake_ctx);
#endif /* MBEDTLS_USE_PSA_CRYPTO */
#if defined(PF_MBEDTLS_SSL_CLI_C)
    pf_mbedtls_free(handshake->ecjpake_cache);
    handshake->ecjpake_cache = NULL;
    handshake->ecjpake_cache_len = 0;
#endif
#endif

#if defined(PF_MBEDTLS_KEY_EXCHANGE_SOME_ECDH_OR_ECDHE_ANY_ENABLED) || \
    defined(PF_MBEDTLS_KEY_EXCHANGE_WITH_ECDSA_ANY_ENABLED) || \
    defined(PF_MBEDTLS_KEY_EXCHANGE_ECJPAKE_ENABLED)
    /* explicit void pointer cast for buggy MS compiler */
    pf_mbedtls_free((void *) handshake->curves_tls_id);
#endif

#if defined(PF_MBEDTLS_SSL_HANDSHAKE_WITH_PSK_ENABLED)
#if defined(PF_MBEDTLS_USE_PSA_CRYPTO)
    if (!pf_mbedtls_svc_key_id_is_null(ssl->handshake->psk_opaque)) {
        /* The maintenance of the external PSK key slot is the
         * user's responsibility. */
        if (ssl->handshake->psk_opaque_is_internal) {
            pf_psa_destroy_key(ssl->handshake->psk_opaque);
            ssl->handshake->psk_opaque_is_internal = 0;
        }
        ssl->handshake->psk_opaque = PF_MBEDTLS_SVC_KEY_ID_INIT;
    }
#else
    if (handshake->psk != NULL) {
        pf_mbedtls_zeroize_and_free(handshake->psk, handshake->psk_len);
    }
#endif /* MBEDTLS_USE_PSA_CRYPTO */
#endif /* MBEDTLS_SSL_HANDSHAKE_WITH_PSK_ENABLED */

#if defined(PF_MBEDTLS_X509_CRT_PARSE_C) && \
    defined(PF_MBEDTLS_SSL_SERVER_NAME_INDICATION)
    /*
     * Free only the linked list wrapper, not the keys themselves
     * since the belong to the SNI callback
     */
    ssl_key_cert_free(handshake->sni_key_cert);
#endif /* MBEDTLS_X509_CRT_PARSE_C && MBEDTLS_SSL_SERVER_NAME_INDICATION */

#if defined(PF_MBEDTLS_SSL_ECP_RESTARTABLE_ENABLED)
    pf_mbedtls_x509_crt_restart_free(&handshake->ecrs_ctx);
    if (handshake->ecrs_peer_cert != NULL) {
        pf_mbedtls_x509_crt_free(handshake->ecrs_peer_cert);
        pf_mbedtls_free(handshake->ecrs_peer_cert);
    }
#endif

#if defined(PF_MBEDTLS_X509_CRT_PARSE_C) &&        \
    !defined(PF_MBEDTLS_SSL_KEEP_PEER_CERTIFICATE)
    pf_mbedtls_pk_free(&handshake->peer_pubkey);
#endif /* MBEDTLS_X509_CRT_PARSE_C && !MBEDTLS_SSL_KEEP_PEER_CERTIFICATE */

#if defined(PF_MBEDTLS_SSL_CLI_C) && \
    (defined(PF_MBEDTLS_SSL_PROTO_DTLS) || defined(PF_MBEDTLS_SSL_PROTO_TLS1_3))
    pf_mbedtls_free(handshake->cookie);
#endif /* MBEDTLS_SSL_CLI_C &&
          ( MBEDTLS_SSL_PROTO_DTLS || MBEDTLS_SSL_PROTO_TLS1_3 ) */

#if defined(PF_MBEDTLS_SSL_PROTO_DTLS)
    pf_mbedtls_ssl_flight_free(handshake->flight);
    pf_mbedtls_ssl_buffering_free(ssl);
#endif /* MBEDTLS_SSL_PROTO_DTLS */

#if defined(PF_MBEDTLS_KEY_EXCHANGE_SOME_XXDH_PSA_ANY_ENABLED)
    if (handshake->xxdh_psa_privkey_is_external == 0) {
        pf_psa_destroy_key(handshake->xxdh_psa_privkey);
    }
#endif /* MBEDTLS_KEY_EXCHANGE_SOME_XXDH_PSA_ANY_ENABLED */

#if defined(PF_MBEDTLS_SSL_PROTO_TLS1_3)
    pf_mbedtls_ssl_transform_free(handshake->transform_handshake);
    pf_mbedtls_free(handshake->transform_handshake);
#if defined(PF_MBEDTLS_SSL_EARLY_DATA)
    pf_mbedtls_ssl_transform_free(handshake->transform_earlydata);
    pf_mbedtls_free(handshake->transform_earlydata);
#endif
#endif /* MBEDTLS_SSL_PROTO_TLS1_3 */


#if defined(PF_MBEDTLS_SSL_VARIABLE_BUFFER_LENGTH)
    /* If the buffers are too big - reallocate. Because of the way Mbed TLS
     * processes datagrams and the fact that a datagram is allowed to have
     * several records in it, it is possible that the I/O buffers are not
     * empty at this stage */
    handle_buffer_resizing(ssl, 1, pf_mbedtls_ssl_get_input_buflen(ssl),
                           pf_mbedtls_ssl_get_output_buflen(ssl));
#endif

    /* mbedtls_platform_zeroize MUST be last one in this function */
    pf_mbedtls_platform_zeroize(handshake,
                             sizeof(pf_mbedtls_ssl_handshake_params));
}

void pf_mbedtls_ssl_session_free(pf_mbedtls_ssl_session *session)
{
    if (session == NULL) {
        return;
    }

#if defined(PF_MBEDTLS_X509_CRT_PARSE_C)
    ssl_clear_peer_cert(session);
#endif

#if defined(PF_MBEDTLS_SSL_SESSION_TICKETS) && defined(PF_MBEDTLS_SSL_CLI_C)
#if defined(PF_MBEDTLS_SSL_PROTO_TLS1_3) && \
    defined(PF_MBEDTLS_SSL_SERVER_NAME_INDICATION)
    pf_mbedtls_free(session->hostname);
#endif
    pf_mbedtls_free(session->ticket);
#endif

#if defined(PF_MBEDTLS_SSL_EARLY_DATA) && defined(PF_MBEDTLS_SSL_ALPN) && \
    defined(PF_MBEDTLS_SSL_SRV_C)
    pf_mbedtls_free(session->ticket_alpn);
#endif

    pf_mbedtls_platform_zeroize(session, sizeof(pf_mbedtls_ssl_session));

    /* Set verify_result to -1u to indicate 'result not available'. */
    session->verify_result = 0xFFFFFFFF;
}

#if defined(PF_MBEDTLS_SSL_CONTEXT_SERIALIZATION)

#if defined(PF_MBEDTLS_SSL_DTLS_CONNECTION_ID)
#define SSL_SERIALIZED_CONTEXT_CONFIG_DTLS_CONNECTION_ID 1u
#else
#define SSL_SERIALIZED_CONTEXT_CONFIG_DTLS_CONNECTION_ID 0u
#endif /* MBEDTLS_SSL_DTLS_CONNECTION_ID */

#define SSL_SERIALIZED_CONTEXT_CONFIG_DTLS_BADMAC_LIMIT 1u

#if defined(PF_MBEDTLS_SSL_DTLS_ANTI_REPLAY)
#define SSL_SERIALIZED_CONTEXT_CONFIG_DTLS_ANTI_REPLAY 1u
#else
#define SSL_SERIALIZED_CONTEXT_CONFIG_DTLS_ANTI_REPLAY 0u
#endif /* MBEDTLS_SSL_DTLS_ANTI_REPLAY */

#if defined(PF_MBEDTLS_SSL_ALPN)
#define SSL_SERIALIZED_CONTEXT_CONFIG_ALPN 1u
#else
#define SSL_SERIALIZED_CONTEXT_CONFIG_ALPN 0u
#endif /* MBEDTLS_SSL_ALPN */

#define SSL_SERIALIZED_CONTEXT_CONFIG_DTLS_CONNECTION_ID_BIT    0
#define SSL_SERIALIZED_CONTEXT_CONFIG_DTLS_BADMAC_LIMIT_BIT     1
#define SSL_SERIALIZED_CONTEXT_CONFIG_DTLS_ANTI_REPLAY_BIT      2
#define SSL_SERIALIZED_CONTEXT_CONFIG_ALPN_BIT                  3

#define SSL_SERIALIZED_CONTEXT_CONFIG_BITFLAG   \
    ((uint32_t) (                              \
         (SSL_SERIALIZED_CONTEXT_CONFIG_DTLS_CONNECTION_ID << \
             SSL_SERIALIZED_CONTEXT_CONFIG_DTLS_CONNECTION_ID_BIT) | \
         (SSL_SERIALIZED_CONTEXT_CONFIG_DTLS_BADMAC_LIMIT << \
             SSL_SERIALIZED_CONTEXT_CONFIG_DTLS_BADMAC_LIMIT_BIT) | \
         (SSL_SERIALIZED_CONTEXT_CONFIG_DTLS_ANTI_REPLAY << \
             SSL_SERIALIZED_CONTEXT_CONFIG_DTLS_ANTI_REPLAY_BIT) | \
         (SSL_SERIALIZED_CONTEXT_CONFIG_ALPN << SSL_SERIALIZED_CONTEXT_CONFIG_ALPN_BIT) | \
         0u))

static const unsigned char ssl_serialized_context_header[] = {
    PF_MBEDTLS_VERSION_MAJOR,
    PF_MBEDTLS_VERSION_MINOR,
    PF_MBEDTLS_VERSION_PATCH,
    PF_MBEDTLS_BYTE_1(SSL_SERIALIZED_SESSION_CONFIG_BITFLAG),
    PF_MBEDTLS_BYTE_0(SSL_SERIALIZED_SESSION_CONFIG_BITFLAG),
    PF_MBEDTLS_BYTE_2(SSL_SERIALIZED_CONTEXT_CONFIG_BITFLAG),
    PF_MBEDTLS_BYTE_1(SSL_SERIALIZED_CONTEXT_CONFIG_BITFLAG),
    PF_MBEDTLS_BYTE_0(SSL_SERIALIZED_CONTEXT_CONFIG_BITFLAG),
};

/*
 * Serialize a full SSL context
 *
 * The format of the serialized data is:
 * (in the presentation language of TLS, RFC 8446 section 3)
 *
 *  // header
 *  opaque mbedtls_version[3];   // major, minor, patch
 *  opaque context_format[5];    // version-specific field determining
 *                               // the format of the remaining
 *                               // serialized data.
 *  Note: When updating the format, remember to keep these
 *        version+format bytes. (We may make their size part of the API.)
 *
 *  // session sub-structure
 *  opaque session<1..2^32-1>;  // see mbedtls_ssl_session_save()
 *  // transform sub-structure
 *  uint8 random[64];           // ServerHello.random+ClientHello.random
 *  uint8 in_cid<0..2^8-1>      // Connection ID: expected incoming value
 *  uint8 out_cid<0..2^8-1>     // Connection ID: outgoing value to use
 *  // fields from ssl_context
 *  uint32 badmac_seen_or_in_hsfraglen;         // DTLS: number of records with failing MAC
 *  uint64 in_window_top;       // DTLS: last validated record seq_num
 *  uint64 in_window;           // DTLS: bitmask for replay protection
 *  uint8 disable_datagram_packing; // DTLS: only one record per datagram
 *  uint64 cur_out_ctr;         // Record layer: outgoing sequence number
 *  uint16 mtu;                 // DTLS: path mtu (max outgoing fragment size)
 *  uint8 alpn_chosen<0..2^8-1> // ALPN: negotiated application protocol
 *
 * Note that many fields of the ssl_context or sub-structures are not
 * serialized, as they fall in one of the following categories:
 *
 *  1. forced value (eg in_left must be 0)
 *  2. pointer to dynamically-allocated memory (eg session, transform)
 *  3. value can be re-derived from other data (eg session keys from MS)
 *  4. value was temporary (eg content of input buffer)
 *  5. value will be provided by the user again (eg I/O callbacks and context)
 */
int pf_mbedtls_ssl_context_save(pf_mbedtls_ssl_context *ssl,
                             unsigned char *buf,
                             size_t buf_len,
                             size_t *olen)
{
    unsigned char *p = buf;
    size_t used = 0;
    size_t session_len;
    int ret = 0;

    /*
     * Enforce usage restrictions, see "return BAD_INPUT_DATA" in
     * this function's documentation.
     *
     * These are due to assumptions/limitations in the implementation. Some of
     * them are likely to stay (no handshake in progress) some might go away
     * (only DTLS) but are currently used to simplify the implementation.
     */
    /* The initial handshake must be over */
    if (pf_mbedtls_ssl_is_handshake_over(ssl) == 0) {
        PF_MBEDTLS_SSL_DEBUG_MSG(1, ("Initial handshake isn't over"));
        return PF_MBEDTLS_ERR_SSL_BAD_INPUT_DATA;
    }
    if (ssl->handshake != NULL) {
        PF_MBEDTLS_SSL_DEBUG_MSG(1, ("Handshake isn't completed"));
        return PF_MBEDTLS_ERR_SSL_BAD_INPUT_DATA;
    }
    /* Double-check that sub-structures are indeed ready */
    if (ssl->transform == NULL || ssl->session == NULL) {
        PF_MBEDTLS_SSL_DEBUG_MSG(1, ("Serialised structures aren't ready"));
        return PF_MBEDTLS_ERR_SSL_BAD_INPUT_DATA;
    }
    /* There must be no pending incoming or outgoing data */
    if (pf_mbedtls_ssl_check_pending(ssl) != 0) {
        PF_MBEDTLS_SSL_DEBUG_MSG(1, ("There is pending incoming data"));
        return PF_MBEDTLS_ERR_SSL_BAD_INPUT_DATA;
    }
    if (ssl->out_left != 0) {
        PF_MBEDTLS_SSL_DEBUG_MSG(1, ("There is pending outgoing data"));
        return PF_MBEDTLS_ERR_SSL_BAD_INPUT_DATA;
    }
    /* Protocol must be DTLS, not TLS */
    if (ssl->conf->transport != PF_MBEDTLS_SSL_TRANSPORT_DATAGRAM) {
        PF_MBEDTLS_SSL_DEBUG_MSG(1, ("Only DTLS is supported"));
        return PF_MBEDTLS_ERR_SSL_BAD_INPUT_DATA;
    }
    /* Version must be 1.2 */
    if (ssl->tls_version != PF_MBEDTLS_SSL_VERSION_TLS1_2) {
        PF_MBEDTLS_SSL_DEBUG_MSG(1, ("Only version 1.2 supported"));
        return PF_MBEDTLS_ERR_SSL_BAD_INPUT_DATA;
    }
    /* We must be using an AEAD ciphersuite */
    if (pf_mbedtls_ssl_transform_uses_aead(ssl->transform) != 1) {
        PF_MBEDTLS_SSL_DEBUG_MSG(1, ("Only AEAD ciphersuites supported"));
        return PF_MBEDTLS_ERR_SSL_BAD_INPUT_DATA;
    }
    /* Renegotiation must not be enabled */
#if defined(PF_MBEDTLS_SSL_RENEGOTIATION)
    if (ssl->conf->disable_renegotiation != PF_MBEDTLS_SSL_RENEGOTIATION_DISABLED) {
        PF_MBEDTLS_SSL_DEBUG_MSG(1, ("Renegotiation must not be enabled"));
        return PF_MBEDTLS_ERR_SSL_BAD_INPUT_DATA;
    }
#endif

    /*
     * Version and format identifier
     */
    used += sizeof(ssl_serialized_context_header);

    if (used <= buf_len) {
        memcpy(p, ssl_serialized_context_header,
               sizeof(ssl_serialized_context_header));
        p += sizeof(ssl_serialized_context_header);
    }

    /*
     * Session (length + data)
     */
    ret = ssl_session_save(ssl->session, 1, NULL, 0, &session_len);
    if (ret != PF_MBEDTLS_ERR_SSL_BUFFER_TOO_SMALL) {
        return ret;
    }

    used += 4 + session_len;
    if (used <= buf_len) {
        PF_MBEDTLS_PUT_UINT32_BE(session_len, p, 0);
        p += 4;

        ret = ssl_session_save(ssl->session, 1,
                               p, session_len, &session_len);
        if (ret != 0) {
            return ret;
        }

        p += session_len;
    }

    /*
     * Transform
     */
    used += sizeof(ssl->transform->randbytes);
    if (used <= buf_len) {
        memcpy(p, ssl->transform->randbytes,
               sizeof(ssl->transform->randbytes));
        p += sizeof(ssl->transform->randbytes);
    }

#if defined(PF_MBEDTLS_SSL_DTLS_CONNECTION_ID)
    used += 2U + ssl->transform->in_cid_len + ssl->transform->out_cid_len;
    if (used <= buf_len) {
        *p++ = ssl->transform->in_cid_len;
        memcpy(p, ssl->transform->in_cid, ssl->transform->in_cid_len);
        p += ssl->transform->in_cid_len;

        *p++ = ssl->transform->out_cid_len;
        memcpy(p, ssl->transform->out_cid, ssl->transform->out_cid_len);
        p += ssl->transform->out_cid_len;
    }
#endif /* MBEDTLS_SSL_DTLS_CONNECTION_ID */

    /*
     * Saved fields from top-level ssl_context structure
     */
    used += 4;
    if (used <= buf_len) {
        PF_MBEDTLS_PUT_UINT32_BE(ssl->badmac_seen_or_in_hsfraglen, p, 0);
        p += 4;
    }

#if defined(PF_MBEDTLS_SSL_DTLS_ANTI_REPLAY)
    used += 16;
    if (used <= buf_len) {
        PF_MBEDTLS_PUT_UINT64_BE(ssl->in_window_top, p, 0);
        p += 8;

        PF_MBEDTLS_PUT_UINT64_BE(ssl->in_window, p, 0);
        p += 8;
    }
#endif /* MBEDTLS_SSL_DTLS_ANTI_REPLAY */

#if defined(PF_MBEDTLS_SSL_PROTO_DTLS)
    used += 1;
    if (used <= buf_len) {
        *p++ = ssl->disable_datagram_packing;
    }
#endif /* MBEDTLS_SSL_PROTO_DTLS */

    used += PF_MBEDTLS_SSL_SEQUENCE_NUMBER_LEN;
    if (used <= buf_len) {
        memcpy(p, ssl->cur_out_ctr, PF_MBEDTLS_SSL_SEQUENCE_NUMBER_LEN);
        p += PF_MBEDTLS_SSL_SEQUENCE_NUMBER_LEN;
    }

#if defined(PF_MBEDTLS_SSL_PROTO_DTLS)
    used += 2;
    if (used <= buf_len) {
        PF_MBEDTLS_PUT_UINT16_BE(ssl->mtu, p, 0);
        p += 2;
    }
#endif /* MBEDTLS_SSL_PROTO_DTLS */

#if defined(PF_MBEDTLS_SSL_ALPN)
    {
        const uint8_t alpn_len = ssl->alpn_chosen
                               ? (uint8_t) strlen(ssl->alpn_chosen)
                               : 0;

        used += 1 + alpn_len;
        if (used <= buf_len) {
            *p++ = alpn_len;

            if (ssl->alpn_chosen != NULL) {
                memcpy(p, ssl->alpn_chosen, alpn_len);
                p += alpn_len;
            }
        }
    }
#endif /* MBEDTLS_SSL_ALPN */

    /*
     * Done
     */
    *olen = used;

    if (used > buf_len) {
        return PF_MBEDTLS_ERR_SSL_BUFFER_TOO_SMALL;
    }

    PF_MBEDTLS_SSL_DEBUG_BUF(4, "saved context", buf, used);

    return pf_mbedtls_ssl_session_reset_int(ssl, 0);
}

/*
 * Deserialize context, see mbedtls_ssl_context_save() for format.
 *
 * This internal version is wrapped by a public function that cleans up in
 * case of error.
 */
PF_MBEDTLS_CHECK_RETURN_CRITICAL
static int ssl_context_load(pf_mbedtls_ssl_context *ssl,
                            const unsigned char *buf,
                            size_t len)
{
    const unsigned char *p = buf;
    const unsigned char * const end = buf + len;
    size_t session_len;
    int ret = PF_MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
#if defined(PF_MBEDTLS_SSL_PROTO_TLS1_2)
    tls_prf_fn prf_func = NULL;
#endif

    /*
     * The context should have been freshly setup or reset.
     * Give the user an error in case of obvious misuse.
     * (Checking session is useful because it won't be NULL if we're
     * renegotiating, or if the user mistakenly loaded a session first.)
     */
    if (ssl->state != PF_MBEDTLS_SSL_HELLO_REQUEST ||
        ssl->session != NULL) {
        return PF_MBEDTLS_ERR_SSL_BAD_INPUT_DATA;
    }

    /*
     * We can't check that the config matches the initial one, but we can at
     * least check it matches the requirements for serializing.
     */
    if (
#if defined(PF_MBEDTLS_SSL_RENEGOTIATION)
        ssl->conf->disable_renegotiation != PF_MBEDTLS_SSL_RENEGOTIATION_DISABLED ||
#endif
        ssl->conf->transport != PF_MBEDTLS_SSL_TRANSPORT_DATAGRAM ||
        ssl->conf->max_tls_version < PF_MBEDTLS_SSL_VERSION_TLS1_2 ||
        ssl->conf->min_tls_version > PF_MBEDTLS_SSL_VERSION_TLS1_2
        ) {
        return PF_MBEDTLS_ERR_SSL_BAD_INPUT_DATA;
    }

    PF_MBEDTLS_SSL_DEBUG_BUF(4, "context to load", buf, len);

    /*
     * Check version identifier
     */
    if ((size_t) (end - p) < sizeof(ssl_serialized_context_header)) {
        return PF_MBEDTLS_ERR_SSL_BAD_INPUT_DATA;
    }

    if (memcmp(p, ssl_serialized_context_header,
               sizeof(ssl_serialized_context_header)) != 0) {
        return PF_MBEDTLS_ERR_SSL_VERSION_MISMATCH;
    }
    p += sizeof(ssl_serialized_context_header);

    /*
     * Session
     */
    if ((size_t) (end - p) < 4) {
        return PF_MBEDTLS_ERR_SSL_BAD_INPUT_DATA;
    }

    session_len = PF_MBEDTLS_GET_UINT32_BE(p, 0);
    p += 4;

    /* This has been allocated by ssl_handshake_init(), called by
     * by either mbedtls_ssl_session_reset_int() or mbedtls_ssl_setup(). */
    ssl->session = ssl->session_negotiate;
    ssl->session_in = ssl->session;
    ssl->session_out = ssl->session;
    ssl->session_negotiate = NULL;

    if ((size_t) (end - p) < session_len) {
        return PF_MBEDTLS_ERR_SSL_BAD_INPUT_DATA;
    }

    ret = ssl_session_load(ssl->session, 1, p, session_len);
    if (ret != 0) {
        pf_mbedtls_ssl_session_free(ssl->session);
        return ret;
    }

    p += session_len;

    /*
     * Transform
     */

    /* This has been allocated by ssl_handshake_init(), called by
     * by either mbedtls_ssl_session_reset_int() or mbedtls_ssl_setup(). */
#if defined(PF_MBEDTLS_SSL_PROTO_TLS1_2)
    ssl->transform = ssl->transform_negotiate;
    ssl->transform_in = ssl->transform;
    ssl->transform_out = ssl->transform;
    ssl->transform_negotiate = NULL;
#endif

#if defined(PF_MBEDTLS_SSL_PROTO_TLS1_2)
    prf_func = ssl_tls12prf_from_cs(ssl->session->ciphersuite);
    if (prf_func == NULL) {
        return PF_MBEDTLS_ERR_SSL_BAD_INPUT_DATA;
    }

    /* Read random bytes and populate structure */
    if ((size_t) (end - p) < sizeof(ssl->transform->randbytes)) {
        return PF_MBEDTLS_ERR_SSL_BAD_INPUT_DATA;
    }

    ret = ssl_tls12_populate_transform(ssl->transform,
                                       ssl->session->ciphersuite,
                                       ssl->session->master,
#if defined(PF_MBEDTLS_SSL_SOME_SUITES_USE_CBC_ETM)
                                       ssl->session->encrypt_then_mac,
#endif /* MBEDTLS_SSL_SOME_SUITES_USE_CBC_ETM */
                                       prf_func,
                                       p, /* currently pointing to randbytes */
                                       PF_MBEDTLS_SSL_VERSION_TLS1_2, /* (D)TLS 1.2 is forced */
                                       ssl->conf->endpoint,
                                       ssl);
    if (ret != 0) {
        return ret;
    }
#endif /* MBEDTLS_SSL_PROTO_TLS1_2 */
    p += sizeof(ssl->transform->randbytes);

#if defined(PF_MBEDTLS_SSL_DTLS_CONNECTION_ID)
    /* Read connection IDs and store them */
    if ((size_t) (end - p) < 1) {
        return PF_MBEDTLS_ERR_SSL_BAD_INPUT_DATA;
    }

    ssl->transform->in_cid_len = *p++;

    if ((size_t) (end - p) < ssl->transform->in_cid_len + 1u) {
        return PF_MBEDTLS_ERR_SSL_BAD_INPUT_DATA;
    }

    if (ssl->transform->in_cid_len > sizeof(ssl->transform->in_cid)) {
        return PF_MBEDTLS_ERR_SSL_BAD_INPUT_DATA;
    }

    memcpy(ssl->transform->in_cid, p, ssl->transform->in_cid_len);
    p += ssl->transform->in_cid_len;

    ssl->transform->out_cid_len = *p++;

    if ((size_t) (end - p) < ssl->transform->out_cid_len) {
        return PF_MBEDTLS_ERR_SSL_BAD_INPUT_DATA;
    }

    if (ssl->transform->out_cid_len > sizeof(ssl->transform->out_cid)) {
        return PF_MBEDTLS_ERR_SSL_BAD_INPUT_DATA;
    }

    memcpy(ssl->transform->out_cid, p, ssl->transform->out_cid_len);
    p += ssl->transform->out_cid_len;
#endif /* MBEDTLS_SSL_DTLS_CONNECTION_ID */

    /*
     * Saved fields from top-level ssl_context structure
     */
    if ((size_t) (end - p) < 4) {
        return PF_MBEDTLS_ERR_SSL_BAD_INPUT_DATA;
    }

    ssl->badmac_seen_or_in_hsfraglen = PF_MBEDTLS_GET_UINT32_BE(p, 0);
    p += 4;

#if defined(PF_MBEDTLS_SSL_DTLS_ANTI_REPLAY)
    if ((size_t) (end - p) < 16) {
        return PF_MBEDTLS_ERR_SSL_BAD_INPUT_DATA;
    }

    ssl->in_window_top = PF_MBEDTLS_GET_UINT64_BE(p, 0);
    p += 8;

    ssl->in_window = PF_MBEDTLS_GET_UINT64_BE(p, 0);
    p += 8;
#endif /* MBEDTLS_SSL_DTLS_ANTI_REPLAY */

#if defined(PF_MBEDTLS_SSL_PROTO_DTLS)
    if ((size_t) (end - p) < 1) {
        return PF_MBEDTLS_ERR_SSL_BAD_INPUT_DATA;
    }

    ssl->disable_datagram_packing = *p++;
#endif /* MBEDTLS_SSL_PROTO_DTLS */

    if ((size_t) (end - p) < sizeof(ssl->cur_out_ctr)) {
        return PF_MBEDTLS_ERR_SSL_BAD_INPUT_DATA;
    }
    memcpy(ssl->cur_out_ctr, p, sizeof(ssl->cur_out_ctr));
    p += sizeof(ssl->cur_out_ctr);

#if defined(PF_MBEDTLS_SSL_PROTO_DTLS)
    if ((size_t) (end - p) < 2) {
        return PF_MBEDTLS_ERR_SSL_BAD_INPUT_DATA;
    }

    ssl->mtu = PF_MBEDTLS_GET_UINT16_BE(p, 0);
    p += 2;
#endif /* MBEDTLS_SSL_PROTO_DTLS */

#if defined(PF_MBEDTLS_SSL_ALPN)
    {
        uint8_t alpn_len;
        const char **cur;

        if ((size_t) (end - p) < 1) {
            return PF_MBEDTLS_ERR_SSL_BAD_INPUT_DATA;
        }

        alpn_len = *p++;

        if (alpn_len != 0 && ssl->conf->alpn_list != NULL) {
            /* alpn_chosen should point to an item in the configured list */
            for (cur = ssl->conf->alpn_list; *cur != NULL; cur++) {
                if (strlen(*cur) == alpn_len &&
                    memcmp(p, *cur, alpn_len) == 0) {
                    ssl->alpn_chosen = *cur;
                    break;
                }
            }
        }

        /* can only happen on conf mismatch */
        if (alpn_len != 0 && ssl->alpn_chosen == NULL) {
            return PF_MBEDTLS_ERR_SSL_BAD_INPUT_DATA;
        }

        p += alpn_len;
    }
#endif /* MBEDTLS_SSL_ALPN */

    /*
     * Forced fields from top-level ssl_context structure
     *
     * Most of them already set to the correct value by mbedtls_ssl_init() and
     * mbedtls_ssl_reset(), so we only need to set the remaining ones.
     */
    pf_mbedtls_ssl_handshake_set_state(ssl, PF_MBEDTLS_SSL_HANDSHAKE_OVER);
    ssl->tls_version = PF_MBEDTLS_SSL_VERSION_TLS1_2;

    /* Adjust pointers for header fields of outgoing records to
     * the given transform, accounting for explicit IV and CID. */
    pf_mbedtls_ssl_update_out_pointers(ssl, ssl->transform);

#if defined(PF_MBEDTLS_SSL_PROTO_DTLS)
    ssl->in_epoch = 1;
#endif

    /* mbedtls_ssl_reset() leaves the handshake sub-structure allocated,
     * which we don't want - otherwise we'd end up freeing the wrong transform
     * by calling mbedtls_ssl_handshake_wrapup_free_hs_transform()
     * inappropriately. */
    if (ssl->handshake != NULL) {
        pf_mbedtls_ssl_handshake_free(ssl);
        pf_mbedtls_free(ssl->handshake);
        ssl->handshake = NULL;
    }

    /*
     * Done - should have consumed entire buffer
     */
    if (p != end) {
        return PF_MBEDTLS_ERR_SSL_BAD_INPUT_DATA;
    }

    return 0;
}

/*
 * Deserialize context: public wrapper for error cleaning
 */
int pf_mbedtls_ssl_context_load(pf_mbedtls_ssl_context *context,
                             const unsigned char *buf,
                             size_t len)
{
    int ret = ssl_context_load(context, buf, len);

    if (ret != 0) {
        pf_mbedtls_ssl_free(context);
    }

    return ret;
}
#endif /* MBEDTLS_SSL_CONTEXT_SERIALIZATION */

/*
 * Free an SSL context
 */
void pf_mbedtls_ssl_free(pf_mbedtls_ssl_context *ssl)
{
    if (ssl == NULL) {
        return;
    }

    PF_MBEDTLS_SSL_DEBUG_MSG(2, ("=> free"));

    if (ssl->out_buf != NULL) {
#if defined(PF_MBEDTLS_SSL_VARIABLE_BUFFER_LENGTH)
        size_t out_buf_len = ssl->out_buf_len;
#else
        size_t out_buf_len = PF_MBEDTLS_SSL_OUT_BUFFER_LEN;
#endif

        pf_mbedtls_zeroize_and_free(ssl->out_buf, out_buf_len);
        ssl->out_buf = NULL;
    }

    if (ssl->in_buf != NULL) {
#if defined(PF_MBEDTLS_SSL_VARIABLE_BUFFER_LENGTH)
        size_t in_buf_len = ssl->in_buf_len;
#else
        size_t in_buf_len = PF_MBEDTLS_SSL_IN_BUFFER_LEN;
#endif

        pf_mbedtls_zeroize_and_free(ssl->in_buf, in_buf_len);
        ssl->in_buf = NULL;
    }

    if (ssl->transform) {
        pf_mbedtls_ssl_transform_free(ssl->transform);
        pf_mbedtls_free(ssl->transform);
    }

    if (ssl->handshake) {
        pf_mbedtls_ssl_handshake_free(ssl);
        pf_mbedtls_free(ssl->handshake);

#if defined(PF_MBEDTLS_SSL_PROTO_TLS1_2)
        pf_mbedtls_ssl_transform_free(ssl->transform_negotiate);
        pf_mbedtls_free(ssl->transform_negotiate);
#endif

        pf_mbedtls_ssl_session_free(ssl->session_negotiate);
        pf_mbedtls_free(ssl->session_negotiate);
    }

#if defined(PF_MBEDTLS_SSL_PROTO_TLS1_3)
    pf_mbedtls_ssl_transform_free(ssl->transform_application);
    pf_mbedtls_free(ssl->transform_application);
#endif /* MBEDTLS_SSL_PROTO_TLS1_3 */

    if (ssl->session) {
        pf_mbedtls_ssl_session_free(ssl->session);
        pf_mbedtls_free(ssl->session);
    }

#if defined(PF_MBEDTLS_X509_CRT_PARSE_C)
    pf_mbedtls_ssl_free_hostname(ssl);
#endif

#if defined(PF_MBEDTLS_SSL_DTLS_HELLO_VERIFY) && defined(PF_MBEDTLS_SSL_SRV_C)
    pf_mbedtls_free(ssl->cli_id);
#endif

    PF_MBEDTLS_SSL_DEBUG_MSG(2, ("<= free"));

    /* Actually clear after last debug message */
    pf_mbedtls_platform_zeroize(ssl, sizeof(pf_mbedtls_ssl_context));
}

/*
 * Initialize mbedtls_ssl_config
 */
void pf_mbedtls_ssl_config_init(pf_mbedtls_ssl_config *conf)
{
    memset(conf, 0, sizeof(pf_mbedtls_ssl_config));
}

/* The selection should be the same as mbedtls_x509_crt_profile_default in
 * x509_crt.c, plus Montgomery curves for ECDHE. Here, the order matters:
 * curves with a lower resource usage come first.
 * See the documentation of mbedtls_ssl_conf_curves() for what we promise
 * about this list.
 */
static const uint16_t ssl_preset_default_groups[] = {
#if defined(PF_MBEDTLS_ECP_HAVE_CURVE25519)
    PF_MBEDTLS_SSL_IANA_TLS_GROUP_X25519,
#endif
#if defined(PF_MBEDTLS_ECP_HAVE_SECP256R1)
    PF_MBEDTLS_SSL_IANA_TLS_GROUP_SECP256R1,
#endif
#if defined(PF_MBEDTLS_ECP_HAVE_SECP384R1)
    PF_MBEDTLS_SSL_IANA_TLS_GROUP_SECP384R1,
#endif
#if defined(PF_MBEDTLS_ECP_HAVE_CURVE448)
    PF_MBEDTLS_SSL_IANA_TLS_GROUP_X448,
#endif
#if defined(PF_MBEDTLS_ECP_HAVE_SECP521R1)
    PF_MBEDTLS_SSL_IANA_TLS_GROUP_SECP521R1,
#endif
#if defined(PF_MBEDTLS_ECP_HAVE_BP256R1)
    PF_MBEDTLS_SSL_IANA_TLS_GROUP_BP256R1,
#endif
#if defined(PF_MBEDTLS_ECP_HAVE_BP384R1)
    PF_MBEDTLS_SSL_IANA_TLS_GROUP_BP384R1,
#endif
#if defined(PF_MBEDTLS_ECP_HAVE_BP512R1)
    PF_MBEDTLS_SSL_IANA_TLS_GROUP_BP512R1,
#endif
#if defined(PF_PSA_WANT_ALG_FFDH)
    PF_MBEDTLS_SSL_IANA_TLS_GROUP_FFDHE2048,
    PF_MBEDTLS_SSL_IANA_TLS_GROUP_FFDHE3072,
    PF_MBEDTLS_SSL_IANA_TLS_GROUP_FFDHE4096,
    PF_MBEDTLS_SSL_IANA_TLS_GROUP_FFDHE6144,
    PF_MBEDTLS_SSL_IANA_TLS_GROUP_FFDHE8192,
#endif
    PF_MBEDTLS_SSL_IANA_TLS_GROUP_NONE
};

static const int ssl_preset_suiteb_ciphersuites[] = {
    PF_MBEDTLS_TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
    PF_MBEDTLS_TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
    0
};

#if defined(PF_MBEDTLS_SSL_HANDSHAKE_WITH_CERT_ENABLED)

/* NOTICE:
 *   For ssl_preset_*_sig_algs and ssl_tls12_preset_*_sig_algs, the following
 *   rules SHOULD be upheld.
 *   - No duplicate entries.
 *   - But if there is a good reason, do not change the order of the algorithms.
 *   - ssl_tls12_preset* is for TLS 1.2 use only.
 *   - ssl_preset_* is for TLS 1.3 only or hybrid TLS 1.3/1.2 handshakes.
 */
static const uint16_t ssl_preset_default_sig_algs[] = {

#if defined(PF_MBEDTLS_KEY_EXCHANGE_ECDSA_CERT_REQ_ANY_ALLOWED_ENABLED) && \
    defined(PF_MBEDTLS_MD_CAN_SHA256) && \
    defined(PF_PSA_WANT_ECC_SECP_R1_256)
    PF_MBEDTLS_TLS1_3_SIG_ECDSA_SECP256R1_SHA256,
    // == MBEDTLS_SSL_TLS12_SIG_AND_HASH_ALG(MBEDTLS_SSL_SIG_ECDSA, MBEDTLS_SSL_HASH_SHA256)
#endif

#if defined(PF_MBEDTLS_KEY_EXCHANGE_ECDSA_CERT_REQ_ANY_ALLOWED_ENABLED) && \
    defined(PF_MBEDTLS_MD_CAN_SHA384) && \
    defined(PF_PSA_WANT_ECC_SECP_R1_384)
    PF_MBEDTLS_TLS1_3_SIG_ECDSA_SECP384R1_SHA384,
    // == MBEDTLS_SSL_TLS12_SIG_AND_HASH_ALG(MBEDTLS_SSL_SIG_ECDSA, MBEDTLS_SSL_HASH_SHA384)
#endif

#if defined(PF_MBEDTLS_KEY_EXCHANGE_ECDSA_CERT_REQ_ANY_ALLOWED_ENABLED) && \
    defined(PF_MBEDTLS_MD_CAN_SHA512) && \
    defined(PF_PSA_WANT_ECC_SECP_R1_521)
    PF_MBEDTLS_TLS1_3_SIG_ECDSA_SECP521R1_SHA512,
    // == MBEDTLS_SSL_TLS12_SIG_AND_HASH_ALG(MBEDTLS_SSL_SIG_ECDSA, MBEDTLS_SSL_HASH_SHA512)
#endif

#if defined(PF_MBEDTLS_X509_RSASSA_PSS_SUPPORT) && defined(PF_MBEDTLS_MD_CAN_SHA512)
    PF_MBEDTLS_TLS1_3_SIG_RSA_PSS_RSAE_SHA512,
#endif

#if defined(PF_MBEDTLS_X509_RSASSA_PSS_SUPPORT) && defined(PF_MBEDTLS_MD_CAN_SHA384)
    PF_MBEDTLS_TLS1_3_SIG_RSA_PSS_RSAE_SHA384,
#endif

#if defined(PF_MBEDTLS_X509_RSASSA_PSS_SUPPORT) && defined(PF_MBEDTLS_MD_CAN_SHA256)
    PF_MBEDTLS_TLS1_3_SIG_RSA_PSS_RSAE_SHA256,
#endif

#if defined(PF_MBEDTLS_RSA_C) && defined(PF_MBEDTLS_MD_CAN_SHA512)
    PF_MBEDTLS_TLS1_3_SIG_RSA_PKCS1_SHA512,
#endif /* MBEDTLS_RSA_C && MBEDTLS_MD_CAN_SHA512 */

#if defined(PF_MBEDTLS_RSA_C) && defined(PF_MBEDTLS_MD_CAN_SHA384)
    PF_MBEDTLS_TLS1_3_SIG_RSA_PKCS1_SHA384,
#endif /* MBEDTLS_RSA_C && MBEDTLS_MD_CAN_SHA384 */

#if defined(PF_MBEDTLS_RSA_C) && defined(PF_MBEDTLS_MD_CAN_SHA256)
    PF_MBEDTLS_TLS1_3_SIG_RSA_PKCS1_SHA256,
#endif /* MBEDTLS_RSA_C && MBEDTLS_MD_CAN_SHA256 */

    PF_MBEDTLS_TLS_SIG_NONE
};

/* NOTICE: see above */
#if defined(PF_MBEDTLS_SSL_PROTO_TLS1_2)
static const uint16_t ssl_tls12_preset_default_sig_algs[] = {

#if defined(PF_MBEDTLS_MD_CAN_SHA512)
#if defined(PF_MBEDTLS_KEY_EXCHANGE_ECDSA_CERT_REQ_ALLOWED_ENABLED)
    PF_MBEDTLS_SSL_TLS12_SIG_AND_HASH_ALG(PF_MBEDTLS_SSL_SIG_ECDSA, PF_MBEDTLS_SSL_HASH_SHA512),
#endif
#if defined(PF_MBEDTLS_X509_RSASSA_PSS_SUPPORT)
    PF_MBEDTLS_TLS1_3_SIG_RSA_PSS_RSAE_SHA512,
#endif
#if defined(PF_MBEDTLS_RSA_C)
    PF_MBEDTLS_SSL_TLS12_SIG_AND_HASH_ALG(PF_MBEDTLS_SSL_SIG_RSA, PF_MBEDTLS_SSL_HASH_SHA512),
#endif
#endif /* MBEDTLS_MD_CAN_SHA512 */

#if defined(PF_MBEDTLS_MD_CAN_SHA384)
#if defined(PF_MBEDTLS_KEY_EXCHANGE_ECDSA_CERT_REQ_ALLOWED_ENABLED)
    PF_MBEDTLS_SSL_TLS12_SIG_AND_HASH_ALG(PF_MBEDTLS_SSL_SIG_ECDSA, PF_MBEDTLS_SSL_HASH_SHA384),
#endif
#if defined(PF_MBEDTLS_X509_RSASSA_PSS_SUPPORT)
    PF_MBEDTLS_TLS1_3_SIG_RSA_PSS_RSAE_SHA384,
#endif
#if defined(PF_MBEDTLS_RSA_C)
    PF_MBEDTLS_SSL_TLS12_SIG_AND_HASH_ALG(PF_MBEDTLS_SSL_SIG_RSA, PF_MBEDTLS_SSL_HASH_SHA384),
#endif
#endif /* MBEDTLS_MD_CAN_SHA384 */

#if defined(PF_MBEDTLS_MD_CAN_SHA256)
#if defined(PF_MBEDTLS_KEY_EXCHANGE_ECDSA_CERT_REQ_ALLOWED_ENABLED)
    PF_MBEDTLS_SSL_TLS12_SIG_AND_HASH_ALG(PF_MBEDTLS_SSL_SIG_ECDSA, PF_MBEDTLS_SSL_HASH_SHA256),
#endif
#if defined(PF_MBEDTLS_X509_RSASSA_PSS_SUPPORT)
    PF_MBEDTLS_TLS1_3_SIG_RSA_PSS_RSAE_SHA256,
#endif
#if defined(PF_MBEDTLS_RSA_C)
    PF_MBEDTLS_SSL_TLS12_SIG_AND_HASH_ALG(PF_MBEDTLS_SSL_SIG_RSA, PF_MBEDTLS_SSL_HASH_SHA256),
#endif
#endif /* MBEDTLS_MD_CAN_SHA256 */

    PF_MBEDTLS_TLS_SIG_NONE
};
#endif /* MBEDTLS_SSL_PROTO_TLS1_2 */

/* NOTICE: see above */
static const uint16_t ssl_preset_suiteb_sig_algs[] = {

#if defined(PF_MBEDTLS_KEY_EXCHANGE_ECDSA_CERT_REQ_ANY_ALLOWED_ENABLED) && \
    defined(PF_MBEDTLS_MD_CAN_SHA256) && \
    defined(PF_MBEDTLS_ECP_HAVE_SECP256R1)
    PF_MBEDTLS_TLS1_3_SIG_ECDSA_SECP256R1_SHA256,
    // == MBEDTLS_SSL_TLS12_SIG_AND_HASH_ALG(MBEDTLS_SSL_SIG_ECDSA, MBEDTLS_SSL_HASH_SHA256)
#endif

#if defined(PF_MBEDTLS_KEY_EXCHANGE_ECDSA_CERT_REQ_ANY_ALLOWED_ENABLED) && \
    defined(PF_MBEDTLS_MD_CAN_SHA384) && \
    defined(PF_MBEDTLS_ECP_HAVE_SECP384R1)
    PF_MBEDTLS_TLS1_3_SIG_ECDSA_SECP384R1_SHA384,
    // == MBEDTLS_SSL_TLS12_SIG_AND_HASH_ALG(MBEDTLS_SSL_SIG_ECDSA, MBEDTLS_SSL_HASH_SHA384)
#endif

    PF_MBEDTLS_TLS_SIG_NONE
};

/* NOTICE: see above */
#if defined(PF_MBEDTLS_SSL_PROTO_TLS1_2)
static const uint16_t ssl_tls12_preset_suiteb_sig_algs[] = {

#if defined(PF_MBEDTLS_MD_CAN_SHA256)
#if defined(PF_MBEDTLS_KEY_EXCHANGE_ECDSA_CERT_REQ_ALLOWED_ENABLED)
    PF_MBEDTLS_SSL_TLS12_SIG_AND_HASH_ALG(PF_MBEDTLS_SSL_SIG_ECDSA, PF_MBEDTLS_SSL_HASH_SHA256),
#endif
#endif /* MBEDTLS_MD_CAN_SHA256 */

#if defined(PF_MBEDTLS_MD_CAN_SHA384)
#if defined(PF_MBEDTLS_KEY_EXCHANGE_ECDSA_CERT_REQ_ALLOWED_ENABLED)
    PF_MBEDTLS_SSL_TLS12_SIG_AND_HASH_ALG(PF_MBEDTLS_SSL_SIG_ECDSA, PF_MBEDTLS_SSL_HASH_SHA384),
#endif
#endif /* MBEDTLS_MD_CAN_SHA384 */

    PF_MBEDTLS_TLS_SIG_NONE
};
#endif /* MBEDTLS_SSL_PROTO_TLS1_2 */

#endif /* MBEDTLS_SSL_HANDSHAKE_WITH_CERT_ENABLED */

static const uint16_t ssl_preset_suiteb_groups[] = {
#if defined(PF_MBEDTLS_ECP_HAVE_SECP256R1)
    PF_MBEDTLS_SSL_IANA_TLS_GROUP_SECP256R1,
#endif
#if defined(PF_MBEDTLS_ECP_HAVE_SECP384R1)
    PF_MBEDTLS_SSL_IANA_TLS_GROUP_SECP384R1,
#endif
    PF_MBEDTLS_SSL_IANA_TLS_GROUP_NONE
};

#if defined(PF_MBEDTLS_DEBUG_C) && defined(PF_MBEDTLS_SSL_HANDSHAKE_WITH_CERT_ENABLED)
/* Function for checking `ssl_preset_*_sig_algs` and `ssl_tls12_preset_*_sig_algs`
 * to make sure there are no duplicated signature algorithm entries. */
PF_MBEDTLS_CHECK_RETURN_CRITICAL
static int ssl_check_no_sig_alg_duplication(const uint16_t *sig_algs)
{
    size_t i, j;
    int ret = 0;

    for (i = 0; sig_algs[i] != PF_MBEDTLS_TLS_SIG_NONE; i++) {
        for (j = 0; j < i; j++) {
            if (sig_algs[i] != sig_algs[j]) {
                continue;
            }
            pf_mbedtls_printf(" entry(%04x,%" PF_MBEDTLS_PRINTF_SIZET
                           ") is duplicated at %" PF_MBEDTLS_PRINTF_SIZET "\n",
                           sig_algs[i], j, i);
            ret = -1;
        }
    }
    return ret;
}

#endif /* MBEDTLS_DEBUG_C && MBEDTLS_SSL_HANDSHAKE_WITH_CERT_ENABLED */

/*
 * Load default in mbedtls_ssl_config
 */
int pf_mbedtls_ssl_config_defaults(pf_mbedtls_ssl_config *conf,
                                int endpoint, int transport, int preset)
{
#if defined(PF_MBEDTLS_DHM_C) && defined(PF_MBEDTLS_SSL_SRV_C)
    int ret = PF_MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
#endif

#if defined(PF_MBEDTLS_DEBUG_C) && defined(PF_MBEDTLS_SSL_HANDSHAKE_WITH_CERT_ENABLED)
    if (ssl_check_no_sig_alg_duplication(ssl_preset_suiteb_sig_algs)) {
        pf_mbedtls_printf("ssl_preset_suiteb_sig_algs has duplicated entries\n");
        return PF_MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    }

    if (ssl_check_no_sig_alg_duplication(ssl_preset_default_sig_algs)) {
        pf_mbedtls_printf("ssl_preset_default_sig_algs has duplicated entries\n");
        return PF_MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    }

#if defined(PF_MBEDTLS_SSL_PROTO_TLS1_2)
    if (ssl_check_no_sig_alg_duplication(ssl_tls12_preset_suiteb_sig_algs)) {
        pf_mbedtls_printf("ssl_tls12_preset_suiteb_sig_algs has duplicated entries\n");
        return PF_MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    }

    if (ssl_check_no_sig_alg_duplication(ssl_tls12_preset_default_sig_algs)) {
        pf_mbedtls_printf("ssl_tls12_preset_default_sig_algs has duplicated entries\n");
        return PF_MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    }
#endif /* MBEDTLS_SSL_PROTO_TLS1_2 */
#endif /* MBEDTLS_DEBUG_C && MBEDTLS_SSL_HANDSHAKE_WITH_CERT_ENABLED */

    /* Use the functions here so that they are covered in tests,
     * but otherwise access member directly for efficiency */
    pf_mbedtls_ssl_conf_endpoint(conf, endpoint);
    pf_mbedtls_ssl_conf_transport(conf, transport);

    /*
     * Things that are common to all presets
     */
#if defined(PF_MBEDTLS_SSL_CLI_C)
    if (endpoint == PF_MBEDTLS_SSL_IS_CLIENT) {
        conf->authmode = PF_MBEDTLS_SSL_VERIFY_REQUIRED;
#if defined(PF_MBEDTLS_SSL_SESSION_TICKETS)
        pf_mbedtls_ssl_conf_session_tickets(conf, PF_MBEDTLS_SSL_SESSION_TICKETS_ENABLED);
#if defined(PF_MBEDTLS_SSL_PROTO_TLS1_3)
        /* Contrary to TLS 1.2 tickets, TLS 1.3 NewSessionTicket message
         * handling is disabled by default in Mbed TLS 3.6.x for backward
         * compatibility with client applications developed using Mbed TLS 3.5
         * or earlier with the default configuration.
         *
         * Up to Mbed TLS 3.5, in the default configuration TLS 1.3 was
         * disabled, and a Mbed TLS client with the default configuration would
         * establish a TLS 1.2 connection with a TLS 1.2 and TLS 1.3 capable
         * server.
         *
         * Starting with Mbed TLS 3.6.0, TLS 1.3 is enabled by default, and thus
         * an Mbed TLS client with the default configuration establishes a
         * TLS 1.3 connection with a TLS 1.2 and TLS 1.3 capable server. If
         * following the handshake the TLS 1.3 server sends NewSessionTicket
         * messages and the Mbed TLS client processes them, this results in
         * Mbed TLS high level APIs (mbedtls_ssl_read(),
         * mbedtls_ssl_handshake(), ...) to eventually return an
         * #MBEDTLS_ERR_SSL_RECEIVED_NEW_SESSION_TICKET non fatal error code
         * (see the documentation of mbedtls_ssl_read() for more information on
         * that error code). Applications unaware of that TLS 1.3 specific non
         * fatal error code are then failing.
         */
        pf_mbedtls_ssl_conf_tls13_enable_signal_new_session_tickets(
            conf, PF_MBEDTLS_SSL_TLS1_3_SIGNAL_NEW_SESSION_TICKETS_DISABLED);
#endif
#endif
    }
#endif

#if defined(PF_MBEDTLS_SSL_ENCRYPT_THEN_MAC)
    conf->encrypt_then_mac = PF_MBEDTLS_SSL_ETM_ENABLED;
#endif

#if defined(PF_MBEDTLS_SSL_EXTENDED_MASTER_SECRET)
    conf->extended_ms = PF_MBEDTLS_SSL_EXTENDED_MS_ENABLED;
#endif

#if defined(PF_MBEDTLS_SSL_DTLS_HELLO_VERIFY) && defined(PF_MBEDTLS_SSL_SRV_C)
    conf->f_cookie_write = ssl_cookie_write_dummy;
    conf->f_cookie_check = ssl_cookie_check_dummy;
#endif

#if defined(PF_MBEDTLS_SSL_DTLS_ANTI_REPLAY)
    conf->anti_replay = PF_MBEDTLS_SSL_ANTI_REPLAY_ENABLED;
#endif

#if defined(PF_MBEDTLS_SSL_SRV_C)
    conf->cert_req_ca_list = PF_MBEDTLS_SSL_CERT_REQ_CA_LIST_ENABLED;
    conf->respect_cli_pref = PF_MBEDTLS_SSL_SRV_CIPHERSUITE_ORDER_SERVER;
#endif

#if defined(PF_MBEDTLS_SSL_PROTO_DTLS)
    conf->hs_timeout_min = PF_MBEDTLS_SSL_DTLS_TIMEOUT_DFL_MIN;
    conf->hs_timeout_max = PF_MBEDTLS_SSL_DTLS_TIMEOUT_DFL_MAX;
#endif

#if defined(PF_MBEDTLS_SSL_RENEGOTIATION)
    conf->renego_max_records = PF_MBEDTLS_SSL_RENEGO_MAX_RECORDS_DEFAULT;
    memset(conf->renego_period,     0x00, 2);
    memset(conf->renego_period + 2, 0xFF, 6);
#endif

#if defined(PF_MBEDTLS_DHM_C) && defined(PF_MBEDTLS_SSL_SRV_C)
    if (endpoint == PF_MBEDTLS_SSL_IS_SERVER) {
        const unsigned char dhm_p[] =
            PF_MBEDTLS_DHM_RFC3526_MODP_2048_P_BIN;
        const unsigned char dhm_g[] =
            PF_MBEDTLS_DHM_RFC3526_MODP_2048_G_BIN;

        if ((ret = pf_mbedtls_ssl_conf_dh_param_bin(conf,
                                                 dhm_p, sizeof(dhm_p),
                                                 dhm_g, sizeof(dhm_g))) != 0) {
            return ret;
        }
    }
#endif

#if defined(PF_MBEDTLS_SSL_PROTO_TLS1_3)

#if defined(PF_MBEDTLS_SSL_EARLY_DATA)
    pf_mbedtls_ssl_conf_early_data(conf, PF_MBEDTLS_SSL_EARLY_DATA_DISABLED);
#if defined(PF_MBEDTLS_SSL_SRV_C)
    pf_mbedtls_ssl_conf_max_early_data_size(conf, PF_MBEDTLS_SSL_MAX_EARLY_DATA_SIZE);
#endif
#endif /* MBEDTLS_SSL_EARLY_DATA */

#if defined(PF_MBEDTLS_SSL_SRV_C) && defined(PF_MBEDTLS_SSL_SESSION_TICKETS)
    pf_mbedtls_ssl_conf_new_session_tickets(
        conf, PF_MBEDTLS_SSL_TLS1_3_DEFAULT_NEW_SESSION_TICKETS);
#endif
    /*
     * Allow all TLS 1.3 key exchange modes by default.
     */
    conf->tls13_kex_modes = PF_MBEDTLS_SSL_TLS1_3_KEY_EXCHANGE_MODE_ALL;
#endif /* MBEDTLS_SSL_PROTO_TLS1_3 */

    if (transport == PF_MBEDTLS_SSL_TRANSPORT_DATAGRAM) {
#if defined(PF_MBEDTLS_SSL_PROTO_TLS1_2)
        conf->min_tls_version = PF_MBEDTLS_SSL_VERSION_TLS1_2;
        conf->max_tls_version = PF_MBEDTLS_SSL_VERSION_TLS1_2;
#else
        return PF_MBEDTLS_ERR_SSL_FEATURE_UNAVAILABLE;
#endif
    } else {
#if defined(PF_MBEDTLS_SSL_PROTO_TLS1_2) && defined(PF_MBEDTLS_SSL_PROTO_TLS1_3)
        conf->min_tls_version = PF_MBEDTLS_SSL_VERSION_TLS1_2;
        conf->max_tls_version = PF_MBEDTLS_SSL_VERSION_TLS1_3;
#elif defined(PF_MBEDTLS_SSL_PROTO_TLS1_3)
        conf->min_tls_version = PF_MBEDTLS_SSL_VERSION_TLS1_3;
        conf->max_tls_version = PF_MBEDTLS_SSL_VERSION_TLS1_3;
#elif defined(PF_MBEDTLS_SSL_PROTO_TLS1_2)
        conf->min_tls_version = PF_MBEDTLS_SSL_VERSION_TLS1_2;
        conf->max_tls_version = PF_MBEDTLS_SSL_VERSION_TLS1_2;
#else
        return PF_MBEDTLS_ERR_SSL_FEATURE_UNAVAILABLE;
#endif
    }

    /*
     * Preset-specific defaults
     */
    switch (preset) {
        /*
         * NSA Suite B
         */
        case PF_MBEDTLS_SSL_PRESET_SUITEB:

            conf->ciphersuite_list = ssl_preset_suiteb_ciphersuites;

#if defined(PF_MBEDTLS_X509_CRT_PARSE_C)
            conf->cert_profile = &pf_mbedtls_x509_crt_profile_suiteb;
#endif

#if defined(PF_MBEDTLS_SSL_HANDSHAKE_WITH_CERT_ENABLED)
#if defined(PF_MBEDTLS_SSL_PROTO_TLS1_2)
            if (pf_mbedtls_ssl_conf_is_tls12_only(conf)) {
                conf->sig_algs = ssl_tls12_preset_suiteb_sig_algs;
            } else
#endif /* MBEDTLS_SSL_PROTO_TLS1_2 */
            conf->sig_algs = ssl_preset_suiteb_sig_algs;
#endif /* MBEDTLS_SSL_HANDSHAKE_WITH_CERT_ENABLED */

#if defined(PF_MBEDTLS_ECP_C) && !defined(PF_MBEDTLS_DEPRECATED_REMOVED)
            conf->curve_list = NULL;
#endif
            conf->group_list = ssl_preset_suiteb_groups;
            break;

        /*
         * Default
         */
        default:

            conf->ciphersuite_list = pf_mbedtls_ssl_list_ciphersuites();

#if defined(PF_MBEDTLS_X509_CRT_PARSE_C)
            conf->cert_profile = &pf_mbedtls_x509_crt_profile_default;
#endif

#if defined(PF_MBEDTLS_SSL_HANDSHAKE_WITH_CERT_ENABLED)
#if defined(PF_MBEDTLS_SSL_PROTO_TLS1_2)
            if (pf_mbedtls_ssl_conf_is_tls12_only(conf)) {
                conf->sig_algs = ssl_tls12_preset_default_sig_algs;
            } else
#endif /* MBEDTLS_SSL_PROTO_TLS1_2 */
            conf->sig_algs = ssl_preset_default_sig_algs;
#endif /* MBEDTLS_SSL_HANDSHAKE_WITH_CERT_ENABLED */

#if defined(PF_MBEDTLS_ECP_C) && !defined(PF_MBEDTLS_DEPRECATED_REMOVED)
            conf->curve_list = NULL;
#endif
            conf->group_list = ssl_preset_default_groups;

#if defined(PF_MBEDTLS_DHM_C) && defined(PF_MBEDTLS_SSL_CLI_C)
            conf->dhm_min_bitlen = 1024;
#endif
    }

    return 0;
}

/*
 * Free mbedtls_ssl_config
 */
void pf_mbedtls_ssl_config_free(pf_mbedtls_ssl_config *conf)
{
    if (conf == NULL) {
        return;
    }

#if defined(PF_MBEDTLS_DHM_C)
    pf_mbedtls_mpi_free(&conf->dhm_P);
    pf_mbedtls_mpi_free(&conf->dhm_G);
#endif

#if defined(PF_MBEDTLS_SSL_HANDSHAKE_WITH_PSK_ENABLED)
#if defined(PF_MBEDTLS_USE_PSA_CRYPTO)
    if (!pf_mbedtls_svc_key_id_is_null(conf->psk_opaque)) {
        conf->psk_opaque = PF_MBEDTLS_SVC_KEY_ID_INIT;
    }
#endif /* MBEDTLS_USE_PSA_CRYPTO */
    if (conf->psk != NULL) {
        pf_mbedtls_zeroize_and_free(conf->psk, conf->psk_len);
        conf->psk = NULL;
        conf->psk_len = 0;
    }

    if (conf->psk_identity != NULL) {
        pf_mbedtls_zeroize_and_free(conf->psk_identity, conf->psk_identity_len);
        conf->psk_identity = NULL;
        conf->psk_identity_len = 0;
    }
#endif /* MBEDTLS_SSL_HANDSHAKE_WITH_PSK_ENABLED */

#if defined(PF_MBEDTLS_X509_CRT_PARSE_C)
    ssl_key_cert_free(conf->key_cert);
#endif

    pf_mbedtls_platform_zeroize(conf, sizeof(pf_mbedtls_ssl_config));
}

#if defined(PF_MBEDTLS_PK_C) && \
    (defined(PF_MBEDTLS_RSA_C) || defined(PF_MBEDTLS_KEY_EXCHANGE_ECDSA_CERT_REQ_ANY_ALLOWED_ENABLED))
/*
 * Convert between MBEDTLS_PK_XXX and SSL_SIG_XXX
 */
unsigned char pf_mbedtls_ssl_sig_from_pk(pf_mbedtls_pk_context *pk)
{
#if defined(PF_MBEDTLS_RSA_C)
    if (pf_mbedtls_pk_can_do(pk, PF_MBEDTLS_PK_RSA)) {
        return PF_MBEDTLS_SSL_SIG_RSA;
    }
#endif
#if defined(PF_MBEDTLS_KEY_EXCHANGE_ECDSA_CERT_REQ_ANY_ALLOWED_ENABLED)
    if (pf_mbedtls_pk_can_do(pk, PF_MBEDTLS_PK_ECDSA)) {
        return PF_MBEDTLS_SSL_SIG_ECDSA;
    }
#endif
    return PF_MBEDTLS_SSL_SIG_ANON;
}

unsigned char pf_mbedtls_ssl_sig_from_pk_alg(pf_mbedtls_pk_type_t type)
{
    switch (type) {
        case PF_MBEDTLS_PK_RSA:
            return PF_MBEDTLS_SSL_SIG_RSA;
        case PF_MBEDTLS_PK_ECDSA:
        case PF_MBEDTLS_PK_ECKEY:
            return PF_MBEDTLS_SSL_SIG_ECDSA;
        default:
            return PF_MBEDTLS_SSL_SIG_ANON;
    }
}

pf_mbedtls_pk_type_t pf_mbedtls_ssl_pk_alg_from_sig(unsigned char sig)
{
    switch (sig) {
#if defined(PF_MBEDTLS_RSA_C)
        case PF_MBEDTLS_SSL_SIG_RSA:
            return PF_MBEDTLS_PK_RSA;
#endif
#if defined(PF_MBEDTLS_KEY_EXCHANGE_ECDSA_CERT_REQ_ANY_ALLOWED_ENABLED)
        case PF_MBEDTLS_SSL_SIG_ECDSA:
            return PF_MBEDTLS_PK_ECDSA;
#endif
        default:
            return PF_MBEDTLS_PK_NONE;
    }
}
#endif /* MBEDTLS_PK_C &&
          ( MBEDTLS_RSA_C || MBEDTLS_KEY_EXCHANGE_ECDSA_CERT_REQ_ANY_ALLOWED_ENABLED ) */

/*
 * Convert from MBEDTLS_SSL_HASH_XXX to MBEDTLS_MD_XXX
 */
pf_mbedtls_md_type_t pf_mbedtls_ssl_md_alg_from_hash(unsigned char hash)
{
    switch (hash) {
#if defined(PF_MBEDTLS_MD_CAN_MD5)
        case PF_MBEDTLS_SSL_HASH_MD5:
            return PF_MBEDTLS_MD_MD5;
#endif
#if defined(PF_MBEDTLS_MD_CAN_SHA1)
        case PF_MBEDTLS_SSL_HASH_SHA1:
            return PF_MBEDTLS_MD_SHA1;
#endif
#if defined(PF_MBEDTLS_MD_CAN_SHA224)
        case PF_MBEDTLS_SSL_HASH_SHA224:
            return PF_MBEDTLS_MD_SHA224;
#endif
#if defined(PF_MBEDTLS_MD_CAN_SHA256)
        case PF_MBEDTLS_SSL_HASH_SHA256:
            return PF_MBEDTLS_MD_SHA256;
#endif
#if defined(PF_MBEDTLS_MD_CAN_SHA384)
        case PF_MBEDTLS_SSL_HASH_SHA384:
            return PF_MBEDTLS_MD_SHA384;
#endif
#if defined(PF_MBEDTLS_MD_CAN_SHA512)
        case PF_MBEDTLS_SSL_HASH_SHA512:
            return PF_MBEDTLS_MD_SHA512;
#endif
        default:
            return PF_MBEDTLS_MD_NONE;
    }
}

/*
 * Convert from MBEDTLS_MD_XXX to MBEDTLS_SSL_HASH_XXX
 */
unsigned char pf_mbedtls_ssl_hash_from_md_alg(int md)
{
    switch (md) {
#if defined(PF_MBEDTLS_MD_CAN_MD5)
        case PF_MBEDTLS_MD_MD5:
            return PF_MBEDTLS_SSL_HASH_MD5;
#endif
#if defined(PF_MBEDTLS_MD_CAN_SHA1)
        case PF_MBEDTLS_MD_SHA1:
            return PF_MBEDTLS_SSL_HASH_SHA1;
#endif
#if defined(PF_MBEDTLS_MD_CAN_SHA224)
        case PF_MBEDTLS_MD_SHA224:
            return PF_MBEDTLS_SSL_HASH_SHA224;
#endif
#if defined(PF_MBEDTLS_MD_CAN_SHA256)
        case PF_MBEDTLS_MD_SHA256:
            return PF_MBEDTLS_SSL_HASH_SHA256;
#endif
#if defined(PF_MBEDTLS_MD_CAN_SHA384)
        case PF_MBEDTLS_MD_SHA384:
            return PF_MBEDTLS_SSL_HASH_SHA384;
#endif
#if defined(PF_MBEDTLS_MD_CAN_SHA512)
        case PF_MBEDTLS_MD_SHA512:
            return PF_MBEDTLS_SSL_HASH_SHA512;
#endif
        default:
            return PF_MBEDTLS_SSL_HASH_NONE;
    }
}

/*
 * Check if a curve proposed by the peer is in our list.
 * Return 0 if we're willing to use it, -1 otherwise.
 */
int pf_mbedtls_ssl_check_curve_tls_id(const pf_mbedtls_ssl_context *ssl, uint16_t tls_id)
{
    const uint16_t *group_list = pf_mbedtls_ssl_get_groups(ssl);

    if (group_list == NULL) {
        return -1;
    }

    for (; *group_list != 0; group_list++) {
        if (*group_list == tls_id) {
            return 0;
        }
    }

    return -1;
}

#if defined(PF_MBEDTLS_PK_HAVE_ECC_KEYS)
/*
 * Same as mbedtls_ssl_check_curve_tls_id() but with a mbedtls_ecp_group_id.
 */
int pf_mbedtls_ssl_check_curve(const pf_mbedtls_ssl_context *ssl, pf_mbedtls_ecp_group_id grp_id)
{
    uint16_t tls_id = pf_mbedtls_ssl_get_tls_id_from_ecp_group_id(grp_id);

    if (tls_id == 0) {
        return -1;
    }

    return pf_mbedtls_ssl_check_curve_tls_id(ssl, tls_id);
}
#endif /* MBEDTLS_PK_HAVE_ECC_KEYS */

static const struct {
    uint16_t tls_id;
    pf_mbedtls_ecp_group_id ecp_group_id;
    pf_psa_ecc_family_t pf_psa_family;
    uint16_t bits;
} tls_id_match_table[] =
{
#if defined(PF_MBEDTLS_ECP_HAVE_SECP521R1)
    { 25, PF_MBEDTLS_ECP_DP_SECP521R1, PF_PSA_ECC_FAMILY_SECP_R1, 521 },
#endif
#if defined(PF_MBEDTLS_ECP_HAVE_BP512R1)
    { 28, PF_MBEDTLS_ECP_DP_BP512R1, PF_PSA_ECC_FAMILY_BRAINPOOL_P_R1, 512 },
#endif
#if defined(PF_MBEDTLS_ECP_HAVE_SECP384R1)
    { 24, PF_MBEDTLS_ECP_DP_SECP384R1, PF_PSA_ECC_FAMILY_SECP_R1, 384 },
#endif
#if defined(PF_MBEDTLS_ECP_HAVE_BP384R1)
    { 27, PF_MBEDTLS_ECP_DP_BP384R1, PF_PSA_ECC_FAMILY_BRAINPOOL_P_R1, 384 },
#endif
#if defined(PF_MBEDTLS_ECP_HAVE_SECP256R1)
    { 23, PF_MBEDTLS_ECP_DP_SECP256R1, PF_PSA_ECC_FAMILY_SECP_R1, 256 },
#endif
#if defined(PF_MBEDTLS_ECP_HAVE_SECP256K1)
    { 22, PF_MBEDTLS_ECP_DP_SECP256K1, PF_PSA_ECC_FAMILY_SECP_K1, 256 },
#endif
#if defined(PF_MBEDTLS_ECP_HAVE_BP256R1)
    { 26, PF_MBEDTLS_ECP_DP_BP256R1, PF_PSA_ECC_FAMILY_BRAINPOOL_P_R1, 256 },
#endif
#if defined(PF_MBEDTLS_ECP_HAVE_SECP224R1)
    { 21, PF_MBEDTLS_ECP_DP_SECP224R1, PF_PSA_ECC_FAMILY_SECP_R1, 224 },
#endif
#if defined(PF_MBEDTLS_ECP_HAVE_SECP224K1)
    { 20, PF_MBEDTLS_ECP_DP_SECP224K1, PF_PSA_ECC_FAMILY_SECP_K1, 224 },
#endif
#if defined(PF_MBEDTLS_ECP_HAVE_SECP192R1)
    { 19, PF_MBEDTLS_ECP_DP_SECP192R1, PF_PSA_ECC_FAMILY_SECP_R1, 192 },
#endif
#if defined(PF_MBEDTLS_ECP_HAVE_SECP192K1)
    { 18, PF_MBEDTLS_ECP_DP_SECP192K1, PF_PSA_ECC_FAMILY_SECP_K1, 192 },
#endif
#if defined(PF_MBEDTLS_ECP_HAVE_CURVE25519)
    { 29, PF_MBEDTLS_ECP_DP_CURVE25519, PF_PSA_ECC_FAMILY_MONTGOMERY, 255 },
#endif
#if defined(PF_MBEDTLS_ECP_HAVE_CURVE448)
    { 30, PF_MBEDTLS_ECP_DP_CURVE448, PF_PSA_ECC_FAMILY_MONTGOMERY, 448 },
#endif
    { 0, PF_MBEDTLS_ECP_DP_NONE, 0, 0 },
};

int pf_mbedtls_ssl_get_psa_curve_info_from_tls_id(uint16_t tls_id,
                                               pf_psa_key_type_t *type,
                                               size_t *bits)
{
    for (int i = 0; tls_id_match_table[i].tls_id != 0; i++) {
        if (tls_id_match_table[i].tls_id == tls_id) {
            if (type != NULL) {
                *type = PF_PSA_KEY_TYPE_ECC_KEY_PAIR(tls_id_match_table[i].pf_psa_family);
            }
            if (bits != NULL) {
                *bits = tls_id_match_table[i].bits;
            }
            return PF_PSA_SUCCESS;
        }
    }

    return PF_PSA_ERROR_NOT_SUPPORTED;
}

pf_mbedtls_ecp_group_id pf_mbedtls_ssl_get_ecp_group_id_from_tls_id(uint16_t tls_id)
{
    for (int i = 0; tls_id_match_table[i].tls_id != 0; i++) {
        if (tls_id_match_table[i].tls_id == tls_id) {
            return tls_id_match_table[i].ecp_group_id;
        }
    }

    return PF_MBEDTLS_ECP_DP_NONE;
}

uint16_t pf_mbedtls_ssl_get_tls_id_from_ecp_group_id(pf_mbedtls_ecp_group_id grp_id)
{
    for (int i = 0; tls_id_match_table[i].ecp_group_id != PF_MBEDTLS_ECP_DP_NONE;
         i++) {
        if (tls_id_match_table[i].ecp_group_id == grp_id) {
            return tls_id_match_table[i].tls_id;
        }
    }

    return 0;
}

#if defined(PF_MBEDTLS_DEBUG_C)
static const struct {
    uint16_t tls_id;
    const char *name;
} tls_id_curve_name_table[] =
{
    { PF_MBEDTLS_SSL_IANA_TLS_GROUP_SECP521R1, "secp521r1" },
    { PF_MBEDTLS_SSL_IANA_TLS_GROUP_BP512R1, "brainpoolP512r1" },
    { PF_MBEDTLS_SSL_IANA_TLS_GROUP_SECP384R1, "secp384r1" },
    { PF_MBEDTLS_SSL_IANA_TLS_GROUP_BP384R1, "brainpoolP384r1" },
    { PF_MBEDTLS_SSL_IANA_TLS_GROUP_SECP256R1, "secp256r1" },
    { PF_MBEDTLS_SSL_IANA_TLS_GROUP_SECP256K1, "secp256k1" },
    { PF_MBEDTLS_SSL_IANA_TLS_GROUP_BP256R1, "brainpoolP256r1" },
    { PF_MBEDTLS_SSL_IANA_TLS_GROUP_SECP224R1, "secp224r1" },
    { PF_MBEDTLS_SSL_IANA_TLS_GROUP_SECP224K1, "secp224k1" },
    { PF_MBEDTLS_SSL_IANA_TLS_GROUP_SECP192R1, "secp192r1" },
    { PF_MBEDTLS_SSL_IANA_TLS_GROUP_SECP192K1, "secp192k1" },
    { PF_MBEDTLS_SSL_IANA_TLS_GROUP_X25519, "x25519" },
    { PF_MBEDTLS_SSL_IANA_TLS_GROUP_X448, "x448" },
    { 0, NULL },
};

const char *pf_mbedtls_ssl_get_curve_name_from_tls_id(uint16_t tls_id)
{
    for (int i = 0; tls_id_curve_name_table[i].tls_id != 0; i++) {
        if (tls_id_curve_name_table[i].tls_id == tls_id) {
            return tls_id_curve_name_table[i].name;
        }
    }

    return NULL;
}
#endif

#if defined(PF_MBEDTLS_USE_PSA_CRYPTO)
int pf_mbedtls_ssl_get_handshake_transcript(pf_mbedtls_ssl_context *ssl,
                                         const pf_mbedtls_md_type_t md,
                                         unsigned char *dst,
                                         size_t dst_len,
                                         size_t *olen)
{
    pf_psa_status_t status = PF_PSA_ERROR_CORRUPTION_DETECTED;
    pf_psa_hash_operation_t *hash_operation_to_clone;
    pf_psa_hash_operation_t hash_operation = pf_psa_hash_operation_init();

    *olen = 0;

    switch (md) {
#if defined(PF_MBEDTLS_MD_CAN_SHA384)
        case PF_MBEDTLS_MD_SHA384:
            hash_operation_to_clone = &ssl->handshake->fin_sha384_psa;
            break;
#endif

#if defined(PF_MBEDTLS_MD_CAN_SHA256)
        case PF_MBEDTLS_MD_SHA256:
            hash_operation_to_clone = &ssl->handshake->fin_sha256_psa;
            break;
#endif

        default:
            goto exit;
    }

    status = pf_psa_hash_clone(hash_operation_to_clone, &hash_operation);
    if (status != PF_PSA_SUCCESS) {
        goto exit;
    }

    status = pf_psa_hash_finish(&hash_operation, dst, dst_len, olen);
    if (status != PF_PSA_SUCCESS) {
        goto exit;
    }

exit:
#if !defined(PF_MBEDTLS_MD_CAN_SHA384) && \
    !defined(PF_MBEDTLS_MD_CAN_SHA256)
    (void) ssl;
#endif
    return PF_PSA_TO_MBEDTLS_ERR(status);
}
#else /* MBEDTLS_USE_PSA_CRYPTO */

#if defined(PF_MBEDTLS_MD_CAN_SHA384)
PF_MBEDTLS_CHECK_RETURN_CRITICAL
static int ssl_get_handshake_transcript_sha384(pf_mbedtls_ssl_context *ssl,
                                               unsigned char *dst,
                                               size_t dst_len,
                                               size_t *olen)
{
    int ret;
    pf_mbedtls_md_context_t sha384;

    if (dst_len < 48) {
        return PF_MBEDTLS_ERR_SSL_INTERNAL_ERROR;
    }

    pf_mbedtls_md_init(&sha384);
    ret = pf_mbedtls_md_setup(&sha384, pf_mbedtls_md_info_from_type(PF_MBEDTLS_MD_SHA384), 0);
    if (ret != 0) {
        goto exit;
    }
    ret = pf_mbedtls_md_clone(&sha384, &ssl->handshake->fin_sha384);
    if (ret != 0) {
        goto exit;
    }

    if ((ret = pf_mbedtls_md_finish(&sha384, dst)) != 0) {
        PF_MBEDTLS_SSL_DEBUG_RET(1, "mbedtls_md_finish", ret);
        goto exit;
    }

    *olen = 48;

exit:

    pf_mbedtls_md_free(&sha384);
    return ret;
}
#endif /* MBEDTLS_MD_CAN_SHA384 */

#if defined(PF_MBEDTLS_MD_CAN_SHA256)
PF_MBEDTLS_CHECK_RETURN_CRITICAL
static int ssl_get_handshake_transcript_sha256(pf_mbedtls_ssl_context *ssl,
                                               unsigned char *dst,
                                               size_t dst_len,
                                               size_t *olen)
{
    int ret;
    pf_mbedtls_md_context_t sha256;

    if (dst_len < 32) {
        return PF_MBEDTLS_ERR_SSL_INTERNAL_ERROR;
    }

    pf_mbedtls_md_init(&sha256);
    ret = pf_mbedtls_md_setup(&sha256, pf_mbedtls_md_info_from_type(PF_MBEDTLS_MD_SHA256), 0);
    if (ret != 0) {
        goto exit;
    }
    ret = pf_mbedtls_md_clone(&sha256, &ssl->handshake->fin_sha256);
    if (ret != 0) {
        goto exit;
    }

    if ((ret = pf_mbedtls_md_finish(&sha256, dst)) != 0) {
        PF_MBEDTLS_SSL_DEBUG_RET(1, "mbedtls_md_finish", ret);
        goto exit;
    }

    *olen = 32;

exit:

    pf_mbedtls_md_free(&sha256);
    return ret;
}
#endif /* MBEDTLS_MD_CAN_SHA256 */

int pf_mbedtls_ssl_get_handshake_transcript(pf_mbedtls_ssl_context *ssl,
                                         const pf_mbedtls_md_type_t md,
                                         unsigned char *dst,
                                         size_t dst_len,
                                         size_t *olen)
{
    switch (md) {

#if defined(PF_MBEDTLS_MD_CAN_SHA384)
        case PF_MBEDTLS_MD_SHA384:
            return ssl_get_handshake_transcript_sha384(ssl, dst, dst_len, olen);
#endif /* MBEDTLS_MD_CAN_SHA384*/

#if defined(PF_MBEDTLS_MD_CAN_SHA256)
        case PF_MBEDTLS_MD_SHA256:
            return ssl_get_handshake_transcript_sha256(ssl, dst, dst_len, olen);
#endif /* MBEDTLS_MD_CAN_SHA256*/

        default:
#if !defined(PF_MBEDTLS_MD_CAN_SHA384) && \
            !defined(PF_MBEDTLS_MD_CAN_SHA256)
            (void) ssl;
            (void) dst;
            (void) dst_len;
            (void) olen;
#endif
            break;
    }
    return PF_MBEDTLS_ERR_SSL_INTERNAL_ERROR;
}

#endif /* !MBEDTLS_USE_PSA_CRYPTO */

#if defined(PF_MBEDTLS_SSL_HANDSHAKE_WITH_CERT_ENABLED)
/* mbedtls_ssl_parse_sig_alg_ext()
 *
 * The `extension_data` field of signature algorithm contains  a `SignatureSchemeList`
 * value (TLS 1.3 RFC8446):
 *      enum {
 *         ....
 *        ecdsa_secp256r1_sha256( 0x0403 ),
 *        ecdsa_secp384r1_sha384( 0x0503 ),
 *        ecdsa_secp521r1_sha512( 0x0603 ),
 *         ....
 *      } SignatureScheme;
 *
 *      struct {
 *         SignatureScheme supported_signature_algorithms<2..2^16-2>;
 *      } SignatureSchemeList;
 *
 * The `extension_data` field of signature algorithm contains a `SignatureAndHashAlgorithm`
 * value (TLS 1.2 RFC5246):
 *      enum {
 *          none(0), md5(1), sha1(2), sha224(3), sha256(4), sha384(5),
 *          sha512(6), (255)
 *      } HashAlgorithm;
 *
 *      enum { anonymous(0), rsa(1), dsa(2), ecdsa(3), (255) }
 *        SignatureAlgorithm;
 *
 *      struct {
 *          HashAlgorithm hash;
 *          SignatureAlgorithm signature;
 *      } SignatureAndHashAlgorithm;
 *
 *      SignatureAndHashAlgorithm
 *        supported_signature_algorithms<2..2^16-2>;
 *
 * The TLS 1.3 signature algorithm extension was defined to be a compatible
 * generalization of the TLS 1.2 signature algorithm extension.
 * `SignatureAndHashAlgorithm` field of TLS 1.2 can be represented by
 * `SignatureScheme` field of TLS 1.3
 *
 */
int pf_mbedtls_ssl_parse_sig_alg_ext(pf_mbedtls_ssl_context *ssl,
                                  const unsigned char *buf,
                                  const unsigned char *end)
{
    const unsigned char *p = buf;
    size_t supported_sig_algs_len = 0;
    const unsigned char *supported_sig_algs_end;
    uint16_t sig_alg;
    uint32_t common_idx = 0;

    PF_MBEDTLS_SSL_CHK_BUF_READ_PTR(p, end, 2);
    supported_sig_algs_len = PF_MBEDTLS_GET_UINT16_BE(p, 0);
    p += 2;

    memset(ssl->handshake->received_sig_algs, 0,
           sizeof(ssl->handshake->received_sig_algs));

    PF_MBEDTLS_SSL_CHK_BUF_READ_PTR(p, end, supported_sig_algs_len);
    supported_sig_algs_end = p + supported_sig_algs_len;
    while (p < supported_sig_algs_end) {
        PF_MBEDTLS_SSL_CHK_BUF_READ_PTR(p, supported_sig_algs_end, 2);
        sig_alg = PF_MBEDTLS_GET_UINT16_BE(p, 0);
        p += 2;
        PF_MBEDTLS_SSL_DEBUG_MSG(4, ("received signature algorithm: 0x%x %s",
                                  sig_alg,
                                  pf_mbedtls_ssl_sig_alg_to_str(sig_alg)));
#if defined(PF_MBEDTLS_SSL_PROTO_TLS1_2)
        if (ssl->tls_version == PF_MBEDTLS_SSL_VERSION_TLS1_2 &&
            (!(pf_mbedtls_ssl_sig_alg_is_supported(ssl, sig_alg) &&
               pf_mbedtls_ssl_sig_alg_is_offered(ssl, sig_alg)))) {
            continue;
        }
#endif /* MBEDTLS_SSL_PROTO_TLS1_2 */

        PF_MBEDTLS_SSL_DEBUG_MSG(4, ("valid signature algorithm: %s",
                                  pf_mbedtls_ssl_sig_alg_to_str(sig_alg)));

        if (common_idx + 1 < PF_MBEDTLS_RECEIVED_SIG_ALGS_SIZE) {
            ssl->handshake->received_sig_algs[common_idx] = sig_alg;
            common_idx += 1;
        }
    }
    /* Check that we consumed all the message. */
    if (p != end) {
        PF_MBEDTLS_SSL_DEBUG_MSG(1,
                              ("Signature algorithms extension length misaligned"));
        PF_MBEDTLS_SSL_PEND_FATAL_ALERT(PF_MBEDTLS_SSL_ALERT_MSG_DECODE_ERROR,
                                     PF_MBEDTLS_ERR_SSL_DECODE_ERROR);
        return PF_MBEDTLS_ERR_SSL_DECODE_ERROR;
    }

    if (common_idx == 0) {
        PF_MBEDTLS_SSL_DEBUG_MSG(3, ("no signature algorithm in common"));
        PF_MBEDTLS_SSL_PEND_FATAL_ALERT(PF_MBEDTLS_SSL_ALERT_MSG_HANDSHAKE_FAILURE,
                                     PF_MBEDTLS_ERR_SSL_HANDSHAKE_FAILURE);
        return PF_MBEDTLS_ERR_SSL_HANDSHAKE_FAILURE;
    }

    ssl->handshake->received_sig_algs[common_idx] = PF_MBEDTLS_TLS_SIG_NONE;
    return 0;
}

#endif /* MBEDTLS_SSL_HANDSHAKE_WITH_CERT_ENABLED */

#if defined(PF_MBEDTLS_SSL_PROTO_TLS1_2)

#if defined(PF_MBEDTLS_USE_PSA_CRYPTO)

static pf_psa_status_t setup_psa_key_derivation(pf_psa_key_derivation_operation_t *derivation,
                                             pf_mbedtls_svc_key_id_t key,
                                             pf_psa_algorithm_t alg,
                                             const unsigned char *raw_psk, size_t raw_psk_length,
                                             const unsigned char *seed, size_t seed_length,
                                             const unsigned char *label, size_t label_length,
                                             const unsigned char *other_secret,
                                             size_t other_secret_length,
                                             size_t capacity)
{
    pf_psa_status_t status;

    status = pf_psa_key_derivation_setup(derivation, alg);
    if (status != PF_PSA_SUCCESS) {
        return status;
    }

    if (PF_PSA_ALG_IS_TLS12_PRF(alg) || PF_PSA_ALG_IS_TLS12_PSK_TO_MS(alg)) {
        status = pf_psa_key_derivation_input_bytes(derivation,
                                                PF_PSA_KEY_DERIVATION_INPUT_SEED,
                                                seed, seed_length);
        if (status != PF_PSA_SUCCESS) {
            return status;
        }

        if (other_secret != NULL) {
            status = pf_psa_key_derivation_input_bytes(derivation,
                                                    PF_PSA_KEY_DERIVATION_INPUT_OTHER_SECRET,
                                                    other_secret, other_secret_length);
            if (status != PF_PSA_SUCCESS) {
                return status;
            }
        }

        if (pf_mbedtls_svc_key_id_is_null(key)) {
            status = pf_psa_key_derivation_input_bytes(
                derivation, PF_PSA_KEY_DERIVATION_INPUT_SECRET,
                raw_psk, raw_psk_length);
        } else {
            status = pf_psa_key_derivation_input_key(
                derivation, PF_PSA_KEY_DERIVATION_INPUT_SECRET, key);
        }
        if (status != PF_PSA_SUCCESS) {
            return status;
        }

        status = pf_psa_key_derivation_input_bytes(derivation,
                                                PF_PSA_KEY_DERIVATION_INPUT_LABEL,
                                                label, label_length);
        if (status != PF_PSA_SUCCESS) {
            return status;
        }
    } else {
        return PF_PSA_ERROR_NOT_SUPPORTED;
    }

    status = pf_psa_key_derivation_set_capacity(derivation, capacity);
    if (status != PF_PSA_SUCCESS) {
        return status;
    }

    return PF_PSA_SUCCESS;
}

#if defined(PF_PSA_WANT_ALG_SHA_384) || \
    defined(PF_PSA_WANT_ALG_SHA_256)
PF_MBEDTLS_CHECK_RETURN_CRITICAL
static int tls_prf_generic(pf_mbedtls_md_type_t md_type,
                           const unsigned char *secret, size_t slen,
                           const char *label, size_t label_len,
                           const unsigned char *random, size_t rlen,
                           unsigned char *dstbuf, size_t dlen)
{
    pf_psa_status_t status;
    pf_psa_algorithm_t alg;
    pf_mbedtls_svc_key_id_t master_key = PF_MBEDTLS_SVC_KEY_ID_INIT;
    pf_psa_key_derivation_operation_t derivation =
        PF_PSA_KEY_DERIVATION_OPERATION_INIT;

    if (md_type == PF_MBEDTLS_MD_SHA384) {
        alg = PF_PSA_ALG_TLS12_PRF(PF_PSA_ALG_SHA_384);
    } else {
        alg = PF_PSA_ALG_TLS12_PRF(PF_PSA_ALG_SHA_256);
    }

    /* Normally a "secret" should be long enough to be impossible to
     * find by brute force, and in particular should not be empty. But
     * this PRF is also used to derive an IV, in particular in EAP-TLS,
     * and for this use case it makes sense to have a 0-length "secret".
     * Since the key API doesn't allow importing a key of length 0,
     * keep master_key=0, which setup_psa_key_derivation() understands
     * to mean a 0-length "secret" input. */
    if (slen != 0) {
        pf_psa_key_attributes_t key_attributes = pf_psa_key_attributes_init();
        pf_psa_set_key_usage_flags(&key_attributes, PF_PSA_KEY_USAGE_DERIVE);
        pf_psa_set_key_algorithm(&key_attributes, alg);
        pf_psa_set_key_type(&key_attributes, PF_PSA_KEY_TYPE_DERIVE);

        status = pf_psa_import_key(&key_attributes, secret, slen, &master_key);
        if (status != PF_PSA_SUCCESS) {
            return PF_MBEDTLS_ERR_SSL_HW_ACCEL_FAILED;
        }
    }

    status = setup_psa_key_derivation(&derivation,
                                      master_key, alg,
                                      NULL, 0,
                                      random, rlen,
                                      (unsigned char const *) label,
                                      label_len,
                                      NULL, 0,
                                      dlen);
    if (status != PF_PSA_SUCCESS) {
        pf_psa_key_derivation_abort(&derivation);
        pf_psa_destroy_key(master_key);
        return PF_MBEDTLS_ERR_SSL_HW_ACCEL_FAILED;
    }

    status = pf_psa_key_derivation_output_bytes(&derivation, dstbuf, dlen);
    if (status != PF_PSA_SUCCESS) {
        pf_psa_key_derivation_abort(&derivation);
        pf_psa_destroy_key(master_key);
        return PF_MBEDTLS_ERR_SSL_HW_ACCEL_FAILED;
    }

    status = pf_psa_key_derivation_abort(&derivation);
    if (status != PF_PSA_SUCCESS) {
        pf_psa_destroy_key(master_key);
        return PF_MBEDTLS_ERR_SSL_HW_ACCEL_FAILED;
    }

    if (!pf_mbedtls_svc_key_id_is_null(master_key)) {
        status = pf_psa_destroy_key(master_key);
    }
    if (status != PF_PSA_SUCCESS) {
        return PF_MBEDTLS_ERR_SSL_HW_ACCEL_FAILED;
    }

    return 0;
}
#endif /* PSA_WANT_ALG_SHA_256 || PSA_WANT_ALG_SHA_384 */
#else /* MBEDTLS_USE_PSA_CRYPTO */

#if defined(PF_MBEDTLS_MD_C) &&       \
    (defined(PF_MBEDTLS_MD_CAN_SHA256) || \
    defined(PF_MBEDTLS_MD_CAN_SHA384))
PF_MBEDTLS_CHECK_RETURN_CRITICAL
static int tls_prf_generic(pf_mbedtls_md_type_t md_type,
                           const unsigned char *secret, size_t slen,
                           const char *label, size_t label_len,
                           const unsigned char *random, size_t rlen,
                           unsigned char *dstbuf, size_t dlen)
{
    size_t nb;
    size_t i, j, k, md_len;
    unsigned char *tmp;
    size_t tmp_len = 0;
    unsigned char h_i[PF_MBEDTLS_MD_MAX_SIZE];
    const pf_mbedtls_md_info_t *md_info;
    pf_mbedtls_md_context_t md_ctx;
    int ret = PF_MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;

    pf_mbedtls_md_init(&md_ctx);

    if ((md_info = pf_mbedtls_md_info_from_type(md_type)) == NULL) {
        return PF_MBEDTLS_ERR_SSL_INTERNAL_ERROR;
    }

    md_len = pf_mbedtls_md_get_size(md_info);

    tmp_len = md_len + label_len + rlen;
    tmp = pf_mbedtls_calloc(1, tmp_len);
    if (tmp == NULL) {
        ret = PF_MBEDTLS_ERR_SSL_ALLOC_FAILED;
        goto exit;
    }

    nb = label_len;
    memcpy(tmp + md_len, label, nb);
    memcpy(tmp + md_len + nb, random, rlen);
    nb += rlen;

    /*
     * Compute P_<hash>(secret, label + random)[0..dlen]
     */
    if ((ret = pf_mbedtls_md_setup(&md_ctx, md_info, 1)) != 0) {
        goto exit;
    }

    ret = pf_mbedtls_md_hmac_starts(&md_ctx, secret, slen);
    if (ret != 0) {
        goto exit;
    }
    ret = pf_mbedtls_md_hmac_update(&md_ctx, tmp + md_len, nb);
    if (ret != 0) {
        goto exit;
    }
    ret = pf_mbedtls_md_hmac_finish(&md_ctx, tmp);
    if (ret != 0) {
        goto exit;
    }

    for (i = 0; i < dlen; i += md_len) {
        ret = pf_mbedtls_md_hmac_reset(&md_ctx);
        if (ret != 0) {
            goto exit;
        }
        ret = pf_mbedtls_md_hmac_update(&md_ctx, tmp, md_len + nb);
        if (ret != 0) {
            goto exit;
        }
        ret = pf_mbedtls_md_hmac_finish(&md_ctx, h_i);
        if (ret != 0) {
            goto exit;
        }

        ret = pf_mbedtls_md_hmac_reset(&md_ctx);
        if (ret != 0) {
            goto exit;
        }
        ret = pf_mbedtls_md_hmac_update(&md_ctx, tmp, md_len);
        if (ret != 0) {
            goto exit;
        }
        ret = pf_mbedtls_md_hmac_finish(&md_ctx, tmp);
        if (ret != 0) {
            goto exit;
        }

        k = (i + md_len > dlen) ? dlen % md_len : md_len;

        for (j = 0; j < k; j++) {
            dstbuf[i + j]  = h_i[j];
        }
    }

exit:
    pf_mbedtls_md_free(&md_ctx);

    if (tmp != NULL) {
        pf_mbedtls_platform_zeroize(tmp, tmp_len);
    }

    pf_mbedtls_platform_zeroize(h_i, sizeof(h_i));

    pf_mbedtls_free(tmp);

    return ret;
}
#endif /* MBEDTLS_MD_C && ( MBEDTLS_MD_CAN_SHA256 || MBEDTLS_MD_CAN_SHA384 ) */
#endif /* MBEDTLS_USE_PSA_CRYPTO */

#if defined(PF_MBEDTLS_MD_CAN_SHA256)
PF_MBEDTLS_CHECK_RETURN_CRITICAL
static int tls_prf_sha256(const unsigned char *secret, size_t slen,
                          const char *label,
                          const unsigned char *random, size_t rlen,
                          unsigned char *dstbuf, size_t dlen)
{
    return tls_prf_generic(PF_MBEDTLS_MD_SHA256, secret, slen,
                           label, strlen(label), random, rlen, dstbuf, dlen);
}
#endif /* MBEDTLS_MD_CAN_SHA256*/

#if defined(PF_MBEDTLS_MD_CAN_SHA384)
PF_MBEDTLS_CHECK_RETURN_CRITICAL
static int tls_prf_sha384(const unsigned char *secret, size_t slen,
                          const char *label,
                          const unsigned char *random, size_t rlen,
                          unsigned char *dstbuf, size_t dlen)
{
    return tls_prf_generic(PF_MBEDTLS_MD_SHA384, secret, slen,
                           label, strlen(label), random, rlen, dstbuf, dlen);
}
#endif /* MBEDTLS_MD_CAN_SHA384*/

/*
 * Set appropriate PRF function and other SSL / TLS1.2 functions
 *
 * Inputs:
 * - hash associated with the ciphersuite (only used by TLS 1.2)
 *
 * Outputs:
 * - the tls_prf, calc_verify and calc_finished members of handshake structure
 */
PF_MBEDTLS_CHECK_RETURN_CRITICAL
static int ssl_set_handshake_prfs(pf_mbedtls_ssl_handshake_params *handshake,
                                  pf_mbedtls_md_type_t hash)
{
#if defined(PF_MBEDTLS_MD_CAN_SHA384)
    if (hash == PF_MBEDTLS_MD_SHA384) {
        handshake->tls_prf = tls_prf_sha384;
        handshake->calc_verify = ssl_calc_verify_tls_sha384;
        handshake->calc_finished = ssl_calc_finished_tls_sha384;
    } else
#endif
#if defined(PF_MBEDTLS_MD_CAN_SHA256)
    {
        (void) hash;
        handshake->tls_prf = tls_prf_sha256;
        handshake->calc_verify = ssl_calc_verify_tls_sha256;
        handshake->calc_finished = ssl_calc_finished_tls_sha256;
    }
#else
    {
        (void) handshake;
        (void) hash;
        return PF_MBEDTLS_ERR_SSL_INTERNAL_ERROR;
    }
#endif

    return 0;
}

/*
 * Compute master secret if needed
 *
 * Parameters:
 * [in/out] handshake
 *          [in] resume, premaster, extended_ms, calc_verify, tls_prf
 *               (PSA-PSK) ciphersuite_info, psk_opaque
 *          [out] premaster (cleared)
 * [out] master
 * [in] ssl: optionally used for debugging, EMS and PSA-PSK
 *      debug: conf->f_dbg, conf->p_dbg
 *      EMS: passed to calc_verify (debug + session_negotiate)
 *      PSA-PSA: conf
 */
PF_MBEDTLS_CHECK_RETURN_CRITICAL
static int ssl_compute_master(pf_mbedtls_ssl_handshake_params *handshake,
                              unsigned char *master,
                              const pf_mbedtls_ssl_context *ssl)
{
    int ret = PF_MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;

    /* cf. RFC 5246, Section 8.1:
     * "The master secret is always exactly 48 bytes in length." */
    size_t const master_secret_len = 48;

#if defined(PF_MBEDTLS_SSL_EXTENDED_MASTER_SECRET)
    unsigned char session_hash[48];
#endif /* MBEDTLS_SSL_EXTENDED_MASTER_SECRET */

    /* The label for the KDF used for key expansion.
     * This is either "master secret" or "extended master secret"
     * depending on whether the Extended Master Secret extension
     * is used. */
    char const *lbl = "master secret";

    /* The seed for the KDF used for key expansion.
     * - If the Extended Master Secret extension is not used,
     *   this is ClientHello.Random + ServerHello.Random
     *   (see Sect. 8.1 in RFC 5246).
     * - If the Extended Master Secret extension is used,
     *   this is the transcript of the handshake so far.
     *   (see Sect. 4 in RFC 7627). */
    unsigned char const *seed = handshake->randbytes;
    size_t seed_len = 64;

#if !defined(PF_MBEDTLS_DEBUG_C) &&                    \
    !defined(PF_MBEDTLS_SSL_EXTENDED_MASTER_SECRET) && \
    !(defined(PF_MBEDTLS_USE_PSA_CRYPTO) &&            \
    defined(PF_MBEDTLS_KEY_EXCHANGE_PSK_ENABLED))
    ssl = NULL; /* make sure we don't use it except for those cases */
    (void) ssl;
#endif

    if (handshake->resume != 0) {
        PF_MBEDTLS_SSL_DEBUG_MSG(3, ("no premaster (session resumed)"));
        return 0;
    }

#if defined(PF_MBEDTLS_SSL_EXTENDED_MASTER_SECRET)
    if (handshake->extended_ms == PF_MBEDTLS_SSL_EXTENDED_MS_ENABLED) {
        lbl  = "extended master secret";
        ret = handshake->calc_verify(ssl, session_hash, &seed_len);
        if (ret != 0) {
            PF_MBEDTLS_SSL_DEBUG_RET(1, "calc_verify", ret);
            return ret;
        }
        if (seed_len > sizeof(session_hash)) {
            PF_MBEDTLS_SSL_DEBUG_MSG(1, ("bad session hash length"));
            return PF_MBEDTLS_ERR_SSL_INTERNAL_ERROR;
        }
        seed = session_hash;

        PF_MBEDTLS_SSL_DEBUG_BUF(3, "session hash for extended master secret",
                              session_hash, seed_len);
    }
#endif /* MBEDTLS_SSL_EXTENDED_MASTER_SECRET */

#if defined(PF_MBEDTLS_USE_PSA_CRYPTO) &&                   \
    defined(PF_MBEDTLS_KEY_EXCHANGE_SOME_PSK_ENABLED)
    if (pf_mbedtls_ssl_ciphersuite_uses_psk(handshake->ciphersuite_info) == 1) {
        /* Perform PSK-to-MS expansion in a single step. */
        pf_psa_status_t status;
        pf_psa_algorithm_t alg;
        pf_mbedtls_svc_key_id_t psk;
        pf_psa_key_derivation_operation_t derivation =
            PF_PSA_KEY_DERIVATION_OPERATION_INIT;
        pf_mbedtls_md_type_t hash_alg = (pf_mbedtls_md_type_t) handshake->ciphersuite_info->mac;

        PF_MBEDTLS_SSL_DEBUG_MSG(2, ("perform PSA-based PSK-to-MS expansion"));

        psk = pf_mbedtls_ssl_get_opaque_psk(ssl);

        if (hash_alg == PF_MBEDTLS_MD_SHA384) {
            alg = PF_PSA_ALG_TLS12_PSK_TO_MS(PF_PSA_ALG_SHA_384);
        } else {
            alg = PF_PSA_ALG_TLS12_PSK_TO_MS(PF_PSA_ALG_SHA_256);
        }

        size_t other_secret_len = 0;
        unsigned char *other_secret = NULL;

        switch (handshake->ciphersuite_info->key_exchange) {
            /* Provide other secret.
             * Other secret is stored in premaster, where first 2 bytes hold the
             * length of the other key.
             */
            case PF_MBEDTLS_KEY_EXCHANGE_RSA_PSK:
                /* For RSA-PSK other key length is always 48 bytes. */
                other_secret_len = 48;
                other_secret = handshake->premaster + 2;
                break;
            case PF_MBEDTLS_KEY_EXCHANGE_ECDHE_PSK:
            case PF_MBEDTLS_KEY_EXCHANGE_DHE_PSK:
                other_secret_len = PF_MBEDTLS_GET_UINT16_BE(handshake->premaster, 0);
                other_secret = handshake->premaster + 2;
                break;
            default:
                break;
        }

        status = setup_psa_key_derivation(&derivation, psk, alg,
                                          ssl->conf->psk, ssl->conf->psk_len,
                                          seed, seed_len,
                                          (unsigned char const *) lbl,
                                          (size_t) strlen(lbl),
                                          other_secret, other_secret_len,
                                          master_secret_len);
        if (status != PF_PSA_SUCCESS) {
            pf_psa_key_derivation_abort(&derivation);
            return PF_MBEDTLS_ERR_SSL_HW_ACCEL_FAILED;
        }

        status = pf_psa_key_derivation_output_bytes(&derivation,
                                                 master,
                                                 master_secret_len);
        if (status != PF_PSA_SUCCESS) {
            pf_psa_key_derivation_abort(&derivation);
            return PF_MBEDTLS_ERR_SSL_HW_ACCEL_FAILED;
        }

        status = pf_psa_key_derivation_abort(&derivation);
        if (status != PF_PSA_SUCCESS) {
            return PF_MBEDTLS_ERR_SSL_HW_ACCEL_FAILED;
        }
    } else
#endif
    {
#if defined(PF_MBEDTLS_USE_PSA_CRYPTO) &&                              \
        defined(PF_MBEDTLS_KEY_EXCHANGE_ECJPAKE_ENABLED)
        if (handshake->ciphersuite_info->key_exchange == PF_MBEDTLS_KEY_EXCHANGE_ECJPAKE) {
            pf_psa_status_t status;
            pf_psa_algorithm_t alg = PF_PSA_ALG_TLS12_ECJPAKE_TO_PMS;
            pf_psa_key_derivation_operation_t derivation =
                PF_PSA_KEY_DERIVATION_OPERATION_INIT;

            PF_MBEDTLS_SSL_DEBUG_MSG(2, ("perform PSA-based PMS KDF for ECJPAKE"));

            handshake->pmslen = PF_PSA_TLS12_ECJPAKE_TO_PMS_DATA_SIZE;

            status = pf_psa_key_derivation_setup(&derivation, alg);
            if (status != PF_PSA_SUCCESS) {
                return PF_MBEDTLS_ERR_SSL_HW_ACCEL_FAILED;
            }

            status = pf_psa_key_derivation_set_capacity(&derivation,
                                                     PF_PSA_TLS12_ECJPAKE_TO_PMS_DATA_SIZE);
            if (status != PF_PSA_SUCCESS) {
                pf_psa_key_derivation_abort(&derivation);
                return PF_MBEDTLS_ERR_SSL_HW_ACCEL_FAILED;
            }

            status = pf_psa_pake_get_implicit_key(&handshake->pf_psa_pake_ctx,
                                               &derivation);
            if (status != PF_PSA_SUCCESS) {
                pf_psa_key_derivation_abort(&derivation);
                return PF_MBEDTLS_ERR_SSL_HW_ACCEL_FAILED;
            }

            status = pf_psa_key_derivation_output_bytes(&derivation,
                                                     handshake->premaster,
                                                     handshake->pmslen);
            if (status != PF_PSA_SUCCESS) {
                pf_psa_key_derivation_abort(&derivation);
                return PF_MBEDTLS_ERR_SSL_HW_ACCEL_FAILED;
            }

            status = pf_psa_key_derivation_abort(&derivation);
            if (status != PF_PSA_SUCCESS) {
                return PF_MBEDTLS_ERR_SSL_HW_ACCEL_FAILED;
            }
        }
#endif
        ret = handshake->tls_prf(handshake->premaster, handshake->pmslen,
                                 lbl, seed, seed_len,
                                 master,
                                 master_secret_len);
        if (ret != 0) {
            PF_MBEDTLS_SSL_DEBUG_RET(1, "prf", ret);
            return ret;
        }

        PF_MBEDTLS_SSL_DEBUG_BUF(3, "premaster secret",
                              handshake->premaster,
                              handshake->pmslen);

        pf_mbedtls_platform_zeroize(handshake->premaster,
                                 sizeof(handshake->premaster));
    }

    return 0;
}

int pf_mbedtls_ssl_derive_keys(pf_mbedtls_ssl_context *ssl)
{
    int ret = PF_MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    const pf_mbedtls_ssl_ciphersuite_t * const ciphersuite_info =
        ssl->handshake->ciphersuite_info;

    PF_MBEDTLS_SSL_DEBUG_MSG(2, ("=> derive keys"));

    /* Set PRF, calc_verify and calc_finished function pointers */
    ret = ssl_set_handshake_prfs(ssl->handshake,
                                 (pf_mbedtls_md_type_t) ciphersuite_info->mac);
    if (ret != 0) {
        PF_MBEDTLS_SSL_DEBUG_RET(1, "ssl_set_handshake_prfs", ret);
        return ret;
    }

    /* Compute master secret if needed */
    ret = ssl_compute_master(ssl->handshake,
                             ssl->session_negotiate->master,
                             ssl);
    if (ret != 0) {
        PF_MBEDTLS_SSL_DEBUG_RET(1, "ssl_compute_master", ret);
        return ret;
    }

    /* Swap the client and server random values:
     * - MS derivation wanted client+server (RFC 5246 8.1)
     * - key derivation wants server+client (RFC 5246 6.3) */
    {
        unsigned char tmp[64];
        memcpy(tmp, ssl->handshake->randbytes, 64);
        memcpy(ssl->handshake->randbytes, tmp + 32, 32);
        memcpy(ssl->handshake->randbytes + 32, tmp, 32);
        pf_mbedtls_platform_zeroize(tmp, sizeof(tmp));
    }

    /* Populate transform structure */
    ret = ssl_tls12_populate_transform(ssl->transform_negotiate,
                                       ssl->session_negotiate->ciphersuite,
                                       ssl->session_negotiate->master,
#if defined(PF_MBEDTLS_SSL_SOME_SUITES_USE_CBC_ETM)
                                       ssl->session_negotiate->encrypt_then_mac,
#endif /* MBEDTLS_SSL_SOME_SUITES_USE_CBC_ETM */
                                       ssl->handshake->tls_prf,
                                       ssl->handshake->randbytes,
                                       ssl->tls_version,
                                       ssl->conf->endpoint,
                                       ssl);
    if (ret != 0) {
        PF_MBEDTLS_SSL_DEBUG_RET(1, "ssl_tls12_populate_transform", ret);
        return ret;
    }

    /* We no longer need Server/ClientHello.random values */
    pf_mbedtls_platform_zeroize(ssl->handshake->randbytes,
                             sizeof(ssl->handshake->randbytes));

    PF_MBEDTLS_SSL_DEBUG_MSG(2, ("<= derive keys"));

    return 0;
}

int pf_mbedtls_ssl_set_calc_verify_md(pf_mbedtls_ssl_context *ssl, int md)
{
    switch (md) {
#if defined(PF_MBEDTLS_MD_CAN_SHA384)
        case PF_MBEDTLS_SSL_HASH_SHA384:
            ssl->handshake->calc_verify = ssl_calc_verify_tls_sha384;
            break;
#endif
#if defined(PF_MBEDTLS_MD_CAN_SHA256)
        case PF_MBEDTLS_SSL_HASH_SHA256:
            ssl->handshake->calc_verify = ssl_calc_verify_tls_sha256;
            break;
#endif
        default:
            return -1;
    }
#if !defined(PF_MBEDTLS_MD_CAN_SHA384) && \
    !defined(PF_MBEDTLS_MD_CAN_SHA256)
    (void) ssl;
#endif
    return 0;
}

#if defined(PF_MBEDTLS_USE_PSA_CRYPTO)
static int ssl_calc_verify_tls_psa(const pf_mbedtls_ssl_context *ssl,
                                   const pf_psa_hash_operation_t *hs_op,
                                   size_t buffer_size,
                                   unsigned char *hash,
                                   size_t *hlen)
{
    pf_psa_status_t status;
    pf_psa_hash_operation_t cloned_op = pf_psa_hash_operation_init();

#if !defined(PF_MBEDTLS_DEBUG_C)
    (void) ssl;
#endif
    PF_MBEDTLS_SSL_DEBUG_MSG(2, ("=> PSA calc verify"));
    status = pf_psa_hash_clone(hs_op, &cloned_op);
    if (status != PF_PSA_SUCCESS) {
        goto exit;
    }

    status = pf_psa_hash_finish(&cloned_op, hash, buffer_size, hlen);
    if (status != PF_PSA_SUCCESS) {
        goto exit;
    }

    PF_MBEDTLS_SSL_DEBUG_BUF(3, "PSA calculated verify result", hash, *hlen);
    PF_MBEDTLS_SSL_DEBUG_MSG(2, ("<= PSA calc verify"));

exit:
    pf_psa_hash_abort(&cloned_op);
    return PF_PSA_TO_MBEDTLS_ERR(status);
}
#else
static int ssl_calc_verify_tls_legacy(const pf_mbedtls_ssl_context *ssl,
                                      const pf_mbedtls_md_context_t *hs_ctx,
                                      unsigned char *hash,
                                      size_t *hlen)
{
    int ret = PF_MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    pf_mbedtls_md_context_t cloned_ctx;

    pf_mbedtls_md_init(&cloned_ctx);

#if !defined(PF_MBEDTLS_DEBUG_C)
    (void) ssl;
#endif
    PF_MBEDTLS_SSL_DEBUG_MSG(2, ("=> calc verify"));

    ret = pf_mbedtls_md_setup(&cloned_ctx, pf_mbedtls_md_info_from_ctx(hs_ctx), 0);
    if (ret != 0) {
        goto exit;
    }
    ret = pf_mbedtls_md_clone(&cloned_ctx, hs_ctx);
    if (ret != 0) {
        goto exit;
    }

    ret = pf_mbedtls_md_finish(&cloned_ctx, hash);
    if (ret != 0) {
        goto exit;
    }

    *hlen = pf_mbedtls_md_get_size(pf_mbedtls_md_info_from_ctx(hs_ctx));

    PF_MBEDTLS_SSL_DEBUG_BUF(3, "calculated verify result", hash, *hlen);
    PF_MBEDTLS_SSL_DEBUG_MSG(2, ("<= calc verify"));

exit:
    pf_mbedtls_md_free(&cloned_ctx);
    return ret;
}
#endif /* MBEDTLS_USE_PSA_CRYPTO */

#if defined(PF_MBEDTLS_MD_CAN_SHA256)
int ssl_calc_verify_tls_sha256(const pf_mbedtls_ssl_context *ssl,
                               unsigned char *hash,
                               size_t *hlen)
{
#if defined(PF_MBEDTLS_USE_PSA_CRYPTO)
    return ssl_calc_verify_tls_psa(ssl, &ssl->handshake->fin_sha256_psa, 32,
                                   hash, hlen);
#else
    return ssl_calc_verify_tls_legacy(ssl, &ssl->handshake->fin_sha256,
                                      hash, hlen);
#endif /* MBEDTLS_USE_PSA_CRYPTO */
}
#endif /* MBEDTLS_MD_CAN_SHA256 */

#if defined(PF_MBEDTLS_MD_CAN_SHA384)
int ssl_calc_verify_tls_sha384(const pf_mbedtls_ssl_context *ssl,
                               unsigned char *hash,
                               size_t *hlen)
{
#if defined(PF_MBEDTLS_USE_PSA_CRYPTO)
    return ssl_calc_verify_tls_psa(ssl, &ssl->handshake->fin_sha384_psa, 48,
                                   hash, hlen);
#else
    return ssl_calc_verify_tls_legacy(ssl, &ssl->handshake->fin_sha384,
                                      hash, hlen);
#endif /* MBEDTLS_USE_PSA_CRYPTO */
}
#endif /* MBEDTLS_MD_CAN_SHA384 */

#if !defined(PF_MBEDTLS_USE_PSA_CRYPTO) &&                      \
    defined(PF_MBEDTLS_KEY_EXCHANGE_SOME_PSK_ENABLED)
int pf_mbedtls_ssl_psk_derive_premaster(pf_mbedtls_ssl_context *ssl, pf_mbedtls_key_exchange_type_t key_ex)
{
    unsigned char *p = ssl->handshake->premaster;
    unsigned char *end = p + sizeof(ssl->handshake->premaster);
    const unsigned char *psk = NULL;
    size_t psk_len = 0;
    int psk_ret = pf_mbedtls_ssl_get_psk(ssl, &psk, &psk_len);

    if (psk_ret == PF_MBEDTLS_ERR_SSL_PRIVATE_KEY_REQUIRED) {
        /*
         * This should never happen because the existence of a PSK is always
         * checked before calling this function.
         *
         * The exception is opaque DHE-PSK. For DHE-PSK fill premaster with
         * the shared secret without PSK.
         */
        if (key_ex != PF_MBEDTLS_KEY_EXCHANGE_DHE_PSK) {
            PF_MBEDTLS_SSL_DEBUG_MSG(1, ("should never happen"));
            return PF_MBEDTLS_ERR_SSL_INTERNAL_ERROR;
        }
    }

    /*
     * PMS = struct {
     *     opaque other_secret<0..2^16-1>;
     *     opaque psk<0..2^16-1>;
     * };
     * with "other_secret" depending on the particular key exchange
     */
#if defined(PF_MBEDTLS_KEY_EXCHANGE_PSK_ENABLED)
    if (key_ex == PF_MBEDTLS_KEY_EXCHANGE_PSK) {
        if (end - p < 2) {
            return PF_MBEDTLS_ERR_SSL_BAD_INPUT_DATA;
        }

        PF_MBEDTLS_PUT_UINT16_BE(psk_len, p, 0);
        p += 2;

        if (end < p || (size_t) (end - p) < psk_len) {
            return PF_MBEDTLS_ERR_SSL_BAD_INPUT_DATA;
        }

        memset(p, 0, psk_len);
        p += psk_len;
    } else
#endif /* MBEDTLS_KEY_EXCHANGE_PSK_ENABLED */
#if defined(PF_MBEDTLS_KEY_EXCHANGE_RSA_PSK_ENABLED)
    if (key_ex == PF_MBEDTLS_KEY_EXCHANGE_RSA_PSK) {
        /*
         * other_secret already set by the ClientKeyExchange message,
         * and is 48 bytes long
         */
        if (end - p < 2) {
            return PF_MBEDTLS_ERR_SSL_BAD_INPUT_DATA;
        }

        *p++ = 0;
        *p++ = 48;
        p += 48;
    } else
#endif /* MBEDTLS_KEY_EXCHANGE_RSA_PSK_ENABLED */
#if defined(PF_MBEDTLS_KEY_EXCHANGE_DHE_PSK_ENABLED)
    if (key_ex == PF_MBEDTLS_KEY_EXCHANGE_DHE_PSK) {
        int ret = PF_MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
        size_t len;

        /* Write length only when we know the actual value */
        if ((ret = pf_mbedtls_dhm_calc_secret(&ssl->handshake->dhm_ctx,
                                           p + 2, (size_t) (end - (p + 2)), &len,
                                           ssl->conf->f_rng, ssl->conf->p_rng)) != 0) {
            PF_MBEDTLS_SSL_DEBUG_RET(1, "mbedtls_dhm_calc_secret", ret);
            return ret;
        }
        PF_MBEDTLS_PUT_UINT16_BE(len, p, 0);
        p += 2 + len;

        PF_MBEDTLS_SSL_DEBUG_MPI(3, "DHM: K ", &ssl->handshake->dhm_ctx.K);
    } else
#endif /* MBEDTLS_KEY_EXCHANGE_DHE_PSK_ENABLED */
#if defined(PF_MBEDTLS_KEY_EXCHANGE_ECDHE_PSK_ENABLED)
    if (key_ex == PF_MBEDTLS_KEY_EXCHANGE_ECDHE_PSK) {
        int ret = PF_MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
        size_t zlen;

        if ((ret = pf_mbedtls_ecdh_calc_secret(&ssl->handshake->ecdh_ctx, &zlen,
                                            p + 2, (size_t) (end - (p + 2)),
                                            ssl->conf->f_rng, ssl->conf->p_rng)) != 0) {
            PF_MBEDTLS_SSL_DEBUG_RET(1, "mbedtls_ecdh_calc_secret", ret);
            return ret;
        }

        PF_MBEDTLS_PUT_UINT16_BE(zlen, p, 0);
        p += 2 + zlen;

        PF_MBEDTLS_SSL_DEBUG_ECDH(3, &ssl->handshake->ecdh_ctx,
                               PF_MBEDTLS_DEBUG_ECDH_Z);
    } else
#endif /* MBEDTLS_KEY_EXCHANGE_ECDHE_PSK_ENABLED */
    {
        PF_MBEDTLS_SSL_DEBUG_MSG(1, ("should never happen"));
        return PF_MBEDTLS_ERR_SSL_INTERNAL_ERROR;
    }

    /* opaque psk<0..2^16-1>; */
    if (end - p < 2) {
        return PF_MBEDTLS_ERR_SSL_BAD_INPUT_DATA;
    }

    PF_MBEDTLS_PUT_UINT16_BE(psk_len, p, 0);
    p += 2;

    if (end < p || (size_t) (end - p) < psk_len) {
        return PF_MBEDTLS_ERR_SSL_BAD_INPUT_DATA;
    }

    memcpy(p, psk, psk_len);
    p += psk_len;

    ssl->handshake->pmslen = (size_t) (p - ssl->handshake->premaster);

    return 0;
}
#endif /* !MBEDTLS_USE_PSA_CRYPTO && MBEDTLS_KEY_EXCHANGE_SOME_PSK_ENABLED */

#if defined(PF_MBEDTLS_SSL_SRV_C) && defined(PF_MBEDTLS_SSL_RENEGOTIATION)
PF_MBEDTLS_CHECK_RETURN_CRITICAL
static int ssl_write_hello_request(pf_mbedtls_ssl_context *ssl);

#if defined(PF_MBEDTLS_SSL_PROTO_DTLS)
int pf_mbedtls_ssl_resend_hello_request(pf_mbedtls_ssl_context *ssl)
{
    /* If renegotiation is not enforced, retransmit until we would reach max
     * timeout if we were using the usual handshake doubling scheme */
    if (ssl->conf->renego_max_records < 0) {
        uint32_t ratio = ssl->conf->hs_timeout_max / ssl->conf->hs_timeout_min + 1;
        unsigned char doublings = 1;

        while (ratio != 0) {
            ++doublings;
            ratio >>= 1;
        }

        if (++ssl->renego_records_seen > doublings) {
            PF_MBEDTLS_SSL_DEBUG_MSG(2, ("no longer retransmitting hello request"));
            return 0;
        }
    }

    return ssl_write_hello_request(ssl);
}
#endif
#endif /* MBEDTLS_SSL_SRV_C && MBEDTLS_SSL_RENEGOTIATION */

/*
 * Handshake functions
 */
#if !defined(PF_MBEDTLS_KEY_EXCHANGE_WITH_CERT_ENABLED)
/* No certificate support -> dummy functions */
int pf_mbedtls_ssl_write_certificate(pf_mbedtls_ssl_context *ssl)
{
    const pf_mbedtls_ssl_ciphersuite_t *ciphersuite_info =
        ssl->handshake->ciphersuite_info;

    PF_MBEDTLS_SSL_DEBUG_MSG(2, ("=> write certificate"));

    if (!pf_mbedtls_ssl_ciphersuite_uses_srv_cert(ciphersuite_info)) {
        PF_MBEDTLS_SSL_DEBUG_MSG(2, ("<= skip write certificate"));
        pf_mbedtls_ssl_handshake_increment_state(ssl);
        return 0;
    }

    PF_MBEDTLS_SSL_DEBUG_MSG(1, ("should never happen"));
    return PF_MBEDTLS_ERR_SSL_INTERNAL_ERROR;
}

int pf_mbedtls_ssl_parse_certificate(pf_mbedtls_ssl_context *ssl)
{
    const pf_mbedtls_ssl_ciphersuite_t *ciphersuite_info =
        ssl->handshake->ciphersuite_info;

    PF_MBEDTLS_SSL_DEBUG_MSG(2, ("=> parse certificate"));

    if (!pf_mbedtls_ssl_ciphersuite_uses_srv_cert(ciphersuite_info)) {
        PF_MBEDTLS_SSL_DEBUG_MSG(2, ("<= skip parse certificate"));
        pf_mbedtls_ssl_handshake_increment_state(ssl);
        return 0;
    }

    PF_MBEDTLS_SSL_DEBUG_MSG(1, ("should never happen"));
    return PF_MBEDTLS_ERR_SSL_INTERNAL_ERROR;
}

#else /* MBEDTLS_KEY_EXCHANGE_WITH_CERT_ENABLED */
/* Some certificate support -> implement write and parse */

int pf_mbedtls_ssl_write_certificate(pf_mbedtls_ssl_context *ssl)
{
    int ret = PF_MBEDTLS_ERR_SSL_FEATURE_UNAVAILABLE;
    size_t i, n;
    const pf_mbedtls_x509_crt *crt;
    const pf_mbedtls_ssl_ciphersuite_t *ciphersuite_info =
        ssl->handshake->ciphersuite_info;

    PF_MBEDTLS_SSL_DEBUG_MSG(2, ("=> write certificate"));

    if (!pf_mbedtls_ssl_ciphersuite_uses_srv_cert(ciphersuite_info)) {
        PF_MBEDTLS_SSL_DEBUG_MSG(2, ("<= skip write certificate"));
        pf_mbedtls_ssl_handshake_increment_state(ssl);
        return 0;
    }

#if defined(PF_MBEDTLS_SSL_CLI_C)
    if (ssl->conf->endpoint == PF_MBEDTLS_SSL_IS_CLIENT) {
        if (ssl->handshake->client_auth == 0) {
            PF_MBEDTLS_SSL_DEBUG_MSG(2, ("<= skip write certificate"));
            pf_mbedtls_ssl_handshake_increment_state(ssl);
            return 0;
        }
    }
#endif /* MBEDTLS_SSL_CLI_C */
#if defined(PF_MBEDTLS_SSL_SRV_C)
    if (ssl->conf->endpoint == PF_MBEDTLS_SSL_IS_SERVER) {
        if (pf_mbedtls_ssl_own_cert(ssl) == NULL) {
            /* Should never happen because we shouldn't have picked the
             * ciphersuite if we don't have a certificate. */
            return PF_MBEDTLS_ERR_SSL_INTERNAL_ERROR;
        }
    }
#endif

    PF_MBEDTLS_SSL_DEBUG_CRT(3, "own certificate", pf_mbedtls_ssl_own_cert(ssl));

    /*
     *     0  .  0    handshake type
     *     1  .  3    handshake length
     *     4  .  6    length of all certs
     *     7  .  9    length of cert. 1
     *    10  . n-1   peer certificate
     *     n  . n+2   length of cert. 2
     *    n+3 . ...   upper level cert, etc.
     */
    i = 7;
    crt = pf_mbedtls_ssl_own_cert(ssl);

    while (crt != NULL) {
        n = crt->raw.len;
        if (n > PF_MBEDTLS_SSL_OUT_CONTENT_LEN - 3 - i) {
            PF_MBEDTLS_SSL_DEBUG_MSG(1, ("certificate too large, %" PF_MBEDTLS_PRINTF_SIZET
                                      " > %" PF_MBEDTLS_PRINTF_SIZET,
                                      i + 3 + n, (size_t) PF_MBEDTLS_SSL_OUT_CONTENT_LEN));
            return PF_MBEDTLS_ERR_SSL_BUFFER_TOO_SMALL;
        }

        ssl->out_msg[i] = PF_MBEDTLS_BYTE_2(n);
        ssl->out_msg[i + 1] = PF_MBEDTLS_BYTE_1(n);
        ssl->out_msg[i + 2] = PF_MBEDTLS_BYTE_0(n);

        i += 3; memcpy(ssl->out_msg + i, crt->raw.p, n);
        i += n; crt = crt->next;
    }

    ssl->out_msg[4]  = PF_MBEDTLS_BYTE_2(i - 7);
    ssl->out_msg[5]  = PF_MBEDTLS_BYTE_1(i - 7);
    ssl->out_msg[6]  = PF_MBEDTLS_BYTE_0(i - 7);

    ssl->out_msglen  = i;
    ssl->out_msgtype = PF_MBEDTLS_SSL_MSG_HANDSHAKE;
    ssl->out_msg[0]  = PF_MBEDTLS_SSL_HS_CERTIFICATE;

    pf_mbedtls_ssl_handshake_increment_state(ssl);

    if ((ret = pf_mbedtls_ssl_write_handshake_msg(ssl)) != 0) {
        PF_MBEDTLS_SSL_DEBUG_RET(1, "mbedtls_ssl_write_handshake_msg", ret);
        return ret;
    }

    PF_MBEDTLS_SSL_DEBUG_MSG(2, ("<= write certificate"));

    return ret;
}

#if defined(PF_MBEDTLS_SSL_RENEGOTIATION) && defined(PF_MBEDTLS_SSL_CLI_C)

#if defined(PF_MBEDTLS_SSL_KEEP_PEER_CERTIFICATE)
PF_MBEDTLS_CHECK_RETURN_CRITICAL
static int ssl_check_peer_crt_unchanged(pf_mbedtls_ssl_context *ssl,
                                        unsigned char *crt_buf,
                                        size_t crt_buf_len)
{
    pf_mbedtls_x509_crt const * const peer_crt = ssl->session->peer_cert;

    if (peer_crt == NULL) {
        return -1;
    }

    if (peer_crt->raw.len != crt_buf_len) {
        return -1;
    }

    return memcmp(peer_crt->raw.p, crt_buf, peer_crt->raw.len);
}
#else /* MBEDTLS_SSL_KEEP_PEER_CERTIFICATE */
PF_MBEDTLS_CHECK_RETURN_CRITICAL
static int ssl_check_peer_crt_unchanged(pf_mbedtls_ssl_context *ssl,
                                        unsigned char *crt_buf,
                                        size_t crt_buf_len)
{
    int ret = PF_MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    unsigned char const * const peer_cert_digest =
        ssl->session->peer_cert_digest;
    pf_mbedtls_md_type_t const peer_cert_digest_type =
        ssl->session->peer_cert_digest_type;
    pf_mbedtls_md_info_t const * const digest_info =
        pf_mbedtls_md_info_from_type(peer_cert_digest_type);
    unsigned char tmp_digest[PF_MBEDTLS_SSL_PEER_CERT_DIGEST_MAX_LEN];
    size_t digest_len;

    if (peer_cert_digest == NULL || digest_info == NULL) {
        return -1;
    }

    digest_len = pf_mbedtls_md_get_size(digest_info);
    if (digest_len > PF_MBEDTLS_SSL_PEER_CERT_DIGEST_MAX_LEN) {
        return -1;
    }

    ret = pf_mbedtls_md(digest_info, crt_buf, crt_buf_len, tmp_digest);
    if (ret != 0) {
        return -1;
    }

    return memcmp(tmp_digest, peer_cert_digest, digest_len);
}
#endif /* MBEDTLS_SSL_KEEP_PEER_CERTIFICATE */
#endif /* MBEDTLS_SSL_RENEGOTIATION && MBEDTLS_SSL_CLI_C */

/*
 * Once the certificate message is read, parse it into a cert chain and
 * perform basic checks, but leave actual verification to the caller
 */
PF_MBEDTLS_CHECK_RETURN_CRITICAL
static int ssl_parse_certificate_chain(pf_mbedtls_ssl_context *ssl,
                                       pf_mbedtls_x509_crt *chain)
{
    int ret = PF_MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
#if defined(PF_MBEDTLS_SSL_RENEGOTIATION) && defined(PF_MBEDTLS_SSL_CLI_C)
    int crt_cnt = 0;
#endif
    size_t i, n;
    uint8_t alert;

    if (ssl->in_msgtype != PF_MBEDTLS_SSL_MSG_HANDSHAKE) {
        PF_MBEDTLS_SSL_DEBUG_MSG(1, ("bad certificate message"));
        pf_mbedtls_ssl_send_alert_message(ssl, PF_MBEDTLS_SSL_ALERT_LEVEL_FATAL,
                                       PF_MBEDTLS_SSL_ALERT_MSG_UNEXPECTED_MESSAGE);
        return PF_MBEDTLS_ERR_SSL_UNEXPECTED_MESSAGE;
    }

    if (ssl->in_msg[0] != PF_MBEDTLS_SSL_HS_CERTIFICATE) {
        pf_mbedtls_ssl_send_alert_message(ssl, PF_MBEDTLS_SSL_ALERT_LEVEL_FATAL,
                                       PF_MBEDTLS_SSL_ALERT_MSG_UNEXPECTED_MESSAGE);
        return PF_MBEDTLS_ERR_SSL_UNEXPECTED_MESSAGE;
    }

    if (ssl->in_hslen < pf_mbedtls_ssl_hs_hdr_len(ssl) + 3 + 3) {
        PF_MBEDTLS_SSL_DEBUG_MSG(1, ("bad certificate message"));
        pf_mbedtls_ssl_send_alert_message(ssl, PF_MBEDTLS_SSL_ALERT_LEVEL_FATAL,
                                       PF_MBEDTLS_SSL_ALERT_MSG_DECODE_ERROR);
        return PF_MBEDTLS_ERR_SSL_DECODE_ERROR;
    }

    i = pf_mbedtls_ssl_hs_hdr_len(ssl);

    /*
     * Same message structure as in mbedtls_ssl_write_certificate()
     */
    n = PF_MBEDTLS_GET_UINT16_BE(ssl->in_msg, i + 1);

    if (ssl->in_msg[i] != 0 ||
        ssl->in_hslen != n + 3 + pf_mbedtls_ssl_hs_hdr_len(ssl)) {
        PF_MBEDTLS_SSL_DEBUG_MSG(1, ("bad certificate message"));
        pf_mbedtls_ssl_send_alert_message(ssl, PF_MBEDTLS_SSL_ALERT_LEVEL_FATAL,
                                       PF_MBEDTLS_SSL_ALERT_MSG_DECODE_ERROR);
        return PF_MBEDTLS_ERR_SSL_DECODE_ERROR;
    }

    /* Make &ssl->in_msg[i] point to the beginning of the CRT chain. */
    i += 3;

    /* Iterate through and parse the CRTs in the provided chain. */
    while (i < ssl->in_hslen) {
        /* Check that there's room for the next CRT's length fields. */
        if (i + 3 > ssl->in_hslen) {
            PF_MBEDTLS_SSL_DEBUG_MSG(1, ("bad certificate message"));
            pf_mbedtls_ssl_send_alert_message(ssl,
                                           PF_MBEDTLS_SSL_ALERT_LEVEL_FATAL,
                                           PF_MBEDTLS_SSL_ALERT_MSG_DECODE_ERROR);
            return PF_MBEDTLS_ERR_SSL_DECODE_ERROR;
        }
        /* In theory, the CRT can be up to 2**24 Bytes, but we don't support
         * anything beyond 2**16 ~ 64K. */
        if (ssl->in_msg[i] != 0) {
            PF_MBEDTLS_SSL_DEBUG_MSG(1, ("bad certificate message"));
            pf_mbedtls_ssl_send_alert_message(ssl,
                                           PF_MBEDTLS_SSL_ALERT_LEVEL_FATAL,
                                           PF_MBEDTLS_SSL_ALERT_MSG_UNSUPPORTED_CERT);
            return PF_MBEDTLS_ERR_SSL_BAD_CERTIFICATE;
        }

        /* Read length of the next CRT in the chain. */
        n = PF_MBEDTLS_GET_UINT16_BE(ssl->in_msg, i + 1);
        i += 3;

        if (n < 128 || i + n > ssl->in_hslen) {
            PF_MBEDTLS_SSL_DEBUG_MSG(1, ("bad certificate message"));
            pf_mbedtls_ssl_send_alert_message(ssl,
                                           PF_MBEDTLS_SSL_ALERT_LEVEL_FATAL,
                                           PF_MBEDTLS_SSL_ALERT_MSG_DECODE_ERROR);
            return PF_MBEDTLS_ERR_SSL_DECODE_ERROR;
        }

        /* Check if we're handling the first CRT in the chain. */
#if defined(PF_MBEDTLS_SSL_RENEGOTIATION) && defined(PF_MBEDTLS_SSL_CLI_C)
        if (crt_cnt++ == 0 &&
            ssl->conf->endpoint == PF_MBEDTLS_SSL_IS_CLIENT &&
            ssl->renego_status == PF_MBEDTLS_SSL_RENEGOTIATION_IN_PROGRESS) {
            /* During client-side renegotiation, check that the server's
             * end-CRTs hasn't changed compared to the initial handshake,
             * mitigating the triple handshake attack. On success, reuse
             * the original end-CRT instead of parsing it again. */
            PF_MBEDTLS_SSL_DEBUG_MSG(3, ("Check that peer CRT hasn't changed during renegotiation"));
            if (ssl_check_peer_crt_unchanged(ssl,
                                             &ssl->in_msg[i],
                                             n) != 0) {
                PF_MBEDTLS_SSL_DEBUG_MSG(1, ("new server cert during renegotiation"));
                pf_mbedtls_ssl_send_alert_message(ssl,
                                               PF_MBEDTLS_SSL_ALERT_LEVEL_FATAL,
                                               PF_MBEDTLS_SSL_ALERT_MSG_ACCESS_DENIED);
                return PF_MBEDTLS_ERR_SSL_BAD_CERTIFICATE;
            }

            /* Now we can safely free the original chain. */
            ssl_clear_peer_cert(ssl->session);
        }
#endif /* MBEDTLS_SSL_RENEGOTIATION && MBEDTLS_SSL_CLI_C */

        /* Parse the next certificate in the chain. */
#if defined(PF_MBEDTLS_SSL_KEEP_PEER_CERTIFICATE)
        ret = pf_mbedtls_x509_crt_parse_der(chain, ssl->in_msg + i, n);
#else
        /* If we don't need to store the CRT chain permanently, parse
         * it in-place from the input buffer instead of making a copy. */
        ret = pf_mbedtls_x509_crt_parse_der_nocopy(chain, ssl->in_msg + i, n);
#endif /* MBEDTLS_SSL_KEEP_PEER_CERTIFICATE */
        switch (ret) {
            case 0: /*ok*/
            case PF_MBEDTLS_ERR_X509_UNKNOWN_SIG_ALG + PF_MBEDTLS_ERR_OID_NOT_FOUND:
                /* Ignore certificate with an unknown algorithm: maybe a
                   prior certificate was already trusted. */
                break;

            case PF_MBEDTLS_ERR_X509_ALLOC_FAILED:
                alert = PF_MBEDTLS_SSL_ALERT_MSG_INTERNAL_ERROR;
                goto crt_parse_der_failed;

            case PF_MBEDTLS_ERR_X509_UNKNOWN_VERSION:
                alert = PF_MBEDTLS_SSL_ALERT_MSG_UNSUPPORTED_CERT;
                goto crt_parse_der_failed;

            default:
                alert = PF_MBEDTLS_SSL_ALERT_MSG_BAD_CERT;
crt_parse_der_failed:
                pf_mbedtls_ssl_send_alert_message(ssl, PF_MBEDTLS_SSL_ALERT_LEVEL_FATAL, alert);
                PF_MBEDTLS_SSL_DEBUG_RET(1, " mbedtls_x509_crt_parse_der", ret);
                return ret;
        }

        i += n;
    }

    PF_MBEDTLS_SSL_DEBUG_CRT(3, "peer certificate", chain);
    return 0;
}

#if defined(PF_MBEDTLS_SSL_SRV_C)
PF_MBEDTLS_CHECK_RETURN_CRITICAL
static int ssl_srv_check_client_no_crt_notification(pf_mbedtls_ssl_context *ssl)
{
    if (ssl->conf->endpoint == PF_MBEDTLS_SSL_IS_CLIENT) {
        return -1;
    }

    if (ssl->in_hslen   == 3 + pf_mbedtls_ssl_hs_hdr_len(ssl) &&
        ssl->in_msgtype == PF_MBEDTLS_SSL_MSG_HANDSHAKE    &&
        ssl->in_msg[0]  == PF_MBEDTLS_SSL_HS_CERTIFICATE   &&
        memcmp(ssl->in_msg + pf_mbedtls_ssl_hs_hdr_len(ssl), "\0\0\0", 3) == 0) {
        PF_MBEDTLS_SSL_DEBUG_MSG(1, ("peer has no certificate"));
        return 0;
    }
    return -1;
}
#endif /* MBEDTLS_SSL_SRV_C */

/* Check if a certificate message is expected.
 * Return either
 * - SSL_CERTIFICATE_EXPECTED, or
 * - SSL_CERTIFICATE_SKIP
 * indicating whether a Certificate message is expected or not.
 */
#define SSL_CERTIFICATE_EXPECTED 0
#define SSL_CERTIFICATE_SKIP     1
PF_MBEDTLS_CHECK_RETURN_CRITICAL
static int ssl_parse_certificate_coordinate(pf_mbedtls_ssl_context *ssl,
                                            int authmode)
{
    const pf_mbedtls_ssl_ciphersuite_t *ciphersuite_info =
        ssl->handshake->ciphersuite_info;

    if (!pf_mbedtls_ssl_ciphersuite_uses_srv_cert(ciphersuite_info)) {
        ssl->session_negotiate->verify_result = 0;
        return SSL_CERTIFICATE_SKIP;
    }

#if defined(PF_MBEDTLS_SSL_SRV_C)
    if (ssl->conf->endpoint == PF_MBEDTLS_SSL_IS_SERVER) {
        if (ciphersuite_info->key_exchange == PF_MBEDTLS_KEY_EXCHANGE_RSA_PSK) {
            return SSL_CERTIFICATE_SKIP;
        }

        if (authmode == PF_MBEDTLS_SSL_VERIFY_NONE) {
            ssl->session_negotiate->verify_result =
                PF_MBEDTLS_X509_BADCERT_SKIP_VERIFY;
            return SSL_CERTIFICATE_SKIP;
        }
    }
#else
    ((void) authmode);
#endif /* MBEDTLS_SSL_SRV_C */

    return SSL_CERTIFICATE_EXPECTED;
}

#if !defined(PF_MBEDTLS_SSL_KEEP_PEER_CERTIFICATE)
PF_MBEDTLS_CHECK_RETURN_CRITICAL
static int ssl_remember_peer_crt_digest(pf_mbedtls_ssl_context *ssl,
                                        unsigned char *start, size_t len)
{
    int ret = PF_MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    /* Remember digest of the peer's end-CRT. */
    ssl->session_negotiate->peer_cert_digest =
        pf_mbedtls_calloc(1, PF_MBEDTLS_SSL_PEER_CERT_DIGEST_DFL_LEN);
    if (ssl->session_negotiate->peer_cert_digest == NULL) {
        PF_MBEDTLS_SSL_DEBUG_MSG(1, ("alloc(%d bytes) failed",
                                  PF_MBEDTLS_SSL_PEER_CERT_DIGEST_DFL_LEN));
        pf_mbedtls_ssl_send_alert_message(ssl,
                                       PF_MBEDTLS_SSL_ALERT_LEVEL_FATAL,
                                       PF_MBEDTLS_SSL_ALERT_MSG_INTERNAL_ERROR);

        return PF_MBEDTLS_ERR_SSL_ALLOC_FAILED;
    }

    ret = pf_mbedtls_md(pf_mbedtls_md_info_from_type(
                         PF_MBEDTLS_SSL_PEER_CERT_DIGEST_DFL_TYPE),
                     start, len,
                     ssl->session_negotiate->peer_cert_digest);

    ssl->session_negotiate->peer_cert_digest_type =
        PF_MBEDTLS_SSL_PEER_CERT_DIGEST_DFL_TYPE;
    ssl->session_negotiate->peer_cert_digest_len =
        PF_MBEDTLS_SSL_PEER_CERT_DIGEST_DFL_LEN;

    return ret;
}

PF_MBEDTLS_CHECK_RETURN_CRITICAL
static int ssl_remember_peer_pubkey(pf_mbedtls_ssl_context *ssl,
                                    unsigned char *start, size_t len)
{
    unsigned char *end = start + len;
    int ret = PF_MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;

    /* Make a copy of the peer's raw public key. */
    pf_mbedtls_pk_init(&ssl->handshake->peer_pubkey);
    ret = pf_mbedtls_pk_parse_subpubkey(&start, end,
                                     &ssl->handshake->peer_pubkey);
    if (ret != 0) {
        /* We should have parsed the public key before. */
        return PF_MBEDTLS_ERR_SSL_INTERNAL_ERROR;
    }

    return 0;
}
#endif /* !MBEDTLS_SSL_KEEP_PEER_CERTIFICATE */

int pf_mbedtls_ssl_parse_certificate(pf_mbedtls_ssl_context *ssl)
{
    int ret = 0;
    int crt_expected;
    /* Authmode: precedence order is SNI if used else configuration */
#if defined(PF_MBEDTLS_SSL_SRV_C) && defined(PF_MBEDTLS_SSL_SERVER_NAME_INDICATION)
    const int authmode = ssl->handshake->sni_authmode != PF_MBEDTLS_SSL_VERIFY_UNSET
                       ? ssl->handshake->sni_authmode
                       : ssl->conf->authmode;
#else
    const int authmode = ssl->conf->authmode;
#endif
    void *rs_ctx = NULL;
    pf_mbedtls_x509_crt *chain = NULL;

    PF_MBEDTLS_SSL_DEBUG_MSG(2, ("=> parse certificate"));

    crt_expected = ssl_parse_certificate_coordinate(ssl, authmode);
    if (crt_expected == SSL_CERTIFICATE_SKIP) {
        PF_MBEDTLS_SSL_DEBUG_MSG(2, ("<= skip parse certificate"));
        goto exit;
    }

#if defined(PF_MBEDTLS_SSL_ECP_RESTARTABLE_ENABLED)
    if (ssl->handshake->ecrs_enabled &&
        ssl->handshake->ecrs_state == ssl_ecrs_crt_verify) {
        chain = ssl->handshake->ecrs_peer_cert;
        ssl->handshake->ecrs_peer_cert = NULL;
        goto crt_verify;
    }
#endif

    if ((ret = pf_mbedtls_ssl_read_record(ssl, 1)) != 0) {
        /* mbedtls_ssl_read_record may have sent an alert already. We
           let it decide whether to alert. */
        PF_MBEDTLS_SSL_DEBUG_RET(1, "mbedtls_ssl_read_record", ret);
        goto exit;
    }

#if defined(PF_MBEDTLS_SSL_SRV_C)
    if (ssl_srv_check_client_no_crt_notification(ssl) == 0) {
        ssl->session_negotiate->verify_result = PF_MBEDTLS_X509_BADCERT_MISSING;

        if (authmode != PF_MBEDTLS_SSL_VERIFY_OPTIONAL) {
            ret = PF_MBEDTLS_ERR_SSL_NO_CLIENT_CERTIFICATE;
        }

        goto exit;
    }
#endif /* MBEDTLS_SSL_SRV_C */

    /* Clear existing peer CRT structure in case we tried to
     * reuse a session but it failed, and allocate a new one. */
    ssl_clear_peer_cert(ssl->session_negotiate);

    chain = pf_mbedtls_calloc(1, sizeof(pf_mbedtls_x509_crt));
    if (chain == NULL) {
        PF_MBEDTLS_SSL_DEBUG_MSG(1, ("alloc(%" PF_MBEDTLS_PRINTF_SIZET " bytes) failed",
                                  sizeof(pf_mbedtls_x509_crt)));
        pf_mbedtls_ssl_send_alert_message(ssl,
                                       PF_MBEDTLS_SSL_ALERT_LEVEL_FATAL,
                                       PF_MBEDTLS_SSL_ALERT_MSG_INTERNAL_ERROR);

        ret = PF_MBEDTLS_ERR_SSL_ALLOC_FAILED;
        goto exit;
    }
    pf_mbedtls_x509_crt_init(chain);

    ret = ssl_parse_certificate_chain(ssl, chain);
    if (ret != 0) {
        goto exit;
    }

#if defined(PF_MBEDTLS_SSL_ECP_RESTARTABLE_ENABLED)
    if (ssl->handshake->ecrs_enabled) {
        ssl->handshake->ecrs_state = ssl_ecrs_crt_verify;
    }

crt_verify:
    if (ssl->handshake->ecrs_enabled) {
        rs_ctx = &ssl->handshake->ecrs_ctx;
    }
#endif

    ret = pf_mbedtls_ssl_verify_certificate(ssl, authmode, chain,
                                         ssl->handshake->ciphersuite_info,
                                         rs_ctx);
    if (ret != 0) {
        goto exit;
    }

#if !defined(PF_MBEDTLS_SSL_KEEP_PEER_CERTIFICATE)
    {
        unsigned char *crt_start, *pk_start;
        size_t crt_len, pk_len;

        /* We parse the CRT chain without copying, so
         * these pointers point into the input buffer,
         * and are hence still valid after freeing the
         * CRT chain. */

        crt_start = chain->raw.p;
        crt_len   = chain->raw.len;

        pk_start = chain->pk_raw.p;
        pk_len   = chain->pk_raw.len;

        /* Free the CRT structures before computing
         * digest and copying the peer's public key. */
        pf_mbedtls_x509_crt_free(chain);
        pf_mbedtls_free(chain);
        chain = NULL;

        ret = ssl_remember_peer_crt_digest(ssl, crt_start, crt_len);
        if (ret != 0) {
            goto exit;
        }

        ret = ssl_remember_peer_pubkey(ssl, pk_start, pk_len);
        if (ret != 0) {
            goto exit;
        }
    }
#else /* !MBEDTLS_SSL_KEEP_PEER_CERTIFICATE */
    /* Pass ownership to session structure. */
    ssl->session_negotiate->peer_cert = chain;
    chain = NULL;
#endif /* MBEDTLS_SSL_KEEP_PEER_CERTIFICATE */

    PF_MBEDTLS_SSL_DEBUG_MSG(2, ("<= parse certificate"));

exit:

    if (ret == 0) {
        pf_mbedtls_ssl_handshake_increment_state(ssl);
    }

#if defined(PF_MBEDTLS_SSL_ECP_RESTARTABLE_ENABLED)
    if (ret == PF_MBEDTLS_ERR_SSL_CRYPTO_IN_PROGRESS) {
        ssl->handshake->ecrs_peer_cert = chain;
        chain = NULL;
    }
#endif

    if (chain != NULL) {
        pf_mbedtls_x509_crt_free(chain);
        pf_mbedtls_free(chain);
    }

    return ret;
}
#endif /* MBEDTLS_KEY_EXCHANGE_WITH_CERT_ENABLED */

static int ssl_calc_finished_tls_generic(pf_mbedtls_ssl_context *ssl, void *ctx,
                                         unsigned char *padbuf, size_t hlen,
                                         unsigned char *buf, int from)
{
    unsigned int len = 12;
    const char *sender;
#if defined(PF_MBEDTLS_USE_PSA_CRYPTO)
    pf_psa_status_t status;
    pf_psa_hash_operation_t *hs_op = ctx;
    pf_psa_hash_operation_t cloned_op = PF_PSA_HASH_OPERATION_INIT;
    size_t hash_size;
#else
    int ret = PF_MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    pf_mbedtls_md_context_t *hs_ctx = ctx;
    pf_mbedtls_md_context_t cloned_ctx;
    pf_mbedtls_md_init(&cloned_ctx);
#endif

    pf_mbedtls_ssl_session *session = ssl->session_negotiate;
    if (!session) {
        session = ssl->session;
    }

    sender = (from == PF_MBEDTLS_SSL_IS_CLIENT)
             ? "client finished"
             : "server finished";

#if defined(PF_MBEDTLS_USE_PSA_CRYPTO)
    PF_MBEDTLS_SSL_DEBUG_MSG(2, ("=> calc PSA finished tls"));

    status = pf_psa_hash_clone(hs_op, &cloned_op);
    if (status != PF_PSA_SUCCESS) {
        goto exit;
    }

    status = pf_psa_hash_finish(&cloned_op, padbuf, hlen, &hash_size);
    if (status != PF_PSA_SUCCESS) {
        goto exit;
    }
    PF_MBEDTLS_SSL_DEBUG_BUF(3, "PSA calculated padbuf", padbuf, hlen);
#else
    PF_MBEDTLS_SSL_DEBUG_MSG(2, ("=> calc finished tls"));

    ret = pf_mbedtls_md_setup(&cloned_ctx, pf_mbedtls_md_info_from_ctx(hs_ctx), 0);
    if (ret != 0) {
        goto exit;
    }
    ret = pf_mbedtls_md_clone(&cloned_ctx, hs_ctx);
    if (ret != 0) {
        goto exit;
    }

    ret = pf_mbedtls_md_finish(&cloned_ctx, padbuf);
    if (ret != 0) {
        goto exit;
    }
#endif /* MBEDTLS_USE_PSA_CRYPTO */

    PF_MBEDTLS_SSL_DEBUG_BUF(4, "finished output", padbuf, hlen);

    /*
     * TLSv1.2:
     *   hash = PRF( master, finished_label,
     *               Hash( handshake ) )[0.11]
     */
    ssl->handshake->tls_prf(session->master, 48, sender,
                            padbuf, hlen, buf, len);

    PF_MBEDTLS_SSL_DEBUG_BUF(3, "calc finished result", buf, len);

    pf_mbedtls_platform_zeroize(padbuf, hlen);

    PF_MBEDTLS_SSL_DEBUG_MSG(2, ("<= calc finished"));

exit:
#if defined(PF_MBEDTLS_USE_PSA_CRYPTO)
    pf_psa_hash_abort(&cloned_op);
    return PF_PSA_TO_MBEDTLS_ERR(status);
#else
    pf_mbedtls_md_free(&cloned_ctx);
    return ret;
#endif /* MBEDTLS_USE_PSA_CRYPTO */
}

#if defined(PF_MBEDTLS_MD_CAN_SHA256)
static int ssl_calc_finished_tls_sha256(
    pf_mbedtls_ssl_context *ssl, unsigned char *buf, int from)
{
    unsigned char padbuf[32];
    return ssl_calc_finished_tls_generic(ssl,
#if defined(PF_MBEDTLS_USE_PSA_CRYPTO)
                                         &ssl->handshake->fin_sha256_psa,
#else
                                         &ssl->handshake->fin_sha256,
#endif
                                         padbuf, sizeof(padbuf),
                                         buf, from);
}
#endif /* MBEDTLS_MD_CAN_SHA256*/


#if defined(PF_MBEDTLS_MD_CAN_SHA384)
static int ssl_calc_finished_tls_sha384(
    pf_mbedtls_ssl_context *ssl, unsigned char *buf, int from)
{
    unsigned char padbuf[48];
    return ssl_calc_finished_tls_generic(ssl,
#if defined(PF_MBEDTLS_USE_PSA_CRYPTO)
                                         &ssl->handshake->fin_sha384_psa,
#else
                                         &ssl->handshake->fin_sha384,
#endif
                                         padbuf, sizeof(padbuf),
                                         buf, from);
}
#endif /* MBEDTLS_MD_CAN_SHA384*/

void pf_mbedtls_ssl_handshake_wrapup_free_hs_transform(pf_mbedtls_ssl_context *ssl)
{
    PF_MBEDTLS_SSL_DEBUG_MSG(3, ("=> handshake wrapup: final free"));

    /*
     * Free our handshake params
     */
    pf_mbedtls_ssl_handshake_free(ssl);
    pf_mbedtls_free(ssl->handshake);
    ssl->handshake = NULL;

    /*
     * Free the previous transform and switch in the current one
     */
    if (ssl->transform) {
        pf_mbedtls_ssl_transform_free(ssl->transform);
        pf_mbedtls_free(ssl->transform);
    }
    ssl->transform = ssl->transform_negotiate;
    ssl->transform_negotiate = NULL;

    PF_MBEDTLS_SSL_DEBUG_MSG(3, ("<= handshake wrapup: final free"));
}

void pf_mbedtls_ssl_handshake_wrapup(pf_mbedtls_ssl_context *ssl)
{
    int resume = ssl->handshake->resume;

    PF_MBEDTLS_SSL_DEBUG_MSG(3, ("=> handshake wrapup"));

#if defined(PF_MBEDTLS_SSL_RENEGOTIATION)
    if (ssl->renego_status == PF_MBEDTLS_SSL_RENEGOTIATION_IN_PROGRESS) {
        ssl->renego_status =  PF_MBEDTLS_SSL_RENEGOTIATION_DONE;
        ssl->renego_records_seen = 0;
    }
#endif

    /*
     * Free the previous session and switch in the current one
     */
    if (ssl->session) {
#if defined(PF_MBEDTLS_SSL_ENCRYPT_THEN_MAC)
        /* RFC 7366 3.1: keep the EtM state */
        ssl->session_negotiate->encrypt_then_mac =
            ssl->session->encrypt_then_mac;
#endif

        pf_mbedtls_ssl_session_free(ssl->session);
        pf_mbedtls_free(ssl->session);
    }
    ssl->session = ssl->session_negotiate;
    ssl->session_negotiate = NULL;

    /*
     * Add cache entry
     */
    if (ssl->conf->f_set_cache != NULL &&
        ssl->session->id_len != 0 &&
        resume == 0) {
        if (ssl->conf->f_set_cache(ssl->conf->p_cache,
                                   ssl->session->id,
                                   ssl->session->id_len,
                                   ssl->session) != 0) {
            PF_MBEDTLS_SSL_DEBUG_MSG(1, ("cache did not store session"));
        }
    }

#if defined(PF_MBEDTLS_SSL_PROTO_DTLS)
    if (ssl->conf->transport == PF_MBEDTLS_SSL_TRANSPORT_DATAGRAM &&
        ssl->handshake->flight != NULL) {
        /* Cancel handshake timer */
        pf_mbedtls_ssl_set_timer(ssl, 0);

        /* Keep last flight around in case we need to resend it:
         * we need the handshake and transform structures for that */
        PF_MBEDTLS_SSL_DEBUG_MSG(3, ("skip freeing handshake and transform"));
    } else
#endif
    pf_mbedtls_ssl_handshake_wrapup_free_hs_transform(ssl);

    pf_mbedtls_ssl_handshake_set_state(ssl, PF_MBEDTLS_SSL_HANDSHAKE_OVER);

    PF_MBEDTLS_SSL_DEBUG_MSG(3, ("<= handshake wrapup"));
}

int pf_mbedtls_ssl_write_finished(pf_mbedtls_ssl_context *ssl)
{
    int ret;
    unsigned int hash_len;

    PF_MBEDTLS_SSL_DEBUG_MSG(2, ("=> write finished"));

    pf_mbedtls_ssl_update_out_pointers(ssl, ssl->transform_negotiate);

    ret = ssl->handshake->calc_finished(ssl, ssl->out_msg + 4, ssl->conf->endpoint);
    if (ret != 0) {
        PF_MBEDTLS_SSL_DEBUG_RET(1, "calc_finished", ret);
        return ret;
    }

    /*
     * RFC 5246 7.4.9 (Page 63) says 12 is the default length and ciphersuites
     * may define some other value. Currently (early 2016), no defined
     * ciphersuite does this (and this is unlikely to change as activity has
     * moved to TLS 1.3 now) so we can keep the hardcoded 12 here.
     */
    hash_len = 12;

#if defined(PF_MBEDTLS_SSL_RENEGOTIATION)
    ssl->verify_data_len = hash_len;
    memcpy(ssl->own_verify_data, ssl->out_msg + 4, hash_len);
#endif

    ssl->out_msglen  = 4 + hash_len;
    ssl->out_msgtype = PF_MBEDTLS_SSL_MSG_HANDSHAKE;
    ssl->out_msg[0]  = PF_MBEDTLS_SSL_HS_FINISHED;

    /*
     * In case of session resuming, invert the client and server
     * ChangeCipherSpec messages order.
     */
    if (ssl->handshake->resume != 0) {
#if defined(PF_MBEDTLS_SSL_CLI_C)
        if (ssl->conf->endpoint == PF_MBEDTLS_SSL_IS_CLIENT) {
            pf_mbedtls_ssl_handshake_set_state(ssl, PF_MBEDTLS_SSL_HANDSHAKE_WRAPUP);
        }
#endif
#if defined(PF_MBEDTLS_SSL_SRV_C)
        if (ssl->conf->endpoint == PF_MBEDTLS_SSL_IS_SERVER) {
            pf_mbedtls_ssl_handshake_set_state(ssl, PF_MBEDTLS_SSL_CLIENT_CHANGE_CIPHER_SPEC);
        }
#endif
    } else {
        pf_mbedtls_ssl_handshake_increment_state(ssl);
    }

    /*
     * Switch to our negotiated transform and session parameters for outbound
     * data.
     */
    PF_MBEDTLS_SSL_DEBUG_MSG(3, ("switching to new transform spec for outbound data"));

#if defined(PF_MBEDTLS_SSL_PROTO_DTLS)
    if (ssl->conf->transport == PF_MBEDTLS_SSL_TRANSPORT_DATAGRAM) {
        unsigned char i;

        /* Remember current epoch settings for resending */
        ssl->handshake->alt_transform_out = ssl->transform_out;
        memcpy(ssl->handshake->alt_out_ctr, ssl->cur_out_ctr,
               sizeof(ssl->handshake->alt_out_ctr));

        /* Set sequence_number to zero */
        memset(&ssl->cur_out_ctr[2], 0, sizeof(ssl->cur_out_ctr) - 2);


        /* Increment epoch */
        for (i = 2; i > 0; i--) {
            if (++ssl->cur_out_ctr[i - 1] != 0) {
                break;
            }
        }

        /* The loop goes to its end iff the counter is wrapping */
        if (i == 0) {
            PF_MBEDTLS_SSL_DEBUG_MSG(1, ("DTLS epoch would wrap"));
            return PF_MBEDTLS_ERR_SSL_COUNTER_WRAPPING;
        }
    } else
#endif /* MBEDTLS_SSL_PROTO_DTLS */
    memset(ssl->cur_out_ctr, 0, sizeof(ssl->cur_out_ctr));

    ssl->transform_out = ssl->transform_negotiate;
    ssl->session_out = ssl->session_negotiate;

#if defined(PF_MBEDTLS_SSL_PROTO_DTLS)
    if (ssl->conf->transport == PF_MBEDTLS_SSL_TRANSPORT_DATAGRAM) {
        pf_mbedtls_ssl_send_flight_completed(ssl);
    }
#endif

    if ((ret = pf_mbedtls_ssl_write_handshake_msg(ssl)) != 0) {
        PF_MBEDTLS_SSL_DEBUG_RET(1, "mbedtls_ssl_write_handshake_msg", ret);
        return ret;
    }

#if defined(PF_MBEDTLS_SSL_PROTO_DTLS)
    if (ssl->conf->transport == PF_MBEDTLS_SSL_TRANSPORT_DATAGRAM &&
        (ret = pf_mbedtls_ssl_flight_transmit(ssl)) != 0) {
        PF_MBEDTLS_SSL_DEBUG_RET(1, "mbedtls_ssl_flight_transmit", ret);
        return ret;
    }
#endif

    PF_MBEDTLS_SSL_DEBUG_MSG(2, ("<= write finished"));

    return 0;
}

#define SSL_MAX_HASH_LEN 12

int pf_mbedtls_ssl_parse_finished(pf_mbedtls_ssl_context *ssl)
{
    int ret = PF_MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    unsigned int hash_len = 12;
    unsigned char buf[SSL_MAX_HASH_LEN];

    PF_MBEDTLS_SSL_DEBUG_MSG(2, ("=> parse finished"));

    ret = ssl->handshake->calc_finished(ssl, buf, ssl->conf->endpoint ^ 1);
    if (ret != 0) {
        PF_MBEDTLS_SSL_DEBUG_RET(1, "calc_finished", ret);
        return ret;
    }

    if ((ret = pf_mbedtls_ssl_read_record(ssl, 1)) != 0) {
        PF_MBEDTLS_SSL_DEBUG_RET(1, "mbedtls_ssl_read_record", ret);
        goto exit;
    }

    if (ssl->in_msgtype != PF_MBEDTLS_SSL_MSG_HANDSHAKE) {
        PF_MBEDTLS_SSL_DEBUG_MSG(1, ("bad finished message"));
        pf_mbedtls_ssl_send_alert_message(ssl, PF_MBEDTLS_SSL_ALERT_LEVEL_FATAL,
                                       PF_MBEDTLS_SSL_ALERT_MSG_UNEXPECTED_MESSAGE);
        ret = PF_MBEDTLS_ERR_SSL_UNEXPECTED_MESSAGE;
        goto exit;
    }

    if (ssl->in_msg[0] != PF_MBEDTLS_SSL_HS_FINISHED) {
        pf_mbedtls_ssl_send_alert_message(ssl, PF_MBEDTLS_SSL_ALERT_LEVEL_FATAL,
                                       PF_MBEDTLS_SSL_ALERT_MSG_UNEXPECTED_MESSAGE);
        ret = PF_MBEDTLS_ERR_SSL_UNEXPECTED_MESSAGE;
        goto exit;
    }

    if (ssl->in_hslen  != pf_mbedtls_ssl_hs_hdr_len(ssl) + hash_len) {
        PF_MBEDTLS_SSL_DEBUG_MSG(1, ("bad finished message"));
        pf_mbedtls_ssl_send_alert_message(ssl, PF_MBEDTLS_SSL_ALERT_LEVEL_FATAL,
                                       PF_MBEDTLS_SSL_ALERT_MSG_DECODE_ERROR);
        ret = PF_MBEDTLS_ERR_SSL_DECODE_ERROR;
        goto exit;
    }

    if (pf_mbedtls_ct_memcmp(ssl->in_msg + pf_mbedtls_ssl_hs_hdr_len(ssl),
                          buf, hash_len) != 0) {
        PF_MBEDTLS_SSL_DEBUG_MSG(1, ("bad finished message"));
        pf_mbedtls_ssl_send_alert_message(ssl, PF_MBEDTLS_SSL_ALERT_LEVEL_FATAL,
                                       PF_MBEDTLS_SSL_ALERT_MSG_DECRYPT_ERROR);
        ret = PF_MBEDTLS_ERR_SSL_HANDSHAKE_FAILURE;
        goto exit;
    }

#if defined(PF_MBEDTLS_SSL_RENEGOTIATION)
    ssl->verify_data_len = hash_len;
    memcpy(ssl->peer_verify_data, buf, hash_len);
#endif

    if (ssl->handshake->resume != 0) {
#if defined(PF_MBEDTLS_SSL_CLI_C)
        if (ssl->conf->endpoint == PF_MBEDTLS_SSL_IS_CLIENT) {
            pf_mbedtls_ssl_handshake_set_state(ssl, PF_MBEDTLS_SSL_CLIENT_CHANGE_CIPHER_SPEC);
        }
#endif
#if defined(PF_MBEDTLS_SSL_SRV_C)
        if (ssl->conf->endpoint == PF_MBEDTLS_SSL_IS_SERVER) {
            pf_mbedtls_ssl_handshake_set_state(ssl, PF_MBEDTLS_SSL_HANDSHAKE_WRAPUP);
        }
#endif
    } else {
        pf_mbedtls_ssl_handshake_increment_state(ssl);
    }

#if defined(PF_MBEDTLS_SSL_PROTO_DTLS)
    if (ssl->conf->transport == PF_MBEDTLS_SSL_TRANSPORT_DATAGRAM) {
        pf_mbedtls_ssl_recv_flight_completed(ssl);
    }
#endif

    PF_MBEDTLS_SSL_DEBUG_MSG(2, ("<= parse finished"));

exit:
    pf_mbedtls_platform_zeroize(buf, hash_len);
    return ret;
}

#if defined(PF_MBEDTLS_SSL_CONTEXT_SERIALIZATION)
/*
 * Helper to get TLS 1.2 PRF from ciphersuite
 * (Duplicates bits of logic from ssl_set_handshake_prfs().)
 */
static tls_prf_fn ssl_tls12prf_from_cs(int ciphersuite_id)
{
    const pf_mbedtls_ssl_ciphersuite_t * const ciphersuite_info =
        pf_mbedtls_ssl_ciphersuite_from_id(ciphersuite_id);
#if defined(PF_MBEDTLS_MD_CAN_SHA384)
    if (ciphersuite_info != NULL && ciphersuite_info->mac == PF_MBEDTLS_MD_SHA384) {
        return tls_prf_sha384;
    } else
#endif
#if defined(PF_MBEDTLS_MD_CAN_SHA256)
    {
        if (ciphersuite_info != NULL && ciphersuite_info->mac == PF_MBEDTLS_MD_SHA256) {
            return tls_prf_sha256;
        }
    }
#endif
#if !defined(PF_MBEDTLS_MD_CAN_SHA384) && \
    !defined(PF_MBEDTLS_MD_CAN_SHA256)
    (void) ciphersuite_info;
#endif

    return NULL;
}
#endif /* MBEDTLS_SSL_CONTEXT_SERIALIZATION */

static pf_mbedtls_tls_prf_types tls_prf_get_type(pf_mbedtls_ssl_tls_prf_cb *tls_prf)
{
    ((void) tls_prf);
#if defined(PF_MBEDTLS_MD_CAN_SHA384)
    if (tls_prf == tls_prf_sha384) {
        return PF_MBEDTLS_SSL_TLS_PRF_SHA384;
    } else
#endif
#if defined(PF_MBEDTLS_MD_CAN_SHA256)
    if (tls_prf == tls_prf_sha256) {
        return PF_MBEDTLS_SSL_TLS_PRF_SHA256;
    } else
#endif
    return PF_MBEDTLS_SSL_TLS_PRF_NONE;
}

/*
 * Populate a transform structure with session keys and all the other
 * necessary information.
 *
 * Parameters:
 * - [in/out]: transform: structure to populate
 *      [in] must be just initialised with mbedtls_ssl_transform_init()
 *      [out] fully populated, ready for use by mbedtls_ssl_{en,de}crypt_buf()
 * - [in] ciphersuite
 * - [in] master
 * - [in] encrypt_then_mac
 * - [in] tls_prf: pointer to PRF to use for key derivation
 * - [in] randbytes: buffer holding ServerHello.random + ClientHello.random
 * - [in] tls_version: TLS version
 * - [in] endpoint: client or server
 * - [in] ssl: used for:
 *        - ssl->conf->{f,p}_export_keys
 *      [in] optionally used for:
 *        - MBEDTLS_DEBUG_C: ssl->conf->{f,p}_dbg
 */
PF_MBEDTLS_CHECK_RETURN_CRITICAL
static int ssl_tls12_populate_transform(pf_mbedtls_ssl_transform *transform,
                                        int ciphersuite,
                                        const unsigned char master[48],
#if defined(PF_MBEDTLS_SSL_SOME_SUITES_USE_CBC_ETM)
                                        int encrypt_then_mac,
#endif /* MBEDTLS_SSL_SOME_SUITES_USE_CBC_ETM */
                                        ssl_tls_prf_t tls_prf,
                                        const unsigned char randbytes[64],
                                        pf_mbedtls_ssl_protocol_version tls_version,
                                        unsigned endpoint,
                                        const pf_mbedtls_ssl_context *ssl)
{
    int ret = 0;
    unsigned char keyblk[256];
    unsigned char *key1;
    unsigned char *key2;
    unsigned char *mac_enc;
    unsigned char *mac_dec;
    size_t mac_key_len = 0;
    size_t iv_copy_len;
    size_t keylen;
    const pf_mbedtls_ssl_ciphersuite_t *ciphersuite_info;
    pf_mbedtls_ssl_mode_t ssl_mode;
#if !defined(PF_MBEDTLS_USE_PSA_CRYPTO)
    const pf_mbedtls_cipher_info_t *cipher_info;
    const pf_mbedtls_md_info_t *md_info;
#endif /* !MBEDTLS_USE_PSA_CRYPTO */

#if defined(PF_MBEDTLS_USE_PSA_CRYPTO)
    pf_psa_key_type_t key_type;
    pf_psa_key_attributes_t attributes = PF_PSA_KEY_ATTRIBUTES_INIT;
    pf_psa_algorithm_t alg;
    pf_psa_algorithm_t mac_alg = 0;
    size_t key_bits;
    pf_psa_status_t status = PF_PSA_ERROR_CORRUPTION_DETECTED;
#endif

    /*
     * Some data just needs copying into the structure
     */
#if defined(PF_MBEDTLS_SSL_SOME_SUITES_USE_CBC_ETM)
    transform->encrypt_then_mac = encrypt_then_mac;
#endif /* MBEDTLS_SSL_SOME_SUITES_USE_CBC_ETM */
    transform->tls_version = tls_version;

#if defined(PF_MBEDTLS_SSL_KEEP_RANDBYTES)
    memcpy(transform->randbytes, randbytes, sizeof(transform->randbytes));
#endif

#if defined(PF_MBEDTLS_SSL_PROTO_TLS1_3)
    if (tls_version == PF_MBEDTLS_SSL_VERSION_TLS1_3) {
        /* At the moment, we keep TLS <= 1.2 and TLS 1.3 transform
         * generation separate. This should never happen. */
        return PF_MBEDTLS_ERR_SSL_INTERNAL_ERROR;
    }
#endif /* MBEDTLS_SSL_PROTO_TLS1_3 */

    /*
     * Get various info structures
     */
    ciphersuite_info = pf_mbedtls_ssl_ciphersuite_from_id(ciphersuite);
    if (ciphersuite_info == NULL) {
        PF_MBEDTLS_SSL_DEBUG_MSG(1, ("ciphersuite info for %d not found",
                                  ciphersuite));
        return PF_MBEDTLS_ERR_SSL_BAD_INPUT_DATA;
    }

    ssl_mode = pf_mbedtls_ssl_get_mode_from_ciphersuite(
#if defined(PF_MBEDTLS_SSL_SOME_SUITES_USE_CBC_ETM)
        encrypt_then_mac,
#endif /* MBEDTLS_SSL_SOME_SUITES_USE_CBC_ETM */
        ciphersuite_info);

    if (ssl_mode == PF_MBEDTLS_SSL_MODE_AEAD) {
        transform->taglen =
            ciphersuite_info->flags & PF_MBEDTLS_CIPHERSUITE_SHORT_TAG ? 8 : 16;
    }

#if defined(PF_MBEDTLS_USE_PSA_CRYPTO)
    if ((status = pf_mbedtls_ssl_cipher_to_psa((pf_mbedtls_cipher_type_t) ciphersuite_info->cipher,
                                            transform->taglen,
                                            &alg,
                                            &key_type,
                                            &key_bits)) != PF_PSA_SUCCESS) {
        ret = PF_PSA_TO_MBEDTLS_ERR(status);
        PF_MBEDTLS_SSL_DEBUG_RET(1, "mbedtls_ssl_cipher_to_psa", ret);
        goto end;
    }
#else
    cipher_info = pf_mbedtls_cipher_info_from_type((pf_mbedtls_cipher_type_t) ciphersuite_info->cipher);
    if (cipher_info == NULL) {
        PF_MBEDTLS_SSL_DEBUG_MSG(1, ("cipher info for %u not found",
                                  ciphersuite_info->cipher));
        return PF_MBEDTLS_ERR_SSL_BAD_INPUT_DATA;
    }
#endif /* MBEDTLS_USE_PSA_CRYPTO */

#if defined(PF_MBEDTLS_USE_PSA_CRYPTO)
    mac_alg = pf_mbedtls_md_psa_alg_from_type((pf_mbedtls_md_type_t) ciphersuite_info->mac);
    if (mac_alg == 0) {
        PF_MBEDTLS_SSL_DEBUG_MSG(1, ("mbedtls_md_psa_alg_from_type for %u not found",
                                  (unsigned) ciphersuite_info->mac));
        return PF_MBEDTLS_ERR_SSL_BAD_INPUT_DATA;
    }
#else
    md_info = pf_mbedtls_md_info_from_type((pf_mbedtls_md_type_t) ciphersuite_info->mac);
    if (md_info == NULL) {
        PF_MBEDTLS_SSL_DEBUG_MSG(1, ("mbedtls_md info for %u not found",
                                  (unsigned) ciphersuite_info->mac));
        return PF_MBEDTLS_ERR_SSL_BAD_INPUT_DATA;
    }
#endif /* MBEDTLS_USE_PSA_CRYPTO */

#if defined(PF_MBEDTLS_SSL_DTLS_CONNECTION_ID)
    /* Copy own and peer's CID if the use of the CID
     * extension has been negotiated. */
    if (ssl->handshake->cid_in_use == PF_MBEDTLS_SSL_CID_ENABLED) {
        PF_MBEDTLS_SSL_DEBUG_MSG(3, ("Copy CIDs into SSL transform"));

        transform->in_cid_len = ssl->own_cid_len;
        memcpy(transform->in_cid, ssl->own_cid, ssl->own_cid_len);
        PF_MBEDTLS_SSL_DEBUG_BUF(3, "Incoming CID", transform->in_cid,
                              transform->in_cid_len);

        transform->out_cid_len = ssl->handshake->peer_cid_len;
        memcpy(transform->out_cid, ssl->handshake->peer_cid,
               ssl->handshake->peer_cid_len);
        PF_MBEDTLS_SSL_DEBUG_BUF(3, "Outgoing CID", transform->out_cid,
                              transform->out_cid_len);
    }
#endif /* MBEDTLS_SSL_DTLS_CONNECTION_ID */

    /*
     * Compute key block using the PRF
     */
    ret = tls_prf(master, 48, "key expansion", randbytes, 64, keyblk, 256);
    if (ret != 0) {
        PF_MBEDTLS_SSL_DEBUG_RET(1, "prf", ret);
        return ret;
    }

    PF_MBEDTLS_SSL_DEBUG_MSG(3, ("ciphersuite = %s",
                              pf_mbedtls_ssl_get_ciphersuite_name(ciphersuite)));
    PF_MBEDTLS_SSL_DEBUG_BUF(3, "master secret", master, 48);
    PF_MBEDTLS_SSL_DEBUG_BUF(4, "random bytes", randbytes, 64);
    PF_MBEDTLS_SSL_DEBUG_BUF(4, "key block", keyblk, 256);

    /*
     * Determine the appropriate key, IV and MAC length.
     */

#if defined(PF_MBEDTLS_USE_PSA_CRYPTO)
    keylen = PF_PSA_BITS_TO_BYTES(key_bits);
#else
    keylen = pf_mbedtls_cipher_info_get_key_bitlen(cipher_info) / 8;
#endif

#if defined(PF_MBEDTLS_SSL_HAVE_AEAD)
    if (ssl_mode == PF_MBEDTLS_SSL_MODE_AEAD) {
        size_t explicit_ivlen;

        transform->maclen = 0;
        mac_key_len = 0;

        /* All modes haves 96-bit IVs, but the length of the static parts vary
         * with mode and version:
         * - For GCM and CCM in TLS 1.2, there's a static IV of 4 Bytes
         *   (to be concatenated with a dynamically chosen IV of 8 Bytes)
         * - For ChaChaPoly in TLS 1.2, and all modes in TLS 1.3, there's
         *   a static IV of 12 Bytes (to be XOR'ed with the 8 Byte record
         *   sequence number).
         */
        transform->ivlen = 12;

        int is_chachapoly = 0;
#if defined(PF_MBEDTLS_USE_PSA_CRYPTO)
        is_chachapoly = (key_type == PF_PSA_KEY_TYPE_CHACHA20);
#else
        is_chachapoly = (pf_mbedtls_cipher_info_get_mode(cipher_info)
                         == PF_MBEDTLS_MODE_CHACHAPOLY);
#endif /* MBEDTLS_USE_PSA_CRYPTO */

        if (is_chachapoly) {
            transform->fixed_ivlen = 12;
        } else {
            transform->fixed_ivlen = 4;
        }

        /* Minimum length of encrypted record */
        explicit_ivlen = transform->ivlen - transform->fixed_ivlen;
        transform->minlen = explicit_ivlen + transform->taglen;
    } else
#endif /* MBEDTLS_SSL_HAVE_AEAD */
#if defined(PF_MBEDTLS_SSL_SOME_SUITES_USE_MAC)
    if (ssl_mode == PF_MBEDTLS_SSL_MODE_STREAM ||
        ssl_mode == PF_MBEDTLS_SSL_MODE_CBC ||
        ssl_mode == PF_MBEDTLS_SSL_MODE_CBC_ETM) {
#if defined(PF_MBEDTLS_USE_PSA_CRYPTO)
        size_t block_size = PF_PSA_BLOCK_CIPHER_BLOCK_LENGTH(key_type);
#else
        size_t block_size = pf_mbedtls_cipher_info_get_block_size(cipher_info);
#endif /* MBEDTLS_USE_PSA_CRYPTO */

#if defined(PF_MBEDTLS_USE_PSA_CRYPTO)
        /* Get MAC length */
        mac_key_len = PF_PSA_HASH_LENGTH(mac_alg);
#else
        /* Initialize HMAC contexts */
        if ((ret = pf_mbedtls_md_setup(&transform->md_ctx_enc, md_info, 1)) != 0 ||
            (ret = pf_mbedtls_md_setup(&transform->md_ctx_dec, md_info, 1)) != 0) {
            PF_MBEDTLS_SSL_DEBUG_RET(1, "mbedtls_md_setup", ret);
            goto end;
        }

        /* Get MAC length */
        mac_key_len = pf_mbedtls_md_get_size(md_info);
#endif /* MBEDTLS_USE_PSA_CRYPTO */
        transform->maclen = mac_key_len;

        /* IV length */
#if defined(PF_MBEDTLS_USE_PSA_CRYPTO)
        transform->ivlen = PF_PSA_CIPHER_IV_LENGTH(key_type, alg);
#else
        transform->ivlen = pf_mbedtls_cipher_info_get_iv_size(cipher_info);
#endif /* MBEDTLS_USE_PSA_CRYPTO */

        /* Minimum length */
        if (ssl_mode == PF_MBEDTLS_SSL_MODE_STREAM) {
            transform->minlen = transform->maclen;
        } else {
            /*
             * GenericBlockCipher:
             * 1. if EtM is in use: one block plus MAC
             *    otherwise: * first multiple of blocklen greater than maclen
             * 2. IV
             */
#if defined(PF_MBEDTLS_SSL_ENCRYPT_THEN_MAC)
            if (ssl_mode == PF_MBEDTLS_SSL_MODE_CBC_ETM) {
                transform->minlen = transform->maclen
                                    + block_size;
            } else
#endif
            {
                transform->minlen = transform->maclen
                                    + block_size
                                    - transform->maclen % block_size;
            }

            if (tls_version == PF_MBEDTLS_SSL_VERSION_TLS1_2) {
                transform->minlen += transform->ivlen;
            } else {
                PF_MBEDTLS_SSL_DEBUG_MSG(1, ("should never happen"));
                ret = PF_MBEDTLS_ERR_SSL_INTERNAL_ERROR;
                goto end;
            }
        }
    } else
#endif /* MBEDTLS_SSL_SOME_SUITES_USE_MAC */
    {
        PF_MBEDTLS_SSL_DEBUG_MSG(1, ("should never happen"));
        return PF_MBEDTLS_ERR_SSL_INTERNAL_ERROR;
    }

    PF_MBEDTLS_SSL_DEBUG_MSG(3, ("keylen: %u, minlen: %u, ivlen: %u, maclen: %u",
                              (unsigned) keylen,
                              (unsigned) transform->minlen,
                              (unsigned) transform->ivlen,
                              (unsigned) transform->maclen));

    /*
     * Finally setup the cipher contexts, IVs and MAC secrets.
     */
#if defined(PF_MBEDTLS_SSL_CLI_C)
    if (endpoint == PF_MBEDTLS_SSL_IS_CLIENT) {
        key1 = keyblk + mac_key_len * 2;
        key2 = keyblk + mac_key_len * 2 + keylen;

        mac_enc = keyblk;
        mac_dec = keyblk + mac_key_len;

        iv_copy_len = (transform->fixed_ivlen) ?
                      transform->fixed_ivlen : transform->ivlen;
        memcpy(transform->iv_enc, key2 + keylen,  iv_copy_len);
        memcpy(transform->iv_dec, key2 + keylen + iv_copy_len,
               iv_copy_len);
    } else
#endif /* MBEDTLS_SSL_CLI_C */
#if defined(PF_MBEDTLS_SSL_SRV_C)
    if (endpoint == PF_MBEDTLS_SSL_IS_SERVER) {
        key1 = keyblk + mac_key_len * 2 + keylen;
        key2 = keyblk + mac_key_len * 2;

        mac_enc = keyblk + mac_key_len;
        mac_dec = keyblk;

        iv_copy_len = (transform->fixed_ivlen) ?
                      transform->fixed_ivlen : transform->ivlen;
        memcpy(transform->iv_dec, key1 + keylen,  iv_copy_len);
        memcpy(transform->iv_enc, key1 + keylen + iv_copy_len,
               iv_copy_len);
    } else
#endif /* MBEDTLS_SSL_SRV_C */
    {
        PF_MBEDTLS_SSL_DEBUG_MSG(1, ("should never happen"));
        ret = PF_MBEDTLS_ERR_SSL_INTERNAL_ERROR;
        goto end;
    }

    if (ssl->f_export_keys != NULL) {
        ssl->f_export_keys(ssl->p_export_keys,
                           PF_MBEDTLS_SSL_KEY_EXPORT_TLS12_MASTER_SECRET,
                           master, 48,
                           randbytes + 32,
                           randbytes,
                           tls_prf_get_type(tls_prf));
    }

#if defined(PF_MBEDTLS_USE_PSA_CRYPTO)
    transform->pf_psa_alg = alg;

    if (alg != PF_MBEDTLS_SSL_NULL_CIPHER) {
        pf_psa_set_key_usage_flags(&attributes, PF_PSA_KEY_USAGE_ENCRYPT);
        pf_psa_set_key_algorithm(&attributes, alg);
        pf_psa_set_key_type(&attributes, key_type);

        if ((status = pf_psa_import_key(&attributes,
                                     key1,
                                     PF_PSA_BITS_TO_BYTES(key_bits),
                                     &transform->pf_psa_key_enc)) != PF_PSA_SUCCESS) {
            PF_MBEDTLS_SSL_DEBUG_RET(3, "psa_import_key", (int) status);
            ret = PF_PSA_TO_MBEDTLS_ERR(status);
            PF_MBEDTLS_SSL_DEBUG_RET(1, "psa_import_key", ret);
            goto end;
        }

        pf_psa_set_key_usage_flags(&attributes, PF_PSA_KEY_USAGE_DECRYPT);

        if ((status = pf_psa_import_key(&attributes,
                                     key2,
                                     PF_PSA_BITS_TO_BYTES(key_bits),
                                     &transform->pf_psa_key_dec)) != PF_PSA_SUCCESS) {
            ret = PF_PSA_TO_MBEDTLS_ERR(status);
            PF_MBEDTLS_SSL_DEBUG_RET(1, "psa_import_key", ret);
            goto end;
        }
    }
#else
    if ((ret = pf_mbedtls_cipher_setup(&transform->cipher_ctx_enc,
                                    cipher_info)) != 0) {
        PF_MBEDTLS_SSL_DEBUG_RET(1, "mbedtls_cipher_setup", ret);
        goto end;
    }

    if ((ret = pf_mbedtls_cipher_setup(&transform->cipher_ctx_dec,
                                    cipher_info)) != 0) {
        PF_MBEDTLS_SSL_DEBUG_RET(1, "mbedtls_cipher_setup", ret);
        goto end;
    }

    if ((ret = pf_mbedtls_cipher_setkey(&transform->cipher_ctx_enc, key1,
                                     (int) pf_mbedtls_cipher_info_get_key_bitlen(cipher_info),
                                     PF_MBEDTLS_ENCRYPT)) != 0) {
        PF_MBEDTLS_SSL_DEBUG_RET(1, "mbedtls_cipher_setkey", ret);
        goto end;
    }

    if ((ret = pf_mbedtls_cipher_setkey(&transform->cipher_ctx_dec, key2,
                                     (int) pf_mbedtls_cipher_info_get_key_bitlen(cipher_info),
                                     PF_MBEDTLS_DECRYPT)) != 0) {
        PF_MBEDTLS_SSL_DEBUG_RET(1, "mbedtls_cipher_setkey", ret);
        goto end;
    }

#if defined(PF_MBEDTLS_CIPHER_MODE_CBC)
    if (pf_mbedtls_cipher_info_get_mode(cipher_info) == PF_MBEDTLS_MODE_CBC) {
        if ((ret = pf_mbedtls_cipher_set_padding_mode(&transform->cipher_ctx_enc,
                                                   PF_MBEDTLS_PADDING_NONE)) != 0) {
            PF_MBEDTLS_SSL_DEBUG_RET(1, "mbedtls_cipher_set_padding_mode", ret);
            goto end;
        }

        if ((ret = pf_mbedtls_cipher_set_padding_mode(&transform->cipher_ctx_dec,
                                                   PF_MBEDTLS_PADDING_NONE)) != 0) {
            PF_MBEDTLS_SSL_DEBUG_RET(1, "mbedtls_cipher_set_padding_mode", ret);
            goto end;
        }
    }
#endif /* MBEDTLS_CIPHER_MODE_CBC */
#endif /* MBEDTLS_USE_PSA_CRYPTO */

#if defined(PF_MBEDTLS_SSL_SOME_SUITES_USE_MAC)
    /* For HMAC-based ciphersuites, initialize the HMAC transforms.
       For AEAD-based ciphersuites, there is nothing to do here. */
    if (mac_key_len != 0) {
#if defined(PF_MBEDTLS_USE_PSA_CRYPTO)
        transform->pf_psa_mac_alg = PF_PSA_ALG_HMAC(mac_alg);

        pf_psa_set_key_usage_flags(&attributes, PF_PSA_KEY_USAGE_SIGN_MESSAGE);
        pf_psa_set_key_algorithm(&attributes, PF_PSA_ALG_HMAC(mac_alg));
        pf_psa_set_key_type(&attributes, PF_PSA_KEY_TYPE_HMAC);

        if ((status = pf_psa_import_key(&attributes,
                                     mac_enc, mac_key_len,
                                     &transform->pf_psa_mac_enc)) != PF_PSA_SUCCESS) {
            ret = PF_PSA_TO_MBEDTLS_ERR(status);
            PF_MBEDTLS_SSL_DEBUG_RET(1, "psa_import_mac_key", ret);
            goto end;
        }

        if ((transform->pf_psa_alg == PF_MBEDTLS_SSL_NULL_CIPHER) ||
            ((transform->pf_psa_alg == PF_PSA_ALG_CBC_NO_PADDING)
#if defined(PF_MBEDTLS_SSL_SOME_SUITES_USE_CBC_ETM)
             && (transform->encrypt_then_mac == PF_MBEDTLS_SSL_ETM_DISABLED)
#endif
            )) {
            /* mbedtls_ct_hmac() requires the key to be exportable */
            pf_psa_set_key_usage_flags(&attributes, PF_PSA_KEY_USAGE_EXPORT |
                                    PF_PSA_KEY_USAGE_VERIFY_HASH);
        } else {
            pf_psa_set_key_usage_flags(&attributes, PF_PSA_KEY_USAGE_VERIFY_HASH);
        }

        if ((status = pf_psa_import_key(&attributes,
                                     mac_dec, mac_key_len,
                                     &transform->pf_psa_mac_dec)) != PF_PSA_SUCCESS) {
            ret = PF_PSA_TO_MBEDTLS_ERR(status);
            PF_MBEDTLS_SSL_DEBUG_RET(1, "psa_import_mac_key", ret);
            goto end;
        }
#else
        ret = pf_mbedtls_md_hmac_starts(&transform->md_ctx_enc, mac_enc, mac_key_len);
        if (ret != 0) {
            goto end;
        }
        ret = pf_mbedtls_md_hmac_starts(&transform->md_ctx_dec, mac_dec, mac_key_len);
        if (ret != 0) {
            goto end;
        }
#endif /* MBEDTLS_USE_PSA_CRYPTO */
    }
#endif /* MBEDTLS_SSL_SOME_SUITES_USE_MAC */

    ((void) mac_dec);
    ((void) mac_enc);

end:
    pf_mbedtls_platform_zeroize(keyblk, sizeof(keyblk));
    return ret;
}

#if defined(PF_MBEDTLS_KEY_EXCHANGE_ECJPAKE_ENABLED) && \
    defined(PF_MBEDTLS_USE_PSA_CRYPTO)
int pf_mbedtls_psa_ecjpake_read_round(
    pf_psa_pake_operation_t *pake_ctx,
    const unsigned char *buf,
    size_t len, pf_mbedtls_ecjpake_rounds_t round)
{
    pf_psa_status_t status;
    size_t input_offset = 0;
    /*
     * At round one repeat the KEY_SHARE, ZK_PUBLIC & ZF_PROOF twice
     * At round two perform a single cycle
     */
    unsigned int remaining_steps = (round == PF_MBEDTLS_ECJPAKE_ROUND_ONE) ? 2 : 1;

    for (; remaining_steps > 0; remaining_steps--) {
        for (pf_psa_pake_step_t step = PF_PSA_PAKE_STEP_KEY_SHARE;
             step <= PF_PSA_PAKE_STEP_ZK_PROOF;
             ++step) {
            /* Length is stored at the first byte */
            size_t length = buf[input_offset];
            input_offset += 1;

            if (input_offset + length > len) {
                return PF_MBEDTLS_ERR_SSL_HANDSHAKE_FAILURE;
            }

            status = pf_psa_pake_input(pake_ctx, step,
                                    buf + input_offset, length);
            if (status != PF_PSA_SUCCESS) {
                return PF_PSA_TO_MBEDTLS_ERR(status);
            }

            input_offset += length;
        }
    }

    if (input_offset != len) {
        return PF_MBEDTLS_ERR_SSL_HANDSHAKE_FAILURE;
    }

    return 0;
}

int pf_mbedtls_psa_ecjpake_write_round(
    pf_psa_pake_operation_t *pake_ctx,
    unsigned char *buf,
    size_t len, size_t *olen,
    pf_mbedtls_ecjpake_rounds_t round)
{
    pf_psa_status_t status;
    size_t output_offset = 0;
    size_t output_len;
    /*
     * At round one repeat the KEY_SHARE, ZK_PUBLIC & ZF_PROOF twice
     * At round two perform a single cycle
     */
    unsigned int remaining_steps = (round == PF_MBEDTLS_ECJPAKE_ROUND_ONE) ? 2 : 1;

    for (; remaining_steps > 0; remaining_steps--) {
        for (pf_psa_pake_step_t step = PF_PSA_PAKE_STEP_KEY_SHARE;
             step <= PF_PSA_PAKE_STEP_ZK_PROOF;
             ++step) {
            /*
             * For each step, prepend 1 byte with the length of the data as
             * given by psa_pake_output().
             */
            status = pf_psa_pake_output(pake_ctx, step,
                                     buf + output_offset + 1,
                                     len - output_offset - 1,
                                     &output_len);
            if (status != PF_PSA_SUCCESS) {
                return PF_PSA_TO_MBEDTLS_ERR(status);
            }

            *(buf + output_offset) = (uint8_t) output_len;

            output_offset += output_len + 1;
        }
    }

    *olen = output_offset;

    return 0;
}
#endif //MBEDTLS_KEY_EXCHANGE_ECJPAKE_ENABLED && MBEDTLS_USE_PSA_CRYPTO

#if defined(PF_MBEDTLS_USE_PSA_CRYPTO)
int pf_mbedtls_ssl_get_key_exchange_md_tls1_2(pf_mbedtls_ssl_context *ssl,
                                           unsigned char *hash, size_t *hashlen,
                                           unsigned char *data, size_t data_len,
                                           pf_mbedtls_md_type_t md_alg)
{
    pf_psa_status_t status;
    pf_psa_hash_operation_t hash_operation = PF_PSA_HASH_OPERATION_INIT;
    pf_psa_algorithm_t hash_alg = pf_mbedtls_md_psa_alg_from_type(md_alg);

    PF_MBEDTLS_SSL_DEBUG_MSG(3, ("Perform PSA-based computation of digest of ServerKeyExchange"));

    if ((status = pf_psa_hash_setup(&hash_operation,
                                 hash_alg)) != PF_PSA_SUCCESS) {
        PF_MBEDTLS_SSL_DEBUG_RET(1, "psa_hash_setup", status);
        goto exit;
    }

    if ((status = pf_psa_hash_update(&hash_operation, ssl->handshake->randbytes,
                                  64)) != PF_PSA_SUCCESS) {
        PF_MBEDTLS_SSL_DEBUG_RET(1, "psa_hash_update", status);
        goto exit;
    }

    if ((status = pf_psa_hash_update(&hash_operation,
                                  data, data_len)) != PF_PSA_SUCCESS) {
        PF_MBEDTLS_SSL_DEBUG_RET(1, "psa_hash_update", status);
        goto exit;
    }

    if ((status = pf_psa_hash_finish(&hash_operation, hash, PF_PSA_HASH_MAX_SIZE,
                                  hashlen)) != PF_PSA_SUCCESS) {
        PF_MBEDTLS_SSL_DEBUG_RET(1, "psa_hash_finish", status);
        goto exit;
    }

exit:
    if (status != PF_PSA_SUCCESS) {
        pf_mbedtls_ssl_send_alert_message(ssl, PF_MBEDTLS_SSL_ALERT_LEVEL_FATAL,
                                       PF_MBEDTLS_SSL_ALERT_MSG_INTERNAL_ERROR);
        switch (status) {
            case PF_PSA_ERROR_NOT_SUPPORTED:
                return PF_MBEDTLS_ERR_MD_FEATURE_UNAVAILABLE;
            case PF_PSA_ERROR_BAD_STATE: /* Intentional fallthrough */
            case PF_PSA_ERROR_BUFFER_TOO_SMALL:
                return PF_MBEDTLS_ERR_MD_BAD_INPUT_DATA;
            case PF_PSA_ERROR_INSUFFICIENT_MEMORY:
                return PF_MBEDTLS_ERR_MD_ALLOC_FAILED;
            default:
                return PF_MBEDTLS_ERR_PLATFORM_HW_ACCEL_FAILED;
        }
    }
    return 0;
}

#else

int pf_mbedtls_ssl_get_key_exchange_md_tls1_2(pf_mbedtls_ssl_context *ssl,
                                           unsigned char *hash, size_t *hashlen,
                                           unsigned char *data, size_t data_len,
                                           pf_mbedtls_md_type_t md_alg)
{
    int ret = 0;
    pf_mbedtls_md_context_t ctx;
    const pf_mbedtls_md_info_t *md_info = pf_mbedtls_md_info_from_type(md_alg);
    *hashlen = pf_mbedtls_md_get_size(md_info);

    PF_MBEDTLS_SSL_DEBUG_MSG(3, ("Perform mbedtls-based computation of digest of ServerKeyExchange"));

    pf_mbedtls_md_init(&ctx);

    /*
     * digitally-signed struct {
     *     opaque client_random[32];
     *     opaque server_random[32];
     *     ServerDHParams params;
     * };
     */
    if ((ret = pf_mbedtls_md_setup(&ctx, md_info, 0)) != 0) {
        PF_MBEDTLS_SSL_DEBUG_RET(1, "mbedtls_md_setup", ret);
        goto exit;
    }
    if ((ret = pf_mbedtls_md_starts(&ctx)) != 0) {
        PF_MBEDTLS_SSL_DEBUG_RET(1, "mbedtls_md_starts", ret);
        goto exit;
    }
    if ((ret = pf_mbedtls_md_update(&ctx, ssl->handshake->randbytes, 64)) != 0) {
        PF_MBEDTLS_SSL_DEBUG_RET(1, "mbedtls_md_update", ret);
        goto exit;
    }
    if ((ret = pf_mbedtls_md_update(&ctx, data, data_len)) != 0) {
        PF_MBEDTLS_SSL_DEBUG_RET(1, "mbedtls_md_update", ret);
        goto exit;
    }
    if ((ret = pf_mbedtls_md_finish(&ctx, hash)) != 0) {
        PF_MBEDTLS_SSL_DEBUG_RET(1, "mbedtls_md_finish", ret);
        goto exit;
    }

exit:
    pf_mbedtls_md_free(&ctx);

    if (ret != 0) {
        pf_mbedtls_ssl_send_alert_message(ssl, PF_MBEDTLS_SSL_ALERT_LEVEL_FATAL,
                                       PF_MBEDTLS_SSL_ALERT_MSG_INTERNAL_ERROR);
    }

    return ret;
}
#endif /* MBEDTLS_USE_PSA_CRYPTO */

#if defined(PF_MBEDTLS_KEY_EXCHANGE_WITH_CERT_ENABLED)

/* Find the preferred hash for a given signature algorithm. */
unsigned int pf_mbedtls_ssl_tls12_get_preferred_hash_for_sig_alg(
    pf_mbedtls_ssl_context *ssl,
    unsigned int sig_alg)
{
    unsigned int i;
    uint16_t *received_sig_algs = ssl->handshake->received_sig_algs;

    if (sig_alg == PF_MBEDTLS_SSL_SIG_ANON) {
        return PF_MBEDTLS_SSL_HASH_NONE;
    }

    for (i = 0; received_sig_algs[i] != PF_MBEDTLS_TLS_SIG_NONE; i++) {
        unsigned int hash_alg_received =
            PF_MBEDTLS_SSL_TLS12_HASH_ALG_FROM_SIG_AND_HASH_ALG(
                received_sig_algs[i]);
        unsigned int sig_alg_received =
            PF_MBEDTLS_SSL_TLS12_SIG_ALG_FROM_SIG_AND_HASH_ALG(
                received_sig_algs[i]);

        pf_mbedtls_md_type_t md_alg =
            pf_mbedtls_ssl_md_alg_from_hash((unsigned char) hash_alg_received);
        if (md_alg == PF_MBEDTLS_MD_NONE) {
            continue;
        }

        if (sig_alg == sig_alg_received) {
#if defined(PF_MBEDTLS_USE_PSA_CRYPTO)
            if (ssl->handshake->key_cert && ssl->handshake->key_cert->key) {
                pf_psa_algorithm_t pf_psa_hash_alg =
                    pf_mbedtls_md_psa_alg_from_type(md_alg);

                if (sig_alg_received == PF_MBEDTLS_SSL_SIG_ECDSA &&
                    !pf_mbedtls_pk_can_do_ext(ssl->handshake->key_cert->key,
                                           PF_PSA_ALG_ECDSA(pf_psa_hash_alg),
                                           PF_PSA_KEY_USAGE_SIGN_HASH)) {
                    continue;
                }

                if (sig_alg_received == PF_MBEDTLS_SSL_SIG_RSA &&
                    !pf_mbedtls_pk_can_do_ext(ssl->handshake->key_cert->key,
                                           PF_PSA_ALG_RSA_PKCS1V15_SIGN(
                                               pf_psa_hash_alg),
                                           PF_PSA_KEY_USAGE_SIGN_HASH)) {
                    continue;
                }
            }
#endif /* MBEDTLS_USE_PSA_CRYPTO */

            return hash_alg_received;
        }
    }

    return PF_MBEDTLS_SSL_HASH_NONE;
}

#endif /* MBEDTLS_KEY_EXCHANGE_WITH_CERT_ENABLED */

#endif /* MBEDTLS_SSL_PROTO_TLS1_2 */

int pf_mbedtls_ssl_validate_ciphersuite(
    const pf_mbedtls_ssl_context *ssl,
    const pf_mbedtls_ssl_ciphersuite_t *suite_info,
    pf_mbedtls_ssl_protocol_version min_tls_version,
    pf_mbedtls_ssl_protocol_version max_tls_version)
{
    (void) ssl;

    if (suite_info == NULL) {
        return -1;
    }

    if ((suite_info->min_tls_version > max_tls_version) ||
        (suite_info->max_tls_version < min_tls_version)) {
        return -1;
    }

#if defined(PF_MBEDTLS_SSL_PROTO_TLS1_2) && defined(PF_MBEDTLS_SSL_CLI_C)
#if defined(PF_MBEDTLS_KEY_EXCHANGE_ECJPAKE_ENABLED)
#if defined(PF_MBEDTLS_USE_PSA_CRYPTO)
    if (suite_info->key_exchange == PF_MBEDTLS_KEY_EXCHANGE_ECJPAKE &&
        ssl->handshake->pf_psa_pake_ctx_is_ok != 1)
#else
    if (suite_info->key_exchange == PF_MBEDTLS_KEY_EXCHANGE_ECJPAKE &&
        pf_mbedtls_ecjpake_check(&ssl->handshake->ecjpake_ctx) != 0)
#endif /* MBEDTLS_USE_PSA_CRYPTO */
    {
        return -1;
    }
#endif

    /* Don't suggest PSK-based ciphersuite if no PSK is available. */
#if defined(PF_MBEDTLS_KEY_EXCHANGE_SOME_PSK_ENABLED)
    if (pf_mbedtls_ssl_ciphersuite_uses_psk(suite_info) &&
        pf_mbedtls_ssl_conf_has_static_psk(ssl->conf) == 0) {
        return -1;
    }
#endif /* MBEDTLS_KEY_EXCHANGE_SOME_PSK_ENABLED */
#endif /* MBEDTLS_SSL_PROTO_TLS1_2 */

    return 0;
}

#if defined(PF_MBEDTLS_SSL_HANDSHAKE_WITH_CERT_ENABLED)
/*
 * Function for writing a signature algorithm extension.
 *
 * The `extension_data` field of signature algorithm contains  a `SignatureSchemeList`
 * value (TLS 1.3 RFC8446):
 *      enum {
 *         ....
 *        ecdsa_secp256r1_sha256( 0x0403 ),
 *        ecdsa_secp384r1_sha384( 0x0503 ),
 *        ecdsa_secp521r1_sha512( 0x0603 ),
 *         ....
 *      } SignatureScheme;
 *
 *      struct {
 *         SignatureScheme supported_signature_algorithms<2..2^16-2>;
 *      } SignatureSchemeList;
 *
 * The `extension_data` field of signature algorithm contains a `SignatureAndHashAlgorithm`
 * value (TLS 1.2 RFC5246):
 *      enum {
 *          none(0), md5(1), sha1(2), sha224(3), sha256(4), sha384(5),
 *          sha512(6), (255)
 *      } HashAlgorithm;
 *
 *      enum { anonymous(0), rsa(1), dsa(2), ecdsa(3), (255) }
 *        SignatureAlgorithm;
 *
 *      struct {
 *          HashAlgorithm hash;
 *          SignatureAlgorithm signature;
 *      } SignatureAndHashAlgorithm;
 *
 *      SignatureAndHashAlgorithm
 *        supported_signature_algorithms<2..2^16-2>;
 *
 * The TLS 1.3 signature algorithm extension was defined to be a compatible
 * generalization of the TLS 1.2 signature algorithm extension.
 * `SignatureAndHashAlgorithm` field of TLS 1.2 can be represented by
 * `SignatureScheme` field of TLS 1.3
 *
 */
int pf_mbedtls_ssl_write_sig_alg_ext(pf_mbedtls_ssl_context *ssl, unsigned char *buf,
                                  const unsigned char *end, size_t *out_len)
{
    unsigned char *p = buf;
    unsigned char *supported_sig_alg; /* Start of supported_signature_algorithms */
    size_t supported_sig_alg_len = 0; /* Length of supported_signature_algorithms */

    *out_len = 0;

    PF_MBEDTLS_SSL_DEBUG_MSG(3, ("adding signature_algorithms extension"));

    /* Check if we have space for header and length field:
     * - extension_type         (2 bytes)
     * - extension_data_length  (2 bytes)
     * - supported_signature_algorithms_length   (2 bytes)
     */
    PF_MBEDTLS_SSL_CHK_BUF_PTR(p, end, 6);
    p += 6;

    /*
     * Write supported_signature_algorithms
     */
    supported_sig_alg = p;
    const uint16_t *sig_alg = pf_mbedtls_ssl_get_sig_algs(ssl);
    if (sig_alg == NULL) {
        return PF_MBEDTLS_ERR_SSL_BAD_CONFIG;
    }

    for (; *sig_alg != PF_MBEDTLS_TLS1_3_SIG_NONE; sig_alg++) {
        PF_MBEDTLS_SSL_DEBUG_MSG(3, ("got signature scheme [%x] %s",
                                  *sig_alg,
                                  pf_mbedtls_ssl_sig_alg_to_str(*sig_alg)));
        if (!pf_mbedtls_ssl_sig_alg_is_supported(ssl, *sig_alg)) {
            continue;
        }
        PF_MBEDTLS_SSL_CHK_BUF_PTR(p, end, 2);
        PF_MBEDTLS_PUT_UINT16_BE(*sig_alg, p, 0);
        p += 2;
        PF_MBEDTLS_SSL_DEBUG_MSG(3, ("sent signature scheme [%x] %s",
                                  *sig_alg,
                                  pf_mbedtls_ssl_sig_alg_to_str(*sig_alg)));
    }

    /* Length of supported_signature_algorithms */
    supported_sig_alg_len = (size_t) (p - supported_sig_alg);
    if (supported_sig_alg_len == 0) {
        PF_MBEDTLS_SSL_DEBUG_MSG(1, ("No signature algorithms defined."));
        return PF_MBEDTLS_ERR_SSL_INTERNAL_ERROR;
    }

    PF_MBEDTLS_PUT_UINT16_BE(PF_MBEDTLS_TLS_EXT_SIG_ALG, buf, 0);
    PF_MBEDTLS_PUT_UINT16_BE(supported_sig_alg_len + 2, buf, 2);
    PF_MBEDTLS_PUT_UINT16_BE(supported_sig_alg_len, buf, 4);

    *out_len = (size_t) (p - buf);

#if defined(PF_MBEDTLS_SSL_PROTO_TLS1_3)
    pf_mbedtls_ssl_tls13_set_hs_sent_ext_mask(ssl, PF_MBEDTLS_TLS_EXT_SIG_ALG);
#endif /* MBEDTLS_SSL_PROTO_TLS1_3 */

    return 0;
}
#endif /* MBEDTLS_SSL_HANDSHAKE_WITH_CERT_ENABLED */

#if defined(PF_MBEDTLS_SSL_SERVER_NAME_INDICATION)
/*
 * mbedtls_ssl_parse_server_name_ext
 *
 * Structure of server_name extension:
 *
 *  enum {
 *        host_name(0), (255)
 *     } NameType;
 *  opaque HostName<1..2^16-1>;
 *
 *  struct {
 *          NameType name_type;
 *          select (name_type) {
 *             case host_name: HostName;
 *           } name;
 *     } ServerName;
 *  struct {
 *          ServerName server_name_list<1..2^16-1>
 *     } ServerNameList;
 */
PF_MBEDTLS_CHECK_RETURN_CRITICAL
int pf_mbedtls_ssl_parse_server_name_ext(pf_mbedtls_ssl_context *ssl,
                                      const unsigned char *buf,
                                      const unsigned char *end)
{
    int ret = PF_MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    const unsigned char *p = buf;
    size_t server_name_list_len, hostname_len;
    const unsigned char *server_name_list_end;

    PF_MBEDTLS_SSL_DEBUG_MSG(3, ("parse ServerName extension"));

    PF_MBEDTLS_SSL_CHK_BUF_READ_PTR(p, end, 2);
    server_name_list_len = PF_MBEDTLS_GET_UINT16_BE(p, 0);
    p += 2;

    PF_MBEDTLS_SSL_CHK_BUF_READ_PTR(p, end, server_name_list_len);
    server_name_list_end = p + server_name_list_len;
    while (p < server_name_list_end) {
        PF_MBEDTLS_SSL_CHK_BUF_READ_PTR(p, server_name_list_end, 3);
        hostname_len = PF_MBEDTLS_GET_UINT16_BE(p, 1);
        PF_MBEDTLS_SSL_CHK_BUF_READ_PTR(p, server_name_list_end,
                                     hostname_len + 3);

        if (p[0] == PF_MBEDTLS_TLS_EXT_SERVERNAME_HOSTNAME) {
            /* sni_name is intended to be used only during the parsing of the
             * ClientHello message (it is reset to NULL before the end of
             * the message parsing). Thus it is ok to just point to the
             * reception buffer and not make a copy of it.
             */
            ssl->handshake->sni_name = p + 3;
            ssl->handshake->sni_name_len = hostname_len;
            if (ssl->conf->f_sni == NULL) {
                return 0;
            }
            ret = ssl->conf->f_sni(ssl->conf->p_sni,
                                   ssl, p + 3, hostname_len);
            if (ret != 0) {
                PF_MBEDTLS_SSL_DEBUG_RET(1, "ssl_sni_wrapper", ret);
                PF_MBEDTLS_SSL_PEND_FATAL_ALERT(PF_MBEDTLS_SSL_ALERT_MSG_UNRECOGNIZED_NAME,
                                             PF_MBEDTLS_ERR_SSL_UNRECOGNIZED_NAME);
                return PF_MBEDTLS_ERR_SSL_UNRECOGNIZED_NAME;
            }
            return 0;
        }

        p += hostname_len + 3;
    }

    return 0;
}
#endif /* MBEDTLS_SSL_SERVER_NAME_INDICATION */

#if defined(PF_MBEDTLS_SSL_ALPN)
PF_MBEDTLS_CHECK_RETURN_CRITICAL
int pf_mbedtls_ssl_parse_alpn_ext(pf_mbedtls_ssl_context *ssl,
                               const unsigned char *buf,
                               const unsigned char *end)
{
    const unsigned char *p = buf;
    size_t protocol_name_list_len;
    const unsigned char *protocol_name_list;
    const unsigned char *protocol_name_list_end;
    size_t protocol_name_len;

    /* If ALPN not configured, just ignore the extension */
    if (ssl->conf->alpn_list == NULL) {
        return 0;
    }

    /*
     * RFC7301, section 3.1
     *      opaque ProtocolName<1..2^8-1>;
     *
     *      struct {
     *          ProtocolName protocol_name_list<2..2^16-1>
     *      } ProtocolNameList;
     */

    /*
     * protocol_name_list_len    2 bytes
     * protocol_name_len         1 bytes
     * protocol_name             >=1 byte
     */
    PF_MBEDTLS_SSL_CHK_BUF_READ_PTR(p, end, 4);

    protocol_name_list_len = PF_MBEDTLS_GET_UINT16_BE(p, 0);
    p += 2;
    PF_MBEDTLS_SSL_CHK_BUF_READ_PTR(p, end, protocol_name_list_len);
    protocol_name_list = p;
    protocol_name_list_end = p + protocol_name_list_len;

    /* Validate peer's list (lengths) */
    while (p < protocol_name_list_end) {
        protocol_name_len = *p++;
        PF_MBEDTLS_SSL_CHK_BUF_READ_PTR(p, protocol_name_list_end,
                                     protocol_name_len);
        if (protocol_name_len == 0) {
            PF_MBEDTLS_SSL_PEND_FATAL_ALERT(
                PF_MBEDTLS_SSL_ALERT_MSG_ILLEGAL_PARAMETER,
                PF_MBEDTLS_ERR_SSL_ILLEGAL_PARAMETER);
            return PF_MBEDTLS_ERR_SSL_ILLEGAL_PARAMETER;
        }

        p += protocol_name_len;
    }

    /* Use our order of preference */
    for (const char **alpn = ssl->conf->alpn_list; *alpn != NULL; alpn++) {
        size_t const alpn_len = strlen(*alpn);
        p = protocol_name_list;
        while (p < protocol_name_list_end) {
            protocol_name_len = *p++;
            if (protocol_name_len == alpn_len &&
                memcmp(p, *alpn, alpn_len) == 0) {
                ssl->alpn_chosen = *alpn;
                return 0;
            }

            p += protocol_name_len;
        }
    }

    /* If we get here, no match was found */
    PF_MBEDTLS_SSL_PEND_FATAL_ALERT(
        PF_MBEDTLS_SSL_ALERT_MSG_NO_APPLICATION_PROTOCOL,
        PF_MBEDTLS_ERR_SSL_NO_APPLICATION_PROTOCOL);
    return PF_MBEDTLS_ERR_SSL_NO_APPLICATION_PROTOCOL;
}

int pf_mbedtls_ssl_write_alpn_ext(pf_mbedtls_ssl_context *ssl,
                               unsigned char *buf,
                               unsigned char *end,
                               size_t *out_len)
{
    unsigned char *p = buf;
    size_t protocol_name_len;
    *out_len = 0;

    if (ssl->alpn_chosen == NULL) {
        return 0;
    }

    protocol_name_len = strlen(ssl->alpn_chosen);
    PF_MBEDTLS_SSL_CHK_BUF_PTR(p, end, 7 + protocol_name_len);

    PF_MBEDTLS_SSL_DEBUG_MSG(3, ("server side, adding alpn extension"));
    /*
     * 0 . 1    ext identifier
     * 2 . 3    ext length
     * 4 . 5    protocol list length
     * 6 . 6    protocol name length
     * 7 . 7+n  protocol name
     */
    PF_MBEDTLS_PUT_UINT16_BE(PF_MBEDTLS_TLS_EXT_ALPN, p, 0);

    *out_len = 7 + protocol_name_len;

    PF_MBEDTLS_PUT_UINT16_BE(protocol_name_len + 3, p, 2);
    PF_MBEDTLS_PUT_UINT16_BE(protocol_name_len + 1, p, 4);
    /* Note: the length of the chosen protocol has been checked to be less
     * than 255 bytes in `mbedtls_ssl_conf_alpn_protocols`.
     */
    p[6] = PF_MBEDTLS_BYTE_0(protocol_name_len);

    memcpy(p + 7, ssl->alpn_chosen, protocol_name_len);

#if defined(PF_MBEDTLS_SSL_PROTO_TLS1_3)
    pf_mbedtls_ssl_tls13_set_hs_sent_ext_mask(ssl, PF_MBEDTLS_TLS_EXT_ALPN);
#endif

    return 0;
}
#endif /* MBEDTLS_SSL_ALPN */

#if defined(PF_MBEDTLS_SSL_PROTO_TLS1_3) && \
    defined(PF_MBEDTLS_SSL_SESSION_TICKETS) && \
    defined(PF_MBEDTLS_SSL_SERVER_NAME_INDICATION) && \
    defined(PF_MBEDTLS_SSL_CLI_C)
int pf_mbedtls_ssl_session_set_hostname(pf_mbedtls_ssl_session *session,
                                     const char *hostname)
{
    /* Initialize to suppress unnecessary compiler warning */
    size_t hostname_len = 0;

    /* Check if new hostname is valid before
     * making any change to current one */
    if (hostname != NULL) {
        hostname_len = strlen(hostname);

        if (hostname_len > PF_MBEDTLS_SSL_MAX_HOST_NAME_LEN) {
            return PF_MBEDTLS_ERR_SSL_BAD_INPUT_DATA;
        }
    }

    /* Now it's clear that we will overwrite the old hostname,
     * so we can free it safely */
    if (session->hostname != NULL) {
        pf_mbedtls_zeroize_and_free(session->hostname,
                                 strlen(session->hostname));
    }

    /* Passing NULL as hostname shall clear the old one */
    if (hostname == NULL) {
        session->hostname = NULL;
    } else {
        session->hostname = pf_mbedtls_calloc(1, hostname_len + 1);
        if (session->hostname == NULL) {
            return PF_MBEDTLS_ERR_SSL_ALLOC_FAILED;
        }

        memcpy(session->hostname, hostname, hostname_len);
    }

    return 0;
}
#endif /* MBEDTLS_SSL_PROTO_TLS1_3 &&
          MBEDTLS_SSL_SESSION_TICKETS &&
          MBEDTLS_SSL_SERVER_NAME_INDICATION &&
          MBEDTLS_SSL_CLI_C */

#if defined(PF_MBEDTLS_SSL_SRV_C) && defined(PF_MBEDTLS_SSL_EARLY_DATA) && \
    defined(PF_MBEDTLS_SSL_ALPN)
int pf_mbedtls_ssl_session_set_ticket_alpn(pf_mbedtls_ssl_session *session,
                                        const char *alpn)
{
    size_t alpn_len = 0;

    if (alpn != NULL) {
        alpn_len = strlen(alpn);

        if (alpn_len > PF_MBEDTLS_SSL_MAX_ALPN_NAME_LEN) {
            return PF_MBEDTLS_ERR_SSL_BAD_INPUT_DATA;
        }
    }

    if (session->ticket_alpn != NULL) {
        pf_mbedtls_zeroize_and_free(session->ticket_alpn,
                                 strlen(session->ticket_alpn));
        session->ticket_alpn = NULL;
    }

    if (alpn != NULL) {
        session->ticket_alpn = pf_mbedtls_calloc(alpn_len + 1, 1);
        if (session->ticket_alpn == NULL) {
            return PF_MBEDTLS_ERR_SSL_ALLOC_FAILED;
        }
        memcpy(session->ticket_alpn, alpn, alpn_len);
    }

    return 0;
}
#endif /* MBEDTLS_SSL_SRV_C && MBEDTLS_SSL_EARLY_DATA && MBEDTLS_SSL_ALPN */

/*
 * The following functions are used by 1.2 and 1.3, client and server.
 */
#if defined(PF_MBEDTLS_SSL_HANDSHAKE_WITH_CERT_ENABLED)
int pf_mbedtls_ssl_check_cert_usage(const pf_mbedtls_x509_crt *cert,
                                 const pf_mbedtls_ssl_ciphersuite_t *ciphersuite,
                                 int recv_endpoint,
                                 pf_mbedtls_ssl_protocol_version tls_version,
                                 uint32_t *flags)
{
    int ret = 0;
    unsigned int usage = 0;
    const char *ext_oid;
    size_t ext_len;

    /*
     * keyUsage
     */

    /* Note: don't guard this with MBEDTLS_SSL_CLI_C because the server wants
     * to check what a compliant client will think while choosing which cert
     * to send to the client. */
#if defined(PF_MBEDTLS_SSL_PROTO_TLS1_2)
    if (tls_version == PF_MBEDTLS_SSL_VERSION_TLS1_2 &&
        recv_endpoint == PF_MBEDTLS_SSL_IS_CLIENT) {
        /* TLS 1.2 server part of the key exchange */
        switch (ciphersuite->key_exchange) {
            case PF_MBEDTLS_KEY_EXCHANGE_RSA:
            case PF_MBEDTLS_KEY_EXCHANGE_RSA_PSK:
                usage = PF_MBEDTLS_X509_KU_KEY_ENCIPHERMENT;
                break;

            case PF_MBEDTLS_KEY_EXCHANGE_DHE_RSA:
            case PF_MBEDTLS_KEY_EXCHANGE_ECDHE_RSA:
            case PF_MBEDTLS_KEY_EXCHANGE_ECDHE_ECDSA:
                usage = PF_MBEDTLS_X509_KU_DIGITAL_SIGNATURE;
                break;

            case PF_MBEDTLS_KEY_EXCHANGE_ECDH_RSA:
            case PF_MBEDTLS_KEY_EXCHANGE_ECDH_ECDSA:
                usage = PF_MBEDTLS_X509_KU_KEY_AGREEMENT;
                break;

            /* Don't use default: we want warnings when adding new values */
            case PF_MBEDTLS_KEY_EXCHANGE_NONE:
            case PF_MBEDTLS_KEY_EXCHANGE_PSK:
            case PF_MBEDTLS_KEY_EXCHANGE_DHE_PSK:
            case PF_MBEDTLS_KEY_EXCHANGE_ECDHE_PSK:
            case PF_MBEDTLS_KEY_EXCHANGE_ECJPAKE:
                usage = 0;
        }
    } else
#endif
    {
        /* This is either TLS 1.3 authentication, which always uses signatures,
         * or 1.2 client auth: rsa_sign and mbedtls_ecdsa_sign are the only
         * options we implement, both using signatures. */
        (void) tls_version;
        (void) ciphersuite;
        usage = PF_MBEDTLS_X509_KU_DIGITAL_SIGNATURE;
    }

    if (pf_mbedtls_x509_crt_check_key_usage(cert, usage) != 0) {
        *flags |= PF_MBEDTLS_X509_BADCERT_KEY_USAGE;
        ret = -1;
    }

    /*
     * extKeyUsage
     */

    if (recv_endpoint == PF_MBEDTLS_SSL_IS_CLIENT) {
        ext_oid = PF_MBEDTLS_OID_SERVER_AUTH;
        ext_len = PF_MBEDTLS_OID_SIZE(PF_MBEDTLS_OID_SERVER_AUTH);
    } else {
        ext_oid = PF_MBEDTLS_OID_CLIENT_AUTH;
        ext_len = PF_MBEDTLS_OID_SIZE(PF_MBEDTLS_OID_CLIENT_AUTH);
    }

    if (pf_mbedtls_x509_crt_check_extended_key_usage(cert, ext_oid, ext_len) != 0) {
        *flags |= PF_MBEDTLS_X509_BADCERT_EXT_KEY_USAGE;
        ret = -1;
    }

    return ret;
}

static int get_hostname_for_verification(pf_mbedtls_ssl_context *ssl,
                                         const char **hostname)
{
    if (!pf_mbedtls_ssl_has_set_hostname_been_called(ssl)) {
        PF_MBEDTLS_SSL_DEBUG_MSG(1, ("Certificate verification without having set hostname"));
#if !defined(PF_MBEDTLS_SSL_CLI_ALLOW_WEAK_CERTIFICATE_VERIFICATION_WITHOUT_HOSTNAME)
        if (pf_mbedtls_ssl_conf_get_endpoint(ssl->conf) == PF_MBEDTLS_SSL_IS_CLIENT &&
            ssl->conf->authmode == PF_MBEDTLS_SSL_VERIFY_REQUIRED) {
            return PF_MBEDTLS_ERR_SSL_CERTIFICATE_VERIFICATION_WITHOUT_HOSTNAME;
        }
#endif
    }

    *hostname = pf_mbedtls_ssl_get_hostname_pointer(ssl);
    if (*hostname == NULL) {
        PF_MBEDTLS_SSL_DEBUG_MSG(2, ("Certificate verification without CN verification"));
    }

    return 0;
}

int pf_mbedtls_ssl_verify_certificate(pf_mbedtls_ssl_context *ssl,
                                   int authmode,
                                   pf_mbedtls_x509_crt *chain,
                                   const pf_mbedtls_ssl_ciphersuite_t *ciphersuite_info,
                                   void *rs_ctx)
{
    if (authmode == PF_MBEDTLS_SSL_VERIFY_NONE) {
        ssl->session_negotiate->verify_result = 0;
        return 0;
    }

    /*
     * Primary check: use the appropriate X.509 verification function
     */
    int (*f_vrfy)(void *, pf_mbedtls_x509_crt *, int, uint32_t *);
    void *p_vrfy;
    if (ssl->f_vrfy != NULL) {
        PF_MBEDTLS_SSL_DEBUG_MSG(3, ("Use context-specific verification callback"));
        f_vrfy = ssl->f_vrfy;
        p_vrfy = ssl->p_vrfy;
    } else {
        PF_MBEDTLS_SSL_DEBUG_MSG(3, ("Use configuration-specific verification callback"));
        f_vrfy = ssl->conf->f_vrfy;
        p_vrfy = ssl->conf->p_vrfy;
    }

    const char *hostname = "";
    int ret = get_hostname_for_verification(ssl, &hostname);
    if (ret != 0) {
        PF_MBEDTLS_SSL_DEBUG_RET(1, "get_hostname_for_verification", ret);
        return ret;
    }

    int have_ca_chain_or_callback = 0;
#if defined(PF_MBEDTLS_X509_TRUSTED_CERTIFICATE_CALLBACK)
    if (ssl->conf->f_ca_cb != NULL) {
        ((void) rs_ctx);
        have_ca_chain_or_callback = 1;

        PF_MBEDTLS_SSL_DEBUG_MSG(3, ("use CA callback for X.509 CRT verification"));
        ret = pf_mbedtls_x509_crt_verify_with_ca_cb(
            chain,
            ssl->conf->f_ca_cb,
            ssl->conf->p_ca_cb,
            ssl->conf->cert_profile,
            hostname,
            &ssl->session_negotiate->verify_result,
            f_vrfy, p_vrfy);
    } else
#endif /* MBEDTLS_X509_TRUSTED_CERTIFICATE_CALLBACK */
    {
        pf_mbedtls_x509_crt *ca_chain;
        pf_mbedtls_x509_crl *ca_crl;
#if defined(PF_MBEDTLS_SSL_SERVER_NAME_INDICATION)
        if (ssl->handshake->sni_ca_chain != NULL) {
            ca_chain = ssl->handshake->sni_ca_chain;
            ca_crl   = ssl->handshake->sni_ca_crl;
        } else
#endif
        {
            ca_chain = ssl->conf->ca_chain;
            ca_crl   = ssl->conf->ca_crl;
        }

        if (ca_chain != NULL) {
            have_ca_chain_or_callback = 1;
        }

        ret = pf_mbedtls_x509_crt_verify_restartable(
            chain,
            ca_chain, ca_crl,
            ssl->conf->cert_profile,
            hostname,
            &ssl->session_negotiate->verify_result,
            f_vrfy, p_vrfy, rs_ctx);
    }

    if (ret != 0) {
        PF_MBEDTLS_SSL_DEBUG_RET(1, "x509_verify_cert", ret);
    }

#if defined(PF_MBEDTLS_SSL_ECP_RESTARTABLE_ENABLED)
    if (ret == PF_MBEDTLS_ERR_ECP_IN_PROGRESS) {
        return PF_MBEDTLS_ERR_SSL_CRYPTO_IN_PROGRESS;
    }
#endif

    /*
     * Secondary checks: always done, but change 'ret' only if it was 0
     */

    /* With TLS 1.2 and ECC certs, check that the curve used by the
     * certificate is on our list of acceptable curves.
     *
     * With TLS 1.3 this is not needed because the curve is part of the
     * signature algorithm (eg ecdsa_secp256r1_sha256) which is checked when
     * we validate the signature made with the key associated to this cert.
     */
#if defined(PF_MBEDTLS_SSL_PROTO_TLS1_2) && \
    defined(PF_MBEDTLS_PK_HAVE_ECC_KEYS)
    if (ssl->tls_version == PF_MBEDTLS_SSL_VERSION_TLS1_2 &&
        pf_mbedtls_pk_can_do(&chain->pk, PF_MBEDTLS_PK_ECKEY)) {
        if (pf_mbedtls_ssl_check_curve(ssl, pf_mbedtls_pk_get_ec_group_id(&chain->pk)) != 0) {
            PF_MBEDTLS_SSL_DEBUG_MSG(1, ("bad certificate (EC key curve)"));
            ssl->session_negotiate->verify_result |= PF_MBEDTLS_X509_BADCERT_BAD_KEY;
            if (ret == 0) {
                ret = PF_MBEDTLS_ERR_SSL_BAD_CERTIFICATE;
            }
        }
    }
#endif /* MBEDTLS_SSL_PROTO_TLS1_2 && MBEDTLS_PK_HAVE_ECC_KEYS */

    /* Check X.509 usage extensions (keyUsage, extKeyUsage) */
    if (pf_mbedtls_ssl_check_cert_usage(chain,
                                     ciphersuite_info,
                                     ssl->conf->endpoint,
                                     ssl->tls_version,
                                     &ssl->session_negotiate->verify_result) != 0) {
        PF_MBEDTLS_SSL_DEBUG_MSG(1, ("bad certificate (usage extensions)"));
        if (ret == 0) {
            ret = PF_MBEDTLS_ERR_SSL_BAD_CERTIFICATE;
        }
    }

    /* With authmode optional, we want to keep going if the certificate was
     * unacceptable, but still fail on other errors (out of memory etc),
     * including fatal errors from the f_vrfy callback.
     *
     * The only acceptable errors are:
     * - MBEDTLS_ERR_X509_CERT_VERIFY_FAILED: cert rejected by primary check;
     * - MBEDTLS_ERR_SSL_BAD_CERTIFICATE: cert rejected by secondary checks.
     * Anything else is a fatal error. */
    if (authmode == PF_MBEDTLS_SSL_VERIFY_OPTIONAL &&
        (ret == PF_MBEDTLS_ERR_X509_CERT_VERIFY_FAILED ||
         ret == PF_MBEDTLS_ERR_SSL_BAD_CERTIFICATE)) {
        ret = 0;
    }

    /* Return a specific error as this is a user error: inconsistent
     * configuration - can't verify without trust anchors. */
    if (have_ca_chain_or_callback == 0 && authmode == PF_MBEDTLS_SSL_VERIFY_REQUIRED) {
        PF_MBEDTLS_SSL_DEBUG_MSG(1, ("got no CA chain"));
        ret = PF_MBEDTLS_ERR_SSL_CA_CHAIN_REQUIRED;
    }

    if (ret != 0) {
        uint8_t alert;

        /* The certificate may have been rejected for several reasons.
           Pick one and send the corresponding alert. Which alert to send
           may be a subject of debate in some cases. */
        if (ssl->session_negotiate->verify_result & PF_MBEDTLS_X509_BADCERT_OTHER) {
            alert = PF_MBEDTLS_SSL_ALERT_MSG_ACCESS_DENIED;
        } else if (ssl->session_negotiate->verify_result & PF_MBEDTLS_X509_BADCERT_CN_MISMATCH) {
            alert = PF_MBEDTLS_SSL_ALERT_MSG_BAD_CERT;
        } else if (ssl->session_negotiate->verify_result & PF_MBEDTLS_X509_BADCERT_KEY_USAGE) {
            alert = PF_MBEDTLS_SSL_ALERT_MSG_UNSUPPORTED_CERT;
        } else if (ssl->session_negotiate->verify_result & PF_MBEDTLS_X509_BADCERT_EXT_KEY_USAGE) {
            alert = PF_MBEDTLS_SSL_ALERT_MSG_UNSUPPORTED_CERT;
        } else if (ssl->session_negotiate->verify_result & PF_MBEDTLS_X509_BADCERT_BAD_PK) {
            alert = PF_MBEDTLS_SSL_ALERT_MSG_UNSUPPORTED_CERT;
        } else if (ssl->session_negotiate->verify_result & PF_MBEDTLS_X509_BADCERT_BAD_KEY) {
            alert = PF_MBEDTLS_SSL_ALERT_MSG_UNSUPPORTED_CERT;
        } else if (ssl->session_negotiate->verify_result & PF_MBEDTLS_X509_BADCERT_EXPIRED) {
            alert = PF_MBEDTLS_SSL_ALERT_MSG_CERT_EXPIRED;
        } else if (ssl->session_negotiate->verify_result & PF_MBEDTLS_X509_BADCERT_REVOKED) {
            alert = PF_MBEDTLS_SSL_ALERT_MSG_CERT_REVOKED;
        } else if (ssl->session_negotiate->verify_result & PF_MBEDTLS_X509_BADCERT_NOT_TRUSTED) {
            alert = PF_MBEDTLS_SSL_ALERT_MSG_UNKNOWN_CA;
        } else {
            alert = PF_MBEDTLS_SSL_ALERT_MSG_CERT_UNKNOWN;
        }
        pf_mbedtls_ssl_send_alert_message(ssl, PF_MBEDTLS_SSL_ALERT_LEVEL_FATAL,
                                       alert);
    }

#if defined(PF_MBEDTLS_DEBUG_C)
    if (ssl->session_negotiate->verify_result != 0) {
        PF_MBEDTLS_SSL_DEBUG_MSG(3, ("! Certificate verification flags %08x",
                                  (unsigned int) ssl->session_negotiate->verify_result));
    } else {
        PF_MBEDTLS_SSL_DEBUG_MSG(3, ("Certificate verification flags clear"));
    }
#endif /* MBEDTLS_DEBUG_C */

    return ret;
}
#endif /* MBEDTLS_SSL_HANDSHAKE_WITH_CERT_ENABLED */

#if defined(PF_MBEDTLS_SSL_KEYING_MATERIAL_EXPORT)

#if defined(PF_MBEDTLS_SSL_PROTO_TLS1_2)
static int pf_mbedtls_ssl_tls12_export_keying_material(const pf_mbedtls_ssl_context *ssl,
                                                    const pf_mbedtls_md_type_t hash_alg,
                                                    uint8_t *out,
                                                    const size_t key_len,
                                                    const char *label,
                                                    const size_t label_len,
                                                    const unsigned char *context,
                                                    const size_t context_len,
                                                    const int use_context)
{
    int ret = 0;
    unsigned char *prf_input = NULL;

    /* The input to the PRF is client_random, then server_random.
     * If a context is provided, this is then followed by the context length
     * as a 16-bit big-endian integer, and then the context itself. */
    const size_t randbytes_len = PF_MBEDTLS_CLIENT_HELLO_RANDOM_LEN + PF_MBEDTLS_SERVER_HELLO_RANDOM_LEN;
    size_t prf_input_len = randbytes_len;
    if (use_context) {
        if (context_len > UINT16_MAX) {
            return PF_MBEDTLS_ERR_SSL_BAD_INPUT_DATA;
        }

        /* This does not overflow a 32-bit size_t because the current value of
         * prf_input_len is 64 (length of client_random + server_random) and
         * context_len fits into two bytes (checked above). */
        prf_input_len += sizeof(uint16_t) + context_len;
    }

    prf_input = pf_mbedtls_calloc(prf_input_len, sizeof(unsigned char));
    if (prf_input == NULL) {
        return PF_MBEDTLS_ERR_SSL_ALLOC_FAILED;
    }

    memcpy(prf_input,
           ssl->transform->randbytes + PF_MBEDTLS_SERVER_HELLO_RANDOM_LEN,
           PF_MBEDTLS_CLIENT_HELLO_RANDOM_LEN);
    memcpy(prf_input + PF_MBEDTLS_CLIENT_HELLO_RANDOM_LEN,
           ssl->transform->randbytes,
           PF_MBEDTLS_SERVER_HELLO_RANDOM_LEN);
    if (use_context) {
        PF_MBEDTLS_PUT_UINT16_BE(context_len, prf_input, randbytes_len);
        memcpy(prf_input + randbytes_len + sizeof(uint16_t), context, context_len);
    }
    ret = tls_prf_generic(hash_alg, ssl->session->master, sizeof(ssl->session->master),
                          label, label_len,
                          prf_input, prf_input_len,
                          out, key_len);
    pf_mbedtls_free(prf_input);
    return ret;
}
#endif /* defined(MBEDTLS_SSL_PROTO_TLS1_2) */

#if defined(PF_MBEDTLS_SSL_PROTO_TLS1_3)
static int pf_mbedtls_ssl_tls13_export_keying_material(pf_mbedtls_ssl_context *ssl,
                                                    const pf_mbedtls_md_type_t hash_alg,
                                                    uint8_t *out,
                                                    const size_t key_len,
                                                    const char *label,
                                                    const size_t label_len,
                                                    const unsigned char *context,
                                                    const size_t context_len)
{
    const pf_psa_algorithm_t pf_psa_hash_alg = pf_mbedtls_md_psa_alg_from_type(hash_alg);
    const size_t hash_len = PF_PSA_HASH_LENGTH(pf_psa_hash_alg);
    const unsigned char *secret = ssl->session->app_secrets.exporter_master_secret;

    /* The length of the label must be at most 249 bytes to fit into the HkdfLabel
     * struct as defined in RFC 8446, Section 7.1.
     *
     * The length of the context is unlimited even though the context field in the
     * struct can only hold up to 255 bytes. This is because we place a *hash* of
     * the context in the field. */
    if (label_len > 249) {
        return PF_MBEDTLS_ERR_SSL_BAD_INPUT_DATA;
    }

    return pf_mbedtls_ssl_tls13_exporter(pf_psa_hash_alg, secret, hash_len,
                                      (const unsigned char *) label, label_len,
                                      context, context_len, out, key_len);
}
#endif /* defined(MBEDTLS_SSL_PROTO_TLS1_3) */

int pf_mbedtls_ssl_export_keying_material(pf_mbedtls_ssl_context *ssl,
                                       uint8_t *out, const size_t key_len,
                                       const char *label, const size_t label_len,
                                       const unsigned char *context, const size_t context_len,
                                       const int use_context)
{
    if (!pf_mbedtls_ssl_is_handshake_over(ssl)) {
        /* TODO: Change this to a more appropriate error code when one is available. */
        return PF_MBEDTLS_ERR_SSL_BAD_INPUT_DATA;
    }

    if (key_len > PF_MBEDTLS_SSL_EXPORT_MAX_KEY_LEN) {
        return PF_MBEDTLS_ERR_SSL_BAD_INPUT_DATA;
    }

    int ciphersuite_id = pf_mbedtls_ssl_get_ciphersuite_id_from_ssl(ssl);
    const pf_mbedtls_ssl_ciphersuite_t *ciphersuite = pf_mbedtls_ssl_ciphersuite_from_id(ciphersuite_id);
    const pf_mbedtls_md_type_t hash_alg = ciphersuite->mac;

    switch (pf_mbedtls_ssl_get_version_number(ssl)) {
#if defined(PF_MBEDTLS_SSL_PROTO_TLS1_2)
        case PF_MBEDTLS_SSL_VERSION_TLS1_2:
            return pf_mbedtls_ssl_tls12_export_keying_material(ssl, hash_alg, out, key_len,
                                                            label, label_len,
                                                            context, context_len, use_context);
#endif
#if defined(PF_MBEDTLS_SSL_PROTO_TLS1_3)
        case PF_MBEDTLS_SSL_VERSION_TLS1_3:
            return pf_mbedtls_ssl_tls13_export_keying_material(ssl,
                                                            hash_alg,
                                                            out,
                                                            key_len,
                                                            label,
                                                            label_len,
                                                            use_context ? context : NULL,
                                                            use_context ? context_len : 0);
#endif
        default:
            return PF_MBEDTLS_ERR_SSL_BAD_PROTOCOL_VERSION;
    }
}

#endif /* defined(MBEDTLS_SSL_KEYING_MATERIAL_EXPORT) */

#endif /* MBEDTLS_SSL_TLS_C */
