#include "../../../pf_build_config.h"
/*
 *  TLS 1.3 functionality shared between client and server
 *
 *  Copyright The Mbed TLS Contributors
 *  SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
 */

#include "common.h"

#if defined(PF_MBEDTLS_SSL_TLS_C) && defined(PF_MBEDTLS_SSL_PROTO_TLS1_3)

#include <string.h>

#include "../include/mbedtls/error.h"
#include "debug_internal.h"
#include "../include/mbedtls/oid.h"
#include "../include/mbedtls/platform.h"
#include "../include/mbedtls/constant_time.h"
#include "../include/psa/crypto.h"
#include "../include/mbedtls/psa_util.h"

#include "ssl_misc.h"
#include "ssl_tls13_invasive.h"
#include "ssl_tls13_keys.h"
#include "ssl_debug_helpers.h"

#include "../include/psa/crypto.h"
#include "psa_util_internal.h"

/* Define a local translating function to save code size by not using too many
 * arguments in each translating place. */
static int local_err_translation(pf_psa_status_t status)
{
    return pf_psa_status_to_mbedtls(status, pf_psa_to_ssl_errors,
                                 ARRAY_LENGTH(pf_psa_to_ssl_errors),
                                 pf_psa_generic_status_to_mbedtls);
}
#define PF_PSA_TO_MBEDTLS_ERR(status) local_err_translation(status)

int pf_mbedtls_ssl_tls13_crypto_init(pf_mbedtls_ssl_context *ssl)
{
    pf_psa_status_t status = pf_psa_crypto_init();
    if (status != PF_PSA_SUCCESS) {
        (void) ssl; // unused when debugging is disabled
        PF_MBEDTLS_SSL_DEBUG_RET(1, "psa_crypto_init", status);
    }
    return PF_PSA_TO_MBEDTLS_ERR(status);
}

const uint8_t pf_mbedtls_ssl_tls13_hello_retry_request_magic[
    PF_MBEDTLS_SERVER_HELLO_RANDOM_LEN] =
{ 0xCF, 0x21, 0xAD, 0x74, 0xE5, 0x9A, 0x61, 0x11,
  0xBE, 0x1D, 0x8C, 0x02, 0x1E, 0x65, 0xB8, 0x91,
  0xC2, 0xA2, 0x11, 0x16, 0x7A, 0xBB, 0x8C, 0x5E,
  0x07, 0x9E, 0x09, 0xE2, 0xC8, 0xA8, 0x33, 0x9C };

int pf_mbedtls_ssl_tls13_fetch_handshake_msg(pf_mbedtls_ssl_context *ssl,
                                          unsigned hs_type,
                                          unsigned char **buf,
                                          size_t *buf_len)
{
    int ret = PF_MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    int require_record_boundary;

    /* Require record-boundary alignment by default. The exceptions below are
     * handshake messages that may legitimately be followed by additional
     * handshake messages in the same record. Using the default behaviour for a
     * message that should be exempt is an interoperability bug; exempting a
     * message that should not be exempt may have security implications.
     */
    switch (hs_type) {
        case PF_MBEDTLS_SSL_HS_NEW_SESSION_TICKET:
        case PF_MBEDTLS_SSL_HS_ENCRYPTED_EXTENSIONS:
        case PF_MBEDTLS_SSL_HS_CERTIFICATE:
        case PF_MBEDTLS_SSL_HS_CERTIFICATE_REQUEST:
        case PF_MBEDTLS_SSL_HS_CERTIFICATE_VERIFY:
        /*
         * For TLS 1.3, ServerHello (including HelloRetryRequest) must end at a
         * record boundary, but not for TLS 1.2. At this point the ServerHello
         * has not yet been processed, so we do not know whether it negotiates
         * TLS 1.3 or TLS 1.2. Defer the boundary check until the protocol
         * version is known to be TLS 1.3.
         */
        case PF_MBEDTLS_SSL_HS_SERVER_HELLO:
            require_record_boundary = 0;
            break;

        default:
            /* ClientHello, EndOfEarlyData, Finished, and KeyUpdate.
             */
            require_record_boundary = 1;
    }

    ret = pf_mbedtls_ssl_read_record(ssl, 0);
    if (ret != 0) {
        PF_MBEDTLS_SSL_DEBUG_RET(1, "mbedtls_ssl_read_record", ret);
        goto error;
    }

    ret = PF_MBEDTLS_ERR_SSL_UNEXPECTED_MESSAGE;
    if (ssl->in_msgtype != PF_MBEDTLS_SSL_MSG_HANDSHAKE ||
        ssl->in_msg[0]  != hs_type) {
        PF_MBEDTLS_SSL_DEBUG_MSG(1, ("Receive unexpected handshake message."));
        goto error;
    }

    if (require_record_boundary && (ssl->in_hslen != ssl->in_msglen)) {
        PF_MBEDTLS_SSL_DEBUG_MSG(1, ("Handshake message %s end not aligned with a record boundary",
                                  pf_mbedtls_ssl_get_hs_msg_name(hs_type)));
        goto error;
    }

    /*
     * Jump handshake header (4 bytes, see Section 4 of RFC 8446).
     *    ...
     *    HandshakeType msg_type;
     *    uint24 length;
     *    ...
     */
    *buf = ssl->in_msg + 4;
    *buf_len = ssl->in_hslen - 4;
    return 0;

error:
    if (ret == PF_MBEDTLS_ERR_SSL_UNEXPECTED_MESSAGE) {
        PF_MBEDTLS_SSL_PEND_FATAL_ALERT(PF_MBEDTLS_SSL_ALERT_MSG_UNEXPECTED_MESSAGE,
                                     PF_MBEDTLS_ERR_SSL_UNEXPECTED_MESSAGE);
    }
    return ret;
}

int pf_mbedtls_ssl_tls13_is_supported_versions_ext_present_in_exts(
    pf_mbedtls_ssl_context *ssl,
    const unsigned char *buf, const unsigned char *end,
    const unsigned char **supported_versions_data,
    const unsigned char **supported_versions_data_end)
{
    const unsigned char *p = buf;
    size_t extensions_len;
    const unsigned char *extensions_end;

    *supported_versions_data = NULL;
    *supported_versions_data_end = NULL;

    /* Case of no extension */
    if (p == end) {
        return 0;
    }

    /* ...
     * Extension extensions<x..2^16-1>;
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

    while (p < extensions_end) {
        unsigned int extension_type;
        size_t extension_data_len;

        PF_MBEDTLS_SSL_CHK_BUF_READ_PTR(p, extensions_end, 4);
        extension_type = PF_MBEDTLS_GET_UINT16_BE(p, 0);
        extension_data_len = PF_MBEDTLS_GET_UINT16_BE(p, 2);
        p += 4;
        PF_MBEDTLS_SSL_CHK_BUF_READ_PTR(p, extensions_end, extension_data_len);

        if (extension_type == PF_MBEDTLS_TLS_EXT_SUPPORTED_VERSIONS) {
            *supported_versions_data = p;
            *supported_versions_data_end = p + extension_data_len;
            return 1;
        }
        p += extension_data_len;
    }

    return 0;
}

#if defined(PF_MBEDTLS_SSL_TLS1_3_KEY_EXCHANGE_MODE_EPHEMERAL_ENABLED)
/*
 * STATE HANDLING: Read CertificateVerify
 */
/* Macro to express the maximum length of the verify structure.
 *
 * The structure is computed per TLS 1.3 specification as:
 *   - 64 bytes of octet 32,
 *   - 33 bytes for the context string
 *        (which is either "TLS 1.3, client CertificateVerify"
 *         or "TLS 1.3, server CertificateVerify"),
 *   - 1 byte for the octet 0x0, which serves as a separator,
 *   - 32 or 48 bytes for the Transcript-Hash(Handshake Context, Certificate)
 *     (depending on the size of the transcript_hash)
 *
 * This results in a total size of
 * - 130 bytes for a SHA256-based transcript hash, or
 *   (64 + 33 + 1 + 32 bytes)
 * - 146 bytes for a SHA384-based transcript hash.
 *   (64 + 33 + 1 + 48 bytes)
 *
 */
#define SSL_VERIFY_STRUCT_MAX_SIZE  (64 +                          \
                                     33 +                          \
                                     1 +                          \
                                     PF_MBEDTLS_TLS1_3_MD_MAX_SIZE    \
                                     )

/*
 * The ssl_tls13_create_verify_structure() creates the verify structure.
 * As input, it requires the transcript hash.
 *
 * The caller has to ensure that the buffer has size at least
 * SSL_VERIFY_STRUCT_MAX_SIZE bytes.
 */
static void ssl_tls13_create_verify_structure(const unsigned char *transcript_hash,
                                              size_t transcript_hash_len,
                                              unsigned char *verify_buffer,
                                              size_t *verify_buffer_len,
                                              int from)
{
    size_t idx;

    /* RFC 8446, Section 4.4.3:
     *
     * The digital signature [in the CertificateVerify message] is then
     * computed over the concatenation of:
     * -  A string that consists of octet 32 (0x20) repeated 64 times
     * -  The context string
     * -  A single 0 byte which serves as the separator
     * -  The content to be signed
     */
    memset(verify_buffer, 0x20, 64);
    idx = 64;

    if (from == PF_MBEDTLS_SSL_IS_CLIENT) {
        memcpy(verify_buffer + idx, pf_mbedtls_ssl_tls13_labels.client_cv,
               PF_MBEDTLS_SSL_TLS1_3_LBL_LEN(client_cv));
        idx += PF_MBEDTLS_SSL_TLS1_3_LBL_LEN(client_cv);
    } else { /* from == MBEDTLS_SSL_IS_SERVER */
        memcpy(verify_buffer + idx, pf_mbedtls_ssl_tls13_labels.server_cv,
               PF_MBEDTLS_SSL_TLS1_3_LBL_LEN(server_cv));
        idx += PF_MBEDTLS_SSL_TLS1_3_LBL_LEN(server_cv);
    }

    verify_buffer[idx++] = 0x0;

    memcpy(verify_buffer + idx, transcript_hash, transcript_hash_len);
    idx += transcript_hash_len;

    *verify_buffer_len = idx;
}

PF_MBEDTLS_CHECK_RETURN_CRITICAL
static int ssl_tls13_parse_certificate_verify(pf_mbedtls_ssl_context *ssl,
                                              const unsigned char *buf,
                                              const unsigned char *end,
                                              const unsigned char *verify_buffer,
                                              size_t verify_buffer_len)
{
    int ret = PF_MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    pf_psa_status_t status = PF_PSA_ERROR_CORRUPTION_DETECTED;
    const unsigned char *p = buf;
    uint16_t algorithm;
    size_t signature_len;
    pf_mbedtls_pk_type_t sig_alg;
    pf_mbedtls_md_type_t md_alg;
    pf_psa_algorithm_t hash_alg = PF_PSA_ALG_NONE;
    unsigned char verify_hash[PF_PSA_HASH_MAX_SIZE];
    size_t verify_hash_len;

    void const *options = NULL;
#if defined(PF_MBEDTLS_X509_RSASSA_PSS_SUPPORT)
    pf_mbedtls_pk_rsassa_pss_options rsassa_pss_options;
#endif /* MBEDTLS_X509_RSASSA_PSS_SUPPORT */

    /*
     * struct {
     *     SignatureScheme algorithm;
     *     opaque signature<0..2^16-1>;
     * } CertificateVerify;
     */
    PF_MBEDTLS_SSL_CHK_BUF_READ_PTR(p, end, 2);
    algorithm = PF_MBEDTLS_GET_UINT16_BE(p, 0);
    p += 2;

    /* RFC 8446 section 4.4.3
     *
     * If the CertificateVerify message is sent by a server, the signature
     * algorithm MUST be one offered in the client's "signature_algorithms"
     * extension unless no valid certificate chain can be produced without
     * unsupported algorithms
     *
     * RFC 8446 section 4.4.2.2
     *
     * If the client cannot construct an acceptable chain using the provided
     * certificates and decides to abort the handshake, then it MUST abort the
     * handshake with an appropriate certificate-related alert
     * (by default, "unsupported_certificate").
     *
     * Check if algorithm is an offered signature algorithm.
     */
    if (!pf_mbedtls_ssl_sig_alg_is_offered(ssl, algorithm)) {
        /* algorithm not in offered signature algorithms list */
        PF_MBEDTLS_SSL_DEBUG_MSG(1, ("Received signature algorithm(%04x) is not "
                                  "offered.",
                                  (unsigned int) algorithm));
        goto error;
    }

    if (pf_mbedtls_ssl_get_pk_type_and_md_alg_from_sig_alg(
            algorithm, &sig_alg, &md_alg) != 0) {
        goto error;
    }

    hash_alg = pf_mbedtls_md_psa_alg_from_type(md_alg);
    if (hash_alg == 0) {
        goto error;
    }

    PF_MBEDTLS_SSL_DEBUG_MSG(3, ("Certificate Verify: Signature algorithm ( %04x )",
                              (unsigned int) algorithm));

    /*
     * Check the certificate's key type matches the signature alg
     */
    if (!pf_mbedtls_pk_can_do(&ssl->session_negotiate->peer_cert->pk, sig_alg)) {
        PF_MBEDTLS_SSL_DEBUG_MSG(1, ("signature algorithm doesn't match cert key"));
        goto error;
    }

    PF_MBEDTLS_SSL_CHK_BUF_READ_PTR(p, end, 2);
    signature_len = PF_MBEDTLS_GET_UINT16_BE(p, 0);
    p += 2;
    PF_MBEDTLS_SSL_CHK_BUF_READ_PTR(p, end, signature_len);

    status = pf_psa_hash_compute(hash_alg,
                              verify_buffer,
                              verify_buffer_len,
                              verify_hash,
                              sizeof(verify_hash),
                              &verify_hash_len);
    if (status != PF_PSA_SUCCESS) {
        PF_MBEDTLS_SSL_DEBUG_RET(1, "hash computation PSA error", status);
        goto error;
    }

    PF_MBEDTLS_SSL_DEBUG_BUF(3, "verify hash", verify_hash, verify_hash_len);
#if defined(PF_MBEDTLS_X509_RSASSA_PSS_SUPPORT)
    if (sig_alg == PF_MBEDTLS_PK_RSASSA_PSS) {
        rsassa_pss_options.mgf1_hash_id = md_alg;

        rsassa_pss_options.expected_salt_len = PF_PSA_HASH_LENGTH(hash_alg);
        options = (const void *) &rsassa_pss_options;
    }
#endif /* MBEDTLS_X509_RSASSA_PSS_SUPPORT */

    ret = pf_mbedtls_pk_verify_ext(sig_alg, options,
                                &ssl->session_negotiate->peer_cert->pk,
                                md_alg, verify_hash, verify_hash_len,
                                p, signature_len);
    if (ret == 0) {
        return ret;
    }
    PF_MBEDTLS_SSL_DEBUG_RET(1, "mbedtls_pk_verify_ext", ret);

error:
    /* RFC 8446 section 4.4.3
     *
     * If the verification fails, the receiver MUST terminate the handshake
     * with a "decrypt_error" alert.
     */
    PF_MBEDTLS_SSL_PEND_FATAL_ALERT(PF_MBEDTLS_SSL_ALERT_MSG_DECRYPT_ERROR,
                                 PF_MBEDTLS_ERR_SSL_HANDSHAKE_FAILURE);
    return PF_MBEDTLS_ERR_SSL_HANDSHAKE_FAILURE;

}
#endif /* MBEDTLS_SSL_TLS1_3_KEY_EXCHANGE_MODE_EPHEMERAL_ENABLED */

int pf_mbedtls_ssl_tls13_process_certificate_verify(pf_mbedtls_ssl_context *ssl)
{

#if defined(PF_MBEDTLS_SSL_TLS1_3_KEY_EXCHANGE_MODE_EPHEMERAL_ENABLED)
    int ret = PF_MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    unsigned char verify_buffer[SSL_VERIFY_STRUCT_MAX_SIZE];
    size_t verify_buffer_len;
    unsigned char transcript[PF_MBEDTLS_TLS1_3_MD_MAX_SIZE];
    size_t transcript_len;
    unsigned char *buf;
    size_t buf_len;

    PF_MBEDTLS_SSL_DEBUG_MSG(2, ("=> parse certificate verify"));

    PF_MBEDTLS_SSL_PROC_CHK(
        pf_mbedtls_ssl_tls13_fetch_handshake_msg(
            ssl, PF_MBEDTLS_SSL_HS_CERTIFICATE_VERIFY, &buf, &buf_len));

    /* Need to calculate the hash of the transcript first
     * before reading the message since otherwise it gets
     * included in the transcript
     */
    ret = pf_mbedtls_ssl_get_handshake_transcript(
        ssl,
        (pf_mbedtls_md_type_t) ssl->handshake->ciphersuite_info->mac,
        transcript, sizeof(transcript),
        &transcript_len);
    if (ret != 0) {
        PF_MBEDTLS_SSL_PEND_FATAL_ALERT(
            PF_MBEDTLS_SSL_ALERT_MSG_INTERNAL_ERROR,
            PF_MBEDTLS_ERR_SSL_INTERNAL_ERROR);
        return ret;
    }

    PF_MBEDTLS_SSL_DEBUG_BUF(3, "handshake hash", transcript, transcript_len);

    /* Create verify structure */
    ssl_tls13_create_verify_structure(transcript,
                                      transcript_len,
                                      verify_buffer,
                                      &verify_buffer_len,
                                      (ssl->conf->endpoint == PF_MBEDTLS_SSL_IS_CLIENT) ?
                                      PF_MBEDTLS_SSL_IS_SERVER :
                                      PF_MBEDTLS_SSL_IS_CLIENT);

    /* Process the message contents */
    PF_MBEDTLS_SSL_PROC_CHK(ssl_tls13_parse_certificate_verify(
                             ssl, buf, buf + buf_len,
                             verify_buffer, verify_buffer_len));

    PF_MBEDTLS_SSL_PROC_CHK(pf_mbedtls_ssl_add_hs_msg_to_checksum(
                             ssl, PF_MBEDTLS_SSL_HS_CERTIFICATE_VERIFY,
                             buf, buf_len));

cleanup:

    PF_MBEDTLS_SSL_DEBUG_MSG(2, ("<= parse certificate verify"));
    PF_MBEDTLS_SSL_DEBUG_RET(1, "mbedtls_ssl_tls13_process_certificate_verify", ret);
    return ret;
#else
    ((void) ssl);
    PF_MBEDTLS_SSL_DEBUG_MSG(1, ("should never happen"));
    return PF_MBEDTLS_ERR_SSL_INTERNAL_ERROR;
#endif /* MBEDTLS_SSL_TLS1_3_KEY_EXCHANGE_MODE_EPHEMERAL_ENABLED */
}

/*
 *
 * STATE HANDLING: Incoming Certificate.
 *
 */

#if defined(PF_MBEDTLS_SSL_TLS1_3_KEY_EXCHANGE_MODE_EPHEMERAL_ENABLED)
#if defined(PF_MBEDTLS_SSL_KEEP_PEER_CERTIFICATE)
/*
 * Structure of Certificate message:
 *
 * enum {
 *     X509(0),
 *     RawPublicKey(2),
 *     (255)
 * } CertificateType;
 *
 * struct {
 *     select (certificate_type) {
 *         case RawPublicKey:
 *           * From RFC 7250 ASN.1_subjectPublicKeyInfo *
 *           opaque ASN1_subjectPublicKeyInfo<1..2^24-1>;
 *         case X509:
 *           opaque cert_data<1..2^24-1>;
 *     };
 *     Extension extensions<0..2^16-1>;
 * } CertificateEntry;
 *
 * struct {
 *     opaque certificate_request_context<0..2^8-1>;
 *     CertificateEntry certificate_list<0..2^24-1>;
 * } Certificate;
 *
 */

/* Parse certificate chain send by the server. */
PF_MBEDTLS_CHECK_RETURN_CRITICAL
PF_MBEDTLS_STATIC_TESTABLE
int pf_mbedtls_ssl_tls13_parse_certificate(pf_mbedtls_ssl_context *ssl,
                                        const unsigned char *buf,
                                        const unsigned char *end)
{
    int ret = PF_MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    size_t certificate_request_context_len = 0;
    size_t certificate_list_len = 0;
    const unsigned char *p = buf;
    const unsigned char *certificate_list_end;
    pf_mbedtls_ssl_handshake_params *handshake = ssl->handshake;

    PF_MBEDTLS_SSL_CHK_BUF_READ_PTR(p, end, 4);
    certificate_request_context_len = p[0];
    certificate_list_len = PF_MBEDTLS_GET_UINT24_BE(p, 1);
    p += 4;

    /* In theory, the certificate list can be up to 2^24 Bytes, but we don't
     * support anything beyond 2^16 = 64K.
     */
    if ((certificate_request_context_len != 0) ||
        (certificate_list_len >= 0x10000)) {
        PF_MBEDTLS_SSL_DEBUG_MSG(1, ("bad certificate message"));
        PF_MBEDTLS_SSL_PEND_FATAL_ALERT(PF_MBEDTLS_SSL_ALERT_MSG_DECODE_ERROR,
                                     PF_MBEDTLS_ERR_SSL_DECODE_ERROR);
        return PF_MBEDTLS_ERR_SSL_DECODE_ERROR;
    }

    /* In case we tried to reuse a session but it failed */
    if (ssl->session_negotiate->peer_cert != NULL) {
        pf_mbedtls_x509_crt_free(ssl->session_negotiate->peer_cert);
        pf_mbedtls_free(ssl->session_negotiate->peer_cert);
    }

    /* This is used by ssl_tls13_validate_certificate() */
    if (certificate_list_len == 0) {
        ssl->session_negotiate->peer_cert = NULL;
        ret = 0;
        goto exit;
    }

    if ((ssl->session_negotiate->peer_cert =
             pf_mbedtls_calloc(1, sizeof(pf_mbedtls_x509_crt))) == NULL) {
        PF_MBEDTLS_SSL_DEBUG_MSG(1, ("alloc( %" PF_MBEDTLS_PRINTF_SIZET " bytes ) failed",
                                  sizeof(pf_mbedtls_x509_crt)));
        PF_MBEDTLS_SSL_PEND_FATAL_ALERT(PF_MBEDTLS_SSL_ALERT_MSG_INTERNAL_ERROR,
                                     PF_MBEDTLS_ERR_SSL_ALLOC_FAILED);
        return PF_MBEDTLS_ERR_SSL_ALLOC_FAILED;
    }

    pf_mbedtls_x509_crt_init(ssl->session_negotiate->peer_cert);

    PF_MBEDTLS_SSL_CHK_BUF_READ_PTR(p, end, certificate_list_len);
    certificate_list_end = p + certificate_list_len;
    while (p < certificate_list_end) {
        size_t cert_data_len, extensions_len;
        const unsigned char *extensions_end;

        PF_MBEDTLS_SSL_CHK_BUF_READ_PTR(p, certificate_list_end, 3);
        cert_data_len = PF_MBEDTLS_GET_UINT24_BE(p, 0);
        p += 3;

        /* In theory, the CRT can be up to 2^24 Bytes, but we don't support
         * anything beyond 2^16 = 64K. Otherwise as in the TLS 1.2 code,
         * check that we have a minimum of 128 bytes of data, this is not
         * clear why we need that though.
         */
        if ((cert_data_len < 128) || (cert_data_len >= 0x10000)) {
            PF_MBEDTLS_SSL_DEBUG_MSG(1, ("bad Certificate message"));
            PF_MBEDTLS_SSL_PEND_FATAL_ALERT(PF_MBEDTLS_SSL_ALERT_MSG_DECODE_ERROR,
                                         PF_MBEDTLS_ERR_SSL_DECODE_ERROR);
            return PF_MBEDTLS_ERR_SSL_DECODE_ERROR;
        }

        PF_MBEDTLS_SSL_CHK_BUF_READ_PTR(p, certificate_list_end, cert_data_len);
        ret = pf_mbedtls_x509_crt_parse_der(ssl->session_negotiate->peer_cert,
                                         p, cert_data_len);

        switch (ret) {
            case 0: /*ok*/
                break;
            case PF_MBEDTLS_ERR_X509_UNKNOWN_SIG_ALG + PF_MBEDTLS_ERR_OID_NOT_FOUND:
                /* Ignore certificate with an unknown algorithm: maybe a
                   prior certificate was already trusted. */
                break;

            case PF_MBEDTLS_ERR_X509_ALLOC_FAILED:
                PF_MBEDTLS_SSL_PEND_FATAL_ALERT(PF_MBEDTLS_SSL_ALERT_MSG_INTERNAL_ERROR,
                                             PF_MBEDTLS_ERR_X509_ALLOC_FAILED);
                PF_MBEDTLS_SSL_DEBUG_RET(1, " mbedtls_x509_crt_parse_der", ret);
                return ret;

            case PF_MBEDTLS_ERR_X509_UNKNOWN_VERSION:
                PF_MBEDTLS_SSL_PEND_FATAL_ALERT(PF_MBEDTLS_SSL_ALERT_MSG_UNSUPPORTED_CERT,
                                             PF_MBEDTLS_ERR_X509_UNKNOWN_VERSION);
                PF_MBEDTLS_SSL_DEBUG_RET(1, " mbedtls_x509_crt_parse_der", ret);
                return ret;

            default:
                PF_MBEDTLS_SSL_PEND_FATAL_ALERT(PF_MBEDTLS_SSL_ALERT_MSG_BAD_CERT,
                                             ret);
                PF_MBEDTLS_SSL_DEBUG_RET(1, " mbedtls_x509_crt_parse_der", ret);
                return ret;
        }

        p += cert_data_len;

        /* Certificate extensions length */
        PF_MBEDTLS_SSL_CHK_BUF_READ_PTR(p, certificate_list_end, 2);
        extensions_len = PF_MBEDTLS_GET_UINT16_BE(p, 0);
        p += 2;
        PF_MBEDTLS_SSL_CHK_BUF_READ_PTR(p, certificate_list_end, extensions_len);

        extensions_end = p + extensions_len;
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
                ssl, PF_MBEDTLS_SSL_HS_CERTIFICATE, extension_type,
                PF_MBEDTLS_SSL_TLS1_3_ALLOWED_EXTS_OF_CT);
            if (ret != 0) {
                return ret;
            }

            switch (extension_type) {
                default:
                    PF_MBEDTLS_SSL_PRINT_EXT(
                        3, PF_MBEDTLS_SSL_HS_CERTIFICATE,
                        extension_type, "( ignored )");
                    break;
            }

            p += extension_data_len;
        }

        PF_MBEDTLS_SSL_PRINT_EXTS(3, PF_MBEDTLS_SSL_HS_CERTIFICATE,
                               handshake->received_extensions);
    }

exit:
    /* Check that all the message is consumed. */
    if (p != end) {
        PF_MBEDTLS_SSL_DEBUG_MSG(1, ("bad Certificate message"));
        PF_MBEDTLS_SSL_PEND_FATAL_ALERT(PF_MBEDTLS_SSL_ALERT_MSG_DECODE_ERROR,
                                     PF_MBEDTLS_ERR_SSL_DECODE_ERROR);
        return PF_MBEDTLS_ERR_SSL_DECODE_ERROR;
    }

    PF_MBEDTLS_SSL_DEBUG_CRT(3, "peer certificate",
                          ssl->session_negotiate->peer_cert);

    return ret;
}
#else
PF_MBEDTLS_CHECK_RETURN_CRITICAL
PF_MBEDTLS_STATIC_TESTABLE
int pf_mbedtls_ssl_tls13_parse_certificate(pf_mbedtls_ssl_context *ssl,
                                        const unsigned char *buf,
                                        const unsigned char *end)
{
    ((void) ssl);
    ((void) buf);
    ((void) end);
    return PF_MBEDTLS_ERR_SSL_FEATURE_UNAVAILABLE;
}
#endif /* MBEDTLS_SSL_KEEP_PEER_CERTIFICATE */
#endif /* MBEDTLS_SSL_TLS1_3_KEY_EXCHANGE_MODE_EPHEMERAL_ENABLED */

#if defined(PF_MBEDTLS_SSL_TLS1_3_KEY_EXCHANGE_MODE_EPHEMERAL_ENABLED)
#if defined(PF_MBEDTLS_SSL_KEEP_PEER_CERTIFICATE)
/* Validate certificate chain sent by the server. */
PF_MBEDTLS_CHECK_RETURN_CRITICAL
static int ssl_tls13_validate_certificate(pf_mbedtls_ssl_context *ssl)
{
    /* Authmode: precedence order is SNI if used else configuration */
#if defined(PF_MBEDTLS_SSL_SRV_C) && defined(PF_MBEDTLS_SSL_SERVER_NAME_INDICATION)
    const int authmode = ssl->handshake->sni_authmode != PF_MBEDTLS_SSL_VERIFY_UNSET
                       ? ssl->handshake->sni_authmode
                       : ssl->conf->authmode;
#else
    const int authmode = ssl->conf->authmode;
#endif

    /*
     * If the peer hasn't sent a certificate ( i.e. it sent
     * an empty certificate chain ), this is reflected in the peer CRT
     * structure being unset.
     * Check for that and handle it depending on the
     * authentication mode.
     */
    if (ssl->session_negotiate->peer_cert == NULL) {
        PF_MBEDTLS_SSL_DEBUG_MSG(1, ("peer has no certificate"));

#if defined(PF_MBEDTLS_SSL_SRV_C)
        if (ssl->conf->endpoint == PF_MBEDTLS_SSL_IS_SERVER) {
            /* The client was asked for a certificate but didn't send
             * one. The client should know what's going on, so we
             * don't send an alert.
             */
            ssl->session_negotiate->verify_result = PF_MBEDTLS_X509_BADCERT_MISSING;
            if (authmode == PF_MBEDTLS_SSL_VERIFY_OPTIONAL) {
                return 0;
            } else {
                PF_MBEDTLS_SSL_PEND_FATAL_ALERT(
                    PF_MBEDTLS_SSL_ALERT_MSG_NO_CERT,
                    PF_MBEDTLS_ERR_SSL_NO_CLIENT_CERTIFICATE);
                return PF_MBEDTLS_ERR_SSL_NO_CLIENT_CERTIFICATE;
            }
        }
#endif /* MBEDTLS_SSL_SRV_C */

#if defined(PF_MBEDTLS_SSL_CLI_C)
        /* Regardless of authmode, the server is not allowed to send an empty
         * certificate chain. (Last paragraph before 4.4.2.1 in RFC 8446: "The
         * server's certificate_list MUST always be non-empty.") With authmode
         * optional/none, we continue the handshake if we can't validate the
         * server's cert, but we still break it if no certificate was sent. */
        if (ssl->conf->endpoint == PF_MBEDTLS_SSL_IS_CLIENT) {
            PF_MBEDTLS_SSL_PEND_FATAL_ALERT(PF_MBEDTLS_SSL_ALERT_MSG_NO_CERT,
                                         PF_MBEDTLS_ERR_SSL_FATAL_ALERT_MESSAGE);
            return PF_MBEDTLS_ERR_SSL_FATAL_ALERT_MESSAGE;
        }
#endif /* MBEDTLS_SSL_CLI_C */
    }

    return pf_mbedtls_ssl_verify_certificate(ssl, authmode,
                                          ssl->session_negotiate->peer_cert,
                                          NULL, NULL);
}
#else /* MBEDTLS_SSL_KEEP_PEER_CERTIFICATE */
PF_MBEDTLS_CHECK_RETURN_CRITICAL
static int ssl_tls13_validate_certificate(pf_mbedtls_ssl_context *ssl)
{
    ((void) ssl);
    return PF_MBEDTLS_ERR_SSL_FEATURE_UNAVAILABLE;
}
#endif /* MBEDTLS_SSL_KEEP_PEER_CERTIFICATE */
#endif /* MBEDTLS_SSL_TLS1_3_KEY_EXCHANGE_MODE_EPHEMERAL_ENABLED */

int pf_mbedtls_ssl_tls13_process_certificate(pf_mbedtls_ssl_context *ssl)
{
    int ret = PF_MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    PF_MBEDTLS_SSL_DEBUG_MSG(2, ("=> parse certificate"));

#if defined(PF_MBEDTLS_SSL_TLS1_3_KEY_EXCHANGE_MODE_EPHEMERAL_ENABLED)
    unsigned char *buf;
    size_t buf_len;

    PF_MBEDTLS_SSL_PROC_CHK(pf_mbedtls_ssl_tls13_fetch_handshake_msg(
                             ssl, PF_MBEDTLS_SSL_HS_CERTIFICATE,
                             &buf, &buf_len));

    /* Parse the certificate chain sent by the peer. */
    PF_MBEDTLS_SSL_PROC_CHK(pf_mbedtls_ssl_tls13_parse_certificate(ssl, buf,
                                                             buf + buf_len));
    /* Validate the certificate chain and set the verification results. */
    PF_MBEDTLS_SSL_PROC_CHK(ssl_tls13_validate_certificate(ssl));

    PF_MBEDTLS_SSL_PROC_CHK(pf_mbedtls_ssl_add_hs_msg_to_checksum(
                             ssl, PF_MBEDTLS_SSL_HS_CERTIFICATE, buf, buf_len));

cleanup:
#else /* MBEDTLS_SSL_TLS1_3_KEY_EXCHANGE_MODE_EPHEMERAL_ENABLED */
    (void) ssl;
#endif /* MBEDTLS_SSL_TLS1_3_KEY_EXCHANGE_MODE_EPHEMERAL_ENABLED */

    PF_MBEDTLS_SSL_DEBUG_MSG(2, ("<= parse certificate"));
    return ret;
}
#if defined(PF_MBEDTLS_SSL_TLS1_3_KEY_EXCHANGE_MODE_EPHEMERAL_ENABLED)
/*
 *  enum {
 *        X509(0),
 *        RawPublicKey(2),
 *        (255)
 *    } CertificateType;
 *
 *    struct {
 *        select (certificate_type) {
 *            case RawPublicKey:
 *              // From RFC 7250 ASN.1_subjectPublicKeyInfo
 *              opaque ASN1_subjectPublicKeyInfo<1..2^24-1>;
 *
 *            case X509:
 *              opaque cert_data<1..2^24-1>;
 *        };
 *        Extension extensions<0..2^16-1>;
 *    } CertificateEntry;
 *
 *    struct {
 *        opaque certificate_request_context<0..2^8-1>;
 *        CertificateEntry certificate_list<0..2^24-1>;
 *    } Certificate;
 */
PF_MBEDTLS_CHECK_RETURN_CRITICAL
static int ssl_tls13_write_certificate_body(pf_mbedtls_ssl_context *ssl,
                                            unsigned char *buf,
                                            unsigned char *end,
                                            size_t *out_len)
{
    const pf_mbedtls_x509_crt *crt = pf_mbedtls_ssl_own_cert(ssl);
    unsigned char *p = buf;
    unsigned char *certificate_request_context =
        ssl->handshake->certificate_request_context;
    unsigned char certificate_request_context_len =
        ssl->handshake->certificate_request_context_len;
    unsigned char *p_certificate_list_len;


    /* ...
     * opaque certificate_request_context<0..2^8-1>;
     * ...
     */
    PF_MBEDTLS_SSL_CHK_BUF_PTR(p, end, certificate_request_context_len + 1);
    *p++ = certificate_request_context_len;
    if (certificate_request_context_len > 0) {
        memcpy(p, certificate_request_context, certificate_request_context_len);
        p += certificate_request_context_len;
    }

    /* ...
     * CertificateEntry certificate_list<0..2^24-1>;
     * ...
     */
    PF_MBEDTLS_SSL_CHK_BUF_PTR(p, end, 3);
    p_certificate_list_len = p;
    p += 3;

    PF_MBEDTLS_SSL_DEBUG_CRT(3, "own certificate", crt);

    while (crt != NULL) {
        size_t cert_data_len = crt->raw.len;

        PF_MBEDTLS_SSL_CHK_BUF_PTR(p, end, cert_data_len + 3 + 2);
        PF_MBEDTLS_PUT_UINT24_BE(cert_data_len, p, 0);
        p += 3;

        memcpy(p, crt->raw.p, cert_data_len);
        p += cert_data_len;
        crt = crt->next;

        /* Currently, we don't have any certificate extensions defined.
         * Hence, we are sending an empty extension with length zero.
         */
        PF_MBEDTLS_PUT_UINT16_BE(0, p, 0);
        p += 2;
    }

    PF_MBEDTLS_PUT_UINT24_BE(p - p_certificate_list_len - 3,
                          p_certificate_list_len, 0);

    *out_len = p - buf;

    PF_MBEDTLS_SSL_PRINT_EXTS(
        3, PF_MBEDTLS_SSL_HS_CERTIFICATE, ssl->handshake->sent_extensions);

    return 0;
}

int pf_mbedtls_ssl_tls13_write_certificate(pf_mbedtls_ssl_context *ssl)
{
    int ret;
    unsigned char *buf;
    size_t buf_len, msg_len;

    PF_MBEDTLS_SSL_DEBUG_MSG(2, ("=> write certificate"));

    PF_MBEDTLS_SSL_PROC_CHK(pf_mbedtls_ssl_start_handshake_msg(
                             ssl, PF_MBEDTLS_SSL_HS_CERTIFICATE, &buf, &buf_len));

    PF_MBEDTLS_SSL_PROC_CHK(ssl_tls13_write_certificate_body(ssl,
                                                          buf,
                                                          buf + buf_len,
                                                          &msg_len));

    PF_MBEDTLS_SSL_PROC_CHK(pf_mbedtls_ssl_add_hs_msg_to_checksum(
                             ssl, PF_MBEDTLS_SSL_HS_CERTIFICATE, buf, msg_len));

    PF_MBEDTLS_SSL_PROC_CHK(pf_mbedtls_ssl_finish_handshake_msg(
                             ssl, buf_len, msg_len));
cleanup:

    PF_MBEDTLS_SSL_DEBUG_MSG(2, ("<= write certificate"));
    return ret;
}

/*
 * STATE HANDLING: Output Certificate Verify
 */
int pf_mbedtls_ssl_tls13_check_sig_alg_cert_key_match(uint16_t sig_alg,
                                                   pf_mbedtls_pk_context *key)
{
    pf_mbedtls_pk_type_t pk_type = (pf_mbedtls_pk_type_t) pf_mbedtls_ssl_sig_from_pk(key);
    size_t key_size = pf_mbedtls_pk_get_bitlen(key);

    switch (pk_type) {
        case PF_MBEDTLS_SSL_SIG_ECDSA:
            switch (key_size) {
                case 256:
                    return
                        sig_alg == PF_MBEDTLS_TLS1_3_SIG_ECDSA_SECP256R1_SHA256;

                case 384:
                    return
                        sig_alg == PF_MBEDTLS_TLS1_3_SIG_ECDSA_SECP384R1_SHA384;

                case 521:
                    return
                        sig_alg == PF_MBEDTLS_TLS1_3_SIG_ECDSA_SECP521R1_SHA512;
                default:
                    break;
            }
            break;

        case PF_MBEDTLS_SSL_SIG_RSA:
            switch (sig_alg) {
                case PF_MBEDTLS_TLS1_3_SIG_RSA_PSS_RSAE_SHA256: /* Intentional fallthrough */
                case PF_MBEDTLS_TLS1_3_SIG_RSA_PSS_RSAE_SHA384: /* Intentional fallthrough */
                case PF_MBEDTLS_TLS1_3_SIG_RSA_PSS_RSAE_SHA512:
                    return 1;

                default:
                    break;
            }
            break;

        default:
            break;
    }

    return 0;
}

PF_MBEDTLS_CHECK_RETURN_CRITICAL
static int ssl_tls13_write_certificate_verify_body(pf_mbedtls_ssl_context *ssl,
                                                   unsigned char *buf,
                                                   unsigned char *end,
                                                   size_t *out_len)
{
    int ret = PF_MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    unsigned char *p = buf;
    pf_mbedtls_pk_context *own_key;

    unsigned char handshake_hash[PF_MBEDTLS_TLS1_3_MD_MAX_SIZE];
    size_t handshake_hash_len;
    unsigned char verify_buffer[SSL_VERIFY_STRUCT_MAX_SIZE];
    size_t verify_buffer_len;

    uint16_t *sig_alg = ssl->handshake->received_sig_algs;
    size_t signature_len = 0;

    *out_len = 0;

    own_key = pf_mbedtls_ssl_own_key(ssl);
    if (own_key == NULL) {
        PF_MBEDTLS_SSL_DEBUG_MSG(1, ("should never happen"));
        return PF_MBEDTLS_ERR_SSL_INTERNAL_ERROR;
    }

    ret = pf_mbedtls_ssl_get_handshake_transcript(
        ssl, (pf_mbedtls_md_type_t) ssl->handshake->ciphersuite_info->mac,
        handshake_hash, sizeof(handshake_hash), &handshake_hash_len);
    if (ret != 0) {
        return ret;
    }

    PF_MBEDTLS_SSL_DEBUG_BUF(3, "handshake hash",
                          handshake_hash,
                          handshake_hash_len);

    ssl_tls13_create_verify_structure(handshake_hash, handshake_hash_len,
                                      verify_buffer, &verify_buffer_len,
                                      ssl->conf->endpoint);

    /*
     *  struct {
     *    SignatureScheme algorithm;
     *    opaque signature<0..2^16-1>;
     *  } CertificateVerify;
     */
    /* Check there is space for the algorithm identifier (2 bytes) and the
     * signature length (2 bytes).
     */
    PF_MBEDTLS_SSL_CHK_BUF_PTR(p, end, 4);

    for (; *sig_alg != PF_MBEDTLS_TLS1_3_SIG_NONE; sig_alg++) {
        pf_psa_status_t status = PF_PSA_ERROR_CORRUPTION_DETECTED;
        pf_mbedtls_pk_type_t pk_type = PF_MBEDTLS_PK_NONE;
        pf_mbedtls_md_type_t md_alg = PF_MBEDTLS_MD_NONE;
        pf_psa_algorithm_t pf_psa_algorithm = PF_PSA_ALG_NONE;
        unsigned char verify_hash[PF_PSA_HASH_MAX_SIZE];
        size_t verify_hash_len;

        if (!pf_mbedtls_ssl_sig_alg_is_offered(ssl, *sig_alg)) {
            continue;
        }

        if (!pf_mbedtls_ssl_tls13_sig_alg_for_cert_verify_is_supported(*sig_alg)) {
            continue;
        }

        if (!pf_mbedtls_ssl_tls13_check_sig_alg_cert_key_match(*sig_alg, own_key)) {
            continue;
        }

        if (pf_mbedtls_ssl_get_pk_type_and_md_alg_from_sig_alg(
                *sig_alg, &pk_type, &md_alg) != 0) {
            return PF_MBEDTLS_ERR_SSL_INTERNAL_ERROR;
        }

        /* Hash verify buffer with indicated hash function */
        pf_psa_algorithm = pf_mbedtls_md_psa_alg_from_type(md_alg);
        status = pf_psa_hash_compute(pf_psa_algorithm,
                                  verify_buffer,
                                  verify_buffer_len,
                                  verify_hash, sizeof(verify_hash),
                                  &verify_hash_len);
        if (status != PF_PSA_SUCCESS) {
            return PF_PSA_TO_MBEDTLS_ERR(status);
        }

        PF_MBEDTLS_SSL_DEBUG_BUF(3, "verify hash", verify_hash, verify_hash_len);

        if ((ret = pf_mbedtls_pk_sign_ext(pk_type, own_key,
                                       md_alg, verify_hash, verify_hash_len,
                                       p + 4, (size_t) (end - (p + 4)), &signature_len,
                                       ssl->conf->f_rng, ssl->conf->p_rng)) != 0) {
            PF_MBEDTLS_SSL_DEBUG_MSG(2, ("CertificateVerify signature failed with %s",
                                      pf_mbedtls_ssl_sig_alg_to_str(*sig_alg)));
            PF_MBEDTLS_SSL_DEBUG_RET(2, "mbedtls_pk_sign_ext", ret);

            /* The signature failed. This is possible if the private key
             * was not suitable for the signature operation as purposely we
             * did not check its suitability completely. Let's try with
             * another signature algorithm.
             */
            continue;
        }

        PF_MBEDTLS_SSL_DEBUG_MSG(2, ("CertificateVerify signature with %s",
                                  pf_mbedtls_ssl_sig_alg_to_str(*sig_alg)));

        break;
    }

    if (*sig_alg == PF_MBEDTLS_TLS1_3_SIG_NONE) {
        PF_MBEDTLS_SSL_DEBUG_MSG(1, ("no suitable signature algorithm"));
        PF_MBEDTLS_SSL_PEND_FATAL_ALERT(PF_MBEDTLS_SSL_ALERT_MSG_HANDSHAKE_FAILURE,
                                     PF_MBEDTLS_ERR_SSL_HANDSHAKE_FAILURE);
        return PF_MBEDTLS_ERR_SSL_HANDSHAKE_FAILURE;
    }

    PF_MBEDTLS_PUT_UINT16_BE(*sig_alg, p, 0);
    PF_MBEDTLS_PUT_UINT16_BE(signature_len, p, 2);

    *out_len = 4 + signature_len;

    return 0;
}

int pf_mbedtls_ssl_tls13_write_certificate_verify(pf_mbedtls_ssl_context *ssl)
{
    int ret = 0;
    unsigned char *buf;
    size_t buf_len, msg_len;

    PF_MBEDTLS_SSL_DEBUG_MSG(2, ("=> write certificate verify"));

    PF_MBEDTLS_SSL_PROC_CHK(pf_mbedtls_ssl_start_handshake_msg(
                             ssl, PF_MBEDTLS_SSL_HS_CERTIFICATE_VERIFY,
                             &buf, &buf_len));

    PF_MBEDTLS_SSL_PROC_CHK(ssl_tls13_write_certificate_verify_body(
                             ssl, buf, buf + buf_len, &msg_len));

    PF_MBEDTLS_SSL_PROC_CHK(pf_mbedtls_ssl_add_hs_msg_to_checksum(
                             ssl, PF_MBEDTLS_SSL_HS_CERTIFICATE_VERIFY,
                             buf, msg_len));

    PF_MBEDTLS_SSL_PROC_CHK(pf_mbedtls_ssl_finish_handshake_msg(
                             ssl, buf_len, msg_len));

cleanup:

    PF_MBEDTLS_SSL_DEBUG_MSG(2, ("<= write certificate verify"));
    return ret;
}

#endif /* MBEDTLS_SSL_TLS1_3_KEY_EXCHANGE_MODE_EPHEMERAL_ENABLED */

/*
 *
 * STATE HANDLING: Incoming Finished message.
 */
/*
 * Implementation
 */

PF_MBEDTLS_CHECK_RETURN_CRITICAL
static int ssl_tls13_preprocess_finished_message(pf_mbedtls_ssl_context *ssl)
{
    int ret;

    ret = pf_mbedtls_ssl_tls13_calculate_verify_data(
        ssl,
        ssl->handshake->state_local.finished_in.digest,
        sizeof(ssl->handshake->state_local.finished_in.digest),
        &ssl->handshake->state_local.finished_in.digest_len,
        ssl->conf->endpoint == PF_MBEDTLS_SSL_IS_CLIENT ?
        PF_MBEDTLS_SSL_IS_SERVER : PF_MBEDTLS_SSL_IS_CLIENT);
    if (ret != 0) {
        PF_MBEDTLS_SSL_DEBUG_RET(1, "mbedtls_ssl_tls13_calculate_verify_data", ret);
        return ret;
    }

    return 0;
}

PF_MBEDTLS_CHECK_RETURN_CRITICAL
static int ssl_tls13_parse_finished_message(pf_mbedtls_ssl_context *ssl,
                                            const unsigned char *buf,
                                            const unsigned char *end)
{
    /*
     * struct {
     *     opaque verify_data[Hash.length];
     * } Finished;
     */
    const unsigned char *expected_verify_data =
        ssl->handshake->state_local.finished_in.digest;
    size_t expected_verify_data_len =
        ssl->handshake->state_local.finished_in.digest_len;
    /* Structural validation */
    if ((size_t) (end - buf) != expected_verify_data_len) {
        PF_MBEDTLS_SSL_DEBUG_MSG(1, ("bad finished message"));

        PF_MBEDTLS_SSL_PEND_FATAL_ALERT(PF_MBEDTLS_SSL_ALERT_MSG_DECODE_ERROR,
                                     PF_MBEDTLS_ERR_SSL_DECODE_ERROR);
        return PF_MBEDTLS_ERR_SSL_DECODE_ERROR;
    }

    PF_MBEDTLS_SSL_DEBUG_BUF(4, "verify_data (self-computed):",
                          expected_verify_data,
                          expected_verify_data_len);
    PF_MBEDTLS_SSL_DEBUG_BUF(4, "verify_data (received message):", buf,
                          expected_verify_data_len);

    /* Semantic validation */
    if (pf_mbedtls_ct_memcmp(buf,
                          expected_verify_data,
                          expected_verify_data_len) != 0) {
        PF_MBEDTLS_SSL_DEBUG_MSG(1, ("bad finished message"));

        PF_MBEDTLS_SSL_PEND_FATAL_ALERT(PF_MBEDTLS_SSL_ALERT_MSG_DECRYPT_ERROR,
                                     PF_MBEDTLS_ERR_SSL_HANDSHAKE_FAILURE);
        return PF_MBEDTLS_ERR_SSL_HANDSHAKE_FAILURE;
    }
    return 0;
}

int pf_mbedtls_ssl_tls13_process_finished_message(pf_mbedtls_ssl_context *ssl)
{
    int ret = PF_MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    unsigned char *buf;
    size_t buf_len;

    PF_MBEDTLS_SSL_DEBUG_MSG(2, ("=> parse finished message"));

    PF_MBEDTLS_SSL_PROC_CHK(pf_mbedtls_ssl_tls13_fetch_handshake_msg(
                             ssl, PF_MBEDTLS_SSL_HS_FINISHED, &buf, &buf_len));

    /* Preprocessing step: Compute handshake digest */
    PF_MBEDTLS_SSL_PROC_CHK(ssl_tls13_preprocess_finished_message(ssl));

    PF_MBEDTLS_SSL_PROC_CHK(ssl_tls13_parse_finished_message(
                             ssl, buf, buf + buf_len));

    PF_MBEDTLS_SSL_PROC_CHK(pf_mbedtls_ssl_add_hs_msg_to_checksum(
                             ssl, PF_MBEDTLS_SSL_HS_FINISHED, buf, buf_len));

cleanup:

    PF_MBEDTLS_SSL_DEBUG_MSG(2, ("<= parse finished message"));
    return ret;
}

/*
 *
 * STATE HANDLING: Write and send Finished message.
 *
 */
/*
 * Implement
 */

PF_MBEDTLS_CHECK_RETURN_CRITICAL
static int ssl_tls13_prepare_finished_message(pf_mbedtls_ssl_context *ssl)
{
    int ret;

    /* Compute transcript of handshake up to now. */
    ret = pf_mbedtls_ssl_tls13_calculate_verify_data(ssl,
                                                  ssl->handshake->state_local.finished_out.digest,
                                                  sizeof(ssl->handshake->state_local.finished_out.
                                                         digest),
                                                  &ssl->handshake->state_local.finished_out.digest_len,
                                                  ssl->conf->endpoint);

    if (ret != 0) {
        PF_MBEDTLS_SSL_DEBUG_RET(1, "calculate_verify_data failed", ret);
        return ret;
    }

    return 0;
}

PF_MBEDTLS_CHECK_RETURN_CRITICAL
static int ssl_tls13_write_finished_message_body(pf_mbedtls_ssl_context *ssl,
                                                 unsigned char *buf,
                                                 unsigned char *end,
                                                 size_t *out_len)
{
    size_t verify_data_len = ssl->handshake->state_local.finished_out.digest_len;
    /*
     * struct {
     *     opaque verify_data[Hash.length];
     * } Finished;
     */
    PF_MBEDTLS_SSL_CHK_BUF_PTR(buf, end, verify_data_len);

    memcpy(buf, ssl->handshake->state_local.finished_out.digest,
           verify_data_len);

    *out_len = verify_data_len;
    return 0;
}

/* Main entry point: orchestrates the other functions */
int pf_mbedtls_ssl_tls13_write_finished_message(pf_mbedtls_ssl_context *ssl)
{
    int ret = PF_MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    unsigned char *buf;
    size_t buf_len, msg_len;

    PF_MBEDTLS_SSL_DEBUG_MSG(2, ("=> write finished message"));

    PF_MBEDTLS_SSL_PROC_CHK(ssl_tls13_prepare_finished_message(ssl));

    PF_MBEDTLS_SSL_PROC_CHK(pf_mbedtls_ssl_start_handshake_msg(ssl,
                                                         PF_MBEDTLS_SSL_HS_FINISHED, &buf, &buf_len));

    PF_MBEDTLS_SSL_PROC_CHK(ssl_tls13_write_finished_message_body(
                             ssl, buf, buf + buf_len, &msg_len));

    PF_MBEDTLS_SSL_PROC_CHK(pf_mbedtls_ssl_add_hs_msg_to_checksum(ssl,
                                                            PF_MBEDTLS_SSL_HS_FINISHED, buf, msg_len));

    PF_MBEDTLS_SSL_PROC_CHK(pf_mbedtls_ssl_finish_handshake_msg(
                             ssl, buf_len, msg_len));
cleanup:

    PF_MBEDTLS_SSL_DEBUG_MSG(2, ("<= write finished message"));
    return ret;
}

void pf_mbedtls_ssl_tls13_handshake_wrapup(pf_mbedtls_ssl_context *ssl)
{

    PF_MBEDTLS_SSL_DEBUG_MSG(3, ("=> handshake wrapup"));

    PF_MBEDTLS_SSL_DEBUG_MSG(1, ("Switch to application keys for inbound traffic"));
    pf_mbedtls_ssl_set_inbound_transform(ssl, ssl->transform_application);

    PF_MBEDTLS_SSL_DEBUG_MSG(1, ("Switch to application keys for outbound traffic"));
    pf_mbedtls_ssl_set_outbound_transform(ssl, ssl->transform_application);

    /*
     * Free the previous session and switch to the current one.
     */
    if (ssl->session) {
        pf_mbedtls_ssl_session_free(ssl->session);
        pf_mbedtls_free(ssl->session);
    }
    ssl->session = ssl->session_negotiate;
    ssl->session_negotiate = NULL;

    PF_MBEDTLS_SSL_DEBUG_MSG(3, ("<= handshake wrapup"));
}

/*
 *
 * STATE HANDLING: Write ChangeCipherSpec
 *
 */
#if defined(PF_MBEDTLS_SSL_TLS1_3_COMPATIBILITY_MODE)
PF_MBEDTLS_CHECK_RETURN_CRITICAL
static int ssl_tls13_write_change_cipher_spec_body(pf_mbedtls_ssl_context *ssl,
                                                   unsigned char *buf,
                                                   unsigned char *end,
                                                   size_t *olen)
{
    ((void) ssl);

    PF_MBEDTLS_SSL_CHK_BUF_PTR(buf, end, 1);
    buf[0] = 1;
    *olen = 1;

    return 0;
}

int pf_mbedtls_ssl_tls13_write_change_cipher_spec(pf_mbedtls_ssl_context *ssl)
{
    int ret = PF_MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;

    PF_MBEDTLS_SSL_DEBUG_MSG(2, ("=> write change cipher spec"));

    /* Only one CCS to send. */
    if (ssl->handshake->ccs_sent) {
        ret = 0;
        goto cleanup;
    }

    /* Write CCS message */
    PF_MBEDTLS_SSL_PROC_CHK(ssl_tls13_write_change_cipher_spec_body(
                             ssl, ssl->out_msg,
                             ssl->out_msg + PF_MBEDTLS_SSL_OUT_CONTENT_LEN,
                             &ssl->out_msglen));

    ssl->out_msgtype = PF_MBEDTLS_SSL_MSG_CHANGE_CIPHER_SPEC;

    /* Dispatch message */
    PF_MBEDTLS_SSL_PROC_CHK(pf_mbedtls_ssl_write_record(ssl, 0));

    ssl->handshake->ccs_sent = 1;

cleanup:

    PF_MBEDTLS_SSL_DEBUG_MSG(2, ("<= write change cipher spec"));
    return ret;
}

#endif /* MBEDTLS_SSL_TLS1_3_COMPATIBILITY_MODE */

/* Early Data Indication Extension
 *
 * struct {
 *   select ( Handshake.msg_type ) {
 *     case new_session_ticket:   uint32 max_early_data_size;
 *     case client_hello:         Empty;
 *     case encrypted_extensions: Empty;
 *   };
 * } EarlyDataIndication;
 */
#if defined(PF_MBEDTLS_SSL_EARLY_DATA)
int pf_mbedtls_ssl_tls13_write_early_data_ext(pf_mbedtls_ssl_context *ssl,
                                           int in_new_session_ticket,
                                           unsigned char *buf,
                                           const unsigned char *end,
                                           size_t *out_len)
{
    unsigned char *p = buf;

#if defined(PF_MBEDTLS_SSL_SRV_C)
    const size_t needed = in_new_session_ticket ? 8 : 4;
#else
    const size_t needed = 4;
    ((void) in_new_session_ticket);
#endif

    *out_len = 0;

    PF_MBEDTLS_SSL_CHK_BUF_PTR(p, end, needed);

    PF_MBEDTLS_PUT_UINT16_BE(PF_MBEDTLS_TLS_EXT_EARLY_DATA, p, 0);
    PF_MBEDTLS_PUT_UINT16_BE(needed - 4, p, 2);

#if defined(PF_MBEDTLS_SSL_SRV_C)
    if (in_new_session_ticket) {
        PF_MBEDTLS_PUT_UINT32_BE(ssl->conf->max_early_data_size, p, 4);
        PF_MBEDTLS_SSL_DEBUG_MSG(
            4, ("Sent max_early_data_size=%u",
                (unsigned int) ssl->conf->max_early_data_size));
    }
#endif

    *out_len = needed;

    pf_mbedtls_ssl_tls13_set_hs_sent_ext_mask(ssl, PF_MBEDTLS_TLS_EXT_EARLY_DATA);

    return 0;
}

#if defined(PF_MBEDTLS_SSL_SRV_C)
int pf_mbedtls_ssl_tls13_check_early_data_len(pf_mbedtls_ssl_context *ssl,
                                           size_t early_data_len)
{
    /*
     * This function should be called only while an handshake is in progress
     * and thus a session under negotiation. Add a sanity check to detect a
     * misuse.
     */
    if (ssl->session_negotiate == NULL) {
        return PF_MBEDTLS_ERR_SSL_INTERNAL_ERROR;
    }

    /* RFC 8446 section 4.6.1
     *
     * A server receiving more than max_early_data_size bytes of 0-RTT data
     * SHOULD terminate the connection with an "unexpected_message" alert.
     * Note that if it is still possible to send early_data_len bytes of early
     * data, it means that early_data_len is smaller than max_early_data_size
     * (type uint32_t) and can fit in an uint32_t. We use this further
     * down.
     */
    if (early_data_len >
        (ssl->session_negotiate->max_early_data_size -
         ssl->total_early_data_size)) {

        PF_MBEDTLS_SSL_DEBUG_MSG(
            2, ("EarlyData: Too much early data received, "
                "%lu + %" PF_MBEDTLS_PRINTF_SIZET " > %lu",
                (unsigned long) ssl->total_early_data_size,
                early_data_len,
                (unsigned long) ssl->session_negotiate->max_early_data_size));

        PF_MBEDTLS_SSL_PEND_FATAL_ALERT(
            PF_MBEDTLS_SSL_ALERT_MSG_UNEXPECTED_MESSAGE,
            PF_MBEDTLS_ERR_SSL_UNEXPECTED_MESSAGE);
        return PF_MBEDTLS_ERR_SSL_UNEXPECTED_MESSAGE;
    }

    /*
     * early_data_len has been checked to be less than max_early_data_size
     * that is uint32_t. Its cast to an uint32_t below is thus safe. We need
     * the cast to appease some compilers.
     */
    ssl->total_early_data_size += (uint32_t) early_data_len;

    return 0;
}
#endif /* MBEDTLS_SSL_SRV_C */
#endif /* MBEDTLS_SSL_EARLY_DATA */

/* Reset SSL context and update hash for handling HRR.
 *
 * Replace Transcript-Hash(X) by
 * Transcript-Hash( message_hash     ||
 *                 00 00 Hash.length ||
 *                 X )
 * A few states of the handshake are preserved, including:
 *   - session ID
 *   - session ticket
 *   - negotiated ciphersuite
 */
int pf_mbedtls_ssl_reset_transcript_for_hrr(pf_mbedtls_ssl_context *ssl)
{
    int ret = PF_MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    unsigned char hash_transcript[PF_PSA_HASH_MAX_SIZE + 4];
    size_t hash_len;
    const pf_mbedtls_ssl_ciphersuite_t *ciphersuite_info =
        ssl->handshake->ciphersuite_info;

    PF_MBEDTLS_SSL_DEBUG_MSG(3, ("Reset SSL session for HRR"));

    ret = pf_mbedtls_ssl_get_handshake_transcript(ssl, (pf_mbedtls_md_type_t) ciphersuite_info->mac,
                                               hash_transcript + 4,
                                               PF_PSA_HASH_MAX_SIZE,
                                               &hash_len);
    if (ret != 0) {
        PF_MBEDTLS_SSL_DEBUG_RET(1, "mbedtls_ssl_get_handshake_transcript", ret);
        return ret;
    }

    hash_transcript[0] = PF_MBEDTLS_SSL_HS_MESSAGE_HASH;
    hash_transcript[1] = 0;
    hash_transcript[2] = 0;
    hash_transcript[3] = (unsigned char) hash_len;

    hash_len += 4;

    PF_MBEDTLS_SSL_DEBUG_BUF(4, "Truncated handshake transcript",
                          hash_transcript, hash_len);

    /* Reset running hash and replace it with a hash of the transcript */
    ret = pf_mbedtls_ssl_reset_checksum(ssl);
    if (ret != 0) {
        PF_MBEDTLS_SSL_DEBUG_RET(1, "mbedtls_ssl_reset_checksum", ret);
        return ret;
    }
    ret = ssl->handshake->update_checksum(ssl, hash_transcript, hash_len);
    if (ret != 0) {
        PF_MBEDTLS_SSL_DEBUG_RET(1, "update_checksum", ret);
        return ret;
    }

    return ret;
}

#if defined(PF_MBEDTLS_SSL_TLS1_3_KEY_EXCHANGE_MODE_SOME_EPHEMERAL_ENABLED)

int pf_mbedtls_ssl_tls13_read_public_xxdhe_share(pf_mbedtls_ssl_context *ssl,
                                              const unsigned char *buf,
                                              size_t buf_len)
{
    uint8_t *p = (uint8_t *) buf;
    const uint8_t *end = buf + buf_len;
    pf_mbedtls_ssl_handshake_params *handshake = ssl->handshake;

    /* Get size of the TLS opaque key_exchange field of the KeyShareEntry struct. */
    PF_MBEDTLS_SSL_CHK_BUF_READ_PTR(p, end, 2);
    uint16_t peerkey_len = PF_MBEDTLS_GET_UINT16_BE(p, 0);
    p += 2;

    /* Check if key size is consistent with given buffer length. */
    PF_MBEDTLS_SSL_CHK_BUF_READ_PTR(p, end, peerkey_len);

    /* Store peer's ECDH/FFDH public key. */
    if (peerkey_len > sizeof(handshake->xxdh_psa_peerkey)) {
        PF_MBEDTLS_SSL_DEBUG_MSG(1, ("Invalid public key length: %u > %" PF_MBEDTLS_PRINTF_SIZET,
                                  (unsigned) peerkey_len,
                                  sizeof(handshake->xxdh_psa_peerkey)));
        return PF_MBEDTLS_ERR_SSL_HANDSHAKE_FAILURE;
    }
    memcpy(handshake->xxdh_psa_peerkey, p, peerkey_len);
    handshake->xxdh_psa_peerkey_len = peerkey_len;

    return 0;
}

#if defined(PF_PSA_WANT_ALG_FFDH)
static pf_psa_status_t  pf_mbedtls_ssl_get_psa_ffdh_info_from_tls_id(
    uint16_t tls_id, size_t *bits, pf_psa_key_type_t *key_type)
{
    switch (tls_id) {
#if defined(PF_PSA_WANT_DH_RFC7919_2048)
        case PF_MBEDTLS_SSL_IANA_TLS_GROUP_FFDHE2048:
            *bits = 2048;
            *key_type = PF_PSA_KEY_TYPE_DH_KEY_PAIR(PF_PSA_DH_FAMILY_RFC7919);
            return PF_PSA_SUCCESS;
#endif /* PSA_WANT_DH_RFC7919_2048 */
#if defined(PF_PSA_WANT_DH_RFC7919_3072)
        case PF_MBEDTLS_SSL_IANA_TLS_GROUP_FFDHE3072:
            *bits = 3072;
            *key_type =  PF_PSA_KEY_TYPE_DH_KEY_PAIR(PF_PSA_DH_FAMILY_RFC7919);
            return PF_PSA_SUCCESS;
#endif /* PSA_WANT_DH_RFC7919_3072 */
#if defined(PF_PSA_WANT_DH_RFC7919_4096)
        case PF_MBEDTLS_SSL_IANA_TLS_GROUP_FFDHE4096:
            *bits = 4096;
            *key_type =  PF_PSA_KEY_TYPE_DH_KEY_PAIR(PF_PSA_DH_FAMILY_RFC7919);
            return PF_PSA_SUCCESS;
#endif /* PSA_WANT_DH_RFC7919_4096 */
#if defined(PF_PSA_WANT_DH_RFC7919_6144)
        case PF_MBEDTLS_SSL_IANA_TLS_GROUP_FFDHE6144:
            *bits = 6144;
            *key_type =  PF_PSA_KEY_TYPE_DH_KEY_PAIR(PF_PSA_DH_FAMILY_RFC7919);
            return PF_PSA_SUCCESS;
#endif /* PSA_WANT_DH_RFC7919_6144 */
#if defined(PF_PSA_WANT_DH_RFC7919_8192)
        case PF_MBEDTLS_SSL_IANA_TLS_GROUP_FFDHE8192:
            *bits = 8192;
            *key_type =  PF_PSA_KEY_TYPE_DH_KEY_PAIR(PF_PSA_DH_FAMILY_RFC7919);
            return PF_PSA_SUCCESS;
#endif /* PSA_WANT_DH_RFC7919_8192 */
        default:
            return PF_PSA_ERROR_NOT_SUPPORTED;
    }
}
#endif /* PSA_WANT_ALG_FFDH */

int pf_mbedtls_ssl_tls13_generate_and_write_xxdh_key_exchange(
    pf_mbedtls_ssl_context *ssl,
    uint16_t named_group,
    unsigned char *buf,
    unsigned char *end,
    size_t *out_len)
{
    pf_psa_status_t status = PF_PSA_ERROR_GENERIC_ERROR;
    int ret = PF_MBEDTLS_ERR_SSL_FEATURE_UNAVAILABLE;
    pf_psa_key_attributes_t key_attributes;
    size_t own_pubkey_len;
    pf_mbedtls_ssl_handshake_params *handshake = ssl->handshake;
    size_t bits = 0;
    pf_psa_key_type_t key_type = PF_PSA_KEY_TYPE_NONE;
    pf_psa_algorithm_t alg = PF_PSA_ALG_NONE;
    size_t buf_size = (size_t) (end - buf);

    PF_MBEDTLS_SSL_DEBUG_MSG(1, ("Perform PSA-based ECDH/FFDH computation."));

    /* Convert EC's TLS ID to PSA key type. */
#if defined(PF_PSA_WANT_ALG_ECDH)
    if (pf_mbedtls_ssl_get_psa_curve_info_from_tls_id(
            named_group, &key_type, &bits) == PF_PSA_SUCCESS) {
        alg = PF_PSA_ALG_ECDH;
    }
#endif
#if defined(PF_PSA_WANT_ALG_FFDH)
    if (pf_mbedtls_ssl_get_psa_ffdh_info_from_tls_id(named_group, &bits,
                                                  &key_type) == PF_PSA_SUCCESS) {
        alg = PF_PSA_ALG_FFDH;
    }
#endif

    if (key_type == PF_PSA_KEY_TYPE_NONE) {
        return PF_MBEDTLS_ERR_SSL_HANDSHAKE_FAILURE;
    }

    if (buf_size < PF_PSA_BITS_TO_BYTES(bits)) {
        return PF_MBEDTLS_ERR_SSL_BUFFER_TOO_SMALL;
    }

    handshake->xxdh_psa_type = key_type;
    ssl->handshake->xxdh_psa_bits = bits;

    key_attributes = pf_psa_key_attributes_init();
    pf_psa_set_key_usage_flags(&key_attributes, PF_PSA_KEY_USAGE_DERIVE);
    pf_psa_set_key_algorithm(&key_attributes, alg);
    pf_psa_set_key_type(&key_attributes, handshake->xxdh_psa_type);
    pf_psa_set_key_bits(&key_attributes, handshake->xxdh_psa_bits);

    /* Generate ECDH/FFDH private key. */
    status = pf_psa_generate_key(&key_attributes,
                              &handshake->xxdh_psa_privkey);
    if (status != PF_PSA_SUCCESS) {
        ret = PF_PSA_TO_MBEDTLS_ERR(status);
        PF_MBEDTLS_SSL_DEBUG_RET(1, "psa_generate_key", ret);
        return ret;

    }

    /* Export the public part of the ECDH/FFDH private key from PSA. */
    status = pf_psa_export_public_key(handshake->xxdh_psa_privkey,
                                   buf, buf_size,
                                   &own_pubkey_len);

    if (status != PF_PSA_SUCCESS) {
        ret = PF_PSA_TO_MBEDTLS_ERR(status);
        PF_MBEDTLS_SSL_DEBUG_RET(1, "psa_export_public_key", ret);
        return ret;
    }

    *out_len = own_pubkey_len;

    return 0;
}
#endif /* MBEDTLS_SSL_TLS1_3_KEY_EXCHANGE_MODE_SOME_EPHEMERAL_ENABLED */

/* RFC 8446 section 4.2
 *
 * If an implementation receives an extension which it recognizes and which is
 * not specified for the message in which it appears, it MUST abort the handshake
 * with an "illegal_parameter" alert.
 *
 */
int pf_mbedtls_ssl_tls13_check_received_extension(
    pf_mbedtls_ssl_context *ssl,
    int hs_msg_type,
    unsigned int received_extension_type,
    uint32_t hs_msg_allowed_extensions_mask)
{
    uint32_t extension_mask = pf_mbedtls_ssl_get_extension_mask(
        received_extension_type);

    PF_MBEDTLS_SSL_PRINT_EXT(
        3, hs_msg_type, received_extension_type, "received");

    if ((extension_mask & hs_msg_allowed_extensions_mask) == 0) {
        PF_MBEDTLS_SSL_PRINT_EXT(
            3, hs_msg_type, received_extension_type, "is illegal");
        PF_MBEDTLS_SSL_PEND_FATAL_ALERT(
            PF_MBEDTLS_SSL_ALERT_MSG_ILLEGAL_PARAMETER,
            PF_MBEDTLS_ERR_SSL_ILLEGAL_PARAMETER);
        return PF_MBEDTLS_ERR_SSL_ILLEGAL_PARAMETER;
    }

    ssl->handshake->received_extensions |= extension_mask;
    /*
     * If it is a message containing extension responses, check that we
     * previously sent the extension.
     */
    switch (hs_msg_type) {
        case PF_MBEDTLS_SSL_HS_SERVER_HELLO:
        case PF_MBEDTLS_SSL_TLS1_3_HS_HELLO_RETRY_REQUEST:
        case PF_MBEDTLS_SSL_HS_ENCRYPTED_EXTENSIONS:
        case PF_MBEDTLS_SSL_HS_CERTIFICATE:
            /* Check if the received extension is sent by peer message.*/
            if ((ssl->handshake->sent_extensions & extension_mask) != 0) {
                return 0;
            }
            break;
        default:
            return 0;
    }

    PF_MBEDTLS_SSL_PRINT_EXT(
        3, hs_msg_type, received_extension_type, "is unsupported");
    PF_MBEDTLS_SSL_PEND_FATAL_ALERT(
        PF_MBEDTLS_SSL_ALERT_MSG_UNSUPPORTED_EXT,
        PF_MBEDTLS_ERR_SSL_UNSUPPORTED_EXTENSION);
    return PF_MBEDTLS_ERR_SSL_UNSUPPORTED_EXTENSION;
}

#if defined(PF_MBEDTLS_SSL_RECORD_SIZE_LIMIT)

/* RFC 8449, section 4:
 *
 * The ExtensionData of the "record_size_limit" extension is
 * RecordSizeLimit:
 *     uint16 RecordSizeLimit;
 */
PF_MBEDTLS_CHECK_RETURN_CRITICAL
int pf_mbedtls_ssl_tls13_parse_record_size_limit_ext(pf_mbedtls_ssl_context *ssl,
                                                  const unsigned char *buf,
                                                  const unsigned char *end)
{
    const unsigned char *p = buf;
    uint16_t record_size_limit;
    const size_t extension_data_len = end - buf;

    if (extension_data_len !=
        PF_MBEDTLS_SSL_RECORD_SIZE_LIMIT_EXTENSION_DATA_LENGTH) {
        PF_MBEDTLS_SSL_DEBUG_MSG(2,
                              ("record_size_limit extension has invalid length: %"
                               PF_MBEDTLS_PRINTF_SIZET " Bytes",
                               extension_data_len));

        PF_MBEDTLS_SSL_PEND_FATAL_ALERT(
            PF_MBEDTLS_SSL_ALERT_MSG_ILLEGAL_PARAMETER,
            PF_MBEDTLS_ERR_SSL_ILLEGAL_PARAMETER);
        return PF_MBEDTLS_ERR_SSL_ILLEGAL_PARAMETER;
    }

    PF_MBEDTLS_SSL_CHK_BUF_READ_PTR(p, end, 2);
    record_size_limit = PF_MBEDTLS_GET_UINT16_BE(p, 0);

    PF_MBEDTLS_SSL_DEBUG_MSG(2, ("RecordSizeLimit: %u Bytes", record_size_limit));

    /* RFC 8449, section 4:
     *
     * Endpoints MUST NOT send a "record_size_limit" extension with a value
     * smaller than 64.  An endpoint MUST treat receipt of a smaller value
     * as a fatal error and generate an "illegal_parameter" alert.
     */
    if (record_size_limit < PF_MBEDTLS_SSL_RECORD_SIZE_LIMIT_MIN) {
        PF_MBEDTLS_SSL_DEBUG_MSG(1, ("Invalid record size limit : %u Bytes",
                                  record_size_limit));
        PF_MBEDTLS_SSL_PEND_FATAL_ALERT(
            PF_MBEDTLS_SSL_ALERT_MSG_ILLEGAL_PARAMETER,
            PF_MBEDTLS_ERR_SSL_ILLEGAL_PARAMETER);
        return PF_MBEDTLS_ERR_SSL_ILLEGAL_PARAMETER;
    }

    ssl->session_negotiate->record_size_limit = record_size_limit;

    return 0;
}

PF_MBEDTLS_CHECK_RETURN_CRITICAL
int pf_mbedtls_ssl_tls13_write_record_size_limit_ext(pf_mbedtls_ssl_context *ssl,
                                                  unsigned char *buf,
                                                  const unsigned char *end,
                                                  size_t *out_len)
{
    unsigned char *p = buf;
    *out_len = 0;

    PF_MBEDTLS_STATIC_ASSERT(PF_MBEDTLS_SSL_IN_CONTENT_LEN >= PF_MBEDTLS_SSL_RECORD_SIZE_LIMIT_MIN,
                          "MBEDTLS_SSL_IN_CONTENT_LEN is less than the "
                          "minimum record size limit");

    PF_MBEDTLS_SSL_CHK_BUF_PTR(p, end, 6);

    PF_MBEDTLS_PUT_UINT16_BE(PF_MBEDTLS_TLS_EXT_RECORD_SIZE_LIMIT, p, 0);
    PF_MBEDTLS_PUT_UINT16_BE(PF_MBEDTLS_SSL_RECORD_SIZE_LIMIT_EXTENSION_DATA_LENGTH,
                          p, 2);
    PF_MBEDTLS_PUT_UINT16_BE(PF_MBEDTLS_SSL_IN_CONTENT_LEN, p, 4);

    *out_len = 6;

    PF_MBEDTLS_SSL_DEBUG_MSG(2, ("Sent RecordSizeLimit: %d Bytes",
                              PF_MBEDTLS_SSL_IN_CONTENT_LEN));

    pf_mbedtls_ssl_tls13_set_hs_sent_ext_mask(ssl, PF_MBEDTLS_TLS_EXT_RECORD_SIZE_LIMIT);

    return 0;
}

#endif /* MBEDTLS_SSL_RECORD_SIZE_LIMIT */

#endif /* MBEDTLS_SSL_TLS_C && MBEDTLS_SSL_PROTO_TLS1_3 */
