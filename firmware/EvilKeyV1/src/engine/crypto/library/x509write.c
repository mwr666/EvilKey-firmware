#include "../../../pf_build_config.h"
/*
 *  X.509 internal, common functions for writing
 *
 *  Copyright The Mbed TLS Contributors
 *  SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
 */
#include "common.h"
#if defined(PF_MBEDTLS_X509_CSR_WRITE_C) || defined(PF_MBEDTLS_X509_CRT_WRITE_C)

#include "../include/mbedtls/x509_crt.h"
#include "x509_internal.h"
#include "../include/mbedtls/asn1write.h"
#include "../include/mbedtls/error.h"
#include "../include/mbedtls/oid.h"
#include "../include/mbedtls/platform.h"
#include "../include/mbedtls/platform_util.h"

#include <string.h>
#include <stdint.h>

#if defined(PF_MBEDTLS_PEM_WRITE_C)
#include "../include/mbedtls/pem.h"
#endif /* MBEDTLS_PEM_WRITE_C */

#if defined(PF_MBEDTLS_USE_PSA_CRYPTO)
#include "../include/psa/crypto.h"
#include "../include/mbedtls/psa_util.h"
#include "md_psa.h"
#endif /* MBEDTLS_USE_PSA_CRYPTO */

#define CHECK_OVERFLOW_ADD(a, b) \
    do                         \
    {                           \
        if (a > SIZE_MAX - (b)) \
        { \
            return PF_MBEDTLS_ERR_X509_BAD_INPUT_DATA; \
        }                            \
        a += b; \
    } while (0)

int pf_mbedtls_x509_write_set_san_common(pf_mbedtls_asn1_named_data **extensions,
                                      const pf_mbedtls_x509_san_list *san_list)
{
    int ret = 0;
    const pf_mbedtls_x509_san_list *cur;
    unsigned char *buf;
    unsigned char *p;
    size_t len;
    size_t buflen = 0;

    /* Determine the maximum size of the SubjectAltName list */
    for (cur = san_list; cur != NULL; cur = cur->next) {
        /* Calculate size of the required buffer */
        switch (cur->node.type) {
            case PF_MBEDTLS_X509_SAN_DNS_NAME:
            case PF_MBEDTLS_X509_SAN_UNIFORM_RESOURCE_IDENTIFIER:
            case PF_MBEDTLS_X509_SAN_IP_ADDRESS:
            case PF_MBEDTLS_X509_SAN_RFC822_NAME:
                /* length of value for each name entry,
                 * maximum 4 bytes for the length field,
                 * 1 byte for the tag/type.
                 */
                CHECK_OVERFLOW_ADD(buflen, cur->node.san.unstructured_name.len);
                CHECK_OVERFLOW_ADD(buflen, 4 + 1);
                break;
            case PF_MBEDTLS_X509_SAN_DIRECTORY_NAME:
            {
                const pf_mbedtls_asn1_named_data *chunk = &cur->node.san.directory_name;
                while (chunk != NULL) {
                    // Max 4 bytes for length, +1 for tag,
                    // additional 4 max for length, +1 for tag.
                    // See x509_write_name for more information.
                    CHECK_OVERFLOW_ADD(buflen, 4 + 1 + 4 + 1);
                    CHECK_OVERFLOW_ADD(buflen, chunk->oid.len);
                    CHECK_OVERFLOW_ADD(buflen, chunk->val.len);
                    chunk = chunk->next;
                }
                CHECK_OVERFLOW_ADD(buflen, 4 + 1);
                break;
            }
            default:
                /* Not supported - return. */
                return PF_MBEDTLS_ERR_X509_FEATURE_UNAVAILABLE;
        }
    }

    /* Add the extra length field and tag */
    CHECK_OVERFLOW_ADD(buflen, 4 + 1);

    /* Allocate buffer */
    buf = pf_mbedtls_calloc(1, buflen);
    if (buf == NULL) {
        return PF_MBEDTLS_ERR_ASN1_ALLOC_FAILED;
    }
    p = buf + buflen;

    /* Write ASN.1-based structure */
    cur = san_list;
    len = 0;
    while (cur != NULL) {
        size_t single_san_len = 0;
        switch (cur->node.type) {
            case PF_MBEDTLS_X509_SAN_DNS_NAME:
            case PF_MBEDTLS_X509_SAN_RFC822_NAME:
            case PF_MBEDTLS_X509_SAN_UNIFORM_RESOURCE_IDENTIFIER:
            case PF_MBEDTLS_X509_SAN_IP_ADDRESS:
            {
                const unsigned char *unstructured_name =
                    (const unsigned char *) cur->node.san.unstructured_name.p;
                size_t unstructured_name_len = cur->node.san.unstructured_name.len;

                PF_MBEDTLS_ASN1_CHK_CLEANUP_ADD(single_san_len,
                                             pf_mbedtls_asn1_write_raw_buffer(
                                                 &p, buf,
                                                 unstructured_name, unstructured_name_len));
                PF_MBEDTLS_ASN1_CHK_CLEANUP_ADD(single_san_len, pf_mbedtls_asn1_write_len(
                                                 &p, buf, unstructured_name_len));
                PF_MBEDTLS_ASN1_CHK_CLEANUP_ADD(single_san_len,
                                             pf_mbedtls_asn1_write_tag(
                                                 &p, buf,
                                                 PF_MBEDTLS_ASN1_CONTEXT_SPECIFIC | cur->node.type));
            }
            break;
            case PF_MBEDTLS_X509_SAN_DIRECTORY_NAME:
                PF_MBEDTLS_ASN1_CHK_CLEANUP_ADD(single_san_len,
                                             pf_mbedtls_x509_write_names(&p, buf,
                                                                      (pf_mbedtls_asn1_named_data *) &
                                                                      cur->node
                                                                      .san.directory_name));
                PF_MBEDTLS_ASN1_CHK_CLEANUP_ADD(single_san_len,
                                             pf_mbedtls_asn1_write_len(&p, buf, single_san_len));
                PF_MBEDTLS_ASN1_CHK_CLEANUP_ADD(single_san_len,
                                             pf_mbedtls_asn1_write_tag(&p, buf,
                                                                    PF_MBEDTLS_ASN1_CONTEXT_SPECIFIC |
                                                                    PF_MBEDTLS_ASN1_CONSTRUCTED |
                                                                    PF_MBEDTLS_X509_SAN_DIRECTORY_NAME));
                break;
            default:
                /* Error out on an unsupported SAN */
                ret = PF_MBEDTLS_ERR_X509_FEATURE_UNAVAILABLE;
                goto cleanup;
        }
        cur = cur->next;
        /* check for overflow */
        if (len > SIZE_MAX - single_san_len) {
            ret = PF_MBEDTLS_ERR_X509_BAD_INPUT_DATA;
            goto cleanup;
        }
        len += single_san_len;
    }

    PF_MBEDTLS_ASN1_CHK_CLEANUP_ADD(len, pf_mbedtls_asn1_write_len(&p, buf, len));
    PF_MBEDTLS_ASN1_CHK_CLEANUP_ADD(len,
                                 pf_mbedtls_asn1_write_tag(&p, buf,
                                                        PF_MBEDTLS_ASN1_CONSTRUCTED |
                                                        PF_MBEDTLS_ASN1_SEQUENCE));

    ret = pf_mbedtls_x509_set_extension(extensions,
                                     PF_MBEDTLS_OID_SUBJECT_ALT_NAME,
                                     PF_MBEDTLS_OID_SIZE(PF_MBEDTLS_OID_SUBJECT_ALT_NAME),
                                     0,
                                     buf + buflen - len, len);

    /* If we exceeded the allocated buffer it means that maximum size of the SubjectAltName list
     * was incorrectly calculated and memory is corrupted. */
    if (p < buf) {
        ret = PF_MBEDTLS_ERR_ASN1_LENGTH_MISMATCH;
    }
cleanup:
    pf_mbedtls_free(buf);
    return ret;
}

#endif /* MBEDTLS_X509_CSR_WRITE_C || MBEDTLS_X509_CRT_WRITE_C */
