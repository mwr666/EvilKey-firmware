#include "../../../pf_build_config.h"
/*
 *  X.509 Certificate Signing Request writing
 *
 *  Copyright The Mbed TLS Contributors
 *  SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
 */
/*
 * References:
 * - CSRs: PKCS#10 v1.7 aka RFC 2986
 * - attributes: PKCS#9 v2.0 aka RFC 2985
 */

#include "common.h"

#if defined(PF_MBEDTLS_X509_CSR_WRITE_C)

#include "x509_internal.h"
#include "../include/mbedtls/x509_csr.h"
#include "../include/mbedtls/asn1write.h"
#include "../include/mbedtls/error.h"
#include "../include/mbedtls/oid.h"
#include "../include/mbedtls/platform_util.h"

#if defined(PF_MBEDTLS_USE_PSA_CRYPTO)
#include "../include/psa/crypto.h"
#include "psa_util_internal.h"
#include "../include/mbedtls/psa_util.h"
#endif /* MBEDTLS_USE_PSA_CRYPTO */

#include <string.h>
#include <stdlib.h>

#if defined(PF_MBEDTLS_PEM_WRITE_C)
#include "../include/mbedtls/pem.h"
#endif

#include "../include/mbedtls/platform.h"

void pf_mbedtls_x509write_csr_init(pf_mbedtls_x509write_csr *ctx)
{
    memset(ctx, 0, sizeof(pf_mbedtls_x509write_csr));
}

void pf_mbedtls_x509write_csr_free(pf_mbedtls_x509write_csr *ctx)
{
    if (ctx == NULL) {
        return;
    }

    pf_mbedtls_asn1_free_named_data_list(&ctx->subject);
    pf_mbedtls_asn1_free_named_data_list(&ctx->extensions);

    pf_mbedtls_platform_zeroize(ctx, sizeof(pf_mbedtls_x509write_csr));
}

void pf_mbedtls_x509write_csr_set_md_alg(pf_mbedtls_x509write_csr *ctx, pf_mbedtls_md_type_t md_alg)
{
    ctx->md_alg = md_alg;
}

void pf_mbedtls_x509write_csr_set_key(pf_mbedtls_x509write_csr *ctx, pf_mbedtls_pk_context *key)
{
    ctx->key = key;
}

int pf_mbedtls_x509write_csr_set_subject_name(pf_mbedtls_x509write_csr *ctx,
                                           const char *subject_name)
{
    pf_mbedtls_asn1_free_named_data_list(&ctx->subject);
    return pf_mbedtls_x509_string_to_names(&ctx->subject, subject_name);
}

int pf_mbedtls_x509write_csr_set_extension(pf_mbedtls_x509write_csr *ctx,
                                        const char *oid, size_t oid_len,
                                        int critical,
                                        const unsigned char *val, size_t val_len)
{
    return pf_mbedtls_x509_set_extension(&ctx->extensions, oid, oid_len,
                                      critical, val, val_len);
}

int pf_mbedtls_x509write_csr_set_subject_alternative_name(pf_mbedtls_x509write_csr *ctx,
                                                       const pf_mbedtls_x509_san_list *san_list)
{
    return pf_mbedtls_x509_write_set_san_common(&ctx->extensions, san_list);
}

int pf_mbedtls_x509write_csr_set_key_usage(pf_mbedtls_x509write_csr *ctx, unsigned char key_usage)
{
    unsigned char buf[4] = { 0 };
    unsigned char *c;
    int ret = PF_MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;

    c = buf + 4;

    ret = pf_mbedtls_asn1_write_named_bitstring(&c, buf, &key_usage, 8);
    if (ret < 3 || ret > 4) {
        return ret;
    }

    ret = pf_mbedtls_x509write_csr_set_extension(ctx, PF_MBEDTLS_OID_KEY_USAGE,
                                              PF_MBEDTLS_OID_SIZE(PF_MBEDTLS_OID_KEY_USAGE),
                                              0, c, (size_t) ret);
    if (ret != 0) {
        return ret;
    }

    return 0;
}

int pf_mbedtls_x509write_csr_set_ns_cert_type(pf_mbedtls_x509write_csr *ctx,
                                           unsigned char ns_cert_type)
{
    unsigned char buf[4] = { 0 };
    unsigned char *c;
    int ret = PF_MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;

    c = buf + 4;

    ret = pf_mbedtls_asn1_write_named_bitstring(&c, buf, &ns_cert_type, 8);
    if (ret < 3 || ret > 4) {
        return ret;
    }

    ret = pf_mbedtls_x509write_csr_set_extension(ctx, PF_MBEDTLS_OID_NS_CERT_TYPE,
                                              PF_MBEDTLS_OID_SIZE(PF_MBEDTLS_OID_NS_CERT_TYPE),
                                              0, c, (size_t) ret);
    if (ret != 0) {
        return ret;
    }

    return 0;
}

static int x509write_csr_der_internal(pf_mbedtls_x509write_csr *ctx,
                                      unsigned char *buf,
                                      size_t size,
                                      unsigned char *sig, size_t sig_size,
                                      int (*f_rng)(void *, unsigned char *, size_t),
                                      void *p_rng)
{
    int ret = PF_MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    const char *sig_oid;
    size_t sig_oid_len = 0;
    unsigned char *c, *c2;
    unsigned char hash[PF_MBEDTLS_MD_MAX_SIZE];
    size_t pub_len = 0, sig_and_oid_len = 0, sig_len;
    size_t len = 0;
    pf_mbedtls_pk_type_t pk_alg;
#if defined(PF_MBEDTLS_USE_PSA_CRYPTO)
    size_t hash_len;
    pf_psa_algorithm_t hash_alg = pf_mbedtls_md_psa_alg_from_type(ctx->md_alg);
#endif /* MBEDTLS_USE_PSA_CRYPTO */

    /* Write the CSR backwards starting from the end of buf */
    c = buf + size;

    PF_MBEDTLS_ASN1_CHK_ADD(len, pf_mbedtls_x509_write_extensions(&c, buf,
                                                            ctx->extensions));

    if (len) {
        PF_MBEDTLS_ASN1_CHK_ADD(len, pf_mbedtls_asn1_write_len(&c, buf, len));
        PF_MBEDTLS_ASN1_CHK_ADD(len,
                             pf_mbedtls_asn1_write_tag(
                                 &c, buf,
                                 PF_MBEDTLS_ASN1_CONSTRUCTED | PF_MBEDTLS_ASN1_SEQUENCE));

        PF_MBEDTLS_ASN1_CHK_ADD(len, pf_mbedtls_asn1_write_len(&c, buf, len));
        PF_MBEDTLS_ASN1_CHK_ADD(len,
                             pf_mbedtls_asn1_write_tag(
                                 &c, buf,
                                 PF_MBEDTLS_ASN1_CONSTRUCTED | PF_MBEDTLS_ASN1_SET));

        PF_MBEDTLS_ASN1_CHK_ADD(len,
                             pf_mbedtls_asn1_write_oid(
                                 &c, buf, PF_MBEDTLS_OID_PKCS9_CSR_EXT_REQ,
                                 PF_MBEDTLS_OID_SIZE(PF_MBEDTLS_OID_PKCS9_CSR_EXT_REQ)));

        PF_MBEDTLS_ASN1_CHK_ADD(len, pf_mbedtls_asn1_write_len(&c, buf, len));
        PF_MBEDTLS_ASN1_CHK_ADD(len,
                             pf_mbedtls_asn1_write_tag(
                                 &c, buf,
                                 PF_MBEDTLS_ASN1_CONSTRUCTED | PF_MBEDTLS_ASN1_SEQUENCE));
    }

    PF_MBEDTLS_ASN1_CHK_ADD(len, pf_mbedtls_asn1_write_len(&c, buf, len));
    PF_MBEDTLS_ASN1_CHK_ADD(len,
                         pf_mbedtls_asn1_write_tag(
                             &c, buf,
                             PF_MBEDTLS_ASN1_CONSTRUCTED | PF_MBEDTLS_ASN1_CONTEXT_SPECIFIC));

    PF_MBEDTLS_ASN1_CHK_ADD(pub_len, pf_mbedtls_pk_write_pubkey_der(ctx->key,
                                                              buf, (size_t) (c - buf)));
    c -= pub_len;
    len += pub_len;

    /*
     *  Subject  ::=  Name
     */
    PF_MBEDTLS_ASN1_CHK_ADD(len, pf_mbedtls_x509_write_names(&c, buf,
                                                       ctx->subject));

    /*
     *  Version  ::=  INTEGER  {  v1(0), v2(1), v3(2)  }
     */
    PF_MBEDTLS_ASN1_CHK_ADD(len, pf_mbedtls_asn1_write_int(&c, buf, 0));

    PF_MBEDTLS_ASN1_CHK_ADD(len, pf_mbedtls_asn1_write_len(&c, buf, len));
    PF_MBEDTLS_ASN1_CHK_ADD(len,
                         pf_mbedtls_asn1_write_tag(
                             &c, buf,
                             PF_MBEDTLS_ASN1_CONSTRUCTED | PF_MBEDTLS_ASN1_SEQUENCE));

    /*
     * Sign the written CSR data into the sig buffer
     * Note: hash errors can happen only after an internal error
     */
#if defined(PF_MBEDTLS_USE_PSA_CRYPTO)
    if (pf_psa_hash_compute(hash_alg,
                         c,
                         len,
                         hash,
                         sizeof(hash),
                         &hash_len) != PF_PSA_SUCCESS) {
        return PF_MBEDTLS_ERR_PLATFORM_HW_ACCEL_FAILED;
    }
#else /* MBEDTLS_USE_PSA_CRYPTO */
    ret = pf_mbedtls_md(pf_mbedtls_md_info_from_type(ctx->md_alg), c, len, hash);
    if (ret != 0) {
        return ret;
    }
#endif
    if ((ret = pf_mbedtls_pk_sign(ctx->key, ctx->md_alg, hash, 0,
                               sig, sig_size, &sig_len,
                               f_rng, p_rng)) != 0) {
        return ret;
    }

    if (pf_mbedtls_pk_can_do(ctx->key, PF_MBEDTLS_PK_RSA)) {
        pk_alg = PF_MBEDTLS_PK_RSA;
    } else if (pf_mbedtls_pk_can_do(ctx->key, PF_MBEDTLS_PK_ECDSA)) {
        pk_alg = PF_MBEDTLS_PK_ECDSA;
    } else {
        return PF_MBEDTLS_ERR_X509_INVALID_ALG;
    }

    if ((ret = pf_mbedtls_oid_get_oid_by_sig_alg(pk_alg, ctx->md_alg,
                                              &sig_oid, &sig_oid_len)) != 0) {
        return ret;
    }

    /*
     * Move the written CSR data to the start of buf to create space for
     * writing the signature into buf.
     */
    memmove(buf, c, len);

    /*
     * Write sig and its OID into buf backwards from the end of buf.
     * Note: mbedtls_x509_write_sig will check for c2 - ( buf + len ) < sig_len
     * and return MBEDTLS_ERR_ASN1_BUF_TOO_SMALL if needed.
     */
    c2 = buf + size;
    PF_MBEDTLS_ASN1_CHK_ADD(sig_and_oid_len,
                         pf_mbedtls_x509_write_sig(&c2, buf + len, sig_oid, sig_oid_len,
                                                sig, sig_len, pk_alg));

    /*
     * Compact the space between the CSR data and signature by moving the
     * CSR data to the start of the signature.
     */
    c2 -= len;
    memmove(c2, buf, len);

    /* ASN encode the total size and tag the CSR data with it. */
    len += sig_and_oid_len;
    PF_MBEDTLS_ASN1_CHK_ADD(len, pf_mbedtls_asn1_write_len(&c2, buf, len));
    PF_MBEDTLS_ASN1_CHK_ADD(len,
                         pf_mbedtls_asn1_write_tag(
                             &c2, buf,
                             PF_MBEDTLS_ASN1_CONSTRUCTED | PF_MBEDTLS_ASN1_SEQUENCE));

    /* Zero the unused bytes at the start of buf */
    memset(buf, 0, (size_t) (c2 - buf));

    return (int) len;
}

int pf_mbedtls_x509write_csr_der(pf_mbedtls_x509write_csr *ctx, unsigned char *buf,
                              size_t size,
                              int (*f_rng)(void *, unsigned char *, size_t),
                              void *p_rng)
{
    int ret;
    unsigned char *sig;

    if ((sig = pf_mbedtls_calloc(1, PF_MBEDTLS_PK_SIGNATURE_MAX_SIZE)) == NULL) {
        return PF_MBEDTLS_ERR_X509_ALLOC_FAILED;
    }

    ret = x509write_csr_der_internal(ctx, buf, size,
                                     sig, PF_MBEDTLS_PK_SIGNATURE_MAX_SIZE,
                                     f_rng, p_rng);

    pf_mbedtls_free(sig);

    return ret;
}

#define PEM_BEGIN_CSR           "-----BEGIN CERTIFICATE REQUEST-----\n"
#define PEM_END_CSR             "-----END CERTIFICATE REQUEST-----\n"

#if defined(PF_MBEDTLS_PEM_WRITE_C)
int pf_mbedtls_x509write_csr_pem(pf_mbedtls_x509write_csr *ctx, unsigned char *buf, size_t size,
                              int (*f_rng)(void *, unsigned char *, size_t),
                              void *p_rng)
{
    int ret = PF_MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    size_t olen = 0;

    if ((ret = pf_mbedtls_x509write_csr_der(ctx, buf, size,
                                         f_rng, p_rng)) < 0) {
        return ret;
    }

    if ((ret = pf_mbedtls_pem_write_buffer(PEM_BEGIN_CSR, PEM_END_CSR,
                                        buf + size - ret,
                                        ret, buf, size, &olen)) != 0) {
        return ret;
    }

    return 0;
}
#endif /* MBEDTLS_PEM_WRITE_C */

#endif /* MBEDTLS_X509_CSR_WRITE_C */
