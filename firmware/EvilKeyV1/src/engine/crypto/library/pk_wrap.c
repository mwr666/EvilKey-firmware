#include "../../../pf_build_config.h"
/*
 *  Public Key abstraction layer: wrapper functions
 *
 *  Copyright The Mbed TLS Contributors
 *  SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
 */

#include "common.h"

#include "../include/mbedtls/platform_util.h"

#if defined(PF_MBEDTLS_PK_C)
#include "pk_wrap.h"
#include "pk_internal.h"
#include "../include/mbedtls/error.h"
#include "../include/mbedtls/psa_util.h"

/* Even if RSA not activated, for the sake of RSA-alt */
#include "../include/mbedtls/rsa.h"

#if defined(PF_MBEDTLS_ECP_C)
#include "../include/mbedtls/ecp.h"
#endif

#if defined(PF_MBEDTLS_ECDSA_C)
#include "../include/mbedtls/ecdsa.h"
#endif

#if defined(PF_MBEDTLS_USE_PSA_CRYPTO)
#include "psa_util_internal.h"
#include "../include/psa/crypto.h"
#include "../include/mbedtls/psa_util.h"

#if defined(PF_MBEDTLS_RSA_C)
#include "pkwrite.h"
#include "rsa_internal.h"
#include "constant_time_internal.h"
#endif

#if defined(PF_MBEDTLS_PK_CAN_ECDSA_SOME)
#include "../include/mbedtls/asn1write.h"
#include "../include/mbedtls/asn1.h"
#endif
#endif  /* MBEDTLS_USE_PSA_CRYPTO */

#include "../include/mbedtls/platform.h"

#include <limits.h>
#include <stdint.h>
#include <string.h>

#if defined(PF_MBEDTLS_RSA_C)
static int rsa_can_do(pf_mbedtls_pk_type_t type)
{
    return type == PF_MBEDTLS_PK_RSA ||
           type == PF_MBEDTLS_PK_RSASSA_PSS;
}

static size_t rsa_get_bitlen(pf_mbedtls_pk_context *pk)
{
    const pf_mbedtls_rsa_context *rsa = (const pf_mbedtls_rsa_context *) pk->pk_ctx;
    return pf_mbedtls_rsa_get_bitlen(rsa);
}

#if defined(PF_MBEDTLS_USE_PSA_CRYPTO)
static int rsa_verify_wrap(pf_mbedtls_pk_context *pk, pf_mbedtls_md_type_t md_alg,
                           const unsigned char *hash, size_t hash_len,
                           const unsigned char *sig, size_t sig_len)
{
    pf_mbedtls_rsa_context *rsa = (pf_mbedtls_rsa_context *) pk->pk_ctx;
    int ret = PF_MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    pf_psa_key_attributes_t attributes = PF_PSA_KEY_ATTRIBUTES_INIT;
    pf_mbedtls_svc_key_id_t key_id = PF_MBEDTLS_SVC_KEY_ID_INIT;
    pf_psa_status_t status;
    int key_len;
    unsigned char buf[PF_PSA_KEY_EXPORT_RSA_PUBLIC_KEY_MAX_SIZE(PF_PSA_VENDOR_RSA_MAX_KEY_BITS)];
    unsigned char *p = buf + sizeof(buf);
    pf_psa_algorithm_t pf_psa_alg_md;
    size_t rsa_len = pf_mbedtls_rsa_get_len(rsa);

#if SIZE_MAX > UINT_MAX
    if (md_alg == PF_MBEDTLS_MD_NONE && UINT_MAX < hash_len) {
        return PF_MBEDTLS_ERR_PK_BAD_INPUT_DATA;
    }
#endif

    if (pf_mbedtls_rsa_get_padding_mode(rsa) == PF_MBEDTLS_RSA_PKCS_V21) {
        pf_psa_alg_md = PF_PSA_ALG_RSA_PSS(pf_mbedtls_md_psa_alg_from_type(md_alg));
    } else {
        pf_psa_alg_md = PF_PSA_ALG_RSA_PKCS1V15_SIGN(pf_mbedtls_md_psa_alg_from_type(md_alg));
    }

    if (sig_len < rsa_len) {
        return PF_MBEDTLS_ERR_RSA_VERIFY_FAILED;
    }

    key_len = pf_mbedtls_rsa_write_pubkey(rsa, buf, &p);
    if (key_len <= 0) {
        return PF_MBEDTLS_ERR_PK_BAD_INPUT_DATA;
    }

    pf_psa_set_key_usage_flags(&attributes, PF_PSA_KEY_USAGE_VERIFY_HASH);
    pf_psa_set_key_algorithm(&attributes, pf_psa_alg_md);
    pf_psa_set_key_type(&attributes, PF_PSA_KEY_TYPE_RSA_PUBLIC_KEY);

    status = pf_psa_import_key(&attributes,
                            buf + sizeof(buf) - key_len, key_len,
                            &key_id);
    if (status != PF_PSA_SUCCESS) {
        ret = PF_PSA_PK_TO_MBEDTLS_ERR(status);
        goto cleanup;
    }

    status = pf_psa_verify_hash(key_id, pf_psa_alg_md, hash, hash_len,
                             sig, sig_len);
    if (status != PF_PSA_SUCCESS) {
        ret = PF_PSA_PK_RSA_TO_MBEDTLS_ERR(status);
        goto cleanup;
    }
    ret = 0;

cleanup:
    status = pf_psa_destroy_key(key_id);
    if (ret == 0 && status != PF_PSA_SUCCESS) {
        ret = PF_PSA_PK_TO_MBEDTLS_ERR(status);
    }

    return ret;
}
#else /* MBEDTLS_USE_PSA_CRYPTO */
static int rsa_verify_wrap(pf_mbedtls_pk_context *pk, pf_mbedtls_md_type_t md_alg,
                           const unsigned char *hash, size_t hash_len,
                           const unsigned char *sig, size_t sig_len)
{
    int ret = PF_MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    pf_mbedtls_rsa_context *rsa = (pf_mbedtls_rsa_context *) pk->pk_ctx;
    size_t rsa_len = pf_mbedtls_rsa_get_len(rsa);

#if SIZE_MAX > UINT_MAX
    if (md_alg == PF_MBEDTLS_MD_NONE && UINT_MAX < hash_len) {
        return PF_MBEDTLS_ERR_PK_BAD_INPUT_DATA;
    }
#endif

    if (sig_len < rsa_len) {
        return PF_MBEDTLS_ERR_RSA_VERIFY_FAILED;
    }

    if ((ret = pf_mbedtls_rsa_pkcs1_verify(rsa, md_alg,
                                        (unsigned int) hash_len,
                                        hash, sig)) != 0) {
        return ret;
    }

    /* The buffer contains a valid signature followed by extra data.
     * We have a special error code for that so that so that callers can
     * use mbedtls_pk_verify() to check "Does the buffer start with a
     * valid signature?" and not just "Does the buffer contain a valid
     * signature?". */
    if (sig_len > rsa_len) {
        return PF_MBEDTLS_ERR_PK_SIG_LEN_MISMATCH;
    }

    return 0;
}
#endif /* MBEDTLS_USE_PSA_CRYPTO */

#if defined(PF_MBEDTLS_USE_PSA_CRYPTO)
int  pf_mbedtls_pk_psa_rsa_sign_ext(pf_psa_algorithm_t alg,
                                 pf_mbedtls_rsa_context *rsa_ctx,
                                 const unsigned char *hash, size_t hash_len,
                                 unsigned char *sig, size_t sig_size,
                                 size_t *sig_len)
{
    int ret = PF_MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    pf_psa_key_attributes_t attributes = PF_PSA_KEY_ATTRIBUTES_INIT;
    pf_mbedtls_svc_key_id_t key_id = PF_MBEDTLS_SVC_KEY_ID_INIT;
    pf_psa_status_t status;
    int key_len;
    unsigned char *buf = NULL;
    unsigned char *p;

    buf = pf_mbedtls_calloc(1, PF_MBEDTLS_PK_RSA_PRV_DER_MAX_BYTES);
    if (buf == NULL) {
        return PF_MBEDTLS_ERR_PK_ALLOC_FAILED;
    }
    p = buf + PF_MBEDTLS_PK_RSA_PRV_DER_MAX_BYTES;

    *sig_len = pf_mbedtls_rsa_get_len(rsa_ctx);
    if (sig_size < *sig_len) {
        pf_mbedtls_free(buf);
        return PF_MBEDTLS_ERR_PK_BUFFER_TOO_SMALL;
    }

    key_len = pf_mbedtls_rsa_write_key(rsa_ctx, buf, &p);
    if (key_len <= 0) {
        pf_mbedtls_free(buf);
        return PF_MBEDTLS_ERR_PK_BAD_INPUT_DATA;
    }
    pf_psa_set_key_usage_flags(&attributes, PF_PSA_KEY_USAGE_SIGN_HASH);
    pf_psa_set_key_algorithm(&attributes, alg);
    pf_psa_set_key_type(&attributes, PF_PSA_KEY_TYPE_RSA_KEY_PAIR);

    status = pf_psa_import_key(&attributes,
                            buf + PF_MBEDTLS_PK_RSA_PRV_DER_MAX_BYTES - key_len, key_len,
                            &key_id);
    if (status != PF_PSA_SUCCESS) {
        ret = PF_PSA_PK_TO_MBEDTLS_ERR(status);
        goto cleanup;
    }
    status = pf_psa_sign_hash(key_id, alg, hash, hash_len,
                           sig, sig_size, sig_len);
    if (status != PF_PSA_SUCCESS) {
        ret = PF_PSA_PK_RSA_TO_MBEDTLS_ERR(status);
        goto cleanup;
    }

    ret = 0;

cleanup:
    pf_mbedtls_free(buf);
    status = pf_psa_destroy_key(key_id);
    if (ret == 0 && status != PF_PSA_SUCCESS) {
        ret = PF_PSA_PK_TO_MBEDTLS_ERR(status);
    }
    return ret;
}
#endif /* MBEDTLS_USE_PSA_CRYPTO */

#if defined(PF_MBEDTLS_USE_PSA_CRYPTO)
static int rsa_sign_wrap(pf_mbedtls_pk_context *pk, pf_mbedtls_md_type_t md_alg,
                         const unsigned char *hash, size_t hash_len,
                         unsigned char *sig, size_t sig_size, size_t *sig_len,
                         int (*f_rng)(void *, unsigned char *, size_t), void *p_rng)
{
    ((void) f_rng);
    ((void) p_rng);

    pf_psa_algorithm_t pf_psa_md_alg;
    pf_psa_md_alg = pf_mbedtls_md_psa_alg_from_type(md_alg);
    if (pf_psa_md_alg == 0) {
        return PF_MBEDTLS_ERR_PK_BAD_INPUT_DATA;
    }
    pf_psa_algorithm_t pf_psa_alg;
    if (pf_mbedtls_rsa_get_padding_mode(pf_mbedtls_pk_rsa(*pk)) == PF_MBEDTLS_RSA_PKCS_V21) {
        pf_psa_alg = PF_PSA_ALG_RSA_PSS(pf_psa_md_alg);
    } else {
        pf_psa_alg = PF_PSA_ALG_RSA_PKCS1V15_SIGN(pf_psa_md_alg);
    }

    return pf_mbedtls_pk_psa_rsa_sign_ext(pf_psa_alg, pk->pk_ctx, hash, hash_len,
                                       sig, sig_size, sig_len);
}
#else /* MBEDTLS_USE_PSA_CRYPTO */
static int rsa_sign_wrap(pf_mbedtls_pk_context *pk, pf_mbedtls_md_type_t md_alg,
                         const unsigned char *hash, size_t hash_len,
                         unsigned char *sig, size_t sig_size, size_t *sig_len,
                         int (*f_rng)(void *, unsigned char *, size_t), void *p_rng)
{
    pf_mbedtls_rsa_context *rsa = (pf_mbedtls_rsa_context *) pk->pk_ctx;

#if SIZE_MAX > UINT_MAX
    if (md_alg == PF_MBEDTLS_MD_NONE && UINT_MAX < hash_len) {
        return PF_MBEDTLS_ERR_PK_BAD_INPUT_DATA;
    }
#endif

    *sig_len = pf_mbedtls_rsa_get_len(rsa);
    if (sig_size < *sig_len) {
        return PF_MBEDTLS_ERR_PK_BUFFER_TOO_SMALL;
    }

    return pf_mbedtls_rsa_pkcs1_sign(rsa, f_rng, p_rng,
                                  md_alg, (unsigned int) hash_len,
                                  hash, sig);
}
#endif /* MBEDTLS_USE_PSA_CRYPTO */

#if defined(PF_MBEDTLS_USE_PSA_CRYPTO)
static int rsa_decrypt_wrap(pf_mbedtls_pk_context *pk,
                            const unsigned char *input, size_t ilen,
                            unsigned char *output, size_t *olen, size_t osize,
                            int (*f_rng)(void *, unsigned char *, size_t), void *p_rng)
{
    pf_mbedtls_rsa_context *rsa = (pf_mbedtls_rsa_context *) pk->pk_ctx;
    int ret = PF_MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    pf_psa_key_attributes_t attributes = PF_PSA_KEY_ATTRIBUTES_INIT;
    pf_mbedtls_svc_key_id_t key_id = PF_MBEDTLS_SVC_KEY_ID_INIT;
    pf_psa_algorithm_t pf_psa_md_alg, decrypt_alg;
    pf_psa_status_t status;
    int key_len;
    ((void) f_rng);
    ((void) p_rng);

    if (ilen != pf_mbedtls_rsa_get_len(rsa)) {
        return PF_MBEDTLS_ERR_RSA_BAD_INPUT_DATA;
    }

    const size_t key_bits = pf_mbedtls_pk_get_bitlen(pk);
    /* mbedtls_rsa_write_key() uses the same format as PSA export, which
     * actually calls it under the hood, so we can use the PSA size macro. */
    const size_t buf_size = PF_PSA_KEY_EXPORT_RSA_KEY_PAIR_MAX_SIZE(key_bits);
    unsigned char *buf = pf_mbedtls_calloc(1, buf_size);

    unsigned char *p = buf + buf_size;
    key_len = pf_mbedtls_rsa_write_key(rsa, buf, &p);
    if (key_len <= 0) {
        return PF_MBEDTLS_ERR_PK_BAD_INPUT_DATA;
    }

    pf_psa_set_key_type(&attributes, PF_PSA_KEY_TYPE_RSA_KEY_PAIR);
    pf_psa_set_key_usage_flags(&attributes, PF_PSA_KEY_USAGE_DECRYPT);
    if (pf_mbedtls_rsa_get_padding_mode(rsa) == PF_MBEDTLS_RSA_PKCS_V21) {
        pf_psa_md_alg = pf_mbedtls_md_psa_alg_from_type((pf_mbedtls_md_type_t) pf_mbedtls_rsa_get_md_alg(rsa));
        decrypt_alg = PF_PSA_ALG_RSA_OAEP(pf_psa_md_alg);
    } else {
        decrypt_alg = PF_PSA_ALG_RSA_PKCS1V15_CRYPT;
    }
    pf_psa_set_key_algorithm(&attributes, decrypt_alg);

    status = pf_psa_import_key(&attributes,
                            buf + buf_size - key_len, key_len,
                            &key_id);
    if (status != PF_PSA_SUCCESS) {
        ret = PF_PSA_PK_TO_MBEDTLS_ERR(status);
        goto cleanup;
    }

    status = pf_psa_asymmetric_decrypt(key_id, decrypt_alg,
                                    input, ilen,
                                    NULL, 0,
                                    output, osize, olen);

#if defined(PF_MBEDTLS_PKCS1_V15)
    /* Translate error codes from PSA to legacy
     * Success vs INVALID_PADDING vs BUFFER_TOO_SMALL is sensitive
     * (padding oracle attack), so we take care to translate that
     * part in constant time.
     */
    int problem;
    status = pf_mbedtls_rsa_decrypt_decompose_ret(
        PF_PSA_ERROR_INVALID_PADDING, PF_MBEDTLS_ERR_RSA_INVALID_PADDING,
        PF_PSA_ERROR_BUFFER_TOO_SMALL, PF_MBEDTLS_ERR_RSA_OUTPUT_TOO_LARGE,
        status, &problem);
    ret = PF_PSA_PK_RSA_TO_MBEDTLS_ERR(status);
    ret |= problem;
#else
    ret = PF_PSA_PK_RSA_TO_MBEDTLS_ERR(status);
#endif

cleanup:
    pf_mbedtls_zeroize_and_free(buf, buf_size);
    status = pf_psa_destroy_key(key_id);
    /* Don't branch on ret as it is a sensitive value
     * (it reveals whether padding was valid).
     * Instead branch on status. That means when both ret and
     * status were errors, we'll return the unlock status while we would
     * normally return the first error, but that's better than leaking info. */
    return (status != PF_PSA_SUCCESS) ? PF_PSA_PK_TO_MBEDTLS_ERR(status) : ret;
}
#else /* MBEDTLS_USE_PSA_CRYPTO */
static int rsa_decrypt_wrap(pf_mbedtls_pk_context *pk,
                            const unsigned char *input, size_t ilen,
                            unsigned char *output, size_t *olen, size_t osize,
                            int (*f_rng)(void *, unsigned char *, size_t), void *p_rng)
{
    pf_mbedtls_rsa_context *rsa = (pf_mbedtls_rsa_context *) pk->pk_ctx;

    if (ilen != pf_mbedtls_rsa_get_len(rsa)) {
        return PF_MBEDTLS_ERR_RSA_BAD_INPUT_DATA;
    }

    return pf_mbedtls_rsa_pkcs1_decrypt(rsa, f_rng, p_rng,
                                     olen, input, output, osize);
}
#endif /* MBEDTLS_USE_PSA_CRYPTO */

#if defined(PF_MBEDTLS_USE_PSA_CRYPTO)
static int rsa_encrypt_wrap(pf_mbedtls_pk_context *pk,
                            const unsigned char *input, size_t ilen,
                            unsigned char *output, size_t *olen, size_t osize,
                            int (*f_rng)(void *, unsigned char *, size_t), void *p_rng)
{
    pf_mbedtls_rsa_context *rsa = (pf_mbedtls_rsa_context *) pk->pk_ctx;
    int ret = PF_MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    pf_psa_key_attributes_t attributes = PF_PSA_KEY_ATTRIBUTES_INIT;
    pf_mbedtls_svc_key_id_t key_id = PF_MBEDTLS_SVC_KEY_ID_INIT;
    pf_psa_algorithm_t pf_psa_md_alg, pf_psa_encrypt_alg;
    pf_psa_status_t status;
    int key_len;
    unsigned char buf[PF_PSA_KEY_EXPORT_RSA_PUBLIC_KEY_MAX_SIZE(PF_PSA_VENDOR_RSA_MAX_KEY_BITS)];
    unsigned char *p = buf + sizeof(buf);

    ((void) f_rng);
    ((void) p_rng);

    if (pf_mbedtls_rsa_get_len(rsa) > osize) {
        return PF_MBEDTLS_ERR_RSA_OUTPUT_TOO_LARGE;
    }

    key_len = pf_mbedtls_rsa_write_pubkey(rsa, buf, &p);
    if (key_len <= 0) {
        return PF_MBEDTLS_ERR_PK_BAD_INPUT_DATA;
    }

    pf_psa_set_key_usage_flags(&attributes, PF_PSA_KEY_USAGE_ENCRYPT);
    if (pf_mbedtls_rsa_get_padding_mode(rsa) == PF_MBEDTLS_RSA_PKCS_V21) {
        pf_psa_md_alg = pf_mbedtls_md_psa_alg_from_type((pf_mbedtls_md_type_t) pf_mbedtls_rsa_get_md_alg(rsa));
        pf_psa_encrypt_alg = PF_PSA_ALG_RSA_OAEP(pf_psa_md_alg);
    } else {
        pf_psa_encrypt_alg = PF_PSA_ALG_RSA_PKCS1V15_CRYPT;
    }
    pf_psa_set_key_algorithm(&attributes, pf_psa_encrypt_alg);
    pf_psa_set_key_type(&attributes, PF_PSA_KEY_TYPE_RSA_PUBLIC_KEY);

    status = pf_psa_import_key(&attributes,
                            buf + sizeof(buf) - key_len, key_len,
                            &key_id);
    if (status != PF_PSA_SUCCESS) {
        ret = PF_PSA_PK_TO_MBEDTLS_ERR(status);
        goto cleanup;
    }

    status = pf_psa_asymmetric_encrypt(key_id, pf_psa_encrypt_alg,
                                    input, ilen,
                                    NULL, 0,
                                    output, osize, olen);
    if (status != PF_PSA_SUCCESS) {
        ret = PF_PSA_PK_RSA_TO_MBEDTLS_ERR(status);
        goto cleanup;
    }

    ret = 0;

cleanup:
    status = pf_psa_destroy_key(key_id);
    if (ret == 0 && status != PF_PSA_SUCCESS) {
        ret = PF_PSA_PK_TO_MBEDTLS_ERR(status);
    }

    return ret;
}
#else /* MBEDTLS_USE_PSA_CRYPTO */
static int rsa_encrypt_wrap(pf_mbedtls_pk_context *pk,
                            const unsigned char *input, size_t ilen,
                            unsigned char *output, size_t *olen, size_t osize,
                            int (*f_rng)(void *, unsigned char *, size_t), void *p_rng)
{
    pf_mbedtls_rsa_context *rsa = (pf_mbedtls_rsa_context *) pk->pk_ctx;
    *olen = pf_mbedtls_rsa_get_len(rsa);

    if (*olen > osize) {
        return PF_MBEDTLS_ERR_RSA_OUTPUT_TOO_LARGE;
    }

    return pf_mbedtls_rsa_pkcs1_encrypt(rsa, f_rng, p_rng,
                                     ilen, input, output);
}
#endif /* MBEDTLS_USE_PSA_CRYPTO */

static int rsa_check_pair_wrap(pf_mbedtls_pk_context *pub, pf_mbedtls_pk_context *prv,
                               int (*f_rng)(void *, unsigned char *, size_t),
                               void *p_rng)
{
    (void) f_rng;
    (void) p_rng;
    return pf_mbedtls_rsa_check_pub_priv((const pf_mbedtls_rsa_context *) pub->pk_ctx,
                                      (const pf_mbedtls_rsa_context *) prv->pk_ctx);
}

static void *rsa_alloc_wrap(void)
{
    void *ctx = pf_mbedtls_calloc(1, sizeof(pf_mbedtls_rsa_context));

    if (ctx != NULL) {
        pf_mbedtls_rsa_init((pf_mbedtls_rsa_context *) ctx);
    }

    return ctx;
}

static void rsa_free_wrap(void *ctx)
{
    pf_mbedtls_rsa_free((pf_mbedtls_rsa_context *) ctx);
    pf_mbedtls_free(ctx);
}

static void rsa_debug(pf_mbedtls_pk_context *pk, pf_mbedtls_pk_debug_item *items)
{
#if defined(PF_MBEDTLS_RSA_ALT)
    /* Not supported */
    (void) pk;
    (void) items;
#else
    pf_mbedtls_rsa_context *rsa = (pf_mbedtls_rsa_context *) pk->pk_ctx;

    items->type = PF_MBEDTLS_PK_DEBUG_MPI;
    items->name = "rsa.N";
    items->value = &(rsa->N);

    items++;

    items->type = PF_MBEDTLS_PK_DEBUG_MPI;
    items->name = "rsa.E";
    items->value = &(rsa->E);
#endif
}

const pf_mbedtls_pk_info_t pf_mbedtls_rsa_info = {
    .type = PF_MBEDTLS_PK_RSA,
    .name = "RSA",
    .get_bitlen = rsa_get_bitlen,
    .can_do = rsa_can_do,
    .verify_func = rsa_verify_wrap,
    .sign_func = rsa_sign_wrap,
#if defined(PF_MBEDTLS_ECDSA_C) && defined(PF_MBEDTLS_ECP_RESTARTABLE)
    .verify_rs_func = NULL,
    .sign_rs_func = NULL,
    .rs_alloc_func = NULL,
    .rs_free_func = NULL,
#endif /* MBEDTLS_ECDSA_C && MBEDTLS_ECP_RESTARTABLE */
    .decrypt_func = rsa_decrypt_wrap,
    .encrypt_func = rsa_encrypt_wrap,
    .check_pair_func = rsa_check_pair_wrap,
    .ctx_alloc_func = rsa_alloc_wrap,
    .ctx_free_func = rsa_free_wrap,
    .debug_func = rsa_debug,
};
#endif /* MBEDTLS_RSA_C */

#if defined(PF_MBEDTLS_PK_HAVE_ECC_KEYS)
/*
 * Generic EC key
 */
static int eckey_can_do(pf_mbedtls_pk_type_t type)
{
    return type == PF_MBEDTLS_PK_ECKEY ||
           type == PF_MBEDTLS_PK_ECKEY_DH ||
           type == PF_MBEDTLS_PK_ECDSA;
}

static size_t eckey_get_bitlen(pf_mbedtls_pk_context *pk)
{
#if defined(PF_MBEDTLS_PK_USE_PSA_EC_DATA)
    return pk->ec_bits;
#else /* MBEDTLS_PK_USE_PSA_EC_DATA */
    pf_mbedtls_ecp_keypair *ecp = (pf_mbedtls_ecp_keypair *) pk->pk_ctx;
    return ecp->grp.pbits;
#endif /* MBEDTLS_PK_USE_PSA_EC_DATA */
}

#if defined(PF_MBEDTLS_PK_CAN_ECDSA_VERIFY)
#if defined(PF_MBEDTLS_USE_PSA_CRYPTO)
/* Common helper for ECDSA verify using PSA functions. */
static int ecdsa_verify_psa(unsigned char *key, size_t key_len,
                            pf_psa_ecc_family_t curve, size_t curve_bits,
                            const unsigned char *hash, size_t hash_len,
                            const unsigned char *sig, size_t sig_len)
{
    int ret = PF_MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    pf_psa_key_attributes_t attributes = PF_PSA_KEY_ATTRIBUTES_INIT;
    pf_mbedtls_svc_key_id_t key_id = PF_MBEDTLS_SVC_KEY_ID_INIT;
    pf_psa_algorithm_t pf_psa_sig_md = PF_PSA_ALG_ECDSA_ANY;
    size_t signature_len = PF_PSA_ECDSA_SIGNATURE_SIZE(curve_bits);
    size_t converted_sig_len;
    unsigned char extracted_sig[PF_PSA_VENDOR_ECDSA_SIGNATURE_MAX_SIZE];
    unsigned char *p;
    pf_psa_status_t status;

    if (curve == 0) {
        return PF_MBEDTLS_ERR_PK_BAD_INPUT_DATA;
    }

    pf_psa_set_key_type(&attributes, PF_PSA_KEY_TYPE_ECC_PUBLIC_KEY(curve));
    pf_psa_set_key_usage_flags(&attributes, PF_PSA_KEY_USAGE_VERIFY_HASH);
    pf_psa_set_key_algorithm(&attributes, pf_psa_sig_md);

    status = pf_psa_import_key(&attributes, key, key_len, &key_id);
    if (status != PF_PSA_SUCCESS) {
        ret = PF_PSA_PK_TO_MBEDTLS_ERR(status);
        goto cleanup;
    }

    if (signature_len > sizeof(extracted_sig)) {
        ret = PF_MBEDTLS_ERR_PK_BAD_INPUT_DATA;
        goto cleanup;
    }

    p = (unsigned char *) sig;
    ret = pf_mbedtls_ecdsa_der_to_raw(curve_bits, p, sig_len, extracted_sig,
                                   sizeof(extracted_sig), &converted_sig_len);
    if (ret != 0) {
        goto cleanup;
    }

    if (converted_sig_len != signature_len) {
        ret = PF_MBEDTLS_ERR_PK_BAD_INPUT_DATA;
        goto cleanup;
    }

    status = pf_psa_verify_hash(key_id, pf_psa_sig_md, hash, hash_len,
                             extracted_sig, signature_len);
    if (status != PF_PSA_SUCCESS) {
        ret = PF_PSA_PK_ECDSA_TO_MBEDTLS_ERR(status);
        goto cleanup;
    }

    ret = 0;

cleanup:
    status = pf_psa_destroy_key(key_id);
    if (ret == 0 && status != PF_PSA_SUCCESS) {
        ret = PF_PSA_PK_TO_MBEDTLS_ERR(status);
    }

    return ret;
}

static int ecdsa_opaque_verify_wrap(pf_mbedtls_pk_context *pk,
                                    pf_mbedtls_md_type_t md_alg,
                                    const unsigned char *hash, size_t hash_len,
                                    const unsigned char *sig, size_t sig_len)
{
    (void) md_alg;
    unsigned char key[PF_MBEDTLS_PK_MAX_EC_PUBKEY_RAW_LEN];
    size_t key_len;
    pf_psa_key_attributes_t key_attr = PF_PSA_KEY_ATTRIBUTES_INIT;
    pf_psa_ecc_family_t curve;
    size_t curve_bits;
    pf_psa_status_t status;

    status = pf_psa_get_key_attributes(pk->priv_id, &key_attr);
    if (status != PF_PSA_SUCCESS) {
        return PF_PSA_PK_ECDSA_TO_MBEDTLS_ERR(status);
    }
    curve = PF_PSA_KEY_TYPE_ECC_GET_FAMILY(pf_psa_get_key_type(&key_attr));
    curve_bits = pf_psa_get_key_bits(&key_attr);
    pf_psa_reset_key_attributes(&key_attr);

    status = pf_psa_export_public_key(pk->priv_id, key, sizeof(key), &key_len);
    if (status != PF_PSA_SUCCESS) {
        return PF_PSA_PK_ECDSA_TO_MBEDTLS_ERR(status);
    }

    return ecdsa_verify_psa(key, key_len, curve, curve_bits,
                            hash, hash_len, sig, sig_len);
}

#if defined(PF_MBEDTLS_PK_USE_PSA_EC_DATA)
static int ecdsa_verify_wrap(pf_mbedtls_pk_context *pk,
                             pf_mbedtls_md_type_t md_alg,
                             const unsigned char *hash, size_t hash_len,
                             const unsigned char *sig, size_t sig_len)
{
    (void) md_alg;
    pf_psa_ecc_family_t curve = pk->ec_family;
    size_t curve_bits = pk->ec_bits;

    return ecdsa_verify_psa(pk->pub_raw, pk->pub_raw_len, curve, curve_bits,
                            hash, hash_len, sig, sig_len);
}
#else /* MBEDTLS_PK_USE_PSA_EC_DATA */
static int ecdsa_verify_wrap(pf_mbedtls_pk_context *pk,
                             pf_mbedtls_md_type_t md_alg,
                             const unsigned char *hash, size_t hash_len,
                             const unsigned char *sig, size_t sig_len)
{
    (void) md_alg;
    int ret = PF_MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    pf_mbedtls_ecp_keypair *ctx = pk->pk_ctx;
    unsigned char key[PF_MBEDTLS_PSA_MAX_EC_PUBKEY_LENGTH];
    size_t key_len;
    size_t curve_bits;
    pf_psa_ecc_family_t curve = pf_mbedtls_ecc_group_to_psa(ctx->grp.id, &curve_bits);

    ret = pf_mbedtls_ecp_point_write_binary(&ctx->grp, &ctx->Q,
                                         PF_MBEDTLS_ECP_PF_UNCOMPRESSED,
                                         &key_len, key, sizeof(key));
    if (ret != 0) {
        return ret;
    }

    return ecdsa_verify_psa(key, key_len, curve, curve_bits,
                            hash, hash_len, sig, sig_len);
}
#endif /* MBEDTLS_PK_USE_PSA_EC_DATA */
#else /* MBEDTLS_USE_PSA_CRYPTO */
static int ecdsa_verify_wrap(pf_mbedtls_pk_context *pk, pf_mbedtls_md_type_t md_alg,
                             const unsigned char *hash, size_t hash_len,
                             const unsigned char *sig, size_t sig_len)
{
    int ret = PF_MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    ((void) md_alg);

    ret = pf_mbedtls_ecdsa_read_signature((pf_mbedtls_ecdsa_context *) pk->pk_ctx,
                                       hash, hash_len, sig, sig_len);

    if (ret == PF_MBEDTLS_ERR_ECP_SIG_LEN_MISMATCH) {
        return PF_MBEDTLS_ERR_PK_SIG_LEN_MISMATCH;
    }

    return ret;
}
#endif /* MBEDTLS_USE_PSA_CRYPTO */
#endif /* MBEDTLS_PK_CAN_ECDSA_VERIFY */

#if defined(PF_MBEDTLS_PK_CAN_ECDSA_SIGN)
#if defined(PF_MBEDTLS_USE_PSA_CRYPTO)
/* Common helper for ECDSA sign using PSA functions.
 * Instead of extracting key's properties in order to check which kind of ECDSA
 * signature it supports, we try both deterministic and non-deterministic.
 */
static int ecdsa_sign_psa(pf_mbedtls_svc_key_id_t key_id, pf_mbedtls_md_type_t md_alg,
                          const unsigned char *hash, size_t hash_len,
                          unsigned char *sig, size_t sig_size, size_t *sig_len)
{
    int ret = PF_MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    pf_psa_status_t status;
    pf_psa_key_attributes_t key_attr = PF_PSA_KEY_ATTRIBUTES_INIT;
    size_t key_bits = 0;

    status = pf_psa_get_key_attributes(key_id, &key_attr);
    if (status != PF_PSA_SUCCESS) {
        return PF_PSA_PK_ECDSA_TO_MBEDTLS_ERR(status);
    }
    key_bits = pf_psa_get_key_bits(&key_attr);
    pf_psa_reset_key_attributes(&key_attr);

    status = pf_psa_sign_hash(key_id,
                           PF_PSA_ALG_DETERMINISTIC_ECDSA(pf_mbedtls_md_psa_alg_from_type(md_alg)),
                           hash, hash_len, sig, sig_size, sig_len);
    if (status == PF_PSA_SUCCESS) {
        goto done;
    } else if (status != PF_PSA_ERROR_NOT_PERMITTED) {
        return PF_PSA_PK_ECDSA_TO_MBEDTLS_ERR(status);
    }

    status = pf_psa_sign_hash(key_id,
                           PF_PSA_ALG_ECDSA(pf_mbedtls_md_psa_alg_from_type(md_alg)),
                           hash, hash_len, sig, sig_size, sig_len);
    if (status != PF_PSA_SUCCESS) {
        return PF_PSA_PK_ECDSA_TO_MBEDTLS_ERR(status);
    }

done:
    ret = pf_mbedtls_ecdsa_raw_to_der(key_bits, sig, *sig_len, sig, sig_size, sig_len);

    return ret;
}

static int ecdsa_opaque_sign_wrap(pf_mbedtls_pk_context *pk,
                                  pf_mbedtls_md_type_t md_alg,
                                  const unsigned char *hash, size_t hash_len,
                                  unsigned char *sig, size_t sig_size,
                                  size_t *sig_len,
                                  int (*f_rng)(void *, unsigned char *, size_t),
                                  void *p_rng)
{
    ((void) f_rng);
    ((void) p_rng);

    return ecdsa_sign_psa(pk->priv_id, md_alg, hash, hash_len, sig, sig_size,
                          sig_len);
}

#if defined(PF_MBEDTLS_PK_USE_PSA_EC_DATA)
/* When PK_USE_PSA_EC_DATA is defined opaque and non-opaque keys end up
 * using the same function. */
#define ecdsa_sign_wrap     ecdsa_opaque_sign_wrap
#else /* MBEDTLS_PK_USE_PSA_EC_DATA */
static int ecdsa_sign_wrap(pf_mbedtls_pk_context *pk, pf_mbedtls_md_type_t md_alg,
                           const unsigned char *hash, size_t hash_len,
                           unsigned char *sig, size_t sig_size, size_t *sig_len,
                           int (*f_rng)(void *, unsigned char *, size_t), void *p_rng)
{
    int ret = PF_MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    pf_mbedtls_svc_key_id_t key_id = PF_MBEDTLS_SVC_KEY_ID_INIT;
    pf_psa_status_t status;
    pf_mbedtls_ecp_keypair *ctx = pk->pk_ctx;
    pf_psa_key_attributes_t attributes = PF_PSA_KEY_ATTRIBUTES_INIT;
    unsigned char buf[PF_MBEDTLS_PSA_MAX_EC_KEY_PAIR_LENGTH];
    size_t curve_bits;
    pf_psa_ecc_family_t curve =
        pf_mbedtls_ecc_group_to_psa(ctx->grp.id, &curve_bits);
    size_t key_len = PF_PSA_BITS_TO_BYTES(curve_bits);
    pf_psa_algorithm_t pf_psa_hash = pf_mbedtls_md_psa_alg_from_type(md_alg);
    pf_psa_algorithm_t pf_psa_sig_md = PF_MBEDTLS_PK_PSA_ALG_ECDSA_MAYBE_DET(pf_psa_hash);
    ((void) f_rng);
    ((void) p_rng);

    if (curve == 0) {
        return PF_MBEDTLS_ERR_PK_BAD_INPUT_DATA;
    }

    if (key_len > sizeof(buf)) {
        return PF_MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    }
    ret = pf_mbedtls_mpi_write_binary(&ctx->d, buf, key_len);
    if (ret != 0) {
        goto cleanup;
    }

    pf_psa_set_key_type(&attributes, PF_PSA_KEY_TYPE_ECC_KEY_PAIR(curve));
    pf_psa_set_key_usage_flags(&attributes, PF_PSA_KEY_USAGE_SIGN_HASH);
    pf_psa_set_key_algorithm(&attributes, pf_psa_sig_md);

    status = pf_psa_import_key(&attributes, buf, key_len, &key_id);
    if (status != PF_PSA_SUCCESS) {
        ret = PF_PSA_PK_TO_MBEDTLS_ERR(status);
        goto cleanup;
    }

    ret = ecdsa_sign_psa(key_id, md_alg, hash, hash_len, sig, sig_size, sig_len);

cleanup:
    pf_mbedtls_platform_zeroize(buf, sizeof(buf));
    status = pf_psa_destroy_key(key_id);
    if (ret == 0 && status != PF_PSA_SUCCESS) {
        ret = PF_PSA_PK_TO_MBEDTLS_ERR(status);
    }

    return ret;
}
#endif /* MBEDTLS_PK_USE_PSA_EC_DATA */
#else /* MBEDTLS_USE_PSA_CRYPTO */
static int ecdsa_sign_wrap(pf_mbedtls_pk_context *pk, pf_mbedtls_md_type_t md_alg,
                           const unsigned char *hash, size_t hash_len,
                           unsigned char *sig, size_t sig_size, size_t *sig_len,
                           int (*f_rng)(void *, unsigned char *, size_t), void *p_rng)
{
    return pf_mbedtls_ecdsa_write_signature((pf_mbedtls_ecdsa_context *) pk->pk_ctx,
                                         md_alg, hash, hash_len,
                                         sig, sig_size, sig_len,
                                         f_rng, p_rng);
}
#endif /* MBEDTLS_USE_PSA_CRYPTO */
#endif /* MBEDTLS_PK_CAN_ECDSA_SIGN */

#if defined(PF_MBEDTLS_ECDSA_C) && defined(PF_MBEDTLS_ECP_RESTARTABLE)
/* Forward declarations */
static int ecdsa_verify_rs_wrap(pf_mbedtls_pk_context *ctx, pf_mbedtls_md_type_t md_alg,
                                const unsigned char *hash, size_t hash_len,
                                const unsigned char *sig, size_t sig_len,
                                void *rs_ctx);

static int ecdsa_sign_rs_wrap(pf_mbedtls_pk_context *ctx, pf_mbedtls_md_type_t md_alg,
                              const unsigned char *hash, size_t hash_len,
                              unsigned char *sig, size_t sig_size, size_t *sig_len,
                              int (*f_rng)(void *, unsigned char *, size_t), void *p_rng,
                              void *rs_ctx);

/*
 * Restart context for ECDSA operations with ECKEY context
 *
 * We need to store an actual ECDSA context, as we need to pass the same to
 * the underlying ecdsa function, so we can't create it on the fly every time.
 */
typedef struct {
    pf_mbedtls_ecdsa_restart_ctx ecdsa_rs;
    pf_mbedtls_ecdsa_context ecdsa_ctx;
} eckey_restart_ctx;

static void *eckey_rs_alloc(void)
{
    eckey_restart_ctx *rs_ctx;

    void *ctx = pf_mbedtls_calloc(1, sizeof(eckey_restart_ctx));

    if (ctx != NULL) {
        rs_ctx = ctx;
        pf_mbedtls_ecdsa_restart_init(&rs_ctx->ecdsa_rs);
        pf_mbedtls_ecdsa_init(&rs_ctx->ecdsa_ctx);
    }

    return ctx;
}

static void eckey_rs_free(void *ctx)
{
    eckey_restart_ctx *rs_ctx;

    if (ctx == NULL) {
        return;
    }

    rs_ctx = ctx;
    pf_mbedtls_ecdsa_restart_free(&rs_ctx->ecdsa_rs);
    pf_mbedtls_ecdsa_free(&rs_ctx->ecdsa_ctx);

    pf_mbedtls_free(ctx);
}

static int eckey_verify_rs_wrap(pf_mbedtls_pk_context *pk, pf_mbedtls_md_type_t md_alg,
                                const unsigned char *hash, size_t hash_len,
                                const unsigned char *sig, size_t sig_len,
                                void *rs_ctx)
{
    int ret = PF_MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    eckey_restart_ctx *rs = rs_ctx;

    /* Should never happen */
    if (rs == NULL) {
        return PF_MBEDTLS_ERR_PK_BAD_INPUT_DATA;
    }

    /* set up our own sub-context if needed (that is, on first run) */
    if (rs->ecdsa_ctx.grp.pbits == 0) {
        PF_MBEDTLS_MPI_CHK(pf_mbedtls_ecdsa_from_keypair(&rs->ecdsa_ctx, pk->pk_ctx));
    }

    PF_MBEDTLS_MPI_CHK(ecdsa_verify_rs_wrap(pk,
                                         md_alg, hash, hash_len,
                                         sig, sig_len, &rs->ecdsa_rs));

cleanup:
    return ret;
}

static int eckey_sign_rs_wrap(pf_mbedtls_pk_context *pk, pf_mbedtls_md_type_t md_alg,
                              const unsigned char *hash, size_t hash_len,
                              unsigned char *sig, size_t sig_size, size_t *sig_len,
                              int (*f_rng)(void *, unsigned char *, size_t), void *p_rng,
                              void *rs_ctx)
{
    int ret = PF_MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    eckey_restart_ctx *rs = rs_ctx;

    /* Should never happen */
    if (rs == NULL) {
        return PF_MBEDTLS_ERR_PK_BAD_INPUT_DATA;
    }

    /* set up our own sub-context if needed (that is, on first run) */
    if (rs->ecdsa_ctx.grp.pbits == 0) {
        PF_MBEDTLS_MPI_CHK(pf_mbedtls_ecdsa_from_keypair(&rs->ecdsa_ctx, pk->pk_ctx));
    }

    PF_MBEDTLS_MPI_CHK(ecdsa_sign_rs_wrap(pk, md_alg,
                                       hash, hash_len, sig, sig_size, sig_len,
                                       f_rng, p_rng, &rs->ecdsa_rs));

cleanup:
    return ret;
}
#endif /* MBEDTLS_ECDSA_C && MBEDTLS_ECP_RESTARTABLE */

#if defined(PF_MBEDTLS_USE_PSA_CRYPTO)
#if defined(PF_MBEDTLS_PK_USE_PSA_EC_DATA)
static int eckey_check_pair_psa(pf_mbedtls_pk_context *pub, pf_mbedtls_pk_context *prv)
{
    pf_psa_status_t status;
    int ret = PF_MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    uint8_t prv_key_buf[PF_MBEDTLS_PSA_MAX_EC_PUBKEY_LENGTH];
    size_t prv_key_len;
    pf_mbedtls_svc_key_id_t key_id = prv->priv_id;

    status = pf_psa_export_public_key(key_id, prv_key_buf, sizeof(prv_key_buf),
                                   &prv_key_len);
    ret = PF_PSA_PK_TO_MBEDTLS_ERR(status);
    if (ret != 0) {
        return ret;
    }

    if (memcmp(prv_key_buf, pub->pub_raw, pub->pub_raw_len) != 0) {
        return PF_MBEDTLS_ERR_PK_BAD_INPUT_DATA;
    }

    return 0;
}
#else /* MBEDTLS_PK_USE_PSA_EC_DATA */
static int eckey_check_pair_psa(pf_mbedtls_pk_context *pub, pf_mbedtls_pk_context *prv)
{
    pf_psa_status_t status;
    int ret = PF_MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    uint8_t prv_key_buf[PF_MBEDTLS_PSA_MAX_EC_PUBKEY_LENGTH];
    size_t prv_key_len;
    pf_psa_status_t destruction_status;
    pf_mbedtls_svc_key_id_t key_id = PF_MBEDTLS_SVC_KEY_ID_INIT;
    pf_psa_key_attributes_t key_attr = PF_PSA_KEY_ATTRIBUTES_INIT;
    uint8_t pub_key_buf[PF_MBEDTLS_PSA_MAX_EC_PUBKEY_LENGTH];
    size_t pub_key_len;
    size_t curve_bits;
    const pf_psa_ecc_family_t curve =
        pf_mbedtls_ecc_group_to_psa(pf_mbedtls_pk_ec_ro(*prv)->grp.id, &curve_bits);
    const size_t curve_bytes = PF_PSA_BITS_TO_BYTES(curve_bits);

    if (curve == 0) {
        return PF_MBEDTLS_ERR_PK_BAD_INPUT_DATA;
    }

    pf_psa_set_key_type(&key_attr, PF_PSA_KEY_TYPE_ECC_KEY_PAIR(curve));
    pf_psa_set_key_usage_flags(&key_attr, PF_PSA_KEY_USAGE_EXPORT);

    ret = pf_mbedtls_mpi_write_binary(&pf_mbedtls_pk_ec_ro(*prv)->d,
                                   prv_key_buf, curve_bytes);
    if (ret != 0) {
        pf_mbedtls_platform_zeroize(prv_key_buf, sizeof(prv_key_buf));
        return ret;
    }

    status = pf_psa_import_key(&key_attr, prv_key_buf, curve_bytes, &key_id);
    pf_mbedtls_platform_zeroize(prv_key_buf, sizeof(prv_key_buf));
    ret = PF_PSA_PK_TO_MBEDTLS_ERR(status);
    if (ret != 0) {
        return ret;
    }

    // From now on prv_key_buf is used to store the public key of prv.
    status = pf_psa_export_public_key(key_id, prv_key_buf, sizeof(prv_key_buf),
                                   &prv_key_len);
    ret = PF_PSA_PK_TO_MBEDTLS_ERR(status);
    destruction_status = pf_psa_destroy_key(key_id);
    if (ret != 0) {
        return ret;
    } else if (destruction_status != PF_PSA_SUCCESS) {
        return PF_PSA_PK_TO_MBEDTLS_ERR(destruction_status);
    }

    ret = pf_mbedtls_ecp_point_write_binary(&pf_mbedtls_pk_ec_rw(*pub)->grp,
                                         &pf_mbedtls_pk_ec_rw(*pub)->Q,
                                         PF_MBEDTLS_ECP_PF_UNCOMPRESSED,
                                         &pub_key_len, pub_key_buf,
                                         sizeof(pub_key_buf));
    if (ret != 0) {
        return ret;
    }

    if (memcmp(prv_key_buf, pub_key_buf, curve_bytes) != 0) {
        return PF_MBEDTLS_ERR_PK_BAD_INPUT_DATA;
    }

    return 0;
}
#endif /* MBEDTLS_PK_USE_PSA_EC_DATA */

static int eckey_check_pair_wrap(pf_mbedtls_pk_context *pub, pf_mbedtls_pk_context *prv,
                                 int (*f_rng)(void *, unsigned char *, size_t),
                                 void *p_rng)
{
    (void) f_rng;
    (void) p_rng;
    return eckey_check_pair_psa(pub, prv);
}
#else /* MBEDTLS_USE_PSA_CRYPTO */
static int eckey_check_pair_wrap(pf_mbedtls_pk_context *pub, pf_mbedtls_pk_context *prv,
                                 int (*f_rng)(void *, unsigned char *, size_t),
                                 void *p_rng)
{
    return pf_mbedtls_ecp_check_pub_priv((const pf_mbedtls_ecp_keypair *) pub->pk_ctx,
                                      (const pf_mbedtls_ecp_keypair *) prv->pk_ctx,
                                      f_rng, p_rng);
}
#endif /* MBEDTLS_USE_PSA_CRYPTO */

#if defined(PF_MBEDTLS_USE_PSA_CRYPTO)
#if defined(PF_MBEDTLS_PK_USE_PSA_EC_DATA)
/* When PK_USE_PSA_EC_DATA is defined opaque and non-opaque keys end up
 * using the same function. */
#define ecdsa_opaque_check_pair_wrap    eckey_check_pair_wrap
#else /* MBEDTLS_PK_USE_PSA_EC_DATA */
static int ecdsa_opaque_check_pair_wrap(pf_mbedtls_pk_context *pub,
                                        pf_mbedtls_pk_context *prv,
                                        int (*f_rng)(void *, unsigned char *, size_t),
                                        void *p_rng)
{
    pf_psa_status_t status;
    uint8_t exp_pub_key[PF_MBEDTLS_PK_MAX_EC_PUBKEY_RAW_LEN];
    size_t exp_pub_key_len = 0;
    uint8_t pub_key[PF_MBEDTLS_PK_MAX_EC_PUBKEY_RAW_LEN];
    size_t pub_key_len = 0;
    int ret;
    (void) f_rng;
    (void) p_rng;

    status = pf_psa_export_public_key(prv->priv_id, exp_pub_key, sizeof(exp_pub_key),
                                   &exp_pub_key_len);
    if (status != PF_PSA_SUCCESS) {
        ret = pf_psa_pk_status_to_mbedtls(status);
        return ret;
    }
    ret = pf_mbedtls_ecp_point_write_binary(&(pf_mbedtls_pk_ec_ro(*pub)->grp),
                                         &(pf_mbedtls_pk_ec_ro(*pub)->Q),
                                         PF_MBEDTLS_ECP_PF_UNCOMPRESSED,
                                         &pub_key_len, pub_key, sizeof(pub_key));
    if (ret != 0) {
        return ret;
    }
    if ((exp_pub_key_len != pub_key_len) ||
        memcmp(exp_pub_key, pub_key, exp_pub_key_len)) {
        return PF_MBEDTLS_ERR_PK_BAD_INPUT_DATA;
    }
    return 0;
}
#endif /* MBEDTLS_PK_USE_PSA_EC_DATA */
#endif /* MBEDTLS_USE_PSA_CRYPTO */

#if !defined(PF_MBEDTLS_PK_USE_PSA_EC_DATA)
static void *eckey_alloc_wrap(void)
{
    void *ctx = pf_mbedtls_calloc(1, sizeof(pf_mbedtls_ecp_keypair));

    if (ctx != NULL) {
        pf_mbedtls_ecp_keypair_init(ctx);
    }

    return ctx;
}

static void eckey_free_wrap(void *ctx)
{
    pf_mbedtls_ecp_keypair_free((pf_mbedtls_ecp_keypair *) ctx);
    pf_mbedtls_free(ctx);
}
#endif /* MBEDTLS_PK_USE_PSA_EC_DATA */

static void eckey_debug(pf_mbedtls_pk_context *pk, pf_mbedtls_pk_debug_item *items)
{
#if defined(PF_MBEDTLS_PK_USE_PSA_EC_DATA)
    items->type = PF_MBEDTLS_PK_DEBUG_PSA_EC;
    items->name = "eckey.Q";
    items->value = pk;
#else /* MBEDTLS_PK_USE_PSA_EC_DATA */
    pf_mbedtls_ecp_keypair *ecp = (pf_mbedtls_ecp_keypair *) pk->pk_ctx;
    items->type = PF_MBEDTLS_PK_DEBUG_ECP;
    items->name = "eckey.Q";
    items->value = &(ecp->Q);
#endif /* MBEDTLS_PK_USE_PSA_EC_DATA */
}

const pf_mbedtls_pk_info_t pf_mbedtls_eckey_info = {
    .type = PF_MBEDTLS_PK_ECKEY,
    .name = "EC",
    .get_bitlen = eckey_get_bitlen,
    .can_do = eckey_can_do,
#if defined(PF_MBEDTLS_PK_CAN_ECDSA_VERIFY)
    .verify_func = ecdsa_verify_wrap,   /* Compatible key structures */
#else /* MBEDTLS_PK_CAN_ECDSA_VERIFY */
    .verify_func = NULL,
#endif /* MBEDTLS_PK_CAN_ECDSA_VERIFY */
#if defined(PF_MBEDTLS_PK_CAN_ECDSA_SIGN)
    .sign_func = ecdsa_sign_wrap,   /* Compatible key structures */
#else /* MBEDTLS_PK_CAN_ECDSA_VERIFY */
    .sign_func = NULL,
#endif /* MBEDTLS_PK_CAN_ECDSA_VERIFY */
#if defined(PF_MBEDTLS_ECDSA_C) && defined(PF_MBEDTLS_ECP_RESTARTABLE)
    .verify_rs_func = eckey_verify_rs_wrap,
    .sign_rs_func = eckey_sign_rs_wrap,
    .rs_alloc_func = eckey_rs_alloc,
    .rs_free_func = eckey_rs_free,
#endif /* MBEDTLS_ECDSA_C && MBEDTLS_ECP_RESTARTABLE */
    .decrypt_func = NULL,
    .encrypt_func = NULL,
    .check_pair_func = eckey_check_pair_wrap,
#if defined(PF_MBEDTLS_PK_USE_PSA_EC_DATA)
    .ctx_alloc_func = NULL,
    .ctx_free_func = NULL,
#else /* MBEDTLS_PK_USE_PSA_EC_DATA */
    .ctx_alloc_func = eckey_alloc_wrap,
    .ctx_free_func = eckey_free_wrap,
#endif /* MBEDTLS_PK_USE_PSA_EC_DATA */
    .debug_func = eckey_debug,
};

/*
 * EC key restricted to ECDH
 */
static int eckeydh_can_do(pf_mbedtls_pk_type_t type)
{
    return type == PF_MBEDTLS_PK_ECKEY ||
           type == PF_MBEDTLS_PK_ECKEY_DH;
}

const pf_mbedtls_pk_info_t pf_mbedtls_eckeydh_info = {
    .type = PF_MBEDTLS_PK_ECKEY_DH,
    .name = "EC_DH",
    .get_bitlen = eckey_get_bitlen,         /* Same underlying key structure */
    .can_do = eckeydh_can_do,
    .verify_func = NULL,
    .sign_func = NULL,
#if defined(PF_MBEDTLS_ECDSA_C) && defined(PF_MBEDTLS_ECP_RESTARTABLE)
    .verify_rs_func = NULL,
    .sign_rs_func = NULL,
#endif /* MBEDTLS_ECDSA_C && MBEDTLS_ECP_RESTARTABLE */
    .decrypt_func = NULL,
    .encrypt_func = NULL,
    .check_pair_func = eckey_check_pair_wrap,
#if defined(PF_MBEDTLS_PK_USE_PSA_EC_DATA)
    .ctx_alloc_func = NULL,
    .ctx_free_func = NULL,
#else /* MBEDTLS_PK_USE_PSA_EC_DATA */
    .ctx_alloc_func = eckey_alloc_wrap,   /* Same underlying key structure */
    .ctx_free_func = eckey_free_wrap,    /* Same underlying key structure */
#endif /* MBEDTLS_PK_USE_PSA_EC_DATA */
    .debug_func = eckey_debug,            /* Same underlying key structure */
};

#if defined(PF_MBEDTLS_PK_CAN_ECDSA_SOME)
static int ecdsa_can_do(pf_mbedtls_pk_type_t type)
{
    return type == PF_MBEDTLS_PK_ECDSA;
}

#if defined(PF_MBEDTLS_ECDSA_C) && defined(PF_MBEDTLS_ECP_RESTARTABLE)
static int ecdsa_verify_rs_wrap(pf_mbedtls_pk_context *pk, pf_mbedtls_md_type_t md_alg,
                                const unsigned char *hash, size_t hash_len,
                                const unsigned char *sig, size_t sig_len,
                                void *rs_ctx)
{
    int ret = PF_MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    ((void) md_alg);

    ret = pf_mbedtls_ecdsa_read_signature_restartable(
        (pf_mbedtls_ecdsa_context *) pk->pk_ctx,
        hash, hash_len, sig, sig_len,
        (pf_mbedtls_ecdsa_restart_ctx *) rs_ctx);

    if (ret == PF_MBEDTLS_ERR_ECP_SIG_LEN_MISMATCH) {
        return PF_MBEDTLS_ERR_PK_SIG_LEN_MISMATCH;
    }

    return ret;
}

static int ecdsa_sign_rs_wrap(pf_mbedtls_pk_context *pk, pf_mbedtls_md_type_t md_alg,
                              const unsigned char *hash, size_t hash_len,
                              unsigned char *sig, size_t sig_size, size_t *sig_len,
                              int (*f_rng)(void *, unsigned char *, size_t), void *p_rng,
                              void *rs_ctx)
{
    return pf_mbedtls_ecdsa_write_signature_restartable(
        (pf_mbedtls_ecdsa_context *) pk->pk_ctx,
        md_alg, hash, hash_len, sig, sig_size, sig_len, f_rng, p_rng,
        (pf_mbedtls_ecdsa_restart_ctx *) rs_ctx);

}

static void *ecdsa_rs_alloc(void)
{
    void *ctx = pf_mbedtls_calloc(1, sizeof(pf_mbedtls_ecdsa_restart_ctx));

    if (ctx != NULL) {
        pf_mbedtls_ecdsa_restart_init(ctx);
    }

    return ctx;
}

static void ecdsa_rs_free(void *ctx)
{
    pf_mbedtls_ecdsa_restart_free(ctx);
    pf_mbedtls_free(ctx);
}
#endif /* MBEDTLS_ECDSA_C && MBEDTLS_ECP_RESTARTABLE */

const pf_mbedtls_pk_info_t pf_mbedtls_ecdsa_info = {
    .type = PF_MBEDTLS_PK_ECDSA,
    .name = "ECDSA",
    .get_bitlen = eckey_get_bitlen,     /* Compatible key structures */
    .can_do = ecdsa_can_do,
#if defined(PF_MBEDTLS_PK_CAN_ECDSA_VERIFY)
    .verify_func = ecdsa_verify_wrap,   /* Compatible key structures */
#else /* MBEDTLS_PK_CAN_ECDSA_VERIFY */
    .verify_func = NULL,
#endif /* MBEDTLS_PK_CAN_ECDSA_VERIFY */
#if defined(PF_MBEDTLS_PK_CAN_ECDSA_SIGN)
    .sign_func = ecdsa_sign_wrap,   /* Compatible key structures */
#else /* MBEDTLS_PK_CAN_ECDSA_SIGN */
    .sign_func = NULL,
#endif /* MBEDTLS_PK_CAN_ECDSA_SIGN */
#if defined(PF_MBEDTLS_ECDSA_C) && defined(PF_MBEDTLS_ECP_RESTARTABLE)
    .verify_rs_func = ecdsa_verify_rs_wrap,
    .sign_rs_func = ecdsa_sign_rs_wrap,
    .rs_alloc_func = ecdsa_rs_alloc,
    .rs_free_func = ecdsa_rs_free,
#endif /* MBEDTLS_ECDSA_C && MBEDTLS_ECP_RESTARTABLE */
    .decrypt_func = NULL,
    .encrypt_func = NULL,
    .check_pair_func = eckey_check_pair_wrap,   /* Compatible key structures */
#if defined(PF_MBEDTLS_PK_USE_PSA_EC_DATA)
    .ctx_alloc_func = NULL,
    .ctx_free_func = NULL,
#else /* MBEDTLS_PK_USE_PSA_EC_DATA */
    .ctx_alloc_func = eckey_alloc_wrap,   /* Compatible key structures */
    .ctx_free_func = eckey_free_wrap,   /* Compatible key structures */
#endif /* MBEDTLS_PK_USE_PSA_EC_DATA */
    .debug_func = eckey_debug,        /* Compatible key structures */
};
#endif /* MBEDTLS_PK_CAN_ECDSA_SOME */
#endif /* MBEDTLS_PK_HAVE_ECC_KEYS */

#if defined(PF_MBEDTLS_PK_RSA_ALT_SUPPORT)
/*
 * Support for alternative RSA-private implementations
 */

static int rsa_alt_can_do(pf_mbedtls_pk_type_t type)
{
    return type == PF_MBEDTLS_PK_RSA;
}

static size_t rsa_alt_get_bitlen(pf_mbedtls_pk_context *pk)
{
    const pf_mbedtls_rsa_alt_context *rsa_alt = pk->pk_ctx;

    return 8 * rsa_alt->key_len_func(rsa_alt->key);
}

static int rsa_alt_sign_wrap(pf_mbedtls_pk_context *pk, pf_mbedtls_md_type_t md_alg,
                             const unsigned char *hash, size_t hash_len,
                             unsigned char *sig, size_t sig_size, size_t *sig_len,
                             int (*f_rng)(void *, unsigned char *, size_t), void *p_rng)
{
    pf_mbedtls_rsa_alt_context *rsa_alt = pk->pk_ctx;

#if SIZE_MAX > UINT_MAX
    if (UINT_MAX < hash_len) {
        return PF_MBEDTLS_ERR_PK_BAD_INPUT_DATA;
    }
#endif

    *sig_len = rsa_alt->key_len_func(rsa_alt->key);
    if (*sig_len > PF_MBEDTLS_PK_SIGNATURE_MAX_SIZE) {
        return PF_MBEDTLS_ERR_PK_BAD_INPUT_DATA;
    }
    if (*sig_len > sig_size) {
        return PF_MBEDTLS_ERR_PK_BUFFER_TOO_SMALL;
    }

    return rsa_alt->sign_func(rsa_alt->key, f_rng, p_rng,
                              md_alg, (unsigned int) hash_len, hash, sig);
}

static int rsa_alt_decrypt_wrap(pf_mbedtls_pk_context *pk,
                                const unsigned char *input, size_t ilen,
                                unsigned char *output, size_t *olen, size_t osize,
                                int (*f_rng)(void *, unsigned char *, size_t), void *p_rng)
{
    pf_mbedtls_rsa_alt_context *rsa_alt = pk->pk_ctx;

    ((void) f_rng);
    ((void) p_rng);

    if (ilen != rsa_alt->key_len_func(rsa_alt->key)) {
        return PF_MBEDTLS_ERR_RSA_BAD_INPUT_DATA;
    }

    return rsa_alt->decrypt_func(rsa_alt->key,
                                 olen, input, output, osize);
}

#if defined(PF_MBEDTLS_RSA_C)
static int rsa_alt_check_pair(pf_mbedtls_pk_context *pub, pf_mbedtls_pk_context *prv,
                              int (*f_rng)(void *, unsigned char *, size_t),
                              void *p_rng)
{
    unsigned char hash[32];
    size_t sig_len = 0;
    int ret = PF_MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;

    if (rsa_alt_get_bitlen(prv) != rsa_get_bitlen(pub)) {
        return PF_MBEDTLS_ERR_RSA_KEY_CHECK_FAILED;
    }

    size_t sig_size = (rsa_get_bitlen(pub) + 7) / 8;
    unsigned char *sig = pf_mbedtls_calloc(1, sig_size);
    if (sig == NULL) {
        return PF_MBEDTLS_ERR_PK_ALLOC_FAILED;
    }

    memset(hash, 0x2a, sizeof(hash));

    if ((ret = rsa_alt_sign_wrap(prv, PF_MBEDTLS_MD_NONE,
                                 hash, sizeof(hash),
                                 sig, sig_size, &sig_len,
                                 f_rng, p_rng)) != 0) {
        goto cleanup;
    }

    if (rsa_verify_wrap(pub, PF_MBEDTLS_MD_NONE,
                        hash, sizeof(hash), sig, sig_len) != 0) {
        ret = PF_MBEDTLS_ERR_RSA_KEY_CHECK_FAILED;
    }

cleanup:
    pf_mbedtls_zeroize_and_free(sig, sig_size);
    return ret;
}
#endif /* MBEDTLS_RSA_C */

static void *rsa_alt_alloc_wrap(void)
{
    void *ctx = pf_mbedtls_calloc(1, sizeof(pf_mbedtls_rsa_alt_context));

    if (ctx != NULL) {
        memset(ctx, 0, sizeof(pf_mbedtls_rsa_alt_context));
    }

    return ctx;
}

static void rsa_alt_free_wrap(void *ctx)
{
    pf_mbedtls_zeroize_and_free(ctx, sizeof(pf_mbedtls_rsa_alt_context));
}

const pf_mbedtls_pk_info_t pf_mbedtls_rsa_alt_info = {
    .type = PF_MBEDTLS_PK_RSA_ALT,
    .name = "RSA-alt",
    .get_bitlen = rsa_alt_get_bitlen,
    .can_do = rsa_alt_can_do,
    .verify_func = NULL,
    .sign_func = rsa_alt_sign_wrap,
#if defined(PF_MBEDTLS_ECDSA_C) && defined(PF_MBEDTLS_ECP_RESTARTABLE)
    .verify_rs_func = NULL,
    .sign_rs_func = NULL,
    .rs_alloc_func = NULL,
    .rs_free_func = NULL,
#endif /* MBEDTLS_ECDSA_C && MBEDTLS_ECP_RESTARTABLE */
    .decrypt_func = rsa_alt_decrypt_wrap,
    .encrypt_func = NULL,
#if defined(PF_MBEDTLS_RSA_C)
    .check_pair_func = rsa_alt_check_pair,
#else
    .check_pair_func = NULL,
#endif
    .ctx_alloc_func = rsa_alt_alloc_wrap,
    .ctx_free_func = rsa_alt_free_wrap,
    .debug_func = NULL,
};
#endif /* MBEDTLS_PK_RSA_ALT_SUPPORT */

#if defined(PF_MBEDTLS_USE_PSA_CRYPTO)
static size_t opaque_get_bitlen(pf_mbedtls_pk_context *pk)
{
    size_t bits;
    pf_psa_key_attributes_t attributes = PF_PSA_KEY_ATTRIBUTES_INIT;

    if (PF_PSA_SUCCESS != pf_psa_get_key_attributes(pk->priv_id, &attributes)) {
        return 0;
    }

    bits = pf_psa_get_key_bits(&attributes);
    pf_psa_reset_key_attributes(&attributes);
    return bits;
}

#if defined(PF_MBEDTLS_PK_HAVE_ECC_KEYS)
static int ecdsa_opaque_can_do(pf_mbedtls_pk_type_t type)
{
    return type == PF_MBEDTLS_PK_ECKEY ||
           type == PF_MBEDTLS_PK_ECDSA;
}

const pf_mbedtls_pk_info_t pf_mbedtls_ecdsa_opaque_info = {
    .type = PF_MBEDTLS_PK_OPAQUE,
    .name = "Opaque",
    .get_bitlen = opaque_get_bitlen,
    .can_do = ecdsa_opaque_can_do,
#if defined(PF_MBEDTLS_PK_CAN_ECDSA_VERIFY)
    .verify_func = ecdsa_opaque_verify_wrap,
#else /* MBEDTLS_PK_CAN_ECDSA_VERIFY */
    .verify_func = NULL,
#endif /* MBEDTLS_PK_CAN_ECDSA_VERIFY */
#if defined(PF_MBEDTLS_PK_CAN_ECDSA_SIGN)
    .sign_func = ecdsa_opaque_sign_wrap,
#else /* MBEDTLS_PK_CAN_ECDSA_SIGN */
    .sign_func = NULL,
#endif /* MBEDTLS_PK_CAN_ECDSA_SIGN */
#if defined(PF_MBEDTLS_ECDSA_C) && defined(PF_MBEDTLS_ECP_RESTARTABLE)
    .verify_rs_func = NULL,
    .sign_rs_func = NULL,
    .rs_alloc_func = NULL,
    .rs_free_func = NULL,
#endif /* MBEDTLS_ECDSA_C && MBEDTLS_ECP_RESTARTABLE */
    .decrypt_func = NULL,
    .encrypt_func = NULL,
    .check_pair_func = ecdsa_opaque_check_pair_wrap,
    .ctx_alloc_func = NULL,
    .ctx_free_func = NULL,
    .debug_func = NULL,
};
#endif /* MBEDTLS_PK_HAVE_ECC_KEYS */

static int rsa_opaque_can_do(pf_mbedtls_pk_type_t type)
{
    return type == PF_MBEDTLS_PK_RSA ||
           type == PF_MBEDTLS_PK_RSASSA_PSS;
}

#if defined(PF_PSA_WANT_KEY_TYPE_RSA_KEY_PAIR_BASIC)
static int rsa_opaque_decrypt(pf_mbedtls_pk_context *pk,
                              const unsigned char *input, size_t ilen,
                              unsigned char *output, size_t *olen, size_t osize,
                              int (*f_rng)(void *, unsigned char *, size_t), void *p_rng)
{
    pf_psa_key_attributes_t attributes = PF_PSA_KEY_ATTRIBUTES_INIT;
    pf_psa_algorithm_t alg;
    pf_psa_key_type_t type;
    pf_psa_status_t status;

    /* PSA has its own RNG */
    (void) f_rng;
    (void) p_rng;

    status = pf_psa_get_key_attributes(pk->priv_id, &attributes);
    if (status != PF_PSA_SUCCESS) {
        return PF_PSA_PK_TO_MBEDTLS_ERR(status);
    }

    type = pf_psa_get_key_type(&attributes);
    alg = pf_psa_get_key_algorithm(&attributes);
    pf_psa_reset_key_attributes(&attributes);

    if (!PF_PSA_KEY_TYPE_IS_RSA(type)) {
        return PF_MBEDTLS_ERR_PK_FEATURE_UNAVAILABLE;
    }

    status = pf_psa_asymmetric_decrypt(pk->priv_id, alg, input, ilen, NULL, 0, output, osize, olen);
#if defined(PF_MBEDTLS_PKCS1_V15)
    /* Translate error codes from PSA to legacy
     * Success vs INVALID_PADDING vs BUFFER_TOO_SMALL is sensitive
     * (padding oracle attack), so we take care to translate that
     * part in constant time.
     */
    int problem;
    status = pf_mbedtls_rsa_decrypt_decompose_ret(
        PF_PSA_ERROR_INVALID_PADDING, PF_MBEDTLS_ERR_RSA_INVALID_PADDING,
        PF_PSA_ERROR_BUFFER_TOO_SMALL, PF_MBEDTLS_ERR_RSA_OUTPUT_TOO_LARGE,
        status, &problem);
    return PF_PSA_PK_RSA_TO_MBEDTLS_ERR(status) | problem;
#else
    return PF_PSA_PK_RSA_TO_MBEDTLS_ERR(status);
#endif
}
#endif /* PSA_WANT_KEY_TYPE_RSA_KEY_PAIR_BASIC */

static int rsa_opaque_sign_wrap(pf_mbedtls_pk_context *pk, pf_mbedtls_md_type_t md_alg,
                                const unsigned char *hash, size_t hash_len,
                                unsigned char *sig, size_t sig_size, size_t *sig_len,
                                int (*f_rng)(void *, unsigned char *, size_t), void *p_rng)
{
#if defined(PF_MBEDTLS_RSA_C)
    pf_psa_key_attributes_t attributes = PF_PSA_KEY_ATTRIBUTES_INIT;
    pf_psa_algorithm_t alg;
    pf_psa_key_type_t type;
    pf_psa_status_t status;

    /* PSA has its own RNG */
    (void) f_rng;
    (void) p_rng;

    status = pf_psa_get_key_attributes(pk->priv_id, &attributes);
    if (status != PF_PSA_SUCCESS) {
        return PF_PSA_PK_TO_MBEDTLS_ERR(status);
    }

    type = pf_psa_get_key_type(&attributes);
    alg = pf_psa_get_key_algorithm(&attributes);
    pf_psa_reset_key_attributes(&attributes);

    if (PF_PSA_KEY_TYPE_IS_RSA(type)) {
        alg = (alg & ~PF_PSA_ALG_HASH_MASK) | pf_mbedtls_md_psa_alg_from_type(md_alg);
    } else {
        return PF_MBEDTLS_ERR_PK_FEATURE_UNAVAILABLE;
    }

    status = pf_psa_sign_hash(pk->priv_id, alg, hash, hash_len, sig, sig_size, sig_len);
    if (status != PF_PSA_SUCCESS) {
        if (PF_PSA_KEY_TYPE_IS_RSA(type)) {
            return PF_PSA_PK_RSA_TO_MBEDTLS_ERR(status);
        } else {
            return PF_PSA_PK_TO_MBEDTLS_ERR(status);
        }
    }

    return 0;
#else /* !MBEDTLS_RSA_C */
    ((void) pk);
    ((void) md_alg);
    ((void) hash);
    ((void) hash_len);
    ((void) sig);
    ((void) sig_size);
    ((void) sig_len);
    ((void) f_rng);
    ((void) p_rng);
    return PF_MBEDTLS_ERR_PK_FEATURE_UNAVAILABLE;
#endif /* !MBEDTLS_RSA_C */
}

const pf_mbedtls_pk_info_t pf_mbedtls_rsa_opaque_info = {
    .type = PF_MBEDTLS_PK_OPAQUE,
    .name = "Opaque",
    .get_bitlen = opaque_get_bitlen,
    .can_do = rsa_opaque_can_do,
    .verify_func = NULL,
    .sign_func = rsa_opaque_sign_wrap,
#if defined(PF_MBEDTLS_ECDSA_C) && defined(PF_MBEDTLS_ECP_RESTARTABLE)
    .verify_rs_func = NULL,
    .sign_rs_func = NULL,
    .rs_alloc_func = NULL,
    .rs_free_func = NULL,
#endif /* MBEDTLS_ECDSA_C && MBEDTLS_ECP_RESTARTABLE */
#if defined(PF_PSA_WANT_KEY_TYPE_RSA_KEY_PAIR_BASIC)
    .decrypt_func = rsa_opaque_decrypt,
#else /* PSA_WANT_KEY_TYPE_RSA_KEY_PAIR_BASIC */
    .decrypt_func = NULL,
#endif /* PSA_WANT_KEY_TYPE_RSA_KEY_PAIR_BASIC */
    .encrypt_func = NULL,
    .check_pair_func = NULL,
    .ctx_alloc_func = NULL,
    .ctx_free_func = NULL,
    .debug_func = NULL,
};

#endif /* MBEDTLS_USE_PSA_CRYPTO */

#endif /* MBEDTLS_PK_C */
