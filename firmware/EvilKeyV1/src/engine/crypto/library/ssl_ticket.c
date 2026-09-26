#include "../../../pf_build_config.h"
/*
 *  TLS server tickets callbacks implementation
 *
 *  Copyright The Mbed TLS Contributors
 *  SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
 */

#include "common.h"

#if defined(PF_MBEDTLS_SSL_TICKET_C)

#include "../include/mbedtls/platform.h"

#include "ssl_misc.h"
#include "../include/mbedtls/ssl_ticket.h"
#include "../include/mbedtls/error.h"
#include "../include/mbedtls/platform_util.h"

#include <string.h>

#if defined(PF_MBEDTLS_USE_PSA_CRYPTO)
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

/*
 * Initialize context
 */
void pf_mbedtls_ssl_ticket_init(pf_mbedtls_ssl_ticket_context *ctx)
{
    memset(ctx, 0, sizeof(pf_mbedtls_ssl_ticket_context));

#if defined(PF_MBEDTLS_THREADING_C)
    pf_mbedtls_mutex_init(&ctx->mutex);
#endif
}

#define MAX_KEY_BYTES           PF_MBEDTLS_SSL_TICKET_MAX_KEY_BYTES

#define TICKET_KEY_NAME_BYTES   PF_MBEDTLS_SSL_TICKET_KEY_NAME_BYTES
#define TICKET_IV_BYTES         12
#define TICKET_CRYPT_LEN_BYTES   2
#define TICKET_AUTH_TAG_BYTES   16

#define TICKET_MIN_LEN (TICKET_KEY_NAME_BYTES  +        \
                        TICKET_IV_BYTES        +        \
                        TICKET_CRYPT_LEN_BYTES +        \
                        TICKET_AUTH_TAG_BYTES)
#define TICKET_ADD_DATA_LEN (TICKET_KEY_NAME_BYTES  +        \
                             TICKET_IV_BYTES        +        \
                             TICKET_CRYPT_LEN_BYTES)

/*
 * Generate/update a key
 */
PF_MBEDTLS_CHECK_RETURN_CRITICAL
static int ssl_ticket_gen_key(pf_mbedtls_ssl_ticket_context *ctx,
                              unsigned char index)
{
    int ret = PF_MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    unsigned char buf[MAX_KEY_BYTES] = { 0 };
    pf_mbedtls_ssl_ticket_key *key = ctx->keys + index;

#if defined(PF_MBEDTLS_USE_PSA_CRYPTO)
    pf_psa_key_attributes_t attributes = PF_PSA_KEY_ATTRIBUTES_INIT;
#endif

#if defined(PF_MBEDTLS_HAVE_TIME)
    key->generation_time = pf_mbedtls_time(NULL);
#endif
    /* The lifetime of a key is the configured lifetime of the tickets when
     * the key is created.
     */
    key->lifetime = ctx->ticket_lifetime;

    if ((ret = ctx->f_rng(ctx->p_rng, key->name, sizeof(key->name))) != 0) {
        return ret;
    }

    if ((ret = ctx->f_rng(ctx->p_rng, buf, sizeof(buf))) != 0) {
        return ret;
    }

#if defined(PF_MBEDTLS_USE_PSA_CRYPTO)
    pf_psa_set_key_usage_flags(&attributes,
                            PF_PSA_KEY_USAGE_ENCRYPT | PF_PSA_KEY_USAGE_DECRYPT);
    pf_psa_set_key_algorithm(&attributes, key->alg);
    pf_psa_set_key_type(&attributes, key->key_type);
    pf_psa_set_key_bits(&attributes, key->key_bits);

    ret = PF_PSA_TO_MBEDTLS_ERR(
        pf_psa_import_key(&attributes, buf,
                       PF_PSA_BITS_TO_BYTES(key->key_bits),
                       &key->key));
#else
    /* With GCM and CCM, same context can encrypt & decrypt */
    ret = pf_mbedtls_cipher_setkey(&key->ctx, buf,
                                pf_mbedtls_cipher_get_key_bitlen(&key->ctx),
                                PF_MBEDTLS_ENCRYPT);
#endif /* MBEDTLS_USE_PSA_CRYPTO */

    pf_mbedtls_platform_zeroize(buf, sizeof(buf));

    return ret;
}

/*
 * Rotate/generate keys if necessary
 */
PF_MBEDTLS_CHECK_RETURN_CRITICAL
static int ssl_ticket_update_keys(pf_mbedtls_ssl_ticket_context *ctx)
{
#if !defined(PF_MBEDTLS_HAVE_TIME)
    ((void) ctx);
#else
    pf_mbedtls_ssl_ticket_key * const key = ctx->keys + ctx->active;
    if (key->lifetime != 0) {
        pf_mbedtls_time_t current_time = pf_mbedtls_time(NULL);
        pf_mbedtls_time_t key_time = key->generation_time;

#if defined(PF_MBEDTLS_USE_PSA_CRYPTO)
        pf_psa_status_t status = PF_PSA_ERROR_CORRUPTION_DETECTED;
#endif

        if (current_time >= key_time &&
            (uint64_t) (current_time - key_time) < key->lifetime) {
            return 0;
        }

        ctx->active = 1 - ctx->active;

#if defined(PF_MBEDTLS_USE_PSA_CRYPTO)
        if ((status = pf_psa_destroy_key(ctx->keys[ctx->active].key)) != PF_PSA_SUCCESS) {
            return PF_PSA_TO_MBEDTLS_ERR(status);
        }
#endif /* MBEDTLS_USE_PSA_CRYPTO */

        return ssl_ticket_gen_key(ctx, ctx->active);
    } else
#endif /* MBEDTLS_HAVE_TIME */
    return 0;
}

/*
 * Rotate active session ticket encryption key
 */
int pf_mbedtls_ssl_ticket_rotate(pf_mbedtls_ssl_ticket_context *ctx,
                              const unsigned char *name, size_t nlength,
                              const unsigned char *k, size_t klength,
                              uint32_t lifetime)
{
    const unsigned char idx = 1 - ctx->active;
    pf_mbedtls_ssl_ticket_key * const key = ctx->keys + idx;
    int ret = PF_MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;

#if defined(PF_MBEDTLS_USE_PSA_CRYPTO)
    pf_psa_status_t status = PF_PSA_ERROR_CORRUPTION_DETECTED;
    pf_psa_key_attributes_t attributes = PF_PSA_KEY_ATTRIBUTES_INIT;
    const size_t bitlen = key->key_bits;
#else
    const int bitlen = pf_mbedtls_cipher_get_key_bitlen(&key->ctx);
#endif

    if (nlength < TICKET_KEY_NAME_BYTES || klength * 8 < (size_t) bitlen) {
        return PF_MBEDTLS_ERR_CIPHER_BAD_INPUT_DATA;
    }

#if defined(PF_MBEDTLS_USE_PSA_CRYPTO)
    if ((status = pf_psa_destroy_key(key->key)) != PF_PSA_SUCCESS) {
        ret = PF_PSA_TO_MBEDTLS_ERR(status);
        return ret;
    }

    pf_psa_set_key_usage_flags(&attributes,
                            PF_PSA_KEY_USAGE_ENCRYPT | PF_PSA_KEY_USAGE_DECRYPT);
    pf_psa_set_key_algorithm(&attributes, key->alg);
    pf_psa_set_key_type(&attributes, key->key_type);
    pf_psa_set_key_bits(&attributes, key->key_bits);

    if ((status = pf_psa_import_key(&attributes, k,
                                 PF_PSA_BITS_TO_BYTES(key->key_bits),
                                 &key->key)) != PF_PSA_SUCCESS) {
        ret = PF_PSA_TO_MBEDTLS_ERR(status);
        return ret;
    }
#else
    ret = pf_mbedtls_cipher_setkey(&key->ctx, k, bitlen, PF_MBEDTLS_ENCRYPT);
    if (ret != 0) {
        return ret;
    }
#endif /* MBEDTLS_USE_PSA_CRYPTO */

    ctx->active = idx;
    ctx->ticket_lifetime = lifetime;
    memcpy(key->name, name, TICKET_KEY_NAME_BYTES);
#if defined(PF_MBEDTLS_HAVE_TIME)
    key->generation_time = pf_mbedtls_time(NULL);
#endif
    key->lifetime = lifetime;

    return 0;
}

/*
 * Setup context for actual use
 */
int pf_mbedtls_ssl_ticket_setup(pf_mbedtls_ssl_ticket_context *ctx,
                             int (*f_rng)(void *, unsigned char *, size_t), void *p_rng,
                             pf_mbedtls_cipher_type_t cipher,
                             uint32_t lifetime)
{
    int ret = PF_MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    size_t key_bits;

#if defined(PF_MBEDTLS_USE_PSA_CRYPTO)
    pf_psa_algorithm_t alg;
    pf_psa_key_type_t key_type;
#else
    const pf_mbedtls_cipher_info_t *cipher_info;
#endif /* MBEDTLS_USE_PSA_CRYPTO */

#if defined(PF_MBEDTLS_USE_PSA_CRYPTO)
    if (pf_mbedtls_ssl_cipher_to_psa(cipher, TICKET_AUTH_TAG_BYTES,
                                  &alg, &key_type, &key_bits) != PF_PSA_SUCCESS) {
        return PF_MBEDTLS_ERR_SSL_BAD_INPUT_DATA;
    }

    if (PF_PSA_ALG_IS_AEAD(alg) == 0) {
        return PF_MBEDTLS_ERR_SSL_BAD_INPUT_DATA;
    }
#else
    cipher_info = pf_mbedtls_cipher_info_from_type(cipher);

    if (pf_mbedtls_cipher_info_get_mode(cipher_info) != PF_MBEDTLS_MODE_GCM &&
        pf_mbedtls_cipher_info_get_mode(cipher_info) != PF_MBEDTLS_MODE_CCM &&
        pf_mbedtls_cipher_info_get_mode(cipher_info) != PF_MBEDTLS_MODE_CHACHAPOLY) {
        return PF_MBEDTLS_ERR_SSL_BAD_INPUT_DATA;
    }

    key_bits = pf_mbedtls_cipher_info_get_key_bitlen(cipher_info);
#endif /* MBEDTLS_USE_PSA_CRYPTO */

    if (key_bits > 8 * MAX_KEY_BYTES) {
        return PF_MBEDTLS_ERR_SSL_BAD_INPUT_DATA;
    }

    ctx->f_rng = f_rng;
    ctx->p_rng = p_rng;

    ctx->ticket_lifetime = lifetime;

#if defined(PF_MBEDTLS_USE_PSA_CRYPTO)
    ctx->keys[0].alg = alg;
    ctx->keys[0].key_type = key_type;
    ctx->keys[0].key_bits = key_bits;

    ctx->keys[1].alg = alg;
    ctx->keys[1].key_type = key_type;
    ctx->keys[1].key_bits = key_bits;
#else
    if ((ret = pf_mbedtls_cipher_setup(&ctx->keys[0].ctx, cipher_info)) != 0) {
        return ret;
    }

    if ((ret = pf_mbedtls_cipher_setup(&ctx->keys[1].ctx, cipher_info)) != 0) {
        return ret;
    }
#endif /* MBEDTLS_USE_PSA_CRYPTO */

    if ((ret = ssl_ticket_gen_key(ctx, 0)) != 0 ||
        (ret = ssl_ticket_gen_key(ctx, 1)) != 0) {
        return ret;
    }

    return 0;
}

/*
 * Create session ticket, with the following structure:
 *
 *    struct {
 *        opaque key_name[4];
 *        opaque iv[12];
 *        opaque encrypted_state<0..2^16-1>;
 *        opaque tag[16];
 *    } ticket;
 *
 * The key_name, iv, and length of encrypted_state are the additional
 * authenticated data.
 */

int pf_mbedtls_ssl_ticket_write(void *p_ticket,
                             const pf_mbedtls_ssl_session *session,
                             unsigned char *start,
                             const unsigned char *end,
                             size_t *tlen,
                             uint32_t *ticket_lifetime)
{
    int ret = PF_MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    pf_mbedtls_ssl_ticket_context *ctx = p_ticket;
    pf_mbedtls_ssl_ticket_key *key;
    unsigned char *key_name = start;
    unsigned char *iv = start + TICKET_KEY_NAME_BYTES;
    unsigned char *state_len_bytes = iv + TICKET_IV_BYTES;
    unsigned char *state = state_len_bytes + TICKET_CRYPT_LEN_BYTES;
    size_t clear_len, ciph_len;

#if defined(PF_MBEDTLS_USE_PSA_CRYPTO)
    pf_psa_status_t status = PF_PSA_ERROR_CORRUPTION_DETECTED;
#endif

    *tlen = 0;

    if (ctx == NULL || ctx->f_rng == NULL) {
        return PF_MBEDTLS_ERR_SSL_BAD_INPUT_DATA;
    }

    /* We need at least 4 bytes for key_name, 12 for IV, 2 for len 16 for tag,
     * in addition to session itself, that will be checked when writing it. */
    PF_MBEDTLS_SSL_CHK_BUF_PTR(start, end, TICKET_MIN_LEN);

#if defined(PF_MBEDTLS_THREADING_C)
    if ((ret = pf_mbedtls_mutex_lock(&ctx->mutex)) != 0) {
        return ret;
    }
#endif

    if ((ret = ssl_ticket_update_keys(ctx)) != 0) {
        goto cleanup;
    }

    key = &ctx->keys[ctx->active];

    *ticket_lifetime = key->lifetime;

    memcpy(key_name, key->name, TICKET_KEY_NAME_BYTES);

    if ((ret = ctx->f_rng(ctx->p_rng, iv, TICKET_IV_BYTES)) != 0) {
        goto cleanup;
    }

    /* Dump session state */
    if ((ret = pf_mbedtls_ssl_session_save(session,
                                        state, (size_t) (end - state),
                                        &clear_len)) != 0 ||
        (unsigned long) clear_len > 65535) {
        goto cleanup;
    }
    PF_MBEDTLS_PUT_UINT16_BE(clear_len, state_len_bytes, 0);

    /* Encrypt and authenticate */
#if defined(PF_MBEDTLS_USE_PSA_CRYPTO)
    if ((status = pf_psa_aead_encrypt(key->key, key->alg, iv, TICKET_IV_BYTES,
                                   key_name, TICKET_ADD_DATA_LEN,
                                   state, clear_len,
                                   state, end - state,
                                   &ciph_len)) != PF_PSA_SUCCESS) {
        ret = PF_PSA_TO_MBEDTLS_ERR(status);
        goto cleanup;
    }
#else
    if ((ret = pf_mbedtls_cipher_auth_encrypt_ext(&key->ctx,
                                               iv, TICKET_IV_BYTES,
                                               /* Additional data: key name, IV and length */
                                               key_name, TICKET_ADD_DATA_LEN,
                                               state, clear_len,
                                               state, (size_t) (end - state), &ciph_len,
                                               TICKET_AUTH_TAG_BYTES)) != 0) {
        goto cleanup;
    }
#endif /* MBEDTLS_USE_PSA_CRYPTO */

    if (ciph_len != clear_len + TICKET_AUTH_TAG_BYTES) {
        ret = PF_MBEDTLS_ERR_SSL_INTERNAL_ERROR;
        goto cleanup;
    }

    *tlen = TICKET_MIN_LEN + ciph_len - TICKET_AUTH_TAG_BYTES;

cleanup:
#if defined(PF_MBEDTLS_THREADING_C)
    if (pf_mbedtls_mutex_unlock(&ctx->mutex) != 0) {
        return PF_MBEDTLS_ERR_THREADING_MUTEX_ERROR;
    }
#endif

    return ret;
}

/*
 * Select key based on name
 */
static pf_mbedtls_ssl_ticket_key *ssl_ticket_select_key(
    pf_mbedtls_ssl_ticket_context *ctx,
    const unsigned char name[4])
{
    unsigned char i;

    for (i = 0; i < sizeof(ctx->keys) / sizeof(*ctx->keys); i++) {
        if (memcmp(name, ctx->keys[i].name, 4) == 0) {
            return &ctx->keys[i];
        }
    }

    return NULL;
}

/*
 * Load session ticket (see mbedtls_ssl_ticket_write for structure)
 */
int pf_mbedtls_ssl_ticket_parse(void *p_ticket,
                             pf_mbedtls_ssl_session *session,
                             unsigned char *buf,
                             size_t len)
{
    int ret = PF_MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    pf_mbedtls_ssl_ticket_context *ctx = p_ticket;
    pf_mbedtls_ssl_ticket_key *key;
    unsigned char *key_name = buf;
    unsigned char *iv = buf + TICKET_KEY_NAME_BYTES;
    unsigned char *enc_len_p = iv + TICKET_IV_BYTES;
    unsigned char *ticket = enc_len_p + TICKET_CRYPT_LEN_BYTES;
    size_t enc_len, clear_len;

#if defined(PF_MBEDTLS_USE_PSA_CRYPTO)
    pf_psa_status_t status = PF_PSA_ERROR_CORRUPTION_DETECTED;
#endif

    if (ctx == NULL || ctx->f_rng == NULL) {
        return PF_MBEDTLS_ERR_SSL_BAD_INPUT_DATA;
    }

    if (len < TICKET_MIN_LEN) {
        return PF_MBEDTLS_ERR_SSL_BAD_INPUT_DATA;
    }

#if defined(PF_MBEDTLS_THREADING_C)
    if ((ret = pf_mbedtls_mutex_lock(&ctx->mutex)) != 0) {
        return ret;
    }
#endif

    if ((ret = ssl_ticket_update_keys(ctx)) != 0) {
        goto cleanup;
    }

    enc_len = PF_MBEDTLS_GET_UINT16_BE(enc_len_p, 0);

    if (len != TICKET_MIN_LEN + enc_len) {
        ret = PF_MBEDTLS_ERR_SSL_BAD_INPUT_DATA;
        goto cleanup;
    }

    /* Select key */
    if ((key = ssl_ticket_select_key(ctx, key_name)) == NULL) {
        /* We can't know for sure but this is a likely option unless we're
         * under attack - this is only informative anyway */
        ret = PF_MBEDTLS_ERR_SSL_SESSION_TICKET_EXPIRED;
        goto cleanup;
    }

    /* Decrypt and authenticate */
#if defined(PF_MBEDTLS_USE_PSA_CRYPTO)
    if ((status = pf_psa_aead_decrypt(key->key, key->alg, iv, TICKET_IV_BYTES,
                                   key_name, TICKET_ADD_DATA_LEN,
                                   ticket, enc_len + TICKET_AUTH_TAG_BYTES,
                                   ticket, enc_len, &clear_len)) != PF_PSA_SUCCESS) {
        ret = PF_PSA_TO_MBEDTLS_ERR(status);
        goto cleanup;
    }
#else
    if ((ret = pf_mbedtls_cipher_auth_decrypt_ext(&key->ctx,
                                               iv, TICKET_IV_BYTES,
                                               /* Additional data: key name, IV and length */
                                               key_name, TICKET_ADD_DATA_LEN,
                                               ticket, enc_len + TICKET_AUTH_TAG_BYTES,
                                               ticket, enc_len, &clear_len,
                                               TICKET_AUTH_TAG_BYTES)) != 0) {
        if (ret == PF_MBEDTLS_ERR_CIPHER_AUTH_FAILED) {
            ret = PF_MBEDTLS_ERR_SSL_INVALID_MAC;
        }

        goto cleanup;
    }
#endif /* MBEDTLS_USE_PSA_CRYPTO */

    if (clear_len != enc_len) {
        ret = PF_MBEDTLS_ERR_SSL_INTERNAL_ERROR;
        goto cleanup;
    }

    /* Actually load session */
    if ((ret = pf_mbedtls_ssl_session_load(session, ticket, clear_len)) != 0) {
        goto cleanup;
    }

#if defined(PF_MBEDTLS_HAVE_TIME)
    pf_mbedtls_ms_time_t ticket_creation_time, ticket_age;
    pf_mbedtls_ms_time_t ticket_lifetime =
        (pf_mbedtls_ms_time_t) key->lifetime * 1000;

    ret = pf_mbedtls_ssl_session_get_ticket_creation_time(session,
                                                       &ticket_creation_time);
    if (ret != 0) {
        goto cleanup;
    }

    ticket_age = pf_mbedtls_ms_time() - ticket_creation_time;
    if (ticket_age < 0 || ticket_age > ticket_lifetime) {
        ret = PF_MBEDTLS_ERR_SSL_SESSION_TICKET_EXPIRED;
        goto cleanup;
    }
#endif

cleanup:
#if defined(PF_MBEDTLS_THREADING_C)
    if (pf_mbedtls_mutex_unlock(&ctx->mutex) != 0) {
        return PF_MBEDTLS_ERR_THREADING_MUTEX_ERROR;
    }
#endif

    return ret;
}

/*
 * Free context
 */
void pf_mbedtls_ssl_ticket_free(pf_mbedtls_ssl_ticket_context *ctx)
{
    if (ctx == NULL) {
        return;
    }

#if defined(PF_MBEDTLS_USE_PSA_CRYPTO)
    pf_psa_destroy_key(ctx->keys[0].key);
    pf_psa_destroy_key(ctx->keys[1].key);
#else
    pf_mbedtls_cipher_free(&ctx->keys[0].ctx);
    pf_mbedtls_cipher_free(&ctx->keys[1].ctx);
#endif /* MBEDTLS_USE_PSA_CRYPTO */

#if defined(PF_MBEDTLS_THREADING_C)
    pf_mbedtls_mutex_free(&ctx->mutex);
#endif

    pf_mbedtls_platform_zeroize(ctx, sizeof(pf_mbedtls_ssl_ticket_context));
}

#endif /* MBEDTLS_SSL_TICKET_C */
