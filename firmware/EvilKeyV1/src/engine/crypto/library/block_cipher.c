#include "../../../pf_build_config.h"
/**
 * \file block_cipher.c
 *
 * \brief Lightweight abstraction layer for block ciphers with 128 bit blocks,
 * for use by the GCM and CCM modules.
 */
/*
 *  Copyright The Mbed TLS Contributors
 *  SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
 */

#include "common.h"

#if defined(PF_MBEDTLS_BLOCK_CIPHER_SOME_PSA)
#include "../include/psa/crypto.h"
#include "psa_crypto_core.h"
#include "psa_util_internal.h"
#endif

#include "block_cipher_internal.h"

#if defined(PF_MBEDTLS_BLOCK_CIPHER_C)

#if defined(PF_MBEDTLS_BLOCK_CIPHER_SOME_PSA)
static pf_psa_key_type_t pf_psa_key_type_from_block_cipher_id(pf_mbedtls_block_cipher_id_t cipher_id)
{
    switch (cipher_id) {
#if defined(PF_MBEDTLS_BLOCK_CIPHER_AES_VIA_PSA)
        case PF_MBEDTLS_BLOCK_CIPHER_ID_AES:
            return PF_PSA_KEY_TYPE_AES;
#endif
#if defined(PF_MBEDTLS_BLOCK_CIPHER_ARIA_VIA_PSA)
        case PF_MBEDTLS_BLOCK_CIPHER_ID_ARIA:
            return PF_PSA_KEY_TYPE_ARIA;
#endif
#if defined(PF_MBEDTLS_BLOCK_CIPHER_CAMELLIA_VIA_PSA)
        case PF_MBEDTLS_BLOCK_CIPHER_ID_CAMELLIA:
            return PF_PSA_KEY_TYPE_CAMELLIA;
#endif
        default:
            return PF_PSA_KEY_TYPE_NONE;
    }
}

static int pf_mbedtls_cipher_error_from_psa(pf_psa_status_t status)
{
    return PF_PSA_TO_MBEDTLS_ERR_LIST(status, pf_psa_to_cipher_errors,
                                   pf_psa_generic_status_to_mbedtls);
}
#endif /* MBEDTLS_BLOCK_CIPHER_SOME_PSA */

void pf_mbedtls_block_cipher_free(pf_mbedtls_block_cipher_context_t *ctx)
{
    if (ctx == NULL) {
        return;
    }

#if defined(PF_MBEDTLS_BLOCK_CIPHER_SOME_PSA)
    if (ctx->engine == PF_MBEDTLS_BLOCK_CIPHER_ENGINE_PSA) {
        pf_psa_destroy_key(ctx->pf_psa_key_id);
        return;
    }
#endif
    switch (ctx->id) {
#if defined(PF_MBEDTLS_AES_C)
        case PF_MBEDTLS_BLOCK_CIPHER_ID_AES:
            pf_mbedtls_aes_free(&ctx->ctx.aes);
            break;
#endif
#if defined(PF_MBEDTLS_ARIA_C)
        case PF_MBEDTLS_BLOCK_CIPHER_ID_ARIA:
            pf_mbedtls_aria_free(&ctx->ctx.aria);
            break;
#endif
#if defined(PF_MBEDTLS_CAMELLIA_C)
        case PF_MBEDTLS_BLOCK_CIPHER_ID_CAMELLIA:
            pf_mbedtls_camellia_free(&ctx->ctx.camellia);
            break;
#endif
        default:
            break;
    }
    ctx->id = PF_MBEDTLS_BLOCK_CIPHER_ID_NONE;
}

int pf_mbedtls_block_cipher_setup(pf_mbedtls_block_cipher_context_t *ctx,
                               pf_mbedtls_cipher_id_t cipher_id)
{
    ctx->id = (cipher_id == PF_MBEDTLS_CIPHER_ID_AES) ? PF_MBEDTLS_BLOCK_CIPHER_ID_AES :
              (cipher_id == PF_MBEDTLS_CIPHER_ID_ARIA) ? PF_MBEDTLS_BLOCK_CIPHER_ID_ARIA :
              (cipher_id == PF_MBEDTLS_CIPHER_ID_CAMELLIA) ? PF_MBEDTLS_BLOCK_CIPHER_ID_CAMELLIA :
              PF_MBEDTLS_BLOCK_CIPHER_ID_NONE;

#if defined(PF_MBEDTLS_BLOCK_CIPHER_SOME_PSA)
    pf_psa_key_type_t pf_psa_key_type = pf_psa_key_type_from_block_cipher_id(ctx->id);
    if (pf_psa_key_type != PF_PSA_KEY_TYPE_NONE &&
        pf_psa_can_do_cipher(pf_psa_key_type, PF_PSA_ALG_ECB_NO_PADDING)) {
        ctx->engine = PF_MBEDTLS_BLOCK_CIPHER_ENGINE_PSA;
        return 0;
    }
    ctx->engine = PF_MBEDTLS_BLOCK_CIPHER_ENGINE_LEGACY;
#endif

    switch (ctx->id) {
#if defined(PF_MBEDTLS_AES_C)
        case PF_MBEDTLS_BLOCK_CIPHER_ID_AES:
            pf_mbedtls_aes_init(&ctx->ctx.aes);
            return 0;
#endif
#if defined(PF_MBEDTLS_ARIA_C)
        case PF_MBEDTLS_BLOCK_CIPHER_ID_ARIA:
            pf_mbedtls_aria_init(&ctx->ctx.aria);
            return 0;
#endif
#if defined(PF_MBEDTLS_CAMELLIA_C)
        case PF_MBEDTLS_BLOCK_CIPHER_ID_CAMELLIA:
            pf_mbedtls_camellia_init(&ctx->ctx.camellia);
            return 0;
#endif
        default:
            ctx->id = PF_MBEDTLS_BLOCK_CIPHER_ID_NONE;
            return PF_MBEDTLS_ERR_CIPHER_BAD_INPUT_DATA;
    }
}

int pf_mbedtls_block_cipher_setkey(pf_mbedtls_block_cipher_context_t *ctx,
                                const unsigned char *key,
                                unsigned key_bitlen)
{
#if defined(PF_MBEDTLS_BLOCK_CIPHER_SOME_PSA)
    if (ctx->engine == PF_MBEDTLS_BLOCK_CIPHER_ENGINE_PSA) {
        pf_psa_key_attributes_t key_attr = PF_PSA_KEY_ATTRIBUTES_INIT;
        pf_psa_status_t status;

        pf_psa_set_key_type(&key_attr, pf_psa_key_type_from_block_cipher_id(ctx->id));
        pf_psa_set_key_bits(&key_attr, key_bitlen);
        pf_psa_set_key_algorithm(&key_attr, PF_PSA_ALG_ECB_NO_PADDING);
        pf_psa_set_key_usage_flags(&key_attr, PF_PSA_KEY_USAGE_ENCRYPT);

        status = pf_psa_import_key(&key_attr, key, PF_PSA_BITS_TO_BYTES(key_bitlen), &ctx->pf_psa_key_id);
        if (status != PF_PSA_SUCCESS) {
            return pf_mbedtls_cipher_error_from_psa(status);
        }
        pf_psa_reset_key_attributes(&key_attr);

        return 0;
    }
#endif /* MBEDTLS_BLOCK_CIPHER_SOME_PSA */

    switch (ctx->id) {
#if defined(PF_MBEDTLS_AES_C)
        case PF_MBEDTLS_BLOCK_CIPHER_ID_AES:
            return pf_mbedtls_aes_setkey_enc(&ctx->ctx.aes, key, key_bitlen);
#endif
#if defined(PF_MBEDTLS_ARIA_C)
        case PF_MBEDTLS_BLOCK_CIPHER_ID_ARIA:
            return pf_mbedtls_aria_setkey_enc(&ctx->ctx.aria, key, key_bitlen);
#endif
#if defined(PF_MBEDTLS_CAMELLIA_C)
        case PF_MBEDTLS_BLOCK_CIPHER_ID_CAMELLIA:
            return pf_mbedtls_camellia_setkey_enc(&ctx->ctx.camellia, key, key_bitlen);
#endif
        default:
            return PF_MBEDTLS_ERR_CIPHER_INVALID_CONTEXT;
    }
}

int pf_mbedtls_block_cipher_encrypt(pf_mbedtls_block_cipher_context_t *ctx,
                                 const unsigned char input[16],
                                 unsigned char output[16])
{
#if defined(PF_MBEDTLS_BLOCK_CIPHER_SOME_PSA)
    if (ctx->engine == PF_MBEDTLS_BLOCK_CIPHER_ENGINE_PSA) {
        pf_psa_status_t status;
        size_t olen;

        status = pf_psa_cipher_encrypt(ctx->pf_psa_key_id, PF_PSA_ALG_ECB_NO_PADDING,
                                    input, 16, output, 16, &olen);
        if (status != PF_PSA_SUCCESS) {
            return pf_mbedtls_cipher_error_from_psa(status);
        }
        return 0;
    }
#endif /* MBEDTLS_BLOCK_CIPHER_SOME_PSA */

    switch (ctx->id) {
#if defined(PF_MBEDTLS_AES_C)
        case PF_MBEDTLS_BLOCK_CIPHER_ID_AES:
            return pf_mbedtls_aes_crypt_ecb(&ctx->ctx.aes, PF_MBEDTLS_AES_ENCRYPT,
                                         input, output);
#endif
#if defined(PF_MBEDTLS_ARIA_C)
        case PF_MBEDTLS_BLOCK_CIPHER_ID_ARIA:
            return pf_mbedtls_aria_crypt_ecb(&ctx->ctx.aria, input, output);
#endif
#if defined(PF_MBEDTLS_CAMELLIA_C)
        case PF_MBEDTLS_BLOCK_CIPHER_ID_CAMELLIA:
            return pf_mbedtls_camellia_crypt_ecb(&ctx->ctx.camellia,
                                              PF_MBEDTLS_CAMELLIA_ENCRYPT,
                                              input, output);
#endif
        default:
            return PF_MBEDTLS_ERR_CIPHER_INVALID_CONTEXT;
    }
}

#endif /* MBEDTLS_BLOCK_CIPHER_C */
