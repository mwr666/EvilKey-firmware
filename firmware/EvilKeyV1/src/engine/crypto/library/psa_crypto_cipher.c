#include "../../../pf_build_config.h"
/*
 *  PSA cipher driver entry points
 */
/*
 *  Copyright The Mbed TLS Contributors
 *  SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
 */

#include "common.h"

#if defined(PF_MBEDTLS_PSA_CRYPTO_C)

#include "psa_crypto_cipher.h"
#include "psa_crypto_core.h"
#include "psa_crypto_random_impl.h"
#include "constant_time_internal.h"

#include "../include/mbedtls/cipher.h"
#include "../include/mbedtls/error.h"

#include <string.h>

/* mbedtls_cipher_values_from_psa() below only checks if the proper build symbols
 * are enabled, but it does not provide any compatibility check between them
 * (i.e. if the specified key works with the specified algorithm). This helper
 * function is meant to provide this support.
 * mbedtls_cipher_info_from_psa() might be used for the same purpose, but it
 * requires CIPHER_C to be enabled.
 */
static pf_psa_status_t pf_mbedtls_cipher_validate_values(
    pf_psa_algorithm_t alg,
    pf_psa_key_type_t key_type)
{
    /* Reduce code size - hinting to the compiler about what it can assume allows the compiler to
       eliminate bits of the logic below. */
#if !defined(PF_PSA_WANT_KEY_TYPE_AES)
    PF_MBEDTLS_ASSUME(key_type != PF_PSA_KEY_TYPE_AES);
#endif
#if !defined(PF_PSA_WANT_KEY_TYPE_ARIA)
    PF_MBEDTLS_ASSUME(key_type != PF_PSA_KEY_TYPE_ARIA);
#endif
#if !defined(PF_PSA_WANT_KEY_TYPE_CAMELLIA)
    PF_MBEDTLS_ASSUME(key_type != PF_PSA_KEY_TYPE_CAMELLIA);
#endif
#if !defined(PF_PSA_WANT_KEY_TYPE_CHACHA20)
    PF_MBEDTLS_ASSUME(key_type != PF_PSA_KEY_TYPE_CHACHA20);
#endif
#if !defined(PF_PSA_WANT_KEY_TYPE_DES)
    PF_MBEDTLS_ASSUME(key_type != PF_PSA_KEY_TYPE_DES);
#endif
#if !defined(PF_PSA_WANT_ALG_CCM)
    PF_MBEDTLS_ASSUME(alg != PF_PSA_ALG_AEAD_WITH_SHORTENED_TAG(PF_PSA_ALG_CCM, 0));
#endif
#if !defined(PF_PSA_WANT_ALG_GCM)
    PF_MBEDTLS_ASSUME(alg != PF_PSA_ALG_AEAD_WITH_SHORTENED_TAG(PF_PSA_ALG_GCM, 0));
#endif
#if !defined(PF_PSA_WANT_ALG_STREAM_CIPHER)
    PF_MBEDTLS_ASSUME(alg != PF_PSA_ALG_STREAM_CIPHER);
#endif
#if !defined(PF_PSA_WANT_ALG_CHACHA20_POLY1305)
    PF_MBEDTLS_ASSUME(alg != PF_PSA_ALG_AEAD_WITH_SHORTENED_TAG(PF_PSA_ALG_CHACHA20_POLY1305, 0));
#endif
#if !defined(PF_PSA_WANT_ALG_CCM_STAR_NO_TAG)
    PF_MBEDTLS_ASSUME(alg != PF_PSA_ALG_CCM_STAR_NO_TAG);
#endif
#if !defined(PF_PSA_WANT_ALG_CTR)
    PF_MBEDTLS_ASSUME(alg != PF_PSA_ALG_CTR);
#endif
#if !defined(PF_PSA_WANT_ALG_CFB)
    PF_MBEDTLS_ASSUME(alg != PF_PSA_ALG_CFB);
#endif
#if !defined(PF_PSA_WANT_ALG_OFB)
    PF_MBEDTLS_ASSUME(alg != PF_PSA_ALG_OFB);
#endif
#if !defined(PF_PSA_WANT_ALG_ECB_NO_PADDING)
    PF_MBEDTLS_ASSUME(alg != PF_PSA_ALG_ECB_NO_PADDING);
#endif
#if !defined(PF_PSA_WANT_ALG_CBC_NO_PADDING)
    PF_MBEDTLS_ASSUME(alg != PF_PSA_ALG_CBC_NO_PADDING);
#endif
#if !defined(PF_PSA_WANT_ALG_CBC_PKCS7)
    PF_MBEDTLS_ASSUME(alg != PF_PSA_ALG_CBC_PKCS7);
#endif
#if !defined(PF_PSA_WANT_ALG_CMAC)
    PF_MBEDTLS_ASSUME(alg != PF_PSA_ALG_CMAC);
#endif

    if (alg == PF_PSA_ALG_STREAM_CIPHER ||
        alg == PF_PSA_ALG_AEAD_WITH_SHORTENED_TAG(PF_PSA_ALG_CHACHA20_POLY1305, 0)) {
        if (key_type == PF_PSA_KEY_TYPE_CHACHA20) {
            return PF_PSA_SUCCESS;
        }
    }

    if (alg == PF_PSA_ALG_AEAD_WITH_SHORTENED_TAG(PF_PSA_ALG_CCM, 0) ||
        alg == PF_PSA_ALG_AEAD_WITH_SHORTENED_TAG(PF_PSA_ALG_GCM, 0) ||
        alg == PF_PSA_ALG_CCM_STAR_NO_TAG) {
        if (key_type == PF_PSA_KEY_TYPE_AES ||
            key_type == PF_PSA_KEY_TYPE_ARIA ||
            key_type == PF_PSA_KEY_TYPE_CAMELLIA) {
            return PF_PSA_SUCCESS;
        }
    }

    if (alg == PF_PSA_ALG_CTR ||
        alg == PF_PSA_ALG_CFB ||
        alg == PF_PSA_ALG_OFB ||
        alg == PF_PSA_ALG_XTS ||
        alg == PF_PSA_ALG_ECB_NO_PADDING ||
        alg == PF_PSA_ALG_CBC_NO_PADDING ||
        alg == PF_PSA_ALG_CBC_PKCS7 ||
        alg == PF_PSA_ALG_CMAC) {
        if (key_type == PF_PSA_KEY_TYPE_AES ||
            key_type == PF_PSA_KEY_TYPE_ARIA ||
            key_type == PF_PSA_KEY_TYPE_DES ||
            key_type == PF_PSA_KEY_TYPE_CAMELLIA) {
            return PF_PSA_SUCCESS;
        }
    }

    return PF_PSA_ERROR_NOT_SUPPORTED;
}

pf_psa_status_t pf_mbedtls_cipher_values_from_psa(
    pf_psa_algorithm_t alg,
    pf_psa_key_type_t key_type,
    size_t *key_bits,
    pf_mbedtls_cipher_mode_t *mode,
    pf_mbedtls_cipher_id_t *cipher_id)
{
    pf_mbedtls_cipher_id_t cipher_id_tmp;
    /* Only DES modifies key_bits */
#if !defined(PF_MBEDTLS_PSA_BUILTIN_KEY_TYPE_DES)
    (void) key_bits;
#endif

    if (PF_PSA_ALG_IS_AEAD(alg)) {
        alg = PF_PSA_ALG_AEAD_WITH_SHORTENED_TAG(alg, 0);
    }

    if (PF_PSA_ALG_IS_CIPHER(alg) || PF_PSA_ALG_IS_AEAD(alg)) {
        switch (alg) {
#if defined(PF_MBEDTLS_PSA_BUILTIN_ALG_STREAM_CIPHER)
            case PF_PSA_ALG_STREAM_CIPHER:
                *mode = PF_MBEDTLS_MODE_STREAM;
                break;
#endif
#if defined(PF_MBEDTLS_PSA_BUILTIN_ALG_CTR)
            case PF_PSA_ALG_CTR:
                *mode = PF_MBEDTLS_MODE_CTR;
                break;
#endif
#if defined(PF_MBEDTLS_PSA_BUILTIN_ALG_CFB)
            case PF_PSA_ALG_CFB:
                *mode = PF_MBEDTLS_MODE_CFB;
                break;
#endif
#if defined(PF_MBEDTLS_PSA_BUILTIN_ALG_OFB)
            case PF_PSA_ALG_OFB:
                *mode = PF_MBEDTLS_MODE_OFB;
                break;
#endif
#if defined(PF_MBEDTLS_PSA_BUILTIN_ALG_ECB_NO_PADDING)
            case PF_PSA_ALG_ECB_NO_PADDING:
                *mode = PF_MBEDTLS_MODE_ECB;
                break;
#endif
#if defined(PF_MBEDTLS_PSA_BUILTIN_ALG_CBC_NO_PADDING)
            case PF_PSA_ALG_CBC_NO_PADDING:
                *mode = PF_MBEDTLS_MODE_CBC;
                break;
#endif
#if defined(PF_MBEDTLS_PSA_BUILTIN_ALG_CBC_PKCS7)
            case PF_PSA_ALG_CBC_PKCS7:
                *mode = PF_MBEDTLS_MODE_CBC;
                break;
#endif
#if defined(PF_MBEDTLS_PSA_BUILTIN_ALG_CCM_STAR_NO_TAG)
            case PF_PSA_ALG_CCM_STAR_NO_TAG:
                *mode = PF_MBEDTLS_MODE_CCM_STAR_NO_TAG;
                break;
#endif
#if defined(PF_MBEDTLS_PSA_BUILTIN_ALG_CCM)
            case PF_PSA_ALG_AEAD_WITH_SHORTENED_TAG(PF_PSA_ALG_CCM, 0):
                *mode = PF_MBEDTLS_MODE_CCM;
                break;
#endif
#if defined(PF_MBEDTLS_PSA_BUILTIN_ALG_GCM)
            case PF_PSA_ALG_AEAD_WITH_SHORTENED_TAG(PF_PSA_ALG_GCM, 0):
                *mode = PF_MBEDTLS_MODE_GCM;
                break;
#endif
#if defined(PF_MBEDTLS_PSA_BUILTIN_ALG_CHACHA20_POLY1305)
            case PF_PSA_ALG_AEAD_WITH_SHORTENED_TAG(PF_PSA_ALG_CHACHA20_POLY1305, 0):
                *mode = PF_MBEDTLS_MODE_CHACHAPOLY;
                break;
#endif
            default:
                return PF_PSA_ERROR_NOT_SUPPORTED;
        }
    } else if (alg == PF_PSA_ALG_CMAC) {
        *mode = PF_MBEDTLS_MODE_ECB;
    } else {
        return PF_PSA_ERROR_NOT_SUPPORTED;
    }

    switch (key_type) {
#if defined(PF_MBEDTLS_PSA_BUILTIN_KEY_TYPE_AES)
        case PF_PSA_KEY_TYPE_AES:
            cipher_id_tmp = PF_MBEDTLS_CIPHER_ID_AES;
            break;
#endif
#if defined(PF_MBEDTLS_PSA_BUILTIN_KEY_TYPE_ARIA)
        case PF_PSA_KEY_TYPE_ARIA:
            cipher_id_tmp = PF_MBEDTLS_CIPHER_ID_ARIA;
            break;
#endif
#if defined(PF_MBEDTLS_PSA_BUILTIN_KEY_TYPE_DES)
        case PF_PSA_KEY_TYPE_DES:
            /* key_bits is 64 for Single-DES, 128 for two-key Triple-DES,
             * and 192 for three-key Triple-DES. */
            if (*key_bits == 64) {
                cipher_id_tmp = PF_MBEDTLS_CIPHER_ID_DES;
            } else {
                cipher_id_tmp = PF_MBEDTLS_CIPHER_ID_3DES;
            }
            /* mbedtls doesn't recognize two-key Triple-DES as an algorithm,
             * but two-key Triple-DES is functionally three-key Triple-DES
             * with K1=K3, so that's how we present it to mbedtls. */
            if (*key_bits == 128) {
                *key_bits = 192;
            }
            break;
#endif
#if defined(PF_MBEDTLS_PSA_BUILTIN_KEY_TYPE_CAMELLIA)
        case PF_PSA_KEY_TYPE_CAMELLIA:
            cipher_id_tmp = PF_MBEDTLS_CIPHER_ID_CAMELLIA;
            break;
#endif
#if defined(PF_MBEDTLS_PSA_BUILTIN_KEY_TYPE_CHACHA20)
        case PF_PSA_KEY_TYPE_CHACHA20:
            cipher_id_tmp = PF_MBEDTLS_CIPHER_ID_CHACHA20;
            break;
#endif
        default:
            return PF_PSA_ERROR_NOT_SUPPORTED;
    }
    if (cipher_id != NULL) {
        *cipher_id = cipher_id_tmp;
    }

    return pf_mbedtls_cipher_validate_values(alg, key_type);
}

#if defined(PF_MBEDTLS_CIPHER_C)
const pf_mbedtls_cipher_info_t *pf_mbedtls_cipher_info_from_psa(
    pf_psa_algorithm_t alg,
    pf_psa_key_type_t key_type,
    size_t key_bits,
    pf_mbedtls_cipher_id_t *cipher_id)
{
    pf_mbedtls_cipher_mode_t mode;
    pf_psa_status_t status;
    pf_mbedtls_cipher_id_t cipher_id_tmp = PF_MBEDTLS_CIPHER_ID_NONE;

    status = pf_mbedtls_cipher_values_from_psa(alg, key_type, &key_bits, &mode, &cipher_id_tmp);
    if (status != PF_PSA_SUCCESS) {
        return NULL;
    }
    if (cipher_id != NULL) {
        *cipher_id = cipher_id_tmp;
    }

    return pf_mbedtls_cipher_info_from_values(cipher_id_tmp, (int) key_bits, mode);
}
#endif /* MBEDTLS_CIPHER_C */

#if defined(PF_MBEDTLS_PSA_BUILTIN_CIPHER)

static pf_psa_status_t pf_psa_cipher_setup(
    pf_mbedtls_psa_cipher_operation_t *operation,
    const pf_psa_key_attributes_t *attributes,
    const uint8_t *key_buffer, size_t key_buffer_size,
    pf_psa_algorithm_t alg,
    pf_mbedtls_operation_t cipher_operation)
{
    int ret = 0;
    size_t key_bits;
    const pf_mbedtls_cipher_info_t *cipher_info = NULL;
    pf_psa_key_type_t key_type = attributes->type;

    (void) key_buffer_size;

    pf_mbedtls_cipher_init(&operation->ctx.cipher);

    operation->alg = alg;
    key_bits = attributes->bits;
    cipher_info = pf_mbedtls_cipher_info_from_psa(alg, key_type,
                                               key_bits, NULL);
    if (cipher_info == NULL) {
        return PF_PSA_ERROR_NOT_SUPPORTED;
    }

    ret = pf_mbedtls_cipher_setup(&operation->ctx.cipher, cipher_info);
    if (ret != 0) {
        goto exit;
    }

#if defined(PF_MBEDTLS_PSA_BUILTIN_KEY_TYPE_DES)
    if (key_type == PF_PSA_KEY_TYPE_DES && key_bits == 128) {
        /* Two-key Triple-DES is 3-key Triple-DES with K1=K3 */
        uint8_t keys[24];
        memcpy(keys, key_buffer, 16);
        memcpy(keys + 16, key_buffer, 8);
        ret = pf_mbedtls_cipher_setkey(&operation->ctx.cipher,
                                    keys,
                                    192, cipher_operation);
    } else
#endif
    {
        ret = pf_mbedtls_cipher_setkey(&operation->ctx.cipher, key_buffer,
                                    (int) key_bits, cipher_operation);
    }
    if (ret != 0) {
        goto exit;
    }

#if defined(PF_MBEDTLS_PSA_BUILTIN_ALG_CBC_NO_PADDING) || \
    defined(PF_MBEDTLS_PSA_BUILTIN_ALG_CBC_PKCS7)
    switch (alg) {
        case PF_PSA_ALG_CBC_NO_PADDING:
            ret = pf_mbedtls_cipher_set_padding_mode(&operation->ctx.cipher,
                                                  PF_MBEDTLS_PADDING_NONE);
            break;
        case PF_PSA_ALG_CBC_PKCS7:
            ret = pf_mbedtls_cipher_set_padding_mode(&operation->ctx.cipher,
                                                  PF_MBEDTLS_PADDING_PKCS7);
            break;
        default:
            /* The algorithm doesn't involve padding. */
            ret = 0;
            break;
    }
    if (ret != 0) {
        goto exit;
    }
#endif /* MBEDTLS_PSA_BUILTIN_ALG_CBC_NO_PADDING ||
          MBEDTLS_PSA_BUILTIN_ALG_CBC_PKCS7 */

    operation->block_length = (PF_PSA_ALG_IS_STREAM_CIPHER(alg) ? 1 :
                               PF_PSA_BLOCK_CIPHER_BLOCK_LENGTH(key_type));
    operation->iv_length = PF_PSA_CIPHER_IV_LENGTH(key_type, alg);

exit:
    return pf_mbedtls_to_psa_error(ret);
}

pf_psa_status_t pf_mbedtls_psa_cipher_encrypt_setup(
    pf_mbedtls_psa_cipher_operation_t *operation,
    const pf_psa_key_attributes_t *attributes,
    const uint8_t *key_buffer, size_t key_buffer_size,
    pf_psa_algorithm_t alg)
{
    return pf_psa_cipher_setup(operation, attributes,
                            key_buffer, key_buffer_size,
                            alg, PF_MBEDTLS_ENCRYPT);
}

pf_psa_status_t pf_mbedtls_psa_cipher_decrypt_setup(
    pf_mbedtls_psa_cipher_operation_t *operation,
    const pf_psa_key_attributes_t *attributes,
    const uint8_t *key_buffer, size_t key_buffer_size,
    pf_psa_algorithm_t alg)
{
    return pf_psa_cipher_setup(operation, attributes,
                            key_buffer, key_buffer_size,
                            alg, PF_MBEDTLS_DECRYPT);
}

pf_psa_status_t pf_mbedtls_psa_cipher_set_iv(
    pf_mbedtls_psa_cipher_operation_t *operation,
    const uint8_t *iv, size_t iv_length)
{
    if (iv_length != operation->iv_length) {
        return PF_PSA_ERROR_INVALID_ARGUMENT;
    }

    return pf_mbedtls_to_psa_error(
        pf_mbedtls_cipher_set_iv(&operation->ctx.cipher,
                              iv, iv_length));
}

#if defined(PF_MBEDTLS_PSA_BUILTIN_ALG_ECB_NO_PADDING)
/** Process input for which the algorithm is set to ECB mode.
 *
 * This requires manual processing, since the PSA API is defined as being
 * able to process arbitrary-length calls to psa_cipher_update() with ECB mode,
 * but the underlying mbedtls_cipher_update only takes full blocks.
 *
 * \param ctx           The mbedtls cipher context to use. It must have been
 *                      set up for ECB.
 * \param[in] input     The input plaintext or ciphertext to process.
 * \param input_length  The number of bytes to process from \p input.
 *                      This does not need to be aligned to a block boundary.
 *                      If there is a partial block at the end of the input,
 *                      it is stored in \p ctx for future processing.
 * \param output        The buffer where the output is written. It must be
 *                      at least `BS * floor((p + input_length) / BS)` bytes
 *                      long, where `p` is the number of bytes in the
 *                      unprocessed partial block in \p ctx (with
 *                      `0 <= p <= BS - 1`) and `BS` is the block size.
 * \param output_length On success, the number of bytes written to \p output.
 *                      \c 0 on error.
 *
 * \return #PSA_SUCCESS or an error from a hardware accelerator
 */
static pf_psa_status_t pf_psa_cipher_update_ecb(
    pf_mbedtls_cipher_context_t *ctx,
    const uint8_t *input,
    size_t input_length,
    uint8_t *output,
    size_t *output_length)
{
    pf_psa_status_t status = PF_PSA_ERROR_CORRUPTION_DETECTED;
    size_t block_size = pf_mbedtls_cipher_info_get_block_size(ctx->cipher_info);
    size_t internal_output_length = 0;
    *output_length = 0;

    if (input_length == 0) {
        status = PF_PSA_SUCCESS;
        goto exit;
    }

    if (ctx->unprocessed_len > 0) {
        /* Fill up to block size, and run the block if there's a full one. */
        size_t bytes_to_copy = block_size - ctx->unprocessed_len;

        if (input_length < bytes_to_copy) {
            bytes_to_copy = input_length;
        }

        memcpy(&(ctx->unprocessed_data[ctx->unprocessed_len]),
               input, bytes_to_copy);
        input_length -= bytes_to_copy;
        input += bytes_to_copy;
        ctx->unprocessed_len += bytes_to_copy;

        if (ctx->unprocessed_len == block_size) {
            status = pf_mbedtls_to_psa_error(
                pf_mbedtls_cipher_update(ctx,
                                      ctx->unprocessed_data,
                                      block_size,
                                      output, &internal_output_length));

            if (status != PF_PSA_SUCCESS) {
                goto exit;
            }

            output += internal_output_length;
            *output_length += internal_output_length;
            ctx->unprocessed_len = 0;
        }
    }

    while (input_length >= block_size) {
        /* Run all full blocks we have, one by one */
        status = pf_mbedtls_to_psa_error(
            pf_mbedtls_cipher_update(ctx, input,
                                  block_size,
                                  output, &internal_output_length));

        if (status != PF_PSA_SUCCESS) {
            goto exit;
        }

        input_length -= block_size;
        input += block_size;

        output += internal_output_length;
        *output_length += internal_output_length;
    }

    if (input_length > 0) {
        /* Save unprocessed bytes for later processing */
        memcpy(&(ctx->unprocessed_data[ctx->unprocessed_len]),
               input, input_length);
        ctx->unprocessed_len += input_length;
    }

    status = PF_PSA_SUCCESS;

exit:
    return status;
}
#endif /* MBEDTLS_PSA_BUILTIN_ALG_ECB_NO_PADDING */

pf_psa_status_t pf_mbedtls_psa_cipher_update(
    pf_mbedtls_psa_cipher_operation_t *operation,
    const uint8_t *input, size_t input_length,
    uint8_t *output, size_t output_size, size_t *output_length)
{
    pf_psa_status_t status = PF_PSA_ERROR_CORRUPTION_DETECTED;
    size_t expected_output_size;

    if (!PF_PSA_ALG_IS_STREAM_CIPHER(operation->alg)) {
        /* Take the unprocessed partial block left over from previous
         * update calls, if any, plus the input to this call. Remove
         * the last partial block, if any. You get the data that will be
         * output in this call. */
        expected_output_size =
            (operation->ctx.cipher.unprocessed_len + input_length)
            / operation->block_length * operation->block_length;
    } else {
        expected_output_size = input_length;
    }

    if (output_size < expected_output_size) {
        return PF_PSA_ERROR_BUFFER_TOO_SMALL;
    }

#if defined(PF_MBEDTLS_PSA_BUILTIN_ALG_ECB_NO_PADDING)
    if (operation->alg == PF_PSA_ALG_ECB_NO_PADDING) {
        /* mbedtls_cipher_update has an API inconsistency: it will only
         * process a single block at a time in ECB mode. Abstract away that
         * inconsistency here to match the PSA API behaviour. */
        status = pf_psa_cipher_update_ecb(&operation->ctx.cipher,
                                       input,
                                       input_length,
                                       output,
                                       output_length);
    } else
#endif /* MBEDTLS_PSA_BUILTIN_ALG_ECB_NO_PADDING */
    if (input_length == 0) {
        /* There is no input, nothing to be done */
        *output_length = 0;
        status = PF_PSA_SUCCESS;
    } else {
        status = pf_mbedtls_to_psa_error(
            pf_mbedtls_cipher_update(&operation->ctx.cipher, input,
                                  input_length, output, output_length));

        if (*output_length > output_size) {
            return PF_PSA_ERROR_CORRUPTION_DETECTED;
        }
    }

    return status;
}

pf_psa_status_t pf_mbedtls_psa_cipher_finish(
    pf_mbedtls_psa_cipher_operation_t *operation,
    uint8_t *output, size_t output_size, size_t *output_length)
{
    pf_psa_status_t status = PF_PSA_ERROR_GENERIC_ERROR;
    size_t invalid_padding = 0;

    /* We will copy output_size bytes from temp_output_buffer to the
     * output buffer. We can't use *output_length to determine how
     * much to copy because we must not leak that value through timing
     * when doing decryption with unpadding. But the underlying function
     * is not guaranteed to write beyond *output_length. To ensure we don't
     * leak the former content of the stack to the caller, wipe that
     * former content. */
    uint8_t temp_output_buffer[PF_MBEDTLS_MAX_BLOCK_LENGTH] = { 0 };
    if (output_size > sizeof(temp_output_buffer)) {
        output_size = sizeof(temp_output_buffer);
    }

    if (operation->ctx.cipher.unprocessed_len != 0) {
        if (operation->alg == PF_PSA_ALG_ECB_NO_PADDING ||
            operation->alg == PF_PSA_ALG_CBC_NO_PADDING) {
            status = PF_PSA_ERROR_INVALID_ARGUMENT;
            goto exit;
        }
    }

    status = pf_mbedtls_to_psa_error(
        pf_mbedtls_cipher_finish_padded(&operation->ctx.cipher,
                                     temp_output_buffer,
                                     output_length,
                                     &invalid_padding));
    if (status != PF_PSA_SUCCESS) {
        goto exit;
    }

    if (output_size == 0) {
        ; /* Nothing to copy. Note that output may be NULL in this case. */
    } else {
        /* Do not use the value of *output_length to determine how much
         * to copy. When decrypting a padded cipher, the output length is
         * sensitive, and leaking it could allow a padding oracle attack. */
        memcpy(output, temp_output_buffer, output_size);
    }

    status = pf_mbedtls_ct_error_if_else_0(invalid_padding,
                                        PF_PSA_ERROR_INVALID_PADDING);
    pf_mbedtls_ct_condition_t buffer_too_small =
        pf_mbedtls_ct_uint_lt(output_size, *output_length);
    status = pf_mbedtls_ct_error_if(buffer_too_small,
                                 PF_PSA_ERROR_BUFFER_TOO_SMALL,
                                 status);

exit:
    pf_mbedtls_platform_zeroize(temp_output_buffer,
                             sizeof(temp_output_buffer));
    return status;
}

pf_psa_status_t pf_mbedtls_psa_cipher_abort(
    pf_mbedtls_psa_cipher_operation_t *operation)
{
    /* Sanity check (shouldn't happen: operation->alg should
     * always have been initialized to a valid value). */
    if (!PF_PSA_ALG_IS_CIPHER(operation->alg)) {
        return PF_PSA_ERROR_BAD_STATE;
    }

    pf_mbedtls_cipher_free(&operation->ctx.cipher);

    return PF_PSA_SUCCESS;
}

pf_psa_status_t pf_mbedtls_psa_cipher_encrypt(
    const pf_psa_key_attributes_t *attributes,
    const uint8_t *key_buffer,
    size_t key_buffer_size,
    pf_psa_algorithm_t alg,
    const uint8_t *iv,
    size_t iv_length,
    const uint8_t *input,
    size_t input_length,
    uint8_t *output,
    size_t output_size,
    size_t *output_length)
{
    pf_psa_status_t status = PF_PSA_ERROR_CORRUPTION_DETECTED;
    pf_mbedtls_psa_cipher_operation_t operation = PF_MBEDTLS_PSA_CIPHER_OPERATION_INIT;
    size_t update_output_length, finish_output_length;

    status = pf_mbedtls_psa_cipher_encrypt_setup(&operation, attributes,
                                              key_buffer, key_buffer_size,
                                              alg);
    if (status != PF_PSA_SUCCESS) {
        goto exit;
    }

    if (iv_length > 0) {
        status = pf_mbedtls_psa_cipher_set_iv(&operation, iv, iv_length);
        if (status != PF_PSA_SUCCESS) {
            goto exit;
        }
    }

    status = pf_mbedtls_psa_cipher_update(&operation, input, input_length,
                                       output, output_size,
                                       &update_output_length);
    if (status != PF_PSA_SUCCESS) {
        goto exit;
    }

    status = pf_mbedtls_psa_cipher_finish(
        &operation,
        pf_mbedtls_buffer_offset(output, update_output_length),
        output_size - update_output_length, &finish_output_length);
    if (status != PF_PSA_SUCCESS) {
        goto exit;
    }

    *output_length = update_output_length + finish_output_length;

exit:
    if (status == PF_PSA_SUCCESS) {
        status = pf_mbedtls_psa_cipher_abort(&operation);
    } else {
        pf_mbedtls_psa_cipher_abort(&operation);
    }

    return status;
}

pf_psa_status_t pf_mbedtls_psa_cipher_decrypt(
    const pf_psa_key_attributes_t *attributes,
    const uint8_t *key_buffer,
    size_t key_buffer_size,
    pf_psa_algorithm_t alg,
    const uint8_t *input,
    size_t input_length,
    uint8_t *output,
    size_t output_size,
    size_t *output_length)
{
    pf_psa_status_t status = PF_PSA_ERROR_CORRUPTION_DETECTED;
    pf_mbedtls_psa_cipher_operation_t operation = PF_MBEDTLS_PSA_CIPHER_OPERATION_INIT;
    size_t olength, accumulated_length;

    status = pf_mbedtls_psa_cipher_decrypt_setup(&operation, attributes,
                                              key_buffer, key_buffer_size,
                                              alg);
    if (status != PF_PSA_SUCCESS) {
        goto exit;
    }

    if (operation.iv_length > 0) {
        status = pf_mbedtls_psa_cipher_set_iv(&operation,
                                           input, operation.iv_length);
        if (status != PF_PSA_SUCCESS) {
            goto exit;
        }
    }

    status = pf_mbedtls_psa_cipher_update(
        &operation,
        pf_mbedtls_buffer_offset_const(input, operation.iv_length),
        input_length - operation.iv_length,
        output, output_size, &olength);
    if (status != PF_PSA_SUCCESS) {
        goto exit;
    }

    accumulated_length = olength;

    status = pf_mbedtls_psa_cipher_finish(
        &operation,
        pf_mbedtls_buffer_offset(output, accumulated_length),
        output_size - accumulated_length, &olength);

    *output_length = accumulated_length + olength;

exit:
    /* C99 doesn't allow a declaration to follow a label */;
    pf_psa_status_t abort_status = pf_mbedtls_psa_cipher_abort(&operation);
    /* Normally abort shouldn't fail unless the operation is in a bad
     * state, in which case we'd expect finish to fail with the same error.
     * So it doesn't matter much which call's error code we pick when both
     * fail. However, in unauthenticated decryption specifically, the
     * distinction between PSA_SUCCESS and PSA_ERROR_INVALID_PADDING is
     * security-sensitive (risk of a padding oracle attack), so here we
     * must not have a code path that depends on the value of status. */
    if (abort_status != PF_PSA_SUCCESS) {
        status = abort_status;
    }

    return status;
}
#endif /* MBEDTLS_PSA_BUILTIN_CIPHER */

#endif /* MBEDTLS_PSA_CRYPTO_C */
