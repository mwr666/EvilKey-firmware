#include "../../../pf_build_config.h"
/*
 *  PSA hashing layer on top of Mbed TLS software crypto
 */
/*
 *  Copyright The Mbed TLS Contributors
 *  SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
 */

#include "common.h"

#if defined(PF_MBEDTLS_PSA_CRYPTO_C)

#include "../include/psa/crypto.h"
#include "psa_crypto_core.h"
#include "psa_crypto_hash.h"

#include "../include/mbedtls/error.h"
#include <string.h>

#if defined(PF_MBEDTLS_PSA_BUILTIN_HASH)
pf_psa_status_t pf_mbedtls_psa_hash_abort(
    pf_mbedtls_psa_hash_operation_t *operation)
{
    switch (operation->alg) {
        case 0:
            /* The object has (apparently) been initialized but it is not
             * in use. It's ok to call abort on such an object, and there's
             * nothing to do. */
            break;
#if defined(PF_MBEDTLS_PSA_BUILTIN_ALG_MD5)
        case PF_PSA_ALG_MD5:
            pf_mbedtls_md5_free(&operation->ctx.md5);
            break;
#endif
#if defined(PF_MBEDTLS_PSA_BUILTIN_ALG_RIPEMD160)
        case PF_PSA_ALG_RIPEMD160:
            pf_mbedtls_ripemd160_free(&operation->ctx.ripemd160);
            break;
#endif
#if defined(PF_MBEDTLS_PSA_BUILTIN_ALG_SHA_1)
        case PF_PSA_ALG_SHA_1:
            pf_mbedtls_sha1_free(&operation->ctx.sha1);
            break;
#endif
#if defined(PF_MBEDTLS_PSA_BUILTIN_ALG_SHA_224)
        case PF_PSA_ALG_SHA_224:
            pf_mbedtls_sha256_free(&operation->ctx.sha256);
            break;
#endif
#if defined(PF_MBEDTLS_PSA_BUILTIN_ALG_SHA_256)
        case PF_PSA_ALG_SHA_256:
            pf_mbedtls_sha256_free(&operation->ctx.sha256);
            break;
#endif
#if defined(PF_MBEDTLS_PSA_BUILTIN_ALG_SHA_384)
        case PF_PSA_ALG_SHA_384:
            pf_mbedtls_sha512_free(&operation->ctx.sha512);
            break;
#endif
#if defined(PF_MBEDTLS_PSA_BUILTIN_ALG_SHA_512)
        case PF_PSA_ALG_SHA_512:
            pf_mbedtls_sha512_free(&operation->ctx.sha512);
            break;
#endif
#if defined(PF_MBEDTLS_PSA_BUILTIN_ALG_SHA3_224)
        case PF_PSA_ALG_SHA3_224:
#endif
#if defined(PF_MBEDTLS_PSA_BUILTIN_ALG_SHA3_256)
        case PF_PSA_ALG_SHA3_256:
#endif
#if defined(PF_MBEDTLS_PSA_BUILTIN_ALG_SHA3_384)
        case PF_PSA_ALG_SHA3_384:
#endif
#if defined(PF_MBEDTLS_PSA_BUILTIN_ALG_SHA3_512)
        case PF_PSA_ALG_SHA3_512:
#endif
#if defined(PF_MBEDTLS_PSA_BUILTIN_ALG_SHA3_224) || \
            defined(PF_MBEDTLS_PSA_BUILTIN_ALG_SHA3_256) || \
            defined(PF_MBEDTLS_PSA_BUILTIN_ALG_SHA3_384) || \
            defined(PF_MBEDTLS_PSA_BUILTIN_ALG_SHA3_512)
            pf_mbedtls_sha3_free(&operation->ctx.sha3);
            break;
#endif
        default:
            return PF_PSA_ERROR_BAD_STATE;
    }
    operation->alg = 0;
    return PF_PSA_SUCCESS;
}

pf_psa_status_t pf_mbedtls_psa_hash_setup(
    pf_mbedtls_psa_hash_operation_t *operation,
    pf_psa_algorithm_t alg)
{
    int ret = PF_MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;

    /* A context must be freshly initialized before it can be set up. */
    if (operation->alg != 0) {
        return PF_PSA_ERROR_BAD_STATE;
    }

    switch (alg) {
#if defined(PF_MBEDTLS_PSA_BUILTIN_ALG_MD5)
        case PF_PSA_ALG_MD5:
            pf_mbedtls_md5_init(&operation->ctx.md5);
            ret = pf_mbedtls_md5_starts(&operation->ctx.md5);
            break;
#endif
#if defined(PF_MBEDTLS_PSA_BUILTIN_ALG_RIPEMD160)
        case PF_PSA_ALG_RIPEMD160:
            pf_mbedtls_ripemd160_init(&operation->ctx.ripemd160);
            ret = pf_mbedtls_ripemd160_starts(&operation->ctx.ripemd160);
            break;
#endif
#if defined(PF_MBEDTLS_PSA_BUILTIN_ALG_SHA_1)
        case PF_PSA_ALG_SHA_1:
            pf_mbedtls_sha1_init(&operation->ctx.sha1);
            ret = pf_mbedtls_sha1_starts(&operation->ctx.sha1);
            break;
#endif
#if defined(PF_MBEDTLS_PSA_BUILTIN_ALG_SHA_224)
        case PF_PSA_ALG_SHA_224:
            pf_mbedtls_sha256_init(&operation->ctx.sha256);
            ret = pf_mbedtls_sha256_starts(&operation->ctx.sha256, 1);
            break;
#endif
#if defined(PF_MBEDTLS_PSA_BUILTIN_ALG_SHA_256)
        case PF_PSA_ALG_SHA_256:
            pf_mbedtls_sha256_init(&operation->ctx.sha256);
            ret = pf_mbedtls_sha256_starts(&operation->ctx.sha256, 0);
            break;
#endif
#if defined(PF_MBEDTLS_PSA_BUILTIN_ALG_SHA_384)
        case PF_PSA_ALG_SHA_384:
            pf_mbedtls_sha512_init(&operation->ctx.sha512);
            ret = pf_mbedtls_sha512_starts(&operation->ctx.sha512, 1);
            break;
#endif
#if defined(PF_MBEDTLS_PSA_BUILTIN_ALG_SHA_512)
        case PF_PSA_ALG_SHA_512:
            pf_mbedtls_sha512_init(&operation->ctx.sha512);
            ret = pf_mbedtls_sha512_starts(&operation->ctx.sha512, 0);
            break;
#endif
#if defined(PF_MBEDTLS_PSA_BUILTIN_ALG_SHA3_224)
        case PF_PSA_ALG_SHA3_224:
            pf_mbedtls_sha3_init(&operation->ctx.sha3);
            ret = pf_mbedtls_sha3_starts(&operation->ctx.sha3, PF_MBEDTLS_SHA3_224);
            break;
#endif
#if defined(PF_MBEDTLS_PSA_BUILTIN_ALG_SHA3_256)
        case PF_PSA_ALG_SHA3_256:
            pf_mbedtls_sha3_init(&operation->ctx.sha3);
            ret = pf_mbedtls_sha3_starts(&operation->ctx.sha3, PF_MBEDTLS_SHA3_256);
            break;
#endif
#if defined(PF_MBEDTLS_PSA_BUILTIN_ALG_SHA3_384)
        case PF_PSA_ALG_SHA3_384:
            pf_mbedtls_sha3_init(&operation->ctx.sha3);
            ret = pf_mbedtls_sha3_starts(&operation->ctx.sha3, PF_MBEDTLS_SHA3_384);
            break;
#endif
#if defined(PF_MBEDTLS_PSA_BUILTIN_ALG_SHA3_512)
        case PF_PSA_ALG_SHA3_512:
            pf_mbedtls_sha3_init(&operation->ctx.sha3);
            ret = pf_mbedtls_sha3_starts(&operation->ctx.sha3, PF_MBEDTLS_SHA3_512);
            break;
#endif
        default:
            return PF_PSA_ALG_IS_HASH(alg) ?
                   PF_PSA_ERROR_NOT_SUPPORTED :
                   PF_PSA_ERROR_INVALID_ARGUMENT;
    }
    if (ret == 0) {
        operation->alg = alg;
    } else {
        pf_mbedtls_psa_hash_abort(operation);
    }
    return pf_mbedtls_to_psa_error(ret);
}

pf_psa_status_t pf_mbedtls_psa_hash_clone(
    const pf_mbedtls_psa_hash_operation_t *source_operation,
    pf_mbedtls_psa_hash_operation_t *target_operation)
{
    switch (source_operation->alg) {
        case 0:
            return PF_PSA_ERROR_BAD_STATE;
#if defined(PF_MBEDTLS_PSA_BUILTIN_ALG_MD5)
        case PF_PSA_ALG_MD5:
            pf_mbedtls_md5_clone(&target_operation->ctx.md5,
                              &source_operation->ctx.md5);
            break;
#endif
#if defined(PF_MBEDTLS_PSA_BUILTIN_ALG_RIPEMD160)
        case PF_PSA_ALG_RIPEMD160:
            pf_mbedtls_ripemd160_clone(&target_operation->ctx.ripemd160,
                                    &source_operation->ctx.ripemd160);
            break;
#endif
#if defined(PF_MBEDTLS_PSA_BUILTIN_ALG_SHA_1)
        case PF_PSA_ALG_SHA_1:
            pf_mbedtls_sha1_clone(&target_operation->ctx.sha1,
                               &source_operation->ctx.sha1);
            break;
#endif
#if defined(PF_MBEDTLS_PSA_BUILTIN_ALG_SHA_224)
        case PF_PSA_ALG_SHA_224:
            pf_mbedtls_sha256_clone(&target_operation->ctx.sha256,
                                 &source_operation->ctx.sha256);
            break;
#endif
#if defined(PF_MBEDTLS_PSA_BUILTIN_ALG_SHA_256)
        case PF_PSA_ALG_SHA_256:
            pf_mbedtls_sha256_clone(&target_operation->ctx.sha256,
                                 &source_operation->ctx.sha256);
            break;
#endif
#if defined(PF_MBEDTLS_PSA_BUILTIN_ALG_SHA_384)
        case PF_PSA_ALG_SHA_384:
            pf_mbedtls_sha512_clone(&target_operation->ctx.sha512,
                                 &source_operation->ctx.sha512);
            break;
#endif
#if defined(PF_MBEDTLS_PSA_BUILTIN_ALG_SHA_512)
        case PF_PSA_ALG_SHA_512:
            pf_mbedtls_sha512_clone(&target_operation->ctx.sha512,
                                 &source_operation->ctx.sha512);
            break;
#endif
#if defined(PF_MBEDTLS_PSA_BUILTIN_ALG_SHA3_224)
        case PF_PSA_ALG_SHA3_224:
#endif
#if defined(PF_MBEDTLS_PSA_BUILTIN_ALG_SHA3_256)
        case PF_PSA_ALG_SHA3_256:
#endif
#if defined(PF_MBEDTLS_PSA_BUILTIN_ALG_SHA3_384)
        case PF_PSA_ALG_SHA3_384:
#endif
#if defined(PF_MBEDTLS_PSA_BUILTIN_ALG_SHA3_512)
        case PF_PSA_ALG_SHA3_512:
#endif
#if defined(PF_MBEDTLS_PSA_BUILTIN_ALG_SHA3_224) || \
            defined(PF_MBEDTLS_PSA_BUILTIN_ALG_SHA3_256) || \
            defined(PF_MBEDTLS_PSA_BUILTIN_ALG_SHA3_384) || \
            defined(PF_MBEDTLS_PSA_BUILTIN_ALG_SHA3_512)
            pf_mbedtls_sha3_clone(&target_operation->ctx.sha3,
                               &source_operation->ctx.sha3);
            break;
#endif
        default:
            (void) source_operation;
            (void) target_operation;
            return PF_PSA_ERROR_NOT_SUPPORTED;
    }

    target_operation->alg = source_operation->alg;
    return PF_PSA_SUCCESS;
}

pf_psa_status_t pf_mbedtls_psa_hash_update(
    pf_mbedtls_psa_hash_operation_t *operation,
    const uint8_t *input,
    size_t input_length)
{
    int ret = PF_MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;

    switch (operation->alg) {
#if defined(PF_MBEDTLS_PSA_BUILTIN_ALG_MD5)
        case PF_PSA_ALG_MD5:
            ret = pf_mbedtls_md5_update(&operation->ctx.md5,
                                     input, input_length);
            break;
#endif
#if defined(PF_MBEDTLS_PSA_BUILTIN_ALG_RIPEMD160)
        case PF_PSA_ALG_RIPEMD160:
            ret = pf_mbedtls_ripemd160_update(&operation->ctx.ripemd160,
                                           input, input_length);
            break;
#endif
#if defined(PF_MBEDTLS_PSA_BUILTIN_ALG_SHA_1)
        case PF_PSA_ALG_SHA_1:
            ret = pf_mbedtls_sha1_update(&operation->ctx.sha1,
                                      input, input_length);
            break;
#endif
#if defined(PF_MBEDTLS_PSA_BUILTIN_ALG_SHA_224)
        case PF_PSA_ALG_SHA_224:
            ret = pf_mbedtls_sha256_update(&operation->ctx.sha256,
                                        input, input_length);
            break;
#endif
#if defined(PF_MBEDTLS_PSA_BUILTIN_ALG_SHA_256)
        case PF_PSA_ALG_SHA_256:
            ret = pf_mbedtls_sha256_update(&operation->ctx.sha256,
                                        input, input_length);
            break;
#endif
#if defined(PF_MBEDTLS_PSA_BUILTIN_ALG_SHA_384)
        case PF_PSA_ALG_SHA_384:
            ret = pf_mbedtls_sha512_update(&operation->ctx.sha512,
                                        input, input_length);
            break;
#endif
#if defined(PF_MBEDTLS_PSA_BUILTIN_ALG_SHA_512)
        case PF_PSA_ALG_SHA_512:
            ret = pf_mbedtls_sha512_update(&operation->ctx.sha512,
                                        input, input_length);
            break;
#endif
#if defined(PF_MBEDTLS_PSA_BUILTIN_ALG_SHA3_224)
        case PF_PSA_ALG_SHA3_224:
#endif
#if defined(PF_MBEDTLS_PSA_BUILTIN_ALG_SHA3_256)
        case PF_PSA_ALG_SHA3_256:
#endif
#if defined(PF_MBEDTLS_PSA_BUILTIN_ALG_SHA3_384)
        case PF_PSA_ALG_SHA3_384:
#endif
#if defined(PF_MBEDTLS_PSA_BUILTIN_ALG_SHA3_512)
        case PF_PSA_ALG_SHA3_512:
#endif
#if defined(PF_MBEDTLS_PSA_BUILTIN_ALG_SHA3_224) || \
    defined(PF_MBEDTLS_PSA_BUILTIN_ALG_SHA3_256) || \
    defined(PF_MBEDTLS_PSA_BUILTIN_ALG_SHA3_384) || \
    defined(PF_MBEDTLS_PSA_BUILTIN_ALG_SHA3_512)
    ret = pf_mbedtls_sha3_update(&operation->ctx.sha3,
                              input, input_length);
    break;
#endif
        default:
            (void) input;
            (void) input_length;
            return PF_PSA_ERROR_BAD_STATE;
    }

    return pf_mbedtls_to_psa_error(ret);
}

pf_psa_status_t pf_mbedtls_psa_hash_finish(
    pf_mbedtls_psa_hash_operation_t *operation,
    uint8_t *hash,
    size_t hash_size,
    size_t *hash_length)
{
    pf_psa_status_t status;
    int ret = PF_MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    size_t actual_hash_length = PF_PSA_HASH_LENGTH(operation->alg);

    /* Fill the output buffer with something that isn't a valid hash
     * (barring an attack on the hash and deliberately-crafted input),
     * in case the caller doesn't check the return status properly. */
    *hash_length = hash_size;
    /* If hash_size is 0 then hash may be NULL and then the
     * call to memset would have undefined behavior. */
    if (hash_size != 0) {
        memset(hash, '!', hash_size);
    }

    if (hash_size < actual_hash_length) {
        status = PF_PSA_ERROR_BUFFER_TOO_SMALL;
        goto exit;
    }

    switch (operation->alg) {
#if defined(PF_MBEDTLS_PSA_BUILTIN_ALG_MD5)
        case PF_PSA_ALG_MD5:
            ret = pf_mbedtls_md5_finish(&operation->ctx.md5, hash);
            break;
#endif
#if defined(PF_MBEDTLS_PSA_BUILTIN_ALG_RIPEMD160)
        case PF_PSA_ALG_RIPEMD160:
            ret = pf_mbedtls_ripemd160_finish(&operation->ctx.ripemd160, hash);
            break;
#endif
#if defined(PF_MBEDTLS_PSA_BUILTIN_ALG_SHA_1)
        case PF_PSA_ALG_SHA_1:
            ret = pf_mbedtls_sha1_finish(&operation->ctx.sha1, hash);
            break;
#endif
#if defined(PF_MBEDTLS_PSA_BUILTIN_ALG_SHA_224)
        case PF_PSA_ALG_SHA_224:
            ret = pf_mbedtls_sha256_finish(&operation->ctx.sha256, hash);
            break;
#endif
#if defined(PF_MBEDTLS_PSA_BUILTIN_ALG_SHA_256)
        case PF_PSA_ALG_SHA_256:
            ret = pf_mbedtls_sha256_finish(&operation->ctx.sha256, hash);
            break;
#endif
#if defined(PF_MBEDTLS_PSA_BUILTIN_ALG_SHA_384)
        case PF_PSA_ALG_SHA_384:
            ret = pf_mbedtls_sha512_finish(&operation->ctx.sha512, hash);
            break;
#endif
#if defined(PF_MBEDTLS_PSA_BUILTIN_ALG_SHA_512)
        case PF_PSA_ALG_SHA_512:
            ret = pf_mbedtls_sha512_finish(&operation->ctx.sha512, hash);
            break;
#endif
#if defined(PF_MBEDTLS_PSA_BUILTIN_ALG_SHA3_224)
        case PF_PSA_ALG_SHA3_224:
#endif
#if defined(PF_MBEDTLS_PSA_BUILTIN_ALG_SHA3_256)
        case PF_PSA_ALG_SHA3_256:
#endif
#if defined(PF_MBEDTLS_PSA_BUILTIN_ALG_SHA3_384)
        case PF_PSA_ALG_SHA3_384:
#endif
#if defined(PF_MBEDTLS_PSA_BUILTIN_ALG_SHA3_512)
        case PF_PSA_ALG_SHA3_512:
#endif
#if defined(PF_MBEDTLS_PSA_BUILTIN_ALG_SHA3_224) || \
    defined(PF_MBEDTLS_PSA_BUILTIN_ALG_SHA3_256) || \
    defined(PF_MBEDTLS_PSA_BUILTIN_ALG_SHA3_384) || \
    defined(PF_MBEDTLS_PSA_BUILTIN_ALG_SHA3_512)
    ret = pf_mbedtls_sha3_finish(&operation->ctx.sha3, hash, hash_size);
    break;
#endif
        default:
            (void) hash;
            return PF_PSA_ERROR_BAD_STATE;
    }
    status = pf_mbedtls_to_psa_error(ret);

exit:
    if (status == PF_PSA_SUCCESS) {
        *hash_length = actual_hash_length;
    }
    return status;
}

pf_psa_status_t pf_mbedtls_psa_hash_compute(
    pf_psa_algorithm_t alg,
    const uint8_t *input,
    size_t input_length,
    uint8_t *hash,
    size_t hash_size,
    size_t *hash_length)
{
    pf_mbedtls_psa_hash_operation_t operation = PF_MBEDTLS_PSA_HASH_OPERATION_INIT;
    pf_psa_status_t status = PF_PSA_ERROR_CORRUPTION_DETECTED;
    pf_psa_status_t abort_status = PF_PSA_ERROR_CORRUPTION_DETECTED;

    *hash_length = hash_size;
    status = pf_mbedtls_psa_hash_setup(&operation, alg);
    if (status != PF_PSA_SUCCESS) {
        goto exit;
    }
    status = pf_mbedtls_psa_hash_update(&operation, input, input_length);
    if (status != PF_PSA_SUCCESS) {
        goto exit;
    }
    status = pf_mbedtls_psa_hash_finish(&operation, hash, hash_size, hash_length);
    if (status != PF_PSA_SUCCESS) {
        goto exit;
    }

exit:
    abort_status = pf_mbedtls_psa_hash_abort(&operation);
    if (status == PF_PSA_SUCCESS) {
        return abort_status;
    } else {
        return status;
    }

}
#endif /* MBEDTLS_PSA_BUILTIN_HASH */

#endif /* MBEDTLS_PSA_CRYPTO_C */
