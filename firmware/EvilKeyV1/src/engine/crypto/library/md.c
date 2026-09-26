#include "../../../pf_build_config.h"
/**
 * \file md.c
 *
 * \brief Generic message digest wrapper for Mbed TLS
 *
 * \author Adriaan de Jong <dejong@fox-it.com>
 *
 *  Copyright The Mbed TLS Contributors
 *  SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
 */

#include "common.h"

/*
 * Availability of functions in this module is controlled by two
 * feature macros:
 * - MBEDTLS_MD_C enables the whole module;
 * - MBEDTLS_MD_LIGHT enables only functions for hashing and accessing
 * most hash metadata (everything except string names); is it
 * automatically set whenever MBEDTLS_MD_C is defined.
 *
 * In this file, functions from MD_LIGHT are at the top, MD_C at the end.
 *
 * In the future we may want to change the contract of some functions
 * (behaviour with NULL arguments) depending on whether MD_C is defined or
 * only MD_LIGHT. Also, the exact scope of MD_LIGHT might vary.
 *
 * For these reasons, we're keeping MD_LIGHT internal for now.
 */
#if defined(PF_MBEDTLS_MD_LIGHT)

#include "../include/mbedtls/md.h"
#include "md_wrap.h"
#include "../include/mbedtls/platform_util.h"
#include "../include/mbedtls/error.h"

#include "../include/mbedtls/md5.h"
#include "../include/mbedtls/ripemd160.h"
#include "../include/mbedtls/sha1.h"
#include "../include/mbedtls/sha256.h"
#include "../include/mbedtls/sha512.h"
#include "../include/mbedtls/sha3.h"

#if defined(PF_MBEDTLS_PSA_CRYPTO_CLIENT)
#include "../include/psa/crypto.h"
#include "md_psa.h"
#include "psa_util_internal.h"
#endif

#if defined(PF_MBEDTLS_MD_SOME_PSA)
#include "psa_crypto_core.h"
#endif

#include "../include/mbedtls/platform.h"

#include <string.h>

#if defined(PF_MBEDTLS_FS_IO)
#include <stdio.h>
#endif

/* See comment above MBEDTLS_MD_MAX_SIZE in md.h */
#if defined(PF_MBEDTLS_PSA_CRYPTO_C) && PF_MBEDTLS_MD_MAX_SIZE < PF_PSA_HASH_MAX_SIZE
#error "Internal error: MBEDTLS_MD_MAX_SIZE < PSA_HASH_MAX_SIZE"
#endif

#if defined(PF_MBEDTLS_MD_C)
#define MD_INFO(type, out_size, block_size) type, out_size, block_size,
#else
#define MD_INFO(type, out_size, block_size) type, out_size,
#endif

#if defined(PF_MBEDTLS_MD_CAN_MD5)
static const pf_mbedtls_md_info_t pf_mbedtls_md5_info = {
    MD_INFO(PF_MBEDTLS_MD_MD5, 16, 64)
};
#endif

#if defined(PF_MBEDTLS_MD_CAN_RIPEMD160)
static const pf_mbedtls_md_info_t pf_mbedtls_ripemd160_info = {
    MD_INFO(PF_MBEDTLS_MD_RIPEMD160, 20, 64)
};
#endif

#if defined(PF_MBEDTLS_MD_CAN_SHA1)
static const pf_mbedtls_md_info_t pf_mbedtls_sha1_info = {
    MD_INFO(PF_MBEDTLS_MD_SHA1, 20, 64)
};
#endif

#if defined(PF_MBEDTLS_MD_CAN_SHA224)
static const pf_mbedtls_md_info_t pf_mbedtls_sha224_info = {
    MD_INFO(PF_MBEDTLS_MD_SHA224, 28, 64)
};
#endif

#if defined(PF_MBEDTLS_MD_CAN_SHA256)
static const pf_mbedtls_md_info_t pf_mbedtls_sha256_info = {
    MD_INFO(PF_MBEDTLS_MD_SHA256, 32, 64)
};
#endif

#if defined(PF_MBEDTLS_MD_CAN_SHA384)
static const pf_mbedtls_md_info_t pf_mbedtls_sha384_info = {
    MD_INFO(PF_MBEDTLS_MD_SHA384, 48, 128)
};
#endif

#if defined(PF_MBEDTLS_MD_CAN_SHA512)
static const pf_mbedtls_md_info_t pf_mbedtls_sha512_info = {
    MD_INFO(PF_MBEDTLS_MD_SHA512, 64, 128)
};
#endif

#if defined(PF_MBEDTLS_MD_CAN_SHA3_224)
static const pf_mbedtls_md_info_t pf_mbedtls_sha3_224_info = {
    MD_INFO(PF_MBEDTLS_MD_SHA3_224, 28, 144)
};
#endif

#if defined(PF_MBEDTLS_MD_CAN_SHA3_256)
static const pf_mbedtls_md_info_t pf_mbedtls_sha3_256_info = {
    MD_INFO(PF_MBEDTLS_MD_SHA3_256, 32, 136)
};
#endif

#if defined(PF_MBEDTLS_MD_CAN_SHA3_384)
static const pf_mbedtls_md_info_t pf_mbedtls_sha3_384_info = {
    MD_INFO(PF_MBEDTLS_MD_SHA3_384, 48, 104)
};
#endif

#if defined(PF_MBEDTLS_MD_CAN_SHA3_512)
static const pf_mbedtls_md_info_t pf_mbedtls_sha3_512_info = {
    MD_INFO(PF_MBEDTLS_MD_SHA3_512, 64, 72)
};
#endif

const pf_mbedtls_md_info_t *pf_mbedtls_md_info_from_type(pf_mbedtls_md_type_t md_type)
{
    switch (md_type) {
#if defined(PF_MBEDTLS_MD_CAN_MD5)
        case PF_MBEDTLS_MD_MD5:
            return &pf_mbedtls_md5_info;
#endif
#if defined(PF_MBEDTLS_MD_CAN_RIPEMD160)
        case PF_MBEDTLS_MD_RIPEMD160:
            return &pf_mbedtls_ripemd160_info;
#endif
#if defined(PF_MBEDTLS_MD_CAN_SHA1)
        case PF_MBEDTLS_MD_SHA1:
            return &pf_mbedtls_sha1_info;
#endif
#if defined(PF_MBEDTLS_MD_CAN_SHA224)
        case PF_MBEDTLS_MD_SHA224:
            return &pf_mbedtls_sha224_info;
#endif
#if defined(PF_MBEDTLS_MD_CAN_SHA256)
        case PF_MBEDTLS_MD_SHA256:
            return &pf_mbedtls_sha256_info;
#endif
#if defined(PF_MBEDTLS_MD_CAN_SHA384)
        case PF_MBEDTLS_MD_SHA384:
            return &pf_mbedtls_sha384_info;
#endif
#if defined(PF_MBEDTLS_MD_CAN_SHA512)
        case PF_MBEDTLS_MD_SHA512:
            return &pf_mbedtls_sha512_info;
#endif
#if defined(PF_MBEDTLS_MD_CAN_SHA3_224)
        case PF_MBEDTLS_MD_SHA3_224:
            return &pf_mbedtls_sha3_224_info;
#endif
#if defined(PF_MBEDTLS_MD_CAN_SHA3_256)
        case PF_MBEDTLS_MD_SHA3_256:
            return &pf_mbedtls_sha3_256_info;
#endif
#if defined(PF_MBEDTLS_MD_CAN_SHA3_384)
        case PF_MBEDTLS_MD_SHA3_384:
            return &pf_mbedtls_sha3_384_info;
#endif
#if defined(PF_MBEDTLS_MD_CAN_SHA3_512)
        case PF_MBEDTLS_MD_SHA3_512:
            return &pf_mbedtls_sha3_512_info;
#endif
        default:
            return NULL;
    }
}

#if defined(PF_MBEDTLS_MD_SOME_PSA)
static pf_psa_algorithm_t pf_psa_alg_of_md(const pf_mbedtls_md_info_t *info)
{
    switch (info->type) {
#if defined(PF_MBEDTLS_MD_MD5_VIA_PSA)
        case PF_MBEDTLS_MD_MD5:
            return PF_PSA_ALG_MD5;
#endif
#if defined(PF_MBEDTLS_MD_RIPEMD160_VIA_PSA)
        case PF_MBEDTLS_MD_RIPEMD160:
            return PF_PSA_ALG_RIPEMD160;
#endif
#if defined(PF_MBEDTLS_MD_SHA1_VIA_PSA)
        case PF_MBEDTLS_MD_SHA1:
            return PF_PSA_ALG_SHA_1;
#endif
#if defined(PF_MBEDTLS_MD_SHA224_VIA_PSA)
        case PF_MBEDTLS_MD_SHA224:
            return PF_PSA_ALG_SHA_224;
#endif
#if defined(PF_MBEDTLS_MD_SHA256_VIA_PSA)
        case PF_MBEDTLS_MD_SHA256:
            return PF_PSA_ALG_SHA_256;
#endif
#if defined(PF_MBEDTLS_MD_SHA384_VIA_PSA)
        case PF_MBEDTLS_MD_SHA384:
            return PF_PSA_ALG_SHA_384;
#endif
#if defined(PF_MBEDTLS_MD_SHA512_VIA_PSA)
        case PF_MBEDTLS_MD_SHA512:
            return PF_PSA_ALG_SHA_512;
#endif
#if defined(PF_MBEDTLS_MD_SHA3_224_VIA_PSA)
        case PF_MBEDTLS_MD_SHA3_224:
            return PF_PSA_ALG_SHA3_224;
#endif
#if defined(PF_MBEDTLS_MD_SHA3_256_VIA_PSA)
        case PF_MBEDTLS_MD_SHA3_256:
            return PF_PSA_ALG_SHA3_256;
#endif
#if defined(PF_MBEDTLS_MD_SHA3_384_VIA_PSA)
        case PF_MBEDTLS_MD_SHA3_384:
            return PF_PSA_ALG_SHA3_384;
#endif
#if defined(PF_MBEDTLS_MD_SHA3_512_VIA_PSA)
        case PF_MBEDTLS_MD_SHA3_512:
            return PF_PSA_ALG_SHA3_512;
#endif
        default:
            return PF_PSA_ALG_NONE;
    }
}

static int md_can_use_psa(const pf_mbedtls_md_info_t *info)
{
    pf_psa_algorithm_t alg = pf_psa_alg_of_md(info);
    if (alg == PF_PSA_ALG_NONE) {
        return 0;
    }

    return pf_psa_can_do_hash(alg);
}
#endif /* MBEDTLS_MD_SOME_PSA */

void pf_mbedtls_md_init(pf_mbedtls_md_context_t *ctx)
{
    /* Note: this sets engine (if present) to MBEDTLS_MD_ENGINE_LEGACY */
    memset(ctx, 0, sizeof(pf_mbedtls_md_context_t));
}

void pf_mbedtls_md_free(pf_mbedtls_md_context_t *ctx)
{
    if (ctx == NULL || ctx->md_info == NULL) {
        return;
    }

    if (ctx->md_ctx != NULL) {
#if defined(PF_MBEDTLS_MD_SOME_PSA)
        if (ctx->engine == PF_MBEDTLS_MD_ENGINE_PSA) {
            pf_psa_hash_abort(ctx->md_ctx);
        } else
#endif
        switch (ctx->md_info->type) {
#if defined(PF_MBEDTLS_MD5_C)
            case PF_MBEDTLS_MD_MD5:
                pf_mbedtls_md5_free(ctx->md_ctx);
                break;
#endif
#if defined(PF_MBEDTLS_RIPEMD160_C)
            case PF_MBEDTLS_MD_RIPEMD160:
                pf_mbedtls_ripemd160_free(ctx->md_ctx);
                break;
#endif
#if defined(PF_MBEDTLS_SHA1_C)
            case PF_MBEDTLS_MD_SHA1:
                pf_mbedtls_sha1_free(ctx->md_ctx);
                break;
#endif
#if defined(PF_MBEDTLS_SHA224_C)
            case PF_MBEDTLS_MD_SHA224:
                pf_mbedtls_sha256_free(ctx->md_ctx);
                break;
#endif
#if defined(PF_MBEDTLS_SHA256_C)
            case PF_MBEDTLS_MD_SHA256:
                pf_mbedtls_sha256_free(ctx->md_ctx);
                break;
#endif
#if defined(PF_MBEDTLS_SHA384_C)
            case PF_MBEDTLS_MD_SHA384:
                pf_mbedtls_sha512_free(ctx->md_ctx);
                break;
#endif
#if defined(PF_MBEDTLS_SHA512_C)
            case PF_MBEDTLS_MD_SHA512:
                pf_mbedtls_sha512_free(ctx->md_ctx);
                break;
#endif
#if defined(PF_MBEDTLS_SHA3_C)
            case PF_MBEDTLS_MD_SHA3_224:
            case PF_MBEDTLS_MD_SHA3_256:
            case PF_MBEDTLS_MD_SHA3_384:
            case PF_MBEDTLS_MD_SHA3_512:
                pf_mbedtls_sha3_free(ctx->md_ctx);
                break;
#endif
            default:
                /* Shouldn't happen */
                break;
        }
        pf_mbedtls_free(ctx->md_ctx);
    }

#if defined(PF_MBEDTLS_MD_C)
    if (ctx->hmac_ctx != NULL) {
        pf_mbedtls_zeroize_and_free(ctx->hmac_ctx,
                                 2 * ctx->md_info->block_size);
    }
#endif

    pf_mbedtls_platform_zeroize(ctx, sizeof(pf_mbedtls_md_context_t));
}

int pf_mbedtls_md_clone(pf_mbedtls_md_context_t *dst,
                     const pf_mbedtls_md_context_t *src)
{
    if (dst == NULL || dst->md_info == NULL ||
        src == NULL || src->md_info == NULL ||
        dst->md_info != src->md_info) {
        return PF_MBEDTLS_ERR_MD_BAD_INPUT_DATA;
    }

#if defined(PF_MBEDTLS_MD_SOME_PSA)
    if (src->engine != dst->engine) {
        /* This can happen with src set to legacy because PSA wasn't ready
         * yet, and dst to PSA because it became ready in the meantime.
         * We currently don't support that case (we'd need to re-allocate
         * md_ctx to the size of the appropriate MD context). */
        return PF_MBEDTLS_ERR_MD_FEATURE_UNAVAILABLE;
    }

    if (src->engine == PF_MBEDTLS_MD_ENGINE_PSA) {
        pf_psa_status_t status = pf_psa_hash_clone(src->md_ctx, dst->md_ctx);
        return pf_mbedtls_md_error_from_psa(status);
    }
#endif

    switch (src->md_info->type) {
#if defined(PF_MBEDTLS_MD5_C)
        case PF_MBEDTLS_MD_MD5:
            pf_mbedtls_md5_clone(dst->md_ctx, src->md_ctx);
            break;
#endif
#if defined(PF_MBEDTLS_RIPEMD160_C)
        case PF_MBEDTLS_MD_RIPEMD160:
            pf_mbedtls_ripemd160_clone(dst->md_ctx, src->md_ctx);
            break;
#endif
#if defined(PF_MBEDTLS_SHA1_C)
        case PF_MBEDTLS_MD_SHA1:
            pf_mbedtls_sha1_clone(dst->md_ctx, src->md_ctx);
            break;
#endif
#if defined(PF_MBEDTLS_SHA224_C)
        case PF_MBEDTLS_MD_SHA224:
            pf_mbedtls_sha256_clone(dst->md_ctx, src->md_ctx);
            break;
#endif
#if defined(PF_MBEDTLS_SHA256_C)
        case PF_MBEDTLS_MD_SHA256:
            pf_mbedtls_sha256_clone(dst->md_ctx, src->md_ctx);
            break;
#endif
#if defined(PF_MBEDTLS_SHA384_C)
        case PF_MBEDTLS_MD_SHA384:
            pf_mbedtls_sha512_clone(dst->md_ctx, src->md_ctx);
            break;
#endif
#if defined(PF_MBEDTLS_SHA512_C)
        case PF_MBEDTLS_MD_SHA512:
            pf_mbedtls_sha512_clone(dst->md_ctx, src->md_ctx);
            break;
#endif
#if defined(PF_MBEDTLS_SHA3_C)
        case PF_MBEDTLS_MD_SHA3_224:
        case PF_MBEDTLS_MD_SHA3_256:
        case PF_MBEDTLS_MD_SHA3_384:
        case PF_MBEDTLS_MD_SHA3_512:
            pf_mbedtls_sha3_clone(dst->md_ctx, src->md_ctx);
            break;
#endif
        default:
            return PF_MBEDTLS_ERR_MD_BAD_INPUT_DATA;
    }

    return 0;
}

#define ALLOC(type)                                                   \
    do {                                                                \
        ctx->md_ctx = pf_mbedtls_calloc(1, sizeof(pf_mbedtls_##type##_context)); \
        if (ctx->md_ctx == NULL)                                       \
        return PF_MBEDTLS_ERR_MD_ALLOC_FAILED;                      \
        pf_mbedtls_##type##_init(ctx->md_ctx);                           \
    }                                                                   \
    while (0)

int pf_mbedtls_md_setup(pf_mbedtls_md_context_t *ctx, const pf_mbedtls_md_info_t *md_info, int hmac)
{
#if defined(PF_MBEDTLS_MD_C)
    if (ctx == NULL) {
        return PF_MBEDTLS_ERR_MD_BAD_INPUT_DATA;
    }
#endif
    if (md_info == NULL) {
        return PF_MBEDTLS_ERR_MD_BAD_INPUT_DATA;
    }

    ctx->md_info = md_info;
    ctx->md_ctx = NULL;
#if defined(PF_MBEDTLS_MD_C)
    ctx->hmac_ctx = NULL;
#else
    if (hmac != 0) {
        return PF_MBEDTLS_ERR_MD_BAD_INPUT_DATA;
    }
#endif

#if defined(PF_MBEDTLS_MD_SOME_PSA)
    if (md_can_use_psa(ctx->md_info)) {
        ctx->md_ctx = pf_mbedtls_calloc(1, sizeof(pf_psa_hash_operation_t));
        if (ctx->md_ctx == NULL) {
            return PF_MBEDTLS_ERR_MD_ALLOC_FAILED;
        }
        ctx->engine = PF_MBEDTLS_MD_ENGINE_PSA;
    } else
#endif
    switch (md_info->type) {
#if defined(PF_MBEDTLS_MD5_C)
        case PF_MBEDTLS_MD_MD5:
            ALLOC(md5);
            break;
#endif
#if defined(PF_MBEDTLS_RIPEMD160_C)
        case PF_MBEDTLS_MD_RIPEMD160:
            ALLOC(ripemd160);
            break;
#endif
#if defined(PF_MBEDTLS_SHA1_C)
        case PF_MBEDTLS_MD_SHA1:
            ALLOC(sha1);
            break;
#endif
#if defined(PF_MBEDTLS_SHA224_C)
        case PF_MBEDTLS_MD_SHA224:
            ALLOC(sha256);
            break;
#endif
#if defined(PF_MBEDTLS_SHA256_C)
        case PF_MBEDTLS_MD_SHA256:
            ALLOC(sha256);
            break;
#endif
#if defined(PF_MBEDTLS_SHA384_C)
        case PF_MBEDTLS_MD_SHA384:
            ALLOC(sha512);
            break;
#endif
#if defined(PF_MBEDTLS_SHA512_C)
        case PF_MBEDTLS_MD_SHA512:
            ALLOC(sha512);
            break;
#endif
#if defined(PF_MBEDTLS_SHA3_C)
        case PF_MBEDTLS_MD_SHA3_224:
        case PF_MBEDTLS_MD_SHA3_256:
        case PF_MBEDTLS_MD_SHA3_384:
        case PF_MBEDTLS_MD_SHA3_512:
            ALLOC(sha3);
            break;
#endif
        default:
            return PF_MBEDTLS_ERR_MD_BAD_INPUT_DATA;
    }

#if defined(PF_MBEDTLS_MD_C)
    if (hmac != 0) {
        ctx->hmac_ctx = pf_mbedtls_calloc(2, md_info->block_size);
        if (ctx->hmac_ctx == NULL) {
            pf_mbedtls_md_free(ctx);
            return PF_MBEDTLS_ERR_MD_ALLOC_FAILED;
        }
    }
#endif

    return 0;
}
#undef ALLOC

int pf_mbedtls_md_starts(pf_mbedtls_md_context_t *ctx)
{
#if defined(PF_MBEDTLS_MD_C)
    if (ctx == NULL || ctx->md_info == NULL) {
        return PF_MBEDTLS_ERR_MD_BAD_INPUT_DATA;
    }
#endif

#if defined(PF_MBEDTLS_MD_SOME_PSA)
    if (ctx->engine == PF_MBEDTLS_MD_ENGINE_PSA) {
        pf_psa_algorithm_t alg = pf_psa_alg_of_md(ctx->md_info);
        pf_psa_hash_abort(ctx->md_ctx);
        pf_psa_status_t status = pf_psa_hash_setup(ctx->md_ctx, alg);
        return pf_mbedtls_md_error_from_psa(status);
    }
#endif

    switch (ctx->md_info->type) {
#if defined(PF_MBEDTLS_MD5_C)
        case PF_MBEDTLS_MD_MD5:
            return pf_mbedtls_md5_starts(ctx->md_ctx);
#endif
#if defined(PF_MBEDTLS_RIPEMD160_C)
        case PF_MBEDTLS_MD_RIPEMD160:
            return pf_mbedtls_ripemd160_starts(ctx->md_ctx);
#endif
#if defined(PF_MBEDTLS_SHA1_C)
        case PF_MBEDTLS_MD_SHA1:
            return pf_mbedtls_sha1_starts(ctx->md_ctx);
#endif
#if defined(PF_MBEDTLS_SHA224_C)
        case PF_MBEDTLS_MD_SHA224:
            return pf_mbedtls_sha256_starts(ctx->md_ctx, 1);
#endif
#if defined(PF_MBEDTLS_SHA256_C)
        case PF_MBEDTLS_MD_SHA256:
            return pf_mbedtls_sha256_starts(ctx->md_ctx, 0);
#endif
#if defined(PF_MBEDTLS_SHA384_C)
        case PF_MBEDTLS_MD_SHA384:
            return pf_mbedtls_sha512_starts(ctx->md_ctx, 1);
#endif
#if defined(PF_MBEDTLS_SHA512_C)
        case PF_MBEDTLS_MD_SHA512:
            return pf_mbedtls_sha512_starts(ctx->md_ctx, 0);
#endif
#if defined(PF_MBEDTLS_SHA3_C)
        case PF_MBEDTLS_MD_SHA3_224:
            return pf_mbedtls_sha3_starts(ctx->md_ctx, PF_MBEDTLS_SHA3_224);
        case PF_MBEDTLS_MD_SHA3_256:
            return pf_mbedtls_sha3_starts(ctx->md_ctx, PF_MBEDTLS_SHA3_256);
        case PF_MBEDTLS_MD_SHA3_384:
            return pf_mbedtls_sha3_starts(ctx->md_ctx, PF_MBEDTLS_SHA3_384);
        case PF_MBEDTLS_MD_SHA3_512:
            return pf_mbedtls_sha3_starts(ctx->md_ctx, PF_MBEDTLS_SHA3_512);
#endif
        default:
            return PF_MBEDTLS_ERR_MD_BAD_INPUT_DATA;
    }
}

int pf_mbedtls_md_update(pf_mbedtls_md_context_t *ctx, const unsigned char *input, size_t ilen)
{
#if defined(PF_MBEDTLS_MD_C)
    if (ctx == NULL || ctx->md_info == NULL) {
        return PF_MBEDTLS_ERR_MD_BAD_INPUT_DATA;
    }
#endif

#if defined(PF_MBEDTLS_MD_SOME_PSA)
    if (ctx->engine == PF_MBEDTLS_MD_ENGINE_PSA) {
        pf_psa_status_t status = pf_psa_hash_update(ctx->md_ctx, input, ilen);
        return pf_mbedtls_md_error_from_psa(status);
    }
#endif

    switch (ctx->md_info->type) {
#if defined(PF_MBEDTLS_MD5_C)
        case PF_MBEDTLS_MD_MD5:
            return pf_mbedtls_md5_update(ctx->md_ctx, input, ilen);
#endif
#if defined(PF_MBEDTLS_RIPEMD160_C)
        case PF_MBEDTLS_MD_RIPEMD160:
            return pf_mbedtls_ripemd160_update(ctx->md_ctx, input, ilen);
#endif
#if defined(PF_MBEDTLS_SHA1_C)
        case PF_MBEDTLS_MD_SHA1:
            return pf_mbedtls_sha1_update(ctx->md_ctx, input, ilen);
#endif
#if defined(PF_MBEDTLS_SHA224_C)
        case PF_MBEDTLS_MD_SHA224:
            return pf_mbedtls_sha256_update(ctx->md_ctx, input, ilen);
#endif
#if defined(PF_MBEDTLS_SHA256_C)
        case PF_MBEDTLS_MD_SHA256:
            return pf_mbedtls_sha256_update(ctx->md_ctx, input, ilen);
#endif
#if defined(PF_MBEDTLS_SHA384_C)
        case PF_MBEDTLS_MD_SHA384:
            return pf_mbedtls_sha512_update(ctx->md_ctx, input, ilen);
#endif
#if defined(PF_MBEDTLS_SHA512_C)
        case PF_MBEDTLS_MD_SHA512:
            return pf_mbedtls_sha512_update(ctx->md_ctx, input, ilen);
#endif
#if defined(PF_MBEDTLS_SHA3_C)
        case PF_MBEDTLS_MD_SHA3_224:
        case PF_MBEDTLS_MD_SHA3_256:
        case PF_MBEDTLS_MD_SHA3_384:
        case PF_MBEDTLS_MD_SHA3_512:
            return pf_mbedtls_sha3_update(ctx->md_ctx, input, ilen);
#endif
        default:
            return PF_MBEDTLS_ERR_MD_BAD_INPUT_DATA;
    }
}

int pf_mbedtls_md_finish(pf_mbedtls_md_context_t *ctx, unsigned char *output)
{
#if defined(PF_MBEDTLS_MD_C)
    if (ctx == NULL || ctx->md_info == NULL) {
        return PF_MBEDTLS_ERR_MD_BAD_INPUT_DATA;
    }
#endif

#if defined(PF_MBEDTLS_MD_SOME_PSA)
    if (ctx->engine == PF_MBEDTLS_MD_ENGINE_PSA) {
        size_t size = ctx->md_info->size;
        pf_psa_status_t status = pf_psa_hash_finish(ctx->md_ctx,
                                              output, size, &size);
        return pf_mbedtls_md_error_from_psa(status);
    }
#endif

    switch (ctx->md_info->type) {
#if defined(PF_MBEDTLS_MD5_C)
        case PF_MBEDTLS_MD_MD5:
            return pf_mbedtls_md5_finish(ctx->md_ctx, output);
#endif
#if defined(PF_MBEDTLS_RIPEMD160_C)
        case PF_MBEDTLS_MD_RIPEMD160:
            return pf_mbedtls_ripemd160_finish(ctx->md_ctx, output);
#endif
#if defined(PF_MBEDTLS_SHA1_C)
        case PF_MBEDTLS_MD_SHA1:
            return pf_mbedtls_sha1_finish(ctx->md_ctx, output);
#endif
#if defined(PF_MBEDTLS_SHA224_C)
        case PF_MBEDTLS_MD_SHA224:
            return pf_mbedtls_sha256_finish(ctx->md_ctx, output);
#endif
#if defined(PF_MBEDTLS_SHA256_C)
        case PF_MBEDTLS_MD_SHA256:
            return pf_mbedtls_sha256_finish(ctx->md_ctx, output);
#endif
#if defined(PF_MBEDTLS_SHA384_C)
        case PF_MBEDTLS_MD_SHA384:
            return pf_mbedtls_sha512_finish(ctx->md_ctx, output);
#endif
#if defined(PF_MBEDTLS_SHA512_C)
        case PF_MBEDTLS_MD_SHA512:
            return pf_mbedtls_sha512_finish(ctx->md_ctx, output);
#endif
#if defined(PF_MBEDTLS_SHA3_C)
        case PF_MBEDTLS_MD_SHA3_224:
        case PF_MBEDTLS_MD_SHA3_256:
        case PF_MBEDTLS_MD_SHA3_384:
        case PF_MBEDTLS_MD_SHA3_512:
            return pf_mbedtls_sha3_finish(ctx->md_ctx, output, ctx->md_info->size);
#endif
        default:
            return PF_MBEDTLS_ERR_MD_BAD_INPUT_DATA;
    }
}

int pf_mbedtls_md(const pf_mbedtls_md_info_t *md_info, const unsigned char *input, size_t ilen,
               unsigned char *output)
{
    if (md_info == NULL) {
        return PF_MBEDTLS_ERR_MD_BAD_INPUT_DATA;
    }

#if defined(PF_MBEDTLS_MD_SOME_PSA)
    if (md_can_use_psa(md_info)) {
        size_t size = md_info->size;
        pf_psa_status_t status = pf_psa_hash_compute(pf_psa_alg_of_md(md_info),
                                               input, ilen,
                                               output, size, &size);
        return pf_mbedtls_md_error_from_psa(status);
    }
#endif

    switch (md_info->type) {
#if defined(PF_MBEDTLS_MD5_C)
        case PF_MBEDTLS_MD_MD5:
            return pf_mbedtls_md5(input, ilen, output);
#endif
#if defined(PF_MBEDTLS_RIPEMD160_C)
        case PF_MBEDTLS_MD_RIPEMD160:
            return pf_mbedtls_ripemd160(input, ilen, output);
#endif
#if defined(PF_MBEDTLS_SHA1_C)
        case PF_MBEDTLS_MD_SHA1:
            return pf_mbedtls_sha1(input, ilen, output);
#endif
#if defined(PF_MBEDTLS_SHA224_C)
        case PF_MBEDTLS_MD_SHA224:
            return pf_mbedtls_sha256(input, ilen, output, 1);
#endif
#if defined(PF_MBEDTLS_SHA256_C)
        case PF_MBEDTLS_MD_SHA256:
            return pf_mbedtls_sha256(input, ilen, output, 0);
#endif
#if defined(PF_MBEDTLS_SHA384_C)
        case PF_MBEDTLS_MD_SHA384:
            return pf_mbedtls_sha512(input, ilen, output, 1);
#endif
#if defined(PF_MBEDTLS_SHA512_C)
        case PF_MBEDTLS_MD_SHA512:
            return pf_mbedtls_sha512(input, ilen, output, 0);
#endif
#if defined(PF_MBEDTLS_SHA3_C)
        case PF_MBEDTLS_MD_SHA3_224:
            return pf_mbedtls_sha3(PF_MBEDTLS_SHA3_224, input, ilen, output, md_info->size);
        case PF_MBEDTLS_MD_SHA3_256:
            return pf_mbedtls_sha3(PF_MBEDTLS_SHA3_256, input, ilen, output, md_info->size);
        case PF_MBEDTLS_MD_SHA3_384:
            return pf_mbedtls_sha3(PF_MBEDTLS_SHA3_384, input, ilen, output, md_info->size);
        case PF_MBEDTLS_MD_SHA3_512:
            return pf_mbedtls_sha3(PF_MBEDTLS_SHA3_512, input, ilen, output, md_info->size);
#endif
        default:
            return PF_MBEDTLS_ERR_MD_BAD_INPUT_DATA;
    }
}

unsigned char pf_mbedtls_md_get_size(const pf_mbedtls_md_info_t *md_info)
{
    if (md_info == NULL) {
        return 0;
    }

    return md_info->size;
}

pf_mbedtls_md_type_t pf_mbedtls_md_get_type(const pf_mbedtls_md_info_t *md_info)
{
    if (md_info == NULL) {
        return PF_MBEDTLS_MD_NONE;
    }

    return md_info->type;
}

#if defined(PF_MBEDTLS_PSA_CRYPTO_CLIENT)
int pf_mbedtls_md_error_from_psa(pf_psa_status_t status)
{
    return PF_PSA_TO_MBEDTLS_ERR_LIST(status, pf_psa_to_md_errors,
                                   pf_psa_generic_status_to_mbedtls);
}
#endif /* MBEDTLS_PSA_CRYPTO_CLIENT */


/************************************************************************
 * Functions above this separator are part of MBEDTLS_MD_LIGHT,         *
 * functions below are only available when MBEDTLS_MD_C is set.         *
 ************************************************************************/
#if defined(PF_MBEDTLS_MD_C)

/*
 * Reminder: update profiles in x509_crt.c when adding a new hash!
 */
static const int supported_digests[] = {

#if defined(PF_MBEDTLS_MD_CAN_SHA512)
    PF_MBEDTLS_MD_SHA512,
#endif

#if defined(PF_MBEDTLS_MD_CAN_SHA384)
    PF_MBEDTLS_MD_SHA384,
#endif

#if defined(PF_MBEDTLS_MD_CAN_SHA256)
    PF_MBEDTLS_MD_SHA256,
#endif
#if defined(PF_MBEDTLS_MD_CAN_SHA224)
    PF_MBEDTLS_MD_SHA224,
#endif

#if defined(PF_MBEDTLS_MD_CAN_SHA1)
    PF_MBEDTLS_MD_SHA1,
#endif

#if defined(PF_MBEDTLS_MD_CAN_RIPEMD160)
    PF_MBEDTLS_MD_RIPEMD160,
#endif

#if defined(PF_MBEDTLS_MD_CAN_MD5)
    PF_MBEDTLS_MD_MD5,
#endif

#if defined(PF_MBEDTLS_MD_CAN_SHA3_224)
    PF_MBEDTLS_MD_SHA3_224,
#endif

#if defined(PF_MBEDTLS_MD_CAN_SHA3_256)
    PF_MBEDTLS_MD_SHA3_256,
#endif

#if defined(PF_MBEDTLS_MD_CAN_SHA3_384)
    PF_MBEDTLS_MD_SHA3_384,
#endif

#if defined(PF_MBEDTLS_MD_CAN_SHA3_512)
    PF_MBEDTLS_MD_SHA3_512,
#endif

    PF_MBEDTLS_MD_NONE
};

const int *pf_mbedtls_md_list(void)
{
    return supported_digests;
}

typedef struct {
    const char *md_name;
    pf_mbedtls_md_type_t md_type;
} md_name_entry;

static const md_name_entry md_names[] = {
#if defined(PF_MBEDTLS_MD_CAN_MD5)
    { "MD5", PF_MBEDTLS_MD_MD5 },
#endif
#if defined(PF_MBEDTLS_MD_CAN_RIPEMD160)
    { "RIPEMD160", PF_MBEDTLS_MD_RIPEMD160 },
#endif
#if defined(PF_MBEDTLS_MD_CAN_SHA1)
    { "SHA1", PF_MBEDTLS_MD_SHA1 },
    { "SHA", PF_MBEDTLS_MD_SHA1 }, // compatibility fallback
#endif
#if defined(PF_MBEDTLS_MD_CAN_SHA224)
    { "SHA224", PF_MBEDTLS_MD_SHA224 },
#endif
#if defined(PF_MBEDTLS_MD_CAN_SHA256)
    { "SHA256", PF_MBEDTLS_MD_SHA256 },
#endif
#if defined(PF_MBEDTLS_MD_CAN_SHA384)
    { "SHA384", PF_MBEDTLS_MD_SHA384 },
#endif
#if defined(PF_MBEDTLS_MD_CAN_SHA512)
    { "SHA512", PF_MBEDTLS_MD_SHA512 },
#endif
#if defined(PF_MBEDTLS_MD_CAN_SHA3_224)
    { "SHA3-224", PF_MBEDTLS_MD_SHA3_224 },
#endif
#if defined(PF_MBEDTLS_MD_CAN_SHA3_256)
    { "SHA3-256", PF_MBEDTLS_MD_SHA3_256 },
#endif
#if defined(PF_MBEDTLS_MD_CAN_SHA3_384)
    { "SHA3-384", PF_MBEDTLS_MD_SHA3_384 },
#endif
#if defined(PF_MBEDTLS_MD_CAN_SHA3_512)
    { "SHA3-512", PF_MBEDTLS_MD_SHA3_512 },
#endif
    { NULL, PF_MBEDTLS_MD_NONE },
};

const pf_mbedtls_md_info_t *pf_mbedtls_md_info_from_string(const char *md_name)
{
    if (NULL == md_name) {
        return NULL;
    }

    const md_name_entry *entry = md_names;
    while (entry->md_name != NULL &&
           strcmp(entry->md_name, md_name) != 0) {
        ++entry;
    }

    return pf_mbedtls_md_info_from_type(entry->md_type);
}

const char *pf_mbedtls_md_get_name(const pf_mbedtls_md_info_t *md_info)
{
    if (md_info == NULL) {
        return NULL;
    }

    const md_name_entry *entry = md_names;
    while (entry->md_type != PF_MBEDTLS_MD_NONE &&
           entry->md_type != md_info->type) {
        ++entry;
    }

    return entry->md_name;
}

const pf_mbedtls_md_info_t *pf_mbedtls_md_info_from_ctx(
    const pf_mbedtls_md_context_t *ctx)
{
    if (ctx == NULL) {
        return NULL;
    }

    return ctx->PF_MBEDTLS_PRIVATE(md_info);
}

#if defined(PF_MBEDTLS_FS_IO)
int pf_mbedtls_md_file(const pf_mbedtls_md_info_t *md_info, const char *path, unsigned char *output)
{
    int ret = PF_MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    FILE *f;
    size_t n;
    pf_mbedtls_md_context_t ctx;
    unsigned char buf[1024];

    if (md_info == NULL) {
        return PF_MBEDTLS_ERR_MD_BAD_INPUT_DATA;
    }

    if ((f = fopen(path, "rb")) == NULL) {
        return PF_MBEDTLS_ERR_MD_FILE_IO_ERROR;
    }

    /* Ensure no stdio buffering of secrets, as such buffers cannot be wiped. */
    pf_mbedtls_setbuf(f, NULL);

    pf_mbedtls_md_init(&ctx);

    if ((ret = pf_mbedtls_md_setup(&ctx, md_info, 0)) != 0) {
        goto cleanup;
    }

    if ((ret = pf_mbedtls_md_starts(&ctx)) != 0) {
        goto cleanup;
    }

    while ((n = fread(buf, 1, sizeof(buf), f)) > 0) {
        if ((ret = pf_mbedtls_md_update(&ctx, buf, n)) != 0) {
            goto cleanup;
        }
    }

    if (ferror(f) != 0) {
        ret = PF_MBEDTLS_ERR_MD_FILE_IO_ERROR;
    } else {
        ret = pf_mbedtls_md_finish(&ctx, output);
    }

cleanup:
    pf_mbedtls_platform_zeroize(buf, sizeof(buf));
    fclose(f);
    pf_mbedtls_md_free(&ctx);

    return ret;
}
#endif /* MBEDTLS_FS_IO */

int pf_mbedtls_md_hmac_starts(pf_mbedtls_md_context_t *ctx, const unsigned char *key, size_t keylen)
{
    int ret = PF_MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    unsigned char sum[PF_MBEDTLS_MD_MAX_SIZE];
    unsigned char *ipad, *opad;

    if (ctx == NULL || ctx->md_info == NULL || ctx->hmac_ctx == NULL) {
        return PF_MBEDTLS_ERR_MD_BAD_INPUT_DATA;
    }

    if (keylen > (size_t) ctx->md_info->block_size) {
        if ((ret = pf_mbedtls_md_starts(ctx)) != 0) {
            goto cleanup;
        }
        if ((ret = pf_mbedtls_md_update(ctx, key, keylen)) != 0) {
            goto cleanup;
        }
        if ((ret = pf_mbedtls_md_finish(ctx, sum)) != 0) {
            goto cleanup;
        }

        keylen = ctx->md_info->size;
        key = sum;
    }

    ipad = (unsigned char *) ctx->hmac_ctx;
    opad = (unsigned char *) ctx->hmac_ctx + ctx->md_info->block_size;

    memset(ipad, 0x36, ctx->md_info->block_size);
    memset(opad, 0x5C, ctx->md_info->block_size);

    pf_mbedtls_xor(ipad, ipad, key, keylen);
    pf_mbedtls_xor(opad, opad, key, keylen);

    if ((ret = pf_mbedtls_md_starts(ctx)) != 0) {
        goto cleanup;
    }
    if ((ret = pf_mbedtls_md_update(ctx, ipad,
                                 ctx->md_info->block_size)) != 0) {
        goto cleanup;
    }

cleanup:
    pf_mbedtls_platform_zeroize(sum, sizeof(sum));

    return ret;
}

int pf_mbedtls_md_hmac_update(pf_mbedtls_md_context_t *ctx, const unsigned char *input, size_t ilen)
{
    if (ctx == NULL || ctx->md_info == NULL || ctx->hmac_ctx == NULL) {
        return PF_MBEDTLS_ERR_MD_BAD_INPUT_DATA;
    }

    return pf_mbedtls_md_update(ctx, input, ilen);
}

int pf_mbedtls_md_hmac_finish(pf_mbedtls_md_context_t *ctx, unsigned char *output)
{
    int ret = PF_MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    unsigned char tmp[PF_MBEDTLS_MD_MAX_SIZE];
    unsigned char *opad;

    if (ctx == NULL || ctx->md_info == NULL || ctx->hmac_ctx == NULL) {
        return PF_MBEDTLS_ERR_MD_BAD_INPUT_DATA;
    }

    opad = (unsigned char *) ctx->hmac_ctx + ctx->md_info->block_size;

    if ((ret = pf_mbedtls_md_finish(ctx, tmp)) != 0) {
        return ret;
    }
    if ((ret = pf_mbedtls_md_starts(ctx)) != 0) {
        return ret;
    }
    if ((ret = pf_mbedtls_md_update(ctx, opad,
                                 ctx->md_info->block_size)) != 0) {
        return ret;
    }
    if ((ret = pf_mbedtls_md_update(ctx, tmp,
                                 ctx->md_info->size)) != 0) {
        return ret;
    }
    return pf_mbedtls_md_finish(ctx, output);
}

int pf_mbedtls_md_hmac_reset(pf_mbedtls_md_context_t *ctx)
{
    int ret = PF_MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    unsigned char *ipad;

    if (ctx == NULL || ctx->md_info == NULL || ctx->hmac_ctx == NULL) {
        return PF_MBEDTLS_ERR_MD_BAD_INPUT_DATA;
    }

    ipad = (unsigned char *) ctx->hmac_ctx;

    if ((ret = pf_mbedtls_md_starts(ctx)) != 0) {
        return ret;
    }
    return pf_mbedtls_md_update(ctx, ipad, ctx->md_info->block_size);
}

int pf_mbedtls_md_hmac(const pf_mbedtls_md_info_t *md_info,
                    const unsigned char *key, size_t keylen,
                    const unsigned char *input, size_t ilen,
                    unsigned char *output)
{
    pf_mbedtls_md_context_t ctx;
    int ret = PF_MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;

    if (md_info == NULL) {
        return PF_MBEDTLS_ERR_MD_BAD_INPUT_DATA;
    }

    pf_mbedtls_md_init(&ctx);

    if ((ret = pf_mbedtls_md_setup(&ctx, md_info, 1)) != 0) {
        goto cleanup;
    }

    if ((ret = pf_mbedtls_md_hmac_starts(&ctx, key, keylen)) != 0) {
        goto cleanup;
    }
    if ((ret = pf_mbedtls_md_hmac_update(&ctx, input, ilen)) != 0) {
        goto cleanup;
    }
    if ((ret = pf_mbedtls_md_hmac_finish(&ctx, output)) != 0) {
        goto cleanup;
    }

cleanup:
    pf_mbedtls_md_free(&ctx);

    return ret;
}

#endif /* MBEDTLS_MD_C */

#endif /* MBEDTLS_MD_LIGHT */
