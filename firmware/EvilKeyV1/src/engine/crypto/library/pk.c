#include "../../../pf_build_config.h"
/*
 *  Public Key abstraction layer
 *
 *  Copyright The Mbed TLS Contributors
 *  SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
 */

#include "common.h"

#if defined(PF_MBEDTLS_PK_C)
#include "../include/mbedtls/pk.h"
#include "pk_wrap.h"
#include "pkwrite.h"
#include "pk_internal.h"

#include "../include/mbedtls/platform_util.h"
#include "../include/mbedtls/error.h"

#if defined(PF_MBEDTLS_RSA_C)
#include "../include/mbedtls/rsa.h"
#include "rsa_internal.h"
#endif
#if defined(PF_MBEDTLS_PK_HAVE_ECC_KEYS)
#include "../include/mbedtls/ecp.h"
#endif
#if defined(PF_MBEDTLS_ECDSA_C)
#include "../include/mbedtls/ecdsa.h"
#endif

#if defined(PF_MBEDTLS_PSA_CRYPTO_CLIENT)
#include "psa_util_internal.h"
#include "../include/mbedtls/psa_util.h"
#endif

#include <limits.h>
#include <stdint.h>

#if !defined(PK_EXPORT_KEYS_ON_THE_STACK)
#include "../include/mbedtls/platform.h" // for calloc/free
#endif

#if defined(PF_MBEDTLS_PSA_CRYPTO_CLIENT)
#define PF_MBEDTLS_PK_MAX_EC_PUBKEY_RAW_LEN \
    PF_PSA_KEY_EXPORT_ECC_PUBLIC_KEY_MAX_SIZE(PF_PSA_VENDOR_ECC_MAX_CURVE_BITS)

#define PF_MBEDTLS_PK_MAX_RSA_PUBKEY_RAW_LEN \
    PF_PSA_KEY_EXPORT_RSA_PUBLIC_KEY_MAX_SIZE(PF_PSA_VENDOR_RSA_MAX_KEY_BITS)

#define PF_MBEDTLS_PK_MAX_PUBKEY_RAW_LEN 0
#if defined(PF_MBEDTLS_PK_HAVE_ECC_KEYS) && \
    PF_MBEDTLS_PK_MAX_EC_PUBKEY_RAW_LEN > PF_MBEDTLS_PK_MAX_PUBKEY_RAW_LEN
#undef PF_MBEDTLS_PK_MAX_PUBKEY_RAW_LEN
#define PF_MBEDTLS_PK_MAX_PUBKEY_RAW_LEN PF_MBEDTLS_PK_MAX_EC_PUBKEY_RAW_LEN
#endif
#if (defined(PF_MBEDTLS_RSA_C) || \
    (defined(PF_MBEDTLS_USE_PSA_CRYPTO) && defined(PF_PSA_WANT_KEY_TYPE_RSA_PUBLIC_KEY))) && \
    PF_MBEDTLS_PK_MAX_RSA_PUBKEY_RAW_LEN > PF_MBEDTLS_PK_MAX_PUBKEY_RAW_LEN
#undef PF_MBEDTLS_PK_MAX_PUBKEY_RAW_LEN
#define PF_MBEDTLS_PK_MAX_PUBKEY_RAW_LEN PF_MBEDTLS_PK_MAX_RSA_PUBKEY_RAW_LEN
#endif
#endif /* MBEDTLS_PSA_CRYPTO_CLIENT */

/*
 * Initialise a mbedtls_pk_context
 */
void pf_mbedtls_pk_init(pf_mbedtls_pk_context *ctx)
{
    ctx->pk_info = NULL;
    ctx->pk_ctx = NULL;
#if defined(PF_MBEDTLS_USE_PSA_CRYPTO)
    ctx->priv_id = PF_MBEDTLS_SVC_KEY_ID_INIT;
#endif /* MBEDTLS_USE_PSA_CRYPTO */
#if defined(PF_MBEDTLS_PK_USE_PSA_EC_DATA)
    memset(ctx->pub_raw, 0, sizeof(ctx->pub_raw));
    ctx->pub_raw_len = 0;
    ctx->ec_family = 0;
    ctx->ec_bits = 0;
#endif /* MBEDTLS_PK_USE_PSA_EC_DATA */
}

/*
 * Free (the components of) a mbedtls_pk_context
 */
void pf_mbedtls_pk_free(pf_mbedtls_pk_context *ctx)
{
    if (ctx == NULL) {
        return;
    }

    if ((ctx->pk_info != NULL) && (ctx->pk_info->ctx_free_func != NULL)) {
        ctx->pk_info->ctx_free_func(ctx->pk_ctx);
    }

#if defined(PF_MBEDTLS_PK_USE_PSA_EC_DATA)
    /* The ownership of the priv_id key for opaque keys is external of the PK
     * module. It's the user responsibility to clear it after use. */
    if ((ctx->pk_info != NULL) && (ctx->pk_info->type != PF_MBEDTLS_PK_OPAQUE)) {
        pf_psa_destroy_key(ctx->priv_id);
    }
#endif /* MBEDTLS_PK_USE_PSA_EC_DATA */

    pf_mbedtls_platform_zeroize(ctx, sizeof(pf_mbedtls_pk_context));
}

#if defined(PF_MBEDTLS_ECDSA_C) && defined(PF_MBEDTLS_ECP_RESTARTABLE)
/*
 * Initialize a restart context
 */
void pf_mbedtls_pk_restart_init(pf_mbedtls_pk_restart_ctx *ctx)
{
    ctx->pk_info = NULL;
    ctx->rs_ctx = NULL;
}

/*
 * Free the components of a restart context
 */
void pf_mbedtls_pk_restart_free(pf_mbedtls_pk_restart_ctx *ctx)
{
    if (ctx == NULL || ctx->pk_info == NULL ||
        ctx->pk_info->rs_free_func == NULL) {
        return;
    }

    ctx->pk_info->rs_free_func(ctx->rs_ctx);

    ctx->pk_info = NULL;
    ctx->rs_ctx = NULL;
}
#endif /* MBEDTLS_ECDSA_C && MBEDTLS_ECP_RESTARTABLE */

/*
 * Get pk_info structure from type
 */
const pf_mbedtls_pk_info_t *pf_mbedtls_pk_info_from_type(pf_mbedtls_pk_type_t pk_type)
{
    switch (pk_type) {
#if defined(PF_MBEDTLS_RSA_C)
        case PF_MBEDTLS_PK_RSA:
            return &pf_mbedtls_rsa_info;
#endif /* MBEDTLS_RSA_C */
#if defined(PF_MBEDTLS_PK_HAVE_ECC_KEYS)
        case PF_MBEDTLS_PK_ECKEY:
            return &pf_mbedtls_eckey_info;
        case PF_MBEDTLS_PK_ECKEY_DH:
            return &pf_mbedtls_eckeydh_info;
#endif /* MBEDTLS_PK_HAVE_ECC_KEYS */
#if defined(PF_MBEDTLS_PK_CAN_ECDSA_SOME)
        case PF_MBEDTLS_PK_ECDSA:
            return &pf_mbedtls_ecdsa_info;
#endif /* MBEDTLS_PK_CAN_ECDSA_SOME */
        /* MBEDTLS_PK_RSA_ALT omitted on purpose */
        default:
            return NULL;
    }
}

/*
 * Initialise context
 */
int pf_mbedtls_pk_setup(pf_mbedtls_pk_context *ctx, const pf_mbedtls_pk_info_t *info)
{
    if (info == NULL || ctx->pk_info != NULL) {
        return PF_MBEDTLS_ERR_PK_BAD_INPUT_DATA;
    }

    if ((info->ctx_alloc_func != NULL) &&
        ((ctx->pk_ctx = info->ctx_alloc_func()) == NULL)) {
        return PF_MBEDTLS_ERR_PK_ALLOC_FAILED;
    }

    ctx->pk_info = info;

    return 0;
}

#if defined(PF_MBEDTLS_USE_PSA_CRYPTO)
/*
 * Initialise a PSA-wrapping context
 */
int pf_mbedtls_pk_setup_opaque(pf_mbedtls_pk_context *ctx,
                            const pf_mbedtls_svc_key_id_t key)
{
    const pf_mbedtls_pk_info_t *info = NULL;
    pf_psa_key_attributes_t attributes = PF_PSA_KEY_ATTRIBUTES_INIT;
    pf_psa_key_type_t type;

    if (ctx == NULL || ctx->pk_info != NULL) {
        return PF_MBEDTLS_ERR_PK_BAD_INPUT_DATA;
    }

    if (PF_PSA_SUCCESS != pf_psa_get_key_attributes(key, &attributes)) {
        return PF_MBEDTLS_ERR_PK_BAD_INPUT_DATA;
    }
    type = pf_psa_get_key_type(&attributes);
    pf_psa_reset_key_attributes(&attributes);

#if defined(PF_MBEDTLS_PK_HAVE_ECC_KEYS)
    if (PF_PSA_KEY_TYPE_IS_ECC_KEY_PAIR(type)) {
        info = &pf_mbedtls_ecdsa_opaque_info;
    } else
#endif /* MBEDTLS_PK_HAVE_ECC_KEYS */
    if (type == PF_PSA_KEY_TYPE_RSA_KEY_PAIR) {
        info = &pf_mbedtls_rsa_opaque_info;
    } else {
        return PF_MBEDTLS_ERR_PK_FEATURE_UNAVAILABLE;
    }

    ctx->pk_info = info;
    ctx->priv_id = key;

    return 0;
}
#endif /* MBEDTLS_USE_PSA_CRYPTO */

#if defined(PF_MBEDTLS_PK_RSA_ALT_SUPPORT)
/*
 * Initialize an RSA-alt context
 */
int pf_mbedtls_pk_setup_rsa_alt(pf_mbedtls_pk_context *ctx, void *key,
                             pf_mbedtls_pk_rsa_alt_decrypt_func decrypt_func,
                             pf_mbedtls_pk_rsa_alt_sign_func sign_func,
                             pf_mbedtls_pk_rsa_alt_key_len_func key_len_func)
{
    pf_mbedtls_rsa_alt_context *rsa_alt;
    const pf_mbedtls_pk_info_t *info = &pf_mbedtls_rsa_alt_info;

    if (ctx->pk_info != NULL) {
        return PF_MBEDTLS_ERR_PK_BAD_INPUT_DATA;
    }

    if ((ctx->pk_ctx = info->ctx_alloc_func()) == NULL) {
        return PF_MBEDTLS_ERR_PK_ALLOC_FAILED;
    }

    ctx->pk_info = info;

    rsa_alt = (pf_mbedtls_rsa_alt_context *) ctx->pk_ctx;

    rsa_alt->key = key;
    rsa_alt->decrypt_func = decrypt_func;
    rsa_alt->sign_func = sign_func;
    rsa_alt->key_len_func = key_len_func;

    return 0;
}
#endif /* MBEDTLS_PK_RSA_ALT_SUPPORT */

/*
 * Tell if a PK can do the operations of the given type
 */
int pf_mbedtls_pk_can_do(const pf_mbedtls_pk_context *ctx, pf_mbedtls_pk_type_t type)
{
    /* A context with null pk_info is not set up yet and can't do anything.
     * For backward compatibility, also accept NULL instead of a context
     * pointer. */
    if (ctx == NULL || ctx->pk_info == NULL) {
        return 0;
    }

    return ctx->pk_info->can_do(type);
}

#if defined(PF_MBEDTLS_USE_PSA_CRYPTO)
/*
 * Tell if a PK can do the operations of the given PSA algorithm
 */
int pf_mbedtls_pk_can_do_ext(const pf_mbedtls_pk_context *ctx, pf_psa_algorithm_t alg,
                          pf_psa_key_usage_t usage)
{
    pf_psa_key_usage_t key_usage;

    /* A context with null pk_info is not set up yet and can't do anything.
     * For backward compatibility, also accept NULL instead of a context
     * pointer. */
    if (ctx == NULL || ctx->pk_info == NULL) {
        return 0;
    }

    /* Filter out non allowed algorithms */
    if (PF_PSA_ALG_IS_ECDSA(alg) == 0 &&
        PF_PSA_ALG_IS_RSA_PKCS1V15_SIGN(alg) == 0 &&
        PF_PSA_ALG_IS_RSA_PSS(alg) == 0 &&
        alg != PF_PSA_ALG_RSA_PKCS1V15_CRYPT &&
        PF_PSA_ALG_IS_ECDH(alg) == 0) {
        return 0;
    }

    /* Filter out non allowed usage flags */
    if (usage == 0 ||
        (usage & ~(PF_PSA_KEY_USAGE_SIGN_HASH |
                   PF_PSA_KEY_USAGE_DECRYPT |
                   PF_PSA_KEY_USAGE_DERIVE)) != 0) {
        return 0;
    }

    /* Wildcard hash is not allowed */
    if (PF_PSA_ALG_IS_SIGN_HASH(alg) &&
        PF_PSA_ALG_SIGN_GET_HASH(alg) == PF_PSA_ALG_ANY_HASH) {
        return 0;
    }

    if (pf_mbedtls_pk_get_type(ctx) != PF_MBEDTLS_PK_OPAQUE) {
        pf_mbedtls_pk_type_t type;

        if (PF_PSA_ALG_IS_ECDSA(alg) || PF_PSA_ALG_IS_ECDH(alg)) {
            type = PF_MBEDTLS_PK_ECKEY;
        } else if (PF_PSA_ALG_IS_RSA_PKCS1V15_SIGN(alg) ||
                   alg == PF_PSA_ALG_RSA_PKCS1V15_CRYPT) {
            type = PF_MBEDTLS_PK_RSA;
        } else if (PF_PSA_ALG_IS_RSA_PSS(alg)) {
            type = PF_MBEDTLS_PK_RSASSA_PSS;
        } else {
            return 0;
        }

        if (ctx->pk_info->can_do(type) == 0) {
            return 0;
        }

        switch (type) {
            case PF_MBEDTLS_PK_ECKEY:
                key_usage = PF_PSA_KEY_USAGE_SIGN_HASH | PF_PSA_KEY_USAGE_DERIVE;
                break;
            case PF_MBEDTLS_PK_RSA:
            case PF_MBEDTLS_PK_RSASSA_PSS:
                key_usage = PF_PSA_KEY_USAGE_SIGN_HASH |
                            PF_PSA_KEY_USAGE_SIGN_MESSAGE |
                            PF_PSA_KEY_USAGE_DECRYPT;
                break;
            default:
                /* Should never happen */
                return 0;
        }

        return (key_usage & usage) == usage;
    }

    pf_psa_key_attributes_t attributes = PF_PSA_KEY_ATTRIBUTES_INIT;
    pf_psa_status_t status;

    status = pf_psa_get_key_attributes(ctx->priv_id, &attributes);
    if (status != PF_PSA_SUCCESS) {
        return 0;
    }

    pf_psa_algorithm_t key_alg = pf_psa_get_key_algorithm(&attributes);
    /* Key's enrollment is available only when an Mbed TLS implementation of PSA
     * Crypto is being used, i.e. when MBEDTLS_PSA_CRYPTO_C is defined.
     * Even though we don't officially support using other implementations of PSA
     * Crypto with TLS and X.509 (yet), we try to keep vendor's customizations
     * separated. */
#if defined(PF_MBEDTLS_PSA_CRYPTO_C)
    pf_psa_algorithm_t key_alg2 = pf_psa_get_key_enrollment_algorithm(&attributes);
#endif /* MBEDTLS_PSA_CRYPTO_C */
    key_usage = pf_psa_get_key_usage_flags(&attributes);
    pf_psa_reset_key_attributes(&attributes);

    if ((key_usage & usage) != usage) {
        return 0;
    }

    /*
     * Common case: the key alg [or alg2] only allows alg.
     * This will match PSA_ALG_RSA_PKCS1V15_CRYPT & PSA_ALG_IS_ECDH
     * directly.
     * This would also match ECDSA/RSA_PKCS1V15_SIGN/RSA_PSS with
     * a fixed hash on key_alg [or key_alg2].
     */
    if (alg == key_alg) {
        return 1;
    }
#if defined(PF_MBEDTLS_PSA_CRYPTO_C)
    if (alg == key_alg2) {
        return 1;
    }
#endif /* MBEDTLS_PSA_CRYPTO_C */

    /*
     * If key_alg [or key_alg2] is a hash-and-sign with a wildcard for the hash,
     * and alg is the same hash-and-sign family with any hash,
     * then alg is compliant with this key alg
     */
    if (PF_PSA_ALG_IS_SIGN_HASH(alg)) {
        if (PF_PSA_ALG_IS_SIGN_HASH(key_alg) &&
            PF_PSA_ALG_SIGN_GET_HASH(key_alg) == PF_PSA_ALG_ANY_HASH &&
            (alg & ~PF_PSA_ALG_HASH_MASK) == (key_alg & ~PF_PSA_ALG_HASH_MASK)) {
            return 1;
        }
#if defined(PF_MBEDTLS_PSA_CRYPTO_C)
        if (PF_PSA_ALG_IS_SIGN_HASH(key_alg2) &&
            PF_PSA_ALG_SIGN_GET_HASH(key_alg2) == PF_PSA_ALG_ANY_HASH &&
            (alg & ~PF_PSA_ALG_HASH_MASK) == (key_alg2 & ~PF_PSA_ALG_HASH_MASK)) {
            return 1;
        }
#endif /* MBEDTLS_PSA_CRYPTO_C */
    }

    return 0;
}
#endif /* MBEDTLS_USE_PSA_CRYPTO */

#if defined(PF_MBEDTLS_PSA_CRYPTO_CLIENT)
#if defined(PF_MBEDTLS_RSA_C)
static pf_psa_algorithm_t pf_psa_algorithm_for_rsa(const pf_mbedtls_rsa_context *rsa,
                                             int want_crypt)
{
    if (pf_mbedtls_rsa_get_padding_mode(rsa) == PF_MBEDTLS_RSA_PKCS_V21) {
        if (want_crypt) {
            pf_mbedtls_md_type_t md_type = (pf_mbedtls_md_type_t) pf_mbedtls_rsa_get_md_alg(rsa);
            return PF_PSA_ALG_RSA_OAEP(pf_mbedtls_md_psa_alg_from_type(md_type));
        } else {
            return PF_PSA_ALG_RSA_PSS_ANY_SALT(PF_PSA_ALG_ANY_HASH);
        }
    } else {
        if (want_crypt) {
            return PF_PSA_ALG_RSA_PKCS1V15_CRYPT;
        } else {
            return PF_PSA_ALG_RSA_PKCS1V15_SIGN(PF_PSA_ALG_ANY_HASH);
        }
    }
}
#endif /* MBEDTLS_RSA_C */

int pf_mbedtls_pk_get_psa_attributes(const pf_mbedtls_pk_context *pk,
                                  pf_psa_key_usage_t usage,
                                  pf_psa_key_attributes_t *attributes)
{
    pf_mbedtls_pk_type_t pk_type = pf_mbedtls_pk_get_type(pk);

    pf_psa_key_usage_t more_usage = usage;
    if (usage == PF_PSA_KEY_USAGE_SIGN_MESSAGE) {
        more_usage |= PF_PSA_KEY_USAGE_VERIFY_MESSAGE;
    } else if (usage == PF_PSA_KEY_USAGE_SIGN_HASH) {
        more_usage |= PF_PSA_KEY_USAGE_VERIFY_HASH;
    } else if (usage == PF_PSA_KEY_USAGE_DECRYPT) {
        more_usage |= PF_PSA_KEY_USAGE_ENCRYPT;
    }
    more_usage |= PF_PSA_KEY_USAGE_EXPORT | PF_PSA_KEY_USAGE_COPY;

    int want_private = !(usage == PF_PSA_KEY_USAGE_VERIFY_MESSAGE ||
                         usage == PF_PSA_KEY_USAGE_VERIFY_HASH ||
                         usage == PF_PSA_KEY_USAGE_ENCRYPT);

    switch (pk_type) {
#if defined(PF_MBEDTLS_RSA_C)
        case PF_MBEDTLS_PK_RSA:
        {
            int want_crypt = 0; /* 0: sign/verify; 1: encrypt/decrypt */
            switch (usage) {
                case PF_PSA_KEY_USAGE_SIGN_MESSAGE:
                case PF_PSA_KEY_USAGE_SIGN_HASH:
                case PF_PSA_KEY_USAGE_VERIFY_MESSAGE:
                case PF_PSA_KEY_USAGE_VERIFY_HASH:
                    /* Nothing to do. */
                    break;
                case PF_PSA_KEY_USAGE_DECRYPT:
                case PF_PSA_KEY_USAGE_ENCRYPT:
                    want_crypt = 1;
                    break;
                default:
                    return PF_MBEDTLS_ERR_PK_TYPE_MISMATCH;
            }
            /* Detect the presence of a private key in a way that works both
             * in CRT and non-CRT configurations. */
            pf_mbedtls_rsa_context *rsa = pf_mbedtls_pk_rsa(*pk);
            int has_private = (pf_mbedtls_rsa_check_privkey(rsa) == 0);
            if (want_private && !has_private) {
                return PF_MBEDTLS_ERR_PK_TYPE_MISMATCH;
            }
            pf_psa_set_key_type(attributes, (want_private ?
                                          PF_PSA_KEY_TYPE_RSA_KEY_PAIR :
                                          PF_PSA_KEY_TYPE_RSA_PUBLIC_KEY));
            pf_psa_set_key_bits(attributes, pf_mbedtls_pk_get_bitlen(pk));
            pf_psa_set_key_algorithm(attributes,
                                  pf_psa_algorithm_for_rsa(rsa, want_crypt));
            break;
        }
#endif /* MBEDTLS_RSA_C */

#if defined(PF_MBEDTLS_PK_HAVE_ECC_KEYS)
        case PF_MBEDTLS_PK_ECKEY:
        case PF_MBEDTLS_PK_ECKEY_DH:
        case PF_MBEDTLS_PK_ECDSA:
        {
            int sign_ok = (pk_type != PF_MBEDTLS_PK_ECKEY_DH);
            int derive_ok = (pk_type != PF_MBEDTLS_PK_ECDSA);
#if defined(PF_MBEDTLS_PK_USE_PSA_EC_DATA)
            pf_psa_ecc_family_t family = pk->ec_family;
            size_t bits = pk->ec_bits;
            int has_private = 0;
            if (pk->priv_id != PF_MBEDTLS_SVC_KEY_ID_INIT) {
                has_private = 1;
            }
#else
            const pf_mbedtls_ecp_keypair *ec = pf_mbedtls_pk_ec_ro(*pk);
            int has_private = (ec->d.n != 0);
            size_t bits = 0;
            pf_psa_ecc_family_t family =
                pf_mbedtls_ecc_group_to_psa(ec->grp.id, &bits);
#endif
            pf_psa_algorithm_t alg = 0;
            switch (usage) {
                case PF_PSA_KEY_USAGE_SIGN_MESSAGE:
                case PF_PSA_KEY_USAGE_SIGN_HASH:
                case PF_PSA_KEY_USAGE_VERIFY_MESSAGE:
                case PF_PSA_KEY_USAGE_VERIFY_HASH:
                    if (!sign_ok) {
                        return PF_MBEDTLS_ERR_PK_TYPE_MISMATCH;
                    }
#if defined(PF_MBEDTLS_ECDSA_DETERMINISTIC)
                    alg = PF_PSA_ALG_DETERMINISTIC_ECDSA(PF_PSA_ALG_ANY_HASH);
#else
                    alg = PF_PSA_ALG_ECDSA(PF_PSA_ALG_ANY_HASH);
#endif
                    break;
                case PF_PSA_KEY_USAGE_DERIVE:
                    alg = PF_PSA_ALG_ECDH;
                    if (!derive_ok) {
                        return PF_MBEDTLS_ERR_PK_TYPE_MISMATCH;
                    }
                    break;
                default:
                    return PF_MBEDTLS_ERR_PK_TYPE_MISMATCH;
            }
            if (want_private && !has_private) {
                return PF_MBEDTLS_ERR_PK_TYPE_MISMATCH;
            }
            pf_psa_set_key_type(attributes, (want_private ?
                                          PF_PSA_KEY_TYPE_ECC_KEY_PAIR(family) :
                                          PF_PSA_KEY_TYPE_ECC_PUBLIC_KEY(family)));
            pf_psa_set_key_bits(attributes, bits);
            pf_psa_set_key_algorithm(attributes, alg);
            break;
        }
#endif /* MBEDTLS_PK_HAVE_ECC_KEYS */

#if defined(PF_MBEDTLS_PK_RSA_ALT_SUPPORT)
        case PF_MBEDTLS_PK_RSA_ALT:
            return PF_MBEDTLS_ERR_PK_FEATURE_UNAVAILABLE;
#endif /* MBEDTLS_PK_RSA_ALT_SUPPORT */

#if defined(PF_MBEDTLS_USE_PSA_CRYPTO)
        case PF_MBEDTLS_PK_OPAQUE:
        {
            pf_psa_key_attributes_t old_attributes = PF_PSA_KEY_ATTRIBUTES_INIT;
            pf_psa_status_t status = PF_PSA_ERROR_CORRUPTION_DETECTED;
            status = pf_psa_get_key_attributes(pk->priv_id, &old_attributes);
            if (status != PF_PSA_SUCCESS) {
                return PF_MBEDTLS_ERR_PK_BAD_INPUT_DATA;
            }
            pf_psa_key_type_t old_type = pf_psa_get_key_type(&old_attributes);
            switch (usage) {
                case PF_PSA_KEY_USAGE_SIGN_MESSAGE:
                case PF_PSA_KEY_USAGE_SIGN_HASH:
                case PF_PSA_KEY_USAGE_VERIFY_MESSAGE:
                case PF_PSA_KEY_USAGE_VERIFY_HASH:
                    if (!(PF_PSA_KEY_TYPE_IS_ECC_KEY_PAIR(old_type) ||
                          old_type == PF_PSA_KEY_TYPE_RSA_KEY_PAIR)) {
                        return PF_MBEDTLS_ERR_PK_TYPE_MISMATCH;
                    }
                    break;
                case PF_PSA_KEY_USAGE_DECRYPT:
                case PF_PSA_KEY_USAGE_ENCRYPT:
                    if (old_type != PF_PSA_KEY_TYPE_RSA_KEY_PAIR) {
                        return PF_MBEDTLS_ERR_PK_TYPE_MISMATCH;
                    }
                    break;
                case PF_PSA_KEY_USAGE_DERIVE:
                    if (!(PF_PSA_KEY_TYPE_IS_ECC_KEY_PAIR(old_type))) {
                        return PF_MBEDTLS_ERR_PK_TYPE_MISMATCH;
                    }
                    break;
                default:
                    return PF_MBEDTLS_ERR_PK_TYPE_MISMATCH;
            }
            pf_psa_key_type_t new_type = old_type;
            /* Opaque keys are always key pairs, so we don't need a check
             * on the input if the required usage is private. We just need
             * to adjust the type correctly if the required usage is public. */
            if (!want_private) {
                new_type = PF_PSA_KEY_TYPE_PUBLIC_KEY_OF_KEY_PAIR(new_type);
            }
            more_usage = pf_psa_get_key_usage_flags(&old_attributes);
            if ((usage & more_usage) == 0) {
                return PF_MBEDTLS_ERR_PK_TYPE_MISMATCH;
            }
            pf_psa_set_key_type(attributes, new_type);
            pf_psa_set_key_bits(attributes, pf_psa_get_key_bits(&old_attributes));
            pf_psa_set_key_algorithm(attributes, pf_psa_get_key_algorithm(&old_attributes));
            break;
        }
#endif /* MBEDTLS_USE_PSA_CRYPTO */

        default:
            return PF_MBEDTLS_ERR_PK_BAD_INPUT_DATA;
    }

    pf_psa_set_key_usage_flags(attributes, more_usage);
    /* Key's enrollment is available only when an Mbed TLS implementation of PSA
     * Crypto is being used, i.e. when MBEDTLS_PSA_CRYPTO_C is defined.
     * Even though we don't officially support using other implementations of PSA
     * Crypto with TLS and X.509 (yet), we try to keep vendor's customizations
     * separated. */
#if defined(PF_MBEDTLS_PSA_CRYPTO_C)
    pf_psa_set_key_enrollment_algorithm(attributes, PF_PSA_ALG_NONE);
#endif

    return 0;
}

#if defined(PF_MBEDTLS_PK_USE_PSA_EC_DATA) || defined(PF_MBEDTLS_USE_PSA_CRYPTO)
static pf_psa_status_t export_import_into_psa(pf_mbedtls_svc_key_id_t old_key_id,
                                           pf_psa_key_type_t old_type, size_t old_bits,
                                           const pf_psa_key_attributes_t *attributes,
                                           pf_mbedtls_svc_key_id_t *new_key_id)
{
#if !defined(PK_EXPORT_KEYS_ON_THE_STACK)
    unsigned char *key_buffer = NULL;
    size_t key_buffer_size = 0;
#else
    unsigned char key_buffer[PK_EXPORT_KEY_STACK_BUFFER_SIZE];
    const size_t key_buffer_size = sizeof(key_buffer);
#endif
    size_t key_length = 0;

    /* We are exporting from a PK object, so we know key type is valid for PK */
#if !defined(PK_EXPORT_KEYS_ON_THE_STACK)
    key_buffer_size = PF_PSA_EXPORT_KEY_OUTPUT_SIZE(old_type, old_bits);
    key_buffer = pf_mbedtls_calloc(1, key_buffer_size);
    if (key_buffer == NULL) {
        return PF_MBEDTLS_ERR_PK_ALLOC_FAILED;
    }
#else
    (void) old_type;
    (void) old_bits;
#endif

    pf_psa_status_t status = pf_psa_export_key(old_key_id,
                                         key_buffer, key_buffer_size,
                                         &key_length);
    if (status != PF_PSA_SUCCESS) {
        goto cleanup;
    }
    status = pf_psa_import_key(attributes, key_buffer, key_length, new_key_id);
    pf_mbedtls_platform_zeroize(key_buffer, key_length);

cleanup:
#if !defined(PK_EXPORT_KEYS_ON_THE_STACK)
    pf_mbedtls_free(key_buffer);
#endif
    return status;
}

static int copy_into_psa(pf_mbedtls_svc_key_id_t old_key_id,
                         const pf_psa_key_attributes_t *attributes,
                         pf_mbedtls_svc_key_id_t *new_key_id)
{
    /* Normally, we prefer copying: it's more efficient and works even
     * for non-exportable keys. */
    pf_psa_status_t status = pf_psa_copy_key(old_key_id, attributes, new_key_id);
    if (status == PF_PSA_ERROR_NOT_PERMITTED /*missing COPY usage*/ ||
        status == PF_PSA_ERROR_INVALID_ARGUMENT /*incompatible policy*/) {
        /* There are edge cases where copying won't work, but export+import
         * might:
         * - If the old key does not allow PSA_KEY_USAGE_COPY.
         * - If the old key's usage does not allow what attributes wants.
         *   Because the key was intended for use in the pk module, and may
         *   have had a policy chosen solely for what pk needs rather than
         *   based on a detailed understanding of PSA policies, we are a bit
         *   more liberal than psa_copy_key() here.
         */
        /* Here we need to check that the types match, otherwise we risk
         * importing nonsensical data. */
        pf_psa_key_attributes_t old_attributes = PF_PSA_KEY_ATTRIBUTES_INIT;
        status = pf_psa_get_key_attributes(old_key_id, &old_attributes);
        if (status != PF_PSA_SUCCESS) {
            return PF_MBEDTLS_ERR_PK_BAD_INPUT_DATA;
        }
        pf_psa_key_type_t old_type = pf_psa_get_key_type(&old_attributes);
        size_t old_bits = pf_psa_get_key_bits(&old_attributes);
        pf_psa_reset_key_attributes(&old_attributes);
        if (old_type != pf_psa_get_key_type(attributes)) {
            return PF_MBEDTLS_ERR_PK_TYPE_MISMATCH;
        }
        status = export_import_into_psa(old_key_id, old_type, old_bits,
                                        attributes, new_key_id);
    }
    return PF_PSA_PK_TO_MBEDTLS_ERR(status);
}
#endif /* MBEDTLS_PK_USE_PSA_EC_DATA || MBEDTLS_USE_PSA_CRYPTO */

static int import_pair_into_psa(const pf_mbedtls_pk_context *pk,
                                const pf_psa_key_attributes_t *attributes,
                                pf_mbedtls_svc_key_id_t *key_id)
{
    switch (pf_mbedtls_pk_get_type(pk)) {
#if defined(PF_MBEDTLS_RSA_C)
        case PF_MBEDTLS_PK_RSA:
        {
            if (pf_psa_get_key_type(attributes) != PF_PSA_KEY_TYPE_RSA_KEY_PAIR) {
                return PF_MBEDTLS_ERR_PK_TYPE_MISMATCH;
            }
            size_t key_bits = pf_psa_get_key_bits(attributes);
            size_t key_buffer_size = PF_PSA_KEY_EXPORT_RSA_KEY_PAIR_MAX_SIZE(key_bits);
            unsigned char *key_buffer = pf_mbedtls_calloc(1, key_buffer_size);
            if (key_buffer == NULL) {
                return PF_MBEDTLS_ERR_PK_ALLOC_FAILED;
            }
            unsigned char *const key_end = key_buffer + key_buffer_size;
            unsigned char *key_data = key_end;
            int ret = pf_mbedtls_rsa_write_key(pf_mbedtls_pk_rsa(*pk),
                                            key_buffer, &key_data);
            if (ret < 0) {
                goto cleanup_rsa;
            }
            size_t key_length = key_end - key_data;
            ret = PF_PSA_PK_TO_MBEDTLS_ERR(pf_psa_import_key(attributes,
                                                       key_data, key_length,
                                                       key_id));
cleanup_rsa:
            pf_mbedtls_zeroize_and_free(key_buffer, key_buffer_size);
            return ret;
        }
#endif /* MBEDTLS_RSA_C */

#if defined(PF_MBEDTLS_PK_HAVE_ECC_KEYS)
        case PF_MBEDTLS_PK_ECKEY:
        case PF_MBEDTLS_PK_ECKEY_DH:
        case PF_MBEDTLS_PK_ECDSA:
        {
            /* We need to check the curve family, otherwise the import could
             * succeed with nonsensical data.
             * We don't check the bit-size: it's optional in attributes,
             * and if it's specified, psa_import_key() will know from the key
             * data length and will check that the bit-size matches. */
            pf_psa_key_type_t to_type = pf_psa_get_key_type(attributes);
#if defined(PF_MBEDTLS_PK_USE_PSA_EC_DATA)
            pf_psa_ecc_family_t from_family = pk->ec_family;
#else /* MBEDTLS_PK_USE_PSA_EC_DATA */
            const pf_mbedtls_ecp_keypair *ec = pf_mbedtls_pk_ec_ro(*pk);
            size_t from_bits = 0;
            pf_psa_ecc_family_t from_family = pf_mbedtls_ecc_group_to_psa(ec->grp.id,
                                                                    &from_bits);
#endif /* MBEDTLS_PK_USE_PSA_EC_DATA */
            if (to_type != PF_PSA_KEY_TYPE_ECC_KEY_PAIR(from_family)) {
                return PF_MBEDTLS_ERR_PK_TYPE_MISMATCH;
            }

#if defined(PF_MBEDTLS_PK_USE_PSA_EC_DATA)
            if (pf_mbedtls_svc_key_id_is_null(pk->priv_id)) {
                /* We have a public key and want a key pair. */
                return PF_MBEDTLS_ERR_PK_TYPE_MISMATCH;
            }
            return copy_into_psa(pk->priv_id, attributes, key_id);
#else /* MBEDTLS_PK_USE_PSA_EC_DATA */
            if (ec->d.n == 0) {
                /* Private key not set. Assume the input is a public key only.
                 * (The other possibility is that it's an incomplete object
                 * where the group is set but neither the public key nor
                 * the private key. This is not possible through ecp.h
                 * functions, so we don't bother reporting a more suitable
                 * error in that case.) */
                return PF_MBEDTLS_ERR_PK_TYPE_MISMATCH;
            }
            unsigned char key_buffer[PF_PSA_BITS_TO_BYTES(PF_PSA_VENDOR_ECC_MAX_CURVE_BITS)];
            size_t key_length = 0;
            int ret = pf_mbedtls_ecp_write_key_ext(ec, &key_length,
                                                key_buffer, sizeof(key_buffer));
            if (ret < 0) {
                return ret;
            }
            ret = PF_PSA_PK_TO_MBEDTLS_ERR(pf_psa_import_key(attributes,
                                                       key_buffer, key_length,
                                                       key_id));
            pf_mbedtls_platform_zeroize(key_buffer, key_length);
            return ret;
#endif /* MBEDTLS_PK_USE_PSA_EC_DATA */
        }
#endif /* MBEDTLS_PK_HAVE_ECC_KEYS */

#if defined(PF_MBEDTLS_USE_PSA_CRYPTO)
        case PF_MBEDTLS_PK_OPAQUE:
            return copy_into_psa(pk->priv_id, attributes, key_id);
#endif /* MBEDTLS_USE_PSA_CRYPTO */

        default:
            return PF_MBEDTLS_ERR_PK_BAD_INPUT_DATA;
    }
}

static int import_public_into_psa(const pf_mbedtls_pk_context *pk,
                                  const pf_psa_key_attributes_t *attributes,
                                  pf_mbedtls_svc_key_id_t *key_id)
{
    pf_psa_key_type_t pf_psa_type = pf_psa_get_key_type(attributes);

#if defined(PF_MBEDTLS_RSA_C) ||                                           \
    (defined(PF_MBEDTLS_PK_HAVE_ECC_KEYS) && !defined(PF_MBEDTLS_PK_USE_PSA_EC_DATA)) || \
    defined(PF_MBEDTLS_USE_PSA_CRYPTO)
    unsigned char key_buffer[PF_MBEDTLS_PK_MAX_PUBKEY_RAW_LEN];
#endif
    unsigned char *key_data = NULL;
    size_t key_length = 0;

    switch (pf_mbedtls_pk_get_type(pk)) {
#if defined(PF_MBEDTLS_RSA_C)
        case PF_MBEDTLS_PK_RSA:
        {
            if (pf_psa_type != PF_PSA_KEY_TYPE_RSA_PUBLIC_KEY) {
                return PF_MBEDTLS_ERR_PK_TYPE_MISMATCH;
            }
            unsigned char *const key_end = key_buffer + sizeof(key_buffer);
            key_data = key_end;
            int ret = pf_mbedtls_rsa_write_pubkey(pf_mbedtls_pk_rsa(*pk),
                                               key_buffer, &key_data);
            if (ret < 0) {
                return ret;
            }
            key_length = (size_t) ret;
            break;
        }
#endif /*MBEDTLS_RSA_C */

#if defined(PF_MBEDTLS_PK_HAVE_ECC_KEYS)
        case PF_MBEDTLS_PK_ECKEY:
        case PF_MBEDTLS_PK_ECKEY_DH:
        case PF_MBEDTLS_PK_ECDSA:
        {
            /* We need to check the curve family, otherwise the import could
             * succeed with nonsensical data.
             * We don't check the bit-size: it's optional in attributes,
             * and if it's specified, psa_import_key() will know from the key
             * data length and will check that the bit-size matches. */
#if defined(PF_MBEDTLS_PK_USE_PSA_EC_DATA)
            if (pf_psa_type != PF_PSA_KEY_TYPE_ECC_PUBLIC_KEY(pk->ec_family)) {
                return PF_MBEDTLS_ERR_PK_TYPE_MISMATCH;
            }
            key_data = (unsigned char *) pk->pub_raw;
            key_length = pk->pub_raw_len;
#else /* MBEDTLS_PK_USE_PSA_EC_DATA */
            const pf_mbedtls_ecp_keypair *ec = pf_mbedtls_pk_ec_ro(*pk);
            size_t from_bits = 0;
            pf_psa_ecc_family_t from_family = pf_mbedtls_ecc_group_to_psa(ec->grp.id,
                                                                    &from_bits);
            if (pf_psa_type != PF_PSA_KEY_TYPE_ECC_PUBLIC_KEY(from_family)) {
                return PF_MBEDTLS_ERR_PK_TYPE_MISMATCH;
            }
            int ret = pf_mbedtls_ecp_write_public_key(
                ec, PF_MBEDTLS_ECP_PF_UNCOMPRESSED,
                &key_length, key_buffer, sizeof(key_buffer));
            if (ret < 0) {
                return ret;
            }
            key_data = key_buffer;
#endif /* MBEDTLS_PK_USE_PSA_EC_DATA */
            break;
        }
#endif /* MBEDTLS_PK_HAVE_ECC_KEYS */

#if defined(PF_MBEDTLS_USE_PSA_CRYPTO)
        case PF_MBEDTLS_PK_OPAQUE:
        {
            pf_psa_key_attributes_t old_attributes = PF_PSA_KEY_ATTRIBUTES_INIT;
            pf_psa_status_t status =
                pf_psa_get_key_attributes(pk->priv_id, &old_attributes);
            if (status != PF_PSA_SUCCESS) {
                return PF_MBEDTLS_ERR_PK_BAD_INPUT_DATA;
            }
            pf_psa_key_type_t old_type = pf_psa_get_key_type(&old_attributes);
            pf_psa_reset_key_attributes(&old_attributes);
            if (pf_psa_type != PF_PSA_KEY_TYPE_PUBLIC_KEY_OF_KEY_PAIR(old_type)) {
                return PF_MBEDTLS_ERR_PK_TYPE_MISMATCH;
            }
            status = pf_psa_export_public_key(pk->priv_id,
                                           key_buffer, sizeof(key_buffer),
                                           &key_length);
            if (status != PF_PSA_SUCCESS) {
                return PF_PSA_PK_TO_MBEDTLS_ERR(status);
            }
            key_data = key_buffer;
            break;
        }
#endif /* MBEDTLS_USE_PSA_CRYPTO */

        default:
            return PF_MBEDTLS_ERR_PK_BAD_INPUT_DATA;
    }

    return PF_PSA_PK_TO_MBEDTLS_ERR(pf_psa_import_key(attributes,
                                                key_data, key_length,
                                                key_id));
}

int pf_mbedtls_pk_import_into_psa(const pf_mbedtls_pk_context *pk,
                               const pf_psa_key_attributes_t *attributes,
                               pf_mbedtls_svc_key_id_t *key_id)
{
    /* Set the output immediately so that it won't contain garbage even
     * if we error out before calling psa_import_key(). */
    *key_id = PF_MBEDTLS_SVC_KEY_ID_INIT;

#if defined(PF_MBEDTLS_PK_RSA_ALT_SUPPORT)
    if (pf_mbedtls_pk_get_type(pk) == PF_MBEDTLS_PK_RSA_ALT) {
        return PF_MBEDTLS_ERR_PK_FEATURE_UNAVAILABLE;
    }
#endif /* MBEDTLS_PK_RSA_ALT_SUPPORT */

    int want_public = PF_PSA_KEY_TYPE_IS_PUBLIC_KEY(pf_psa_get_key_type(attributes));
    if (want_public) {
        return import_public_into_psa(pk, attributes, key_id);
    } else {
        return import_pair_into_psa(pk, attributes, key_id);
    }
}

static int is_valid_for_pk(pf_psa_key_type_t key_type)
{
#if defined(PF_MBEDTLS_PK_HAVE_ECC_KEYS)
    if (PF_PSA_KEY_TYPE_IS_ECC(key_type)) {
        return 1;
    }
#endif
#if defined(PF_MBEDTLS_RSA_C)
    if (PF_PSA_KEY_TYPE_IS_RSA(key_type)) {
        return 1;
    }
#endif
    return 0;
}

static int copy_from_psa(pf_mbedtls_svc_key_id_t key_id,
                         pf_mbedtls_pk_context *pk,
                         int public_only)
{
    pf_psa_status_t status;
    pf_psa_key_attributes_t key_attr = PF_PSA_KEY_ATTRIBUTES_INIT;
    pf_psa_key_type_t key_type;
    size_t key_bits;
#if !defined(PK_EXPORT_KEYS_ON_THE_STACK)
    unsigned char *exp_key = NULL;
    size_t exp_key_size = 0;
#else
    unsigned char exp_key[PK_EXPORT_KEY_STACK_BUFFER_SIZE];
    const size_t exp_key_size = sizeof(exp_key);
#endif
    size_t exp_key_len;
    int ret = PF_MBEDTLS_ERR_PK_BAD_INPUT_DATA;

    if (pk == NULL) {
        return PF_MBEDTLS_ERR_PK_BAD_INPUT_DATA;
    }

    status = pf_psa_get_key_attributes(key_id, &key_attr);
    if (status != PF_PSA_SUCCESS) {
        return PF_MBEDTLS_ERR_PK_BAD_INPUT_DATA;
    }

    key_type = pf_psa_get_key_type(&key_attr);
    if (!is_valid_for_pk(key_type)) {
        return PF_MBEDTLS_ERR_PK_BAD_INPUT_DATA;
    }

    if (public_only) {
        key_type = PF_PSA_KEY_TYPE_PUBLIC_KEY_OF_KEY_PAIR(key_type);
    }
    key_bits = pf_psa_get_key_bits(&key_attr);

#if !defined(PK_EXPORT_KEYS_ON_THE_STACK)
    exp_key_size = PF_PSA_EXPORT_KEY_OUTPUT_SIZE(key_type, key_bits);
    exp_key = pf_mbedtls_calloc(1, exp_key_size);
    if (exp_key == NULL) {
        return PF_MBEDTLS_ERR_PK_ALLOC_FAILED;
    }
#endif

    if (public_only) {
        status = pf_psa_export_public_key(key_id, exp_key, exp_key_size, &exp_key_len);
    } else {
        status = pf_psa_export_key(key_id, exp_key, exp_key_size, &exp_key_len);
    }
    if (status != PF_PSA_SUCCESS) {
        ret = PF_PSA_PK_TO_MBEDTLS_ERR(status);
        goto exit;
    }

    key_type = pf_psa_get_key_type(&key_attr);
    if (public_only) {
        key_type = PF_PSA_KEY_TYPE_PUBLIC_KEY_OF_KEY_PAIR(key_type);
    }
    key_bits = pf_psa_get_key_bits(&key_attr);

#if defined(PF_MBEDTLS_RSA_C)
    if ((key_type == PF_PSA_KEY_TYPE_RSA_KEY_PAIR) ||
        (key_type == PF_PSA_KEY_TYPE_RSA_PUBLIC_KEY)) {

        ret = pf_mbedtls_pk_setup(pk, pf_mbedtls_pk_info_from_type(PF_MBEDTLS_PK_RSA));
        if (ret != 0) {
            goto exit;
        }

        if (key_type == PF_PSA_KEY_TYPE_RSA_KEY_PAIR) {
            ret = pf_mbedtls_rsa_parse_key(pf_mbedtls_pk_rsa(*pk), exp_key, exp_key_len);
        } else {
            ret = pf_mbedtls_rsa_parse_pubkey(pf_mbedtls_pk_rsa(*pk), exp_key, exp_key_len);
        }
        if (ret != 0) {
            goto exit;
        }

        pf_psa_algorithm_t alg_type = pf_psa_get_key_algorithm(&key_attr);
        pf_mbedtls_md_type_t md_type = PF_MBEDTLS_MD_NONE;
        if (PF_PSA_ALG_GET_HASH(alg_type) != PF_PSA_ALG_ANY_HASH) {
            md_type = pf_mbedtls_md_type_from_psa_alg(alg_type);
        }

        if (PF_PSA_ALG_IS_RSA_OAEP(alg_type) || PF_PSA_ALG_IS_RSA_PSS(alg_type)) {
            ret = pf_mbedtls_rsa_set_padding(pf_mbedtls_pk_rsa(*pk), PF_MBEDTLS_RSA_PKCS_V21, md_type);
        } else if (PF_PSA_ALG_IS_RSA_PKCS1V15_SIGN(alg_type) ||
                   alg_type == PF_PSA_ALG_RSA_PKCS1V15_CRYPT) {
            ret = pf_mbedtls_rsa_set_padding(pf_mbedtls_pk_rsa(*pk), PF_MBEDTLS_RSA_PKCS_V15, md_type);
        }
        if (ret != 0) {
            goto exit;
        }
    } else
#endif /* MBEDTLS_RSA_C */
#if defined(PF_MBEDTLS_PK_HAVE_ECC_KEYS)
    if (PF_PSA_KEY_TYPE_IS_ECC_KEY_PAIR(key_type) ||
        PF_PSA_KEY_TYPE_IS_ECC_PUBLIC_KEY(key_type)) {
        pf_mbedtls_ecp_group_id grp_id;

        ret = pf_mbedtls_pk_setup(pk, pf_mbedtls_pk_info_from_type(PF_MBEDTLS_PK_ECKEY));
        if (ret != 0) {
            goto exit;
        }

        grp_id = pf_mbedtls_ecc_group_from_psa(PF_PSA_KEY_TYPE_ECC_GET_FAMILY(key_type), key_bits);
        ret = pf_mbedtls_pk_ecc_set_group(pk, grp_id);
        if (ret != 0) {
            goto exit;
        }

        if (PF_PSA_KEY_TYPE_IS_ECC_KEY_PAIR(key_type)) {
            ret = pf_mbedtls_pk_ecc_set_key(pk, exp_key, exp_key_len);
            if (ret != 0) {
                goto exit;
            }
            ret = pf_mbedtls_pk_ecc_set_pubkey_from_prv(pk, exp_key, exp_key_len,
                                                     pf_mbedtls_psa_get_random,
                                                     PF_MBEDTLS_PSA_RANDOM_STATE);
        } else {
            ret = pf_mbedtls_pk_ecc_set_pubkey(pk, exp_key, exp_key_len);
        }
        if (ret != 0) {
            goto exit;
        }
    } else
#endif /* MBEDTLS_PK_HAVE_ECC_KEYS */
    {
        (void) key_bits;
        ret = PF_MBEDTLS_ERR_PK_BAD_INPUT_DATA;
        goto exit;
    }

exit:
    pf_mbedtls_platform_zeroize(exp_key, exp_key_size);
#if !defined(PK_EXPORT_KEYS_ON_THE_STACK)
    pf_mbedtls_free(exp_key);
#endif
    pf_psa_reset_key_attributes(&key_attr);

    return ret;
}

int pf_mbedtls_pk_copy_from_psa(pf_mbedtls_svc_key_id_t key_id,
                             pf_mbedtls_pk_context *pk)
{
    return copy_from_psa(key_id, pk, 0);
}

int pf_mbedtls_pk_copy_public_from_psa(pf_mbedtls_svc_key_id_t key_id,
                                    pf_mbedtls_pk_context *pk)
{
    return copy_from_psa(key_id, pk, 1);
}
#endif /* MBEDTLS_PSA_CRYPTO_CLIENT */

/*
 * Helper for mbedtls_pk_sign and mbedtls_pk_verify
 */
static inline int pk_hashlen_helper(pf_mbedtls_md_type_t md_alg, size_t *hash_len)
{
    if (*hash_len != 0) {
        return 0;
    }

    *hash_len = pf_mbedtls_md_get_size_from_type(md_alg);

    if (*hash_len == 0) {
        return -1;
    }

    return 0;
}

#if defined(PF_MBEDTLS_ECDSA_C) && defined(PF_MBEDTLS_ECP_RESTARTABLE)
/*
 * Helper to set up a restart context if needed
 */
static int pk_restart_setup(pf_mbedtls_pk_restart_ctx *ctx,
                            const pf_mbedtls_pk_info_t *info)
{
    /* Don't do anything if already set up or invalid */
    if (ctx == NULL || ctx->pk_info != NULL) {
        return 0;
    }

    /* Should never happen when we're called */
    if (info->rs_alloc_func == NULL || info->rs_free_func == NULL) {
        return PF_MBEDTLS_ERR_PK_BAD_INPUT_DATA;
    }

    if ((ctx->rs_ctx = info->rs_alloc_func()) == NULL) {
        return PF_MBEDTLS_ERR_PK_ALLOC_FAILED;
    }

    ctx->pk_info = info;

    return 0;
}
#endif /* MBEDTLS_ECDSA_C && MBEDTLS_ECP_RESTARTABLE */

/*
 * Verify a signature (restartable)
 */
int pf_mbedtls_pk_verify_restartable(pf_mbedtls_pk_context *ctx,
                                  pf_mbedtls_md_type_t md_alg,
                                  const unsigned char *hash, size_t hash_len,
                                  const unsigned char *sig, size_t sig_len,
                                  pf_mbedtls_pk_restart_ctx *rs_ctx)
{
    if ((md_alg != PF_MBEDTLS_MD_NONE || hash_len != 0) && hash == NULL) {
        return PF_MBEDTLS_ERR_PK_BAD_INPUT_DATA;
    }

    if (ctx->pk_info == NULL ||
        pk_hashlen_helper(md_alg, &hash_len) != 0) {
        return PF_MBEDTLS_ERR_PK_BAD_INPUT_DATA;
    }

#if defined(PF_MBEDTLS_ECDSA_C) && defined(PF_MBEDTLS_ECP_RESTARTABLE)
    /* optimization: use non-restartable version if restart disabled */
    if (rs_ctx != NULL &&
        pf_mbedtls_ecp_restart_is_enabled() &&
        ctx->pk_info->verify_rs_func != NULL) {
        int ret = PF_MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;

        if ((ret = pk_restart_setup(rs_ctx, ctx->pk_info)) != 0) {
            return ret;
        }

        ret = ctx->pk_info->verify_rs_func(ctx,
                                           md_alg, hash, hash_len, sig, sig_len, rs_ctx->rs_ctx);

        if (ret != PF_MBEDTLS_ERR_ECP_IN_PROGRESS) {
            pf_mbedtls_pk_restart_free(rs_ctx);
        }

        return ret;
    }
#else /* MBEDTLS_ECDSA_C && MBEDTLS_ECP_RESTARTABLE */
    (void) rs_ctx;
#endif /* MBEDTLS_ECDSA_C && MBEDTLS_ECP_RESTARTABLE */

    if (ctx->pk_info->verify_func == NULL) {
        return PF_MBEDTLS_ERR_PK_TYPE_MISMATCH;
    }

    return ctx->pk_info->verify_func(ctx, md_alg, hash, hash_len,
                                     sig, sig_len);
}

/*
 * Verify a signature
 */
int pf_mbedtls_pk_verify(pf_mbedtls_pk_context *ctx, pf_mbedtls_md_type_t md_alg,
                      const unsigned char *hash, size_t hash_len,
                      const unsigned char *sig, size_t sig_len)
{
    return pf_mbedtls_pk_verify_restartable(ctx, md_alg, hash, hash_len,
                                         sig, sig_len, NULL);
}

/*
 * Verify a signature with options
 */
int pf_mbedtls_pk_verify_ext(pf_mbedtls_pk_type_t type, const void *options,
                          pf_mbedtls_pk_context *ctx, pf_mbedtls_md_type_t md_alg,
                          const unsigned char *hash, size_t hash_len,
                          const unsigned char *sig, size_t sig_len)
{
    if ((md_alg != PF_MBEDTLS_MD_NONE || hash_len != 0) && hash == NULL) {
        return PF_MBEDTLS_ERR_PK_BAD_INPUT_DATA;
    }

    if (ctx->pk_info == NULL) {
        return PF_MBEDTLS_ERR_PK_BAD_INPUT_DATA;
    }

    if (!pf_mbedtls_pk_can_do(ctx, type)) {
        return PF_MBEDTLS_ERR_PK_TYPE_MISMATCH;
    }

    if (type != PF_MBEDTLS_PK_RSASSA_PSS) {
        /* General case: no options */
        if (options != NULL) {
            return PF_MBEDTLS_ERR_PK_BAD_INPUT_DATA;
        }

        return pf_mbedtls_pk_verify(ctx, md_alg, hash, hash_len, sig, sig_len);
    }

    /* Ensure the PK context is of the right type otherwise mbedtls_pk_rsa()
     * below would return a NULL pointer. */
    if (pf_mbedtls_pk_get_type(ctx) != PF_MBEDTLS_PK_RSA) {
        return PF_MBEDTLS_ERR_PK_FEATURE_UNAVAILABLE;
    }

#if defined(PF_MBEDTLS_RSA_C) && defined(PF_MBEDTLS_PKCS1_V21)
    int ret = PF_MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    const pf_mbedtls_pk_rsassa_pss_options *pss_opts;

#if SIZE_MAX > UINT_MAX
    if (md_alg == PF_MBEDTLS_MD_NONE && UINT_MAX < hash_len) {
        return PF_MBEDTLS_ERR_PK_BAD_INPUT_DATA;
    }
#endif

    if (options == NULL) {
        return PF_MBEDTLS_ERR_PK_BAD_INPUT_DATA;
    }

    pss_opts = (const pf_mbedtls_pk_rsassa_pss_options *) options;

#if defined(PF_MBEDTLS_USE_PSA_CRYPTO)
    if (pss_opts->mgf1_hash_id == md_alg) {
        unsigned char buf[PF_PSA_KEY_EXPORT_RSA_PUBLIC_KEY_MAX_SIZE(PF_PSA_VENDOR_RSA_MAX_KEY_BITS)];
        unsigned char *p;
        int key_len;
        size_t signature_length;
        pf_psa_status_t status = PF_PSA_ERROR_DATA_CORRUPT;
        pf_psa_status_t destruction_status = PF_PSA_ERROR_DATA_CORRUPT;

        pf_psa_algorithm_t pf_psa_md_alg = pf_mbedtls_md_psa_alg_from_type(md_alg);
        pf_mbedtls_svc_key_id_t key_id = PF_MBEDTLS_SVC_KEY_ID_INIT;
        pf_psa_key_attributes_t attributes = PF_PSA_KEY_ATTRIBUTES_INIT;
        pf_psa_algorithm_t pf_psa_sig_alg = PF_PSA_ALG_RSA_PSS_ANY_SALT(pf_psa_md_alg);
        p = buf + sizeof(buf);
        key_len = pf_mbedtls_rsa_write_pubkey(pf_mbedtls_pk_rsa(*ctx), buf, &p);

        if (key_len < 0) {
            return key_len;
        }

        pf_psa_set_key_type(&attributes, PF_PSA_KEY_TYPE_RSA_PUBLIC_KEY);
        pf_psa_set_key_usage_flags(&attributes, PF_PSA_KEY_USAGE_VERIFY_HASH);
        pf_psa_set_key_algorithm(&attributes, pf_psa_sig_alg);

        status = pf_psa_import_key(&attributes,
                                buf + sizeof(buf) - key_len, key_len,
                                &key_id);
        if (status != PF_PSA_SUCCESS) {
            pf_psa_destroy_key(key_id);
            return PF_PSA_PK_TO_MBEDTLS_ERR(status);
        }

        /* This function requires returning MBEDTLS_ERR_PK_SIG_LEN_MISMATCH
         * on a valid signature with trailing data in a buffer, but
         * mbedtls_psa_rsa_verify_hash requires the sig_len to be exact,
         * so for this reason the passed sig_len is overwritten. Smaller
         * signature lengths should not be accepted for verification. */
        signature_length = sig_len > pf_mbedtls_pk_get_len(ctx) ?
                           pf_mbedtls_pk_get_len(ctx) : sig_len;
        status = pf_psa_verify_hash(key_id, pf_psa_sig_alg, hash,
                                 hash_len, sig, signature_length);
        destruction_status = pf_psa_destroy_key(key_id);

        if (status == PF_PSA_SUCCESS && sig_len > pf_mbedtls_pk_get_len(ctx)) {
            return PF_MBEDTLS_ERR_PK_SIG_LEN_MISMATCH;
        }

        if (status == PF_PSA_SUCCESS) {
            status = destruction_status;
        }

        return PF_PSA_PK_RSA_TO_MBEDTLS_ERR(status);
    } else
#endif /* MBEDTLS_USE_PSA_CRYPTO */
    {
        if (sig_len < pf_mbedtls_pk_get_len(ctx)) {
            return PF_MBEDTLS_ERR_RSA_VERIFY_FAILED;
        }

        ret = pf_mbedtls_rsa_rsassa_pss_verify_ext(pf_mbedtls_pk_rsa(*ctx),
                                                md_alg, (unsigned int) hash_len, hash,
                                                pss_opts->mgf1_hash_id,
                                                pss_opts->expected_salt_len,
                                                sig);
        if (ret != 0) {
            return ret;
        }

        if (sig_len > pf_mbedtls_pk_get_len(ctx)) {
            return PF_MBEDTLS_ERR_PK_SIG_LEN_MISMATCH;
        }

        return 0;
    }
#else
    return PF_MBEDTLS_ERR_PK_FEATURE_UNAVAILABLE;
#endif /* MBEDTLS_RSA_C && MBEDTLS_PKCS1_V21 */
}

/*
 * Make a signature (restartable)
 */
int pf_mbedtls_pk_sign_restartable(pf_mbedtls_pk_context *ctx,
                                pf_mbedtls_md_type_t md_alg,
                                const unsigned char *hash, size_t hash_len,
                                unsigned char *sig, size_t sig_size, size_t *sig_len,
                                int (*f_rng)(void *, unsigned char *, size_t), void *p_rng,
                                pf_mbedtls_pk_restart_ctx *rs_ctx)
{
    if ((md_alg != PF_MBEDTLS_MD_NONE || hash_len != 0) && hash == NULL) {
        return PF_MBEDTLS_ERR_PK_BAD_INPUT_DATA;
    }

    if (ctx->pk_info == NULL || pk_hashlen_helper(md_alg, &hash_len) != 0) {
        return PF_MBEDTLS_ERR_PK_BAD_INPUT_DATA;
    }

#if defined(PF_MBEDTLS_ECDSA_C) && defined(PF_MBEDTLS_ECP_RESTARTABLE)
    /* optimization: use non-restartable version if restart disabled */
    if (rs_ctx != NULL &&
        pf_mbedtls_ecp_restart_is_enabled() &&
        ctx->pk_info->sign_rs_func != NULL) {
        int ret = PF_MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;

        if ((ret = pk_restart_setup(rs_ctx, ctx->pk_info)) != 0) {
            return ret;
        }

        ret = ctx->pk_info->sign_rs_func(ctx, md_alg,
                                         hash, hash_len,
                                         sig, sig_size, sig_len,
                                         f_rng, p_rng, rs_ctx->rs_ctx);

        if (ret != PF_MBEDTLS_ERR_ECP_IN_PROGRESS) {
            pf_mbedtls_pk_restart_free(rs_ctx);
        }

        return ret;
    }
#else /* MBEDTLS_ECDSA_C && MBEDTLS_ECP_RESTARTABLE */
    (void) rs_ctx;
#endif /* MBEDTLS_ECDSA_C && MBEDTLS_ECP_RESTARTABLE */

    if (ctx->pk_info->sign_func == NULL) {
        return PF_MBEDTLS_ERR_PK_TYPE_MISMATCH;
    }

    return ctx->pk_info->sign_func(ctx, md_alg,
                                   hash, hash_len,
                                   sig, sig_size, sig_len,
                                   f_rng, p_rng);
}

/*
 * Make a signature
 */
int pf_mbedtls_pk_sign(pf_mbedtls_pk_context *ctx, pf_mbedtls_md_type_t md_alg,
                    const unsigned char *hash, size_t hash_len,
                    unsigned char *sig, size_t sig_size, size_t *sig_len,
                    int (*f_rng)(void *, unsigned char *, size_t), void *p_rng)
{
    return pf_mbedtls_pk_sign_restartable(ctx, md_alg, hash, hash_len,
                                       sig, sig_size, sig_len,
                                       f_rng, p_rng, NULL);
}

/*
 * Make a signature given a signature type.
 */
int pf_mbedtls_pk_sign_ext(pf_mbedtls_pk_type_t pk_type,
                        pf_mbedtls_pk_context *ctx,
                        pf_mbedtls_md_type_t md_alg,
                        const unsigned char *hash, size_t hash_len,
                        unsigned char *sig, size_t sig_size, size_t *sig_len,
                        int (*f_rng)(void *, unsigned char *, size_t),
                        void *p_rng)
{
    if (ctx->pk_info == NULL) {
        return PF_MBEDTLS_ERR_PK_BAD_INPUT_DATA;
    }

    if (!pf_mbedtls_pk_can_do(ctx, pk_type)) {
        return PF_MBEDTLS_ERR_PK_TYPE_MISMATCH;
    }

    if (pk_type != PF_MBEDTLS_PK_RSASSA_PSS) {
        return pf_mbedtls_pk_sign(ctx, md_alg, hash, hash_len,
                               sig, sig_size, sig_len, f_rng, p_rng);
    }

#if defined(PF_MBEDTLS_RSA_C) && defined(PF_MBEDTLS_PKCS1_V21)

#if defined(PF_MBEDTLS_USE_PSA_CRYPTO)
    const pf_psa_algorithm_t pf_psa_md_alg = pf_mbedtls_md_psa_alg_from_type(md_alg);
    if (pf_psa_md_alg == 0) {
        return PF_MBEDTLS_ERR_PK_BAD_INPUT_DATA;
    }

    if (pf_mbedtls_pk_get_type(ctx) == PF_MBEDTLS_PK_OPAQUE) {
        pf_psa_status_t status;

        /* PSA_ALG_RSA_PSS() behaves the same as PSA_ALG_RSA_PSS_ANY_SALT() when
         * performing a signature, but they are encoded differently. Instead of
         * extracting the proper one from the wrapped key policy, just try both. */
        status = pf_psa_sign_hash(ctx->priv_id, PF_PSA_ALG_RSA_PSS(pf_psa_md_alg),
                               hash, hash_len,
                               sig, sig_size, sig_len);
        if (status == PF_PSA_ERROR_NOT_PERMITTED) {
            status = pf_psa_sign_hash(ctx->priv_id, PF_PSA_ALG_RSA_PSS_ANY_SALT(pf_psa_md_alg),
                                   hash, hash_len,
                                   sig, sig_size, sig_len);
        }
        return PF_PSA_PK_RSA_TO_MBEDTLS_ERR(status);
    }

    return pf_mbedtls_pk_psa_rsa_sign_ext(PF_PSA_ALG_RSA_PSS(pf_psa_md_alg),
                                       ctx->pk_ctx, hash, hash_len,
                                       sig, sig_size, sig_len);
#else /* MBEDTLS_USE_PSA_CRYPTO */

    if (sig_size < pf_mbedtls_pk_get_len(ctx)) {
        return PF_MBEDTLS_ERR_PK_BUFFER_TOO_SMALL;
    }

    if (pk_hashlen_helper(md_alg, &hash_len) != 0) {
        return PF_MBEDTLS_ERR_PK_BAD_INPUT_DATA;
    }

    pf_mbedtls_rsa_context *const rsa_ctx = pf_mbedtls_pk_rsa(*ctx);

    const int ret = pf_mbedtls_rsa_rsassa_pss_sign_no_mode_check(rsa_ctx, f_rng, p_rng, md_alg,
                                                              (unsigned int) hash_len, hash, sig);
    if (ret == 0) {
        *sig_len = rsa_ctx->len;
    }
    return ret;

#endif /* MBEDTLS_USE_PSA_CRYPTO */

#else
    return PF_MBEDTLS_ERR_PK_FEATURE_UNAVAILABLE;
#endif /* MBEDTLS_RSA_C && MBEDTLS_PKCS1_V21 */
}

/*
 * Decrypt message
 */
int pf_mbedtls_pk_decrypt(pf_mbedtls_pk_context *ctx,
                       const unsigned char *input, size_t ilen,
                       unsigned char *output, size_t *olen, size_t osize,
                       int (*f_rng)(void *, unsigned char *, size_t), void *p_rng)
{
    if (ctx->pk_info == NULL) {
        return PF_MBEDTLS_ERR_PK_BAD_INPUT_DATA;
    }

    if (ctx->pk_info->decrypt_func == NULL) {
        return PF_MBEDTLS_ERR_PK_TYPE_MISMATCH;
    }

    return ctx->pk_info->decrypt_func(ctx, input, ilen,
                                      output, olen, osize, f_rng, p_rng);
}

/*
 * Encrypt message
 */
int pf_mbedtls_pk_encrypt(pf_mbedtls_pk_context *ctx,
                       const unsigned char *input, size_t ilen,
                       unsigned char *output, size_t *olen, size_t osize,
                       int (*f_rng)(void *, unsigned char *, size_t), void *p_rng)
{
    if (ctx->pk_info == NULL) {
        return PF_MBEDTLS_ERR_PK_BAD_INPUT_DATA;
    }

    if (ctx->pk_info->encrypt_func == NULL) {
        return PF_MBEDTLS_ERR_PK_TYPE_MISMATCH;
    }

    return ctx->pk_info->encrypt_func(ctx, input, ilen,
                                      output, olen, osize, f_rng, p_rng);
}

/*
 * Check public-private key pair
 */
int pf_mbedtls_pk_check_pair(const pf_mbedtls_pk_context *pub,
                          const pf_mbedtls_pk_context *prv,
                          int (*f_rng)(void *, unsigned char *, size_t),
                          void *p_rng)
{
    if (pub->pk_info == NULL ||
        prv->pk_info == NULL) {
        return PF_MBEDTLS_ERR_PK_BAD_INPUT_DATA;
    }

    if (f_rng == NULL) {
        return PF_MBEDTLS_ERR_PK_BAD_INPUT_DATA;
    }

    if (prv->pk_info->check_pair_func == NULL) {
        return PF_MBEDTLS_ERR_PK_FEATURE_UNAVAILABLE;
    }

    if (prv->pk_info->type == PF_MBEDTLS_PK_RSA_ALT) {
        if (pub->pk_info->type != PF_MBEDTLS_PK_RSA) {
            return PF_MBEDTLS_ERR_PK_TYPE_MISMATCH;
        }
    } else {
        if ((prv->pk_info->type != PF_MBEDTLS_PK_OPAQUE) &&
            (pub->pk_info != prv->pk_info)) {
            return PF_MBEDTLS_ERR_PK_TYPE_MISMATCH;
        }
    }

    return prv->pk_info->check_pair_func((pf_mbedtls_pk_context *) pub,
                                         (pf_mbedtls_pk_context *) prv,
                                         f_rng, p_rng);
}

/*
 * Get key size in bits
 */
size_t pf_mbedtls_pk_get_bitlen(const pf_mbedtls_pk_context *ctx)
{
    /* For backward compatibility, accept NULL or a context that
     * isn't set up yet, and return a fake value that should be safe. */
    if (ctx == NULL || ctx->pk_info == NULL) {
        return 0;
    }

    return ctx->pk_info->get_bitlen((pf_mbedtls_pk_context *) ctx);
}

/*
 * Export debug information
 */
int pf_mbedtls_pk_debug(const pf_mbedtls_pk_context *ctx, pf_mbedtls_pk_debug_item *items)
{
    if (ctx->pk_info == NULL) {
        return PF_MBEDTLS_ERR_PK_BAD_INPUT_DATA;
    }

    if (ctx->pk_info->debug_func == NULL) {
        return PF_MBEDTLS_ERR_PK_TYPE_MISMATCH;
    }

    ctx->pk_info->debug_func((pf_mbedtls_pk_context *) ctx, items);
    return 0;
}

/*
 * Access the PK type name
 */
const char *pf_mbedtls_pk_get_name(const pf_mbedtls_pk_context *ctx)
{
    if (ctx == NULL || ctx->pk_info == NULL) {
        return "invalid PK";
    }

    return ctx->pk_info->name;
}

/*
 * Access the PK type
 */
pf_mbedtls_pk_type_t pf_mbedtls_pk_get_type(const pf_mbedtls_pk_context *ctx)
{
    if (ctx == NULL || ctx->pk_info == NULL) {
        return PF_MBEDTLS_PK_NONE;
    }

    return ctx->pk_info->type;
}

#endif /* MBEDTLS_PK_C */
