#include "../../../pf_build_config.h"
/*
 *  Elliptic curve DSA
 *
 *  Copyright The Mbed TLS Contributors
 *  SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
 */

/*
 * References:
 *
 * SEC1 https://www.secg.org/sec1-v2.pdf
 */

#include "common.h"

#if defined(PF_MBEDTLS_ECDSA_C)

#include "../include/mbedtls/ecdsa.h"
#include "../include/mbedtls/asn1write.h"
#include "bignum_internal.h"

#include <string.h>

#if defined(PF_MBEDTLS_ECDSA_DETERMINISTIC)
#include "../include/mbedtls/hmac_drbg.h"
#endif

#include "../include/mbedtls/platform.h"

#include "../include/mbedtls/platform_util.h"
#include "../include/mbedtls/error.h"

#if defined(PF_MBEDTLS_ECP_RESTARTABLE)

/*
 * Sub-context for ecdsa_verify()
 */
struct pf_mbedtls_ecdsa_restart_ver {
    pf_mbedtls_mpi u1, u2;     /* intermediate values  */
    enum {                  /* what to do next?     */
        ecdsa_ver_init = 0, /* getting started      */
        ecdsa_ver_muladd,   /* muladd step          */
    } state;
};

/*
 * Init verify restart sub-context
 */
static void ecdsa_restart_ver_init(pf_mbedtls_ecdsa_restart_ver_ctx *ctx)
{
    pf_mbedtls_mpi_init(&ctx->u1);
    pf_mbedtls_mpi_init(&ctx->u2);
    ctx->state = ecdsa_ver_init;
}

/*
 * Free the components of a verify restart sub-context
 */
static void ecdsa_restart_ver_free(pf_mbedtls_ecdsa_restart_ver_ctx *ctx)
{
    if (ctx == NULL) {
        return;
    }

    pf_mbedtls_mpi_free(&ctx->u1);
    pf_mbedtls_mpi_free(&ctx->u2);

    ecdsa_restart_ver_init(ctx);
}

/*
 * Sub-context for ecdsa_sign()
 */
struct pf_mbedtls_ecdsa_restart_sig {
    int sign_tries;
    int key_tries;
    pf_mbedtls_mpi k;          /* per-signature random */
    pf_mbedtls_mpi r;          /* r value              */
    enum {                  /* what to do next?     */
        ecdsa_sig_init = 0, /* getting started      */
        ecdsa_sig_mul,      /* doing ecp_mul()      */
        ecdsa_sig_modn,     /* mod N computations   */
    } state;
};

/*
 * Init verify sign sub-context
 */
static void ecdsa_restart_sig_init(pf_mbedtls_ecdsa_restart_sig_ctx *ctx)
{
    ctx->sign_tries = 0;
    ctx->key_tries = 0;
    pf_mbedtls_mpi_init(&ctx->k);
    pf_mbedtls_mpi_init(&ctx->r);
    ctx->state = ecdsa_sig_init;
}

/*
 * Free the components of a sign restart sub-context
 */
static void ecdsa_restart_sig_free(pf_mbedtls_ecdsa_restart_sig_ctx *ctx)
{
    if (ctx == NULL) {
        return;
    }

    pf_mbedtls_mpi_free(&ctx->k);
    pf_mbedtls_mpi_free(&ctx->r);
}

#if defined(PF_MBEDTLS_ECDSA_DETERMINISTIC)
/*
 * Sub-context for ecdsa_sign_det()
 */
struct pf_mbedtls_ecdsa_restart_det {
    pf_mbedtls_hmac_drbg_context rng_ctx;  /* DRBG state   */
    enum {                      /* what to do next?     */
        ecdsa_det_init = 0,     /* getting started      */
        ecdsa_det_sign,         /* make signature       */
    } state;
};

/*
 * Init verify sign_det sub-context
 */
static void ecdsa_restart_det_init(pf_mbedtls_ecdsa_restart_det_ctx *ctx)
{
    pf_mbedtls_hmac_drbg_init(&ctx->rng_ctx);
    ctx->state = ecdsa_det_init;
}

/*
 * Free the components of a sign_det restart sub-context
 */
static void ecdsa_restart_det_free(pf_mbedtls_ecdsa_restart_det_ctx *ctx)
{
    if (ctx == NULL) {
        return;
    }

    pf_mbedtls_hmac_drbg_free(&ctx->rng_ctx);

    ecdsa_restart_det_init(ctx);
}
#endif /* MBEDTLS_ECDSA_DETERMINISTIC */

#define ECDSA_RS_ECP    (rs_ctx == NULL ? NULL : &rs_ctx->ecp)

/* Utility macro for checking and updating ops budget */
#define ECDSA_BUDGET(ops)   \
    PF_MBEDTLS_MPI_CHK(pf_mbedtls_ecp_check_budget(grp, ECDSA_RS_ECP, ops));

/* Call this when entering a function that needs its own sub-context */
#define ECDSA_RS_ENTER(SUB)   do {                                 \
        /* reset ops count for this call if top-level */                 \
        if (rs_ctx != NULL && rs_ctx->ecp.depth++ == 0)                 \
        rs_ctx->ecp.ops_done = 0;                                    \
                                                                     \
        /* set up our own sub-context if needed */                       \
        if (pf_mbedtls_ecp_restart_is_enabled() &&                          \
            rs_ctx != NULL && rs_ctx->SUB == NULL)                      \
        {                                                                \
            rs_ctx->SUB = pf_mbedtls_calloc(1, sizeof(*rs_ctx->SUB));   \
            if (rs_ctx->SUB == NULL)                                    \
            return PF_MBEDTLS_ERR_ECP_ALLOC_FAILED;                  \
                                                                   \
            ecdsa_restart_## SUB ##_init(rs_ctx->SUB);                 \
        }                                                                \
} while (0)

/* Call this when leaving a function that needs its own sub-context */
#define ECDSA_RS_LEAVE(SUB)   do {                                 \
        /* clear our sub-context when not in progress (done or error) */ \
        if (rs_ctx != NULL && rs_ctx->SUB != NULL &&                     \
            ret != PF_MBEDTLS_ERR_ECP_IN_PROGRESS)                         \
        {                                                                \
            ecdsa_restart_## SUB ##_free(rs_ctx->SUB);                 \
            pf_mbedtls_free(rs_ctx->SUB);                                 \
            rs_ctx->SUB = NULL;                                          \
        }                                                                \
                                                                     \
        if (rs_ctx != NULL)                                             \
        rs_ctx->ecp.depth--;                                         \
} while (0)

#else /* MBEDTLS_ECP_RESTARTABLE */

#define ECDSA_RS_ECP    NULL

#define ECDSA_BUDGET(ops)     /* no-op; for compatibility */

#define ECDSA_RS_ENTER(SUB)   (void) rs_ctx
#define ECDSA_RS_LEAVE(SUB)   (void) rs_ctx

#endif /* MBEDTLS_ECP_RESTARTABLE */

#if defined(PF_MBEDTLS_ECDSA_DETERMINISTIC) || \
    !defined(PF_MBEDTLS_ECDSA_SIGN_ALT)     || \
    !defined(PF_MBEDTLS_ECDSA_VERIFY_ALT)
/*
 * Derive a suitable integer for group grp from a buffer of length len
 * SEC1 4.1.3 step 5 aka SEC1 4.1.4 step 3
 */
static int derive_mpi(const pf_mbedtls_ecp_group *grp, pf_mbedtls_mpi *x,
                      const unsigned char *buf, size_t blen)
{
    int ret = PF_MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    size_t n_size = (grp->nbits + 7) / 8;
    size_t use_size = blen > n_size ? n_size : blen;

    PF_MBEDTLS_MPI_CHK(pf_mbedtls_mpi_read_binary(x, buf, use_size));
    if (use_size * 8 > grp->nbits) {
        PF_MBEDTLS_MPI_CHK(pf_mbedtls_mpi_shift_r(x, use_size * 8 - grp->nbits));
    }

    /* While at it, reduce modulo N */
    if (pf_mbedtls_mpi_cmp_mpi(x, &grp->N) >= 0) {
        PF_MBEDTLS_MPI_CHK(pf_mbedtls_mpi_sub_mpi(x, x, &grp->N));
    }

cleanup:
    return ret;
}
#endif /* ECDSA_DETERMINISTIC || !ECDSA_SIGN_ALT || !ECDSA_VERIFY_ALT */

int pf_mbedtls_ecdsa_can_do(pf_mbedtls_ecp_group_id gid)
{
    switch (gid) {
#ifdef PF_MBEDTLS_ECP_DP_CURVE25519_ENABLED
        case PF_MBEDTLS_ECP_DP_CURVE25519: return 0;
#endif
#ifdef PF_MBEDTLS_ECP_DP_CURVE448_ENABLED
        case PF_MBEDTLS_ECP_DP_CURVE448: return 0;
#endif
        default: return 1;
    }
}

#if !defined(PF_MBEDTLS_ECDSA_SIGN_ALT)
/*
 * Compute ECDSA signature of a hashed message (SEC1 4.1.3)
 * Obviously, compared to SEC1 4.1.3, we skip step 4 (hash message)
 */
int pf_mbedtls_ecdsa_sign_restartable(pf_mbedtls_ecp_group *grp,
                                   pf_mbedtls_mpi *r, pf_mbedtls_mpi *s,
                                   const pf_mbedtls_mpi *d, const unsigned char *buf, size_t blen,
                                   int (*f_rng)(void *, unsigned char *, size_t), void *p_rng,
                                   int (*f_rng_blind)(void *, unsigned char *, size_t),
                                   void *p_rng_blind,
                                   pf_mbedtls_ecdsa_restart_ctx *rs_ctx)
{
    int ret, key_tries, sign_tries;
    int *p_sign_tries = &sign_tries, *p_key_tries = &key_tries;
    pf_mbedtls_ecp_point R;
    pf_mbedtls_mpi k, e;
    pf_mbedtls_mpi *pk = &k, *pr = r;

    /* Fail cleanly on curves such as Curve25519 that can't be used for ECDSA */
    if (!pf_mbedtls_ecdsa_can_do(grp->id) || grp->N.p == NULL) {
        return PF_MBEDTLS_ERR_ECP_BAD_INPUT_DATA;
    }

    /* Make sure d is in range 1..n-1 */
    if (pf_mbedtls_mpi_cmp_int(d, 1) < 0 || pf_mbedtls_mpi_cmp_mpi(d, &grp->N) >= 0) {
        return PF_MBEDTLS_ERR_ECP_INVALID_KEY;
    }

    pf_mbedtls_ecp_point_init(&R);
    pf_mbedtls_mpi_init(&k); pf_mbedtls_mpi_init(&e);

    ECDSA_RS_ENTER(sig);

#if defined(PF_MBEDTLS_ECP_RESTARTABLE)
    if (rs_ctx != NULL && rs_ctx->sig != NULL) {
        /* redirect to our context */
        p_sign_tries = &rs_ctx->sig->sign_tries;
        p_key_tries = &rs_ctx->sig->key_tries;
        pk = &rs_ctx->sig->k;
        pr = &rs_ctx->sig->r;

        /* jump to current step */
        if (rs_ctx->sig->state == ecdsa_sig_mul) {
            goto mul;
        }
        if (rs_ctx->sig->state == ecdsa_sig_modn) {
            goto modn;
        }
    }
#endif /* MBEDTLS_ECP_RESTARTABLE */

    *p_sign_tries = 0;
    do {
        if ((*p_sign_tries)++ > 10) {
            ret = PF_MBEDTLS_ERR_ECP_RANDOM_FAILED;
            goto cleanup;
        }

        /*
         * Steps 1-3: generate a suitable ephemeral keypair
         * and set r = xR mod n
         */
        *p_key_tries = 0;
        do {
            if ((*p_key_tries)++ > 10) {
                ret = PF_MBEDTLS_ERR_ECP_RANDOM_FAILED;
                goto cleanup;
            }

            PF_MBEDTLS_MPI_CHK(pf_mbedtls_ecp_gen_privkey(grp, pk, f_rng, p_rng));

#if defined(PF_MBEDTLS_ECP_RESTARTABLE)
            if (rs_ctx != NULL && rs_ctx->sig != NULL) {
                rs_ctx->sig->state = ecdsa_sig_mul;
            }

mul:
#endif
            PF_MBEDTLS_MPI_CHK(pf_mbedtls_ecp_mul_restartable(grp, &R, pk, &grp->G,
                                                        f_rng_blind,
                                                        p_rng_blind,
                                                        ECDSA_RS_ECP));
            PF_MBEDTLS_MPI_CHK(pf_mbedtls_mpi_mod_mpi(pr, &R.X, &grp->N));
        } while (pf_mbedtls_mpi_cmp_int(pr, 0) == 0);

#if defined(PF_MBEDTLS_ECP_RESTARTABLE)
        if (rs_ctx != NULL && rs_ctx->sig != NULL) {
            rs_ctx->sig->state = ecdsa_sig_modn;
        }

modn:
#endif
        /*
         * Accounting for everything up to the end of the loop
         * (step 6, but checking now avoids saving e and t)
         */
        ECDSA_BUDGET(PF_MBEDTLS_ECP_OPS_INV + 4);

        /*
         * Step 5: derive MPI from hashed message
         */
        PF_MBEDTLS_MPI_CHK(derive_mpi(grp, &e, buf, blen));

        /*
         * Step 6: compute s = (e + r * d) / k
         */
        PF_MBEDTLS_MPI_CHK(pf_mbedtls_mpi_mul_mpi(s, pr, d));
        PF_MBEDTLS_MPI_CHK(pf_mbedtls_mpi_add_mpi(&e, &e, s));
        PF_MBEDTLS_MPI_CHK(pf_mbedtls_mpi_gcd_modinv_odd(NULL, s, pk, &grp->N));
        PF_MBEDTLS_MPI_CHK(pf_mbedtls_mpi_mul_mpi(s, s, &e));
        PF_MBEDTLS_MPI_CHK(pf_mbedtls_mpi_mod_mpi(s, s, &grp->N));
    } while (pf_mbedtls_mpi_cmp_int(s, 0) == 0);

#if defined(PF_MBEDTLS_ECP_RESTARTABLE)
    if (rs_ctx != NULL && rs_ctx->sig != NULL) {
        PF_MBEDTLS_MPI_CHK(pf_mbedtls_mpi_copy(r, pr));
    }
#endif

cleanup:
    pf_mbedtls_ecp_point_free(&R);
    pf_mbedtls_mpi_free(&k); pf_mbedtls_mpi_free(&e);

    ECDSA_RS_LEAVE(sig);

    return ret;
}

/*
 * Compute ECDSA signature of a hashed message
 */
int pf_mbedtls_ecdsa_sign(pf_mbedtls_ecp_group *grp, pf_mbedtls_mpi *r, pf_mbedtls_mpi *s,
                       const pf_mbedtls_mpi *d, const unsigned char *buf, size_t blen,
                       int (*f_rng)(void *, unsigned char *, size_t), void *p_rng)
{
    /* Use the same RNG for both blinding and ephemeral key generation */
    return pf_mbedtls_ecdsa_sign_restartable(grp, r, s, d, buf, blen,
                                          f_rng, p_rng, f_rng, p_rng, NULL);
}
#endif /* !MBEDTLS_ECDSA_SIGN_ALT */

#if defined(PF_MBEDTLS_ECDSA_DETERMINISTIC)
/*
 * Deterministic signature wrapper
 *
 * note:    The f_rng_blind parameter must not be NULL.
 *
 */
int pf_mbedtls_ecdsa_sign_det_restartable(pf_mbedtls_ecp_group *grp,
                                       pf_mbedtls_mpi *r, pf_mbedtls_mpi *s,
                                       const pf_mbedtls_mpi *d, const unsigned char *buf, size_t blen,
                                       pf_mbedtls_md_type_t md_alg,
                                       int (*f_rng_blind)(void *, unsigned char *, size_t),
                                       void *p_rng_blind,
                                       pf_mbedtls_ecdsa_restart_ctx *rs_ctx)
{
    int ret = PF_MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    pf_mbedtls_hmac_drbg_context rng_ctx;
    pf_mbedtls_hmac_drbg_context *p_rng = &rng_ctx;
    unsigned char data[2 * PF_MBEDTLS_ECP_MAX_BYTES];
    size_t grp_len = (grp->nbits + 7) / 8;
    const pf_mbedtls_md_info_t *md_info;
    pf_mbedtls_mpi h;

    if ((md_info = pf_mbedtls_md_info_from_type(md_alg)) == NULL) {
        return PF_MBEDTLS_ERR_ECP_BAD_INPUT_DATA;
    }

    pf_mbedtls_mpi_init(&h);
    pf_mbedtls_hmac_drbg_init(&rng_ctx);

    ECDSA_RS_ENTER(det);

#if defined(PF_MBEDTLS_ECP_RESTARTABLE)
    if (rs_ctx != NULL && rs_ctx->det != NULL) {
        /* redirect to our context */
        p_rng = &rs_ctx->det->rng_ctx;

        /* jump to current step */
        if (rs_ctx->det->state == ecdsa_det_sign) {
            goto sign;
        }
    }
#endif /* MBEDTLS_ECP_RESTARTABLE */

    /* Use private key and message hash (reduced) to initialize HMAC_DRBG */
    PF_MBEDTLS_MPI_CHK(pf_mbedtls_mpi_write_binary(d, data, grp_len));
    PF_MBEDTLS_MPI_CHK(derive_mpi(grp, &h, buf, blen));
    PF_MBEDTLS_MPI_CHK(pf_mbedtls_mpi_write_binary(&h, data + grp_len, grp_len));
    PF_MBEDTLS_MPI_CHK(pf_mbedtls_hmac_drbg_seed_buf(p_rng, md_info, data, 2 * grp_len));

#if defined(PF_MBEDTLS_ECP_RESTARTABLE)
    if (rs_ctx != NULL && rs_ctx->det != NULL) {
        rs_ctx->det->state = ecdsa_det_sign;
    }

sign:
#endif
#if defined(PF_MBEDTLS_ECDSA_SIGN_ALT)
    (void) f_rng_blind;
    (void) p_rng_blind;
    ret = pf_mbedtls_ecdsa_sign(grp, r, s, d, buf, blen,
                             pf_mbedtls_hmac_drbg_random, p_rng);
#else
    ret = pf_mbedtls_ecdsa_sign_restartable(grp, r, s, d, buf, blen,
                                         pf_mbedtls_hmac_drbg_random, p_rng,
                                         f_rng_blind, p_rng_blind, rs_ctx);
#endif /* MBEDTLS_ECDSA_SIGN_ALT */

cleanup:
    pf_mbedtls_hmac_drbg_free(&rng_ctx);
    pf_mbedtls_mpi_free(&h);

    ECDSA_RS_LEAVE(det);

    return ret;
}

/*
 * Deterministic signature wrapper
 */
int pf_mbedtls_ecdsa_sign_det_ext(pf_mbedtls_ecp_group *grp, pf_mbedtls_mpi *r,
                               pf_mbedtls_mpi *s, const pf_mbedtls_mpi *d,
                               const unsigned char *buf, size_t blen,
                               pf_mbedtls_md_type_t md_alg,
                               int (*f_rng_blind)(void *, unsigned char *,
                                                  size_t),
                               void *p_rng_blind)
{
    return pf_mbedtls_ecdsa_sign_det_restartable(grp, r, s, d, buf, blen, md_alg,
                                              f_rng_blind, p_rng_blind, NULL);
}
#endif /* MBEDTLS_ECDSA_DETERMINISTIC */

#if !defined(PF_MBEDTLS_ECDSA_VERIFY_ALT)
/*
 * Verify ECDSA signature of hashed message (SEC1 4.1.4)
 * Obviously, compared to SEC1 4.1.3, we skip step 2 (hash message)
 */
int pf_mbedtls_ecdsa_verify_restartable(pf_mbedtls_ecp_group *grp,
                                     const unsigned char *buf, size_t blen,
                                     const pf_mbedtls_ecp_point *Q,
                                     const pf_mbedtls_mpi *r,
                                     const pf_mbedtls_mpi *s,
                                     pf_mbedtls_ecdsa_restart_ctx *rs_ctx)
{
    int ret = PF_MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    pf_mbedtls_mpi e, s_inv, u1, u2;
    pf_mbedtls_ecp_point R;
    pf_mbedtls_mpi *pu1 = &u1, *pu2 = &u2;

    pf_mbedtls_ecp_point_init(&R);
    pf_mbedtls_mpi_init(&e); pf_mbedtls_mpi_init(&s_inv);
    pf_mbedtls_mpi_init(&u1); pf_mbedtls_mpi_init(&u2);

    /* Fail cleanly on curves such as Curve25519 that can't be used for ECDSA */
    if (!pf_mbedtls_ecdsa_can_do(grp->id) || grp->N.p == NULL) {
        return PF_MBEDTLS_ERR_ECP_BAD_INPUT_DATA;
    }

    ECDSA_RS_ENTER(ver);

#if defined(PF_MBEDTLS_ECP_RESTARTABLE)
    if (rs_ctx != NULL && rs_ctx->ver != NULL) {
        /* redirect to our context */
        pu1 = &rs_ctx->ver->u1;
        pu2 = &rs_ctx->ver->u2;

        /* jump to current step */
        if (rs_ctx->ver->state == ecdsa_ver_muladd) {
            goto muladd;
        }
    }
#endif /* MBEDTLS_ECP_RESTARTABLE */

    /*
     * Step 1: make sure r and s are in range 1..n-1
     */
    if (pf_mbedtls_mpi_cmp_int(r, 1) < 0 || pf_mbedtls_mpi_cmp_mpi(r, &grp->N) >= 0 ||
        pf_mbedtls_mpi_cmp_int(s, 1) < 0 || pf_mbedtls_mpi_cmp_mpi(s, &grp->N) >= 0) {
        ret = PF_MBEDTLS_ERR_ECP_VERIFY_FAILED;
        goto cleanup;
    }

    /*
     * Step 3: derive MPI from hashed message
     */
    PF_MBEDTLS_MPI_CHK(derive_mpi(grp, &e, buf, blen));

    /*
     * Step 4: u1 = e / s mod n, u2 = r / s mod n
     */
    ECDSA_BUDGET(PF_MBEDTLS_ECP_OPS_CHK + PF_MBEDTLS_ECP_OPS_INV + 2);

    PF_MBEDTLS_MPI_CHK(pf_mbedtls_mpi_gcd_modinv_odd(NULL, &s_inv, s, &grp->N));

    PF_MBEDTLS_MPI_CHK(pf_mbedtls_mpi_mul_mpi(pu1, &e, &s_inv));
    PF_MBEDTLS_MPI_CHK(pf_mbedtls_mpi_mod_mpi(pu1, pu1, &grp->N));

    PF_MBEDTLS_MPI_CHK(pf_mbedtls_mpi_mul_mpi(pu2, r, &s_inv));
    PF_MBEDTLS_MPI_CHK(pf_mbedtls_mpi_mod_mpi(pu2, pu2, &grp->N));

#if defined(PF_MBEDTLS_ECP_RESTARTABLE)
    if (rs_ctx != NULL && rs_ctx->ver != NULL) {
        rs_ctx->ver->state = ecdsa_ver_muladd;
    }

muladd:
#endif
    /*
     * Step 5: R = u1 G + u2 Q
     */
    PF_MBEDTLS_MPI_CHK(pf_mbedtls_ecp_muladd_restartable(grp,
                                                   &R, pu1, &grp->G, pu2, Q, ECDSA_RS_ECP));

    if (pf_mbedtls_ecp_is_zero_ext(grp, &R)) {
        ret = PF_MBEDTLS_ERR_ECP_VERIFY_FAILED;
        goto cleanup;
    }

    /*
     * Step 6: convert xR to an integer (no-op)
     * Step 7: reduce xR mod n (gives v)
     */
    PF_MBEDTLS_MPI_CHK(pf_mbedtls_mpi_mod_mpi(&R.X, &R.X, &grp->N));

    /*
     * Step 8: check if v (that is, R.X) is equal to r
     */
    if (pf_mbedtls_mpi_cmp_mpi(&R.X, r) != 0) {
        ret = PF_MBEDTLS_ERR_ECP_VERIFY_FAILED;
        goto cleanup;
    }

cleanup:
    pf_mbedtls_ecp_point_free(&R);
    pf_mbedtls_mpi_free(&e); pf_mbedtls_mpi_free(&s_inv);
    pf_mbedtls_mpi_free(&u1); pf_mbedtls_mpi_free(&u2);

    ECDSA_RS_LEAVE(ver);

    return ret;
}

/*
 * Verify ECDSA signature of hashed message
 */
int pf_mbedtls_ecdsa_verify(pf_mbedtls_ecp_group *grp,
                         const unsigned char *buf, size_t blen,
                         const pf_mbedtls_ecp_point *Q,
                         const pf_mbedtls_mpi *r,
                         const pf_mbedtls_mpi *s)
{
    return pf_mbedtls_ecdsa_verify_restartable(grp, buf, blen, Q, r, s, NULL);
}
#endif /* !MBEDTLS_ECDSA_VERIFY_ALT */

/*
 * Convert a signature (given by context) to ASN.1
 */
static int ecdsa_signature_to_asn1(const pf_mbedtls_mpi *r, const pf_mbedtls_mpi *s,
                                   unsigned char *sig, size_t sig_size,
                                   size_t *slen)
{
    int ret = PF_MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    unsigned char buf[PF_MBEDTLS_ECDSA_MAX_LEN] = { 0 };
    unsigned char *p = buf + sizeof(buf);
    size_t len = 0;

    PF_MBEDTLS_ASN1_CHK_ADD(len, pf_mbedtls_asn1_write_mpi(&p, buf, s));
    PF_MBEDTLS_ASN1_CHK_ADD(len, pf_mbedtls_asn1_write_mpi(&p, buf, r));

    PF_MBEDTLS_ASN1_CHK_ADD(len, pf_mbedtls_asn1_write_len(&p, buf, len));
    PF_MBEDTLS_ASN1_CHK_ADD(len, pf_mbedtls_asn1_write_tag(&p, buf,
                                                     PF_MBEDTLS_ASN1_CONSTRUCTED |
                                                     PF_MBEDTLS_ASN1_SEQUENCE));

    if (len > sig_size) {
        return PF_MBEDTLS_ERR_ECP_BUFFER_TOO_SMALL;
    }

    memcpy(sig, p, len);
    *slen = len;

    return 0;
}

/*
 * Compute and write signature
 */
int pf_mbedtls_ecdsa_write_signature_restartable(pf_mbedtls_ecdsa_context *ctx,
                                              pf_mbedtls_md_type_t md_alg,
                                              const unsigned char *hash, size_t hlen,
                                              unsigned char *sig, size_t sig_size, size_t *slen,
                                              int (*f_rng)(void *, unsigned char *, size_t),
                                              void *p_rng,
                                              pf_mbedtls_ecdsa_restart_ctx *rs_ctx)
{
    int ret = PF_MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    pf_mbedtls_mpi r, s;
    if (f_rng == NULL) {
        return PF_MBEDTLS_ERR_ECP_BAD_INPUT_DATA;
    }

    pf_mbedtls_mpi_init(&r);
    pf_mbedtls_mpi_init(&s);

#if defined(PF_MBEDTLS_ECDSA_DETERMINISTIC)
    PF_MBEDTLS_MPI_CHK(pf_mbedtls_ecdsa_sign_det_restartable(&ctx->grp, &r, &s, &ctx->d,
                                                       hash, hlen, md_alg, f_rng,
                                                       p_rng, rs_ctx));
#else
    (void) md_alg;

#if defined(PF_MBEDTLS_ECDSA_SIGN_ALT)
    (void) rs_ctx;

    PF_MBEDTLS_MPI_CHK(pf_mbedtls_ecdsa_sign(&ctx->grp, &r, &s, &ctx->d,
                                       hash, hlen, f_rng, p_rng));
#else
    /* Use the same RNG for both blinding and ephemeral key generation */
    PF_MBEDTLS_MPI_CHK(pf_mbedtls_ecdsa_sign_restartable(&ctx->grp, &r, &s, &ctx->d,
                                                   hash, hlen, f_rng, p_rng, f_rng,
                                                   p_rng, rs_ctx));
#endif /* MBEDTLS_ECDSA_SIGN_ALT */
#endif /* MBEDTLS_ECDSA_DETERMINISTIC */

    PF_MBEDTLS_MPI_CHK(ecdsa_signature_to_asn1(&r, &s, sig, sig_size, slen));

cleanup:
    pf_mbedtls_mpi_free(&r);
    pf_mbedtls_mpi_free(&s);

    return ret;
}

/*
 * Compute and write signature
 */
int pf_mbedtls_ecdsa_write_signature(pf_mbedtls_ecdsa_context *ctx,
                                  pf_mbedtls_md_type_t md_alg,
                                  const unsigned char *hash, size_t hlen,
                                  unsigned char *sig, size_t sig_size, size_t *slen,
                                  int (*f_rng)(void *, unsigned char *, size_t),
                                  void *p_rng)
{
    return pf_mbedtls_ecdsa_write_signature_restartable(
        ctx, md_alg, hash, hlen, sig, sig_size, slen,
        f_rng, p_rng, NULL);
}

/*
 * Read and check signature
 */
int pf_mbedtls_ecdsa_read_signature(pf_mbedtls_ecdsa_context *ctx,
                                 const unsigned char *hash, size_t hlen,
                                 const unsigned char *sig, size_t slen)
{
    return pf_mbedtls_ecdsa_read_signature_restartable(
        ctx, hash, hlen, sig, slen, NULL);
}

/*
 * Restartable read and check signature
 */
int pf_mbedtls_ecdsa_read_signature_restartable(pf_mbedtls_ecdsa_context *ctx,
                                             const unsigned char *hash, size_t hlen,
                                             const unsigned char *sig, size_t slen,
                                             pf_mbedtls_ecdsa_restart_ctx *rs_ctx)
{
    int ret = PF_MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    unsigned char *p = (unsigned char *) sig;
    const unsigned char *end = sig + slen;
    size_t len;
    pf_mbedtls_mpi r, s;
    pf_mbedtls_mpi_init(&r);
    pf_mbedtls_mpi_init(&s);

    if ((ret = pf_mbedtls_asn1_get_tag(&p, end, &len,
                                    PF_MBEDTLS_ASN1_CONSTRUCTED | PF_MBEDTLS_ASN1_SEQUENCE)) != 0) {
        ret += PF_MBEDTLS_ERR_ECP_BAD_INPUT_DATA;
        goto cleanup;
    }

    if (p + len != end) {
        ret = PF_MBEDTLS_ERROR_ADD(PF_MBEDTLS_ERR_ECP_BAD_INPUT_DATA,
                                PF_MBEDTLS_ERR_ASN1_LENGTH_MISMATCH);
        goto cleanup;
    }

    if ((ret = pf_mbedtls_asn1_get_mpi(&p, end, &r)) != 0 ||
        (ret = pf_mbedtls_asn1_get_mpi(&p, end, &s)) != 0) {
        ret += PF_MBEDTLS_ERR_ECP_BAD_INPUT_DATA;
        goto cleanup;
    }
#if defined(PF_MBEDTLS_ECDSA_VERIFY_ALT)
    (void) rs_ctx;

    if ((ret = pf_mbedtls_ecdsa_verify(&ctx->grp, hash, hlen,
                                    &ctx->Q, &r, &s)) != 0) {
        goto cleanup;
    }
#else
    if ((ret = pf_mbedtls_ecdsa_verify_restartable(&ctx->grp, hash, hlen,
                                                &ctx->Q, &r, &s, rs_ctx)) != 0) {
        goto cleanup;
    }
#endif /* MBEDTLS_ECDSA_VERIFY_ALT */

    /* At this point we know that the buffer starts with a valid signature.
     * Return 0 if the buffer just contains the signature, and a specific
     * error code if the valid signature is followed by more data. */
    if (p != end) {
        ret = PF_MBEDTLS_ERR_ECP_SIG_LEN_MISMATCH;
    }

cleanup:
    pf_mbedtls_mpi_free(&r);
    pf_mbedtls_mpi_free(&s);

    return ret;
}

#if !defined(PF_MBEDTLS_ECDSA_GENKEY_ALT)
/*
 * Generate key pair
 */
int pf_mbedtls_ecdsa_genkey(pf_mbedtls_ecdsa_context *ctx, pf_mbedtls_ecp_group_id gid,
                         int (*f_rng)(void *, unsigned char *, size_t), void *p_rng)
{
    int ret = 0;
    ret = pf_mbedtls_ecp_group_load(&ctx->grp, gid);
    if (ret != 0) {
        return ret;
    }

    return pf_mbedtls_ecp_gen_keypair(&ctx->grp, &ctx->d,
                                   &ctx->Q, f_rng, p_rng);
}
#endif /* !MBEDTLS_ECDSA_GENKEY_ALT */

/*
 * Set context from an mbedtls_ecp_keypair
 */
int pf_mbedtls_ecdsa_from_keypair(pf_mbedtls_ecdsa_context *ctx, const pf_mbedtls_ecp_keypair *key)
{
    int ret = PF_MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    if ((ret = pf_mbedtls_ecp_group_copy(&ctx->grp, &key->grp)) != 0 ||
        (ret = pf_mbedtls_mpi_copy(&ctx->d, &key->d)) != 0 ||
        (ret = pf_mbedtls_ecp_copy(&ctx->Q, &key->Q)) != 0) {
        pf_mbedtls_ecdsa_free(ctx);
    }

    return ret;
}

/*
 * Initialize context
 */
void pf_mbedtls_ecdsa_init(pf_mbedtls_ecdsa_context *ctx)
{
    pf_mbedtls_ecp_keypair_init(ctx);
}

/*
 * Free context
 */
void pf_mbedtls_ecdsa_free(pf_mbedtls_ecdsa_context *ctx)
{
    if (ctx == NULL) {
        return;
    }

    pf_mbedtls_ecp_keypair_free(ctx);
}

#if defined(PF_MBEDTLS_ECP_RESTARTABLE)
/*
 * Initialize a restart context
 */
void pf_mbedtls_ecdsa_restart_init(pf_mbedtls_ecdsa_restart_ctx *ctx)
{
    pf_mbedtls_ecp_restart_init(&ctx->ecp);

    ctx->ver = NULL;
    ctx->sig = NULL;
#if defined(PF_MBEDTLS_ECDSA_DETERMINISTIC)
    ctx->det = NULL;
#endif
}

/*
 * Free the components of a restart context
 */
void pf_mbedtls_ecdsa_restart_free(pf_mbedtls_ecdsa_restart_ctx *ctx)
{
    if (ctx == NULL) {
        return;
    }

    pf_mbedtls_ecp_restart_free(&ctx->ecp);

    ecdsa_restart_ver_free(ctx->ver);
    pf_mbedtls_free(ctx->ver);
    ctx->ver = NULL;

    ecdsa_restart_sig_free(ctx->sig);
    pf_mbedtls_free(ctx->sig);
    ctx->sig = NULL;

#if defined(PF_MBEDTLS_ECDSA_DETERMINISTIC)
    ecdsa_restart_det_free(ctx->det);
    pf_mbedtls_free(ctx->det);
    ctx->det = NULL;
#endif
}
#endif /* MBEDTLS_ECP_RESTARTABLE */

#endif /* MBEDTLS_ECDSA_C */
