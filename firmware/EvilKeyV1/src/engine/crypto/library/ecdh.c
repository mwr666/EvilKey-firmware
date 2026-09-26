#include "../../../pf_build_config.h"
/*
 *  Elliptic curve Diffie-Hellman
 *
 *  Copyright The Mbed TLS Contributors
 *  SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
 */

/*
 * References:
 *
 * SEC1 https://www.secg.org/sec1-v2.pdf
 * RFC 4492
 */

#include "common.h"

#if defined(PF_MBEDTLS_ECDH_C)

#include "../include/mbedtls/ecdh.h"
#include "../include/mbedtls/platform_util.h"
#include "../include/mbedtls/error.h"

#include <string.h>

#if defined(PF_MBEDTLS_ECDH_LEGACY_CONTEXT)
typedef pf_mbedtls_ecdh_context pf_mbedtls_ecdh_context_mbed;
#endif

static pf_mbedtls_ecp_group_id pf_mbedtls_ecdh_grp_id(
    const pf_mbedtls_ecdh_context *ctx)
{
#if defined(PF_MBEDTLS_ECDH_LEGACY_CONTEXT)
    return ctx->grp.id;
#else
    return ctx->grp_id;
#endif
}

int pf_mbedtls_ecdh_can_do(pf_mbedtls_ecp_group_id gid)
{
    /* At this time, all groups support ECDH. */
    (void) gid;
    return 1;
}

#if !defined(PF_MBEDTLS_ECDH_GEN_PUBLIC_ALT)
/*
 * Generate public key (restartable version)
 *
 * Note: this internal function relies on its caller preserving the value of
 * the output parameter 'd' across continuation calls. This would not be
 * acceptable for a public function but is OK here as we control call sites.
 */
static int ecdh_gen_public_restartable(pf_mbedtls_ecp_group *grp,
                                       pf_mbedtls_mpi *d, pf_mbedtls_ecp_point *Q,
                                       int (*f_rng)(void *, unsigned char *, size_t),
                                       void *p_rng,
                                       pf_mbedtls_ecp_restart_ctx *rs_ctx)
{
    int ret = PF_MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;

    int restarting = 0;
#if defined(PF_MBEDTLS_ECP_RESTARTABLE)
    restarting = (rs_ctx != NULL && rs_ctx->rsm != NULL);
#endif
    /* If multiplication is in progress, we already generated a privkey */
    if (!restarting) {
        PF_MBEDTLS_MPI_CHK(pf_mbedtls_ecp_gen_privkey(grp, d, f_rng, p_rng));
    }

    PF_MBEDTLS_MPI_CHK(pf_mbedtls_ecp_mul_restartable(grp, Q, d, &grp->G,
                                                f_rng, p_rng, rs_ctx));

cleanup:
    return ret;
}

/*
 * Generate public key
 */
int pf_mbedtls_ecdh_gen_public(pf_mbedtls_ecp_group *grp, pf_mbedtls_mpi *d, pf_mbedtls_ecp_point *Q,
                            int (*f_rng)(void *, unsigned char *, size_t),
                            void *p_rng)
{
    return ecdh_gen_public_restartable(grp, d, Q, f_rng, p_rng, NULL);
}
#endif /* !MBEDTLS_ECDH_GEN_PUBLIC_ALT */

#if !defined(PF_MBEDTLS_ECDH_COMPUTE_SHARED_ALT)
/*
 * Compute shared secret (SEC1 3.3.1)
 */
static int ecdh_compute_shared_restartable(pf_mbedtls_ecp_group *grp,
                                           pf_mbedtls_mpi *z,
                                           const pf_mbedtls_ecp_point *Q, const pf_mbedtls_mpi *d,
                                           int (*f_rng)(void *, unsigned char *, size_t),
                                           void *p_rng,
                                           pf_mbedtls_ecp_restart_ctx *rs_ctx)
{
    int ret = PF_MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    pf_mbedtls_ecp_point P;

    pf_mbedtls_ecp_point_init(&P);

    PF_MBEDTLS_MPI_CHK(pf_mbedtls_ecp_mul_restartable(grp, &P, d, Q,
                                                f_rng, p_rng, rs_ctx));

    if (pf_mbedtls_ecp_is_zero_ext(grp, &P)) {
        ret = PF_MBEDTLS_ERR_ECP_BAD_INPUT_DATA;
        goto cleanup;
    }

    PF_MBEDTLS_MPI_CHK(pf_mbedtls_mpi_copy(z, &P.X));

cleanup:
    pf_mbedtls_ecp_point_free(&P);

    return ret;
}

/*
 * Compute shared secret (SEC1 3.3.1)
 */
int pf_mbedtls_ecdh_compute_shared(pf_mbedtls_ecp_group *grp, pf_mbedtls_mpi *z,
                                const pf_mbedtls_ecp_point *Q, const pf_mbedtls_mpi *d,
                                int (*f_rng)(void *, unsigned char *, size_t),
                                void *p_rng)
{
    return ecdh_compute_shared_restartable(grp, z, Q, d,
                                           f_rng, p_rng, NULL);
}
#endif /* !MBEDTLS_ECDH_COMPUTE_SHARED_ALT */

static void ecdh_init_internal(pf_mbedtls_ecdh_context_mbed *ctx)
{
    pf_mbedtls_ecp_group_init(&ctx->grp);
    pf_mbedtls_mpi_init(&ctx->d);
    pf_mbedtls_ecp_point_init(&ctx->Q);
    pf_mbedtls_ecp_point_init(&ctx->Qp);
    pf_mbedtls_mpi_init(&ctx->z);

#if defined(PF_MBEDTLS_ECP_RESTARTABLE)
    pf_mbedtls_ecp_restart_init(&ctx->rs);
#endif
}

pf_mbedtls_ecp_group_id pf_mbedtls_ecdh_get_grp_id(pf_mbedtls_ecdh_context *ctx)
{
#if defined(PF_MBEDTLS_ECDH_LEGACY_CONTEXT)
    return ctx->PF_MBEDTLS_PRIVATE(grp).id;
#else
    return ctx->PF_MBEDTLS_PRIVATE(grp_id);
#endif
}

/*
 * Initialize context
 */
void pf_mbedtls_ecdh_init(pf_mbedtls_ecdh_context *ctx)
{
#if defined(PF_MBEDTLS_ECDH_LEGACY_CONTEXT)
    ecdh_init_internal(ctx);
    pf_mbedtls_ecp_point_init(&ctx->Vi);
    pf_mbedtls_ecp_point_init(&ctx->Vf);
    pf_mbedtls_mpi_init(&ctx->_d);
#else
    memset(ctx, 0, sizeof(pf_mbedtls_ecdh_context));

    ctx->var = PF_MBEDTLS_ECDH_VARIANT_NONE;
#endif
    ctx->point_format = PF_MBEDTLS_ECP_PF_UNCOMPRESSED;
#if defined(PF_MBEDTLS_ECP_RESTARTABLE)
    ctx->restart_enabled = 0;
#endif
}

static int ecdh_setup_internal(pf_mbedtls_ecdh_context_mbed *ctx,
                               pf_mbedtls_ecp_group_id grp_id)
{
    int ret = PF_MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;

    ret = pf_mbedtls_ecp_group_load(&ctx->grp, grp_id);
    if (ret != 0) {
        return PF_MBEDTLS_ERR_ECP_FEATURE_UNAVAILABLE;
    }

    return 0;
}

/*
 * Setup context
 */
int pf_mbedtls_ecdh_setup(pf_mbedtls_ecdh_context *ctx, pf_mbedtls_ecp_group_id grp_id)
{
#if defined(PF_MBEDTLS_ECDH_LEGACY_CONTEXT)
    return ecdh_setup_internal(ctx, grp_id);
#else
    switch (grp_id) {
#if defined(PF_MBEDTLS_ECDH_VARIANT_EVEREST_ENABLED)
        case PF_MBEDTLS_ECP_DP_CURVE25519:
            ctx->point_format = PF_MBEDTLS_ECP_PF_COMPRESSED;
            ctx->var = PF_MBEDTLS_ECDH_VARIANT_EVEREST;
            ctx->grp_id = grp_id;
            return pf_mbedtls_everest_setup(&ctx->ctx.everest_ecdh, grp_id);
#endif
        default:
            ctx->point_format = PF_MBEDTLS_ECP_PF_UNCOMPRESSED;
            ctx->var = PF_MBEDTLS_ECDH_VARIANT_MBEDTLS_2_0;
            ctx->grp_id = grp_id;
            ecdh_init_internal(&ctx->ctx.mbed_ecdh);
            return ecdh_setup_internal(&ctx->ctx.mbed_ecdh, grp_id);
    }
#endif
}

static void ecdh_free_internal(pf_mbedtls_ecdh_context_mbed *ctx)
{
    pf_mbedtls_ecp_group_free(&ctx->grp);
    pf_mbedtls_mpi_free(&ctx->d);
    pf_mbedtls_ecp_point_free(&ctx->Q);
    pf_mbedtls_ecp_point_free(&ctx->Qp);
    pf_mbedtls_mpi_free(&ctx->z);

#if defined(PF_MBEDTLS_ECP_RESTARTABLE)
    pf_mbedtls_ecp_restart_free(&ctx->rs);
#endif
}

#if defined(PF_MBEDTLS_ECP_RESTARTABLE)
/*
 * Enable restartable operations for context
 */
void pf_mbedtls_ecdh_enable_restart(pf_mbedtls_ecdh_context *ctx)
{
    ctx->restart_enabled = 1;
}
#endif

/*
 * Free context
 */
void pf_mbedtls_ecdh_free(pf_mbedtls_ecdh_context *ctx)
{
    if (ctx == NULL) {
        return;
    }

#if defined(PF_MBEDTLS_ECDH_LEGACY_CONTEXT)
    pf_mbedtls_ecp_point_free(&ctx->Vi);
    pf_mbedtls_ecp_point_free(&ctx->Vf);
    pf_mbedtls_mpi_free(&ctx->_d);
    ecdh_free_internal(ctx);
#else
    switch (ctx->var) {
#if defined(PF_MBEDTLS_ECDH_VARIANT_EVEREST_ENABLED)
        case PF_MBEDTLS_ECDH_VARIANT_EVEREST:
            pf_mbedtls_everest_free(&ctx->ctx.everest_ecdh);
            break;
#endif
        case PF_MBEDTLS_ECDH_VARIANT_MBEDTLS_2_0:
            ecdh_free_internal(&ctx->ctx.mbed_ecdh);
            break;
        default:
            break;
    }

    ctx->point_format = PF_MBEDTLS_ECP_PF_UNCOMPRESSED;
    ctx->var = PF_MBEDTLS_ECDH_VARIANT_NONE;
    ctx->grp_id = PF_MBEDTLS_ECP_DP_NONE;
#endif
}

static int ecdh_make_params_internal(pf_mbedtls_ecdh_context_mbed *ctx,
                                     size_t *olen, int point_format,
                                     unsigned char *buf, size_t blen,
                                     int (*f_rng)(void *,
                                                  unsigned char *,
                                                  size_t),
                                     void *p_rng,
                                     int restart_enabled)
{
    int ret = PF_MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    size_t grp_len, pt_len;
#if defined(PF_MBEDTLS_ECP_RESTARTABLE)
    pf_mbedtls_ecp_restart_ctx *rs_ctx = NULL;
#endif

    if (ctx->grp.pbits == 0) {
        return PF_MBEDTLS_ERR_ECP_BAD_INPUT_DATA;
    }

#if defined(PF_MBEDTLS_ECP_RESTARTABLE)
    if (restart_enabled) {
        rs_ctx = &ctx->rs;
    }
#else
    (void) restart_enabled;
#endif


#if defined(PF_MBEDTLS_ECP_RESTARTABLE)
    if ((ret = ecdh_gen_public_restartable(&ctx->grp, &ctx->d, &ctx->Q,
                                           f_rng, p_rng, rs_ctx)) != 0) {
        return ret;
    }
#else
    if ((ret = pf_mbedtls_ecdh_gen_public(&ctx->grp, &ctx->d, &ctx->Q,
                                       f_rng, p_rng)) != 0) {
        return ret;
    }
#endif /* MBEDTLS_ECP_RESTARTABLE */

    if ((ret = pf_mbedtls_ecp_tls_write_group(&ctx->grp, &grp_len, buf,
                                           blen)) != 0) {
        return ret;
    }

    buf += grp_len;
    blen -= grp_len;

    if ((ret = pf_mbedtls_ecp_tls_write_point(&ctx->grp, &ctx->Q, point_format,
                                           &pt_len, buf, blen)) != 0) {
        return ret;
    }

    *olen = grp_len + pt_len;
    return 0;
}

/*
 * Setup and write the ServerKeyExchange parameters (RFC 4492)
 *      struct {
 *          ECParameters    curve_params;
 *          ECPoint         public;
 *      } ServerECDHParams;
 */
int pf_mbedtls_ecdh_make_params(pf_mbedtls_ecdh_context *ctx, size_t *olen,
                             unsigned char *buf, size_t blen,
                             int (*f_rng)(void *, unsigned char *, size_t),
                             void *p_rng)
{
    int restart_enabled = 0;
#if defined(PF_MBEDTLS_ECP_RESTARTABLE)
    restart_enabled = ctx->restart_enabled;
#else
    (void) restart_enabled;
#endif

#if defined(PF_MBEDTLS_ECDH_LEGACY_CONTEXT)
    return ecdh_make_params_internal(ctx, olen, ctx->point_format, buf, blen,
                                     f_rng, p_rng, restart_enabled);
#else
    switch (ctx->var) {
#if defined(PF_MBEDTLS_ECDH_VARIANT_EVEREST_ENABLED)
        case PF_MBEDTLS_ECDH_VARIANT_EVEREST:
            return pf_mbedtls_everest_make_params(&ctx->ctx.everest_ecdh, olen,
                                               buf, blen, f_rng, p_rng);
#endif
        case PF_MBEDTLS_ECDH_VARIANT_MBEDTLS_2_0:
            return ecdh_make_params_internal(&ctx->ctx.mbed_ecdh, olen,
                                             ctx->point_format, buf, blen,
                                             f_rng, p_rng,
                                             restart_enabled);
        default:
            return PF_MBEDTLS_ERR_ECP_BAD_INPUT_DATA;
    }
#endif
}

static int ecdh_read_params_internal(pf_mbedtls_ecdh_context_mbed *ctx,
                                     const unsigned char **buf,
                                     const unsigned char *end)
{
    return pf_mbedtls_ecp_tls_read_point(&ctx->grp, &ctx->Qp, buf,
                                      (size_t) (end - *buf));
}

/*
 * Read the ServerKeyExchange parameters (RFC 4492)
 *      struct {
 *          ECParameters    curve_params;
 *          ECPoint         public;
 *      } ServerECDHParams;
 */
int pf_mbedtls_ecdh_read_params(pf_mbedtls_ecdh_context *ctx,
                             const unsigned char **buf,
                             const unsigned char *end)
{
    int ret = PF_MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    pf_mbedtls_ecp_group_id grp_id;
    if ((ret = pf_mbedtls_ecp_tls_read_group_id(&grp_id, buf, (size_t) (end - *buf)))
        != 0) {
        return ret;
    }

    if ((ret = pf_mbedtls_ecdh_setup(ctx, grp_id)) != 0) {
        return ret;
    }

#if defined(PF_MBEDTLS_ECDH_LEGACY_CONTEXT)
    return ecdh_read_params_internal(ctx, buf, end);
#else
    switch (ctx->var) {
#if defined(PF_MBEDTLS_ECDH_VARIANT_EVEREST_ENABLED)
        case PF_MBEDTLS_ECDH_VARIANT_EVEREST:
            return pf_mbedtls_everest_read_params(&ctx->ctx.everest_ecdh,
                                               buf, end);
#endif
        case PF_MBEDTLS_ECDH_VARIANT_MBEDTLS_2_0:
            return ecdh_read_params_internal(&ctx->ctx.mbed_ecdh,
                                             buf, end);
        default:
            return PF_MBEDTLS_ERR_ECP_BAD_INPUT_DATA;
    }
#endif
}

static int ecdh_get_params_internal(pf_mbedtls_ecdh_context_mbed *ctx,
                                    const pf_mbedtls_ecp_keypair *key,
                                    pf_mbedtls_ecdh_side side)
{
    int ret = PF_MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;

    /* If it's not our key, just import the public part as Qp */
    if (side == PF_MBEDTLS_ECDH_THEIRS) {
        return pf_mbedtls_ecp_copy(&ctx->Qp, &key->Q);
    }

    /* Our key: import public (as Q) and private parts */
    if (side != PF_MBEDTLS_ECDH_OURS) {
        return PF_MBEDTLS_ERR_ECP_BAD_INPUT_DATA;
    }

    if ((ret = pf_mbedtls_ecp_copy(&ctx->Q, &key->Q)) != 0 ||
        (ret = pf_mbedtls_mpi_copy(&ctx->d, &key->d)) != 0) {
        return ret;
    }

    return 0;
}

/*
 * Get parameters from a keypair
 */
int pf_mbedtls_ecdh_get_params(pf_mbedtls_ecdh_context *ctx,
                            const pf_mbedtls_ecp_keypair *key,
                            pf_mbedtls_ecdh_side side)
{
    int ret = PF_MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    if (side != PF_MBEDTLS_ECDH_OURS && side != PF_MBEDTLS_ECDH_THEIRS) {
        return PF_MBEDTLS_ERR_ECP_BAD_INPUT_DATA;
    }

    if (pf_mbedtls_ecdh_grp_id(ctx) == PF_MBEDTLS_ECP_DP_NONE) {
        /* This is the first call to get_params(). Set up the context
         * for use with the group. */
        if ((ret = pf_mbedtls_ecdh_setup(ctx, key->grp.id)) != 0) {
            return ret;
        }
    } else {
        /* This is not the first call to get_params(). Check that the
         * current key's group is the same as the context's, which was set
         * from the first key's group. */
        if (pf_mbedtls_ecdh_grp_id(ctx) != key->grp.id) {
            return PF_MBEDTLS_ERR_ECP_BAD_INPUT_DATA;
        }
    }

#if defined(PF_MBEDTLS_ECDH_LEGACY_CONTEXT)
    return ecdh_get_params_internal(ctx, key, side);
#else
    switch (ctx->var) {
#if defined(PF_MBEDTLS_ECDH_VARIANT_EVEREST_ENABLED)
        case PF_MBEDTLS_ECDH_VARIANT_EVEREST:
        {
            pf_mbedtls_everest_ecdh_side s = side == PF_MBEDTLS_ECDH_OURS ?
                                          PF_MBEDTLS_EVEREST_ECDH_OURS :
                                          PF_MBEDTLS_EVEREST_ECDH_THEIRS;
            return pf_mbedtls_everest_get_params(&ctx->ctx.everest_ecdh,
                                              key, s);
        }
#endif
        case PF_MBEDTLS_ECDH_VARIANT_MBEDTLS_2_0:
            return ecdh_get_params_internal(&ctx->ctx.mbed_ecdh,
                                            key, side);
        default:
            return PF_MBEDTLS_ERR_ECP_BAD_INPUT_DATA;
    }
#endif
}

static int ecdh_make_public_internal(pf_mbedtls_ecdh_context_mbed *ctx,
                                     size_t *olen, int point_format,
                                     unsigned char *buf, size_t blen,
                                     int (*f_rng)(void *,
                                                  unsigned char *,
                                                  size_t),
                                     void *p_rng,
                                     int restart_enabled)
{
    int ret = PF_MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
#if defined(PF_MBEDTLS_ECP_RESTARTABLE)
    pf_mbedtls_ecp_restart_ctx *rs_ctx = NULL;
#endif

    if (ctx->grp.pbits == 0) {
        return PF_MBEDTLS_ERR_ECP_BAD_INPUT_DATA;
    }

#if defined(PF_MBEDTLS_ECP_RESTARTABLE)
    if (restart_enabled) {
        rs_ctx = &ctx->rs;
    }
#else
    (void) restart_enabled;
#endif

#if defined(PF_MBEDTLS_ECP_RESTARTABLE)
    if ((ret = ecdh_gen_public_restartable(&ctx->grp, &ctx->d, &ctx->Q,
                                           f_rng, p_rng, rs_ctx)) != 0) {
        return ret;
    }
#else
    if ((ret = pf_mbedtls_ecdh_gen_public(&ctx->grp, &ctx->d, &ctx->Q,
                                       f_rng, p_rng)) != 0) {
        return ret;
    }
#endif /* MBEDTLS_ECP_RESTARTABLE */

    return pf_mbedtls_ecp_tls_write_point(&ctx->grp, &ctx->Q, point_format, olen,
                                       buf, blen);
}

/*
 * Setup and export the client public value
 */
int pf_mbedtls_ecdh_make_public(pf_mbedtls_ecdh_context *ctx, size_t *olen,
                             unsigned char *buf, size_t blen,
                             int (*f_rng)(void *, unsigned char *, size_t),
                             void *p_rng)
{
    int restart_enabled = 0;
#if defined(PF_MBEDTLS_ECP_RESTARTABLE)
    restart_enabled = ctx->restart_enabled;
#endif

#if defined(PF_MBEDTLS_ECDH_LEGACY_CONTEXT)
    return ecdh_make_public_internal(ctx, olen, ctx->point_format, buf, blen,
                                     f_rng, p_rng, restart_enabled);
#else
    switch (ctx->var) {
#if defined(PF_MBEDTLS_ECDH_VARIANT_EVEREST_ENABLED)
        case PF_MBEDTLS_ECDH_VARIANT_EVEREST:
            return pf_mbedtls_everest_make_public(&ctx->ctx.everest_ecdh, olen,
                                               buf, blen, f_rng, p_rng);
#endif
        case PF_MBEDTLS_ECDH_VARIANT_MBEDTLS_2_0:
            return ecdh_make_public_internal(&ctx->ctx.mbed_ecdh, olen,
                                             ctx->point_format, buf, blen,
                                             f_rng, p_rng,
                                             restart_enabled);
        default:
            return PF_MBEDTLS_ERR_ECP_BAD_INPUT_DATA;
    }
#endif
}

static int ecdh_read_public_internal(pf_mbedtls_ecdh_context_mbed *ctx,
                                     const unsigned char *buf, size_t blen)
{
    int ret = PF_MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    const unsigned char *p = buf;

    if ((ret = pf_mbedtls_ecp_tls_read_point(&ctx->grp, &ctx->Qp, &p,
                                          blen)) != 0) {
        return ret;
    }

    if ((size_t) (p - buf) != blen) {
        return PF_MBEDTLS_ERR_ECP_BAD_INPUT_DATA;
    }

    return 0;
}

/*
 * Parse and import the client's public value
 */
int pf_mbedtls_ecdh_read_public(pf_mbedtls_ecdh_context *ctx,
                             const unsigned char *buf, size_t blen)
{
#if defined(PF_MBEDTLS_ECDH_LEGACY_CONTEXT)
    return ecdh_read_public_internal(ctx, buf, blen);
#else
    switch (ctx->var) {
#if defined(PF_MBEDTLS_ECDH_VARIANT_EVEREST_ENABLED)
        case PF_MBEDTLS_ECDH_VARIANT_EVEREST:
            return pf_mbedtls_everest_read_public(&ctx->ctx.everest_ecdh,
                                               buf, blen);
#endif
        case PF_MBEDTLS_ECDH_VARIANT_MBEDTLS_2_0:
            return ecdh_read_public_internal(&ctx->ctx.mbed_ecdh,
                                             buf, blen);
        default:
            return PF_MBEDTLS_ERR_ECP_BAD_INPUT_DATA;
    }
#endif
}

static int ecdh_calc_secret_internal(pf_mbedtls_ecdh_context_mbed *ctx,
                                     size_t *olen, unsigned char *buf,
                                     size_t blen,
                                     int (*f_rng)(void *,
                                                  unsigned char *,
                                                  size_t),
                                     void *p_rng,
                                     int restart_enabled)
{
    int ret = PF_MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
#if defined(PF_MBEDTLS_ECP_RESTARTABLE)
    pf_mbedtls_ecp_restart_ctx *rs_ctx = NULL;
#endif

    if (ctx == NULL || ctx->grp.pbits == 0) {
        return PF_MBEDTLS_ERR_ECP_BAD_INPUT_DATA;
    }

#if defined(PF_MBEDTLS_ECP_RESTARTABLE)
    if (restart_enabled) {
        rs_ctx = &ctx->rs;
    }
#else
    (void) restart_enabled;
#endif

#if defined(PF_MBEDTLS_ECP_RESTARTABLE)
    if ((ret = ecdh_compute_shared_restartable(&ctx->grp, &ctx->z, &ctx->Qp,
                                               &ctx->d, f_rng, p_rng,
                                               rs_ctx)) != 0) {
        return ret;
    }
#else
    if ((ret = pf_mbedtls_ecdh_compute_shared(&ctx->grp, &ctx->z, &ctx->Qp,
                                           &ctx->d, f_rng, p_rng)) != 0) {
        return ret;
    }
#endif /* MBEDTLS_ECP_RESTARTABLE */

    size_t p_bytes = ctx->grp.pbits / 8 + ((ctx->grp.pbits % 8) != 0);

    if (p_bytes > blen) {
        return PF_MBEDTLS_ERR_ECP_BUFFER_TOO_SMALL;
    }

    *olen = p_bytes;

    if (pf_mbedtls_ecp_get_type(&ctx->grp) == PF_MBEDTLS_ECP_TYPE_MONTGOMERY) {
        return pf_mbedtls_mpi_write_binary_le(&ctx->z, buf, *olen);
    }

    return pf_mbedtls_mpi_write_binary(&ctx->z, buf, *olen);
}

/*
 * Derive and export the shared secret
 */
int pf_mbedtls_ecdh_calc_secret(pf_mbedtls_ecdh_context *ctx, size_t *olen,
                             unsigned char *buf, size_t blen,
                             int (*f_rng)(void *, unsigned char *, size_t),
                             void *p_rng)
{
    int restart_enabled = 0;
#if defined(PF_MBEDTLS_ECP_RESTARTABLE)
    restart_enabled = ctx->restart_enabled;
#endif

#if defined(PF_MBEDTLS_ECDH_LEGACY_CONTEXT)
    return ecdh_calc_secret_internal(ctx, olen, buf, blen, f_rng, p_rng,
                                     restart_enabled);
#else
    switch (ctx->var) {
#if defined(PF_MBEDTLS_ECDH_VARIANT_EVEREST_ENABLED)
        case PF_MBEDTLS_ECDH_VARIANT_EVEREST:
            return pf_mbedtls_everest_calc_secret(&ctx->ctx.everest_ecdh, olen,
                                               buf, blen, f_rng, p_rng);
#endif
        case PF_MBEDTLS_ECDH_VARIANT_MBEDTLS_2_0:
            return ecdh_calc_secret_internal(&ctx->ctx.mbed_ecdh, olen, buf,
                                             blen, f_rng, p_rng,
                                             restart_enabled);
        default:
            return PF_MBEDTLS_ERR_ECP_BAD_INPUT_DATA;
    }
#endif
}
#endif /* MBEDTLS_ECDH_C */
