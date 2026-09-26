#include "../../../pf_build_config.h"
/*
 *  Edwards-curve Digital Signature Algorithm
 *
 *  Copyright The Mbed TLS Contributors
 *  SPDX-License-Identifier: Apache-2.0
 *
 *  Licensed under the Apache License, Version 2.0 (the "License"); you may
 *  not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 *  WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */

/*
 * References:
 *
 * SEC1 http://www.secg.org/index.php?action=secg,docs_secg
 */

#include "common.h"

#if defined(PF_MBEDTLS_EDDSA_C)

#include "../include/mbedtls/eddsa.h"
#include <string.h>

#include "../include/mbedtls/platform.h"

#include "../include/mbedtls/platform_util.h"
#include "../include/mbedtls/error.h"
#if defined(PF_MBEDTLS_ECP_DP_ED25519_ENABLED)
#include "../include/mbedtls/sha512.h"
#endif
#if defined(PF_MBEDTLS_ECP_DP_ED448_ENABLED)
#include "../include/mbedtls/sha3.h"
#endif

int pf_mbedtls_eddsa_can_do(pf_mbedtls_ecp_group_id gid)
{
    switch (gid) {
#ifdef PF_MBEDTLS_ECP_DP_ED25519_ENABLED
        case PF_MBEDTLS_ECP_DP_ED25519: return 1;
#endif
#ifdef PF_MBEDTLS_ECP_DP_ED448_ENABLED
        case PF_MBEDTLS_ECP_DP_ED448: return 1;
#endif
        default: return 0;
    }
}

#ifdef PF_MBEDTLS_ECP_DP_ED25519_ENABLED
static int pf_mbedtls_eddsa_put_dom2_ctx(int flag, const unsigned char *ctx,
                                      size_t ctx_len, pf_mbedtls_sha512_context *sha_ctx)
{
    unsigned char ct_init_string[] = "SigEd25519 no Ed25519 collisions";
    unsigned char ct_flag = flag;
    unsigned char ct_ctx_len = ctx_len & 0xff;

    pf_mbedtls_sha512_update(sha_ctx, ct_init_string, 32);
    pf_mbedtls_sha512_update(sha_ctx, &ct_flag, 1);
    pf_mbedtls_sha512_update(sha_ctx, &ct_ctx_len, 1);

    if (ctx && ctx_len > 0) {
        pf_mbedtls_sha512_update(sha_ctx, ctx, ctx_len);
    }

    return 0;
}
#endif

#ifdef PF_MBEDTLS_ECP_DP_ED448_ENABLED
static int pf_mbedtls_eddsa_put_dom4_ctx(int flag, const unsigned char *ctx,
                                      size_t ctx_len, pf_mbedtls_sha3_context *sha_ctx)
{
    unsigned char ct_init_string[] = "SigEd448";
    unsigned char ct_flag = flag;
    unsigned char ct_ctx_len = ctx_len & 0xff;

    pf_mbedtls_sha3_update(sha_ctx, ct_init_string, 8);
    pf_mbedtls_sha3_update(sha_ctx, &ct_flag, 1);
    pf_mbedtls_sha3_update(sha_ctx, &ct_ctx_len, 1);

    if (ctx && ctx_len > 0) {
        pf_mbedtls_sha3_update(sha_ctx, ctx, ctx_len);
    }

    return 0;
}
#endif

/*
 * Compute EdDSA signature of a message.
 * For PREHASH operation, the message is already previously hashed.
 * Obviously, for PREHASH, we skip hash message step.
 */
int pf_mbedtls_eddsa_sign(pf_mbedtls_ecp_group *grp,
                       pf_mbedtls_mpi *r, pf_mbedtls_mpi *s,
                       const pf_mbedtls_mpi *d, const unsigned char *buf, size_t blen,
                       pf_mbedtls_eddsa_id eddsa_id,
                       const unsigned char *ed_ctx, size_t ed_ctx_len,
                       int (*f_rng)(void *, unsigned char *, size_t), void *p_rng)
{
    int ret;
    pf_mbedtls_ecp_point Q, R;
    pf_mbedtls_mpi q, prefix, rq, h;

    /* EdDSA only should be used with Ed25519 and Ed448 curves  */
    if (!pf_mbedtls_eddsa_can_do(grp->id) || grp->N.p == NULL) {
        return PF_MBEDTLS_ERR_ECP_BAD_INPUT_DATA;
    }

#ifdef PF_MBEDTLS_ECP_DP_ED25519_ENABLED
    if (grp->id == PF_MBEDTLS_ECP_DP_ED25519 && eddsa_id != PF_MBEDTLS_EDDSA_PURE &&
        eddsa_id != PF_MBEDTLS_EDDSA_CTX && eddsa_id != PF_MBEDTLS_EDDSA_PREHASH) {
        return PF_MBEDTLS_ERR_ECP_FEATURE_UNAVAILABLE;
    }
#endif
#ifdef PF_MBEDTLS_ECP_DP_ED448_ENABLED
    if (grp->id == PF_MBEDTLS_ECP_DP_ED448 && eddsa_id != PF_MBEDTLS_EDDSA_PURE &&
        eddsa_id != PF_MBEDTLS_EDDSA_PREHASH) {
        return PF_MBEDTLS_ERR_ECP_FEATURE_UNAVAILABLE;
    }
#endif

    if (eddsa_id == PF_MBEDTLS_EDDSA_PREHASH && blen != 64) {
        return PF_MBEDTLS_ERR_ECP_BAD_INPUT_DATA;
    }

    pf_mbedtls_ecp_point_init(&Q); pf_mbedtls_ecp_point_init(&R);

    pf_mbedtls_mpi_init(&q); pf_mbedtls_mpi_init(&prefix); pf_mbedtls_mpi_init(&rq); pf_mbedtls_mpi_init(&h);

    /* Step 1 */
    PF_MBEDTLS_MPI_CHK(pf_mbedtls_ecp_expand_edwards(grp, d, &q, &prefix));

    PF_MBEDTLS_MPI_CHK(pf_mbedtls_ecp_mul(grp, &Q, &q, &grp->G, f_rng, p_rng));

    switch (grp->id) {
#ifdef PF_MBEDTLS_ECP_DP_ED25519_ENABLED
        case PF_MBEDTLS_ECP_DP_ED25519:
        {
            pf_mbedtls_sha512_context sha_ctx;
            unsigned char sha_buf[64], tmp_buf[32];
            size_t olen = 0;

            /* r computation */
            pf_mbedtls_sha512_init(&sha_ctx);
            pf_mbedtls_sha512_starts(&sha_ctx, 0);

            /* Step 2 */
            if (eddsa_id == PF_MBEDTLS_EDDSA_CTX) {
                PF_MBEDTLS_MPI_CHK(pf_mbedtls_eddsa_put_dom2_ctx(0, ed_ctx, ed_ctx_len, &sha_ctx));
            } else if (eddsa_id == PF_MBEDTLS_EDDSA_PREHASH) {
                PF_MBEDTLS_MPI_CHK(pf_mbedtls_eddsa_put_dom2_ctx(1, ed_ctx, ed_ctx_len, &sha_ctx));
            }

            /* Update SHA with prefix */
            PF_MBEDTLS_MPI_CHK(pf_mbedtls_mpi_write_binary_le(&prefix, tmp_buf, sizeof(tmp_buf)));

            pf_mbedtls_sha512_update(&sha_ctx, tmp_buf, sizeof(tmp_buf));

            pf_mbedtls_platform_zeroize(tmp_buf, sizeof(tmp_buf));

            /* In EDDSA_PREHASH, buf should contain the SHA512 hash. It contains the whole message otherwise */
            pf_mbedtls_sha512_update(&sha_ctx, buf, blen);

            pf_mbedtls_sha512_finish(&sha_ctx, sha_buf);
            pf_mbedtls_sha512_free(&sha_ctx);

            PF_MBEDTLS_MPI_CHK(pf_mbedtls_mpi_read_binary_le(&rq, sha_buf, sizeof(sha_buf)));

            pf_mbedtls_platform_zeroize(sha_buf, sizeof(sha_buf));

            PF_MBEDTLS_MPI_CHK(pf_mbedtls_mpi_mod_mpi(&rq, &rq, &grp->N));

            /* Step 3 */
            PF_MBEDTLS_MPI_CHK(pf_mbedtls_ecp_mul(grp, &R, &rq, &grp->G, f_rng, p_rng));

            /* We encode the R point to r */
            PF_MBEDTLS_MPI_CHK(pf_mbedtls_ecp_point_encode(grp, r, &R));

            /* s computation */
            pf_mbedtls_sha512_init(&sha_ctx);
            pf_mbedtls_sha512_starts(&sha_ctx, 0);

            /* Step 4 */
            if (eddsa_id == PF_MBEDTLS_EDDSA_CTX) {
                PF_MBEDTLS_MPI_CHK(pf_mbedtls_eddsa_put_dom2_ctx(0, ed_ctx, ed_ctx_len, &sha_ctx));
            } else if (eddsa_id == PF_MBEDTLS_EDDSA_PREHASH) {
                PF_MBEDTLS_MPI_CHK(pf_mbedtls_eddsa_put_dom2_ctx(1, ed_ctx, ed_ctx_len, &sha_ctx));
            }

            PF_MBEDTLS_MPI_CHK(pf_mbedtls_ecp_point_write_binary(grp, &R, PF_MBEDTLS_ECP_PF_COMPRESSED,
                                                           &olen, tmp_buf, sizeof(tmp_buf)));
            pf_mbedtls_sha512_update(&sha_ctx, tmp_buf, sizeof(tmp_buf));

            PF_MBEDTLS_MPI_CHK(pf_mbedtls_ecp_point_write_binary(grp, &Q, PF_MBEDTLS_ECP_PF_COMPRESSED,
                                                           &olen, tmp_buf, sizeof(tmp_buf)));
            pf_mbedtls_sha512_update(&sha_ctx, tmp_buf, sizeof(tmp_buf));

            pf_mbedtls_platform_zeroize(tmp_buf, sizeof(tmp_buf));

            /* In EDDSA_PREHASH, buf should contain the SHA512 hash. It contains the whole message otherwise */
            pf_mbedtls_sha512_update(&sha_ctx, buf, blen);

            pf_mbedtls_sha512_finish(&sha_ctx, sha_buf);
            pf_mbedtls_sha512_free(&sha_ctx);

            PF_MBEDTLS_MPI_CHK(pf_mbedtls_mpi_read_binary_le(&h, sha_buf, sizeof(sha_buf)));
            pf_mbedtls_platform_zeroize(sha_buf, sizeof(sha_buf));

            break;
        }
#endif
#ifdef PF_MBEDTLS_ECP_DP_ED448_ENABLED
        case PF_MBEDTLS_ECP_DP_ED448:
        {
            pf_mbedtls_sha3_context sha_ctx;
            unsigned char sha_buf[114], tmp_buf[57];
            size_t olen = 0;

            /* r computation */
            pf_mbedtls_sha3_init(&sha_ctx);
            pf_mbedtls_sha3_starts(&sha_ctx, PF_MBEDTLS_SHA3_SHAKE256);

            /* Step 2 */
            if (eddsa_id == PF_MBEDTLS_EDDSA_PURE) {
                PF_MBEDTLS_MPI_CHK(pf_mbedtls_eddsa_put_dom4_ctx(0, ed_ctx, ed_ctx_len, &sha_ctx));
            } else if (eddsa_id == PF_MBEDTLS_EDDSA_PREHASH) {
                PF_MBEDTLS_MPI_CHK(pf_mbedtls_eddsa_put_dom4_ctx(1, ed_ctx, ed_ctx_len, &sha_ctx));
            }

            /* Update SHA with prefix */
            PF_MBEDTLS_MPI_CHK(pf_mbedtls_mpi_write_binary_le(&prefix, tmp_buf, sizeof(tmp_buf)));

            pf_mbedtls_sha3_update(&sha_ctx, tmp_buf, sizeof(tmp_buf));

            pf_mbedtls_platform_zeroize(tmp_buf, sizeof(tmp_buf));

            /* In EDDSA_PREHASH, buf should contain the SHA512 hash. It contains the whole message otherwise */
            pf_mbedtls_sha3_update(&sha_ctx, buf, blen);

            pf_mbedtls_sha3_finish(&sha_ctx, sha_buf, 114);
            pf_mbedtls_sha3_free(&sha_ctx);

            PF_MBEDTLS_MPI_CHK(pf_mbedtls_mpi_read_binary_le(&rq, sha_buf, sizeof(sha_buf)));

            pf_mbedtls_platform_zeroize(sha_buf, sizeof(sha_buf));

            PF_MBEDTLS_MPI_CHK(pf_mbedtls_mpi_mod_mpi(&rq, &rq, &grp->N));

            /* Step 3 */
            PF_MBEDTLS_MPI_CHK(pf_mbedtls_ecp_mul(grp, &R, &rq, &grp->G, f_rng, p_rng));

            /* We encode the R point to r */
            PF_MBEDTLS_MPI_CHK(pf_mbedtls_ecp_point_encode(grp, r, &R));

            /* s computation */
            pf_mbedtls_sha3_init(&sha_ctx);
            pf_mbedtls_sha3_starts(&sha_ctx, PF_MBEDTLS_SHA3_SHAKE256);

            /* Step 4 */
            if (eddsa_id == PF_MBEDTLS_EDDSA_PURE) {
                PF_MBEDTLS_MPI_CHK(pf_mbedtls_eddsa_put_dom4_ctx(0, ed_ctx, ed_ctx_len, &sha_ctx));
            } else if (eddsa_id == PF_MBEDTLS_EDDSA_PREHASH) {
                PF_MBEDTLS_MPI_CHK(pf_mbedtls_eddsa_put_dom4_ctx(1, ed_ctx, ed_ctx_len, &sha_ctx));
            }

            PF_MBEDTLS_MPI_CHK(pf_mbedtls_ecp_point_write_binary(grp, &R, PF_MBEDTLS_ECP_PF_COMPRESSED,
                                                           &olen, tmp_buf, sizeof(tmp_buf)));
            pf_mbedtls_sha3_update(&sha_ctx, tmp_buf, sizeof(tmp_buf));

            PF_MBEDTLS_MPI_CHK(pf_mbedtls_ecp_point_write_binary(grp, &Q, PF_MBEDTLS_ECP_PF_COMPRESSED,
                                                           &olen, tmp_buf, sizeof(tmp_buf)));
            pf_mbedtls_sha3_update(&sha_ctx, tmp_buf, sizeof(tmp_buf));

            pf_mbedtls_platform_zeroize(tmp_buf, sizeof(tmp_buf));

            /* In EDDSA_PREHASH, buf should contain the SHAKE256 hash. It contains the whole message otherwise */
            pf_mbedtls_sha3_update(&sha_ctx, buf, blen);

            pf_mbedtls_sha3_finish(&sha_ctx, sha_buf, 114);
            pf_mbedtls_sha3_free(&sha_ctx);

            PF_MBEDTLS_MPI_CHK(pf_mbedtls_mpi_read_binary_le(&h, sha_buf, sizeof(sha_buf)));
            pf_mbedtls_platform_zeroize(sha_buf, sizeof(sha_buf));

            break;
        }
#endif
        default:
            break;
    }

    /* Step 5 */
    PF_MBEDTLS_MPI_CHK(pf_mbedtls_mpi_mod_mpi(&h, &h, &grp->N));

    PF_MBEDTLS_MPI_CHK(pf_mbedtls_mpi_mul_mpi(&h, &h, &q));

    PF_MBEDTLS_MPI_CHK(pf_mbedtls_mpi_add_mpi(s, &h, &rq));

    PF_MBEDTLS_MPI_CHK(pf_mbedtls_mpi_mod_mpi(s, s, &grp->N));

cleanup:
    pf_mbedtls_mpi_free(&q);
    pf_mbedtls_mpi_free(&prefix);
    pf_mbedtls_mpi_free(&rq);
    pf_mbedtls_mpi_free(&h);
    pf_mbedtls_ecp_point_free(&Q);
    pf_mbedtls_ecp_point_free(&R);

    return ret;

}

int pf_mbedtls_eddsa_verify(pf_mbedtls_ecp_group *grp,
                         const unsigned char *buf, size_t blen,
                         const pf_mbedtls_ecp_point *Q, const pf_mbedtls_mpi *r,
                         const pf_mbedtls_mpi *s,
                         pf_mbedtls_eddsa_id eddsa_id,
                         const unsigned char *ed_ctx, size_t ed_ctx_len)
{
    int ret = 0;
    pf_mbedtls_mpi h;
    pf_mbedtls_ecp_point R;

    pf_mbedtls_mpi_init(&h);
    pf_mbedtls_ecp_point_init(&R);

    /* Step 1 */
    if (pf_mbedtls_mpi_cmp_mpi(s, &grp->N) >= 0 || pf_mbedtls_mpi_cmp_int(s, 0) < 0) {
        return PF_MBEDTLS_ERR_ECP_BAD_INPUT_DATA;
    }

    switch (grp->id) {
#ifdef PF_MBEDTLS_ECP_DP_ED25519_ENABLED
        case PF_MBEDTLS_ECP_DP_ED25519: {
            pf_mbedtls_sha512_context sha_ctx;
            unsigned char sha_buf[64], tmp_buf[32];
            size_t olen = 0;

            pf_mbedtls_sha512_init(&sha_ctx);
            pf_mbedtls_sha512_starts(&sha_ctx, 0);

            /* Step 2 */
            if (eddsa_id == PF_MBEDTLS_EDDSA_CTX) {
                PF_MBEDTLS_MPI_CHK(pf_mbedtls_eddsa_put_dom2_ctx(0, ed_ctx, ed_ctx_len, &sha_ctx));
            } else if (eddsa_id == PF_MBEDTLS_EDDSA_PREHASH) {
                PF_MBEDTLS_MPI_CHK(pf_mbedtls_eddsa_put_dom2_ctx(1, ed_ctx, ed_ctx_len, &sha_ctx));
            }

            PF_MBEDTLS_MPI_CHK(pf_mbedtls_mpi_write_binary_le(r, tmp_buf, sizeof(tmp_buf)));
            pf_mbedtls_sha512_update(&sha_ctx, tmp_buf, sizeof(tmp_buf));

            PF_MBEDTLS_MPI_CHK(pf_mbedtls_ecp_point_write_binary(grp, Q, PF_MBEDTLS_ECP_PF_COMPRESSED, &olen,
                                                           tmp_buf, sizeof(tmp_buf)));
            pf_mbedtls_sha512_update(&sha_ctx, tmp_buf, sizeof(tmp_buf));
            pf_mbedtls_platform_zeroize(tmp_buf, sizeof(tmp_buf));

            /* In EDDSA_PREHASH, buf should contain the SHA512 hash. It contains the whole message otherwise */
            pf_mbedtls_sha512_update(&sha_ctx, buf, blen);

            pf_mbedtls_sha512_finish(&sha_ctx, sha_buf);
            pf_mbedtls_sha512_free(&sha_ctx);

            PF_MBEDTLS_MPI_CHK(pf_mbedtls_mpi_read_binary_le(&h, sha_buf, sizeof(sha_buf)));
            pf_mbedtls_platform_zeroize(sha_buf, sizeof(sha_buf));

            break;
        }
#endif
#ifdef PF_MBEDTLS_ECP_DP_ED448_ENABLED
        case PF_MBEDTLS_ECP_DP_ED448: {
            pf_mbedtls_sha3_context sha_ctx;
            unsigned char sha_buf[114], tmp_buf[57];
            size_t olen = 0;

            pf_mbedtls_sha3_init(&sha_ctx);
            pf_mbedtls_sha3_starts(&sha_ctx, PF_MBEDTLS_SHA3_SHAKE256);

            /* Step 2 */
            if (eddsa_id == PF_MBEDTLS_EDDSA_PURE) {
                PF_MBEDTLS_MPI_CHK(pf_mbedtls_eddsa_put_dom4_ctx(0, ed_ctx, ed_ctx_len, &sha_ctx));
            } else if (eddsa_id == PF_MBEDTLS_EDDSA_PREHASH) {
                PF_MBEDTLS_MPI_CHK(pf_mbedtls_eddsa_put_dom4_ctx(1, ed_ctx, ed_ctx_len, &sha_ctx));
            }

            PF_MBEDTLS_MPI_CHK(pf_mbedtls_mpi_write_binary_le(r, tmp_buf, sizeof(tmp_buf)));
            pf_mbedtls_sha3_update(&sha_ctx, tmp_buf, sizeof(tmp_buf));

            PF_MBEDTLS_MPI_CHK(pf_mbedtls_ecp_point_write_binary(grp, Q, PF_MBEDTLS_ECP_PF_COMPRESSED, &olen,
                                                           tmp_buf, sizeof(tmp_buf)));
            pf_mbedtls_sha3_update(&sha_ctx, tmp_buf, sizeof(tmp_buf));
            pf_mbedtls_platform_zeroize(tmp_buf, sizeof(tmp_buf));

            /* In EDDSA_PREHASH, buf should contain the SHAKE256 hash. It contains the whole message otherwise */
            pf_mbedtls_sha3_update(&sha_ctx, buf, blen);

            pf_mbedtls_sha3_finish(&sha_ctx, sha_buf, 114);
            pf_mbedtls_sha3_free(&sha_ctx);

            PF_MBEDTLS_MPI_CHK(pf_mbedtls_mpi_read_binary_le(&h, sha_buf, sizeof(sha_buf)));
            pf_mbedtls_platform_zeroize(sha_buf, sizeof(sha_buf));

            break;
        }
#endif
        default:
            break;
    }

    PF_MBEDTLS_MPI_CHK(pf_mbedtls_mpi_mod_mpi(&h, &h, &grp->N));

    /* Step 3 */
    /* We perform fast single-signature verification by compressing sB-hA and comparing with r without decompressing it (expensive) */
    PF_MBEDTLS_MPI_CHK(pf_mbedtls_mpi_sub_mpi(&h, &grp->N, &h));
    PF_MBEDTLS_MPI_CHK(pf_mbedtls_ecp_muladd(grp, &R, s, &grp->G, &h, Q));
    PF_MBEDTLS_MPI_CHK(pf_mbedtls_ecp_point_encode(grp, &h, &R));     /* We reuse h */

    /* Since h is a compressed point, we are free to compare with r without decompressing it */
    if (pf_mbedtls_mpi_cmp_mpi(&h, r) != 0) {
        ret = PF_MBEDTLS_ERR_ECP_VERIFY_FAILED;
        goto cleanup;
    }

cleanup:
    pf_mbedtls_mpi_free(&h);
    pf_mbedtls_ecp_point_free(&R);
    return ret;
}

/*
 * Convert a signature (given by context) to binary
 */
static int eddsa_signature_to_binary(const pf_mbedtls_ecp_group *grp,
                                     const pf_mbedtls_mpi *r,
                                     const pf_mbedtls_mpi *s,
                                     unsigned char *sig,
                                     size_t sig_size,
                                     size_t *slen)
{
    int ret = PF_MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    size_t plen = (grp->pbits + 1 + 7) >> 3;

    if (2 * plen > sig_size) {
        return PF_MBEDTLS_ERR_ECP_BUFFER_TOO_SMALL;
    }

    ret = pf_mbedtls_mpi_write_binary_le(r, sig, plen);
    if (ret != 0) {
        return ret;
    }
    ret = pf_mbedtls_mpi_write_binary_le(s, sig + plen, plen);
    if (ret != 0) {
        return ret;
    }
    *slen = 2 * plen;

    return 0;
}

/*
 * Compute and write signature
 */
int pf_mbedtls_eddsa_write_signature(pf_mbedtls_ecp_keypair *ctx,
                                  const unsigned char *hash, size_t hlen,
                                  unsigned char *sig, size_t sig_size, size_t *slen,
                                  pf_mbedtls_eddsa_id eddsa_id,
                                  const unsigned char *ed_ctx, size_t ed_ctx_len,
                                  int (*f_rng)(void *, unsigned char *, size_t),
                                  void *p_rng)
{
    int ret = PF_MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    pf_mbedtls_mpi r, s;

    if (ctx == NULL || hash == NULL || sig == NULL || slen == NULL || f_rng == NULL) {
        return PF_MBEDTLS_ERR_ECP_BAD_INPUT_DATA;
    }

    pf_mbedtls_mpi_init(&r);
    pf_mbedtls_mpi_init(&s);

    PF_MBEDTLS_MPI_CHK(pf_mbedtls_eddsa_sign(&ctx->grp, &r, &s, &ctx->d,
                                       hash, hlen, eddsa_id, ed_ctx,
                                       ed_ctx_len, f_rng,
                                       p_rng));

    PF_MBEDTLS_MPI_CHK(eddsa_signature_to_binary(&ctx->grp, &r, &s, sig, sig_size, slen));

cleanup:
    pf_mbedtls_mpi_free(&r);
    pf_mbedtls_mpi_free(&s);

    return ret;
}

/*
 * Restartable read and check signature
 */
int pf_mbedtls_eddsa_read_signature(pf_mbedtls_ecp_keypair *ctx,
                                 const unsigned char *hash, size_t hlen,
                                 const unsigned char *sig, size_t slen,
                                 pf_mbedtls_eddsa_id eddsa_id,
                                 const unsigned char *ed_ctx, size_t ed_ctx_len)
{
    int ret = PF_MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    size_t plen = (ctx->grp.pbits + 1 + 7) >> 3;
    pf_mbedtls_mpi r, s;

    if (ctx == NULL || hash == NULL || sig == NULL) {
        return PF_MBEDTLS_ERR_ECP_BAD_INPUT_DATA;
    }

    if (2 * plen > slen) {
        return PF_MBEDTLS_ERR_ECP_BAD_INPUT_DATA;
    }

    pf_mbedtls_mpi_init(&r);
    pf_mbedtls_mpi_init(&s);

    PF_MBEDTLS_MPI_CHK(pf_mbedtls_mpi_read_binary_le(&r, sig, plen));
    PF_MBEDTLS_MPI_CHK(pf_mbedtls_mpi_read_binary_le(&s, sig + plen, plen));

    if ((ret = pf_mbedtls_eddsa_verify(&ctx->grp, hash, hlen,
                                    &ctx->Q, &r, &s,
                                    eddsa_id, ed_ctx, ed_ctx_len)) != 0) {
        goto cleanup;
    }

cleanup:
    pf_mbedtls_mpi_free(&r);
    pf_mbedtls_mpi_free(&s);

    return ret;
}

#endif /* MBEDTLS_EDDSA_C */
