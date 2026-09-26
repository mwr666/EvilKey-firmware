#include "../../../pf_build_config.h"
/*
 *  Low-level modular bignum functions
 *
 *  Copyright The Mbed TLS Contributors
 *  SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
 */

#include "common.h"

#if defined(PF_MBEDTLS_BIGNUM_C) && defined(PF_MBEDTLS_ECP_WITH_MPI_UINT)

#include <string.h>

#include "../include/mbedtls/error.h"
#include "../include/mbedtls/platform_util.h"

#include "../include/mbedtls/platform.h"

#include "bignum_core.h"
#include "bignum_mod_raw.h"
#include "bignum_mod.h"
#include "constant_time_internal.h"

#include "bignum_mod_raw_invasive.h"

void pf_mbedtls_mpi_mod_raw_cond_assign(pf_mbedtls_mpi_uint *X,
                                     const pf_mbedtls_mpi_uint *A,
                                     const pf_mbedtls_mpi_mod_modulus *N,
                                     unsigned char assign)
{
    pf_mbedtls_mpi_core_cond_assign(X, A, N->limbs, pf_mbedtls_ct_bool(assign));
}

void pf_mbedtls_mpi_mod_raw_cond_swap(pf_mbedtls_mpi_uint *X,
                                   pf_mbedtls_mpi_uint *Y,
                                   const pf_mbedtls_mpi_mod_modulus *N,
                                   unsigned char swap)
{
    pf_mbedtls_mpi_core_cond_swap(X, Y, N->limbs, pf_mbedtls_ct_bool(swap));
}

int pf_mbedtls_mpi_mod_raw_read(pf_mbedtls_mpi_uint *X,
                             const pf_mbedtls_mpi_mod_modulus *N,
                             const unsigned char *input,
                             size_t input_length,
                             pf_mbedtls_mpi_mod_ext_rep ext_rep)
{
    int ret = PF_MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;

    switch (ext_rep) {
        case PF_MBEDTLS_MPI_MOD_EXT_REP_LE:
            ret = pf_mbedtls_mpi_core_read_le(X, N->limbs,
                                           input, input_length);
            break;
        case PF_MBEDTLS_MPI_MOD_EXT_REP_BE:
            ret = pf_mbedtls_mpi_core_read_be(X, N->limbs,
                                           input, input_length);
            break;
        default:
            return PF_MBEDTLS_ERR_MPI_BAD_INPUT_DATA;
    }

    if (ret != 0) {
        goto cleanup;
    }

    if (!pf_mbedtls_mpi_core_lt_ct(X, N->p, N->limbs)) {
        ret = PF_MBEDTLS_ERR_MPI_BAD_INPUT_DATA;
        goto cleanup;
    }

cleanup:

    return ret;
}

int pf_mbedtls_mpi_mod_raw_write(const pf_mbedtls_mpi_uint *A,
                              const pf_mbedtls_mpi_mod_modulus *N,
                              unsigned char *output,
                              size_t output_length,
                              pf_mbedtls_mpi_mod_ext_rep ext_rep)
{
    switch (ext_rep) {
        case PF_MBEDTLS_MPI_MOD_EXT_REP_LE:
            return pf_mbedtls_mpi_core_write_le(A, N->limbs,
                                             output, output_length);
        case PF_MBEDTLS_MPI_MOD_EXT_REP_BE:
            return pf_mbedtls_mpi_core_write_be(A, N->limbs,
                                             output, output_length);
        default:
            return PF_MBEDTLS_ERR_MPI_BAD_INPUT_DATA;
    }
}

void pf_mbedtls_mpi_mod_raw_sub(pf_mbedtls_mpi_uint *X,
                             const pf_mbedtls_mpi_uint *A,
                             const pf_mbedtls_mpi_uint *B,
                             const pf_mbedtls_mpi_mod_modulus *N)
{
    pf_mbedtls_mpi_uint c = pf_mbedtls_mpi_core_sub(X, A, B, N->limbs);

    (void) pf_mbedtls_mpi_core_add_if(X, N->p, N->limbs, (unsigned) c);
}

PF_MBEDTLS_STATIC_TESTABLE
void pf_mbedtls_mpi_mod_raw_fix_quasi_reduction(pf_mbedtls_mpi_uint *X,
                                             const pf_mbedtls_mpi_mod_modulus *N)
{
    pf_mbedtls_mpi_uint c = pf_mbedtls_mpi_core_sub(X, X, N->p, N->limbs);

    (void) pf_mbedtls_mpi_core_add_if(X, N->p, N->limbs, (unsigned) c);
}


void pf_mbedtls_mpi_mod_raw_mul(pf_mbedtls_mpi_uint *X,
                             const pf_mbedtls_mpi_uint *A,
                             const pf_mbedtls_mpi_uint *B,
                             const pf_mbedtls_mpi_mod_modulus *N,
                             pf_mbedtls_mpi_uint *T)
{
    /* Standard (A * B) multiplication stored into pre-allocated T
     * buffer of fixed limb size of (2N + 1).
     *
     * The space may not not fully filled by when
     * MBEDTLS_MPI_MOD_REP_OPT_RED is used. */
    const size_t T_limbs = BITS_TO_LIMBS(N->bits) * 2;
    switch (N->int_rep) {
        case PF_MBEDTLS_MPI_MOD_REP_MONTGOMERY:
            pf_mbedtls_mpi_core_montmul(X, A, B, N->limbs, N->p, N->limbs,
                                     N->rep.mont.mm, T);
            break;
        case PF_MBEDTLS_MPI_MOD_REP_OPT_RED:
            pf_mbedtls_mpi_core_mul(T, A, N->limbs, B, N->limbs);

            /* Optimised Reduction */
            (*N->rep.ored.modp)(T, T_limbs);

            /* Convert back to canonical representation */
            pf_mbedtls_mpi_mod_raw_fix_quasi_reduction(T, N);
            memcpy(X, T, N->limbs * sizeof(pf_mbedtls_mpi_uint));
            break;
        default:
            break;
    }

}

size_t pf_mbedtls_mpi_mod_raw_inv_prime_working_limbs(size_t AN_limbs)
{
    /* mbedtls_mpi_mod_raw_inv_prime() needs a temporary for the exponent,
     * which will be the same size as the modulus and input (AN_limbs),
     * and additional space to pass to mbedtls_mpi_core_exp_mod(). */
    return AN_limbs +
           pf_mbedtls_mpi_core_exp_mod_working_limbs(AN_limbs, AN_limbs);
}

void pf_mbedtls_mpi_mod_raw_inv_prime(pf_mbedtls_mpi_uint *X,
                                   const pf_mbedtls_mpi_uint *A,
                                   const pf_mbedtls_mpi_uint *N,
                                   size_t AN_limbs,
                                   const pf_mbedtls_mpi_uint *RR,
                                   pf_mbedtls_mpi_uint *T)
{
    /* Inversion by power: g^|G| = 1 => g^(-1) = g^(|G|-1), and
     *                       |G| = N - 1, so we want
     *                 g^(|G|-1) = g^(N - 2)
     */

    /* Use the first AN_limbs of T to hold N - 2 */
    pf_mbedtls_mpi_uint *Nminus2 = T;
    (void) pf_mbedtls_mpi_core_sub_int(Nminus2, N, 2, AN_limbs);

    /* Rest of T is given to exp_mod for its working space */
    pf_mbedtls_mpi_core_exp_mod(X,
                             A, N, AN_limbs, Nminus2, AN_limbs,
                             RR, T + AN_limbs);
}

void pf_mbedtls_mpi_mod_raw_add(pf_mbedtls_mpi_uint *X,
                             const pf_mbedtls_mpi_uint *A,
                             const pf_mbedtls_mpi_uint *B,
                             const pf_mbedtls_mpi_mod_modulus *N)
{
    pf_mbedtls_mpi_uint carry, borrow;
    carry  = pf_mbedtls_mpi_core_add(X, A, B, N->limbs);
    borrow = pf_mbedtls_mpi_core_sub(X, X, N->p, N->limbs);
    (void) pf_mbedtls_mpi_core_add_if(X, N->p, N->limbs, (unsigned) (carry ^ borrow));
}

int pf_mbedtls_mpi_mod_raw_canonical_to_modulus_rep(
    pf_mbedtls_mpi_uint *X,
    const pf_mbedtls_mpi_mod_modulus *N)
{
    switch (N->int_rep) {
        case PF_MBEDTLS_MPI_MOD_REP_MONTGOMERY:
            return pf_mbedtls_mpi_mod_raw_to_mont_rep(X, N);
        case PF_MBEDTLS_MPI_MOD_REP_OPT_RED:
            return 0;
        default:
            return PF_MBEDTLS_ERR_MPI_BAD_INPUT_DATA;
    }
}

int pf_mbedtls_mpi_mod_raw_modulus_to_canonical_rep(
    pf_mbedtls_mpi_uint *X,
    const pf_mbedtls_mpi_mod_modulus *N)
{
    switch (N->int_rep) {
        case PF_MBEDTLS_MPI_MOD_REP_MONTGOMERY:
            return pf_mbedtls_mpi_mod_raw_from_mont_rep(X, N);
        case PF_MBEDTLS_MPI_MOD_REP_OPT_RED:
            return 0;
        default:
            return PF_MBEDTLS_ERR_MPI_BAD_INPUT_DATA;
    }
}

int pf_mbedtls_mpi_mod_raw_random(pf_mbedtls_mpi_uint *X,
                               pf_mbedtls_mpi_uint min,
                               const pf_mbedtls_mpi_mod_modulus *N,
                               int (*f_rng)(void *, unsigned char *, size_t),
                               void *p_rng)
{
    int ret = pf_mbedtls_mpi_core_random(X, min, N->p, N->limbs, f_rng, p_rng);
    if (ret != 0) {
        return ret;
    }
    return pf_mbedtls_mpi_mod_raw_canonical_to_modulus_rep(X, N);
}

int pf_mbedtls_mpi_mod_raw_to_mont_rep(pf_mbedtls_mpi_uint *X,
                                    const pf_mbedtls_mpi_mod_modulus *N)
{
    pf_mbedtls_mpi_uint *T;
    const size_t t_limbs = pf_mbedtls_mpi_core_montmul_working_limbs(N->limbs);

    if ((T = (pf_mbedtls_mpi_uint *) pf_mbedtls_calloc(t_limbs, ciL)) == NULL) {
        return PF_MBEDTLS_ERR_MPI_ALLOC_FAILED;
    }

    pf_mbedtls_mpi_core_to_mont_rep(X, X, N->p, N->limbs,
                                 N->rep.mont.mm, N->rep.mont.rr, T);

    pf_mbedtls_zeroize_and_free(T, t_limbs * ciL);
    return 0;
}

int pf_mbedtls_mpi_mod_raw_from_mont_rep(pf_mbedtls_mpi_uint *X,
                                      const pf_mbedtls_mpi_mod_modulus *N)
{
    const size_t t_limbs = pf_mbedtls_mpi_core_montmul_working_limbs(N->limbs);
    pf_mbedtls_mpi_uint *T;

    if ((T = (pf_mbedtls_mpi_uint *) pf_mbedtls_calloc(t_limbs, ciL)) == NULL) {
        return PF_MBEDTLS_ERR_MPI_ALLOC_FAILED;
    }

    pf_mbedtls_mpi_core_from_mont_rep(X, X, N->p, N->limbs, N->rep.mont.mm, T);

    pf_mbedtls_zeroize_and_free(T, t_limbs * ciL);
    return 0;
}

void pf_mbedtls_mpi_mod_raw_neg(pf_mbedtls_mpi_uint *X,
                             const pf_mbedtls_mpi_uint *A,
                             const pf_mbedtls_mpi_mod_modulus *N)
{
    pf_mbedtls_mpi_core_sub(X, N->p, A, N->limbs);

    /* If A=0 initially, then X=N now. Detect this by
     * subtracting N and catching the carry. */
    pf_mbedtls_mpi_uint borrow = pf_mbedtls_mpi_core_sub(X, X, N->p, N->limbs);
    (void) pf_mbedtls_mpi_core_add_if(X, N->p, N->limbs, (unsigned) borrow);
}

#endif /* MBEDTLS_BIGNUM_C && MBEDTLS_ECP_WITH_MPI_UINT */
