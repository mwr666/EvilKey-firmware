/**
 * \file bignum_mod_raw_invasive.h
 *
 * \brief Function declarations for invasive functions of Low-level
 *        modular bignum.
 */
/**
 *  Copyright The Mbed TLS Contributors
 *  SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
 */

#ifndef PF_MBEDTLS_BIGNUM_MOD_RAW_INVASIVE_H
#define PF_MBEDTLS_BIGNUM_MOD_RAW_INVASIVE_H

#include "common.h"
#include "../include/mbedtls/bignum.h"
#include "bignum_mod.h"

#if defined(PF_MBEDTLS_TEST_HOOKS)

/** Convert the result of a quasi-reduction to its canonical representative.
 *
 * \param[in,out] X     The address of the MPI to be converted. Must have the
 *                      same number of limbs as \p N. The input value must
 *                      be in range 0 <= X < 2N.
 * \param[in]     N     The address of the modulus.
 */
PF_MBEDTLS_STATIC_TESTABLE
void pf_mbedtls_mpi_mod_raw_fix_quasi_reduction(pf_mbedtls_mpi_uint *X,
                                             const pf_mbedtls_mpi_mod_modulus *N);

#endif /* MBEDTLS_TEST_HOOKS */

#endif /* MBEDTLS_BIGNUM_MOD_RAW_INVASIVE_H */
