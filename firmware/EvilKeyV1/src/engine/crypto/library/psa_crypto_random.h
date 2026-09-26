/*
 *  PSA crypto random generator internal functions.
 */
/*
 *  Copyright The Mbed TLS Contributors
 *  SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
 */

#ifndef PF_PSA_CRYPTO_RANDOM_H
#define PF_PSA_CRYPTO_RANDOM_H

#include "common.h"

#if !defined(PF_MBEDTLS_PSA_CRYPTO_EXTERNAL_RNG)

#include "../include/psa/crypto.h"
#include "psa_crypto_random_impl.h"

/** Initialize the PSA random generator.
 *
 * \param[out] rng      The random generator context to initialize.
 */
void pf_psa_random_internal_init(pf_mbedtls_psa_random_context_t *rng);

/** Deinitialize the PSA random generator.
 *
 * \param[in,out] rng   The random generator context to deinitialize.
 */
void pf_psa_random_internal_free(pf_mbedtls_psa_random_context_t *rng);

/** Seed the PSA random generator.
 *
 * \note This function is not thread-safe.
 *
 * \param[in,out] rng   The random generator context to seed.
 *
 * \retval #PSA_SUCCESS
 *         Success.
 * \retval #PSA_ERROR_INSUFFICIENT_ENTROPY
 *         The entropy source failed.
 */
pf_psa_status_t pf_psa_random_internal_seed(pf_mbedtls_psa_random_context_t *rng);

/**
 * \brief Generate random bytes. Like psa_generate_random(), but for use
 *        inside the library.
 *
 * This function is thread-safe.
 *
 * \warning This function **can** fail! Callers MUST check the return status
 *          and MUST NOT use the content of the output buffer if the return
 *          status is not #PSA_SUCCESS.
 *
 * \param[in,out] rng       The random generator context to seed.
 * \param[out] output       Output buffer for the generated data.
 * \param output_size       Number of bytes to generate and output.
 *
 * \retval #PSA_SUCCESS
 *         Success.
 * \retval #PSA_ERROR_INSUFFICIENT_ENTROPY
 *         The random generator needed to reseed, and the entropy
 *         source failed.
 * \retval #PSA_ERROR_HARDWARE_FAILURE
 *         A hardware accelerator failed.
 */
pf_psa_status_t pf_psa_random_internal_generate(
    pf_mbedtls_psa_random_context_t *rng,
    uint8_t *output, size_t output_size);

#endif /* !defined(MBEDTLS_PSA_CRYPTO_EXTERNAL_RNG) */

#endif /* PSA_CRYPTO_RANDOM_H */
